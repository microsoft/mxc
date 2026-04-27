// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `NanVixScriptRunner` -- executes code inside a NanVix micro-VM.
//!
//! The initial runtime is CPython 3.12 with a trimmed FAT32 stdlib filesystem.
//! The architecture supports additional runtimes (QuickJS, C, C++, Rust binaries).
//!
//! ## I/O model
//!
//! - **stdin**: runner writes script code, then closes (EOF triggers `exec()`)
//! - **stdout**: relayed directly to parent process via `Stdio::inherit()` (not captured)
//! - **stderr**: relayed directly to parent process via `Stdio::inherit()` (kernel traces)
//!
//! **Note for SDK consumers:** Because stdout/stderr are inherited (not captured),
//! `ScriptResponse.standard_out` and `standard_err` are always empty strings for
//! the NanVix backend. Output is streamed directly to the parent's console/pipes.
//! Programmatic consumers that need captured output should redirect wxc-exec's
//! stdout/stderr at the process level.
//!
//! ## Exit codes
//!
//! `nanvixd` propagates the guest process exit code directly.
//!
//! ## Auto-discovery
//!
//! All required binaries (`nanvixd.exe`, `python.elf`, `cpython-ramfs.img`)
//! are discovered next to the running executable. No configuration is needed.

use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::logger::Logger;
use crate::models::{CodexRequest, NetworkPolicy, ScriptResponse};
use crate::script_runner::ScriptRunner;

/// CPython guest binary loaded by NanVix.
const PYTHON_BINARY: &str = "python.elf";
/// Guest PYTHONHOME value used by CPython inside NanVix.
/// Must NOT contain ';' or spaces — these are NanVix argument delimiters
/// that would corrupt the guest cmdline string.
const PYTHON_HOME: &str = "/sysroot";
/// NanVix daemon binary launched by the host runner.
const NANVIXD_BINARY: &str = "nanvixd.exe";
/// CPython stdlib ramfs image mounted by NanVix.
const RAMFS_IMAGE: &str = "cpython-ramfs.img";
/// Boot grace period that is always enforced.
const BOOT_TIMEOUT_MS: u64 = 60_000;
/// Generic error exit code returned to host callers.
const ERROR_EXIT_CODE: i32 = -1;
const ERR_DENIED_PATHS: &str = "denied_paths is not meaningful for the microvm backend \
     -- the guest has no host filesystem visibility. \
     Only readwrite_paths and readonly_paths are supported";
const ERR_NETWORK_POLICY: &str =
    "network policy is not supported by the NanVix backend -- NanVix has no network stack";
const ERR_PROXY_POLICY: &str =
    "network proxy is not supported by the NanVix backend -- NanVix has no network stack";
const ERR_WORKDIR: &str = "workingDirectory is not supported by the NanVix backend -- guest has its own filesystem namespace";

// -- NanVix error classification ---------------------------------------------

/// Classifies NanVix runner errors for structured error handling.
#[derive(Debug)]
enum NanVixError {
    /// Pre-spawn validation failures (missing artifacts, invalid config, unsupported policy).
    Preflight(String),
    /// OS/platform failures while spawning/managing the NanVix process (WHP/spawn/handles).
    Platform(String),
    /// Stdin broken pipe, VM crash.
    Runtime(String),
    /// Watchdog killed the process.
    Timeout {
        script_timeout_ms: u32,
        total_ms: u64,
    },
}

impl std::fmt::Display for NanVixError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NanVixError::Preflight(msg) => write!(f, "NanVix preflight error: {}", msg),
            NanVixError::Platform(msg) => write!(f, "NanVix platform error: {}", msg),
            NanVixError::Runtime(msg) => write!(f, "NanVix runtime error: {}", msg),
            NanVixError::Timeout {
                script_timeout_ms,
                total_ms,
            } => write!(
                f,
                "NanVix execution timed out after {}ms \
                 (boot_timeout={}ms, script_timeout={}ms)",
                total_ms, BOOT_TIMEOUT_MS, script_timeout_ms
            ),
        }
    }
}

impl NanVixError {
    fn to_response(&self) -> ScriptResponse {
        ScriptResponse {
            exit_code: ERROR_EXIT_CODE,
            error_message: self.to_string(),
            ..Default::default()
        }
    }
}

/// Returns the directory containing the current executable.
fn exe_dir() -> Result<PathBuf, NanVixError> {
    crate::process_util::exe_dir().map_err(|e| NanVixError::Preflight(e.to_string()))
}

/// Watchdog thread: waits for timeout or cancellation, then terminates the process.
fn watchdog_thread_fn(
    process_handle_raw: usize,
    duration: Duration,
    cancel_pair: Arc<(Mutex<bool>, Condvar)>,
    timed_out: Arc<AtomicBool>,
) {
    let (lock, cvar) = &*cancel_pair;
    let mut cancelled = lock.lock().unwrap_or_else(|e| e.into_inner());
    let start = Instant::now();
    let mut remaining = duration;
    loop {
        let result = cvar
            .wait_timeout(cancelled, remaining)
            .unwrap_or_else(|e| e.into_inner());
        cancelled = result.0;
        if *cancelled || result.1.timed_out() {
            break;
        }
        let elapsed = start.elapsed();
        if elapsed >= duration {
            break;
        }
        remaining = duration.saturating_sub(elapsed);
    }

    // Always close the duplicated handle to avoid leaks.
    let close_handle = |handle_raw: usize| {
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        let handle = HANDLE(handle_raw as *mut std::ffi::c_void);
        // SAFETY: `handle` was returned by `DuplicateHandle` in this
        // process and is closed exactly once by this watchdog thread.
        let _ = unsafe { CloseHandle(handle) };
    };

    if *cancelled {
        // Process already exited — close the handle and return.
        close_handle(process_handle_raw);
        return;
    }

    // Timeout elapsed and process is still running — kill it.
    // Set the timed_out flag BEFORE terminating so the main thread
    // always sees it as true after child.wait() returns from a kill.
    timed_out.store(true, Ordering::SeqCst);

    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Threading::TerminateProcess;

    let handle = HANDLE(process_handle_raw as *mut std::ffi::c_void);
    // SAFETY: `handle` is a valid duplicated process handle owned by
    // this thread, and passing exit code 1 is valid for termination.
    let _ = unsafe { TerminateProcess(handle, 1) };
    close_handle(process_handle_raw);
}

/// Components returned by [`NanVixScriptRunner::setup_watchdog`]: the watchdog
/// thread handle (if a finite timeout was requested), the cancellation pair
/// used to signal early completion, and the `timed_out` flag.
type WatchdogState = (
    Option<JoinHandle<()>>,
    Arc<(Mutex<bool>, Condvar)>,
    Arc<AtomicBool>,
);

// -- NanVixScriptRunner ------------------------------------------------------

/// Script runner that executes Python code inside a NanVix microkernel VM.
///
/// All binaries are auto-discovered next to the running executable.
pub struct NanVixScriptRunner {
    _private: (),
}

impl Default for NanVixScriptRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl NanVixScriptRunner {
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Resolve and validate all required paths next to the running executable.
    fn resolve_paths(&self) -> Result<(PathBuf, PathBuf, PathBuf, PathBuf), NanVixError> {
        let dir = exe_dir()?;
        // NanVix runtime artifacts (nanvixd.exe, kernel.elf, python.elf, cpython-ramfs.img)
        // are distributed via GitHub releases from nanvix/nanvix and nanvix/cpython.
        // They are placed next to wxc-exec.exe by setup scripts.

        let nanvixd = dir.join(NANVIXD_BINARY);
        if !nanvixd.exists() {
            return Err(NanVixError::Preflight(format!(
                "{} not found in {:?}",
                NANVIXD_BINARY, dir
            )));
        }

        let ramfs = dir.join(RAMFS_IMAGE);
        if !ramfs.exists() {
            return Err(NanVixError::Preflight(format!(
                "{} not found in {:?}",
                RAMFS_IMAGE, dir
            )));
        }

        let python = dir.join(PYTHON_BINARY);
        if !python.exists() {
            return Err(NanVixError::Preflight(format!(
                "{} not found in {:?}",
                PYTHON_BINARY, dir
            )));
        }

        Ok((nanvixd, dir, ramfs, python))
    }

    /// Compute total timeout: boot grace + staging overhead + script timeout.
    fn total_timeout_ms(script_timeout: u32, staging_overhead_ms: u64) -> u64 {
        if script_timeout == 0 {
            u64::MAX
        } else {
            BOOT_TIMEOUT_MS
                .saturating_add(staging_overhead_ms)
                .saturating_add(script_timeout as u64)
        }
    }

    fn validate_policies(request: &CodexRequest) -> Result<(), NanVixError> {
        // denied_paths is explicitly rejected — microvm has no host visibility.
        if !request.policy.denied_paths.is_empty() {
            return Err(NanVixError::Preflight(ERR_DENIED_PATHS.to_string()));
        }
        // readwrite_paths and readonly_paths are now accepted (handled via staging dir).
        // Network policy is still rejected — NanVix has no network stack.
        if !request.policy.allowed_hosts.is_empty()
            || !request.policy.blocked_hosts.is_empty()
            || request.policy.default_network_policy != NetworkPolicy::Allow
        {
            return Err(NanVixError::Preflight(ERR_NETWORK_POLICY.to_string()));
        }
        if request.policy.network_proxy.is_enabled() {
            return Err(NanVixError::Preflight(ERR_PROXY_POLICY.to_string()));
        }
        if !request.working_directory.is_empty() {
            return Err(NanVixError::Preflight(ERR_WORKDIR.to_string()));
        }

        Ok(())
    }

    fn build_guest_args() -> String {
        // Build the NanVix guest argument string for mount-based script delivery.
        // Format: "-S -B /mnt/.mxc-bootstrap.py;PYTHONHOME=/sysroot"
        //
        // -S: skip site.py (critical — site import is very slow with large ramfs)
        // -B: no .pyc writing (read-only filesystem)
        //
        // The bootstrap script lives in the staging directory mounted at /mnt.
        // It reads /mnt/.mxc-pathmap.json, exports MXC_PATH_* env vars,
        // then runs /mnt/.mxc-script.py via runpy.run_path().
        //
        // NanVix splits on spaces: argv = ["python.elf", "-S", "-B", "/mnt/..."]
        // NanVix splits on ';': env = ["PYTHONHOME=/sysroot"]
        format!("-S -B /mnt/.mxc-bootstrap.py;PYTHONHOME={}", PYTHON_HOME)
    }

    fn spawn_nanvixd(
        paths: (&Path, &Path, &Path, &Path),
        guest_args: &str,
        staging_dir: &Path,
    ) -> Result<std::process::Child, NanVixError> {
        let (nanvixd_path, bin_dir, ramfs_path, python_path) = paths;
        Command::new(nanvixd_path)
            .arg("-bin-dir")
            .arg(bin_dir)
            .arg("-ramfs")
            .arg(ramfs_path)
            .arg("-mount")
            .arg(staging_dir)
            .arg("--")
            .arg(python_path)
            .arg(guest_args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| {
                NanVixError::Platform(format!("failed to spawn {}: {}", NANVIXD_BINARY, e))
            })
    }

    fn start_watchdog(
        child: &std::process::Child,
        timeout_ms: u64,
        cancel_pair: Arc<(Mutex<bool>, Condvar)>,
        timed_out: Arc<AtomicBool>,
    ) -> Option<thread::JoinHandle<()>> {
        if timeout_ms == u64::MAX {
            return None;
        }

        let duration = Duration::from_millis(timeout_ms);

        // Duplicate the process handle at spawn time (safe against PID reuse).
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE};
        use windows::Win32::System::Threading::GetCurrentProcess;

        let raw = child.as_raw_handle();
        let mut dup_handle = HANDLE::default();
        let dup_ok = unsafe {
            // SAFETY: `raw` is the live process HANDLE from `std::process::Child`.
            // We duplicate it into the current process with same access rights so
            // the watchdog thread can safely terminate/close it independently.
            DuplicateHandle(
                GetCurrentProcess(),
                HANDLE(raw),
                GetCurrentProcess(),
                &mut dup_handle,
                0,
                false,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if dup_ok.is_err() {
            return None;
        }
        let process_handle_raw = dup_handle.0 as usize;

        Some(thread::spawn(move || {
            watchdog_thread_fn(process_handle_raw, duration, cancel_pair, timed_out);
        }))
    }

    fn setup_watchdog(
        child: &mut std::process::Child,
        timeout_ms: u64,
        logger: &mut Logger,
    ) -> Result<WatchdogState, ScriptResponse> {
        let timed_out = Arc::new(AtomicBool::new(false));
        let cancel_pair = Arc::new((Mutex::new(false), Condvar::new()));

        let watchdog = if timeout_ms < u64::MAX {
            match Self::start_watchdog(
                child,
                timeout_ms,
                Arc::clone(&cancel_pair),
                Arc::clone(&timed_out),
            ) {
                Some(handle) => Some(handle),
                None => {
                    let err = NanVixError::Platform(format!(
                        "failed to duplicate {} process handle",
                        NANVIXD_BINARY
                    ));
                    let _ = writeln!(logger, "{}", err);
                    if let Err(e) = child.kill() {
                        let _ = writeln!(
                            logger,
                            "NanVix: failed to kill child after handle dup failure: {}",
                            e
                        );
                    }
                    if let Err(e) = child.wait() {
                        let _ = writeln!(
                            logger,
                            "NanVix: failed to wait for child after handle dup failure: {}",
                            e
                        );
                    }
                    return Err(err.to_response());
                }
            }
        } else {
            None
        };

        Ok((watchdog, cancel_pair, timed_out))
    }

    fn log_resolved_paths(
        logger: &mut Logger,
        nanvixd: &Path,
        bin_dir: &Path,
        ramfs: &Path,
        python: &Path,
    ) {
        let _ = writeln!(logger, "NanVix: nanvixd={:?}", nanvixd);
        let _ = writeln!(logger, "NanVix: bin_dir={:?}", bin_dir);
        let _ = writeln!(logger, "NanVix: ramfs={:?}", ramfs);
        let _ = writeln!(logger, "NanVix: python={:?}", python);
    }

    fn wait_and_respond(
        child: &mut Child,
        watchdog: Option<JoinHandle<()>>,
        cancel_pair: &Arc<(Mutex<bool>, Condvar)>,
        timed_out: &AtomicBool,
        timeout_ms: u64,
        script_timeout: u32,
        logger: &mut Logger,
    ) -> ScriptResponse {
        let exit_status = child.wait();

        {
            let (lock, cvar) = &**cancel_pair;
            let mut cancelled = lock.lock().unwrap_or_else(|e| e.into_inner());
            *cancelled = true;
            cvar.notify_one();
        }

        if let Some(handle) = watchdog {
            let _ = handle.join();
        }

        if timed_out.load(Ordering::SeqCst) {
            let _ = child.kill();
            let err = NanVixError::Timeout {
                script_timeout_ms: script_timeout,
                total_ms: timeout_ms,
            };
            let _ = writeln!(logger, "{}", err);
            return err.to_response();
        }

        match exit_status {
            Ok(status) => {
                let exit_code = status.code().unwrap_or(ERROR_EXIT_CODE);
                let _ = writeln!(logger, "NanVix: process exited with code {}", exit_code);
                ScriptResponse {
                    exit_code,
                    ..Default::default()
                }
            }
            Err(e) => {
                let err =
                    NanVixError::Runtime(format!("failed to wait for {}: {}", NANVIXD_BINARY, e));
                let _ = writeln!(logger, "{}", err);
                err.to_response()
            }
        }
    }
}

impl ScriptRunner for NanVixScriptRunner {
    fn run(&mut self, request: &CodexRequest, logger: &mut Logger) -> ScriptResponse {
        if let Err(e) = Self::validate_policies(request) {
            return e.to_response();
        }

        let (nanvixd_path, bin_dir, ramfs_path, python_path) = match self.resolve_paths() {
            Ok(paths) => paths,
            Err(e) => return e.to_response(),
        };

        // Build staging directory with script and filesystem policy paths.
        let staging_root = std::env::temp_dir().join("mxc-microvm");
        let staging = match crate::microvm_staging::StagingDir::new(
            staging_root,
            &request.script_code,
            &request.policy.readwrite_paths,
            &request.policy.readonly_paths,
        ) {
            Ok(s) => s,
            Err(e) => {
                let err = NanVixError::Preflight(e.to_string());
                let _ = writeln!(logger, "{}", err);
                return err.to_response();
            }
        };

        Self::log_resolved_paths(logger, &nanvixd_path, &bin_dir, &ramfs_path, &python_path);
        let _ = writeln!(logger, "NanVix: staging_dir={:?}", staging.path());
        let guest_args = Self::build_guest_args();

        let mut child = match Self::spawn_nanvixd(
            (&nanvixd_path, &bin_dir, &ramfs_path, &python_path),
            &guest_args,
            staging.path(),
        ) {
            Ok(c) => c,
            Err(e) => {
                let _ = writeln!(logger, "{}", e);
                return e.to_response();
            }
        };

        let staging_overhead = staging.staging_overhead_ms();
        let timeout_ms = Self::total_timeout_ms(request.script_timeout, staging_overhead);
        let (watchdog, cancel_pair, timed_out) =
            match Self::setup_watchdog(&mut child, timeout_ms, logger) {
                Ok(v) => v,
                Err(resp) => return resp,
            };

        Self::wait_and_respond(
            &mut child,
            watchdog,
            &cancel_pair,
            timed_out.as_ref(),
            timeout_ms,
            request.script_timeout,
            logger,
        )
        // staging is dropped here → cleanup
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logger::{Logger, Mode};
    use crate::models::{ContainerPolicy, NetworkPolicy};

    #[test]
    fn total_timeout_adds_boot_staging_and_script() {
        // script_timeout=0 => infinite script timeout sentinel.
        assert_eq!(NanVixScriptRunner::total_timeout_ms(0, 0), u64::MAX);
        // script_timeout=30000, staging_overhead=500 -> 30s + 500ms + 60s boot = 90.5s
        assert_eq!(NanVixScriptRunner::total_timeout_ms(30_000, 500), 90_500);
        // script_timeout=30000, no staging -> 30s + 60s boot = 90s
        assert_eq!(NanVixScriptRunner::total_timeout_ms(30_000, 0), 90_000);
    }

    #[test]
    fn resolve_paths_fails_when_exe_dir_has_no_binaries() {
        let runner = NanVixScriptRunner::new();
        let err = runner.resolve_paths().unwrap_err();
        assert!(err.to_string().contains("not found"), "got: {}", err);
    }

    // -- Policy validation tests -------------------------------------------------

    #[test]
    fn policy_accepts_readwrite_paths() {
        // readwrite_paths are now accepted (staging dir handles them).
        // Validation passes; the runner fails later on path resolution.
        let request = CodexRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec!["/tmp".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let result = NanVixScriptRunner::validate_policies(&request);
        assert!(result.is_ok(), "readwrite_paths should be accepted");
    }

    #[test]
    fn policy_accepts_readonly_paths() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                readonly_paths: vec!["/data".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let result = NanVixScriptRunner::validate_policies(&request);
        assert!(result.is_ok(), "readonly_paths should be accepted");
    }

    #[test]
    fn policy_rejects_denied_paths() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                denied_paths: vec!["/secret".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let result = NanVixScriptRunner::validate_policies(&request);
        assert!(result.is_err(), "denied_paths should be rejected");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains(ERR_DENIED_PATHS),
            "expected denied_paths error, got: {}",
            err
        );
    }

    #[test]
    fn policy_rejects_network_hosts() {
        let mut runner = NanVixScriptRunner::new();
        let request = CodexRequest {
            policy: ContainerPolicy {
                allowed_hosts: vec!["example.com".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let mut logger = Logger::new(Mode::Buffer);
        let resp = runner.run(&request, &mut logger);
        assert_eq!(resp.exit_code, ERROR_EXIT_CODE);
        assert!(resp.error_message.contains(ERR_NETWORK_POLICY));
    }

    #[test]
    fn policy_rejects_blocked_network_hosts() {
        let mut runner = NanVixScriptRunner::new();
        let request = CodexRequest {
            policy: ContainerPolicy {
                blocked_hosts: vec!["evil.com".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let mut logger = Logger::new(Mode::Buffer);
        let resp = runner.run(&request, &mut logger);
        assert_eq!(resp.exit_code, ERROR_EXIT_CODE);
        assert!(resp.error_message.contains(ERR_NETWORK_POLICY));
    }

    #[test]
    fn policy_rejects_network_block_policy() {
        let mut runner = NanVixScriptRunner::new();
        let request = CodexRequest {
            policy: ContainerPolicy {
                default_network_policy: NetworkPolicy::Block,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut logger = Logger::new(Mode::Buffer);
        let resp = runner.run(&request, &mut logger);
        assert_eq!(resp.exit_code, ERROR_EXIT_CODE);
        assert!(resp.error_message.contains(ERR_NETWORK_POLICY));
    }

    #[test]
    fn policy_rejects_working_directory() {
        let mut runner = NanVixScriptRunner::new();
        let request = CodexRequest {
            working_directory: "/home/user".to_string(),
            ..Default::default()
        };
        let mut logger = Logger::new(Mode::Buffer);
        let resp = runner.run(&request, &mut logger);
        assert_eq!(resp.exit_code, ERROR_EXIT_CODE);
        assert!(resp.error_message.contains(ERR_WORKDIR));
    }

    #[test]
    fn policy_allows_defaults() {
        // A request with all-default policies should pass validation and
        // fail later on path resolution (nanvixd not found), NOT on policy.
        let mut runner = NanVixScriptRunner::new();
        let request = CodexRequest::default();
        let mut logger = Logger::new(Mode::Buffer);
        let resp = runner.run(&request, &mut logger);
        assert_eq!(resp.exit_code, ERROR_EXIT_CODE);
        assert!(
            !resp.error_message.contains("denied_paths"),
            "default request should not trigger filesystem policy rejection"
        );
        assert!(
            !resp.error_message.contains(ERR_NETWORK_POLICY),
            "default request should not trigger network policy rejection"
        );
        assert!(
            !resp.error_message.contains(ERR_WORKDIR),
            "default request should not trigger workingDirectory rejection"
        );
    }

    #[test]
    fn policy_rejects_network_proxy() {
        let mut runner = NanVixScriptRunner::new();
        let request = CodexRequest {
            policy: ContainerPolicy {
                network_proxy: crate::models::ProxyConfig {
                    address: Some(crate::models::ProxyAddress::new(
                        "127.0.0.1".to_string(),
                        8080,
                    )),
                    builtin_test_server: false,
                },
                ..Default::default()
            },
            ..Default::default()
        };
        let mut logger = Logger::new(Mode::Buffer);
        let resp = runner.run(&request, &mut logger);
        assert_eq!(resp.exit_code, ERROR_EXIT_CODE);
        assert!(resp.error_message.contains(ERR_PROXY_POLICY));
    }

    #[test]
    fn python_home_constant_has_no_delimiters() {
        // PYTHON_HOME must not contain ';' or spaces — these are NanVix
        // argument delimiters that would corrupt the guest arg string.
        assert!(!PYTHON_HOME.contains(';'), "PYTHON_HOME contains ';'");
        assert!(!PYTHON_HOME.contains(' '), "PYTHON_HOME contains space");
    }

    #[test]
    fn guest_args_format_is_correct() {
        let expected = "-S -B /mnt/.mxc-bootstrap.py;PYTHONHOME=/sysroot";
        let actual = NanVixScriptRunner::build_guest_args();
        assert_eq!(actual, expected);
        // The bootstrap path segment itself must not contain spaces.
        // (The -S and -B flags are intentional space-separated argv entries.)
        assert!(
            actual.contains("/mnt/.mxc-bootstrap.py"),
            "must contain bootstrap path"
        );
    }

    #[test]
    fn guest_args_use_bootstrap_path() {
        let args = NanVixScriptRunner::build_guest_args();
        assert!(
            args.contains(".mxc-bootstrap.py"),
            "guest args should reference bootstrap script, got: {}",
            args
        );
        assert!(
            !args.contains("exec(__import__"),
            "guest args should NOT use stdin exec trick, got: {}",
            args
        );
    }
}
