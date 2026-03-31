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
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use crate::logger::Logger;
use crate::models::{CodexRequest, NetworkPolicy, ScriptResponse};
use crate::script_runner::{get_timeout_milliseconds, ScriptRunner};

const PYTHON_BINARY: &str = "python.elf";
const PYTHON_HOME: &str = "/sysroot";
const BOOT_TIMEOUT_MS: u64 = 60_000;

// -- NanVix error classification ---------------------------------------------

/// Classifies NanVix runner errors for structured error handling.
#[derive(Debug)]
enum NanVixError {
    /// Missing binaries, invalid paths, unsupported policies.
    Preflight(String),
    /// WHP unavailable, spawn failure.
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
            exit_code: -1,
            error_message: self.to_string(),
            ..Default::default()
        }
    }
}

/// Returns the directory containing the current executable.
fn exe_dir() -> Result<PathBuf, NanVixError> {
    let exe = std::env::current_exe()
        .map_err(|e| NanVixError::Preflight(format!("cannot determine exe path: {}", e)))?;
    exe.parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| NanVixError::Preflight("exe has no parent directory".to_string()))
}

// -- NanVixScriptRunner ------------------------------------------------------

/// Script runner that executes Python code inside a NanVix microkernel VM.
///
/// All binaries are auto-discovered next to the running executable.
pub struct NanVixScriptRunner {
    _private: (),
}

impl NanVixScriptRunner {
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Resolve and validate all required paths next to the running executable.
    fn resolve_paths(&self) -> Result<(PathBuf, PathBuf, PathBuf, PathBuf), NanVixError> {
        let dir = exe_dir()?;

        let nanvixd = dir.join("nanvixd.exe");
        if !nanvixd.exists() {
            return Err(NanVixError::Preflight(format!(
                "nanvixd.exe not found in {:?}",
                dir
            )));
        }

        let ramfs = dir.join("cpython-ramfs.img");
        if !ramfs.exists() {
            return Err(NanVixError::Preflight(format!(
                "cpython-ramfs.img not found in {:?}",
                dir
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

    /// Compute total timeout: boot grace + script timeout.
    fn total_timeout_ms(script_timeout: u32) -> u64 {
        let script_ms = get_timeout_milliseconds(script_timeout) as u64;
        BOOT_TIMEOUT_MS.saturating_add(script_ms)
    }
}

impl ScriptRunner for NanVixScriptRunner {
    fn run(&mut self, request: &CodexRequest, logger: &mut Logger) -> ScriptResponse {
        // -- Policy validation ---------------------------------------------------
        // Reject unsupported policies — NanVix provides its own isolation model.
        // Fail-closed: any policy setting not meaningful for NanVix is rejected.
        if !request.policy.readwrite_paths.is_empty()
            || !request.policy.readonly_paths.is_empty()
            || !request.policy.denied_paths.is_empty()
        {
            return NanVixError::Preflight(
                "filesystem policy is not supported by the NanVix backend \
                 -- guest has a read-only ramfs"
                    .to_string(),
            )
            .to_response();
        }
        if !request.policy.allowed_hosts.is_empty()
            || !request.policy.blocked_hosts.is_empty()
            || request.policy.default_network_policy != NetworkPolicy::Allow
        {
            return NanVixError::Preflight(
                "network policy is not supported by the NanVix backend \
                 -- NanVix has no network stack"
                    .to_string(),
            )
            .to_response();
        }
        if request.policy.network_proxy.is_enabled() {
            return NanVixError::Preflight(
                "network proxy is not supported by the NanVix backend \
                 — NanVix has no network stack"
                    .to_string(),
            )
            .to_response();
        }
        if !request.working_directory.is_empty() {
            return NanVixError::Preflight(
                "workingDirectory is not supported by the NanVix backend \
                 -- guest has its own filesystem namespace"
                    .to_string(),
            )
            .to_response();
        }

        // Validate PYTHON_HOME doesn't contain NanVix delimiters that could
        // corrupt the guest argument string (';' separates argv from env vars,
        // spaces separate argv entries).
        if PYTHON_HOME.contains(';') || PYTHON_HOME.contains(' ') {
            return NanVixError::Preflight(format!(
                "PYTHON_HOME '{}' contains invalid characters (';' or space) \
                 — these are NanVix argument delimiters",
                PYTHON_HOME
            ))
            .to_response();
        }

        // -- Path resolution -----------------------------------------------------
        let (nanvixd_path, bin_dir, ramfs_path, python_path) = match self.resolve_paths() {
            Ok(paths) => paths,
            Err(e) => return e.to_response(),
        };

        let _ = writeln!(logger, "NanVix: nanvixd={:?}", nanvixd_path);
        let _ = writeln!(logger, "NanVix: bin_dir={:?}", bin_dir);
        let _ = writeln!(logger, "NanVix: ramfs={:?}", ramfs_path);
        let _ = writeln!(logger, "NanVix: python={:?}", python_path);

        // Build the guest argument string.
        // The ';' is NanVix's separator between argv and environment variables:
        //   everything before ';' -> kernel splits on spaces -> argv[]
        //   everything after ';'  -> kernel sets as env vars
        // -S: skip site.py, -B: no .pyc writing
        // -c exec(...): reads all of stdin and executes it (no interactive >>> prompts)
        // Note: exec(__import__('sys').stdin.read()) has NO spaces, so it survives
        //       NanVix's space-splitting in build_string_table().
        let guest_args = format!(
            "-S -B -c exec(__import__('sys').stdin.read());PYTHONHOME={}",
            PYTHON_HOME
        );

        // -- Spawn nanvixd -------------------------------------------------------
        // stdout/stderr are inherited (relayed directly to parent process).
        // Only stdin is piped so we can write the script and send EOF.
        let mut child = match Command::new(&nanvixd_path)
            .arg("-bin-dir")
            .arg(&bin_dir)
            .arg("-ramfs")
            .arg(&ramfs_path)
            .arg("--")
            .arg(&python_path)
            .arg(&guest_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                let err = NanVixError::Platform(format!("failed to spawn nanvixd: {}", e));
                let _ = writeln!(logger, "{}", err);
                return err.to_response();
            }
        };

        // Write script to stdin, then close (EOF triggers exec() in guest Python).
        // With inherited stdout/stderr there is no pipe buffer deadlock risk.
        if let Some(mut stdin) = child.stdin.take() {
            if let Err(e) = stdin.write_all(request.script_code.as_bytes()) {
                let err = NanVixError::Runtime(format!(
                    "failed to write script to nanvixd stdin: {}",
                    e
                ));
                let _ = writeln!(logger, "{}", err);
                let _ = child.kill();
                let _ = child.wait();
                return err.to_response();
            }
            // stdin dropped here -- sends EOF to nanvixd
        }

        // -- Watchdog ------------------------------------------------------------
        // Condvar-based watchdog with duplicated HANDLE for safe termination.
        let timeout_ms = Self::total_timeout_ms(request.script_timeout);
        let timed_out = Arc::new(AtomicBool::new(false));
        let cancel_pair = Arc::new((Mutex::new(false), Condvar::new()));

        let watchdog = if timeout_ms < u32::MAX as u64 {
            let timed_out_clone = Arc::clone(&timed_out);
            let cancel_pair_clone = Arc::clone(&cancel_pair);
            let duration = Duration::from_millis(timeout_ms);

            // Duplicate the process handle at spawn time (safe against PID reuse).
            use std::os::windows::io::AsRawHandle;
            use windows::Win32::Foundation::{DuplicateHandle, HANDLE, DUPLICATE_SAME_ACCESS};
            use windows::Win32::System::Threading::GetCurrentProcess;

            let raw = child.as_raw_handle();
            let mut dup_handle = HANDLE::default();
            let dup_ok = unsafe {
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
            let process_handle_raw: Option<usize> = if dup_ok.is_ok() {
                Some(dup_handle.0 as usize)
            } else {
                None
            };

            Some(thread::spawn(move || {
                let (lock, cvar) = &*cancel_pair_clone;
                let mut cancelled = lock.lock().unwrap();
                let result = cvar.wait_timeout(cancelled, duration).unwrap();
                cancelled = result.0;

                // Always close the duplicated handle to avoid leaks.
                let close_handle = |handle_raw: usize| {
                    use windows::Win32::Foundation::{CloseHandle, HANDLE};
                    let handle = HANDLE(handle_raw as *mut std::ffi::c_void);
                    let _ = unsafe { CloseHandle(handle) };
                };

                if *cancelled {
                    // Process already exited — close the handle and return.
                    if let Some(handle_raw) = process_handle_raw {
                        close_handle(handle_raw);
                    }
                    return;
                }

                // Timeout elapsed and process is still running — kill it.
                if let Some(handle_raw) = process_handle_raw {
                    use windows::Win32::Foundation::HANDLE;
                    use windows::Win32::System::Threading::TerminateProcess;

                    let handle = HANDLE(handle_raw as *mut std::ffi::c_void);
                    let kill_result = unsafe { TerminateProcess(handle, 1) };
                    close_handle(handle_raw);

                    if kill_result.is_ok() {
                        timed_out_clone.store(true, Ordering::SeqCst);
                    }
                }
            }))
        } else {
            None
        };

        // -- Wait + cleanup ------------------------------------------------------
        let exit_status = child.wait();

        // Signal watchdog to stop
        {
            let (lock, cvar) = &*cancel_pair;
            let mut cancelled = lock.lock().unwrap();
            *cancelled = true;
            cvar.notify_one();
        }
        if let Some(t) = watchdog {
            let _ = t.join();
        }

        let was_timed_out = timed_out.load(Ordering::SeqCst);

        if was_timed_out {
            let err = NanVixError::Timeout {
                script_timeout_ms: request.script_timeout,
                total_ms: timeout_ms,
            };
            let _ = writeln!(logger, "{}", err);
            return err.to_response();
        }

        match exit_status {
            Ok(status) => {
                let exit_code = status.code().unwrap_or(-1);
                let _ = writeln!(logger, "NanVix: process exited with code {}", exit_code);
                ScriptResponse {
                    exit_code,
                    ..Default::default()
                }
            }
            Err(e) => {
                let err = NanVixError::Runtime(format!("failed to wait for nanvixd: {}", e));
                let _ = writeln!(logger, "{}", err);
                err.to_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logger::{Logger, Mode};
    use crate::models::{ContainerPolicy, NetworkPolicy};

    #[test]
    fn total_timeout_adds_boot_and_script() {
        // script_timeout=0 -> u32::MAX (infinite), so total saturates
        assert_eq!(
            NanVixScriptRunner::total_timeout_ms(0),
            u32::MAX as u64 + BOOT_TIMEOUT_MS
        );
        // script_timeout=30000 -> 30s + 60s boot = 90s
        assert_eq!(NanVixScriptRunner::total_timeout_ms(30_000), 90_000);
    }

    #[test]
    fn resolve_paths_fails_when_exe_dir_has_no_binaries() {
        let runner = NanVixScriptRunner::new();
        let err = runner.resolve_paths().unwrap_err();
        assert!(err.to_string().contains("not found"), "got: {}", err);
    }

    // -- Policy validation tests -------------------------------------------------

    #[test]
    fn policy_rejects_filesystem_paths() {
        let mut runner = NanVixScriptRunner::new();
        let request = CodexRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec!["/tmp".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let mut logger = Logger::new(Mode::Buffer);
        let resp = runner.run(&request, &mut logger);
        assert_eq!(resp.exit_code, -1);
        assert!(resp.error_message.contains("filesystem policy"));
    }

    #[test]
    fn policy_rejects_readonly_paths() {
        let mut runner = NanVixScriptRunner::new();
        let request = CodexRequest {
            policy: ContainerPolicy {
                readonly_paths: vec!["/data".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let mut logger = Logger::new(Mode::Buffer);
        let resp = runner.run(&request, &mut logger);
        assert_eq!(resp.exit_code, -1);
        assert!(resp.error_message.contains("filesystem policy"));
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
        assert_eq!(resp.exit_code, -1);
        assert!(resp.error_message.contains("network policy"));
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
        assert_eq!(resp.exit_code, -1);
        assert!(resp.error_message.contains("network policy"));
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
        assert_eq!(resp.exit_code, -1);
        assert!(resp.error_message.contains("network policy"));
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
        assert_eq!(resp.exit_code, -1);
        assert!(resp.error_message.contains("workingDirectory"));
    }

    #[test]
    fn policy_allows_defaults() {
        // A request with all-default policies should pass validation and
        // fail later on path resolution (nanvixd not found), NOT on policy.
        let mut runner = NanVixScriptRunner::new();
        let request = CodexRequest::default();
        let mut logger = Logger::new(Mode::Buffer);
        let resp = runner.run(&request, &mut logger);
        assert_eq!(resp.exit_code, -1);
        assert!(
            !resp.error_message.contains("filesystem policy"),
            "default request should not trigger filesystem policy rejection"
        );
        assert!(
            !resp.error_message.contains("network policy"),
            "default request should not trigger network policy rejection"
        );
        assert!(
            !resp.error_message.contains("workingDirectory"),
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
                        true,
                    )),
                    builtin_test_server: false,
                },
                ..Default::default()
            },
            ..Default::default()
        };
        let mut logger = Logger::new(Mode::Buffer);
        let resp = runner.run(&request, &mut logger);
        assert_eq!(resp.exit_code, -1);
        assert!(resp.error_message.contains("network proxy"));
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
        let expected = "-S -B -c exec(__import__('sys').stdin.read());PYTHONHOME=/sysroot";
        let actual = format!(
            "-S -B -c exec(__import__('sys').stdin.read());PYTHONHOME={}",
            PYTHON_HOME
        );
        assert_eq!(actual, expected);
        assert!(!"exec(__import__('sys').stdin.read())".contains(' '));
    }
}
