// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `NanVixScriptRunner` -- executes code inside a NanVix micro-VM.
//!
//! The initial runtime is CPython 3.12 with a trimmed FAT32 stdlib filesystem.
//! The architecture supports additional runtimes (QuickJS, C, C++, Rust binaries).
//!
//! ## I/O model
//!
//! - **stdin**: set to `Stdio::null()` (NanVix guest does not read host stdin)
//! - **stdout**: inherited from parent via `Stdio::inherit()` (not captured)
//! - **stderr**: inherited from parent by default (kernel traces stream
//!   straight to the parent terminal). When the `MXC_NANVIX_TRACE` env var
//!   is truthy, stderr is piped and captured so it can be embedded in the
//!   wxc-exec log on non-zero exit.
//!
//! **Note for SDK consumers:** Use `usePty: false` (non-PTY mode) for the MicroVM
//! backend. PTY mode is not supported. Because stdout/stderr are inherited,
//! `ScriptResponse.standard_out` and `standard_err` are always empty strings.
//! Output is streamed directly to the parent's pipes.
//!
//! ## Diagnostics
//!
//! By default the runner sets `RUST_LOG=off` in nanvixd's environment, which
//! suppresses the per-run `%LOCALAPPDATA%\nanvix\logs\nanvixd_*.log` trace
//! file and noticeably reduces warm-start latency. Set `MXC_NANVIX_TRACE=1`
//! (or `true`/`yes`, case-insensitive) before invoking wxc-exec to let
//! nanvixd use its own `RUST_LOG` default and to capture nanvixd's stderr
//! for inclusion in the wxc-exec log.
//!
//! ## Exit codes
//!
//! `nanvixd` propagates the guest process exit code directly.
//!
//! ## Networking
//!
//! Host networking is **off by default** and is enabled per-run by passing
//! `-allow-host-networking` to `nanvixd`. The runner adds that flag when the
//! request sets `network.defaultPolicy = "allow"`, or when `allowedHosts` /
//! `blockedHosts` is present (forwarded as `-allow-host` / `-block-host`).
//! Network proxies are not supported and are rejected at validation time.
//!
//! Auto-discovery
//!
//! All required binaries (`nanvixd.exe`, `python3.initrd`, `nanvix_rootfs.img`)
//! are discovered next to the running executable. No configuration is needed.

use std::fmt::Write;
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use wxc_common::logger::Logger;
use wxc_common::models::{ExecutionRequest, NetworkPolicy, ScriptResponse};
use wxc_common::script_runner::ScriptRunner;

/// Multi-binary initrd (daemons + CPython) loaded by NanVix at warm start.
const INITRD_BINARY: &str = nanvix_common::INITRD_BINARY;
/// NanVix daemon binary launched by the host runner (platform-conditional).
const NANVIXD_BINARY: &str = nanvix_common::NANVIXD_BINARY;
/// Combined rootfs image (NanVix kernel userspace + CPython stdlib).
const RAMFS_IMAGE: &str = nanvix_common::RAMFS_IMAGE;
/// Pre-built VM state snapshot (CBOR) for warm start (Windows/WHP only).
#[cfg(target_os = "windows")]
const SNAPSHOT_CBOR: &str = nanvix_common::SNAPSHOT_CBOR;
/// Subdirectory holding snapshot files next to the exe (Windows/WHP only).
#[cfg(target_os = "windows")]
const SNAPSHOTS_DIR: &str = nanvix_common::SNAPSHOTS_SUBDIR;
/// Subdirectory holding kernel binary.
const BIN_DIR: &str = nanvix_common::BIN_SUBDIR;
/// Env var override for the NanVix snapshot home directory. Set this to
/// force a specific location; otherwise the runner uses a standard
/// OS-local data path or falls back to `<exe>/snapshots/`.
#[cfg(target_os = "windows")]
const NANVIX_HOME_ENV: &str = "NANVIX_HOME";
/// Env var that opts in to nanvixd's verbose tracing (and captured stderr).
/// When unset (the default), the runner forces `RUST_LOG=off` for nanvixd
/// and inherits stderr, which saves ~25–30 ms per warm execution by
/// avoiding nanvixd's per-run log file and the host-side stderr drain.
const NANVIX_TRACE_ENV: &str = "MXC_NANVIX_TRACE";
/// Final component of the default OS-local data path (Windows only).
#[cfg(target_os = "windows")]
const DEFAULT_HOME_LEAF: &str = "nanvix";
/// Boot grace period that is always enforced.
const BOOT_TIMEOUT_MS: u64 = 60_000;
/// Generic error exit code returned to host callers.
const ERROR_EXIT_CODE: i32 = -1;
/// Maximum age of orphaned staging dirs before cleanup (1 hour).
const ORPHAN_SWEEP_MAX_AGE_SECS: u64 = 3600;
const ERR_DENIED_PATHS: &str = concat!(
    "denied_paths is not meaningful for the microvm backend ",
    "-- the guest has no host filesystem visibility. ",
    "Only readwrite_paths and readonly_paths are supported",
);
const ERR_NETWORK_HOSTS: &str = concat!(
    "allowedHosts and blockedHosts are mutually exclusive for the NanVix backend -- ",
    "the guest egress filter is allow-XOR-block. Specify an allowlist (allowedHosts) ",
    "or a blocklist (blockedHosts), not both",
);
const ERR_HOSTS_UNRESOLVED: &str = concat!(
    "none of the specified allowedHosts/blockedHosts resolved to an IPv4 address -- ",
    "the NanVix guest filter is IPv4-only; use IPv4 literals/CIDR or hosts with A records",
);
const ERR_PROXY_POLICY: &str = "network proxy is not supported by the NanVix backend";
const ERR_WORKDIR: &str = "workingDirectory is not supported by the NanVix backend -- guest has its own filesystem namespace";

/// Maps a finished child's [`ExitStatus`] to a host-visible exit code.
///
/// On Unix, processes terminated by a signal have no exit code (`status.code()`
/// returns `None`); we surface them as the negated signal number (e.g. SIGKILL
/// → `-9`) so callers can distinguish them from normal exits and from the
/// generic [`ERROR_EXIT_CODE`] sentinel. On Windows, `status.code()` always
/// returns `Some(_)`.
fn exit_code_from_status(status: &std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return -signal;
        }
    }
    ERROR_EXIT_CODE
}

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
///
/// Inlined (rather than reusing `wxc_common::process_util::exe_dir`) because
/// `process_util` is gated to `target_os = "windows"`.
fn exe_dir() -> Result<PathBuf, NanVixError> {
    std::env::current_exe()
        .map_err(|e| NanVixError::Preflight(format!("cannot determine exe path: {}", e)))
        .and_then(|exe| {
            exe.parent()
                .map(|p| p.to_path_buf())
                .ok_or_else(|| NanVixError::Preflight("exe has no parent directory".to_string()))
        })
}

/// Returns `true` when [`NANVIX_TRACE_ENV`] is set to a truthy value
/// (`"1"`, `"true"`, or `"yes"`, case-insensitive). Any other value
/// (including unset, empty, or `"0"`/`"false"`/`"no"`) means trace is off.
fn nanvix_trace_enabled() -> bool {
    match std::env::var(NANVIX_TRACE_ENV) {
        Ok(v) => matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"),
        Err(_) => false,
    }
}

/// Watchdog thread: waits for timeout or cancellation, then terminates the process.
///
/// On Windows, `process_id_or_handle` is a duplicated process HANDLE (as usize).
/// On Linux, `process_id_or_handle` is the child PID (as usize).
fn watchdog_thread_fn(
    process_id_or_handle: usize,
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

    #[cfg(target_os = "windows")]
    {
        // Always close the duplicated handle to avoid leaks.
        let close_handle = |handle_raw: usize| {
            use windows::Win32::Foundation::{CloseHandle, HANDLE};
            let handle = HANDLE(handle_raw as *mut std::ffi::c_void);
            // SAFETY: `handle` was returned by `DuplicateHandle` in this
            // process and is closed exactly once by this watchdog thread.
            let _ = unsafe { CloseHandle(handle) };
        };

        if *cancelled {
            close_handle(process_id_or_handle);
            return;
        }

        timed_out.store(true, Ordering::SeqCst);

        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::Threading::TerminateProcess;

        let handle = HANDLE(process_id_or_handle as *mut std::ffi::c_void);
        // SAFETY: `handle` is a valid duplicated process handle owned by
        // this thread, and passing exit code 1 is valid for termination.
        let _ = unsafe { TerminateProcess(handle, 1) };
        close_handle(process_id_or_handle);
    }

    #[cfg(target_os = "linux")]
    {
        if *cancelled {
            return;
        }

        timed_out.store(true, Ordering::SeqCst);

        // Kill the child process by PID using SIGKILL.
        let pid = process_id_or_handle as i32;
        // SAFETY: sending SIGKILL to a known child PID is always valid.
        // If the process already exited, `kill()` returns ESRCH which we ignore.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
    }
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

/// Resolved paths for NanVix invocation.
#[derive(Debug)]
struct ResolvedPaths {
    nanvixd: PathBuf,
    ramfs: PathBuf,
    initrd: PathBuf,
    /// Directory holding the `bin/` subdir next to the exe.
    exe_dir: PathBuf,
    /// Snapshot home directory — used as cwd for nanvixd so it can locate
    /// `snapshots/kernel.vmem` relative to cwd (nanvixd constraint).
    snapshot_home: PathBuf,
}

impl NanVixScriptRunner {
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Resolve and validate all required paths next to the running executable.
    fn resolve_paths(&self) -> Result<ResolvedPaths, NanVixError> {
        let dir = exe_dir()?;

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

        let initrd = dir.join(INITRD_BINARY);
        if !initrd.exists() {
            return Err(NanVixError::Preflight(format!(
                "{} not found in {:?}",
                INITRD_BINARY, dir
            )));
        }

        // Preflight-check bin/ subdir contents (nanvixd loads `./bin/kernel.elf`
        // via `-bin-dir`; missing the file here yields a clearer error than
        // letting nanvixd fail at boot time).
        let bin_subdir = dir.join(BIN_DIR);
        for name in nanvix_common::BIN_SUBDIR_FILES {
            let path = bin_subdir.join(name);
            if !path.exists() {
                return Err(NanVixError::Preflight(format!(
                    "{}/{} not found in {:?}",
                    BIN_DIR, name, dir
                )));
            }
        }

        // Snapshot resolution — Windows only (WHP snapshots for warm start).
        // Linux uses cold boot via KVM every time.
        #[cfg(target_os = "windows")]
        let snapshot_home = {
            let home = Self::resolve_snapshot_home(&dir)?;
            // Warm start requires *all* snapshot files (kernel.vmem + kernel.whp.cbor);
            // a partial/corrupt set must trigger regeneration instead of a late failure
            // inside nanvixd.
            let snapshots_present = nanvix_common::SNAPSHOT_FILES
                .iter()
                .all(|name| home.join(SNAPSHOTS_DIR).join(name).exists());
            if !snapshots_present {
                // No (complete) snapshot yet — generate one via cold boot
                // (one-time cost, ~400–500 ms). Subsequent runs restore directly.
                Self::generate_snapshot(&dir, &home, &nanvixd, &ramfs, &initrd)?;
            }
            home
        };

        #[cfg(target_os = "linux")]
        let snapshot_home = dir.clone();

        Ok(ResolvedPaths {
            nanvixd,
            ramfs,
            initrd,
            exe_dir: dir,
            snapshot_home,
        })
    }

    /// Resolve the snapshot home directory (Windows only — WHP snapshots).
    ///
    /// Discovery chain (first match wins):
    /// 1. `$NANVIX_HOME` env var (if set and non-empty)
    /// 2. `<exe>` directory itself, when a complete set of pre-generated
    ///    snapshots already lives in `<exe>/snapshots/` (build-time output
    ///    or shipped artifacts) — using it avoids a redundant cold boot.
    /// 3. OS-local data path (`%LOCALAPPDATA%\nanvix` on Windows)
    /// 4. `<exe>` directory itself as a last-resort fallback (dev builds —
    ///    nanvixd will write snapshots into `<exe>/snapshots/`).
    #[cfg(target_os = "windows")]
    fn resolve_snapshot_home(exe_dir: &Path) -> Result<PathBuf, NanVixError> {
        // 1. Env var override.
        if let Some(val) = std::env::var_os(NANVIX_HOME_ENV) {
            let p = PathBuf::from(val);
            if !p.as_os_str().is_empty() {
                std::fs::create_dir_all(&p).map_err(|e| {
                    NanVixError::Preflight(format!(
                        "cannot create ${} directory {:?}: {}",
                        NANVIX_HOME_ENV, p, e
                    ))
                })?;
                return Ok(p);
            }
        }

        // 2. Prefer exe-side snapshots when they're already complete, so
        //    build-time-generated artifacts shipped next to wxc-exec are
        //    actually used instead of triggering a fresh cold boot in
        //    %LOCALAPPDATA%.
        let exe_snapshots = exe_dir.join(SNAPSHOTS_DIR);
        let exe_snapshots_complete = nanvix_common::SNAPSHOT_FILES
            .iter()
            .all(|name| exe_snapshots.join(name).exists());
        if exe_snapshots_complete {
            return Ok(exe_dir.to_path_buf());
        }

        // 3. OS-local data path.
        if let Some(home) = Self::default_home() {
            if home.exists() || std::fs::create_dir_all(&home).is_ok() {
                return Ok(home);
            }
        }

        // 4. Fallback: exe directory itself (nanvixd writes to <cwd>/snapshots/).
        Ok(exe_dir.to_path_buf())
    }

    /// Default OS-local snapshot home path.
    #[cfg(target_os = "windows")]
    fn default_home() -> Option<PathBuf> {
        std::env::var_os("LOCALAPPDATA").map(|d| PathBuf::from(d).join(DEFAULT_HOME_LEAF))
    }

    /// Generate a WHP snapshot via cold boot (one-time cost, Windows only).
    ///
    /// Delegates to `nanvix_common::generate_snapshot` which runs nanvixd with
    /// `-kernel-args snapshot` and cwd set to `snapshot_home`. nanvixd writes
    /// snapshot files to `<snapshot_home>/snapshots/` directly. Subsequent runs
    /// restore from the snapshot (~20 ms vs ~430 ms cold boot).
    #[cfg(target_os = "windows")]
    fn generate_snapshot(
        exe_dir: &Path,
        snapshot_home: &Path,
        nanvixd: &Path,
        ramfs: &Path,
        initrd: &Path,
    ) -> Result<(), NanVixError> {
        std::fs::create_dir_all(snapshot_home).map_err(|e| {
            NanVixError::Preflight(format!("failed to create snapshot home: {}", e))
        })?;

        eprintln!("nanvix: no snapshot found — generating via cold boot (one-time cost)...");

        let start = Instant::now();
        nanvix_common::generate_snapshot(
            snapshot_home,
            nanvixd,
            &exe_dir.join(BIN_DIR),
            ramfs,
            initrd,
        )
        .map_err(NanVixError::Preflight)?;

        eprintln!(
            "nanvix: snapshot generated in {:.0?} — subsequent runs will use warm start",
            start.elapsed()
        );
        Ok(())
    }

    /// Compute total timeout: boot grace + staging overhead + script timeout.
    /// When `script_timeout == 0` the caller intends "no limit", so the watchdog
    /// is disabled entirely (returns `u64::MAX`). Boot and staging time are
    /// unbounded in this case — this is by design for interactive/exploratory use.
    fn total_timeout_ms(script_timeout: u32, staging_overhead_ms: u64) -> u64 {
        if script_timeout == 0 {
            u64::MAX
        } else {
            BOOT_TIMEOUT_MS
                .saturating_add(staging_overhead_ms)
                .saturating_add(script_timeout as u64)
        }
    }

    /// Returns whether the request opts in to host networking.
    ///
    /// Host networking is enabled when `network.defaultPolicy = "allow"` OR when
    /// a per-host allow/block list is present (a list always implies networking,
    /// regardless of `defaultPolicy`). When enabled, the runner passes
    /// `-allow-host-networking` to nanvixd; per-host lists are additionally
    /// forwarded as `-allow-host`/`-block-host` (see [`Self::spawn_nanvixd`]).
    fn host_networking_enabled(request: &ExecutionRequest) -> bool {
        request.policy.default_network_policy == NetworkPolicy::Allow
            || !request.policy.allowed_hosts.is_empty()
            || !request.policy.blocked_hosts.is_empty()
    }

    /// Resolves a host entry list into IPv4/CIDR literals for nanvixd's
    /// `-allow-host`/`-block-host` flags.
    ///
    /// - `a.b.c.d` and `a.b.c.d/n` literals pass through unchanged.
    /// - Hostnames resolve to their IPv4 (A-record) addresses; AAAA results are
    ///   dropped because the guest filter is IPv4-only.
    /// - Entries that fail to parse or resolve contribute nothing.
    ///
    /// Mirrors `lxc::network_iptables::resolve_host` so the two backends agree
    /// on resolution semantics.
    fn resolve_hosts(hosts: &[String]) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for host in hosts {
            let entry = host.trim();
            if entry.is_empty() {
                continue;
            }
            // CIDR literal: pass through only when the address is IPv4 and the
            // prefix is in range. nanvixd parses CIDR directly.
            if let Some((addr, prefix)) = entry.split_once('/') {
                let addr_ok = addr.trim().parse::<std::net::Ipv4Addr>().is_ok();
                let prefix_ok = prefix
                    .trim()
                    .parse::<u8>()
                    .map(|p| p <= 32)
                    .unwrap_or(false);
                if addr_ok && prefix_ok {
                    out.push(entry.to_string());
                }
                continue;
            }
            // Bare IP literal: keep IPv4, drop IPv6.
            if let Ok(addr) = entry.parse::<std::net::IpAddr>() {
                if addr.is_ipv4() {
                    out.push(entry.to_string());
                }
                continue;
            }
            // Hostname: resolve to IPv4 A records.
            if let Ok(addrs) = format!("{}:0", entry).to_socket_addrs() {
                for ip in addrs.map(|a| a.ip()).filter(|ip| ip.is_ipv4()) {
                    out.push(ip.to_string());
                }
            }
        }
        out
    }

    /// Resolves the request's allow/block host lists, failing closed.
    ///
    /// Returns `(resolved_allow, resolved_block)`. At most one list is non-empty
    /// (the mutual-exclusion check in [`Self::validate_policies`] runs first). If
    /// a user-supplied list resolves to nothing — e.g. an allowlist of names
    /// that have no A records — this returns an error rather than silently
    /// emitting `-allow-host-networking` with no filter (which nanvixd would
    /// treat as allow-all), so an allowlist never fails open.
    fn resolve_host_lists(
        request: &ExecutionRequest,
    ) -> Result<(Vec<String>, Vec<String>), NanVixError> {
        let allow = Self::resolve_hosts(&request.policy.allowed_hosts);
        if !request.policy.allowed_hosts.is_empty() && allow.is_empty() {
            return Err(NanVixError::Preflight(ERR_HOSTS_UNRESOLVED.to_string()));
        }
        let block = Self::resolve_hosts(&request.policy.blocked_hosts);
        if !request.policy.blocked_hosts.is_empty() && block.is_empty() {
            return Err(NanVixError::Preflight(ERR_HOSTS_UNRESOLVED.to_string()));
        }
        Ok((allow, block))
    }

    fn validate_policies(request: &ExecutionRequest) -> Result<(), NanVixError> {
        // denied_paths is explicitly rejected — microvm has no host visibility.
        if !request.policy.denied_paths.is_empty() {
            return Err(NanVixError::Preflight(ERR_DENIED_PATHS.to_string()));
        }
        // Per-host filtering is supported (forwarded to nanvixd as
        // -allow-host/-block-host). The guest egress filter is allow-XOR-block,
        // so the two lists are mutually exclusive; defaultPolicy is ignored when
        // either list is present.
        if !request.policy.allowed_hosts.is_empty() && !request.policy.blocked_hosts.is_empty() {
            return Err(NanVixError::Preflight(ERR_NETWORK_HOSTS.to_string()));
        }
        if request.policy.network_proxy.is_enabled() {
            return Err(NanVixError::Preflight(ERR_PROXY_POLICY.to_string()));
        }
        if !request.working_directory.is_empty() {
            return Err(NanVixError::Preflight(ERR_WORKDIR.to_string()));
        }

        Ok(())
    }

    fn spawn_nanvixd(
        paths: &ResolvedPaths,
        staging_dir: &Path,
        host_networking: bool,
        allow_hosts: &[String],
        block_hosts: &[String],
    ) -> Result<std::process::Child, NanVixError> {
        let trace = nanvix_trace_enabled();
        // Default: silence nanvixd and inherit stderr so kernel traces (if
        // any) stream straight to the parent terminal without a per-run
        // host-side drain. Diagnostic mode pipes stderr so the runner can
        // attach it to the wxc-exec log on failure.
        let stderr = if trace {
            Stdio::piped()
        } else {
            Stdio::inherit()
        };

        let mut cmd = Command::new(&paths.nanvixd);

        // Host networking is opt-in. When enabled, attach the host network
        // backend; nanvixd parses this flag regardless of argument order, so
        // it is added up front for both the Windows (snapshot) and Linux
        // (cold-boot) invocations below. Verified to work on warm-start
        // snapshot restore as well as cold boot.
        if host_networking {
            cmd.arg("-allow-host-networking");
        }

        // Per-host egress filtering. The two lists are mutually exclusive
        // (validated upstream), so at most one of these loops emits flags.
        // nanvixd requires `-allow-host-networking` for these to take effect,
        // which is guaranteed because a non-empty list forces host_networking
        // on (see `host_networking_enabled`). The guest daemon auto-exempts the
        // DNS port in allowlist mode, so no resolver IPs are added here.
        for host in allow_hosts {
            cmd.arg("-allow-host").arg(host);
        }
        for host in block_hosts {
            cmd.arg("-block-host").arg(host);
        }

        #[cfg(target_os = "windows")]
        {
            // nanvixd loads kernel.vmem from <cwd>/snapshots/ so cwd must be
            // the snapshot home. All other paths are passed as absolute.
            //   nanvixd.exe [-allow-host-networking] -snapshot snapshots/kernel.whp.cbor
            //              -bin-dir <exe>/bin -ramfs <img> -mount <staging> -- python3.initrd
            let snapshot_rel = Path::new(SNAPSHOTS_DIR).join(SNAPSHOT_CBOR);
            cmd.current_dir(&paths.snapshot_home)
                .arg("-snapshot")
                .arg(&snapshot_rel)
                .arg("-bin-dir")
                .arg(paths.exe_dir.join(BIN_DIR))
                .arg("-ramfs")
                .arg(&paths.ramfs)
                .arg("-mount")
                .arg(staging_dir)
                .arg("--")
                .arg(&paths.initrd);
        }

        #[cfg(target_os = "linux")]
        {
            // Linux invocation (cold boot via KVM):
            //   nanvixd.elf [-allow-host-networking] -ramfs <rootfs.img> -mount <staging_dir> -- python3.initrd
            cmd.current_dir(&paths.exe_dir)
                .arg("-ramfs")
                .arg(&paths.ramfs)
                .arg("-mount")
                .arg(staging_dir)
                .arg("--")
                .arg(&paths.initrd);
        }

        cmd.stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(stderr);
        if !trace {
            // Suppress nanvixd's env_logger output and per-run log file.
            cmd.env("RUST_LOG", "off");
        }
        cmd.spawn().map_err(|e| {
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

        #[cfg(target_os = "windows")]
        {
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
            let process_id_or_handle = dup_handle.0 as usize;

            Some(thread::spawn(move || {
                watchdog_thread_fn(process_id_or_handle, duration, cancel_pair, timed_out);
            }))
        }

        #[cfg(target_os = "linux")]
        {
            // On Linux, use the child PID directly for kill-based termination.
            let pid = child.id() as usize;

            Some(thread::spawn(move || {
                watchdog_thread_fn(pid, duration, cancel_pair, timed_out);
            }))
        }
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

    fn log_resolved_paths(logger: &mut Logger, paths: &ResolvedPaths) {
        let _ = writeln!(logger, "NanVix: nanvixd={:?}", paths.nanvixd);
        let _ = writeln!(logger, "NanVix: ramfs={:?}", paths.ramfs);
        let _ = writeln!(logger, "NanVix: initrd={:?}", paths.initrd);
        let _ = writeln!(logger, "NanVix: snapshot_home={:?}", paths.snapshot_home);
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
        // Drain stderr concurrently with `wait()` so a verbose child cannot
        // block on a full pipe buffer. We retain only the last
        // [`nanvix_common::STDERR_TAIL_BYTES`] bytes so an untrusted guest
        // emitting unbounded stderr cannot cause host memory growth
        // (availability / DoS hardening). In the default (non-trace) mode
        // stderr is inherited and `child.stderr` is `None`, so the join
        // returns the empty string immediately.
        let stderr_handle = child
            .stderr
            .take()
            .map(|s| thread::spawn(move || nanvix_common::drain_stderr_tail(s)));

        let exit_status = child.wait();

        let stderr_output = stderr_handle
            .and_then(|h| h.join().ok())
            .map(|(bytes, truncated)| nanvix_common::format_stderr_tail(&bytes, truncated))
            .unwrap_or_default();

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
                let exit_code = exit_code_from_status(&status);
                let _ = writeln!(logger, "NanVix: process exited with code {}", exit_code);
                if exit_code != 0 && !stderr_output.is_empty() {
                    let _ = writeln!(logger, "NanVix stderr:\n{}", stderr_output);
                }
                ScriptResponse {
                    exit_code,
                    ..Default::default()
                }
            }
            Err(e) => {
                if !stderr_output.is_empty() {
                    let _ = writeln!(logger, "NanVix stderr:\n{}", stderr_output);
                }
                let err =
                    NanVixError::Runtime(format!("failed to wait for {}: {}", NANVIXD_BINARY, e));
                let _ = writeln!(logger, "{}", err);
                err.to_response()
            }
        }
    }
    /// Returns `true` when filesystem copyback should run.
    /// Copyback runs on any normal process exit (including non-zero exit codes).
    /// It is skipped for preflight, spawn, runtime, and timeout errors, and for
    /// OS crashes (negative exit codes from NTSTATUS values).
    fn should_copy_back(response: &ScriptResponse) -> bool {
        response.error_message.is_empty() && response.exit_code >= 0
    }
}

impl ScriptRunner for NanVixScriptRunner {
    fn validate_runner(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        Self::validate_policies(request).map_err(|e| e.to_response())
    }

    fn execute(&mut self, request: &ExecutionRequest, logger: &mut Logger) -> ScriptResponse {
        let paths = match self.resolve_paths() {
            Ok(p) => p,
            Err(e) => return e.to_response(),
        };

        // Build staging directory with script and filesystem policy paths.
        let staging_root = std::env::temp_dir().join("mxc-microvm");
        // Sweep orphaned staging dirs from previous crashed runs (older than 1 hour).
        wxc_common::microvm_staging::sweep_orphaned_staging_dirs(
            &staging_root,
            std::time::Duration::from_secs(ORPHAN_SWEEP_MAX_AGE_SECS),
        );
        let mut staging = match wxc_common::microvm_staging::StagingDir::new(
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

        Self::log_resolved_paths(logger, &paths);
        let _ = writeln!(logger, "NanVix: staging_dir={:?}", staging.path());

        let host_networking = Self::host_networking_enabled(request);
        if host_networking {
            let _ = writeln!(logger, "NanVix: host networking enabled");
        }
        let (allow_hosts, block_hosts) = match Self::resolve_host_lists(request) {
            Ok(v) => v,
            Err(e) => {
                let _ = writeln!(logger, "{}", e);
                return e.to_response();
            }
        };
        if !allow_hosts.is_empty() {
            let _ = writeln!(logger, "NanVix: egress allowlist={:?}", allow_hosts);
        }
        if !block_hosts.is_empty() {
            let _ = writeln!(logger, "NanVix: egress blocklist={:?}", block_hosts);
        }
        let mut child = match Self::spawn_nanvixd(
            &paths,
            staging.path(),
            host_networking,
            &allow_hosts,
            &block_hosts,
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

        let response = Self::wait_and_respond(
            &mut child,
            watchdog,
            &cancel_pair,
            timed_out.as_ref(),
            timeout_ms,
            request.script_timeout,
            logger,
        );

        // Copy back RW filesystem changes on normal process exit.
        if Self::should_copy_back(&response) {
            if let Err(e) = staging.copy_back_to_host() {
                let preserved = staging
                    .preserved_path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default();
                let err = NanVixError::Runtime(format!(
                    "failed to copy back microvm filesystem changes: {}. \
                     Staged files preserved at: {}",
                    e, preserved
                ));
                let _ = writeln!(logger, "{}", err);
                return err.to_response();
            }
        }

        response
        // staging is dropped here → cleanup
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::logger::{Logger, Mode};
    use wxc_common::models::{ContainerPolicy, NetworkPolicy};

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
        // Validation passes; the runner fails later on path resolution.
        let request = ExecutionRequest {
            script_code: "echo test".to_string(),
            policy: ContainerPolicy {
                readwrite_paths: vec!["/tmp".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let result = NanVixScriptRunner::validate_policies(&request);
        assert!(result.is_ok(), "readwrite_paths accepted");
    }

    #[test]
    fn policy_accepts_readonly_paths() {
        let request = ExecutionRequest {
            script_code: "echo test".to_string(),
            policy: ContainerPolicy {
                readonly_paths: vec!["/data".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let result = NanVixScriptRunner::validate_policies(&request);
        assert!(result.is_ok(), "readonly_paths accepted");
    }

    #[test]
    fn policy_rejects_denied_paths() {
        let request = ExecutionRequest {
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
    fn policy_accepts_allowlist_only() {
        // A bare allowlist is now supported (forwarded as -allow-host).
        let request = ExecutionRequest {
            script_code: "echo test".to_string(),
            policy: ContainerPolicy {
                allowed_hosts: vec!["93.184.216.34".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(
            NanVixScriptRunner::validate_policies(&request).is_ok(),
            "a bare allowlist should pass validation"
        );
        // A list implies host networking regardless of defaultPolicy (Block).
        assert!(NanVixScriptRunner::host_networking_enabled(&request));
    }

    #[test]
    fn policy_accepts_blocklist_only() {
        // A bare blocklist is now supported (forwarded as -block-host).
        let request = ExecutionRequest {
            script_code: "echo test".to_string(),
            policy: ContainerPolicy {
                blocked_hosts: vec!["93.184.216.34".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(
            NanVixScriptRunner::validate_policies(&request).is_ok(),
            "a bare blocklist should pass validation"
        );
        assert!(NanVixScriptRunner::host_networking_enabled(&request));
    }

    #[test]
    fn policy_rejects_both_host_lists() {
        // allow + block are mutually exclusive (the guest filter is allow-XOR-block).
        let request = ExecutionRequest {
            script_code: "echo test".to_string(),
            policy: ContainerPolicy {
                allowed_hosts: vec!["10.0.0.1".to_string()],
                blocked_hosts: vec!["10.0.0.2".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = NanVixScriptRunner::validate_policies(&request).unwrap_err();
        assert!(
            err.to_string().contains(ERR_NETWORK_HOSTS),
            "both lists should be rejected, got: {}",
            err
        );
    }

    // -- Host resolution / decision-matrix tests --------------------------------

    #[test]
    fn resolve_hosts_passes_ipv4_and_cidr_literals() {
        let hosts = vec![
            "1.2.3.4".to_string(),
            "10.0.0.0/8".to_string(),
            "192.168.1.1/32".to_string(),
        ];
        let resolved = NanVixScriptRunner::resolve_hosts(&hosts);
        assert_eq!(resolved, vec!["1.2.3.4", "10.0.0.0/8", "192.168.1.1/32"]);
    }

    #[test]
    fn resolve_hosts_drops_ipv6_and_bad_entries() {
        let hosts = vec![
            "::1".to_string(),           // IPv6 literal -> dropped
            "2001:db8::/32".to_string(), // IPv6 CIDR -> dropped (addr not IPv4)
            "1.2.3.4/33".to_string(),    // out-of-range prefix -> dropped
            "  ".to_string(),            // blank -> skipped
            "5.6.7.8".to_string(),       // valid -> kept
        ];
        let resolved = NanVixScriptRunner::resolve_hosts(&hosts);
        assert_eq!(resolved, vec!["5.6.7.8"]);
    }

    #[test]
    fn resolve_host_lists_returns_resolved_allow() {
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                allowed_hosts: vec!["1.1.1.1".to_string(), "8.8.8.8/32".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let (allow, block) = NanVixScriptRunner::resolve_host_lists(&request).unwrap();
        assert_eq!(allow, vec!["1.1.1.1", "8.8.8.8/32"]);
        assert!(block.is_empty());
    }

    #[test]
    fn resolve_host_lists_fails_closed_when_allowlist_unresolvable() {
        // A non-empty allowlist that resolves to nothing must error rather than
        // silently fall through to allow-all.
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                // IPv6-only literal resolves to no IPv4 entry.
                allowed_hosts: vec!["::1".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = NanVixScriptRunner::resolve_host_lists(&request).unwrap_err();
        assert!(
            err.to_string().contains(ERR_HOSTS_UNRESOLVED),
            "unresolvable allowlist should fail closed, got: {}",
            err
        );
    }

    #[test]
    fn default_block_no_lists_disables_host_networking() {
        // The default posture (block, no lists) keeps networking off.
        let request = ExecutionRequest::default();
        assert!(!NanVixScriptRunner::host_networking_enabled(&request));
        let (allow, block) = NanVixScriptRunner::resolve_host_lists(&request).unwrap();
        assert!(allow.is_empty() && block.is_empty());
    }

    #[test]
    fn allow_policy_enables_host_networking() {
        // `network.defaultPolicy = "allow"` maps to host networking and must
        // pass validation (the run later fails on missing nanvixd binaries,
        // not on policy). Per-host filtering is absent, so it is accepted.
        let request = ExecutionRequest {
            script_code: "echo test".to_string(),
            policy: ContainerPolicy {
                default_network_policy: NetworkPolicy::Allow,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(NanVixScriptRunner::host_networking_enabled(&request));
        assert!(
            NanVixScriptRunner::validate_policies(&request).is_ok(),
            "allow posture without per-host filtering should pass validation"
        );

        let mut runner = NanVixScriptRunner::new();
        let mut logger = Logger::new(Mode::Buffer);
        let resp = runner.run(&request, &mut logger);
        assert_eq!(resp.exit_code, ERROR_EXIT_CODE);
        assert!(
            !resp.error_message.contains(ERR_NETWORK_HOSTS),
            "allow posture must not trigger a network policy rejection, got: {}",
            resp.error_message
        );
    }

    #[test]
    fn policy_rejects_working_directory() {
        let mut runner = NanVixScriptRunner::new();
        let request = ExecutionRequest {
            script_code: "echo test".to_string(),
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
        // NanVix accepts a default (deny-by-default) policy. With no host
        // networking requested, the run later fails on missing nanvixd
        // binaries, not on policy.
        let mut runner = NanVixScriptRunner::new();
        let request = ExecutionRequest {
            script_code: "echo test".to_string(),
            ..Default::default()
        };
        assert!(!NanVixScriptRunner::host_networking_enabled(&request));
        let mut logger = Logger::new(Mode::Buffer);
        let resp = runner.run(&request, &mut logger);
        assert_eq!(resp.exit_code, ERROR_EXIT_CODE);
        assert!(
            !resp.error_message.contains(ERR_NETWORK_HOSTS),
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
        let request = ExecutionRequest {
            script_code: "echo test".to_string(),
            policy: ContainerPolicy {
                network_proxy: wxc_common::models::ProxyConfig {
                    address: Some(wxc_common::models::ProxyAddress::new(
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
    fn resolve_paths_checks_for_snapshot() {
        let runner = NanVixScriptRunner::new();
        let err = runner.resolve_paths().unwrap_err();
        // Should fail on missing binaries (not on snapshot specifically,
        // since nanvixd.exe is checked first).
        assert!(err.to_string().contains("not found"), "got: {}", err);
    }

    // -- Copyback decision tests ------------------------------------------------

    #[test]
    fn copyback_allowed_for_zero_exit() {
        let response = ScriptResponse {
            exit_code: 0,
            ..Default::default()
        };
        assert!(NanVixScriptRunner::should_copy_back(&response));
    }

    #[test]
    fn copyback_allowed_for_nonzero_normal_exit() {
        let response = ScriptResponse {
            exit_code: 42,
            ..Default::default()
        };
        assert!(NanVixScriptRunner::should_copy_back(&response));
    }

    #[test]
    fn copyback_skipped_for_runner_error() {
        let response = ScriptResponse {
            exit_code: ERROR_EXIT_CODE,
            error_message: "NanVix execution timed out after 90000ms".to_string(),
            ..Default::default()
        };
        assert!(!NanVixScriptRunner::should_copy_back(&response));
    }

    #[test]
    fn copyback_skipped_for_os_crash() {
        // STATUS_ACCESS_VIOLATION = 0xC0000005 → interpreted as i32 = -1073741819.
        // This is a nanvixd OS crash — copyback must be suppressed.
        let response = ScriptResponse {
            exit_code: -1073741819_i32,
            error_message: String::new(),
            ..Default::default()
        };
        assert!(
            !NanVixScriptRunner::should_copy_back(&response),
            "copyback must be skipped for NTSTATUS crash exit codes"
        );
    }

    #[test]
    fn copyback_skipped_for_signal_killed() {
        // On Linux, SIGKILL results in exit code -9 (negative signal number).
        let response = ScriptResponse {
            exit_code: -9,
            error_message: String::new(),
            ..Default::default()
        };
        assert!(
            !NanVixScriptRunner::should_copy_back(&response),
            "copyback must be skipped for signal-killed processes"
        );
    }

    // -- Platform-specific constant tests ---------------------------------------

    #[test]
    fn nanvixd_binary_matches_platform() {
        #[cfg(target_os = "linux")]
        assert_eq!(NANVIXD_BINARY, "nanvixd.elf");
        #[cfg(target_os = "windows")]
        assert_eq!(NANVIXD_BINARY, "nanvixd.exe");
    }

    #[test]
    fn total_timeout_infinite_when_zero() {
        assert_eq!(NanVixScriptRunner::total_timeout_ms(0, 0), u64::MAX);
        assert_eq!(NanVixScriptRunner::total_timeout_ms(0, 500), u64::MAX);
    }

    #[test]
    fn total_timeout_saturates_on_overflow() {
        // With values that would cause u64 overflow, should saturate at u64::MAX.
        let result = NanVixScriptRunner::total_timeout_ms(u32::MAX, u64::MAX - 1);
        assert_eq!(result, u64::MAX);
    }

    // -- Watchdog timeout state tests ------------------------------------------

    #[test]
    fn watchdog_state_no_thread_when_infinite_timeout() {
        // When timeout is u64::MAX, start_watchdog should return None.
        // We can't test this directly without a real child process, but we can
        // verify the total_timeout_ms sentinel logic.
        let timeout = NanVixScriptRunner::total_timeout_ms(0, 0);
        assert_eq!(
            timeout,
            u64::MAX,
            "zero script_timeout should yield infinite"
        );
    }

    // -- NanVixError display tests ---------------------------------------------

    #[test]
    fn error_display_preflight() {
        let err = NanVixError::Preflight("missing binary".to_string());
        assert!(err.to_string().contains("preflight"));
        assert!(err.to_string().contains("missing binary"));
    }

    #[test]
    fn error_display_platform() {
        let err = NanVixError::Platform("spawn failed".to_string());
        assert!(err.to_string().contains("platform"));
        assert!(err.to_string().contains("spawn failed"));
    }

    #[test]
    fn error_display_runtime() {
        let err = NanVixError::Runtime("VM crashed".to_string());
        assert!(err.to_string().contains("runtime"));
        assert!(err.to_string().contains("VM crashed"));
    }

    #[test]
    fn error_display_timeout() {
        let err = NanVixError::Timeout {
            script_timeout_ms: 5000,
            total_ms: 65000,
        };
        let msg = err.to_string();
        assert!(msg.contains("timed out"));
        assert!(msg.contains("65000"));
        assert!(msg.contains("5000"));
    }

    #[test]
    fn error_to_response_has_error_exit_code() {
        let err = NanVixError::Preflight("test".to_string());
        let resp = err.to_response();
        assert_eq!(resp.exit_code, ERROR_EXIT_CODE);
        assert!(!resp.error_message.is_empty());
    }
}
