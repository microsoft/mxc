// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Rust port of the permissive learning mode (PLM) PowerShell scripts.
//!
//! Subcommands:
//! - `start`: cancel any active WPR trace and start a new one using
//!   `plm.wprp!AccessFailureProfile`.
//! - `stop`: stop the trace and write `trace.etl` into a log directory.
//! - `log`: interactive — Enter to start, Enter to stop.
//!
//! The functional binary wraps WPR / ETW / EventLog APIs that have no
//! cross-platform equivalent and is therefore Windows-only. On
//! Linux/macOS we still compile a stub binary so the crate sits inside
//! the workspace `default-members` list (one members list to maintain,
//! cross-platform CI catches drift); invoking it prints a message and
//! exits non-zero.

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("plm is Windows-only; this stub binary does nothing on non-Windows targets.");
    std::process::exit(1);
}

#[cfg(target_os = "windows")]
use anyhow::{Context, Result};
#[cfg(target_os = "windows")]
use clap::{Parser, Subcommand};
#[cfg(target_os = "windows")]
use std::path::PathBuf;
#[cfg(target_os = "windows")]
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
#[cfg(target_os = "windows")]
use std::time::Duration;

#[cfg(target_os = "windows")]
use plm::coordination::{singleton_bypass_requested, wait_until_cleared, PLM_LOG_START_IN_FLIGHT};
#[cfg(target_os = "windows")]
use plm::{log, profile_gen, start, stop};

/// Raw `HANDLE` value of the named-mutex singleton acquired by
/// `acquire_singleton_if_needed` (zero when unheld). Stashed in a
/// static so the console-control handler can release the host-wide
/// `Global\Mxc_Plm_Audit` guard before `ExitProcess` runs and skips
/// Rust destructors, preventing the retry-on-conflict path in
/// `start_plm_trace` from `wpr -cancel`ing a peer PLM trace.
#[cfg(target_os = "windows")]
static PLM_SINGLETON_HANDLE: AtomicIsize = AtomicIsize::new(0);

/// Backing storage for `AcquiredSingleton::mark_trace_active` /
/// `clear_trace_active` / `cancel_active_trace`.
///
/// Kept as a process-wide `static` (not an owned field of
/// `AcquiredSingleton`) for one narrow reason: the Windows console-
/// control handler `plm_ctrl_handler` is an OS-owned `extern "system"`
/// callback with no `self` / captured environment. It can only reach
/// state via process globals. Access from the `main` thread, however,
/// is gated behind `&AcquiredSingleton` methods so it is a
/// compile-time invariant that the trace-active flag can only be
/// mutated while we hold the host-wide singleton mutex — you can't
/// call `mark_trace_active()` in a free function without first
/// producing an `AcquiredSingleton`.
#[cfg(target_os = "windows")]
static PLM_TRACE_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Release the named-mutex singleton if held. Idempotent.
#[cfg(target_os = "windows")]
fn release_plm_singleton() {
    plm::coordination::singleton::release(&PLM_SINGLETON_HANDLE);
}

/// Cancel any active PLM trace from a context that can't produce an
/// `&AcquiredSingleton` — currently just the ctrl handler, which
/// runs in an OS-owned callback with no captured environment. All
/// non-signal-context callers should use
/// `AcquiredSingleton::cancel_active_trace(&self)` instead so the
/// call site proves the singleton is held.
#[cfg(target_os = "windows")]
fn cancel_active_plm_trace_from_signal() {
    if PLM_TRACE_ACTIVE.swap(false, Ordering::SeqCst) {
        // Use the kernel-published System32 path.
        let _ = plm::wpr_path::wpr_command()
            .arg("-cancel")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

/// RAII wrapper for the host-wide `Global\Mxc_Plm_Audit` singleton.
/// Ownership of the singleton is the precondition for touching the
/// trace-active flag — the methods below take `&self` so a live
/// `AcquiredSingleton` must exist at every call site.
#[cfg(target_os = "windows")]
struct AcquiredSingleton;

#[cfg(target_os = "windows")]
impl AcquiredSingleton {
    /// Mark the kernel ETW session as live; called immediately after
    /// `start::start_plm_trace` succeeds.
    fn mark_trace_active(&self) {
        PLM_TRACE_ACTIVE.store(true, Ordering::SeqCst);
    }

    /// Clear the trace-active flag; called after `wpr -stop` drains
    /// the kernel session so a subsequent Ctrl+C doesn't issue a
    /// stale `wpr -cancel`.
    fn clear_trace_active(&self) {
        PLM_TRACE_ACTIVE.store(false, Ordering::SeqCst);
    }

    /// Issue `wpr -cancel` iff a trace was marked active by this
    /// process. Idempotent. Non-signal-context callers use this
    /// method; the ctrl handler uses `cancel_active_plm_trace_from_signal`.
    fn cancel_active_trace(&self) {
        cancel_active_plm_trace_from_signal();
    }
}

#[cfg(target_os = "windows")]
impl Drop for AcquiredSingleton {
    fn drop(&mut self) {
        // Cancel any leftover trace before releasing the singleton so
        // a caller that returns an error mid-flow can't leak the
        // kernel session past our exit.
        self.cancel_active_trace();
        release_plm_singleton();
    }
}

#[cfg(target_os = "windows")]
fn acquire_singleton_if_needed() -> Result<Option<AcquiredSingleton>> {
    if singleton_bypass_requested() {
        // Outer process holds the mutex for the whole audit window;
        // re-acquiring here would deadlock.
        return Ok(None);
    }
    use plm::coordination::singleton::{try_acquire, AcquireError};
    match try_acquire(&PLM_SINGLETON_HANDLE) {
        Ok(()) => Ok(Some(AcquiredSingleton)),
        Err(AcquireError::AlreadyHeld) => anyhow::bail!(
            "another PLM trace is already in progress (Global\\Mxc_Plm_Audit held); \
             refusing to start a second concurrent trace — only one NT Kernel Logger \
             session can exist per host"
        ),
        Err(AcquireError::CreateFailed(e)) => {
            Err(e).context("CreateMutexW failed for Global\\Mxc_Plm_Audit")
        }
    }
}

/// Windows console-control handler. Fires on Ctrl+C, Ctrl+Break,
/// console close, logoff, and shutdown. Tears down any in-flight WPR
/// session and releases the singleton mutex before the default handler
/// calls `ExitProcess` (which skips Rust destructors).
///
/// We poll `PLM_LOG_START_IN_FLIGHT` via `wait_until_cleared` instead
/// of a proper wait-object (Event / condvar) for two reasons:
///  1. `wpr -start`'s underlying kernel session engagement isn't
///     signalled by any OS-published handle we can wait on; the only
///     transition we can observe is the child `wpr.exe` process
///     returning. Wrapping a Rust `Event` around that in the ctrl
///     handler would still require polling / a spawn-time helper
///     thread purely to `SetEvent`.
///  2. The polling interval (50ms) is bounded above by
///     `CTRL_HANDLER_DRAIN_TIMEOUT` (2s) which is well under
///     Windows's ~5s ctrl-handler kill budget, so at most ~40 polls
///     fire — negligible CPU, zero cost on the happy path (the flag
///     is normally already clear when the handler runs).
#[cfg(target_os = "windows")]
unsafe extern "system" fn plm_ctrl_handler(_ctrl_type: u32) -> windows::core::BOOL {
    // if `plm log`'s `wpr -start` is
    // still in flight when Ctrl+C arrives, briefly wait for it to
    // settle before deciding whether to issue `wpr -cancel`. Without
    // this wait, a cancel that races a not-yet-engaged session is a
    // no-op and the kernel session leaks past `plm.exe` exit.
    //
    // timeout sourced from the
    // shared `plm::coordination::CTRL_HANDLER_DRAIN_TIMEOUT` so
    // `plm.exe` and `wxc-exec`'s `dacl_ctrl_handler` cannot drift
    // apart. The const docs explain the ~5s OS kill budget rationale.
    // Polls via the shared `wait_until_cleared` helper so the same
    // loop is tested in one place — see `plm::coordination::tests`.
    let _ = wait_until_cleared(
        &PLM_LOG_START_IN_FLIGHT,
        plm::coordination::CTRL_HANDLER_DRAIN_TIMEOUT,
        Duration::from_millis(50),
    );
    cancel_active_plm_trace_from_signal();
    release_plm_singleton();
    // Return FALSE so the default handler still runs and terminates
    // the process. Matches `wxc-exec`'s dacl_ctrl_handler pattern.
    windows::core::BOOL(0)
}

#[cfg(target_os = "windows")]
fn install_ctrl_handler() {
    use windows::Win32::System::Console::SetConsoleCtrlHandler;
    // SAFETY: handler has the correct ABI; Add=TRUE merely appends to
    // the OS handler chain.
    let _ = unsafe { SetConsoleCtrlHandler(Some(plm_ctrl_handler), true) };
}

#[derive(Parser, Debug)]
#[command(
    name = "plm",
    about = "Rust port of the permissive learning mode PowerShell scripts.",
    version
)]
#[cfg(target_os = "windows")]
struct Cli {
    /// Internal handshake flag used by `wxc-exec --audit` to hand off
    /// a directory the elevated `plm.exe` writes its stdout/stderr
    /// into. See `redirect_stdio_from_argv`. Hidden from `--help`;
    /// not part of the user-facing CLI. Declared here so clap accepts
    /// (and ignores) the flag during subcommand parsing.
    #[arg(long = "wxc-capture-dir", hide = true)]
    _wxc_capture_dir: Option<std::path::PathBuf>,

    /// Internal handshake flag used by `wxc-exec --audit` to tell us
    /// it already holds the `Global\Mxc_Plm_Audit` singleton so we
    /// skip acquisition and avoid a deadlock. Companion of
    /// `--wxc-capture-dir`; both migrated off the previous env-var
    /// mechanism because `ShellExecuteExW` + `runas` does not
    /// propagate environment across the elevation boundary.
    #[arg(long = "wxc-singleton-held-by-parent", hide = true)]
    wxc_singleton_held_by_parent: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
#[cfg(target_os = "windows")]
enum Cmd {
    /// Start a new WPR trace using plm.wprp!AccessFailureProfile.
    Start {
        /// Override path to plm.wprp. Defaults to <exe dir>\plm.wprp.
        #[arg(long)]
        wprp: Option<PathBuf>,
    },
    /// Stop the trace and write `trace.etl` into a log directory.
    Stop {
        /// Directory for trace.etl, copied input config, and Adjusted_*.json.
        #[arg(long)]
        log_dir: Option<PathBuf>,
        /// Path treated as the application binary's location. Defaults
        /// to the directory containing the plm executable.
        #[arg(long)]
        bin_path: Option<PathBuf>,
        /// Path to the MXC container config (JSON) to update.
        #[arg(long)]
        config_path: Option<PathBuf>,
        /// Override for the adjusted config output path.
        #[arg(long)]
        adjusted_config_path: Option<PathBuf>,
        /// Re-process a previously captured .etl instead of stopping a
        /// live WPR session. When set, `wpr -stop` is skipped and the
        /// supplied file is parsed as-is.
        #[arg(long)]
        trace_file: Option<PathBuf>,
        /// Emit per-event/per-ACE diagnostic output.
        #[arg(long)]
        verbose_logging: bool,
    },
    /// Interactive: press Enter to start logging, press Enter again to stop.
    Log {
        /// Override path to plm.wprp. Defaults to <exe dir>\plm.wprp.
        #[arg(long)]
        wprp: Option<PathBuf>,
        /// Emit per-event/per-ACE diagnostic output.
        #[arg(long)]
        verbose_logging: bool,
    },
}

#[cfg(target_os = "windows")]
fn exe_dir() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("failed to resolve current exe path")?;
    Ok(exe
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".")))
}

/// Scan argv for `--wxc-capture-dir <path>` and, if present, redirect
/// this process's stdout/stderr to `<path>/stdout.log` and
/// `<path>/stderr.log`. Called before `Cli::parse()` so any error the
/// runtime prints (including our own arg-parse errors) reaches the
/// capture files.
///
/// Used when `wxc-exec --audit` launches us elevated via
/// `ShellExecuteExW` + `runas`. That elevation path can inherit
/// neither our stdio handles nor our environment block (the AppInfo
/// service creates the child with a fresh env for the elevated
/// token), so environment-variable–based handoff of the capture
/// paths does not work — we must pass them on the command line. The
/// flag is also declared as a hidden `#[arg(long, hide = true)]` on
/// `Cli` so clap accepts (and ignores) it during subcommand parsing.
///
/// On file-open failure we silently fall through — the operator
/// loses that stream's diagnostics but the rest of plm still runs.
#[cfg(target_os = "windows")]
fn redirect_stdio_from_argv() {
    use std::fs::OpenOptions;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Console::{SetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE};

    let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let mut dir: Option<std::path::PathBuf> = None;
    let mut i = 1;
    while i < argv.len() {
        if argv[i] == "--wxc-capture-dir" && i + 1 < argv.len() {
            dir = Some(std::path::PathBuf::from(&argv[i + 1]));
            break;
        }
        i += 1;
    }
    let Some(dir) = dir else { return };

    fn redirect_one(path: &Path, which: windows::Win32::System::Console::STD_HANDLE) {
        // `create_new(true)` maps to `CREATE_NEW` on Windows, which
        // fails with `ERROR_FILE_EXISTS` if anything (regular file,
        // directory, symlink, junction target — any reparse point)
        // already occupies the path. Combined with the caller-side
        // random-suffix temp dir (see `plm_launch::run_plm_elevated`),
        // this closes the elevation-boundary symlink attack: a same-
        // user medium-IL attacker cannot pre-plant `stdout.log` /
        // `stderr.log` as a symlink pointing at an admin-only file
        // and have this elevated (admin-token) process silently
        // append attacker-controllable bytes to that target.
        //
        // If create_new fails (attacker successfully raced us, or
        // some other fs error) we silently give up — the operator
        // loses that stream's diagnostics but no privilege boundary
        // is crossed.
        let Ok(f) = OpenOptions::new().create_new(true).append(true).open(path) else {
            return;
        };
        let handle = HANDLE(f.as_raw_handle());
        // Leak the file so the handle stays alive for the process's
        // lifetime. `SetStdHandle` records the raw handle; if the
        // File drops, the handle closes and subsequent writes fail.
        std::mem::forget(f);
        // SAFETY: `which` is a valid STD_* constant; `handle` was
        // just returned from OpenOptions::open and remains valid
        // because we forgot the File.
        let _ = unsafe { SetStdHandle(which, handle) };
    }

    redirect_one(&dir.join("stdout.log"), STD_OUTPUT_HANDLE);
    redirect_one(&dir.join("stderr.log"), STD_ERROR_HANDLE);
}

#[cfg(target_os = "windows")]
fn main() -> Result<()> {
    // If wxc-exec spawned us elevated via ShellExecuteExW+runas, it
    // cannot inherit our stdio pipes across the elevation boundary
    // AND the AppInfo service that brokers the elevation does not
    // propagate our environment block to the elevated child. The
    // capture-file directory is therefore passed as a hidden CLI
    // argument (`--wxc-capture-dir`) rather than via env; we redirect
    // stdout/stderr to files inside it before touching clap so any
    // arg-parse errors also reach the operator. Silent no-op when
    // the flag is absent (direct user invocation from an elevated
    // shell).
    redirect_stdio_from_argv();

    let cli = Cli::parse();
    // Honour the parent-holds-singleton signal wxc-exec passed as a
    // CLI flag. Set BEFORE any acquire_singleton_if_needed call so
    // the bypass fires. We keep the env-var path in
    // singleton_bypass_requested as a compatibility fallback for
    // direct callers that inherit env normally (see coordination.rs).
    if cli.wxc_singleton_held_by_parent {
        plm::coordination::set_singleton_bypass_override(true);
    }
    let exe = exe_dir()?;

    // Confirm the resolved wpr.exe exists at `%SystemDirectory%`
    // before we go further. We rely on `GetSystemDirectoryW` (not
    // env-spoofable) plus the OS TrustedInstaller ACL on that
    // directory as the trust boundary; see `wpr_path` module docs for
    // why we do not run WinVerifyTrust on the resolved binary.
    plm::wpr_path::verify_wpr_signed().map_err(|e| anyhow::anyhow!("wpr.exe check failed: {e}"))?;

    // Install the Ctrl+C handler unconditionally so signals during any
    // subcommand (in particular interactive `log`) tear down the WPR
    // session and release the singleton before ExitProcess fires.
    install_ctrl_handler();

    match cli.cmd {
        Cmd::Start { wprp } => {
            let _singleton = acquire_singleton_if_needed()?;
            // Default: materialize the embedded `plm.wprp` next to the
            // exe if one isn't already there.
            let wprp_path = match wprp {
                Some(p) => p,
                None => profile_gen::ensure_wprp_next_to_exe(&exe)
                    .context("failed to stage plm.wprp next to plm.exe")?,
            };
            start::start_plm_trace(&wprp_path)?;
            // `plm start` exits immediately and leaves the kernel ETW
            // session running until a later `plm stop` / `wpr -stop`.
            // We deliberately do NOT mark PLM_TRACE_ACTIVE here: this
            // process is about to exit and can't be the one to cancel
            // the session it just kicked off. The matching `plm stop`
            // (or wxc-exec's `cancel_active_audit_trace` cleanup path
            // on Ctrl+C) is what owns teardown.
            Ok(())
        }
        Cmd::Stop {
            log_dir,
            bin_path,
            config_path,
            adjusted_config_path,
            trace_file,
            verbose_logging,
        } => {
            let _singleton = acquire_singleton_if_needed()?;
            stop::run(
                stop::StopOptions {
                    log_dir,
                    bin_path,
                    config_path,
                    adjusted_config_path,
                    trace_file,
                    verbose: verbose_logging,
                },
                &exe,
            )
        }
        Cmd::Log {
            wprp,
            verbose_logging,
        } => {
            let singleton = acquire_singleton_if_needed()?;
            // see `Cmd::Start` above — stage the embedded profile if
            // missing.
            let wprp_path = match wprp {
                Some(p) => p,
                None => profile_gen::ensure_wprp_next_to_exe(&exe)
                    .context("failed to stage plm.wprp next to plm.exe")?,
            };
            // The interactive `log` flow is the only standalone path
            // that holds a live trace inside a single process. We hand
            // `log::run` closures that call
            // `AcquiredSingleton::mark_trace_active` /
            // `clear_trace_active` on the borrowed singleton — the
            // `&AcquiredSingleton` methods encode at compile time that
            // trace-active can only be set while we hold the host-wide
            // singleton mutex. `mark_trace_active` flips the flag only
            // AFTER `wpr -start` has actually engaged the kernel
            // session, so a stdin-EOF or spawn-fail before that point
            // cannot trip the Ctrl+C handler into `wpr -cancel`ing an
            // unrelated host WPR session.
            let result = if let Some(s) = singleton.as_ref() {
                log::run(
                    &wprp_path,
                    verbose_logging,
                    || s.mark_trace_active(),
                    || s.clear_trace_active(),
                )
            } else {
                // Singleton bypass path (wxc-exec --audit already
                // holds the mutex). No `AcquiredSingleton` exists in
                // this process, so we can't gate the flag on it —
                // fall back to the free-function path that the ctrl
                // handler also uses. The outer process owns cleanup.
                log::run(
                    &wprp_path,
                    verbose_logging,
                    || PLM_TRACE_ACTIVE.store(true, Ordering::SeqCst),
                    || PLM_TRACE_ACTIVE.store(false, Ordering::SeqCst),
                )
            };
            // If `log::run` returned Err AND the trace had been marked
            // active (start succeeded but stop or later step failed),
            // the flag is still set — issue `wpr -cancel` so the NT
            // Kernel Logger session doesn't leak until reboot.
            if result.is_err() {
                if let Some(s) = singleton.as_ref() {
                    s.cancel_active_trace();
                } else {
                    cancel_active_plm_trace_from_signal();
                }
            }
            result
        }
    }
}
