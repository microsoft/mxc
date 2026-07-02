//! Rust port of the permissive learning mode (PLM) PowerShell scripts.
//!
//! Subcommands (PR1 skeleton):
//! - `start`: cancel any active WPR trace and start a new one using
//!   `plm.wprp!AccessFailureProfile`.
//! - `stop`: stop the trace; later PRs add event parsing and config
//!   merging.
//! - `log`: interactive — Enter to start, Enter to stop; later PRs add
//!   the in-memory parse-and-print-changes flow.
//!
//! `extract-caps` (standalone ACE decoder) lands in the
//! capability-extraction PR.
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

/// Set to `true` while a `wpr -start` has succeeded but the matching
/// stop hasn't run yet. Read by the console-control handler so that a
/// Ctrl+C / Ctrl+Break that arrives during `plm log` (or between
/// `plm start` and the operator's matching `plm stop`) still tears
/// down the kernel ETW session instead of leaking it.
///
/// The `wxc-exec --audit` path has its own AUDIT_ACTIVE flag +
/// SetConsoleCtrlHandler; the standalone `plm log` interactive flow
/// had neither, so Ctrl+C left the NT Kernel Logger session live
/// until reboot or manual `wpr -cancel`.
#[cfg(target_os = "windows")]
static PLM_TRACE_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Raw `HANDLE` value of the named-mutex singleton acquired by
/// `acquire_singleton_if_needed` (zero when unheld). Stashed in a
/// static so the console-control handler can release the host-wide
/// guard before `ExitProcess` runs and skips Rust destructors.
///
/// `plm log` / direct `plm start` / direct `plm stop` previously
/// bypassed the `Global\Mxc_Plm_Audit` singleton entirely, so the
/// retry-on-conflict path in `start_plm_trace` could silently
/// `wpr -cancel` a peer PLM trace.
#[cfg(target_os = "windows")]
static PLM_SINGLETON_HANDLE: AtomicIsize = AtomicIsize::new(0);

/// Mark the kernel ETW session as live; called immediately after
/// `start::start_plm_trace` succeeds.
#[cfg(target_os = "windows")]
fn mark_plm_trace_active() {
    PLM_TRACE_ACTIVE.store(true, Ordering::SeqCst);
}

#[cfg(target_os = "windows")]
fn clear_plm_trace_active() {
    PLM_TRACE_ACTIVE.store(false, Ordering::SeqCst);
}

/// Issue `wpr -cancel` iff a trace was marked active by this process.
/// Idempotent and safe to call from the console-control handler.
#[cfg(target_os = "windows")]
fn cancel_active_plm_trace() {
    if PLM_TRACE_ACTIVE.swap(false, Ordering::SeqCst) {
        // Use the kernel-published System32 path.
        let _ = plm::wpr_path::wpr_command()
            .arg("-cancel")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

/// Release the named-mutex singleton if held. Idempotent.
#[cfg(target_os = "windows")]
fn release_plm_singleton() {
    let raw = PLM_SINGLETON_HANDLE.swap(0, Ordering::SeqCst);
    if raw != 0 {
        let handle = windows::Win32::Foundation::HANDLE(raw as *mut _);
        unsafe {
            let _ = windows::Win32::System::Threading::ReleaseMutex(handle);
            let _ = windows::Win32::Foundation::CloseHandle(handle);
        }
    }
}

/// Acquire the host-wide PLM audit mutex unless our parent process
/// (typically `wxc-exec --audit`) already holds it. Returns an
/// `AcquiredSingleton` whose `Drop` releases the mutex on the normal
/// path; the static handle is also drained by the console-control
/// handler so Ctrl+C cleanup tears it down.
#[cfg(target_os = "windows")]
struct AcquiredSingleton;

#[cfg(target_os = "windows")]
impl Drop for AcquiredSingleton {
    fn drop(&mut self) {
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
    use windows::core::w;
    use windows::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
    use windows::Win32::System::Threading::CreateMutexW;

    let name = w!("Global\\Mxc_Plm_Audit");
    let handle = unsafe { CreateMutexW(None, true, name) }
        .context("CreateMutexW failed for Global\\Mxc_Plm_Audit")?;
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(handle);
        }
        anyhow::bail!(
            "another PLM trace is already in progress (Global\\Mxc_Plm_Audit held); \
             refusing to start a second concurrent trace — only one NT Kernel Logger \
             session can exist per host"
        );
    }
    PLM_SINGLETON_HANDLE.store(handle.0 as isize, Ordering::SeqCst);
    Ok(Some(AcquiredSingleton))
}

/// Windows console-control handler. Fires on Ctrl+C, Ctrl+Break,
/// console close, logoff, and shutdown. Tears down any in-flight WPR
/// session and releases the singleton mutex before the default handler
/// calls `ExitProcess` (which skips Rust destructors).
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
    cancel_active_plm_trace();
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
    /// Stop the trace. Event parsing / config merging arrives in later PRs.
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

#[cfg(target_os = "windows")]
fn main() -> Result<()> {
    let cli = Cli::parse();
    let exe = exe_dir()?;

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
            let _singleton = acquire_singleton_if_needed()?;
            // see `Cmd::Start` above — stage the embedded profile if
            // missing.
            let wprp_path = match wprp {
                Some(p) => p,
                None => profile_gen::ensure_wprp_next_to_exe(&exe)
                    .context("failed to stage plm.wprp next to plm.exe")?,
            };
            // The interactive `log` flow is the only standalone path
            // that holds a live trace inside a single process. We hand
            // `log::run` a `mark_active` callback so PLM_TRACE_ACTIVE
            // flips true only AFTER `wpr -start` has actually engaged
            // the kernel session — a stdin-EOF or spawn-fail before
            // that point cannot trip the Ctrl+C handler into
            // `wpr -cancel`ing an unrelated host WPR session. The
            // matching `clear_active` callback fires once `wpr -stop`
            // has drained the session so subsequent Ctrl+C is a no-op.
            let result = log::run(
                &wprp_path,
                verbose_logging,
                mark_plm_trace_active,
                clear_plm_trace_active,
            );
            // If `log::run` returned Err AND the trace had been marked
            // active (start succeeded but stop or later step failed),
            // the flag is still set — issue `wpr -cancel` so the NT
            // Kernel Logger session doesn't leak until reboot.
            if result.is_err() {
                cancel_active_plm_trace();
            }
            result
        }
    }
}
