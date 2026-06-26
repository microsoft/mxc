//! Rust port of the permissive learning mode (PLM) PowerShell scripts.
//!
//! Subcommands:
//! - `start`: cancel any active WPR trace and start a new one using
//!   `plm.wprp!AccessFailureProfile` (port of `start_plm_logging.ps1`).
//! - `stop`: stop the trace, parse events, merge findings into a config
//!   (port of `stop_plm_logging.ps1`).
//!
//! Windows-only: the binary wraps WPR / ETW / EventLog APIs that have no
//! cross-platform equivalent. The crate is excluded from the workspace's
//! `default-members`, so `cargo build` on Linux/macOS never reaches this
//! file; the build script (`build.bat`) opts it in explicitly with
//! `-p plm`.

#![cfg(target_os = "windows")]

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::time::Duration;

use plm::coordination::{singleton_bypass_requested, wait_until_cleared, PLM_LOG_START_IN_FLIGHT};
use plm::{extract_caps, log, start, stop};

/// Set to `true` while a `wpr -start` has succeeded but the matching
/// stop hasn't run yet. Read by the console-control handler so that a
/// Ctrl+C / Ctrl+Break that arrives during `plm log` (or between
/// `plm start` and the operator's matching `plm stop`) still tears
/// down the kernel ETW session instead of leaking it.
///
/// Round-6 reliability finding #1: the `wxc-exec --audit` path has its
/// own AUDIT_ACTIVE flag + SetConsoleCtrlHandler; the standalone
/// `plm log` interactive flow had neither, so Ctrl+C left the NT
/// Kernel Logger session live until reboot or manual `wpr -cancel`.
static PLM_TRACE_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Raw `HANDLE` value of the named-mutex singleton acquired by
/// `acquire_singleton_if_needed` (zero when unheld). Stashed in a
/// static so the console-control handler can release the host-wide
/// guard before `ExitProcess` runs and skips Rust destructors.
///
/// Round-6 reliability finding #2: `plm log` / direct `plm start` /
/// direct `plm stop` previously bypassed the `Global\Mxc_Plm_Audit`
/// singleton entirely, so the retry-on-conflict path in
/// `start_plm_trace` could silently `wpr -cancel` a peer PLM trace.
static PLM_SINGLETON_HANDLE: AtomicIsize = AtomicIsize::new(0);

/// Mark the kernel ETW session as live; called immediately after
/// `start::start_plm_trace` succeeds.
fn mark_plm_trace_active() {
    PLM_TRACE_ACTIVE.store(true, Ordering::SeqCst);
}

fn clear_plm_trace_active() {
    PLM_TRACE_ACTIVE.store(false, Ordering::SeqCst);
}

/// Issue `wpr -cancel` iff a trace was marked active by this process.
/// Idempotent and safe to call from the console-control handler.
fn cancel_active_plm_trace() {
    if PLM_TRACE_ACTIVE.swap(false, Ordering::SeqCst) {
        // Use the kernel-published System32 path (round-4/5 security
        // hardening — see wpr_path.rs).
        let _ = plm::wpr_path::wpr_command()
            .arg("-cancel")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

/// Release the named-mutex singleton if held. Idempotent.
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
struct AcquiredSingleton;

impl Drop for AcquiredSingleton {
    fn drop(&mut self) {
        release_plm_singleton();
    }
}

fn acquire_singleton_if_needed() -> Result<Option<AcquiredSingleton>> {
    if singleton_bypass_requested() {
        // Outer process holds the mutex for the whole audit window;
        // re-acquiring here would deadlock.
        return Ok(None);
    }
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
    use windows::Win32::System::Threading::CreateMutexW;

    let name: Vec<u16> = "Global\\Mxc_Plm_Audit"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let handle = unsafe { CreateMutexW(None, true, PCWSTR(name.as_ptr())) }
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
    // Round-7 reliability finding #1: if `plm log`'s `wpr -start` is
    // still in flight when Ctrl+C arrives, briefly wait for it to
    // settle before deciding whether to issue `wpr -cancel`. Without
    // this wait, a cancel that races a not-yet-engaged session is a
    // no-op and the kernel session leaks past `plm.exe` exit.
    //
    // Round-9 testability finding #1: timeout sourced from the
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
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Start a new WPR trace using plm.wprp!AccessFailureProfile.
    Start {
        /// Override path to plm.wprp. Defaults to <exe dir>\plm.wprp.
        #[arg(long)]
        wprp: Option<PathBuf>,
    },
    /// Stop the trace and (optionally) merge findings into a config.
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
    /// Run extract_caps on a hex-encoded ACE blob and print matched
    /// capability names. Mirrors the standalone usage of extract_caps.ps1.
    ExtractCaps {
        /// Hex-encoded ACE buffer (whitespace allowed, even length).
        #[arg(long)]
        hex_bytes: String,
        /// Emit per-ACE diagnostic output.
        #[arg(long)]
        verbose_logging: bool,
    },
    /// Interactive: press Enter to start logging, press Enter again to
    /// stop, then print the changes a blank config would receive.
    Log {
        /// Override path to plm.wprp. Defaults to <exe dir>\plm.wprp.
        #[arg(long)]
        wprp: Option<PathBuf>,
        /// Emit per-event/per-ACE diagnostic output.
        #[arg(long)]
        verbose_logging: bool,
    },
}

fn exe_dir() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("failed to resolve current exe path")?;
    Ok(exe
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".")))
}

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
            // Round-8 coverage finding #4: filename must match the
            // lowercase `plm.wprp` written by `build.rs`. Mismatched
            // casing works on default case-insensitive NTFS but fails
            // opaquely on per-directory case-sensitive trees (WSL-
            // adjacent, `git core.ignorecase=false`).
            let wprp_path = wprp.unwrap_or_else(|| exe.join("plm.wprp"));
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
        Cmd::ExtractCaps {
            hex_bytes,
            verbose_logging,
        } => {
            let caps = extract_caps::extract_caps(&hex_bytes, verbose_logging)?;
            let mut sorted: Vec<&String> = caps.iter().collect();
            sorted.sort();
            for c in sorted {
                println!("{c}");
            }
            Ok(())
        }
        Cmd::Log {
            wprp,
            verbose_logging,
        } => {
            let _singleton = acquire_singleton_if_needed()?;
            // Round-8 coverage finding #4: see `Cmd::Start` above —
            // lowercase to match `build.rs` staging.
            let wprp_path = wprp.unwrap_or_else(|| exe.join("plm.wprp"));
            // The interactive `log` flow is the only standalone path
            // that holds a live trace inside a single process. Mark
            // the trace active so a Ctrl+C between the start and the
            // operator's matching stdin-Enter tears the session down.
            mark_plm_trace_active();
            let result = log::run(&wprp_path, verbose_logging);
            // On the normal path `log::run` performs its own
            // `wpr -stop` and the trace is no longer live; clear the
            // flag so the Ctrl+C handler doesn't issue a stale cancel.
            clear_plm_trace_active();
            result
        }
    }
}
