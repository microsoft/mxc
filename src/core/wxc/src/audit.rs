// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Graceful-exit PLM audit-trace lifecycle for `wxc-exec --audit`.
//!
//! **Invariant: `wxc-exec.exe` runs unelevated.** Starting a WPR
//! kernel ETW session requires administrator, so `--audit` does NOT
//! self-elevate `wxc-exec`; instead it delegates the privileged work
//! to `plm.exe`, which carries a `requireAdministrator` manifest and
//! is spawned via `ShellExecuteExW` + `runas` (UAC). See
//! [`crate::plm_launch::run_plm_elevated`] for the spawn wrapper.
//! Every `run_plm_command(...)` call in this module therefore
//! triggers a UAC prompt when invoked from a medium-IL shell — one
//! prompt per `plm start`, one per `plm stop`.
//!
//! `--audit` runs `plm.exe start`, which leaves a live WPR ETW session
//! in the kernel for the duration of the workload. The matching
//! `plm.exe stop` tears it down. If anything between those two calls
//! aborts wxc-exec — Ctrl-C, panic, `process::exit`, container-runner
//! kill — the kernel session stays allocated until reboot or manual
//! `wpr -cancel`, blocking all other WPR consumers on the host (only
//! one NT Kernel Logger session can exist at a time).
//!
//! We bracket the live-trace window with `AUDIT_ACTIVE` plus a stack-
//! owned `AuditTraceGuard`. Cleanup paths:
//!  * Normal exit and panic unwind — `AuditTraceGuard::drop` invokes
//!    `cancel_active_audit_trace()`.
//!  * Ctrl-C / Ctrl-Break / console close — the `dacl_ctrl_handler`
//!    (in `main.rs`) also calls `cancel_active_audit_trace()` after
//!    handling DACLs.
//!
//! `cancel_active_audit_trace()` is idempotent via the AtomicBool, so
//! it is safe for both paths to call it.
//!
//! The host-wide named-mutex singleton (`Global\Mxc_Plm_Audit`) is
//! shared with `plm.exe`; both binaries acquire and release it via
//! `plm::coordination::singleton` so their retry-on-conflict paths can
//! never silently `wpr -cancel` a peer trace.

use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};

use wxc_common::logger::Logger;

/// Path to `plm.exe`, expected to sit next to `wxc-exec.exe` in the
/// same install directory. Returns `None` when the current exe path
/// can't be resolved.
pub fn plm_exe_path() -> Option<std::path::PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("plm.exe")))
}

/// Run `plm.exe <subcommand> <args...>` synchronously and route stdio
/// through to wxc-exec's console. Audit tracing is a best-effort
/// diagnostic: missing-binary / spawn / non-zero-exit conditions are
/// logged and returned as `false` — this function never calls
/// `process::exit` on its own. The caller (currently the `--audit`
/// entry point) is responsible for deciding whether a `false` return
/// should abort the workload; today the `plm start` caller does abort
/// rather than run --audit without an active trace, while `plm stop`
/// merely falls through to the `wpr -cancel` cleanup path.
///
/// Returns `true` iff the spawn succeeded **and** plm.exe exited with
/// a zero status. The caller needs this signal to decide whether to
/// clear `AUDIT_ACTIVE` (only after a successful `plm stop`); without
/// it, `AUDIT_ACTIVE.store(false)` would run unconditionally and
/// silently leak the kernel ETW session on every failure path.
pub fn run_plm_command(args: &[&std::ffi::OsStr], logger: &mut Logger, verbose: bool) -> bool {
    use std::fmt::Write as _;

    let Some(plm) = plm_exe_path() else {
        let _ = writeln!(logger, "[audit] could not resolve plm.exe path");
        return false;
    };
    if !plm.exists() {
        let _ = writeln!(
            logger,
            "[audit] plm.exe not found at {} - skipping",
            plm.display()
        );
        return false;
    }

    let mut summary = String::new();
    let _ = write!(summary, "[audit] running {}", plm.display());
    for a in args {
        let _ = write!(summary, " {}", a.to_string_lossy());
    }
    let _ = writeln!(logger, "{summary}");
    if verbose {
        eprintln!("{summary}");
    }

    // plm.exe normally acquires the `Global\Mxc_Plm_Audit` named-
    // mutex singleton on direct operator invocations (`plm log` /
    // `plm start` / `plm stop`) so its retry-on-conflict path can't
    // silently `wpr -cancel` a peer trace. When wxc-exec spawns
    // plm.exe we already hold that mutex for the whole audit window
    // — tell the child to skip its own acquisition so we don't
    // deadlock on the same global name. The signal used to be an env
    // var (SINGLETON_HELD_BY_PARENT_ENV) but `ShellExecuteExW` +
    // `runas` (used by run_plm_elevated) does not propagate the
    // caller's environment across the elevation boundary, so it now
    // rides on a hidden CLI flag.
    match crate::plm_launch::run_plm_elevated(&plm, args, true) {
        Ok(run) if run.exit_code == 0 => {
            if verbose {
                replay_captured(logger, &run.stdout, &run.stderr);
            }
            true
        }
        Ok(run) => {
            let _ = writeln!(logger, "[audit] plm exited with code {}", run.exit_code);
            replay_captured(logger, &run.stdout, &run.stderr);
            if verbose {
                eprintln!("[audit] plm exited with code {}", run.exit_code);
            }
            false
        }
        Err(msg) => {
            let _ = writeln!(logger, "[audit] failed to launch elevated plm: {msg}");
            if verbose {
                eprintln!("[audit] failed to launch elevated plm: {msg}");
            }
            false
        }
    }
}

/// Replay captured stdout/stderr bytes to the current process's own
/// streams. Used on failure (and in verbose mode on success) so the
/// happy path can stay silent while diagnostics still surface. Byte
/// slices come from `ShellExecuteExW`-elevated child capture, which
/// cannot go through OS pipe inheritance and is redirected to temp
/// files at the plm.exe end (see `plm_launch::run_plm_elevated`).
fn replay_captured(logger: &mut Logger, stdout: &[u8], stderr: &[u8]) {
    use std::fmt::Write as _;
    use std::io::Write as _;
    if !stdout.is_empty() {
        let _ = std::io::stdout().write_all(stdout);
        let _ = write!(logger, "{}", String::from_utf8_lossy(stdout));
    }
    if !stderr.is_empty() {
        let _ = std::io::stderr().write_all(stderr);
        let _ = write!(logger, "{}", String::from_utf8_lossy(stderr));
    }
}

pub static AUDIT_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Set to `true` while `plm start` is being spawned and has not yet
/// returned. `AUDIT_ACTIVE` is flipped to `true` BEFORE `plm.exe` is
/// spawned (because `mark_audit_active()` has to run early to cover a
/// Ctrl+C arriving mid-spawn), but the kernel ETW session is not
/// actually engaged until `plm.exe`'s child `wpr -start` returns. A
/// Ctrl+C in that gap would fire `wpr -cancel` against a not-yet-
/// existing session, then `wpr -start` would silently succeed AFTER
/// the cancel — leaking the session past `wxc-exec`'s own cleanup. We
/// close the race by making the Ctrl+C handler wait (bounded) until
/// `plm start` has finished its spawn round-trip before deciding
/// whether to issue the cancel.
pub static AUDIT_START_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

/// Mark that the wxc-exec process owns a live PLM audit trace. Called
/// just before `plm start` is spawned so a Ctrl-C arriving mid-spawn
/// still triggers cleanup (over-cancelling a not-yet-started session
/// is harmless — `wpr -cancel` returns non-zero and we discard).
pub fn mark_audit_active() {
    AUDIT_ACTIVE.store(true, Ordering::SeqCst);
}

/// Cancel an in-flight PLM audit trace iff one is active, then clear
/// the flag. Idempotent; safe to call from the Ctrl-C handler and the
/// stack guard's Drop. Failures (no active session, missing wpr.exe)
/// are silenced because the call is best-effort cleanup.
///
/// Invokes `wpr.exe` by absolute path (`%SystemRoot%\System32\wpr.exe`)
/// rather than as a bare name so `CreateProcessW`'s implicit CWD-first
/// search order can't be abused to substitute a planted binary.
/// `wxc-exec` itself runs unelevated; the privileged `wpr -start` /
/// `wpr -stop` calls are delegated to the elevated `plm.exe` child
/// (see [`crate::plm_launch::run_plm_elevated`]). We still resolve
/// wpr by absolute path here for the best-effort panic / ctrl-c
/// cleanup so behavior is consistent with the plm.exe side, which
/// applies the same hardening in its own resolver.
pub fn cancel_active_audit_trace() {
    if AUDIT_ACTIVE.swap(false, Ordering::SeqCst) {
        let wpr = resolve_system32_wpr();
        let _ = std::process::Command::new(&wpr)
            .arg("-cancel")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

/// Resolve `<System32>\wpr.exe` via `GetSystemDirectoryW`. Reading
/// `%SystemRoot%` from the process env is unsafe because UAC inherits
/// env from the unelevated parent — a standard user could `setx
/// SystemRoot=C:\\Users\\Public\\evil` and plant `wpr.exe` for a later
/// admin run. `GetSystemDirectoryW` is kernel-published and not
/// env-spoofable.
fn resolve_system32_wpr() -> std::path::PathBuf {
    use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
    let mut buf = vec![0u16; 260];
    // SAFETY: buf is initialized; we pass valid length and own the
    // memory for the duration of the call.
    let n = unsafe { GetSystemDirectoryW(Some(&mut buf)) };
    if n == 0 || (n as usize) > buf.len() {
        return std::path::PathBuf::from("C:\\Windows\\System32\\wpr.exe");
    }
    let dir = wxc_common::string_util::from_wide(&buf[..n as usize]);
    let mut p = std::path::PathBuf::from(dir);
    p.push("wpr.exe");
    p
}

/// Stack-owned guard: ensures the audit trace is cancelled on panic
/// unwind and on normal function return.
pub struct AuditTraceGuard;

impl Drop for AuditTraceGuard {
    fn drop(&mut self) {
        cancel_active_audit_trace();
    }
}

/// Raw handle of the host-wide single-instance mutex for PLM audit
/// mode. Two concurrent `wxc-exec --audit` runs would share a single
/// NT Kernel Logger session, so the second one's `wpr -start` would
/// either steal the first's session or fail and silently corrupt the
/// first run's findings. `wxc-exec` (unelevated) acquires the named
/// mutex (`Global\\` so it's machine-wide across sessions) and
/// refuses to start if another wxc-exec audit is already running.
/// The elevated `plm.exe` child skips its own acquisition of the
/// same mutex via the `--wxc-singleton-held-by-parent` flag so the
/// parent's handle remains the sole owner for the trace lifetime.
///
/// The handle is stashed in a static atomic (not just the stack guard)
/// so the explicit cleanup before `process::exit` — which skips
/// destructors — can release it too. `AuditSingletonGuard::drop` is
/// a thin shim over `release_audit_singleton`; both paths are
/// idempotent.
static AUDIT_SINGLETON_HANDLE: AtomicIsize = AtomicIsize::new(0);

pub struct AuditSingletonGuard;

impl Drop for AuditSingletonGuard {
    fn drop(&mut self) {
        release_audit_singleton();
    }
}

/// Release the host-wide audit singleton if held. Idempotent: safe to
/// call from `Drop`, from the explicit pre-`process::exit` cleanup,
/// and from error paths.
pub fn release_audit_singleton() {
    plm::coordination::singleton::release(&AUDIT_SINGLETON_HANDLE);
}

pub fn try_acquire_audit_singleton() -> Result<AuditSingletonGuard, String> {
    use plm::coordination::singleton::{try_acquire, AcquireError};
    match try_acquire(&AUDIT_SINGLETON_HANDLE) {
        Ok(()) => Ok(AuditSingletonGuard),
        Err(AcquireError::AlreadyHeld) => Err(String::from(
            "another wxc-exec --audit run holds the Global\\Mxc_Plm_Audit mutex; \
             refusing to start a second concurrent PLM trace (only one NT Kernel \
             Logger session can exist per host)",
        )),
        Err(AcquireError::CreateFailed(e)) => Err(format!("CreateMutexW failed: {e}")),
    }
}
