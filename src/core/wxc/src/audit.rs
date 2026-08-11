// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Graceful-exit PLM audit-trace lifecycle for `wxc-exec --audit`.
//!
//! **Invariant: `wxc-exec.exe` runs unelevated.** Starting a WPR
//! kernel ETW session requires administrator, so `--audit` does NOT
//! self-elevate `wxc-exec`; instead it launches PLM's hidden, fixed-operation
//! START child through UAC and retains its authenticated control pipe.
//!
//! The child opens and validates the wxc-exec owner before starting WPR, stays
//! alive through the workload, and cancels on owner death or pipe break.
//! Successful stop signals its stop/transfer milestone over the authenticated
//! parent pipe, then explicitly sends DISARM before trace analysis continues.
//!
//! The host-wide named-mutex singleton (`Global\Mxc_Plm_Audit`) is
//! shared with `plm.exe`; both binaries acquire and release it via
//! `plm::coordination::singleton` so their retry-on-conflict paths can
//! never silently `wpr -cancel` a peer trace.

use std::sync::atomic::AtomicIsize;

use wxc_common::logger::Logger;

/// Path to `plm.exe`, expected to sit next to `wxc-exec.exe` in the
/// same install directory. Returns `None` when the current exe path
/// can't be resolved.
pub fn plm_exe_path() -> Option<std::path::PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("plm.exe")))
}

/// Run the public `plm.exe <subcommand> <args...>` synchronously under the
/// current token, capturing stdout/stderr and replaying them only on non-zero
/// exit or when `verbose` is set. Audit tracing is a best-effort
/// diagnostic: missing-binary / spawn / non-zero-exit conditions are
/// logged and returned as `false` — this function never calls
/// `process::exit` on its own. The caller (currently the `--audit`
/// entry point) is responsible for deciding whether a `false` return should
/// abort the workload.
///
/// Returns `true` iff the spawn succeeded **and** plm.exe exited with
/// a zero status.
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

    // Public plm.exe normally acquires the `Global\Mxc_Plm_Audit` named-
    // mutex singleton on direct operator invocations (`plm log` /
    // `plm start` / `plm stop`) so its retry-on-conflict path can't
    // silently `wpr -cancel` a peer trace. When wxc-exec spawns
    // plm.exe we already hold that mutex for the whole audit window
    // — tell the child to skip its own acquisition so we don't
    // deadlock on the same global name. The bypass uses a local named pipe
    // whose server/client PIDs are checked in both directions; there is no
    // spoofable environment variable or bare hidden flag.
    let output = spawn_authorized_public_plm(&plm, args).and_then(|(child, _connection)| {
        child
            .wait_with_output()
            .map_err(|error| format!("failed to wait for public plm.exe: {error}"))
    });
    report_plm_output(output, logger, verbose)
}

pub fn run_plm_stop_command(
    args: &[&std::ffi::OsStr],
    guard: &mut AuditTraceGuard,
    logger: &mut Logger,
    verbose: bool,
) -> bool {
    use std::fmt::Write as _;

    let Some(plm) = plm_exe_path() else {
        let _ = writeln!(logger, "[audit] could not resolve plm.exe path");
        return false;
    };
    if !plm.exists() {
        let _ = writeln!(logger, "[audit] plm.exe not found at {}", plm.display());
        return false;
    }

    let mut summary = format!("[audit] running {}", plm.display());
    for arg in args {
        let _ = write!(summary, " {}", arg.to_string_lossy());
    }
    let _ = writeln!(logger, "{summary}");
    if verbose {
        eprintln!("{summary}");
    }

    let (child, mut connection) = match spawn_authorized_public_plm(&plm, args) {
        Ok(run) => run,
        Err(error) => {
            let _ = writeln!(logger, "[audit] failed to launch plm: {error}");
            return false;
        }
    };
    let milestone = connection.wait_for_trace_stopped();
    let disarmed = match milestone {
        Ok(()) => guard.disarm(logger, verbose),
        Err(error) => {
            let _ = writeln!(
                logger,
                "[audit] did not receive trace-stopped milestone: {error}"
            );
            false
        }
    };
    let output = child
        .wait_with_output()
        .map_err(|error| format!("failed to wait for public plm.exe: {error}"));
    report_plm_output(output, logger, verbose) && disarmed
}

fn report_plm_output(
    output: Result<std::process::Output, String>,
    logger: &mut Logger,
    verbose: bool,
) -> bool {
    use std::fmt::Write as _;

    match output {
        Ok(run) if run.status.success() => {
            if verbose {
                replay_captured(logger, &run.stdout, &run.stderr);
            }
            true
        }
        Ok(run) => {
            let code = run.status.code().unwrap_or(-1);
            let _ = writeln!(logger, "[audit] plm exited with code {code}");
            replay_captured(logger, &run.stdout, &run.stderr);
            if verbose {
                eprintln!("[audit] plm exited with code {code}");
            }
            false
        }
        Err(error) => {
            let _ = writeln!(logger, "[audit] failed to launch plm: {error}");
            if verbose {
                eprintln!("[audit] failed to launch plm: {error}");
            }
            false
        }
    }
}

/// Replay captured stdout/stderr bytes to the current process's own
/// streams. Used on failure (and in verbose mode on success) so the happy path
/// can stay silent while diagnostics still surface.
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

fn spawn_authorized_public_plm(
    plm_path: &std::path::Path,
    args: &[&std::ffi::OsStr],
) -> Result<(std::process::Child, plm::parent_auth::ParentConnection), String> {
    let authorization = plm::parent_auth::ParentAuthorization::new()?;
    let mut child = std::process::Command::new(plm_path)
        .arg("--wxc-parent-auth")
        .arg(authorization.pipe_name())
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| format!("failed to spawn public plm.exe: {error}"))?;
    match authorization.authorize(child.id()) {
        Ok(connection) => Ok((child, connection)),
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(error)
        }
    }
}

/// Stack-owned guarded START session.
#[derive(Debug)]
pub struct AuditTraceGuard {
    session: plm::elevated::GuardedSession,
}

impl AuditTraceGuard {
    pub fn start(logger: &mut Logger, verbose: bool) -> Result<Self, String> {
        use std::fmt::Write as _;

        let plm = plm_exe_path().ok_or_else(|| {
            let message = "could not resolve plm.exe path".to_string();
            let _ = writeln!(logger, "[audit] {message}");
            message
        })?;
        if !plm.exists() {
            let message = format!("plm.exe not found at {}", plm.display());
            let _ = writeln!(logger, "[audit] {message}");
            return Err(message);
        }

        let summary = format!("[audit] running {} start", plm.display());
        let _ = writeln!(logger, "{summary}");
        if verbose {
            eprintln!("{summary}");
        }
        let owner_pid = unsafe { windows::Win32::System::Threading::GetCurrentProcessId() };
        plm::elevated::start_guarded_session_with_executable(&plm, owner_pid)
            .map(|session| Self { session })
            .map_err(|error| {
                let message = format!("guarded plm start failed: {error:#}");
                let _ = writeln!(logger, "[audit] {message}");
                if verbose {
                    eprintln!("[audit] {message}");
                }
                message
            })
    }

    pub fn disarm(&mut self, logger: &mut Logger, verbose: bool) -> bool {
        use std::fmt::Write as _;

        match self.session.disarm() {
            Ok(()) => true,
            Err(error) => {
                let _ = writeln!(logger, "[audit] failed to disarm guarded start: {error:#}");
                if verbose {
                    eprintln!("[audit] failed to disarm guarded start: {error:#}");
                }
                false
            }
        }
    }
}

/// Raw handle of the host-wide single-instance mutex for PLM audit
/// mode. Two concurrent `wxc-exec --audit` runs would share a single
/// NT Kernel Logger session, so the second one's `wpr -start` would
/// either steal the first's session or fail and silently corrupt the
/// first run's findings. `wxc-exec` (unelevated) acquires the named
/// mutex (`Global\\` so it's machine-wide across sessions) and
/// refuses to start if another wxc-exec audit is already running.
/// Each public `plm.exe` child skips its own acquisition only after a
/// mutually authenticated named-pipe handshake with this direct parent, so
/// the parent's handle remains the sole owner for the trace lifetime without
/// exposing a spoofable bypass flag.
///
/// The handle is stashed in a static atomic (not just the stack guard)
/// so the explicit cleanup before `process::exit` — which skips
/// destructors — can release it too. `AuditSingletonGuard::drop` is
/// a thin shim over `release_audit_singleton`; both paths are
/// idempotent.
static AUDIT_SINGLETON_HANDLE: AtomicIsize = AtomicIsize::new(0);

pub struct AuditSingletonGuard {
    outcome: plm::coordination::singleton::AcquireOutcome,
}

impl AuditSingletonGuard {
    pub fn inherited_abandoned_owner(&self) -> bool {
        self.outcome == plm::coordination::singleton::AcquireOutcome::Abandoned
    }
}

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
        Ok(outcome) => Ok(AuditSingletonGuard { outcome }),
        Err(AcquireError::AlreadyHeld) => Err(String::from(
            "another wxc-exec --audit run holds the Global\\Mxc_Plm_Audit mutex; \
             refusing to start a second concurrent PLM trace (only one NT Kernel \
             Logger session can exist per host)",
        )),
        Err(AcquireError::CreateFailed(e)) => Err(format!("CreateMutexW failed: {e}")),
    }
}
