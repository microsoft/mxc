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
//! The retained child also performs the fixed stop and ETL transfer operation,
//! so the normal audit lifecycle needs only the original UAC prompt. The
//! singleton is released only after that child reports the trace stopped.
//!
//! The retained child exclusively owns the protected host-wide named-mutex
//! singleton (`Global\Mxc_Plm_Audit`) together with its WPR session.

use wxc_common::logger::Logger;

/// Path to `plm.exe`, expected to sit next to `wxc-exec.exe` in the
/// same install directory. Returns `None` when the current exe path
/// can't be resolved.
pub fn plm_exe_path() -> Option<std::path::PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("plm.exe")))
}

pub struct CapturedAudit {
    pub log_dir: std::path::PathBuf,
    pub trace_path: std::path::PathBuf,
}

pub fn capture_and_stop(
    guard: &mut AuditTraceGuard,
    logger: &mut Logger,
) -> Result<CapturedAudit, String> {
    use std::fmt::Write as _;

    let plm = plm_exe_path().ok_or_else(|| "could not resolve plm.exe path".to_string())?;
    let exe_dir = plm
        .parent()
        .ok_or_else(|| "plm.exe path has no parent directory".to_string())?;
    let log_dir = plm::stop::default_log_dir(exe_dir);
    std::fs::create_dir_all(&log_dir)
        .map_err(|error| format!("failed to create audit log directory: {error}"))?;
    let trace_path = log_dir.join("trace.etl");

    let _ = writeln!(
        logger,
        "[audit] stopping trace into {}",
        trace_path.display()
    );
    guard.stop(&trace_path, logger).map_err(|error| {
        let message = format!("failed to stop and transfer PLM trace: {error:#}");
        let _ = writeln!(logger, "[audit] {message}");
        message
    })?;
    Ok(CapturedAudit {
        log_dir,
        trace_path,
    })
}

/// Run a normal public PLM command after wxc-exec has released the singleton.
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

    let output = std::process::Command::new(&plm)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| format!("failed to spawn public plm.exe: {error}"))
        .and_then(|child| {
            child
                .wait_with_output()
                .map_err(|error| format!("failed to wait for public plm.exe: {error}"))
        });
    report_plm_output(output, logger, verbose)
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

    pub fn stop(
        &mut self,
        trace_destination: &std::path::Path,
        logger: &mut Logger,
    ) -> Result<(), String> {
        use std::fmt::Write as _;

        self.session.stop(trace_destination).map_err(|error| {
            let message = format!("guarded PLM stop failed: {error:#}");
            let _ = writeln!(logger, "[audit] {message}");
            message
        })
    }

    pub fn cancel(&mut self, logger: &mut Logger) -> Result<(), String> {
        use std::fmt::Write as _;

        self.session.cancel().map_err(|error| {
            let message = format!("guarded PLM cancellation failed: {error:#}");
            let _ = writeln!(logger, "[audit] {message}");
            message
        })
    }
}
