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

const PLM_ANALYSIS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10 * 60);
const PLM_WAIT_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(50);

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

    let log_dir = plm::stop::default_log_dir();
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
        .and_then(|child| wait_with_output_timeout(child, PLM_ANALYSIS_TIMEOUT));
    report_plm_output(output, logger, verbose)
}

fn wait_with_output_timeout(
    mut child: std::process::Child,
    timeout: std::time::Duration,
) -> Result<std::process::Output, String> {
    use std::io::Read as _;

    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err("public plm.exe stdout was not captured".to_string());
    };
    let Some(stderr) = child.stderr.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err("public plm.exe stderr was not captured".to_string());
    };
    let stdout_reader = match std::thread::Builder::new()
        .name("plm-audit-stdout".to_string())
        .spawn(move || {
            let mut bytes = Vec::new();
            let mut stdout = stdout;
            stdout.read_to_end(&mut bytes).map(|_| bytes)
        }) {
        Ok(reader) => reader,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("failed to start plm stdout reader: {error}"));
        }
    };
    let stderr_reader = match std::thread::Builder::new()
        .name("plm-audit-stderr".to_string())
        .spawn(move || {
            let mut bytes = Vec::new();
            let mut stderr = stderr;
            stderr.read_to_end(&mut bytes).map(|_| bytes)
        }) {
        Ok(reader) => reader,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            return Err(format!("failed to start plm stderr reader: {error}"));
        }
    };

    let deadline = std::time::Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(PLM_WAIT_POLL_INTERVAL);
            }
            Ok(None) => {
                child.kill().map_err(|error| {
                    format!(
                        "public plm.exe exceeded the {} second audit-analysis timeout, \
                         but termination failed: {error}",
                        timeout.as_secs()
                    )
                })?;
                child.wait().map_err(|error| {
                    format!(
                        "public plm.exe exceeded the {} second audit-analysis timeout, \
                         was terminated, but could not be reaped: {error}",
                        timeout.as_secs()
                    )
                })?;
                return Err(format!(
                    "public plm.exe exceeded the {} second audit-analysis timeout and was terminated",
                    timeout.as_secs()
                ));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("failed to poll public plm.exe: {error}"));
            }
        }
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| "public plm.exe stdout reader panicked".to_string())?
        .map_err(|error| format!("failed to read public plm.exe stdout: {error}"))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| "public plm.exe stderr reader panicked".to_string())?
        .map_err(|error| format!("failed to read public plm.exe stderr: {error}"))?;
    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{
        OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE,
    };

    #[test]
    fn analysis_watchdog_terminates_timed_out_child() {
        let child = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-Command", "Start-Sleep -Seconds 60"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn long-running child");
        let process = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, child.id()) }
            .expect("open child synchronization handle");

        let error = wait_with_output_timeout(child, std::time::Duration::from_millis(50))
            .expect_err("watchdog should time out");
        assert!(error.contains("timeout"));
        assert_eq!(
            unsafe { WaitForSingleObject(process, 1_000) },
            WAIT_OBJECT_0,
            "timed-out child should be terminated and reaped"
        );
        unsafe {
            let _ = CloseHandle(process);
        }
    }
}
