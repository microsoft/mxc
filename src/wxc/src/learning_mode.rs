// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Audit-mode helpers that drive the PowerShell PLM logging scripts in
//! `src/learning_mode/`. These are invoked when the user passes `--audit`
//! to `wxc-exec`.

use std::fmt::Write;
use std::path::PathBuf;

use wxc_common::logger::Logger;

const START_SCRIPT: &str = "start_plm_logging.ps1";
const STOP_SCRIPT: &str = "stop_plm_logging.ps1";

/// Resolve a PLM script path next to the running `wxc-exec.exe` so audit
/// mode works regardless of the caller's current working directory. Falls
/// back to a bare relative path (preserving the historical behaviour) if
/// the executable path cannot be determined.
fn script_path(name: &str) -> PathBuf {
    match std::env::current_exe() {
        Ok(exe) => match exe.parent() {
            Some(dir) => dir.join(name),
            None => PathBuf::from(name),
        },
        Err(_) => PathBuf::from(name),
    }
}

/// Invoke `start_plm_logging.ps1` to begin an ACP profiling session.
pub fn start_audit_logging(logger: &mut Logger) {
    let script = script_path(START_SCRIPT);
    match std::process::Command::new("pwsh.exe")
        .args(["-File".as_ref(), script.as_os_str()])
        .status()
    {
        Ok(status) => {
            let _ = writeln!(logger, "start_plm_logging.ps1 start exited with {}", status);
        }
        Err(e) => {
            let _ = writeln!(logger, "Failed to start start_plm_logging.ps1: {}", e);
        }
    }
}

/// Invoke `stop_plm_logging.ps1` to end the profiling session and merge the
/// observed file accesses into `config_path` (if supplied).
///
/// `log_dir` and `adjusted_config_path`, when set, are forwarded to the
/// PowerShell script as `-LogDir` and `-AdjustedConfigPath` respectively so
/// callers can control where the trace, the captured config copy, and the
/// adjusted config end up.
pub fn stop_audit_logging(
    logger: &mut Logger,
    config_path: Option<&str>,
    log_dir: Option<&str>,
    adjusted_config_path: Option<&str>,
) {
    let script = script_path(STOP_SCRIPT);
    let mut cmd = std::process::Command::new("pwsh.exe");
    cmd.arg("-File")
        .arg(&script)
        .arg("-ConfigPath")
        .arg(config_path.unwrap_or_default());
    if let Some(dir) = log_dir {
        cmd.arg("-LogDir").arg(dir);
    }
    if let Some(adjusted) = adjusted_config_path {
        cmd.arg("-AdjustedConfigPath").arg(adjusted);
    }

    match cmd.status() {
        Ok(status) => {
            let _ = writeln!(logger, "stop_plm_logging.ps1 stop exited with {}", status);
        }
        Err(e) => {
            let _ = writeln!(logger, "Failed to stop stop_plm_logging.ps1: {}", e);
        }
    }
}
