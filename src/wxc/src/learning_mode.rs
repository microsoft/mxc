// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Audit-mode helpers that drive the PowerShell PLM logging scripts in
//! `src/learning_mode/`. These are invoked when the user passes `--audit`
//! to `wxc-exec`.

use std::fmt::Write;

use wxc_common::logger::Logger;

const START_SCRIPT: &str = ".\\start_plm_logging.ps1";
const STOP_SCRIPT: &str = ".\\stop_plm_logging.ps1";

/// Invoke `start_plm_logging.ps1` to begin an ACP profiling session.
pub fn start_audit_logging(logger: &mut Logger) {
    match std::process::Command::new("pwsh.exe")
        .args(["-command", START_SCRIPT])
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
pub fn stop_audit_logging(logger: &mut Logger, config_path: Option<&str>) {
    match std::process::Command::new("pwsh.exe")
        .args([
            "-command",
            STOP_SCRIPT,
            "-ConfigPath",
            config_path.unwrap_or_default(),
        ])
        .status()
    {
        Ok(status) => {
            let _ = writeln!(logger, "stop_plm_logging.ps1 stop exited with {}", status);
        }
        Err(e) => {
            let _ = writeln!(logger, "Failed to stop stop_plm_logging.ps1: {}", e);
        }
    }
}
