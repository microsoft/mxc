// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `SeatbeltScriptRunner` — executes scripts inside Apple's Seatbelt
//! sandbox via `/usr/bin/sandbox-exec`.
//!
//! It generates a TinyScheme profile from the [`CodexRequest`] using
//! [`crate::profile_builder::build_profile`], writes it to a tempfile in
//! `TMPDIR`, then spawns `sandbox-exec -f <profile> /bin/sh -c <script>`
//! through [`mxc_pty::run_with_pty`] so the inner shell sees a real TTY
//! and the host can stream its output as it arrives. The pty bridge is
//! the same one the LXC backend uses.
//!
//! Compiled only on macOS — the rest of the workspace continues to build
//! on Windows / Linux unchanged.

use std::fmt::Write as FmtWrite;
use std::io::Write as IoWrite;
use std::process::Command;
use std::time::Duration;

use mxc_pty::{run_with_pty, PtyOptions, PtyOutcome};
use wxc_common::logger::Logger;
use wxc_common::models::{CodexRequest, ScriptResponse};
use wxc_common::script_runner::ScriptRunner;

use crate::profile_builder::build_profile;

/// Path to the system-provided sandbox launcher. Present on every macOS
/// release (deprecated in headers since 10.7 but still shipped through
/// current versions).
const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// Default shell used to execute `script_code`. `/bin/sh` is guaranteed
/// to exist and is on the SIP-protected path so it's always reachable
/// from inside the sandbox.
const DEFAULT_SHELL: &str = "/bin/sh";

#[derive(Default)]
pub struct SeatbeltScriptRunner;

impl SeatbeltScriptRunner {
    pub fn new() -> Self {
        Self
    }
}

impl ScriptRunner for SeatbeltScriptRunner {
    fn validate_runner(&self, request: &CodexRequest) -> Result<(), ScriptResponse> {
        // Seatbelt cannot filter network by hostname — reject blockedHosts
        // rather than silently allowing traffic the user expects to be denied.
        if !request.policy.blocked_hosts.is_empty() {
            return Err(error_response(
                "macOS Seatbelt does not support per-host network filtering. \
                 'blockedHosts' cannot be enforced; remove it or use \
                 defaultPolicy: \"block\" to deny all network."
                    .to_string(),
            ));
        }

        // Reject timeouts that are too small for the pty bridge's poll
        // interval to enforce accurately.
        let poll_ms = PtyOptions::POLL_INTERVAL.as_millis() as u64;
        if request.script_timeout > 0 && u64::from(request.script_timeout) < poll_ms {
            return Err(error_response(format!(
                "scriptTimeout {}ms is below the minimum of {}ms",
                request.script_timeout, poll_ms
            )));
        }

        Ok(())
    }

    fn execute(&mut self, request: &CodexRequest, logger: &mut Logger) -> ScriptResponse {
        // 1. Build the Seatbelt profile from the policy.
        let profile = build_profile(request);

        // 2. Persist it to a tempfile so sandbox-exec can read it via -f.
        //    We use `tempfile::NamedTempFile` so the file is removed on drop
        //    even on panic.
        let mut profile_file = match tempfile::Builder::new()
            .prefix("mxc-seatbelt-")
            .suffix(".sb")
            .tempfile()
        {
            Ok(file) => file,
            Err(error) => {
                return error_response(format!("failed to create profile tempfile: {error}"))
            }
        };

        if let Err(error) = profile_file.write_all(profile.as_bytes()) {
            return error_response(format!("failed to write profile: {error}"));
        }
        if let Err(error) = profile_file.flush() {
            return error_response(format!("failed to flush profile: {error}"));
        }

        let profile_path = profile_file.path().to_path_buf();
        let _ = writeln!(
            logger,
            "Seatbelt: profile written to {}",
            profile_path.display()
        );

        // 3. Build `sandbox-exec -f <profile> /bin/sh -c <script>`.
        let mut command = Command::new(SANDBOX_EXEC);
        command
            .arg("-f")
            .arg(&profile_path)
            .arg(DEFAULT_SHELL)
            .arg("-c")
            .arg(&request.script_code);

        // Apply env if any was specified — otherwise inherit the parent
        // environment (matches LXC behaviour for empty env vectors).
        if !request.env.is_empty() {
            command.env_clear();
            for kv in &request.env {
                if let Some((key, value)) = kv.split_once('=') {
                    command.env(key, value);
                }
            }
        }

        if !request.working_directory.is_empty() {
            command.current_dir(&request.working_directory);
        }

        // 4. Hand off to the shared pty bridge. Seatbelt has no parent-side
        //    sigwait watchdog (unlike LXC's signal_cleanup), so no signals
        //    need unblocking in the child.
        let timeout = if request.script_timeout == 0 {
            None
        } else {
            Some(Duration::from_millis(u64::from(request.script_timeout)))
        };

        let options = PtyOptions {
            timeout,
            ..PtyOptions::default()
        };

        match run_with_pty(command, options) {
            Ok(PtyOutcome::Exited(status)) => ScriptResponse {
                exit_code: status.code().unwrap_or(-1),
                ..Default::default()
            },
            Ok(PtyOutcome::TimedOut) => {
                let msg = format!(
                    "Seatbelt: script timed out after {}ms",
                    request.script_timeout
                );
                let _ = writeln!(logger, "{msg}");
                error_response(msg)
            }
            Err(error) => error_response(format!(
                "failed to spawn {SANDBOX_EXEC}: {error}; ensure sandbox-exec exists"
            )),
        }
    }
}

fn error_response(message: String) -> ScriptResponse {
    ScriptResponse {
        error_message: message,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::models::{CodexRequest, SeatbeltConfig};

    fn base_request() -> CodexRequest {
        CodexRequest {
            experimental_enabled: true,
            experimental: wxc_common::models::ExperimentalConfig {
                seatbelt: Some(SeatbeltConfig::default()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn rejects_blocked_hosts() {
        let mut request = base_request();
        request.policy.blocked_hosts = vec!["evil.example.com".into()];
        let runner = SeatbeltScriptRunner::new();
        let response = runner.validate_runner(&request).unwrap_err();
        assert_eq!(response.exit_code, -1);
        assert!(response.error_message.contains("blockedHosts"));
        assert!(response.error_message.contains("cannot be enforced"));
    }
}
