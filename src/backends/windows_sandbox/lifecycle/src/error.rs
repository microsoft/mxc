// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Typed failure modes for the transient one-shot Windows Sandbox runner.
//!
//! Each variant carries a developer-facing detail string and maps to a
//! [`ScriptResponse`] with a user-facing `error_message` plus the raw detail
//! in `extended_error`. Keeping the variants distinct (rather than a single
//! opaque string) lets the orchestration code attribute a failure to a
//! specific lifecycle phase and lays the groundwork for richer typed wire
//! errors in the state-aware backend.

use wxc_common::models::{FailurePhase, ScriptResponse};

/// Failure modes of a single transient one-shot execution.
#[derive(Debug)]
pub(crate) enum OneShotError {
    /// `WindowsSandbox.exe` is not present (optional feature not installed).
    SandboxUnavailable(String),
    /// No usable host Python installation was found.
    PythonNotFound(String),
    /// A foreign Windows Sandbox VM is already running; refusing to start a
    /// disposable one (the host allows only a single running instance).
    Busy(String),
    /// The current-thread tokio runtime could not be created.
    RuntimeSetup(String),
    /// Preparing or launching the VM (`.wsb` generation / `WindowsSandbox.exe`)
    /// failed.
    Launch(String),
    /// The guest agent never published its rendezvous address in time.
    Rendezvous(String),
    /// The TCP channels to the guest agent could not be established.
    Connect(String),
    /// Relaying the execution over the guest channels failed.
    Exec(String),
}

impl OneShotError {
    /// Render this error as a [`ScriptResponse`]. The user-facing summary
    /// lands in both `standard_err` and `error_message`; the raw detail lands
    /// in `extended_error` for diagnostics.
    pub(crate) fn into_response(self) -> ScriptResponse {
        let (summary, detail): (&str, String) = match self {
            OneShotError::SandboxUnavailable(d) => (
                "Windows Sandbox is not available on this host. Enable the \
                 'Containers-DisposableClientVM' optional feature and reboot.",
                d,
            ),
            OneShotError::PythonNotFound(d) => (
                "Python is required on the host for Windows Sandbox execution; \
                 install Python and ensure python.exe is on PATH.",
                d,
            ),
            OneShotError::Busy(d) => (
                "Windows Sandbox is already running and was not started by a \
                 disposable MXC run. Refusing to start a one-shot sandbox \
                 (the host allows only one running instance). Close the \
                 existing sandbox and retry.",
                d,
            ),
            OneShotError::RuntimeSetup(d) => (
                "Failed to initialise the async runtime for Windows Sandbox.",
                d,
            ),
            OneShotError::Launch(d) => ("Failed to launch the Windows Sandbox VM.", d),
            OneShotError::Rendezvous(d) => (
                "Timed out waiting for the Windows Sandbox guest agent to start.",
                d,
            ),
            OneShotError::Connect(d) => {
                ("Failed to connect to the Windows Sandbox guest agent.", d)
            }
            OneShotError::Exec(d) => ("Execution inside the Windows Sandbox failed.", d),
        };

        ScriptResponse {
            exit_code: -1,
            standard_err: summary.to_string(),
            error_message: summary.to_string(),
            extended_error: detail,
            failure_phase: FailurePhase::LaunchFailed,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn busy_maps_to_launch_failed_with_detail() {
        let resp = OneShotError::Busy("vm already up".to_string()).into_response();
        assert_eq!(resp.exit_code, -1);
        assert_eq!(resp.failure_phase, FailurePhase::LaunchFailed);
        assert_eq!(resp.extended_error, "vm already up");
        assert!(!resp.error_message.is_empty());
    }

    #[test]
    fn rendezvous_detail_preserved_in_extended_error() {
        let resp = OneShotError::Rendezvous("timed out after 360s".to_string()).into_response();
        assert_eq!(resp.extended_error, "timed out after 360s");
        assert!(resp.error_message.contains("guest agent"));
    }
}
