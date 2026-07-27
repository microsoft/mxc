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
    SandboxUnavailable(String),
    Busy(String),
    RuntimeSetup(String),
    Launch(String),
    Policy(String),
    Exec(String),
}

impl OneShotError {
    /// Render this error as a [`ScriptResponse`]. The user-facing summary
    /// lands in both `standard_err` and `error_message`; the raw detail lands
    /// in `extended_error` for diagnostics.
    pub(crate) fn into_response(self) -> ScriptResponse {
        let failure_phase = self.failure_phase();
        let (summary, detail): (&str, String) = match self {
            OneShotError::SandboxUnavailable(d) => (
                "Windows Sandbox is not available on this host. Enable the \
                 'Containers-DisposableClientVM' optional feature and reboot.",
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
            OneShotError::Launch(d) => (
                "Failed to launch the Windows Sandbox VM or connect to the guest agent.",
                d,
            ),
            OneShotError::Policy(d) => (
                "The request's policy cannot be enforced by the Windows Sandbox \
                 backend.",
                d,
            ),
            OneShotError::Exec(d) => ("Execution inside the Windows Sandbox failed.", d),
        };

        ScriptResponse {
            exit_code: -1,
            standard_err: summary.to_string(),
            error_message: summary.to_string(),
            extended_error: detail,
            failure_phase,
            ..Default::default()
        }
    }

    /// Lifecycle phase this error is attributed to, so a caller can decide
    /// whether a retry could ever succeed.
    fn failure_phase(&self) -> FailurePhase {
        match self {
            // Non-retryable preflight: the request/config cannot be honored or a
            // required host prerequisite is missing. Retrying the same input on
            // the same host will not succeed.
            OneShotError::SandboxUnavailable(_) | OneShotError::Policy(_) => FailurePhase::Rejected,
            // Launch attempt failed (incl. transient single-instance contention,
            // async-runtime setup, capture-proof, rendezvous wait, and the
            // initial guest connect) — generally worth retrying.
            OneShotError::Busy(_) | OneShotError::RuntimeSetup(_) | OneShotError::Launch(_) => {
                FailurePhase::LaunchFailed
            }
            // The execution relay failed while running user code.
            OneShotError::Exec(_) => FailurePhase::PostLaunchFailed,
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
    fn policy_and_prereq_errors_map_to_rejected() {
        for err in [
            OneShotError::Policy("denied path in share".to_string()),
            OneShotError::SandboxUnavailable("feature off".to_string()),
        ] {
            let resp = err.into_response();
            assert_eq!(
                resp.failure_phase,
                FailurePhase::Rejected,
                "non-retryable preflight should map to Rejected"
            );
        }
    }

    #[test]
    fn launch_and_exec_errors_map_to_post_launch_phases() {
        // After `Rendezvous` / `Connect` merged into `Launch`, only Launch +
        // Exec remain as the post-pre-flight
        // failure categories. Launch -> retry-the-launch
        // (LaunchFailed); Exec -> the relay broke after a successful
        // launch (PostLaunchFailed).
        assert_eq!(
            OneShotError::Launch("rendezvous timed out after 360s".to_string())
                .into_response()
                .failure_phase,
            FailurePhase::LaunchFailed
        );
        assert_eq!(
            OneShotError::Exec("relay broke".to_string())
                .into_response()
                .failure_phase,
            FailurePhase::PostLaunchFailed
        );
    }

    #[test]
    fn launch_detail_preserved_in_extended_error() {
        let resp =
            OneShotError::Launch("rendezvous timed out after 360s".to_string()).into_response();
        assert_eq!(resp.extended_error, "rendezvous timed out after 360s");
        assert!(resp.error_message.contains("launch"));
    }
}
