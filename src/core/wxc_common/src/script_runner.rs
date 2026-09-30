// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::logger::Logger;
use crate::models::{ExecutionRequest, FailurePhase, ScriptResponse};
use crate::mxc_error::{MxcError, ResponseEnvelope};
use crate::validator::{validate_common, validate_network_policy_support, NetworkPolicySupport};

/// Trait for executing scripts within a containment backend.
///
/// Each backend (AppContainer, Windows Sandbox, etc.) implements this trait
/// to provide a uniform interface for `wxc-exec`.
///
/// Implementors provide [`execute`](ScriptRunner::execute) and optionally
/// [`validate_runner`](ScriptRunner::validate_runner). The provided
/// [`run`](ScriptRunner::run) method handles validation, dry-run mode,
/// and delegates to [`execute`](ScriptRunner::execute).
pub trait ScriptRunner {
    /// Validate shared network support and runner-specific constraints.
    fn validate_runner(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        validate_network_policy_support(request, NetworkPolicySupport::LEGACY)?;
        Ok(())
    }

    /// Execute the script inside this backend's containment and return the response.
    /// Implement this instead of `run` — validation and dry-run are handled by the trait.
    fn execute(&mut self, request: &ExecutionRequest, logger: &mut Logger) -> ScriptResponse;

    /// Entry point called by the binary. Runs shared validation, runner-specific
    /// validation, checks for dry-run mode, then delegates to
    /// [`execute`](ScriptRunner::execute).
    fn run(&mut self, request: &ExecutionRequest, logger: &mut Logger) -> ScriptResponse {
        if let Err(response) = validate_common(request) {
            return response;
        }

        if let Err(response) = self.validate_runner(request) {
            return response;
        }

        if request.dry_run {
            return ScriptResponse {
                exit_code: 0,
                ..Default::default()
            };
        }

        self.execute(request, logger)
    }
}

/// Convert a timeout value to milliseconds, treating 0 as infinite (INFINITE = `u32::MAX`).
pub fn get_timeout_milliseconds(timeout: u32) -> u32 {
    if timeout == 0 {
        u32::MAX
    } else {
        timeout
    }
}

/// Print a dry-run result message to the logger, flush, and exit the process.
///
/// A dry run ends here, before the caller's normal relay path, so the
/// rejection reason and its envelope are emitted here too — validation itself
/// writes neither to the logger. Both helpers are no-ops for a dry run that
/// passed.
pub fn handle_dry_run_exit(response: &ScriptResponse, logger: &mut Logger) -> ! {
    use std::fmt::Write;
    if response.exit_code == 0 {
        let _ = writeln!(logger, "Dry run completed. Result: validation passed");
    } else {
        let _ = writeln!(logger, "Dry run completed. Result: validation failed");
    }
    print!("{}", logger.get_buffer());
    emit_captured_stderr(response);
    emit_backend_error_envelope(response);
    std::process::exit(process_exit_code(response));
}

/// Process exit code for a completed run.
///
/// A rejected request exits 1, matching a parser-side rejection, so a caller
/// can tell a refused policy from an MXC-side launch, lifecycle or timeout
/// failure — all of which report -1. Every other phase keeps the runner's own
/// exit code, including a faithfully propagated guest code.
///
/// A rejection built in-process already carries that code; the mapping also
/// covers a response decoded from a peer that did not.
pub fn process_exit_code(response: &ScriptResponse) -> i32 {
    match response.failure_phase {
        FailurePhase::Rejected => FailurePhase::Rejected.mxc_exit_code(),
        _ => response.exit_code,
    }
}

/// Whether [`emit_backend_error_envelope`] will emit for this response.
fn envelope_applies(response: &ScriptResponse) -> bool {
    response.exit_code != 0 && !response.error_message.is_empty()
}

/// Whether the workload itself ran, so `standard_err` holds its output rather
/// than a copy of an MXC error message.
fn workload_ran(phase: FailurePhase) -> bool {
    matches!(phase, FailurePhase::ProcessExited | FailurePhase::Timeout)
}

/// The captured stderr to relay for a completed run, paired with whether a
/// terminating newline still has to be written so that the diagnostic
/// [`emit_backend_error_envelope`] prints next starts on its own line. `None`
/// when there is nothing to relay.
///
/// Borrows `standard_err` rather than copying it: captured workload output is
/// unbounded and every executor binary relays it through here. When no
/// diagnostic follows, the workload's bytes are relayed exactly as captured —
/// partial progress output must not gain a newline it never wrote.
///
/// A response for a workload that never ran copies `error_message` into
/// `standard_err`; the envelope already carries that text, so it is not
/// printed a second time. A workload that did run keeps its stderr even when a
/// backend mirrors it into `error_message`.
fn captured_stderr_to_emit(response: &ScriptResponse) -> Option<(&str, bool)> {
    let envelope_follows = envelope_applies(response);
    let duplicates_envelope = !workload_ran(response.failure_phase)
        && envelope_follows
        && response.standard_err == response.error_message;
    if response.standard_err.is_empty() || duplicates_envelope {
        return None;
    }
    let text = response.standard_err.as_str();
    Some((text, envelope_follows && !text.ends_with('\n')))
}

/// Relay a completed run's captured stderr.
pub fn emit_captured_stderr(response: &ScriptResponse) {
    match captured_stderr_to_emit(response) {
        Some((text, true)) => eprintln!("{text}"),
        Some((text, false)) => eprint!("{text}"),
        None => {}
    }
}

/// Emit a structured JSON error envelope for a failure raised *before* any run
/// produced a [`ScriptResponse`], then exit with the code it maps to.
///
/// Backend selection fails before a response exists, so the typed
/// [`MxcErrorCode`] the engine already carries is the only classification
/// available. Preserving it keeps an unusable host (`backend_unavailable`,
/// exit -1) distinguishable from a request the caller must change
/// (`policy_validation` / `unsupported_containment` / `malformed_request`,
/// exit 1) — the same contract [`emit_backend_error_envelope`] applies once a
/// response exists.
///
/// The buffered diagnostics go to stdout, as [`handle_dry_run_exit`] does, so
/// that stderr carries the envelope alone and stays machine-parseable.
pub fn emit_mxc_error_exit(error: &MxcError, logger: &mut Logger) -> ! {
    print!("{}", logger.get_buffer());
    if let Ok(json) = serde_json::to_string(&ResponseEnvelope::<()>::from_error(error)) {
        eprintln!("{json}");
    }
    std::process::exit(error.code.mxc_exit_code());
}

/// Emit a structured JSON error envelope on stderr when a completed run carries
/// an infrastructure error message.
///
/// Shared by `wxc-exec` and `lxc-exec` so that MXC never exits non-zero on an
/// infrastructure failure without first printing a machine-readable diagnostic
/// (see issue #564). This deliberately keys off a **non-empty**
/// `error_message`: a sandboxed process that merely exits non-zero on its own
/// (a faithfully propagated guest exit code, no MXC error) leaves
/// `error_message` empty and is intentionally not annotated here.
///
/// The code is derived from the response's [`FailurePhase`], so a backend
/// rejection is reported as `policy_validation` — the same typed code a
/// parser-side rejection produces.
///
/// In non-debug mode the diagnostic `Logger` is buffered and never flushed, so
/// this envelope is the only place the error surfaces to the caller.
pub fn emit_backend_error_envelope(response: &ScriptResponse) {
    if !envelope_applies(response) {
        return;
    }

    let mut envelope = serde_json::json!({
        "error": {
            "code": response.wire_error_code().as_str(),
            "message": response.error_message,
        }
    });
    if !response.extended_error.is_empty() {
        envelope["error"]["extended_error"] =
            serde_json::Value::String(response.extended_error.clone());
    }
    if let Ok(json) = serde_json::to_string(&envelope) {
        eprintln!("{json}");
    }
}

#[cfg(test)]
mod tests {
    use super::get_timeout_milliseconds;

    #[test]
    fn timeout_zero_returns_u32_max() {
        let result = get_timeout_milliseconds(0);
        assert_eq!(result, u32::MAX);
    }

    #[test]
    fn timeout_non_zero_returns_same_value() {
        let value = 1500u32;
        let result = get_timeout_milliseconds(value);
        assert_eq!(result, value);
    }

    #[test]
    fn error_envelope_is_noop_without_error() {
        use crate::models::ScriptResponse;
        // exit 0 => no-op; non-zero but empty message (clean sandbox exit) => no-op.
        super::emit_backend_error_envelope(&ScriptResponse {
            exit_code: 0,
            error_message: "ignored on success".to_string(),
            ..Default::default()
        });
        super::emit_backend_error_envelope(&ScriptResponse {
            exit_code: 1,
            error_message: String::new(),
            ..Default::default()
        });
    }

    #[test]
    fn error_envelope_emits_on_infra_failure() {
        use crate::models::ScriptResponse;
        // Exercises the serialization branch (writes to stderr); must not panic.
        super::emit_backend_error_envelope(&ScriptResponse {
            exit_code: 1,
            error_message: "backend unavailable".to_string(),
            extended_error: "WIN32_ERROR(1920)".to_string(),
            ..Default::default()
        });
    }

    #[test]
    fn failure_phase_selects_the_envelope_code() {
        use crate::models::FailurePhase;
        use crate::mxc_error::MxcErrorCode;

        assert_eq!(
            FailurePhase::Rejected.error_code(),
            MxcErrorCode::PolicyValidation
        );
        assert_eq!(
            FailurePhase::BackendUnavailable.error_code(),
            MxcErrorCode::BackendUnavailable
        );
        for phase in [
            FailurePhase::None,
            FailurePhase::LaunchFailed,
            FailurePhase::PostLaunchFailed,
            FailurePhase::ProcessExited,
            FailurePhase::Timeout,
        ] {
            assert_eq!(phase.error_code(), MxcErrorCode::BackendError, "{phase:?}");
        }
    }

    #[test]
    fn an_explicit_code_outranks_the_phase_it_was_built_from() {
        use crate::models::{FailurePhase, ScriptResponse};
        use crate::mxc_error::MxcErrorCode;

        // A malformed request is refused like a policy failure — exit 1 — but
        // names itself precisely, matching the state-aware surface.
        let malformed = ScriptResponse::malformed("Script content must not be empty.");
        assert_eq!(malformed.failure_phase, FailurePhase::Rejected);
        assert_eq!(super::process_exit_code(&malformed), 1);
        assert_eq!(malformed.wire_error_code(), MxcErrorCode::MalformedRequest);

        // Without an override the phase still decides.
        assert_eq!(
            ScriptResponse::rejected("unsupported policy").wire_error_code(),
            MxcErrorCode::PolicyValidation
        );
    }

    #[test]
    fn a_rejection_exits_one_and_every_other_failure_keeps_its_code() {
        use crate::models::{FailurePhase, ScriptResponse};

        assert_eq!(
            super::process_exit_code(&ScriptResponse::rejected("unsupported policy")),
            1
        );
        // -1 is an MXC-side launch, lifecycle or timeout failure, so a caller
        // that sees 1 knows the request itself was refused.
        for phase in [FailurePhase::LaunchFailed, FailurePhase::Timeout] {
            assert_eq!(
                super::process_exit_code(&ScriptResponse {
                    failure_phase: phase,
                    ..ScriptResponse::error("boom")
                }),
                -1
            );
        }
        assert_eq!(
            super::process_exit_code(&ScriptResponse {
                exit_code: 3,
                failure_phase: FailurePhase::ProcessExited,
                ..Default::default()
            }),
            3
        );
    }

    #[test]
    fn captured_stderr_skips_the_copy_the_envelope_carries() {
        use crate::models::ScriptResponse;

        // A rejection duplicates its message into `standard_err`; the envelope
        // is the machine-readable copy, so nothing is relayed bare here.
        assert_eq!(
            super::captured_stderr_to_emit(&ScriptResponse::rejected("unsupported policy")),
            None
        );
        // Real workload stderr is relayed even when an MXC error is also set.
        assert_eq!(
            super::captured_stderr_to_emit(&ScriptResponse {
                exit_code: -1,
                standard_err: "workload wrote this".to_string(),
                error_message: "script timed out after 2000ms".to_string(),
                ..Default::default()
            })
            .map(|(text, newline)| (text.to_string(), newline)),
            Some(("workload wrote this".to_string(), true))
        );
    }

    #[test]
    fn a_workload_that_ran_keeps_stderr_mirrored_into_the_error_message() {
        use crate::models::{FailurePhase, ScriptResponse};

        // Windows Sandbox mirrors a non-zero guest's stderr into
        // `error_message`; the guest's own output must still reach the caller.
        for phase in [FailurePhase::ProcessExited, FailurePhase::Timeout] {
            assert_eq!(
                super::captured_stderr_to_emit(&ScriptResponse {
                    exit_code: 42,
                    standard_err: "boom".to_string(),
                    error_message: "boom".to_string(),
                    failure_phase: phase,
                    ..Default::default()
                })
                .map(|(text, newline)| (text.to_string(), newline)),
                Some(("boom".to_string(), true)),
                "{phase:?}"
            );
        }
    }

    #[test]
    fn a_terminating_newline_is_added_only_when_a_diagnostic_follows() {
        use crate::models::{FailurePhase, ScriptResponse};

        let relayed = |stderr: &str, error_message: &str| {
            super::captured_stderr_to_emit(&ScriptResponse {
                exit_code: 1,
                standard_err: stderr.to_string(),
                error_message: error_message.to_string(),
                failure_phase: FailurePhase::ProcessExited,
                ..Default::default()
            })
            .map(|(text, newline)| (text.to_string(), newline))
        };
        // No envelope follows, so the workload's bytes are relayed exactly as
        // captured — unterminated progress output must not gain a newline.
        assert_eq!(
            relayed("progress", ""),
            Some(("progress".to_string(), false))
        );
        assert_eq!(relayed("line\n", ""), Some(("line\n".to_string(), false)));
        // An envelope follows, so it must start on its own line.
        assert_eq!(
            relayed("progress", "boom"),
            Some(("progress".to_string(), true))
        );
        // Already terminated, so no second newline is added.
        assert_eq!(
            relayed("line\n", "boom"),
            Some(("line\n".to_string(), false))
        );
        assert_eq!(relayed("", "boom"), None);
    }
}
