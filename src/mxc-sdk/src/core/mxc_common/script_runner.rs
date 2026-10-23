// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::mxc_common::logger::Logger;
use crate::mxc_common::models::{ExecutionRequest, ScriptResponse};
use crate::mxc_common::mxc_error::MxcError;
use crate::mxc_common::validator::{
    validate_common, validate_network_policy_support, NetworkPolicySupport,
};

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
        validate_network_policy_support(request, NetworkPolicySupport::default())?;
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

/// The one-line dry-run verdict, including the rejection reason when there is
/// one.
fn dry_run_summary(response: &ScriptResponse) -> String {
    if response.exit_code == 0 {
        return "Dry run completed. Result: validation passed".to_string();
    }
    if response.error_message.is_empty() {
        return "Dry run completed. Result: validation failed".to_string();
    }
    format!(
        "Dry run completed. Result: validation failed: {}",
        response.error_message
    )
}

/// Print a dry-run result message to the logger, flush, and exit the process.
/// A failed dry run also emits its typed error envelope on stderr.
pub fn handle_dry_run_exit(response: &ScriptResponse, logger: &mut Logger) -> ! {
    use std::fmt::Write;
    let _ = writeln!(logger, "{}", dry_run_summary(response));
    print!("{}", logger.get_buffer());
    emit_backend_error_envelope(response);
    std::process::exit(response.exit_code);
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
/// In non-debug mode the diagnostic `Logger` is buffered and never flushed, so
/// this envelope is the only place the error surfaces to the caller.
///
/// The `code` comes from the response's
/// [`FailurePhase`](crate::mxc_common::models::FailurePhase), so a refused policy is
/// reported as `policy_validation` and a host that cannot provide the backend
/// as `backend_unavailable`, rather than both being flattened into the generic
/// `backend_error` every other failure uses. The envelope starts on a fresh line
/// because the workload's stderr may not end in a newline.
pub fn emit_backend_error_envelope(response: &ScriptResponse) {
    if let Some(line) = backend_error_envelope_line(response) {
        eprintln!("\n{line}");
    }
}

/// The stderr line [`emit_backend_error_envelope`] writes, if any.
fn backend_error_envelope_line(response: &ScriptResponse) -> Option<String> {
    if response.exit_code == 0 || response.error_message.is_empty() {
        return None;
    }

    let mut envelope = serde_json::json!({
        "error": {
            "code": response.failure_phase.error_code().as_str(),
            "message": response.error_message,
        }
    });
    if !response.extended_error.is_empty() {
        envelope["error"]["extended_error"] =
            serde_json::Value::String(response.extended_error.clone());
    }
    serde_json::to_string(&envelope).ok()
}

/// The stderr lines a run's warnings are emitted as, one JSON object each.
///
/// Kept separate from [`emit_warning_envelopes`] so the exact bytes a caller
/// has to parse are testable without capturing the process's stderr.
fn warning_envelope_lines(warnings: &[String]) -> Vec<String> {
    warnings
        .iter()
        .filter(|warning| !warning.trim().is_empty())
        .filter_map(|warning| {
            serde_json::to_string(&serde_json::json!({ "warning": { "message": warning } })).ok()
        })
        .collect()
}

/// Emit each warning as its own structured JSON line on stderr.
///
/// Warnings are reported on success as well as on failure, so this is separate
/// from [`emit_backend_error_envelope`] rather than folded into it. One object
/// per line keeps the stream parseable a line at a time, matching the error
/// envelope. The batch starts on a fresh line because the workload's stderr may
/// not end in a newline.
pub fn emit_warning_envelopes(warnings: &[String]) {
    let lines = warning_envelope_lines(warnings);
    if !lines.is_empty() {
        eprintln!("\n{}", lines.join("\n"));
    }
}

/// Emit a typed JSON error envelope on stderr for a failure raised before any
/// [`ScriptResponse`] exists, then exit with the status its code implies.
///
/// Shared by every executor entry point. Without it such a failure prints a
/// bare line and exits 1, which a caller cannot tell from a typed policy
/// rejection.
pub fn emit_mxc_error_exit(error: &MxcError) -> ! {
    eprintln!("{}", error.to_envelope_string());
    std::process::exit(error.code.exit_code());
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
        use crate::mxc_common::models::ScriptResponse;
        // exit 0 => no-op; non-zero but empty message (clean sandbox exit) => no-op.
        assert!(super::backend_error_envelope_line(&ScriptResponse {
            exit_code: 0,
            error_message: "ignored on success".to_string(),
            ..Default::default()
        })
        .is_none());
        assert!(super::backend_error_envelope_line(&ScriptResponse {
            exit_code: 1,
            error_message: String::new(),
            ..Default::default()
        })
        .is_none());
    }

    #[test]
    fn error_envelope_carries_the_code_for_each_failure_kind() {
        use crate::mxc_common::models::ScriptResponse;
        let cases = [
            (ScriptResponse::rejected("refused"), "policy_validation"),
            (
                ScriptResponse::unavailable("missing"),
                "backend_unavailable",
            ),
            (ScriptResponse::error("broke"), "backend_error"),
        ];
        for (response, code) in cases {
            let line = super::backend_error_envelope_line(&response).expect(code);
            let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(parsed["error"]["code"], code, "{line}");
            assert_eq!(parsed["error"]["message"], response.error_message);
        }
    }

    #[test]
    fn error_envelope_includes_extended_error_when_present() {
        use crate::mxc_common::models::ScriptResponse;
        let line = super::backend_error_envelope_line(&ScriptResponse {
            extended_error: "WIN32_ERROR(1920)".to_string(),
            ..ScriptResponse::unavailable("backend unavailable")
        })
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["error"]["extended_error"], "WIN32_ERROR(1920)");
    }

    #[test]
    fn warning_lines_are_one_parseable_object_each() {
        let lines = super::warning_envelope_lines(&[
            "dacl augmentation fell back".to_string(),
            "quoted \"name\" and \\ backslash".to_string(),
        ]);

        assert_eq!(
            lines[0],
            r#"{"warning":{"message":"dacl augmentation fell back"}}"#
        );
        // A warning is free-form text, so it has to survive JSON escaping.
        let parsed: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
        assert_eq!(
            parsed["warning"]["message"],
            "quoted \"name\" and \\ backslash"
        );
    }

    #[test]
    fn blank_warnings_do_not_reach_the_stream() {
        assert!(super::warning_envelope_lines(&[String::new(), "   ".to_string()]).is_empty());
    }

    #[test]
    fn dry_run_summary_reports_why_validation_failed() {
        use crate::mxc_common::models::ScriptResponse;
        let summary = super::dry_run_summary(&ScriptResponse::rejected(
            "network.egress allow/deny rules are not supported by the selected backend",
        ));
        assert_eq!(
            summary,
            "Dry run completed. Result: validation failed: \
             network.egress allow/deny rules are not supported by the selected backend"
        );
    }

    #[test]
    fn dry_run_summary_keeps_the_bare_verdicts() {
        use crate::mxc_common::models::ScriptResponse;
        assert_eq!(
            super::dry_run_summary(&ScriptResponse {
                exit_code: 0,
                ..Default::default()
            }),
            "Dry run completed. Result: validation passed"
        );
        // A refusal that carried no message must not grow a dangling colon.
        assert_eq!(
            super::dry_run_summary(&ScriptResponse {
                exit_code: 1,
                error_message: String::new(),
                ..Default::default()
            }),
            "Dry run completed. Result: validation failed"
        );
    }
}
