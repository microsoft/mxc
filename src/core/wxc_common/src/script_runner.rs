// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::logger::Logger;
use crate::models::{ExecutionRequest, ScriptResponse};
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
pub fn handle_dry_run_exit(response: &ScriptResponse, logger: &mut Logger) -> ! {
    use std::fmt::Write;
    if response.exit_code == 0 {
        let _ = writeln!(logger, "Dry run completed. Result: validation passed");
    } else {
        let _ = writeln!(logger, "Dry run completed. Result: validation failed");
    }
    print!("{}", logger.get_buffer());
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
pub fn emit_backend_error_envelope(response: &ScriptResponse) {
    if let Some(record) = backend_error_record(response, false) {
        eprint!("{record}");
    }
}

/// Emit requested policy diagnostics with a boundary after unterminated output.
/// Requests without the new controls retain the legacy framing.
pub fn emit_backend_error_envelope_for_request(
    response: &ScriptResponse,
    request: &ExecutionRequest,
) {
    if let Some(record) =
        backend_error_record(response, request.policy.policy_enforcement.is_some())
    {
        eprint!("{record}");
    }
}

fn backend_error_record(response: &ScriptResponse, separate: bool) -> Option<String> {
    if response.exit_code == 0 || response.error_message.is_empty() {
        return None;
    }

    let mut envelope = if let Some(error) = &response.error {
        serde_json::json!({ "error": error })
    } else {
        serde_json::json!({
        "error": {
            "code": "backend_error",
            "message": response.error_message,
        }
        })
    };
    if !response.extended_error.is_empty() {
        envelope["error"]["extended_error"] =
            serde_json::Value::String(response.extended_error.clone());
    }
    if let Some(report) = response
        .output_metadata
        .as_ref()
        .and_then(|metadata| metadata.policy_enforcement.as_ref())
    {
        envelope["error"]["details"]["policyEnforcement"] = serde_json::json!(report);
    }
    Some(stderr_json_record(&envelope.to_string(), separate))
}

/// Emit one already-serialized JSON record, preserving its key order.
///
/// `separate` adds a boundary before new diagnostics because inherited child
/// stderr may not end in a newline. Legacy callers retain their original bytes.
pub fn emit_stderr_json_record(json: &str, separate: bool) {
    eprint!("{}", stderr_json_record(json, separate));
}

fn stderr_json_record(json: &str, separate: bool) -> String {
    let prefix = if separate { "\n" } else { "" };
    format!("{prefix}{json}\n")
}

#[cfg(test)]
mod tests {
    use super::get_timeout_milliseconds;

    #[test]
    fn stderr_json_framing_separates_unterminated_text_from_the_record() {
        let record = serde_json::json!({
            "error": {
                "code": "policy_validation",
                "message": "first line\nsecond line",
            }
        })
        .to_string();
        for prefix in [
            "",
            "policy refused",
            "policy refused\n",
            "policy refused\r\n",
        ] {
            let output = format!("{prefix}{}", super::stderr_json_record(&record, true));
            let json_lines: Vec<_> = output
                .lines()
                .filter(|line| line.starts_with('{'))
                .collect();
            assert_eq!(json_lines.len(), 1);
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(json_lines[0]).unwrap(),
                serde_json::from_str::<serde_json::Value>(&record).unwrap()
            );
            assert!(output.ends_with('\n'));
            assert!(!output.contains("policy refused{"));
        }
    }

    #[test]
    fn stderr_json_framing_keeps_metadata_records_independently_parseable() {
        let capture = serde_json::json!({
            "type": "captureDenials", "outputPath": "capture.json",
        });
        let policy = serde_json::json!({
            "type": "policyEnforcement", "report": { "termination": "created" },
        });
        let output = format!(
            "unterminated child stderr{}{}",
            super::stderr_json_record(&capture.to_string(), true),
            super::stderr_json_record(&policy.to_string(), true),
        );
        let records: Vec<serde_json::Value> = output
            .lines()
            .filter(|line| line.starts_with('{'))
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records, [capture, policy]);
    }

    #[test]
    fn legacy_stderr_json_framing_preserves_exact_bytes() {
        let response = crate::models::ScriptResponse::error("legacy failure");
        let expected = "{\"error\":{\"code\":\"backend_error\",\"message\":\"legacy failure\"}}\n";
        assert_eq!(
            super::backend_error_record(&response, false).as_deref(),
            Some(expected)
        );
        assert_eq!(
            super::backend_error_record(&response, true).as_deref(),
            Some(format!("\n{expected}").as_str())
        );
        for prefix in ["", "unterminated", "terminated\n", "terminated\r\n"] {
            assert_eq!(
                format!(
                    "{prefix}{}",
                    super::stderr_json_record("{\"record\":1}", false)
                ),
                format!("{prefix}{{\"record\":1}}\n")
            );
        }
    }

    #[test]
    fn legacy_capture_json_preserves_struct_field_order() {
        let pointer = crate::models::CaptureDenialsOutput {
            kind: crate::models::CaptureDenialsOutput::KIND.into(),
            output_path: "capture.json".into(),
            exit_code: 0,
            total_denials: 1,
            denied_resources_truncated: false,
            etl_path: None,
        };
        let json = serde_json::to_string(&pointer).unwrap();
        assert_eq!(
            super::stderr_json_record(&json, false),
            "{\"type\":\"captureDenials\",\"outputPath\":\"capture.json\",\"exitCode\":0,\"totalDenials\":1,\"deniedResourcesTruncated\":false}\n"
        );
        assert_eq!(
            super::stderr_json_record(&json, true),
            format!("\n{json}\n")
        );
    }

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
}
