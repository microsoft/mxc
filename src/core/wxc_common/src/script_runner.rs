// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::logger::Logger;
use crate::models::{ExecutionRequest, ScriptResponse};
use crate::validator::validate_common;

/// Trait for executing scripts within a containment backend.
///
/// Each backend (AppContainer, Windows Sandbox, etc.) implements this trait
/// to provide a uniform interface for `wxc-exec`.
///
/// Implementors provide [`execute`](ScriptRunner::execute) and optionally
/// [`validate`](ScriptRunner::validate). The provided
/// [`run`](ScriptRunner::run) method handles validation, dry-run mode,
/// and delegates to [`execute`](ScriptRunner::execute).
pub trait ScriptRunner {
    /// Validate the request before execution. Override to add
    /// runner-specific checks. Default accepts all requests.
    fn validate_runner(&self, _request: &ExecutionRequest) -> Result<(), ScriptResponse> {
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
    if response.exit_code == 0 || response.error_message.is_empty() {
        return;
    }

    let mut envelope = serde_json::json!({
        "error": {
            "code": "backend_error",
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
}
