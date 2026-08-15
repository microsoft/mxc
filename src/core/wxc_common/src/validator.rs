// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::models::{ContainmentBackend, ExecutionRequest, ScriptResponse};
use crate::mxc_error::MxcError;

/// Validates non-backend-specific parts of the request (e.g. non-empty script).
pub fn validate_common(request: &ExecutionRequest) -> Result<(), ScriptResponse> {
    if request.script_code.is_empty() {
        return Err(ScriptResponse::error("Script content must not be empty."));
    }

    // `--wait-for-debugger` only has a pre-execution suspend point on the
    // `processcontainer` backend (and only the AppContainer tier of it — the
    // dispatcher/`BaseContainerRunner::validate` handle that narrower case).
    // Every other backend (Windows Sandbox, WSLC, IsolationSession,
    // Hyperlight, MicroVM, LXC, Bubblewrap, Seatbelt) would otherwise accept
    // the flag and silently run the workload immediately, defeating the
    // flag's contract. Enforced centrally so it applies uniformly to every
    // backend and every present/future one, rather than requiring each
    // runner to remember to check it.
    if request.wait_for_debugger && request.containment != ContainmentBackend::ProcessContainer {
        return Err(ScriptResponse::error(&format!(
            "--wait-for-debugger is only supported by the processcontainer backend \
             (AppContainer tier); {} provides no pre-execution suspend point.",
            request.containment.wire_name()
        )));
    }

    // Enforce the testing-only-features gate centrally so it applies uniformly
    // to all backends — every backend runs `validate_common` before executing.
    // Currently this gates `network.proxy.builtinTestServer` (a deliberately-
    // permissive test proxy); see `ExecutionRequest::testing_features_enabled`
    // for the rationale behind the dedicated `--allow-testing-features` axis.
    if request.policy.network_proxy.builtin_test_server && !request.testing_features_enabled {
        return Err(ScriptResponse::error(
            "network.proxy.builtinTestServer is a testing-only feature and requires the \
             --allow-testing-features flag. For production, point network.proxy at a real \
             HTTP proxy via 'localhost' or 'url'.",
        ));
    }

    Ok(())
}

/// Cross-backend invariants for state-aware `exec`. The dispatcher calls this
/// before the backend's own `validate_exec` hook. Only the exec phase has a
/// common-check today (a non-empty `process.commandLine`).
pub fn validate_exec_common(request: &ExecutionRequest) -> Result<(), MxcError> {
    if request.script_code.is_empty() {
        return Err(MxcError::malformed_request(
            "exec phase requires a non-empty process.commandLine",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ExecutionRequest;
    use crate::mxc_error::MxcErrorCode;

    #[test]
    fn rejects_empty_script() {
        let req = ExecutionRequest {
            script_code: String::new(),
            ..Default::default()
        };
        assert!(validate_common(&req).is_err());
    }

    #[test]
    fn accepts_valid_script() {
        let req = ExecutionRequest {
            script_code: "echo hello".to_string(),
            ..Default::default()
        };
        assert!(validate_common(&req).is_ok());
    }

    #[test]
    fn accepts_full_config() {
        let req = ExecutionRequest {
            script_code: "print('test')".to_string(),
            working_directory: "C:\\temp".to_string(),
            script_timeout: 5000,
            container_id: "Test".to_string(),
            ..Default::default()
        };
        assert!(validate_common(&req).is_ok());
    }

    #[test]
    fn error_mentions_empty() {
        let req = ExecutionRequest::default();
        let err = validate_common(&req).unwrap_err();
        assert!(
            err.error_message.contains("empty"),
            "Error should mention empty: {}",
            err.error_message
        );
    }

    #[test]
    fn validate_exec_common_rejects_empty_command_line() {
        let req = ExecutionRequest::default();
        let err = validate_exec_common(&req).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedRequest);
    }

    #[test]
    fn validate_exec_common_accepts_non_empty_command_line() {
        let req = ExecutionRequest {
            script_code: "echo hello".to_string(),
            ..Default::default()
        };
        assert!(validate_exec_common(&req).is_ok());
    }

    #[test]
    fn rejects_builtin_test_server_without_testing_features() {
        let mut req = ExecutionRequest {
            script_code: "echo hi".to_string(),
            ..Default::default()
        };
        req.policy.network_proxy.builtin_test_server = true;
        req.testing_features_enabled = false;

        let err = validate_common(&req).unwrap_err();
        assert!(
            err.error_message.contains("builtinTestServer")
                && err.error_message.contains("--allow-testing-features"),
            "expected testing-gate error, got: {}",
            err.error_message
        );
    }

    #[test]
    fn accepts_builtin_test_server_with_testing_features() {
        let mut req = ExecutionRequest {
            script_code: "echo hi".to_string(),
            ..Default::default()
        };
        req.policy.network_proxy.builtin_test_server = true;
        req.testing_features_enabled = true;

        assert!(validate_common(&req).is_ok());
    }

    #[test]
    fn rejects_wait_for_debugger_on_non_processcontainer_backend() {
        let req = ExecutionRequest {
            script_code: "echo hi".to_string(),
            containment: crate::models::ContainmentBackend::Lxc,
            wait_for_debugger: true,
            ..Default::default()
        };
        let err = validate_common(&req).unwrap_err();
        assert!(
            err.error_message.contains("--wait-for-debugger") && err.error_message.contains("lxc"),
            "expected wait-for-debugger gate error, got: {}",
            err.error_message
        );
    }

    #[test]
    fn accepts_wait_for_debugger_on_processcontainer_backend() {
        let req = ExecutionRequest {
            script_code: "echo hi".to_string(),
            containment: crate::models::ContainmentBackend::ProcessContainer,
            wait_for_debugger: true,
            ..Default::default()
        };
        assert!(validate_common(&req).is_ok());
    }

    #[test]
    fn accepts_wait_for_debugger_false_on_any_backend() {
        let req = ExecutionRequest {
            script_code: "echo hi".to_string(),
            containment: crate::models::ContainmentBackend::Seatbelt,
            wait_for_debugger: false,
            ..Default::default()
        };
        assert!(validate_common(&req).is_ok());
    }
}
