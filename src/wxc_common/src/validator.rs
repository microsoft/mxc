// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::models::{CodexRequest, ScriptResponse};

/// Validates non-backend-specific parts of the request (e.g. non-empty script).
pub fn validate_common(request: &CodexRequest) -> Result<(), ScriptResponse> {
    if request.script_code.is_empty() {
        return Err(ScriptResponse::error("Script content must not be empty."));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_common;
    use crate::models::CodexRequest;

    #[test]
    fn rejects_empty_script() {
        let req = CodexRequest {
            script_code: String::new(),
            ..Default::default()
        };
        assert!(validate_common(&req).is_err());
    }

    #[test]
    fn accepts_valid_script() {
        let req = CodexRequest {
            script_code: "echo hello".to_string(),
            ..Default::default()
        };
        assert!(validate_common(&req).is_ok());
    }

    #[test]
    fn accepts_full_config() {
        let req = CodexRequest {
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
        let req = CodexRequest::default();
        let err = validate_common(&req).unwrap_err();
        assert!(
            err.error_message.contains("empty"),
            "Error should mention empty: {}",
            err.error_message
        );
    }
}
