// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::error::WxcError;
use crate::models::CodexRequest;

pub fn validate_request(request: &CodexRequest) -> Result<(), WxcError> {
    if request.script_code.is_empty() {
        return Err(WxcError::Validation(
            "Script content must not be empty.".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ContainerPolicy;

    #[test]
    fn validate_request_with_valid_script() {
        let req = CodexRequest {
            script_code: "echo hello".to_string(),
            ..Default::default()
        };
        assert!(validate_request(&req).is_ok());
    }

    #[test]
    fn validate_request_with_empty_script() {
        let req = CodexRequest {
            script_code: String::new(),
            ..Default::default()
        };
        assert!(validate_request(&req).is_err());
    }

    #[test]
    fn validate_request_with_full_config() {
        let req = CodexRequest {
            script_code: "print('test')".to_string(),
            working_directory: "C:\\temp".to_string(),
            script_timeout: 5000,
            policy: ContainerPolicy {
                app_container_name: "Test".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(validate_request(&req).is_ok());
    }

    #[test]
    fn validate_request_error_contains_message() {
        let req = CodexRequest::default();
        let err = validate_request(&req).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("empty"), "Error should mention empty: {}", msg);
    }
}
