// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Process settings shared by backends that run `process.commandLine` in a
//! Linux guest's POSIX shell and add caller environment entries to the
//! guest's default environment: the NVX MicroVM and ACI backends.

use crate::mxc_common::models::ExecutionRequest;
use crate::mxc_common::mxc_error::MxcError;

/// Longest workload timeout, one hour.
pub const MAX_TIMEOUT_MS: u32 = 3_600_000;
/// Longest guest working directory in UTF-8 bytes.
pub const MAX_CWD_BYTES: usize = 4095;
/// Most `process.env` entries, counting repeated names.
pub const MAX_ENVIRONMENT_ENTRIES: usize = 256;
/// Most `process.env` bytes, counting one terminator per entry.
pub const MAX_ENVIRONMENT_BYTES: usize = 32 * 1024;
/// Environment names that would redirect guest traffic through a proxy; use
/// `runtimeConfig.networkProxy` where a backend supports it.
pub const PROXY_ENVIRONMENT_KEYS: [&str; 4] =
    ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"];

/// Validates the command, working directory, timeout, and environment.
///
/// `backend` starts each error message, such as `NVX`.
pub fn validate_process(request: &ExecutionRequest, backend: &str) -> Result<(), MxcError> {
    if request.script_code.contains('\0') || request.working_directory.contains('\0') {
        return Err(MxcError::malformed_request(format!(
            "{backend} process.commandLine and process.cwd must not contain null bytes"
        )));
    }
    if request.script_timeout > MAX_TIMEOUT_MS {
        return Err(MxcError::policy_validation(format!(
            "{backend} process.timeout must not exceed 3600000 ms (one hour)"
        )));
    }
    if request
        .working_directory
        .split('/')
        .any(|component| component == "..")
    {
        return Err(MxcError::policy_validation(format!(
            "{backend} process.cwd must not contain '..' path components"
        )));
    }
    if !request.working_directory.is_empty() && !request.working_directory.starts_with('/') {
        return Err(MxcError::policy_validation(format!(
            "{backend} process.cwd must be an absolute POSIX guest path"
        )));
    }
    if request.working_directory.len() > MAX_CWD_BYTES {
        return Err(MxcError::policy_validation(format!(
            "{backend} process.cwd must not exceed 4095 UTF-8 bytes"
        )));
    }
    if let Some(environment) = &request.env {
        validate_environment(environment, request.inherit_default_env, backend)?;
    }
    Ok(())
}

fn validate_environment(
    environment: &[String],
    inherit_default_env: bool,
    backend: &str,
) -> Result<(), MxcError> {
    if !inherit_default_env {
        return Err(MxcError::policy_validation(format!(
            "{backend} process.env requires inheritDefaultEnv=true"
        )));
    }
    if environment.len() > MAX_ENVIRONMENT_ENTRIES {
        return Err(MxcError::policy_validation(format!(
            "{backend} process.env must not exceed 256 entries"
        )));
    }
    let bytes = environment
        .iter()
        .map(|entry| entry.len().saturating_add(1))
        .sum::<usize>();
    if bytes > MAX_ENVIRONMENT_BYTES {
        return Err(MxcError::policy_validation(format!(
            "{backend} process.env must not exceed 32 KiB"
        )));
    }
    for entry in environment {
        if entry.contains('\0') || entry.split_once('=').is_none_or(|(key, _)| key.is_empty()) {
            return Err(MxcError::malformed_request(format!(
                "{backend} process.env entries must be KEY=VALUE without null bytes"
            )));
        }
        let key = entry.split_once('=').map_or(entry.as_str(), |(key, _)| key);
        if PROXY_ENVIRONMENT_KEYS
            .iter()
            .any(|candidate| key.eq_ignore_ascii_case(candidate))
        {
            return Err(MxcError::policy_validation(format!(
                "{backend} rejects proxy environment variables; use runtimeConfig.networkProxy"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_common::mxc_error::MxcErrorCode;

    fn request() -> ExecutionRequest {
        ExecutionRequest {
            script_code: "echo ok".to_owned(),
            ..ExecutionRequest::default()
        }
    }

    fn assert_policy_error(request: &ExecutionRequest, text: &str) {
        let error = validate_process(request, "TEST").unwrap_err();
        assert_eq!(error.code, MxcErrorCode::PolicyValidation, "{error}");
        assert!(error.message.starts_with("TEST "), "{error}");
        assert!(error.message.contains(text), "{error}");
    }

    #[test]
    fn environment_entry_limit_counts_duplicates_and_preserves_absent_and_empty() {
        let mut request = request();
        assert!(validate_process(&request, "TEST").is_ok());
        request.env = Some(Vec::new());
        assert_policy_error(&request, "inheritDefaultEnv=true");
        request.inherit_default_env = true;
        assert!(validate_process(&request, "TEST").is_ok());
        request.env = Some(vec!["KEY=value".to_owned(); MAX_ENVIRONMENT_ENTRIES]);
        assert!(validate_process(&request, "TEST").is_ok());
        request.env.as_mut().unwrap().push("KEY=later".to_owned());
        assert_policy_error(&request, "must not exceed 256 entries");
    }

    #[test]
    fn cwd_limit_counts_utf8_bytes_instead_of_characters() {
        let mut request = request();
        for directory in [
            format!("/{}", "x".repeat(MAX_CWD_BYTES - 1)),
            format!("/{}", "\u{00e9}".repeat((MAX_CWD_BYTES - 1) / 2)),
        ] {
            assert_eq!(directory.len(), MAX_CWD_BYTES);
            request.working_directory = directory;
            assert!(validate_process(&request, "TEST").is_ok());
            request.working_directory.push('x');
            assert_policy_error(&request, "must not exceed 4095 UTF-8 bytes");
        }
    }

    #[test]
    fn validates_posix_cwd_and_exact_process_boundaries() {
        let mut request = request();
        request.script_timeout = MAX_TIMEOUT_MS;
        request.working_directory = "/tmp/./workspace".to_owned();
        request.env = Some(vec![format!(
            "KEY={}",
            "x".repeat(MAX_ENVIRONMENT_BYTES - 5)
        )]);
        request.inherit_default_env = true;
        assert!(validate_process(&request, "TEST").is_ok());

        request.script_timeout = MAX_TIMEOUT_MS + 1;
        assert_policy_error(&request, "one hour");
        request.script_timeout = 0;
        request.working_directory = "/work/../escape".to_owned();
        assert_policy_error(&request, "must not contain '..'");
        request.working_directory = "C:\\host".to_owned();
        assert_policy_error(&request, "absolute POSIX guest path");
        request.working_directory = "/tmp".to_owned();
        request.env = Some(vec![format!("KEY={}", "x".repeat(MAX_ENVIRONMENT_BYTES))]);
        assert_policy_error(&request, "must not exceed 32 KiB");
        for key in PROXY_ENVIRONMENT_KEYS {
            request.env = Some(vec![format!("{}=value", key.to_ascii_lowercase())]);
            assert_policy_error(&request, "proxy environment");
        }
        for entry in ["=missing-key", "MISSING_EQUALS", "KEY=a\0b"] {
            request.env = Some(vec![entry.to_owned()]);
            let error = validate_process(&request, "TEST").unwrap_err();
            assert_eq!(error.code, MxcErrorCode::MalformedRequest, "{entry:?}");
        }
        request.env = None;
        request.script_code.push('\0');
        assert_eq!(
            validate_process(&request, "TEST").unwrap_err().code,
            MxcErrorCode::MalformedRequest
        );
    }
}
