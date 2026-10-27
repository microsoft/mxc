// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::mxc_common::models::ExecutionRequest;
use crate::mxc_common::mxc_error::MxcError;

const MAX_TIMEOUT_MS: u32 = 3_600_000;
const MAX_ENVIRONMENT_BYTES: usize = 32 * 1024;
const MAX_ENVIRONMENT_ENTRIES: usize = 256;
const MAX_CWD_BYTES: usize = 4095;
const PROXY_ENVIRONMENT_KEYS: [&str; 4] = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"];

pub(super) fn validate_request(request: &ExecutionRequest) -> Result<(), MxcError> {
    if !request.lifecycle.destroy_on_exit {
        return Err(MxcError::policy_validation(
            "NVX requires lifecycle.destroyOnExit=true",
        ));
    }
    if request.lifecycle.preserve_policy {
        return Err(MxcError::policy_validation(
            "NVX requires lifecycle.preservePolicy=false",
        ));
    }
    if !request.policy.readonly_paths.is_empty()
        || !request.policy.readwrite_paths.is_empty()
        || !request.policy.enumerate_paths.is_empty()
        || !request.policy.denied_paths.is_empty()
    {
        return Err(MxcError::policy_validation(
            "NVX does not support filesystem policy",
        ));
    }
    if request.policy.network_specified
        || request.policy.runtime_network_proxy_specified
        || request.policy.network_proxy.is_enabled()
    {
        return Err(MxcError::policy_validation(
            "NVX does not support network policy or proxy configuration",
        ));
    }
    if request.policy.ui_specified {
        return Err(MxcError::policy_validation(
            "NVX does not support UI policy",
        ));
    }
    if request.policy.capture_denials.is_some() {
        return Err(MxcError::policy_validation(
            "NVX does not support processContainer.captureDenials",
        ));
    }
    validate_process(request)
}

fn validate_process(request: &ExecutionRequest) -> Result<(), MxcError> {
    if request.script_code.contains('\0') || request.working_directory.contains('\0') {
        return Err(MxcError::malformed_request(
            "NVX process.commandLine and process.cwd must not contain null bytes",
        ));
    }
    if request.script_timeout > MAX_TIMEOUT_MS {
        return Err(MxcError::policy_validation(
            "NVX process.timeout must not exceed one hour",
        ));
    }
    if request
        .working_directory
        .split('/')
        .any(|component| component == "..")
    {
        return Err(MxcError::policy_validation(
            "NVX process.cwd must not contain '..' path components",
        ));
    }
    if !request.working_directory.is_empty() && !request.working_directory.starts_with('/') {
        return Err(MxcError::policy_validation(
            "NVX process.cwd must be an absolute POSIX guest path",
        ));
    }
    if request.working_directory.len() > MAX_CWD_BYTES {
        return Err(MxcError::policy_validation(
            "NVX process.cwd must not exceed 4095 UTF-8 bytes",
        ));
    }
    if let Some(environment) = &request.env {
        if !request.inherit_default_env {
            return Err(MxcError::policy_validation(
                "NVX process.env requires inheritDefaultEnv=true",
            ));
        }
        if environment.len() > MAX_ENVIRONMENT_ENTRIES {
            return Err(MxcError::policy_validation(
                "NVX process.env must not exceed 256 entries",
            ));
        }
        let bytes = environment
            .iter()
            .map(|entry| entry.len().saturating_add(1))
            .sum::<usize>();
        if bytes > MAX_ENVIRONMENT_BYTES {
            return Err(MxcError::policy_validation(
                "NVX process.env must not exceed 32 KiB",
            ));
        }
        for entry in environment {
            if entry.contains('\0') || entry.split_once('=').is_none_or(|(key, _)| key.is_empty()) {
                return Err(MxcError::malformed_request(
                    "NVX process.env entries must be KEY=VALUE without null bytes",
                ));
            }
            let key = entry.split_once('=').map_or(entry.as_str(), |(key, _)| key);
            if PROXY_ENVIRONMENT_KEYS
                .iter()
                .any(|candidate| key.eq_ignore_ascii_case(candidate))
            {
                return Err(MxcError::policy_validation(
                    "NVX does not support proxy environment variables",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_common::models::{CaptureDenialsConfig, ProxyAddress};
    use crate::mxc_common::mxc_error::MxcErrorCode;

    fn request() -> ExecutionRequest {
        ExecutionRequest {
            script_code: "echo ok".to_owned(),
            ..ExecutionRequest::default()
        }
    }

    fn assert_policy_error(request: &ExecutionRequest, text: &str) {
        let error = validate_request(request).unwrap_err();
        assert_eq!(error.code, MxcErrorCode::PolicyValidation);
        assert!(error.message.contains(text), "{error}");
    }

    #[test]
    fn accepts_command_timeout_cwd_and_additive_environment() {
        let mut request = request();
        request.script_timeout = 30_000;
        request.working_directory = "/workspace".to_owned();
        request.env = Some(vec!["KEY=value".to_owned()]);
        request.inherit_default_env = true;
        assert!(validate_request(&request).is_ok());
    }

    #[test]
    fn rejects_filesystem_network_ui_capture_and_lifecycle_expansion() {
        let mut filesystem = request();
        filesystem
            .policy
            .readwrite_paths
            .push(r"C:\work".to_owned());
        assert_policy_error(&filesystem, "filesystem policy");

        let mut network = request();
        network.policy.network_specified = true;
        assert_policy_error(&network, "network policy");

        let mut proxy = request();
        proxy.policy.network_proxy.address = Some(ProxyAddress::new("127.0.0.1".to_owned(), 8080));
        assert_policy_error(&proxy, "proxy configuration");

        let mut ui = request();
        ui.policy.ui_specified = true;
        assert_policy_error(&ui, "UI policy");

        let mut capture = request();
        capture.policy.capture_denials = Some(CaptureDenialsConfig::default());
        assert_policy_error(&capture, "captureDenials");

        let mut destroy = request();
        destroy.lifecycle.destroy_on_exit = false;
        assert_policy_error(&destroy, "destroyOnExit=true");

        let mut preserve = request();
        preserve.lifecycle.preserve_policy = true;
        assert_policy_error(&preserve, "preservePolicy=false");
    }

    #[test]
    fn adopts_signed_profile_process_limits() {
        let mut parent = request();
        parent.working_directory = "/workspace/../escape".to_owned();
        assert_policy_error(&parent, "must not contain '..'");

        let mut replacement = request();
        replacement.env = Some(vec!["KEY=value".to_owned()]);
        assert_policy_error(&replacement, "inheritDefaultEnv=true");

        let mut proxy = request();
        proxy.env = Some(vec!["hTtP_pRoXy=http://proxy".to_owned()]);
        proxy.inherit_default_env = true;
        assert_policy_error(&proxy, "proxy environment");

        let mut large = request();
        large.env = Some(vec![format!("KEY={}", "x".repeat(MAX_ENVIRONMENT_BYTES))]);
        large.inherit_default_env = true;
        assert_policy_error(&large, "32 KiB");

        let mut timeout = request();
        timeout.script_timeout = MAX_TIMEOUT_MS + 1;
        assert_policy_error(&timeout, "one hour");
    }

    #[test]
    fn environment_entry_limit_counts_duplicates_and_preserves_absent_and_empty() {
        let mut request = request();
        assert!(validate_request(&request).is_ok());
        request.env = Some(Vec::new());
        assert_policy_error(&request, "inheritDefaultEnv=true");
        request.inherit_default_env = true;
        assert!(validate_request(&request).is_ok());
        request.env = Some(vec!["KEY=value".to_owned(); MAX_ENVIRONMENT_ENTRIES]);
        assert!(validate_request(&request).is_ok());
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
            assert!(validate_request(&request).is_ok());
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
        assert!(validate_request(&request).is_ok());

        request.working_directory = "C:\\host".to_owned();
        assert_policy_error(&request, "absolute POSIX guest path");
        request.working_directory = "/tmp".to_owned();
        for key in PROXY_ENVIRONMENT_KEYS {
            request.env = Some(vec![format!("{}=value", key.to_ascii_lowercase())]);
            assert_policy_error(&request, "proxy environment");
        }
        request.env = Some(vec!["=missing-key".to_owned()]);
        assert_eq!(
            validate_request(&request).unwrap_err().code,
            MxcErrorCode::MalformedRequest
        );
        request.env = None;
        request.script_code.push('\0');
        assert_eq!(
            validate_request(&request).unwrap_err().code,
            MxcErrorCode::MalformedRequest
        );
    }
}
