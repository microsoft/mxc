// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Canonical one-shot request parsing for language bindings.

use mxc_sdk::{Error, SandboxRequest};

/// Parse a complete canonical MXC configuration document.
pub(crate) fn build_request_from_json(
    request_json: &str,
    experimental: bool,
) -> Result<SandboxRequest, Error> {
    let mut request = mxc_sdk::ffi_internals::build_request_from_json(request_json)?;
    request.set_experimental(experimental);
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_request_goldens_are_accepted() {
        for request in [
            include_str!("../../../../tests/policy/request-process-container.json"),
            include_str!("../../../../tests/policy/request-directional-network.json"),
            include_str!("../../../../tests/policy/request-wslc.json"),
        ] {
            build_request_from_json(request, true)
                .unwrap_or_else(|error| panic!("canonical request was rejected: {error}"));
        }
    }

    #[test]
    fn canonical_parser_rejects_unknown_and_duplicate_fields() {
        for request in [
            r#"{"version":"0.9.0-alpha","process":{"commandLine":"echo hi"},"unknown":true}"#,
            r#"{"version":"0.9.0-alpha","version":"0.9.0-alpha","process":{"commandLine":"echo hi"}}"#,
            r#"{"version":"0.9.0-alpha","process":{"commandLine":"echo hi","unexpected":true}}"#,
        ] {
            assert!(
                build_request_from_json(request, false).is_err(),
                "{request} must be rejected"
            );
        }
    }

    #[test]
    fn canonical_parser_requires_a_complete_one_shot_request() {
        for request in [
            r#"{"version":"0.9.0-alpha","process":{}}"#,
            include_str!("../../../../tests/policy/state-aware-wslc-provision.json"),
        ] {
            assert!(
                build_request_from_json(request, true).is_err(),
                "{request} must be rejected by the one-shot binding"
            );
        }
    }
}
