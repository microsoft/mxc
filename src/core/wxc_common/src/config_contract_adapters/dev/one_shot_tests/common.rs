// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

pub(super) struct ContainmentCase {
    pub(super) input: &'static str,
    pub(super) expected: &'static str,
}

pub(super) fn request_with_containment(containment: &str) -> String {
    format!(
        r#"{{
            "version": "0.10.0-alpha",
            "containment": "{containment}",
            "process": {{"commandLine": "echo hello"}}
        }}"#
    )
}
pub(super) fn adapt(json: &str) -> crate::common_request_ir::CommonRequestIR {
    let request: contract::OneShotRequest = serde_json::from_str(json).unwrap();
    into_common_request_ir(request)
}
