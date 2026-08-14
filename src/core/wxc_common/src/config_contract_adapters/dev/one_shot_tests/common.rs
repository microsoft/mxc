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
            "version": "0.8.0-alpha",
            "containment": "{containment}",
            "process": {{"commandLine": "echo hello"}}
        }}"#
    )
}

pub(super) fn assert_matches_current_wire_deserialization(json: &str) {
    let current: super::wire::MxcConfig = crate::config_deserialize::from_str(json).unwrap();
    let contract: super::contract::OneShotRequest = serde_json::from_str(json).unwrap();
    let adapted = super::into_wire(contract);

    assert_eq!(
        serde_json::to_value(adapted).unwrap(),
        serde_json::to_value(current).unwrap()
    );
}

pub(super) fn adapt(json: &str) -> wire::MxcConfig {
    let request: contract::OneShotRequest = serde_json::from_str(json).unwrap();
    into_wire(request)
}
