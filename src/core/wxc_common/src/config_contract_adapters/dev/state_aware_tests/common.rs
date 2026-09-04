// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::super::{
    contract, extract_experimental_value, into_state_aware_wire_input, start_into_wire, wire,
};
use crate::state_aware_wire::StateAwareWireInput;

#[test]
fn extract_experimental_value_returns_none_when_absent() {
    let source = r#"{
        "version": "0.9.0-alpha",
        "phase": "start",
        "sandboxId": "sandbox-id"
    }"#;

    assert_eq!(extract_experimental_value(source).unwrap(), None);
}

#[test]
fn extract_experimental_value_preserves_empty_object() {
    let source = r#"{
        "version": "0.9.0-alpha",
        "phase": "start",
        "sandboxId": "sandbox-id",
        "experimental": {}
    }"#;

    assert_eq!(
        extract_experimental_value(source).unwrap(),
        Some(serde_json::json!({}))
    );
}

#[test]
fn extract_experimental_value_preserves_backend_payload_and_telemetry() {
    let source = r#"{
        "version": "0.9.0-alpha",
        "phase": "provision",
        "containment": "isolation_session",
        "network": {
            "defaultPolicy": "allow",
            "allowLocalNetwork": true
        },
        "experimental": {
            "isolation_session": {
                "provision": {
                    "appId": "someAppId"
                }
            },
            "telemetry": {
                "enabled": false
            }
        }
    }"#;

    assert_eq!(
        extract_experimental_value(source).unwrap(),
        Some(serde_json::json!({
            "isolation_session": {
                "provision": {
                    "appId": "someAppId"
                }
            },
            "telemetry": {
                "enabled": false
            }
        }))
    );
}

#[test]
fn into_state_aware_wire_input_packages_config_raw_value_and_source_text() {
    let source = r#"{
        "version": "0.9.0-alpha",
        "phase": "start",
        "sandboxId": "sandbox-id",
        "experimental": {
            "telemetry": {
                "enabled": false
            }
        }
    }"#;
    let request: contract::StartRequest = serde_json::from_str(source).unwrap();
    let config = start_into_wire(request);

    let StateAwareWireInput {
        config,
        experimental_raw,
        source_text,
    } = into_state_aware_wire_input(config, source).unwrap();

    assert!(matches!(config.phase, Some(wire::Phase::Start)));
    assert_eq!(config.sandbox_id.as_deref(), Some("sandbox-id"));
    assert_eq!(
        experimental_raw,
        Some(serde_json::json!({
            "telemetry": {
                "enabled": false
            }
        }))
    );
    assert_eq!(source_text.as_ref(), source);
}
