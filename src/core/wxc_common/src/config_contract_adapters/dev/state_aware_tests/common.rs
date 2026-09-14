// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::super::{
    contract, extract_experimental_value, into_state_aware_wire_input, start_into_wire, wire,
};
use crate::config_parser::parse_rolling_state_aware_wire_input;
use crate::state_aware_wire::StateAwareWireInput;
use serde_json::value::RawValue;

#[derive(serde::Deserialize)]
struct ExperimentalProbe<'a> {
    #[serde(borrow, default)]
    experimental: Option<&'a RawValue>,
}

pub(super) fn assert_config_matches_rolling_state_aware_wire_input(
    source: &str,
    adapted_config: wire::MxcConfig,
) {
    let probe: ExperimentalProbe<'_> = serde_json::from_str(source).unwrap();
    let rolling = parse_rolling_state_aware_wire_input(source, probe.experimental).unwrap();
    let adapted = into_state_aware_wire_input(adapted_config, source).unwrap();

    assert_eq!(
        serde_json::to_value(adapted.config).unwrap(),
        serde_json::to_value(rolling.config).unwrap()
    );
    assert_eq!(adapted.experimental_raw, rolling.experimental_raw);
    assert_eq!(adapted.source_text, rolling.source_text);
}

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
fn extract_experimental_value_preserves_only_backend_payload() {
    let source = r#"{
        "version": "0.9.0-alpha",
        "phase": "provision",
        "containment": "isolation_session",
        "network": {
            "defaultPolicy": "allow",
            "allowLocalNetwork": true
        },
        "telemetry": {
            "enabled": false
        },
        "experimental": {
            "isolation_session": {
                "provision": {
                    "appId": "someAppId"
                }
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
        "telemetry": {
            "enabled": false
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
    assert!(experimental_raw.is_none());
    assert_eq!(config.telemetry.unwrap().enabled, Some(false));
    assert_eq!(source_text.as_ref(), source);
}
