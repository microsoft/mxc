// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::super::{contract, start_into_wire, wire};

const MINIMAL_REQUEST_JSON: &str = r#"{
    "version": "0.8.0-alpha",
    "phase": "start",
    "sandboxId": "sandbox-id"
}"#;

const ALL_FIELDS_REQUEST_JSON: &str = r#"{
    "$schema": "https://example.com/start.schema.json",
    "_comment": "This is a comment",
    "version": "0.8.0-alpha",
    "phase": "start",
    "sandboxId": "sandbox-id",
    "correlationVector": "correlation-vector",
    "experimental": {
        "telemetry": {
            "enabled": false
        }
    }
}"#;

fn request_with_fields(fields: &str) -> String {
    format!(
        r#"{{
            "version": "0.8.0-alpha",
            "phase": "start",
            "sandboxId": "sandbox-id",
            {fields}
        }}"#
    )
}

pub(super) fn adapt(json: &str) -> wire::MxcConfig {
    let request: contract::StartRequest = serde_json::from_str(json).unwrap();
    start_into_wire(request)
}

#[test]
fn minimal_request_maps_expected_wire_fields() {
    let json = MINIMAL_REQUEST_JSON;

    let wire = adapt(json);

    assert!(wire.schema.is_none());
    assert!(wire.comment.is_none());
    assert_eq!(wire.version, Some("0.8.0-alpha".to_string()));
    assert!(matches!(wire.phase, Some(wire::Phase::Start)));
    assert_eq!(wire.sandbox_id, Some("sandbox-id".to_string()));
    assert!(wire.correlation_vector.is_none());
    assert!(wire.container_id.is_none());
    assert!(wire.containment.is_none());
    assert!(wire.process.is_none());
    assert!(wire.lifecycle.is_none());
    assert!(wire.process_container.is_none());
    assert!(wire.lxc.is_none());
    assert!(wire.filesystem.is_none());
    assert!(wire.fallback.is_none());
    assert!(wire.network.is_none());
    assert!(wire.ui.is_none());
    assert!(wire.seatbelt.is_none());
    assert!(wire.experimental.is_none());
}

#[test]
fn request_with_all_fields_maps_expected_wire_fields() {
    let json = ALL_FIELDS_REQUEST_JSON;

    let wire = adapt(json);

    assert_eq!(
        wire.schema,
        Some("https://example.com/start.schema.json".to_string())
    );
    assert_eq!(
        wire.comment.as_ref(),
        Some(&serde_json::json!("This is a comment"))
    );
    assert_eq!(wire.version, Some("0.8.0-alpha".to_string()));
    assert!(matches!(wire.phase, Some(wire::Phase::Start)));
    assert_eq!(wire.sandbox_id, Some("sandbox-id".to_string()));
    assert_eq!(
        wire.correlation_vector,
        Some("correlation-vector".to_string())
    );
    assert!(wire.container_id.is_none());
    assert!(wire.containment.is_none());
    assert!(wire.process.is_none());
    assert!(wire.lifecycle.is_none());
    assert!(wire.process_container.is_none());
    assert!(wire.lxc.is_none());
    assert!(wire.filesystem.is_none());
    assert!(wire.fallback.is_none());
    assert!(wire.network.is_none());
    assert!(wire.ui.is_none());
    assert!(wire.seatbelt.is_none());

    let experimental = wire.experimental.expect("experimental should be populated");

    let telemetry = experimental
        .telemetry
        .expect("telemetry should be populated");
    assert_eq!(telemetry.enabled, Some(false));

    assert!(experimental.test.is_none());
    assert!(experimental.windows_sandbox.is_none());
    assert!(experimental.wslc.is_none());
    assert!(experimental.isolation_session.is_none());
    assert!(experimental.seatbelt.is_none());
}

#[test]
fn empty_experimental_sections_map_to_present_empty_wire_sections() {
    let wire = adapt(&request_with_fields(r#""experimental": {}"#));
    let experimental = wire.experimental.expect("experimental should be populated");
    assert!(experimental.telemetry.is_none());

    let wire = adapt(&request_with_fields(r#""experimental": {"telemetry": {}}"#));
    let experimental = wire.experimental.expect("experimental should be populated");
    let telemetry = experimental
        .telemetry
        .expect("telemetry should be populated");
    assert!(telemetry.enabled.is_none());
}

#[test]
fn empty_identifier_strings_map_expected_wire_fields() {
    let json = r#"{
        "version": "0.8.0-alpha",
        "phase": "start",
        "sandboxId": "",
        "correlationVector": ""
    }"#;

    let wire = adapt(json);
    assert_eq!(wire.sandbox_id.as_deref(), Some(""));
    assert_eq!(wire.correlation_vector.as_deref(), Some(""));
}

#[test]
fn null_comment_maps_expected_wire_field() {
    let wire = adapt(&request_with_fields(r#""_comment": null"#));
    assert_eq!(wire.comment.as_ref(), Some(&serde_json::Value::Null));
}

// Deserialization match tests
pub(super) fn assert_matches_current_wire_deserialization(json: &str) {
    let current: wire::MxcConfig = crate::config_deserialize::from_str(json).unwrap();
    let adapted = adapt(json);

    assert_eq!(
        serde_json::to_value(adapted).unwrap(),
        serde_json::to_value(current).unwrap()
    );
}

#[test]
fn minimal_request_matches_current_wire_deserialization() {
    let json = MINIMAL_REQUEST_JSON;
    assert_matches_current_wire_deserialization(json);
}

#[test]
fn request_with_all_fields_matches_current_wire_deserialization() {
    let json = ALL_FIELDS_REQUEST_JSON;
    assert_matches_current_wire_deserialization(json);
}

#[test]
fn empty_experimental_sections_match_current_wire_deserialization() {
    for fields in [
        r#""experimental": {}"#,
        r#""experimental": {"telemetry": {}}"#,
    ] {
        assert_matches_current_wire_deserialization(&request_with_fields(fields));
    }
}

#[test]
fn empty_identifier_strings_match_current_wire_deserialization() {
    let json = r#"{
        "version": "0.8.0-alpha",
        "phase": "start",
        "sandboxId": "",
        "correlationVector": ""
    }"#;

    assert_matches_current_wire_deserialization(json);
}
