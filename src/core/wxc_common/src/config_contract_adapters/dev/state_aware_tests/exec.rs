// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::super::{contract, exec_into_wire, wire};
use super::common::assert_config_matches_rolling_state_aware_wire_input;

const MINIMAL_REQUEST_JSON: &str = r#"{
    "version": "0.9.0-alpha",
    "phase": "exec",
    "sandboxId": "sandbox-id",
    "process": {
        "commandLine": "echo hello"
    }
}"#;

const ALL_FIELDS_REQUEST_JSON: &str = r#"{
    "$schema": "https://example.com/exec.schema.json",
    "_comment": "This is a comment",
    "version": "0.9.0-alpha",
    "phase": "exec",
    "sandboxId": "sandbox-id",
    "process": {
        "commandLine": "echo hello",
        "cwd": "/work",
        "env": ["FIRST=one", "SECOND=two"],
        "timeout": 60
    },
    "network": {
        "defaultPolicy": "allow",
        "enforcementMode": "both",
        "allowLocalNetwork": false,
        "allowedHosts": ["example.com"],
        "blockedHosts": ["blocked.example.com"],
        "proxy": {
            "url": "http://127.0.0.1:8080"
        }
    },
    "telemetry": {
            "enabled": false
        }
}"#;

fn request_with_fields(fields: &str) -> String {
    format!(
        r#"{{
            "version": "0.9.0-alpha",
            "phase": "exec",
            "sandboxId": "sandbox-id",
            "process": {{"commandLine": "echo hello"}},
            {fields}
        }}"#
    )
}

pub(super) fn adapt(json: &str) -> wire::MxcConfig {
    let request: contract::ExecRequest = serde_json::from_str(json).unwrap();
    exec_into_wire(request)
}

#[test]
fn minimal_request_maps_expected_wire_fields() {
    let json = MINIMAL_REQUEST_JSON;

    let wire = adapt(json);

    assert!(wire.schema.is_none());
    assert!(wire.comment.is_none());
    assert_eq!(wire.version, Some("0.9.0-alpha".to_string()));
    assert!(matches!(wire.phase, Some(wire::Phase::Exec)));
    assert_eq!(wire.sandbox_id, Some("sandbox-id".to_string()));

    let process = wire.process.expect("process should be populated");
    assert_eq!(process.command_line.as_deref(), Some("echo hello"));
    assert!(process.cwd.is_none());
    assert!(process.env.is_none());
    assert!(process.timeout.is_none());
    assert!(wire.container_id.is_none());
    assert!(wire.containment.is_none());
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
        Some("https://example.com/exec.schema.json".to_string())
    );
    assert_eq!(
        wire.comment.as_ref(),
        Some(&serde_json::json!("This is a comment"))
    );
    assert_eq!(wire.version, Some("0.9.0-alpha".to_string()));
    assert!(matches!(wire.phase, Some(wire::Phase::Exec)));
    assert_eq!(wire.sandbox_id, Some("sandbox-id".to_string()));

    let process = wire.process.expect("process should be populated");
    assert_eq!(process.command_line.as_deref(), Some("echo hello"));
    assert_eq!(process.cwd.as_deref(), Some("/work"));
    assert_eq!(
        process.env.as_deref(),
        Some(["FIRST=one".to_string(), "SECOND=two".to_string()].as_slice())
    );
    assert_eq!(process.timeout, Some(60));

    assert!(wire.container_id.is_none());
    assert!(wire.containment.is_none());
    assert!(wire.lifecycle.is_none());
    assert!(wire.process_container.is_none());
    assert!(wire.lxc.is_none());
    assert!(wire.filesystem.is_none());
    assert!(wire.fallback.is_none());
    assert!(wire.ui.is_none());
    assert!(wire.seatbelt.is_none());

    let network = wire.network.expect("network should be populated");
    assert!(matches!(
        network.default_policy,
        Some(wire::NetworkPolicy::Allow)
    ));
    assert!(matches!(
        network.enforcement_mode,
        Some(wire::NetworkEnforcement::Both)
    ));
    assert_eq!(network.allow_local_network, Some(false));
    assert_eq!(
        network.allowed_hosts.as_deref(),
        Some(["example.com".to_string()].as_slice())
    );
    assert_eq!(
        network.blocked_hosts.as_deref(),
        Some(["blocked.example.com".to_string()].as_slice())
    );
    let proxy = network.proxy.expect("proxy should be populated");
    assert!(proxy.localhost.is_none());
    assert!(proxy.builtin_test_server.is_none());
    assert_eq!(proxy.url.as_deref(), Some("http://127.0.0.1:8080"));
    let telemetry = wire.telemetry.expect("telemetry should be populated");
    assert_eq!(telemetry.enabled, Some(false));
    assert!(wire.experimental.is_none());
}

#[test]
fn empty_experimental_sections_map_to_present_empty_wire_sections() {
    let wire = adapt(&request_with_fields(r#""experimental": {}"#));
    assert!(wire.experimental.is_some());
    assert!(wire.telemetry.is_none());

    let wire = adapt(&request_with_fields(r#""telemetry": {}"#));
    assert!(wire.experimental.is_none());
    let telemetry = wire.telemetry.expect("telemetry should be populated");
    assert!(telemetry.enabled.is_none());
}

#[test]
fn empty_network_section_maps_to_present_empty_wire_section() {
    let wire = adapt(&request_with_fields(r#""network": {}"#));
    let network = wire.network.expect("network should be populated");
    assert!(network.default_policy.is_none());
    assert!(network.enforcement_mode.is_none());
    assert!(network.allow_local_network.is_none());
    assert!(network.allowed_hosts.is_none());
    assert!(network.blocked_hosts.is_none());
    assert!(network.proxy.is_none());
}

#[test]
fn empty_identifier_strings_map_expected_wire_fields() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "phase": "exec",
        "sandboxId": "",
        "process": {
            "commandLine": "echo hello",
            "cwd": ""
        }
    }"#;

    let wire = adapt(json);
    assert_eq!(wire.sandbox_id.as_deref(), Some(""));
    assert_eq!(
        wire.process
            .as_ref()
            .and_then(|process| process.cwd.as_deref()),
        Some("")
    );
}

#[test]
fn null_comment_maps_expected_wire_field() {
    let wire = adapt(&request_with_fields(r#""_comment": null"#));
    assert_eq!(wire.comment.as_ref(), Some(&serde_json::Value::Null));
}

// Deserialization match tests
pub(super) fn assert_matches_rolling_state_aware_wire_input(json: &str) {
    let adapted = adapt(json);
    assert_config_matches_rolling_state_aware_wire_input(json, adapted);
}

#[test]
fn minimal_request_matches_rolling_state_aware_wire_input() {
    let json = MINIMAL_REQUEST_JSON;
    assert_matches_rolling_state_aware_wire_input(json);
}

#[test]
fn request_with_all_fields_matches_rolling_state_aware_wire_input() {
    let json = ALL_FIELDS_REQUEST_JSON;
    assert_matches_rolling_state_aware_wire_input(json);
}

#[test]
fn empty_experimental_sections_match_current_wire_deserialization() {
    for fields in [r#""experimental": {}"#, r#""telemetry": {}"#] {
        assert_matches_rolling_state_aware_wire_input(&request_with_fields(fields));
    }
}

#[test]
fn empty_network_section_matches_rolling_state_aware_wire_input() {
    assert_matches_rolling_state_aware_wire_input(&request_with_fields(r#""network": {}"#));
}

#[test]
fn empty_identifier_strings_match_current_wire_deserialization() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "phase": "exec",
        "sandboxId": "",
        "process": {
            "commandLine": "echo hello",
            "cwd": ""
        }
    }"#;

    assert_matches_rolling_state_aware_wire_input(json);
}
