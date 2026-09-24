// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::common::{adapt, request_with_containment};

const TEST_FEATURE_AND_TELEMETRY_REQUEST_JSON: &str = r#"{
    "version": "0.10.0-alpha",
    "containment": "process",
    "process": {
        "commandLine": "echo hello"
    },
    "telemetry": {
        "enabled": false
    },
    "test": {
        "message": "test message"
    }
}"#;

const WINDOWS_SANDBOX_REQUEST_JSON: &str = r#"{
    "version": "0.10.0-alpha",
    "containment": "windows_sandbox",
    "process": {
        "commandLine": "echo hello"
    },
    "windowsSandbox": {
        "idleTimeoutMs": 60000,
        "idleTimeout": 30,
        "daemonPipeName": "custom-sandbox-pipe"
    }
}"#;

#[test]
fn windows_sandbox_maps_expected_wire_fields() {
    let wire = adapt(WINDOWS_SANDBOX_REQUEST_JSON);

    assert!(matches!(
        wire.containment,
        Some(super::wire::Containment::WindowsSandbox)
    ));

    let windows_sandbox = wire
        .windows_sandbox
        .expect("windows_sandbox should be populated");

    assert_eq!(windows_sandbox.idle_timeout_ms, Some(60000));
    assert_eq!(windows_sandbox.idle_timeout, Some(30));
    assert_eq!(
        windows_sandbox.daemon_pipe_name.as_deref(),
        Some("custom-sandbox-pipe")
    );

    assert!(wire.test_feature.is_none());
    assert!(wire.telemetry.is_none());
}

#[test]
fn test_feature_and_telemetry_map_expected_wire_fields() {
    let wire = adapt(TEST_FEATURE_AND_TELEMETRY_REQUEST_JSON);

    let test = wire.test_feature.expect("test should be populated");
    assert_eq!(test.message.as_deref(), Some("test message"));

    let telemetry = wire.telemetry.expect("telemetry should be populated");
    assert_eq!(telemetry.enabled, Some(false));

    assert!(wire.windows_sandbox.is_none());
}

struct DevelopmentContainmentCase {
    input: &'static str,
    expected: &'static str,
}

const DEVELOPMENT_CONTAINMENT_CASES: &[DevelopmentContainmentCase] = &[
    DevelopmentContainmentCase {
        input: "vm",
        expected: "vm",
    },
    DevelopmentContainmentCase {
        input: "windows_sandbox",
        expected: "windows_sandbox",
    },
    DevelopmentContainmentCase {
        input: "microvm",
        expected: "microvm",
    },
    DevelopmentContainmentCase {
        input: "hyperlight",
        expected: "hyperlight",
    },
];

#[test]
fn development_containment_variants_map_expected_wire_values() {
    for case in DEVELOPMENT_CONTAINMENT_CASES {
        let wire = adapt(&request_with_containment(case.input));
        assert_eq!(
            serde_json::to_value(wire.containment.unwrap()).unwrap(),
            serde_json::json!(case.expected)
        );
    }
}
