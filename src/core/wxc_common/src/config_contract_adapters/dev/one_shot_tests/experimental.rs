// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::common::{adapt, assert_matches_current_wire_deserialization, request_with_containment};

const TEST_FEATURE_AND_TELEMETRY_REQUEST_JSON: &str = r#"{
    "version": "0.8.0-alpha",
    "containment": "process",
    "process": {
        "commandLine": "echo hello"
    },
    "experimental": {
        "test": {
            "message": "test message"
        },
        "telemetry": {
            "enabled": false
        }
    }
}"#;

const WINDOWS_SANDBOX_REQUEST_JSON: &str = r#"{
    "version": "0.8.0-alpha",
    "containment": "windows_sandbox",
    "process": {
        "commandLine": "echo hello"
    },
    "experimental": {
        "windows_sandbox": {
            "idleTimeoutMs": 60000,
            "idleTimeout": 30,
            "daemonPipeName": "custom-sandbox-pipe"
        }
    }
}"#;

const WSLC_REQUEST_JSON: &str = r#"{
    "version": "0.8.0-alpha",
    "containment": "wslc",
    "process": {
        "commandLine": "echo hello"
    },
    "experimental": {
        "wslc": {
            "targetOs": "linux",
            "image": "alpine:latest",
            "imageTarPath": "C:\\images\\alpine.tar",
            "cpuCount": 4,
            "memoryMb": 4294967296,
            "gpu": true,
            "storagePath": "C:\\wslc",
            "portMappings": [
                {
                    "windowsPort": 8080,
                    "containerPort": 80
                },
                {
                    "windowsPort": 8443,
                    "containerPort": 443,
                    "protocol": "tcp"
                }
            ]
        }
    }
}"#;

const APPLE_CONTAINER_REQUEST_JSON: &str = r#"{
    "version": "0.8.0-alpha",
    "containment": "apple_container",
    "process": {
        "commandLine": "echo hello"
    },
    "experimental": {
        "apple_container": {
            "image": "docker.io/library/alpine:3.23",
            "cpuCount": 2,
            "memoryMb": 1024
        }
    }
}"#;

#[test]
fn windows_sandbox_maps_expected_wire_fields() {
    let wire = adapt(WINDOWS_SANDBOX_REQUEST_JSON);

    assert!(matches!(
        wire.containment,
        Some(super::wire::Containment::WindowsSandbox)
    ));

    let experimental = wire.experimental.expect("experimental should be populated");

    let windows_sandbox = experimental
        .windows_sandbox
        .expect("windows_sandbox should be populated");

    assert_eq!(windows_sandbox.idle_timeout_ms, Some(60000));
    assert_eq!(windows_sandbox.idle_timeout, Some(30));
    assert_eq!(
        windows_sandbox.daemon_pipe_name.as_deref(),
        Some("custom-sandbox-pipe")
    );

    assert!(experimental.test.is_none());
    assert!(experimental.wslc.is_none());
    assert!(experimental.isolation_session.is_none());
    assert!(experimental.seatbelt.is_none());
    assert!(experimental.telemetry.is_none());
}

#[test]
fn test_feature_and_telemetry_map_expected_wire_fields() {
    let wire = adapt(TEST_FEATURE_AND_TELEMETRY_REQUEST_JSON);

    let experimental = wire.experimental.expect("experimental should be populated");

    let test = experimental.test.expect("test should be populated");
    assert_eq!(test.message.as_deref(), Some("test message"));

    let telemetry = experimental
        .telemetry
        .expect("telemetry should be populated");
    assert_eq!(telemetry.enabled, Some(false));

    assert!(experimental.windows_sandbox.is_none());
    assert!(experimental.wslc.is_none());
    assert!(experimental.isolation_session.is_none());
    assert!(experimental.seatbelt.is_none());
}

#[test]
fn wslc_maps_expected_wire_fields() {
    let wire = adapt(WSLC_REQUEST_JSON);

    assert!(matches!(
        wire.containment,
        Some(super::wire::Containment::Wslc)
    ));

    let experimental = wire.experimental.expect("experimental should be populated");
    let wslc = experimental.wslc.expect("wslc should be populated");

    assert_eq!(wslc.target_os.as_deref(), Some("linux"));
    assert_eq!(wslc.image.as_deref(), Some("alpine:latest"));
    assert_eq!(
        wslc.image_tar_path.as_deref(),
        Some(r"C:\images\alpine.tar")
    );
    assert_eq!(wslc.cpu_count, Some(4));
    assert_eq!(wslc.memory_mb, Some(4294967296));
    assert_eq!(wslc.gpu, Some(true));
    assert_eq!(wslc.storage_path.as_deref(), Some(r"C:\wslc"));
    assert!(wslc.provision.is_none());

    let mappings = wslc
        .port_mappings
        .expect("portMappings should be populated");
    assert_eq!(mappings.len(), 2);

    assert_eq!(mappings[0].windows_port, 8080);
    assert_eq!(mappings[0].container_port, 80);
    assert!(mappings[0].protocol.is_none());

    assert_eq!(mappings[1].windows_port, 8443);
    assert_eq!(mappings[1].container_port, 443);
    assert!(matches!(
        &mappings[1].protocol,
        Some(super::wire::TransportProtocol::Tcp)
    ));

    assert!(experimental.test.is_none());
    assert!(experimental.windows_sandbox.is_none());
    assert!(experimental.isolation_session.is_none());
    assert!(experimental.seatbelt.is_none());
    assert!(experimental.telemetry.is_none());
}

#[test]
fn apple_container_maps_expected_wire_fields() {
    let wire = adapt(APPLE_CONTAINER_REQUEST_JSON);

    assert!(matches!(
        wire.containment,
        Some(super::wire::Containment::AppleContainer)
    ));

    let experimental = wire.experimental.expect("experimental should be populated");
    let apple_container = experimental
        .apple_container
        .expect("apple_container should be populated");

    assert_eq!(apple_container.image, "docker.io/library/alpine:3.23");
    assert_eq!(apple_container.cpu_count, Some(2));
    assert_eq!(apple_container.memory_mb, Some(1024));
}

#[test]
fn windows_sandbox_matches_current_wire_deserialization() {
    assert_matches_current_wire_deserialization(WINDOWS_SANDBOX_REQUEST_JSON);
}

#[test]
fn wslc_matches_current_wire_deserialization() {
    assert_matches_current_wire_deserialization(WSLC_REQUEST_JSON);
}

#[test]
fn apple_container_matches_current_wire_deserialization() {
    assert_matches_current_wire_deserialization(APPLE_CONTAINER_REQUEST_JSON);
}

#[test]
fn test_feature_and_telemetry_match_current_wire_deserialization() {
    assert_matches_current_wire_deserialization(TEST_FEATURE_AND_TELEMETRY_REQUEST_JSON);
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
    DevelopmentContainmentCase {
        input: "wslc",
        expected: "wslc",
    },
    DevelopmentContainmentCase {
        input: "isolation_session",
        expected: "isolation_session",
    },
    DevelopmentContainmentCase {
        input: "apple_container",
        expected: "apple_container",
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

#[test]
fn development_containment_variants_match_current_wire_deserialization() {
    for case in DEVELOPMENT_CONTAINMENT_CASES {
        let json = request_with_containment(case.input);
        assert_matches_current_wire_deserialization(&json);
    }
}
