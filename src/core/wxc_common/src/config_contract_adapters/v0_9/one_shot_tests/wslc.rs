// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::common::adapt;

const WSLC_REQUEST_JSON: &str = r#"{
    "version": "0.9.0-alpha",
    "containment": "wslc",
    "process": {
        "commandLine": "echo hello"
    },
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
}"#;

#[test]
fn wslc_maps_expected_internal_wire_fields() {
    let wire = adapt(WSLC_REQUEST_JSON);

    assert!(matches!(
        wire.containment,
        Some(super::wire::Containment::Wslc)
    ));

    let experimental = wire
        .experimental
        .expect("permanent WSLC settings should map to the internal WSLC slot");
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
}

#[test]
fn absent_wslc_settings_leave_internal_experimental_empty() {
    let wire = adapt(
        r#"{
            "version": "0.9.0-alpha",
            "containment": "wslc",
            "process": {"commandLine": "echo hello"}
        }"#,
    );

    assert!(wire.experimental.is_none());
}
