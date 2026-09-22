// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::{assert_invalid, assert_valid};

fn request(fields: &str) -> String {
    format!(
        r#"{{
            "version": "0.9.0-alpha",
            "containment": "wslc",
            "process": {{"commandLine": "echo"}},
            "wslc": {{{fields}}}
        }}"#
    )
}

#[test]
fn accepts_complete_wslc_settings() {
    assert_valid(&request(
        r#"
            "targetOs": "linux",
            "image": "alpine:latest",
            "imageTarPath": "C:\\images\\alpine.tar",
            "cpuCount": 4,
            "memoryMb": 4294967296,
            "gpu": true,
            "storagePath": "C:\\wslc",
            "portMappings": [
                {"windowsPort": 8080, "containerPort": 80},
                {"windowsPort": 8443, "containerPort": 443, "protocol": "tcp"}
            ]
        "#,
    ));
}

#[test]
fn accepts_wslc_numeric_and_port_boundaries() {
    for fields in [
        r#""cpuCount": 0"#,
        r#""cpuCount": 4294967295"#,
        r#""memoryMb": 0"#,
        r#""memoryMb": 18446744073709551615"#,
        r#""portMappings": [{"windowsPort": 1, "containerPort": 65535}]"#,
        r#""portMappings": [{"windowsPort": 65535, "containerPort": 1}]"#,
    ] {
        assert_valid(&request(fields));
    }
}

#[test]
fn rejects_invalid_wslc_scalar_fields() {
    for fields in [
        r#""targetOs": 42"#,
        r#""image": true"#,
        r#""imageTarPath": []"#,
        r#""cpuCount": -1"#,
        r#""cpuCount": 4294967296"#,
        r#""memoryMb": 1.5"#,
        r#""memoryMb": 18446744073709551616"#,
        r#""gpu": "true""#,
        r#""storagePath": {}"#,
        r#""unknownField": true"#,
    ] {
        assert_invalid(&request(fields));
    }
}

#[test]
fn rejects_invalid_wslc_port_mappings() {
    for mappings in [
        r#"[{"windowsPort": 0, "containerPort": 80}]"#,
        r#"[{"windowsPort": 8080, "containerPort": 65536}]"#,
        r#"[{"containerPort": 80}]"#,
        r#"[{"windowsPort": 8080}]"#,
        r#"[{"windowsPort": 8080, "containerPort": 80, "protocol": "udp"}]"#,
        r#"[{"windowsPort": 8080, "containerPort": 80, "unknown": true}]"#,
        r#"{"windowsPort": 8080, "containerPort": 80}"#,
    ] {
        assert_invalid(&request(&format!(r#""portMappings": {mappings}"#)));
    }
}

#[test]
fn rejects_null_and_duplicate_wslc_fields() {
    for fields in [
        r#""wslc": null"#,
        r#""wslc": {}, "wslc": {}"#,
        r#""wslc": {"image": null}"#,
        r#""wslc": {"image": "first", "image": "second"}"#,
        r#""wslc": {"portMappings": [], "portMappings": []}"#,
        r#""wslc": {"portMappings": [{"windowsPort": 8080, "windowsPort": 8081, "containerPort": 80}]}"#,
    ] {
        assert_invalid(&format!(
            r#"{{
                "version": "0.9.0-alpha",
                "containment": "wslc",
                "process": {{"commandLine": "echo"}},
                {fields}
            }}"#
        ));
    }
}
