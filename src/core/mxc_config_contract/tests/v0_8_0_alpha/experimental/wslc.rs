// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::{assert_invalid, assert_invalid_cases, assert_valid};

fn wslc_request(fields: &str) -> String {
    format!(
        r#"{{
            "version": "0.8.0-alpha",
            "experimental": {{
                "wslc": {{{fields}}}
            }},
            "process": {{"commandLine": "echo"}}
        }}"#
    )
}

#[test]
fn accepts_empty_wslc_object() {
    assert_valid(&wslc_request(""));
}

#[test]
fn accepts_wslc_string_field_values() {
    for field in ["targetOs", "image", "imageTarPath", "storagePath"] {
        for value in ["", "value"] {
            let value_json = serde_json::to_string(value).unwrap();
            assert_valid(&wslc_request(&format!(r#""{field}": {value_json}"#)));
        }
    }
}

#[test]
fn rejects_non_string_wslc_string_field_values() {
    for field in ["targetOs", "image", "imageTarPath", "storagePath"] {
        for value in ["123", "true", "[]", "{}"] {
            assert_invalid(&wslc_request(&format!(r#""{field}": {value}"#)));
        }
    }
}

#[test]
fn accepts_wslc_integer_boundaries() {
    for fields in [
        r#""cpuCount": 0"#,
        r#""cpuCount": 4294967295"#,
        r#""memoryMb": 0"#,
        r#""memoryMb": 4294967296"#,
        r#""memoryMb": 18446744073709551615"#,
    ] {
        assert_valid(&wslc_request(fields));
    }
}

#[test]
fn rejects_invalid_wslc_integer_values() {
    for field in ["cpuCount", "memoryMb"] {
        for value in ["-1", "1.5", r#""1024""#, "true", "[]", "{}"] {
            assert_invalid(&wslc_request(&format!(r#""{field}": {value}"#)));
        }
    }

    assert_invalid(&wslc_request(r#""cpuCount": 4294967296"#));
    assert_invalid(&wslc_request(r#""memoryMb": 18446744073709551616"#));
}

#[test]
fn accepts_wslc_gpu_values() {
    for value in ["true", "false"] {
        assert_valid(&wslc_request(&format!(r#""gpu": {value}"#)));
    }
}

#[test]
fn rejects_non_boolean_wslc_gpu_values() {
    for value in [r#""true""#, "123", "[]", "{}"] {
        assert_invalid(&wslc_request(&format!(r#""gpu": {value}"#)));
    }
}

#[test]
fn rejects_unknown_wslc_field() {
    assert_invalid(&wslc_request(r#""unknownField": "value""#));
}

#[test]
fn rejects_duplicate_wslc_fields() {
    let version_and_process = r#""version": "0.8.0-alpha", "process": {"commandLine": "echo"}"#;

    assert_invalid_cases(
        [
            (
                "experimental.wslc",
                version_and_process,
                r#""experimental": {"wslc": {}, "wslc": {}}"#,
            ),
            (
                "experimental.wslc.targetOs",
                version_and_process,
                r#""experimental": {"wslc": {"targetOs": "linux", "targetOs": "other"}}"#,
            ),
            (
                "experimental.wslc.image",
                version_and_process,
                r#""experimental": {"wslc": {"image": "first", "image": "second"}}"#,
            ),
            (
                "experimental.wslc.imageTarPath",
                version_and_process,
                r#""experimental": {"wslc": {"imageTarPath": "first", "imageTarPath": "second"}}"#,
            ),
            (
                "experimental.wslc.cpuCount",
                version_and_process,
                r#""experimental": {"wslc": {"cpuCount": 1, "cpuCount": 2}}"#,
            ),
            (
                "experimental.wslc.memoryMb",
                version_and_process,
                r#""experimental": {"wslc": {"memoryMb": 1024, "memoryMb": 2048}}"#,
            ),
            (
                "experimental.wslc.gpu",
                version_and_process,
                r#""experimental": {"wslc": {"gpu": true, "gpu": false}}"#,
            ),
            (
                "experimental.wslc.storagePath",
                version_and_process,
                r#""experimental": {"wslc": {"storagePath": "first", "storagePath": "second"}}"#,
            ),
        ],
        "duplicate experimental field",
    );
}

const VALID_PORT_MAPPING: &str = r#"{"windowsPort": 8080, "containerPort": 80}"#;

fn wslc_port_mappings_request(mappings: &str) -> String {
    wslc_request(&format!(r#""portMappings": {mappings}"#))
}

#[test]
fn accepts_empty_wslc_port_mappings() {
    assert_valid(&wslc_port_mappings_request("[]"));
}

#[test]
fn accepts_wslc_port_mappings() {
    for mappings in [
        format!("[{VALID_PORT_MAPPING}]"),
        r#"[{"windowsPort": 8080, "containerPort": 80, "protocol": "tcp"}]"#.to_string(),
        r#"[{"windowsPort": 8080, "containerPort": 80}, {"windowsPort": 8443, "containerPort": 443}]"#
            .to_string(),
    ] {
        assert_valid(&wslc_port_mappings_request(&mappings));
    }
}

#[test]
fn accepts_wslc_port_boundaries() {
    for mappings in [
        r#"[{"windowsPort": 1, "containerPort": 65535}]"#,
        r#"[{"windowsPort": 65535, "containerPort": 1}]"#,
    ] {
        assert_valid(&wslc_port_mappings_request(mappings));
    }
}

#[test]
fn rejects_invalid_wslc_port_values() {
    for field in ["windowsPort", "containerPort"] {
        for value in ["0", "-1", "1.5", "65536", r#""80""#, "true", "[]", "{}"] {
            let other_field = if field == "windowsPort" {
                r#""containerPort": 80"#
            } else {
                r#""windowsPort": 8080"#
            };
            let mappings = format!(r#"[{{"{field}": {value}, {other_field}}}]"#);
            assert_invalid(&wslc_port_mappings_request(&mappings));
        }
    }
}

#[test]
fn rejects_missing_wslc_port_mapping_fields() {
    for mappings in [
        r#"[{"containerPort": 80}]"#,
        r#"[{"windowsPort": 8080}]"#,
        r#"[{"windowsPort": null, "containerPort": 80}]"#,
        r#"[{"windowsPort": 8080, "containerPort": null}]"#,
    ] {
        assert_invalid(&wslc_port_mappings_request(mappings));
    }
}

#[test]
fn rejects_invalid_wslc_port_mappings_shape() {
    for mappings in [
        "{}",
        r#""mapping""#,
        "123",
        "true",
        "[123]",
        r#"["mapping"]"#,
        "[[]]",
    ] {
        assert_invalid(&wslc_port_mappings_request(mappings));
    }
}

#[test]
fn rejects_invalid_wslc_port_mapping_protocol() {
    for protocol in [
        r#""udp""#,
        r#""invalid""#,
        "123",
        "true",
        "[]",
        "{}",
        r#"{"tcp": null}"#,
    ] {
        let mappings =
            format!(r#"[{{"windowsPort": 8080, "containerPort": 80, "protocol": {protocol}}}]"#);
        assert_invalid(&wslc_port_mappings_request(&mappings));
    }
}

#[test]
fn rejects_unknown_wslc_port_mapping_field() {
    let mappings = r#"[{"windowsPort": 8080, "containerPort": 80, "unknownField": "value"}]"#;
    assert_invalid(&wslc_port_mappings_request(mappings));
}

#[test]
fn rejects_duplicate_wslc_port_mapping_fields() {
    let version_and_process = r#""version": "0.8.0-alpha", "process": {"commandLine": "echo"}"#;

    assert_invalid_cases(
        [
            (
                "experimental.wslc.portMappings",
                version_and_process,
                r#""experimental": {"wslc": {"portMappings": [], "portMappings": []}}"#,
            ),
            (
                "experimental.wslc.portMappings[].windowsPort",
                version_and_process,
                r#""experimental": {"wslc": {"portMappings": [{"windowsPort": 8080, "windowsPort": 8081, "containerPort": 80}]}}"#,
            ),
            (
                "experimental.wslc.portMappings[].containerPort",
                version_and_process,
                r#""experimental": {"wslc": {"portMappings": [{"windowsPort": 8080, "containerPort": 80, "containerPort": 81}]}}"#,
            ),
            (
                "experimental.wslc.portMappings[].protocol",
                version_and_process,
                r#""experimental": {"wslc": {"portMappings": [{"windowsPort": 8080, "containerPort": 80, "protocol": "tcp", "protocol": "tcp"}]}}"#,
            ),
        ],
        "duplicate experimental field",
    );
}
