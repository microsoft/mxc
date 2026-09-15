// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::{assert_invalid, assert_invalid_cases, assert_valid};

#[test]
fn accepts_empty_telemetry_object() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "telemetry": {},
        "process": {"commandLine": "echo"}
    }"#;

    assert_valid(json);
}

#[test]
fn accepts_telemetry_enabled_values() {
    for enabled in ["true", "false"] {
        let json = format!(
            r#"{{
                "version": "0.9.0-alpha",
                "telemetry": {{
                    "enabled": {enabled}
                }},
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_valid(&json);
    }
}

#[test]
fn rejects_non_boolean_telemetry_enabled_values() {
    for enabled in ["null", "123", "\"true\"", "\"false\"", "[]", "{}"] {
        let json = format!(
            r#"{{
                "version": "0.9.0-alpha",
                "telemetry": {{
                    "enabled": {enabled}
                }},
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_invalid(&json);
    }
}

#[test]
fn rejects_unknown_telemetry_field() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "telemetry": {
            "unknownField": "value"
        },
        "process": {"commandLine": "echo"}
    }"#;

    assert_invalid(json);
}

#[test]
fn rejects_duplicate_telemetry_fields() {
    let version_and_process = r#""version": "0.9.0-alpha", "process": {"commandLine": "echo"}"#;

    assert_invalid_cases(
        [
            (
                "telemetry",
                version_and_process,
                r#""telemetry": {}, "telemetry": {}"#,
            ),
            (
                "telemetry.enabled",
                version_and_process,
                r#""telemetry": {"enabled": true, "enabled": false}"#,
            ),
        ],
        "duplicate telemetry field",
    );
}
