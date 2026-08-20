// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::{assert_invalid, assert_invalid_cases, assert_valid};

#[test]
fn accepts_empty_test_object() {
    let json = r#"{
        "version": "0.8.0-alpha",
        "experimental": {"test": {}},
        "process": {"commandLine": "echo"}
    }"#;

    assert_valid(json);
}

#[test]
fn accepts_test_message_values() {
    for message in ["", "Hello, world!", "This is a test message."] {
        let json = format!(
            r#"{{
                "version": "0.8.0-alpha",
                "experimental": {{
                    "test": {{
                        "message": "{message}"
                    }}
                }},
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_valid(&json);
    }
}

#[test]
fn rejects_non_string_test_message_values() {
    for message in ["null", "true", "false", "123", "[]", "{}"] {
        let json = format!(
            r#"{{
                "version": "0.8.0-alpha",
                "experimental": {{
                    "test": {{
                        "message": {message}
                    }}
                }},
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_invalid(&json);
    }
}

#[test]
fn rejects_unknown_test_field() {
    let json = r#"{
        "version": "0.8.0-alpha",
        "experimental": {
            "test": {
                "unknownField": "value"
            }
        },
        "process": {"commandLine": "echo"}
    }"#;

    assert_invalid(json);
}

#[test]
fn rejects_duplicate_test_fields() {
    let version_and_process = r#""version": "0.8.0-alpha", "process": {"commandLine": "echo"}"#;

    assert_invalid_cases(
        [
            (
                "experimental.test",
                version_and_process,
                r#""experimental": {"test": {}, "test": {}}"#,
            ),
            (
                "experimental.test.message",
                version_and_process,
                r#""experimental": {"test": {"message": "First", "message": "Second"}}"#,
            ),
        ],
        "duplicate experimental field",
    );
}

#[test]
fn accepts_empty_telemetry_object() {
    let json = r#"{
        "version": "0.8.0-alpha",
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
                "version": "0.8.0-alpha",
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
                "version": "0.8.0-alpha",
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
        "version": "0.8.0-alpha",
        "telemetry": {
            "unknownField": "value"
        },
        "process": {"commandLine": "echo"}
    }"#;

    assert_invalid(json);
}

#[test]
fn rejects_duplicate_telemetry_fields() {
    let version_and_process = r#""version": "0.8.0-alpha", "process": {"commandLine": "echo"}"#;

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
