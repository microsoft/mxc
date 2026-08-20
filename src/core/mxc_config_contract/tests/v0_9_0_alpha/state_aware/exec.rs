// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::common::{
    assert_invalid as assert_invalid_request, assert_valid as assert_valid_request,
};
use mxc_config_contract::dev::ExecRequest;

fn assert_valid(json: &str) {
    assert_valid_request::<ExecRequest>(json);
}

fn assert_invalid(json: &str) {
    assert_invalid_request::<ExecRequest>(json);
}

fn request_with_additional_fields(additional_fields: &str) -> String {
    format!(
        r#"{{
            "version": "0.9.0-alpha",
            "phase": "exec",
            "sandboxId": "test123456",
            "process": {{"commandLine": "echo"}},
            {additional_fields}
        }}"#
    )
}

#[test]
fn accepts_minimal_exec_request() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "phase": "exec",
        "sandboxId": "test123456",
        "process": {"commandLine": "echo"}
    }"#;
    assert_valid(json);
}

#[test]
fn accepts_exec_request_with_optional_fields() {
    let json = r#"{
        "$schema": "https://example.com/exec.schema.json",
        "_comment": "This is a comment",
        "version": "0.9.0-alpha",
        "phase": "exec",
        "sandboxId": "test123456",
        "correlationVector": "test-correlation-vector",
        "process": {"commandLine": "echo"},
        "network": {
            "proxy": {
                "url": "http://proxy.example"
            }
        },
        "experimental": {
            "telemetry": {
                "enabled": true
            }
        }
    }"#;
    assert_valid(json);
}

#[test]
fn accepts_empty_exec_optional_objects() {
    for field in [
        r#""network": {}"#,
        r#""experimental": {}"#,
        r#""experimental": {"telemetry": {}}"#,
    ] {
        assert_valid(&request_with_additional_fields(field));
    }
}

#[test]
fn accepts_exec_telemetry_enabled_values() {
    for enabled in [true, false] {
        let json = format!(
            r#"{{
                "version": "0.9.0-alpha",
                "phase": "exec",
                "sandboxId": "test123456",
                "process": {{"commandLine": "echo"}},
                "experimental": {{
                    "telemetry": {{
                        "enabled": {enabled}
                    }}
                }}
            }}"#
        );
        assert_valid(&json);
    }
}

#[test]
fn accepts_empty_sandbox_id_structurally() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "phase": "exec",
        "sandboxId": "",
        "process": {"commandLine": "echo"}
    }"#;
    assert_valid(json);
}

#[test]
fn exec_phase_accepts_exact_and_escaped_spelling() {
    for phase in ["exec", "ex\\u0065c"] {
        let json = format!(
            r#"{{
                "version": "0.9.0-alpha",
                "phase": "{}",
                "sandboxId": "test123456",
                "process": {{"commandLine": "echo"}}
            }}"#,
            phase
        );
        assert_valid(&json);
    }
}

#[test]
fn exec_request_rejects_other_phases() {
    for phase in ["provision", "start", "stop", "deprovision"] {
        let json = format!(
            r#"{{
                "version": "0.9.0-alpha",
                "phase": "{}",
                "sandboxId": "test123456",
                "process": {{"commandLine": "echo"}}
            }}"#,
            phase
        );
        assert_invalid(&json);
    }
}

#[test]
fn rejects_missing_required_exec_fields() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "phase": "exec",
        "sandboxId": "test123456"
    }"#;
    assert_invalid(json);

    let json = r#"{
        "version": "0.9.0-alpha",
        "phase": "exec",
        "process": {"commandLine": "echo"}
    }"#;

    assert_invalid(json);

    let json = r#"{
        "version": "0.9.0-alpha",
        "sandboxId": "test123456",
        "process": {"commandLine": "echo"}
    }"#;

    assert_invalid(json);

    let json = r#"{
        "phase": "exec",
        "sandboxId": "test123456",
        "process": {"commandLine": "echo"}
    }"#;

    assert_invalid(json);
}

#[test]
fn rejects_null_required_exec_fields() {
    let json = r#"{
        "version": null,
        "phase": "exec",
        "sandboxId": "test123456",
        "process": {"commandLine": "echo"}
    }"#;
    assert_invalid(json);

    let json = r#"{
        "version": "0.9.0-alpha",
        "phase": null,
        "sandboxId": "test123456",
        "process": {"commandLine": "echo"}
    }"#;

    assert_invalid(json);

    let json = r#"{
        "version": "0.9.0-alpha",
        "phase": "exec",
        "sandboxId": null,
        "process": {"commandLine": "echo"}
    }"#;

    assert_invalid(json);

    let json = r#"{
        "version": "0.9.0-alpha",
        "phase": "exec",
        "sandboxId": "test123456",
        "process": null
    }"#;

    assert_invalid(json);
}

#[test]
fn rejects_non_string_phase_field() {
    for phase in ["123", "true", "false", "[]", "{}"] {
        let json = format!(
            r#"{{
                "version": "0.9.0-alpha",
                "phase": {phase},
                "sandboxId": "test123456",
                "process": {{"commandLine": "echo"}}
            }}"#
        );
        assert_invalid(&json);
    }
}

#[test]
fn rejects_non_string_sandbox_id_field() {
    for sandbox_id in ["123", "true", "false", "[]", "{}"] {
        let json = format!(
            r#"{{
                "version": "0.9.0-alpha",
                "phase": "exec",
                "sandboxId": {sandbox_id},
                "process": {{"commandLine": "echo"}}
            }}"#
        );
        assert_invalid(&json);
    }
}

#[test]
fn rejects_non_boolean_experimental_telemetry_enabled_field() {
    for enabled in ["123", "\"true\"", "\"false\"", "[]", "{}"] {
        let json = format!(
            r#"{{
                "version": "0.9.0-alpha",
                "phase": "exec",
                "sandboxId": "test123456",
                "process": {{"commandLine": "echo"}},
                "experimental": {{
                    "telemetry": {{
                        "enabled": {enabled}
                    }}
                }}
            }}"#
        );
        assert_invalid(&json);
    }
}

#[test]
fn rejects_null_optional_fields() {
    for field in [
        r#""$schema": null"#,
        r#""correlationVector": null"#,
        r#""network": null"#,
        r#""experimental": null"#,
        r#""experimental": {"telemetry": null}"#,
        r#""experimental": {"telemetry": {"enabled": null}}"#,
    ] {
        assert_invalid(&request_with_additional_fields(field));
    }
}

#[test]
fn rejects_unknown_exec_fields() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "phase": "exec",
        "sandboxId": "test123456",
        "process": {"commandLine": "echo"},
        "unknownField": "value"
    }"#;
    assert_invalid(json);
}

#[test]
fn rejects_unknown_exec_experimental_fields() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "phase": "exec",
        "sandboxId": "test123456",
        "process": {"commandLine": "echo"},
        "experimental": {
            "unknownField": "value"
        }
    }"#;
    assert_invalid(json);
}

#[test]
fn rejects_unknown_exec_experimental_telemetry_fields() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "phase": "exec",
        "sandboxId": "test123456",
        "process": {"commandLine": "echo"},
        "experimental": {
            "telemetry": {
                "unknownField": "value"
            }
        }
    }"#;
    assert_invalid(json);
}

#[test]
fn rejects_unknown_exec_network_fields() {
    assert_invalid(&request_with_additional_fields(
        r#""network": {"unknownField": true}"#,
    ));
}

#[test]
fn rejects_forbidden_fields() {
    for field in [
        r#""containment": "wslc""#,
        r#""lifecycle": {}"#,
        r#""containerId": "container-id""#,
        r#""processContainer": {}"#,
        r#""appContainer": {}"#,
        r#""lxc": {"distribution": "ubuntu", "release": "20.04"}"#,
        r#""filesystem": {}"#,
        r#""fallback": {}"#,
        r#""ui": {}"#,
        r#""seatbelt": {}"#,
        r#""macos_sandbox": {}"#,
    ] {
        assert_invalid(&request_with_additional_fields(field));
    }
}

#[test]
fn rejects_backend_experimental_fields() {
    for field in [
        r#""test": {}"#,
        r#""windows_sandbox": {}"#,
        r#""isolation_session": {}"#,
        r#""wslc": {}"#,
        r#""seatbelt": {}"#,
        r#""macos_sandbox": {}"#,
    ] {
        let json = request_with_additional_fields(&format!(r#""experimental": {{{field}}}"#));
        assert_invalid(&json);
    }
}

#[test]
fn rejects_duplicate_exec_fields() {
    for fields in [
        r#""$schema": "first", "$schema": "second""#,
        r#""_comment": "first", "_comment": "second""#,
        r#""version": "0.9.0-alpha""#,
        r#""phase": "exec""#,
        r#""sandboxId": "other""#,
        r#""process": {"commandLine": "echo"}"#,
        r#""correlationVector": "first", "correlationVector": "second""#,
        r#""network": {}, "network": {}"#,
        r#""experimental": {}, "experimental": {}"#,
    ] {
        assert_invalid(&request_with_additional_fields(fields));
    }
}

#[test]
fn rejects_duplicate_exec_network_fields() {
    for network in [
        r#""defaultPolicy": "allow", "defaultPolicy": "block""#,
        r#""proxy": {"url": "http://first"}, "proxy": {"url": "http://second"}"#,
    ] {
        assert_invalid(&request_with_additional_fields(&format!(
            r#""network": {{{network}}}"#
        )));
    }
}

#[test]
fn rejects_duplicate_exec_experimental_fields() {
    for experimental in [
        r#""telemetry": {}, "telemetry": {}"#,
        r#""telemetry": {"enabled": true, "enabled": false}"#,
    ] {
        let json =
            request_with_additional_fields(&format!(r#""experimental": {{{experimental}}}"#));
        assert_invalid(&json);
    }
}

#[test]
fn rejects_invalid_version_field() {
    for version in [
        r#""0.7.0-alpha""#,
        r#""0.9.0""#,
        r#""invalid""#,
        "123",
        "true",
        "[]",
        "{}",
    ] {
        let json = format!(
            r#"{{
                "version": {version},
                "phase": "exec",
                "sandboxId": "test123456",
                "process": {{"commandLine": "echo"}}
            }}"#
        );
        assert_invalid(&json);
    }
}

#[test]
fn rejects_unknown_phase_value() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "phase": "restart",
        "sandboxId": "test123456",
        "process": {"commandLine": "echo"}
    }"#;

    assert_invalid(json);
}

#[test]
fn rejects_invalid_optional_field_types() {
    for field in ["$schema", "correlationVector"] {
        for value in ["123", "true", "[]", "{}"] {
            let json = request_with_additional_fields(&format!(r#""{field}": {value}"#));
            assert_invalid(&json);
        }
    }
}

#[test]
fn rejects_invalid_experimental_object_types() {
    // Positional-array rejection is intentionally out of scope.
    for value in [r#""invalid""#, "123", "true"] {
        let json = request_with_additional_fields(&format!(r#""network": {value}"#));
        assert_invalid(&json);

        let json = request_with_additional_fields(&format!(r#""experimental": {value}"#));
        assert_invalid(&json);

        let json =
            request_with_additional_fields(&format!(r#""experimental": {{"telemetry": {value}}}"#));
        assert_invalid(&json);
    }
}

#[test]
fn accepts_comment_value_types() {
    for comment in [
        r#""comment""#,
        r#"{"purpose": "test"}"#,
        r#"["first", 2, false]"#,
        "42",
        "true",
        "null",
    ] {
        let json = request_with_additional_fields(&format!(r#""_comment": {comment}"#));
        assert_valid(&json);
    }
}
