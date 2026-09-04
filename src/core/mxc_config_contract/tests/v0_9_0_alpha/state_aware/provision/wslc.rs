// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::super::common::{
    assert_invalid as assert_invalid_request, assert_valid as assert_valid_request,
};
use mxc_config_contract::dev::WslcProvisionRequest;

fn assert_valid(json: &str) {
    assert_valid_request::<WslcProvisionRequest>(json);
}

fn assert_invalid(json: &str) {
    assert_invalid_request::<WslcProvisionRequest>(json);
}

fn request_with_additional_fields(additional_fields: &str) -> String {
    format!(
        r#"{{
            "version": "0.9.0-alpha",
            "phase": "provision",
            "containment": "wslc",
            {additional_fields}
        }}"#
    )
}

fn request_with_containment_value(containment: &str) -> String {
    format!(
        r#"{{
            "version": "0.9.0-alpha",
            "phase": "provision",
            "containment": {containment}
        }}"#
    )
}

#[test]
fn accepts_minimal_provision_request() {
    assert_valid(
        r#"{
            "version": "0.9.0-alpha",
            "phase": "provision",
            "containment": "wslc"
        }"#,
    );
}

#[test]
fn accepts_provision_request_with_optional_fields() {
    assert_valid(
        r#"{
            "$schema": "https://example.com/provision.schema.json",
            "_comment": "WSLC provision",
            "version": "0.9.0-alpha",
            "phase": "provision",
            "containment": "wslc",
            "filesystem": {
                "readwritePaths": ["C:\\rw"],
                "readonlyPaths": ["C:\\ro"],
                "deniedPaths": ["C:\\denied"]
            },
            "network": {
                "defaultPolicy": "block"
            },
            "telemetry": {
                "enabled": true
            },
            "experimental": {
                "wslc": {
                    "provision": {
                        "image": "alpine:latest",
                        "imageTarPath": "C:\\images\\alpine.tar"
                    }
                }
            }
        }"#,
    );
}

#[test]
fn accepts_empty_optional_objects() {
    for field in [
        r#""filesystem": {}"#,
        r#""network": {}"#,
        r#""experimental": {}"#,
        r#""telemetry": {}"#,
        r#""experimental": {"wslc": {}}"#,
        r#""experimental": {"wslc": {"provision": {}}}"#,
    ] {
        assert_valid(&request_with_additional_fields(field));
    }
}

#[test]
fn accepts_telemetry_enabled_values() {
    for enabled in [true, false] {
        assert_valid(&request_with_additional_fields(&format!(
            r#""telemetry": {{"enabled": {enabled}}}"#
        )));
    }
}

#[test]
fn accepts_provision_string_values() {
    for (field, value) in [
        ("image", r#""""#),
        ("image", r#""alpine:latest""#),
        ("imageTarPath", r#""""#),
        ("imageTarPath", r#""C:\\images\\alpine.tar""#),
    ] {
        assert_valid(&request_with_additional_fields(&format!(
            r#""experimental": {{"wslc": {{"provision": {{"{field}": {value}}}}}}}"#
        )));
    }
}

#[test]
fn phase_accepts_exact_and_escaped_spelling() {
    for phase in ["provision", "provis\\u0069on"] {
        assert_valid(&format!(
            r#"{{
                "version": "0.9.0-alpha",
                "phase": "{phase}",
                "containment": "wslc"
            }}"#
        ));
    }
}

#[test]
fn rejects_other_phases() {
    for phase in ["start", "exec", "stop", "deprovision"] {
        assert_invalid(&format!(
            r#"{{
                "version": "0.9.0-alpha",
                "phase": "{phase}",
                "containment": "wslc"
            }}"#
        ));
    }
}

#[test]
fn containment_accepts_exact_and_escaped_spelling() {
    for containment in ["wslc", "ws\\u006cc"] {
        assert_valid(&request_with_containment_value(&format!(
            r#""{containment}""#
        )));
    }
}

#[test]
fn rejects_other_containment_values() {
    for containment in ["isolation_session", "windows_sandbox", "vm", "unknown"] {
        assert_invalid(&request_with_containment_value(&format!(
            r#""{containment}""#
        )));
    }
}

#[test]
fn rejects_non_string_containment_field() {
    for containment in ["123", "true", "false", "[]", "{}"] {
        assert_invalid(&request_with_containment_value(containment));
    }
}

#[test]
fn rejects_missing_required_fields() {
    for json in [
        r#"{"phase":"provision","containment":"wslc"}"#,
        r#"{"version":"0.9.0-alpha","containment":"wslc"}"#,
        r#"{"version":"0.9.0-alpha","phase":"provision"}"#,
    ] {
        assert_invalid(json);
    }
}

#[test]
fn rejects_null_required_fields() {
    for json in [
        r#"{"version":null,"phase":"provision","containment":"wslc"}"#,
        r#"{"version":"0.9.0-alpha","phase":null,"containment":"wslc"}"#,
        r#"{"version":"0.9.0-alpha","phase":"provision","containment":null}"#,
    ] {
        assert_invalid(json);
    }
}

#[test]
fn rejects_non_string_phase_field() {
    for phase in ["123", "true", "false", "[]", "{}"] {
        assert_invalid(&format!(
            r#"{{
                "version": "0.9.0-alpha",
                "phase": {phase},
                "containment": "wslc"
            }}"#
        ));
    }
}

#[test]
fn rejects_null_optional_fields() {
    for field in [
        r#""$schema": null"#,
        r#""filesystem": null"#,
        r#""filesystem": {"readwritePaths": null}"#,
        r#""filesystem": {"readonlyPaths": null}"#,
        r#""filesystem": {"deniedPaths": null}"#,
        r#""network": null"#,
        r#""network": {"defaultPolicy": null}"#,
        r#""experimental": null"#,
        r#""telemetry": null"#,
        r#""telemetry": {"enabled": null}"#,
        r#""experimental": {"wslc": null}"#,
        r#""experimental": {"wslc": {"provision": null}}"#,
        r#""experimental": {"wslc": {"provision": {"image": null}}}"#,
        r#""experimental": {"wslc": {"provision": {"imageTarPath": null}}}"#,
    ] {
        assert_invalid(&request_with_additional_fields(field));
    }
}

#[test]
fn rejects_unknown_fields_at_each_object_level() {
    for field in [
        r#""unknownField": true"#,
        r#""filesystem": {"unknownField": true}"#,
        r#""network": {"unknownField": true}"#,
        r#""experimental": {"unknownField": true}"#,
        r#""telemetry": {"unknownField": true}"#,
        r#""experimental": {"wslc": {"unknownField": true}}"#,
        r#""experimental": {"wslc": {"provision": {"unknownField": true}}}"#,
    ] {
        assert_invalid(&request_with_additional_fields(field));
    }
}

#[test]
fn rejects_other_wslc_phase_keys() {
    for phase in ["start", "exec", "stop", "deprovision"] {
        assert_invalid(&request_with_additional_fields(&format!(
            r#""experimental": {{"wslc": {{"{phase}": {{}}}}}}"#
        )));
    }
}

#[test]
fn rejects_forbidden_fields() {
    for field in [
        r#""process": {"commandLine": "echo"}"#,
        r#""lifecycle": {}"#,
        r#""containerId": "container-id""#,
        r#""sandboxId": "sandbox-id""#,
        r#""correlationVector": "vector""#,
        r#""processContainer": {}"#,
        r#""appContainer": {}"#,
        r#""lxc": {"distribution": "ubuntu", "release": "20.04"}"#,
        r#""fallback": {}"#,
        r#""ui": {}"#,
        r#""seatbelt": {}"#,
        r#""macos_sandbox": {}"#,
    ] {
        assert_invalid(&request_with_additional_fields(field));
    }
}

#[test]
fn rejects_foreign_backend_experimental_fields() {
    for field in [
        r#""test": {}"#,
        r#""windows_sandbox": {}"#,
        r#""isolation_session": {}"#,
        r#""seatbelt": {}"#,
        r#""macos_sandbox": {}"#,
    ] {
        assert_invalid(&request_with_additional_fields(&format!(
            r#""experimental": {{{field}}}"#
        )));
    }
}

#[test]
fn rejects_duplicate_fields() {
    for fields in [
        r#""$schema": "first", "$schema": "second""#,
        r#""_comment": "first", "_comment": "second""#,
        r#""version": "0.9.0-alpha""#,
        r#""phase": "provision""#,
        r#""containment": "wslc""#,
        r#""filesystem": {}, "filesystem": {}"#,
        r#""network": {}, "network": {}"#,
        r#""experimental": {}, "experimental": {}"#,
    ] {
        assert_invalid(&request_with_additional_fields(fields));
    }
}

#[test]
fn rejects_duplicate_nested_fields() {
    for field in [
        r#""filesystem": {"readwritePaths": [], "readwritePaths": []}"#,
        r#""network": {"defaultPolicy": "block", "defaultPolicy": "allow"}"#,
        r#""telemetry": {}, "telemetry": {}"#,
        r#""experimental": {"wslc": {}, "wslc": {}}"#,
        r#""experimental": {"wslc": {"provision": {}, "provision": {}}}"#,
        r#""experimental": {"wslc": {"provision": {"image": "a", "image": "b"}}}"#,
        r#""experimental": {"wslc": {"provision": {"imageTarPath": "a", "imageTarPath": "b"}}}"#,
    ] {
        assert_invalid(&request_with_additional_fields(field));
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
        assert_invalid(&format!(
            r#"{{
                "version": {version},
                "phase": "provision",
                "containment": "wslc"
            }}"#
        ));
    }
}

#[test]
fn rejects_unknown_phase_value() {
    assert_invalid(
        r#"{
            "version": "0.9.0-alpha",
            "phase": "restart",
            "containment": "wslc"
        }"#,
    );
}

#[test]
fn rejects_non_string_schema_field() {
    for value in ["123", "true", "[]", "{}"] {
        assert_invalid(&request_with_additional_fields(&format!(
            r#""$schema": {value}"#
        )));
    }
}

#[test]
fn rejects_invalid_optional_object_types() {
    // Positional-array rejection is intentionally out of scope.
    for value in [r#""invalid""#, "123", "true"] {
        for field in [
            format!(r#""filesystem": {value}"#),
            format!(r#""network": {value}"#),
            format!(r#""experimental": {value}"#),
            format!(r#""telemetry": {value}"#),
            format!(r#""experimental": {{"wslc": {value}}}"#),
            format!(r#""experimental": {{"wslc": {{"provision": {value}}}}}"#),
        ] {
            assert_invalid(&request_with_additional_fields(&field));
        }
    }
}

#[test]
fn rejects_invalid_filesystem_field_types() {
    for path_field in ["readwritePaths", "readonlyPaths", "deniedPaths"] {
        for value in [r#""path""#, "123", "true", "{}"] {
            assert_invalid(&request_with_additional_fields(&format!(
                r#""filesystem": {{"{path_field}": {value}}}"#
            )));
        }

        for item in ["123", "true", "[]", "{}"] {
            assert_invalid(&request_with_additional_fields(&format!(
                r#""filesystem": {{"{path_field}": [{item}]}}"#
            )));
        }
    }
}

#[test]
fn rejects_invalid_network_field_types() {
    for field in [
        r#""defaultPolicy": 123"#,
        r#""enforcementMode": true"#,
        r#""allowedHosts": "host""#,
        r#""blockedHosts": {}"#,
        r#""allowLocalNetwork": "true""#,
        r#""proxy": "proxy""#,
    ] {
        assert_invalid(&request_with_additional_fields(&format!(
            r#""network": {{{field}}}"#
        )));
    }
}

#[test]
fn rejects_non_string_provision_fields() {
    for field in ["image", "imageTarPath"] {
        for value in ["123", "true", "false", "[]", "{}"] {
            assert_invalid(&request_with_additional_fields(&format!(
                r#""experimental": {{"wslc": {{"provision": {{"{field}": {value}}}}}}}"#
            )));
        }
    }
}

#[test]
fn rejects_non_boolean_telemetry_enabled() {
    for value in ["123", r#""true""#, "[]", "{}"] {
        assert_invalid(&request_with_additional_fields(&format!(
            r#""telemetry": {{"enabled": {value}}}"#
        )));
    }
}

#[test]
fn accepts_comment_value_types() {
    for comment in [
        r#""comment""#,
        r#"{"purpose":"test"}"#,
        r#"["first",2,false]"#,
        "42",
        "true",
        "null",
    ] {
        assert_valid(&request_with_additional_fields(&format!(
            r#""_comment": {comment}"#
        )));
    }
}
