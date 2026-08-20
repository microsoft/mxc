// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::super::common::{
    assert_invalid as assert_invalid_request, assert_valid as assert_valid_request,
};
use mxc_config_contract::dev::IsolationSessionProvisionRequest;

fn assert_valid(json: &str) {
    assert_valid_request::<IsolationSessionProvisionRequest>(json);
}

fn assert_invalid(json: &str) {
    assert_invalid_request::<IsolationSessionProvisionRequest>(json);
}

fn request_with_additional_fields(additional_fields: &str) -> String {
    format!(
        r#"{{
            "version": "0.8.0-alpha",
            "phase": "provision",
            "containment": "isolation_session",
            "network": {{
                "defaultPolicy": "allow",
                "allowLocalNetwork": true
            }},
            {additional_fields}
        }}"#
    )
}

fn request_with_network_fields(network_fields: &str) -> String {
    format!(
        r#"{{
            "version": "0.8.0-alpha",
            "phase": "provision",
            "containment": "isolation_session",
            "network": {{{network_fields}}}
        }}"#
    )
}

fn request_with_containment_value(containment: &str) -> String {
    format!(
        r#"{{
            "version": "0.8.0-alpha",
            "phase": "provision",
            "containment": {containment},
            "network": {{
                "defaultPolicy": "allow",
                "allowLocalNetwork": true
            }}
        }}"#
    )
}

#[test]
fn accepts_minimal_provision_request() {
    let json = r#"{
            "version": "0.8.0-alpha",
            "phase": "provision",
            "containment": "isolation_session",
            "network": {
                "defaultPolicy": "allow",
                "allowLocalNetwork": true
            }
    }"#;
    assert_valid(json);
}

#[test]
fn accepts_provision_request_with_optional_fields() {
    let json = r#"{
        "$schema": "https://example.com/provision.schema.json",
        "_comment": "This is a comment",
        "version": "0.8.0-alpha",
        "phase": "provision",
        "containment": "isolation_session",
        "network": {
            "defaultPolicy": "allow",
            "allowLocalNetwork": true
        },
        "experimental": {
            "telemetry": {
                "enabled": true
            },
            "isolation_session": {
                "provision": {
                  "appId": "someAppId"
                }
            }
        }
    }"#;
    assert_valid(json);
}

#[test]
fn accepts_empty_provision_experimental_objects() {
    for field in [
        r#""experimental": {}"#,
        r#""experimental": {"telemetry": {}}"#,
        r#""experimental": {"isolation_session": {}}"#,
        r#""experimental": {"isolation_session": {"provision": {}}}"#,
    ] {
        assert_valid(&request_with_additional_fields(field));
    }
}

#[test]
fn accepts_provision_telemetry_enabled_values() {
    for enabled in [true, false] {
        let json = format!(
            r#"{{
                "version": "0.8.0-alpha",
                "phase": "provision",
                "containment": "isolation_session",
                "network": {{
                    "defaultPolicy": "allow",
                    "allowLocalNetwork": true
                }},
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
fn provision_phase_accepts_exact_and_escaped_spelling() {
    for phase in ["provision", "pr\\u006Fvision"] {
        let json = format!(
            r#"{{
                "version": "0.8.0-alpha",
                "phase": "{phase}",
                "containment": "isolation_session",
                "network": {{
                    "defaultPolicy": "allow",
                    "allowLocalNetwork": true
                }}
            }}"#
        );
        assert_valid(&json);
    }
}

#[test]
fn provision_request_rejects_other_phases() {
    for phase in ["deprovision", "exec", "start", "stop"] {
        let json = format!(
            r#"{{
                "version": "0.8.0-alpha",
                "phase": "{phase}",
                "containment": "isolation_session",
                "network": {{
                    "defaultPolicy": "allow",
                    "allowLocalNetwork": true
                }}
            }}"#
        );
        assert_invalid(&json);
    }
}

#[test]
fn containment_accepts_exact_and_escaped_spelling() {
    for containment in ["isolation_session", "is\\u006Flation_session"] {
        let json = format!(
            r#"{{
                "version": "0.8.0-alpha",
                "phase": "provision",
                "containment": "{containment}",
                "network": {{
                    "defaultPolicy": "allow",
                    "allowLocalNetwork": true
                }}
            }}"#
        );
        assert_valid(&json);
    }
}

#[test]
fn rejects_missing_required_provision_fields() {
    let json = r#"{
            "phase": "provision",
            "containment": "isolation_session",
            "network": {
                "defaultPolicy": "allow",
                "allowLocalNetwork": true
            }
    }"#;
    assert_invalid(json);

    let json = r#"{
            "version": "0.8.0-alpha",
            "containment": "isolation_session",
            "network": {
                "defaultPolicy": "allow",
                "allowLocalNetwork": true
            }
    }"#;
    assert_invalid(json);

    let json = r#"{
            "version": "0.8.0-alpha",
            "phase": "provision",
            "network": {
                "defaultPolicy": "allow",
                "allowLocalNetwork": true
            }
    }"#;
    assert_invalid(json);

    let json = r#"{
            "version": "0.8.0-alpha",
            "phase": "provision",
            "containment": "isolation_session"
    }"#;
    assert_invalid(json);

    let json = r#"{
            "version": "0.8.0-alpha",
            "phase": "provision",
            "containment": "isolation_session",
            "network": {
                "allowLocalNetwork": true
            }
    }"#;
    assert_invalid(json);

    let json = r#"{
            "version": "0.8.0-alpha",
            "phase": "provision",
            "containment": "isolation_session",
            "network": {
                "defaultPolicy": "allow"
            }
    }"#;
    assert_invalid(json);
}

#[test]
fn rejects_null_required_provision_fields() {
    let json = r#"{
            "version": null,
            "phase": "provision",
            "containment": "isolation_session",
            "network": {
                "defaultPolicy": "allow",
                "allowLocalNetwork": true
            }
    }"#;
    assert_invalid(json);

    let json = r#"{
            "version": "0.8.0-alpha",
            "phase": null,
            "containment": "isolation_session",
            "network": {
                "defaultPolicy": "allow",
                "allowLocalNetwork": true
            }
    }"#;
    assert_invalid(json);

    let json = r#"{
            "version": "0.8.0-alpha",
            "phase": "provision",
            "containment": null,
            "network": {
                "defaultPolicy": "allow",
                "allowLocalNetwork": true
            }
    }"#;
    assert_invalid(json);

    let json = r#"{
            "version": "0.8.0-alpha",
            "phase": "provision",
            "containment": "isolation_session",
            "network": null
    }"#;
    assert_invalid(json);

    let json = r#"{
            "version": "0.8.0-alpha",
            "phase": "provision",
            "containment": "isolation_session",
            "network": {
                "defaultPolicy": null,
                "allowLocalNetwork": true
            }
    }"#;
    assert_invalid(json);

    let json = r#"{
            "version": "0.8.0-alpha",
            "phase": "provision",
            "containment": "isolation_session",
            "network": {
                "defaultPolicy": "allow",
                "allowLocalNetwork": null
            }
    }"#;
    assert_invalid(json);
}

#[test]
fn rejects_non_string_phase_field() {
    for phase in ["123", "true", "false", "[]", "{}"] {
        let json = format!(
            r#"{{
                "version": "0.8.0-alpha",
                "phase": {phase},
                "containment": "isolation_session",
                "network": {{
                    "defaultPolicy": "allow",
                    "allowLocalNetwork": true
                }}
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
                "version": "0.8.0-alpha",
                "phase": "provision",
                "containment": "isolation_session",
                "network": {{
                    "defaultPolicy": "allow",
                    "allowLocalNetwork": true
                }},
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
        r#""experimental": null"#,
        r#""experimental": {"telemetry": null}"#,
        r#""experimental": {"telemetry": {"enabled": null}}"#,
        r#""experimental": {"isolation_session": null }"#,
        r#""experimental": {"isolation_session": {"provision": null }}"#,
        r#""experimental": {"isolation_session": {"provision": {"appId": null }}}"#,
    ] {
        assert_invalid(&request_with_additional_fields(field));
    }
}

#[test]
fn rejects_unknown_provision_fields() {
    let json = r#"{
            "version": "0.8.0-alpha",
            "phase": "provision",
            "containment": "isolation_session",
            "network": {
                "defaultPolicy": "allow",
                "allowLocalNetwork": true
            },
            "unknownField": "unknown"
    }"#;
    assert_invalid(json);
}

#[test]
fn rejects_unknown_provision_experimental_fields() {
    let json = r#"{
            "version": "0.8.0-alpha",
            "phase": "provision",
            "containment": "isolation_session",
            "network": {
                "defaultPolicy": "allow",
                "allowLocalNetwork": true
            },
            "experimental": {
                "unknownField": "unknown"
            }
    }"#;
    assert_invalid(json);
}

#[test]
fn rejects_unknown_provision_experimental_telemetry_fields() {
    let json = r#"{
            "version": "0.8.0-alpha",
            "phase": "provision",
            "containment": "isolation_session",
            "network": {
                "defaultPolicy": "allow",
                "allowLocalNetwork": true
            },
            "experimental": {
                "telemetry": {
                    "unknownField": "unknown"
                }
            }
    }"#;
    assert_invalid(json);
}

#[test]
fn rejects_unknown_provision_experimental_isolation_session_fields() {
    let json = r#"{
            "version": "0.8.0-alpha",
            "phase": "provision",
            "containment": "isolation_session",
            "network": {
                "defaultPolicy": "allow",
                "allowLocalNetwork": true
            },
            "experimental": {
                "isolation_session": {
                    "unknownField": "unknown"
                }
            }
    }"#;
    assert_invalid(json);
}

#[test]
fn rejects_unknown_provision_experimental_isolation_session_provision_fields() {
    let json = r#"{
            "version": "0.8.0-alpha",
            "phase": "provision",
            "containment": "isolation_session",
            "network": {
                "defaultPolicy": "allow",
                "allowLocalNetwork": true
            },
            "experimental": {
                "isolation_session": {
                    "provision": {
                        "unknownField": "unknown"
                    }
                }
            }
    }"#;
    assert_invalid(json);
}

#[test]
fn rejects_forbidden_fields() {
    for field in [
        r#""process": {"commandLine": "echo"}"#,
        r#""lifecycle": {}"#,
        r#""containerId": "container-id""#,
        r#""sandboxId": "sandbox-id""#,
        r#""correlationVector": "someVector""#,
        r#""processContainer": {}"#,
        r#""appContainer": {}"#,
        r#""lxc": {"distribution": "ubuntu", "release": "20.04"}"#,
        r#""fallback": {}"#,
        r#""filesystem": {}"#,
        r#""ui": {}"#,
        r#""seatbelt": {}"#,
        r#""macos_sandbox": {}"#,
    ] {
        assert_invalid(&request_with_additional_fields(field));
    }
}

#[test]
fn accepts_app_id_string_values() {
    for app_id in [r#""""#, r#""someAppId""#] {
        let field = format!(
            r#""experimental": {{
                "isolation_session": {{
                    "provision": {{"appId": {app_id}}}
                }}
            }}"#
        );
        assert_valid(&request_with_additional_fields(&field));
    }
}

#[test]
fn rejects_non_string_app_id() {
    for app_id in ["123", "true", "false", "[]", "{}"] {
        let field = format!(
            r#""experimental": {{
                "isolation_session": {{
                    "provision": {{"appId": {app_id}}}
                }}
            }}"#
        );
        assert_invalid(&request_with_additional_fields(&field));
    }
}

#[test]
fn rejects_non_isolation_session_backend_experimental_fields() {
    for field in [
        r#""test": {}"#,
        r#""windows_sandbox": {}"#,
        r#""wslc": {}"#,
        r#""seatbelt": {}"#,
        r#""macos_sandbox": {}"#,
    ] {
        let json = request_with_additional_fields(&format!(r#""experimental": {{{field}}}"#));
        assert_invalid(&json);
    }
}

#[test]
fn rejects_duplicate_provision_fields() {
    for fields in [
        r#""$schema": "first", "$schema": "second""#,
        r#""_comment": "first", "_comment": "second""#,
        r#""version": "0.8.0-alpha""#,
        r#""phase": "provision""#,
        r#""containment": "isolation_session""#,
        r#""network": {}"#,
    ] {
        assert_invalid(&request_with_additional_fields(fields));
    }
}

#[test]
fn rejects_duplicate_provision_experimental_fields() {
    for experimental in [
        r#""telemetry": {}, "telemetry": {}"#,
        r#""telemetry": {"enabled": true, "enabled": false}"#,
        r#""isolation_session": {}, "isolation_session": {}"#,
        r#""isolation_session": { "provision": {}, "provision": {}}"#,
        r#""isolation_session": { "provision": {"appId": "appIdA", "appId": "appIdB"}}"#,
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
        r#""0.8.0""#,
        r#""invalid""#,
        "123",
        "true",
        "[]",
        "{}",
    ] {
        let json = format!(
            r#"{{
                "version": {version},
                "phase": "provision",
                "containment": "isolation_session",
                "network": {{
                    "defaultPolicy": "allow",
                    "allowLocalNetwork": true
                }}
            }}"#
        );
        assert_invalid(&json);
    }
}

#[test]
fn rejects_unknown_phase_value() {
    let json = r#"{
        "version": "0.8.0-alpha",
        "phase": "startup",
        "containment": "isolation_session",
        "network": {
            "defaultPolicy": "allow",
            "allowLocalNetwork": true
        }
    }"#;

    assert_invalid(json);
}

#[test]
fn rejects_other_isolation_session_phase_keys() {
    for phase in ["start", "exec", "stop", "deprovision"] {
        let field = format!(
            r#""experimental": {{
                "isolation_session": {{
                    "{phase}": {{}}
                }}
            }}"#
        );
        assert_invalid(&request_with_additional_fields(&field));
    }
}

#[test]
fn rejects_non_string_schema_field() {
    for value in ["123", "true", "[]", "{}"] {
        let json = request_with_additional_fields(&format!(r#""$schema": {value}"#));
        assert_invalid(&json);
    }
}

#[test]
fn rejects_invalid_experimental_object_types() {
    // Positional-array rejection is intentionally out of scope.
    for value in [r#""invalid""#, "123", "true"] {
        let json = request_with_additional_fields(&format!(r#""experimental": {value}"#));
        assert_invalid(&json);

        let json =
            request_with_additional_fields(&format!(r#""experimental": {{"telemetry": {value}}}"#));
        assert_invalid(&json);

        let json = request_with_additional_fields(&format!(
            r#""experimental": {{"isolation_session": {value}}}"#
        ));
        assert_invalid(&json);

        let json = request_with_additional_fields(&format!(
            r#""experimental": {{"isolation_session": {{"provision": {value}}}}}"#
        ));
        assert_invalid(&json);
    }
}

#[test]
fn network_default_policy_accepts_exact_and_escaped_spelling() {
    for default_policy in ["allow", "all\\u006fw"] {
        let network_fields =
            format!(r#""defaultPolicy": "{default_policy}", "allowLocalNetwork": true"#);
        assert_valid(&request_with_network_fields(&network_fields));
    }
}

#[test]
fn rejects_network_policy_block() {
    let json = r#"{
            "version": "0.8.0-alpha",
            "phase": "provision",
            "containment": "isolation_session",
            "network": {
                "defaultPolicy": "block",
                "allowLocalNetwork": true
            }
    }"#;
    assert_invalid(json);
}

#[test]
fn rejects_allow_local_network_false() {
    let json = r#"{
            "version": "0.8.0-alpha",
            "phase": "provision",
            "containment": "isolation_session",
            "network": {
                "defaultPolicy": "allow",
                "allowLocalNetwork": false
            }
    }"#;
    assert_invalid(json);
}

#[test]
fn rejects_invalid_network_field_types() {
    for default_policy in ["123", "true", "false", "[]", "{}"] {
        let network_fields =
            format!(r#""defaultPolicy": {default_policy}, "allowLocalNetwork": true"#);
        assert_invalid(&request_with_network_fields(&network_fields));
    }

    for allow_local_network in [r#""true""#, "123", "[]", "{}"] {
        let network_fields =
            format!(r#""defaultPolicy": "allow", "allowLocalNetwork": {allow_local_network}"#);
        assert_invalid(&request_with_network_fields(&network_fields));
    }
}

#[test]
fn rejects_unknown_network_fields() {
    for field in [
        r#""enforcementMode": "capabilities""#,
        r#""allowedHosts": []"#,
        r#""blockedHosts": []"#,
        r#""proxy": {"url": "http://proxy.example"}"#,
        r#""unknownField": true"#,
    ] {
        let network_fields =
            format!(r#""defaultPolicy": "allow", "allowLocalNetwork": true, {field}"#);
        assert_invalid(&request_with_network_fields(&network_fields));
    }
}

#[test]
fn rejects_duplicate_network_fields() {
    for network_fields in [
        r#""defaultPolicy": "allow", "defaultPolicy": "allow", "allowLocalNetwork": true"#,
        r#""defaultPolicy": "allow", "allowLocalNetwork": true, "allowLocalNetwork": true"#,
    ] {
        assert_invalid(&request_with_network_fields(network_fields));
    }
}

#[test]
fn rejects_other_containment_values() {
    for containment in ["windows_sandbox", "wslc", "vm", "unknown"] {
        let containment = format!(r#""{containment}""#);
        assert_invalid(&request_with_containment_value(&containment));
    }
}

#[test]
fn rejects_non_string_containment_field() {
    for containment in ["123", "true", "false", "[]", "{}"] {
        assert_invalid(&request_with_containment_value(containment));
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
