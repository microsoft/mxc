// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::{assert_invalid, assert_valid};

#[test]
fn every_removed_property_is_rejected_from_every_request_root() {
    use mxc_config_contract::published::v0_9_0_alpha::parse_request;
    use serde_json::{json, Map, Value};

    let roots = [
        json!({"process": {"commandLine": "echo"}}),
        json!({
            "phase": "exec",
            "sandboxId": "wslc:id",
            "process": {"commandLine": "echo"}
        }),
        json!({
            "phase": "provision",
            "containment": "isolation_session",
            "network": {
                "egress": {"default": "allow"},
                "ingress": {"default": "allow", "hostLoopback": "allow"}
            }
        }),
        json!({"phase": "start", "sandboxId": "iso:id"}),
        json!({"phase": "stop", "sandboxId": "iso:id"}),
        json!({"phase": "deprovision", "sandboxId": "iso:id"}),
    ];
    for mut valid in roots {
        valid
            .as_object_mut()
            .unwrap()
            .insert("version".to_string(), json!("0.9.0-alpha"));
        let valid_source = serde_json::to_string(&valid).unwrap();
        assert!(parse_request(&valid_source).is_ok(), "{valid_source}");

        for (field, value) in [
            ("defaultPolicy", json!("allow")),
            ("enforcementMode", json!("capabilities")),
            ("allowedHosts", json!([])),
            ("blockedHosts", json!([])),
            ("allowLocalNetwork", json!(false)),
            ("proxy", json!({"url": "http://localhost:8080"})),
        ] {
            let mut invalid = valid.clone();
            invalid
                .as_object_mut()
                .unwrap()
                .entry("network")
                .or_insert_with(|| Value::Object(Map::new()))
                .as_object_mut()
                .unwrap()
                .insert(field.to_string(), value);
            let invalid_source = serde_json::to_string(&invalid).unwrap();
            assert!(parse_request(&invalid_source).is_err(), "{invalid_source}");
        }
    }
}

#[test]
fn exec_runtime_proxy_is_a_closed_optional_string_surface() {
    use mxc_config_contract::published::v0_9_0_alpha::parse_request;
    for runtime in [
        r#"{"networkProxy":null}"#,
        r#"{"networkProxy":true}"#,
        r#"{"networkProxy":8080}"#,
        r#"{"proxy":"http://localhost:8080"}"#,
        r#"{"networkProxy":"first","networkProxy":"second"}"#,
    ] {
        let source = format!(
            r#"{{"version":"0.9.0-alpha","phase":"exec","sandboxId":"wslc:id","process":{{"commandLine":"echo"}},"runtimeConfig":{runtime}}}"#
        );
        assert!(parse_request(&source).is_err(), "{source}");
    }
    for runtime in [r#"{}"#, r#"{"networkProxy":"http://proxy.example:8080"}"#] {
        let source = format!(
            r#"{{"version":"0.9.0-alpha","phase":"exec","sandboxId":"wslc:id","process":{{"commandLine":"echo"}},"runtimeConfig":{runtime}}}"#
        );
        assert!(parse_request(&source).is_ok(), "{source}");
    }
}

// Network proxy tests
#[test]
fn rejects_removed_localhost_proxy_even_at_valid_port_boundaries() {
    for proxy_port in [1, 65535] {
        let json = format!(
            r#"{{
                "version": "0.9.0-alpha",
                "network": {{
                    "proxy": {{
                        "localhost": {proxy_port}
                    }}
                }},
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_invalid(&json);
    }
}

#[test]
fn rejects_localhost_proxy_port_out_of_bounds() {
    for proxy_port in [0, 65536] {
        let json = format!(
            r#"{{
                "version": "0.9.0-alpha",
                "network": {{
                    "proxy": {{
                        "localhost": {proxy_port}
                    }}
                }},
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_invalid(&json);
    }
}

#[test]
fn rejects_removed_builtin_test_server_even_when_true() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "network": {
            "proxy": {
                "builtinTestServer": true
            }
        },
        "process": {"commandLine": "echo"}
    }"#;

    assert_invalid(json);
}

#[test]
fn rejects_builtin_test_server_false() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "network": {
            "proxy": {
                "builtinTestServer": false
            }
        },
        "process": {"commandLine": "echo"}
    }"#;

    assert_invalid(json);
}

#[test]
fn rejects_builtin_test_server_null() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "network": {
            "proxy": {
                "builtinTestServer": null
            }
        },
        "process": {"commandLine": "echo"}
    }"#;

    assert_invalid(json);
}

#[test]
fn rejects_builtin_test_server_non_boolean_values() {
    for builtin_test_server in ["0", "1", "\"true\"", "\"false\"", "[]", "{}"] {
        let json = format!(
            r#"{{
                "version": "0.9.0-alpha",
                "network": {{
                    "proxy": {{
                        "builtinTestServer": {builtin_test_server}
                    }}
                }},
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_invalid(&json);
    }
}

#[test]
fn accepts_url_proxy() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "runtimeConfig": {"networkProxy": "http://myproxy:8080"},
        "process": {"commandLine": "echo"}
    }"#;

    assert_valid(json);
}

#[test]
fn rejects_all_combinations_of_proxy_with_multiple_variants() {
    let builtin_test_server = r#""builtinTestServer": true"#;
    let localhost = r#""localhost": 8080"#;
    let url = r#""url": "http://myproxy:8080""#;

    for combo in [
        format!("{builtin_test_server}, {localhost}"),
        format!("{builtin_test_server}, {url}"),
        format!("{localhost}, {url}"),
        format!("{builtin_test_server}, {localhost}, {url}"),
    ]
    .iter()
    {
        let json = format!(
            r#"{{
        "version": "0.9.0-alpha",
        "network": {{
            "proxy": {{ {combo} }}
        }},
        "process": {{"commandLine": "echo"}}
    }}"#,
        );

        assert_invalid(&json);
    }
}

#[test]
fn rejects_empty_proxy_object() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "network": {
            "proxy": {}
        },
        "process": {"commandLine": "echo"}
    }"#;

    assert_invalid(json);
}

#[test]
fn rejects_unknown_proxy_field() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "network": {
            "proxy": {
                "unknownField": true
            }
        },
        "process": {"commandLine": "echo"}
    }"#;

    assert_invalid(json);
}

// Directional network optional-field tests. Each field inside a rule's `to`
// and `ports` entries is optional; a missing one must not be a parse error.
#[test]
fn accepts_partial_directional_rule_entries() {
    for entry in [
        r#"{"to": [{"cidr": "10.0.0.0/8"}]}"#,
        r#"{"to": [{"cidr": "10.0.0.0/8", "except": ["10.1.0.0/16"]}]}"#,
        r#"{"ports": [{"port": 443}]}"#,
        r#"{"ports": [{"protocol": "tcp"}]}"#,
        r#"{"ports": [{"port": 443, "protocol": "tcp"}]}"#,
        r#"{"ports": [{"port": 30000, "endPort": 30100}]}"#,
        r#"{"ports": [{"port": 30000, "endPort": 30100, "protocol": "udp"}]}"#,
        r#"{"ports": [{}]}"#,
        r#"{}"#,
    ] {
        for section in ["allow", "deny"] {
            let json = format!(
                r#"{{
                    "version": "0.9.0-alpha",
                    "network": {{"egress": {{"{section}": [{entry}]}}}},
                    "process": {{"commandLine": "echo"}}
                }}"#
            );

            assert_valid(&json);
        }
    }
}

#[test]
fn rejects_a_destination_without_a_cidr() {
    assert_invalid(
        r#"{
            "version": "0.9.0-alpha",
            "network": {"egress": {"allow": [{"to": [{"except": ["10.1.0.0/16"]}]}]}},
            "process": {"commandLine": "echo"}
        }"#,
    );
}
