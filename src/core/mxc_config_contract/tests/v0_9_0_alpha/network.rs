// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::{assert_invalid, assert_valid};

// Network proxy tests
#[test]
fn accepts_localhost_proxy_port_boundaries() {
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

        assert_valid(&json);
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
fn accepts_builtin_test_server_true() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "network": {
            "proxy": {
                "builtinTestServer": true
            }
        },
        "process": {"commandLine": "echo"}
    }"#;

    assert_valid(json);
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
        "network": {
            "proxy": {
                "url": "http://myproxy:8080"
            }
        },
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
