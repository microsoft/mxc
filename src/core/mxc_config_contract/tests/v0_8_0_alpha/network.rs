// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::{assert_invalid, assert_valid};

// Network proxy tests
#[test]
fn accepts_localhost_proxy_port_boundaries() {
    for proxy_port in [1, 65535] {
        let json = format!(
            r#"{{
                "version": "0.8.0-alpha",
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
                "version": "0.8.0-alpha",
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
        "version": "0.8.0-alpha",
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
        "version": "0.8.0-alpha",
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
        "version": "0.8.0-alpha",
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
                "version": "0.8.0-alpha",
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
        "version": "0.8.0-alpha",
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
        "version": "0.8.0-alpha",
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
        "version": "0.8.0-alpha",
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
        "version": "0.8.0-alpha",
        "network": {
            "proxy": {
                "unknownField": true
            }
        },
        "process": {"commandLine": "echo"}
    }"#;

    assert_invalid(json);
}

// Directional network tests. The 0.8 contract accepts `network.egress` and
// `network.ingress` alongside the legacy fields; the parser, not the contract,
// rejects mixing the two families.
fn with_network(network: &str) -> String {
    format!(
        r#"{{
            "version": "0.8.0-alpha",
            "network": {network},
            "process": {{"commandLine": "echo"}}
        }}"#
    )
}

#[test]
fn accepts_a_complete_directional_policy() {
    assert_valid(&with_network(
        r#"{
            "egress": {
                "default": "deny",
                "allow": [
                    {
                        "to": [
                            {"cidr": "140.82.112.0/20", "except": ["140.82.113.0/24"]},
                            {"cidr": "2606:50c0::/32"}
                        ],
                        "ports": [
                            {"port": 443, "protocol": "tcp"},
                            {"port": 30000, "endPort": 30100, "protocol": "udp"}
                        ]
                    },
                    {"to": [{"cidr": "198.51.100.0/24"}]},
                    {"ports": [{"protocol": "icmp"}]}
                ],
                "deny": [{"to": [{"cidr": "10.0.0.0/8"}]}]
            },
            "ingress": {"default": "deny", "hostLoopback": "allow"}
        }"#,
    ));
}

// Each field inside a rule's `to` and `ports` entries is optional; a missing
// one must not be a parse error.
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
            assert_valid(&with_network(&format!(
                r#"{{"egress": {{"{section}": [{entry}]}}}}"#
            )));
        }
    }
}

#[test]
fn accepts_empty_directional_sections() {
    for network in [
        r#"{"egress": {}}"#,
        r#"{"ingress": {}}"#,
        r#"{"egress": {}, "ingress": {}}"#,
        r#"{"egress": {"allow": []}}"#,
        r#"{"egress": {"deny": []}}"#,
    ] {
        assert_valid(&with_network(network));
    }
}

#[test]
fn rejects_a_destination_without_a_cidr() {
    assert_invalid(&with_network(
        r#"{"egress": {"allow": [{"to": [{"except": ["10.1.0.0/16"]}]}]}}"#,
    ));
}

// `to` and `ports` are non-empty when present, matching the shipped schema's
// minItems constraint.
#[test]
fn rejects_empty_rule_destination_and_port_arrays() {
    for network in [
        r#"{"egress": {"allow": [{"to": []}]}}"#,
        r#"{"egress": {"allow": [{"ports": []}]}}"#,
        r#"{"egress": {"deny": [{"to": []}]}}"#,
        r#"{"egress": {"deny": [{"ports": []}]}}"#,
    ] {
        assert_invalid(&with_network(network));
    }
}

#[test]
fn accepts_directional_port_boundaries() {
    for port in [1, 65535] {
        assert_valid(&with_network(&format!(
            r#"{{"egress": {{"allow": [{{"ports": [{{"port": {port}}}]}}]}}}}"#
        )));
    }
}

#[test]
fn rejects_directional_ports_out_of_bounds() {
    for port in [0, 65536] {
        assert_invalid(&with_network(&format!(
            r#"{{"egress": {{"allow": [{{"ports": [{{"port": {port}}}]}}]}}}}"#
        )));
        assert_invalid(&with_network(&format!(
            r#"{{"egress": {{"allow": [{{"ports": [{{"port": 1, "endPort": {port}}}]}}]}}}}"#
        )));
    }
}

#[test]
fn accepts_every_network_action_value() {
    for action in ["allow", "deny"] {
        for section in [
            format!(r#"{{"egress": {{"default": "{action}"}}}}"#),
            format!(r#"{{"ingress": {{"default": "{action}"}}}}"#),
            format!(r#"{{"ingress": {{"hostLoopback": "{action}"}}}}"#),
        ] {
            assert_valid(&with_network(&section));
        }
    }
}

// The directional actions are allow/deny; the legacy `defaultPolicy` remains
// allow/block, so `block` must not leak into the directional vocabulary.
#[test]
fn rejects_invalid_network_action_values() {
    for network in [
        r#"{"egress": {"default": "block"}}"#,
        r#"{"ingress": {"default": "block"}}"#,
        r#"{"ingress": {"hostLoopback": "invalid"}}"#,
    ] {
        assert_invalid(&with_network(network));
    }
}

#[test]
fn accepts_every_network_protocol_value() {
    for protocol in ["tcp", "udp", "icmp", "any"] {
        assert_valid(&with_network(&format!(
            r#"{{"egress": {{"allow": [{{"ports": [{{"protocol": "{protocol}"}}]}}]}}}}"#
        )));
    }
}

#[test]
fn rejects_invalid_network_protocol_value() {
    assert_invalid(&with_network(
        r#"{"egress": {"allow": [{"ports": [{"protocol": "sctp"}]}]}}"#,
    ));
}

#[test]
fn rejects_unknown_fields_in_every_directional_object() {
    for network in [
        r#"{"egress": {"nope": true}}"#,
        r#"{"ingress": {"nope": true}}"#,
        r#"{"egress": {"allow": [{"nope": true}]}}"#,
        r#"{"egress": {"allow": [{"to": [{"cidr": "10.0.0.0/8", "nope": true}]}]}}"#,
        r#"{"egress": {"allow": [{"ports": [{"port": 443, "nope": true}]}]}}"#,
    ] {
        assert_invalid(&with_network(network));
    }
}

#[test]
fn rejects_null_in_directional_objects() {
    for network in [
        r#"{"egress": null}"#,
        r#"{"ingress": null}"#,
        r#"{"egress": {"default": null}}"#,
        r#"{"egress": {"allow": null}}"#,
        r#"{"egress": {"deny": null}}"#,
        r#"{"ingress": {"default": null}}"#,
        r#"{"ingress": {"hostLoopback": null}}"#,
        r#"{"egress": {"allow": [{"to": null}]}}"#,
        r#"{"egress": {"allow": [{"ports": null}]}}"#,
        r#"{"egress": {"allow": [{"to": [{"cidr": null}]}]}}"#,
        r#"{"egress": {"allow": [{"to": [{"cidr": "10.0.0.0/8", "except": null}]}]}}"#,
        r#"{"egress": {"allow": [{"ports": [{"protocol": null}]}]}}"#,
        r#"{"egress": {"allow": [{"ports": [{"port": null}]}]}}"#,
        r#"{"egress": {"allow": [{"ports": [{"endPort": null}]}]}}"#,
    ] {
        assert_invalid(&with_network(network));
    }
}

#[test]
fn rejects_non_string_cidr_and_non_integer_ports() {
    for network in [
        r#"{"egress": {"allow": [{"to": [{"cidr": 42}]}]}}"#,
        r#"{"egress": {"allow": [{"ports": [{"port": "443"}]}]}}"#,
    ] {
        assert_invalid(&with_network(network));
    }
}
