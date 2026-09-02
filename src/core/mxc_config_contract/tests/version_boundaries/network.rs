// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::assert_v08_introduces;

#[test]
fn directional_egress_is_introduced_in_v08() {
    assert_v08_introduces(
        r#""network": {
            "egress": {
                "default": "deny",
                "allow": [{
                    "to": [{
                        "cidr": "140.82.112.0/20",
                        "except": ["140.82.113.0/24"]
                    }],
                    "ports": [
                        {"protocol": "tcp", "port": 443},
                        {"protocol": "udp", "port": 30000, "endPort": 30100}
                    ]
                }],
                "deny": [{"to": [{"cidr": "10.0.0.0/8"}]}]
            }
        }"#,
    );
}

#[test]
fn directional_ingress_is_introduced_in_v08() {
    assert_v08_introduces(
        r#""network": {
            "ingress": {
                "default": "deny",
                "hostLoopback": "allow"
            }
        }"#,
    );
}

#[test]
fn runtime_config_is_introduced_in_v08() {
    assert_v08_introduces(
        r#""runtimeConfig": {
        "networkProxy": "http://127.0.0.1:8080"
    }"#,
    );
}

#[test]
fn process_container_allowed_proxy_peer_is_introduced_in_v08() {
    assert_v08_introduces(
        r#""processContainer": {
        "network": {
            "allowedProxyPeer": "127.0.0.1"
        }
    }"#,
    );
}
