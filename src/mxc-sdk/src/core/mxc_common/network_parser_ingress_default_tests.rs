// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests the resolved value of an omitted `network.ingress.hostLoopback`.
//!
//! Contract source: `docs/sandbox-policy/0.8.0/networking/networking.md`
//! ("Host Loopback and Inbound Policy") and `docs/sandbox-policy/0.8.0/policy.md`:
//! both ingress controls default to `deny`, and `hostLoopback` resolves
//! independently of `ingress.default` rather than inheriting it.
//!
//! The inherit reading and the deny reading agree everywhere except under
//! `ingress.default: "allow"` with `hostLoopback` omitted, so that case is
//! pinned explicitly here.

use super::*;

fn sections(ingress: Option<wire::NetworkIngress>, network_present: bool) -> NetworkSections {
    NetworkSections {
        network: network_present.then_some(wire::Network {
            default_policy: None,
            enforcement_mode: None,
            allow_local_network: None,
            allowed_hosts: None,
            blocked_hosts: None,
            proxy: None,
            egress: Some(wire::NetworkEgress {
                default: Some(wire::NetworkAction::Allow),
                allow: None,
                deny: None,
            }),
            ingress,
        }),
        runtime: None,
        process_container: None,
    }
}

fn parse(ingress: Option<wire::NetworkIngress>, network_present: bool) -> NetworkIngressPolicy {
    let mut policy = ContainerPolicy::default();
    parse_network_policy(
        &mut policy,
        sections(ingress, network_present),
        &ContainmentBackend::Lxc,
    )
    .expect("a directional policy without a proxy parses");
    policy
        .network_ingress
        .expect("directional parsing always resolves an ingress posture")
}

#[test]
fn an_omitted_network_section_denies_both_ingress_controls() {
    let ingress = parse(None, false);

    assert_eq!(ingress.default, NetworkAction::Deny);
    assert_eq!(ingress.host_loopback, NetworkAction::Deny);
}

#[test]
fn an_omitted_ingress_section_denies_both_controls() {
    let ingress = parse(None, true);

    assert_eq!(ingress.default, NetworkAction::Deny);
    assert_eq!(ingress.host_loopback, NetworkAction::Deny);
}

#[test]
fn an_omitted_host_loopback_denies_under_a_deny_ingress_default() {
    let ingress = parse(
        Some(wire::NetworkIngress {
            default: Some(wire::NetworkAction::Deny),
            host_loopback: None,
        }),
        true,
    );

    assert_eq!(ingress.default, NetworkAction::Deny);
    assert_eq!(ingress.host_loopback, NetworkAction::Deny);
}

/// The case that separates the two readings: inheriting `ingress.default`
/// would resolve to `allow`.
#[test]
fn an_omitted_host_loopback_denies_under_an_allow_ingress_default() {
    let ingress = parse(
        Some(wire::NetworkIngress {
            default: Some(wire::NetworkAction::Allow),
            host_loopback: None,
        }),
        true,
    );

    assert_eq!(ingress.default, NetworkAction::Allow);
    assert_eq!(
        ingress.host_loopback,
        NetworkAction::Deny,
        "an omitted hostLoopback resolves to deny and does not inherit ingress.default"
    );
}

#[test]
fn an_explicit_host_loopback_allow_overrides_a_deny_ingress_default() {
    let ingress = parse(
        Some(wire::NetworkIngress {
            default: Some(wire::NetworkAction::Deny),
            host_loopback: Some(wire::NetworkAction::Allow),
        }),
        true,
    );

    assert_eq!(ingress.default, NetworkAction::Deny);
    assert_eq!(ingress.host_loopback, NetworkAction::Allow);
}

#[test]
fn an_explicit_host_loopback_deny_is_preserved_under_an_allow_ingress_default() {
    let ingress = parse(
        Some(wire::NetworkIngress {
            default: Some(wire::NetworkAction::Allow),
            host_loopback: Some(wire::NetworkAction::Deny),
        }),
        true,
    );

    assert_eq!(ingress.default, NetworkAction::Allow);
    assert_eq!(ingress.host_loopback, NetworkAction::Deny);
}

/// An omitted `hostLoopback` must be indistinguishable from an explicit
/// `"deny"`, so a caller cannot detect the difference downstream.
#[test]
fn an_omitted_host_loopback_matches_an_explicit_deny() {
    let omitted = parse(
        Some(wire::NetworkIngress {
            default: Some(wire::NetworkAction::Allow),
            host_loopback: None,
        }),
        true,
    );
    let explicit = parse(
        Some(wire::NetworkIngress {
            default: Some(wire::NetworkAction::Allow),
            host_loopback: Some(wire::NetworkAction::Deny),
        }),
        true,
    );

    assert_eq!(omitted, explicit);
}
