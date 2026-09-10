// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Black-box specification for the refusal of a syntactically malformed egress
//! destination.
//!
//! A destination that cannot be parsed is a typo in the configuration file: it
//! resolves to nothing on every host, at every moment, forever. A well-formed
//! hostname whose lookup returned nothing is a different fact about a different
//! moment. Both are refused, because neither can be programmed into a rule.
//! These tests pin the refusals and pin that the two say different things, so a
//! caller can tell a mistyped entry from one their resolver could not answer.
//!
//! Written against the documented contract in
//! `docs/sandbox-policy/0.8.0/networking/networking.md`, which requires a
//! backend that cannot enforce a policy to reject it rather than accept it with
//! partial enforcement.

use super::*;
use wxc_common::logger::{Logger, Mode};
use wxc_common::models::{ContainerPolicy, NetworkEnforcementMode, ProxyAddress, ProxyConfig};

/// A legacy-schema firewall policy carrying the given host lists.
///
/// The legacy lists are the only egress surface that reaches this backend as
/// unparsed text; schema 0.8 peers arrive as an already-parsed `NetworkCidr`
/// and cannot carry a malformed destination.
fn legacy_policy(allowed: &[&str], blocked: &[&str]) -> ContainerPolicy {
    ContainerPolicy {
        network_enforcement_mode: NetworkEnforcementMode::Firewall,
        allowed_hosts: allowed.iter().map(|host| host.to_string()).collect(),
        blocked_hosts: blocked.iter().map(|host| host.to_string()).collect(),
        ..Default::default()
    }
}

/// Apply `policy` through the fake firewall and hand back the verdict, every
/// command the apply issued, and everything it logged.
fn apply_and_collect(policy: &ContainerPolicy) -> (Result<bool, String>, Vec<Vec<String>>, String) {
    let fake = super::test_firewall::install();
    let mut manager = NetworkIptablesManager::new("malformed-spec");
    manager.set_veth_interface("veth-malformed0");
    let mut logger = Logger::new(Mode::Buffer);
    let _ = fake.forget_issued();

    let result = manager.apply_firewall_rules(policy, &mut logger);
    (result, fake.issued(), logger.get_buffer().to_string())
}

/// Every destination string that is a permanent typo rather than a lookup that
/// happened to fail.
fn malformed_destinations() -> Vec<&'static str> {
    vec![
        // Prefix out of range for the family.
        "10.0.0.0/33",
        "2001:db8::/129",
        // `u8::from_str` accepts a leading sign, so iptables would silently
        // canonicalize this to 10.0.0.0/24 and apply a policy nobody wrote.
        "10.0.0.0/+24",
        // Two prefixes.
        "10.0.0.0/20/8",
        // Missing network.
        "/24",
        // Missing prefix.
        "10.0.0.0/",
        // Network is not an address.
        "not-an-address/24",
    ]
}

#[test]
fn a_malformed_allowed_host_refuses_the_apply() {
    for destination in malformed_destinations() {
        let policy = legacy_policy(&[destination], &[]);
        let (result, _, _) = apply_and_collect(&policy);
        assert!(
            result.is_err(),
            "allowedHosts entry {destination:?} is not a destination and must be refused, \
             but the apply succeeded"
        );
    }
}

#[test]
fn a_malformed_blocked_host_refuses_the_apply() {
    for destination in malformed_destinations() {
        let policy = legacy_policy(&[], &[destination]);
        let (result, _, _) = apply_and_collect(&policy);
        assert!(
            result.is_err(),
            "blockedHosts entry {destination:?} is not a destination and must be refused, \
             but the apply succeeded"
        );
    }
}

#[test]
fn a_blank_entry_refuses_the_apply() {
    for destination in ["", "   ", "\t"] {
        let policy = legacy_policy(&[destination], &[]);
        let (result, _, _) = apply_and_collect(&policy);
        assert!(
            result.is_err(),
            "a blank allowedHosts entry {destination:?} names nothing and must be refused, \
             but the apply succeeded"
        );
    }
}

#[test]
fn the_refusal_names_the_field_and_the_offending_entry() {
    let policy = legacy_policy(&["10.0.0.0/33"], &[]);
    let (result, _, _) = apply_and_collect(&policy);

    let message = result.expect_err("a malformed destination must be refused");
    assert!(
        message.contains("10.0.0.0/33"),
        "the refusal must quote the entry the user has to go and fix, got: {message}"
    );
    assert!(
        message.contains("allowedHosts"),
        "the refusal must name the field the entry came from, got: {message}"
    );
}

#[test]
fn a_malformed_entry_refuses_before_any_chain_is_created() {
    let policy = legacy_policy(&["10.0.0.0/33"], &[]);
    let (result, issued, _) = apply_and_collect(&policy);

    assert!(result.is_err(), "a malformed destination must be refused");
    assert!(
        issued.is_empty(),
        "a typo is decidable without touching the network, so the refusal must land \
         before any chain is created and leave nothing to roll back; issued: {issued:?}"
    );
}

#[test]
fn one_malformed_entry_among_good_ones_refuses_the_whole_policy() {
    let policy = legacy_policy(&["10.1.0.0/16", "10.0.0.0/33", "192.168.0.0/24"], &[]);
    let (result, issued, _) = apply_and_collect(&policy);

    assert!(
        result.is_err(),
        "a policy is refused whole: programming the two well-formed entries and warning \
         about the third would run the container under partial enforcement"
    );
    assert!(
        issued.is_empty(),
        "no part of a refused policy may be programmed; issued: {issued:?}"
    );
}

#[test]
fn a_malformed_entry_is_refused_in_proxy_mode_too() {
    let mut policy = legacy_policy(&["10.0.0.0/33"], &[]);
    policy.network_proxy = ProxyConfig {
        address: Some(ProxyAddress::new("127.0.0.1".to_string(), 3128)),
        builtin_test_server: false,
    };

    let (result, _, _) = apply_and_collect(&policy);
    assert!(
        result.is_err(),
        "proxy mode never resolves allowedHosts, so a typo there is invisible to the \
         unresolved-host warning and must still be refused"
    );
}

#[test]
fn a_hostname_that_did_not_resolve_is_also_refused_but_says_something_different() {
    let policy = legacy_policy(&["no-such-host.invalid"], &[]);
    let (result, _, _) = apply_and_collect(&policy);

    let message = result.expect_err(
        "a destination that resolves to no address cannot be programmed, so the caller \
         learns by the request failing",
    );
    assert!(
        message.contains("no-such-host.invalid"),
        "the refusal must name the entry that was not honored, got: {message}"
    );
    assert!(
        !message.contains("is not a valid destination"),
        "a lookup that returned nothing is not a typo, and the two must not collapse \
         into one message, got: {message}"
    );
}

#[test]
fn well_formed_destinations_still_apply() {
    let policy = legacy_policy(
        &["10.0.0.0/24", "192.168.1.1", "2001:db8::/32", "::1"],
        &["172.16.0.0/12"],
    );
    let (result, issued, _) = apply_and_collect(&policy);

    assert!(
        result.is_ok(),
        "every one of these parses as a destination and must still apply, got: {result:?}"
    );
    assert!(
        !issued.is_empty(),
        "a well-formed policy still programs rules"
    );
}
