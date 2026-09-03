// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Black-box specification for the rule that LXC refuses whatever it cannot
//! enforce.
//!
//! A configuration file names what the container may reach. Where this backend
//! cannot program what was named, the caller learns by the request failing --
//! never by a log line under a container that is already running under a policy
//! nobody wrote.
//!
//! Two forms are pinned here. A destination that resolves to no address cannot
//! become a rule. An allow list supplied beside a proxy is never programmed at
//! all, because proxy mode carries the proxy accepts and its closing drop and
//! nothing else.
//!
//! The deny direction is deliberately excluded. An unresolvable deny under a
//! blocking default is already denied by that default, so the policy the caller
//! wrote is fully enforced, and the existing hard error for the case where the
//! default would accept it is untouched.

use super::*;
use wxc_common::logger::{Logger, Mode};
use wxc_common::models::{
    ContainerPolicy, NetworkEnforcementMode, NetworkPolicy, ProxyAddress, ProxyConfig,
};

const CHAIN: &str = "MXC-ERROR-STANDARD";

/// A name reserved by RFC 2606 so that it can never resolve on any host.
///
/// It is well formed, which is what separates it from a typo: the refusal under
/// test has to come from the lookup returning nothing, not from the string
/// failing to parse.
const NEVER_RESOLVES: &str = "no-such-host.invalid";

fn policy_with_allowed(host: &str, default: NetworkPolicy) -> ContainerPolicy {
    ContainerPolicy {
        network_enforcement_mode: NetworkEnforcementMode::Firewall,
        allowed_hosts: vec![host.to_string()],
        default_network_policy: default,
        ..Default::default()
    }
}

fn proxy_policy(allowed: &[&str]) -> ContainerPolicy {
    ContainerPolicy {
        network_enforcement_mode: NetworkEnforcementMode::Firewall,
        allowed_hosts: allowed.iter().map(|host| host.to_string()).collect(),
        network_proxy: ProxyConfig {
            address: Some(ProxyAddress::new("198.51.100.7".to_string(), 8080)),
            builtin_test_server: false,
        },
        ..Default::default()
    }
}

/// Drive a policy through the fake firewall and hand back the verdict and log.
fn apply(policy: &ContainerPolicy) -> (Result<bool, String>, String) {
    let _fake = super::test_firewall::install();
    let mut manager = NetworkIptablesManager::new("error-standard-spec");
    manager.set_veth_interface("veth-errstd0");
    let mut logger = Logger::new(Mode::Buffer);
    let result = manager.apply_firewall_rules(policy, &mut logger);
    (result, logger.get_buffer().to_string())
}

// ---------------------------------------------------------------------------
// A destination that resolves to nothing
// ---------------------------------------------------------------------------

#[test]
fn an_allow_that_resolves_to_no_address_refuses_the_apply() {
    let policy = policy_with_allowed(NEVER_RESOLVES, NetworkPolicy::Block);
    let (result, _) = apply(&policy);

    assert!(
        result.is_err(),
        "an allowed destination that resolves to no address cannot be \
         programmed, so the caller must learn by the request failing; actual: \
         {result:?}"
    );
}

#[test]
fn an_allow_that_resolves_to_no_address_refuses_under_an_allow_default() {
    let policy = policy_with_allowed(NEVER_RESOLVES, NetworkPolicy::Allow);
    let (result, _) = apply(&policy);

    assert!(
        result.is_err(),
        "the default network policy does not change whether the named \
         destination could be programmed; actual: {result:?}"
    );
}

#[test]
fn the_refusal_names_the_destination_that_could_not_be_programmed() {
    let policy = policy_with_allowed(NEVER_RESOLVES, NetworkPolicy::Block);
    let (result, _) = apply(&policy);

    let message = result.expect_err("the apply must fail");
    assert!(
        message.contains(NEVER_RESOLVES),
        "the caller has to be told which line of their configuration was not \
         honored; actual: {message:?}"
    );
}

#[test]
fn build_policy_rules_refuses_an_unresolvable_allow_directly() {
    let policy = policy_with_allowed(NEVER_RESOLVES, NetworkPolicy::Block);
    let mut logger = Logger::new(Mode::Buffer);

    let result =
        NetworkIptablesManager::build_policy_rules_logged(CHAIN, &policy, false, &mut logger);

    assert!(
        result.is_err(),
        "the refusal belongs where the rule is built, so no caller can reach \
         the unenforced policy by another route; actual: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// An allow list supplied beside a proxy
// ---------------------------------------------------------------------------

#[test]
fn an_allow_list_beside_a_proxy_refuses_the_apply() {
    let policy = proxy_policy(&["198.51.100.42/32"]);
    let (result, _) = apply(&policy);

    assert!(
        result.is_err(),
        "proxy mode never programs the allow list, so a caller who supplied \
         one wrote configuration that is not honored; actual: {result:?}"
    );
}

#[test]
fn the_proxy_refusal_says_the_allow_list_is_the_problem() {
    let policy = proxy_policy(&["198.51.100.42/32"]);
    let (result, _) = apply(&policy);

    let message = result.expect_err("the apply must fail");
    assert!(
        message.contains("allowedHosts"),
        "the caller has to be told which part of their configuration cannot \
         be honored beside a proxy; actual: {message:?}"
    );
}

// ---------------------------------------------------------------------------
// Controls -- these must keep passing, or the change reached too far
// ---------------------------------------------------------------------------

#[test]
fn a_proxy_with_no_allow_list_still_applies() {
    let policy = proxy_policy(&[]);
    let (result, _) = apply(&policy);

    assert!(
        result.is_ok(),
        "a proxy on its own is the supported posture and must be unaffected; \
         actual: {result:?}"
    );
}

#[test]
fn a_resolvable_allow_still_applies() {
    let policy = policy_with_allowed("198.51.100.42/32", NetworkPolicy::Block);
    let (result, _) = apply(&policy);

    assert!(
        result.is_ok(),
        "a destination that programs cleanly must be unaffected; actual: \
         {result:?}"
    );
}

#[test]
fn an_unresolvable_deny_under_a_blocking_default_still_applies() {
    let policy = ContainerPolicy {
        network_enforcement_mode: NetworkEnforcementMode::Firewall,
        blocked_hosts: vec![NEVER_RESOLVES.to_string()],
        default_network_policy: NetworkPolicy::Block,
        ..Default::default()
    };
    let (result, _) = apply(&policy);

    assert!(
        result.is_ok(),
        "the blocking default already denies what the entry named, so the \
         policy the caller wrote is fully enforced; actual: {result:?}"
    );
}

#[test]
fn an_unresolvable_deny_under_an_accepting_default_still_refuses() {
    let policy = ContainerPolicy {
        network_enforcement_mode: NetworkEnforcementMode::Firewall,
        blocked_hosts: vec![NEVER_RESOLVES.to_string()],
        default_network_policy: NetworkPolicy::Allow,
        ..Default::default()
    };
    let (result, _) = apply(&policy);

    assert!(
        result.is_err(),
        "this refusal predates the change and must survive it; actual: \
         {result:?}"
    );
}

// ---------------------------------------------------------------------------
// What the refusal says about rules it never programmed
// ---------------------------------------------------------------------------

#[test]
fn a_refused_policy_does_not_report_an_earlier_rule_as_programmed() {
    let policy = ContainerPolicy {
        network_enforcement_mode: NetworkEnforcementMode::Firewall,
        allowed_hosts: vec!["203.0.113.0/24".to_string(), NEVER_RESOLVES.to_string()],
        default_network_policy: NetworkPolicy::Block,
        ..Default::default()
    };
    let (result, log) = apply(&policy);

    assert!(
        result.is_err(),
        "the second entry names a destination no rule can reach; actual: {result:?}"
    );
    assert!(
        !log.contains("Programmed iptables rule"),
        "the refusal abandons every accumulated rule, so a caller reading this \
         log must not be told the earlier destination was programmed; log:\n{log}"
    );
}

// ---------------------------------------------------------------------------
// A mode LXC has no mechanism for
// ---------------------------------------------------------------------------

#[test]
fn a_legacy_capabilities_mode_that_states_a_network_posture_is_refused() {
    let policy = ContainerPolicy {
        network_enforcement_mode: NetworkEnforcementMode::Capabilities,
        network_mode_specified: true,
        default_network_policy: NetworkPolicy::Block,
        ..Default::default()
    };
    let (result, _) = apply(&policy);

    assert!(
        result.is_err(),
        "LXC filters with iptables and has no capability mechanism, so this \
         posture is stated and never enforced; actual: {result:?}"
    );
}

#[test]
fn a_legacy_capabilities_mode_that_states_no_posture_still_applies() {
    let policy = ContainerPolicy {
        network_enforcement_mode: NetworkEnforcementMode::Capabilities,
        network_mode_specified: false,
        default_network_policy: NetworkPolicy::Block,
        ..Default::default()
    };
    let (result, _) = apply(&policy);

    assert!(
        result.is_ok(),
        "the caller named no network posture, so there is nothing LXC failed \
         to honor; actual: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// An IPv6 stack that is loaded but not yet addressed
// ---------------------------------------------------------------------------

#[test]
fn a_loaded_ipv6_stack_with_no_address_is_not_reported_as_kernel_disabled() {
    let loopback_only = "00000000000000000000000000000001 01 80 10 80       lo\n".to_string();

    let state = NetworkIptablesManager::classify_host_ipv6_state(Ok(loopback_only), true);

    assert_ne!(
        state,
        HostIpv6State::Inactive,
        "the file exists, so the kernel carries IPv6 and an address can arrive \
         while the container runs; calling that inactive installs IPv4-only \
         rules and leaves IPv6 egress unfiltered"
    );
}
