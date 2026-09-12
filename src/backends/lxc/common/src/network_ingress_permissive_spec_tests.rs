// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use wxc_common::logger::Mode;
use wxc_common::models::NetworkEnforcementMode;

const UNOCCUPIABLE_NETNS_PID: u32 = u32::MAX;

/// Linux rejects PIDs at or above 2^22.
const PID_MAX_LIMIT: u32 = 1 << 22;

const _: () = assert!(
    UNOCCUPIABLE_NETNS_PID > PID_MAX_LIMIT,
    "the netns PID these tests use must exceed the kernel's PID_MAX_LIMIT; otherwise a \
     privileged Linux run can enter a real process's network namespace and reset its \
     iptables chains"
);

fn make_logger() -> Logger {
    Logger::new(Mode::Buffer)
}

fn firewall_policy(allow_local: bool) -> ContainerPolicy {
    ContainerPolicy {
        allow_local_network: allow_local,
        network_enforcement_mode: NetworkEnforcementMode::Firewall,
        ..Default::default()
    }
}

#[test]
fn permissive_inbound_in_a_container_netns_is_refused_not_installed() {
    let policy = firewall_policy(true);
    let mut mgr = IngressManager::new("test-container-refused", UNOCCUPIABLE_NETNS_PID);
    let mut logger = make_logger();

    let result = mgr.apply_firewall_rules(&policy, &mut logger);

    assert!(
        result.is_err(),
        "allow_local_network=true: expected Err (not-yet-implemented refusal), got {:?}",
        result
    );

    let msg = result.unwrap_err();

    assert!(
        msg.contains("not yet implemented"),
        "error message must contain \"not yet implemented\", got: {:?}",
        msg
    );
    assert!(
        msg.contains("allowLocalNetwork"),
        "error message must contain \"allowLocalNetwork\", got: {:?}",
        msg
    );
    assert!(
        msg.contains("over-broad accept"),
        "error message must contain \"over-broad accept\", got: {:?}",
        msg
    );
}

#[test]
fn permissive_inbound_in_both_mode_is_refused_not_installed() {
    let policy = ContainerPolicy {
        allow_local_network: true,
        network_enforcement_mode: NetworkEnforcementMode::Both,
        ..Default::default()
    };
    let mut mgr = IngressManager::new("test-container-refused-both", UNOCCUPIABLE_NETNS_PID);
    let mut logger = make_logger();

    let result = mgr.apply_firewall_rules(&policy, &mut logger);

    assert!(
        result.is_err(),
        "allow_local_network=true, mode=Both: expected Err, got {:?}",
        result
    );
    let msg = result.unwrap_err();
    assert!(
        msg.contains("not yet implemented"),
        "mode=Both: message must contain \"not yet implemented\", got: {:?}",
        msg
    );
    assert!(
        msg.contains("allowLocalNetwork"),
        "mode=Both: message must contain \"allowLocalNetwork\", got: {:?}",
        msg
    );
    assert!(
        msg.contains("over-broad accept"),
        "mode=Both: message must contain \"over-broad accept\", got: {:?}",
        msg
    );
}

#[test]
fn permissive_inbound_refusal_does_not_set_rules_applied() {
    let policy = firewall_policy(true);
    let mut mgr = IngressManager::new("test-container-refused-state", UNOCCUPIABLE_NETNS_PID);
    let mut logger = make_logger();

    let result = mgr.apply_firewall_rules(&policy, &mut logger);

    assert!(
        result.is_err(),
        "allow_local_network=true: expected Err (refusal), got {:?}",
        result
    );

    assert!(
        !mgr.rules_applied(),
        "rules_applied() must be false after a refusal — no rules were installed so cleanup \
         must not run, got rules_applied()=true"
    );
}

#[test]
fn default_deny_with_netns_is_not_the_permissive_refusal() {
    let policy = firewall_policy(false);
    let mut mgr = IngressManager::new("test-container-deny-with-netns", UNOCCUPIABLE_NETNS_PID);
    let mut logger = make_logger();

    let result = mgr.apply_firewall_rules(&policy, &mut logger);

    if let Err(ref msg) = result {
        assert!(
            !msg.contains("not yet implemented"),
            "allow_local_network=false: must not return the not-yet-implemented refusal, got: {:?}",
            msg
        );
        assert!(
            !msg.contains("over-broad accept"),
            "allow_local_network=false: must not return the over-broad-accept refusal, got: {:?}",
            msg
        );
        eprintln!(
            "WARNING: default_deny_with_netns_is_not_the_permissive_refusal got Err \
             (expected off Linux — no iptables binary / no /proc).  The non-error branch was \
             not exercised.  Re-run on Linux to verify the happy path."
        );
    }
}

#[test]
fn permissive_inbound_is_refused_under_every_accepted_mode() {
    for mode in [
        NetworkEnforcementMode::Firewall,
        NetworkEnforcementMode::Both,
    ] {
        let policy = ContainerPolicy {
            allow_local_network: true,
            network_enforcement_mode: mode.clone(),
            ..Default::default()
        };
        let mut mgr = IngressManager::new("test-container-perm-modes", UNOCCUPIABLE_NETNS_PID);
        let mut logger = make_logger();

        let result = mgr.apply_firewall_rules(&policy, &mut logger);

        assert!(
            result.is_err(),
            "allow_local_network=true, mode={mode:?}: expected refusal, got {result:?}"
        );
    }
}
