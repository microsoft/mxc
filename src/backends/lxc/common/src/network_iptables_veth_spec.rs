//! Spec for the fail-closed contract of `apply_firewall_rules`: when the
//! firewall cannot be scoped to the container, the caller must be told the
//! policy was not applied rather than being handed a chain that filters
//! nothing.
//!
//! Attached to `network_iptables` as a child module via `#[path]`, so it can
//! reach the `#[cfg(test)]` fake-firewall seam.

use super::*;
use wxc_common::logger::{Logger, Mode};
use wxc_common::models::{ContainerPolicy, NetworkEnforcementMode};

/// Build a policy that requests the given network enforcement mode, leaving
/// every other field at its default.
fn policy_requesting(mode: NetworkEnforcementMode) -> ContainerPolicy {
    ContainerPolicy {
        network_enforcement_mode: mode,
        ..Default::default()
    }
}

// A chain that is never hooked to the container's veth interface is a chain
// no packet ever traverses. If the manager does not know which veth belongs
// to the container, it must refuse rather than report success on a firewall
// that filters nothing. This covers the `Firewall` half of R1; `Both` is
// covered separately below so a fix scoped to only one enforcement mode
// cannot pass the suite.
#[test]
fn apply_is_refused_when_the_container_interface_is_unknown_in_firewall_mode() {
    let _fake = super::test_firewall::install();
    let mut manager = NetworkIptablesManager::new("ctrl-firewall");
    let policy = policy_requesting(NetworkEnforcementMode::Firewall);
    let mut logger = Logger::new(Mode::Buffer);

    let result = manager.apply_firewall_rules(&policy, &mut logger);

    assert!(
        result.is_err(),
        "Firewall mode with no veth interface set must fail closed, got {:?}",
        result
    );
}

// Same hazard as above under `Both`, which also requests firewall
// enforcement. A fix that only checks the interface in the `Firewall` arm
// would leave `Both` silently unenforced, and only a dedicated test for this
// mode would catch it.
#[test]
fn apply_is_refused_when_the_container_interface_is_unknown_in_both_mode() {
    let _fake = super::test_firewall::install();
    let mut manager = NetworkIptablesManager::new("ctrl-both");
    let policy = policy_requesting(NetworkEnforcementMode::Both);
    let mut logger = Logger::new(Mode::Buffer);

    let result = manager.apply_firewall_rules(&policy, &mut logger);

    assert!(
        result.is_err(),
        "Both mode with no veth interface set must fail closed, got {:?}",
        result
    );
}

// A caller who is told "firewall applied" while the interface was never known
// deserves an error that says what to check. If the message drops the chain
// name or the "will not be enforced" meaning, an operator debugging why a
// container's traffic is unfiltered has nothing to search logs for.
#[test]
fn refusal_error_names_the_unenforced_chain() {
    let _fake = super::test_firewall::install();
    let mut manager = NetworkIptablesManager::new("acme-web");
    let policy = policy_requesting(NetworkEnforcementMode::Firewall);
    let mut logger = Logger::new(Mode::Buffer);

    let err = manager
        .apply_firewall_rules(&policy, &mut logger)
        .expect_err("Firewall mode with no veth interface set must fail closed");

    let chain = manager.chain_name();
    assert!(
        err.contains(chain),
        "error must name the chain left unenforced ({chain}), got: {err}"
    );

    let lower = err.to_lowercase();
    assert!(
        lower.contains("not") && lower.contains("enforc"),
        "error must convey that the policy will not be enforced, got: {err}"
    );
}

// Negative control for R1: the only thing that changes here is that the veth
// interface is now known. Without this test, R1's failures would prove
// nothing about the interface check specifically -- an `apply_firewall_rules`
// that always returned `Err` would also pass every R1 test above.
#[test]
fn apply_succeeds_once_the_veth_interface_is_known() {
    let fake = super::test_firewall::install();
    let mut manager = NetworkIptablesManager::new("ctrl-negative");
    manager.set_veth_interface("veth-ctrl0");
    let policy = policy_requesting(NetworkEnforcementMode::Firewall);
    let mut logger = Logger::new(Mode::Buffer);
    let _ = fake.forget_issued();

    let result = manager.apply_firewall_rules(&policy, &mut logger);

    assert!(
        result.is_ok(),
        "the same Firewall policy that fails with no veth interface must succeed once one is set, got {:?}",
        result
    );
    assert!(
        !fake.issued().is_empty(),
        "a successful Firewall apply must actually issue iptables commands, not just report success"
    );
}

// A caller who is refused must not be left holding a chain on the host: an
// unhooked-but-still-installed chain is inert today but becomes a liability
// the moment anything later hooks a chain by that name. The failed apply
// must tear down what it created, not merely stop short of hooking it up.
#[test]
fn apply_tears_down_the_chain_it_created_when_it_fails_closed() {
    let fake = super::test_firewall::install();
    let mut manager = NetworkIptablesManager::new("ctrl-teardown");
    let policy = policy_requesting(NetworkEnforcementMode::Firewall);
    let mut logger = Logger::new(Mode::Buffer);
    let _ = fake.forget_issued();

    let result = manager.apply_firewall_rules(&policy, &mut logger);
    assert!(
        result.is_err(),
        "expected the apply to fail closed so the teardown path runs, got {:?}",
        result
    );

    let issued = fake.issued();
    let chain = manager.chain_name();
    let creation_index = issued
        .iter()
        .position(|cmd| cmd.iter().any(|a| a == "-N") && cmd.iter().any(|a| a == chain))
        .unwrap_or_else(|| {
            panic!(
                "expected a chain-creation (-N) command naming {chain} before the failure, issued: {:?}",
                issued
            )
        });
    let teardown_index = issued
        .iter()
        .position(|cmd| {
            (cmd.iter().any(|a| a == "-F") || cmd.iter().any(|a| a == "-X"))
                && cmd.iter().any(|a| a == chain)
        })
        .unwrap_or_else(|| {
            panic!(
                "expected a teardown (-F/-X) command naming {chain} after the failed apply, issued: {:?}",
                issued
            )
        });

    assert!(
        teardown_index > creation_index,
        "teardown of {chain} must be issued after its creation, issued: {:?}",
        issued
    );
}

// Firewall commands here would be an unrequested side effect on a container
// with nothing to enforce.
#[test]
fn a_policy_with_nothing_to_enforce_is_unaffected_by_a_missing_veth_interface() {
    let fake = super::test_firewall::install();
    let mut manager = NetworkIptablesManager::new("ctrl-capsonly");
    let policy = ContainerPolicy {
        network_enforcement_mode: NetworkEnforcementMode::Capabilities,
        default_network_policy: NetworkPolicy::Allow,
        ..Default::default()
    };
    let mut logger = Logger::new(Mode::Buffer);
    let _ = fake.forget_issued();

    let result = manager.apply_firewall_rules(&policy, &mut logger);

    assert!(
        result.is_ok(),
        "a policy with nothing to enforce must not fail just because the veth interface is unknown, got {:?}",
        result
    );
    assert!(
        fake.issued().is_empty(),
        "a policy with nothing to enforce must not issue any iptables commands, issued: {:?}",
        fake.issued()
    );
}
