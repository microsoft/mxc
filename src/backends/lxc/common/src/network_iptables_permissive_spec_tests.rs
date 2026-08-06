//! Spec-derived tests for the not-yet-implemented permissive inbound path.
//! Written from the documented contract only — the implementation was not read.
//!
//! # Decision table
//!
//! All cells assume `NetworkEnforcementMode::Firewall` unless stated otherwise,
//! because `apply_firewall_rules` returns early with `Ok(true)` for
//! `Capabilities` mode before reaching the permissive guard.
//!
//! | allow_local_network | netns PID set | enforcement mode   | Required outcome | Source |
//! |---------------------|---------------|--------------------|------------------|--------|
//! | false               | no            | Firewall           | NOT refused      | guard is permissive-path only |
//! | false               | yes           | Firewall           | NOT refused      | same |
//! | true                | yes           | Firewall           | REFUSED (Err)    | "apply_firewall_rules returns a clear not-yet-implemented error" |
//! | true                | yes           | Both               | REFUSED (Err)    | Both ∈ firewall-using modes per :116 |
//! | true                | yes           | Capabilities       | NOT refused      | early-return before guard; no firewall path |
//! | true                | no            | Firewall           | NOT refused      | refusal is netns-gated by design; no-PID path builds an unhooked chain |

use super::*;
use wxc_common::logger::Mode;
use wxc_common::models::NetworkEnforcementMode;

// ── helpers ──────────────────────────────────────────────────────────────────

fn make_logger() -> Logger {
    Logger::new(Mode::Buffer)
}

/// Build a policy that reaches the permissive guard.
///
/// The guard is only reachable when `network_enforcement_mode` is `Firewall`
/// or `Both`; `Capabilities` (the default) causes an early return before the
/// guard.  Every fixture that must exercise the guard must set one of the
/// firewall-using modes explicitly.
fn firewall_policy(allow_local: bool) -> ContainerPolicy {
    ContainerPolicy {
        allow_local_network: allow_local,
        network_enforcement_mode: NetworkEnforcementMode::Firewall,
        ..Default::default()
    }
}

// ── Refused cases ─────────────────────────────────────────────────────────

/// Contract: "apply_firewall_rules returns a clear not-yet-implemented error
/// for the permissive path" (module-level doc, permissive-path section).
/// NetworkEnforcementMode::Firewall + netns PID reaches the guard.
#[test]
fn permissive_inbound_in_a_container_netns_is_refused_not_installed() {
    let policy = firewall_policy(true);
    let mut mgr = NetworkIptablesManager::new("test-container-refused");
    mgr.set_netns_pid(12345);
    let mut logger = make_logger();

    let result = mgr.apply_firewall_rules(&policy, &mut logger);

    assert!(
        result.is_err(),
        "allow_local_network=true, netns_pid=Some(12345): expected Err (not-yet-implemented \
         refusal), got {:?}",
        result
    );

    let msg = result.unwrap_err();

    // Contract specifies an observable Err string beginning with a distinctive
    // phrase.  We match on substrings, not the whole blob, so a line-rewrap
    // cannot silently break the test while the real guard is still absent.
    assert!(
        msg.contains("not yet implemented"),
        "allow_local_network=true, netns_pid=Some(12345): error message must contain \
         \"not yet implemented\", got: {:?}",
        msg
    );
    assert!(
        msg.contains("allowLocalNetwork"),
        "allow_local_network=true, netns_pid=Some(12345): error message must contain \
         \"allowLocalNetwork\", got: {:?}",
        msg
    );
    assert!(
        msg.contains("over-broad accept"),
        "allow_local_network=true, netns_pid=Some(12345): error message must contain \
         \"over-broad accept\", got: {:?}",
        msg
    );
}

/// NetworkEnforcementMode::Both also uses the firewall path (matches the same
/// arm as Firewall at :116).  The permissive guard must refuse for Both too.
#[test]
fn permissive_inbound_in_both_mode_is_refused_not_installed() {
    let policy = ContainerPolicy {
        allow_local_network: true,
        network_enforcement_mode: NetworkEnforcementMode::Both,
        ..Default::default()
    };
    let mut mgr = NetworkIptablesManager::new("test-container-refused-both");
    mgr.set_netns_pid(22222);
    let mut logger = make_logger();

    let result = mgr.apply_firewall_rules(&policy, &mut logger);

    assert!(
        result.is_err(),
        "allow_local_network=true, mode=Both, netns_pid=Some(22222): expected Err, got {:?}",
        result
    );
    let msg = result.unwrap_err();
    assert!(
        msg.contains("not yet implemented"),
        "allow_local_network=true, mode=Both: message must contain \"not yet implemented\", \
         got: {:?}",
        msg
    );
    assert!(
        msg.contains("allowLocalNetwork"),
        "allow_local_network=true, mode=Both: message must contain \"allowLocalNetwork\", \
         got: {:?}",
        msg
    );
    assert!(
        msg.contains("over-broad accept"),
        "allow_local_network=true, mode=Both: message must contain \"over-broad accept\", \
         got: {:?}",
        msg
    );
}

/// A refusal must not mark the manager as having applied rules, because
/// rules_applied() drives cleanup.  Installing a cleanup pass after a refusal
/// would be wrong and potentially dangerous.
///
/// The contract does not explicitly address this invariant, but it follows
/// directly from the semantics of rules_applied(): if no rules were installed,
/// cleanup must not run.
#[test]
fn permissive_inbound_refusal_does_not_set_rules_applied() {
    let policy = firewall_policy(true);
    let mut mgr = NetworkIptablesManager::new("test-container-refused-state");
    mgr.set_netns_pid(99999);
    let mut logger = make_logger();

    let result = mgr.apply_firewall_rules(&policy, &mut logger);

    // Ensure we actually hit the refusal branch; if not, the assertion below
    // has no meaning.
    assert!(
        result.is_err(),
        "allow_local_network=true, netns_pid=Some(99999): expected Err (refusal), got {:?}",
        result
    );

    assert!(
        !mgr.rules_applied(),
        "allow_local_network=true, netns_pid=Some(99999): rules_applied() must be false \
         after a refusal — no rules were installed so cleanup must not run, got \
         rules_applied()=true"
    );
}

// ── Non-refused cases ────────────────────────────────────────────────────────
//
// On Windows there is no iptables binary, so we cannot assert Ok for paths
// that would run iptables.  Instead we assert the discriminating invariant:
// whatever the outcome, it is NOT the not-yet-implemented refusal.  That
// invariant holds on Linux and Windows and cannot be satisfied by accident.

/// Default-deny policy (allow_local_network=false) with no netns PID.
/// Guard is permissive-path only; default-deny must not produce the NYI error.
#[test]
fn default_deny_without_netns_is_not_the_permissive_refusal() {
    let policy = firewall_policy(false);
    let mut mgr = NetworkIptablesManager::new("test-container-deny-no-netns");
    let mut logger = make_logger();

    let result = mgr.apply_firewall_rules(&policy, &mut logger);

    // Deliberate negative assertion — see module comment.
    if let Err(ref msg) = result {
        assert!(
            !msg.contains("not yet implemented"),
            "allow_local_network=false, netns_pid=None: must not return the \
             not-yet-implemented refusal, got: {:?}",
            msg
        );
        assert!(
            !msg.contains("over-broad accept"),
            "allow_local_network=false, netns_pid=None: must not return the \
             over-broad-accept refusal, got: {:?}",
            msg
        );
        eprintln!(
            "WARNING: default_deny_without_netns_is_not_the_permissive_refusal got Err \
             (expected on Windows — no iptables binary).  The non-error branch was not \
             exercised.  Re-run on Linux to verify the happy path."
        );
    }
}

/// Default-deny policy with a netns PID — normal LXC container, deny mode.
#[test]
fn default_deny_with_netns_is_not_the_permissive_refusal() {
    let policy = firewall_policy(false);
    let mut mgr = NetworkIptablesManager::new("test-container-deny-with-netns");
    mgr.set_netns_pid(55555);
    let mut logger = make_logger();

    let result = mgr.apply_firewall_rules(&policy, &mut logger);

    if let Err(ref msg) = result {
        assert!(
            !msg.contains("not yet implemented"),
            "allow_local_network=false, netns_pid=Some(55555): must not return the \
             not-yet-implemented refusal, got: {:?}",
            msg
        );
        assert!(
            !msg.contains("over-broad accept"),
            "allow_local_network=false, netns_pid=Some(55555): must not return the \
             over-broad-accept refusal, got: {:?}",
            msg
        );
        eprintln!(
            "WARNING: default_deny_with_netns_is_not_the_permissive_refusal got Err \
             (expected on Windows — no iptables binary).  The non-error branch was not \
             exercised.  Re-run on Linux to verify the happy path."
        );
    }
}

/// allow_local_network=true + netns PID set + NetworkEnforcementMode::Capabilities.
///
/// Capabilities mode returns early before the firewall path is entered; the
/// permissive guard is never reached.  This is not a refusal — it is
/// an explicit early exit for configs where no firewall is in use.  This test
/// catches anyone who hoists the guard above the enforcement-mode gate, which
/// would break every capabilities-mode config.
#[test]
fn permissive_inbound_capabilities_mode_is_not_refused() {
    let policy = ContainerPolicy {
        allow_local_network: true,
        network_enforcement_mode: NetworkEnforcementMode::Capabilities,
        ..Default::default()
    };
    let mut mgr = NetworkIptablesManager::new("test-container-perm-caps");
    mgr.set_netns_pid(77777);
    let mut logger = make_logger();

    let result = mgr.apply_firewall_rules(&policy, &mut logger);

    // Deliberate negative assertion: Capabilities mode must not trigger the
    // NYI refusal regardless of allow_local_network.
    if let Err(ref msg) = result {
        assert!(
            !msg.contains("not yet implemented"),
            "allow_local_network=true, mode=Capabilities, netns_pid=Some(77777): must not \
             return the not-yet-implemented refusal, got: {:?}",
            msg
        );
        assert!(
            !msg.contains("over-broad accept"),
            "allow_local_network=true, mode=Capabilities, netns_pid=Some(77777): must not \
             return the over-broad-accept refusal, got: {:?}",
            msg
        );
        eprintln!(
            "WARNING: permissive_inbound_capabilities_mode_is_not_refused got Err \
             (unexpected on Windows — Capabilities mode should return Ok before iptables). \
             Re-run on Linux to verify."
        );
    }
}

/// allow_local_network=true + NO netns PID + Firewall mode.
///
/// The refusal is netns-gated by design: the no-PID path builds an unhooked
/// chain and installs nothing (Bubblewrap shared-net mode); the guard fires
/// only when a real container netns is present.  Must not refuse.
#[test]
fn permissive_inbound_without_netns_is_not_refused() {
    let policy = firewall_policy(true);
    let mut mgr = NetworkIptablesManager::new("test-container-perm-no-netns");
    // No set_netns_pid — Bubblewrap / unit-test shared-net mode.
    let mut logger = make_logger();

    let result = mgr.apply_firewall_rules(&policy, &mut logger);

    // Deliberate negative assertion: without a netns PID the chain is left
    // unhooked and nothing is installed; the NYI refusal must not fire.
    if let Err(ref msg) = result {
        assert!(
            !msg.contains("not yet implemented"),
            "allow_local_network=true, netns_pid=None: must not return the \
             not-yet-implemented refusal (guard is netns-gated by design), got: {:?}",
            msg
        );
        assert!(
            !msg.contains("over-broad accept"),
            "allow_local_network=true, netns_pid=None: must not return the \
             over-broad-accept refusal (guard is netns-gated), got: {:?}",
            msg
        );
        eprintln!(
            "WARNING: permissive_inbound_without_netns_is_not_refused got Err \
             (expected on Windows — no iptables binary).  The non-error branch was not \
             exercised.  Re-run on Linux to verify the happy path."
        );
    }
}
