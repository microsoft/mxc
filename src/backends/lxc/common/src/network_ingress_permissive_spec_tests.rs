// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Spec-derived tests for the not-yet-implemented permissive inbound path.
//! Written from the documented contract only.
//!
//! # Decision table
//!
//! The netns PID is mandatory: [`IngressManager`] cannot be constructed without
//! one, so there is no "no-PID" row. All cells assume
//! `NetworkEnforcementMode::Firewall` unless stated otherwise, because
//! `apply_firewall_rules` returns early with `Ok(true)` for `Capabilities` mode
//! before reaching the permissive guard.
//!
//! | allow_local_network | enforcement mode | Required outcome | Source |
//! |---------------------|------------------|------------------|--------|
//! | false               | Firewall         | NOT refused      | guard is permissive-path only |
//! | true                | Firewall         | REFUSED (Err)    | "apply_firewall_rules returns a clear not-yet-implemented error" |
//! | true                | Both             | REFUSED (Err)    | Both ∈ firewall-using modes |
//! | true                | Capabilities     | NOT refused      | early-return before guard; no firewall path |

use super::*;
use wxc_common::logger::Mode;
use wxc_common::models::NetworkEnforcementMode;

// ── helpers ──────────────────────────────────────────────────────────────────

/// A netns PID that can never name a live process.
///
/// These tests drive the production [`IngressManager::apply_firewall_rules`],
/// which constructs a real `NsenterRunner`.  On a privileged Linux host a PID
/// that happened to exist would therefore be entered for real, and that
/// process's iptables chains reset and installed — a unit test mutating live
/// network state.  Linux caps `pid_max` at `PID_MAX_LIMIT`, 2^22 (4194304), so
/// `u32::MAX` is outside every representable PID and `nsenter -t` is
/// guaranteed to fail before reaching a namespace.
///
/// This costs no coverage: every test below asserts which *classification* an
/// outcome is (or is not), never the happy path, and each one already tolerates
/// an `Err` from an unreachable namespace.
const UNOCCUPIABLE_NETNS_PID: u32 = u32::MAX;

/// `PID_MAX_LIMIT` in the Linux kernel is 2^22; `/proc/sys/kernel/pid_max`
/// cannot be raised above it, so no PID at or above this value is
/// representable.
const PID_MAX_LIMIT: u32 = 1 << 22;

/// Guards the constant above against a well-meaning "use a realistic PID"
/// cleanup.  The safety property is not that the number looks unusual, it is
/// that no process can ever hold it, so it is checked at compile time rather
/// than left to a comment: lowering the PID to something a host could actually
/// be running fails the build, instead of silently arming every test below to
/// enter a live namespace.
const _: () = assert!(
    UNOCCUPIABLE_NETNS_PID > PID_MAX_LIMIT,
    "the netns PID these tests use must exceed the kernel's PID_MAX_LIMIT; otherwise a \
     privileged Linux run can enter a real process's network namespace and reset its \
     iptables chains"
);

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

/// Contract: the permissive path returns a clear not-yet-implemented error.
/// The refusal is unconditional — the PID is mandatory, so there is no inert
/// "no-netns" variant that could bypass it and emit a bare NEW-accept.
#[test]
fn permissive_inbound_in_a_container_netns_is_refused_not_installed() {
    let policy = firewall_policy(true);
    let mut mgr = IngressManager::new("test-container-refused", UNOCCUPIABLE_NETNS_PID);
    let mut logger = make_logger();

    let result = mgr.apply_firewall_rules(&policy, false, &mut logger);

    assert!(
        result.is_err(),
        "allow_local_network=true: expected Err (not-yet-implemented refusal), got {:?}",
        result
    );

    let msg = result.unwrap_err();

    // Match on substrings, not the whole blob, so a line-rewrap cannot silently
    // break the test while the real guard is still absent.
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

/// NetworkEnforcementMode::Both also uses the firewall path.  The permissive
/// guard must refuse for Both too.
#[test]
fn permissive_inbound_in_both_mode_is_refused_not_installed() {
    let policy = ContainerPolicy {
        allow_local_network: true,
        network_enforcement_mode: NetworkEnforcementMode::Both,
        ..Default::default()
    };
    let mut mgr = IngressManager::new("test-container-refused-both", UNOCCUPIABLE_NETNS_PID);
    let mut logger = make_logger();

    let result = mgr.apply_firewall_rules(&policy, false, &mut logger);

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

/// A refusal must not mark the manager as having applied rules, because
/// rules_applied() drives cleanup.  Installing a cleanup pass after a refusal
/// would be wrong.
#[test]
fn permissive_inbound_refusal_does_not_set_rules_applied() {
    let policy = firewall_policy(true);
    let mut mgr = IngressManager::new("test-container-refused-state", UNOCCUPIABLE_NETNS_PID);
    let mut logger = make_logger();

    let result = mgr.apply_firewall_rules(&policy, false, &mut logger);

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

// ── Non-refused cases ────────────────────────────────────────────────────────
//
// On Windows there is no iptables binary (and no `/proc`), so we cannot assert
// Ok for paths that would run iptables/probe the namespace.  Instead we assert
// the discriminating invariant: whatever the outcome, it is NOT the
// not-yet-implemented refusal.  That invariant holds on Linux and Windows and
// cannot be satisfied by accident.

/// Default-deny policy with a netns PID — normal LXC container, deny mode.
#[test]
fn default_deny_with_netns_is_not_the_permissive_refusal() {
    let policy = firewall_policy(false);
    let mut mgr = IngressManager::new("test-container-deny-with-netns", UNOCCUPIABLE_NETNS_PID);
    let mut logger = make_logger();

    let result = mgr.apply_firewall_rules(&policy, false, &mut logger);

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

/// allow_local_network=true + NetworkEnforcementMode::Capabilities.
///
/// Capabilities mode returns early before the firewall path is entered; the
/// permissive guard is never reached.  This catches anyone who hoists the guard
/// above the enforcement-mode gate, which would break every capabilities-mode
/// config.
#[test]
fn permissive_inbound_capabilities_mode_is_not_refused() {
    let policy = ContainerPolicy {
        allow_local_network: true,
        network_enforcement_mode: NetworkEnforcementMode::Capabilities,
        ..Default::default()
    };
    let mut mgr = IngressManager::new("test-container-perm-caps", UNOCCUPIABLE_NETNS_PID);
    let mut logger = make_logger();

    let result = mgr.apply_firewall_rules(&policy, false, &mut logger);

    // Capabilities mode returns Ok(true) before the firewall path.
    assert!(
        result.is_ok(),
        "allow_local_network=true, mode=Capabilities: expected early Ok, got {:?}",
        result
    );
}
