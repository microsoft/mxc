// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Black-box specification for the FORWARD hook that steers a container's
//! egress into its own chain.
//!
//! Written against the documented contract of the hook builders and the
//! topology detectors, not against their bodies.

use super::*;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

/// Hand back a directory path under the OS temp root that no other test (or
/// prior run) has used, so sysfs and netfilter fixtures never collide when
/// tests run concurrently in the same process.
fn fresh_fixture_dir(label: &str) -> PathBuf {
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    std::env::temp_dir().join(format!("mxc-forward-hook-spec-{label}-{pid}-{seq}"))
}

// The op token controls whether this is an install or a removal, and
// iptables reads the operation as the first word of the command; if it were
// buried elsewhere the CLI invocation would not do what the caller asked.
#[test]
fn iface_hook_rule_args_start_with_the_requested_operation() {
    let install =
        NetworkIptablesManager::build_forward_hook_iface_rule_args("-I", "veth10", "MXC-tenant10");
    let delete =
        NetworkIptablesManager::build_forward_hook_iface_rule_args("-D", "veth10", "MXC-tenant10");

    assert_eq!(install.first().map(String::as_str), Some("-I"));
    assert_eq!(delete.first().map(String::as_str), Some("-D"));
}

// This rule must be installed into the kernel's FORWARD chain specifically;
// any other chain would never see forwarded container traffic at all.
#[test]
fn iface_hook_rule_args_operate_on_the_forward_chain() {
    let args =
        NetworkIptablesManager::build_forward_hook_iface_rule_args("-I", "veth11", "MXC-tenant11");

    assert_eq!(
        args.get(1).map(String::as_str),
        Some("FORWARD"),
        "expected the chain immediately after the operation to be FORWARD, got: {args:?}"
    );
}

// The whole point of this builder is to match on the veth's own input
// interface, naming the specific interface passed in.
#[test]
fn iface_hook_rule_args_match_on_the_named_input_interface() {
    let iface = "veth12";
    let args =
        NetworkIptablesManager::build_forward_hook_iface_rule_args("-I", iface, "MXC-tenant12");

    let i_index = args
        .iter()
        .position(|a| a == "-i")
        .expect("expected an -i input-interface match in the rule args");
    assert_eq!(
        args.get(i_index + 1).map(String::as_str),
        Some(iface),
        "expected the -i match to name {iface}, got: {args:?}"
    );
}

// A rule that matches the right interface but jumps to the wrong chain (or
// no chain) would never hook the container's own filtering.
#[test]
fn iface_hook_rule_args_jump_to_the_named_chain() {
    let chain_name = "MXC-tenant13";
    let args =
        NetworkIptablesManager::build_forward_hook_iface_rule_args("-I", "veth13", chain_name);

    let j_index = args
        .iter()
        .position(|a| a == "-j")
        .expect("expected a -j jump target in the rule args");
    assert_eq!(
        args.get(j_index + 1).map(String::as_str),
        Some(chain_name),
        "expected the -j target to be {chain_name}, got: {args:?}"
    );
}

// If this builder ever picked up a physdev match too, it would silently
// start behaving like the bridged-topology rule, defeating the reason the
// two builders are separate functions.
#[test]
fn iface_hook_rule_args_never_carry_a_physdev_match() {
    let args =
        NetworkIptablesManager::build_forward_hook_iface_rule_args("-I", "veth14", "MXC-tenant14");

    assert!(
        !args.iter().any(|a| a == "physdev" || a == "--physdev-in"),
        "an input-interface rule must not also carry a physdev match, got: {args:?}"
    );
}

// A delete that is not token-for-token identical to its insert (apart from
// the operation) will not match anything in the kernel's rule table, and the
// rule it was supposed to remove leaks.
#[test]
fn iface_hook_delete_spec_differs_from_its_insert_only_by_the_operation() {
    let iface = "veth15";
    let chain_name = "MXC-tenant15";
    let install =
        NetworkIptablesManager::build_forward_hook_iface_rule_args("-I", iface, chain_name);
    let delete =
        NetworkIptablesManager::build_forward_hook_iface_rule_args("-D", iface, chain_name);

    assert_eq!(
        install.len(),
        delete.len(),
        "install and delete rule specs must have the same number of tokens, install: {install:?}, delete: {delete:?}"
    );
    assert_ne!(
        install[0], delete[0],
        "the first token is the operation and must differ between install and delete"
    );
    assert_eq!(
        &install[1..],
        &delete[1..],
        "every token besides the operation must match exactly, or the delete will not find the rule the install created"
    );
}

// Same operation-placement guarantee as the interface builder, so an install
// and a delete of a physdev rule both do what the caller asked.
#[test]
fn physdev_hook_rule_args_start_with_the_requested_operation() {
    let install = NetworkIptablesManager::build_forward_hook_physdev_rule_args(
        "-I",
        "veth20",
        "MXC-tenant20",
    );
    let delete = NetworkIptablesManager::build_forward_hook_physdev_rule_args(
        "-D",
        "veth20",
        "MXC-tenant20",
    );

    assert_eq!(install.first().map(String::as_str), Some("-I"));
    assert_eq!(delete.first().map(String::as_str), Some("-D"));
}

// This rule must also land in the kernel's FORWARD chain -- the physdev
// match only changes what is matched within that chain, not which chain it
// is installed into.
#[test]
fn physdev_hook_rule_args_operate_on_the_forward_chain() {
    let args = NetworkIptablesManager::build_forward_hook_physdev_rule_args(
        "-I",
        "veth21",
        "MXC-tenant21",
    );

    assert_eq!(
        args.get(1).map(String::as_str),
        Some("FORWARD"),
        "expected the chain immediately after the operation to be FORWARD, got: {args:?}"
    );
}

// Once a veth is bridge-enslaved, the bridge port it entered on is the only
// thing that still identifies that one container, so the exact token
// sequence iptables needs for the physdev match -- not just "physdev appears
// somewhere" -- is the contract itself.
#[test]
fn physdev_hook_rule_args_match_the_named_physdev_in_port() {
    let iface = "veth-c9f3";
    let chain_name = "MXC-tenant-c9f3";
    let args =
        NetworkIptablesManager::build_forward_hook_physdev_rule_args("-I", iface, chain_name);

    let expected: Vec<String> = ["-m", "physdev", "--physdev-in", iface]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let found = args
        .windows(expected.len())
        .any(|w| w == expected.as_slice());

    assert!(
        found,
        "expected the contiguous sequence {expected:?} in the physdev rule args, got: {args:?}"
    );
}

// A physdev rule that matches the right bridge port but jumps to the wrong
// chain would leave the container's own filtering unhooked, same as the
// interface builder's equivalent guarantee.
#[test]
fn physdev_hook_rule_args_jump_to_the_named_chain() {
    let chain_name = "MXC-tenant23";
    let args =
        NetworkIptablesManager::build_forward_hook_physdev_rule_args("-I", "veth23", chain_name);

    let j_index = args
        .iter()
        .position(|a| a == "-j")
        .expect("expected a -j jump target in the rule args");
    assert_eq!(
        args.get(j_index + 1).map(String::as_str),
        Some(chain_name),
        "expected the -j target to be {chain_name}, got: {args:?}"
    );
}

// Once a veth is bridge-enslaved, FORWARD sees the bridge as the input
// interface, not the veth; an -i match naming the veth would match nothing
// at all, so this builder must not carry one.
#[test]
fn physdev_hook_rule_args_never_carry_an_input_interface_match() {
    let args = NetworkIptablesManager::build_forward_hook_physdev_rule_args(
        "-I",
        "veth24",
        "MXC-tenant24",
    );

    assert!(
        !args.iter().any(|a| a == "-i"),
        "a physdev-matched rule must not also carry an -i input-interface match, got: {args:?}"
    );
}

// Same leak hazard as the interface builder's delete/insert invariant: a
// physdev delete spec that drifts from its insert will not find the rule and
// leaves it installed on the host forever.
#[test]
fn physdev_hook_delete_spec_differs_from_its_insert_only_by_the_operation() {
    let iface = "veth25";
    let chain_name = "MXC-tenant25";
    let install =
        NetworkIptablesManager::build_forward_hook_physdev_rule_args("-I", iface, chain_name);
    let delete =
        NetworkIptablesManager::build_forward_hook_physdev_rule_args("-D", iface, chain_name);

    assert_eq!(
        install.len(),
        delete.len(),
        "install and delete rule specs must have the same number of tokens, install: {install:?}, delete: {delete:?}"
    );
    assert_ne!(
        install[0], delete[0],
        "the first token is the operation and must differ between install and delete"
    );
    assert_eq!(
        &install[1..],
        &delete[1..],
        "every token besides the operation must match exactly, or the delete will not find the rule the install created"
    );
}

// The two builders exist because a directly routed veth and a
// bridge-enslaved veth need different matches to see the same packets. If
// they ever produced identical rule specs, one of those two topologies would
// silently collapse onto the other's match, bringing back the bug this
// change fixes.
#[test]
fn the_iface_and_physdev_hook_builders_never_produce_the_same_rule_specification() {
    let iface = "veth26";
    let chain_name = "MXC-tenant26";
    let iface_rule =
        NetworkIptablesManager::build_forward_hook_iface_rule_args("-I", iface, chain_name);
    let physdev_rule =
        NetworkIptablesManager::build_forward_hook_physdev_rule_args("-I", iface, chain_name);

    assert_ne!(
        iface_rule, physdev_rule,
        "the input-interface rule and the physdev rule must differ, or bridged and directly \
         routed containers would collapse onto the same match"
    );
}

// The kernel only creates a `master` entry once an interface is enslaved to
// a bridge, so its presence alone is what this function is allowed to trust.
#[test]
fn an_interface_with_a_master_entry_is_reported_as_bridge_enslaved() {
    let root = fresh_fixture_dir("enslaved");
    let iface_dir = root.join("veth-a1b2");
    fs::create_dir_all(&iface_dir).expect("failed to create the fake sysfs interface directory");
    fs::write(iface_dir.join("master"), "").expect("failed to create the fake master entry");

    let result = NetworkIptablesManager::veth_topology_in(&root, "veth-a1b2");

    fs::remove_dir_all(&root).expect("failed to clean up the fake sysfs root");
    assert_eq!(
        result,
        VethTopology::Bridged,
        "an interface with a master entry must be reported as bridge-enslaved"
    );
}

// A veth that is not enslaved has an interface directory but no `master`
// entry inside it; this is the ordinary "routed directly" topology.
#[test]
fn an_interface_without_a_master_entry_is_not_bridge_enslaved() {
    let root = fresh_fixture_dir("unenslaved");
    let iface_dir = root.join("veth-d4e5");
    fs::create_dir_all(&iface_dir).expect("failed to create the fake sysfs interface directory");

    let result = NetworkIptablesManager::veth_topology_in(&root, "veth-d4e5");

    fs::remove_dir_all(&root).expect("failed to clean up the fake sysfs root");
    assert_eq!(
        result,
        VethTopology::DirectlyRouted,
        "an interface directory with no master entry is a positive directly-routed finding"
    );
}

// A missing interface directory is not evidence that the interface is
// unenslaved.  The two facts are independent: `discover_veth_interface` parses `lxc-info`,
// not sysfs, so the veth can be known to exist while its sysfs entry is
// missing, masked, or unreadable.  Absence of the directory is therefore a
// failed lookup, not evidence about the topology.
#[test]
fn a_missing_interface_directory_is_an_unknown_topology_not_a_routed_one() {
    let root = fresh_fixture_dir("missing-iface");
    fs::create_dir_all(&root).expect("failed to create the fake sysfs root");

    let result = NetworkIptablesManager::veth_topology_in(&root, "veth-ghost");

    fs::remove_dir_all(&root).expect("failed to clean up the fake sysfs root");
    assert_eq!(
        result,
        VethTopology::Unknown,
        "a missing interface directory establishes nothing about the topology"
    );
}

// The whole sysfs root being absent is the masked/unmounted case from review.
#[test]
fn an_unreadable_sysfs_root_is_an_unknown_topology() {
    let root = fresh_fixture_dir("no-sysfs-at-all");
    let _ = fs::remove_dir_all(&root);

    let result = NetworkIptablesManager::veth_topology_in(&root, "veth-a1b2");

    assert_eq!(
        result,
        VethTopology::Unknown,
        "an absent sysfs root must not be read as a directly-routed topology"
    );
}

// The two probes in `veth_topology_in` read metadata differently on purpose,
// and only a symlink can tell them apart. A dangling `master` still means the
// veth is enslaved, so that probe must NOT follow the link -- following it
// would report a bridged veth as directly routed, which is the relaxed branch.
//
// This is the mutation that survived the first battery. It is Unix-gated
// because a dangling symlink is not creatable without privilege on Windows;
// the same pattern is used by
// `resolve_denied_host_path_fails_closed_on_dangling_symlink`.
#[cfg(unix)]
#[test]
fn a_dangling_master_symlink_still_means_the_veth_is_bridged() {
    use std::os::unix::fs::symlink;

    let root = fresh_fixture_dir("dangling-master");
    let iface_dir = root.join("veth-dangle");
    fs::create_dir_all(&iface_dir).expect("failed to create the fake sysfs root");
    symlink(root.join("no-such-bridge"), iface_dir.join("master"))
        .expect("failed to create the dangling master symlink");

    let result = NetworkIptablesManager::veth_topology_in(&root, "veth-dangle");

    fs::remove_dir_all(&root).expect("failed to clean up the fake sysfs root");
    assert_eq!(
        result,
        VethTopology::Bridged,
        "a dangling master symlink still means enslaved; following it would \
         report a bridged veth as directly routed"
    );
}

// The other half of the asymmetry. `/sys/class/net/<iface>` is itself a symlink
// into `/sys/devices`, so the interface probe MUST follow it -- a dangling one
// proves nothing was observed, and calling that directly routed is the same
// fail-open defect one level down.
#[cfg(unix)]
#[test]
fn a_dangling_interface_symlink_is_an_unknown_topology() {
    use std::os::unix::fs::symlink;

    let root = fresh_fixture_dir("dangling-iface");
    fs::create_dir_all(&root).expect("failed to create the fake sysfs root");
    symlink(root.join("no-such-device"), root.join("veth-ghostlink"))
        .expect("failed to create the dangling interface symlink");

    let result = NetworkIptablesManager::veth_topology_in(&root, "veth-ghostlink");

    fs::remove_dir_all(&root).expect("failed to clean up the fake sysfs root");
    assert_eq!(
        result,
        VethTopology::Unknown,
        "an interface symlink whose target does not resolve establishes nothing"
    );
}

// The decision that actually carries the security weight: which topologies get
// the relaxed treatment that downgrades a failed physdev hook to a warning.
// Only a positive directly-routed finding may.
#[test]
fn only_a_confirmed_directly_routed_topology_escapes_the_bridged_treatment() {
    assert!(
        NetworkIptablesManager::treat_as_bridged(VethTopology::Bridged),
        "a bridged veth must be treated as bridged"
    );
    assert!(
        NetworkIptablesManager::treat_as_bridged(VethTopology::Unknown),
        "an unknown topology must be treated as bridged, so a failed physdev hook stays fatal"
    );
    assert!(
        !NetworkIptablesManager::treat_as_bridged(VethTopology::DirectlyRouted),
        "a confirmed directly-routed veth is the one case that may relax the hook requirement"
    );
}

// The toggle file's documented "on" value is exactly "1"; this is the
// baseline positive case every other Function 4 test is a variation of.
#[test]
fn a_bridge_netfilter_toggle_of_1_is_reported_active() {
    let dir = fresh_fixture_dir("nf-on");
    fs::create_dir_all(&dir).expect("failed to create the fake proc directory");
    let toggle = dir.join("bridge-nf-call-iptables");
    fs::write(&toggle, "1").expect("failed to write the fake netfilter toggle");

    let result = NetworkIptablesManager::bridge_netfilter_active_at(&toggle);

    fs::remove_dir_all(&dir).expect("failed to clean up the fake proc directory");
    assert!(
        result,
        "a toggle file containing exactly \"1\" must be reported as active"
    );
}

// The real kernel file ends in a newline; a comparison that forgets to trim
// would treat every real, active system as inactive.
#[test]
fn a_bridge_netfilter_toggle_of_1_with_a_trailing_newline_is_reported_active() {
    let dir = fresh_fixture_dir("nf-on-newline");
    fs::create_dir_all(&dir).expect("failed to create the fake proc directory");
    let toggle = dir.join("bridge-nf-call-iptables");
    fs::write(&toggle, "1\n").expect("failed to write the fake netfilter toggle");

    let result = NetworkIptablesManager::bridge_netfilter_active_at(&toggle);

    fs::remove_dir_all(&dir).expect("failed to clean up the fake proc directory");
    assert!(
        result,
        "a toggle file containing \"1\\n\", matching the real kernel file's trailing newline, must be reported as active"
    );
}

// "0" is the documented "off" value and must read as inactive, not merely as
// "not 1 so default to something".
#[test]
fn a_bridge_netfilter_toggle_of_0_is_not_active() {
    let dir = fresh_fixture_dir("nf-off");
    fs::create_dir_all(&dir).expect("failed to create the fake proc directory");
    let toggle = dir.join("bridge-nf-call-iptables");
    fs::write(&toggle, "0").expect("failed to write the fake netfilter toggle");

    let result = NetworkIptablesManager::bridge_netfilter_active_at(&toggle);

    fs::remove_dir_all(&dir).expect("failed to clean up the fake proc directory");
    assert!(
        !result,
        "a toggle file containing \"0\" must not be reported as active"
    );
}

// Absence means the bridge-netfilter machinery is not loaded at all, which
// is the unsafe case: it must never be mistaken for "on".
#[test]
fn a_missing_bridge_netfilter_toggle_is_not_active() {
    let dir = fresh_fixture_dir("nf-missing");
    fs::create_dir_all(&dir).expect("failed to create the fake proc directory");
    let toggle = dir.join("bridge-nf-call-iptables");

    let result = NetworkIptablesManager::bridge_netfilter_active_at(&toggle);

    fs::remove_dir_all(&dir).expect("failed to clean up the fake proc directory");
    assert!(
        !result,
        "a toggle file that does not exist at all must not be reported as active"
    );
}

// Empty contents are neither "1" nor "0"; the function must not treat a
// truncated or not-yet-written file as active.
#[test]
fn an_empty_bridge_netfilter_toggle_is_not_active() {
    let dir = fresh_fixture_dir("nf-empty");
    fs::create_dir_all(&dir).expect("failed to create the fake proc directory");
    let toggle = dir.join("bridge-nf-call-iptables");
    fs::write(&toggle, "").expect("failed to write the fake netfilter toggle");

    let result = NetworkIptablesManager::bridge_netfilter_active_at(&toggle);

    fs::remove_dir_all(&dir).expect("failed to clean up the fake proc directory");
    assert!(
        !result,
        "a toggle file with empty contents must not be reported as active"
    );
}

// Whitespace-only contents must not survive trimming into an empty string
// that somehow compares equal to "1"; it must compare as not-"1" and read as
// inactive.
#[test]
fn a_whitespace_only_bridge_netfilter_toggle_is_not_active() {
    let dir = fresh_fixture_dir("nf-whitespace");
    fs::create_dir_all(&dir).expect("failed to create the fake proc directory");
    let toggle = dir.join("bridge-nf-call-iptables");
    fs::write(&toggle, "   \n\t  ").expect("failed to write the fake netfilter toggle");

    let result = NetworkIptablesManager::bridge_netfilter_active_at(&toggle);

    fs::remove_dir_all(&dir).expect("failed to clean up the fake proc directory");
    assert!(
        !result,
        "a toggle file with only whitespace must not be reported as active"
    );
}

// Any value that is not exactly "1" must read as inactive, not just values
// that happen to be "0"; otherwise a fail-open bug could hide behind an
// unexpected value like a stray "2".
#[test]
fn a_bridge_netfilter_toggle_with_an_unrecognized_value_is_not_active() {
    let dir = fresh_fixture_dir("nf-unrecognized");
    fs::create_dir_all(&dir).expect("failed to create the fake proc directory");
    let toggle = dir.join("bridge-nf-call-iptables");
    fs::write(&toggle, "2").expect("failed to write the fake netfilter toggle");

    let result = NetworkIptablesManager::bridge_netfilter_active_at(&toggle);

    fs::remove_dir_all(&dir).expect("failed to clean up the fake proc directory");
    assert!(
        !result,
        "a toggle file containing a value other than \"1\" must not be reported as active"
    );
}

// ---------------------------------------------------------------------------
// Return-path rules
//
// The hooks above steer traffic *leaving* the container. A reply arrives in
// the opposite direction and matches none of them, so under a DROP forward
// policy an explicitly allowed destination is unreachable. These rules carry
// that reply, and the contract they have to keep is narrow: accept only what
// conntrack already knows about, name one container, and never become an
// inbound control.
// ---------------------------------------------------------------------------

// A rule that matched only on the interface would accept inbound packets that
// begin a new connection, which is an inbound policy decision this rule has no
// business making. The state match is what confines it to traffic the egress
// chain already permitted.
#[test]
fn return_rule_args_accept_only_established_and_related_traffic() {
    for args in [
        NetworkIptablesManager::build_forward_return_iface_rule_args("-I", "veth0"),
        NetworkIptablesManager::build_forward_return_physdev_rule_args("-I", "veth0"),
    ] {
        let state = args
            .iter()
            .position(|a| a == "--state")
            .unwrap_or_else(|| panic!("the rule must carry a state match; got: {args:?}"));

        assert_eq!(
            args[state + 1],
            "ESTABLISHED,RELATED",
            "the rule must accept only traffic conntrack already knows; got: {args:?}"
        );
        assert!(
            args.windows(2).any(|w| w[0] == "-m" && w[1] == "state"),
            "the state value needs its match module loaded; got: {args:?}"
        );
    }
}

// The whole point is to accept the reply. Jumping to the MXC chain instead
// would test inbound packets against rules written as `-d <destination>` for
// egress and, under an allow default, fall through to the chain's closing
// ACCEPT -- an inbound enforcement surface acquired by accident.
#[test]
fn return_rule_args_jump_straight_to_accept_and_never_to_a_chain() {
    for args in [
        NetworkIptablesManager::build_forward_return_iface_rule_args("-I", "veth0"),
        NetworkIptablesManager::build_forward_return_physdev_rule_args("-I", "veth0"),
    ] {
        let target = args
            .iter()
            .position(|a| a == "-j")
            .unwrap_or_else(|| panic!("the rule must name a target; got: {args:?}"));

        assert_eq!(
            args[target + 1],
            "ACCEPT",
            "the return rule must accept directly; got: {args:?}"
        );
        assert!(
            !args.iter().any(|a| a.starts_with("MXC-")),
            "the return rule must not reference the policy chain; got: {args:?}"
        );
    }
}

// Matching the reply direction is the entire difference from the hooks. A rule
// that named the container's port as *input* would duplicate the egress hook
// and leave the reply path exactly as broken as before.
#[test]
fn return_rule_args_match_the_container_port_as_output() {
    let iface = NetworkIptablesManager::build_forward_return_iface_rule_args("-I", "veth0");
    assert!(
        iface.windows(2).any(|w| w[0] == "-o" && w[1] == "veth0"),
        "the interface form must match the veth as output; got: {iface:?}"
    );
    assert!(
        !iface.iter().any(|a| a == "-i"),
        "the interface form must not match on input; got: {iface:?}"
    );

    let physdev = NetworkIptablesManager::build_forward_return_physdev_rule_args("-I", "veth0");
    assert!(
        physdev
            .windows(2)
            .any(|w| w[0] == "--physdev-out" && w[1] == "veth0"),
        "the physdev form must match the veth as the outbound bridge port; got: {physdev:?}"
    );
    assert!(
        !physdev.iter().any(|a| a == "--physdev-in"),
        "the physdev form must not match the inbound bridge port; got: {physdev:?}"
    );
}

// An unscoped rule would accept established traffic for every container on the
// host, so one container's flows would be carried by another's policy.
#[test]
fn return_rule_args_name_the_specific_container_port() {
    for args in [
        NetworkIptablesManager::build_forward_return_iface_rule_args("-I", "vethABC"),
        NetworkIptablesManager::build_forward_return_physdev_rule_args("-I", "vethABC"),
    ] {
        assert!(
            args.iter().any(|a| a == "vethABC"),
            "the rule must name the container's port; got: {args:?}"
        );
        assert!(
            !args.iter().any(|a| a == "lxcbr0"),
            "the rule must not be scoped to the shared bridge; got: {args:?}"
        );
    }
}

// iptables deletes by full rule specification, so a delete that differs from
// its insert by any match finds nothing and leaks the rule into a FORWARD
// chain that outlives the container.
#[test]
fn return_rule_delete_specs_differ_from_their_inserts_only_by_the_operation() {
    for (install, remove) in [
        (
            NetworkIptablesManager::build_forward_return_iface_rule_args("-I", "veth0"),
            NetworkIptablesManager::build_forward_return_iface_rule_args("-D", "veth0"),
        ),
        (
            NetworkIptablesManager::build_forward_return_physdev_rule_args("-I", "veth0"),
            NetworkIptablesManager::build_forward_return_physdev_rule_args("-D", "veth0"),
        ),
    ] {
        assert_eq!(
            install[0], "-I",
            "the install must insert; got: {install:?}"
        );
        assert_eq!(remove[0], "-D", "the removal must delete; got: {remove:?}");
        assert_eq!(
            install[1..],
            remove[1..],
            "the delete spec must match the insert exactly apart from the operation"
        );
    }
}

// Both forms are installed together and deleted independently, so if they
// produced the same specification one delete would remove the other's rule and
// the second would silently find nothing.
#[test]
fn the_two_return_rule_forms_never_produce_the_same_specification() {
    let iface = NetworkIptablesManager::build_forward_return_iface_rule_args("-I", "veth0");
    let physdev = NetworkIptablesManager::build_forward_return_physdev_rule_args("-I", "veth0");

    assert_ne!(
        iface, physdev,
        "the two return forms must be distinguishable to iptables"
    );
}

// The return rules must not be mistaken for the egress hooks: those jump to
// the chain and match the inbound direction, and deleting one with the other's
// specification would leave a rule behind.
#[test]
fn return_rules_are_distinguishable_from_the_egress_hooks() {
    let egress = NetworkIptablesManager::build_forward_hook_iface_rule_args("-I", "veth0", "MXC-x");
    let egress_physdev =
        NetworkIptablesManager::build_forward_hook_physdev_rule_args("-I", "veth0", "MXC-x");
    let ret = NetworkIptablesManager::build_forward_return_iface_rule_args("-I", "veth0");
    let ret_physdev = NetworkIptablesManager::build_forward_return_physdev_rule_args("-I", "veth0");

    for e in [&egress, &egress_physdev] {
        for r in [&ret, &ret_physdev] {
            assert_ne!(
                *e, *r,
                "an egress hook and a return rule must never share a specification"
            );
        }
    }
}
