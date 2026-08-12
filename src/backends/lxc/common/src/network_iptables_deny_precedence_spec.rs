// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Black-box specification for deny-precedence and for the fail-closed
//! response to a block-list entry that resolves to no address.
//!
//! Written against the documented contract of the policy rule builder, not
//! against its body.
//!
//! Structural tests (ordering, rule shape, family split) call the test-only
//! `build_policy_rule_args` shim, which panics rather than returning `Err`.
//! Tests that must observe the `Result` or the logger buffer call
//! `build_policy_rules_logged` directly.

use super::*;
// `super::*` re-exports `Logger` (the parent module uses it in its own
// signatures) but not `Mode`, which the parent never names directly.
use wxc_common::logger::Mode;

/// Chain name shared by tests that do not care about its exact value. A
/// couple of tests use a distinct literal on purpose, to prove the chain
/// name is threaded through rather than hard-coded.
const CHAIN: &str = "mxc_test_chain";

// ---------------------------------------------------------------------------
// Shared helpers.
// ---------------------------------------------------------------------------

/// Render a rule as `&str` slices, so it can be compared against a literal
/// without allocating `String`s for the expected side.
fn as_str_slice(rule: &[String]) -> Vec<&str> {
    rule.iter().map(String::as_str).collect()
}

/// The destination argument (`-d <value>`) of a rule.
fn destination_of(rule: &[String]) -> &str {
    let index = rule
        .iter()
        .position(|arg| arg == "-d")
        .unwrap_or_else(|| panic!("rule has no '-d' flag; actual: {rule:?}"));
    &rule[index + 1]
}

/// The jump target argument (`-j <value>`) of a rule.
fn action_of(rule: &[String]) -> &str {
    let index = rule
        .iter()
        .position(|arg| arg == "-j")
        .unwrap_or_else(|| panic!("rule has no '-j' flag; actual: {rule:?}"));
    &rule[index + 1]
}

/// The largest index whose rule targets `DROP`, or `None` if `rules` has no
/// deny rules.
fn last_drop_index(rules: &[Vec<String>]) -> Option<usize> {
    rules.iter().rposition(|rule| action_of(rule) == "DROP")
}

/// The smallest index whose rule targets `ACCEPT`, or `None` if `rules` has
/// no allow rules.
fn first_accept_index(rules: &[Vec<String>]) -> Option<usize> {
    rules.iter().position(|rule| action_of(rule) == "ACCEPT")
}

/// `items`, sorted, so two destination sets can be compared without caring
/// about the order the implementation happened to produce them in.
fn sorted<'a>(items: &[&'a str]) -> Vec<&'a str> {
    let mut items = items.to_vec();
    items.sort_unstable();
    items
}

/// Assert that `rules` contains exactly the given DROP and ACCEPT
/// destinations, as sets, and that every DROP rule precedes every ACCEPT
/// rule -- the B1 deny-precedence guarantee. Order within a single action
/// is not part of the documented contract, so it is deliberately not
/// checked here.
fn assert_deny_precedence(
    rules: &[Vec<String>],
    expected_drop_destinations: &[&str],
    expected_accept_destinations: &[&str],
) {
    let mut drop_destinations: Vec<&str> = Vec::new();
    let mut accept_destinations: Vec<&str> = Vec::new();
    for rule in rules {
        match action_of(rule) {
            "DROP" => drop_destinations.push(destination_of(rule)),
            "ACCEPT" => accept_destinations.push(destination_of(rule)),
            other => panic!("unexpected -j target '{other}'; actual rule: {rule:?}"),
        }
    }

    assert_eq!(
        sorted(&drop_destinations),
        sorted(expected_drop_destinations),
        "DROP destinations did not match expected set; actual rules: {rules:?}"
    );
    assert_eq!(
        sorted(&accept_destinations),
        sorted(expected_accept_destinations),
        "ACCEPT destinations did not match expected set; actual rules: {rules:?}"
    );

    if let (Some(last_drop), Some(first_accept)) =
        (last_drop_index(rules), first_accept_index(rules))
    {
        assert!(
            last_drop < first_accept,
            "every DROP rule must precede every ACCEPT rule (B1); \
             last DROP at index {last_drop}, first ACCEPT at index {first_accept}; \
             actual rules: {rules:?}"
        );
    }
}

/// Unwrap `result`, panicking with the `Err` payload.
///
/// `.unwrap()` would require `Debug` on the `Ok` type, which
/// `FirewallRuleArgs` is not documented to implement.
fn expect_ok(result: Result<FirewallRuleArgs, String>, context: &str) -> FirewallRuleArgs {
    match result {
        Ok(args) => args,
        Err(err) => panic!("{context}; actual Err: {err:?}"),
    }
}

/// Whether `destination` (a bare address or an address/prefix CIDR) parses
/// as IPv4. Used to state the family-split guarantee as an invariant over
/// whatever the implementation actually produced, rather than as a
/// hard-coded list of which literals are which family.
fn parses_as_ipv4(destination: &str) -> bool {
    let address = destination.split('/').next().unwrap_or(destination);
    address.parse::<std::net::Ipv4Addr>().is_ok()
}

/// Whether `destination` (a bare address or an address/prefix CIDR) parses
/// as IPv6. See `parses_as_ipv4` for why this is an invariant, not a table.
fn parses_as_ipv6(destination: &str) -> bool {
    let address = destination.split('/').next().unwrap_or(destination);
    address.parse::<std::net::Ipv6Addr>().is_ok()
}

// ---------------------------------------------------------------------------
// B1 -- deny precedence: blocked-host rules precede allowed-host rules.
// ---------------------------------------------------------------------------

#[test]
fn a_destination_in_both_lists_is_dropped_because_deny_rules_are_emitted_first() {
    let destination = "203.0.113.44";
    let policy = ContainerPolicy {
        blocked_hosts: vec![destination.to_string()],
        allowed_hosts: vec![destination.to_string()],
        default_network_policy: NetworkPolicy::Block,
        ..Default::default()
    };

    let args = NetworkIptablesManager::build_policy_rule_args(CHAIN, &policy);

    // B1: both rules are present -- there is no de-duplication pass -- and
    // the DROP rule precedes the ACCEPT rule so first-match-wins denies.
    assert_eq!(
        args.ipv4.len(),
        2,
        "expected one DROP rule and one ACCEPT rule for a doubly-listed \
         destination; actual: {:?}",
        args.ipv4
    );
    assert_eq!(
        as_str_slice(&args.ipv4[0]),
        vec!["-A", CHAIN, "-d", destination, "-j", "DROP"],
        "the deny rule must be emitted first; actual first rule: {:?}",
        args.ipv4[0]
    );
    assert_eq!(
        as_str_slice(&args.ipv4[1]),
        vec!["-A", CHAIN, "-d", destination, "-j", "ACCEPT"],
        "the allow rule must follow the deny rule; actual second rule: {:?}",
        args.ipv4[1]
    );
    assert!(
        args.ipv6.is_empty(),
        "an IPv4-only policy must not produce IPv6 rules; actual: {:?}",
        args.ipv6
    );
}

#[test]
fn an_ipv6_destination_in_both_lists_is_dropped_because_deny_rules_are_emitted_first() {
    let destination = "2001:db8::44";
    let policy = ContainerPolicy {
        blocked_hosts: vec![destination.to_string()],
        allowed_hosts: vec![destination.to_string()],
        default_network_policy: NetworkPolicy::Block,
        ..Default::default()
    };

    let args = NetworkIptablesManager::build_policy_rule_args(CHAIN, &policy);

    assert_eq!(
        args.ipv6.len(),
        2,
        "expected one DROP rule and one ACCEPT rule for a doubly-listed \
         IPv6 destination; actual: {:?}",
        args.ipv6
    );
    assert_eq!(
        as_str_slice(&args.ipv6[0]),
        vec!["-A", CHAIN, "-d", destination, "-j", "DROP"],
        "the deny rule must be emitted first; actual first rule: {:?}",
        args.ipv6[0]
    );
    assert_eq!(
        as_str_slice(&args.ipv6[1]),
        vec!["-A", CHAIN, "-d", destination, "-j", "ACCEPT"],
        "the allow rule must follow the deny rule; actual second rule: {:?}",
        args.ipv6[1]
    );
    assert!(
        args.ipv4.is_empty(),
        "an IPv6-only policy must not produce IPv4 rules; actual: {:?}",
        args.ipv4
    );
}

#[test]
fn deny_precedence_holds_across_both_families_with_several_entries_in_each_list() {
    let policy = ContainerPolicy {
        blocked_hosts: vec![
            "10.0.0.0/8".to_string(),
            "198.51.100.42/32".to_string(),
            "2606:50c0::/32".to_string(),
        ],
        allowed_hosts: vec![
            "140.82.112.0/20".to_string(),
            "203.0.113.44".to_string(),
            "2001:db8::/32".to_string(),
            "2001:db8::44".to_string(),
        ],
        default_network_policy: NetworkPolicy::Block,
        ..Default::default()
    };

    let args = NetworkIptablesManager::build_policy_rule_args(CHAIN, &policy);

    assert_eq!(
        args.ipv4.len(),
        4,
        "2 blocked + 2 allowed IPv4 destinations must produce 4 IPv4 rules; \
         actual: {:?}",
        args.ipv4
    );
    assert_deny_precedence(
        &args.ipv4,
        &["10.0.0.0/8", "198.51.100.42/32"],
        &["140.82.112.0/20", "203.0.113.44"],
    );

    assert_eq!(
        args.ipv6.len(),
        3,
        "1 blocked + 2 allowed IPv6 destinations must produce 3 IPv6 rules; \
         actual: {:?}",
        args.ipv6
    );
    assert_deny_precedence(
        &args.ipv6,
        &["2606:50c0::/32"],
        &["2001:db8::/32", "2001:db8::44"],
    );
}

// ---------------------------------------------------------------------------
// B4 -- unresolvable entries: fail closed only for a blocked host under an
// Allow default; otherwise log a warning and continue.
// ---------------------------------------------------------------------------

#[test]
fn an_unresolvable_blocked_host_errors_under_an_allow_default_and_names_the_host() {
    let host = "140.82.112.0/not-a-prefix";
    let policy = ContainerPolicy {
        blocked_hosts: vec![host.to_string()],
        default_network_policy: NetworkPolicy::Allow,
        ..Default::default()
    };
    let mut logger = Logger::new(Mode::Buffer);

    let result = NetworkIptablesManager::build_policy_rules_logged(CHAIN, &policy, &mut logger);

    let err = match result {
        Err(err) => err,
        Ok(args) => panic!(
            "expected Err: a blocked, unresolvable host under an Allow \
             default leaves nothing to stop traffic (B4); actual ipv4: {:?}, \
             ipv6: {:?}",
            args.ipv4, args.ipv6
        ),
    };
    assert!(
        err.contains(host),
        "the error message must name the offending host '{host}'; actual \
         message: {err:?}"
    );
}

#[test]
fn the_same_unresolvable_blocked_host_does_not_error_under_a_block_default() {
    let host = "140.82.112.0/not-a-prefix";
    let policy = ContainerPolicy {
        blocked_hosts: vec![host.to_string()],
        default_network_policy: NetworkPolicy::Block,
        ..Default::default()
    };
    let mut logger = Logger::new(Mode::Buffer);

    let result = NetworkIptablesManager::build_policy_rules_logged(CHAIN, &policy, &mut logger);
    let args = expect_ok(
        result,
        "a Block default already denies everything the allow list did not \
         name, so an unresolvable block entry is redundant, not fatal (B4)",
    );

    assert!(
        args.ipv4.is_empty() && args.ipv6.is_empty(),
        "an unresolvable entry contributes no rules; actual ipv4: {:?}, \
         ipv6: {:?}",
        args.ipv4,
        args.ipv6
    );

    let expected_warning = format!("Warning: could not resolve host '{host}'");
    assert!(
        logger
            .get_buffer()
            .lines()
            .any(|line| line == expected_warning),
        "expected the exact warning line {expected_warning:?}; actual \
         buffer: {:?}",
        logger.get_buffer()
    );
}

#[test]
fn an_unresolvable_allowed_host_never_errors_under_an_allow_default() {
    let host = "/20";
    let policy = ContainerPolicy {
        allowed_hosts: vec![host.to_string()],
        default_network_policy: NetworkPolicy::Allow,
        ..Default::default()
    };
    let mut logger = Logger::new(Mode::Buffer);

    let result = NetworkIptablesManager::build_policy_rules_logged(CHAIN, &policy, &mut logger);
    let args = expect_ok(
        result,
        "B4 reserves Err for an unresolvable BLOCK entry under an Allow \
         default; an unresolvable ALLOW entry must never error",
    );

    assert!(
        args.ipv4.is_empty() && args.ipv6.is_empty(),
        "an unresolvable entry contributes no rules; actual ipv4: {:?}, \
         ipv6: {:?}",
        args.ipv4,
        args.ipv6
    );

    let expected_warning = format!("Warning: could not resolve host '{host}'");
    assert!(
        logger
            .get_buffer()
            .lines()
            .any(|line| line == expected_warning),
        "expected the exact warning line {expected_warning:?}; actual \
         buffer: {:?}",
        logger.get_buffer()
    );
}

#[test]
fn an_unresolvable_allowed_host_never_errors_under_a_block_default() {
    let host = "140.82.112.0/20/8";
    let policy = ContainerPolicy {
        allowed_hosts: vec![host.to_string()],
        default_network_policy: NetworkPolicy::Block,
        ..Default::default()
    };
    let mut logger = Logger::new(Mode::Buffer);

    let result = NetworkIptablesManager::build_policy_rules_logged(CHAIN, &policy, &mut logger);
    let args = expect_ok(
        result,
        "an unresolvable ALLOW entry must never error, regardless of the \
         default network policy (B4)",
    );

    assert!(
        args.ipv4.is_empty() && args.ipv6.is_empty(),
        "an unresolvable entry contributes no rules; actual ipv4: {:?}, \
         ipv6: {:?}",
        args.ipv4,
        args.ipv6
    );

    let expected_warning = format!("Warning: could not resolve host '{host}'");
    assert!(
        logger
            .get_buffer()
            .lines()
            .any(|line| line == expected_warning),
        "expected the exact warning line {expected_warning:?}; actual \
         buffer: {:?}",
        logger.get_buffer()
    );
}

#[test]
fn an_unresolvable_entry_does_not_suppress_a_sibling_entrys_rule_or_log_line() {
    let good_destination = "198.51.100.42/32";
    let bad_host = "2606:50c0::/129";
    let policy = ContainerPolicy {
        blocked_hosts: vec![good_destination.to_string(), bad_host.to_string()],
        default_network_policy: NetworkPolicy::Block,
        ..Default::default()
    };
    let mut logger = Logger::new(Mode::Buffer);

    let result = NetworkIptablesManager::build_policy_rules_logged(CHAIN, &policy, &mut logger);
    let args = expect_ok(
        result,
        "an unresolvable block entry under a Block default must not error, \
         and must not stop a sibling entry in the same call from producing \
         a rule (B4)",
    );

    assert_eq!(
        args.ipv4.len(),
        1,
        "the resolvable sibling must still produce exactly one rule; \
         actual: {:?}",
        args.ipv4
    );
    assert_eq!(
        as_str_slice(&args.ipv4[0]),
        vec!["-A", CHAIN, "-d", good_destination, "-j", "DROP"],
        "actual rule: {:?}",
        args.ipv4[0]
    );

    let buffer = logger.get_buffer();
    let expected_warning = format!("Warning: could not resolve host '{bad_host}'");
    assert!(
        buffer.lines().any(|line| line == expected_warning),
        "expected the warning line for the unresolvable sibling; actual \
         buffer: {buffer:?}"
    );
    let expected_programmed_line =
        format!("Programmed iptables rule: -A {CHAIN} -d {good_destination} -j DROP");
    assert!(
        buffer.lines().any(|line| line == expected_programmed_line),
        "expected the programmed-rule line for the resolvable sibling; \
         actual buffer: {buffer:?}"
    );
}

// ---------------------------------------------------------------------------
// B2 / B3 -- rule shape and IPv4 / IPv6 family split.
// ---------------------------------------------------------------------------

#[test]
fn emitted_rules_have_the_exact_iptables_shape_for_both_allow_and_block_actions() {
    let allowed = "203.0.113.44";
    let blocked = "10.0.0.0/8";
    let chain = "mxc_shape_chain";
    let policy = ContainerPolicy {
        allowed_hosts: vec![allowed.to_string()],
        blocked_hosts: vec![blocked.to_string()],
        default_network_policy: NetworkPolicy::Block,
        ..Default::default()
    };

    let args = NetworkIptablesManager::build_policy_rule_args(chain, &policy);

    assert_eq!(
        args.ipv4.len(),
        2,
        "one block entry and one allow entry must produce exactly 2 rules; \
         actual: {:?}",
        args.ipv4
    );
    // B2: exactly `["-A", chain_name, "-d", destination, "-j", target]` --
    // no more, no fewer arguments, and in this order.
    assert_eq!(
        as_str_slice(&args.ipv4[0]),
        vec!["-A", chain, "-d", blocked, "-j", "DROP"],
        "actual rule: {:?}",
        args.ipv4[0]
    );
    assert_eq!(
        as_str_slice(&args.ipv4[1]),
        vec!["-A", chain, "-d", allowed, "-j", "ACCEPT"],
        "actual rule: {:?}",
        args.ipv4[1]
    );
    for rule in &args.ipv4 {
        assert_eq!(
            rule.len(),
            6,
            "a rule must have exactly 6 arguments; actual: {rule:?}"
        );
    }
}

#[test]
fn ipv4_and_ipv6_destinations_are_split_into_the_correct_bucket_and_never_cross_over() {
    let policy = ContainerPolicy {
        allowed_hosts: vec!["140.82.112.0/20".to_string(), "2001:db8::/32".to_string()],
        blocked_hosts: vec!["198.51.100.42/32".to_string(), "fe80::1".to_string()],
        default_network_policy: NetworkPolicy::Block,
        ..Default::default()
    };

    let args = NetworkIptablesManager::build_policy_rule_args(CHAIN, &policy);

    // Property, not an enumerated example: every destination placed in the
    // v4 bucket must itself parse as IPv4, and likewise for v6. This is what
    // actually catches a leak, unlike checking the four inputs by name.
    for rule in &args.ipv4 {
        let destination = destination_of(rule);
        assert!(
            parses_as_ipv4(destination),
            "a destination in the ipv4 bucket must parse as IPv4; actual \
             destination: {destination:?}"
        );
    }
    for rule in &args.ipv6 {
        let destination = destination_of(rule);
        assert!(
            parses_as_ipv6(destination),
            "a destination in the ipv6 bucket must parse as IPv6; actual \
             destination: {destination:?}"
        );
    }

    assert_eq!(
        args.ipv4.len(),
        2,
        "2 of the 4 destinations are IPv4; actual: {:?}",
        args.ipv4
    );
    assert_eq!(
        args.ipv6.len(),
        2,
        "2 of the 4 destinations are IPv6; actual: {:?}",
        args.ipv6
    );
}

// ---------------------------------------------------------------------------
// B5 -- programmed-rule logging.
// ---------------------------------------------------------------------------

#[test]
fn programmed_rules_are_logged_with_the_exact_iptables_and_ip6tables_prefixes() {
    let allowed_v4 = "203.0.113.44";
    let blocked_v6 = "2606:50c0::/32";
    let chain = "mxc_log_chain";
    let policy = ContainerPolicy {
        allowed_hosts: vec![allowed_v4.to_string()],
        blocked_hosts: vec![blocked_v6.to_string()],
        default_network_policy: NetworkPolicy::Block,
        ..Default::default()
    };
    let mut logger = Logger::new(Mode::Buffer);

    let result = NetworkIptablesManager::build_policy_rules_logged(chain, &policy, &mut logger);
    let args = expect_ok(result, "both entries resolve, so no error is expected here");

    assert_eq!(args.ipv4.len(), 1, "actual: {:?}", args.ipv4);
    assert_eq!(args.ipv6.len(), 1, "actual: {:?}", args.ipv6);

    let buffer = logger.get_buffer();
    // Hard-coded from B5's documented format, not derived from `args`, so
    // this test still pins the log format even if the rule-content tests
    // elsewhere were themselves wrong.
    let expected_ipv4_line =
        format!("Programmed iptables rule: -A {chain} -d {allowed_v4} -j ACCEPT");
    let expected_ipv6_line =
        format!("Programmed ip6tables rule: -A {chain} -d {blocked_v6} -j DROP");
    assert!(
        buffer.lines().any(|line| line == expected_ipv4_line),
        "expected the IPv4 programmed-rule line {expected_ipv4_line:?}; \
         actual buffer: {buffer:?}"
    );
    assert!(
        buffer.lines().any(|line| line == expected_ipv6_line),
        "expected the IPv6 programmed-rule line {expected_ipv6_line:?}; \
         actual buffer: {buffer:?}"
    );
}

// ---------------------------------------------------------------------------
// B6 -- empty policy.
// ---------------------------------------------------------------------------

#[test]
fn an_empty_policy_produces_an_empty_ok_result_with_no_log_output() {
    let policy = ContainerPolicy {
        default_network_policy: NetworkPolicy::Block,
        ..Default::default()
    };
    let mut logger = Logger::new(Mode::Buffer);

    let result = NetworkIptablesManager::build_policy_rules_logged(CHAIN, &policy, &mut logger);
    let args = expect_ok(result, "B6: empty host lists must still return Ok");

    assert!(
        args.ipv4.is_empty(),
        "an empty policy must produce no IPv4 rules; actual: {:?}",
        args.ipv4
    );
    assert!(
        args.ipv6.is_empty(),
        "an empty policy must produce no IPv6 rules; actual: {:?}",
        args.ipv6
    );
    assert!(
        logger.get_buffer().is_empty(),
        "with nothing to program and nothing unresolvable, nothing should \
         be logged; actual buffer: {:?}",
        logger.get_buffer()
    );
}
