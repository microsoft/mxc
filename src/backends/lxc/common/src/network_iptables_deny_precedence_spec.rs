// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use wxc_common::logger::Mode;

const CHAIN: &str = "mxc_test_chain";

fn as_str_slice(rule: &[String]) -> Vec<&str> {
    rule.iter().map(String::as_str).collect()
}

fn destination_of(rule: &[String]) -> &str {
    let index = rule
        .iter()
        .position(|arg| arg == "-d")
        .unwrap_or_else(|| panic!("rule has no '-d' flag; actual: {rule:?}"));
    &rule[index + 1]
}

fn action_of(rule: &[String]) -> &str {
    let index = rule
        .iter()
        .position(|arg| arg == "-j")
        .unwrap_or_else(|| panic!("rule has no '-j' flag; actual: {rule:?}"));
    &rule[index + 1]
}

fn last_drop_index(rules: &[Vec<String>]) -> Option<usize> {
    rules.iter().rposition(|rule| action_of(rule) == "DROP")
}

fn first_accept_index(rules: &[Vec<String>]) -> Option<usize> {
    rules.iter().position(|rule| action_of(rule) == "ACCEPT")
}

fn sorted<'a>(items: &[&'a str]) -> Vec<&'a str> {
    let mut items = items.to_vec();
    items.sort_unstable();
    items
}

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

fn expect_ok(result: Result<FirewallRuleArgs, String>, context: &str) -> FirewallRuleArgs {
    match result {
        Ok(args) => args,
        Err(err) => panic!("{context}; actual Err: {err:?}"),
    }
}

fn parses_as_ipv4(destination: &str) -> bool {
    let address = destination.split('/').next().unwrap_or(destination);
    address.parse::<std::net::Ipv4Addr>().is_ok()
}

fn parses_as_ipv6(destination: &str) -> bool {
    let address = destination.split('/').next().unwrap_or(destination);
    address.parse::<std::net::Ipv6Addr>().is_ok()
}

#[test]
fn a_destination_in_both_lists_is_dropped_because_deny_rules_are_emitted_first() {
    let destination = "203.0.113.44";
    let policy = ContainerPolicy {
        blocked_hosts: vec![destination.to_string()],
        allowed_hosts: vec![destination.to_string()],
        default_network_policy: NetworkPolicy::Block,
        ..Default::default()
    };

    let args = NetworkIptablesManager::build_policy_rule_args(CHAIN, &policy, false);

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

    let args = NetworkIptablesManager::build_policy_rule_args(CHAIN, &policy, false);

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

    let args = NetworkIptablesManager::build_policy_rule_args(CHAIN, &policy, false);

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

#[test]
fn an_unresolvable_blocked_host_errors_under_an_allow_default_and_names_the_host() {
    let host = "140.82.112.0/not-a-prefix";
    let policy = ContainerPolicy {
        blocked_hosts: vec![host.to_string()],
        default_network_policy: NetworkPolicy::Allow,
        ..Default::default()
    };
    let mut logger = Logger::new(Mode::Buffer);

    let result =
        NetworkIptablesManager::build_policy_rules_logged(CHAIN, &policy, false, &mut logger);

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

    let result =
        NetworkIptablesManager::build_policy_rules_logged(CHAIN, &policy, false, &mut logger);
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

    let result =
        NetworkIptablesManager::build_policy_rules_logged(CHAIN, &policy, false, &mut logger);
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

    let result =
        NetworkIptablesManager::build_policy_rules_logged(CHAIN, &policy, false, &mut logger);
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

    let result =
        NetworkIptablesManager::build_policy_rules_logged(CHAIN, &policy, false, &mut logger);
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

    let args = NetworkIptablesManager::build_policy_rule_args(chain, &policy, false);

    assert_eq!(
        args.ipv4.len(),
        2,
        "one block entry and one allow entry must produce exactly 2 rules; \
         actual: {:?}",
        args.ipv4
    );
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

    let args = NetworkIptablesManager::build_policy_rule_args(CHAIN, &policy, false);

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

    let result =
        NetworkIptablesManager::build_policy_rules_logged(chain, &policy, false, &mut logger);
    let args = expect_ok(result, "both entries resolve, so no error is expected here");

    assert_eq!(args.ipv4.len(), 1, "actual: {:?}", args.ipv4);
    assert_eq!(args.ipv6.len(), 1, "actual: {:?}", args.ipv6);

    let buffer = logger.get_buffer();
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

#[test]
fn an_empty_policy_produces_an_empty_ok_result_with_no_log_output() {
    let policy = ContainerPolicy {
        default_network_policy: NetworkPolicy::Block,
        ..Default::default()
    };
    let mut logger = Logger::new(Mode::Buffer);

    let result =
        NetworkIptablesManager::build_policy_rules_logged(CHAIN, &policy, false, &mut logger);
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
