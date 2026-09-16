// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use wxc_common::logger::{Logger, Mode};
use wxc_common::models::{
    ContainerPolicy, NetworkEnforcementMode, NetworkPolicy, ProxyAddress, ProxyConfig,
};

fn policy_with_proxy(host: &str, port: u16) -> ContainerPolicy {
    ContainerPolicy {
        network_enforcement_mode: NetworkEnforcementMode::Firewall,
        network_proxy: ProxyConfig {
            address: Some(ProxyAddress::new(host.to_string(), port)),
            builtin_test_server: false,
        },
        ..Default::default()
    }
}

fn apply_and_collect(
    container: &str,
    policy: &ContainerPolicy,
) -> (
    NetworkIptablesManager,
    Vec<Vec<String>>,
    Result<bool, String>,
) {
    let fake = super::test_firewall::install();
    let mut manager = NetworkIptablesManager::new(container, EgressHookPoint::ContainerNetns(4242));
    let mut logger = Logger::new(Mode::Buffer);
    let _ = fake.forget_issued();

    let result = manager.apply_firewall_rules(policy, &mut logger);
    let issued = fake.issued();
    (manager, issued, result)
}

fn appended_rules<'a>(
    issued: &'a [Vec<String>],
    binary: &str,
    chain: &str,
) -> Vec<&'a Vec<String>> {
    issued
        .iter()
        .filter(|argv| {
            argv.first().map(String::as_str) == Some(binary)
                && argv.get(1).map(String::as_str) == Some("-A")
                && argv.get(2).map(String::as_str) == Some(chain)
        })
        .collect()
}

fn action_of(rule: &[String]) -> Option<&str> {
    let index = rule.iter().position(|arg| arg == "-j")?;
    rule.get(index + 1).map(String::as_str)
}

fn has_pair(rule: &[String], flag: &str, value: &str) -> bool {
    rule.windows(2)
        .any(|pair| pair[0] == flag && pair[1] == value)
}

#[test]
fn proxy_mode_forces_a_drop_default_even_when_the_policy_says_allow() {
    assert_eq!(
        NetworkIptablesManager::default_policy_action(NetworkPolicy::Allow, true),
        "DROP"
    );
    assert_eq!(
        NetworkIptablesManager::default_policy_action(NetworkPolicy::Block, true),
        "DROP"
    );
}

#[test]
fn without_a_proxy_the_configured_default_policy_still_decides_the_catch_all() {
    assert_eq!(
        NetworkIptablesManager::default_policy_action(NetworkPolicy::Allow, false),
        "ACCEPT"
    );
    assert_eq!(
        NetworkIptablesManager::default_policy_action(NetworkPolicy::Block, false),
        "DROP"
    );
}

#[test]
fn the_terminal_rule_built_in_proxy_mode_drops() {
    let rule = NetworkIptablesManager::build_default_policy_rule_arg(
        "MXC-proxy-terminal",
        NetworkPolicy::Allow,
        true,
    );

    assert_eq!(action_of(&rule), Some("DROP"), "actual rule: {rule:?}");
}

#[test]
fn an_applied_proxy_chain_ends_in_drop_under_an_allow_default() {
    let mut policy = policy_with_proxy("10.9.8.7", 3128);
    policy.default_network_policy = NetworkPolicy::Allow;

    let (manager, issued, result) = apply_and_collect("proxy-allow-default", &policy);
    assert!(result.is_ok(), "apply must succeed, got {result:?}");

    let rules = appended_rules(&issued, "iptables", manager.chain_name());
    let last = rules.last().expect("the chain must have at least one rule");
    assert_eq!(
        action_of(last),
        Some("DROP"),
        "the last rule appended to a proxied chain must be the closing DROP; actual: {last:?}"
    );
}

#[test]
fn the_proxy_accept_names_the_proxy_address_port_and_protocol() {
    let policy = policy_with_proxy("10.9.8.7", 3128);

    let (manager, issued, result) = apply_and_collect("proxy-shape", &policy);
    assert!(result.is_ok(), "apply must succeed, got {result:?}");

    let rules = appended_rules(&issued, "iptables", manager.chain_name());
    let accepts: Vec<&&Vec<String>> = rules
        .iter()
        .filter(|rule| action_of(rule) == Some("ACCEPT") && !has_pair(rule, "-o", "lo"))
        .collect();

    assert_eq!(
        accepts.len(),
        1,
        "a proxied chain must carry exactly one ACCEPT reaching off-box, for the proxy; \
         actual: {rules:?}"
    );
    let accept = accepts[0];
    assert!(
        has_pair(accept, "-d", "10.9.8.7"),
        "the proxy ACCEPT must name the proxy address; actual: {accept:?}"
    );
    assert!(
        has_pair(accept, "--dport", "3128"),
        "the proxy ACCEPT must name the proxy port; actual: {accept:?}"
    );
    assert!(
        has_pair(accept, "-p", "tcp"),
        "the proxy ACCEPT must be scoped to TCP; actual: {accept:?}"
    );
}

#[test]
fn the_proxy_accept_is_appended_before_the_closing_drop() {
    let policy = policy_with_proxy("10.9.8.7", 3128);

    let (manager, issued, result) = apply_and_collect("proxy-order", &policy);
    assert!(result.is_ok(), "apply must succeed, got {result:?}");

    let rules = appended_rules(&issued, "iptables", manager.chain_name());
    let actions: Vec<Option<&str>> = rules.iter().map(|rule| action_of(rule)).collect();

    assert_eq!(
        actions,
        vec![Some("ACCEPT"), Some("ACCEPT"), Some("DROP")],
        "a proxied chain must read exactly 'keep loopback, accept the proxy, drop the rest'; \
         actual: {rules:?}"
    );
    assert!(
        has_pair(rules[0], "-o", "lo"),
        "loopback comes first; actual: {rules:?}"
    );
    assert!(
        has_pair(rules[1], "-d", "10.9.8.7"),
        "the proxy ACCEPT comes second; actual: {rules:?}"
    );
}

#[test]
fn every_resolved_proxy_address_is_opened() {
    let mut logger = Logger::new(Mode::Buffer);
    let policy = policy_with_proxy("localhost", 8888);

    let (endpoints, _pin) = NetworkIptablesManager::resolve_proxy_endpoints(&policy, &mut logger)
        .expect("localhost must resolve");

    assert!(
        !endpoints.is_empty(),
        "localhost must yield at least one endpoint"
    );
    assert!(
        endpoints.iter().all(|endpoint| endpoint.port == 8888),
        "every endpoint must carry the configured proxy port; actual: {endpoints:?}"
    );
}

#[test]
fn proxy_mode_opens_no_dns_port() {
    let policy = policy_with_proxy("10.9.8.7", 3128);

    let (manager, issued, result) = apply_and_collect("proxy-nodns", &policy);
    assert!(result.is_ok(), "apply must succeed, got {result:?}");

    let rules = appended_rules(&issued, "iptables", manager.chain_name());
    assert!(
        !rules.is_empty(),
        "the proxied chain must have been programmed at all; issued: {issued:?}"
    );

    for rule in rules {
        assert!(
            !has_pair(rule, "--dport", "53"),
            "a proxied chain must not open DNS; actual: {rule:?}"
        );
    }
}

#[test]
fn proxy_mode_keeps_loopback_and_drops_the_conntrack_exemption() {
    let policy = policy_with_proxy("10.9.8.7", 3128);

    let (manager, issued, result) = apply_and_collect("proxy-nobase", &policy);
    assert!(result.is_ok(), "apply must succeed, got {result:?}");

    let rules = appended_rules(&issued, "iptables", manager.chain_name());
    assert!(
        !rules.is_empty(),
        "the proxied chain must have been programmed at all; issued: {issued:?}"
    );

    assert!(
        rules.iter().any(|rule| has_pair(rule, "-o", "lo")),
        "a proxied container must still reach its own loopback; actual: {rules:?}"
    );

    for rule in rules {
        assert!(
            !has_pair(rule, "-i", "lo"),
            "this chain hangs off OUTPUT, where -i never matches; actual: {rule:?}"
        );
        assert!(
            !has_pair(rule, "--state", "ESTABLISHED,RELATED"),
            "a proxied chain must not carry the conntrack exemption; actual: {rule:?}"
        );
    }
}

#[test]
fn proxy_mode_does_not_program_the_allow_list() {
    let mut policy = policy_with_proxy("10.9.8.7", 3128);
    policy.allowed_hosts = vec!["10.1.1.1".to_string()];

    let (manager, issued, result) = apply_and_collect("proxy-nolists", &policy);
    assert!(result.is_ok(), "apply must succeed, got {result:?}");

    let rules = appended_rules(&issued, "iptables", manager.chain_name());
    assert!(
        !rules.is_empty(),
        "the proxied chain must have been programmed at all; issued: {issued:?}"
    );

    for rule in rules {
        assert!(
            !has_pair(rule, "-d", "10.1.1.1"),
            "a proxied chain must ignore the allow list; actual: {rule:?}"
        );
    }
}

#[test]
fn a_proxy_combined_with_a_block_list_is_refused() {
    let mut policy = policy_with_proxy("10.9.8.7", 3128);
    policy.blocked_hosts = vec!["10.2.2.2".to_string()];

    let (_manager, _issued, result) = apply_and_collect("proxy-blocked", &policy);

    let message = result.expect_err("a policy whose block list cannot be enforced must be refused");
    assert!(
        message.contains("blockedHosts"),
        "the refusal must name the setting that cannot be enforced, got: {message}"
    );
}

#[test]
fn the_ipv6_chain_allows_only_loopback_before_its_closing_drop_in_proxy_mode() {
    let policy = policy_with_proxy("10.9.8.7", 3128);

    let (manager, issued, result) = apply_and_collect("proxy-v6", &policy);
    assert!(result.is_ok(), "apply must succeed, got {result:?}");

    let rules = appended_rules(&issued, "ip6tables", manager.chain_name());
    let actions: Vec<Option<&str>> = rules.iter().map(|rule| action_of(rule)).collect();

    assert_eq!(
        actions,
        vec![Some("ACCEPT"), Some("DROP")],
        "the IPv6 chain of a proxied container must deny everything it can route; \
         actual: {rules:?}"
    );
    assert!(
        has_pair(rules[0], "-o", "lo"),
        "the only IPv6 ACCEPT must be the loopback one; actual: {rules:?}"
    );
}

#[test]
fn without_a_proxy_the_base_exemptions_and_host_lists_are_still_programmed() {
    let policy = ContainerPolicy {
        network_enforcement_mode: NetworkEnforcementMode::Firewall,
        allowed_hosts: vec!["10.1.1.1".to_string()],
        ..Default::default()
    };

    let (manager, issued, result) = apply_and_collect("proxy-control", &policy);
    assert!(result.is_ok(), "apply must succeed, got {result:?}");

    let rules = appended_rules(&issued, "iptables", manager.chain_name());
    assert!(
        rules.iter().any(|rule| has_pair(rule, "-o", "lo")),
        "a non-proxied chain must still carry the loopback exemption; actual: {rules:?}"
    );
    assert!(
        rules.iter().any(|rule| has_pair(rule, "--dport", "53")),
        "a non-proxied chain must still open DNS; actual: {rules:?}"
    );
    assert!(
        rules.iter().any(|rule| has_pair(rule, "-d", "10.1.1.1")),
        "a non-proxied chain must still program its allow list; actual: {rules:?}"
    );
}

#[test]
fn no_chain_opens_a_dhcp_port() {
    let filtered = ContainerPolicy {
        network_enforcement_mode: NetworkEnforcementMode::Firewall,
        default_network_policy: NetworkPolicy::Block,
        allowed_hosts: vec!["10.1.1.1".to_string()],
        ..Default::default()
    };

    for (name, policy) in [
        ("dhcp-filtered", filtered),
        ("dhcp-proxied", policy_with_proxy("10.9.8.7", 3128)),
    ] {
        let (manager, issued, result) = apply_and_collect(name, &policy);
        assert!(result.is_ok(), "apply must succeed, got {result:?}");

        let mut programmed = false;
        for binary in ["iptables", "ip6tables"] {
            for rule in appended_rules(&issued, binary, manager.chain_name()) {
                programmed = true;
                assert!(
                    !has_pair(rule, "--dport", "67") && !has_pair(rule, "--dport", "547"),
                    "{name} must not open a DHCP port; actual: {rule:?}"
                );
            }
        }
        assert!(
            programmed,
            "{name} never reached the rule builder, so this assertion would hold \
             vacuously; issued: {issued:?}"
        );
    }
}

#[test]
fn an_ipv6_proxy_literal_is_refused_rather_than_silently_dropped() {
    let mut logger = Logger::new(Mode::Buffer);

    for host in ["2001:db8::1", "[2001:db8::1]"] {
        let policy = policy_with_proxy(host, 3128);
        let err = NetworkIptablesManager::resolve_proxy_endpoints(&policy, &mut logger)
            .expect_err("an IPv6 proxy endpoint must be refused");

        assert!(
            err.to_lowercase().contains("ipv6"),
            "the refusal must say IPv6 is the reason, got: {err}"
        );
    }
}

#[test]
fn ipv6_literals_are_recognized_bracketed_or_bare() {
    assert!(
        NetworkIptablesManager::host_is_ipv6_literal("::1"),
        "a bare IPv6 literal must be recognized"
    );
    assert!(
        NetworkIptablesManager::host_is_ipv6_literal("[::1]"),
        "a bracketed IPv6 literal must be recognized"
    );
    assert!(
        NetworkIptablesManager::host_is_ipv6_literal("2001:db8::1"),
        "a full IPv6 literal must be recognized"
    );
    assert!(
        !NetworkIptablesManager::host_is_ipv6_literal("10.9.8.7"),
        "an IPv4 literal must not be classified as IPv6"
    );
    assert!(
        !NetworkIptablesManager::host_is_ipv6_literal("proxy.example.com"),
        "a hostname must not be classified as IPv6"
    );
}

#[test]
fn a_hostname_proxy_records_a_pin_naming_an_authorized_address() {
    let policy = policy_with_proxy("localhost", 8888);

    let (manager, _issued, result) = apply_and_collect("proxy-pin", &policy);
    assert!(result.is_ok(), "apply must succeed, got {result:?}");

    let pin = manager
        .proxy_host_pin()
        .expect("a hostname proxy must record a pin");
    assert_eq!(pin.hostname(), "localhost");
    assert_eq!(pin.ip().to_string(), "127.0.0.1");
}

#[test]
fn an_ip_literal_proxy_records_no_pin() {
    let policy = policy_with_proxy("10.9.8.7", 3128);

    let (manager, _issued, result) = apply_and_collect("proxy-nopin", &policy);
    assert!(result.is_ok(), "apply must succeed, got {result:?}");

    assert!(
        manager.proxy_host_pin().is_none(),
        "an IP-literal proxy needs no hosts entry"
    );
}

#[test]
fn a_policy_without_a_proxy_records_no_pin() {
    let policy = ContainerPolicy {
        network_enforcement_mode: NetworkEnforcementMode::Firewall,
        ..Default::default()
    };

    let (manager, _issued, result) = apply_and_collect("proxy-absent", &policy);
    assert!(result.is_ok(), "apply must succeed, got {result:?}");

    assert!(
        manager.proxy_host_pin().is_none(),
        "a policy without a proxy must not record a hosts-file pin"
    );
}

#[test]
fn a_zero_proxy_port_is_refused() {
    let mut logger = Logger::new(Mode::Buffer);
    let policy = policy_with_proxy("10.9.8.7", 0);

    let err = NetworkIptablesManager::resolve_proxy_endpoints(&policy, &mut logger)
        .expect_err("port 0 must be refused");

    assert!(
        err.to_lowercase().contains("port"),
        "the refusal must name the port as the reason, got: {err}"
    );
}

#[test]
fn an_unresolvable_proxy_host_is_refused() {
    let mut logger = Logger::new(Mode::Buffer);
    let policy = policy_with_proxy("proxy.invalid", 3128);

    let err = NetworkIptablesManager::resolve_proxy_endpoints(&policy, &mut logger)
        .expect_err("an unresolvable proxy host must be refused");

    assert!(
        err.contains("proxy.invalid"),
        "the refusal must name the host that failed, got: {err}"
    );
}

#[test]
fn a_policy_without_a_proxy_resolves_to_no_endpoints() {
    let mut logger = Logger::new(Mode::Buffer);
    let policy = ContainerPolicy::default();

    let (endpoints, pin) = NetworkIptablesManager::resolve_proxy_endpoints(&policy, &mut logger)
        .expect("a policy with no proxy must not be an error");

    assert!(endpoints.is_empty());
    assert!(pin.is_none());
}

#[test]
fn a_proxy_answer_larger_than_the_cap_contributes_no_more_than_the_cap() {
    let addresses: Vec<String> = (0..40).map(|n| format!("203.0.113.{n}")).collect();
    let mut logger = Logger::new(Mode::Buffer);

    let accepted =
        NetworkIptablesManager::bound_proxy_addresses("proxy.invalid", &addresses, &mut logger);

    assert_eq!(
        accepted.len(),
        NetworkIptablesManager::MAX_PROXY_ENDPOINTS,
        "a 40-address answer must not become 40 ACCEPT rules and 40 iptables \
         processes on the container-start path; actual count: {}",
        accepted.len()
    );

    assert_eq!(
        accepted.first().map(String::as_str),
        Some("203.0.113.0"),
        "the pinned address must survive the bound; actual: {:?}",
        accepted.first()
    );

    let buffer = logger.get_buffer();
    assert!(
        buffer.contains("proxy.invalid") && buffer.contains("40"),
        "a trimmed answer must say which host was trimmed and from what size; \
         actual buffer: {buffer:?}"
    );
}

#[test]
fn a_proxy_answer_within_the_cap_is_left_alone() {
    let addresses: Vec<String> = (0..3).map(|n| format!("203.0.113.{n}")).collect();
    let mut logger = Logger::new(Mode::Buffer);

    let accepted =
        NetworkIptablesManager::bound_proxy_addresses("proxy.invalid", &addresses, &mut logger);

    assert_eq!(
        accepted,
        addresses.as_slice(),
        "an answer within the cap must reach the chain intact"
    );
    assert!(
        logger.get_buffer().is_empty(),
        "an untrimmed answer must not warn; actual buffer: {:?}",
        logger.get_buffer()
    );
}
