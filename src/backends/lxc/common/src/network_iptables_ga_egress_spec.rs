// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Black-box specification for schema 0.8 `network.egress` lowering, written
//! against the rule builder's documented contract rather than its implementation.

use super::*;

fn directional_policy(
    default: NetworkAction,
    allow: Vec<NetworkRule>,
    deny: Vec<NetworkRule>,
) -> ContainerPolicy {
    ContainerPolicy {
        network_mode_specified: true,
        network_egress: Some(NetworkEgressPolicy {
            default,
            allow,
            deny,
        }),
        ..Default::default()
    }
}

fn peer(cidr: &str, except: &[&str]) -> NetworkPeer {
    NetworkPeer {
        cidr: cidr
            .parse()
            .unwrap_or_else(|error| panic!("invalid test CIDR {cidr:?}: {error}")),
        except: except
            .iter()
            .map(|value| {
                value
                    .parse()
                    .unwrap_or_else(|error| panic!("invalid test exclusion {value:?}: {error}"))
            })
            .collect(),
    }
}

fn rule(to: Vec<NetworkPeer>, ports: Vec<NetworkPort>) -> NetworkRule {
    NetworkRule { to, ports }
}

fn port(protocol: NetworkProtocol, port: Option<u16>, end_port: Option<u16>) -> NetworkPort {
    NetworkPort {
        protocol,
        port,
        end_port,
    }
}

fn argument_after<'a>(arguments: &'a [String], flag: &str) -> Option<&'a str> {
    arguments
        .windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].as_str())
}

fn destination_actions<'a>(rules: &'a [Vec<String>], destination: &str) -> Vec<&'a str> {
    rules
        .iter()
        .filter(|rule| argument_after(rule, "-d") == Some(destination))
        .filter_map(|rule| argument_after(rule, "-j"))
        .collect()
}

fn rule_position(rules: &[Vec<String>], destination: &str, action: &str) -> Option<usize> {
    rules.iter().position(|rule| {
        argument_after(rule, "-d") == Some(destination)
            && argument_after(rule, "-j") == Some(action)
    })
}

fn packet_address(value: &str) -> std::net::IpAddr {
    value
        .parse()
        .unwrap_or_else(|error| panic!("invalid test address {value:?}: {error}"))
}

fn destination_matches(rule_destination: &str, packet: std::net::IpAddr) -> bool {
    let network: NetworkCidr = rule_destination.parse().unwrap_or_else(|error| {
        panic!("invalid emitted destination {rule_destination:?}: {error}")
    });
    let packet = NetworkCidr {
        address: packet,
        prefix_length: if packet.is_ipv4() { 32 } else { 128 },
    };
    network.contains_cidr(&packet)
}

fn port_matches(selector: &str, packet_port: u16) -> bool {
    let parse_port = |value: &str| {
        value
            .parse::<u16>()
            .unwrap_or_else(|error| panic!("invalid emitted port {value:?}: {error}"))
    };

    match selector.split_once(':') {
        Some((start, end)) => {
            let start = parse_port(start);
            let end = parse_port(end);
            (start..=end).contains(&packet_port)
        }
        None => parse_port(selector) == packet_port,
    }
}

fn matching_emitted_rule<'a>(
    rules: &'a [Vec<String>],
    destination: std::net::IpAddr,
    protocol: &str,
    port: Option<u16>,
) -> Option<&'a [String]> {
    for rule in rules {
        if rule.iter().any(|argument| argument.contains("ESTABLISHED")) {
            continue;
        }
        if argument_after(rule, "-d")
            .is_some_and(|rule_destination| !destination_matches(rule_destination, destination))
        {
            continue;
        }
        if argument_after(rule, "-p")
            .is_some_and(|rule_protocol| rule_protocol != "all" && rule_protocol != protocol)
        {
            continue;
        }
        if argument_after(rule, "--dport")
            .is_some_and(|selector| !port.is_some_and(|value| port_matches(selector, value)))
        {
            continue;
        }
        if argument_after(rule, "-j").is_some() {
            return Some(rule);
        }
    }

    None
}

fn new_connection_action<'a>(
    rules: &'a [Vec<String>],
    destination: std::net::IpAddr,
    protocol: &str,
    port: Option<u16>,
) -> &'a str {
    matching_emitted_rule(rules, destination, protocol, port)
        .and_then(|rule| argument_after(rule, "-j"))
        .unwrap_or_else(|| {
            panic!(
                "no emitted rule matched destination={destination}, protocol={protocol:?}, port={port:?}, rules={rules:?}"
            )
        })
}

#[test]
fn explicit_deny_precedes_an_overlapping_allow_in_both_families() {
    let ipv4 = "198.51.100.0/24";
    let ipv6 = "2001:db8::/32";
    let matching_rule = || rule(vec![peer(ipv4, &[]), peer(ipv6, &[])], Vec::new());
    let policy = directional_policy(
        NetworkAction::Deny,
        vec![matching_rule()],
        vec![matching_rule()],
    );
    let rules = NetworkIptablesManager::build_policy_rule_args("MXC-test", &policy, true);

    assert_eq!(
        destination_actions(&rules.ipv4, ipv4),
        vec!["DROP", "ACCEPT"],
        "input=allow+deny to {ipv4}, family=IPv4; output={:?}",
        rules.ipv4
    );
    assert_eq!(
        destination_actions(&rules.ipv6, ipv6),
        vec!["DROP", "ACCEPT"],
        "input=allow+deny to {ipv6}, family=IPv6; output={:?}",
        rules.ipv6
    );
}

#[test]
fn an_allow_peer_exclusion_is_denied_before_its_parent_cidr_is_allowed() {
    let parent = "10.0.0.0/8";
    let exclusion = "10.10.0.0/16";
    let policy = directional_policy(
        NetworkAction::Deny,
        vec![rule(vec![peer(parent, &[exclusion])], Vec::new())],
        Vec::new(),
    );
    let rules = NetworkIptablesManager::build_policy_rule_args("MXC-test", &policy, true);
    let exclusion_position = rule_position(&rules.ipv4, exclusion, "DROP");
    let parent_position = rule_position(&rules.ipv4, parent, "ACCEPT");

    assert!(
        matches!(
            (exclusion_position, parent_position),
            (Some(exclusion_position), Some(parent_position))
                if exclusion_position < parent_position
        ),
        "input=default deny, allow.to=[{{cidr:{parent}, except:[{exclusion}]}}]; expected exclusion DROP before parent ACCEPT; positions={exclusion_position:?}/{parent_position:?}; output={:?}",
        rules.ipv4
    );
}

#[test]
fn a_deny_peer_exclusion_remains_outside_the_deny() {
    let parent = "10.0.0.0/8";
    let exclusion = "10.10.0.0/16";
    let policy = directional_policy(
        NetworkAction::Allow,
        Vec::new(),
        vec![rule(vec![peer(parent, &[exclusion])], Vec::new())],
    );
    let rules = NetworkIptablesManager::build_policy_rule_args("MXC-test", &policy, true);

    assert_eq!(
        new_connection_action(
            &rules.ipv4,
            packet_address("10.10.1.1"),
            "tcp",
            Some(443)
        ),
        "ACCEPT",
        "input=default allow, deny.to=[{{cidr:{parent}, except:[{exclusion}]}}], packet=10.10.1.1/tcp/443; output={:?}",
        rules.ipv4
    );
    assert_eq!(
        new_connection_action(
            &rules.ipv4,
            packet_address("10.20.1.1"),
            "tcp",
            Some(443)
        ),
        "DROP",
        "input=default allow, deny.to=[{{cidr:{parent}, except:[{exclusion}]}}], packet=10.20.1.1/tcp/443; output={:?}",
        rules.ipv4
    );
}

#[test]
fn an_exclusion_inside_an_allow_rule_under_an_allow_default_stays_reachable() {
    let parent = "10.0.0.0/8";
    let exclusion = "10.10.0.0/16";
    let policy = directional_policy(
        NetworkAction::Allow,
        vec![rule(vec![peer(parent, &[exclusion])], Vec::new())],
        Vec::new(),
    );
    let rules = NetworkIptablesManager::build_policy_rule_args("MXC-test", &policy, true);

    assert_eq!(
        new_connection_action(&rules.ipv4, packet_address("10.10.1.1"), "tcp", Some(443)),
        "ACCEPT",
        "input=default allow, allow.to=[{{cidr:{parent}, except:[{exclusion}]}}], packet=10.10.1.1/tcp/443; an exclusion narrows its own rule and never reverses the direction default; output={:?}",
        rules.ipv4
    );
    assert!(
        rule_position(&rules.ipv4, exclusion, "DROP").is_none()
            && rule_position(&rules.ipv4, exclusion, "ACCEPT").is_none(),
        "input=default allow, allow.to=[{{cidr:{parent}, except:[{exclusion}]}}]; the exclusion and the default agree, so no carve-out of either action belongs in the chain; output={:?}",
        rules.ipv4
    );
}

#[test]
fn an_exclusion_inside_a_deny_rule_under_a_deny_default_stays_blocked() {
    let parent = "10.0.0.0/8";
    let exclusion = "10.10.0.0/16";
    let policy = directional_policy(
        NetworkAction::Deny,
        Vec::new(),
        vec![rule(vec![peer(parent, &[exclusion])], Vec::new())],
    );
    let rules = NetworkIptablesManager::build_policy_rule_args("MXC-test", &policy, true);

    assert_eq!(
        new_connection_action(&rules.ipv4, packet_address("10.10.1.1"), "tcp", Some(443)),
        "DROP",
        "input=default deny, deny.to=[{{cidr:{parent}, except:[{exclusion}]}}], packet=10.10.1.1/tcp/443; an exclusion narrows its own rule and never reverses the direction default; output={:?}",
        rules.ipv4
    );
    assert!(
        rule_position(&rules.ipv4, exclusion, "ACCEPT").is_none()
            && rule_position(&rules.ipv4, exclusion, "DROP").is_none(),
        "input=default deny, deny.to=[{{cidr:{parent}, except:[{exclusion}]}}]; the exclusion and the default agree, so no carve-out of either action belongs in the chain; output={:?}",
        rules.ipv4
    );
}

#[test]
fn each_cidr_is_emitted_only_in_its_matching_address_family() {
    let ipv4 = "192.0.2.0/24";
    let ipv6 = "2001:db8:1::/48";
    let policy = directional_policy(
        NetworkAction::Deny,
        vec![rule(vec![peer(ipv4, &[]), peer(ipv6, &[])], Vec::new())],
        Vec::new(),
    );
    let rules = NetworkIptablesManager::build_policy_rule_args("MXC-test", &policy, true);

    assert_eq!(
        destination_actions(&rules.ipv4, ipv4),
        vec!["ACCEPT"],
        "input=allow.to=[{ipv4},{ipv6}], expected {ipv4} in IPv4 only; output={:?}",
        rules.ipv4
    );
    assert!(
        destination_actions(&rules.ipv4, ipv6).is_empty(),
        "input=allow.to=[{ipv4},{ipv6}], expected no {ipv6} in IPv4; output={:?}",
        rules.ipv4
    );
    assert_eq!(
        destination_actions(&rules.ipv6, ipv6),
        vec!["ACCEPT"],
        "input=allow.to=[{ipv4},{ipv6}], expected {ipv6} in IPv6 only; output={:?}",
        rules.ipv6
    );
    assert!(
        destination_actions(&rules.ipv6, ipv4).is_empty(),
        "input=allow.to=[{ipv4},{ipv6}], expected no {ipv4} in IPv6; output={:?}",
        rules.ipv6
    );
}

#[test]
fn an_omitted_to_matches_destinations_in_both_address_families() {
    let policy = directional_policy(
        NetworkAction::Deny,
        vec![rule(
            Vec::new(),
            vec![port(NetworkProtocol::Tcp, Some(443), None)],
        )],
        Vec::new(),
    );
    let rules = NetworkIptablesManager::build_policy_rule_args("MXC-test", &policy, true);

    assert_eq!(
        new_connection_action(
            &rules.ipv4,
            packet_address("192.0.2.25"),
            "tcp",
            Some(443)
        ),
        "ACCEPT",
        "input=default deny, allow=[{{to omitted, ports:[tcp/443]}}], packet=192.0.2.25/tcp/443; output={:?}",
        rules.ipv4
    );
    assert_eq!(
        new_connection_action(
            &rules.ipv6,
            packet_address("2001:db8::25"),
            "tcp",
            Some(443)
        ),
        "ACCEPT",
        "input=default deny, allow=[{{to omitted, ports:[tcp/443]}}], packet=2001:db8::25/tcp/443; output={:?}",
        rules.ipv6
    );
}

#[test]
fn omitted_ports_match_every_protocol_and_port() {
    let destination = "192.0.2.0/24";
    let policy = directional_policy(
        NetworkAction::Deny,
        vec![rule(vec![peer(destination, &[])], Vec::new())],
        Vec::new(),
    );
    let rules = NetworkIptablesManager::build_policy_rule_args("MXC-test", &policy, true);
    let address = packet_address("192.0.2.25");

    for (protocol, port) in [("tcp", Some(443)), ("udp", Some(53)), ("icmp", None)] {
        assert_eq!(
            new_connection_action(&rules.ipv4, address, protocol, port),
            "ACCEPT",
            "input=default deny, allow=[{{to:{destination}, ports omitted}}], packet=192.0.2.25/{protocol}/{port:?}; output={:?}",
            rules.ipv4
        );
    }
}

#[test]
fn explicit_any_without_a_port_matches_every_protocol_and_port() {
    let destination = "192.0.2.0/24";
    let policy = directional_policy(
        NetworkAction::Deny,
        vec![rule(
            vec![peer(destination, &[])],
            vec![port(NetworkProtocol::Any, None, None)],
        )],
        Vec::new(),
    );
    let rules = NetworkIptablesManager::build_policy_rule_args("MXC-test", &policy, true);
    let address = packet_address("192.0.2.25");

    for (protocol, port) in [
        ("tcp", Some(1)),
        ("tcp", Some(65535)),
        ("udp", Some(1)),
        ("udp", Some(65535)),
        ("icmp", None),
    ] {
        assert_eq!(
            new_connection_action(&rules.ipv4, address, protocol, port),
            "ACCEPT",
            "input=default deny, allow=[{{to:{destination}, ports:[any]}}], packet=192.0.2.25/{protocol}/{port:?}; output={:?}",
            rules.ipv4
        );
    }
}

#[test]
fn any_with_a_port_expands_to_tcp_and_udp_rules() {
    let destination = "192.0.2.0/24";
    let policy = directional_policy(
        NetworkAction::Deny,
        vec![rule(
            vec![peer(destination, &[])],
            vec![
                port(NetworkProtocol::Any, Some(443), None),
                port(NetworkProtocol::Any, Some(1000), Some(2000)),
            ],
        )],
        Vec::new(),
    );
    let rules = NetworkIptablesManager::build_policy_rule_args("MXC-test", &policy, true);
    let address = packet_address("192.0.2.25");
    let mut selectors = rules
        .ipv4
        .iter()
        .filter(|rule| {
            argument_after(rule, "-d") == Some(destination)
                && argument_after(rule, "-j") == Some("ACCEPT")
        })
        .map(|rule| (argument_after(rule, "-p"), argument_after(rule, "--dport")))
        .collect::<Vec<_>>();
    selectors.sort_unstable();

    assert_eq!(
        selectors,
        vec![
            (Some("tcp"), Some("1000:2000")),
            (Some("tcp"), Some("443")),
            (Some("udp"), Some("1000:2000")),
            (Some("udp"), Some("443")),
        ],
        "input=default deny, allow=[{{to:{destination}, ports:[any/443,any/1000-2000]}}]; expected one TCP and one UDP rule per selector; output={:?}",
        rules.ipv4
    );

    for (protocol, packet_port) in [
        ("tcp", 443),
        ("udp", 443),
        ("tcp", 1000),
        ("tcp", 2000),
        ("udp", 1000),
        ("udp", 2000),
    ] {
        assert_eq!(
            new_connection_action(&rules.ipv4, address, protocol, Some(packet_port)),
            "ACCEPT",
            "input=default deny, allow=[{{to:{destination}, ports:[any/443,any/1000-2000]}}], packet=192.0.2.25/{protocol}/{packet_port}; output={:?}",
            rules.ipv4
        );
    }
    assert!(
        matching_emitted_rule(&rules.ipv4, address, "icmp", Some(443)).is_none(),
        "input=default deny, allow=[{{to:{destination}, ports:[any/443]}}], packet=192.0.2.25/icmp; expected no emitted rule match; output={:?}",
        rules.ipv4
    );
}

#[test]
fn icmp_ignores_a_written_port() {
    let destination = "192.0.2.0/24";
    let policy = directional_policy(
        NetworkAction::Deny,
        vec![rule(
            vec![peer(destination, &[])],
            vec![port(NetworkProtocol::Icmp, Some(443), None)],
        )],
        Vec::new(),
    );
    let rules = NetworkIptablesManager::build_policy_rule_args("MXC-test", &policy, true);
    let emitted_rule = rules.ipv4.iter().find(|rule| {
        argument_after(rule, "-d") == Some(destination)
            && argument_after(rule, "-j") == Some("ACCEPT")
    });

    assert_eq!(
        emitted_rule.and_then(|rule| argument_after(rule, "-p")),
        Some("icmp"),
        "input=default deny, allow=[{{to:{destination}, ports:[icmp/443]}}]; output={:?}",
        rules.ipv4
    );
    assert!(
        emitted_rule.is_some_and(|rule| argument_after(rule, "--dport").is_none()),
        "input=default deny, allow=[{{to:{destination}, ports:[icmp/443]}}]; expected no destination port; output={:?}",
        rules.ipv4
    );
}

#[test]
fn a_single_port_and_an_inclusive_range_restrict_their_protocols() {
    let destination = "192.0.2.0/24";
    let policy = directional_policy(
        NetworkAction::Deny,
        vec![rule(
            vec![peer(destination, &[])],
            vec![
                port(NetworkProtocol::Tcp, Some(443), None),
                port(NetworkProtocol::Udp, Some(1000), Some(2000)),
            ],
        )],
        Vec::new(),
    );
    let rules = NetworkIptablesManager::build_policy_rule_args("MXC-test", &policy, true);
    let address = packet_address("192.0.2.25");

    for (protocol, packet_port, expected_action) in [
        ("tcp", 443, Some("ACCEPT")),
        ("tcp", 444, None),
        ("udp", 1000, Some("ACCEPT")),
        ("udp", 2000, Some("ACCEPT")),
        ("udp", 2001, None),
    ] {
        let matching_action =
            matching_emitted_rule(&rules.ipv4, address, protocol, Some(packet_port))
                .and_then(|rule| argument_after(rule, "-j"));

        assert_eq!(
            matching_action,
            expected_action,
            "input=default deny, allow=[{{to:{destination}, ports:[tcp/443,udp/1000-2000]}}], packet=192.0.2.25/{protocol}/{packet_port}; expected emitted-rule action={expected_action:?}; output={:?}",
            rules.ipv4
        );
    }
}

#[test]
fn each_peer_combines_with_each_port_selector() {
    let first_destination = "192.0.2.0/24";
    let second_destination = "198.51.100.0/24";
    let policy = directional_policy(
        NetworkAction::Deny,
        vec![rule(
            vec![peer(first_destination, &[]), peer(second_destination, &[])],
            vec![
                port(NetworkProtocol::Tcp, Some(443), None),
                port(NetworkProtocol::Udp, Some(53), None),
            ],
        )],
        Vec::new(),
    );
    let rules = NetworkIptablesManager::build_policy_rule_args("MXC-test", &policy, true);

    for (destination, address) in [
        (first_destination, "192.0.2.25"),
        (second_destination, "198.51.100.25"),
    ] {
        for (protocol, packet_port) in [("tcp", 443), ("udp", 53)] {
            assert_eq!(
                new_connection_action(
                    &rules.ipv4,
                    packet_address(address),
                    protocol,
                    Some(packet_port)
                ),
                "ACCEPT",
                "input=default deny, allow=[{{to:[{first_destination},{second_destination}], ports:[tcp/443,udp/53]}}], packet={address}/{protocol}/{packet_port}, selected peer={destination}; output={:?}",
                rules.ipv4
            );
        }
    }
}

#[test]
fn icmp_uses_the_family_specific_protocol_without_a_port() {
    let ipv4 = "192.0.2.0/24";
    let ipv6 = "2001:db8::/32";
    let policy = directional_policy(
        NetworkAction::Deny,
        vec![rule(
            vec![peer(ipv4, &[]), peer(ipv6, &[])],
            vec![port(NetworkProtocol::Icmp, None, None)],
        )],
        Vec::new(),
    );
    let rules = NetworkIptablesManager::build_policy_rule_args("MXC-test", &policy, true);
    let ipv4_rule = rules.ipv4.iter().find(|rule| {
        argument_after(rule, "-d") == Some(ipv4) && argument_after(rule, "-j") == Some("ACCEPT")
    });
    let ipv6_rule = rules.ipv6.iter().find(|rule| {
        argument_after(rule, "-d") == Some(ipv6) && argument_after(rule, "-j") == Some("ACCEPT")
    });

    assert_eq!(
        ipv4_rule.and_then(|rule| argument_after(rule, "-p")),
        Some("icmp"),
        "input=allow.to=[{ipv4},{ipv6}], ports=[icmp], family=IPv4; output={:?}",
        rules.ipv4
    );
    assert!(
        ipv4_rule.is_some_and(|rule| argument_after(rule, "--dport").is_none()),
        "input=allow.to=[{ipv4},{ipv6}], ports=[icmp], family=IPv4; expected no destination port; output={:?}",
        rules.ipv4
    );
    assert_eq!(
        ipv6_rule.and_then(|rule| argument_after(rule, "-p")),
        Some("icmpv6"),
        "input=allow.to=[{ipv4},{ipv6}], ports=[icmp], family=IPv6; output={:?}",
        rules.ipv6
    );
    assert!(
        ipv6_rule.is_some_and(|rule| argument_after(rule, "--dport").is_none()),
        "input=allow.to=[{ipv4},{ipv6}], ports=[icmp], family=IPv6; expected no destination port; output={:?}",
        rules.ipv6
    );
}

fn appended_ipv4_chain_rules(
    container: &str,
    policy: &ContainerPolicy,
    uses_directional_schema: bool,
) -> Vec<Vec<String>> {
    let fake = super::test_firewall::install();
    let mut manager = NetworkIptablesManager::new(container);
    manager.set_veth_interface("veth-dns0");
    manager.set_directional_schema(uses_directional_schema);
    let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);
    let _ = fake.forget_issued();

    let result = manager.apply_firewall_rules(policy, &mut logger);
    assert!(result.is_ok(), "apply must succeed, got {result:?}");

    let chain = manager.chain_name().to_string();
    let appended: Vec<Vec<String>> = fake
        .issued()
        .into_iter()
        .filter(|argv| {
            argv.first().map(String::as_str) == Some("iptables")
                && argv.get(1).map(String::as_str) == Some("-A")
                && argv.get(2).map(String::as_str) == Some(chain.as_str())
        })
        .collect();

    // A policy that installs no chain emits nothing, which satisfies every
    // "does not open DNS" assertion without exercising the builder at all.
    assert!(
        !appended.is_empty(),
        "no rules were appended to {chain}; this policy never reached the rule builder, \
         so any assertion about its rules would hold vacuously"
    );

    appended
}

/// A generated rule always names a destination, unlike the legacy port 53
/// exemption pair this checks for.
fn opens_dns_unconditionally(rules: &[Vec<String>]) -> bool {
    let generated = rules
        .iter()
        .position(|rule| argument_after(rule, "-d").is_some())
        .unwrap_or(rules.len());
    let exempts = |protocol: &str| {
        rules[..generated].iter().any(|rule| {
            argument_after(rule, "-p") == Some(protocol)
                && argument_after(rule, "--dport") == Some("53")
                && argument_after(rule, "-j") == Some("ACCEPT")
        })
    };
    exempts("udp") && exempts("tcp")
}

fn policy_from_json(json: &str) -> ContainerPolicy {
    let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);
    let request = wxc_common::config_parser::load_mxc_request_from_json(json, &mut logger)
        .unwrap_or_else(|_| panic!("config must parse: {json}"));
    match request {
        wxc_common::state_aware_request::MxcRequest::OneShot(request) => request.policy,
        _ => panic!("expected a one-shot request"),
    }
}

// A directional posture governs forwarded DNS the same as every other
// forwarded destination: a resolver the policy never allowed is a resolver
// the container cannot reach.
#[test]
fn a_directional_deny_default_chain_does_not_open_dns() {
    let policy = directional_policy(NetworkAction::Deny, vec![], vec![]);
    let rules = appended_ipv4_chain_rules("ga-dns-deny", &policy, true);

    assert!(
        !opens_dns_unconditionally(&rules),
        "input=egress.default=deny; expected no unscoped port 53 accept; output={rules:?}"
    );
}

// The closing ACCEPT on the allow-default branch already reaches every
// destination, and could mask a reintroduced exemption undetected by the
// test above.
#[test]
fn a_directional_allow_default_chain_does_not_open_dns() {
    let policy = directional_policy(NetworkAction::Allow, vec![], vec![]);
    let rules = appended_ipv4_chain_rules("ga-dns-allow", &policy, true);

    assert!(
        !opens_dns_unconditionally(&rules),
        "input=egress.default=allow; expected no unscoped port 53 accept; output={rules:?}"
    );
}

// An explicit `egress.allow` rule is what the schema offers in place of the
// automatic exemption.
#[test]
fn a_directional_policy_reaches_a_resolver_it_allows() {
    let policy = directional_policy(
        NetworkAction::Deny,
        vec![rule(
            vec![peer("8.8.8.8/32", &[])],
            vec![port(NetworkProtocol::Udp, Some(53), None)],
        )],
        vec![],
    );
    let rules = appended_ipv4_chain_rules("ga-dns-allowed", &policy, true);

    assert!(
        rules.iter().any(|emitted| {
            argument_after(emitted, "-d") == Some("8.8.8.8/32")
                && argument_after(emitted, "--dport") == Some("53")
                && argument_after(emitted, "-j") == Some("ACCEPT")
        }),
        "input=egress.allow=[8.8.8.8/32 udp/53]; expected a scoped accept; output={rules:?}"
    );
}

// Under iptables' first-match semantics, an unscoped accept ahead of an
// explicit deny would win, silently defeating a deny naming the same
// resolver.
#[test]
fn a_directional_deny_naming_a_resolver_is_not_preceded_by_a_dns_accept() {
    let policy = directional_policy(
        NetworkAction::Allow,
        vec![],
        vec![rule(
            vec![peer("8.8.8.8/32", &[])],
            vec![port(NetworkProtocol::Udp, Some(53), None)],
        )],
    );
    let rules = appended_ipv4_chain_rules("ga-dns-denied", &policy, true);

    assert!(
        !opens_dns_unconditionally(&rules),
        "input=egress.deny=[8.8.8.8/32 udp/53]; expected no unscoped port 53 accept ahead of it; output={rules:?}"
    );
    assert!(
        rules.iter().any(|emitted| {
            argument_after(emitted, "-d") == Some("8.8.8.8/32")
                && argument_after(emitted, "-j") == Some("DROP")
        }),
        "input=egress.deny=[8.8.8.8/32 udp/53]; expected the deny rule; output={rules:?}"
    );
}

// Negative control for the four tests above: without a manager that still
// emits the legacy exemption, those tests would pass vacuously against one
// that had stopped emitting base rules at all.  Schema 0.7 carries no field
// naming a legitimate resolver, leaving the exemption a documented limitation
// rather than a closed gap.
#[test]
fn a_legacy_policy_still_opens_dns() {
    let policy = ContainerPolicy {
        network_enforcement_mode: NetworkEnforcementMode::Firewall,
        ..Default::default()
    };
    let rules = appended_ipv4_chain_rules("legacy-dns", &policy, false);

    assert!(
        opens_dns_unconditionally(&rules),
        "input=legacy defaultPolicy=block; expected the documented port 53 accept; output={rules:?}"
    );
}

#[test]
fn a_parsed_legacy_request_keeps_the_dns_exemption() {
    let policy = policy_from_json(
        r#"{"version": "0.7.0-alpha",
            "process": {"commandLine": "echo hi"},
            "network": {"defaultPolicy": "block", "enforcementMode": "firewall"}}"#,
    );
    let rules = appended_ipv4_chain_rules("parsed-legacy", &policy, false);

    assert!(
        opens_dns_unconditionally(&rules),
        "input=0.7 defaultPolicy=block; expected the legacy port 53 accept; output={rules:?}"
    );
}

#[test]
fn a_parsed_directional_request_drops_the_dns_exemption() {
    let policy = policy_from_json(
        r#"{"version": "0.8.0-alpha",
            "process": {"commandLine": "echo hi"},
            "network": {"egress": {"default": "deny"}}}"#,
    );
    let rules = appended_ipv4_chain_rules("parsed-directional", &policy, true);

    assert!(
        !opens_dns_unconditionally(&rules),
        "input=0.8 egress.default=deny; expected no port 53 accept; output={rules:?}"
    );
}

// An omitted network section on 0.8 is a directional deny default, not a
// legacy request.
#[test]
fn a_parsed_v08_request_without_a_network_section_drops_the_dns_exemption() {
    let policy = policy_from_json(
        r#"{"version": "0.8.0-alpha",
            "process": {"commandLine": "echo hi"}}"#,
    );
    let rules = appended_ipv4_chain_rules("parsed-v08-no-network", &policy, true);

    assert!(
        !opens_dns_unconditionally(&rules),
        "input=0.8 with no network section; expected no port 53 accept; output={rules:?}"
    );
}
