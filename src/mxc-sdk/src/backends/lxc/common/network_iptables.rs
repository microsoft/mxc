// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::net::IpAddr;
use std::process::Command;

use crate::mxc_common::hashing::sha256;
use crate::mxc_common::logger::Logger;
use crate::mxc_common::models::{
    ContainerPolicy, NetworkAction, NetworkCidr, NetworkEgressPolicy, NetworkPeer, NetworkPort,
    NetworkProtocol, NetworkRule,
};
use crate::mxc_common::network_blocks::{self, IpFamily, MAX_EGRESS_ENTRIES};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetworkPlan {
    Isolated,

    Filtered,
}

impl NetworkPlan {
    pub(crate) fn omits_interface(self) -> bool {
        matches!(self, Self::Isolated)
    }

    pub(crate) fn installs_firewall(self) -> bool {
        matches!(self, Self::Filtered)
    }
}

pub(crate) fn plan_network(policy: &ContainerPolicy) -> NetworkPlan {
    let egress_permits_nothing = match policy.network_egress.as_ref() {
        Some(egress) => egress.default == NetworkAction::Deny && egress.allow.is_empty(),
        None => true,
    };

    let ingress_permits_nothing = match policy.network_ingress.as_ref() {
        Some(ingress) => {
            ingress.default == NetworkAction::Deny && ingress.host_loopback == NetworkAction::Deny
        }
        None => true,
    };

    if egress_permits_nothing && ingress_permits_nothing {
        NetworkPlan::Isolated
    } else {
        NetworkPlan::Filtered
    }
}

pub(crate) fn needs_network(policy: &ContainerPolicy) -> bool {
    !plan_network(policy).omits_interface()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleAction {
    Allow,
    Deny,
}

// iptables applies first-match-wins; entry order is precedence.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EgressEntry {
    destination: NetworkCidr,
    action: RuleAction,
    matching: RuleMatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleMatch {
    AnyTraffic,

    // iptables uses `icmp`; ip6tables uses `icmpv6`.
    Icmp,

    Transport {
        protocol: TransportProtocol,
        ports: Option<PortRange>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportProtocol {
    Tcp,
    Udp,
}

impl TransportProtocol {
    fn as_arg(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PortRange {
    start: u16,
    end: u16,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct FirewallRuleArgs {
    ipv4: Vec<Vec<String>>,
    ipv6: Vec<Vec<String>>,
}

impl FirewallRuleArgs {
    fn extend(&mut self, other: FirewallRuleArgs) {
        self.ipv4.extend(other.ipv4);
        self.ipv6.extend(other.ipv6);
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CreatedResources {
    v4: FamilyResources,
    v6: FamilyResources,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FamilyResources {
    chain: bool,
    hook: bool,
}

impl FamilyResources {
    fn is_empty(&self) -> bool {
        !self.chain && !self.hook
    }
}

// A flushed user chain returns to its caller instead of reaching its closing DROP,
// and iptables refuses to delete a referenced chain.
fn teardown_chain(
    created_chain: bool,
    hooks_remain: bool,
    logger: &mut Logger,
    mut flush: impl FnMut(&mut Logger),
    mut delete: impl FnMut(&mut Logger) -> bool,
) -> bool {
    if !created_chain {
        return false;
    }
    if hooks_remain {
        return true;
    }
    flush(logger);
    !delete(logger)
}

impl CreatedResources {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn for_test(v4_chain: bool, v6_chain: bool, v4_hook: bool, v6_hook: bool) -> Self {
        Self {
            v4: FamilyResources {
                chain: v4_chain,
                hook: v4_hook,
            },
            v6: FamilyResources {
                chain: v6_chain,
                hook: v6_hook,
            },
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test_all() -> Self {
        let all = FamilyResources {
            chain: true,
            hook: true,
        };

        Self { v4: all, v6: all }
    }
}

// Distinguishes a disabled IPv6 kernel from a broken `ip6tables` on an IPv6-capable host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ip6tablesStatus {
    Available,

    // The kernel has no active IPv6 traffic to filter.
    KernelIpv6Disabled,

    UnusableButIpv6Active,
}

// `Unknown` stays separate from `Inactive` because an unreadable
// `/proc/net/if_inet6` is not evidence that IPv6 is off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostIpv6State {
    Active,

    Inactive,

    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressHookPoint {
    ContainerNetns(u32),

    Unhooked,
}

pub struct NetworkIptablesManager {
    chain_name: String,
    rules_applied: bool,
    preserve_policy: bool,
    hook_point: EgressHookPoint,
    created: CreatedResources,
}

// iptables rejects chain names of 29 characters or more.
pub const CHAIN_NAME_MAX_LEN: usize = 28;

// SHA-256 bytes folded into the chain-name suffix.  Ten bytes is 80 bits,
// exactly 16 base32 characters with no padding.
const CHAIN_HASH_BYTES: usize = 10;

const CHAIN_SLUG_LEN: usize = 7;

// The inbound prefix is one byte longer than the egress prefix.  The slug is
// shortened by one to stay within the iptables chain-name ceiling.
const INGRESS_CHAIN_SLUG_LEN: usize = 6;

// RFC 4648 base32 alphabet, lowercased.  Base32 packs 5 bits per character
// against hex's 4, keeping the 80-bit hash inside the name budget.
const BASE32_LOWER: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

fn base32_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut accumulator: u16 = 0;
    let mut pending_bits: u8 = 0;

    for &byte in bytes {
        accumulator = (accumulator << 8) | u16::from(byte);
        pending_bits += 8;
        while pending_bits >= 5 {
            pending_bits -= 5;
            let index = ((accumulator >> pending_bits) & 0x1f) as usize;
            out.push(BASE32_LOWER[index] as char);
        }
    }

    if pending_bits > 0 {
        let index = ((accumulator << (5 - pending_bits)) & 0x1f) as usize;
        out.push(BASE32_LOWER[index] as char);
    }

    out
}

pub fn chain_name_for(container_name: &str) -> String {
    chain_name_with_prefix("MXC-", CHAIN_SLUG_LEN, container_name)
}

pub fn ingress_chain_name_for(container_name: &str) -> String {
    chain_name_with_prefix("MXCI-", INGRESS_CHAIN_SLUG_LEN, container_name)
}

fn chain_name_with_prefix(prefix: &str, slug_len: usize, container_name: &str) -> String {
    let digest = sha256(container_name.as_bytes());
    let hash = base32_lower(&digest[..CHAIN_HASH_BYTES]);

    let slug: String = container_name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(slug_len)
        .collect();

    if slug.is_empty() {
        format!("{prefix}{hash}")
    } else {
        format!("{prefix}{slug}-{hash}")
    }
}

impl NetworkIptablesManager {
    pub fn new(container_name: &str, hook_point: EgressHookPoint) -> Self {
        Self {
            chain_name: chain_name_for(container_name),
            rules_applied: false,
            preserve_policy: false,
            hook_point,
            created: CreatedResources::default(),
        }
    }

    pub fn is_hooked(&self) -> bool {
        matches!(self.hook_point, EgressHookPoint::ContainerNetns(_))
    }

    pub fn chain_name(&self) -> &str {
        &self.chain_name
    }

    pub fn rules_applied(&self) -> bool {
        self.rules_applied
    }

    pub fn set_preserve_policy(&mut self, preserve: bool) {
        self.preserve_policy = preserve;
    }

    /// Discard the record of what was installed, so no later removal is
    /// attempted.
    pub fn forget(&mut self) {
        self.created = CreatedResources::default();
        self.rules_applied = false;
    }

    fn rule_action_arg(action: &RuleAction) -> &'static str {
        match action {
            RuleAction::Allow => "ACCEPT",
            RuleAction::Deny => "DROP",
        }
    }

    // The selector is `-o`, the outgoing interface.  iptables refuses `-i`
    // on OUTPUT while accepting it into a user chain where it matches nothing.
    fn build_loopback_accept_rule_args(chain_name: &str) -> Vec<String> {
        ["-A", chain_name, "-o", "lo", "-j", "ACCEPT"]
            .into_iter()
            .map(String::from)
            .collect()
    }

    fn build_base_chain_rule_args(chain_name: &str) -> Vec<Vec<String>> {
        vec![
            Self::build_loopback_accept_rule_args(chain_name),
            [
                "-A",
                chain_name,
                "-m",
                "state",
                "--state",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        ]
    }

    fn default_policy_action(default_policy: NetworkAction) -> &'static str {
        match default_policy {
            NetworkAction::Deny => "DROP",
            NetworkAction::Allow => "ACCEPT",
        }
    }

    fn build_default_policy_rule_arg(chain_name: &str, policy: NetworkAction) -> Vec<String> {
        let default_action = Self::default_policy_action(policy);
        vec!["-A", chain_name, "-j", default_action]
            .into_iter()
            .map(String::from)
            .collect()
    }

    fn build_destination_rule_args(
        chain_name: &str,
        destination: &NetworkCidr,
        action: &RuleAction,
        matching: RuleMatch,
    ) -> FirewallRuleArgs {
        let mut args = FirewallRuleArgs::default();
        if let Some((family, block)) = network_blocks::resolve(destination) {
            let destination = format!("{}/{}", block.address(family), block.prefix());
            let rule =
                Self::build_single_rule_args(chain_name, &destination, action, matching, family);
            match family {
                IpFamily::V4 => args.ipv4.push(rule),
                IpFamily::V6 => args.ipv6.push(rule),
            }
        }
        args
    }

    // iptables expects protocol arguments before port arguments.  ip6tables
    // rejects `-p icmp` rather than treating it as ICMPv6.
    fn build_match_args(matching: RuleMatch, family: IpFamily) -> Vec<String> {
        let (protocol, ports) = match matching {
            RuleMatch::AnyTraffic => return Vec::new(),
            RuleMatch::Icmp => (
                match family {
                    IpFamily::V4 => "icmp",
                    IpFamily::V6 => "icmpv6",
                },
                None,
            ),
            RuleMatch::Transport { protocol, ports } => (protocol.as_arg(), ports),
        };

        let mut args = vec!["-p".to_string(), protocol.to_string()];
        if let Some(range) = ports {
            args.push("--dport".to_string());
            args.push(if range.start == range.end {
                range.start.to_string()
            } else {
                format!("{}:{}", range.start, range.end)
            });
        }
        args
    }

    fn build_single_rule_args(
        chain_name: &str,
        destination: &str,
        action: &RuleAction,
        matching: RuleMatch,
        family: IpFamily,
    ) -> Vec<String> {
        let mut args = vec![
            "-A".to_string(),
            chain_name.to_string(),
            "-d".to_string(),
            destination.to_string(),
        ];
        args.extend(Self::build_match_args(matching, family));
        args.push("-j".to_string());
        args.push(Self::rule_action_arg(action).to_string());
        args
    }

    #[cfg(test)]
    fn build_policy_rule_args(chain_name: &str, policy: &ContainerPolicy) -> FirewallRuleArgs {
        let mut logger =
            crate::mxc_common::logger::Logger::new(crate::mxc_common::logger::Mode::Buffer);
        Self::build_policy_rules_logged(chain_name, policy, &mut logger).expect(
            "test policy should not pair an accepting default with an unresolvable block entry",
        )
    }

    fn effective_default_policy(policy: &ContainerPolicy) -> NetworkAction {
        policy
            .network_egress
            .as_ref()
            .map_or(NetworkAction::Deny, |egress| egress.default)
    }

    /// Lower the egress policy for its refusals alone, discarding the rules.
    pub(crate) fn validate_egress_lowering(policy: &ContainerPolicy) -> Result<(), String> {
        Self::lower_egress(policy).map(|_| ())
    }

    fn lower_egress(policy: &ContainerPolicy) -> Result<Vec<EgressEntry>, String> {
        match policy.network_egress.as_ref() {
            Some(egress) => Self::lower_directional_egress(egress),
            None => Ok(Vec::new()),
        }
    }

    // Deny rules precede allow rules under iptables first-match-wins.
    fn lower_directional_egress(egress: &NetworkEgressPolicy) -> Result<Vec<EgressEntry>, String> {
        let mut entries = Vec::new();
        let mut remaining = MAX_EGRESS_ENTRIES;
        for rule in &egress.deny {
            Self::lower_rule(rule, RuleAction::Deny, &mut entries, &mut remaining)?;
        }
        for rule in &egress.allow {
            Self::lower_rule(rule, RuleAction::Allow, &mut entries, &mut remaining)?;
        }
        Ok(entries)
    }

    fn lower_rule(
        rule: &NetworkRule,
        action: RuleAction,
        entries: &mut Vec<EgressEntry>,
        remaining: &mut usize,
    ) -> Result<(), String> {
        let matches = Self::lower_port_selectors(&rule.ports);
        let wildcard_peers;
        let peers = if rule.to.is_empty() {
            wildcard_peers = Self::every_destination_peers();
            &wildcard_peers[..]
        } else {
            &rule.to[..]
        };

        for peer in peers {
            for destination in Self::peer_destinations(peer)? {
                for matching in &matches {
                    if *remaining == 0 {
                        return Err(format!(
                            "network.egress expands into more than {MAX_EGRESS_ENTRIES} firewall \
                             rules. A rule becomes every destination block it resolves to in \
                             every port it names, so narrow the peers, the exclusions, or the \
                             ports."
                        ));
                    }
                    *remaining -= 1;
                    entries.push(EgressEntry {
                        destination: destination.clone(),
                        action,
                        matching: *matching,
                    });
                }
            }
        }
        Ok(())
    }

    /// The destinations a peer covers once its exclusions are removed.
    ///
    /// An `iptables` rule matches one destination block and cannot carry an
    /// exclusion, so the exclusion is subtracted from the peer instead.
    fn peer_destinations(peer: &NetworkPeer) -> Result<Vec<NetworkCidr>, String> {
        // Passing an out-of-range prefix through unchanged keeps it on the path
        // that reports a destination resolving to no address.
        let Some((family, blocks)) = network_blocks::peer_blocks(peer)? else {
            return Ok(vec![peer.cidr.clone()]);
        };

        Ok(blocks
            .into_iter()
            .map(|block| NetworkCidr {
                address: block.address(family),
                prefix_length: block.prefix(),
            })
            .collect())
    }

    // A v4 chain and a v6 chain are programmed separately.  Neither wildcard
    // covers the other.
    fn every_destination_peers() -> Vec<NetworkPeer> {
        vec![
            NetworkPeer {
                cidr: NetworkCidr {
                    address: IpAddr::from([0u8, 0, 0, 0]),
                    prefix_length: 0,
                },
                except: Vec::new(),
            },
            NetworkPeer {
                cidr: NetworkCidr {
                    address: IpAddr::from([0u16; 8]),
                    prefix_length: 0,
                },
                except: Vec::new(),
            },
        ]
    }

    fn lower_port_selectors(ports: &[NetworkPort]) -> Vec<RuleMatch> {
        if ports.is_empty() {
            return vec![RuleMatch::AnyTraffic];
        }
        ports.iter().flat_map(Self::lower_port_selector).collect()
    }

    // Protocol `any` with a port yields separate TCP and UDP matches because
    // `-p all` accepts no `--dport`.
    fn lower_port_selector(port: &NetworkPort) -> Vec<RuleMatch> {
        let ports = port.port.map(|start| PortRange {
            start,
            end: port.end_port.unwrap_or(start),
        });

        match port.protocol {
            // ICMP carries no ports and accepts no `--dport`.
            NetworkProtocol::Icmp => vec![RuleMatch::Icmp],
            NetworkProtocol::Tcp => vec![RuleMatch::Transport {
                protocol: TransportProtocol::Tcp,
                ports,
            }],
            NetworkProtocol::Udp => vec![RuleMatch::Transport {
                protocol: TransportProtocol::Udp,
                ports,
            }],
            NetworkProtocol::Any => match ports {
                None => vec![RuleMatch::AnyTraffic],
                Some(_) => vec![
                    RuleMatch::Transport {
                        protocol: TransportProtocol::Tcp,
                        ports,
                    },
                    RuleMatch::Transport {
                        protocol: TransportProtocol::Udp,
                        ports,
                    },
                ],
            },
        }
    }

    // Destinations are typed CIDRs; the shared block arithmetic determines
    // their firewall family, including IPv4-mapped IPv6 addresses.
    fn build_policy_rules_logged(
        chain_name: &str,
        policy: &ContainerPolicy,
        logger: &mut Logger,
    ) -> Result<FirewallRuleArgs, String> {
        let default_permits = Self::effective_default_policy(policy) == NetworkAction::Allow;
        let mut args = FirewallRuleArgs::default();
        let mut unresolved_denies: Vec<String> = Vec::new();
        let mut catch_all_allows: Vec<String> = Vec::new();
        let entries = Self::lower_egress(policy)?;
        for entry in &entries {
            let host = network_blocks::cidr_text(&entry.destination);
            let action = entry.action;
            let family = network_blocks::resolve(&entry.destination);
            if family.is_none() {
                if default_permits && matches!(action, RuleAction::Deny) {
                    return Err(format!(
                        "network.egress deny destination '{}' resolved to no address, so no rule can be \
                         programmed to deny it, and the default network policy accepts \
                         what no rule matches; refusing to apply a policy that would \
                         leave it reachable",
                        host
                    ));
                }
                if matches!(action, RuleAction::Deny) {
                    unresolved_denies.push(host.clone());
                }
                logger.log_line(&format!(
                    "Warning: could not resolve destination '{}'",
                    host
                ));
            } else if matches!(action, RuleAction::Allow)
                && matches!(entry.matching, RuleMatch::AnyTraffic)
                && entry.destination.prefix_length == 0
            {
                catch_all_allows.push(host.clone());
            }
            let rule_args = Self::build_destination_rule_args(
                chain_name,
                &entry.destination,
                &action,
                entry.matching,
            );
            for rule in &rule_args.ipv4 {
                logger.log_line(&format!("Programmed iptables rule: {}", rule.join(" ")));
            }
            for rule in &rule_args.ipv6 {
                logger.log_line(&format!("Programmed ip6tables rule: {}", rule.join(" ")));
            }
            args.extend(rule_args);
        }
        if !unresolved_denies.is_empty() && !catch_all_allows.is_empty() {
            return Err(format!(
                "network.egress deny destination(s) {} resolved to no address, so no rule can be programmed \
                 to deny them, while allow destination(s) {} accept every address and are \
                 evaluated before the chain's closing DROP; whatever the blocked host \
                 resolves to for the container is therefore accepted, so deny precedence \
                 cannot hold. Fix or remove the unresolvable blocked host, or narrow the \
                 catch-all allow",
                unresolved_denies
                    .iter()
                    .map(|h| format!("'{}'", h))
                    .collect::<Vec<_>>()
                    .join(", "),
                catch_all_allows
                    .iter()
                    .map(|h| format!("'{}'", h))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        Ok(args)
    }

    fn run_iptables(&self, args: &[&str], logger: &mut Logger) -> Result<bool, String> {
        self.run_firewall_command("iptables", args, logger)
    }

    fn run_ip6tables(&self, args: &[&str], logger: &mut Logger) -> Result<bool, String> {
        self.run_firewall_command("ip6tables", args, logger)
    }

    fn command_argv(&self, binary: &str, args: &[&str]) -> Vec<String> {
        let mut argv = match self.hook_point {
            EgressHookPoint::ContainerNetns(pid) => vec![
                "nsenter".to_string(),
                "-t".to_string(),
                pid.to_string(),
                "-n".to_string(),
                binary.to_string(),
            ],
            EgressHookPoint::Unhooked => vec![binary.to_string()],
        };
        argv.extend(args.iter().map(|a| (*a).to_string()));
        argv
    }

    pub(crate) fn classify_ip6tables_status(
        probe_succeeded: bool,
        host_ipv6_active: bool,
    ) -> Ip6tablesStatus {
        match (probe_succeeded, host_ipv6_active) {
            (true, _) => Ip6tablesStatus::Available,
            (false, true) => Ip6tablesStatus::UnusableButIpv6Active,
            (false, false) => Ip6tablesStatus::KernelIpv6Disabled,
        }
    }

    fn host_ipv6_state() -> HostIpv6State {
        Self::classify_host_ipv6_state(
            std::fs::read_to_string("/proc/net/if_inet6"),
            std::path::Path::new("/proc/net").is_dir(),
        )
    }

    // The kernel populates `/proc/net/if_inet6` only when the IPv6 module is
    // loaded, one interface address per line with the device name in the
    // final field.  Loopback is not egress-capable.
    //
    // A `NotFound` error means `Inactive` only when `/proc/net` itself exists;
    // an IPv6-disabled kernel and an unmounted `/proc` both report `NotFound`.
    pub(crate) fn classify_host_ipv6_state(
        read_result: std::io::Result<String>,
        proc_net_present: bool,
    ) -> HostIpv6State {
        match read_result {
            Ok(contents) => {
                let has_egress_capable_interface = contents.lines().any(|line| {
                    let line = line.trim();
                    if line.is_empty() {
                        return false;
                    }
                    match line.split_whitespace().last() {
                        Some(device) => device != "lo",
                        None => false,
                    }
                });
                if has_egress_capable_interface {
                    HostIpv6State::Active
                } else {
                    HostIpv6State::Inactive
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if proc_net_present {
                    HostIpv6State::Inactive
                } else {
                    HostIpv6State::Unknown
                }
            }
            Err(_) => HostIpv6State::Unknown,
        }
    }

    // The IPv6 answer must describe the namespace the rules will enter.
    // The host's IPv6 state says nothing about a container namespace.
    fn namespace_ipv6_state(&self) -> HostIpv6State {
        match self.hook_point {
            EgressHookPoint::ContainerNetns(pid) => {
                let if_inet6 = format!("/proc/{}/net/if_inet6", pid);
                let proc_net = format!("/proc/{}/net", pid);
                Self::classify_container_ipv6_state(
                    std::fs::read_to_string(&if_inet6),
                    std::path::Path::new(&proc_net).is_dir(),
                )
            }
            EgressHookPoint::Unhooked => Self::host_ipv6_state(),
        }
    }

    // Treat file existence as active IPv6 in a container namespace.
    // A container address may still be arriving, and the same address-less
    // file can otherwise look like a disabled stack.
    pub(crate) fn classify_container_ipv6_state(
        read_result: std::io::Result<String>,
        proc_net_present: bool,
    ) -> HostIpv6State {
        match read_result {
            Ok(_) => HostIpv6State::Active,

            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if proc_net_present {
                    HostIpv6State::Inactive
                } else {
                    HostIpv6State::Unknown
                }
            }
            Err(_) => HostIpv6State::Unknown,
        }
    }

    fn ipv6_egress_possible(&self, logger: &mut Logger) -> bool {
        let state = self.namespace_ipv6_state();
        if state == HostIpv6State::Unknown {
            logger.log_line(
                "Could not read if_inet6 to determine the IPv6 state of the namespace \
                 being filtered; treating IPv6 as potentially active and refusing to \
                 fail open.",
            );
        }
        Self::ipv6_state_treated_as_active(state)
    }

    // `Unknown` counts as active.  An unreadable IPv6 state must not be
    // downgraded to off under a drop-required stance.
    pub(crate) fn ipv6_state_treated_as_active(state: HostIpv6State) -> bool {
        match state {
            HostIpv6State::Active | HostIpv6State::Unknown => true,
            HostIpv6State::Inactive => false,
        }
    }

    fn ip6tables_status(&self, logger: &mut Logger) -> Ip6tablesStatus {
        let probe_succeeded = self.ip6tables_probe_succeeded(logger);

        let status =
            Self::classify_ip6tables_status(probe_succeeded, self.ipv6_egress_possible(logger));
        match status {
            Ip6tablesStatus::Available => {}
            Ip6tablesStatus::KernelIpv6Disabled => {
                logger.log_line(
                    "Kernel IPv6 is not active; skipping IPv6 firewall rules \
                     (no IPv6 egress to filter).",
                );
            }
            Ip6tablesStatus::UnusableButIpv6Active => {
                logger.log_line(
                    "ip6tables is unusable but the host has active IPv6; \
                     failing firewall setup to avoid leaving IPv6 egress unfiltered.",
                );
            }
        }
        status
    }

    fn ip6tables_probe_succeeded(&self, logger: &mut Logger) -> bool {
        #[cfg(test)]
        if let Some(succeeded) = test_firewall::intercept_ip6tables_probe() {
            return succeeded;
        }

        let argv = self.command_argv("ip6tables", &["-S"]);
        match Command::new(&argv[0]).args(&argv[1..]).output() {
            Ok(output) if output.status.success() => true,
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                logger.log_line(&format!("ip6tables probe failed ({})", stderr.trim()));
                false
            }
            Err(e) => {
                logger.log_line(&format!("ip6tables not found ({})", e));
                false
            }
        }
    }

    fn run_firewall_command(
        &self,
        command: &str,
        args: &[&str],
        logger: &mut Logger,
    ) -> Result<bool, String> {
        #[cfg(test)]
        if let Some(outcome) = test_firewall::intercept(command, args) {
            return match outcome {
                Ok(()) => Ok(true),
                Err(stderr) => Err(Self::log_command_failure(command, args, &stderr, logger)),
            };
        }

        let argv = self.command_argv(command, args);
        let output = Command::new(&argv[0])
            .args(&argv[1..])
            .output()
            .map_err(|e| format!("Failed to run {}: {}", command, e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Self::log_command_failure(command, args, &stderr, logger));
        }

        Ok(true)
    }

    fn log_command_failure(
        command: &str,
        args: &[&str],
        stderr: &str,
        logger: &mut Logger,
    ) -> String {
        let msg = format!("{} {} failed: {}", command, args.join(" "), stderr);
        logger.log_line(&msg);
        msg
    }

    fn run_iptables_rule_args(
        &self,
        args: &[Vec<String>],
        logger: &mut Logger,
    ) -> Result<(), String> {
        for rule in args {
            let rule_args: Vec<&str> = rule.iter().map(String::as_str).collect();
            self.run_iptables(&rule_args, logger)?;
        }
        Ok(())
    }

    fn run_ip6tables_rule_args(
        &self,
        args: &[Vec<String>],
        logger: &mut Logger,
    ) -> Result<(), String> {
        for rule in args {
            let rule_args: Vec<&str> = rule.iter().map(String::as_str).collect();
            self.run_ip6tables(&rule_args, logger)?;
        }
        Ok(())
    }

    pub fn apply_firewall_rules(
        &mut self,
        policy: &ContainerPolicy,
        logger: &mut Logger,
    ) -> Result<bool, String> {
        let plan = plan_network(policy);
        if !plan.installs_firewall() {
            logger.log_line("Network policy requests no firewall; skipping iptables.");
            return Ok(true);
        }

        if self.rules_applied {
            return Err(format!(
                "Firewall rules are already applied for chain {}; remove them before applying \
                 again. Re-applying would replace the record of what this process created and \
                 strand whatever the earlier attempt left behind.",
                self.chain_name
            ));
        }

        let outcome = self.apply_firewall_rules_inner(policy, logger);
        self.record_apply_outcome(outcome, logger)
    }

    fn record_apply_outcome(
        &mut self,
        outcome: Result<CreatedResources, (String, CreatedResources)>,
        logger: &mut Logger,
    ) -> Result<bool, String> {
        match outcome {
            Ok(created) => {
                self.created = created;
                self.rules_applied = true;
                Ok(true)
            }
            Err((e, residual)) => {
                if self.retain_residual_ownership(residual) {
                    logger.log_line(&format!(
                        "Firewall setup failed: {}. Rollback left iptables state behind; \
                         retained ownership so teardown retries it.",
                        e
                    ));
                } else {
                    logger.log_line(&format!(
                        "Firewall setup failed: {}. Partial iptables state rolled back.",
                        e
                    ));
                }
                Err(e)
            }
        }
    }

    fn retain_residual_ownership(&mut self, residual: CreatedResources) -> bool {
        self.created = residual;
        self.rules_applied = !residual.is_empty();
        self.rules_applied
    }

    fn apply_firewall_rules_inner(
        &self,
        policy: &ContainerPolicy,
        logger: &mut Logger,
    ) -> Result<CreatedResources, (String, CreatedResources)> {
        let mut created = CreatedResources::default();
        match self.install_firewall_rules(policy, logger, &mut created) {
            Ok(()) => Ok(created),
            Err(e) => {
                let residual = self.teardown_created(&self.chain_name, &created, logger);
                Err((e, residual))
            }
        }
    }

    fn install_firewall_rules(
        &self,
        policy: &ContainerPolicy,
        logger: &mut Logger,
        created: &mut CreatedResources,
    ) -> Result<(), String> {
        logger.log_line(&format!(
            "Creating iptables/ip6tables chain: {}",
            self.chain_name
        ));

        let ipv6_enabled = match self.ip6tables_status(logger) {
            Ip6tablesStatus::Available => true,
            Ip6tablesStatus::KernelIpv6Disabled => false,
            Ip6tablesStatus::UnusableButIpv6Active => {
                return Err(
                    "ip6tables is unusable but the namespace being filtered has active \
                     IPv6; refusing to apply an IPv4-only policy that would leave IPv6 \
                     egress unfiltered"
                        .to_string(),
                );
            }
        };

        self.run_iptables(&["-N", &self.chain_name], logger)?;
        created.v4.chain = true;
        Self::publish_created(created);
        if ipv6_enabled {
            self.run_ip6tables(&["-N", &self.chain_name], logger)?;
            created.v6.chain = true;
            Self::publish_created(created);
        }

        let base_rules = Self::build_base_chain_rule_args(&self.chain_name);
        self.run_iptables_rule_args(&base_rules, logger)?;
        if ipv6_enabled {
            self.run_ip6tables_rule_args(&base_rules, logger)?;
        }

        let policy_rules = Self::build_policy_rules_logged(&self.chain_name, policy, logger)?;
        self.run_iptables_rule_args(&policy_rules.ipv4, logger)?;
        if ipv6_enabled {
            self.run_ip6tables_rule_args(&policy_rules.ipv6, logger)?;
        } else if !policy_rules.ipv6.is_empty() {
            logger.log_line(&format!(
                "Warning: {} IPv6 firewall rule(s) not applied because ip6tables \
                 is unavailable; IPv6 egress is unfiltered on this host.",
                policy_rules.ipv6.len()
            ));
        }

        let default_rule = Self::build_default_policy_rule_arg(
            &self.chain_name,
            Self::effective_default_policy(policy),
        );
        let default_args: Vec<&str> = default_rule.iter().map(String::as_str).collect();
        let default_action = default_args.last().copied().unwrap_or("ACCEPT");
        logger.log_line(&format!("Default network policy: {}", default_action));
        self.run_iptables(&default_args, logger)?;
        if ipv6_enabled {
            self.run_ip6tables(&default_args, logger)?;
        }

        // OUTPUT sees each packet the workload originates inside the container
        // namespace, regardless of how its veth is attached.
        if !self.is_hooked() {
            logger.log_line(
                "Warning: no container network namespace to enforce in. \
                 Skipping the OUTPUT hook; this policy is not enforced.",
            );
            return Ok(());
        }

        let hook_args = ["-I", "OUTPUT", "1", "-j", self.chain_name.as_str()];
        let unhook_args = ["-D", "OUTPUT", "-j", self.chain_name.as_str()];

        created.v4.hook = true;
        Self::publish_created(created);
        if let Err(e) = self.run_iptables(&hook_args, logger) {
            // iptables can apply the rule and still report failure.
            // Remove the hook before releasing the claim.
            let _ = self.run_iptables(&unhook_args, logger);
            created.v4.hook = false;
            Self::publish_created(created);
            return Err(e);
        }
        logger.log_line(&format!(
            "OUTPUT hook installed in the container namespace for chain {} (iptables).",
            self.chain_name
        ));

        if ipv6_enabled {
            created.v6.hook = true;
            Self::publish_created(created);
            if let Err(e) = self.run_ip6tables(&hook_args, logger) {
                let _ = self.run_ip6tables(&unhook_args, logger);
                created.v6.hook = false;
                Self::publish_created(created);
                return Err(e);
            }
            logger.log_line(&format!(
                "OUTPUT hook installed in the container namespace for chain {} (ip6tables).",
                self.chain_name
            ));
        }

        Ok(())
    }

    // Publish each created resource before the next command runs.
    // A signal arriving mid-apply would otherwise find an empty set and leak
    // the partially created chain.
    fn publish_created(created: &CreatedResources) {
        crate::lxc_common::signal_cleanup::set_active_created(*created);
    }

    // Remove only the hooks and chains in the ownership record.
    // The chain name is derived solely from the container name, and every
    // run of that name shares it.
    fn teardown_created(
        &self,
        chain_name: &str,
        created: &CreatedResources,
        logger: &mut Logger,
    ) -> CreatedResources {
        let mut residual = *created;

        // iptables deletes by full rule specification.  The insertion index
        // is not stable once anything else touches OUTPUT.
        let hook_args = ["-D", "OUTPUT", "-j", chain_name];

        if created.v4.hook && self.run_iptables(&hook_args, logger).is_ok() {
            residual.v4.hook = false;
        }
        if created.v6.hook && self.run_ip6tables(&hook_args, logger).is_ok() {
            residual.v6.hook = false;
        }

        // iptables refuses to delete a chain while a surviving hook still
        // references it.  The two tables are gated independently.
        residual.v4.chain = teardown_chain(
            created.v4.chain,
            residual.v4.hook,
            logger,
            |logger| {
                let _ = self.run_iptables(&["-F", chain_name], logger);
            },
            |logger| self.run_iptables(&["-X", chain_name], logger).is_ok(),
        );
        residual.v6.chain = teardown_chain(
            created.v6.chain,
            residual.v6.hook,
            logger,
            |logger| {
                let _ = self.run_ip6tables(&["-F", chain_name], logger);
            },
            |logger| self.run_ip6tables(&["-X", chain_name], logger).is_ok(),
        );

        Self::publish_created(&residual);
        residual
    }

    pub fn remove_firewall_rules(&mut self, logger: &mut Logger) -> Result<(), String> {
        if !self.rules_applied {
            return Ok(());
        }

        logger.log_line(&format!(
            "Removing iptables/ip6tables chain: {}",
            self.chain_name
        ));

        let residual = self.teardown_created(&self.chain_name, &self.created, logger);

        self.retain_residual_ownership(residual);
        Ok(())
    }

    // Clean up the iptables state recorded by another thread.
    // The ownership record keeps signal-time cleanup from flushing a later
    // run's chain under the same container name.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn force_cleanup(
        container_name: &str,
        hook_point: EgressHookPoint,
        created: CreatedResources,
        logger: &mut Logger,
    ) {
        if created.is_empty() {
            return;
        }
        let mut mgr = Self::new(container_name, hook_point);

        mgr.rules_applied = true;
        mgr.created = created;
        let _ = mgr.remove_firewall_rules(logger);
    }
}

impl Drop for NetworkIptablesManager {
    fn drop(&mut self) {
        if self.rules_applied && !self.preserve_policy {
            let mut logger =
                crate::mxc_common::logger::Logger::new(crate::mxc_common::logger::Mode::Buffer);
            let _ = self.remove_firewall_rules(&mut logger);
        }
    }
}

#[cfg(test)]
#[path = "network_iptables_ga_egress_spec.rs"]
mod ga_egress_spec;

#[cfg(test)]
pub(crate) mod test_firewall {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    struct State {
        issued: Vec<Vec<String>>,
        scripted: VecDeque<Result<(), String>>,
        fallback: Result<(), String>,
        fail_matching: Option<(String, String)>,
    }

    thread_local! {
        static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
    }

    pub(crate) struct FakeFirewall;

    pub(crate) fn install() -> FakeFirewall {
        STATE.with(|slot| {
            *slot.borrow_mut() = Some(State {
                issued: Vec::new(),
                scripted: VecDeque::new(),
                fallback: Ok(()),
                fail_matching: None,
            });
        });
        FakeFirewall
    }

    impl Drop for FakeFirewall {
        fn drop(&mut self) {
            STATE.with(|slot| *slot.borrow_mut() = None);
        }
    }

    impl FakeFirewall {
        pub(super) fn fail_every_command(&self, stderr: &str) -> &Self {
            Self::with_state(|state| state.fallback = Err(stderr.to_string()));
            self
        }

        pub(crate) fn fail_commands_matching(&self, needle: &str, stderr: &str) -> &Self {
            Self::with_state(|state| {
                state.fail_matching = Some((needle.to_string(), stderr.to_string()));
            });
            self
        }

        pub(crate) fn script_results(&self, results: Vec<Result<(), String>>) -> &Self {
            Self::with_state(|state| state.scripted = results.into());
            self
        }

        pub(crate) fn issued(&self) -> Vec<Vec<String>> {
            Self::with_state(|state| state.issued.clone())
        }

        pub(super) fn forget_issued(&self) -> &Self {
            Self::with_state(|state| state.issued.clear());
            self
        }

        fn with_state<T>(f: impl FnOnce(&mut State) -> T) -> T {
            STATE.with(|slot| {
                let mut slot = slot.borrow_mut();
                let state = slot
                    .as_mut()
                    .expect("the FakeFirewall guard must still be in scope");
                f(state)
            })
        }
    }

    pub(super) fn intercept(command: &str, args: &[&str]) -> Option<Result<(), String>> {
        STATE.with(|slot| {
            let mut slot = slot.borrow_mut();
            let state = slot.as_mut()?;
            let mut argv = Vec::with_capacity(args.len() + 1);
            argv.push(command.to_string());
            argv.extend(args.iter().map(|arg| arg.to_string()));
            state.issued.push(argv.clone());
            if let Some((needle, stderr)) = &state.fail_matching {
                if argv.iter().any(|arg| arg.contains(needle.as_str())) {
                    return Some(Err(stderr.clone()));
                }
            }
            Some(
                state
                    .scripted
                    .pop_front()
                    .unwrap_or_else(|| state.fallback.clone()),
            )
        })
    }

    pub(super) fn intercept_ip6tables_probe() -> Option<bool> {
        STATE.with(|slot| {
            let mut slot = slot.borrow_mut();
            let state = slot.as_mut()?;
            state
                .issued
                .push(vec!["ip6tables".to_string(), "-S".to_string()]);
            Some(true)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_common::logger::{Logger, Mode};
    use crate::mxc_common::models::{ContainerPolicy, NetworkEgressPolicy};
    use std::io::{Error, ErrorKind};

    fn filtered_policy() -> ContainerPolicy {
        ContainerPolicy {
            network_egress: Some(NetworkEgressPolicy {
                default: NetworkAction::Allow,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn an_unhooked_caller_is_not_refused_in_firewall_mode() {
        let _fake = super::test_firewall::install();
        let mut manager = NetworkIptablesManager::new("bwrap-nonetns", EgressHookPoint::Unhooked);
        let policy = filtered_policy();
        let mut logger = Logger::new(Mode::Buffer);

        let result = manager.apply_firewall_rules(&policy, &mut logger);

        assert!(
            result.is_ok(),
            "a caller with no namespace to enforce in must not be failed closed, got {:?}",
            result
        );
    }

    #[test]
    fn a_forgotten_manager_issues_no_removal_when_it_goes_away() {
        let fake = super::test_firewall::install();
        let mut manager =
            NetworkIptablesManager::new("lxc-forget", EgressHookPoint::ContainerNetns(4242));
        let policy = filtered_policy();
        let mut logger = Logger::new(Mode::Buffer);

        manager
            .apply_firewall_rules(&policy, &mut logger)
            .expect("the fake firewall accepts every command");
        assert!(
            manager.rules_applied(),
            "precondition: the manager owns installed state"
        );

        manager.forget();

        assert!(
            !manager.rules_applied(),
            "a forgotten manager must own no installed state"
        );

        fake.forget_issued();
        drop(manager);

        assert!(
            fake.issued().is_empty(),
            "the netns holding the chain is gone, so its dead pid must not be nsentered; got {:?}",
            fake.issued()
        );
    }

    #[test]
    fn a_namespaced_manager_hooks_its_chain_into_output() {
        let fake = super::test_firewall::install();
        let mut manager =
            NetworkIptablesManager::new("lxc-hooked", EgressHookPoint::ContainerNetns(4242));
        let policy = filtered_policy();
        let mut logger = Logger::new(Mode::Buffer);

        manager
            .apply_firewall_rules(&policy, &mut logger)
            .expect("apply must succeed");

        let chain = manager.chain_name().to_string();
        let issued = fake.issued();
        let hooks: Vec<&Vec<String>> = issued
            .iter()
            .filter(|argv| argv.get(1).map(String::as_str) == Some("-I"))
            .filter(|argv| argv.get(2).map(String::as_str) == Some("OUTPUT"))
            .collect();

        assert!(
            !hooks.is_empty(),
            "a manager with a namespace must hook its chain into OUTPUT; issued: {issued:?}"
        );
        for argv in hooks {
            assert_eq!(
                argv.last().map(String::as_str),
                Some(chain.as_str()),
                "the OUTPUT hook must jump to this manager's own chain, got {argv:?}"
            );
        }
    }

    #[test]
    fn an_unhooked_manager_installs_no_output_hook() {
        let fake = super::test_firewall::install();
        let mut manager = NetworkIptablesManager::new("bwrap-nohook", EgressHookPoint::Unhooked);
        let policy = filtered_policy();
        let mut logger = Logger::new(Mode::Buffer);

        manager
            .apply_firewall_rules(&policy, &mut logger)
            .expect("apply must succeed");

        let issued = fake.issued();
        assert!(
            !issued
                .iter()
                .any(|argv| argv.iter().any(|arg| arg == "OUTPUT")),
            "a manager with nowhere to enforce must touch no OUTPUT chain; issued: {issued:?}"
        );
    }

    #[test]
    fn a_namespaced_manager_runs_every_command_inside_the_namespace() {
        let manager = NetworkIptablesManager::new("lxc-ns", EgressHookPoint::ContainerNetns(4242));

        assert_eq!(
            manager.command_argv("iptables", &["-N", "chain"]),
            vec!["nsenter", "-t", "4242", "-n", "iptables", "-N", "chain"],
        );
    }

    #[test]
    fn an_unhooked_manager_enters_no_namespace() {
        let manager = NetworkIptablesManager::new("bwrap-ns", EgressHookPoint::Unhooked);

        assert_eq!(
            manager.command_argv("iptables", &["-N", "chain"]),
            vec!["iptables", "-N", "chain"],
        );
    }

    #[test]
    fn the_ipv6_probe_asks_the_namespace_the_rules_land_in() {
        let manager = NetworkIptablesManager::new("lxc-v6", EgressHookPoint::ContainerNetns(909));

        assert_eq!(
            manager.command_argv("ip6tables", &["-S"]),
            vec!["nsenter", "-t", "909", "-n", "ip6tables", "-S"],
        );
    }

    #[test]
    fn an_empty_ownership_record_is_recognized_as_nothing_to_tear_down() {
        assert!(
            CreatedResources::default().is_empty(),
            "a manager that created nothing must report an empty ownership record"
        );
        for created in [
            CreatedResources::for_test(true, false, false, false),
            CreatedResources::for_test(false, true, false, false),
            CreatedResources::for_test(false, false, true, false),
            CreatedResources::for_test(false, false, false, true),
        ] {
            assert!(
                !created.is_empty(),
                "{created:?} names a real resource and must not be treated as empty"
            );
        }
    }

    #[test]
    fn a_signal_arriving_before_anything_was_created_removes_nothing() {
        let fake = test_firewall::install();
        let mut quiet = Logger::new(Mode::Buffer);
        NetworkIptablesManager::force_cleanup(
            "racer-that-lost",
            EgressHookPoint::ContainerNetns(4242),
            CreatedResources::default(),
            &mut quiet,
        );
        assert_eq!(
            quiet.get_buffer(),
            "",
            "a process holding no ownership must not begin a teardown at all"
        );
        assert!(
            fake.issued().is_empty(),
            "...and must not issue a single command, got: {:?}",
            fake.issued()
        );

        let mut noisy = Logger::new(Mode::Buffer);
        NetworkIptablesManager::force_cleanup(
            "racer-that-won",
            EgressHookPoint::ContainerNetns(4242),
            CreatedResources::for_test(true, false, false, false),
            &mut noisy,
        );
        assert_eq!(
            fake.issued(),
            flush_and_delete("iptables", "racer-that-won"),
            "only the published chain may be flushed and deleted, and only it"
        );
    }

    #[test]
    fn a_signal_removes_every_resource_the_run_published() {
        let fake = test_firewall::install();
        let mut logger = Logger::new(Mode::Buffer);

        NetworkIptablesManager::force_cleanup(
            "all-resources",
            EgressHookPoint::ContainerNetns(4242),
            CreatedResources::for_test_all(),
            &mut logger,
        );

        let chain = chain_name_for("all-resources");
        let issued: Vec<String> = fake.issued().iter().map(|c| c.join(" ")).collect();

        for tool in ["iptables", "ip6tables"] {
            assert!(
                issued.contains(&format!("{tool} -D OUTPUT -j {chain}")),
                "{tool} must remove the hook it published, issued: {issued:?}"
            );
            assert!(
                issued.contains(&format!("{tool} -F {chain}")),
                "{tool} must flush the chain it published, issued: {issued:?}"
            );
            assert!(
                issued.contains(&format!("{tool} -X {chain}")),
                "{tool} must delete the chain it published, issued: {issued:?}"
            );
        }
    }

    #[test]
    fn a_rollback_that_could_not_finish_keeps_ownership_of_what_survived() {
        let fake = test_firewall::install();
        fake.fail_every_command("iptables: chain is not empty");

        let mut manager =
            NetworkIptablesManager::new("survivor", EgressHookPoint::ContainerNetns(4242));
        let retained = manager
            .retain_residual_ownership(CreatedResources::for_test(true, false, false, false));
        assert!(retained, "a non-empty residual must be retained");

        let mut after_partial = Logger::new(Mode::Buffer);
        let _ = manager.remove_firewall_rules(&mut after_partial);
        assert_eq!(
            fake.issued(),
            flush_and_delete("iptables", "survivor"),
            "a chain that survived rollback must still be torn down later"
        );

        fake.forget_issued();
        let mut clean =
            NetworkIptablesManager::new("fully-rolled-back", EgressHookPoint::ContainerNetns(4242));
        let retained_clean = clean.retain_residual_ownership(CreatedResources::default());
        assert!(!retained_clean, "an empty residual must not be retained");

        let mut after_clean = Logger::new(Mode::Buffer);
        let _ = clean.remove_firewall_rules(&mut after_clean);
        assert_eq!(
            after_clean.get_buffer(),
            "",
            "a fully rolled-back apply must not begin a teardown"
        );
        assert!(
            fake.issued().is_empty(),
            "...and must not issue a single command, got: {:?}",
            fake.issued()
        );
    }

    #[test]
    fn a_failed_apply_adopts_the_residual_its_rollback_left_behind() {
        let fake = test_firewall::install();
        fake.fail_every_command("iptables: chain is not empty");

        let mut manager =
            NetworkIptablesManager::new("adopted", EgressHookPoint::ContainerNetns(4242));
        let mut apply_log = Logger::new(Mode::Buffer);
        let outcome = Err((
            "append failed".to_string(),
            CreatedResources::for_test(true, false, false, false),
        ));
        let result = manager.record_apply_outcome(outcome, &mut apply_log);

        assert!(result.is_err(), "a failed apply must still report failure");
        assert!(
            apply_log.get_buffer().contains("retained ownership"),
            "a failed rollback must be reported as retained, not as clean, got: {:?}",
            apply_log.get_buffer()
        );

        let mut teardown_log = Logger::new(Mode::Buffer);
        let _ = manager.remove_firewall_rules(&mut teardown_log);
        assert_eq!(
            fake.issued(),
            flush_and_delete("iptables", "adopted"),
            "what the rollback could not remove must still be torn down later"
        );

        fake.forget_issued();
        let mut clean =
            NetworkIptablesManager::new("clean-failure", EgressHookPoint::ContainerNetns(4242));
        let mut clean_log = Logger::new(Mode::Buffer);
        let clean_result = clean.record_apply_outcome(
            Err(("boom".to_string(), CreatedResources::default())),
            &mut clean_log,
        );

        assert!(clean_result.is_err());
        assert!(
            clean_log.get_buffer().contains("rolled back"),
            "a complete rollback must be reported as clean, got: {:?}",
            clean_log.get_buffer()
        );

        let mut after_clean = Logger::new(Mode::Buffer);
        let _ = clean.remove_firewall_rules(&mut after_clean);
        assert_eq!(
            after_clean.get_buffer(),
            "",
            "a failure that left nothing behind must not begin a teardown"
        );
        assert!(
            fake.issued().is_empty(),
            "...and must not issue a single command, got: {:?}",
            fake.issued()
        );
    }

    #[test]
    fn a_flush_is_withheld_while_the_chain_is_still_hooked() {
        // -F succeeds while OUTPUT still references the chain.  An emptied
        // user chain returns to its caller instead of reaching its own closing DROP.
        let mut logger = Logger::new(Mode::Buffer);
        let mut flushed = false;
        let mut deleted = false;
        let still_owned = teardown_chain(
            true,
            true,
            &mut logger,
            |_| flushed = true,
            |_| {
                deleted = true;
                true
            },
        );

        assert!(
            !flushed,
            "a chain something still jumps to must not be flushed"
        );
        assert!(!deleted, "a referenced chain must not be deleted");
        assert!(
            still_owned,
            "a chain left populated is still ours, so a later pass retries it"
        );

        let mut logger = Logger::new(Mode::Buffer);
        let mut flushed = false;
        let still_owned = teardown_chain(true, false, &mut logger, |_| flushed = true, |_| true);

        assert!(flushed, "an unreferenced chain must be flushed");
        assert!(!still_owned, "a chain whose -X succeeded is no longer ours");

        let mut logger = Logger::new(Mode::Buffer);
        let mut flushed = false;
        let still_owned = teardown_chain(false, false, &mut logger, |_| flushed = true, |_| true);

        assert!(!flushed, "a chain we did not create must not be flushed");
        assert!(!still_owned);
    }

    #[test]
    fn a_removal_whose_commands_failed_stays_owned_for_the_drop_retry() {
        let fake = test_firewall::install();
        fake.fail_every_command("iptables: permission denied");

        let mut manager =
            NetworkIptablesManager::new("stubborn", EgressHookPoint::ContainerNetns(4242));
        manager.retain_residual_ownership(CreatedResources::for_test(true, false, false, false));

        let mut first = Logger::new(Mode::Buffer);
        let _ = manager.remove_firewall_rules(&mut first);
        assert_eq!(
            fake.issued(),
            flush_and_delete("iptables", "stubborn"),
            "the first removal must attempt the teardown"
        );

        fake.forget_issued();
        let mut second = Logger::new(Mode::Buffer);
        let _ = manager.remove_firewall_rules(&mut second);
        assert_eq!(
            fake.issued(),
            flush_and_delete("iptables", "stubborn"),
            "a removal that failed must leave the chain owned so Drop retries it"
        );
    }

    #[test]
    fn a_removal_whose_commands_all_succeeded_releases_ownership() {
        let fake = test_firewall::install();
        let mut manager =
            NetworkIptablesManager::new("released", EgressHookPoint::ContainerNetns(4242));
        manager.retain_residual_ownership(CreatedResources::for_test(true, false, false, false));

        let mut first = Logger::new(Mode::Buffer);
        let _ = manager.remove_firewall_rules(&mut first);
        assert_eq!(
            fake.issued(),
            flush_and_delete("iptables", "released"),
            "the teardown must flush the chain and then delete it"
        );

        fake.forget_issued();
        let mut second = Logger::new(Mode::Buffer);
        let _ = manager.remove_firewall_rules(&mut second);
        assert!(
            fake.issued().is_empty(),
            "a chain whose -X succeeded is no longer ours to remove, got: {:?}",
            fake.issued()
        );
    }

    #[test]
    fn a_second_apply_is_refused_while_the_first_still_owns_resources() {
        let _fake = test_firewall::install();
        let mut manager =
            NetworkIptablesManager::new("already-owned", EgressHookPoint::ContainerNetns(4242));
        manager.retain_residual_ownership(CreatedResources::for_test(true, false, false, false));

        let policy = filtered_policy();
        let mut logger = Logger::new(Mode::Buffer);
        let result = manager.apply_firewall_rules(&policy, &mut logger);

        assert!(
            result.is_err(),
            "applying over live ownership must be refused, got {:?}",
            result
        );
        assert!(
            result.unwrap_err().contains("already applied"),
            "the refusal must say why"
        );
    }

    #[test]
    fn a_manager_that_owns_nothing_still_reaches_the_apply_path() {
        let fake = test_firewall::install();
        let mut manager =
            NetworkIptablesManager::new("fresh", EgressHookPoint::ContainerNetns(4242));
        let policy = filtered_policy();
        let mut logger = Logger::new(Mode::Buffer);
        let result = manager.apply_firewall_rules(&policy, &mut logger);

        if let Err(e) = &result {
            assert!(
                !e.contains("already applied"),
                "a fresh manager must not hit the ownership guard, got: {}",
                e
            );
        }
        let issued = fake.issued();
        assert!(
            issued.contains(&strings(&["iptables", "-N", &chain_name_for("fresh")])),
            "the apply must create the IPv4 chain, got: {:?}",
            issued
        );
        assert!(
            issued.contains(&strings(&["ip6tables", "-N", &chain_name_for("fresh")])),
            "a host whose ip6tables probe succeeds must get the parallel v6 chain, got: {:?}",
            issued
        );
    }

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| arg.to_string()).collect()
    }

    fn flush_and_delete(binary: &str, container: &str) -> Vec<Vec<String>> {
        let chain = chain_name_for(container);
        vec![
            vec![binary.to_string(), "-F".to_string(), chain.clone()],
            vec![binary.to_string(), "-X".to_string(), chain],
        ]
    }

    #[test]
    fn chain_name_sanitization() {
        let mgr =
            NetworkIptablesManager::new("my-container_123", EgressHookPoint::ContainerNetns(4242));
        assert_eq!(mgr.chain_name, chain_name_for("my-container_123"));
        assert!(mgr.chain_name.starts_with("MXC-my-cont-"));
    }

    #[test]
    fn chain_name_respects_the_length_ceiling() {
        let long_name = "a".repeat(50);
        let mgr = NetworkIptablesManager::new(&long_name, EgressHookPoint::ContainerNetns(4242));
        assert!(mgr.chain_name.len() <= CHAIN_NAME_MAX_LEN);
    }

    fn cidr(value: &str) -> NetworkCidr {
        let (address, prefix) = value
            .split_once('/')
            .expect("fixture must include a prefix");
        NetworkCidr {
            address: address.parse().expect("fixture must include an IP address"),
            prefix_length: prefix
                .parse()
                .expect("fixture must include a numeric prefix"),
        }
    }

    #[test]
    fn host_rule_args_route_ipv4_to_iptables_args() {
        let args = NetworkIptablesManager::build_destination_rule_args(
            "MXC-test",
            &cidr("140.82.112.4/32"),
            &RuleAction::Allow,
            RuleMatch::AnyTraffic,
        );

        assert_eq!(
            args.ipv4,
            vec![strings(&[
                "-A",
                "MXC-test",
                "-d",
                "140.82.112.4/32",
                "-j",
                "ACCEPT",
            ])]
        );
        assert!(args.ipv6.is_empty());
    }

    #[test]
    fn host_rule_args_route_ipv6_to_ip6tables_args() {
        let args = NetworkIptablesManager::build_destination_rule_args(
            "MXC-test",
            &cidr("2606:50c0:8000::64/128"),
            &RuleAction::Deny,
            RuleMatch::AnyTraffic,
        );

        assert!(args.ipv4.is_empty());
        assert_eq!(
            args.ipv6,
            vec![strings(&[
                "-A",
                "MXC-test",
                "-d",
                "2606:50c0:8000::64/128",
                "-j",
                "DROP",
            ])]
        );
    }

    #[test]
    fn host_rule_args_pass_cidr_through_unchanged() {
        let v4 = NetworkIptablesManager::build_destination_rule_args(
            "MXC-test",
            &cidr("140.82.112.0/20"),
            &RuleAction::Allow,
            RuleMatch::AnyTraffic,
        );
        assert_eq!(
            v4.ipv4,
            vec![strings(&[
                "-A",
                "MXC-test",
                "-d",
                "140.82.112.0/20",
                "-j",
                "ACCEPT",
            ])]
        );
        assert!(v4.ipv6.is_empty());

        let v6 = NetworkIptablesManager::build_destination_rule_args(
            "MXC-test",
            &cidr("2606:50c0::/32"),
            &RuleAction::Allow,
            RuleMatch::AnyTraffic,
        );
        assert!(v6.ipv4.is_empty());
        assert_eq!(
            v6.ipv6,
            vec![strings(&[
                "-A",
                "MXC-test",
                "-d",
                "2606:50c0::/32",
                "-j",
                "ACCEPT",
            ])]
        );
    }

    #[test]
    fn direct_mapped_ipv6_cidr_uses_ipv4_destination_in_ipv4_chain() {
        let args = NetworkIptablesManager::build_destination_rule_args(
            "MXC-test",
            &cidr("::ffff:192.0.2.0/120"),
            &RuleAction::Allow,
            RuleMatch::AnyTraffic,
        );

        assert_eq!(
            args.ipv4,
            vec![strings(&[
                "-A",
                "MXC-test",
                "-d",
                "192.0.2.0/24",
                "-j",
                "ACCEPT",
            ])]
        );
        assert!(args.ipv6.is_empty());
    }

    #[test]
    fn invalid_typed_cidr_does_not_program_a_rule() {
        let args = NetworkIptablesManager::build_destination_rule_args(
            "MXC-test",
            &NetworkCidr {
                address: IpAddr::from([140, 82, 112, 0]),
                prefix_length: 33,
            },
            &RuleAction::Allow,
            RuleMatch::AnyTraffic,
        );

        assert!(args.ipv4.is_empty());
        assert!(args.ipv6.is_empty());
    }

    #[test]
    fn base_chain_rule_args_are_family_agnostic() {
        let base = NetworkIptablesManager::build_base_chain_rule_args("MXC-test");

        assert_eq!(base.len(), 2);
        for rule in &base {
            assert!(!rule.iter().any(|arg| arg == "icmp"));
            assert!(!rule.iter().any(|arg| arg == "icmpv6"));
        }
    }

    #[test]
    fn typed_cidrs_route_to_their_firewall_family() {
        for (input, expected, is_v4) in [
            ("192.0.2.0/24", "192.0.2.0/24", true),
            ("2001:db8::/32", "2001:db8::/32", false),
            ("::ffff:192.0.2.0/120", "192.0.2.0/24", true),
            ("::ffff:0:0/95", "::fffe:0:0/95", false),
        ] {
            let peer = NetworkPeer {
                cidr: cidr(input),
                except: Vec::new(),
            };
            let lowered =
                NetworkIptablesManager::peer_destinations(&peer).expect("valid CIDR should lower");
            assert_eq!(lowered.len(), 1);
            let args = NetworkIptablesManager::build_destination_rule_args(
                "MXC-test",
                &lowered[0],
                &RuleAction::Allow,
                RuleMatch::AnyTraffic,
            );
            let (present, absent) = if is_v4 {
                (&args.ipv4, &args.ipv6)
            } else {
                (&args.ipv6, &args.ipv4)
            };
            assert!(absent.is_empty(), "wrong family for {input}: {args:?}");
            assert_eq!(present.len(), 1, "missing {input}: {args:?}");
            assert!(present[0].contains(&expected.to_string()));
        }
    }

    fn joined(rule: &[String]) -> String {
        rule.join(" ")
    }

    fn assert_rule_contains(rule: &[String], expected: &str, input: &str) {
        assert!(
            rule.iter().any(|arg| arg == expected),
            "rule for {input} should contain {expected:?}; actual: {rule:?}"
        );
    }

    fn assert_rule_omits(rule: &[String], unexpected: &str, input: &str) {
        assert!(
            !rule.iter().any(|arg| arg == unexpected),
            "rule for {input} should not contain {unexpected:?}; actual: {rule:?}"
        );
    }

    #[test]
    fn allow_and_deny_actions_map_to_exact_iptables_jump_targets() {
        assert_eq!(
            NetworkIptablesManager::rule_action_arg(&RuleAction::Allow),
            "ACCEPT",
            "RuleAction::Allow should map to ACCEPT exactly"
        );
        assert_eq!(
            NetworkIptablesManager::rule_action_arg(&RuleAction::Deny),
            "DROP",
            "RuleAction::Deny should map to DROP exactly"
        );
    }

    #[test]
    fn cidrs_land_only_in_their_address_family_bucket() {
        let cases = [
            ("192.0.2.10/32", "192.0.2.10/32", "ipv4 host CIDR", true),
            ("192.0.2.0/24", "192.0.2.0/24", "ipv4 CIDR", true),
            (
                "2001:db8::10/128",
                "2001:db8::10/128",
                "ipv6 host CIDR",
                false,
            ),
            ("2001:db8::10/64", "2001:db8::/64", "ipv6 CIDR", false),
        ];

        for (destination, expected, label, is_ipv4) in cases {
            let rules = NetworkIptablesManager::build_destination_rule_args(
                "MXC-family-split",
                &cidr(destination),
                &RuleAction::Allow,
                RuleMatch::AnyTraffic,
            );

            if is_ipv4 {
                assert_eq!(
                    rules.ipv4.len(),
                    1,
                    "{label} {destination} should produce one IPv4 rule; actual: {rules:?}"
                );
                assert!(
                    rules.ipv6.is_empty(),
                    "{label} {destination} should leave IPv6 rules empty; actual: {rules:?}"
                );
                assert_rule_contains(&rules.ipv4[0], expected, destination);
            } else {
                assert!(
                    rules.ipv4.is_empty(),
                    "{label} {destination} must not leak into IPv4 rules; actual: {rules:?}"
                );
                assert_eq!(
                    rules.ipv6.len(),
                    1,
                    "{label} {destination} should produce one IPv6 rule; actual: {rules:?}"
                );
                assert_rule_contains(&rules.ipv6[0], expected, destination);
            }
        }
    }

    #[test]
    fn generated_destination_rules_append_to_chain_match_destination_and_jump_target() {
        let chain_name = "MXC-shape";
        let destination = "203.0.113.0/24";
        let rule = NetworkIptablesManager::build_single_rule_args(
            chain_name,
            destination,
            &RuleAction::Deny,
            RuleMatch::AnyTraffic,
            IpFamily::V4,
        );

        assert_eq!(
            rule.first().map(String::as_str),
            Some("-A"),
            "rule for {destination} should append with -A; actual: {rule:?}"
        );
        assert_rule_contains(&rule, chain_name, destination);
        assert_rule_contains(&rule, "-d", destination);
        assert_rule_contains(&rule, destination, destination);
        assert_rule_contains(&rule, "-j", destination);
        assert_rule_contains(&rule, "DROP", destination);

        let rendered = joined(&rule);
        assert!(
            rendered.contains("-A MXC-shape"),
            "rule for {destination} should append to the requested chain; actual: {rendered}"
        );
        assert!(
            rendered.contains("-d 203.0.113.0/24"),
            "CIDR destination should be passed through unchanged in rule; actual: {rendered}"
        );
        assert!(
            rendered.contains("-j DROP"),
            "deny rule for {destination} should jump to DROP; actual: {rendered}"
        );
    }

    #[test]
    fn no_egress_rule_selects_an_incoming_interface() {
        let chain_name = "MXC-sel";
        let rules = NetworkIptablesManager::build_base_chain_rule_args(chain_name);

        for rule in &rules {
            assert!(
                !rule.iter().any(|arg| arg == "-i"),
                "these chains are reached from OUTPUT, where iptables refuses -i outright; \
                 into a user chain it is accepted and then matches nothing: {rule:?}"
            );
        }
    }

    #[test]
    fn every_chain_body_permits_traffic_to_the_containers_own_loopback() {
        let chain_name = "MXC-lo";
        let expected = strings(&["-A", chain_name, "-o", "lo", "-j", "ACCEPT"]);

        assert!(
            NetworkIptablesManager::build_base_chain_rule_args(chain_name).contains(&expected),
            "an ordinary chain must leave intra-container loopback alone"
        );
        assert_eq!(
            NetworkIptablesManager::build_loopback_accept_rule_args(chain_name),
            expected,
            "the proxy path installs this rule directly, on both families"
        );
    }

    #[test]
    fn base_chain_rules_are_two_family_agnostic_rules_in_documented_order() {
        let chain_name = "MXC-base";
        let rules = NetworkIptablesManager::build_base_chain_rule_args(chain_name);
        let expected = vec![
            strings(&["-A", chain_name, "-o", "lo", "-j", "ACCEPT"]),
            strings(&[
                "-A",
                chain_name,
                "-m",
                "state",
                "--state",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ]),
        ];

        assert_eq!(
            rules, expected,
            "base chain rules should be the documented two rules in order"
        );
        for (index, rule) in rules.iter().enumerate() {
            assert_rule_omits(rule, "-d", &format!("base rule {index}"));
            assert!(
                !rule.iter().any(|arg| arg == "icmp" || arg == "icmpv6"),
                "base rule {index} must be family-agnostic; -p icmp is invalid for ip6tables and would make the v6 chain fail: {rule:?}"
            );
        }
    }

    #[test]
    fn directional_default_maps_to_exact_terminal_rule_vector() {
        let chain_name = "MXC-default";

        assert_eq!(
            NetworkIptablesManager::build_default_policy_rule_arg(chain_name, NetworkAction::Deny),
            strings(&["-A", chain_name, "-j", "DROP"]),
            "egress.default=deny should produce the exact DROP terminal rule"
        );
        assert_eq!(
            NetworkIptablesManager::build_default_policy_rule_arg(chain_name, NetworkAction::Allow),
            strings(&["-A", chain_name, "-j", "ACCEPT"]),
            "egress.default=allow should produce the exact ACCEPT terminal rule"
        );
    }

    #[test]
    fn chain_names_carry_the_mxc_prefix_within_the_iptables_length_ceiling() {
        let short_manager =
            NetworkIptablesManager::new("short", EgressHookPoint::ContainerNetns(4242));
        assert!(
            short_manager.chain_name.starts_with("MXC-short-"),
            "a short ASCII name should stay legible in the slug; actual: {}",
            short_manager.chain_name
        );

        let long_name = "abcdefghijklmnopqrstuvwxyz";
        let long_manager =
            NetworkIptablesManager::new(long_name, EgressHookPoint::ContainerNetns(4242));
        assert!(
            long_manager.chain_name.len() <= CHAIN_NAME_MAX_LEN,
            "chain name must fit the iptables ceiling; actual: {}",
            long_manager.chain_name
        );
        assert!(
            long_manager.chain_name.starts_with("MXC-"),
            "long chain name should keep MXC- prefix; actual: {}",
            long_manager.chain_name
        );
    }

    #[test]
    fn empty_policy_produces_no_destination_rules_in_either_bucket() {
        let policy = ContainerPolicy::default();
        let rules = NetworkIptablesManager::build_policy_rule_args("MXC-empty", &policy);

        assert!(
            rules.ipv4.is_empty(),
            "empty policy should produce no IPv4 destination rules; actual: {rules:?}"
        );
        assert!(
            rules.ipv6.is_empty(),
            "empty policy should produce no IPv6 destination rules; actual: {rules:?}"
        );
    }

    #[test]
    fn a_new_manager_reports_no_rules_applied() {
        let manager = NetworkIptablesManager::new("fresh", EgressHookPoint::ContainerNetns(4242));

        assert!(
            !manager.rules_applied(),
            "a newly constructed manager must not report firewall state needing cleanup"
        );
    }

    #[test]
    fn a_policy_permitting_nothing_is_a_successful_no_op() {
        let mut manager =
            NetworkIptablesManager::new("skip-noop", EgressHookPoint::ContainerNetns(4242));
        let policy = ContainerPolicy {
            network_egress: Some(NetworkEgressPolicy::default()),
            ..Default::default()
        };
        let mut logger = Logger::new(Mode::Buffer);

        let result = manager.apply_firewall_rules(&policy, &mut logger);

        assert_eq!(
            result,
            Ok(true),
            "a policy given no interface must be reported as a successful no-op"
        );
        assert!(
            !manager.rules_applied(),
            "a no-op firewall skip must leave no rules marked as applied"
        );
    }

    #[test]
    fn a_directional_policy_installs_the_firewall() {
        let policy = ContainerPolicy {
            network_egress: Some(NetworkEgressPolicy {
                default: NetworkAction::Allow,
                ..Default::default()
            }),
            ..Default::default()
        };

        assert!(
            plan_network(&policy).installs_firewall(),
            "a stated directional posture permitting traffic must install the firewall"
        );
    }

    #[test]
    fn a_directional_request_naming_no_network_fields_is_given_no_interface() {
        let policy = ContainerPolicy {
            network_egress: Some(NetworkEgressPolicy::default()),
            network_ingress: Some(crate::mxc_common::models::NetworkIngressPolicy::default()),
            ..Default::default()
        };

        let plan = plan_network(&policy);
        assert!(plan.omits_interface());
        assert!(!plan.installs_firewall());
    }

    #[test]
    fn a_stated_allow_entry_keeps_the_interface() {
        let policy = ContainerPolicy {
            network_egress: Some(NetworkEgressPolicy {
                default: NetworkAction::Deny,
                allow: vec![NetworkRule::default()],
                ..Default::default()
            }),
            ..Default::default()
        };

        assert!(!plan_network(&policy).omits_interface());
    }

    #[test]
    fn an_admitted_inbound_peer_keeps_the_interface() {
        let policy = ContainerPolicy {
            network_egress: Some(NetworkEgressPolicy::default()),
            network_ingress: Some(crate::mxc_common::models::NetworkIngressPolicy {
                host_loopback: NetworkAction::Allow,
                ..Default::default()
            }),
            ..Default::default()
        };

        assert!(!plan_network(&policy).omits_interface());
    }

    // Alpine's DHCP lease arrives around ten seconds after LXC marks the container running.
    #[test]
    fn a_plan_that_starts_an_interface_demands_an_address() {
        let policy = filtered_policy();

        assert!(
            !plan_network(&policy).omits_interface(),
            "a policy that allows everything is given an interface"
        );
        assert!(
            needs_network(&policy),
            "a container given an interface waits for its address; running the \
             script first points it at a network that is not up yet"
        );
    }

    #[test]
    fn a_plan_that_omits_the_interface_never_demands_an_address() {
        let egress_options = [None, Some(NetworkAction::Deny), Some(NetworkAction::Allow)];
        let ingress_options = [
            None,
            Some((NetworkAction::Deny, NetworkAction::Deny)),
            Some((NetworkAction::Deny, NetworkAction::Allow)),
            Some((NetworkAction::Allow, NetworkAction::Deny)),
            Some((NetworkAction::Allow, NetworkAction::Allow)),
        ];
        let mut omitted = 0;

        for egress in egress_options {
            for ingress in ingress_options {
                for allow_entry in [false, true] {
                    let policy = ContainerPolicy {
                        network_egress: egress.map(|default| NetworkEgressPolicy {
                            default,
                            allow: if allow_entry {
                                vec![NetworkRule::default()]
                            } else {
                                Vec::new()
                            },
                            ..Default::default()
                        }),
                        network_ingress: ingress.map(|(default, host_loopback)| {
                            crate::mxc_common::models::NetworkIngressPolicy {
                                default,
                                host_loopback,
                            }
                        }),
                        ..Default::default()
                    };

                    if plan_network(&policy).omits_interface() {
                        omitted += 1;
                        assert!(
                            !needs_network(&policy),
                            "no interface means no address: egress={egress:?}, \
                                 ingress={ingress:?}, allow_entry={allow_entry}"
                        );
                    }
                }
            }
        }

        assert!(
            omitted > 0,
            "the sweep never produced a no-interface plan and proved nothing"
        );
    }

    #[test]
    fn working_probe_with_active_ipv6_reports_available() {
        let result = NetworkIptablesManager::classify_ip6tables_status(true, true);
        assert_eq!(
            result,
            Ip6tablesStatus::Available,
            "classify_ip6tables_status(probe=true, ipv6_active=true) should be Available; got {result:?}"
        );
    }

    #[test]
    fn working_probe_without_active_ipv6_still_reports_available() {
        let result = NetworkIptablesManager::classify_ip6tables_status(true, false);
        assert_eq!(
            result,
            Ip6tablesStatus::Available,
            "classify_ip6tables_status(probe=true, ipv6_active=false) should be Available; got {result:?}"
        );
    }

    #[test]
    fn failed_probe_with_no_active_ipv6_reports_kernel_ipv6_disabled() {
        let result = NetworkIptablesManager::classify_ip6tables_status(false, false);
        assert_eq!(
            result,
            Ip6tablesStatus::KernelIpv6Disabled,
            "classify_ip6tables_status(probe=false, ipv6_active=false) should be KernelIpv6Disabled; got {result:?}"
        );
    }

    #[test]
    fn live_ipv6_with_a_broken_tool_must_fail_closed_not_skip() {
        let result = NetworkIptablesManager::classify_ip6tables_status(false, true);
        assert_eq!(
            result,
            Ip6tablesStatus::UnusableButIpv6Active,
            "classify_ip6tables_status(probe=false, ipv6_active=true) should be UnusableButIpv6Active (fail-closed); got {result:?}"
        );
    }

    #[test]
    fn working_probe_always_yields_available_regardless_of_ipv6_state() {
        for ipv6_active in [false, true] {
            let result = NetworkIptablesManager::classify_ip6tables_status(true, ipv6_active);
            assert_eq!(
                result,
                Ip6tablesStatus::Available,
                "probe_succeeded=true, ipv6_active={ipv6_active}: expected Available, got {result:?}"
            );
        }
    }

    #[test]
    fn failed_probe_never_reports_available() {
        for ipv6_active in [false, true] {
            let result = NetworkIptablesManager::classify_ip6tables_status(false, ipv6_active);
            assert_ne!(
                result,
                Ip6tablesStatus::Available,
                "probe_succeeded=false, ipv6_active={ipv6_active}: Available must not be returned when the probe failed; got {result:?}"
            );
        }
    }

    #[test]
    fn fail_closed_outcome_is_reachable_only_when_probe_failed_and_ipv6_is_live() {
        let fail_closed = NetworkIptablesManager::classify_ip6tables_status(false, true);
        assert_eq!(
            fail_closed,
            Ip6tablesStatus::UnusableButIpv6Active,
            "classify_ip6tables_status(probe=false, ipv6_active=true) must be UnusableButIpv6Active; got {fail_closed:?}"
        );

        let other_pairs = [(true, true), (true, false), (false, false)];
        for (probe, active) in other_pairs {
            let result = NetworkIptablesManager::classify_ip6tables_status(probe, active);
            assert_ne!(
                result,
                Ip6tablesStatus::UnusableButIpv6Active,
                "classify_ip6tables_status(probe={probe}, ipv6_active={active}) must not be UnusableButIpv6Active; got {result:?}"
            );
        }
    }

    #[test]
    fn safe_skip_outcome_is_reachable_only_when_probe_failed_and_ipv6_is_inactive() {
        let safe_skip = NetworkIptablesManager::classify_ip6tables_status(false, false);
        assert_eq!(
            safe_skip,
            Ip6tablesStatus::KernelIpv6Disabled,
            "classify_ip6tables_status(probe=false, ipv6_active=false) must be KernelIpv6Disabled; got {safe_skip:?}"
        );

        let other_pairs = [(true, true), (true, false), (false, true)];
        for (probe, active) in other_pairs {
            let result = NetworkIptablesManager::classify_ip6tables_status(probe, active);
            assert_ne!(
                result,
                Ip6tablesStatus::KernelIpv6Disabled,
                "classify_ip6tables_status(probe={probe}, ipv6_active={active}) must not be KernelIpv6Disabled; got {result:?}"
            );
        }
    }

    #[test]
    fn ip6tables_status_variants_are_all_distinct_from_each_other() {
        assert_ne!(
            Ip6tablesStatus::Available,
            Ip6tablesStatus::KernelIpv6Disabled,
            "Available and KernelIpv6Disabled must be distinct variants"
        );
        assert_ne!(
            Ip6tablesStatus::Available,
            Ip6tablesStatus::UnusableButIpv6Active,
            "Available and UnusableButIpv6Active must be distinct variants"
        );
        assert_ne!(
            Ip6tablesStatus::KernelIpv6Disabled,
            Ip6tablesStatus::UnusableButIpv6Active,
            "KernelIpv6Disabled and UnusableButIpv6Active must be distinct variants"
        );
    }

    const PROC_NET_MOUNTED: bool = true;

    const PROC_NET_ABSENT: bool = false;

    // A real `/proc/net/if_inet6` line: 32-hex-char address, if_index,
    // prefix_len, scope, flags, and the device name in the final field.
    const LOOPBACK_LINE: &str = "00000000000000000000000000000001 01 80 10 80         lo";
    const ETH0_GLOBAL_LINE: &str = "2606280002200001024818932c5c1946 03 40 00 80         eth0";
    const ETH0_LINKLOCAL_LINE: &str = "fe80000000000000020000fffe000001 03 40 20 80         eth0";

    #[test]
    fn a_real_interface_address_is_classified_active() {
        // A global address on a non-`lo` device is egress-capable IPv6.
        let contents = format!("{LOOPBACK_LINE}\n{ETH0_GLOBAL_LINE}\n");
        let state =
            NetworkIptablesManager::classify_host_ipv6_state(Ok(contents), PROC_NET_MOUNTED);
        assert_eq!(
            state,
            HostIpv6State::Active,
            "a non-loopback interface with an IPv6 address must classify as Active; got {state:?}"
        );
    }

    #[test]
    fn a_link_local_address_on_a_real_interface_is_still_active() {
        // The kernel lists the link-local `fe80::` address on any interface
        // with IPv6 up, and its device is not `lo`.
        let contents = format!("{ETH0_LINKLOCAL_LINE}\n");
        let state =
            NetworkIptablesManager::classify_host_ipv6_state(Ok(contents), PROC_NET_MOUNTED);
        assert_eq!(
            state,
            HostIpv6State::Active,
            "a link-local address on eth0 must classify as Active; got {state:?}"
        );
    }

    #[test]
    fn loopback_only_is_not_a_basis_for_claiming_egress_capable_ipv6() {
        // Loopback is not egress-capable IPv6.
        let contents = format!("{LOOPBACK_LINE}\n");
        let state =
            NetworkIptablesManager::classify_host_ipv6_state(Ok(contents), PROC_NET_MOUNTED);
        assert_eq!(
            state,
            HostIpv6State::Inactive,
            "loopback-only `::1` on `lo` must classify as Inactive, not Active; got {state:?}"
        );
        assert_ne!(
            state,
            HostIpv6State::Active,
            "loopback-only `::1` must never be reported as egress-capable IPv6"
        );
    }

    #[test]
    fn empty_contents_are_inactive() {
        let state =
            NetworkIptablesManager::classify_host_ipv6_state(Ok(String::new()), PROC_NET_MOUNTED);
        assert_eq!(
            state,
            HostIpv6State::Inactive,
            "an empty `/proc/net/if_inet6` means no IPv6 addresses; got {state:?}"
        );
    }

    #[test]
    fn whitespace_only_contents_are_inactive() {
        let state = NetworkIptablesManager::classify_host_ipv6_state(
            Ok("\n  \n".to_string()),
            PROC_NET_MOUNTED,
        );
        assert_eq!(
            state,
            HostIpv6State::Inactive,
            "blank lines carry no interface, so the state is Inactive; got {state:?}"
        );
    }

    #[test]
    fn a_missing_file_is_a_confirmed_negative() {
        // A `NotFound` read while `/proc/net` exists means the kernel never
        // created the file.
        let state = NetworkIptablesManager::classify_host_ipv6_state(
            Err(Error::from(ErrorKind::NotFound)),
            PROC_NET_MOUNTED,
        );
        assert_eq!(
            state,
            HostIpv6State::Inactive,
            "a NotFound read (IPv6 disabled at boot) is a confirmed negative; got {state:?}"
        );
    }

    #[test]
    fn a_missing_file_on_an_unmounted_proc_is_unknown_not_a_confirmed_negative() {
        // An unmounted /proc reports the same NotFound as an IPv6-disabled
        // kernel.  The probe never ran.
        let state = NetworkIptablesManager::classify_host_ipv6_state(
            Err(Error::from(ErrorKind::NotFound)),
            PROC_NET_ABSENT,
        );
        assert_eq!(
            state,
            HostIpv6State::Unknown,
            "NotFound with no /proc/net must be Unknown, not a confirmed negative; got {state:?}"
        );
        assert_ne!(
            state,
            HostIpv6State::Inactive,
            "an unmounted /proc must never be reported as a confirmed 'IPv6 is off'"
        );
    }

    #[test]
    fn an_unreadable_file_is_unknown_not_a_confirmed_negative() {
        // A read error other than NotFound must not be converted into
        // "IPv6 is off".
        let state = NetworkIptablesManager::classify_host_ipv6_state(
            Err(Error::from(ErrorKind::PermissionDenied)),
            PROC_NET_MOUNTED,
        );
        assert_eq!(
            state,
            HostIpv6State::Unknown,
            "a PermissionDenied read must be Unknown, not Inactive; got {state:?}"
        );
        assert_ne!(
            state,
            HostIpv6State::Inactive,
            "an unreadable IPv6 state must never be treated as a confirmed 'IPv6 is off'"
        );
    }

    #[test]
    fn a_generic_io_error_is_unknown_not_a_confirmed_negative() {
        let state = NetworkIptablesManager::classify_host_ipv6_state(
            Err(Error::from(ErrorKind::Other)),
            PROC_NET_MOUNTED,
        );
        assert_eq!(
            state,
            HostIpv6State::Unknown,
            "a generic I/O error must be Unknown, not Inactive; got {state:?}"
        );
    }

    #[test]
    fn host_ipv6_states_are_all_distinct() {
        assert_ne!(HostIpv6State::Active, HostIpv6State::Inactive);
        assert_ne!(HostIpv6State::Active, HostIpv6State::Unknown);
        assert_ne!(HostIpv6State::Inactive, HostIpv6State::Unknown);
    }

    #[test]
    fn active_state_is_treated_as_active() {
        assert!(
            NetworkIptablesManager::ipv6_state_treated_as_active(HostIpv6State::Active),
            "Active must be treated as active"
        );
    }

    #[test]
    fn inactive_state_is_not_treated_as_active() {
        assert!(
            !NetworkIptablesManager::ipv6_state_treated_as_active(HostIpv6State::Inactive),
            "Inactive must not be treated as active; there is genuinely nothing to filter"
        );
    }

    #[test]
    fn unknown_state_is_treated_as_active_to_fail_closed() {
        assert!(
            NetworkIptablesManager::ipv6_state_treated_as_active(HostIpv6State::Unknown),
            "Unknown must be treated as active so an unreadable IPv6 state fails closed"
        );
    }
    #[test]
    fn a_chain_is_still_deleted_when_its_output_hook_never_installed() {
        // The hook is claimed before its `-I` runs.  A signal landing between
        // the command returning and the record being written still finds it.
        let fake = test_firewall::install();
        fake.fail_commands_matching("OUTPUT", "iptables: No chain/target/match by that name");

        let mut manager =
            NetworkIptablesManager::new("stranded", EgressHookPoint::ContainerNetns(4242));
        let policy = filtered_policy();
        let mut logger = Logger::new(Mode::Buffer);

        let outcome = manager.apply_firewall_rules(&policy, &mut logger);
        assert!(
            outcome.is_err(),
            "an apply whose OUTPUT hook could not be installed must fail"
        );

        let chain = chain_name_for("stranded");
        let issued = fake.issued();
        assert!(
            issued
                .iter()
                .any(|cmd| cmd[0] == "iptables" && cmd[1] == "-X" && cmd[2] == chain),
            "the rollback must delete the chain whose hook never installed; issued: {issued:?}"
        );
    }

    #[test]
    fn a_hook_the_kernel_may_have_applied_is_removed_before_the_claim_is_released() {
        // A failure report is not proof the kernel refused the insert.
        // A hook it may have applied must be removed before the claim is released.
        let fake = test_firewall::install();
        fake.fail_commands_matching("OUTPUT", "iptables: Resource temporarily unavailable");

        let mut manager =
            NetworkIptablesManager::new("maybe-applied", EgressHookPoint::ContainerNetns(4242));
        let policy = filtered_policy();
        let mut logger = Logger::new(Mode::Buffer);

        let outcome = manager.apply_firewall_rules(&policy, &mut logger);
        assert!(
            outcome.is_err(),
            "an apply whose OUTPUT hook could not be installed must fail"
        );

        let chain = chain_name_for("maybe-applied");
        let issued = fake.issued();
        assert!(
            issued.iter().any(|cmd| {
                cmd[1] == "-D" && cmd[2] == "OUTPUT" && cmd.iter().any(|arg| arg == &chain)
            }),
            "the failed hook must be removed from OUTPUT before its claim is \
             released, or a rule the kernel did apply is left with nothing \
             recorded to remove it; issued: {issued:?}"
        );
    }

    #[test]
    fn a_chain_whose_hook_did_install_is_not_deleted_while_the_hook_survives() {
        // A hook that is in OUTPUT still points at this chain.  Flushing a
        // chain that is still hooked lets the packet fall past it.
        let fake = test_firewall::install();

        let mut manager =
            NetworkIptablesManager::new("still-hooked", EgressHookPoint::ContainerNetns(4242));
        let policy = filtered_policy();
        let mut apply_logger = Logger::new(Mode::Buffer);
        manager
            .apply_firewall_rules(&policy, &mut apply_logger)
            .expect("the apply must succeed against the fake");

        fake.forget_issued();
        fake.fail_commands_matching("-D", "iptables: Resource temporarily unavailable");
        let mut remove_logger = Logger::new(Mode::Buffer);
        let _ = manager.remove_firewall_rules(&mut remove_logger);

        let chain = chain_name_for("still-hooked");
        let issued = fake.issued();
        for operation in ["-F", "-X"] {
            assert!(
                !issued
                    .iter()
                    .any(|cmd| cmd[1] == operation && cmd[2] == chain),
                "a chain whose hook is still installed must not be {operation}'d; \
                 issued: {issued:?}"
            );
        }

        assert!(
            issued.iter().any(|cmd| cmd[0] == "iptables"
                && cmd[1] == "-D"
                && cmd[2] == "OUTPUT"
                && cmd.last() == Some(&chain)),
            "a hook that installed must still be owned, and so still be removed; \
             issued: {issued:?}"
        );
    }
}
