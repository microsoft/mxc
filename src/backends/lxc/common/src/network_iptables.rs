// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::net::{IpAddr, Ipv6Addr, ToSocketAddrs};
use std::process::Command;

use sha2::{Digest, Sha256};
use wxc_common::logger::Logger;
use wxc_common::models::{
    ContainerPolicy, NetworkAction, NetworkCidr, NetworkEgressPolicy, NetworkPeer, NetworkPolicy,
    NetworkPort, NetworkProtocol, NetworkRule, ProxyAddress, ProxyHostPin,
};

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

pub(crate) fn uses_directional_keys(policy: &ContainerPolicy) -> bool {
    policy.network_egress.is_some() || policy.network_ingress.is_some()
}

pub(crate) fn plan_network(policy: &ContainerPolicy) -> NetworkPlan {
    if uses_directional_keys(policy) {
        plan_directional(policy)
    } else {
        plan_legacy(policy)
    }
}

fn plan_directional(policy: &ContainerPolicy) -> NetworkPlan {
    if policy.network_proxy.is_enabled() {
        return NetworkPlan::Filtered;
    }

    if !policy.allowed_hosts.is_empty() || !policy.blocked_hosts.is_empty() {
        return NetworkPlan::Filtered;
    }

    let egress_permits_nothing = match policy.network_egress.as_ref() {
        Some(egress) => egress.default == NetworkAction::Deny && egress.allow.is_empty(),
        None => matches!(policy.default_network_policy, NetworkPolicy::Block),
    };

    let ingress_permits_nothing = match policy.network_ingress.as_ref() {
        Some(ingress) => {
            ingress.default == NetworkAction::Deny && ingress.host_loopback == NetworkAction::Deny
        }
        None => !policy.allow_local_network,
    };

    if egress_permits_nothing && ingress_permits_nothing {
        NetworkPlan::Isolated
    } else {
        NetworkPlan::Filtered
    }
}

fn plan_legacy(policy: &ContainerPolicy) -> NetworkPlan {
    if policy.network_proxy.is_enabled() {
        return NetworkPlan::Filtered;
    }

    if !policy.allowed_hosts.is_empty() || !policy.blocked_hosts.is_empty() {
        return NetworkPlan::Filtered;
    }

    if matches!(policy.default_network_policy, NetworkPolicy::Block) && !policy.allow_local_network
    {
        return NetworkPlan::Isolated;
    }

    NetworkPlan::Filtered
}

pub(crate) fn needs_network(policy: &ContainerPolicy) -> bool {
    !plan_network(policy).omits_interface()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProxyEndpoint {
    ip: String,
    port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpFamily {
    V4,
    V6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleAction {
    Allow,
    Deny,
}

// iptables applies first-match-wins; entry order is precedence.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EgressEntry {
    destination: String,
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
struct ResolvedDestinations {
    ipv4: Vec<String>,
    ipv6: Vec<String>,
}

impl ResolvedDestinations {
    fn is_empty(&self) -> bool {
        self.ipv4.is_empty() && self.ipv6.is_empty()
    }
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
    proxy_pin: Option<ProxyHostPin>,
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
    let digest = Sha256::digest(container_name.as_bytes());
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
            proxy_pin: None,
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

    // The hosts-file pin a proxied container needs before it runs.
    // DNS round-robin can answer the same name differently on a later lookup.
    pub fn proxy_host_pin(&self) -> Option<&ProxyHostPin> {
        self.proxy_pin.as_ref()
    }

    fn covers_every_address(destination: &str) -> bool {
        destination
            .split_once('/')
            .and_then(|(_, prefix)| prefix.trim().parse::<u8>().ok())
            .is_some_and(|prefix| prefix == 0)
    }

    fn resolve_host(host: &str) -> ResolvedDestinations {
        // Winsock resolves an empty entry formatted as `:0` to every local
        // interface address.  glibc rejects `:0`.
        if host.trim().is_empty() {
            return ResolvedDestinations::default();
        }

        // Linux emits IPv4-mapped destinations as IPv4 packets.
        // They must be programmed with iptables.
        let rewritten = Self::ipv4_mapped_destination(host);
        let host = rewritten.as_deref().unwrap_or(host);

        if host.contains('/') {
            return match Self::destination_family(host) {
                Some(IpFamily::V4) => ResolvedDestinations {
                    ipv4: vec![host.to_string()],
                    ipv6: Vec::new(),
                },
                Some(IpFamily::V6) => ResolvedDestinations {
                    ipv4: Vec::new(),
                    ipv6: vec![host.to_string()],
                },
                None => ResolvedDestinations::default(),
            };
        }

        if let Ok(addr) = host.parse::<IpAddr>() {
            return match addr {
                IpAddr::V4(_) => ResolvedDestinations {
                    ipv4: vec![host.to_string()],
                    ipv6: Vec::new(),
                },
                IpAddr::V6(_) => ResolvedDestinations {
                    ipv4: Vec::new(),
                    ipv6: vec![host.to_string()],
                },
            };
        }

        if let Ok(addrs) = format!("{}:0", host).to_socket_addrs() {
            return Self::bucket_resolved_addrs(addrs.map(|addr| addr.ip()));
        }
        ResolvedDestinations::default()
    }

    // Split A records, AAAA records, and IPv4-mapped AAAA records into the
    // table that can match each packet.
    fn bucket_resolved_addrs<I: IntoIterator<Item = IpAddr>>(addrs: I) -> ResolvedDestinations {
        let mut resolved = ResolvedDestinations::default();
        for ip in addrs {
            match ip {
                IpAddr::V4(ip) => resolved.ipv4.push(ip.to_string()),

                // A resolver can return a AAAA record in mapped form.
                // It travels as IPv4 on the wire.
                IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
                    Some(v4) => resolved.ipv4.push(v4.to_string()),
                    None => resolved.ipv6.push(ip.to_string()),
                },
            }
        }
        resolved
    }

    // Rewrite an IPv4-mapped IPv6 destination to its embedded IPv4 form.
    // Linux puts a genuine IPv4 packet on the wire for a mapped destination.
    //
    // CIDRs inside `::ffff:0:0/96` are handled too: the mapped range is the
    // final 32 bits of that /96.  A prefix shorter than 96 covers addresses
    // outside the mapped range and stays IPv6.
    fn ipv4_mapped_destination(destination: &str) -> Option<String> {
        let Some((network, prefix)) = destination.split_once('/') else {
            return destination
                .parse::<Ipv6Addr>()
                .ok()?
                .to_ipv4_mapped()
                .map(|v4| v4.to_string());
        };

        if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let mapped = network.parse::<Ipv6Addr>().ok()?.to_ipv4_mapped()?;
        let v4_prefix = prefix.parse::<u8>().ok()?.checked_sub(96)?;
        if v4_prefix > 32 {
            return None;
        }
        Some(format!("{}/{}", mapped, v4_prefix))
    }

    fn destination_family(destination: &str) -> Option<IpFamily> {
        if let Some((network, prefix)) = destination.split_once('/') {
            // `u8::from_str` accepts a leading `+`.  iptables canonicalizes
            // `10.0.0.0/+24` to `10.0.0.0/24`.
            if network.is_empty()
                || prefix.is_empty()
                || !prefix.bytes().all(|b| b.is_ascii_digit())
            {
                return None;
            }

            let addr = network.parse::<IpAddr>().ok()?;
            let prefix = prefix.parse::<u8>().ok()?;
            return match addr {
                IpAddr::V4(_) if prefix <= 32 => Some(IpFamily::V4),
                IpAddr::V6(_) if prefix <= 128 => Some(IpFamily::V6),
                _ => None,
            };
        }

        match destination.parse::<IpAddr>().ok()? {
            IpAddr::V4(_) => Some(IpFamily::V4),
            IpAddr::V6(_) => Some(IpFamily::V6),
        }
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

    // The resolver address is not known when a closed chain's allow list is
    // written.  Port 53 is opened until the container can resolve names.
    fn build_dns_resolution_rule_args(chain_name: &str) -> Vec<Vec<String>> {
        vec![
            vec![
                "-A", chain_name, "-p", "udp", "--dport", "53", "-j", "ACCEPT",
            ],
            vec![
                "-A", chain_name, "-p", "tcp", "--dport", "53", "-j", "ACCEPT",
            ],
        ]
        .into_iter()
        .map(|args| args.into_iter().map(String::from).collect())
        .collect()
    }

    fn default_policy_action(default_policy: NetworkPolicy, proxy_enabled: bool) -> &'static str {
        if proxy_enabled {
            return "DROP";
        }
        match default_policy {
            NetworkPolicy::Block => "DROP",
            NetworkPolicy::Allow => "ACCEPT",
        }
    }

    fn build_default_policy_rule_arg(
        chain_name: &str,
        policy: NetworkPolicy,
        proxy_enabled: bool,
    ) -> Vec<String> {
        let default_action = Self::default_policy_action(policy, proxy_enabled);
        vec!["-A", chain_name, "-j", default_action]
            .into_iter()
            .map(String::from)
            .collect()
    }

    // Proxy rules are IPv4 only and must not run through `ip6tables`.
    // A proxied IPv6 chain reaches its closing DROP with only loopback allowed.
    fn build_proxy_chain_rule_args(
        chain_name: &str,
        endpoints: &[ProxyEndpoint],
    ) -> Vec<Vec<String>> {
        endpoints
            .iter()
            .map(|endpoint| {
                vec![
                    "-A".to_string(),
                    chain_name.to_string(),
                    "-p".to_string(),
                    "tcp".to_string(),
                    "-d".to_string(),
                    endpoint.ip.clone(),
                    "--dport".to_string(),
                    endpoint.port.to_string(),
                    "-j".to_string(),
                    "ACCEPT".to_string(),
                ]
            })
            .collect()
    }

    fn host_is_ipv6_literal(host: &str) -> bool {
        let candidate = wxc_common::models::unbracket_host(host);
        matches!(candidate.parse::<IpAddr>(), Ok(IpAddr::V6(_)))
    }

    fn ipv6_proxy_unsupported(host: &str) -> String {
        format!(
            "IPv6 network proxy endpoints are not supported: the proxy firewall rule is \
             emitted with IPv4 iptables only, so '{}' cannot be enforced and would be \
             silently dropped. Use an IPv4 proxy address.",
            host
        )
    }

    // Cap on how many resolved proxy addresses the chain will open.
    // A round-robin or CDN answer is unbounded, and every address becomes
    // its own ACCEPT rule and `iptables` process on the container-start path.
    const MAX_PROXY_ENDPOINTS: usize = 16;

    fn bound_proxy_addresses<'a>(
        host: &str,
        addresses: &'a [String],
        logger: &mut Logger,
    ) -> &'a [String] {
        if addresses.len() <= Self::MAX_PROXY_ENDPOINTS {
            return addresses;
        }

        logger.log_line(&format!(
            "Warning: proxy host '{}' resolved to {} addresses; opening the first {} only. \
             The container is pinned to the first, so it still reaches the proxy.",
            host,
            addresses.len(),
            Self::MAX_PROXY_ENDPOINTS
        ));

        &addresses[..Self::MAX_PROXY_ENDPOINTS]
    }

    // Resolve the proxy with one lookup.  DNS round-robin can answer one
    // name differently on a later lookup.
    fn resolve_proxy_endpoints(
        policy: &ContainerPolicy,
        logger: &mut Logger,
    ) -> Result<(Vec<ProxyEndpoint>, Option<ProxyHostPin>), String> {
        if !policy.network_proxy.is_enabled() {
            return Ok((Vec::new(), None));
        }

        let address = policy.network_proxy.address.as_ref().ok_or_else(|| {
            "Network proxy is enabled but no proxy address is configured".to_string()
        })?;

        if address.port() == 0 {
            return Err("Network proxy port must be between 1 and 65535".to_string());
        }

        if Self::host_is_ipv6_literal(address.host()) {
            return Err(Self::ipv6_proxy_unsupported(address.host()));
        }

        let resolved = Self::resolve_host(address.host());
        if resolved.ipv4.is_empty() {
            if !resolved.ipv6.is_empty() {
                return Err(Self::ipv6_proxy_unsupported(address.host()));
            }
            return Err(format!(
                "Could not resolve network proxy host '{}'",
                address.host()
            ));
        }

        let endpoints: Vec<ProxyEndpoint> =
            Self::bound_proxy_addresses(address.host(), &resolved.ipv4, logger)
                .iter()
                .map(|ip| {
                    logger.log_line(&format!(
                        "Allowing network proxy egress: {}:{} ({})",
                        address.host(),
                        address.port(),
                        ip
                    ));
                    ProxyEndpoint {
                        ip: ip.clone(),
                        port: address.port(),
                    }
                })
                .collect();

        let pin = Self::build_proxy_host_pin(address, &endpoints[0].ip, logger)?;
        Ok((endpoints, pin))
    }

    // A proxied chain opens no port 53.  The hosts-file pin lets the
    // container find the proxy without selecting an address the chain never allowed.
    fn build_proxy_host_pin(
        address: &ProxyAddress,
        ip: &str,
        logger: &mut Logger,
    ) -> Result<Option<ProxyHostPin>, String> {
        let parsed: IpAddr = ip.parse().map_err(|_| {
            format!(
                "Network proxy host '{}' resolved to '{}', which is not an IP address",
                address.host(),
                ip
            )
        })?;

        let pin = address
            .host_pin(parsed)
            .map_err(|e| format!("Cannot pin network proxy host: {}", e))?;

        if let Some(pin) = pin.as_ref() {
            logger.log_line(&format!(
                "Pinning network proxy '{}' to resolved address {} inside the container.",
                pin.hostname(),
                pin.ip()
            ));
        }

        Ok(pin)
    }

    fn build_resolved_destination_rule_args(
        chain_name: &str,
        destinations: &ResolvedDestinations,
        action: &RuleAction,
        matching: RuleMatch,
    ) -> FirewallRuleArgs {
        let mut args = FirewallRuleArgs::default();
        for destination in &destinations.ipv4 {
            args.ipv4.push(Self::build_single_rule_args(
                chain_name,
                destination,
                action,
                matching,
                IpFamily::V4,
            ));
        }
        for destination in &destinations.ipv6 {
            args.ipv6.push(Self::build_single_rule_args(
                chain_name,
                destination,
                action,
                matching,
                IpFamily::V6,
            ));
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
    fn build_host_rule_args(chain_name: &str, host: &str, action: &RuleAction) -> FirewallRuleArgs {
        let destinations = Self::resolve_host(host);
        Self::build_resolved_destination_rule_args(
            chain_name,
            &destinations,
            action,
            RuleMatch::AnyTraffic,
        )
    }

    #[cfg(test)]
    fn build_policy_rule_args(
        chain_name: &str,
        policy: &ContainerPolicy,
        uses_directional_keys: bool,
    ) -> FirewallRuleArgs {
        let mut logger = wxc_common::logger::Logger::new(wxc_common::logger::Mode::Buffer);
        Self::build_policy_rules_logged(chain_name, policy, uses_directional_keys, &mut logger)
            .expect(
                "test policy should not pair an accepting default with an unresolvable block entry",
            )
    }

    fn stated_egress(
        policy: &ContainerPolicy,
        uses_directional_keys: bool,
    ) -> Option<&NetworkEgressPolicy> {
        if uses_directional_keys {
            policy.network_egress.as_ref()
        } else {
            None
        }
    }

    fn effective_default_policy(
        policy: &ContainerPolicy,
        uses_directional_keys: bool,
    ) -> NetworkPolicy {
        match Self::stated_egress(policy, uses_directional_keys) {
            Some(egress) => match egress.default {
                NetworkAction::Allow => NetworkPolicy::Allow,
                NetworkAction::Deny => NetworkPolicy::Block,
            },
            None => policy.default_network_policy.clone(),
        }
    }

    fn lower_egress(policy: &ContainerPolicy, uses_directional_keys: bool) -> Vec<EgressEntry> {
        match Self::stated_egress(policy, uses_directional_keys) {
            Some(egress) => Self::lower_directional_egress(egress),
            None => Self::lower_legacy_hosts(policy),
        }
    }

    // Block entries come first.  Under iptables first-match-wins, exchanging
    // the two halves reverses overlapping allow and block lists.
    fn lower_legacy_hosts(policy: &ContainerPolicy) -> Vec<EgressEntry> {
        policy
            .blocked_hosts
            .iter()
            .map(|host| (host, RuleAction::Deny))
            .chain(
                policy
                    .allowed_hosts
                    .iter()
                    .map(|host| (host, RuleAction::Allow)),
            )
            .map(|(host, action)| EgressEntry {
                destination: host.clone(),
                action,

                matching: RuleMatch::AnyTraffic,
            })
            .collect()
    }

    // Deny rules precede allow rules for the same first-match-wins reason
    // as the legacy lowering.
    fn lower_directional_egress(egress: &NetworkEgressPolicy) -> Vec<EgressEntry> {
        let mut entries = Vec::new();
        let default_action = match egress.default {
            NetworkAction::Allow => RuleAction::Allow,
            NetworkAction::Deny => RuleAction::Deny,
        };
        for rule in &egress.deny {
            Self::lower_rule(rule, RuleAction::Deny, default_action, &mut entries);
        }
        for rule in &egress.allow {
            Self::lower_rule(rule, RuleAction::Allow, default_action, &mut entries);
        }
        entries
    }

    fn lower_rule(
        rule: &NetworkRule,
        action: RuleAction,
        default_action: RuleAction,
        entries: &mut Vec<EgressEntry>,
    ) {
        let matches = Self::lower_port_selectors(&rule.ports);
        let wildcard_peers;
        let peers = if rule.to.is_empty() {
            wildcard_peers = Self::every_destination_peers();
            &wildcard_peers[..]
        } else {
            &rule.to[..]
        };

        for peer in peers {
            for matching in &matches {
                // `except` excludes the range from the rule rather than reversing it.
                // Agreeing verdicts push nothing.
                if default_action != action {
                    for excluded in &peer.except {
                        entries.push(EgressEntry {
                            destination: Self::cidr_destination(excluded),
                            action: default_action,
                            matching: *matching,
                        });
                    }
                }
                entries.push(EgressEntry {
                    destination: Self::cidr_destination(&peer.cidr),
                    action,
                    matching: *matching,
                });
            }
        }
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

    fn cidr_destination(cidr: &NetworkCidr) -> String {
        format!("{}/{}", cidr.address, cidr.prefix_length)
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

    // DNS round-robin can answer one name differently on repeated lookups.
    // Each lowered entry is resolved once before logging and rule generation share the result.
    fn build_policy_rules_logged(
        chain_name: &str,
        policy: &ContainerPolicy,
        uses_directional_keys: bool,
        logger: &mut Logger,
    ) -> Result<FirewallRuleArgs, String> {
        let default_permits = matches!(
            Self::effective_default_policy(policy, uses_directional_keys),
            NetworkPolicy::Allow
        );
        let mut args = FirewallRuleArgs::default();
        let mut unresolved_denies: Vec<&str> = Vec::new();
        let mut catch_all_allows: Vec<&str> = Vec::new();
        let entries = Self::lower_egress(policy, uses_directional_keys);
        for entry in &entries {
            let host = entry.destination.as_str();
            let action = entry.action;
            let destinations = Self::resolve_host(host);
            if destinations.is_empty() {
                if default_permits && matches!(action, RuleAction::Deny) {
                    return Err(format!(
                        "blocked host '{}' resolved to no address, so no rule can be \
                         programmed to deny it, and the default network policy accepts \
                         what no rule matches; refusing to apply a policy that would \
                         leave it reachable",
                        host
                    ));
                }
                if matches!(action, RuleAction::Deny) {
                    unresolved_denies.push(host);
                }
                logger.log_line(&format!("Warning: could not resolve host '{}'", host));
            } else if matches!(action, RuleAction::Allow)
                && matches!(entry.matching, RuleMatch::AnyTraffic)
                && destinations
                    .ipv4
                    .iter()
                    .chain(destinations.ipv6.iter())
                    .any(|dest| Self::covers_every_address(dest))
            {
                catch_all_allows.push(host);
            }
            let rule_args = Self::build_resolved_destination_rule_args(
                chain_name,
                &destinations,
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
                "blocked host(s) {} resolved to no address, so no rule can be programmed \
                 to deny them, while allowed host(s) {} accept every address and are \
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

    fn apply_rules_in_dialect(
        &mut self,
        policy: &ContainerPolicy,
        uses_directional_keys: bool,
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

        let (proxy_endpoints, proxy_pin) = Self::resolve_proxy_endpoints(policy, logger)?;
        self.proxy_pin = proxy_pin;

        let outcome = self.apply_firewall_rules_inner(
            policy,
            uses_directional_keys,
            &proxy_endpoints,
            logger,
        );
        self.record_apply_outcome(outcome, logger)
    }

    pub fn apply_legacy_rules(
        &mut self,
        policy: &ContainerPolicy,
        logger: &mut Logger,
    ) -> Result<bool, String> {
        self.apply_rules_in_dialect(policy, false, logger)
    }

    pub fn apply_directional_rules(
        &mut self,
        policy: &ContainerPolicy,
        logger: &mut Logger,
    ) -> Result<bool, String> {
        self.apply_rules_in_dialect(policy, true, logger)
    }

    pub fn apply_firewall_rules(
        &mut self,
        policy: &ContainerPolicy,
        logger: &mut Logger,
    ) -> Result<bool, String> {
        let dialect = uses_directional_keys(policy);
        self.apply_rules_in_dialect(policy, dialect, logger)
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
        uses_directional_keys: bool,
        proxy_endpoints: &[ProxyEndpoint],
        logger: &mut Logger,
    ) -> Result<CreatedResources, (String, CreatedResources)> {
        let mut created = CreatedResources::default();
        match self.install_firewall_rules(
            policy,
            uses_directional_keys,
            proxy_endpoints,
            logger,
            &mut created,
        ) {
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
        uses_directional_keys: bool,
        proxy_endpoints: &[ProxyEndpoint],
        logger: &mut Logger,
        created: &mut CreatedResources,
    ) -> Result<(), String> {
        logger.log_line(&format!(
            "Creating iptables/ip6tables chain: {}",
            self.chain_name
        ));

        if !proxy_endpoints.is_empty() && !policy.blocked_hosts.is_empty() {
            return Err(
                "network.proxy cannot be combined with blockedHosts: the proxy can fetch a \
                 blocked destination on the container's behalf, so the block list would not \
                 be enforced"
                    .to_string(),
            );
        }

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

        let proxy_mode = !proxy_endpoints.is_empty();

        if proxy_mode {
            // No port 53 accept: the container resolves the proxy through the
            // hosts-file pin, and an unscoped one would be a standing DNS-tunnel
            // exfil path.  No ESTABLISHED,RELATED accept: every packet to the
            // proxy already matches an endpoint ACCEPT.
            let loopback_rules = vec![Self::build_loopback_accept_rule_args(&self.chain_name)];
            self.run_iptables_rule_args(&loopback_rules, logger)?;
            if ipv6_enabled {
                self.run_ip6tables_rule_args(&loopback_rules, logger)?;
            }
            let proxy_rules = Self::build_proxy_chain_rule_args(&self.chain_name, proxy_endpoints);
            self.run_iptables_rule_args(&proxy_rules, logger)?;
            for rule in loopback_rules.iter().chain(proxy_rules.iter()) {
                logger.log_line(&format!("Programmed iptables rule: {}", rule.join(" ")));
            }
            if !policy.allowed_hosts.is_empty() {
                logger.log_line(
                    "Warning: network.proxy is configured, so allowedHosts is not programmed; \
                     the container may reach the proxy and nothing else.",
                );
            }
            if ipv6_enabled {
                logger.log_line(
                    "IPv6 egress is denied outright while a proxy is configured: the proxy \
                     endpoint is IPv4, so the IPv6 chain carries its loopback accept and \
                     its closing DROP.",
                );
            }
        } else {
            let base_rules = Self::build_base_chain_rule_args(&self.chain_name);

            let mut tail_rules: Vec<Vec<String>> = Vec::new();

            // Only a closed chain naming hosts to allow gets DNS.  An open chain
            // needs no grant, and the accept would sit ahead of the deny rules.
            let closed_with_named_hosts = matches!(
                Self::effective_default_policy(policy, uses_directional_keys),
                NetworkPolicy::Block
            ) && !policy.allowed_hosts.is_empty();
            if !uses_directional_keys && closed_with_named_hosts {
                tail_rules.extend(Self::build_dns_resolution_rule_args(&self.chain_name));
            }

            self.run_iptables_rule_args(&base_rules, logger)?;
            if !tail_rules.is_empty() {
                self.run_iptables_rule_args(&tail_rules, logger)?;
            }
            if ipv6_enabled {
                self.run_ip6tables_rule_args(&base_rules, logger)?;
                if !tail_rules.is_empty() {
                    self.run_ip6tables_rule_args(&tail_rules, logger)?;
                }
            }

            let policy_rules = Self::build_policy_rules_logged(
                &self.chain_name,
                policy,
                uses_directional_keys,
                logger,
            )?;
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
        }

        let default_rule = Self::build_default_policy_rule_arg(
            &self.chain_name,
            Self::effective_default_policy(policy, uses_directional_keys),
            proxy_mode,
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
        crate::signal_cleanup::set_active_created(*created);
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
            let mut logger = wxc_common::logger::Logger::new(wxc_common::logger::Mode::Buffer);
            let _ = self.remove_firewall_rules(&mut logger);
        }
    }
}

#[cfg(test)]
#[path = "network_iptables_deny_precedence_spec.rs"]
mod deny_precedence_spec;

#[cfg(test)]
#[path = "network_iptables_proxy_spec.rs"]
mod proxy_spec;

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
    use std::io::{Error, ErrorKind};
    use wxc_common::logger::{Logger, Mode};
    use wxc_common::models::{ContainerPolicy, NetworkEnforcementMode, ProxyAddress, ProxyConfig};

    fn policy_requesting_mode(mode: NetworkEnforcementMode) -> ContainerPolicy {
        ContainerPolicy {
            network_enforcement_mode: mode,
            allowed_hosts: vec!["203.0.113.7".to_string()],
            ..Default::default()
        }
    }

    #[test]
    fn an_unhooked_caller_is_not_refused_in_firewall_mode() {
        let _fake = super::test_firewall::install();
        let mut manager = NetworkIptablesManager::new("bwrap-nonetns", EgressHookPoint::Unhooked);
        let policy = policy_requesting_mode(NetworkEnforcementMode::Firewall);
        let mut logger = Logger::new(Mode::Buffer);

        let result = manager.apply_firewall_rules(&policy, &mut logger);

        assert!(
            result.is_ok(),
            "a caller with no namespace to enforce in must not be failed closed, got {:?}",
            result
        );
    }

    #[test]
    fn an_unhooked_caller_is_not_refused_in_both_mode() {
        let _fake = super::test_firewall::install();
        let mut manager =
            NetworkIptablesManager::new("bwrap-nonetns-both", EgressHookPoint::Unhooked);
        let policy = policy_requesting_mode(NetworkEnforcementMode::Both);
        let mut logger = Logger::new(Mode::Buffer);

        let result = manager.apply_firewall_rules(&policy, &mut logger);

        assert!(
            result.is_ok(),
            "a caller with no namespace to enforce in must not be failed closed, got {:?}",
            result
        );
    }

    #[test]
    fn a_namespaced_manager_hooks_its_chain_into_output() {
        let fake = super::test_firewall::install();
        let mut manager =
            NetworkIptablesManager::new("lxc-hooked", EgressHookPoint::ContainerNetns(4242));
        let policy = policy_requesting_mode(NetworkEnforcementMode::Firewall);
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
        let policy = policy_requesting_mode(NetworkEnforcementMode::Firewall);
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

        let policy = policy_with_enforcement_mode(NetworkEnforcementMode::Firewall);
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
        let policy = policy_with_enforcement_mode(NetworkEnforcementMode::Firewall);
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

    #[test]
    fn resolve_ip_address() {
        let ips = NetworkIptablesManager::resolve_host("127.0.0.1");
        assert_eq!(ips.ipv4, vec!["127.0.0.1"]);
        assert!(ips.ipv6.is_empty());
    }

    #[test]
    fn resolve_host_retains_ipv6_literal() {
        let ips = NetworkIptablesManager::resolve_host("::1");
        assert!(ips.ipv4.is_empty());
        assert_eq!(ips.ipv6, vec!["::1"]);
    }

    #[test]
    fn resolve_host_rewrites_ipv4_mapped_ipv6_literal_to_ipv4() {
        let ips = NetworkIptablesManager::resolve_host("::ffff:127.0.0.1");
        assert_eq!(ips.ipv4, vec!["127.0.0.1"]);
        assert!(ips.ipv6.is_empty());
    }

    #[test]
    fn resolve_host_keeps_ipv4_literal_unchanged() {
        let ips = NetworkIptablesManager::resolve_host("10.0.0.1");
        assert_eq!(ips.ipv4, vec!["10.0.0.1"]);
        assert!(ips.ipv6.is_empty());
    }

    #[test]
    fn resolve_host_retains_valid_cidr_by_family() {
        let v4 = NetworkIptablesManager::resolve_host("140.82.112.0/20");
        assert_eq!(v4.ipv4, vec!["140.82.112.0/20"]);
        assert!(v4.ipv6.is_empty());

        let v6 = NetworkIptablesManager::resolve_host("2606:50c0::/32");
        assert!(v6.ipv4.is_empty());
        assert_eq!(v6.ipv6, vec!["2606:50c0::/32"]);
    }

    #[test]
    fn resolve_host_rejects_invalid_cidr_prefix() {
        assert!(NetworkIptablesManager::resolve_host("140.82.112.0/33").is_empty());
        assert!(NetworkIptablesManager::resolve_host("2606:50c0::/129").is_empty());
        assert!(NetworkIptablesManager::resolve_host("140.82.112.0/not-a-prefix").is_empty());
    }

    #[test]
    fn resolve_host_rejects_malformed_cidr_syntax() {
        assert!(NetworkIptablesManager::resolve_host("/20").is_empty());
        assert!(NetworkIptablesManager::resolve_host("140.82.112.0/").is_empty());
        assert!(NetworkIptablesManager::resolve_host("140.82.112.0/20/8").is_empty());
    }

    #[test]
    fn host_rule_args_route_ipv4_to_iptables_args() {
        let args = NetworkIptablesManager::build_host_rule_args(
            "MXC-test",
            "140.82.112.4",
            &RuleAction::Allow,
        );

        assert_eq!(
            args.ipv4,
            vec![strings(&[
                "-A",
                "MXC-test",
                "-d",
                "140.82.112.4",
                "-j",
                "ACCEPT",
            ])]
        );
        assert!(args.ipv6.is_empty());
    }

    #[test]
    fn host_rule_args_route_ipv6_to_ip6tables_args() {
        let args = NetworkIptablesManager::build_host_rule_args(
            "MXC-test",
            "2606:50c0:8000::64",
            &RuleAction::Deny,
        );

        assert!(args.ipv4.is_empty());
        assert_eq!(
            args.ipv6,
            vec![strings(&[
                "-A",
                "MXC-test",
                "-d",
                "2606:50c0:8000::64",
                "-j",
                "DROP",
            ])]
        );
    }

    #[test]
    fn host_rule_args_pass_cidr_through_unchanged() {
        let v4 = NetworkIptablesManager::build_host_rule_args(
            "MXC-test",
            "140.82.112.0/20",
            &RuleAction::Allow,
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

        let v6 = NetworkIptablesManager::build_host_rule_args(
            "MXC-test",
            "2606:50c0::/32",
            &RuleAction::Allow,
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
    fn host_rule_args_drop_unresolvable_destination() {
        let args = NetworkIptablesManager::build_host_rule_args(
            "MXC-test",
            "140.82.112.0/33",
            &RuleAction::Allow,
        );

        assert!(args.ipv4.is_empty());
        assert!(args.ipv6.is_empty());
    }

    #[test]
    fn build_policy_rule_args_splits_allow_and_block_lists_by_family() {
        let policy = ContainerPolicy {
            allowed_hosts: vec!["140.82.112.0/20".to_string(), "2606:50c0::/32".to_string()],
            blocked_hosts: vec!["10.0.0.0/8".to_string(), "2001:db8::/32".to_string()],
            ..Default::default()
        };

        let args = NetworkIptablesManager::build_policy_rule_args("MXC-test", &policy, false);

        let expected_v4 = vec![
            strings(&["-A", "MXC-test", "-d", "140.82.112.0/20", "-j", "ACCEPT"]),
            strings(&["-A", "MXC-test", "-d", "10.0.0.0/8", "-j", "DROP"]),
        ];
        let expected_v6 = vec![
            strings(&["-A", "MXC-test", "-d", "2606:50c0::/32", "-j", "ACCEPT"]),
            strings(&["-A", "MXC-test", "-d", "2001:db8::/32", "-j", "DROP"]),
        ];

        assert_eq!(args.ipv4.len(), expected_v4.len());
        for rule in &expected_v4 {
            assert!(
                args.ipv4.contains(rule),
                "IPv4 rules should contain {rule:?}; actual: {:?}",
                args.ipv4
            );
        }
        assert_eq!(args.ipv6.len(), expected_v6.len());
        for rule in &expected_v6 {
            assert!(
                args.ipv6.contains(rule),
                "IPv6 rules should contain {rule:?}; actual: {:?}",
                args.ipv6
            );
        }
    }

    #[test]
    fn base_chain_rule_args_are_family_agnostic() {
        let base = NetworkIptablesManager::build_base_chain_rule_args("MXC-test");
        let dns = NetworkIptablesManager::build_dns_resolution_rule_args("MXC-test");

        assert_eq!(base.len(), 2);
        assert_eq!(dns.len(), 2);
        for rule in base.iter().chain(dns.iter()) {
            assert!(!rule.iter().any(|arg| arg == "icmp"));
            assert!(!rule.iter().any(|arg| arg == "icmpv6"));
        }
    }

    fn assert_resolved_exact(input: &str, expected_ipv4: &[&str], expected_ipv6: &[&str]) {
        let resolved = NetworkIptablesManager::resolve_host(input);
        let expected_ipv4: Vec<String> = expected_ipv4
            .iter()
            .map(|value| value.to_string())
            .collect();
        let expected_ipv6: Vec<String> = expected_ipv6
            .iter()
            .map(|value| value.to_string())
            .collect();

        assert_eq!(
            resolved.ipv4, expected_ipv4,
            "unexpected IPv4 destinations for {input:?}"
        );
        assert_eq!(
            resolved.ipv6, expected_ipv6,
            "unexpected IPv6 destinations for {input:?}"
        );
    }

    fn assert_destination_family(input: &str, expected: Option<IpFamily>) {
        assert_eq!(
            NetworkIptablesManager::destination_family(input),
            expected,
            "unexpected destination family for {input:?}"
        );
    }

    #[test]
    fn bare_ip_literals_are_routed_only_to_their_matching_family() {
        let cases = [
            ("192.0.2.1", &["192.0.2.1"][..], &[][..]),
            ("127.0.0.1", &["127.0.0.1"][..], &[][..]),
            ("2606:50c0::153", &[][..], &["2606:50c0::153"][..]),
            (
                "2606:50c0:0000:0000:0000:0000:0000:0153",
                &[][..],
                &["2606:50c0:0000:0000:0000:0000:0000:0153"][..],
            ),
            ("::1", &[][..], &["::1"][..]),
        ];

        for (input, expected_ipv4, expected_ipv6) in cases {
            assert_resolved_exact(input, expected_ipv4, expected_ipv6);
        }
    }

    #[test]
    fn ipv4_mapped_ipv6_literal_is_filed_as_ipv4() {
        assert_resolved_exact("::ffff:127.0.0.1", &["127.0.0.1"], &[]);
    }

    #[test]
    fn ipv4_mapped_cidr_is_translated_to_its_ipv4_prefix() {
        assert_resolved_exact("::ffff:192.0.2.0/120", &["192.0.2.0/24"], &[]);
        assert_resolved_exact("::ffff:198.51.100.42/128", &["198.51.100.42/32"], &[]);
    }

    #[test]
    fn an_ipv6_prefix_shorter_than_the_mapped_range_stays_ipv6() {
        assert_resolved_exact("::ffff:0:0/95", &[], &["::ffff:0:0/95"]);
    }

    #[test]
    fn valid_cidrs_are_passed_through_unchanged_in_their_matching_family() {
        let cases = [
            ("140.82.112.0/20", &["140.82.112.0/20"][..], &[][..]),
            ("2606:50c0::/32", &[][..], &["2606:50c0::/32"][..]),
        ];

        for (input, expected_ipv4, expected_ipv6) in cases {
            assert_resolved_exact(input, expected_ipv4, expected_ipv6);
        }
    }

    #[test]
    fn v4_cidr_with_host_bits_set_is_passed_through_unchanged() {
        assert_resolved_exact("140.82.112.5/20", &["140.82.112.5/20"], &[]);
    }

    #[test]
    fn cidr_prefix_lengths_accept_only_family_specific_bounds() {
        let cases = [
            ("0.0.0.0/0", Some(IpFamily::V4), &["0.0.0.0/0"][..], &[][..]),
            (
                "192.0.2.1/32",
                Some(IpFamily::V4),
                &["192.0.2.1/32"][..],
                &[][..],
            ),
            ("192.0.2.1/33", None, &[][..], &[][..]),
            ("192.0.2.1/129", None, &[][..], &[][..]),
            ("::/0", Some(IpFamily::V6), &[][..], &["::/0"][..]),
            (
                "2001:db8::1/128",
                Some(IpFamily::V6),
                &[][..],
                &["2001:db8::1/128"][..],
            ),
            ("2001:db8::1/129", None, &[][..], &[][..]),
        ];

        for (input, expected_family, expected_ipv4, expected_ipv6) in cases {
            assert_resolved_exact(input, expected_ipv4, expected_ipv6);
            assert_destination_family(input, expected_family);
        }
    }

    #[test]
    fn v6_prefix_length_on_v4_address_is_rejected() {
        assert_resolved_exact("10.0.0.0/64", &[], &[]);
        assert_destination_family("10.0.0.0/64", None);
    }

    #[test]
    fn malformed_cidr_syntax_and_garbage_resolve_to_nothing() {
        let cases = [
            "/24",
            "10.0.0.0/",
            "10.0.0.0//24",
            "10.0.0.0/abc",
            "10.0.0.0/-1",
            "10.0.0.0/ 24",
            "not-a-valid-firewall-destination",
        ];

        for input in cases {
            let resolved = NetworkIptablesManager::resolve_host(input);
            assert!(
                resolved.is_empty(),
                "malformed destination {input:?} should resolve to nothing, got {resolved:?}"
            );
            assert_destination_family(input, None);
        }
    }

    #[test]
    fn cidr_prefix_with_plus_sign_resolves_to_nothing() {
        let input = "10.0.0.0/+24";
        let resolved = NetworkIptablesManager::resolve_host(input);
        assert!(
            resolved.is_empty(),
            "malformed destination {input:?} should resolve to nothing, got {resolved:?}"
        );
        assert_destination_family(input, None);
    }

    #[test]
    fn leading_plus_does_not_smuggle_an_out_of_range_prefix_past_validation() {
        let input = "10.0.0.0/+33";
        let resolved = NetworkIptablesManager::resolve_host(input);
        assert!(
            resolved.is_empty(),
            "a leading `+` must not smuggle an out-of-range prefix past validation, got {resolved:?}"
        );
        assert_destination_family(input, None);
    }

    #[test]
    fn empty_input_resolves_to_nothing() {
        let resolved = NetworkIptablesManager::resolve_host("");
        assert!(
            resolved.is_empty(),
            "empty input should resolve to nothing, got {resolved:?}"
        );
        assert_destination_family("", None);
    }

    fn assert_buckets_are_family_pure(input: &str, resolved: &ResolvedDestinations) {
        for destination in &resolved.ipv4 {
            assert_eq!(
                NetworkIptablesManager::destination_family(destination),
                Some(IpFamily::V4),
                "{input:?}: {destination:?} is in the ipv4 bucket but is not an IPv4 destination"
            );
        }
        for destination in &resolved.ipv6 {
            assert_eq!(
                NetworkIptablesManager::destination_family(destination),
                Some(IpFamily::V6),
                "{input:?}: {destination:?} is in the ipv6 bucket but is not an IPv6 destination"
            );
        }
    }

    #[test]
    fn aaaa_records_land_in_the_v6_bucket_and_never_in_the_v4_bucket() {
        let injected: Vec<IpAddr> = [
            "93.184.216.34",
            "2606:2800:220:1:248:1893:25c8:1946",
            "8.8.8.8",
            "2001:4860:4860::8888",
        ]
        .iter()
        .map(|value| {
            value
                .parse::<IpAddr>()
                .expect("injected test address must parse")
        })
        .collect();

        let resolved = NetworkIptablesManager::bucket_resolved_addrs(injected);

        assert_eq!(
            resolved.ipv4.len(),
            2,
            "both injected A records must land in the v4 bucket, got {:?}",
            resolved.ipv4
        );
        assert_eq!(
            resolved.ipv6.len(),
            2,
            "both injected AAAA records must land in the v6 bucket, got {:?}",
            resolved.ipv6
        );
        assert!(
            !resolved.ipv6.is_empty(),
            "AAAA records must produce at least one v6 destination; an empty v6 \
             bucket means the IPv6 arm was dropped or misrouted into the v4 bucket"
        );
        assert_buckets_are_family_pure("injected A/AAAA mix", &resolved);
    }

    #[test]
    fn live_dual_stack_resolution_keeps_buckets_family_pure() {
        for host in ["dns.google", "one.one.one.one", "localhost"] {
            let resolved = NetworkIptablesManager::resolve_host(host);
            assert_buckets_are_family_pure(host, &resolved);
        }
    }

    #[test]
    fn localhost_resolution_populates_available_loopback_families() {
        let resolved = NetworkIptablesManager::resolve_host("localhost");

        // A minimal host can have a degenerate /etc/hosts.  Accept whichever
        // localhost family is configured while checking that no other address leaks in.
        assert!(
            !resolved.is_empty(),
            "localhost should resolve to at least one loopback family"
        );
        assert!(
            resolved
                .ipv4
                .iter()
                .all(|destination| destination == "127.0.0.1"),
            "localhost IPv4 results should all be 127.0.0.1, got {:?}",
            resolved.ipv4
        );
        assert!(
            resolved.ipv6.iter().all(|destination| destination == "::1"),
            "localhost IPv6 results should all be ::1, got {:?}",
            resolved.ipv6
        );
        assert_buckets_are_family_pure("localhost", &resolved);
    }

    #[test]
    fn unresolvable_invalid_tld_hostname_resolves_to_nothing() {
        let input = "mxc-resolution-spec-7f3b2d9c4a1e6f80.invalid";
        let resolved = NetworkIptablesManager::resolve_host(input);

        assert!(
            resolved.is_empty(),
            "reserved .invalid hostname {input:?} should resolve to nothing, got {resolved:?}"
        );
        assert_destination_family(input, None);
    }

    #[test]
    fn destination_family_agrees_with_every_resolved_destination() {
        let inputs = [
            "192.0.2.44",
            "2606:50c0::153",
            "140.82.112.5/20",
            "2606:50c0::/32",
            "::ffff:127.0.0.1",
            "localhost",
        ];

        for input in inputs {
            let resolved = NetworkIptablesManager::resolve_host(input);

            for destination in &resolved.ipv4 {
                assert_eq!(
                    NetworkIptablesManager::destination_family(destination),
                    Some(IpFamily::V4),
                    "destination_family disagreed with IPv4 filing for input {input:?}, destination {destination:?}"
                );
            }

            for destination in &resolved.ipv6 {
                assert_eq!(
                    NetworkIptablesManager::destination_family(destination),
                    Some(IpFamily::V6),
                    "destination_family disagreed with IPv6 filing for input {input:?}, destination {destination:?}"
                );
            }
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

    fn policy_with_hosts(allowed_hosts: &[&str], blocked_hosts: &[&str]) -> ContainerPolicy {
        ContainerPolicy {
            allowed_hosts: strings(allowed_hosts),
            blocked_hosts: strings(blocked_hosts),
            ..Default::default()
        }
    }

    // `.invalid` is reserved by RFC 2606 and never resolves.
    const UNRESOLVABLE_HOST: &str = "blocked.invalid";

    #[test]
    fn an_unresolvable_deny_under_a_blocking_default_is_fatal_beside_a_catch_all_allow() {
        let policy = ContainerPolicy {
            default_network_policy: NetworkPolicy::Block,
            ..policy_with_hosts(&["0.0.0.0/0"], &[UNRESOLVABLE_HOST])
        };
        let mut logger = wxc_common::logger::Logger::new(wxc_common::logger::Mode::Buffer);

        let err =
            NetworkIptablesManager::build_policy_rules_logged("MXC-x", &policy, false, &mut logger)
                .expect_err("a catch-all allow must not be able to accept an unresolvable deny");

        assert!(
            err.contains(UNRESOLVABLE_HOST) && err.contains("deny precedence"),
            "error should name the host and the invariant, got: {err}"
        );
    }

    #[test]
    fn an_ipv6_catch_all_allow_also_arms_the_deny_precedence_failure() {
        let policy = ContainerPolicy {
            default_network_policy: NetworkPolicy::Block,
            ..policy_with_hosts(&["::/0"], &[UNRESOLVABLE_HOST])
        };
        let mut logger = wxc_common::logger::Logger::new(wxc_common::logger::Mode::Buffer);

        NetworkIptablesManager::build_policy_rules_logged("MXC-x", &policy, false, &mut logger)
            .expect_err("a v6 catch-all allow accepts the unresolved deny just as a v4 one does");
    }

    #[test]
    fn an_unresolvable_deny_beside_a_bounded_allow_stays_a_warning() {
        let policy = ContainerPolicy {
            default_network_policy: NetworkPolicy::Block,
            ..policy_with_hosts(&["192.0.2.10"], &[UNRESOLVABLE_HOST])
        };
        let mut logger = wxc_common::logger::Logger::new(wxc_common::logger::Mode::Buffer);

        NetworkIptablesManager::build_policy_rules_logged("MXC-x", &policy, false, &mut logger)
            .expect("a bounded allow leaves the closing DROP covering the unresolved deny");
    }

    #[test]
    fn a_bounded_cidr_allow_is_not_mistaken_for_a_catch_all() {
        let policy = ContainerPolicy {
            default_network_policy: NetworkPolicy::Block,
            ..policy_with_hosts(&["192.0.2.0/24"], &[UNRESOLVABLE_HOST])
        };
        let mut logger = wxc_common::logger::Logger::new(wxc_common::logger::Mode::Buffer);

        NetworkIptablesManager::build_policy_rules_logged("MXC-x", &policy, false, &mut logger)
            .expect("a /24 allow covers a bounded set, so it proves nothing about the deny");
    }

    #[test]
    fn an_unresolvable_allow_does_not_arm_the_deny_precedence_failure() {
        let policy = ContainerPolicy {
            default_network_policy: NetworkPolicy::Block,
            ..policy_with_hosts(&["allowed.invalid"], &[UNRESOLVABLE_HOST])
        };
        let mut logger = wxc_common::logger::Logger::new(wxc_common::logger::Mode::Buffer);

        NetworkIptablesManager::build_policy_rules_logged("MXC-x", &policy, false, &mut logger)
            .expect("an allow that programs no rule cannot accept the unresolved deny");
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
    fn destination_literals_and_cidrs_land_only_in_their_address_family_bucket() {
        let cases = [
            ("192.0.2.10", "ipv4 bare literal", true),
            ("192.0.2.10/24", "ipv4 CIDR", true),
            ("2001:db8::10", "ipv6 bare literal", false),
            ("2001:db8::10/64", "ipv6 CIDR", false),
        ];

        for (destination, label, is_ipv4) in cases {
            let rules = NetworkIptablesManager::build_host_rule_args(
                "MXC-family-split",
                destination,
                &RuleAction::Allow,
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
                assert_rule_contains(&rules.ipv4[0], destination, destination);
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
                assert_rule_contains(&rules.ipv6[0], destination, destination);
            }
        }
    }

    #[test]
    fn mixed_family_host_list_produces_matching_rule_count_in_each_bucket() {
        let policy = policy_with_hosts(
            &[
                "192.0.2.10",
                "198.51.100.0/24",
                "2001:db8::10",
                "2001:db8:abcd::/48",
            ],
            &[],
        );
        let rules = NetworkIptablesManager::build_policy_rule_args("MXC-mixed", &policy, false);

        assert_eq!(
            rules.ipv4.len(),
            2,
            "mixed host list should produce two IPv4 rules; actual: {rules:?}"
        );
        assert_eq!(
            rules.ipv6.len(),
            2,
            "mixed host list should produce two IPv6 rules; actual: {rules:?}"
        );
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
    fn resolved_destinations_are_split_into_ipv4_and_ipv6_rule_args() {
        let destinations = ResolvedDestinations {
            ipv4: strings(&["192.0.2.10", "198.51.100.0/24"]),
            ipv6: strings(&["2001:db8::10", "2001:db8:abcd::/48"]),
        };
        let rules = NetworkIptablesManager::build_resolved_destination_rule_args(
            "MXC-resolved",
            &destinations,
            &RuleAction::Allow,
            RuleMatch::AnyTraffic,
        );

        assert_eq!(
            rules.ipv4.len(),
            2,
            "resolved destinations should keep both IPv4 rules in IPv4 bucket; actual: {rules:?}"
        );
        assert_eq!(
            rules.ipv6.len(),
            2,
            "resolved destinations should keep both IPv6 rules in IPv6 bucket; actual: {rules:?}"
        );
        for destination in &destinations.ipv4 {
            assert!(
                rules.ipv4.iter().any(|rule| rule.contains(destination)),
                "IPv4 destination {destination} should appear in IPv4 rules; actual: {rules:?}"
            );
            assert!(
                !rules.ipv6.iter().any(|rule| rule.contains(destination)),
                "IPv4 destination {destination} should not appear in IPv6 rules; actual: {rules:?}"
            );
        }
        for destination in &destinations.ipv6 {
            assert!(
                rules.ipv6.iter().any(|rule| rule.contains(destination)),
                "IPv6 destination {destination} should appear in IPv6 rules; actual: {rules:?}"
            );
            assert!(
                !rules.ipv4.iter().any(|rule| rule.contains(destination)),
                "IPv6 destination {destination} must not appear in IPv4 rules; actual: {rules:?}"
            );
        }
    }

    #[test]
    fn no_egress_rule_selects_an_incoming_interface() {
        let chain_name = "MXC-sel";
        let endpoints = vec![ProxyEndpoint {
            ip: "10.0.3.1".to_string(),
            port: 3128,
        }];
        let mut rules = NetworkIptablesManager::build_base_chain_rule_args(chain_name);
        rules.extend(NetworkIptablesManager::build_dns_resolution_rule_args(
            chain_name,
        ));
        rules.extend(NetworkIptablesManager::build_proxy_chain_rule_args(
            chain_name, &endpoints,
        ));
        rules.push(NetworkIptablesManager::build_loopback_accept_rule_args(
            chain_name,
        ));

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
    fn dns_resolution_is_the_documented_udp_then_tcp_pair() {
        let chain_name = "MXC-base";
        let rules = NetworkIptablesManager::build_dns_resolution_rule_args(chain_name);
        let expected = vec![
            strings(&[
                "-A", chain_name, "-p", "udp", "--dport", "53", "-j", "ACCEPT",
            ]),
            strings(&[
                "-A", chain_name, "-p", "tcp", "--dport", "53", "-j", "ACCEPT",
            ]),
        ];

        assert_eq!(
            rules, expected,
            "the DNS resolution grant should be the documented udp/tcp pair"
        );
        for (index, rule) in rules.iter().enumerate() {
            assert_rule_omits(rule, "-d", &format!("dns rule {index}"));
        }
    }

    #[test]
    fn default_network_policy_maps_to_exact_terminal_rule_vector() {
        let chain_name = "MXC-default";

        assert_eq!(
            NetworkIptablesManager::build_default_policy_rule_arg(
                chain_name,
                NetworkPolicy::Block,
                false
            ),
            strings(&["-A", chain_name, "-j", "DROP"]),
            "NetworkPolicy::Block should produce the exact DROP terminal rule"
        );
        assert_eq!(
            NetworkIptablesManager::build_default_policy_rule_arg(
                chain_name,
                NetworkPolicy::Allow,
                false
            ),
            strings(&["-A", chain_name, "-j", "ACCEPT"]),
            "NetworkPolicy::Allow should produce the exact ACCEPT terminal rule"
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
        let policy = policy_with_hosts(&[], &[]);
        let rules = NetworkIptablesManager::build_policy_rule_args("MXC-empty", &policy, false);

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
    fn unresolvable_invalid_hostname_contributes_no_destination_rules() {
        let host = "definitely-unresolvable-mxc-rulegen-spec.invalid";
        let rules =
            NetworkIptablesManager::build_host_rule_args("MXC-invalid", host, &RuleAction::Allow);

        assert!(
            rules.ipv4.is_empty(),
            "unresolvable host {host} should produce no IPv4 rules; actual: {rules:?}"
        );
        assert!(
            rules.ipv6.is_empty(),
            "unresolvable host {host} should produce no IPv6 rules; actual: {rules:?}"
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
            network_enforcement_mode: NetworkEnforcementMode::Firewall,
            default_network_policy: NetworkPolicy::Block,
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
    fn a_legacy_policy_naming_reachable_hosts_installs_the_firewall() {
        for mode in [
            NetworkEnforcementMode::Firewall,
            NetworkEnforcementMode::Both,
        ] {
            let label = format!("{mode:?}");
            let policy = ContainerPolicy {
                network_enforcement_mode: mode,
                allowed_hosts: vec!["example.com".to_string()],
                ..Default::default()
            };

            assert!(
                plan_network(&policy).installs_firewall(),
                "{label}: a 0.7 policy naming hosts it may reach must install the chain"
            );
        }
    }

    #[test]
    fn a_named_host_list_always_installs_the_chain() {
        for (allowed, blocked) in [
            (&["140.82.112.0/20"][..], &[][..]),
            (&[][..], &["140.82.112.0/20"][..]),
        ] {
            for default_policy in [NetworkPolicy::Block, NetworkPolicy::Allow] {
                let policy = ContainerPolicy {
                    default_network_policy: default_policy.clone(),
                    ..policy_with_hosts(allowed, blocked)
                };

                let plan = plan_network(&policy);

                assert!(
                    plan.installs_firewall(),
                    "a policy naming hosts to allow or block states a restriction, and \
                     the default enforcement mode must not discard it; \
                     allowed={allowed:?} blocked={blocked:?} default={default_policy:?} \
                     gave {plan:?}"
                );
            }
        }
    }

    #[test]
    fn a_legacy_policy_that_permits_nothing_is_given_no_interface() {
        let policy = ContainerPolicy {
            network_enforcement_mode: NetworkEnforcementMode::Firewall,
            network_mode_specified: true,
            default_network_policy: NetworkPolicy::Block,
            ..Default::default()
        };

        assert_eq!(
            plan_network(&policy),
            NetworkPlan::Isolated,
            "a policy that blocks outbound, allows no local network, and names no \
             proxy permits nothing, so the container is given no interface rather \
             than an unfiltered one"
        );
    }

    #[test]
    fn a_directional_policy_installs_the_firewall_under_the_capabilities_default() {
        let policy = ContainerPolicy {
            network_enforcement_mode: NetworkEnforcementMode::Capabilities,
            network_mode_specified: true,
            default_network_policy: NetworkPolicy::Allow,
            network_egress: Some(NetworkEgressPolicy {
                default: NetworkAction::Allow,
                ..Default::default()
            }),
            ..Default::default()
        };

        assert!(
            plan_network(&policy).installs_firewall(),
            "a stated 0.8 posture must install the firewall even though enforcementMode \
             is absent from the 0.8 schema and defaults to capabilities"
        );
    }

    #[test]
    fn a_v08_request_naming_no_network_fields_is_given_no_interface() {
        let policy = ContainerPolicy {
            network_egress: Some(NetworkEgressPolicy::default()),
            network_ingress: Some(wxc_common::models::NetworkIngressPolicy::default()),
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
            network_ingress: Some(wxc_common::models::NetworkIngressPolicy {
                host_loopback: NetworkAction::Allow,
                ..Default::default()
            }),
            ..Default::default()
        };

        assert!(!plan_network(&policy).omits_interface());
    }

    #[test]
    fn a_legacy_proxy_policy_installs_the_chain_and_needs_the_network() {
        let mut policy = policy_with_enforcement_mode(NetworkEnforcementMode::Firewall);
        policy.allowed_hosts.clear();
        policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("10.0.0.5".to_string(), 3128)),
            builtin_test_server: false,
        };

        assert!(plan_network(&policy).installs_firewall());
        assert!(needs_network(&policy));
    }

    // Alpine's DHCP lease arrives around ten seconds after LXC marks the container running.
    #[test]
    fn a_plan_that_starts_an_interface_demands_an_address() {
        let mut policy = policy_with_enforcement_mode(NetworkEnforcementMode::Firewall);
        policy.default_network_policy = NetworkPolicy::Allow;

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

        for directional in [false, true] {
            for egress in egress_options {
                for ingress in ingress_options {
                    for bits in 0u8..32 {
                        let policy = ContainerPolicy {
                            network_proxy: ProxyConfig {
                                builtin_test_server: bits & 1 != 0,
                                ..Default::default()
                            },
                            allowed_hosts: if bits & 2 != 0 {
                                vec!["allowed.example".to_string()]
                            } else {
                                Vec::new()
                            },
                            blocked_hosts: if bits & 4 != 0 {
                                vec!["blocked.example".to_string()]
                            } else {
                                Vec::new()
                            },
                            default_network_policy: if bits & 8 != 0 {
                                NetworkPolicy::Block
                            } else {
                                NetworkPolicy::Allow
                            },
                            allow_local_network: bits & 16 != 0,
                            network_egress: egress.map(|default| NetworkEgressPolicy {
                                default,
                                ..Default::default()
                            }),
                            network_ingress: ingress.map(|(default, host_loopback)| {
                                wxc_common::models::NetworkIngressPolicy {
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
                                "no interface means no address, yet this policy would treat a \
                                 missing address as fatal: directional={directional}, \
                                 egress={egress:?}, ingress={ingress:?}, bits={bits:05b}"
                            );
                        }
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
    fn a_proxied_policy_installs_the_chain() {
        let mut policy = policy_with_enforcement_mode(NetworkEnforcementMode::Firewall);
        policy.allowed_hosts.clear();
        policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("10.0.0.5".to_string(), 3128)),
            builtin_test_server: false,
        };

        assert!(plan_network(&policy).installs_firewall());
    }

    #[test]
    fn the_builtin_test_server_proxy_installs_the_chain_the_same_way() {
        let mut policy = policy_with_enforcement_mode(NetworkEnforcementMode::Firewall);
        policy.allowed_hosts.clear();
        policy.network_proxy = ProxyConfig {
            address: None,
            builtin_test_server: true,
        };

        assert!(
            plan_network(&policy).installs_firewall(),
            "an address-free proxy is still a proxy and must not go unenforced"
        );
    }

    fn policy_with_enforcement_mode(
        network_enforcement_mode: NetworkEnforcementMode,
    ) -> ContainerPolicy {
        ContainerPolicy {
            network_enforcement_mode,
            allowed_hosts: vec!["203.0.113.7".to_string()],
            ..Default::default()
        }
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
        let policy = policy_with_enforcement_mode(NetworkEnforcementMode::Firewall);
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
        let policy = policy_with_enforcement_mode(NetworkEnforcementMode::Firewall);
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
        let policy = policy_with_enforcement_mode(NetworkEnforcementMode::Firewall);
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
