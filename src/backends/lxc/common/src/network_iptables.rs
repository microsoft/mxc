// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Network policy enforcement via iptables rules scoped to the LXC container.
//!
//! Maps the platform-agnostic `ContainerPolicy` network settings to iptables
//! and ip6tables rules applied to the container's virtual ethernet (veth)
//! interface.

use std::net::{IpAddr, ToSocketAddrs};
use std::process::Command;

use wxc_common::logger::Logger;
use wxc_common::models::{
    ContainerPolicy, EgressRule, NetworkEnforcementMode, NetworkPolicy, Protocol, RuleAction,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpFamily {
    V4,
    V6,
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

/// Manages iptables rules for an LXC container's network policy.
pub struct NetworkIptablesManager {
    /// Chain name unique to this container (e.g., "MXC-<container-name>").
    chain_name: String,
    /// Whether rules have been applied.
    rules_applied: bool,
    /// The container's veth interface name on the host.
    veth_interface: Option<String>,
}

impl NetworkIptablesManager {
    /// Create a new manager for the given container name.
    pub fn new(container_name: &str) -> Self {
        // Sanitize container name for use in iptables chain name
        let sanitized: String = container_name
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
            .take(20)
            .collect();

        Self {
            chain_name: format!("MXC-{}", sanitized),
            rules_applied: false,
            veth_interface: None,
        }
    }

    /// Whether rules have been applied and need cleanup.
    pub fn rules_applied(&self) -> bool {
        self.rules_applied
    }

    /// Discover the host-side veth interface name for a running container.
    /// Parses the `Link:` line from `lxc-info -n <name>` output.
    /// Returns the veth interface name (e.g., "vethXXXXXX") if found.
    pub fn discover_veth_interface(container_name: &str) -> Option<String> {
        // Use lxc-info without -i to get the full output including the Link: line.
        // Output format includes: "Link:           vethXXXXXX"
        let output = Command::new("lxc-info")
            .arg("-n")
            .arg(container_name)
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse the "Link:" line from lxc-info output
        for line in stdout.lines() {
            let trimmed = line.trim();
            if let Some(link_name) = trimmed.strip_prefix("Link:") {
                let veth = link_name.trim();
                if veth.starts_with("veth") {
                    return Some(veth.to_string());
                }
            }
        }

        None
    }

    /// Set the veth interface name for the container.
    pub fn set_veth_interface(&mut self, iface: &str) {
        self.veth_interface = Some(iface.to_string());
    }

    /// Resolve a destination string to IPv4 and IPv6 firewall destinations.
    ///
    /// Bare IPv4/IPv6 literals are retained in their matching family. CIDR
    /// strings are accepted after validating that the address parses and the
    /// prefix length is within range for its family; the host bits are not
    /// required to be zero, since `iptables`/`ip6tables` apply the prefix mask
    /// themselves. Validated CIDRs are passed through unchanged. Hostnames are
    /// resolved to both A and AAAA records so IPv4 destinations route to
    /// `iptables` and IPv6 destinations route to `ip6tables`.
    fn resolve_host(host: &str) -> ResolvedDestinations {
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

        // Try as IP address first.
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

        // Try DNS resolution.
        let mut resolved = ResolvedDestinations::default();
        if let Ok(addrs) = format!("{}:0", host).to_socket_addrs() {
            for addr in addrs {
                match addr.ip() {
                    IpAddr::V4(ip) => resolved.ipv4.push(ip.to_string()),
                    IpAddr::V6(ip) => resolved.ipv6.push(ip.to_string()),
                }
            }
        }
        resolved
    }

    fn destination_family(destination: &str) -> Option<IpFamily> {
        if let Some((network, prefix)) = destination.split_once('/') {
            if network.is_empty() || prefix.is_empty() || prefix.contains('/') {
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

    /// The iptables/ip6tables `-p` protocol name for a rule in the given
    /// address family. ICMP is family-specific: IPv4 uses `icmp` while IPv6
    /// uses the `ipv6-icmp` name that ip6tables expects (ip6tables rejects
    /// `icmp`).
    fn protocol_arg(protocol: &Protocol, family: IpFamily) -> &'static str {
        match protocol {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Icmp => match family {
                IpFamily::V4 => "icmp",
                IpFamily::V6 => "ipv6-icmp",
            },
        }
    }

    /// Whether a protocol carries transport-layer ports and therefore supports
    /// `--dport`. ICMP/ICMPv6 have no ports.
    fn protocol_supports_ports(protocol: &Protocol) -> bool {
        matches!(protocol, Protocol::Tcp | Protocol::Udp)
    }

    fn rule_action_arg(action: &RuleAction) -> &'static str {
        match action {
            RuleAction::Allow => "ACCEPT",
            RuleAction::Deny => "DROP",
        }
    }

    fn build_base_chain_rule_args(chain_name: &str) -> Vec<Vec<String>> {
        vec![
            vec!["-A", chain_name, "-i", "lo", "-j", "ACCEPT"],
            vec![
                "-A",
                chain_name,
                "-m",
                "state",
                "--state",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ],
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

    fn build_default_policy_rule_arg(chain_name: &str, policy: NetworkPolicy) -> Vec<String> {
        let default_action = match policy {
            NetworkPolicy::Block => "DROP",
            NetworkPolicy::Allow => "ACCEPT",
        };
        vec!["-A", chain_name, "-j", default_action]
            .into_iter()
            .map(String::from)
            .collect()
    }

    fn build_resolved_destination_rule_args(
        chain_name: &str,
        destinations: &ResolvedDestinations,
        action: &RuleAction,
    ) -> FirewallRuleArgs {
        let mut args = FirewallRuleArgs::default();
        for destination in &destinations.ipv4 {
            args.ipv4.push(Self::build_single_rule_args(
                chain_name,
                destination,
                action,
                None,
                None,
                IpFamily::V4,
            ));
        }
        for destination in &destinations.ipv6 {
            args.ipv6.push(Self::build_single_rule_args(
                chain_name,
                destination,
                action,
                None,
                None,
                IpFamily::V6,
            ));
        }
        args
    }

    fn build_destination_rule_args(
        chain_name: &str,
        destination: &str,
        action: &RuleAction,
        protocols: &[Protocol],
        ports: &[u16],
    ) -> FirewallRuleArgs {
        let Some(family) = Self::destination_family(destination) else {
            return FirewallRuleArgs::default();
        };

        let protocol_options: Vec<Option<Protocol>> = if protocols.is_empty() && ports.is_empty() {
            vec![None]
        } else if protocols.is_empty() {
            vec![Some(Protocol::Tcp), Some(Protocol::Udp)]
        } else {
            protocols.iter().cloned().map(Some).collect()
        };
        let port_options: Vec<Option<u16>> = if ports.is_empty() {
            vec![None]
        } else {
            ports.iter().copied().map(Some).collect()
        };

        // ICMP/ICMPv6 carry no ports, so collapse the port dimension for those
        // protocols. This avoids emitting an invalid `--dport` on an ICMP rule
        // (which iptables/ip6tables reject) and prevents duplicating the same
        // portless rule once per configured port.
        let portless = [None];
        let mut args = FirewallRuleArgs::default();
        for protocol in &protocol_options {
            let ports_for_protocol: &[Option<u16>] = match protocol.as_ref() {
                Some(p) if !Self::protocol_supports_ports(p) => &portless,
                _ => &port_options,
            };
            for port in ports_for_protocol {
                let rule = Self::build_single_rule_args(
                    chain_name,
                    destination,
                    action,
                    protocol.as_ref(),
                    *port,
                    family,
                );
                match family {
                    IpFamily::V4 => args.ipv4.push(rule),
                    IpFamily::V6 => args.ipv6.push(rule),
                }
            }
        }
        args
    }

    fn build_single_rule_args(
        chain_name: &str,
        destination: &str,
        action: &RuleAction,
        protocol: Option<&Protocol>,
        port: Option<u16>,
        family: IpFamily,
    ) -> Vec<String> {
        let mut args = vec![
            "-A".to_string(),
            chain_name.to_string(),
            "-d".to_string(),
            destination.to_string(),
        ];
        if let Some(protocol) = protocol {
            args.push("-p".to_string());
            args.push(Self::protocol_arg(protocol, family).to_string());
        }
        // `--dport` is only valid for port-bearing protocols (TCP/UDP); never
        // emit it for ICMP/ICMPv6 (or when no protocol is set), where it would
        // make iptables/ip6tables reject the rule.
        let port_supported = protocol.is_some_and(Self::protocol_supports_ports);
        if let Some(port) = port.filter(|_| port_supported) {
            args.push("--dport".to_string());
            args.push(port.to_string());
        }
        args.push("-j".to_string());
        args.push(Self::rule_action_arg(action).to_string());
        args
    }

    fn build_legacy_host_rule_args(
        chain_name: &str,
        host: &str,
        action: &RuleAction,
    ) -> FirewallRuleArgs {
        let destinations = Self::resolve_host(host);
        Self::build_resolved_destination_rule_args(chain_name, &destinations, action)
    }

    fn build_egress_rule_args(chain_name: &str, rule: &EgressRule) -> FirewallRuleArgs {
        let mut args = FirewallRuleArgs::default();
        for destination in &rule.destinations {
            args.extend(Self::build_destination_rule_args(
                chain_name,
                destination,
                &rule.action,
                &rule.protocols,
                &rule.ports,
            ));
        }
        args
    }

    /// Build the allow/deny rule args for a container policy.
    ///
    /// NOTE — interim ordering (tracked by AB#62830341): rules are emitted in
    /// allow-list, then block-list, then `egress_rules` (author) order, and
    /// iptables/ip6tables apply first-match-wins within the chain. This
    /// model-1 change therefore does **not** yet implement deny-precedence:
    /// a destination present in both the allow and block lists is ACCEPTed,
    /// and `egress_rules` carry no deny priority. Reconciling this to the
    /// GA "deny-wins" ordering across the combined allow/deny model is owned
    /// by net-model-2 (AB#62830341); until then callers must not assume
    /// deny-precedence.
    fn build_policy_rule_args(chain_name: &str, policy: &ContainerPolicy) -> FirewallRuleArgs {
        let mut args = FirewallRuleArgs::default();
        for host in &policy.allowed_hosts {
            args.extend(Self::build_legacy_host_rule_args(
                chain_name,
                host,
                &RuleAction::Allow,
            ));
        }
        for host in &policy.blocked_hosts {
            args.extend(Self::build_legacy_host_rule_args(
                chain_name,
                host,
                &RuleAction::Deny,
            ));
        }
        for rule in &policy.egress_rules {
            args.extend(Self::build_egress_rule_args(chain_name, rule));
        }
        args
    }

    /// Run an iptables command and return success/failure.
    fn run_iptables(args: &[&str], logger: &mut Logger) -> Result<bool, String> {
        Self::run_firewall_command("iptables", args, logger)
    }

    /// Run an ip6tables command and return success/failure.
    fn run_ip6tables(args: &[&str], logger: &mut Logger) -> Result<bool, String> {
        Self::run_firewall_command("ip6tables", args, logger)
    }

    /// Probe whether `ip6tables` can be used on this host.
    ///
    /// Runs a harmless, read-only `ip6tables -S` (list the filter table).
    /// This fails both when the binary is missing (IPv4-only images) and when
    /// the kernel has IPv6 disabled (`ip6tables` reports the table cannot be
    /// initialized). In either case the caller skips the parallel v6 chain and
    /// warns, instead of aborting an otherwise-valid IPv4 policy — a hard
    /// dependency on ip6tables would break pure-IPv4 hosts that worked before
    /// dual-stack support was added.
    fn ip6tables_available(logger: &mut Logger) -> bool {
        match Command::new("ip6tables").arg("-S").output() {
            Ok(output) if output.status.success() => true,
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                logger.log_line(&format!(
                    "ip6tables unavailable ({}); skipping IPv6 firewall rules.",
                    stderr.trim()
                ));
                false
            }
            Err(e) => {
                logger.log_line(&format!(
                    "ip6tables not found ({}); skipping IPv6 firewall rules.",
                    e
                ));
                false
            }
        }
    }

    fn run_firewall_command(
        command: &str,
        args: &[&str],
        logger: &mut Logger,
    ) -> Result<bool, String> {
        let output = Command::new(command)
            .args(args)
            .output()
            .map_err(|e| format!("Failed to run {}: {}", command, e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let msg = format!("{} {} failed: {}", command, args.join(" "), stderr);
            logger.log_line(&msg);
            return Err(msg);
        }

        Ok(true)
    }

    fn run_iptables_rule_args(args: &[Vec<String>], logger: &mut Logger) -> Result<(), String> {
        for rule in args {
            let rule_args: Vec<&str> = rule.iter().map(String::as_str).collect();
            Self::run_iptables(&rule_args, logger)?;
        }
        Ok(())
    }

    fn run_ip6tables_rule_args(args: &[Vec<String>], logger: &mut Logger) -> Result<(), String> {
        for rule in args {
            let rule_args: Vec<&str> = rule.iter().map(String::as_str).collect();
            Self::run_ip6tables(&rule_args, logger)?;
        }
        Ok(())
    }

    /// Apply network firewall rules based on the container policy.
    ///
    /// On any failure after the per-container chains are created, the partially
    /// applied state is torn down before the error is returned, so a retry does
    /// not trip over a leftover `MXC-<name>` chain ("chain already exists") and
    /// leak rules permanently.
    pub fn apply_firewall_rules(
        &mut self,
        policy: &ContainerPolicy,
        logger: &mut Logger,
    ) -> Result<bool, String> {
        // Skip if network enforcement doesn't use firewall
        let use_firewall = matches!(
            policy.network_enforcement_mode,
            NetworkEnforcementMode::Firewall | NetworkEnforcementMode::Both
        );
        if !use_firewall {
            logger.log_line("Network enforcement mode does not use firewall, skipping iptables.");
            return Ok(true);
        }

        match self.apply_firewall_rules_inner(policy, logger) {
            Ok(()) => {
                self.rules_applied = true;
                Ok(true)
            }
            Err(e) => {
                // Roll back whatever was created before the failure. Without
                // this, `remove_firewall_rules` short-circuits on
                // `rules_applied == false` and the orphan chain(s) survive, so
                // the next attempt fails permanently on `-N` ("chain already
                // exists") until someone cleans up by hand.
                logger.log_line(&format!(
                    "Firewall setup failed: {}. Cleaning up partial iptables state.",
                    e
                ));
                self.teardown_chains(logger);
                Err(e)
            }
        }
    }

    /// Fallible body of [`Self::apply_firewall_rules`]. Kept separate so the
    /// public method can roll back partial state on the error path.
    fn apply_firewall_rules_inner(
        &self,
        policy: &ContainerPolicy,
        logger: &mut Logger,
    ) -> Result<(), String> {
        logger.log_line(&format!(
            "Creating iptables/ip6tables chain: {}",
            self.chain_name
        ));

        // Probe ip6tables once. On IPv4-only hosts (binary absent or IPv6
        // disabled in the kernel) enforce the v4 policy and skip the v6 chain
        // rather than failing setup for a policy that worked before dual-stack.
        let ipv6_enabled = Self::ip6tables_available(logger);

        // Create custom chains.
        Self::run_iptables(&["-N", &self.chain_name], logger)?;
        if ipv6_enabled {
            Self::run_ip6tables(&["-N", &self.chain_name], logger)?;
        }

        let base_rules = Self::build_base_chain_rule_args(&self.chain_name);
        Self::run_iptables_rule_args(&base_rules, logger)?;
        if ipv6_enabled {
            Self::run_ip6tables_rule_args(&base_rules, logger)?;
        }

        for host in policy
            .allowed_hosts
            .iter()
            .chain(policy.blocked_hosts.iter())
        {
            if Self::resolve_host(host).is_empty() {
                logger.log_line(&format!("Warning: could not resolve host '{}'", host));
            }
        }

        let policy_rules = Self::build_policy_rule_args(&self.chain_name, policy);
        Self::run_iptables_rule_args(&policy_rules.ipv4, logger)?;
        if ipv6_enabled {
            Self::run_ip6tables_rule_args(&policy_rules.ipv6, logger)?;
        } else if !policy_rules.ipv6.is_empty() {
            logger.log_line(&format!(
                "Warning: {} IPv6 firewall rule(s) not applied because ip6tables \
                 is unavailable; IPv6 egress is unfiltered on this host.",
                policy_rules.ipv6.len()
            ));
        }

        // Append default policy at end of each chain.
        let default_rule = Self::build_default_policy_rule_arg(
            &self.chain_name,
            policy.default_network_policy.clone(),
        );
        let default_args: Vec<&str> = default_rule.iter().map(String::as_str).collect();
        let default_action = default_args.last().copied().unwrap_or("ACCEPT");
        logger.log_line(&format!("Default network policy: {}", default_action));
        Self::run_iptables(&default_args, logger)?;
        if ipv6_enabled {
            Self::run_ip6tables(&default_args, logger)?;
        }

        // Hook the chains into FORWARD for the container's egress traffic.
        // Packets originating in the container arrive at the host on the
        // host-side veth, so they match FORWARD by input interface (`-i`);
        // `-o` would instead match traffic flowing toward the container.
        if let Some(ref iface) = self.veth_interface {
            Self::run_iptables(
                &["-I", "FORWARD", "-i", iface, "-j", &self.chain_name],
                logger,
            )?;
            if ipv6_enabled {
                Self::run_ip6tables(
                    &["-I", "FORWARD", "-i", iface, "-j", &self.chain_name],
                    logger,
                )?;
            }
        } else {
            // Without a veth interface, we cannot safely scope rules to the container.
            // Refuse to apply host-wide rules to avoid affecting all host traffic.
            logger.log_line(
                "Warning: No veth interface set for container. \
                 Cannot scope iptables rules. Skipping FORWARD hook.",
            );
        }

        Ok(())
    }

    /// Best-effort removal of the FORWARD hooks and per-container chains in
    /// both tables. Safe to call even when only part of the state was created
    /// (a missing rule/chain just makes the individual `-D`/`-F`/`-X` call
    /// no-op), so it doubles as the rollback path for a failed apply.
    fn teardown_chains(&self, logger: &mut Logger) {
        // Remove from FORWARD (only if we had a veth interface and hooked it).
        // Must match the `-i` direction used at insertion so the delete finds
        // the rule; a `-o` delete would leak the FORWARD hook.
        if let Some(ref iface) = self.veth_interface {
            let _ = Self::run_iptables(
                &["-D", "FORWARD", "-i", iface, "-j", &self.chain_name],
                logger,
            );
            let _ = Self::run_ip6tables(
                &["-D", "FORWARD", "-i", iface, "-j", &self.chain_name],
                logger,
            );
        }

        // Flush and delete the chains.
        let _ = Self::run_iptables(&["-F", &self.chain_name], logger);
        let _ = Self::run_iptables(&["-X", &self.chain_name], logger);
        let _ = Self::run_ip6tables(&["-F", &self.chain_name], logger);
        let _ = Self::run_ip6tables(&["-X", &self.chain_name], logger);
    }

    /// Remove all iptables/ip6tables rules created by this manager.
    pub fn remove_firewall_rules(&mut self, logger: &mut Logger) -> Result<(), String> {
        if !self.rules_applied {
            return Ok(());
        }

        logger.log_line(&format!(
            "Removing iptables/ip6tables chain: {}",
            self.chain_name
        ));

        self.teardown_chains(logger);

        self.rules_applied = false;
        Ok(())
    }

    /// Best-effort cleanup of any iptables state the runner may have
    /// installed for a container, used when the original
    /// `NetworkIptablesManager` instance isn't reachable (e.g. signal-time
    /// cleanup from the watchdog thread). Builds a fresh manager pointed at
    /// the same chain name so `remove_firewall_rules` does its work
    /// regardless of whether rules were actually installed; iptables itself
    /// is the source of truth.
    pub fn force_cleanup(container_name: &str, veth_interface: Option<&str>, logger: &mut Logger) {
        let mut mgr = Self::new(container_name);
        if let Some(v) = veth_interface {
            mgr.set_veth_interface(v);
        }
        // Bypass the rules_applied gate; if there's nothing to remove the
        // iptables `-D`/`-F`/`-X` calls just no-op.
        mgr.rules_applied = true;
        let _ = mgr.remove_firewall_rules(logger);
    }
}

impl Drop for NetworkIptablesManager {
    fn drop(&mut self) {
        if self.rules_applied {
            let mut logger = wxc_common::logger::Logger::new(wxc_common::logger::Mode::Buffer);
            let _ = self.remove_firewall_rules(&mut logger);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| arg.to_string()).collect()
    }

    #[test]
    fn chain_name_sanitization() {
        let mgr = NetworkIptablesManager::new("my-container_123");
        assert_eq!(mgr.chain_name, "MXC-my-container_123");
    }

    #[test]
    fn chain_name_truncation() {
        let long_name = "a".repeat(50);
        let mgr = NetworkIptablesManager::new(&long_name);
        // 4 chars for "MXC-" + 20 chars max
        assert!(mgr.chain_name.len() <= 24);
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
    fn resolve_host_retains_ipv4_mapped_ipv6_literal() {
        let ips = NetworkIptablesManager::resolve_host("::ffff:127.0.0.1");
        assert!(ips.ipv4.is_empty());
        assert_eq!(ips.ipv6, vec!["::ffff:127.0.0.1"]);
    }

    #[test]
    fn resolve_host_keeps_ipv4_literal_unchanged() {
        // Round-trip: v4 literals must pass through verbatim.
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
    fn build_egress_rule_args_routes_ipv4_to_iptables_args() {
        let rule = EgressRule {
            destinations: vec!["140.82.112.4".to_string()],
            action: RuleAction::Allow,
            ..Default::default()
        };

        let args = NetworkIptablesManager::build_egress_rule_args("MXC-test", &rule);

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
    fn build_egress_rule_args_routes_ipv6_to_ip6tables_args() {
        let rule = EgressRule {
            destinations: vec!["2606:50c0:8000::64".to_string()],
            action: RuleAction::Deny,
            ..Default::default()
        };

        let args = NetworkIptablesManager::build_egress_rule_args("MXC-test", &rule);

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
    fn build_egress_rule_args_passes_cidr_through() {
        let rule = EgressRule {
            destinations: vec!["140.82.112.0/20".to_string(), "2606:50c0::/32".to_string()],
            action: RuleAction::Allow,
            ..Default::default()
        };

        let args = NetworkIptablesManager::build_egress_rule_args("MXC-test", &rule);

        assert_eq!(
            args.ipv4,
            vec![strings(&[
                "-A",
                "MXC-test",
                "-d",
                "140.82.112.0/20",
                "-j",
                "ACCEPT",
            ])]
        );
        assert_eq!(
            args.ipv6,
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
    fn build_egress_rule_args_adds_protocol_and_dport() {
        let rule = EgressRule {
            destinations: vec!["140.82.112.4".to_string()],
            ports: vec![443],
            protocols: vec![Protocol::Tcp],
            action: RuleAction::Allow,
        };

        let args = NetworkIptablesManager::build_egress_rule_args("MXC-test", &rule);

        assert_eq!(
            args.ipv4,
            vec![strings(&[
                "-A",
                "MXC-test",
                "-d",
                "140.82.112.4",
                "-p",
                "tcp",
                "--dport",
                "443",
                "-j",
                "ACCEPT",
            ])]
        );
    }

    #[test]
    fn build_egress_rule_args_cross_products_multi_port_multi_proto() {
        let rule = EgressRule {
            destinations: vec!["140.82.112.4".to_string()],
            ports: vec![80, 443],
            protocols: vec![Protocol::Tcp, Protocol::Udp],
            action: RuleAction::Allow,
        };

        let args = NetworkIptablesManager::build_egress_rule_args("MXC-test", &rule);

        assert_eq!(
            args.ipv4,
            vec![
                strings(&[
                    "-A",
                    "MXC-test",
                    "-d",
                    "140.82.112.4",
                    "-p",
                    "tcp",
                    "--dport",
                    "80",
                    "-j",
                    "ACCEPT",
                ]),
                strings(&[
                    "-A",
                    "MXC-test",
                    "-d",
                    "140.82.112.4",
                    "-p",
                    "tcp",
                    "--dport",
                    "443",
                    "-j",
                    "ACCEPT",
                ]),
                strings(&[
                    "-A",
                    "MXC-test",
                    "-d",
                    "140.82.112.4",
                    "-p",
                    "udp",
                    "--dport",
                    "80",
                    "-j",
                    "ACCEPT",
                ]),
                strings(&[
                    "-A",
                    "MXC-test",
                    "-d",
                    "140.82.112.4",
                    "-p",
                    "udp",
                    "--dport",
                    "443",
                    "-j",
                    "ACCEPT",
                ]),
            ]
        );
        assert!(args.ipv6.is_empty());
    }

    #[test]
    fn build_policy_rule_args_includes_legacy_and_egress_rules() {
        let policy = ContainerPolicy {
            allowed_hosts: vec!["10.0.0.1".to_string()],
            blocked_hosts: vec!["2606:50c0::/32".to_string()],
            egress_rules: vec![EgressRule {
                destinations: vec!["192.0.2.0/24".to_string()],
                action: RuleAction::Deny,
                ..Default::default()
            }],
            ..Default::default()
        };

        let args = NetworkIptablesManager::build_policy_rule_args("MXC-test", &policy);

        assert_eq!(
            args.ipv4,
            vec![
                strings(&["-A", "MXC-test", "-d", "10.0.0.1", "-j", "ACCEPT"]),
                strings(&["-A", "MXC-test", "-d", "192.0.2.0/24", "-j", "DROP"]),
            ]
        );
        assert_eq!(
            args.ipv6,
            vec![strings(&[
                "-A",
                "MXC-test",
                "-d",
                "2606:50c0::/32",
                "-j",
                "DROP",
            ])]
        );
    }

    #[test]
    fn build_egress_rule_args_uses_ipv4_icmp_protocol_name() {
        let rule = EgressRule {
            destinations: vec!["140.82.112.4".to_string()],
            protocols: vec![Protocol::Icmp],
            action: RuleAction::Allow,
            ..Default::default()
        };

        let args = NetworkIptablesManager::build_egress_rule_args("MXC-test", &rule);

        assert!(args.ipv6.is_empty());
        assert_eq!(
            args.ipv4,
            vec![strings(&[
                "-A",
                "MXC-test",
                "-d",
                "140.82.112.4",
                "-p",
                "icmp",
                "-j",
                "ACCEPT",
            ])]
        );
    }

    #[test]
    fn build_egress_rule_args_uses_ipv6_icmp_protocol_name() {
        // ip6tables requires the `ipv6-icmp` protocol name; `icmp` is rejected.
        let rule = EgressRule {
            destinations: vec!["2606:50c0::1".to_string()],
            protocols: vec![Protocol::Icmp],
            action: RuleAction::Allow,
            ..Default::default()
        };

        let args = NetworkIptablesManager::build_egress_rule_args("MXC-test", &rule);

        assert!(args.ipv4.is_empty());
        assert_eq!(
            args.ipv6,
            vec![strings(&[
                "-A",
                "MXC-test",
                "-d",
                "2606:50c0::1",
                "-p",
                "ipv6-icmp",
                "-j",
                "ACCEPT",
            ])]
        );
    }

    #[test]
    fn build_egress_rule_args_omits_dport_for_icmp_even_with_ports() {
        // ICMP has no transport ports: a configured port list must not emit
        // `--dport` and must not fan out into one rule per port.
        let rule = EgressRule {
            destinations: vec!["140.82.112.4".to_string()],
            ports: vec![80, 443],
            protocols: vec![Protocol::Icmp],
            action: RuleAction::Allow,
        };

        let args = NetworkIptablesManager::build_egress_rule_args("MXC-test", &rule);

        assert_eq!(
            args.ipv4,
            vec![strings(&[
                "-A",
                "MXC-test",
                "-d",
                "140.82.112.4",
                "-p",
                "icmp",
                "-j",
                "ACCEPT",
            ])]
        );
        assert!(args.ipv6.is_empty());
    }
}
