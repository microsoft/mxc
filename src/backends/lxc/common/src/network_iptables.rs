// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Network policy enforcement via iptables rules scoped to the LXC container.
//!
//! Maps the platform-agnostic `ContainerPolicy` network settings to iptables
//! rules applied to the container's virtual ethernet (veth) interface.

use std::net::ToSocketAddrs;
use std::process::Command;

use wxc_common::logger::Logger;
use wxc_common::models::{ContainerPolicy, NetworkEnforcementMode, NetworkPolicy};

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProxyEndpoint {
    ip: String,
    port: u16,
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

    /// Resolve a hostname to IPv4 addresses.
    ///
    /// IPv6 records (AAAA from DNS, or IPv6 literals like `"::1"` /
    /// IPv4-mapped IPv6 like `"::ffff:127.0.0.1"`) are silently dropped
    /// because `apply_firewall_rules` only invokes `iptables` (the IPv4
    /// tool), which rejects IPv6 destinations. Full dual-stack support
    /// via parallel `ip6tables` rules would require a separate change.
    /// A host that resolves only to AAAA records will return an empty
    /// vec, meaning no allow/deny rule is emitted and the host is
    /// effectively unreachable from the sandbox under firewall mode.
    fn resolve_host(host: &str) -> Vec<String> {
        // Try as IP address first
        if let Ok(addr) = host.parse::<std::net::IpAddr>() {
            return if addr.is_ipv4() {
                vec![host.to_string()]
            } else {
                Vec::new()
            };
        }

        // Try DNS resolution
        match format!("{}:0", host).to_socket_addrs() {
            Ok(addrs) => addrs
                .map(|a| a.ip())
                .filter(|ip| ip.is_ipv4())
                .map(|ip| ip.to_string())
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Run an iptables command and return success/failure.
    fn run_iptables(args: &[&str], logger: &mut Logger) -> Result<bool, String> {
        let output = Command::new("iptables")
            .args(args)
            .output()
            .map_err(|e| format!("Failed to run iptables: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let msg = format!("iptables {} failed: {}", args.join(" "), stderr);
            logger.log_line(&msg);
            return Err(msg);
        }

        Ok(true)
    }

    fn run_iptables_args(args: &[String], logger: &mut Logger) -> Result<bool, String> {
        let refs = args.iter().map(String::as_str).collect::<Vec<_>>();
        Self::run_iptables(&refs, logger)
    }

    fn build_ordered_egress_rules(
        chain_name: &str,
        blocked_ips: &[String],
        allowed_ips: &[String],
        default_policy: NetworkPolicy,
        proxy_endpoints: &[ProxyEndpoint],
    ) -> Vec<Vec<String>> {
        let mut rules = Vec::new();

        if !proxy_endpoints.is_empty() {
            for endpoint in proxy_endpoints {
                rules.push(vec![
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
                ]);
            }
            rules.push(vec![
                "-A".to_string(),
                chain_name.to_string(),
                "-j".to_string(),
                "DROP".to_string(),
            ]);
            return rules;
        }

        for ip in blocked_ips {
            rules.push(vec![
                "-A".to_string(),
                chain_name.to_string(),
                "-d".to_string(),
                ip.clone(),
                "-j".to_string(),
                "DROP".to_string(),
            ]);
        }

        for ip in allowed_ips {
            rules.push(vec![
                "-A".to_string(),
                chain_name.to_string(),
                "-d".to_string(),
                ip.clone(),
                "-j".to_string(),
                "ACCEPT".to_string(),
            ]);
        }

        let default_action = match default_policy {
            NetworkPolicy::Block => "DROP",
            NetworkPolicy::Allow => "ACCEPT",
        };
        rules.push(vec![
            "-A".to_string(),
            chain_name.to_string(),
            "-j".to_string(),
            default_action.to_string(),
        ]);

        rules
    }

    fn resolve_policy_hosts(hosts: &[String], action: &str, logger: &mut Logger) -> Vec<String> {
        let mut resolved = Vec::new();

        for host in hosts {
            let ips = Self::resolve_host(host);
            if ips.is_empty() {
                logger.log_line(&format!("Warning: could not resolve host '{}'", host));
                continue;
            }
            for ip in ips {
                logger.log_line(&format!("{} host: {} ({})", action, host, ip));
                resolved.push(ip);
            }
        }

        resolved
    }

    fn resolve_proxy_endpoints(
        policy: &ContainerPolicy,
        logger: &mut Logger,
    ) -> Result<Vec<ProxyEndpoint>, String> {
        if !policy.network_proxy.is_enabled() {
            return Ok(Vec::new());
        }

        let address = policy.network_proxy.address.as_ref().ok_or_else(|| {
            "Network proxy is enabled but no proxy address is configured".to_string()
        })?;

        if address.port() == 0 {
            return Err("Network proxy port must be between 1 and 65535".to_string());
        }

        let ips = Self::resolve_host(address.host());
        if ips.is_empty() {
            return Err(format!(
                "Could not resolve network proxy host '{}'",
                address.host()
            ));
        }

        Ok(ips
            .into_iter()
            .map(|ip| {
                logger.log_line(&format!(
                    "Allowing network proxy egress: {}:{} ({})",
                    address.host(),
                    address.port(),
                    ip
                ));
                ProxyEndpoint {
                    ip,
                    port: address.port(),
                }
            })
            .collect())
    }

    /// Apply network firewall rules based on the container policy.
    pub fn apply_firewall_rules(
        &mut self,
        policy: &ContainerPolicy,
        logger: &mut Logger,
    ) -> Result<bool, String> {
        // Skip if network enforcement doesn't use firewall
        let use_firewall = matches!(
            policy.network_enforcement_mode,
            NetworkEnforcementMode::Firewall | NetworkEnforcementMode::Both
        ) || policy.network_proxy.is_enabled();
        if !use_firewall {
            logger.log_line("Network enforcement mode does not use firewall, skipping iptables.");
            return Ok(true);
        }

        let Some(ref iface) = self.veth_interface else {
            return Err(
                "No veth interface set for container; cannot scope iptables FORWARD hook"
                    .to_string(),
            );
        };

        logger.log_line(&format!("Creating iptables chain: {}", self.chain_name));

        // Create custom chain
        Self::run_iptables(&["-N", &self.chain_name], logger)?;

        // Always allow loopback and established connections
        Self::run_iptables(
            &["-A", &self.chain_name, "-i", "lo", "-j", "ACCEPT"],
            logger,
        )?;
        Self::run_iptables(
            &[
                "-A",
                &self.chain_name,
                "-m",
                "state",
                "--state",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ],
            logger,
        )?;

        // Allow DNS (needed for hostname resolution)
        Self::run_iptables(
            &[
                "-A",
                &self.chain_name,
                "-p",
                "udp",
                "--dport",
                "53",
                "-j",
                "ACCEPT",
            ],
            logger,
        )?;
        Self::run_iptables(
            &[
                "-A",
                &self.chain_name,
                "-p",
                "tcp",
                "--dport",
                "53",
                "-j",
                "ACCEPT",
            ],
            logger,
        )?;

        let proxy_endpoints = Self::resolve_proxy_endpoints(policy, logger)?;
        let (blocked_ips, allowed_ips) = if proxy_endpoints.is_empty() {
            (
                Self::resolve_policy_hosts(&policy.blocked_hosts, "Blocking", logger),
                Self::resolve_policy_hosts(&policy.allowed_hosts, "Allowing", logger),
            )
        } else {
            logger.log_line(
                "Network proxy enabled: allowing proxy egress only and dropping all other outbound traffic.",
            );
            (Vec::new(), Vec::new())
        };

        for args in Self::build_ordered_egress_rules(
            &self.chain_name,
            &blocked_ips,
            &allowed_ips,
            policy.default_network_policy.clone(),
            &proxy_endpoints,
        ) {
            Self::run_iptables_args(&args, logger)?;
        }

        // Hook the chain into FORWARD for the container's traffic
        Self::run_iptables(
            &["-I", "FORWARD", "-o", iface, "-j", &self.chain_name],
            logger,
        )?;

        self.rules_applied = true;
        Ok(true)
    }

    /// Remove all iptables rules created by this manager.
    pub fn remove_firewall_rules(&mut self, logger: &mut Logger) -> Result<(), String> {
        if !self.rules_applied {
            return Ok(());
        }

        logger.log_line(&format!("Removing iptables chain: {}", self.chain_name));

        // Remove from FORWARD (only if we had a veth interface and hooked it)
        if let Some(ref iface) = self.veth_interface {
            let _ = Self::run_iptables(
                &["-D", "FORWARD", "-o", iface, "-j", &self.chain_name],
                logger,
            );
        }

        // Flush and delete the chain
        let _ = Self::run_iptables(&["-F", &self.chain_name], logger);
        let _ = Self::run_iptables(&["-X", &self.chain_name], logger);

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
        assert_eq!(ips, vec!["127.0.0.1"]);
    }

    #[test]
    fn resolve_host_drops_ipv6_literal() {
        // IPv6 literals must be silently dropped — `iptables` (v4) would
        // reject them and fail the whole `apply_firewall_rules` call.
        let ips = NetworkIptablesManager::resolve_host("::1");
        assert!(
            ips.is_empty(),
            "expected empty vec for IPv6 literal, got {:?}",
            ips
        );
    }

    #[test]
    fn resolve_host_drops_ipv4_mapped_ipv6_literal() {
        // `::ffff:127.0.0.1` parses as `IpAddr::V6` and is the v6
        // wire-format encoding of an v4 address — `iptables` would
        // still reject it as a v6 destination, so we drop it.
        let ips = NetworkIptablesManager::resolve_host("::ffff:127.0.0.1");
        assert!(
            ips.is_empty(),
            "expected empty vec for v4-mapped-v6 literal, got {:?}",
            ips
        );
    }

    #[test]
    fn resolve_host_keeps_ipv4_literal_unchanged() {
        // Round-trip: v4 literals must pass through verbatim — the
        // IPv4-only filter must not regress the happy path.
        let ips = NetworkIptablesManager::resolve_host("10.0.0.1");
        assert_eq!(ips, vec!["10.0.0.1"]);
    }

    #[test]
    fn firewall_mode_without_veth_fails_fast() {
        let mut mgr = NetworkIptablesManager::new("no-veth");
        let policy = ContainerPolicy {
            network_enforcement_mode: NetworkEnforcementMode::Firewall,
            ..Default::default()
        };
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);

        let err = mgr.apply_firewall_rules(&policy, &mut logger).unwrap_err();

        assert!(err.contains("No veth interface set"));
        assert!(!mgr.rules_applied());
    }

    #[test]
    fn ordered_egress_rules_put_deny_before_allow() {
        let blocked = vec!["10.0.0.5".to_string()];
        let allowed = vec!["10.0.0.0".to_string()];

        let rules = NetworkIptablesManager::build_ordered_egress_rules(
            "MXC-test",
            &blocked,
            &allowed,
            NetworkPolicy::Block,
            &[],
        );

        assert_eq!(
            rules,
            vec![
                vec!["-A", "MXC-test", "-d", "10.0.0.5", "-j", "DROP"],
                vec!["-A", "MXC-test", "-d", "10.0.0.0", "-j", "ACCEPT"],
                vec!["-A", "MXC-test", "-j", "DROP"],
            ]
        );
    }

    #[test]
    fn proxy_egress_rules_allow_only_proxy_then_drop() {
        let blocked = vec!["10.0.0.5".to_string()];
        let allowed = vec!["10.0.0.0".to_string()];
        let proxy = vec![ProxyEndpoint {
            ip: "127.0.0.1".to_string(),
            port: 8080,
        }];

        let rules = NetworkIptablesManager::build_ordered_egress_rules(
            "MXC-test",
            &blocked,
            &allowed,
            NetworkPolicy::Allow,
            &proxy,
        );

        assert_eq!(
            rules,
            vec![
                vec![
                    "-A",
                    "MXC-test",
                    "-p",
                    "tcp",
                    "-d",
                    "127.0.0.1",
                    "--dport",
                    "8080",
                    "-j",
                    "ACCEPT",
                ],
                vec!["-A", "MXC-test", "-j", "DROP"],
            ]
        );
    }
}
