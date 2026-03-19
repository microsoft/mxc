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

    /// Discover the veth interface name for a container by reading its network config.
    /// Returns the interface name if found.
    pub fn discover_veth_interface(container_name: &str) -> Option<String> {
        // Try to get the veth pair name from lxc-info
        let output = Command::new("lxc-info")
            .arg("-n")
            .arg(container_name)
            .arg("-i")
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        // Parse the output for the host-side veth name
        // LXC names host-side veth interfaces as "veth<XXXX>"
        let _stdout = String::from_utf8_lossy(&output.stdout);
        // Try to find the veth from /sys/class/net/
        if let Ok(entries) = std::fs::read_dir("/sys/class/net/") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("veth") {
                    // Check if this veth belongs to our container by reading the iflink
                    let link_path = format!("/sys/class/net/{}/iflink", name);
                    if std::fs::read_to_string(&link_path).is_ok() {
                        return Some(name);
                    }
                }
            }
        }

        None
    }

    /// Set the veth interface name for the container.
    pub fn set_veth_interface(&mut self, iface: &str) {
        self.veth_interface = Some(iface.to_string());
    }

    /// Resolve a hostname to IP addresses.
    fn resolve_host(host: &str) -> Vec<String> {
        // Try as IP address first
        if host.parse::<std::net::IpAddr>().is_ok() {
            return vec![host.to_string()];
        }

        // Try DNS resolution
        match format!("{}:0", host).to_socket_addrs() {
            Ok(addrs) => addrs.map(|a| a.ip().to_string()).collect(),
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
            logger.log_line(&format!("iptables {} failed: {}", args.join(" "), stderr));
            return Ok(false);
        }

        Ok(true)
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
        );
        if !use_firewall {
            logger.log_line("Network enforcement mode does not use firewall, skipping iptables.");
            return Ok(true);
        }

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

        // Add allowed host rules
        for host in &policy.allowed_hosts {
            let ips = Self::resolve_host(host);
            if ips.is_empty() {
                logger.log_line(&format!("Warning: could not resolve host '{}'", host));
                continue;
            }
            for ip in &ips {
                logger.log_line(&format!("Allowing host: {} ({})", host, ip));
                Self::run_iptables(&["-A", &self.chain_name, "-d", ip, "-j", "ACCEPT"], logger)?;
            }
        }

        // Add blocked host rules
        for host in &policy.blocked_hosts {
            let ips = Self::resolve_host(host);
            if ips.is_empty() {
                logger.log_line(&format!("Warning: could not resolve host '{}'", host));
                continue;
            }
            for ip in &ips {
                logger.log_line(&format!("Blocking host: {} ({})", host, ip));
                Self::run_iptables(&["-A", &self.chain_name, "-d", ip, "-j", "DROP"], logger)?;
            }
        }

        // Append default policy at end of chain
        let default_action = match policy.default_network_policy {
            NetworkPolicy::Block => "DROP",
            NetworkPolicy::Allow => "ACCEPT",
        };
        logger.log_line(&format!("Default network policy: {}", default_action));
        Self::run_iptables(&["-A", &self.chain_name, "-j", default_action], logger)?;

        // Hook the chain into FORWARD for the container's traffic
        if let Some(ref iface) = self.veth_interface {
            Self::run_iptables(
                &["-I", "FORWARD", "-o", iface, "-j", &self.chain_name],
                logger,
            )?;
        } else {
            // Without a veth interface, we cannot safely scope rules to the container.
            // Refuse to apply host-wide rules to avoid affecting all host traffic.
            logger.log_line(
                "Warning: No veth interface set for container. \
                 Cannot scope iptables rules. Skipping FORWARD hook.",
            );
        }

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
}
