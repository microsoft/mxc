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

    /// Apply network firewall rules based on the container policy.
    ///
    /// Resolves `allowedHosts`/`blockedHosts` (DNS + warnings happen here),
    /// delegates rule construction to the pure [`Self::build_firewall_rules`],
    /// then executes each emitted `iptables` argument vector. Keeping argv
    /// construction in a pure function (mirroring the bubblewrap `build_args`
    /// and seatbelt `build_profile` backends) is what makes the emitted rule
    /// set unit-testable without root or a live `iptables`.
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

        // Resolve host allow/block lists up front. DNS resolution and the
        // per-host warning/allow/block logging live here so that the rule
        // builder (`build_firewall_rules`) stays a pure function with no I/O
        // and is therefore unit-testable without root or a live `iptables`.
        let allowed_ips = self.resolve_hosts_logged(&policy.allowed_hosts, "Allowing", logger);
        let blocked_ips = self.resolve_hosts_logged(&policy.blocked_hosts, "Blocking", logger);

        if self.veth_interface.is_none() {
            // Without a veth interface, we cannot safely scope rules to the
            // container. `build_firewall_rules` omits the FORWARD hook in that
            // case; warn so the operator knows the chain was built but the
            // host-wide hook was intentionally skipped.
            logger.log_line(
                "Warning: No veth interface set for container. \
                 Cannot scope iptables rules. Skipping FORWARD hook.",
            );
        }

        logger.log_line(&format!("Creating iptables chain: {}", self.chain_name));
        logger.log_line(&format!(
            "Default network policy: {}",
            match policy.default_network_policy {
                NetworkPolicy::Block => "DROP",
                NetworkPolicy::Allow => "ACCEPT",
            }
        ));

        let rules = Self::build_firewall_rules(
            &self.chain_name,
            policy,
            self.veth_interface.as_deref(),
            &allowed_ips,
            &blocked_ips,
        );

        for rule in &rules {
            let argv: Vec<&str> = rule.iter().map(String::as_str).collect();
            Self::run_iptables(&argv, logger)?;
        }

        self.rules_applied = true;
        Ok(true)
    }

    /// Resolve a host allow/block list to IPv4 addresses, logging each
    /// resolved mapping and warning on unresolvable hosts. Split out of the
    /// rule builder so that the builder can stay pure (no DNS, no logging)
    /// and therefore unit-testable. `verb` is the log prefix ("Allowing" /
    /// "Blocking").
    fn resolve_hosts_logged(
        &self,
        hosts: &[String],
        verb: &str,
        logger: &mut Logger,
    ) -> Vec<String> {
        let mut out = Vec::new();
        for host in hosts {
            let ips = Self::resolve_host(host);
            if ips.is_empty() {
                logger.log_line(&format!("Warning: could not resolve host '{}'", host));
                continue;
            }
            for ip in ips {
                logger.log_line(&format!("{} host: {} ({})", verb, host, ip));
                out.push(ip);
            }
        }
        out
    }

    /// Build the ordered list of `iptables` argument vectors for `policy`.
    ///
    /// Pure: performs no process execution, no DNS resolution, and no logging.
    /// Every input — including the already-resolved `allowed_ips`/`blocked_ips`
    /// — is passed in, so this compiles and can be unit-tested on any host.
    /// This mirrors the bubblewrap `build_args` and seatbelt `build_profile`
    /// builders. `apply_firewall_rules` resolves hosts, calls this, then
    /// executes each returned vector.
    ///
    /// **Inbound control (roadmap N2 / `allowLocalNetwork`).** The chain is
    /// hooked into the host `FORWARD` chain with `-o <veth>`, so every packet
    /// it sees is destined *into* the container. After accepting loopback and
    /// established/related return traffic, a single `--state NEW` rule decides
    /// whether *new* inbound connections to the container are accepted
    /// (`allowLocalNetwork: true`) or dropped (default). This is independent of
    /// `default_network_policy`, which is applied as the terminal rule.
    fn build_firewall_rules(
        chain: &str,
        policy: &ContainerPolicy,
        veth: Option<&str>,
        allowed_ips: &[String],
        blocked_ips: &[String],
    ) -> Vec<Vec<String>> {
        fn argv(args: &[&str]) -> Vec<String> {
            args.iter().map(|s| s.to_string()).collect()
        }

        let accept = "ACCEPT";
        let drop = "DROP";
        let mut rules: Vec<Vec<String>> = Vec::new();

        // Create the container's custom chain.
        rules.push(argv(&["-N", chain]));

        // Loopback must always pass. Restored to an unconditional ACCEPT: the
        // previous code flipped this verb for `allowLocalNetwork`, but a
        // forwarded packet never arrives on `lo`, so it was a no-op — and a
        // conditional `-i lo -j DROP` would become an active hazard (breaking
        // in-container `127.0.0.1`) if the chain were ever moved to the
        // container's INPUT path.
        rules.push(argv(&["-A", chain, "-i", "lo", "-j", accept]));

        // Accept return traffic for connections the container itself opened.
        // MUST precede the NEW-inbound decision below so container-initiated
        // flows survive an inbound DROP.
        rules.push(argv(&[
            "-A", chain, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", accept,
        ]));

        // Inbound control (roadmap N2): accept or drop NEW inbound connections
        // to the container based on `allowLocalNetwork`. Independent of the
        // outbound default policy applied at the end of the chain.
        let inbound_verb = if policy.allow_local_network { accept } else { drop };
        rules.push(argv(&[
            "-A", chain, "-m", "state", "--state", "NEW", "-j", inbound_verb,
        ]));

        // Allow DNS (needed for hostname resolution).
        rules.push(argv(&["-A", chain, "-p", "udp", "--dport", "53", "-j", accept]));
        rules.push(argv(&["-A", chain, "-p", "tcp", "--dport", "53", "-j", accept]));

        // Allowed / blocked host IPs (already resolved by the caller).
        for ip in allowed_ips {
            rules.push(argv(&["-A", chain, "-d", ip, "-j", accept]));
        }
        for ip in blocked_ips {
            rules.push(argv(&["-A", chain, "-d", ip, "-j", drop]));
        }

        // Terminal default policy.
        let default_action = match policy.default_network_policy {
            NetworkPolicy::Block => drop,
            NetworkPolicy::Allow => accept,
        };
        rules.push(argv(&["-A", chain, "-j", default_action]));

        // Hook the chain into FORWARD for the container's traffic — only when a
        // veth is known, so rules stay scoped to the container.
        if let Some(iface) = veth {
            rules.push(argv(&["-I", "FORWARD", "-o", iface, "-j", chain]));
        }

        rules
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

    // ---- build_firewall_rules: pure rule-emission coverage ---------------
    //
    // These exercise the extracted pure builder directly (no root, no
    // `iptables`, no DNS), mirroring how the other backends unit-test their
    // policy→artifact builders (bubblewrap `build_args`, seatbelt
    // `build_profile`). They pin the emitted argv so the inbound verb-flip
    // that Gudge flagged is covered by CI.

    /// A `ContainerPolicy` with the two fields these tests vary; everything
    /// else defaults. Built via `..Default::default()` like the fixtures in
    /// the other backends.
    fn policy_with(allow_local: bool, default: NetworkPolicy) -> ContainerPolicy {
        ContainerPolicy {
            allow_local_network: allow_local,
            default_network_policy: default,
            ..Default::default()
        }
    }

    /// Exact-match a single emitted rule against an expected argv.
    fn is(rule: &[String], want: &[&str]) -> bool {
        rule.len() == want.len() && rule.iter().zip(want).all(|(a, b)| a == b)
    }

    fn has(rules: &[Vec<String>], want: &[&str]) -> bool {
        rules.iter().any(|r| is(r, want))
    }

    fn pos(rules: &[Vec<String>], want: &[&str]) -> Option<usize> {
        rules.iter().position(|r| is(r, want))
    }

    fn build(allow_local: bool, default: NetworkPolicy, veth: Option<&str>) -> Vec<Vec<String>> {
        NetworkIptablesManager::build_firewall_rules(
            "MXC-t",
            &policy_with(allow_local, default),
            veth,
            &[],
            &[],
        )
    }

    #[test]
    fn loopback_always_accepts_regardless_of_allow_local() {
        for allow in [true, false] {
            let rules = build(allow, NetworkPolicy::Block, Some("veth0"));
            assert!(
                has(&rules, &["-A", "MXC-t", "-i", "lo", "-j", "ACCEPT"]),
                "loopback must be an unconditional ACCEPT (allow_local={allow})"
            );
            assert!(
                !has(&rules, &["-A", "MXC-t", "-i", "lo", "-j", "DROP"]),
                "loopback must never be DROP (allow_local={allow})"
            );
        }
    }

    #[test]
    fn allow_local_true_accepts_new_inbound() {
        let rules = build(true, NetworkPolicy::Block, Some("veth0"));
        assert!(has(
            &rules,
            &["-A", "MXC-t", "-m", "state", "--state", "NEW", "-j", "ACCEPT"]
        ));
        assert!(!has(
            &rules,
            &["-A", "MXC-t", "-m", "state", "--state", "NEW", "-j", "DROP"]
        ));
    }

    #[test]
    fn allow_local_false_drops_new_inbound() {
        let rules = build(false, NetworkPolicy::Block, Some("veth0"));
        assert!(has(
            &rules,
            &["-A", "MXC-t", "-m", "state", "--state", "NEW", "-j", "DROP"]
        ));
        assert!(!has(
            &rules,
            &["-A", "MXC-t", "-m", "state", "--state", "NEW", "-j", "ACCEPT"]
        ));
    }

    #[test]
    fn established_precedes_new_inbound_decision() {
        let rules = build(false, NetworkPolicy::Block, Some("veth0"));
        let est = pos(
            &rules,
            &["-A", "MXC-t", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        )
        .expect("ESTABLISHED,RELATED rule must be emitted");
        let new = pos(
            &rules,
            &["-A", "MXC-t", "-m", "state", "--state", "NEW", "-j", "DROP"],
        )
        .expect("NEW rule must be emitted");
        assert!(est < new, "ESTABLISHED,RELATED must precede the NEW-inbound rule");
    }

    #[test]
    fn new_inbound_precedes_terminal_default() {
        let rules = build(true, NetworkPolicy::Block, Some("veth0"));
        let new = pos(
            &rules,
            &["-A", "MXC-t", "-m", "state", "--state", "NEW", "-j", "ACCEPT"],
        )
        .expect("NEW rule must be emitted");
        let def = pos(&rules, &["-A", "MXC-t", "-j", "DROP"]).expect("terminal default must be emitted");
        assert!(new < def, "NEW-inbound accept must precede the terminal default DROP");
    }

    #[test]
    fn forward_hook_present_with_veth() {
        let rules = build(true, NetworkPolicy::Block, Some("veth0"));
        assert!(has(&rules, &["-I", "FORWARD", "-o", "veth0", "-j", "MXC-t"]));
    }

    #[test]
    fn forward_hook_absent_without_veth() {
        let rules = build(true, NetworkPolicy::Block, None);
        assert!(
            !rules.iter().any(|r| r.first().map(|s| s == "-I").unwrap_or(false)),
            "no FORWARD hook may be emitted without a veth interface"
        );
    }

    #[test]
    fn dns_rules_emitted() {
        let rules = build(false, NetworkPolicy::Block, Some("veth0"));
        assert!(has(
            &rules,
            &["-A", "MXC-t", "-p", "udp", "--dport", "53", "-j", "ACCEPT"]
        ));
        assert!(has(
            &rules,
            &["-A", "MXC-t", "-p", "tcp", "--dport", "53", "-j", "ACCEPT"]
        ));
    }

    #[test]
    fn default_policy_maps_to_terminal_verb() {
        let block = build(false, NetworkPolicy::Block, Some("veth0"));
        assert!(
            has(&block, &["-A", "MXC-t", "-j", "DROP"]),
            "Block default must emit a terminal DROP"
        );
        let allow = build(false, NetworkPolicy::Allow, Some("veth0"));
        assert!(
            has(&allow, &["-A", "MXC-t", "-j", "ACCEPT"]),
            "Allow default must emit a terminal ACCEPT"
        );
    }

    #[test]
    fn allowed_and_blocked_ips_emit_dest_rules() {
        let rules = NetworkIptablesManager::build_firewall_rules(
            "MXC-t",
            &policy_with(false, NetworkPolicy::Block),
            Some("veth0"),
            &["1.2.3.4".to_string()],
            &["5.6.7.8".to_string()],
        );
        assert!(has(&rules, &["-A", "MXC-t", "-d", "1.2.3.4", "-j", "ACCEPT"]));
        assert!(has(&rules, &["-A", "MXC-t", "-d", "5.6.7.8", "-j", "DROP"]));
    }

    #[test]
    fn chain_is_created_first() {
        let rules = build(false, NetworkPolicy::Block, Some("veth0"));
        assert!(is(&rules[0], &["-N", "MXC-t"]), "chain must be created first");
    }
}
