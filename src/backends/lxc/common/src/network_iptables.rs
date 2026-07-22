// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Inbound network policy enforcement via iptables, scoped to the container's
//! own network namespace.
//!
//! Implements the GA `ingress.hostLoopback` control for the LXC backend (and,
//! when a netns target is supplied, Bubblewrap): host-to-container and
//! external inbound traffic is dropped by default; `allowLocalNetwork` /
//! `ingress.hostLoopback: "allow"` opens new inbound connections to the
//! container's listening sockets.
//!
//! **Why the container netns.** A packet destined to a container socket
//! traverses the *container's* `INPUT` chain, inside the container's network
//! namespace — never the host's `INPUT` (the host only ever sees such packets
//! in `FORWARD`, if it routes them). So the rules are executed with
//! `nsenter -t <init-pid> -n iptables …`, landing them in the container's
//! netfilter tables. This matches the GA networking spec, which enforces LXC
//! ingress "via iptables INPUT" (`docs/sandbox-policy/v2/networking.md`).
//! Egress (allow/deny lists, DNS, proxy) is a separate control and is
//! intentionally not handled here — GA ingress is loopback-only with no CIDR
//! peers.

use std::process::Command;

use wxc_common::logger::Logger;
use wxc_common::models::{ContainerPolicy, NetworkEnforcementMode};

/// Manages the container's inbound iptables `INPUT` chain.
pub struct NetworkIptablesManager {
    /// Chain name unique to this container (e.g., "MXC-<container-name>").
    chain_name: String,
    /// Whether rules have been applied.
    rules_applied: bool,
    /// PID of the container's init process. Used to enter the container's
    /// network namespace (`nsenter -t <pid> -n`) so the `INPUT` rules land in
    /// the *container's* netfilter tables, not the host's. `None` means the
    /// caller has no separate container netns (Bubblewrap shared-net mode,
    /// unit tests): the chain is still built but left unhooked, so we never
    /// attach a rule to the host's own `INPUT` chain.
    netns_pid: Option<u32>,
}

impl NetworkIptablesManager {
    /// Create a new manager for the given container name.
    pub fn new(container_name: &str) -> Self {
        // Sanitize container name for use in iptables chain name.
        let sanitized: String = container_name
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
            .take(20)
            .collect();

        Self {
            chain_name: format!("MXC-{}", sanitized),
            rules_applied: false,
            netns_pid: None,
        }
    }

    /// Whether rules have been applied and need cleanup.
    pub fn rules_applied(&self) -> bool {
        self.rules_applied
    }

    /// Set the PID of the container's init process so the `INPUT` rules are
    /// applied inside the container's network namespace. Without this, the
    /// chain is built but not hooked (see [`NetworkIptablesManager::netns_pid`]).
    pub fn set_netns_pid(&mut self, pid: u32) {
        self.netns_pid = Some(pid);
    }

    /// Apply the inbound firewall rules for `policy`.
    ///
    /// Delegates argv construction to the pure [`Self::build_firewall_rules`]
    /// (unit-testable without root or `iptables`, mirroring the bubblewrap
    /// `build_args` / seatbelt `build_profile` backends), then executes each
    /// emitted vector — inside the container netns when a PID is known.
    pub fn apply_firewall_rules(
        &mut self,
        policy: &ContainerPolicy,
        logger: &mut Logger,
    ) -> Result<bool, String> {
        // Skip if network enforcement doesn't use a firewall.
        let use_firewall = matches!(
            policy.network_enforcement_mode,
            NetworkEnforcementMode::Firewall | NetworkEnforcementMode::Both
        );
        if !use_firewall {
            logger.log_line("Network enforcement mode does not use firewall, skipping iptables.");
            return Ok(true);
        }

        if self.netns_pid.is_none() {
            // No container netns to target. Hooking the host's INPUT chain
            // here would filter the *host's* own inbound traffic, not the
            // container's, so `build_firewall_rules` omits the hook and the
            // chain is inert. Bubblewrap shared-net mode reaches this path;
            // its egress is enforced by the proxy / `--unshare-net`, not here.
            logger.log_line(
                "Warning: no container network namespace PID set; \
                 building inbound chain without an INPUT hook (inert).",
            );
        }

        logger.log_line(&format!("Creating iptables chain: {}", self.chain_name));
        logger.log_line(&format!(
            "Inbound (hostLoopback) policy: {}",
            if policy.allow_local_network {
                "ACCEPT new inbound connections"
            } else {
                "DROP new inbound connections (default-deny)"
            }
        ));

        let rules = Self::build_firewall_rules(&self.chain_name, policy, self.netns_pid.is_some());

        for rule in &rules {
            let argv: Vec<&str> = rule.iter().map(String::as_str).collect();
            Self::run_iptables(self.netns_pid, &argv, logger)?;
        }

        self.rules_applied = true;
        Ok(true)
    }

    /// Build the ordered list of `iptables` argument vectors for `policy`.
    ///
    /// Pure: performs no process execution, no I/O, and no logging. Every
    /// input is passed in, so this compiles and can be unit-tested on any
    /// host. Mirrors the bubblewrap `build_args` and seatbelt `build_profile`
    /// builders.
    ///
    /// **Inbound control (GA `ingress.hostLoopback`).** The chain is hooked
    /// into the container's `INPUT` chain (executed inside the container netns
    /// by the caller), so every packet it sees is destined *to a container
    /// socket*. Intra-container loopback and established/related return
    /// traffic always pass; a single `--state NEW` rule then accepts
    /// (`allowLocalNetwork: true`) or drops (default) new inbound connections;
    /// a terminal `DROP` makes inbound default-deny regardless of the egress
    /// policy. `hook` gates the `-I INPUT` jump so we never attach to the
    /// host's `INPUT` chain when there is no container netns to enter.
    fn build_firewall_rules(chain: &str, policy: &ContainerPolicy, hook: bool) -> Vec<Vec<String>> {
        fn argv(args: &[&str]) -> Vec<String> {
            args.iter().map(|s| s.to_string()).collect()
        }

        let accept = "ACCEPT";
        let drop = "DROP";
        let mut rules: Vec<Vec<String>> = Vec::new();

        // Create the container's custom chain.
        rules.push(argv(&["-N", chain]));

        // Intra-container loopback (127.0.0.1 / ::1 inside the sandbox) must
        // always pass — GA keeps intra-container loopback unaffected by the
        // host-to-container inbound policy.
        rules.push(argv(&["-A", chain, "-i", "lo", "-j", accept]));

        // Accept return traffic for connections the container itself opened.
        // MUST precede the NEW-inbound decision below so container-initiated
        // flows survive an inbound DROP.
        rules.push(argv(&[
            "-A", chain, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", accept,
        ]));

        // hostLoopback toggle: accept or drop NEW inbound connections to the
        // container's listening sockets.
        let inbound_verb = if policy.allow_local_network { accept } else { drop };
        rules.push(argv(&[
            "-A", chain, "-m", "state", "--state", "NEW", "-j", inbound_verb,
        ]));

        // Ingress default-deny: host/external inbound is blocked by default
        // (GA). Deliberately independent of the egress `default_network_policy`
        // — an "allow" egress posture must not open the container to inbound.
        rules.push(argv(&["-A", chain, "-j", drop]));

        // Hook into the container's INPUT chain — only when we have a netns to
        // enter, so we never filter the host's own inbound traffic.
        if hook {
            rules.push(argv(&["-I", "INPUT", "-j", chain]));
        }

        rules
    }

    /// Remove the iptables rules created by this manager (best-effort).
    ///
    /// When the rules live in the container netns they vanish with the netns
    /// once the container is destroyed, so this is only strictly needed for
    /// reused/persistent containers; the `-D`/`-F`/`-X` calls simply no-op if
    /// the netns (and its chain) is already gone.
    pub fn remove_firewall_rules(&mut self, logger: &mut Logger) -> Result<(), String> {
        if !self.rules_applied {
            return Ok(());
        }

        logger.log_line(&format!("Removing iptables chain: {}", self.chain_name));

        // Unhook from INPUT (only if we hooked it, i.e. had a netns target).
        if self.netns_pid.is_some() {
            let _ = Self::run_iptables(
                self.netns_pid,
                &["-D", "INPUT", "-j", &self.chain_name],
                logger,
            );
        }

        // Flush and delete the chain.
        let _ = Self::run_iptables(self.netns_pid, &["-F", &self.chain_name], logger);
        let _ = Self::run_iptables(self.netns_pid, &["-X", &self.chain_name], logger);

        self.rules_applied = false;
        Ok(())
    }

    /// Best-effort cleanup of iptables state when the owning
    /// `NetworkIptablesManager` instance isn't reachable (e.g. signal-time
    /// cleanup from the watchdog thread). Builds a fresh manager pointed at
    /// the same chain name and netns so `remove_firewall_rules` does its work
    /// regardless of whether rules were actually installed; iptables itself is
    /// the source of truth. `netns_pid` is `None` when the container's netns
    /// is already gone, in which case there is nothing to remove.
    pub fn force_cleanup(container_name: &str, netns_pid: Option<u32>, logger: &mut Logger) {
        let mut mgr = Self::new(container_name);
        mgr.netns_pid = netns_pid;
        // Bypass the rules_applied gate; if there's nothing to remove the
        // iptables `-D`/`-F`/`-X` calls just no-op.
        mgr.rules_applied = true;
        let _ = mgr.remove_firewall_rules(logger);
    }

    /// Run an `iptables` command, entering the container's network namespace
    /// first when `netns_pid` is set. Uses the host `iptables` binary via
    /// `nsenter -t <pid> -n` so no `iptables` need exist in the container
    /// image; the runner is host-root and holds `CAP_NET_ADMIN` over the
    /// (child) network namespace.
    fn run_iptables(
        netns_pid: Option<u32>,
        args: &[&str],
        logger: &mut Logger,
    ) -> Result<bool, String> {
        let mut command = if let Some(pid) = netns_pid {
            let mut c = Command::new("nsenter");
            c.arg("-t").arg(pid.to_string()).arg("-n").arg("iptables");
            c
        } else {
            Command::new("iptables")
        };
        command.args(args);

        let output = command
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
    use wxc_common::models::NetworkPolicy;

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

    // ---- build_firewall_rules: pure rule-emission coverage ---------------
    //
    // These exercise the extracted pure builder directly (no root, no
    // `iptables`, no netns), mirroring how the other backends unit-test their
    // policy→artifact builders (bubblewrap `build_args`, seatbelt
    // `build_profile`). They pin the emitted argv so the inbound INPUT-chain
    // design is covered by CI.

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

    fn build(allow_local: bool, hook: bool) -> Vec<Vec<String>> {
        NetworkIptablesManager::build_firewall_rules(
            "MXC-t",
            &policy_with(allow_local, NetworkPolicy::Block),
            hook,
        )
    }

    #[test]
    fn loopback_always_accepts_regardless_of_allow_local() {
        for allow in [true, false] {
            let rules = build(allow, true);
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
        let rules = build(true, true);
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
        let rules = build(false, true);
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
        let rules = build(false, true);
        let est = pos(
            &rules,
            &[
                "-A", "MXC-t", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT",
            ],
        )
        .expect("ESTABLISHED,RELATED rule must be emitted");
        let new = pos(
            &rules,
            &["-A", "MXC-t", "-m", "state", "--state", "NEW", "-j", "DROP"],
        )
        .expect("NEW rule must be emitted");
        assert!(
            est < new,
            "ESTABLISHED,RELATED must precede the NEW-inbound rule"
        );
    }

    #[test]
    fn new_inbound_precedes_terminal_default() {
        let rules = build(true, true);
        let new = pos(
            &rules,
            &["-A", "MXC-t", "-m", "state", "--state", "NEW", "-j", "ACCEPT"],
        )
        .expect("NEW rule must be emitted");
        let def =
            pos(&rules, &["-A", "MXC-t", "-j", "DROP"]).expect("terminal default must be emitted");
        assert!(
            new < def,
            "NEW-inbound accept must precede the terminal default DROP"
        );
    }

    #[test]
    fn terminal_default_is_always_drop_regardless_of_egress_policy() {
        // Ingress is default-deny per GA; the egress `default_network_policy`
        // must not turn it into a default-accept.
        for default in [NetworkPolicy::Block, NetworkPolicy::Allow] {
            let rules = NetworkIptablesManager::build_firewall_rules(
                "MXC-t",
                &policy_with(false, default.clone()),
                true,
            );
            assert!(
                has(&rules, &["-A", "MXC-t", "-j", "DROP"]),
                "terminal must be DROP (egress default={default:?})"
            );
            assert!(
                !has(&rules, &["-A", "MXC-t", "-j", "ACCEPT"]),
                "terminal must never be a bare ACCEPT (egress default={default:?})"
            );
        }
    }

    #[test]
    fn input_hook_present_with_netns() {
        let rules = build(true, true);
        assert!(has(&rules, &["-I", "INPUT", "-j", "MXC-t"]));
    }

    #[test]
    fn input_hook_absent_without_netns() {
        let rules = build(true, false);
        assert!(
            !rules
                .iter()
                .any(|r| r.first().map(|s| s == "-I").unwrap_or(false)),
            "no INPUT hook may be emitted without a container netns"
        );
    }

    #[test]
    fn no_egress_dest_or_dns_rules_in_ingress_chain() {
        // GA ingress is loopback-only with no CIDR peers: the ingress chain
        // must not carry egress-intent destination/DNS accepts.
        let rules = build(false, true);
        assert!(
            !rules.iter().any(|r| r.iter().any(|a| a == "-d")),
            "ingress chain must not emit -d destination rules"
        );
        assert!(
            !rules.iter().any(|r| r.iter().any(|a| a == "--dport")),
            "ingress chain must not emit --dport (DNS) rules"
        );
    }

    #[test]
    fn chain_is_created_first() {
        let rules = build(false, true);
        assert!(is(&rules[0], &["-N", "MXC-t"]), "chain must be created first");
    }
}
