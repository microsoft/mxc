// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Inbound network policy enforcement via iptables, scoped to the container's
//! own network namespace.
//!
//! Implements the `allowLocalNetwork` inbound control for the LXC backend (and,
//! when a netns target is supplied, Bubblewrap): host-to-container and external
//! inbound traffic is dropped by default. The permissive form
//! (`allowLocalNetwork: true`) is not yet implemented — see below — so today
//! this manager only installs the default-deny chain.
//!
//! **Dual-stack.** A dual-stack container is reachable over IPv4 or IPv6, so an
//! IPv4-only chain would let IPv6 inbound bypass the deny entirely. A rule set
//! is installed through `iptables` and, when the family is usable, a
//! separately built one through `ip6tables`; teardown removes both. The IPv6
//! set is not a verbatim replay of the IPv4 set: because IPv6 uses ICMPv6
//! Neighbor Discovery (RFC 4861) in place of IPv4's layer-2 ARP, and ND *is*
//! filtered by `ip6tables`, the IPv6 chain additionally accepts the ICMPv6
//! control-plane types (see `IpFamily` / `ICMPV6_ALLOW_TYPES`) so a hardened
//! default-deny container keeps working IPv6 address resolution and
//! autoconfiguration while ordinary new inbound connections stay dropped.
//! `ip6tables` being unusable is only safe when IPv6 is
//! positively known to be disabled on the host (no `/proc/net/if_inet6`
//! addresses): there the IPv4 chain is enforced alone. When IPv6 is live but
//! `ip6tables` cannot run, the inbound deny is unenforceable for that family,
//! so the run fails closed rather than silently leaving IPv6 open. This matches
//! PR #632's probe (`ip6tables_available` / `host_has_ipv6`).
//!
//! **Permissive path is not yet implemented.** `allowLocalNetwork: true` is
//! meant to open *host-loopback* inbound only, but scoping to host loopback
//! needs a schema field that does not exist yet (`loopbackPorts`) plus an
//! MXC-owned host-loopback forwarder. The only rule available today is an
//! unscoped `--state NEW -j ACCEPT` that would accept inbound from every
//! interface and source (LAN and WAN). Rather than install that over-broad
//! accept, [`Self::apply_firewall_rules`] returns a clear not-yet-implemented
//! error for the permissive path (MGudgin's requested interim).
//!
//! **Why the container netns.** A packet destined to a container socket
//! traverses the *container's* `INPUT` chain, inside the container's network
//! namespace — never the host's `INPUT` (the host only ever sees such packets
//! in `FORWARD`, if it routes them). So the rules are executed with
//! `nsenter -t <init-pid> -n iptables …`, landing them in the container's
//! netfilter tables. This matches the networking design spec, which enforces
//! the LXC inbound control "via iptables INPUT"
//! (`docs/sandbox-policy/v2/networking.md`; that spec's forward-looking GA
//! field is `ingress.hostLoopback`, which this branch does not carry — the
//! code reads main's `allowLocalNetwork`). Egress (allow/deny lists, DNS,
//! proxy) is a separate control and is intentionally not handled here.

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

/// The IP families the inbound chain may exist in. A dual-stack container is
/// reachable over either family, so a chain that lives only in IPv4 lets IPv6
/// inbound bypass the default-deny entirely. Teardown is family-agnostic (the
/// `-D`/`-F`/`-X` chain operations carry no IP literals), so this constant
/// drives the best-effort remove path over both families (a stale
/// `-D`/`-F`/`-X` simply no-ops). Install is *not* family-agnostic: see
/// [`IpFamily`] and [`NetworkIptablesManager::build_firewall_rules`], because
/// the IPv6 chain must additionally accept ICMPv6 Neighbor Discovery.
const IPTABLES_BINARIES: [&str; 2] = ["iptables", "ip6tables"];

/// IP family an inbound chain is being built for.
///
/// The two families are *not* interchangeable at install time. IPv4 address
/// resolution is ARP, a layer-2 protocol that never traverses `iptables`, so
/// the IPv4 chain needs no special allowances. IPv6 replaces ARP with ICMPv6
/// Neighbor Discovery (RFC 4861) — Neighbor/Router Solicitation and
/// Advertisement — which rides on IPv6 and *is* filtered by `ip6tables`.
/// Inbound ND packets are connection-state `NEW`, so replaying the IPv4 rule
/// set (a single `--state NEW` accept-or-drop then a terminal `DROP`) into
/// `ip6tables` drops ND and breaks IPv6 address resolution and stateless
/// autoconfiguration. [`IpFamily::V6`] therefore additionally permits the
/// ICMPv6 control-plane types in [`ICMPV6_ALLOW_TYPES`]; [`IpFamily::V4`] does
/// not, so IPv4 behavior is unchanged.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum IpFamily {
    V4,
    V6,
}

/// ICMPv6 message types the IPv6 inbound chain accepts so a hardened
/// default-deny container still has a functioning IPv6 stack. Numeric values
/// are used rather than names because RFC 4443 defines the numbers
/// normatively, so they are unambiguous and cannot be mis-spelled; each is
/// annotated with its RFC 4443 name below. Note that the named forms are not
/// known to be broken — `ip6tables` v1.8.10 (nf_tables) resolves both
/// `neighbour-solicitation` and `neighbor-solicitation` — so the numbers are
/// chosen for determinism, not to work around a specific build.
/// Selection follows RFC 4890 ("Recommendations for Filtering ICMPv6
/// Messages in Firewalls"):
///
///   - 133–136 Neighbor Discovery (RS/RA/NS/NA) — RFC 4890 §4.4.1 "must not be
///     dropped"; without these IPv6 address resolution and SLAAC stop working.
///   - 130–132, 143 Multicast Listener Discovery — RFC 4890 §4.3.1; required
///     for multicast group membership, which ND itself relies on
///     (solicited-node multicast).
///   - 1–4 essential errors (destination-unreachable, packet-too-big,
///     time-exceeded, parameter-problem) — RFC 4890 §4.4.1 "must not be
///     dropped"; packet-too-big (2) in particular is required for Path MTU
///     Discovery.
///
/// Echo request/reply (128/129) and Redirect (137) are deliberately *omitted*:
/// leaving inbound ping and router redirects dropped keeps the hardened
/// posture (RFC 4890 permits dropping echo at a firewall), while every type
/// above is needed for basic IPv6 operation. Ordinary `NEW` inbound
/// connections are still dropped — only these control-plane types are opened.
const ICMPV6_ALLOW_TYPES: [&str; 12] = [
    // Neighbor Discovery (RFC 4861), RFC 4890 §4.4.1.
    "133", // router-solicitation
    "134", // router-advertisement
    "135", // neighbour-solicitation
    "136", // neighbour-advertisement
    // Multicast Listener Discovery (RFC 2710 / RFC 3810), RFC 4890 §4.3.1.
    "130", // multicast-listener-query
    "131", // multicast-listener-report
    "132", // multicast-listener-done
    "143", // multicast-listener-report-v2
    // Essential error messages, RFC 4890 §4.4.1.
    "1", // destination-unreachable
    "2", // packet-too-big (Path MTU Discovery)
    "3", // time-exceeded
    "4", // parameter-problem
];

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

        // Permissive host-loopback inbound (`allowLocalNetwork: true`) is not
        // yet implementable safely. Scoping it to host loopback needs a schema
        // field that does not exist yet (`loopbackPorts`) plus an MXC-owned
        // host-loopback forwarder. The only rule we could emit today is an
        // unscoped `--state NEW -j ACCEPT`, which opens the container to new
        // inbound connections from every interface and source — LAN and WAN
        // included, not just host loopback. Refuse with a clear error rather
        // than silently installing that over-broad accept (MGudgin's requested
        // interim, comment 5120422486). Gate on a real netns hook so the inert
        // Bubblewrap shared-net path, which installs nothing, keeps working.
        if policy.allow_local_network && self.netns_pid.is_some() {
            return Err(
                "allowLocalNetwork (permissive host-loopback inbound) is not yet implemented \
                 for the LXC firewall path. Scoping inbound to host loopback requires a \
                 loopbackPorts policy field and an MXC-owned host-loopback forwarder that do \
                 not exist yet; the only rule available today would accept new inbound \
                 connections from every interface and source (LAN and WAN), which is broader \
                 than requested. Refusing rather than installing an over-broad accept."
                    .to_string(),
            );
        }

        logger.log_line(&format!("Creating iptables chain: {}", self.chain_name));
        logger.log_line(&format!(
            "Inbound (allowLocalNetwork) policy: {}",
            if policy.allow_local_network {
                "ACCEPT new inbound connections"
            } else {
                "DROP new inbound connections (default-deny)"
            }
        ));

        let ipv4_rules = Self::build_firewall_rules(
            &self.chain_name,
            policy,
            self.netns_pid.is_some(),
            IpFamily::V4,
        );

        // IPv6 handling. The inbound chain is *always* default-deny (terminal
        // DROP) on the path that reaches here — the permissive `allowLocalNetwork`
        // case returned above — so IPv6 always needs the same chain or v6 inbound
        // bypasses the deny. Unlike PR #632's egress model there is no allow
        // stance that would make skipping v6 harmless.
        //
        // Being unable to run `ip6tables` is only safe when the host has no IPv6
        // stack at all. On a host with live IPv6 it means we cannot filter a
        // whole address family, which is exactly the fail-open this fix closes,
        // so we abort. When IPv6 is positively known to be disabled we enforce
        // the IPv4 chain alone. This mirrors PR #632's probe so the two branches
        // agree on the distinction (`network_iptables.rs` `ip6tables_available`
        // / `host_has_ipv6` there).
        let ipv6_enabled = Self::ip6tables_available(logger);
        if !ipv6_enabled {
            if Self::host_has_ipv6() {
                return Err(format!(
                    "ip6tables is unusable on this host but IPv6 is live \
                     (/proc/net/if_inet6 lists addresses), so inbound IPv6 for container \
                     '{}' cannot be denied. Refusing to start with an unenforceable inbound \
                     policy: disable IPv6 on the host, or install/enable ip6tables.",
                    self.chain_name
                ));
            }
            logger.log_line(
                "ip6tables unusable and no live IPv6 stack on this host; enforcing the \
                 IPv4 inbound policy only.",
            );
        }

        // Install the IPv4 rule set through `iptables`, and — when the family
        // is usable — a *separately built* IPv6 rule set through `ip6tables`,
        // so IPv6 inbound cannot bypass an IPv4-only deny on a dual-stack
        // container. The two sets are not identical: the IPv6 set additionally
        // permits ICMPv6 Neighbor Discovery (see `IpFamily`), so replaying the
        // IPv4 argv verbatim into `ip6tables` — which would drop ND and break
        // IPv6 — no longer happens.
        for rule in &ipv4_rules {
            let argv: Vec<&str> = rule.iter().map(String::as_str).collect();
            Self::run_iptables("iptables", self.netns_pid, &argv, logger)?;
        }
        if ipv6_enabled {
            let ipv6_rules = Self::build_firewall_rules(
                &self.chain_name,
                policy,
                self.netns_pid.is_some(),
                IpFamily::V6,
            );
            for rule in &ipv6_rules {
                let argv: Vec<&str> = rule.iter().map(String::as_str).collect();
                Self::run_iptables("ip6tables", self.netns_pid, &argv, logger)?;
            }
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
    /// `family` selects the IP family. The IPv4 and IPv6 rule sets are
    /// intentionally *not* identical: the IPv6 set additionally accepts the
    /// ICMPv6 control-plane types in [`ICMPV6_ALLOW_TYPES`] (Neighbor Discovery,
    /// Multicast Listener Discovery, and essential errors) so a hardened
    /// default-deny container keeps a working IPv6 stack. The IPv4 set carries
    /// no ICMP allowances — IPv4 uses ARP, a layer-2 protocol iptables never
    /// sees — so [`IpFamily::V4`] reproduces the historical IPv4 sequence
    /// exactly. See [`IpFamily`].
    ///
    /// **Inbound control (`allowLocalNetwork`).** The chain is hooked
    /// into the container's `INPUT` chain (executed inside the container netns
    /// by the caller), so every packet it sees is destined *to a container
    /// socket*. Intra-container loopback and established/related return
    /// traffic always pass; a single `--state NEW` rule then accepts
    /// (`allowLocalNetwork: true`) or drops (default) new inbound connections;
    /// a terminal `DROP` makes inbound default-deny regardless of the egress
    /// policy. `hook` gates the `-I INPUT` jump so we never attach to the
    /// host's `INPUT` chain when there is no container netns to enter.
    fn build_firewall_rules(
        chain: &str,
        policy: &ContainerPolicy,
        hook: bool,
        family: IpFamily,
    ) -> Vec<Vec<String>> {
        fn argv(args: &[&str]) -> Vec<String> {
            args.iter().map(|s| s.to_string()).collect()
        }

        let accept = "ACCEPT";
        let drop = "DROP";
        let mut rules: Vec<Vec<String>> = Vec::new();

        // Create the container's custom chain.
        rules.push(argv(&["-N", chain]));

        // Intra-container loopback (127.0.0.1 / ::1 inside the sandbox) must
        // always pass — intra-container loopback is unaffected by the
        // host-to-container inbound policy.
        rules.push(argv(&["-A", chain, "-i", "lo", "-j", accept]));

        // Accept return traffic for connections the container itself opened.
        // MUST precede the NEW-inbound decision below so container-initiated
        // flows survive an inbound DROP.
        rules.push(argv(&[
            "-A",
            chain,
            "-m",
            "state",
            "--state",
            "ESTABLISHED,RELATED",
            "-j",
            accept,
        ]));

        // IPv6 only: permit the ICMPv6 control-plane types a functioning IPv6
        // stack needs (Neighbor Discovery, Multicast Listener Discovery, and
        // essential errors). These arrive as `NEW`, so they MUST precede the
        // `--state NEW` decision and the terminal `DROP` below or address
        // resolution and autoconfiguration break. IPv4 emits nothing here —
        // ARP is layer 2 and never reaches iptables — so the IPv4 sequence is
        // unchanged. See `ICMPV6_ALLOW_TYPES` for the type list and RFC 4890
        // citation.
        if family == IpFamily::V6 {
            for icmpv6_type in ICMPV6_ALLOW_TYPES {
                rules.push(argv(&[
                    "-A",
                    chain,
                    "-p",
                    "icmpv6",
                    "--icmpv6-type",
                    icmpv6_type,
                    "-j",
                    accept,
                ]));
            }
        }

        // allowLocalNetwork toggle: accept or drop NEW inbound connections to
        // the container's listening sockets.
        let inbound_verb = if policy.allow_local_network {
            accept
        } else {
            drop
        };
        rules.push(argv(&[
            "-A",
            chain,
            "-m",
            "state",
            "--state",
            "NEW",
            "-j",
            inbound_verb,
        ]));

        // Inbound default-deny: host/external inbound is blocked by default.
        // Deliberately independent of the egress `default_network_policy` — an
        // "allow" egress posture must not open the container to inbound.
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

        // Tear the chain down in both IP families, mirroring the dual-stack
        // install. Unhook from INPUT (only if we hooked it, i.e. had a netns
        // target), then flush and delete. Each call is best-effort: a `-D`/`-F`/
        // `-X` simply no-ops if the netns (and its chain) is already gone.
        for binary in IPTABLES_BINARIES {
            if self.netns_pid.is_some() {
                let _ = Self::run_iptables(
                    binary,
                    self.netns_pid,
                    &["-D", "INPUT", "-j", &self.chain_name],
                    logger,
                );
            }

            let _ = Self::run_iptables(binary, self.netns_pid, &["-F", &self.chain_name], logger);
            let _ = Self::run_iptables(binary, self.netns_pid, &["-X", &self.chain_name], logger);
        }

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

    /// Probe whether `ip6tables` can be used on this host.
    ///
    /// Runs a harmless, read-only `ip6tables -S` (list the filter table). This
    /// fails both when the binary is missing (IPv4-only images) and when the
    /// kernel has IPv6 disabled (`ip6tables` reports the table cannot be
    /// initialized). The two cases are **not** equivalent, so callers must pair
    /// this with [`Self::host_has_ipv6`]: skipping the v6 chain is safe only on
    /// a host that has no IPv6 stack to leak through.
    ///
    /// Probed on the host (not via `nsenter`), mirroring PR #632. The
    /// `ip6_tables` kernel module is global rather than per-netns, so a
    /// successful host probe predicts that the in-netns `ip6tables` invocation
    /// this manager actually runs will work too.
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

    /// Whether this host has a live IPv6 stack.
    ///
    /// `/proc/net/if_inet6` exists only when the kernel's IPv6 support is
    /// present, and lists one line per configured address — so it is empty when
    /// IPv6 is administratively disabled everywhere
    /// (`net.ipv6.conf.all.disable_ipv6=1`). Absent or empty therefore means
    /// "no IPv6 to filter"; anything else means IPv6 is live. A host with no
    /// IPv6 stack cannot hand one to a container netns, so this host-level probe
    /// is a conservative predictor for the in-netns inbound path.
    ///
    /// If the file exists but cannot be read we report `true` so the caller
    /// fails closed rather than assuming away a family it cannot filter.
    fn host_has_ipv6() -> bool {
        let path = std::path::Path::new("/proc/net/if_inet6");
        if !path.exists() {
            return false;
        }
        match std::fs::read_to_string(path) {
            Ok(contents) => contents.lines().any(|line| !line.trim().is_empty()),
            Err(_) => true,
        }
    }

    /// Run an `iptables`/`ip6tables` command, entering the container's network
    /// namespace first when `netns_pid` is set. Uses the host `binary` via
    /// `nsenter -t <pid> -n` so no packet-filter tools need exist in the
    /// container image; the runner is host-root and holds `CAP_NET_ADMIN` over
    /// the (child) network namespace.
    fn run_iptables(
        binary: &str,
        netns_pid: Option<u32>,
        args: &[&str],
        logger: &mut Logger,
    ) -> Result<bool, String> {
        let mut command = if let Some(pid) = netns_pid {
            let mut c = Command::new("nsenter");
            c.arg("-t").arg(pid.to_string()).arg("-n").arg(binary);
            c
        } else {
            Command::new(binary)
        };
        command.args(args);

        let output = command
            .output()
            .map_err(|e| format!("Failed to run {}: {}", binary, e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let msg = format!("{} {} failed: {}", binary, args.join(" "), stderr);
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
#[path = "network_iptables_permissive_spec_tests.rs"]
mod permissive_spec_tests;

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
            IpFamily::V4,
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
                "-A",
                "MXC-t",
                "-m",
                "state",
                "--state",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
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
            &[
                "-A", "MXC-t", "-m", "state", "--state", "NEW", "-j", "ACCEPT",
            ],
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
        // Inbound is default-deny; the egress `default_network_policy` must not
        // turn it into a default-accept.
        for default in [NetworkPolicy::Block, NetworkPolicy::Allow] {
            let rules = NetworkIptablesManager::build_firewall_rules(
                "MXC-t",
                &policy_with(false, default.clone()),
                true,
                IpFamily::V4,
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
        // The inbound chain is loopback + established + a single NEW-state
        // decision with no CIDR peers, so it must not carry egress-intent
        // destination or DNS accepts.
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
        assert!(
            is(&rules[0], &["-N", "MXC-t"]),
            "chain must be created first"
        );
    }

    // ---- family-awareness: IPv4 pinned, IPv6 gains ICMPv6 ND ------------
    //
    // These pin the exact per-family argv so the fix for the "IPv4 rule set
    // replayed verbatim into ip6tables" defect is covered by CI: IPv4 must be
    // byte-for-byte its historical sequence (no ICMP allowances — ARP is
    // layer 2 and never reaches iptables), while IPv6 must additionally permit
    // the ICMPv6 Neighbor Discovery / MLD / essential-error types a working
    // IPv6 stack needs, without opening ordinary new inbound.

    fn build_family(allow_local: bool, hook: bool, family: IpFamily) -> Vec<Vec<String>> {
        NetworkIptablesManager::build_firewall_rules(
            "MXC-t",
            &policy_with(allow_local, NetworkPolicy::Block),
            hook,
            family,
        )
    }

    /// The IPv4 rule set must be exactly the historical sequence, in order —
    /// this is the regression pin proving IPv4 behavior did not change when
    /// IPv6 became family-aware.
    #[test]
    fn ipv4_full_sequence_is_pinned_exactly() {
        let rules = build_family(false, true, IpFamily::V4);
        let want: &[&[&str]] = &[
            &["-N", "MXC-t"],
            &["-A", "MXC-t", "-i", "lo", "-j", "ACCEPT"],
            &[
                "-A",
                "MXC-t",
                "-m",
                "state",
                "--state",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ],
            &["-A", "MXC-t", "-m", "state", "--state", "NEW", "-j", "DROP"],
            &["-A", "MXC-t", "-j", "DROP"],
            &["-I", "INPUT", "-j", "MXC-t"],
        ];
        assert_eq!(
            rules.len(),
            want.len(),
            "IPv4 rule count changed: got {rules:?}"
        );
        for (i, expected) in want.iter().enumerate() {
            assert!(
                is(&rules[i], expected),
                "IPv4 rule {i} changed: got {:?}, want {:?}",
                rules[i],
                expected
            );
        }
    }

    /// IPv4 must emit no ICMP/ICMPv6 rules at all — ARP is layer 2, so the IPv4
    /// chain never needs a control-plane allowance.
    #[test]
    fn ipv4_emits_no_icmpv6_rules() {
        for allow in [true, false] {
            let rules = build_family(allow, true, IpFamily::V4);
            assert!(
                !rules
                    .iter()
                    .any(|r| r.iter().any(|a| a == "--icmpv6-type" || a == "icmpv6")),
                "IPv4 chain must not emit any ICMPv6 rule (allow_local={allow})"
            );
        }
    }

    /// IPv6 must accept each Neighbor Discovery type (RS/RA/NS/NA), or inbound
    /// ND is dropped by the NEW rule and IPv6 address resolution breaks.
    #[test]
    fn ipv6_permits_neighbor_discovery_types() {
        let rules = build_family(false, true, IpFamily::V6);
        for (num, name) in [
            ("133", "router-solicitation"),
            ("134", "router-advertisement"),
            ("135", "neighbour-solicitation"),
            ("136", "neighbour-advertisement"),
        ] {
            assert!(
                has(
                    &rules,
                    &[
                        "-A",
                        "MXC-t",
                        "-p",
                        "icmpv6",
                        "--icmpv6-type",
                        num,
                        "-j",
                        "ACCEPT"
                    ]
                ),
                "IPv6 chain must accept ICMPv6 type {num} ({name})"
            );
        }
    }

    /// IPv6 must accept the Multicast Listener Discovery and essential-error
    /// types (packet-too-big is required for Path MTU Discovery).
    #[test]
    fn ipv6_permits_mld_and_essential_error_types() {
        let rules = build_family(false, true, IpFamily::V6);
        for (num, name) in [
            ("130", "multicast-listener-query"),
            ("131", "multicast-listener-report"),
            ("132", "multicast-listener-done"),
            ("143", "multicast-listener-report-v2"),
            ("1", "destination-unreachable"),
            ("2", "packet-too-big"),
            ("3", "time-exceeded"),
            ("4", "parameter-problem"),
        ] {
            assert!(
                has(
                    &rules,
                    &[
                        "-A",
                        "MXC-t",
                        "-p",
                        "icmpv6",
                        "--icmpv6-type",
                        num,
                        "-j",
                        "ACCEPT"
                    ]
                ),
                "IPv6 chain must accept ICMPv6 type {num} ({name})"
            );
        }
    }

    /// Every ICMPv6 accept must come before the `--state NEW` decision and the
    /// terminal DROP, or ND (which is NEW) would be dropped before it matches.
    #[test]
    fn ipv6_icmpv6_accepts_precede_new_and_terminal_drop() {
        let rules = build_family(false, true, IpFamily::V6);
        let new = pos(
            &rules,
            &["-A", "MXC-t", "-m", "state", "--state", "NEW", "-j", "DROP"],
        )
        .expect("NEW rule must be emitted");
        let terminal = rules
            .iter()
            .rposition(|r| is(r, &["-A", "MXC-t", "-j", "DROP"]))
            .expect("terminal DROP must be emitted");
        for num in ["133", "134", "135", "136", "130", "143", "2"] {
            let at = pos(
                &rules,
                &[
                    "-A",
                    "MXC-t",
                    "-p",
                    "icmpv6",
                    "--icmpv6-type",
                    num,
                    "-j",
                    "ACCEPT",
                ],
            )
            .unwrap_or_else(|| panic!("ICMPv6 type {num} accept must be emitted"));
            assert!(
                at < new,
                "ICMPv6 type {num} accept must precede the NEW decision"
            );
            assert!(
                at < terminal,
                "ICMPv6 type {num} accept must precede the terminal DROP"
            );
        }
    }

    /// The IPv6 fix must not become a blanket ICMPv6 accept: only the specific
    /// control-plane types are opened, and ordinary new inbound (and inbound
    /// ping / redirects) stay dropped.
    #[test]
    fn ipv6_does_not_blanket_accept_icmpv6_or_new_inbound() {
        let rules = build_family(false, true, IpFamily::V6);
        // No untyped `-p icmpv6 -j ACCEPT` (would accept every ICMPv6 message).
        assert!(
            !has(&rules, &["-A", "MXC-t", "-p", "icmpv6", "-j", "ACCEPT"]),
            "IPv6 chain must not blanket-accept all ICMPv6"
        );
        // Echo request (128) and Redirect (137) are deliberately not opened.
        for num in ["128", "137"] {
            assert!(
                !has(
                    &rules,
                    &[
                        "-A",
                        "MXC-t",
                        "-p",
                        "icmpv6",
                        "--icmpv6-type",
                        num,
                        "-j",
                        "ACCEPT"
                    ]
                ),
                "IPv6 chain must not accept ICMPv6 type {num}"
            );
        }
        // Default-deny still holds: NEW inbound dropped, terminal DROP present.
        assert!(
            has(
                &rules,
                &["-A", "MXC-t", "-m", "state", "--state", "NEW", "-j", "DROP"]
            ),
            "IPv6 chain must still drop NEW inbound by default"
        );
        assert!(
            has(&rules, &["-A", "MXC-t", "-j", "DROP"]),
            "IPv6 chain must still end in a terminal DROP"
        );
    }

    /// With `allowLocalNetwork: true` the IPv6 NEW decision flips to ACCEPT
    /// just like IPv4 — the ICMPv6 allowances are independent of the toggle.
    #[test]
    fn ipv6_new_decision_follows_allow_local_toggle() {
        let allow = build_family(true, true, IpFamily::V6);
        assert!(has(
            &allow,
            &["-A", "MXC-t", "-m", "state", "--state", "NEW", "-j", "ACCEPT"]
        ));
        let deny = build_family(false, true, IpFamily::V6);
        assert!(has(
            &deny,
            &["-A", "MXC-t", "-m", "state", "--state", "NEW", "-j", "DROP"]
        ));
    }
}
