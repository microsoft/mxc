// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Network policy enforcement via iptables rules scoped to the LXC container.
//!
//! Maps the platform-agnostic `ContainerPolicy` network settings to iptables
//! and ip6tables rules applied to the container's virtual ethernet (veth)
//! interface.

use std::net::{IpAddr, Ipv6Addr, ToSocketAddrs};
use std::path::Path;
use std::process::Command;

use wxc_common::logger::Logger;
use wxc_common::models::{
    ContainerPolicy, NetworkEnforcementMode, NetworkPolicy, ProxyAddress, ProxyHostPin,
};

/// One destination the container is allowed to reach when the policy routes
/// egress through a cooperative proxy: an address the proxy host resolved to,
/// and the TCP port the proxy listens on.
///
/// The address is held as a string because that is what an iptables `-d`
/// argument takes, matching [`ResolvedDestinations`].
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

/// Where the kernel reports per-interface attributes. Injectable in tests via
/// the `_in` form of the lookup below.
const SYSFS_NET_ROOT: &str = "/sys/class/net";

/// Toggles that decide whether bridged packets are handed to iptables and
/// ip6tables at all. A bridged container's chain is unreachable unless the
/// matching one reads `1`.
const BRIDGE_NF_CALL_IPTABLES: &str = "/proc/sys/net/bridge/bridge-nf-call-iptables";
const BRIDGE_NF_CALL_IP6TABLES: &str = "/proc/sys/net/bridge/bridge-nf-call-ip6tables";

/// Whether a host-list entry produces an ACCEPT or a DROP rule. Local to this
/// backend: it distinguishes `allowedHosts` from `blockedHosts` and is not a
/// policy-schema type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleAction {
    Allow,
    Deny,
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

/// Records exactly which per-family chains and FORWARD hooks a single apply
/// attempt created, so rollback and teardown remove only what this manager
/// installed. Without this, a partial-failure rollback would tear down chains
/// this attempt never created, and because chain names truncate at 20 chars a
/// torn-down chain can belong to a different container.
///
/// Visible to the crate (with private fields) purely so `signal_cleanup` can
/// carry the value from the runner thread to the watchdog thread. The watchdog
/// never inspects it; it only hands it back to [`NetworkIptablesManager::force_cleanup`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CreatedResources {
    v4_chain: bool,
    v6_chain: bool,
    v4_hook: bool,
    v6_hook: bool,
    v4_physdev_hook: bool,
    v6_physdev_hook: bool,
}

/// Flush and delete the chain, reporting whether it is still owned afterward.
///
/// `hooks_remain` gates the entire step, flush included. That ordering is the
/// point of the function: a hook that survived its own delete still jumps to
/// this chain, and a flushed chain returns to the caller instead of reaching
/// its closing DROP. Flushing first would therefore fail a still-running
/// container open, and `-X` would fail anyway because iptables refuses to
/// delete a referenced chain -- so the flush buys nothing and costs the
/// container its filtering. Leaving the chain populated keeps the intermediate
/// state fail closed, and returning `true` keeps it published so a later pass
/// retries.
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
    /// Whether nothing was created, in which case there is nothing to tear
    /// down and teardown must not run a single iptables command.
    ///
    /// Only reachable from the signal path, which is Linux-only; kept
    /// compiled on every target so Windows and macOS CI still type-check it.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn is_empty(&self) -> bool {
        !self.v4_chain
            && !self.v6_chain
            && !self.v4_hook
            && !self.v6_hook
            && !self.v4_physdev_hook
            && !self.v6_physdev_hook
    }

    /// Test-only constructor so `signal_cleanup`'s tests can build a
    /// distinguishable, non-default ownership record without widening the
    /// production API. Production code only ever obtains one of these by
    /// creating the resources it names.
    #[cfg(test)]
    pub(crate) fn for_test(v4_chain: bool, v6_chain: bool, v4_hook: bool, v6_hook: bool) -> Self {
        Self {
            v4_chain,
            v6_chain,
            v4_hook,
            v6_hook,
            v4_physdev_hook: false,
            v6_physdev_hook: false,
        }
    }
}

/// Three-way classification of whether `ip6tables` can be used on this host.
///
/// The old boolean probe collapsed two very different situations into "skip
/// IPv6": a kernel with IPv6 disabled (nothing to filter, safe to skip) and an
/// IPv6-capable host whose `ip6tables` userspace tool is missing or broken
/// (IPv6 egress is live but unfiltered, which is a silent fail-open on a
/// security control). They must be handled differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ip6tablesStatus {
    /// `ip6tables` works; program the parallel IPv6 chain.
    Available,
    /// The kernel has no active IPv6, so there is no IPv6 traffic to filter.
    /// Skipping the IPv6 chain is safe.
    KernelIpv6Disabled,
    /// The host has active IPv6 but `ip6tables` is missing or broken. Applying
    /// only the IPv4 policy would leave IPv6 egress unfiltered, so setup must
    /// fail closed instead.
    UnusableButIpv6Active,
}

/// Whether the host has egress-capable IPv6, or whether that could not be
/// determined.
///
/// Distinguishing `Unknown` from `Inactive` keeps a failed read of
/// `/proc/net/if_inet6` from being silently converted into a confirmed "IPv6
/// is off". That conflation would fail open — proceeding with an IPv4-only
/// policy that leaves IPv6 egress unfiltered — on a host whose IPv6 state we
/// could not actually read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostIpv6State {
    /// A non-loopback interface carries an IPv6 address, so IPv6 egress is
    /// possible and must be filtered.
    Active,
    /// No IPv6 addresses beyond loopback (`::1` on `lo`), or the kernel never
    /// created `/proc/net/if_inet6` at all (IPv6 disabled at boot). Either way
    /// there is no IPv6 egress to filter.
    Inactive,
    /// The IPv6 state could not be read. This is deliberately **not** treated
    /// as a confirmed negative: an unreadable `/proc/net/if_inet6` means "we
    /// do not know", not "IPv6 is off".
    Unknown,
}

/// Manages iptables rules for an LXC container's network policy.
pub struct NetworkIptablesManager {
    /// Chain name unique to this container (e.g., "MXC-<container-name>").
    chain_name: String,
    /// Whether rules have been applied.
    rules_applied: bool,
    /// The container's veth interface name on the host.
    veth_interface: Option<String>,
    /// Whether a caller that never supplies a veth is expected rather than
    /// broken. Defaults to `false`, so a missing veth fails fast.
    veth_scoping_optional: bool,
    /// Chains and FORWARD hooks this manager successfully created, so teardown
    /// and rollback remove only resources this attempt actually installed.
    created: CreatedResources,
    /// The hosts-file pin the container needs so it resolves the proxy
    /// hostname to the one address this manager authorized. Recorded during
    /// apply, because the resolution that produced the firewall rule is the
    /// only one the container is allowed to agree with.
    proxy_pin: Option<ProxyHostPin>,
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
            veth_scoping_optional: false,
            created: CreatedResources::default(),
            proxy_pin: None,
        }
    }

    /// Whether rules have been applied and need cleanup.
    pub fn rules_applied(&self) -> bool {
        self.rules_applied
    }

    /// The hosts-file pin a proxied container must be given before it runs, or
    /// `None` when the policy needs no pin.
    ///
    /// Populated by [`Self::apply_firewall_rules`] and only meaningful after
    /// it succeeds: the pin names the address that apply authorized, and
    /// resolving the proxy host a second time to build it could return a
    /// different address under round-robin or split-horizon DNS -- one the
    /// chain does not allow.
    pub fn proxy_host_pin(&self) -> Option<&ProxyHostPin> {
        self.proxy_pin.as_ref()
    }

    /// Whether this manager has been told a missing veth is expected.
    ///
    /// Lets a backend that structurally has no veth assert it made the
    /// declaration without standing up a real firewall.
    pub fn veth_scoping_is_optional(&self) -> bool {
        self.veth_scoping_optional
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

    /// Declare that this caller has no veth to scope the chain to, so a missing
    /// one is a structural fact rather than a failed lookup.
    ///
    /// LXC always names a veth once the container is running, so a manager that
    /// reaches rule installation without one has lost the interface it needed
    /// and must fail fast. Unprivileged Bubblewrap has no veth at all — the
    /// sandbox either shares the host network namespace or gets a private one,
    /// and neither yields a host-side interface to match on. Failing there would
    /// refuse to start every Bubblewrap sandbox that asks for firewall mode.
    ///
    /// Callers that set this get the pre-existing behavior: the chain is built,
    /// the FORWARD hook is skipped, and the skip is logged. The policy is
    /// therefore **not** enforced, which is why this is opt-in and loud rather
    /// than the default.
    pub fn allow_missing_veth_interface(&mut self) {
        self.veth_scoping_optional = true;
    }

    /// Build one FORWARD hook rule matching the veth as the input interface.
    ///
    /// `op` is `-I` to install or `-D` to remove. Both come from this one
    /// builder so a delete can never drift from the insert it has to match:
    /// iptables deletes by full rule specification, and a spec that differs by
    /// even one match leaves the hook in place.
    fn build_forward_hook_iface_rule_args(op: &str, iface: &str, chain_name: &str) -> Vec<String> {
        vec![
            op.to_string(),
            "FORWARD".to_string(),
            "-i".to_string(),
            iface.to_string(),
            "-j".to_string(),
            chain_name.to_string(),
        ]
    }

    /// Build one FORWARD hook rule matching the veth as the *bridge port* the
    /// packet entered on.
    ///
    /// This is the rule that does the work whenever the container is attached
    /// to a bridge, which is the default LXC topology (`lxc.net.0.link` set to
    /// `lxcbr0`). A packet leaving such a container is bridged onto `lxcbr0`
    /// and then routed off it, so by the time FORWARD sees the packet its
    /// input interface is the bridge and not the veth -- an `-i <veth>` rule
    /// matches nothing at all. Measured on a live container: with both rules
    /// present in FORWARD and the same traffic flowing, the `--physdev-in`
    /// rule counted 11 packets while the `-i` rule counted zero.
    ///
    /// `--physdev-in` still names one specific bridge port, so the chain stays
    /// scoped to a single container. Matching the bridge itself would apply
    /// one container's policy to every container sharing it.
    fn build_forward_hook_physdev_rule_args(
        op: &str,
        iface: &str,
        chain_name: &str,
    ) -> Vec<String> {
        vec![
            op.to_string(),
            "FORWARD".to_string(),
            "-m".to_string(),
            "physdev".to_string(),
            "--physdev-in".to_string(),
            iface.to_string(),
            "-j".to_string(),
            chain_name.to_string(),
        ]
    }

    /// Whether `iface` is enslaved to a bridge, looked up under an injectable
    /// sysfs root so this is testable without a live interface.
    ///
    /// The kernel exposes `master` only for an enslaved interface, so its mere
    /// presence is the answer.
    fn veth_is_bridge_enslaved_in(sysfs_net_root: &Path, iface: &str) -> bool {
        sysfs_net_root.join(iface).join("master").exists()
    }

    /// Whether bridged traffic is delivered to iptables at all, read from an
    /// injectable path.
    ///
    /// The file exists only when `br_netfilter` is loaded, and a value of `1`
    /// is what makes `--physdev-in` able to match. Absent or `0`, a bridged
    /// container's packets bypass these chains entirely.
    fn bridge_netfilter_active_at(path: &Path) -> bool {
        std::fs::read_to_string(path)
            .map(|contents| contents.trim() == "1")
            .unwrap_or(false)
    }

    /// Production wrapper over [`Self::veth_is_bridge_enslaved_in`].
    fn veth_is_bridge_enslaved(iface: &str) -> bool {
        Self::veth_is_bridge_enslaved_in(Path::new(SYSFS_NET_ROOT), iface)
    }

    /// Production wrapper over [`Self::bridge_netfilter_active_at`].
    fn bridge_netfilter_active(path: &str) -> bool {
        Self::bridge_netfilter_active_at(Path::new(path))
    }

    /// Install the `--physdev-in` FORWARD hook for one family.
    ///
    /// Whether a failure here is fatal depends entirely on the topology, so
    /// the decision lives in one place rather than being duplicated per
    /// family. On a bridged veth this rule is the only one that can ever
    /// match, so failing to install it means the policy is not enforced and
    /// the caller must not be told otherwise. On a directly routed veth the
    /// `-i` rule already carries the traffic and this one is redundant, so a
    /// host whose kernel lacks the `physdev` match is still correctly
    /// filtered and only warrants a warning.
    fn install_physdev_hook(
        run: fn(&[Vec<String>], &mut Logger) -> Result<(), String>,
        iface: &str,
        chain_name: &str,
        bridged: bool,
        tool: &str,
        logger: &mut Logger,
    ) -> Result<bool, String> {
        let rule = Self::build_forward_hook_physdev_rule_args("-I", iface, chain_name);
        match run(&[rule], logger) {
            Ok(()) => Ok(true),
            Err(err) if bridged => Err(format!(
                "Failed to install the physdev FORWARD hook on bridged veth {} for chain {} \
                 ({}): {}. That rule is the only one a bridged container's packets can match, \
                 so the policy would not be enforced. Refusing to report success for an \
                 unenforceable policy.",
                iface, chain_name, tool, err
            )),
            Err(err) => {
                logger.log_line(&format!(
                    "Warning: could not install the physdev FORWARD hook on {} for chain {} \
                     ({}): {}. The veth is not bridged, so the interface hook already carries \
                     this container's traffic.",
                    iface, chain_name, tool, err
                ));
                Ok(false)
            }
        }
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
        // An empty entry is not a hostname. Without this guard the DNS branch
        // below formats ":0", which Winsock resolves to every local interface
        // address, so an empty policy entry would emit rules for the host's
        // own addresses. glibc rejects ":0", so this only shows up on Windows.
        if host.trim().is_empty() {
            return ResolvedDestinations::default();
        }

        // Rewrite IPv4-mapped destinations to their embedded IPv4 form before
        // the family split, so they are filed under IPv4 and programmed with
        // `iptables`.
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

        // Try DNS resolution. The family split is factored into
        // `bucket_resolved_addrs` so it can be exercised with injected
        // addresses, independent of whether this host has live IPv6 DNS.
        if let Ok(addrs) = format!("{}:0", host).to_socket_addrs() {
            return Self::bucket_resolved_addrs(addrs.map(|addr| addr.ip()));
        }
        ResolvedDestinations::default()
    }

    /// Split resolved addresses into per-family destination buckets: every A
    /// record lands in the IPv4 bucket and every AAAA record in the IPv6
    /// bucket. Pure so the bucketing — the step that keeps an AAAA record from
    /// being handed to `iptables` (the dual-stack bypass AB#62830559 exists to
    /// close) — can be asserted with injected input rather than depending on
    /// the host having live IPv6 DNS.
    fn bucket_resolved_addrs<I: IntoIterator<Item = IpAddr>>(addrs: I) -> ResolvedDestinations {
        let mut resolved = ResolvedDestinations::default();
        for ip in addrs {
            match ip {
                IpAddr::V4(ip) => resolved.ipv4.push(ip.to_string()),
                // A resolver can return a AAAA record in mapped form. It
                // travels as IPv4 on the wire, so it belongs in the IPv4
                // bucket — see `ipv4_mapped_destination`.
                IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
                    Some(v4) => resolved.ipv4.push(v4.to_string()),
                    None => resolved.ipv6.push(ip.to_string()),
                },
            }
        }
        resolved
    }

    /// Rewrite an IPv4-mapped IPv6 destination to its embedded IPv4 form,
    /// returning `None` when `destination` is not mapped.
    ///
    /// Linux puts a genuine IPv4 packet on the wire for a mapped destination,
    /// so an `ip6tables -d ::ffff:a.b.c.d` rule names traffic that never
    /// reaches the IPv6 table and therefore never matches. Under a
    /// `defaultPolicy: allow` policy a mapped `blockedHosts` entry would fail
    /// open: the operator sees a rule programmed, and the traffic is allowed
    /// anyway. Rewriting to `a.b.c.d` files the entry under `iptables`, where
    /// it matches.
    ///
    /// Handles CIDRs inside `::ffff:0:0/96` as well. Because the mapped range
    /// is the final 32 bits of that /96, an IPv6 prefix of `96 + n` is exactly
    /// an IPv4 prefix of `n`. A prefix shorter than 96 covers addresses
    /// outside the mapped range and cannot be expressed as one IPv4 CIDR, so
    /// it is left as IPv6.
    fn ipv4_mapped_destination(destination: &str) -> Option<String> {
        let Some((network, prefix)) = destination.split_once('/') else {
            return destination
                .parse::<Ipv6Addr>()
                .ok()?
                .to_ipv4_mapped()
                .map(|v4| v4.to_string());
        };

        // Match `destination_family`'s digits-only rule so this rewrite cannot
        // launder a malformed prefix (`/+120`) into a well-formed IPv4 CIDR.
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
            // The prefix must be digits only. `u8::from_str` would otherwise
            // accept a leading `+`, so `10.0.0.0/+24` would be forwarded to
            // iptables, which silently canonicalizes it to `10.0.0.0/24`. A
            // typo in a policy file would then be applied instead of being
            // reported by the unresolved-host warning. Also subsumes the
            // embedded-slash case, e.g. `10.0.0.0/20/8`.
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

    /// The catch-all action for a chain. Proxy mode is "deny all except the
    /// proxy", so it always closes with DROP regardless of the configured
    /// default policy.
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

    /// Build the ACCEPT rules that open the proxy endpoints, and nothing else.
    ///
    /// These are the only allow rules a proxied chain carries. They are emitted
    /// straight before the closing DROP from
    /// [`Self::build_default_policy_rule_arg`], so the chain reads "the proxy,
    /// then nothing".
    ///
    /// IPv4 only, so the caller must not run these through `ip6tables`: the
    /// endpoints come from [`Self::resolve_proxy_endpoints`], which refuses an
    /// IPv6 proxy rather than programming a rule for it. A proxied IPv6 chain
    /// therefore holds its closing DROP alone, which is the fail-closed
    /// outcome -- IPv6 egress is denied rather than left open.
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

    /// Whether `host` is an IPv6 literal (bracketed `[..]` or bare).
    ///
    /// The proxy firewall rule is emitted with IPv4 `iptables` only, so an IPv6
    /// proxy endpoint cannot be enforced. It must be rejected explicitly rather
    /// than passed through IPv4-only endpoint selection, which would drop it and
    /// leave a deny-all container whose proxy was silently discarded.
    fn host_is_ipv6_literal(host: &str) -> bool {
        let candidate = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        matches!(candidate.parse::<IpAddr>(), Ok(IpAddr::V6(_)))
    }

    /// The error returned when a proxy endpoint is IPv6, which the IPv4-only
    /// proxy firewall rule cannot enforce.
    fn ipv6_proxy_unsupported(host: &str) -> String {
        format!(
            "IPv6 network proxy endpoints are not supported: the proxy firewall rule is \
             emitted with IPv4 iptables only, so '{}' cannot be enforced and would be \
             silently dropped. Use an IPv4 proxy address.",
            host
        )
    }

    /// Resolve the policy's proxy into the destinations the chain will allow,
    /// and the hosts-file pin the container needs to agree with them.
    ///
    /// Returns an empty vector when the policy carries no proxy, which is what
    /// puts the chain back on the ordinary allow/block path.
    ///
    /// The pin is produced from this same resolution rather than from a second
    /// lookup. Two lookups of one name can disagree -- DNS round-robin returns
    /// a different order, or a TTL expires between the calls -- and a container
    /// pinned to an address this chain did not authorize cannot reach its
    /// proxy at all. `None` means no pin is needed because the address is
    /// already an IP literal.
    ///
    /// Every resolved IPv4 address is opened, not just the pinned one. They are
    /// all addresses of the configured proxy host, so the posture is unchanged,
    /// and a client that resolves the name through something other than
    /// `/etc/hosts` still reaches the proxy instead of being dropped.
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

        // Reject an IPv6 literal explicitly. Selecting the IPv4 bucket below
        // would leave it empty, which the emptiness check would then report as
        // an unresolvable host -- a misleading error for a perfectly valid
        // literal we simply cannot enforce.
        if Self::host_is_ipv6_literal(address.host()) {
            return Err(Self::ipv6_proxy_unsupported(address.host()));
        }

        let resolved = Self::resolve_host(address.host());
        if resolved.ipv4.is_empty() {
            // A name with AAAA records and no A records is the same
            // unenforceable case as the literal above, so say so rather than
            // claiming the name does not resolve.
            if !resolved.ipv6.is_empty() {
                return Err(Self::ipv6_proxy_unsupported(address.host()));
            }
            return Err(format!(
                "Could not resolve network proxy host '{}'",
                address.host()
            ));
        }

        let endpoints: Vec<ProxyEndpoint> = resolved
            .ipv4
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

    /// Build the hosts-file pin that makes the container resolve the proxy
    /// hostname to `ip`.
    ///
    /// Under "deny all except the proxy" the chain opens no port 53, so the
    /// container has no resolver to reach: the pin is what lets it find the
    /// proxy at all, and it also stops the container selecting an address the
    /// chain never allowed.
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
    ) -> FirewallRuleArgs {
        let mut args = FirewallRuleArgs::default();
        for destination in &destinations.ipv4 {
            args.ipv4.push(Self::build_single_rule_args(
                chain_name,
                destination,
                action,
            ));
        }
        for destination in &destinations.ipv6 {
            args.ipv6.push(Self::build_single_rule_args(
                chain_name,
                destination,
                action,
            ));
        }
        args
    }

    fn build_single_rule_args(
        chain_name: &str,
        destination: &str,
        action: &RuleAction,
    ) -> Vec<String> {
        vec![
            "-A".to_string(),
            chain_name.to_string(),
            "-d".to_string(),
            destination.to_string(),
            "-j".to_string(),
            Self::rule_action_arg(action).to_string(),
        ]
    }

    /// Build the allow/deny rule args for a single host by resolving it once.
    /// Test-only: production goes through [`Self::build_policy_rules_logged`],
    /// which resolves every entry exactly once and reuses that result for both
    /// the unresolved-host warning and rule construction.
    #[cfg(test)]
    fn build_host_rule_args(chain_name: &str, host: &str, action: &RuleAction) -> FirewallRuleArgs {
        let destinations = Self::resolve_host(host);
        Self::build_resolved_destination_rule_args(chain_name, &destinations, action)
    }

    /// Build the allow/deny rule args for a container policy.
    ///
    /// Test-only shim over the shipping path [`Self::build_policy_rules_logged`]
    /// so the rulegen spec assertions — including the deny-before-allow
    /// ordering that is a security-semantics contract (AB#62830341) — bind to
    /// the code that actually runs, not to a duplicate iteration. The
    /// unresolved-host warning is irrelevant to rule generation, so it is
    /// discarded to a buffer logger. Production must never call this: it takes
    /// no logger and would resolve entries a second time relative to the
    /// warning pass.
    ///
    /// This shim panics on the unresolvable-block-entry error so that the many
    /// rulegen assertions over well-formed policies keep a plain return type. A
    /// test that exercises the error path must call
    /// [`Self::build_policy_rules_logged`] directly and inspect the `Result`.
    #[cfg(test)]
    fn build_policy_rule_args(chain_name: &str, policy: &ContainerPolicy) -> FirewallRuleArgs {
        let mut logger = wxc_common::logger::Logger::new(wxc_common::logger::Mode::Buffer);
        Self::build_policy_rules_logged(chain_name, policy, &mut logger).expect(
            "test policy should not pair an accepting default with an unresolvable block entry",
        )
    }

    /// Resolve every allow/block entry exactly once and build the rule args
    /// from that single resolution, logging a warning for any entry that
    /// resolved to nothing. This is the shipping rule-generation path.
    ///
    /// Resolving once is a correctness requirement, not just an optimization:
    /// the previous apply path resolved each host once for the warning pass
    /// and again inside rule construction, and two lookups of the same name
    /// can disagree — DNS round-robin returns a different address, or a TTL
    /// expires between the calls — so the rule installed would not match the
    /// rule that was validated and logged.
    ///
    /// Deny-precedence (AB#62830341): block-list rules are emitted before
    /// allow-list rules, and iptables/ip6tables apply first-match-wins within
    /// the chain, so a destination present in both lists is DROPped. Emission
    /// order is the entire precedence mechanism — there is no separate
    /// resolution pass — so swapping these two iterators silently reverses the
    /// security semantics of every policy whose lists overlap.
    ///
    /// A block entry that resolves to nothing programs no rule. That is a
    /// containment failure only when something else would then permit the
    /// destination, so the response depends on the default policy. Under
    /// [`NetworkPolicy::Allow`] the chain ends in ACCEPT and the unwritten deny
    /// rule was the only thing that would have stopped the traffic, so the
    /// apply fails closed with an error rather than reporting success over a
    /// policy it did not enforce. Under [`NetworkPolicy::Block`] the closing
    /// DROP already denies every destination the allow list did not name, so an
    /// unresolvable block entry is redundant rather than missing — the ordinary
    /// case being a blocklist naming a host that does not exist at all — and a
    /// warning is the proportionate response.
    ///
    /// That reasoning holds only while the closing DROP is what the traffic
    /// actually reaches. An allow rule is evaluated first, and since
    /// `resolve_host` passes CIDRs through unchanged, one entry can legally
    /// cover the whole address space. So under [`NetworkPolicy::Block`] the
    /// combination of an unresolvable deny and any programmed allow fails
    /// closed as well. Deciding it does not require the address the deny failed
    /// to resolve to: precisely because that address is unknown, no allow can
    /// be shown to miss it, and a deny that cannot be shown to win does not
    /// win.
    ///
    /// An unresolvable allow entry is always a warning: it withholds traffic
    /// that was meant to be permitted, which costs availability and cannot
    /// widen what the container can reach.
    fn build_policy_rules_logged(
        chain_name: &str,
        policy: &ContainerPolicy,
        logger: &mut Logger,
    ) -> Result<FirewallRuleArgs, String> {
        let default_permits = matches!(policy.default_network_policy, NetworkPolicy::Allow);
        let mut args = FirewallRuleArgs::default();
        let mut unresolved_denies: Vec<&str> = Vec::new();
        let mut programmed_an_allow = false;
        let entries = policy
            .blocked_hosts
            .iter()
            .map(|host| (host, RuleAction::Deny))
            .chain(
                policy
                    .allowed_hosts
                    .iter()
                    .map(|host| (host, RuleAction::Allow)),
            );
        for (host, action) in entries {
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
            } else if matches!(action, RuleAction::Allow) {
                programmed_an_allow = true;
            }
            let rule_args =
                Self::build_resolved_destination_rule_args(chain_name, &destinations, &action);
            // Log each destination rule that will be programmed, derived from
            // the built args rather than from `destinations`, so that removing
            // destination-rule emission also removes these lines. This is the
            // observable surface the end-to-end scripts assert on to prove a
            // rule for a specific destination was actually generated while the
            // chain is live (a warning-only or chain-only run would not).
            for rule in &rule_args.ipv4 {
                logger.log_line(&format!("Programmed iptables rule: {}", rule.join(" ")));
            }
            for rule in &rule_args.ipv6 {
                logger.log_line(&format!("Programmed ip6tables rule: {}", rule.join(" ")));
            }
            args.extend(rule_args);
        }
        // Under a denying default an unresolvable deny was tolerated on the
        // grounds that the chain's closing DROP covers whatever the missing
        // rule would have covered. That holds only while nothing can ACCEPT
        // first. A programmed allow -- and `resolve_host` passes CIDRs through
        // untouched, so `0.0.0.0/0` is a legal one -- emits its ACCEPT ahead of
        // that DROP. Because the deny never resolved, its addresses are
        // unknown, so no allow can be shown to miss them; the very destination
        // the operator named is then accepted by a rule they wrote for an
        // unrelated purpose. Deny-wins cannot be established, so fail closed.
        if !unresolved_denies.is_empty() && programmed_an_allow {
            return Err(format!(
                "blocked host(s) {} resolved to no address, so no rule can be programmed \
                 to deny them, and this policy also programs an allow rule that is \
                 evaluated before the chain's closing DROP; because the blocked host has \
                 no known address, that allow cannot be shown not to cover it, and deny \
                 precedence cannot be guaranteed. Fix or remove the unresolvable blocked \
                 host, or remove the allowed hosts",
                unresolved_denies
                    .iter()
                    .map(|h| format!("'{}'", h))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        Ok(args)
    }

    /// Run an iptables command and return success/failure.
    fn run_iptables(args: &[&str], logger: &mut Logger) -> Result<bool, String> {
        Self::run_firewall_command("iptables", args, logger)
    }

    /// Run an ip6tables command and return success/failure.
    fn run_ip6tables(args: &[&str], logger: &mut Logger) -> Result<bool, String> {
        Self::run_firewall_command("ip6tables", args, logger)
    }

    /// Classify whether `ip6tables` is usable, given whether the read-only
    /// probe succeeded and whether the host currently has active IPv6. Pure so
    /// the fail-open-vs-fail-closed decision can be unit-tested without a
    /// privileged Linux host.
    ///
    /// A working probe means the tool is usable regardless of address state.
    /// A failed probe splits on whether IPv6 is live: if the kernel has no
    /// active IPv6 there is nothing to filter and skipping is safe, but if
    /// IPv6 is live the tool is genuinely missing or broken and setup must
    /// fail closed rather than leave IPv6 egress unfiltered.
    fn classify_ip6tables_status(probe_succeeded: bool, host_ipv6_active: bool) -> Ip6tablesStatus {
        match (probe_succeeded, host_ipv6_active) {
            (true, _) => Ip6tablesStatus::Available,
            (false, true) => Ip6tablesStatus::UnusableButIpv6Active,
            (false, false) => Ip6tablesStatus::KernelIpv6Disabled,
        }
    }

    /// Whether the host has an active, egress-capable IPv6 stack, independent
    /// of `ip6tables`.
    ///
    /// Reads `/proc/net/if_inet6` and defers the parse/classify decision to
    /// [`Self::classify_host_ipv6_state`] so the file-content → state mapping
    /// is unit-testable without a privileged Linux host. Also reports whether
    /// `/proc/net` exists, which is what separates "the kernel has IPv6 off"
    /// from "`/proc` is not mounted here".
    fn host_ipv6_state() -> HostIpv6State {
        Self::classify_host_ipv6_state(
            std::fs::read_to_string("/proc/net/if_inet6"),
            std::path::Path::new("/proc/net").is_dir(),
        )
    }

    /// Classify host IPv6 activity from the result of reading
    /// `/proc/net/if_inet6`. Pure so every branch — including the read-error
    /// case — can be exercised with injected input.
    ///
    /// `/proc/net/if_inet6` is populated by the kernel only when the IPv6
    /// module is loaded, and lists one interface IPv6 address per line with
    /// the device name in the final whitespace-delimited field. Loopback
    /// (`::1` on `lo`) is present even on IPv4-only hosts and is not
    /// egress-capable, so a line is treated as evidence of active IPv6 only
    /// when its device is something other than `lo`.
    ///
    /// The error handling is deliberate:
    /// - A `NotFound` error **while `/proc/net` exists** means the kernel
    ///   never created the file (IPv6 disabled at boot via `ipv6.disable=1`,
    ///   or the module is not loaded). That is a genuine, confirmed negative
    ///   → `Inactive`.
    /// - A `NotFound` error when `/proc/net` is *also* absent says nothing
    ///   about IPv6: `/proc` is not mounted, so the probe never ran. Both
    ///   cases surface as the same `ErrorKind`, so without the directory
    ///   check an unmounted `/proc` would be read as a confirmed "IPv6 is
    ///   off" → `Unknown`.
    /// - Any other read error (permission denied, I/O error) likewise leaves
    ///   the state `Unknown` rather than asserting IPv6 is off. Converting
    ///   such an error into `Inactive` would fail open.
    fn classify_host_ipv6_state(
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
                    // The device name is the final field; loopback carries only
                    // `::1`, which is not egress-capable.
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
            // A missing `/proc/net/if_inet6` is only evidence that IPv6 is off
            // when `/proc/net` itself is there. Both an IPv6-disabled kernel
            // and an unmounted `/proc` report `NotFound` for the file, and
            // treating the second as "IPv6 is off" would fail open on a host
            // whose IPv6 state was never actually read.
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

    /// Whether the IPv6 status probe should treat the host as capable of IPv6
    /// egress. Reads the host state, logs the `Unknown` case distinctly so the
    /// uncertainty is visible in the run output, then defers the mapping to the
    /// pure [`Self::ipv6_state_treated_as_active`].
    fn host_ipv6_egress_possible(logger: &mut Logger) -> bool {
        let state = Self::host_ipv6_state();
        if state == HostIpv6State::Unknown {
            logger.log_line(
                "Could not read /proc/net/if_inet6 to determine host IPv6 state; \
                 treating IPv6 as potentially active and refusing to fail open.",
            );
        }
        Self::ipv6_state_treated_as_active(state)
    }

    /// Map a host IPv6 state to whether the `ip6tables` probe should treat IPv6
    /// as active. `Active` obviously counts; `Unknown` also counts, because an
    /// unreadable IPv6 state must not be silently downgraded to "IPv6 is off" —
    /// under a drop-required stance the safe reaction to "we do not know" is to
    /// keep filtering (and, if `ip6tables` is then unusable, to fail closed)
    /// rather than to leave IPv6 egress unfiltered. Pure so the decision is
    /// unit-testable.
    fn ipv6_state_treated_as_active(state: HostIpv6State) -> bool {
        match state {
            HostIpv6State::Active | HostIpv6State::Unknown => true,
            HostIpv6State::Inactive => false,
        }
    }

    /// Probe whether `ip6tables` can be used on this host and classify the
    /// result. Runs a harmless, read-only `ip6tables -S` (list the filter
    /// table), then distinguishes a kernel with IPv6 disabled (safe to skip
    /// the parallel v6 chain) from an IPv6-capable host whose `ip6tables` is
    /// missing or broken (must fail setup, since applying only the v4 policy
    /// would silently leave IPv6 egress unfiltered).
    fn ip6tables_status(logger: &mut Logger) -> Ip6tablesStatus {
        let probe_succeeded = Self::ip6tables_probe_succeeded(logger);

        let status = Self::classify_ip6tables_status(
            probe_succeeded,
            Self::host_ipv6_egress_possible(logger),
        );
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

    /// Run the read-only `ip6tables -S` probe, reporting whether the tool is
    /// usable.
    ///
    /// Split out from [`Self::ip6tables_status`] because it is the second of
    /// this file's two process spawns and the apply path reaches it before any
    /// chain exists, so a test that does not intercept it takes a different
    /// branch depending on the host's `ip6tables`.
    fn ip6tables_probe_succeeded(logger: &mut Logger) -> bool {
        #[cfg(test)]
        if let Some(succeeded) = test_firewall::intercept_ip6tables_probe() {
            return succeeded;
        }

        match Command::new("ip6tables").arg("-S").output() {
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
        command: &str,
        args: &[&str],
        logger: &mut Logger,
    ) -> Result<bool, String> {
        // A unit test may install a fake to record this command and supply its
        // outcome, so the test states its own precondition instead of
        // inheriting one from whatever `iptables` the host happens to have.
        // Interception is opt-in: with no fake installed the real binary runs
        // exactly as it did before, so tests that do not opt in are unaffected.
        #[cfg(test)]
        if let Some(outcome) = test_firewall::intercept(command, args) {
            return match outcome {
                Ok(()) => Ok(true),
                Err(stderr) => Err(Self::log_command_failure(command, args, &stderr, logger)),
            };
        }

        let output = Command::new(command)
            .args(args)
            .output()
            .map_err(|e| format!("Failed to run {}: {}", command, e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Self::log_command_failure(command, args, &stderr, logger));
        }

        Ok(true)
    }

    /// Log a failed firewall command and return the message that becomes the
    /// error. Shared by the real path and the test fake so a scripted failure
    /// produces the same log line and error text as a genuine one, rather than
    /// the fake reimplementing the format and drifting from it.
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

    /// Whether the given enforcement mode is served by the iptables firewall
    /// backend. Pure and side-effect-free so the gate can be exercised without
    /// invoking the host firewall.
    fn enforcement_mode_uses_firewall(mode: &NetworkEnforcementMode) -> bool {
        matches!(
            mode,
            NetworkEnforcementMode::Firewall | NetworkEnforcementMode::Both
        )
    }

    /// Apply network firewall rules based on the container policy.
    ///
    /// On any failure after resources are created, the inner call rolls back
    /// exactly the per-family chains and FORWARD hooks this attempt installed
    /// before the error is returned, so a retry does not trip over a leftover
    /// `MXC-<name>` chain ("chain already exists") and a partial failure never
    /// tears down a chain this attempt did not create.
    ///
    /// A policy carrying a proxy is resolved here, once, before any rule is
    /// installed. The resulting endpoints are what the chain opens and the
    /// recorded [`Self::proxy_host_pin`] is what the container must be given,
    /// so both sides name the address a single lookup returned.
    pub fn apply_firewall_rules(
        &mut self,
        policy: &ContainerPolicy,
        logger: &mut Logger,
    ) -> Result<bool, String> {
        // Skip if network enforcement doesn't use firewall.
        if !Self::enforcement_mode_uses_firewall(&policy.network_enforcement_mode) {
            logger.log_line("Network enforcement mode does not use firewall, skipping iptables.");
            return Ok(true);
        }

        // Both arms below replace `self.created` with this attempt's set, so a
        // second apply on a manager that still owns resources would drop the
        // earlier record and strand whatever it named. Every caller builds a
        // manager immediately before its single apply, so refusing here costs
        // nothing and makes the hazard unreachable rather than leaving it to
        // callers to avoid.
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

        let outcome = self.apply_firewall_rules_inner(policy, &proxy_endpoints, logger);
        self.record_apply_outcome(outcome, logger)
    }

    /// Record what an apply attempt left behind and turn it into the public
    /// result.
    ///
    /// Split out from [`Self::apply_firewall_rules`] so a test can drive the
    /// failure arm directly. On a real host the inner call fails on its very
    /// first command, which rolls back nothing and so never produces the
    /// residual this arm exists to adopt -- the branch that matters is the one
    /// that is hardest to reach by accident.
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
                // The inner call rolled back exactly what it created, but a
                // removal command can itself fail. Whatever survived is still
                // ours, so adopt it rather than reporting a clean failure:
                // otherwise `remove_firewall_rules` and `Drop` are both gated
                // off and the leaked chain is never retried.
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

    /// Take ownership of whatever a teardown could not remove, so the
    /// remaining cleanup paths retry it.
    ///
    /// Returns whether anything was retained. `rules_applied` is the gate on
    /// both [`Self::remove_firewall_rules`] and `Drop`, so clearing it after a
    /// teardown that only partly succeeded strands the survivors: no later path
    /// would know they were ours to remove.  This is shared by the failed-apply
    /// rollback and the ordinary removal path, which have the same obligation.
    fn retain_residual_ownership(&mut self, residual: CreatedResources) -> bool {
        self.created = residual;
        self.rules_applied = !residual.is_empty();
        self.rules_applied
    }

    /// Fallible body of [`Self::apply_firewall_rules`]. Tracks the chains and
    /// hooks it creates, rolls back exactly those on the error path, and
    /// returns the created set on success so the manager can tear down only
    /// what it installed.
    ///
    /// On failure it returns the error alongside the **residual** set: the
    /// resources whose rollback command itself failed and which therefore may
    /// still exist. A failed rollback is not a clean failure, so the caller
    /// must adopt the residual instead of discarding it.
    fn apply_firewall_rules_inner(
        &self,
        policy: &ContainerPolicy,
        proxy_endpoints: &[ProxyEndpoint],
        logger: &mut Logger,
    ) -> Result<CreatedResources, (String, CreatedResources)> {
        let mut created = CreatedResources::default();
        match self.install_firewall_rules(policy, proxy_endpoints, logger, &mut created) {
            Ok(()) => Ok(created),
            Err(e) => {
                let residual = Self::teardown_created(
                    &self.chain_name,
                    self.veth_interface.as_deref(),
                    &created,
                    logger,
                );
                Err((e, residual))
            }
        }
    }

    /// Install the per-family chains, rules, and FORWARD hooks, recording each
    /// resource in `created` immediately after it is successfully installed so
    /// the caller can roll back precisely on any later failure.
    fn install_firewall_rules(
        &self,
        policy: &ContainerPolicy,
        proxy_endpoints: &[ProxyEndpoint],
        logger: &mut Logger,
        created: &mut CreatedResources,
    ) -> Result<(), String> {
        logger.log_line(&format!(
            "Creating iptables/ip6tables chain: {}",
            self.chain_name
        ));

        // Probe ip6tables once. Skip the v6 chain when the kernel has no
        // active IPv6 (nothing to filter), but fail closed when IPv6 is live
        // and ip6tables is missing or broken rather than silently leaving
        // IPv6 egress unfiltered.
        let ipv6_enabled = match Self::ip6tables_status(logger) {
            Ip6tablesStatus::Available => true,
            Ip6tablesStatus::KernelIpv6Disabled => false,
            Ip6tablesStatus::UnusableButIpv6Active => {
                return Err(
                    "ip6tables is unusable but the host has active IPv6; refusing to \
                     apply an IPv4-only policy that would leave IPv6 egress unfiltered"
                        .to_string(),
                );
            }
        };

        // Create custom chains, recording each family as created so rollback
        // removes only the chains this attempt installed.
        Self::run_iptables(&["-N", &self.chain_name], logger)?;
        created.v4_chain = true;
        Self::publish_created(created);
        if ipv6_enabled {
            Self::run_ip6tables(&["-N", &self.chain_name], logger)?;
            created.v6_chain = true;
            Self::publish_created(created);
        }

        let proxy_mode = !proxy_endpoints.is_empty();

        if proxy_mode {
            // Proxy mode is "deny all except the proxy", so the chain carries
            // the proxy ACCEPTs and its closing DROP and nothing else.
            //
            // None of the base exemptions belong here. There is no port 53
            // accept because the container resolves the proxy through the
            // hosts-file pin instead, and an unscoped one would be a standing
            // DNS-tunnel exfil path through a posture whose whole point is
            // that the proxy is the only reachable destination. There is no
            // `-i lo` accept because every packet reaching this chain arrived
            // on the container's veth by construction, and no
            // ESTABLISHED,RELATED accept because return traffic flows toward
            // the container and never traverses it -- such a rule would only
            // let flows opened before the chain existed keep running straight
            // through the deny-all posture.
            //
            // The allow and block lists are not programmed either: every
            // destination other than the proxy is denied by the closing DROP,
            // so a block entry is redundant, and an allow entry naming
            // anything but the proxy contradicts the model.
            let proxy_rules = Self::build_proxy_chain_rule_args(&self.chain_name, proxy_endpoints);
            Self::run_iptables_rule_args(&proxy_rules, logger)?;
            for rule in &proxy_rules {
                logger.log_line(&format!("Programmed iptables rule: {}", rule.join(" ")));
            }
            if !policy.allowed_hosts.is_empty() || !policy.blocked_hosts.is_empty() {
                logger.log_line(
                    "Warning: network.proxy is configured, so allowedHosts and blockedHosts \
                     are not programmed; the container may reach the proxy and nothing else.",
                );
            }
            if ipv6_enabled {
                logger.log_line(
                    "IPv6 egress is denied outright while a proxy is configured: the proxy \
                     endpoint is IPv4, so the IPv6 chain carries only its closing DROP.",
                );
            }
        } else {
            let base_rules = Self::build_base_chain_rule_args(&self.chain_name);
            Self::run_iptables_rule_args(&base_rules, logger)?;
            if ipv6_enabled {
                Self::run_ip6tables_rule_args(&base_rules, logger)?;
            }

            // Resolve every allow/block entry exactly once and reuse that single
            // resolution for both the unresolved-host warning and rule
            // construction, so the rule installed matches the entry that was
            // validated and logged. A block entry that resolves to nothing is an
            // error here rather than a warning, and propagating it aborts the
            // apply so the caller rolls back the chains created above instead of
            // leaving a chain that is missing one of its deny rules.
            let policy_rules = Self::build_policy_rules_logged(&self.chain_name, policy, logger)?;
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
        }

        // Append default policy at end of each chain.
        let default_rule = Self::build_default_policy_rule_arg(
            &self.chain_name,
            policy.default_network_policy.clone(),
            proxy_mode,
        );
        let default_args: Vec<&str> = default_rule.iter().map(String::as_str).collect();
        let default_action = default_args.last().copied().unwrap_or("ACCEPT");
        logger.log_line(&format!("Default network policy: {}", default_action));
        Self::run_iptables(&default_args, logger)?;
        if ipv6_enabled {
            Self::run_ip6tables(&default_args, logger)?;
        }

        // Hook the chains into FORWARD for the container's egress traffic.
        //
        // Two rules per family, because the input interface FORWARD sees
        // depends on how the veth is attached. A veth routed directly by the
        // host arrives as `-i <veth>`. A veth enslaved to a bridge -- the
        // default LXC topology -- arrives as `-i <bridge>`, and only
        // `--physdev-in <veth>` still identifies the container. Installing
        // only the first is what let a fully populated deny-all chain sit in
        // the ruleset filtering nothing.
        //
        // The two are mutually exclusive for any given packet, so no packet is
        // counted twice. `-o` would instead match traffic flowing toward the
        // container.
        if let Some(ref iface) = self.veth_interface {
            let bridged = Self::veth_is_bridge_enslaved(iface);
            let chain_name = self.chain_name.clone();

            // On a bridged veth the physdev rule is the only one that can
            // match, and it can only match while br_netfilter is delivering
            // bridged packets to iptables. Without that, both rules install
            // cleanly and neither ever fires, which is the exact failure this
            // change exists to remove: a chain that looks enforced and is not.
            if bridged && !Self::bridge_netfilter_active(BRIDGE_NF_CALL_IPTABLES) {
                return Err(format!(
                    "Container veth {} is enslaved to a bridge but bridged packets are not \
                     delivered to iptables ({} is absent or 0), so chain {} could never be \
                     reached from FORWARD. Refusing to report success for an unenforceable \
                     policy.",
                    iface, BRIDGE_NF_CALL_IPTABLES, chain_name
                ));
            }

            Self::run_iptables_rule_args(
                &[Self::build_forward_hook_iface_rule_args(
                    "-I",
                    iface,
                    &chain_name,
                )],
                logger,
            )?;
            created.v4_hook = true;
            Self::publish_created(created);

            created.v4_physdev_hook = Self::install_physdev_hook(
                Self::run_iptables_rule_args,
                iface,
                &chain_name,
                bridged,
                "iptables",
                logger,
            )?;
            Self::publish_created(created);
            logger.log_line(&format!(
                "FORWARD hook installed on {} for chain {} (iptables).",
                iface, chain_name
            ));
            if ipv6_enabled {
                if bridged && !Self::bridge_netfilter_active(BRIDGE_NF_CALL_IP6TABLES) {
                    return Err(format!(
                        "Container veth {} is enslaved to a bridge but bridged packets are not \
                         delivered to ip6tables ({} is absent or 0), so chain {} could never be \
                         reached from FORWARD for IPv6. Refusing to report success for an \
                         unenforceable policy.",
                        iface, BRIDGE_NF_CALL_IP6TABLES, chain_name
                    ));
                }

                Self::run_ip6tables_rule_args(
                    &[Self::build_forward_hook_iface_rule_args(
                        "-I",
                        iface,
                        &chain_name,
                    )],
                    logger,
                )?;
                created.v6_hook = true;
                Self::publish_created(created);

                created.v6_physdev_hook = Self::install_physdev_hook(
                    Self::run_ip6tables_rule_args,
                    iface,
                    &chain_name,
                    bridged,
                    "ip6tables",
                    logger,
                )?;
                Self::publish_created(created);

                logger.log_line(&format!(
                    "FORWARD hook installed on {} for chain {} (ip6tables).",
                    iface, chain_name
                ));
            }
        } else {
            // Without a veth interface there is nothing to hook the chain to,
            // and an unhooked chain is never traversed: FORWARD reaches it only
            // via a rule naming the veth, whether as the input interface or as
            // the bridge port. Reporting success here would hand the caller a
            // fully populated deny-all chain that filters nothing, which is
            // strictly worse than no firewall at all because it looks enforced.
            //
            // The alternative -- installing the rules host-wide so they do take
            // effect -- is not acceptable either: unscoped they would apply to
            // every container and to the host's own traffic.
            //
            // So the only honest outcome is to fail. `apply_firewall_rules_inner`
            // rolls back the chains recorded in `created`, and `lxc_runner`
            // destroys the container rather than starting a workload that
            // believes it is confined.
            //
            // A caller that has declared it never had a veth to begin with is
            // the one exception. For it a missing veth is not a lost lookup, so
            // failing would only refuse to start a sandbox that was never going
            // to be scopable. It keeps the pre-existing skip, which leaves the
            // policy unenforced -- see `allow_missing_veth_interface`.
            if !self.veth_scoping_optional {
                return Err(format!(
                    "No veth interface for container; cannot scope iptables rules to chain {}. \
                     The chain would never be reached from FORWARD, so the network policy would \
                     not be enforced. Refusing to report success for an unenforceable policy.",
                    self.chain_name
                ));
            }

            logger.log_line(
                "Warning: No veth interface set for container. \
                 Cannot scope iptables rules. Skipping FORWARD hook.",
            );
        }

        Ok(())
    }

    /// Publish the set of resources created so far to the signal-cleanup
    /// registry, so a fatal signal tears down exactly what exists.
    ///
    /// Called after **each** individual resource is installed rather than once
    /// at the end of a successful apply. Publishing only on success would mean
    /// a signal arriving mid-apply sees an empty set, removes nothing, and
    /// leaks the partially created chain.
    fn publish_created(created: &CreatedResources) {
        crate::signal_cleanup::set_active_created(*created);
    }

    /// Best-effort removal of the FORWARD hooks and per-container chains that
    /// `created` records were installed, in both tables. Only resources marked
    /// as created are touched, so a partial-failure rollback never tears down
    /// a chain this attempt did not create — which matters because chain names
    /// truncate at 20 characters and can collide across containers. A missing
    /// rule/chain still makes an individual `-D`/`-F`/`-X` call a no-op, so it
    /// doubles as the rollback path for a failed apply.
    ///
    /// Returns the **residual** set: the resources whose removal command
    /// failed and which therefore may still exist. Clearing ownership for a
    /// deletion that failed would strand the resource, because nothing would
    /// then know it was ours to remove. The residual is published before
    /// returning, so signal-time cleanup retries exactly the leftovers.
    fn teardown_created(
        chain_name: &str,
        veth_interface: Option<&str>,
        created: &CreatedResources,
        logger: &mut Logger,
    ) -> CreatedResources {
        let mut residual = *created;

        // Remove from FORWARD only for families this attempt hooked, and only
        // the hook forms it actually installed. Both specs come from the same
        // builders used at insertion, because iptables deletes by full rule
        // specification: a spec that differs by even one match -- `-o` instead
        // of `-i`, or the interface rule standing in for the physdev one --
        // finds nothing and leaks the hook.
        if let Some(iface) = veth_interface {
            if created.v4_hook
                && Self::run_iptables_rule_args(
                    &[Self::build_forward_hook_iface_rule_args(
                        "-D", iface, chain_name,
                    )],
                    logger,
                )
                .is_ok()
            {
                residual.v4_hook = false;
            }
            if created.v4_physdev_hook
                && Self::run_iptables_rule_args(
                    &[Self::build_forward_hook_physdev_rule_args(
                        "-D", iface, chain_name,
                    )],
                    logger,
                )
                .is_ok()
            {
                residual.v4_physdev_hook = false;
            }
            if created.v6_hook
                && Self::run_ip6tables_rule_args(
                    &[Self::build_forward_hook_iface_rule_args(
                        "-D", iface, chain_name,
                    )],
                    logger,
                )
                .is_ok()
            {
                residual.v6_hook = false;
            }
            if created.v6_physdev_hook
                && Self::run_ip6tables_rule_args(
                    &[Self::build_forward_hook_physdev_rule_args(
                        "-D", iface, chain_name,
                    )],
                    logger,
                )
                .is_ok()
            {
                residual.v6_physdev_hook = false;
            }
        }

        // Flush and delete only the chains this attempt created, and only once
        // every FORWARD hook for that family is confirmed gone. `-X` is the
        // command that actually relinquishes the chain, so ownership is only
        // cleared when it succeeds. Either surviving hook still references the
        // chain, so both gate the delete. The gate is per family because the
        // two chains live in different tables and are referenced independently.
        residual.v4_chain = teardown_chain(
            created.v4_chain,
            residual.v4_hook || residual.v4_physdev_hook,
            logger,
            |logger| {
                let _ = Self::run_iptables(&["-F", chain_name], logger);
            },
            |logger| Self::run_iptables(&["-X", chain_name], logger).is_ok(),
        );
        residual.v6_chain = teardown_chain(
            created.v6_chain,
            residual.v6_hook || residual.v6_physdev_hook,
            logger,
            |logger| {
                let _ = Self::run_ip6tables(&["-F", chain_name], logger);
            },
            |logger| Self::run_ip6tables(&["-X", chain_name], logger).is_ok(),
        );

        Self::publish_created(&residual);
        residual
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

        let residual = Self::teardown_created(
            &self.chain_name,
            self.veth_interface.as_deref(),
            &self.created,
            logger,
        );

        // A removal command can fail, and what survived is still ours. Clearing
        // the gate here regardless would strand it: Drop would then skip the
        // retry that is the last chance to remove it.
        self.retain_residual_ownership(residual);
        Ok(())
    }

    /// Best-effort cleanup of any iptables state the runner installed for a
    /// container, used when the original `NetworkIptablesManager` instance
    /// isn't reachable (e.g. signal-time cleanup from the watchdog thread).
    ///
    /// `created` is the ownership record the runner published as it installed
    /// each resource, carried across the thread boundary by `signal_cleanup`.
    /// Using it — rather than assuming every chain and hook exists — is what
    /// keeps this path from flushing a *different* container's live chain:
    /// chain names sanitize and truncate to 20 characters, so a name collision
    /// would otherwise let a signal delivered to container A empty container
    /// B's chain, silently failing B open.
    ///
    /// The sole caller (`signal_cleanup::run_watchdog`) is Linux-only, so this
    /// is dead code elsewhere. It stays compiled on every target rather than
    /// being `cfg`-gated so Windows and macOS CI still type-check it.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn force_cleanup(
        container_name: &str,
        veth_interface: Option<&str>,
        created: CreatedResources,
        logger: &mut Logger,
    ) {
        // This process created nothing, so there is nothing of ours to remove.
        // Anything present under this chain name belongs to someone else.
        if created.is_empty() {
            return;
        }
        let mut mgr = Self::new(container_name);
        if let Some(v) = veth_interface {
            mgr.set_veth_interface(v);
        }
        // Bypass the rules_applied gate: the manager that set it is on another
        // thread and unreachable from here.
        mgr.rules_applied = true;
        mgr.created = created;
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

/// Test-only interception of this file's two process spawns.
///
/// Unit tests must not reach the real `iptables` binary. As root it would
/// flush and delete whatever live chain answers to a colliding `MXC-<name>`,
/// and a test that needs a command to *fail* would otherwise inherit that
/// outcome from the host rather than arranging it -- so the same test passes
/// on a machine without `iptables` and fails on one with it.
///
/// Interception is opt-in. A test that installs no fake behaves exactly as it
/// did before this seam existed, so the ~70 tests in this file that never
/// reach a firewall command are untouched.
///
/// The installed fake lives in thread-local storage because the firewall entry
/// points are associated functions with no `self` to carry a runner, and
/// because `cargo test` runs tests in parallel -- a process-global fake would
/// have to be serialized behind a lock and would let one test observe
/// another's commands.
/// Spec for the fail-closed behavior when rules cannot be scoped to the
/// container. Attached as a child module rather than a `tests/` integration
/// test because the `test_firewall` seam below is `#[cfg(test)]`, which an
/// integration test -- a separate crate -- can never see. Kept in its own file
/// so this one does not grow further.
#[cfg(test)]
#[path = "network_iptables_veth_spec.rs"]
mod veth_spec;

/// Black-box specification for the FORWARD hook wiring, kept in its own file
/// for the same reason as `veth_spec`.
#[cfg(test)]
#[path = "network_iptables_forward_hook_spec.rs"]
mod forward_hook_spec;

/// Black-box specification for deny-precedence ordering and the fail-closed
/// response to an unresolvable block entry, kept in its own file for the same
/// reason as `veth_spec`.
#[cfg(test)]
#[path = "network_iptables_deny_precedence_spec.rs"]
mod deny_precedence_spec;

/// Black-box specification for cooperative-proxy egress enforcement, kept in
/// its own file for the same reason as `veth_spec`.
#[cfg(test)]
#[path = "network_iptables_proxy_spec.rs"]
mod proxy_spec;

#[cfg(test)]
mod test_firewall {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    struct State {
        issued: Vec<Vec<String>>,
        /// Outcome for the next commands, in order. An exhausted queue falls
        /// back to `fallback`.
        scripted: VecDeque<Result<(), String>>,
        fallback: Result<(), String>,
    }

    thread_local! {
        static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
    }

    /// Installs the fake for the current thread and uninstalls it on drop.
    ///
    /// Declare the guard **before** any manager whose `Drop` tears down: locals
    /// drop in reverse declaration order, so a guard declared first is still
    /// installed while the manager runs its teardown.
    pub(super) struct FakeFirewall;

    /// Intercept every firewall command on this thread. Commands succeed and
    /// the `ip6tables` probe reports the tool available, so a test that cares
    /// about neither gets a deterministic dual-stack host.
    pub(super) fn install() -> FakeFirewall {
        STATE.with(|slot| {
            *slot.borrow_mut() = Some(State {
                issued: Vec::new(),
                scripted: VecDeque::new(),
                fallback: Ok(()),
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
        /// Every command from here on fails with `stderr`.
        pub(super) fn fail_every_command(&self, stderr: &str) -> &Self {
            Self::with_state(|state| state.fallback = Err(stderr.to_string()));
            self
        }

        /// Every command issued so far, in order, each as `[binary, args..]`.
        pub(super) fn issued(&self) -> Vec<Vec<String>> {
            Self::with_state(|state| state.issued.clone())
        }

        /// Forget the commands issued so far, so a later assertion covers only
        /// what was issued after this point.
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

    /// Record a command and return its scripted outcome, or `None` when no
    /// fake is installed so the caller runs the real binary.
    pub(super) fn intercept(command: &str, args: &[&str]) -> Option<Result<(), String>> {
        STATE.with(|slot| {
            let mut slot = slot.borrow_mut();
            let state = slot.as_mut()?;
            let mut argv = Vec::with_capacity(args.len() + 1);
            argv.push(command.to_string());
            argv.extend(args.iter().map(|arg| arg.to_string()));
            state.issued.push(argv);
            Some(
                state
                    .scripted
                    .pop_front()
                    .unwrap_or_else(|| state.fallback.clone()),
            )
        })
    }

    /// The scripted result of the `ip6tables -S` probe, or `None` when no fake
    /// is installed so the caller runs the real probe.
    ///
    /// A fake always reports the tool available. `classify_ip6tables_status`
    /// maps `(true, _)` to `Available` without consulting the host's IPv6
    /// state, so this is the one answer that makes the apply path independent
    /// of the machine the test runs on. Reporting the probe as *failed* would
    /// not be: the classification then turns on `/proc/net/if_inet6`, which
    /// this seam does not fake. Those branches are covered by the pure-function
    /// tests of `classify_ip6tables_status` instead.
    ///
    /// The probe is recorded like any other command so `issued` stays a
    /// complete account of what the code under test would have run.
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
    use wxc_common::models::{ContainerPolicy, NetworkEnforcementMode};

    /// Build a policy requesting the given enforcement mode, leaving every
    /// other field at its default.
    fn policy_requesting_mode(mode: NetworkEnforcementMode) -> ContainerPolicy {
        ContainerPolicy {
            network_enforcement_mode: mode,
            ..Default::default()
        }
    }

    // Bubblewrap has no veth at all, so the fail-closed path that protects LXC
    // would refuse to start every Bubblewrap sandbox asking for firewall mode.
    // A caller that declares the absence up front must still get its chain
    // built. `Firewall` and `Both` are covered separately so a fix scoped to
    // one enforcement mode cannot pass the pair.
    #[test]
    fn a_caller_that_declared_it_has_no_veth_is_not_refused_in_firewall_mode() {
        let _fake = super::test_firewall::install();
        let mut manager = NetworkIptablesManager::new("bwrap-noveth");
        manager.allow_missing_veth_interface();
        let policy = policy_requesting_mode(NetworkEnforcementMode::Firewall);
        let mut logger = Logger::new(Mode::Buffer);

        let result = manager.apply_firewall_rules(&policy, &mut logger);

        assert!(
            result.is_ok(),
            "a caller that declared it has no veth must not be failed closed, got {:?}",
            result
        );
    }

    #[test]
    fn a_caller_that_declared_it_has_no_veth_is_not_refused_in_both_mode() {
        let _fake = super::test_firewall::install();
        let mut manager = NetworkIptablesManager::new("bwrap-noveth-both");
        manager.allow_missing_veth_interface();
        let policy = policy_requesting_mode(NetworkEnforcementMode::Both);
        let mut logger = Logger::new(Mode::Buffer);

        let result = manager.apply_firewall_rules(&policy, &mut logger);

        assert!(
            result.is_ok(),
            "a caller that declared it has no veth must not be failed closed, got {:?}",
            result
        );
    }

    // The accessor is what the Bubblewrap suite asserts on, so it has to be
    // able to say "no". An accessor stuck at true would let that suite pass
    // even if the declaration were never made.
    #[test]
    fn a_fresh_manager_has_not_declared_a_missing_veth_as_expected() {
        let manager = NetworkIptablesManager::new("fresh");

        assert!(
            !manager.veth_scoping_is_optional(),
            "a manager that was never told otherwise must report that a missing \
             veth is not expected"
        );
    }

    // The declaration is opt-in precisely because it leaves the policy
    // unenforced. A manager that never made it must keep failing closed, so
    // the two behaviors cannot quietly collapse into one.
    #[test]
    fn a_manager_that_never_declared_a_missing_veth_still_fails_closed() {
        let _fake = super::test_firewall::install();
        let mut manager = NetworkIptablesManager::new("lxc-lost-veth");
        let policy = policy_requesting_mode(NetworkEnforcementMode::Firewall);
        let mut logger = Logger::new(Mode::Buffer);

        let result = manager.apply_firewall_rules(&policy, &mut logger);

        assert!(
            result.is_err(),
            "a manager with no veth and no declaration must fail closed, got {:?}",
            result
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
        // force_cleanup is ownership-blind once it starts: it rebuilds the
        // chain name and removes whatever answers to it. The empty-record guard
        // is the only thing standing between a process that created nothing and
        // the chain of a concurrent start that did. Asserting the guard's
        // predicate in isolation would not catch its deletion, so this drives
        // force_cleanup itself and observes the commands it issued.
        let fake = test_firewall::install();
        let mut quiet = Logger::new(Mode::Buffer);
        NetworkIptablesManager::force_cleanup(
            "racer-that-lost",
            Some("mxcv-loser"),
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

        // Positive control: the same call with one resource published does
        // reach the teardown, so the assertion above discriminates between the
        // two cases rather than observing a permanently silent function.
        let mut noisy = Logger::new(Mode::Buffer);
        NetworkIptablesManager::force_cleanup(
            "racer-that-won",
            Some("mxcv-winner"),
            CreatedResources::for_test(true, false, false, false),
            &mut noisy,
        );
        assert_eq!(
            fake.issued(),
            vec![
                strings(&["iptables", "-F", "MXC-racer-that-won"]),
                strings(&["iptables", "-X", "MXC-racer-that-won"]),
            ],
            "only the published chain may be flushed and deleted, and only it"
        );
    }

    #[test]
    fn a_rollback_that_could_not_finish_keeps_ownership_of_what_survived() {
        // A failed apply is not automatically a clean failure: teardown_created
        // reports a residual when its own removal commands fail, and those
        // survivors are still this manager's to remove. rules_applied gates
        // both remove_firewall_rules and Drop, so dropping the residual on the
        // floor strands the chain -- nothing afterward knows it was ours.
        //
        // Asserting rules_applied directly would only restate the assignment.
        // This drives the downstream path instead and observes the commands it
        // issued, since removing the chain is what the ownership is for.
        let fake = test_firewall::install();
        fake.fail_every_command("iptables: chain is not empty");

        let mut manager = NetworkIptablesManager::new("survivor");
        let retained = manager
            .retain_residual_ownership(CreatedResources::for_test(true, false, false, false));
        assert!(retained, "a non-empty residual must be retained");

        let mut after_partial = Logger::new(Mode::Buffer);
        let _ = manager.remove_firewall_rules(&mut after_partial);
        assert_eq!(
            fake.issued(),
            vec![
                strings(&["iptables", "-F", "MXC-survivor"]),
                strings(&["iptables", "-X", "MXC-survivor"]),
            ],
            "a chain that survived rollback must still be torn down later"
        );

        // Negative control: a rollback that removed everything leaves nothing
        // owned, so teardown must not run at all. Without this the assertion
        // above would pass even if ownership were retained unconditionally,
        // which would resurrect the collision the ownership record exists to
        // prevent.
        fake.forget_issued();
        let mut clean = NetworkIptablesManager::new("fully-rolled-back");
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
        // The test above starts from an already-retained residual, so it proves
        // only that ownership works once held -- it would still pass if the
        // failure arm threw the residual away before getting there. This one
        // drives that arm: it hands the recording step exactly what a rollback
        // whose own removal command failed reports, and asserts the manager
        // adopts it. The observable is the same downstream one, because
        // teardown is what the ownership is for.
        let fake = test_firewall::install();
        fake.fail_every_command("iptables: chain is not empty");

        let mut manager = NetworkIptablesManager::new("adopted");
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
            vec![
                strings(&["iptables", "-F", "MXC-adopted"]),
                strings(&["iptables", "-X", "MXC-adopted"]),
            ],
            "what the rollback could not remove must still be torn down later"
        );

        // Negative control: a rollback that removed everything must leave the
        // manager owning nothing, so the assertion above cannot be satisfied by
        // retaining unconditionally.
        fake.forget_issued();
        let mut clean = NetworkIptablesManager::new("clean-failure");
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
        // -F succeeds no matter who references the chain, and an emptied user
        // chain returns to its caller instead of reaching its own closing DROP.
        // So flushing a chain FORWARD still jumps to unfilters a container that
        // may still be running -- a fail-open.  -X would fail anyway on a
        // referenced chain, so the flush buys nothing and costs the filtering.
        // The whole step is gated on the hook being confirmed gone.
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

        // Negative control: once the hook is gone the step must actually run
        // and must release ownership, so the assertions above cannot be
        // satisfied by never flushing at all.
        let mut logger = Logger::new(Mode::Buffer);
        let mut flushed = false;
        let still_owned = teardown_chain(true, false, &mut logger, |_| flushed = true, |_| true);

        assert!(flushed, "an unreferenced chain must be flushed");
        assert!(!still_owned, "a chain whose -X succeeded is no longer ours");

        // A chain this attempt never created is not ours to touch at all --
        // chain names truncate and can collide with a live container.
        let mut logger = Logger::new(Mode::Buffer);
        let mut flushed = false;
        let still_owned = teardown_chain(false, false, &mut logger, |_| flushed = true, |_| true);

        assert!(!flushed, "a chain we did not create must not be flushed");
        assert!(!still_owned);
    }

    #[test]
    fn a_removal_whose_commands_failed_stays_owned_for_the_drop_retry() {
        // remove_firewall_rules used to clear rules_applied unconditionally, so
        // a teardown whose commands failed reported itself done while the chain
        // was still installed.  Drop is gated on the same flag, so that threw
        // away the last retry.  The fake scripts the failure, so the test states
        // its own precondition rather than depending on the host's iptables
        // refusing the command -- which is what made this pass on a machine
        // without iptables and fail on one with it.
        let fake = test_firewall::install();
        fake.fail_every_command("iptables: permission denied");

        let mut manager = NetworkIptablesManager::new("stubborn");
        manager.retain_residual_ownership(CreatedResources::for_test(true, false, false, false));

        let mut first = Logger::new(Mode::Buffer);
        let _ = manager.remove_firewall_rules(&mut first);
        assert_eq!(
            fake.issued(),
            vec![
                strings(&["iptables", "-F", "MXC-stubborn"]),
                strings(&["iptables", "-X", "MXC-stubborn"]),
            ],
            "the first removal must attempt the teardown"
        );

        // The observable for "still owned" is that a second removal still
        // issues the commands rather than short-circuiting on the gate.  That
        // second call is what Drop makes.
        fake.forget_issued();
        let mut second = Logger::new(Mode::Buffer);
        let _ = manager.remove_firewall_rules(&mut second);
        assert_eq!(
            fake.issued(),
            vec![
                strings(&["iptables", "-F", "MXC-stubborn"]),
                strings(&["iptables", "-X", "MXC-stubborn"]),
            ],
            "a removal that failed must leave the chain owned so Drop retries it"
        );
    }

    #[test]
    fn a_removal_whose_commands_all_succeeded_releases_ownership() {
        // The mirror of the test above, and the arm that could not be reached
        // before the fake existed: `-X` is what actually relinquishes the
        // chain, so a teardown whose commands all succeed must clear the gate
        // and leave Drop nothing to retry.  Without it, "still owned after a
        // failure" would be satisfied by never releasing ownership at all.
        let fake = test_firewall::install();
        let mut manager = NetworkIptablesManager::new("released");
        manager.retain_residual_ownership(CreatedResources::for_test(true, false, false, false));

        let mut first = Logger::new(Mode::Buffer);
        let _ = manager.remove_firewall_rules(&mut first);
        assert_eq!(
            fake.issued(),
            vec![
                strings(&["iptables", "-F", "MXC-released"]),
                strings(&["iptables", "-X", "MXC-released"]),
            ],
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
        // Both arms of apply_firewall_rules replace self.created with the new
        // attempt's set, so a second apply on a manager that still owns
        // something would drop the earlier record and strand whatever it named.
        // Refusing makes that unreachable instead of relying on callers to
        // build a fresh manager each time.
        //
        // The fake is declared first so it outlives `manager`: locals drop in
        // reverse declaration order, and this manager still owns a chain, so
        // its Drop runs a teardown that must not reach the real binary.
        let _fake = test_firewall::install();
        let mut manager = NetworkIptablesManager::new("already-owned");
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
        // Negative control for the guard above: it must key on live ownership,
        // not refuse every apply.  The observable is that the apply actually
        // issued its chain-creation commands rather than short-circuiting.
        //
        // The fake is declared first so it outlives `manager`, whose Drop tears
        // down the chains this apply creates.
        let fake = test_firewall::install();
        let mut manager = NetworkIptablesManager::new("fresh");
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
            issued.contains(&strings(&["iptables", "-N", "MXC-fresh"])),
            "the apply must create the IPv4 chain, got: {:?}",
            issued
        );
        assert!(
            issued.contains(&strings(&["ip6tables", "-N", "MXC-fresh"])),
            "a host whose ip6tables probe succeeds must get the parallel v6 chain, got: {:?}",
            issued
        );
    }

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
    fn resolve_host_rewrites_ipv4_mapped_ipv6_literal_to_ipv4() {
        // A mapped destination is emitted as an IPv4 packet, so it must be
        // programmed with iptables; an ip6tables rule would never match it.
        let ips = NetworkIptablesManager::resolve_host("::ffff:127.0.0.1");
        assert_eq!(ips.ipv4, vec!["127.0.0.1"]);
        assert!(ips.ipv6.is_empty());
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
        // Out-of-range prefixes and non-numeric prefixes are dropped rather
        // than passed to iptables, which would reject them at apply time.
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
        // iptables/ip6tables apply the prefix mask themselves, so the CIDR is
        // forwarded verbatim rather than expanded or normalized.
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

        let args = NetworkIptablesManager::build_policy_rule_args("MXC-test", &policy);

        // Membership rather than sequence: this test owns the family split, and
        // the order the two lists are emitted in is the deny-precedence
        // contract, asserted by the deny_precedence_spec module.
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
        // The same base rules are fed to both iptables and ip6tables, so they
        // must not name an address family or a v4-only protocol.
        let base = NetworkIptablesManager::build_base_chain_rule_args("MXC-test");

        assert_eq!(base.len(), 4);
        for rule in &base {
            assert!(!rule.iter().any(|arg| arg == "icmp"));
        }
    }

    // -----------------------------------------------------------------------
    // Spec-derived tests: resolution
    // -----------------------------------------------------------------------

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
        // An IPv4-mapped destination travels as an IPv4 packet, so an ip6tables
        // rule naming it would never match and a blocked entry would fail open
        // under default-allow. It must be programmed with iptables instead.
        assert_resolved_exact("::ffff:127.0.0.1", &["127.0.0.1"], &[]);
    }

    #[test]
    fn ipv4_mapped_cidr_is_translated_to_its_ipv4_prefix() {
        // The mapped range is the last 32 bits of ::ffff:0:0/96, so an IPv6
        // prefix of 96 + n is exactly an IPv4 prefix of n.
        assert_resolved_exact("::ffff:192.0.2.0/120", &["192.0.2.0/24"], &[]);
        assert_resolved_exact("::ffff:198.51.100.42/128", &["198.51.100.42/32"], &[]);
    }

    #[test]
    fn an_ipv6_prefix_shorter_than_the_mapped_range_stays_ipv6() {
        // A /95 covers addresses outside ::ffff:0:0/96, so it cannot be expressed
        // as a single IPv4 CIDR and must not be rewritten.
        assert_resolved_exact("::ffff:0:0/95", &[], &["::ffff:0:0/95"]);
    }

    #[test]
    fn valid_cidrs_are_passed_through_unchanged_in_their_matching_family() {
        // SPEC_BRIEF §3 requires validated CIDRs to be passed through unchanged.
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
        // SPEC_BRIEF §3 says host bits are not required to be zero because iptables applies the mask.
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

    // Independent of the leading-`+` rejection above, the family range check must
    // still reject an out-of-range prefix.
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

    /// Every string in a bucket must be a destination of that bucket's family.
    ///
    /// This is the invariant that keeps an AAAA record from being handed to
    /// `iptables` (and an A record to `ip6tables`). It is asserted as a property so
    /// it holds whatever the resolver happens to return.
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

    // The dual-stack bypass lived in the DNS family split: an AAAA record must land
    // in the v6 bucket and must never leak into the v4 bucket. The split is a pure
    // function (`bucket_resolved_addrs`), so it is exercised here with injected A
    // and AAAA addresses -- no dependency on the host having live IPv6 DNS -- and
    // the presence of a v6 destination is asserted **hard**. If the split routed
    // AAAA records into the v4 bucket, `resolved.ipv6` would be empty (failing the
    // non-empty assertion) and the v4 bucket would hold a value that does not parse
    // as IPv4 (failing family purity).
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

    // Live characterization: over whatever the host's resolver returns for
    // well-known dual-stack names, the buckets must stay family-pure. This does not
    // depend on the host having IPv6 DNS -- the purity invariant holds for any
    // result -- and it does not paper over a missing v6 arm with a warning that
    // still passes. The deterministic proof that AAAA records reach the v6 bucket
    // lives in `aaaa_records_land_in_the_v6_bucket_and_never_in_the_v4_bucket`, and
    // end-to-end IPv6 rule coverage lives in run_lxc_network_dualstack_test.sh.
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

        // SPEC_BRIEF §3 requires hostnames to resolve to both A and AAAA. Some
        // minimal hosts can have a degenerate /etc/hosts, so this accepts whichever
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

    // -----------------------------------------------------------------------
    // Spec-derived tests: rule generation
    // -----------------------------------------------------------------------

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

    /// `.invalid` is reserved by RFC 2606 and never resolves, so it is a stable
    /// way to exercise the unresolvable path without depending on the network.
    const UNRESOLVABLE_HOST: &str = "blocked.invalid";

    #[test]
    fn an_unresolvable_deny_under_a_blocking_default_is_fatal_when_an_allow_is_programmed() {
        // The allow is evaluated before the chain's closing DROP, and the deny
        // has no known address, so nothing establishes deny precedence.
        let policy = ContainerPolicy {
            default_network_policy: NetworkPolicy::Block,
            ..policy_with_hosts(&["0.0.0.0/0"], &[UNRESOLVABLE_HOST])
        };
        let mut logger = wxc_common::logger::Logger::new(wxc_common::logger::Mode::Buffer);

        let err = NetworkIptablesManager::build_policy_rules_logged("MXC-x", &policy, &mut logger)
            .expect_err("a broad allow must not be able to accept an unresolvable deny");

        assert!(
            err.contains(UNRESOLVABLE_HOST) && err.contains("deny precedence"),
            "error should name the host and the invariant, got: {err}"
        );
    }

    #[test]
    fn a_narrow_allow_is_equally_fatal_because_the_deny_address_is_unknown() {
        // The check cannot depend on how broad the allow looks: the deny never
        // resolved, so a narrow allow cannot be shown to miss it either.
        let policy = ContainerPolicy {
            default_network_policy: NetworkPolicy::Block,
            ..policy_with_hosts(&["192.0.2.10"], &[UNRESOLVABLE_HOST])
        };
        let mut logger = wxc_common::logger::Logger::new(wxc_common::logger::Mode::Buffer);

        NetworkIptablesManager::build_policy_rules_logged("MXC-x", &policy, &mut logger)
            .expect_err("a narrow allow cannot be proven disjoint from an unresolved deny");
    }

    #[test]
    fn an_unresolvable_deny_under_a_blocking_default_stays_a_warning_with_no_allow() {
        // With nothing to ACCEPT ahead of it, the closing DROP genuinely covers
        // whatever the missing rule would have covered, so this must keep
        // working rather than become a new hard failure.
        let policy = ContainerPolicy {
            default_network_policy: NetworkPolicy::Block,
            ..policy_with_hosts(&[], &[UNRESOLVABLE_HOST])
        };
        let mut logger = wxc_common::logger::Logger::new(wxc_common::logger::Mode::Buffer);

        NetworkIptablesManager::build_policy_rules_logged("MXC-x", &policy, &mut logger)
            .expect("an unresolvable deny with no allow rules is covered by the closing DROP");
    }

    #[test]
    fn an_unresolvable_allow_does_not_arm_the_deny_precedence_failure() {
        // An allow that resolved to nothing programs no ACCEPT, so it cannot
        // preempt the closing DROP and must not be counted as one that did.
        let policy = ContainerPolicy {
            default_network_policy: NetworkPolicy::Block,
            ..policy_with_hosts(&["allowed.invalid"], &[UNRESOLVABLE_HOST])
        };
        let mut logger = wxc_common::logger::Logger::new(wxc_common::logger::Mode::Buffer);

        NetworkIptablesManager::build_policy_rules_logged("MXC-x", &policy, &mut logger)
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
        let rules = NetworkIptablesManager::build_policy_rule_args("MXC-mixed", &policy);

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
    fn base_chain_rules_are_four_family_agnostic_rules_in_documented_order() {
        let chain_name = "MXC-base";
        let rules = NetworkIptablesManager::build_base_chain_rule_args(chain_name);
        let expected = vec![
            strings(&["-A", chain_name, "-i", "lo", "-j", "ACCEPT"]),
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
            strings(&[
                "-A", chain_name, "-p", "udp", "--dport", "53", "-j", "ACCEPT",
            ]),
            strings(&[
                "-A", chain_name, "-p", "tcp", "--dport", "53", "-j", "ACCEPT",
            ]),
        ];

        assert_eq!(
            rules, expected,
            "base chain rules should be the documented four rules in order"
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
    fn chain_names_have_mxc_prefix_and_total_length_cap_of_twenty_four() {
        let short_name = "short";
        let short_manager = NetworkIptablesManager::new(short_name);
        assert_eq!(
            short_manager.chain_name, "MXC-short",
            "short container name {short_name} should be preserved after MXC- prefix"
        );

        let long_name = "abcdefghijklmnopqrstuvwxyz";
        let long_manager = NetworkIptablesManager::new(long_name);
        let expected = "MXC-abcdefghijklmnopqrst";
        assert_eq!(
            long_manager.chain_name, expected,
            "long container name should be truncated to 20 chars after MXC- prefix"
        );
        assert_eq!(
            long_manager.chain_name.len(),
            24,
            "chain name length cap should apply to total length including MXC- prefix"
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

    // -----------------------------------------------------------------------
    // Spec-derived tests: lifecycle
    // -----------------------------------------------------------------------

    #[test]
    fn a_new_manager_reports_no_rules_applied() {
        let manager = NetworkIptablesManager::new("fresh");

        assert!(
            !manager.rules_applied(),
            "a newly constructed manager must not report firewall state needing cleanup"
        );
    }

    #[test]
    fn a_non_firewall_policy_is_a_successful_no_op() {
        let mut manager = NetworkIptablesManager::new("skip-noop");
        manager.set_veth_interface("veth-skip");
        let policy = policy_with_enforcement_mode(NetworkEnforcementMode::Capabilities);
        let mut logger = Logger::new(Mode::Buffer);

        let result = manager.apply_firewall_rules(&policy, &mut logger);

        assert_eq!(
            result,
            Ok(true),
            "a policy that does not use firewall enforcement must be reported as a successful no-op"
        );
        assert!(
            !manager.rules_applied(),
            "a no-op firewall skip must leave no rules marked as applied"
        );
    }

    #[test]
    fn every_enforcement_mode_takes_the_contractual_firewall_gate() {
        for (mode, uses_firewall) in enforcement_modes_with_firewall_contract() {
            assert_eq!(
                NetworkIptablesManager::enforcement_mode_uses_firewall(&mode),
                uses_firewall,
                "{mode:?} firewall-gate predicate mismatch"
            );
        }
    }

    fn policy_with_enforcement_mode(
        network_enforcement_mode: NetworkEnforcementMode,
    ) -> ContainerPolicy {
        ContainerPolicy {
            network_enforcement_mode,
            ..Default::default()
        }
    }

    /// The expected answers are written out as literals rather than derived from
    /// a second copy of the predicate. A test that recomputes the contract it is
    /// checking passes even when both copies are wrong in the same way.
    fn enforcement_modes_with_firewall_contract() -> [(NetworkEnforcementMode, bool); 3] {
        use NetworkEnforcementMode::{Both, Capabilities, Firewall};

        [(Capabilities, false), (Firewall, true), (Both, true)]
    }

    // -----------------------------------------------------------------------
    // Spec-derived tests: ip6tables status
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Truth table — all four input combinations are enumerated and pinned.
    // -----------------------------------------------------------------------

    #[test]
    fn working_probe_with_active_ipv6_reports_available() {
        // "A working probe means the tool is usable regardless of address state."
        let result = NetworkIptablesManager::classify_ip6tables_status(true, true);
        assert_eq!(
            result,
            Ip6tablesStatus::Available,
            "classify_ip6tables_status(probe=true, ipv6_active=true) should be Available; got {result:?}"
        );
    }

    #[test]
    fn working_probe_without_active_ipv6_still_reports_available() {
        // "A working probe means the tool is usable regardless of address state."
        let result = NetworkIptablesManager::classify_ip6tables_status(true, false);
        assert_eq!(
            result,
            Ip6tablesStatus::Available,
            "classify_ip6tables_status(probe=true, ipv6_active=false) should be Available; got {result:?}"
        );
    }

    #[test]
    fn failed_probe_with_no_active_ipv6_reports_kernel_ipv6_disabled() {
        // "if the kernel has no active IPv6 there is nothing to filter and skipping is safe"
        let result = NetworkIptablesManager::classify_ip6tables_status(false, false);
        assert_eq!(
            result,
            Ip6tablesStatus::KernelIpv6Disabled,
            "classify_ip6tables_status(probe=false, ipv6_active=false) should be KernelIpv6Disabled; got {result:?}"
        );
    }

    #[test]
    fn live_ipv6_with_a_broken_tool_must_fail_closed_not_skip() {
        // "if IPv6 is live the tool is genuinely missing or broken and setup must
        // fail closed rather than leave IPv6 egress unfiltered"
        let result = NetworkIptablesManager::classify_ip6tables_status(false, true);
        assert_eq!(
            result,
            Ip6tablesStatus::UnusableButIpv6Active,
            "classify_ip6tables_status(probe=false, ipv6_active=true) should be UnusableButIpv6Active (fail-closed); got {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Invariants — properties that must hold across the whole domain.
    // -----------------------------------------------------------------------

    /// A working probe always yields Available, regardless of IPv6 address state.
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

    /// A failed probe must never return Available — it can only be KernelIpv6Disabled
    /// or UnusableButIpv6Active.
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

    /// UnusableButIpv6Active is ONLY reachable when the probe failed AND IPv6 is
    /// live.  If a mutation makes the fail-closed branch unreachable (silent
    /// fail-open), this test catches it.
    #[test]
    fn fail_closed_outcome_is_reachable_only_when_probe_failed_and_ipv6_is_live() {
        // The one combination that MUST produce UnusableButIpv6Active.
        let fail_closed = NetworkIptablesManager::classify_ip6tables_status(false, true);
        assert_eq!(
            fail_closed,
            Ip6tablesStatus::UnusableButIpv6Active,
            "classify_ip6tables_status(probe=false, ipv6_active=true) must be UnusableButIpv6Active; got {fail_closed:?}"
        );

        // All other combinations must NOT produce UnusableButIpv6Active.
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

    /// KernelIpv6Disabled is ONLY reachable when the probe failed AND IPv6 is
    /// inactive.  It must not surface as a safe-skip when IPv6 is actually live.
    #[test]
    fn safe_skip_outcome_is_reachable_only_when_probe_failed_and_ipv6_is_inactive() {
        // The one combination that MUST produce KernelIpv6Disabled.
        let safe_skip = NetworkIptablesManager::classify_ip6tables_status(false, false);
        assert_eq!(
            safe_skip,
            Ip6tablesStatus::KernelIpv6Disabled,
            "classify_ip6tables_status(probe=false, ipv6_active=false) must be KernelIpv6Disabled; got {safe_skip:?}"
        );

        // All other combinations must NOT produce KernelIpv6Disabled.
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

    // -----------------------------------------------------------------------
    // Discriminant distinctness — a mutation that collapses two variants must
    // be caught before PartialEq-based assertions below would silently accept it.
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Spec-derived tests: host IPv6 state
    // -----------------------------------------------------------------------

    /// `/proc/net` exists, which is the ordinary case on any Linux host and the
    /// precondition that makes a missing `if_inet6` mean "IPv6 is off".
    const PROC_NET_MOUNTED: bool = true;

    /// `/proc` is not mounted, so no IPv6 probe ever ran.
    const PROC_NET_ABSENT: bool = false;

    // A real `/proc/net/if_inet6` line: 32-hex-char address, if_index, prefix_len,
    // scope, flags, and the device name in the final field. These samples mirror
    // the kernel's actual formatting (space-separated fields).
    const LOOPBACK_LINE: &str = "00000000000000000000000000000001 01 80 10 80         lo";
    const ETH0_GLOBAL_LINE: &str = "2606280002200001024818932c5c1946 03 40 00 80         eth0";
    const ETH0_LINKLOCAL_LINE: &str = "fe80000000000000020000fffe000001 03 40 20 80         eth0";

    #[test]
    fn a_real_interface_address_is_classified_active() {
        // "a line is treated as evidence of active IPv6 only when its device is
        // something other than `lo`" -- a global address on eth0 is egress-capable.
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
        // The kernel lists the link-local `fe80::` address on any interface with
        // IPv6 up; its device is not `lo`, so the host has an IPv6 stack to filter.
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
        // An IPv4-only host commonly still lists `::1` on `lo`. Loopback is not
        // egress-capable, so it must NOT be treated as active IPv6.
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
        // A `NotFound` read *while `/proc/net` exists* means the kernel never
        // created the file (IPv6 disabled at boot), which IS a genuine
        // "IPv6 is off" -> Inactive.
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
        // kernel, but says nothing at all about IPv6: the probe never ran.
        // Reading it as "IPv6 is off" would apply an IPv4-only policy and leave
        // IPv6 egress unfiltered.
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
        // Any read error other than NotFound (permission denied, I/O error, /proc
        // not mounted) means "we could not determine the state", which must NOT be
        // silently converted into "IPv6 is off". This is the fail-open guard.
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

    // The three states must be distinct, or the PartialEq-based assertions above
    // could silently accept a mutation that collapses two of them.
    #[test]
    fn host_ipv6_states_are_all_distinct() {
        assert_ne!(HostIpv6State::Active, HostIpv6State::Inactive);
        assert_ne!(HostIpv6State::Active, HostIpv6State::Unknown);
        assert_ne!(HostIpv6State::Inactive, HostIpv6State::Unknown);
    }

    // -----------------------------------------------------------------------
    // State -> "treat as active" mapping. This is the fail-open guard: Unknown
    // must be treated as active so an unreadable IPv6 state fails closed rather
    // than leaving IPv6 egress unfiltered.
    // -----------------------------------------------------------------------

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
        // The fail-open guard: "we could not determine IPv6 state" must NOT become
        // "IPv6 is off". Treating Unknown as active means a failed ip6tables probe
        // then fails setup closed instead of leaving IPv6 egress unfiltered.
        assert!(
            NetworkIptablesManager::ipv6_state_treated_as_active(HostIpv6State::Unknown),
            "Unknown must be treated as active so an unreadable IPv6 state fails closed"
        );
    }
}
