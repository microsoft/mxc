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

use sha2::{Digest, Sha256};
use wxc_common::logger::Logger;
use wxc_common::models::{
    ContainerPolicy, NetworkAction, NetworkCidr, NetworkEgressPolicy, NetworkEnforcementMode,
    NetworkPeer, NetworkPolicy, NetworkPort, NetworkProtocol, NetworkRule, ProxyAddress,
    ProxyHostPin,
};

/// True when this policy describes anything the egress firewall has to carry,
/// in either schema.
///
/// Deliberately keyed on what the policy *says* rather than on
/// `network.enforcementMode`. The mode is a request for enforcement and this is
/// the question of whether enforcement is owed, and answering the second with
/// the first lets a policy that restricts egress start with an open chain
/// because it never named a mode. A caller may get more enforcement than the
/// mode asked for, never less.
///
/// The directional arm is what admits schema 0.8, which has no mode to name:
/// the parser rejects `enforcementMode` beside `egress`/`ingress`, so every
/// directional policy carries the `Capabilities` default. The arm is written
/// out rather than left to the `Block` arm to cover it, because `Block` covers
/// it only by being the parser's default for a field 0.8 never writes — an
/// `egress.default: allow` config would stop being enforced the day that
/// default changed.
///
/// This asks what LXC does about a policy rather than what the policy is, which
/// is why it lives beside the emitter it gates and not on the shared contract
/// type. No other backend installs iptables chains from it.
///
/// A config that names no `network` section is not a config that asked to deny
/// all egress, and `network_specified` is the only field that tells the two
/// apart. The parser hands every network-less config a
/// `Some(NetworkEgressPolicy::default())` whose action default is `Deny`, on
/// the same path that leaves `default_network_policy` at `Block`. Without the
/// guard both arms answer yes for a config that never mentioned networking, and
/// every container installs chains nobody asked for.
pub(crate) fn requires_firewall(policy: &ContainerPolicy) -> bool {
    if !policy.network_specified {
        return false;
    }

    policy.default_network_policy == NetworkPolicy::Block
        || !policy.allowed_hosts.is_empty()
        || !policy.blocked_hosts.is_empty()
        || policy.network_proxy.is_enabled()
        || policy.network_egress.is_some()
}

/// True when the run installs firewall chains at all, which is a wider question
/// than [`requires_firewall`].
///
/// The two differ on one shape: `enforcementMode: firewall` (or `both`) with a
/// permissive egress default and no host lists. Outbound, that policy has no
/// rule to install, so skipping the chain costs nothing and `requires_firewall`
/// correctly answers no. Inbound, the chain *is* the policy — its default deny
/// is what keeps `allowLocalNetwork: false` true — so skipping opens the
/// container to new inbound connections the config asked to refuse. Anything
/// gating the inbound chain has to ask this instead.
///
/// Schema 0.8 needs no arm of its own here. It cannot carry `enforcementMode`,
/// and `requires_firewall` already answers every directional policy that named
/// a `network` section. The mode arm needs no guard of its own: a mode reaches
/// anything other than its `Capabilities` default only from a `network`
/// section, which is the same section `network_specified` records.
pub(crate) fn installs_firewall(policy: &ContainerPolicy) -> bool {
    requires_firewall(policy)
        || matches!(
            policy.network_enforcement_mode,
            NetworkEnforcementMode::Firewall | NetworkEnforcementMode::Both
        )
}

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

/// One egress entry the chain emits a rule for, lowered from whichever network
/// schema the policy was written in.
///
/// The emitter consumes these in list order and iptables applies
/// first-match-wins within a chain, which makes an entry's position its
/// precedence. Deny-precedence is therefore a property each lowering function
/// establishes, and the emitter only has to preserve the order it is handed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EgressEntry {
    /// Hostname, IP literal, or CIDR. Interpreted by
    /// [`NetworkIptablesManager::resolve_host`]. Owned because a 0.8 peer
    /// arrives as a parsed [`NetworkCidr`] with no string to borrow.
    destination: String,
    action: RuleAction,
    matching: RuleMatch,
}

/// The protocol and port match a single emitted rule carries.
///
/// Only matches one iptables rule can express are representable. A `ports`
/// selector naming protocol `any` alongside a port has no `-p all --dport`
/// form, and the lowering expands it into a TCP match and a UDP match rather
/// than admitting a state the emitter would have to reject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleMatch {
    /// Every protocol and every port. What a 0.8 rule with no `ports`
    /// selector matches, and the only match a legacy host-list entry has.
    AnyTraffic,
    /// ICMP, which carries no port. Rendered `icmp` under `iptables` and
    /// `icmpv6` under `ip6tables`: the same selector has a different protocol
    /// name per family, and naming it `icmp` on the IPv6 command is rejected
    /// rather than silently ignored.
    Icmp,
    /// TCP or UDP, optionally narrowed to an inclusive destination port range.
    Transport {
        protocol: TransportProtocol,
        ports: Option<PortRange>,
    },
}

/// The two protocols that carry a destination port.
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

/// An inclusive destination port range. A single port is a range whose ends
/// are equal, which keeps one representation for both schema forms.
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

/// Records exactly which per-family chains and FORWARD hooks a single apply
/// attempt created, so rollback and teardown remove only what this manager
/// installed. Without this, a partial-failure rollback would tear down chains
/// this attempt never created: the chain name is a pure function of the
/// container name, so a chain already present under our name belongs to an
/// earlier or concurrent run and is not ours to remove.
///
/// Visible to the crate (with private fields) purely so `signal_cleanup` can
/// carry the value from the runner thread to the watchdog thread. The watchdog
/// never inspects it; it only hands it back to [`NetworkIptablesManager::force_cleanup`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CreatedResources {
    v4: FamilyResources,
    v6: FamilyResources,
}

/// What one address family's apply installed, and therefore owes a teardown.
///
/// The two families are symmetric in every path that reads this, so they are
/// the same type rather than parallel fields with a `v4_`/`v6_` prefix. That
/// symmetry is what lets setup, rollback, and teardown be written once.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FamilyResources {
    chain: bool,
    hook: bool,
    physdev_hook: bool,
    return_rule: bool,
    physdev_return: bool,
}

impl FamilyResources {
    fn is_empty(&self) -> bool {
        !self.chain && !self.hook && !self.physdev_hook && !self.return_rule && !self.physdev_return
    }

    /// Whether a FORWARD hook survived teardown and still references the chain.
    fn hooks_remain(&self) -> bool {
        self.hook || self.physdev_hook
    }
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
        self.v4.is_empty() && self.v6.is_empty()
    }

    /// Test-only constructor so `signal_cleanup`'s tests can build a
    /// distinguishable, non-default ownership record without widening the
    /// production API. Production code only ever obtains one of these by
    /// creating the resources it names.
    #[cfg(test)]
    pub(crate) fn for_test(v4_chain: bool, v6_chain: bool, v4_hook: bool, v6_hook: bool) -> Self {
        Self {
            v4: FamilyResources {
                chain: v4_chain,
                hook: v4_hook,
                ..Default::default()
            },
            v6: FamilyResources {
                chain: v6_chain,
                hook: v6_hook,
                ..Default::default()
            },
        }
    }

    /// Every field published, for tests that must notice a teardown skipping
    /// one of them.
    #[cfg(test)]
    pub(crate) fn for_test_all() -> Self {
        let all = FamilyResources {
            chain: true,
            hook: true,
            physdev_hook: true,
            return_rule: true,
            physdev_return: true,
        };

        Self { v4: all, v6: all }
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
pub(crate) enum Ip6tablesStatus {
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
pub(crate) enum HostIpv6State {
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
    /// Chain name unique to this container, as built by [`chain_name_for`].
    chain_name: String,
    /// Whether rules have been applied.
    rules_applied: bool,
    /// Whether the caller asked for this policy to outlive the run.
    preserve_policy: bool,
    /// The container's veth interface name on the host.
    veth_interface: Option<String>,
    /// Whether a caller that never supplies a veth is expected rather than
    /// broken.
    veth_scoping_optional: bool,
    /// Topology the hook logic assumes, in place of the sysfs probe.
    ///
    /// Test-only. A build host has no `/sys/class/net`, so the probe's
    /// honest answer there is [`VethTopology::Unknown`] for every container.
    #[cfg(test)]
    topology_override: Option<VethTopology>,
    /// Chains and FORWARD hooks this manager successfully created, so teardown
    /// and rollback remove only resources this attempt actually installed.
    created: CreatedResources,
    /// The hosts-file pin that resolves the proxy hostname to the one address
    /// this manager authorized -- the same resolution the firewall rule was
    /// built from.
    proxy_pin: Option<ProxyHostPin>,
}

/// iptables rejects chain names of 29 characters or more, so 28 is the ceiling
/// every generated name must respect.
pub const CHAIN_NAME_MAX_LEN: usize = 28;

/// SHA-256 bytes folded into the chain-name suffix. Ten bytes is 80 bits, and
/// encodes to exactly 16 base32 characters with no padding.
const CHAIN_HASH_BYTES: usize = 10;

/// Characters of the original container name kept as a human-readable hint.
/// This carries no identity; two containers may share a slug.
const CHAIN_SLUG_LEN: usize = 7;

/// Slug budget for the inbound (ingress) chain. The ingress prefix `MXCI-` is
/// one byte longer than the egress `MXC-`, so the slug is shortened by one to
/// keep `MXCI-<slug>-<hash>` within [`CHAIN_NAME_MAX_LEN`]
/// (5 + 6 + 1 + 16 = 28).
const INGRESS_CHAIN_SLUG_LEN: usize = 6;

/// RFC 4648 base32 alphabet, lowercased. Base32 packs 5 bits per character
/// against hex's 4, so 80 bits needs 16 characters here where hex would need
/// 20. `MXC-`, the slug, and the slug's separator take 12 of the 28 bytes,
/// leaving exactly 16 for the hash, so hex could not carry 80 bits without
/// giving up the slug entirely.
const BASE32_LOWER: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Encode bytes as lowercase base32 without padding.
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

/// Build the iptables chain name for a container.
///
/// Produces `MXC-<slug>-<hash>`, or `MXC-<hash>` when the container name
/// contains no characters a slug may keep. The result is always ASCII, always
/// at most [`CHAIN_NAME_MAX_LEN`] bytes, and always the same for the same
/// input.
///
/// The slug keeps the first [`CHAIN_SLUG_LEN`] ASCII alphanumeric, `-`, or `_`
/// characters of the container name, in order, discarding everything else. It
/// is a debugging hint only.
///
/// The hash is taken over the *original* container name, so container names
/// that differ only in characters the slug drops, or only past the slug's
/// length, still receive different chains. Two names collide only if their
/// SHA-256 digests collide in the leading 80 bits.
///
/// This defends against accidental collision, not against an adversary who
/// chooses container names; that requires a persisted ownership record rather
/// than a longer name, because 28 characters caps the available entropy.
pub fn chain_name_for(container_name: &str) -> String {
    chain_name_with_prefix("MXC-", CHAIN_SLUG_LEN, container_name)
}

/// Build the *inbound* (ingress) iptables chain name for a container.
///
/// Uses a distinct `MXCI-` prefix (vs [`chain_name_for`]'s `MXC-`) so the
/// inbound `INPUT` chain and the egress `FORWARD` chain for the same container
/// can never collide or be torn down for each other. Reuses the same base32
/// hash machinery and stays within [`CHAIN_NAME_MAX_LEN`]; see
/// [`INGRESS_CHAIN_SLUG_LEN`]. The hash is over the *original* container name,
/// as in [`chain_name_for`].
pub fn ingress_chain_name_for(container_name: &str) -> String {
    chain_name_with_prefix("MXCI-", INGRESS_CHAIN_SLUG_LEN, container_name)
}

/// Shared chain-name builder: `<prefix><slug>-<hash>`, or `<prefix><hash>` when
/// the container name yields no slug. The hash is the leading
/// [`CHAIN_HASH_BYTES`] of the SHA-256 of the original container name, base32
/// encoded, so names that differ only in slug-dropped characters still receive
/// different chains.
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

/// What a sysfs lookup established about a veth's topology.
///
/// Failure to establish it is a third answer rather than a negative one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VethTopology {
    /// The interface is attached to a bridge.
    Bridged,
    /// The interface is not attached to a bridge. Established, not assumed.
    DirectlyRouted,
    /// The topology could not be established.
    Unknown,
}
impl NetworkIptablesManager {
    /// Create a new manager for the given container name.
    pub fn new(container_name: &str) -> Self {
        Self {
            chain_name: chain_name_for(container_name),
            rules_applied: false,
            preserve_policy: false,
            veth_interface: None,
            veth_scoping_optional: false,
            #[cfg(test)]
            topology_override: Some(VethTopology::DirectlyRouted),
            created: CreatedResources::default(),
            proxy_pin: None,
        }
    }

    /// The iptables chain name this manager owns.
    pub fn chain_name(&self) -> &str {
        &self.chain_name
    }

    /// Whether rules have been applied and need cleanup.
    pub fn rules_applied(&self) -> bool {
        self.rules_applied
    }

    /// Leave the chain and its FORWARD hooks installed when this manager is
    /// dropped.
    pub fn set_preserve_policy(&mut self, preserve: bool) {
        self.preserve_policy = preserve;
    }

    /// The hosts-file pin a proxied container must be given before it runs, or
    /// `None` when the policy needs no pin.
    ///
    /// The pin is a record of a lookup rather than something recomputed on
    /// demand, because round-robin and split-horizon DNS can answer one name
    /// with a different address each time. A pin built from a second lookup
    /// could name an address the chain never allowed.
    pub fn proxy_host_pin(&self) -> Option<&ProxyHostPin> {
        self.proxy_pin.as_ref()
    }

    /// Whether this manager has been told a missing veth is expected.
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

    /// Declare the topology the hook logic should assume, in place of probing.
    #[cfg(test)]
    fn set_topology_override(&mut self, topology: VethTopology) {
        self.topology_override = Some(topology);
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
    /// The policy is **not** enforced for a caller that sets this: there is no
    /// host-side interface to hook FORWARD on, so the chain exists and nothing
    /// reaches it. That is why the declaration is opt-in and logged -- an
    /// unenforced chain is indistinguishable from an enforced one otherwise.
    pub fn allow_missing_veth_interface(&mut self) {
        self.veth_scoping_optional = true;
    }

    /// Build one FORWARD hook rule matching the veth as the input interface.
    ///
    /// `op` is `-I` or `-D`. One builder serves both because iptables deletes
    /// by full rule specification: a delete whose spec differs from the insert
    /// by even one match removes nothing, reports nothing, and leaves the hook
    /// in place.
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
    /// On the default LXC topology the veth is attached to a bridge
    /// (`lxc.net.0.link` set to `lxcbr0`). A packet leaving such a container is
    /// bridged onto `lxcbr0` and then routed off it, so by the time FORWARD
    /// sees the packet its input interface is the bridge and not the veth --
    /// an `-i <veth>` rule matches nothing at all.
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

    /// Determine whether `iface` is attached to a bridge, looked up under an
    /// injectable sysfs root so this is testable without a live interface.
    ///
    /// `master` is a symlink, and `Path::exists` follows links, so it would
    /// report a dangling `master` as absent -- a bridged interface read as
    /// directly routed. Only `symlink_metadata` sees the link itself.
    fn veth_topology_in(sysfs_net_root: &Path, iface: &str) -> VethTopology {
        let iface_dir = sysfs_net_root.join(iface);
        match std::fs::symlink_metadata(iface_dir.join("master")) {
            Ok(_) => VethTopology::Bridged,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // `metadata` here, not `symlink_metadata`, and the asymmetry is
                // deliberate. In real sysfs `/sys/class/net/<iface>` is itself a
                // symlink into `/sys/devices`, and `symlink_metadata` succeeds
                // on a dangling one -- which would report an interface whose
                // target is unreachable as positively directly routed. Only a
                // directory that actually resolves proves the absent `master`
                // was observed rather than merely unreachable.
                match std::fs::metadata(&iface_dir) {
                    Ok(_) => VethTopology::DirectlyRouted,
                    Err(_) => VethTopology::Unknown,
                }
            }
            Err(_) => VethTopology::Unknown,
        }
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

    /// Probe the real sysfs, unless a test declared the topology outright.
    fn veth_topology(&self, iface: &str) -> VethTopology {
        #[cfg(test)]
        if let Some(topology) = self.topology_override {
            return topology;
        }
        Self::veth_topology_in(Path::new(SYSFS_NET_ROOT), iface)
    }

    /// Whether the hook logic must treat `topology` as bridged.
    ///
    /// Bridged is the conservative answer, so it is what an absence of
    /// evidence reaches. Only a positive [`VethTopology::DirectlyRouted`]
    /// finding earns the other one, which is why this tests for that finding
    /// rather than for [`VethTopology::Bridged`].
    fn treat_as_bridged(topology: VethTopology) -> bool {
        topology != VethTopology::DirectlyRouted
    }

    /// Production wrapper over [`Self::bridge_netfilter_active_at`].
    fn bridge_netfilter_active(path: &str) -> bool {
        Self::bridge_netfilter_active_at(Path::new(path))
    }

    /// Install the `--physdev-in` FORWARD hook for one family.
    ///
    /// Whether a failure is fatal turns on the topology and not on the family,
    /// which is why `bridged` is the only thing that decides it. The `physdev`
    /// match is a separate kernel module a host may simply not have: where the
    /// `-i` hook already carries the traffic its absence costs nothing, and
    /// where it does not the chain is unreachable from FORWARD and the policy
    /// is unenforced.
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

    /// Build one FORWARD rule accepting reply traffic back to the container.
    ///
    /// The chain hooks traffic *leaving* the container (`-i` / `--physdev-in`),
    /// so a reply -- which arrives with the container's port as the output
    /// interface -- matches no MXC rule and falls through to the host's FORWARD
    /// policy. Where that policy is DROP, which is what installing Docker sets
    /// it to, an explicitly allowed destination is unreachable: the request
    /// goes out and the answer never comes back.
    ///
    /// Accepting on connection state cannot widen the policy, because a packet
    /// the chain drops never creates state. Conntrack attaches an *unconfirmed*
    /// entry at PREROUTING, but only `nf_conntrack_confirm` inserts it into the
    /// table, and that runs after the FORWARD verdict -- so a dropped packet is
    /// freed and takes its unconfirmed entry with it. The reverse packet then
    /// finds no state, is classified `NEW` rather than `ESTABLISHED`, matches
    /// nothing here, and falls to the host policy.
    ///
    /// The flows it does carry include ones the *host* authorized inbound, not
    /// only ones this chain authorized outbound: any connection whose first
    /// packet already passed the host's own policy has state. Inbound `NEW`
    /// connections match nothing here.
    ///
    /// It accepts rather than jumping to the chain, even though the chain
    /// carries an `ESTABLISHED,RELATED` rule of its own that would match. The
    /// chain's other rules are written against `-d <destination>` for egress,
    /// so an inbound packet that is not established would be tested against
    /// egress-shaped rules and, under an `allow` default, hit the chain's
    /// closing ACCEPT -- making this an inbound enforcement surface carrying
    /// egress semantics.
    fn build_forward_return_iface_rule_args(op: &str, iface: &str) -> Vec<String> {
        vec![
            op.to_string(),
            "FORWARD".to_string(),
            "-o".to_string(),
            iface.to_string(),
            "-m".to_string(),
            "state".to_string(),
            "--state".to_string(),
            "ESTABLISHED,RELATED".to_string(),
            "-j".to_string(),
            "ACCEPT".to_string(),
        ]
    }

    /// The bridge-port form of [`Self::build_forward_return_iface_rule_args`].
    ///
    /// `--physdev-out` names a bridge port that has already been selected,
    /// which happens for a packet being bridged. A reply from outside arrives
    /// on the host's uplink and is routed toward `lxcbr0`, so on the default
    /// bridged topology no port is selected while FORWARD runs and this rule
    /// does not match -- nor does the interface form, whose output device is
    /// `lxcbr0` rather than the veth. The ingress pair is not symmetric with
    /// it: `--physdev-in` matches because the packet demonstrably arrived on
    /// the veth.
    fn build_forward_return_physdev_rule_args(op: &str, iface: &str) -> Vec<String> {
        vec![
            op.to_string(),
            "FORWARD".to_string(),
            "-m".to_string(),
            "physdev".to_string(),
            "--physdev-out".to_string(),
            iface.to_string(),
            "-m".to_string(),
            "state".to_string(),
            "--state".to_string(),
            "ESTABLISHED,RELATED".to_string(),
            "-j".to_string(),
            "ACCEPT".to_string(),
        ]
    }

    /// Install one return-path rule, downgrading any failure to a warning.
    ///
    /// Unlike the chain hooks, a missing rule here cannot fail open: the rule
    /// only ever *accepts*, so failing to install it can leave the container
    /// less connected but never less filtered. Refusing to run over it would
    /// turn a connectivity limitation into an outage on hosts where the
    /// forward policy is ACCEPT and nothing was broken to begin with.
    ///
    /// Takes the builder rather than a built rule so the removal it attempts on
    /// failure cannot drift from the insert. `-I` reporting failure is only
    /// nearly conclusive -- a command killed after the kernel accepted its rule
    /// reports failure too -- and this returns `false`, which clears ownership.
    /// Without the removal that combination strands an `ESTABLISHED,RELATED`
    /// ACCEPT on a veth name the host is free to hand to another container.
    fn install_return_rule(
        run: fn(&[Vec<String>], &mut Logger) -> Result<(), String>,
        build: fn(&str, &str) -> Vec<String>,
        form: &str,
        iface: &str,
        tool: &str,
        logger: &mut Logger,
    ) -> bool {
        match run(&[build("-I", iface)], logger) {
            Ok(()) => true,
            Err(err) => {
                let _ = run(&[build("-D", iface)], logger);
                logger.log_line(&format!(
                    "Warning: could not install the {} return-path rule for {} ({}): {}. \
                     Replies to allowed outbound connections will rely on the host's FORWARD \
                     policy, so a DROP policy would make allowed destinations unreachable.",
                    form, iface, tool, err
                ));
                false
            }
        }
    }

    /// Whether a programmed destination accepts every address in its family.
    ///
    /// The question is provable coverage, not likely coverage. A prefix length
    /// of zero covers an unknown address without anyone having to know what
    /// that address is; a literal or any longer prefix names a bounded set that
    /// an unresolved host may or may not fall inside, and nothing available
    /// here can decide which. Only the first is treated as coverage.
    fn covers_every_address(destination: &str) -> bool {
        destination
            .split_once('/')
            .and_then(|(_, prefix)| prefix.trim().parse::<u8>().ok())
            .is_some_and(|prefix| prefix == 0)
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
        ]
        .into_iter()
        .map(|args| args.into_iter().map(String::from).collect())
        .collect()
    }

    /// The unconditional port 53 accept that only the legacy host-list path
    /// carries.
    ///
    /// A directional posture governs forwarded DNS with the same rules as
    /// every other forwarded destination: a resolver the policy never allowed
    /// is a resolver the container cannot reach.  Emitting this pair there
    /// would accept port 53 to the whole internet ahead of the generated
    /// rules, leaving a standing DNS-tunnel path out of an
    /// `egress.default: "deny"` container.
    fn build_legacy_dns_exemption_rule_args(chain_name: &str) -> Vec<Vec<String>> {
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
    /// These are the only allow rules a proxied chain carries; every other
    /// destination is left to the chain's closing DROP.
    ///
    /// The rules are IPv4 only, so they must not be run through `ip6tables`. A
    /// proxied IPv6 chain therefore holds its closing DROP alone, which is the
    /// fail-closed outcome -- IPv6 egress is denied rather than left open.
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
    /// An IPv6 proxy endpoint cannot be enforced, since the proxy rules are
    /// emitted with IPv4 `iptables` only. It needs naming as its own case
    /// because the failure would otherwise be silent: an IPv6 literal yields
    /// no IPv4 endpoint, and a proxied chain with no endpoints is a deny-all
    /// container whose proxy was discarded.
    fn host_is_ipv6_literal(host: &str) -> bool {
        let candidate = wxc_common::models::unbracket_host(host);
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

    /// Cap on how many resolved proxy addresses the chain will open.
    ///
    /// A round-robin or CDN answer is unbounded, and every address becomes its
    /// own ACCEPT rule and its own `iptables` process on the container-start
    /// path. Trimming fails closed, and the pinned address is always the first
    /// one, so the container can still reach the proxy it was pinned to.
    const MAX_PROXY_ENDPOINTS: usize = 16;

    /// Trim a resolved proxy answer to the addresses the chain will accept.
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

    /// Resolve the policy's proxy into the destinations the chain will allow,
    /// and the hosts-file pin the container needs to agree with them.
    ///
    /// Both come out of a single lookup. Two lookups of one name can disagree
    /// -- DNS round-robin returns a different order, or a TTL expires between
    /// the calls -- and a container pinned to an address this chain did not
    /// authorize cannot reach its proxy at all. A pin of `None` means the
    /// configured address is already an IP literal, which needs no pinning.
    ///
    /// The chain opens every resolved IPv4 address rather than the pinned one
    /// alone. They are all addresses of the same configured host, so the
    /// posture is unchanged, and a client that resolves the name through
    /// something other than the pin still reaches the proxy instead of being
    /// dropped.
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

    /// Build the hosts-file pin that makes the container resolve the proxy
    /// hostname to `ip`.
    ///
    /// A proxied chain opens no port 53, so the container has no resolver to
    /// reach: the pin is what lets it find the proxy at all, and it also stops
    /// the container selecting an address the chain never allowed.
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

    /// The `-p`/`--dport` arguments a match contributes, in the order
    /// `iptables` expects them.
    ///
    /// The family decides the ICMP protocol name. `ip6tables` rejects
    /// `-p icmp` outright rather than treating it as ICMPv6, which would
    /// otherwise turn an ICMP rule into a failed command on the v6 chain.
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

    /// Build the allow/deny rule args for a single host by resolving it once.
    /// Test-only: production goes through [`Self::build_policy_rules_logged`],
    /// which resolves every entry exactly once and reuses that result for both
    /// the unresolved-host warning and rule construction.
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
    /// rulegen assertions over well-formed policies keep a plain return type.
    #[cfg(test)]
    fn build_policy_rule_args(chain_name: &str, policy: &ContainerPolicy) -> FirewallRuleArgs {
        let mut logger = wxc_common::logger::Logger::new(wxc_common::logger::Mode::Buffer);
        Self::build_policy_rules_logged(chain_name, policy, &mut logger).expect(
            "test policy should not pair an accepting default with an unresolvable block entry",
        )
    }

    /// The 0.8 `network.egress` section, but only when the author actually
    /// stated a directional posture.
    ///
    /// This is the single place that decides which schema governs the chain,
    /// and the filter on `network_mode_specified` is what makes it correct.
    /// The parser hands every 0.8 config a defaulted `NetworkEgressPolicy`
    /// even when the config carries no `network` block at all, and
    /// `NetworkAction::Deny` is that default, so reading
    /// `network_egress.is_some()` alone would cut outbound traffic for every
    /// existing 0.8 LXC config that never asked for a directional posture.
    /// `network_mode_specified` is set only when an `egress` or `ingress`
    /// section was written, and `validate_network_policy_support` gates on
    /// the same field.
    fn stated_egress(policy: &ContainerPolicy) -> Option<&NetworkEgressPolicy> {
        policy
            .network_egress
            .as_ref()
            .filter(|_| policy.network_mode_specified)
    }

    /// The default policy the chain's closing rule must express.
    ///
    /// A 0.8 config states its outbound default in `network.egress.default`
    /// and never writes the legacy `network.defaultPolicy`, which the parser
    /// leaves at its `Block` default. Reading the legacy field alone closes
    /// every 0.8 chain with DROP, discarding an `egress.default: allow` the
    /// operator asked for. The legacy field still decides for a policy that
    /// stated no directional posture.
    fn effective_default_policy(policy: &ContainerPolicy) -> NetworkPolicy {
        match Self::stated_egress(policy) {
            Some(egress) => match egress.default {
                NetworkAction::Allow => NetworkPolicy::Allow,
                NetworkAction::Deny => NetworkPolicy::Block,
            },
            None => policy.default_network_policy.clone(),
        }
    }

    /// Lower whichever network schema the policy was written in into the
    /// entries the chain emits, in the order they must be emitted.
    ///
    /// The two schema shapes are alternatives, never a union: the parser
    /// rejects a config mixing them, and the directional path never writes
    /// the legacy host lists.
    fn lower_egress(policy: &ContainerPolicy) -> Vec<EgressEntry> {
        match Self::stated_egress(policy) {
            Some(egress) => Self::lower_directional_egress(egress),
            None => Self::lower_legacy_hosts(policy),
        }
    }

    /// Lower the legacy `blockedHosts`/`allowedHosts` lists into the entries
    /// the chain emits, in the order they must be emitted.
    ///
    /// Block entries come first. Deny-precedence (AB#62830341) is emission
    /// order and nothing else: iptables/ip6tables apply first-match-wins
    /// within the chain, which makes a destination present in both lists
    /// DROP. There is no separate reconciliation pass anywhere in this
    /// backend. Exchanging the two halves reverses the security semantics of
    /// every policy whose lists overlap and produces no other symptom.
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
                // A legacy entry names a destination and nothing else, so it
                // matches every protocol and port reaching that destination.
                matching: RuleMatch::AnyTraffic,
            })
            .collect()
    }

    /// Lower a 0.8 `network.egress` section into the entries the chain emits.
    ///
    /// `deny` rules precede `allow` rules for the same reason the legacy
    /// lowering puts blocks first: the chain is first-match-wins and holds no
    /// reconciliation pass, so a destination named in both lists is DROPped
    /// only while the deny is emitted first. The schema states the two lists
    /// independently and fixes no order between them, which makes
    /// establishing that order this function's job.
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

    /// Expand one 0.8 rule into one entry per (peer, port selector) pair.
    ///
    /// The expansion happens here rather than in the emitter because a rule
    /// names a set of destinations and a set of port selectors, while an
    /// iptables rule names exactly one of each.
    ///
    /// An omitted `to` selects every destination, matching the schema's
    /// documented wildcard behavior for an absent field. The parser rejects
    /// an explicitly empty array, so an empty `to` here can only be the
    /// omitted form.
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
                // An `except` range narrows the peer that follows it, and the
                // chain is first-match-wins, so the carve-out must be emitted
                // before the rule it narrows or it can never be reached.
                //
                // The carve-out carries the direction's default verdict rather
                // than the opposite of the rule's own. The schema defines
                // `except` as an exclusion from the peer, which puts the range
                // outside the rule entirely and leaves it whatever the
                // direction would have given it. Emitting the rule's opposite
                // instead denies an excepted range under `default: allow` —
                // the operator asking for a range to be spared and getting it
                // blocked.
                //
                // Nothing is emitted when the two already agree: the range
                // reaches the identical verdict at the closing rule, and an
                // extra `iptables` invocation on the container-start path buys
                // no change in behavior.
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

    /// The peer list standing in for an omitted `to`: every address in both
    /// families. Two entries rather than one because a v4 chain and a v6
    /// chain are programmed separately and neither wildcard covers the other.
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

    /// Render a parsed CIDR back into the destination string `resolve_host`
    /// reads. `resolve_host` passes a validated CIDR through untouched, so a
    /// 0.8 peer and a legacy CIDR entry reach the emitter by the same path.
    fn cidr_destination(cidr: &NetworkCidr) -> String {
        format!("{}/{}", cidr.address, cidr.prefix_length)
    }

    /// Lower a rule's `ports` array into the per-rule matches it selects.
    ///
    /// An empty array is the omitted form -- the parser rejects an explicit
    /// empty array -- and selects every protocol and port.
    fn lower_port_selectors(ports: &[NetworkPort]) -> Vec<RuleMatch> {
        if ports.is_empty() {
            return vec![RuleMatch::AnyTraffic];
        }
        ports.iter().flat_map(Self::lower_port_selector).collect()
    }

    /// Lower one `ports` selector into the matches a single iptables rule can
    /// express.
    ///
    /// Protocol `any` with a port is the case that yields two matches.
    /// `-p all` accepts no `--dport`, and the port has to survive, so the
    /// selector becomes one TCP match and one UDP match. ICMP is excluded
    /// from that pair deliberately: it carries no port, so a selector naming
    /// a port cannot have meant it.
    fn lower_port_selector(port: &NetworkPort) -> Vec<RuleMatch> {
        let ports = port.port.map(|start| PortRange {
            start,
            // A selector with no `endPort` names a single port, which is the
            // range whose ends are equal.
            end: port.end_port.unwrap_or(start),
        });

        match port.protocol {
            // ICMP has no ports. A port alongside it is dropped rather than
            // emitted, since `-p icmp --dport` is not a legal match.
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

    /// Resolve every lowered entry exactly once and build the rule args from
    /// that single resolution, logging a warning for any entry that resolved
    /// to nothing. This is the shipping rule-generation path.
    ///
    /// Resolving once is a correctness requirement, not just an optimization:
    /// the previous apply path resolved each host once for the warning pass
    /// and again inside rule construction, and two lookups of the same name
    /// can disagree — DNS round-robin returns a different address, or a TTL
    /// expires between the calls — so the rule installed would not match the
    /// rule that was validated and logged.
    ///
    /// Entries are emitted in the order the lowering produced them, which is
    /// the whole of this backend's deny-precedence guarantee. See
    /// [`Self::lower_legacy_hosts`] for why that order is load-bearing.
    ///
    /// An entry that resolves to nothing programs no rule, and the two
    /// directions are not symmetric. An unwritten deny leaves reachable a
    /// destination the operator named as unreachable, so it is a hard error
    /// wherever something else in the chain would accept that destination.
    /// An unwritten allow only withholds traffic that was meant to be
    /// permitted, which costs availability and can never widen what the
    /// container reaches, so it is always a warning.
    fn build_policy_rules_logged(
        chain_name: &str,
        policy: &ContainerPolicy,
        logger: &mut Logger,
    ) -> Result<FirewallRuleArgs, String> {
        let default_permits = matches!(policy.default_network_policy, NetworkPolicy::Allow);
        let mut args = FirewallRuleArgs::default();
        let mut unresolved_denies: Vec<&str> = Vec::new();
        let mut catch_all_allows: Vec<&str> = Vec::new();
        let entries = Self::lower_egress(policy);
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
                // A catch-all is what defeats an unwritten deny, and only an
                // entry matching every protocol and port can do that. An
                // allow of `0.0.0.0/0` on one port accepts a single port
                // rather than whatever the unresolvable deny named, so
                // counting it here would reject ordinary policies.
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
        // Under a denying default an unresolvable deny is tolerable on the
        // grounds that the chain's closing DROP covers whatever the missing
        // rule would have covered. That holds only while no ACCEPT can match
        // first. `resolve_host` passes validated CIDRs through untouched, so
        // `0.0.0.0/0` is a legal allow entry, and it accepts every address --
        // including whatever the blocked host would have resolved to. There
        // the deny is *provably* defeated, and no evidence could rescue it,
        // so fail closed.
        //
        // A narrower allow is left as a warning on purpose. Its destinations
        // are a finite set the operator named and vouched for, the closing
        // DROP still covers everything outside that set, and nothing here can
        // show the missing deny falls inside it. Rejecting that case too
        // would make an ordinary policy -- an allowlist plus a blocked host
        // that no longer exists -- a hard failure, and the cheapest way out
        // of it is to delete the blocklist entry. Trading a recorded warning
        // for a silently shortened blocklist is a worse security outcome than
        // the residual risk it removes.
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
    ///
    /// Exposed to the crate so the inbound (ingress) chain in
    /// [`crate::network_ingress`] reuses this pure fail-open-vs-fail-closed
    /// decision while feeding it a *container-namespace*-scoped probe.
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
    ///
    /// Exposed to the crate so [`crate::network_ingress`] can classify a
    /// *container-namespace* `/proc/<pid>/net/if_inet6` read with the same
    /// pure logic.
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
    /// unit-testable. Exposed to the crate for reuse by
    /// [`crate::network_ingress`].
    pub(crate) fn ipv6_state_treated_as_active(state: HostIpv6State) -> bool {
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

    /// Apply network firewall rules based on the container policy.
    ///
    /// On any failure after resources are created, the inner call rolls back
    /// exactly the per-family chains and FORWARD hooks this attempt installed
    /// before the error is returned, so a retry does not trip over a leftover
    /// `MXC-<name>` chain ("chain already exists") and a partial failure never
    /// tears down a chain this attempt did not create.
    ///
    /// A proxied policy whose proxy is named rather than an IP literal also
    /// produces [`Self::proxy_host_pin`], which the caller must give the
    /// container before it runs. A proxied chain opens no port 53, so a
    /// container started without that pin cannot resolve the proxy name and
    /// reaches nothing at all.
    pub fn apply_firewall_rules(
        &mut self,
        policy: &ContainerPolicy,
        logger: &mut Logger,
    ) -> Result<bool, String> {
        // `enforcementMode` is deliberately not consulted here; a caller may get
        // more enforcement than the mode asked for, never less. That is what
        // makes a proxy safe without a special case: `requires_firewall` counts
        // an enabled proxy, so a proxied policy can no longer reach this skip
        // and report success while the runner injects HTTP(S)_PROXY into a
        // container whose egress was never restricted.
        if !requires_firewall(policy) {
            logger.log_line(
                "Network policy requires no egress firewall (permissive default, no host \
                 lists, no proxy, no directional posture); skipping iptables.",
            );
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

        // A blocked destination stays reachable through the proxy, which MXC
        // does not configure, so programming the rest would report success for
        // a control that is not in effect.
        if !proxy_endpoints.is_empty() && !policy.blocked_hosts.is_empty() {
            return Err(
                "network.proxy cannot be combined with blockedHosts: the proxy can fetch a \
                 blocked destination on the container's behalf, so the block list would not \
                 be enforced"
                    .to_string(),
            );
        }

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
        created.v4.chain = true;
        Self::publish_created(created);
        if ipv6_enabled {
            Self::run_ip6tables(&["-N", &self.chain_name], logger)?;
            created.v6.chain = true;
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
            // The allow list is not programmed either: an entry naming
            // anything but the proxy contradicts the model, and one naming the
            // proxy is already covered. A block list never reaches here.
            let proxy_rules = Self::build_proxy_chain_rule_args(&self.chain_name, proxy_endpoints);
            Self::run_iptables_rule_args(&proxy_rules, logger)?;
            for rule in &proxy_rules {
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
                     endpoint is IPv4, so the IPv6 chain carries only its closing DROP.",
                );
            }
        } else {
            let mut base_rules = Self::build_base_chain_rule_args(&self.chain_name);
            // The field records the network format the parser actually chose,
            // not the version the request declared: a 0.8 request written in
            // the legacy shape lands here and keeps legacy DNS behavior.
            if policy.network_egress.is_none() {
                base_rules.extend(Self::build_legacy_dns_exemption_rule_args(&self.chain_name));
            }
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
            Self::effective_default_policy(policy),
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
        // host arrives as `-i <veth>`. A veth attached to a bridge -- the
        // default LXC topology -- arrives as `-i <bridge>`, and only
        // `--physdev-in <veth>` still identifies the container. Installing
        // only the first is what let a fully populated deny-all chain sit in
        // the ruleset filtering nothing.
        //
        // The two are mutually exclusive for any given packet, so no packet is
        // counted twice.
        //
        // `-o` matches the reply direction rather than egress, which is why it
        // has no place in the hooks -- and why the return-path rules installed
        // alongside them below use it instead. Those are scoped to this same
        // block: a caller with no veth has no port to name, and an unscoped
        // ACCEPT would carry traffic for every container on the host.
        if let Some(ref iface) = self.veth_interface {
            let topology = self.veth_topology(iface);
            // Only a positive "directly routed" finding earns the relaxed
            // treatment. An unreadable sysfs establishes nothing, and the
            // relaxed branch is the one that downgrades a failed physdev hook
            // to a warning -- so an unknown topology is handled as bridged.
            let bridged = Self::treat_as_bridged(topology);
            if topology == VethTopology::Unknown {
                logger.log_line(&format!(
                    "Warning: could not determine whether container veth {} is bridged \
                     ({} is unreadable). Treating it as bridged, which keeps a failed \
                     physdev hook fatal rather than silently unenforced.",
                    iface, SYSFS_NET_ROOT
                ));
            }
            let chain_name = self.chain_name.clone();

            Self::install_family_hooks(
                created,
                |created| &mut created.v4,
                Self::run_iptables_rule_args,
                "iptables",
                BRIDGE_NF_CALL_IPTABLES,
                iface,
                &chain_name,
                bridged,
                logger,
            )?;

            if ipv6_enabled {
                Self::install_family_hooks(
                    created,
                    |created| &mut created.v6,
                    Self::run_ip6tables_rule_args,
                    "ip6tables",
                    BRIDGE_NF_CALL_IP6TABLES,
                    iface,
                    &chain_name,
                    bridged,
                    logger,
                )?;
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
    ///
    /// FORWARD hooks are claimed *before* their `-I` runs, and chains are
    /// deliberately not claimed before their `-N`. The asymmetry is in the two
    /// iptables commands. A hook that was never inserted can be disowned again
    /// the moment its `-I` reports failure, so claiming early costs nothing
    /// that [`Self::install_claimed_hook`] cannot give back. `-N` fails when
    /// the name is already taken, and the chain holding that name belongs to
    /// someone else, so claiming early would let the rollback of a failed
    /// create delete a live chain -- trading a leak for the removal of another
    /// container's enforcement.
    ///
    /// The window an early claim closes is between the command returning and
    /// the record being written: a signal landing there leaves an installed
    /// hook absent from the snapshot, cleanup skips it, and the surviving hook
    /// holds a reference that keeps the chain undeletable.
    fn publish_created(created: &CreatedResources) {
        crate::signal_cleanup::set_active_created(*created);
    }

    /// Install one family's FORWARD hooks and return-path rules, recording
    /// ownership as each one lands.
    ///
    /// The families differ only in the tool that programs them, the sysctl
    /// that governs bridged delivery, and which half of `created` they own.
    /// Sharing one body is what stops a fix reaching one family and silently
    /// missing the other.
    #[allow(clippy::too_many_arguments)]
    fn install_family_hooks(
        created: &mut CreatedResources,
        family: fn(&mut CreatedResources) -> &mut FamilyResources,
        run: fn(&[Vec<String>], &mut Logger) -> Result<(), String>,
        tool: &str,
        bridge_nf_path: &str,
        iface: &str,
        chain_name: &str,
        bridged: bool,
        logger: &mut Logger,
    ) -> Result<(), String> {
        // On a bridged veth the physdev rule is the only one that can match,
        // and it can only match while br_netfilter is delivering bridged
        // packets to the filter tables. Without that, both rules install
        // cleanly and neither ever fires, which is the exact failure this
        // change exists to remove: a chain that looks enforced and is not.
        if bridged && !Self::bridge_netfilter_active(bridge_nf_path) {
            return Err(format!(
                "Container veth {} is attached to a bridge but bridged packets are not \
                 delivered to {} ({} is absent or 0), so chain {} could never be reached \
                 from FORWARD. Refusing to report success for an unenforceable policy.",
                iface, tool, bridge_nf_path, chain_name
            ));
        }

        Self::install_claimed_hook(
            created,
            |created, claimed| family(created).hook = claimed,
            |logger| {
                run(
                    &[Self::build_forward_hook_iface_rule_args(
                        "-I", iface, chain_name,
                    )],
                    logger,
                )
            },
            |logger| {
                let _ = run(
                    &[Self::build_forward_hook_iface_rule_args(
                        "-D", iface, chain_name,
                    )],
                    logger,
                );
            },
            logger,
        )?;

        let physdev_installed = Self::install_claimed_hook(
            created,
            |created, claimed| family(created).physdev_hook = claimed,
            |logger| Self::install_physdev_hook(run, iface, chain_name, bridged, tool, logger),
            |logger| {
                let _ = run(
                    &[Self::build_forward_hook_physdev_rule_args(
                        "-D", iface, chain_name,
                    )],
                    logger,
                );
            },
            logger,
        )?;
        family(created).physdev_hook = physdev_installed;
        Self::publish_created(created);

        // Claimed before insertion for the same reason the hooks are: a fatal
        // signal between the call and the record would leave the rule
        // installed and absent from the cleanup snapshot.
        let claimed = family(created);
        claimed.return_rule = true;
        claimed.physdev_return = true;
        Self::publish_created(created);

        let return_installed = Self::install_return_rule(
            run,
            Self::build_forward_return_iface_rule_args,
            "interface",
            iface,
            tool,
            logger,
        );
        let physdev_return_installed = Self::install_return_rule(
            run,
            Self::build_forward_return_physdev_rule_args,
            "physdev",
            iface,
            tool,
            logger,
        );
        let installed = family(created);
        installed.return_rule = return_installed;
        installed.physdev_return = physdev_return_installed;
        Self::publish_created(created);

        logger.log_line(&format!(
            "FORWARD hook installed on {} for chain {} ({}).",
            iface, chain_name, tool
        ));

        Ok(())
    }

    /// Claim a FORWARD hook, install it, and hand the claim back if the install
    /// reports that it never landed.
    ///
    /// The claim has to be made first, because the window it closes is the one
    /// between the command returning and the record being written -- see
    /// [`Self::publish_created`]. Holding it after a *failed* install is a
    /// different matter: `-D` removes by full rule specification and reports a
    /// specification that matches nothing as an error, so the rollback of a
    /// hook that was never inserted cannot clear its own claim. A hook still
    /// recorded as present is what [`teardown_chain`] reads as a live
    /// reference, and it leaves the chain unflushed and undeleted rather than
    /// orphan a jump target. The chain then outlives the apply that failed, and
    /// the next run for the same container dies at `-N` because the name is
    /// taken -- one failed setup, and that container name never starts again
    /// without a human clearing it.
    ///
    /// `undo` still runs before the claim is released, and runs even though the
    /// install just said it failed. The exit status of `-I` is only *nearly*
    /// conclusive: a command killed after the kernel accepted its rule also
    /// reports failure, and releasing a claim on a rule that is really there
    /// would strand it where nothing knows to remove it. Attempting the removal
    /// costs one no-op command on a path that has already failed, and it makes
    /// the release safe whichever way the ambiguity fell.
    fn install_claimed_hook<T>(
        created: &mut CreatedResources,
        mut claim: impl FnMut(&mut CreatedResources, bool),
        install: impl FnOnce(&mut Logger) -> Result<T, String>,
        undo: impl FnOnce(&mut Logger),
        logger: &mut Logger,
    ) -> Result<T, String> {
        claim(created, true);
        Self::publish_created(created);
        let outcome = install(logger);
        if outcome.is_err() {
            undo(logger);
            claim(created, false);
            Self::publish_created(created);
        }
        outcome
    }

    /// Best-effort removal of the FORWARD hooks and per-container chains that
    /// `created` records were installed, in both tables. Only resources marked
    /// as created are touched, so a partial-failure rollback never tears down
    /// a chain this attempt did not create — which matters because the chain
    /// name is derived solely from the container name, so every run of that
    /// name shares it. A missing rule/chain still makes an individual
    /// `-D`/`-F`/`-X` call a no-op, so it doubles as the rollback path for a
    /// failed apply.
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
            Self::teardown_family_forward(
                Self::run_iptables_rule_args,
                chain_name,
                iface,
                &created.v4,
                &mut residual.v4,
                logger,
            );
            Self::teardown_family_forward(
                Self::run_ip6tables_rule_args,
                chain_name,
                iface,
                &created.v6,
                &mut residual.v6,
                logger,
            );
        }

        // Flush and delete only the chains this attempt created, and only once
        // every FORWARD hook for that family is confirmed gone. `-X` is the
        // command that actually relinquishes the chain, so ownership is only
        // cleared when it succeeds. Either surviving hook still references the
        // chain, so both gate the delete. The gate is per family because the
        // two chains live in different tables and are referenced independently.
        residual.v4.chain = teardown_chain(
            created.v4.chain,
            residual.v4.hooks_remain(),
            logger,
            |logger| {
                let _ = Self::run_iptables(&["-F", chain_name], logger);
            },
            |logger| Self::run_iptables(&["-X", chain_name], logger).is_ok(),
        );
        residual.v6.chain = teardown_chain(
            created.v6.chain,
            residual.v6.hooks_remain(),
            logger,
            |logger| {
                let _ = Self::run_ip6tables(&["-F", chain_name], logger);
            },
            |logger| Self::run_ip6tables(&["-X", chain_name], logger).is_ok(),
        );

        Self::publish_created(&residual);
        residual
    }

    /// Remove one family's FORWARD rules, clearing ownership only where the
    /// removal succeeded.
    fn teardown_family_forward(
        run: fn(&[Vec<String>], &mut Logger) -> Result<(), String>,
        chain_name: &str,
        iface: &str,
        created: &FamilyResources,
        residual: &mut FamilyResources,
        logger: &mut Logger,
    ) {
        if created.hook
            && run(
                &[Self::build_forward_hook_iface_rule_args(
                    "-D", iface, chain_name,
                )],
                logger,
            )
            .is_ok()
        {
            residual.hook = false;
        }
        if created.physdev_hook
            && run(
                &[Self::build_forward_hook_physdev_rule_args(
                    "-D", iface, chain_name,
                )],
                logger,
            )
            .is_ok()
        {
            residual.physdev_hook = false;
        }

        // The return-path rules jump to ACCEPT rather than to the chain, so
        // unlike the hooks above they hold no reference to it and do not gate
        // the delete. They are still this attempt's to remove: left behind,
        // they would accept established traffic for a veth name the kernel may
        // later hand to a different container.
        if created.return_rule
            && run(
                &[Self::build_forward_return_iface_rule_args("-D", iface)],
                logger,
            )
            .is_ok()
        {
            residual.return_rule = false;
        }
        if created.physdev_return
            && run(
                &[Self::build_forward_return_physdev_rule_args("-D", iface)],
                logger,
            )
            .is_ok()
        {
            residual.physdev_return = false;
        }
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
    /// keeps this path from flushing a live chain we do not own: the chain
    /// name is a pure function of the container name, so a signal delivered
    /// to one run would otherwise empty the chain belonging to a later run of
    /// the same name, silently failing it open.
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
        if self.rules_applied && !self.preserve_policy {
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

/// Black-box specification for schema 0.8 `network.egress` lowering, kept in
/// its own file for the same reason as `veth_spec`.
#[cfg(test)]
#[path = "network_iptables_ga_egress_spec.rs"]
mod ga_egress_spec;

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
        /// A needle, and the message every command whose argv contains it
        /// fails with. Takes precedence over `scripted` and `fallback`.
        fail_matching: Option<(String, String)>,
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
        /// Every command from here on fails with `stderr`.
        pub(super) fn fail_every_command(&self, stderr: &str) -> &Self {
            Self::with_state(|state| state.fallback = Err(stderr.to_string()));
            self
        }

        /// Every command containing `needle` in its argument vector fails with
        /// `stderr`; every other command succeeds. Lets a test fail one
        /// specific step of an apply without having to count the commands that
        /// precede it.
        pub(super) fn fail_commands_matching(&self, needle: &str, stderr: &str) -> &Self {
            Self::with_state(|state| {
                state.fail_matching = Some((needle.to_string(), stderr.to_string()));
            });
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
    use wxc_common::models::{ContainerPolicy, NetworkEnforcementMode, ProxyAddress, ProxyConfig};

    /// Build a policy requesting the given enforcement mode, leaving every
    /// other field at its default.
    fn policy_requesting_mode(mode: NetworkEnforcementMode) -> ContainerPolicy {
        ContainerPolicy {
            network_specified: true,
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
            flush_and_delete("iptables", "racer-that-won"),
            "only the published chain may be flushed and deleted, and only it"
        );
    }

    #[test]
    fn a_signal_removes_every_resource_the_run_published() {
        // The ownership record grew physdev and return fields, but every other
        // force_cleanup test constructs the original chain-and-hook shape, so a
        // teardown that skipped one of the newer fields would leak a rule into
        // FORWARD and still pass the suite.
        let fake = test_firewall::install();
        let mut logger = Logger::new(Mode::Buffer);

        NetworkIptablesManager::force_cleanup(
            "all-resources",
            Some("mxcv-all"),
            CreatedResources::for_test_all(),
            &mut logger,
        );

        let chain = chain_name_for("all-resources");
        let issued: Vec<String> = fake.issued().iter().map(|c| c.join(" ")).collect();

        for tool in ["iptables", "ip6tables"] {
            let deletes = issued
                .iter()
                .filter(|c| c.starts_with(&format!("{tool} -D FORWARD")))
                .count();
            assert_eq!(
                deletes, 4,
                "{tool} published an interface hook, a physdev hook, a return \
                 rule and a physdev return rule, so all four must be deleted; \
                 issued: {issued:?}"
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
            flush_and_delete("iptables", "survivor"),
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
            flush_and_delete("iptables", "adopted"),
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
        // the name is shared by every run of the same container name, so it
        // may belong to a run that is still live.
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
            flush_and_delete("iptables", "stubborn"),
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
            flush_and_delete("iptables", "stubborn"),
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

    /// The flush-then-delete pair a teardown issues for `container`'s chain.
    fn flush_and_delete(binary: &str, container: &str) -> Vec<Vec<String>> {
        let chain = chain_name_for(container);
        vec![
            vec![binary.to_string(), "-F".to_string(), chain.clone()],
            vec![binary.to_string(), "-X".to_string(), chain],
        ]
    }

    #[test]
    fn chain_name_sanitization() {
        let mgr = NetworkIptablesManager::new("my-container_123");
        assert_eq!(mgr.chain_name, chain_name_for("my-container_123"));
        assert!(mgr.chain_name.starts_with("MXC-my-cont-"));
    }

    #[test]
    fn chain_name_respects_the_length_ceiling() {
        let long_name = "a".repeat(50);
        let mgr = NetworkIptablesManager::new(&long_name);
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
        // The same rules are fed to both iptables and ip6tables, so neither
        // builder may name an address family or a v4-only protocol.
        let base = NetworkIptablesManager::build_base_chain_rule_args("MXC-test");
        let dns = NetworkIptablesManager::build_legacy_dns_exemption_rule_args("MXC-test");

        assert_eq!(base.len(), 2);
        assert_eq!(dns.len(), 2);
        for rule in base.iter().chain(dns.iter()) {
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
            network_specified: true,
            allowed_hosts: strings(allowed_hosts),
            blocked_hosts: strings(blocked_hosts),
            ..Default::default()
        }
    }

    /// `.invalid` is reserved by RFC 2606 and never resolves, so it is a stable
    /// way to exercise the unresolvable path without depending on the network.
    const UNRESOLVABLE_HOST: &str = "blocked.invalid";

    #[test]
    fn an_unresolvable_deny_under_a_blocking_default_is_fatal_beside_a_catch_all_allow() {
        // The allow is evaluated before the chain's closing DROP and accepts
        // every address, so it accepts the blocked host whatever it resolves
        // to for the container.
        let policy = ContainerPolicy {
            default_network_policy: NetworkPolicy::Block,
            ..policy_with_hosts(&["0.0.0.0/0"], &[UNRESOLVABLE_HOST])
        };
        let mut logger = wxc_common::logger::Logger::new(wxc_common::logger::Mode::Buffer);

        let err = NetworkIptablesManager::build_policy_rules_logged("MXC-x", &policy, &mut logger)
            .expect_err("a catch-all allow must not be able to accept an unresolvable deny");

        assert!(
            err.contains(UNRESOLVABLE_HOST) && err.contains("deny precedence"),
            "error should name the host and the invariant, got: {err}"
        );
    }

    #[test]
    fn an_ipv6_catch_all_allow_also_arms_the_deny_precedence_failure() {
        // The proof is per family and neither family may be overlooked, so a
        // v4-only check would leave the identical v6 hole open.
        let policy = ContainerPolicy {
            default_network_policy: NetworkPolicy::Block,
            ..policy_with_hosts(&["::/0"], &[UNRESOLVABLE_HOST])
        };
        let mut logger = wxc_common::logger::Logger::new(wxc_common::logger::Mode::Buffer);

        NetworkIptablesManager::build_policy_rules_logged("MXC-x", &policy, &mut logger)
            .expect_err("a v6 catch-all allow accepts the unresolved deny just as a v4 one does");
    }

    #[test]
    fn an_unresolvable_deny_beside_a_bounded_allow_stays_a_warning() {
        // An allowlist next to a blocked host that no longer exists is the
        // ordinary case. The allow names one address, the closing DROP still
        // covers every other, and nothing shows the missing deny is that
        // address -- so this must not become a hard failure.
        let policy = ContainerPolicy {
            default_network_policy: NetworkPolicy::Block,
            ..policy_with_hosts(&["192.0.2.10"], &[UNRESOLVABLE_HOST])
        };
        let mut logger = wxc_common::logger::Logger::new(wxc_common::logger::Mode::Buffer);

        NetworkIptablesManager::build_policy_rules_logged("MXC-x", &policy, &mut logger)
            .expect("a bounded allow leaves the closing DROP covering the unresolved deny");
    }

    #[test]
    fn a_bounded_cidr_allow_is_not_mistaken_for_a_catch_all() {
        // Guards the prefix length specifically: a check that only looked for
        // a '/' would reject every CIDR allow, and one that only compared the
        // address would reject `0.0.0.0/8`.
        let policy = ContainerPolicy {
            default_network_policy: NetworkPolicy::Block,
            ..policy_with_hosts(&["192.0.2.0/24"], &[UNRESOLVABLE_HOST])
        };
        let mut logger = wxc_common::logger::Logger::new(wxc_common::logger::Mode::Buffer);

        NetworkIptablesManager::build_policy_rules_logged("MXC-x", &policy, &mut logger)
            .expect("a /24 allow covers a bounded set, so it proves nothing about the deny");
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
    fn an_unknown_topology_reaches_the_call_site_and_says_so() {
        // The probe states three things, but only the call site decides. This
        // pins the join: an unreadable sysfs must arrive as Unknown, be handled
        // as bridged, and leave a diagnosable trace. Without the log line the
        // fail-closed choice is invisible in the field, which is how the
        // original fail-open behavior survived review in the first place.
        //
        // The apply's Result is deliberately not asserted: whether the bridged
        // branch then errors depends on whether the host has br_netfilter
        // active, which is not what this test is about.
        let _fake = test_firewall::install();

        let mut manager = NetworkIptablesManager::new("unknown-topology");
        manager.set_veth_interface("mxcv-unknown");
        manager.set_topology_override(VethTopology::Unknown);
        let policy = policy_with_enforcement_mode(NetworkEnforcementMode::Firewall);
        let mut logger = Logger::new(Mode::Buffer);

        let _ = manager.apply_firewall_rules(&policy, &mut logger);

        let logged = logger.get_buffer();
        assert!(
            logged.contains("could not determine whether container veth mxcv-unknown is bridged"),
            "an unknown topology must be reported, or the fail-closed choice is \
             undiagnosable in the field; logged: {logged}"
        );
        assert!(
            logged.contains("Treating it as bridged"),
            "the log must say which way the ambiguity was resolved; logged: {logged}"
        );
    }

    #[test]
    fn a_forward_hook_is_owned_even_when_its_insert_command_never_completed() {
        // The signal race this guards: the kernel accepts `-I`, and the process
        // dies before recording it. Ownership must already cover the hook at
        // that point, or cleanup skips it and the surviving rule keeps the
        // chain referenced and undeletable.
        //
        // A signal cannot be delivered mid-apply in a unit test, so this uses
        // the observable that distinguishes the two orderings: a hook insert
        // that does not complete successfully. Claiming after the command would
        // leave it unowned and the rollback silent; claiming before means the
        // rollback still tries to remove it.
        let fake = test_firewall::install();
        fake.fail_commands_matching("FORWARD", "simulated interruption");

        let mut manager = NetworkIptablesManager::new("hook-race");
        manager.set_veth_interface("mxcv-race");
        let policy = policy_with_enforcement_mode(NetworkEnforcementMode::Firewall);
        let mut logger = Logger::new(Mode::Buffer);

        let result = manager.apply_firewall_rules(&policy, &mut logger);
        assert!(
            result.is_err(),
            "a failed FORWARD hook insert must fail the apply, got {:?}",
            result
        );

        let issued = fake.issued();
        let attempted_hook_removal = issued
            .iter()
            .any(|cmd| cmd.iter().any(|arg| arg == "-D") && cmd.iter().any(|arg| arg == "FORWARD"));
        assert!(
            attempted_hook_removal,
            "the rollback must try to remove a hook whose insert did not complete, \
             otherwise a signal in that same window would leak it; issued: {:?}",
            issued
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
    fn base_chain_rules_are_two_family_agnostic_rules_in_documented_order() {
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
    fn legacy_dns_exemption_is_the_documented_udp_then_tcp_pair() {
        let chain_name = "MXC-base";
        let rules = NetworkIptablesManager::build_legacy_dns_exemption_rule_args(chain_name);
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
            "the legacy DNS exemption should be the documented udp/tcp pair"
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
        let short_manager = NetworkIptablesManager::new("short");
        assert!(
            short_manager.chain_name.starts_with("MXC-short-"),
            "a short ASCII name should stay legible in the slug; actual: {}",
            short_manager.chain_name
        );

        let long_name = "abcdefghijklmnopqrstuvwxyz";
        let long_manager = NetworkIptablesManager::new(long_name);
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
        let policy = policy_requiring_no_firewall();
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
    fn no_enforcement_mode_changes_the_firewall_gate() {
        use NetworkEnforcementMode::{Both, Capabilities, Firewall};

        // The mode is a request for enforcement; the gate answers whether
        // enforcement is owed. Reading the first to decide the second is what
        // let a restrictive policy start with an open chain.
        for mode in [Capabilities, Firewall, Both] {
            let label = format!("{mode:?}");

            let restrictive = ContainerPolicy {
                network_specified: true,
                network_enforcement_mode: mode.clone(),
                blocked_hosts: vec!["example.com".to_string()],
                ..Default::default()
            };
            assert!(
                requires_firewall(&restrictive),
                "{label}: a policy that restricts egress is owed the firewall"
            );

            let permissive = ContainerPolicy {
                network_specified: true,
                network_enforcement_mode: mode,
                default_network_policy: NetworkPolicy::Allow,
                ..Default::default()
            };
            assert!(
                !requires_firewall(&permissive),
                "{label}: a policy that restricts nothing is owed no firewall"
            );
        }
    }

    // A 0.8 config cannot carry `enforcementMode` -- the parser rejects it
    // beside `egress` -- so it always arrives with the `Capabilities` default.
    // Reading the mode alone would skip the chain the `egress` section just
    // asked for, leaving the policy unenforced while the run reported success.
    #[test]
    fn a_stated_directional_egress_posture_requests_the_firewall_under_the_capabilities_default() {
        let policy = ContainerPolicy {
            network_specified: true,
            network_enforcement_mode: NetworkEnforcementMode::Capabilities,
            network_mode_specified: true,
            default_network_policy: NetworkPolicy::Allow,
            network_egress: Some(NetworkEgressPolicy::default()),
            ..Default::default()
        };

        assert!(
            requires_firewall(&policy),
            "a stated 0.8 egress posture must request the firewall even though \
             enforcementMode is absent from the 0.8 schema and defaults to capabilities"
        );
    }

    // The shape that put iptables chains in front of every container on the
    // branch: a config with no `network` section is still handed a deny-all
    // egress policy by the parser, on the same path that leaves
    // `default_network_policy` at `Block`. Both arms answer yes to it, and
    // none of it was asked for. Hosts without bridge netfilter then refuse the
    // chain and the container never starts.
    #[test]
    fn a_config_naming_no_network_section_is_owed_no_firewall() {
        let policy = ContainerPolicy {
            network_egress: Some(NetworkEgressPolicy::default()),
            ..Default::default()
        };

        assert!(
            !policy.network_specified,
            "fixture must model a config that named no network section"
        );
        assert!(
            !requires_firewall(&policy),
            "a config that never mentioned networking must not request the firewall"
        );
        assert!(
            !installs_firewall(&policy),
            "a config that never mentioned networking must not install chains"
        );
    }

    // The `Block` arm answers this policy too, but only because `Block` is the
    // parser's default for a field 0.8 never writes. Pinning the permissive
    // default here keeps the directional arm as the thing under test.
    #[test]
    fn a_legacy_policy_under_capabilities_is_still_owed_the_firewall() {
        let policy = ContainerPolicy {
            network_specified: true,
            network_enforcement_mode: NetworkEnforcementMode::Capabilities,
            network_mode_specified: true,
            default_network_policy: NetworkPolicy::Allow,
            blocked_hosts: vec!["example.com".to_string()],
            network_egress: None,
            ..Default::default()
        };

        assert!(
            requires_firewall(&policy),
            "a 0.7 policy naming blocked hosts is owed the firewall whatever mode it \
             names; the engine rewrites the mode to firewall when host rules arrive \
             without a proxy, but nothing rejects this shape and a hand-built \
             ExecutionRequest reaches here and would otherwise restrict nothing"
        );
    }

    // The JSON parser rejects proxy-under-capabilities, but it is not the only
    // way in: `LxcScriptRunner::execute` and `mxc_engine::run` take an
    // already-built `ExecutionRequest`. Skipping here would report success for
    // an enforcement that never happened, while the runner still injects the
    // proxy environment -- a container that advertises a proxy and restricts
    // nothing.
    // The runner injects HTTP(S)_PROXY from the same policy regardless of what
    // the firewall does, so a proxied policy that skipped the chain would
    // advertise a proxy and restrict nothing -- any client that ignores the
    // environment reaches the network directly. Counting the proxy in the gate
    // makes that skip unreachable rather than something to refuse afterward.
    #[test]
    fn a_proxied_policy_is_owed_the_firewall_whatever_mode_it_names() {
        let mut policy = policy_requiring_no_firewall();
        policy.network_enforcement_mode = NetworkEnforcementMode::Capabilities;
        policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("10.0.0.5".to_string(), 3128)),
            builtin_test_server: false,
        };

        assert!(
            requires_firewall(&policy),
            "a proxied policy must never reach the firewall skip, whatever enforcement \
             mode it names or defaults to"
        );
    }

    // `builtin_test_server` enables the proxy without an address, and it takes
    // the same injection path, so the gate cannot key on the address alone.
    #[test]
    fn the_builtin_test_server_proxy_is_owed_the_firewall_too() {
        let mut policy = policy_requiring_no_firewall();
        policy.network_enforcement_mode = NetworkEnforcementMode::Capabilities;
        policy.network_proxy = ProxyConfig {
            address: None,
            builtin_test_server: true,
        };

        assert!(
            requires_firewall(&policy),
            "an address-free proxy is still a proxy and must not be silently unenforced"
        );
    }

    // The gate stays narrow: a policy that restricts nothing and names no proxy
    // has no rules to install, so skipping it is correct rather than dangerous.
    #[test]
    fn a_proxy_free_permissive_policy_still_skips_cleanly() {
        let policy = policy_requiring_no_firewall();
        let mut manager = NetworkIptablesManager::new("no-proxy-skip");
        let mut logger = Logger::new(Mode::Buffer);

        assert_eq!(
            manager.apply_firewall_rules(&policy, &mut logger),
            Ok(true),
            "a policy with nothing to enforce must stay a successful no-op"
        );
    }

    /// A policy whose only distinguishing feature is its enforcement mode.
    /// Restrictive by default: the policy names a network section and leaves
    /// `default_network_policy` at `Block`, which is what makes the firewall
    /// owed and runs the apply path.
    fn policy_with_enforcement_mode(
        network_enforcement_mode: NetworkEnforcementMode,
    ) -> ContainerPolicy {
        ContainerPolicy {
            network_specified: true,
            network_enforcement_mode,
            ..Default::default()
        }
    }

    /// A policy that names a network section and restricts nothing in it. The
    /// gate skips two shapes -- this one, and a config carrying no network
    /// section at all -- and keeping `network_specified` set here holds this
    /// fixture on the first.
    fn policy_requiring_no_firewall() -> ContainerPolicy {
        ContainerPolicy {
            network_specified: true,
            default_network_policy: NetworkPolicy::Allow,
            ..Default::default()
        }
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
    #[test]
    fn an_ownership_record_naming_only_a_return_rule_is_not_treated_as_empty() {
        // is_empty gates the whole teardown. A return rule missing from it
        // would leave an ACCEPT in FORWARD naming a veth the kernel is free to
        // reassign, so a later container would inherit it.
        for created in [
            CreatedResources {
                v4: FamilyResources {
                    return_rule: true,
                    ..Default::default()
                },
                ..Default::default()
            },
            CreatedResources {
                v6: FamilyResources {
                    return_rule: true,
                    ..Default::default()
                },
                ..Default::default()
            },
            CreatedResources {
                v4: FamilyResources {
                    physdev_return: true,
                    ..Default::default()
                },
                ..Default::default()
            },
            CreatedResources {
                v6: FamilyResources {
                    physdev_return: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        ] {
            assert!(
                !created.is_empty(),
                "{created:?} names an installed rule and must not be treated as empty"
            );
        }
    }

    #[test]
    fn an_apply_installs_a_return_path_rule_in_both_directions_of_the_bridge() {
        // Without these, a reply to an allowed destination matches neither
        // ingress hook and falls through to the host's FORWARD policy; under
        // Docker's DROP default the allowed destination is unreachable.
        let fake = test_firewall::install();
        let mut manager = NetworkIptablesManager::new("return-install");
        manager.set_veth_interface("mxcv-ret");
        let policy = policy_with_enforcement_mode(NetworkEnforcementMode::Firewall);
        let mut logger = Logger::new(Mode::Buffer);

        manager
            .apply_firewall_rules(&policy, &mut logger)
            .expect("the apply must succeed against the fake");

        // Pinned to the binary on purpose: the builders are family-agnostic, so
        // an IPv4 rule and an IPv6 rule differ only by which tool issued them.
        // An assertion that ignored the binary would be satisfied by whichever
        // family still worked, and would pass with the other one deleted.
        let issued = fake.issued();
        for tool in ["iptables", "ip6tables"] {
            for (form, expected) in [
                (
                    "interface",
                    NetworkIptablesManager::build_forward_return_iface_rule_args("-I", "mxcv-ret"),
                ),
                (
                    "physdev",
                    NetworkIptablesManager::build_forward_return_physdev_rule_args(
                        "-I", "mxcv-ret",
                    ),
                ),
            ] {
                assert!(
                    issued
                        .iter()
                        .any(|cmd| cmd[0] == tool && cmd[1..] == expected[..]),
                    "the apply must install the {form} return rule via {tool}; issued: {issued:?}"
                );
            }
        }
    }

    #[test]
    fn a_teardown_removes_every_return_rule_the_apply_installed() {
        // iptables deletes by full specification, so a return rule the teardown
        // does not name outlives the container in the host's FORWARD chain.
        let fake = test_firewall::install();
        let mut manager = NetworkIptablesManager::new("return-teardown");
        manager.set_veth_interface("mxcv-down");
        let policy = policy_with_enforcement_mode(NetworkEnforcementMode::Firewall);
        let mut apply_logger = Logger::new(Mode::Buffer);
        manager
            .apply_firewall_rules(&policy, &mut apply_logger)
            .expect("the apply must succeed against the fake");

        fake.forget_issued();
        let mut remove_logger = Logger::new(Mode::Buffer);
        let _ = manager.remove_firewall_rules(&mut remove_logger);

        // Pinned to the binary for the same reason the install test is: a
        // family-blind assertion would let one family's delete stand in for the
        // other's, and the missed rule would outlive the container.
        let issued = fake.issued();
        for tool in ["iptables", "ip6tables"] {
            for (form, expected) in [
                (
                    "interface",
                    NetworkIptablesManager::build_forward_return_iface_rule_args("-D", "mxcv-down"),
                ),
                (
                    "physdev",
                    NetworkIptablesManager::build_forward_return_physdev_rule_args(
                        "-D",
                        "mxcv-down",
                    ),
                ),
            ] {
                assert!(
                    issued
                        .iter()
                        .any(|cmd| cmd[0] == tool && cmd[1..] == expected[..]),
                    "the teardown must remove the {form} return rule via {tool}; issued: {issued:?}"
                );
            }
        }
    }

    #[test]
    fn a_return_rule_that_could_not_be_installed_warns_instead_of_failing_the_apply() {
        // The asymmetry that justifies this: the ingress hook is what confines
        // traffic to the chain, so losing it fails open and must be fatal. A
        // return rule only ever ACCEPTs, so losing it can only leave the
        // container less connected -- never less enforced. Failing the apply
        // there would refuse to start a container whose policy is fully
        // installed.
        let fake = test_firewall::install();
        fake.fail_commands_matching("--physdev-out", "simulated missing physdev module");

        let mut manager = NetworkIptablesManager::new("return-warn");
        manager.set_veth_interface("mxcv-warn");
        let policy = policy_with_enforcement_mode(NetworkEnforcementMode::Firewall);
        let mut logger = Logger::new(Mode::Buffer);

        let result = manager.apply_firewall_rules(&policy, &mut logger);

        assert!(
            result.is_ok(),
            "a failed return rule must not fail the apply, got {result:?}"
        );
        assert!(
            logger.get_buffer().contains("return-path rule"),
            "the failure must be reported, not swallowed; log: {}",
            logger.get_buffer()
        );
    }

    #[test]
    fn a_return_rule_whose_install_failed_is_deleted_before_its_claim_is_released() {
        // `-I` reporting failure is only nearly conclusive: a command killed
        // after the kernel accepted its rule reports failure too. Releasing the
        // claim without attempting the removal strands an ESTABLISHED,RELATED
        // ACCEPT on a veth name the host can hand to a different container
        // later. The hooks already close this window through
        // `install_claimed_hook`; the return rules did not.
        let fake = test_firewall::install();
        fake.fail_commands_matching("--physdev-out", "simulated missing physdev module");

        let mut manager = NetworkIptablesManager::new("return-undo");
        manager.set_veth_interface("mxcv-undo");
        let policy = policy_with_enforcement_mode(NetworkEnforcementMode::Firewall);
        let mut logger = Logger::new(Mode::Buffer);

        manager
            .apply_firewall_rules(&policy, &mut logger)
            .expect("a failed return rule must not fail the apply");

        let issued = fake.issued();
        let undo =
            NetworkIptablesManager::build_forward_return_physdev_rule_args("-D", "mxcv-undo");
        for tool in ["iptables", "ip6tables"] {
            assert!(
                issued
                    .iter()
                    .any(|cmd| cmd[0] == tool && cmd[1..] == undo[..]),
                "{tool} must try to remove the return rule whose insert failed; issued: {issued:?}"
            );
        }
    }

    #[test]
    fn a_caller_with_no_veth_installs_no_return_path_rule() {
        // The return rules are only safe because they name one container's
        // port. A caller that declared it has no veth -- Bubblewrap -- has no
        // port to name, and a rule installed without one would accept
        // established traffic for every container on the host.
        let fake = test_firewall::install();
        let mut manager = NetworkIptablesManager::new("noveth-return");
        manager.allow_missing_veth_interface();
        let policy = policy_with_enforcement_mode(NetworkEnforcementMode::Firewall);
        let mut logger = Logger::new(Mode::Buffer);

        manager
            .apply_firewall_rules(&policy, &mut logger)
            .expect("a caller with no veth must not be refused");

        let issued = fake.issued();
        assert!(
            !issued
                .iter()
                .any(|cmd| cmd.iter().any(|arg| arg == "ESTABLISHED,RELATED")
                    && cmd.iter().any(|arg| arg == "FORWARD")),
            "no return rule may be installed without a veth to scope it to; issued: {issued:?}"
        );
    }

    #[test]
    fn a_return_rule_whose_install_failed_is_not_deleted_on_teardown() {
        // The teardown deletes by full specification and a delete that matches
        // nothing is reported as a failure, which would keep residual ownership
        // for a rule that never existed and make Drop retry it forever.
        let fake = test_firewall::install();
        fake.fail_commands_matching("--physdev-out", "simulated missing physdev module");

        let mut manager = NetworkIptablesManager::new("return-nodelete");
        manager.set_veth_interface("mxcv-nodel");
        let policy = policy_with_enforcement_mode(NetworkEnforcementMode::Firewall);
        let mut apply_logger = Logger::new(Mode::Buffer);
        manager
            .apply_firewall_rules(&policy, &mut apply_logger)
            .expect("the apply must succeed against the fake");

        fake.forget_issued();
        let mut remove_logger = Logger::new(Mode::Buffer);
        let _ = manager.remove_firewall_rules(&mut remove_logger);

        let issued = fake.issued();
        let deleted =
            NetworkIptablesManager::build_forward_return_physdev_rule_args("-D", "mxcv-nodel");
        for tool in ["iptables", "ip6tables"] {
            assert!(
                !issued
                    .iter()
                    .any(|cmd| cmd[0] == tool && cmd[1..] == deleted[..]),
                "a rule whose install failed must not be deleted by {tool}; issued: {issued:?}"
            );
        }
    }

    #[test]
    fn a_chain_is_still_deleted_when_its_forward_hook_never_installed() {
        // The hook is claimed before its `-I` runs, so a signal landing between
        // the command returning and the record being written still finds it.
        // Keeping that claim after a *failed* insert is what used to strand the
        // chain: rollback deletes by full specification, iptables reports a
        // specification matching nothing as an error, and a hook still on the
        // books is read as a live reference to the chain -- so the chain was
        // neither flushed nor deleted. It outlived the apply that failed, and
        // the next run for the same container died at `-N` with the name
        // already taken, which meant one failed setup retired that container
        // name until a human cleared it by hand.
        //
        // The observable here is the chain delete rather than the ownership
        // flag, because the flag is only the mechanism -- a chain nobody can
        // remove is the harm.
        let fake = test_firewall::install();
        fake.fail_commands_matching(
            "mxcv-strand",
            "iptables: No chain/target/match by that name",
        );

        let mut manager = NetworkIptablesManager::new("stranded");
        manager.set_veth_interface("mxcv-strand");
        let policy = policy_with_enforcement_mode(NetworkEnforcementMode::Firewall);
        let mut logger = Logger::new(Mode::Buffer);

        let outcome = manager.apply_firewall_rules(&policy, &mut logger);
        assert!(
            outcome.is_err(),
            "an apply whose FORWARD hook could not be installed must fail"
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
    fn a_chain_whose_hook_did_install_is_not_deleted_while_the_hook_survives() {
        // The negative control for the test above. Releasing the claim on a
        // failed insert must not decay into releasing it whenever removal is
        // hard: a hook that really is in FORWARD still points at this chain,
        // and flushing a chain that is still hooked drops it back into FORWARD
        // with nothing to stop the packet -- the fail-open outcome this module
        // exists to prevent. Here every install succeeds and only the deletes
        // fail, which is the shape of a busy or half-broken host.
        let fake = test_firewall::install();

        let mut manager = NetworkIptablesManager::new("still-hooked");
        manager.set_veth_interface("mxcv-hooked");
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

        // The claim must also survive the install that succeeded, or the
        // teardown would have nothing recorded to remove and would walk past
        // the hook it put in FORWARD. Asserting the attempt rather than the
        // result is the point: these deletes are the ones being failed, and a
        // release on success shows up as the command never being issued.
        let removal =
            NetworkIptablesManager::build_forward_hook_iface_rule_args("-D", "mxcv-hooked", &chain);
        assert!(
            issued
                .iter()
                .any(|cmd| cmd[0] == "iptables" && cmd[1..] == removal[..]),
            "a hook that installed must still be owned, and so still be removed; \
             issued: {issued:?}"
        );
    }
}
