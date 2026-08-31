// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Egress rule model for the sandbox's private network namespace.
//!
//! Rules are programmed inside the sandbox's own network namespace by the
//! supervisor (see [`crate::proxy_network`]), so this module only has to decide
//! *what* to install. It covers both callers:
//!
//! - proxy-only egress, whose plan is a single accepted endpoint, and
//! - `enforcementMode: "firewall"`, whose plan comes from the policy's host
//!   lists.
//!
//! # Addresses are IP literals and CIDRs, never names
//!
//! The 0.8 networking contract (`docs/sandbox-policy/0.8.0/networking`, D3)
//! makes rule addresses IPv4/IPv6 literals or CIDRs and rejects DNS names at
//! validation time: a name is bypassable and non-deterministic, since the
//! sandbox can resolve it itself and the answer varies by resolver, TTL and
//! cache. Domain-level control is the proxy's job — it inspects the CONNECT
//! host — not the packet filter's.
//!
//! # The rules file never contains caller text
//!
//! Every address is re-rendered from its parsed form, so what reaches the
//! supervisor's shell is the canonical output of Rust's IP address types plus
//! an integer prefix. A rejected string cannot reach the script, and an
//! accepted one cannot carry anything but digits, dots, colons and a slash.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use wxc_common::models::{
    ContainerPolicy, ExecutionRequest, NetworkAction, NetworkCidr, NetworkEgressPolicy,
    NetworkPeer, NetworkPolicy, NetworkPort, NetworkProtocol, NetworkRule,
};

/// Which `iptables` binary carries a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuleFamily {
    V4,
    V6,
}

/// Prefix the supervisor globs to find a family's restore payloads. The script
/// carries a copy of these, pinned by a test, because a shell glob cannot be
/// passed as an argument without losing the expansion.
pub(crate) const PAYLOAD_PREFIX_V4: &str = "rules.v4.";
pub(crate) const PAYLOAD_PREFIX_V6: &str = "rules.v6.";

impl RuleFamily {
    pub(crate) fn payload_prefix(self) -> &'static str {
        match self {
            RuleFamily::V4 => PAYLOAD_PREFIX_V4,
            RuleFamily::V6 => PAYLOAD_PREFIX_V6,
        }
    }
}

/// Minimum index width, so the common single-digit case still sorts and the
/// names stay stable for the sizes every real policy produces.
const PAYLOAD_INDEX_MIN_WIDTH: usize = 3;

/// Basename of the `index`-th of `total` restore payloads for `family`.
///
/// The supervisor applies these with a shell glob, which expands in lexical
/// order, so the index is zero-padded to keep lexical order equal to apply
/// order. Rule order *is* the policy, and the hooks ride in the final payload,
/// so a mis-sort would both reorder first-match rules and land the hooks over a
/// half-built chain -- a brief fail-open.
///
/// The width is derived from `total` rather than fixed because the host lists
/// are unbounded: any constant width is a silent correctness cliff one entry
/// past it (`rules.v4.1000` sorts before `rules.v4.101`). Deriving it means
/// lexical order equals numeric order for every count.
pub(crate) fn payload_file_name(family: RuleFamily, index: usize, total: usize) -> String {
    let width = decimal_width(total.saturating_sub(1)).max(PAYLOAD_INDEX_MIN_WIDTH);
    format!("{}{index:0width$}", family.payload_prefix())
}

/// Number of decimal digits needed to write `value`.
fn decimal_width(value: usize) -> usize {
    let mut width = 1;
    let mut remaining = value;
    while remaining >= 10 {
        remaining /= 10;
        width += 1;
    }
    width
}

/// What the packet filter does with a match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuleVerdict {
    Accept,
    Drop,
}

impl RuleVerdict {
    /// The `-j` target, which is also what the supervisor validates against.
    pub(crate) fn target(self) -> &'static str {
        match self {
            Self::Accept => "ACCEPT",
            Self::Drop => "DROP",
        }
    }
}

impl fmt::Display for RuleVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.target())
    }
}

/// A validated destination: an IP literal or a CIDR block.
///
/// Held as its canonical rendering rather than the caller's string, so the
/// supervisor never sees unvalidated input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuleAddress {
    family: RuleFamily,
    text: String,
}

impl RuleAddress {
    /// Classify one `allowedHosts`/`blockedHosts` entry.
    ///
    /// # Errors
    ///
    /// Returns the caller-facing reason when the entry is empty, malformed, or
    /// a DNS name, which D3 rejects rather than resolves.
    pub(crate) fn parse(entry: &str) -> Result<Self, String> {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            return Err("Bubblewrap: an empty network rule address is not a destination".into());
        }

        if let Some((address, prefix)) = trimmed.split_once('/') {
            return Self::parse_cidr(trimmed, address, prefix);
        }

        match trimmed.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => Ok(Self {
                family: RuleFamily::V4,
                text: ip.to_string(),
            }),
            Ok(IpAddr::V6(ip)) => match ip.to_ipv4_mapped() {
                Some(v4) => Ok(Self {
                    family: RuleFamily::V4,
                    text: v4.to_string(),
                }),
                None => Ok(Self {
                    family: RuleFamily::V6,
                    text: ip.to_string(),
                }),
            },
            Err(_) => Err(name_rejected(trimmed)),
        }
    }

    /// Validate `address/prefix`, keeping the prefix within its family's width.
    fn parse_cidr(entry: &str, address: &str, prefix: &str) -> Result<Self, String> {
        let parsed = match address.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => return Err(name_rejected(entry)),
        };

        let width = match parsed {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let bits: u8 = prefix.parse().map_err(|_| {
            format!(
                "Bubblewrap: network rule '{entry}' has a malformed CIDR prefix; expected a \
                 number between 0 and {width}."
            )
        })?;
        if bits > width {
            return Err(format!(
                "Bubblewrap: network rule '{entry}' has a CIDR prefix wider than its address \
                 family allows; expected a number between 0 and {width}."
            ));
        }

        // The prefix is validated against the family the caller wrote, so a
        // mapped block is only rewritten once its own notation checks out.
        let (family, canonical, bits) = match parsed {
            IpAddr::V4(ip) => (RuleFamily::V4, ip.to_string(), bits),
            IpAddr::V6(ip) => match mapped_v4_block(ip, bits) {
                Some((v4, v4_bits)) => (RuleFamily::V4, v4.to_string(), v4_bits),
                None if covers_ipv4_mapped_range(ip, bits) => {
                    return Err(straddles_mapped_range(entry))
                }
                None => (RuleFamily::V6, ip.to_string(), bits),
            },
        };

        Ok(Self {
            family,
            text: format!("{canonical}/{bits}"),
        })
    }

    /// The block matching every address in `family`.
    ///
    /// A directional rule with no `to` matches both families ("Omission matches
    /// both IP families"), which `iptables` expresses as the family's widest
    /// block rather than an absent `-d`.
    fn any(family: RuleFamily) -> Self {
        let text = match family {
            RuleFamily::V4 => "0.0.0.0/0",
            RuleFamily::V6 => "::/0",
        };
        Self {
            family,
            text: text.to_string(),
        }
    }

    /// Render one numeric block back to its canonical CIDR text.
    fn from_block(family: RuleFamily, address: IpAddr, prefix: u8) -> Self {
        Self {
            family,
            text: format!("{address}/{prefix}"),
        }
    }
}

/// An IPv4-mapped CIDR as its IPv4 equivalent, when it has one.
///
/// Linux puts a genuine IPv4 packet on the wire for a mapped destination, so an
/// `ip6tables` rule naming one never matches: under `defaultPolicy: allow` a
/// mapped `blockedHosts` entry would otherwise fail open. LXC normalizes
/// literals and `/96`-or-longer CIDRs the same way, so those policies mean the
/// same thing on both; it does not yet reject the straddling blocks below.
///
/// The mapped range is the last 32 bits of `::ffff:0:0/96`, so an IPv6 prefix
/// of `96 + n` is exactly an IPv4 prefix of `n`. A shorter prefix also covers
/// addresses outside that range, which do travel as IPv6, so it has no single
/// IPv4 equivalent; [`covers_ipv4_mapped_range`] decides whether such a block
/// is merely unrelated to the mapped range or straddles it.
fn mapped_v4_block(ip: Ipv6Addr, bits: u8) -> Option<(Ipv4Addr, u8)> {
    Some((ip.to_ipv4_mapped()?, bits.checked_sub(96)?))
}

/// Whether a sub-`/96` block contains the whole IPv4-mapped range.
///
/// CIDR blocks nest or are disjoint, so a block shorter than `/96` either
/// contains all of `::ffff:0:0/96` or misses it entirely — there is no partial
/// overlap to split. That is why such a block cannot be projected onto a
/// narrower IPv4 rule: its mapped half is always the entire IPv4 space.
fn covers_ipv4_mapped_range(ip: Ipv6Addr, bits: u8) -> bool {
    if bits >= 96 {
        return false;
    }
    // `u128::MAX << 128` is undefined, so the /0 case is masked explicitly.
    let mask = if bits == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(bits))
    };
    let mapped_base = u128::from(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0, 0));
    (u128::from(ip) & mask) == (mapped_base & mask)
}

/// The message for an IPv6 block that swallows the IPv4-mapped range.
///
/// Such a block cannot be honored as written. Its mapped half travels as IPv4,
/// so an `ip6tables` rule never matches it — under `defaultPolicy: allow` a
/// `blockedHosts` entry would fail open. Projecting it onto IPv4 instead would
/// silently widen the rule to all of IPv4 (the mapped half of any sub-`/96`
/// block is the whole space), turning `::/0` into "and every IPv4 address too".
/// Neither reading is safe to guess, so the caller is asked to say which they
/// meant.
fn straddles_mapped_range(entry: &str) -> String {
    format!(
        "Bubblewrap: network rule '{entry}' is an IPv6 block shorter than /96 that contains the \
         IPv4-mapped range '::ffff:0:0/96'. Addresses in that range travel as IPv4 packets, so an \
         ip6tables rule would not match them and the rule would be silently unenforced. Write the \
         IPv4 side explicitly instead: keep the IPv6 block for native IPv6 traffic and add the \
         IPv4 block you intend (for example '0.0.0.0/0' to cover all of IPv4)."
    )
}

/// The message for an address that is neither a literal nor a CIDR.
///
/// Names are called out explicitly: rejecting them is a deliberate contract
/// decision, so the error explains the alternative rather than reading as a
/// parse failure.
fn name_rejected(entry: &str) -> String {
    format!(
        "Bubblewrap: network rule '{entry}' is not an IP address or CIDR block. Host filtering \
         matches on addresses, not names: a sandbox resolves DNS itself, so a name can be mapped \
         to another address and is not enforceable. Use an IPv4/IPv6 literal or CIDR (for example \
         '203.0.113.4' or '10.0.0.0/8'), or route the traffic through network.proxy, which \
         filters on the requested host."
    )
}

/// A destination block in numeric form, so exclusions can be computed on it.
///
/// `base` is always the block's first address, so comparisons are plain integer
/// ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Block {
    base: u128,
    prefix: u8,
}

/// Ceiling on the blocks one peer may expand into.
///
/// Subtracting an exclusion splits the surrounding block once per prefix level,
/// so a `/32` removed from a `/8` is 24 blocks and a deep IPv6 exclusion is
/// bounded by 128. Several exclusions add up, and each block becomes a rule in
/// every port the rule names, so an unbounded expansion could outgrow the
/// restore transaction. Failing loudly beats installing a partial policy.
const MAX_BLOCKS_PER_PEER: usize = 256;

/// Ceiling on the rules one policy may lower into, across every entry.
///
/// [`MAX_BLOCKS_PER_PEER`] bounds a single peer, but a rule is a cross product
/// of blocks and ports and neither the peer list, the port list, nor the rule
/// lists themselves are bounded by the wire contract. Without a total, a small
/// policy expands into an arbitrarily large allocation. This is far above any
/// real policy; it exists to turn runaway amplification into a rejection.
const MAX_EGRESS_RULES: usize = 65_536;

impl Block {
    fn width(family: RuleFamily) -> u8 {
        match family {
            RuleFamily::V4 => 32,
            RuleFamily::V6 => 128,
        }
    }

    /// Mask covering the low `bits` bits, saturating at the full width.
    fn host_mask(bits: u8) -> u128 {
        if bits >= 128 {
            u128::MAX
        } else {
            (1u128 << bits) - 1
        }
    }

    /// The block's last address.
    fn last(self, width: u8) -> u128 {
        self.base | Self::host_mask(width - self.prefix)
    }

    fn contains(self, other: Self, width: u8) -> bool {
        self.base <= other.base && other.last(width) <= self.last(width)
    }

    fn intersects(self, other: Self, width: u8) -> bool {
        self.base <= other.last(width) && other.base <= self.last(width)
    }

    /// A parsed CIDR as a normalized numeric block, plus the family it belongs
    /// to after IPv4-mapped rewriting.
    ///
    /// # Errors
    ///
    /// Rejects a prefix wider than its address family, and a sub-`/96` IPv6
    /// block that swallows the IPv4-mapped range, for the reason
    /// [`straddles_mapped_range`] gives. `RuleAddress::parse` makes the same
    /// refusals on the legacy string path; both entry points into the renderer
    /// must agree, or the directional shape becomes a way to install the rule
    /// the legacy shape refuses.
    fn from_cidr(cidr: &NetworkCidr) -> Result<(RuleFamily, Self), String> {
        // Checked against the *source* family, before mapped rewriting: a
        // `::ffff:0:0/97` is out of range as v6 even though the /33 it rewrites
        // to would look in range for v4. `NetworkCidr` has public fields and
        // only its `FromStr` validates, so unchecked `width - prefix` underflows
        // on a programmatic request.
        let source_width = match cidr.address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if cidr.prefix_length > source_width {
            return Err(format!(
                "network rule address '{}/{}' has a prefix wider than its address family \
                 (max /{source_width})",
                cidr.address, cidr.prefix_length
            ));
        }

        let (family, address, prefix) = match cidr.address {
            IpAddr::V4(ip) => (RuleFamily::V4, IpAddr::V4(ip), cidr.prefix_length),
            IpAddr::V6(ip) => match mapped_v4_block(ip, cidr.prefix_length) {
                Some((v4, bits)) => (RuleFamily::V4, IpAddr::V4(v4), bits),
                None if covers_ipv4_mapped_range(ip, cidr.prefix_length) => {
                    return Err(straddles_mapped_range(&format!(
                        "{}/{}",
                        cidr.address, cidr.prefix_length
                    )))
                }
                None => (RuleFamily::V6, IpAddr::V6(ip), cidr.prefix_length),
            },
        };

        let raw = match address {
            IpAddr::V4(ip) => u32::from(ip) as u128,
            IpAddr::V6(ip) => u128::from(ip),
        };
        let width = Self::width(family);
        let base = raw & !Self::host_mask(width - prefix);
        Ok((family, Self { base, prefix }))
    }

    /// Back to an address for rendering.
    fn address(self, family: RuleFamily) -> IpAddr {
        match family {
            RuleFamily::V4 => IpAddr::V4(Ipv4Addr::from(self.base as u32)),
            RuleFamily::V6 => IpAddr::V6(Ipv6Addr::from(self.base)),
        }
    }
}

/// `block` minus `excepts`, as the smallest set of whole CIDR blocks.
///
/// `iptables` has no per-rule exclusion: a rule matches one destination block,
/// and there is no way to say "this block but not that one" in a single rule.
/// The alternative of emitting a preceding `DROP` for each exclusion would be
/// wrong in both directions -- it would leak into *later* rules, and it inverts
/// the meaning entirely for a `deny` rule, where an exclusion must *not* become
/// a drop. Subtracting the blocks instead keeps the rule's meaning local and
/// order-independent, which is what the contract describes.
///
/// # Errors
///
/// Returns a caller-facing message when the expansion exceeds
/// [`MAX_BLOCKS_PER_PEER`].
fn subtract_blocks(
    block: Block,
    excepts: &[Block],
    family: RuleFamily,
    out: &mut Vec<Block>,
    remaining: &mut usize,
) -> Result<(), String> {
    let width = Block::width(family);

    if excepts.iter().any(|e| e.contains(block, width)) {
        return Ok(());
    }

    if !excepts.iter().any(|e| e.intersects(block, width)) {
        if *remaining == 0 {
            return Err(format!(
                "Bubblewrap: a network.egress peer expands into more than {MAX_BLOCKS_PER_PEER} \
                 address blocks once its 'except' entries are removed. Narrow the peer's CIDR or \
                 use fewer exclusions."
            ));
        }
        *remaining -= 1;
        out.push(block);
        return Ok(());
    }

    // Intersecting but not contained, so part of the block survives. A single
    // address cannot reach here: it is either contained or disjoint.
    if block.prefix >= width {
        return Ok(());
    }

    let child_prefix = block.prefix + 1;
    let step = Block::host_mask(width - child_prefix) + 1;
    for base in [block.base, block.base + step] {
        subtract_blocks(
            Block {
                base,
                prefix: child_prefix,
            },
            excepts,
            family,
            out,
            remaining,
        )?;
    }
    Ok(())
}

/// Expand one directional rule into the `iptables` rules it becomes.
///
/// A rule is a cross product: every destination block it resolves to, in every
/// protocol/port selector it names. Both halves mean "everything" when omitted,
/// which the wire contract states for `to` ("Omission matches both IP
/// families") and `ports` ("Omission matches all").
fn lower_rule(
    rule: &NetworkRule,
    verdict: RuleVerdict,
    out: &mut Vec<EgressRule>,
) -> Result<(), String> {
    // `out` carries the running total, so each rule is lowered against what
    // the budget has left rather than against the ceiling.
    let remaining = MAX_EGRESS_RULES.saturating_sub(out.len());
    let addresses = lower_peers(&rule.to, remaining)?;
    let ports = lower_ports(&rule.ports)?;

    // Counted before the product is built, so an over-budget policy is
    // rejected rather than materialized.
    let emitted = addresses.len().checked_mul(ports.len());
    if emitted.is_none_or(|count| count > remaining) {
        return Err(egress_budget_error());
    }

    for address in &addresses {
        for port in &ports {
            out.push(EgressRule {
                verdict,
                address: address.clone(),
                port: *port,
            });
        }
    }
    Ok(())
}

/// The refusal shared by both places the rule budget is enforced.
fn egress_budget_error() -> String {
    format!(
        "Bubblewrap: network.egress expands into more than {MAX_EGRESS_RULES} firewall \
         rules. A rule becomes every destination block it resolves to in every port it \
         names, so narrow the peers, the exclusions, or the ports."
    )
}

/// The destination blocks a rule's peers resolve to, exclusions removed.
///
/// `budget` is what the rule ceiling has left. A rule emits at least one entry
/// per address, so an address vector already past the budget can never fit;
/// stopping there bounds the intermediate rather than letting an unbounded
/// peer count materialize first and be rejected afterwards.
///
/// # Errors
///
/// Propagates an `except` expansion that exceeds the per-peer ceiling, and
/// refuses a peer list whose blocks alone exceed `budget`.
fn lower_peers(peers: &[NetworkPeer], budget: usize) -> Result<Vec<RuleAddress>, String> {
    if peers.is_empty() {
        return Ok(vec![
            RuleAddress::any(RuleFamily::V4),
            RuleAddress::any(RuleFamily::V6),
        ]);
    }

    let mut addresses = Vec::new();
    for peer in peers {
        let (family, block) = Block::from_cidr(&peer.cidr)?;

        // An exclusion in the other family cannot overlap this peer, so it is
        // discarded rather than being compared across families, where the
        // numeric ordering would be meaningless.
        let mut excepts = Vec::new();
        for except in &peer.except {
            let (except_family, block) = Block::from_cidr(except)?;
            if except_family == family {
                excepts.push(block);
            }
        }

        let mut blocks = Vec::new();
        let mut remaining = MAX_BLOCKS_PER_PEER;
        subtract_blocks(block, &excepts, family, &mut blocks, &mut remaining)?;
        addresses.extend(
            blocks
                .into_iter()
                .map(|block| RuleAddress::from_block(family, block.address(family), block.prefix)),
        );
        if addresses.len() > budget {
            return Err(egress_budget_error());
        }
    }
    Ok(addresses)
}

/// The protocol/port selectors a rule names.
///
/// # Errors
///
/// Rejects an inverted range, an end without a start, and a port on ICMP --
/// each of which describes traffic no `iptables` rule can match, so silently
/// dropping the qualifier would install a broader rule than asked for.
fn lower_ports(ports: &[NetworkPort]) -> Result<Vec<PortSpec>, String> {
    if ports.is_empty() {
        return Ok(vec![PortSpec::ALL]);
    }

    let mut specs = Vec::new();
    for port in ports {
        // `NetworkPort` has public fields, so a programmatic caller can hand us
        // a zero the JSON parser would have refused.
        if port.port == Some(0) || port.end_port == Some(0) {
            return Err(
                "Bubblewrap: network.egress port values must be between 1 and 65535.".to_string(),
            );
        }
        let range = match (port.port, port.end_port) {
            (Some(start), Some(end)) if end < start => {
                return Err(format!(
                    "Bubblewrap: network.egress port range {start}-{end} ends before it starts."
                ));
            }
            (Some(start), Some(end)) => Some((start, end)),
            (Some(start), None) => Some((start, start)),
            (None, Some(end)) => {
                return Err(format!(
                    "Bubblewrap: network.egress endPort {end} needs a matching port."
                ));
            }
            (None, None) => None,
        };

        match port.protocol {
            NetworkProtocol::Tcp => specs.push(PortSpec {
                protocol: Some("tcp"),
                range,
            }),
            NetworkProtocol::Udp => specs.push(PortSpec {
                protocol: Some("udp"),
                range,
            }),
            NetworkProtocol::Icmp => {
                if range.is_some() {
                    return Err(
                        "Bubblewrap: network.egress protocol 'icmp' carries no ports, so a port \
                         selector cannot be honored. Drop the port, or name 'tcp'/'udp'."
                            .to_string(),
                    );
                }
                specs.push(PortSpec {
                    protocol: Some("icmp"),
                    range: None,
                });
            }
            // `--dport` comes from a protocol match extension, so iptables
            // cannot express a port without naming a protocol; `any` therefore
            // narrows to TCP and UDP. Safe only because every mode installing
            // these rules runs behind slirp4netns, which carries nothing else
            // (#980).
            NetworkProtocol::Any => match range {
                None => specs.push(PortSpec::ALL),
                Some(range) => {
                    specs.push(PortSpec {
                        protocol: Some("tcp"),
                        range: Some(range),
                    });
                    specs.push(PortSpec {
                        protocol: Some("udp"),
                        range: Some(range),
                    });
                }
            },
        }
    }
    Ok(specs)
}

/// Which traffic a rule narrows to, beyond its destination address.
///
/// Both halves are optional because the 0.8 contract makes them optional:
/// `ports` omitted "matches all", and `protocol` defaults to `any`. Absent
/// means the match expression is left off entirely rather than guessed, so a
/// rule that names no protocol filters none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct PortSpec {
    /// `-p` value, or `None` to match every protocol.
    protocol: Option<&'static str>,
    /// Inclusive `--dport` range, or `None` to match every port.
    ///
    /// A single port is held as `(n, n)` so rendering has one path.
    range: Option<(u16, u16)>,
}

impl PortSpec {
    /// Match everything: no `-p`, no `--dport`.
    const ALL: Self = Self {
        protocol: None,
        range: None,
    };

    /// One TCP port, as the proxy endpoint needs.
    fn tcp_port(port: u16) -> Self {
        Self {
            protocol: Some("tcp"),
            range: Some((port, port)),
        }
    }
}

/// One installed rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EgressRule {
    verdict: RuleVerdict,
    address: RuleAddress,
    /// Protocol and destination port, when the rule narrows to one service.
    port: PortSpec,
}

impl EgressRule {
    /// The rule's `iptables-restore` line, without the leading `-A <chain>`.
    ///
    /// The destination is always written, using the family's "any address"
    /// block when the rule names no peer, so the line shape stays uniform.
    fn render(&self) -> String {
        let protocol = match self.port.protocol {
            // ICMP is a different protocol number and a different iptables
            // match on each family: `ip6tables` rejects `-p icmp` outright, so
            // carrying the V4 token into the V6 table fails the whole restore
            // and installs nothing. The 0.8 contract's `icmp` selector means
            // "ICMP for this destination's family", which is what this renders.
            Some("icmp") if self.address.family == RuleFamily::V6 => "-p icmpv6 ".to_string(),
            Some(protocol) => format!("-p {protocol} "),
            None => String::new(),
        };
        let dport = match self.port.range {
            Some((start, end)) if start == end => format!(" --dport {start}"),
            Some((start, end)) => format!(" --dport {start}:{end}"),
            None => String::new(),
        };
        format!(
            "{protocol}-d {}{dport} -j {}",
            self.address.text,
            self.verdict.target()
        )
    }
}

/// The complete filtering posture for one sandbox.
///
/// Ordering is the contract: rules are appended to the chain in the order held
/// here, and the terminal verdict closes each family. Denies precede allows so
/// an explicit deny overrides a broader allow, per the 0.8 contract's D4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EgressPlan {
    rules: Vec<EgressRule>,
    v4_terminal: RuleVerdict,
    v6_terminal: RuleVerdict,
}

/// Byte budget for one `iptables-restore` transaction.
///
/// `nf_tables` applies a restore as a single netlink transaction with a bounded
/// message size. Exceeding it fails the *whole* table with `sendmsg() failed:
/// Message too long` and installs nothing, so an unbounded transaction would
/// turn a large host list into a sandbox that cannot launch. Measured on
/// `iptables v1.8.10` the ceiling sits near 20 KiB of payload text, and lower
/// per rule for rules carrying more match expressions -- each expression costs
/// more on the kernel side than in text, so the limit is a byte ceiling rather
/// than a rule count. This budget stays well under the smallest observed
/// failure so it holds whatever shape the caller's rules take.
const RESTORE_PAYLOAD_BUDGET: usize = 8 * 1024;

/// Terminator every `iptables-restore` transaction ends with.
const COMMIT: &str = "COMMIT\n";

impl EgressPlan {
    /// The proxy-only posture: one endpoint reachable, everything else dropped.
    ///
    /// IPv6 carries no rule and closes on `DROP`: the endpoint is IPv4, so v6
    /// egress fails closed rather than being left open.
    pub(crate) fn for_proxy(ip: Ipv4Addr, port: u16) -> Self {
        Self {
            rules: vec![EgressRule {
                verdict: RuleVerdict::Accept,
                address: RuleAddress {
                    family: RuleFamily::V4,
                    text: ip.to_string(),
                },
                port: PortSpec::tcp_port(port),
            }],
            v4_terminal: RuleVerdict::Drop,
            v6_terminal: RuleVerdict::Drop,
        }
    }

    /// The outbound posture for one request, from whichever schema shape it used.
    ///
    /// Schema 0.8 carries the outbound posture in either the legacy host lists
    /// or the directional `network.egress` section, never both, so this selects
    /// the authoritative one instead of merging them. Every caller goes through
    /// here; [`Self::for_policy`] stays legacy-only so the chain consumers have
    /// today cannot drift.
    ///
    /// `network_egress` is the format discriminator because the parser fills it
    /// in only on the directional path (`network_parser::apply_directional_network`)
    /// and leaves it `None` on the legacy one. `network_mode_specified` looks like
    /// the obvious signal and is *not*: the legacy path sets it too, from
    /// `defaultPolicy`/`allowedHosts`/`blockedHosts`, so keying on it would route
    /// every legacy firewall config into the directional builder.
    ///
    /// # Errors
    ///
    /// Propagates the selected builder's rejection.
    pub(crate) fn for_request(request: &ExecutionRequest) -> Result<Self, String> {
        // Either section present means the directional shape. The parser fills
        // both in together, but losing the host-loopback drop is silent, so
        // this does not depend on that invariant.
        if !crate::bwrap_command::is_directional(&request.policy) {
            return Self::for_policy(request);
        }

        Self::for_directional_policy_with_ingress(
            &request.policy.network_egress.clone().unwrap_or_default(),
            // An absent ingress section still denies: `hostLoopback` defaults
            // to `Deny`, so omitting it is not a way to opt out.
            request
                .policy
                .network_ingress
                .as_ref()
                .map_or(NetworkAction::Deny, |ingress| ingress.host_loopback),
        )
    }

    /// The directional posture, including the inbound section's host-loopback
    /// control.
    ///
    /// `ingress.hostLoopback` governs traffic in *both* directions, so denying
    /// it has to close the container-to-host path as well -- under slirp that
    /// path is the gateway, which maps onto the host's own loopback. The drop
    /// is lowered ahead of every caller rule because the chain is first-match:
    /// behind them, any `allow` covering the gateway (a bare `0.0.0.0/0`
    /// included) would silently win.
    ///
    /// IPv4 only: slirp gives the sandbox no IPv6 route to the host. Proxy
    /// mode needs no equivalent -- `for_proxy` opens the proxy endpoint alone
    /// and closes on `DROP`.
    ///
    /// `egress.default` sets the terminal verdict for both families, and
    /// denies are lowered before allows so an explicit deny beats a broader
    /// allow, per the contract's D4.
    ///
    /// # Errors
    ///
    /// Propagates an unrenderable rule: an `except` expansion that exceeds the
    /// per-peer block ceiling, an ICMP selector carrying a port, or an inverted
    /// port range.
    fn for_directional_policy_with_ingress(
        egress: &NetworkEgressPolicy,
        host_loopback: NetworkAction,
    ) -> Result<Self, String> {
        let terminal = match egress.default {
            NetworkAction::Allow => RuleVerdict::Accept,
            NetworkAction::Deny => RuleVerdict::Drop,
        };

        let mut rules = Vec::new();
        // Ahead of the caller's rules: first-match means anything later cannot
        // reopen it.
        if host_loopback == NetworkAction::Deny {
            rules.push(EgressRule {
                verdict: RuleVerdict::Drop,
                address: RuleAddress::from_block(
                    RuleFamily::V4,
                    IpAddr::V4(crate::proxy_network::SLIRP_HOST_GATEWAY_IP),
                    32,
                ),
                port: PortSpec::ALL,
            });
        }
        for rule in &egress.deny {
            lower_rule(rule, RuleVerdict::Drop, &mut rules)?;
        }
        for rule in &egress.allow {
            lower_rule(rule, RuleVerdict::Accept, &mut rules)?;
        }

        Ok(Self {
            rules,
            v4_terminal: terminal,
            v6_terminal: terminal,
        })
    }

    /// The `enforcementMode: "firewall"` posture, from the policy's host lists.
    ///
    /// `defaultPolicy` sets the terminal verdict for both families, so a family
    /// with no rules of its own still inherits the requested posture instead of
    /// being silently open or silently closed.
    ///
    /// # Errors
    ///
    /// Returns the first address that is not a literal or CIDR.
    pub(crate) fn for_policy(request: &ExecutionRequest) -> Result<Self, String> {
        let policy = &request.policy;
        let terminal = match policy.default_network_policy {
            NetworkPolicy::Allow => RuleVerdict::Accept,
            NetworkPolicy::Block => RuleVerdict::Drop,
        };

        // Denies first: the chain is evaluated in order and the first match
        // wins, so this is what makes an explicit deny beat a broader allow.
        let mut rules = Vec::with_capacity(policy.blocked_hosts.len() + policy.allowed_hosts.len());
        for entry in &policy.blocked_hosts {
            rules.push(EgressRule {
                verdict: RuleVerdict::Drop,
                address: RuleAddress::parse(entry)?,
                port: PortSpec::ALL,
            });
        }
        for entry in &policy.allowed_hosts {
            rules.push(EgressRule {
                verdict: RuleVerdict::Accept,
                address: RuleAddress::parse(entry)?,
                port: PortSpec::ALL,
            });
        }

        Ok(Self {
            rules,
            v4_terminal: terminal,
            v6_terminal: terminal,
        })
    }

    /// The chain body for one family: the loopback exemption, the family's
    /// rules in order, and the terminal verdict that closes it.
    ///
    /// Ordering is the policy: the chain is evaluated first-match, so loopback
    /// is exempted ahead of everything because it is the sandbox's own isolated
    /// loopback, and denies precede allows so an explicit deny overrides a
    /// broader allow. A family with no rules of its own still gets its terminal
    /// verdict, so IPv6 under an IPv4-only policy fails closed rather than
    /// being left open.
    fn chain_lines(&self, family: RuleFamily) -> Vec<String> {
        let terminal = match family {
            RuleFamily::V4 => self.v4_terminal,
            RuleFamily::V6 => self.v6_terminal,
        };

        let mut lines = vec!["-o lo -j ACCEPT".to_string()];
        lines.extend(
            self.rules
                .iter()
                .filter(|rule| rule.address.family == family)
                .map(EgressRule::render),
        );
        lines.push(format!("-j {terminal}"));
        lines
    }
}

/// The inbound posture for one sandbox.
///
/// Bubblewrap's sandbox already has no inbound path -- it runs in a private
/// network namespace and slirp is launched without port forwarding -- so this
/// chain is defense in depth plus the shape the 0.8 contract's D6 specifies,
/// rather than new protection. It becomes load-bearing the moment any inbound
/// path is configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IngressPlan {
    /// Verdict for a connection the sandbox did not initiate.
    new_inbound: RuleVerdict,
}

impl IngressPlan {
    /// The posture the policy asks for.
    ///
    /// Schema 0.8 carries the inbound posture in either the legacy
    /// `allowLocalNetwork` field or the directional `network.ingress` section,
    /// never both, so the format selects which one is authoritative rather than
    /// the two being merged. The legacy arm is left exactly as it was:
    /// consumers still on the legacy shape must keep the chain they have.
    ///
    /// `network_ingress` is the format discriminator because the parser fills it
    /// in only on the directional path and leaves it `None` on the legacy one.
    /// `network_mode_specified` is *not* usable here: the legacy path sets it
    /// too, from `defaultPolicy`/`allowLocalNetwork`/host lists.
    ///
    /// Only the deny posture is reachable on the private-namespace path today.
    /// `allowLocalNetwork: true` is refused before this point at schema 0.8+
    /// (see `bwrap_command::local_network_diagnostic_for_mode`) and its
    /// directional twins `ingress.default: allow` and `ingress.hostLoopback:
    /// allow` are refused alongside it, because honoring either needs slirp port
    /// forwarding and a port contract neither schema expresses. The mapping is
    /// written out in full anyway so the policy lives in one readable place and
    /// lifting a rejection is a change at the rejection, not here.
    pub(crate) fn for_policy(policy: &ContainerPolicy) -> Self {
        let accepts_new_inbound = match policy.network_ingress.as_ref() {
            Some(ingress) => ingress.default == NetworkAction::Allow,
            None => policy.allow_local_network,
        };

        Self {
            new_inbound: if accepts_new_inbound {
                RuleVerdict::Accept
            } else {
                RuleVerdict::Drop
            },
        }
    }

    /// The chain body for one family.
    ///
    /// The `ESTABLISHED,RELATED` accept is not optional: the terminal `DROP`
    /// applies to *every* inbound packet, and a reply to sandbox-initiated
    /// egress arrives inbound. Without it this chain would break all
    /// networking rather than restrict it.
    ///
    /// `RELATED` is broader than it needs to be, and is safe only because
    /// nothing forwards traffic into the sandbox today: a loaded connection
    /// tracking ALG helper can mark an unsolicited inbound flow `RELATED` and
    /// so bypass the `NEW` verdict. Narrow this to `ESTABLISHED` when host port
    /// forwarding lands and there is an inbound path for that to matter on.
    ///
    /// The terminal verdict is `DROP` regardless of `defaultPolicy`, which
    /// governs egress only -- an open outbound posture must not open inbound.
    ///
    /// Both families get the same body. IPv6 needs an RFC 4890 ICMPv6 carve-out
    /// (NDP and MLD, which a terminal `DROP` would otherwise break) before it
    /// can carry traffic, as `lxc_common::network_ingress` has; it is omitted
    /// here because slirp is launched without `--enable-ipv6`, so the sandbox
    /// namespace has no IPv6 connectivity for those rules to protect. Enabling
    /// IPv6 means adding them in the same change.
    fn chain_lines(&self, _family: RuleFamily) -> Vec<String> {
        vec![
            // The sandbox's own loopback, which never leaves the sandbox.
            "-i lo -j ACCEPT".to_string(),
            "-m state --state ESTABLISHED,RELATED -j ACCEPT".to_string(),
            format!("-m state --state NEW -j {}", self.new_inbound.target()),
            "-j DROP".to_string(),
        ]
    }
}

/// One chain in a rendered table: its name, the built-in hook that jumps to it,
/// and its body.
struct ChainSection {
    chain: &'static str,
    hook: &'static str,
    lines: Vec<String>,
}

/// The `iptables-restore` payloads installing both directions for one family,
/// in the order they must be applied.
///
/// A policy is split across as many transactions as its size requires, because
/// a single restore is one bounded netlink transaction (see
/// [`RESTORE_PAYLOAD_BUDGET`]). Splitting is what keeps a large host list from
/// failing the whole table, and it preserves the two properties that matter:
///
/// * **A hook is never live over a partially built chain.** Both `-A OUTPUT` /
///   `-A INPUT` hooks travel in the *final* transaction, so the built-in chains
///   are redirected only once every rule is already installed. Until then the
///   custom chains exist but nothing jumps to them.
/// * **An unsupported rule still fails closed.** A line the host kernel cannot
///   apply -- the `state` match without `nf_conntrack`, say -- rejects its whole
///   transaction, the supervisor aborts, and the workload is never released.
///
/// Later transactions rely on `iptables-restore -n`, which appends rather than
/// flushing, so only the first declares the chains.
pub(crate) fn render_filter_payloads(
    egress: &EgressPlan,
    ingress: &IngressPlan,
    family: RuleFamily,
    egress_chain: &'static str,
    ingress_chain: &'static str,
) -> Vec<String> {
    let sections = [
        ChainSection {
            chain: egress_chain,
            hook: "OUTPUT",
            lines: egress.chain_lines(family),
        },
        ChainSection {
            chain: ingress_chain,
            hook: "INPUT",
            lines: ingress.chain_lines(family),
        },
    ];

    let declarations: String = sections
        .iter()
        .map(|section| format!(":{} - [0:0]\n", section.chain))
        .collect();
    let hooks: String = sections
        .iter()
        .map(|section| format!("-A {} -j {}\n", section.hook, section.chain))
        .collect();
    let body: Vec<String> = sections
        .iter()
        .flat_map(|section| {
            section
                .lines
                .iter()
                .map(move |line| format!("-A {} {line}\n", section.chain))
        })
        .collect();

    // The first transaction carries the chain declarations, so it starts with
    // less room than the rest.
    let mut payloads: Vec<String> = Vec::new();
    let mut current = format!("*filter\n{declarations}");
    let mut lines_in_current = 0usize;
    for line in body {
        // A transaction always takes at least one line, so a single line larger
        // than the budget still gets applied rather than looping forever. No
        // rule this renderer emits comes close, but the invariant is what makes
        // the loop total.
        if lines_in_current > 0
            && current.len() + line.len() + COMMIT.len() > RESTORE_PAYLOAD_BUDGET
        {
            current.push_str(COMMIT);
            payloads.push(std::mem::replace(&mut current, String::from("*filter\n")));
            lines_in_current = 0;
        }
        current.push_str(&line);
        lines_in_current += 1;
    }

    // Hooks close out the last transaction, unless they would push it over
    // budget, in which case they get one of their own. Either way they are last.
    if lines_in_current > 0 && current.len() + hooks.len() + COMMIT.len() > RESTORE_PAYLOAD_BUDGET {
        current.push_str(COMMIT);
        payloads.push(std::mem::replace(&mut current, String::from("*filter\n")));
    }
    current.push_str(&hooks);
    current.push_str(COMMIT);
    payloads.push(current);

    payloads
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::logger::{Logger, Mode};
    use wxc_common::models::{
        ContainerPolicy, NetworkAction, NetworkEgressPolicy, NetworkIngressPolicy, NetworkRule,
    };
    use wxc_common::state_aware_request::MxcRequest;

    /// The supervisor applies payloads in shell-glob (lexical) order, so lexical
    /// order must equal numeric order for *every* count. A fixed 3-digit width
    /// broke this one payload past 999 -- `rules.v4.1000` sorts before
    /// `rules.v4.101` -- which would reorder first-match rules and apply the
    /// hook-bearing final payload over a half-built chain.
    #[test]
    fn payload_names_sort_in_apply_order_past_a_digit_boundary() {
        for total in [1, 2, 10, 999, 1000, 1001, 10_000] {
            let names: Vec<String> = (0..total)
                .map(|index| payload_file_name(RuleFamily::V4, index, total))
                .collect();
            let mut sorted = names.clone();
            sorted.sort();
            assert_eq!(
                names, sorted,
                "payload names for total={total} do not sort into apply order"
            );
        }
    }

    /// The common case keeps the names it has always had, so the doc and the
    /// script's glob stay accurate.
    #[test]
    fn small_payload_counts_keep_three_digit_names() {
        assert_eq!(payload_file_name(RuleFamily::V4, 0, 1), "rules.v4.000");
        assert_eq!(payload_file_name(RuleFamily::V6, 7, 12), "rules.v6.007");
    }

    fn request(default: NetworkPolicy, allowed: &[&str], blocked: &[&str]) -> ExecutionRequest {
        ExecutionRequest {
            script_code: "echo hello".into(),
            policy: ContainerPolicy {
                default_network_policy: default,
                allowed_hosts: allowed.iter().map(|host| host.to_string()).collect(),
                blocked_hosts: blocked.iter().map(|host| host.to_string()).collect(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn an_ipv4_literal_is_accepted_as_a_host_rule() {
        let address = RuleAddress::parse("203.0.113.4").expect("a literal is a valid rule address");
        assert_eq!(address.family, RuleFamily::V4);
        assert_eq!(address.text, "203.0.113.4");
    }

    #[test]
    fn an_ipv6_literal_is_accepted_and_canonicalized() {
        let address = RuleAddress::parse("2001:DB8:0:0:0:0:0:1").expect("a v6 literal is valid");
        assert_eq!(address.family, RuleFamily::V6);
        // Rendered from the parsed value, so the file never carries the
        // caller's spelling.
        assert_eq!(address.text, "2001:db8::1");
    }

    #[test]
    fn an_ipv4_mapped_literal_is_programmed_as_ipv4() {
        // Linux emits a genuine IPv4 packet for a mapped destination, so an
        // ip6tables rule naming one never matches: under defaultPolicy 'allow'
        // a mapped blockedHosts entry would fail open.
        let address = RuleAddress::parse("::ffff:203.0.113.5").expect("a mapped literal is valid");
        assert_eq!(address.family, RuleFamily::V4);
        assert_eq!(address.text, "203.0.113.5");
    }

    #[test]
    fn an_ipv4_mapped_cidr_is_translated_to_its_ipv4_prefix() {
        // The mapped range is the last 32 bits of ::ffff:0:0/96, so a v6
        // prefix of 96 + n is exactly a v4 prefix of n.
        let address = RuleAddress::parse("::ffff:192.0.2.0/120").expect("a mapped CIDR is valid");
        assert_eq!(address.family, RuleFamily::V4);
        assert_eq!(address.text, "192.0.2.0/24");

        let host = RuleAddress::parse("::ffff:198.51.100.42/128").expect("a mapped /128 is valid");
        assert_eq!(host.family, RuleFamily::V4);
        assert_eq!(host.text, "198.51.100.42/32");
    }

    #[test]
    fn a_prefix_shorter_than_the_mapped_range_is_rejected() {
        // A /95 covers all of ::ffff:0:0/96, whose members travel as IPv4
        // packets an ip6tables rule never sees. Keeping it on ip6tables would
        // silently unenforce the mapped half (a fail-open for a deny rule under
        // defaultPolicy 'allow'), and projecting it onto IPv4 would widen it to
        // every IPv4 address. Neither is safe to guess, so it is refused.
        let error = RuleAddress::parse("::ffff:0:0/95").expect_err("a straddling block is refused");
        assert!(
            error.contains("shorter than /96") && error.contains("::ffff:0:0/96"),
            "the message should name the mapped range and the boundary: {error}"
        );
    }

    #[test]
    fn the_whole_ipv6_space_is_rejected_for_the_same_reason() {
        // ::/0 is the case most likely to be written by hand, and the one where
        // silently projecting onto IPv4 would be most surprising: "block all
        // IPv6" would become "and all IPv4 too".
        let error = RuleAddress::parse("::/0").expect_err("::/0 contains the mapped range");
        assert!(
            error.contains("shorter than /96"),
            "unexpected message: {error}"
        );
    }

    #[test]
    fn a_sub_96_block_clear_of_the_mapped_range_stays_ipv6() {
        // The rejection is scoped to blocks that actually contain the mapped
        // range. Ordinary IPv6 CIDRs are unaffected, so native IPv6 filtering
        // keeps working.
        let address = RuleAddress::parse("2001:db8::/32").expect("a native v6 CIDR is valid");
        assert_eq!(address.family, RuleFamily::V6);
        assert_eq!(address.text, "2001:db8::/32");

        // Immediately below the mapped range and disjoint from it: a /95 pairs
        // ::fffc/::fffd, while the mapped range sits in the ::fffe/::ffff pair.
        let neighbour = RuleAddress::parse("::fffc:0:0/95").expect("a neighbouring block is valid");
        assert_eq!(neighbour.family, RuleFamily::V6);
    }

    #[test]
    fn the_mapped_range_itself_is_still_translated_not_rejected() {
        // Exactly /96 is the boundary: it maps to 0.0.0.0/0 with no ambiguity,
        // so it is translated rather than refused.
        let address = RuleAddress::parse("::ffff:0:0/96").expect("the mapped range is valid");
        assert_eq!(address.family, RuleFamily::V4);
        assert_eq!(address.text, "0.0.0.0/0");
    }

    #[test]
    fn a_mapped_prefix_is_validated_against_the_notation_the_caller_wrote() {
        // The caller wrote v6, so the width they are held to is 128 — the
        // rewrite happens only once their own notation checks out.
        let error = RuleAddress::parse("::ffff:192.0.2.0/129")
            .expect_err("a prefix past the v6 width is malformed");
        assert!(
            error.contains("wider than its address family allows"),
            "{error}"
        );
    }

    #[test]
    fn a_non_mapped_v6_address_is_left_on_ipv6() {
        // NAT64 traffic really is emitted as IPv6, so it belongs in ip6tables.
        let address = RuleAddress::parse("64:ff9b::/96").expect("a NAT64 block is valid");
        assert_eq!(address.family, RuleFamily::V6);
        assert_eq!(address.text, "64:ff9b::/96");
    }

    #[test]
    fn a_cidr_block_keeps_its_prefix() {
        let address = RuleAddress::parse("10.0.0.0/8").expect("a CIDR is a valid rule address");
        assert_eq!(address.family, RuleFamily::V4);
        assert_eq!(address.text, "10.0.0.0/8");
    }

    #[test]
    fn the_widest_prefix_of_each_family_is_allowed() {
        assert_eq!(
            RuleAddress::parse("192.0.2.1/32")
                .expect("a /32 is a host route")
                .text,
            "192.0.2.1/32"
        );
        assert_eq!(
            RuleAddress::parse("2001:db8::1/128")
                .expect("a /128 is a host route")
                .text,
            "2001:db8::1/128"
        );
    }

    #[test]
    fn a_prefix_wider_than_the_family_is_rejected() {
        let error = RuleAddress::parse("10.0.0.0/33").expect_err("v4 has 32 bits");
        assert!(error.contains("wider than its address family"), "{error}");

        let error = RuleAddress::parse("2001:db8::/129").expect_err("v6 has 128 bits");
        assert!(error.contains("wider than its address family"), "{error}");
    }

    #[test]
    fn a_non_numeric_prefix_is_rejected() {
        let error = RuleAddress::parse("10.0.0.0/eight").expect_err("a prefix must be a number");
        assert!(error.contains("malformed CIDR prefix"), "{error}");
    }

    #[test]
    fn a_dns_name_is_rejected_with_the_alternatives() {
        let error = RuleAddress::parse("api.github.com").expect_err("names are not enforceable");
        assert!(error.contains("not an IP address or CIDR"), "{error}");
        assert!(error.contains("network.proxy"), "{error}");
    }

    #[test]
    fn an_empty_entry_is_rejected() {
        let error = RuleAddress::parse("   ").expect_err("an empty entry names nothing");
        assert!(error.contains("empty network rule address"), "{error}");
    }

    /// The rules file is interpolated into a shell loop, so anything that could
    /// change the record's shape has to be rejected before it gets there.
    #[test]
    fn shell_and_field_metacharacters_cannot_reach_the_rules_file() {
        for hostile in [
            "10.0.0.1; rm -rf /",
            "10.0.0.1 -j ACCEPT",
            "$(id)",
            "10.0.0.1\n4 ACCEPT 0.0.0.0/0 - -",
            "`id`",
            "10.0.0.1|id",
        ] {
            let error = RuleAddress::parse(hostile)
                .expect_err("only literals and CIDRs may reach the supervisor");
            assert!(
                error.contains("not an IP address or CIDR") || error.contains("CIDR prefix"),
                "unexpected rejection for {hostile:?}: {error}"
            );
        }
    }

    const EGRESS: &str = "EG";
    const INGRESS: &str = "IN";

    /// Every transaction for one family, concatenated. Tests that care about
    /// chain contents read through this; tests that care about the split read
    /// the payload vector directly.
    fn payload(plan: &EgressPlan, family: RuleFamily) -> String {
        payloads(plan, family).concat()
    }

    fn payloads(plan: &EgressPlan, family: RuleFamily) -> Vec<String> {
        render_filter_payloads(plan, &denied_ingress(), family, EGRESS, INGRESS)
    }

    fn denied_ingress() -> IngressPlan {
        IngressPlan::for_policy(&ContainerPolicy::default())
    }

    /// The rules appended to `chain`, in order, stripped of the `-A <chain>`
    /// prefix so the assertion reads as policy rather than syntax.
    fn chain_body(payload: &str, chain: &str) -> Vec<String> {
        let prefix = format!("-A {chain} ");
        payload
            .lines()
            .filter_map(|line| line.strip_prefix(&prefix).map(str::to_owned))
            .collect()
    }

    fn v4(plan: &EgressPlan) -> Vec<String> {
        chain_body(&payload(plan, RuleFamily::V4), EGRESS)
    }

    fn v6(plan: &EgressPlan) -> Vec<String> {
        chain_body(&payload(plan, RuleFamily::V6), EGRESS)
    }

    /// The egress chain's fixed frame, with `rules` in between.
    fn egress(rules: &[&str], terminal: &str) -> Vec<String> {
        let mut expected = vec!["-o lo -j ACCEPT".to_string()];
        expected.extend(rules.iter().map(|rule| rule.to_string()));
        expected.push(format!("-j {terminal}"));
        expected
    }

    /// The V4 expectation for a *directional* plan.
    ///
    /// Every directional posture closes the container-to-host-loopback path,
    /// which under slirp is the gateway, and does so ahead of the caller's
    /// rules so nothing later can reopen it. Expressed as a helper so the
    /// ordering is asserted once rather than restated in every test.
    fn directional_egress(rules: &[&str], terminal: &str) -> Vec<String> {
        let mut all = vec![HOST_LOOPBACK_DROP];
        all.extend_from_slice(rules);
        egress(&all, terminal)
    }

    /// The rule that closes the host-loopback path.
    const HOST_LOOPBACK_DROP: &str = "-d 10.0.2.2/32 -j DROP";

    #[test]
    fn a_block_policy_closes_both_families_and_accepts_its_allowlist() {
        let plan = EgressPlan::for_policy(&request(NetworkPolicy::Block, &["10.0.0.0/8"], &[]))
            .expect("a CIDR allowlist is enforceable");

        assert_eq!(v4(&plan), egress(&["-d 10.0.0.0/8 -j ACCEPT"], "DROP"));
        assert_eq!(v6(&plan), egress(&[], "DROP"));
    }

    #[test]
    fn an_allow_policy_keeps_both_families_open_and_drops_its_denylist() {
        let plan = EgressPlan::for_policy(&request(NetworkPolicy::Allow, &[], &["192.0.2.0/24"]))
            .expect("a CIDR denylist is enforceable");

        assert_eq!(v4(&plan), egress(&["-d 192.0.2.0/24 -j DROP"], "ACCEPT"));
        assert_eq!(v6(&plan), egress(&[], "ACCEPT"));
    }

    /// A legacy config keeps the chain it has today, all the way through the
    /// real parser.
    ///
    /// Schema 0.8 accepts either the legacy network shape or the directional
    /// one, and consumers still on the legacy shape must be unaffected by the
    /// directional work. This goes through `load_mxc_request_from_json` rather
    /// than building a policy by hand because the bug it guards is in the
    /// *parser's* output: the legacy path also sets `network_mode_specified`,
    /// so a dispatcher keyed on that flag routes legacy configs into the
    /// directional builder. Only a parser-driven test sees that.
    fn plan_for_config(json: &str) -> EgressPlan {
        let mut logger = Logger::new(Mode::Buffer);
        let parsed = wxc_common::config_parser::load_mxc_request_from_json(json, &mut logger)
            .expect("the config parses");
        let MxcRequest::OneShot(request) = parsed else {
            panic!("expected a one-shot request");
        };
        EgressPlan::for_request(&request).expect("the parsed posture is enforceable")
    }

    #[test]
    fn a_legacy_config_keeps_its_chain_at_schema_0_8() {
        let plan = plan_for_config(
            r#"{
                "version": "0.8.0-alpha",
                "containment": "bubblewrap",
                "process": {"commandLine": "echo hi"},
                "network": {
                    "defaultPolicy": "allow",
                    "enforcementMode": "firewall",
                    "blockedHosts": ["192.0.2.0/24"]
                }
            }"#,
        );

        assert_eq!(v4(&plan), egress(&["-d 192.0.2.0/24 -j DROP"], "ACCEPT"));
        assert_eq!(v6(&plan), egress(&[], "ACCEPT"));
    }

    #[test]
    fn a_legacy_config_keeps_its_chain_at_schema_0_7() {
        let plan = plan_for_config(
            r#"{
                "version": "0.7.0-alpha",
                "containment": "bubblewrap",
                "process": {"commandLine": "echo hi"},
                "network": {
                    "defaultPolicy": "block",
                    "enforcementMode": "firewall",
                    "allowedHosts": ["10.0.0.0/8"]
                }
            }"#,
        );

        assert_eq!(v4(&plan), egress(&["-d 10.0.0.0/8 -j ACCEPT"], "DROP"));
        assert_eq!(v6(&plan), egress(&[], "DROP"));
    }

    /// The directional shape reaches the directional builder, again through the
    /// parser, so the two arms are proven to be selected by real configs.
    #[test]
    fn a_directional_config_closes_both_families_at_schema_0_8() {
        let plan = plan_for_config(
            r#"{
                "version": "0.8.0-alpha",
                "containment": "bubblewrap",
                "process": {"commandLine": "echo hi"},
                "network": {
                    "egress": {"default": "deny"},
                    "ingress": {"default": "deny", "hostLoopback": "deny"}
                }
            }"#,
        );

        assert_eq!(v4(&plan), directional_egress(&[], "DROP"));
        assert_eq!(v6(&plan), egress(&[], "DROP"));
    }

    /// A policy that selected the directional shape, as the parser marks it.
    fn directional_ingress_policy(
        default: NetworkAction,
        host_loopback: NetworkAction,
    ) -> ContainerPolicy {
        ContainerPolicy {
            network_ingress: Some(NetworkIngressPolicy {
                default,
                host_loopback,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn a_directional_ingress_deny_closes_the_inbound_chain() {
        assert_eq!(
            IngressPlan::for_policy(&directional_ingress_policy(
                NetworkAction::Deny,
                NetworkAction::Deny
            )),
            denied_ingress()
        );
    }

    /// The two shapes are mutually exclusive, so once the directional section is
    /// authoritative a legacy `allowLocalNetwork` left alongside it must not
    /// re-open inbound. Merging the two would fail open on exactly this input.
    #[test]
    fn a_directional_policy_ignores_the_legacy_inbound_field() {
        let mut policy = directional_ingress_policy(NetworkAction::Deny, NetworkAction::Deny);
        policy.allow_local_network = true;

        assert_eq!(IngressPlan::for_policy(&policy), denied_ingress());
    }

    /// `ingress.default: allow` is refused before it reaches the plan, but the
    /// mapping still carries it so lifting that rejection is a change at the
    /// rejection rather than a silent no-op here.
    #[test]
    fn a_directional_ingress_allow_opens_the_inbound_chain() {
        let plan = IngressPlan::for_policy(&directional_ingress_policy(
            NetworkAction::Allow,
            NetworkAction::Deny,
        ));

        assert_ne!(plan, denied_ingress());
        assert!(
            plan.chain_lines(RuleFamily::V4)
                .iter()
                .any(|line| line == "-m state --state NEW -j ACCEPT"),
            "an allow posture must reach the chain as an ACCEPT"
        );
    }

    /// A request that selected the directional shape, as the parser marks it.
    fn directional_egress_request(default: NetworkAction) -> ExecutionRequest {
        ExecutionRequest {
            script_code: "echo hello".into(),
            policy: ContainerPolicy {
                network_egress: Some(NetworkEgressPolicy {
                    default,
                    ..Default::default()
                }),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn a_directional_egress_deny_closes_both_families() {
        let plan = EgressPlan::for_request(&directional_egress_request(NetworkAction::Deny))
            .expect("a directional deny posture is enforceable");

        assert_eq!(v4(&plan), directional_egress(&[], "DROP"));
        assert_eq!(v6(&plan), egress(&[], "DROP"));
    }

    #[test]
    fn a_directional_egress_allow_opens_both_families() {
        let plan = EgressPlan::for_request(&directional_egress_request(NetworkAction::Allow))
            .expect("a directional allow posture is enforceable");

        assert_eq!(v4(&plan), directional_egress(&[], "ACCEPT"));
        assert_eq!(v6(&plan), egress(&[], "ACCEPT"));
    }

    /// The two shapes are mutually exclusive, so a legacy host list left
    /// alongside an authoritative directional section must not be programmed.
    /// Merging them would reopen exactly what the directional deny closed.
    #[test]
    fn a_directional_egress_policy_ignores_the_legacy_host_lists() {
        let mut req = directional_egress_request(NetworkAction::Deny);
        req.policy.default_network_policy = NetworkPolicy::Allow;
        req.policy.allowed_hosts = vec!["10.0.0.0/8".to_string()];

        let plan = EgressPlan::for_request(&req).expect("the directional posture is enforceable");

        assert_eq!(v4(&plan), directional_egress(&[], "DROP"));
        assert_eq!(v6(&plan), egress(&[], "DROP"));
    }

    /// The legacy request keeps reaching the legacy builder through the
    /// dispatcher, unchanged.
    #[test]
    fn a_legacy_request_still_routes_to_the_legacy_builder() {
        let req = request(NetworkPolicy::Allow, &[], &["192.0.2.0/24"]);

        let dispatched = EgressPlan::for_request(&req).expect("the legacy denylist is enforceable");
        let direct = EgressPlan::for_policy(&req).expect("the legacy denylist is enforceable");

        assert_eq!(v4(&dispatched), v4(&direct));
        assert_eq!(v6(&dispatched), v6(&direct));
    }

    /// Build a directional request carrying `allow`/`deny` rules.
    fn directional_rules_request(
        default: NetworkAction,
        allow: Vec<NetworkRule>,
        deny: Vec<NetworkRule>,
    ) -> ExecutionRequest {
        let mut req = directional_egress_request(default);
        let egress = req
            .policy
            .network_egress
            .as_mut()
            .expect("the request carries an egress section");
        egress.allow = allow;
        egress.deny = deny;
        req
    }

    fn peer(cidr: &str, except: &[&str]) -> NetworkPeer {
        NetworkPeer {
            cidr: cidr.parse().expect("the test CIDR parses"),
            except: except
                .iter()
                .map(|entry| entry.parse().expect("the test CIDR parses"))
                .collect(),
        }
    }

    fn rule(peers: Vec<NetworkPeer>, ports: Vec<NetworkPort>) -> NetworkRule {
        NetworkRule { to: peers, ports }
    }

    fn port(protocol: NetworkProtocol, port: Option<u16>, end_port: Option<u16>) -> NetworkPort {
        NetworkPort {
            protocol,
            port,
            end_port,
        }
    }

    /// `iptables` cannot exclude a sub-block inside a rule, so an `except` is
    /// lowered as CIDR subtraction. The result must cover the peer exactly:
    /// every address the caller allowed and none they excluded.
    #[test]
    fn an_exclusion_expands_into_the_surrounding_blocks() {
        let req = directional_rules_request(
            NetworkAction::Deny,
            vec![rule(vec![peer("10.0.0.0/8", &["10.1.0.0/16"])], Vec::new())],
            Vec::new(),
        );

        let plan = EgressPlan::for_request(&req).expect("the exclusion is renderable");

        assert_eq!(
            v4(&plan),
            vec![
                "-o lo -j ACCEPT",
                HOST_LOOPBACK_DROP,
                "-d 10.0.0.0/16 -j ACCEPT",
                "-d 10.2.0.0/15 -j ACCEPT",
                "-d 10.4.0.0/14 -j ACCEPT",
                "-d 10.8.0.0/13 -j ACCEPT",
                "-d 10.16.0.0/12 -j ACCEPT",
                "-d 10.32.0.0/11 -j ACCEPT",
                "-d 10.64.0.0/10 -j ACCEPT",
                "-d 10.128.0.0/9 -j ACCEPT",
                "-j DROP",
            ],
            "the excluded /16 must be absent and the rest of the /8 covered"
        );
    }

    /// The subtraction is the part most likely to be subtly wrong, so this
    /// checks it against ground truth rather than against a hand-written block
    /// list: every address in a small space is classified independently and
    /// compared with what the emitted blocks actually match.
    #[test]
    fn the_exclusion_math_matches_address_by_address() {
        let excluded: std::collections::HashSet<u32> = (0xC000_0210..=0xC000_021F).collect();

        let req = directional_rules_request(
            NetworkAction::Deny,
            vec![rule(
                vec![peer("192.0.2.0/24", &["192.0.2.16/28"])],
                Vec::new(),
            )],
            Vec::new(),
        );
        let plan = EgressPlan::for_request(&req).expect("the exclusion is renderable");

        let blocks: Vec<(u32, u8)> = v4(&plan)
            .iter()
            .filter_map(|line| line.strip_prefix("-d "))
            .filter_map(|line| line.split(" -j").next())
            .map(|cidr| {
                let (address, prefix) = cidr.split_once('/').expect("rendered as a CIDR");
                (
                    u32::from(address.parse::<Ipv4Addr>().expect("an IPv4 block")),
                    prefix.parse::<u8>().expect("a numeric prefix"),
                )
            })
            .collect();

        for address in 0xC000_0200u32..=0xC000_02FF {
            let matched = blocks.iter().any(|(base, prefix)| {
                let shift = 32 - u32::from(*prefix);
                // A /0 would shift by 32, which is undefined for u32.
                shift == 32 || (address >> shift) == (base >> shift)
            });
            assert_eq!(
                matched,
                !excluded.contains(&address),
                "{} classified wrongly",
                Ipv4Addr::from(address)
            );
        }
    }

    /// The inversion guard. An `except` inside a *deny* rule must shrink what
    /// is dropped; lowering it as a preceding DROP -- the obvious shortcut --
    /// would drop exactly the addresses the caller carved out.
    #[test]
    fn an_exclusion_inside_a_deny_rule_is_not_itself_denied() {
        let req = directional_rules_request(
            NetworkAction::Allow,
            Vec::new(),
            vec![rule(vec![peer("10.0.0.0/8", &["10.1.0.0/16"])], Vec::new())],
        );

        let plan = EgressPlan::for_request(&req).expect("the exclusion is renderable");

        assert!(
            !v4(&plan).iter().any(|line| line.contains("10.1.0.0/16")),
            "the carved-out block must not appear as a drop: {:?}",
            v4(&plan)
        );
        assert!(
            v4(&plan).contains(&"-d 10.0.0.0/16 -j DROP".to_string()),
            "the rest of the peer must still be dropped: {:?}",
            v4(&plan)
        );
    }

    /// D4: an explicit deny beats a broader allow, which on a first-match chain
    /// means every deny is emitted ahead of every allow.
    #[test]
    fn denies_are_emitted_before_allows() {
        let req = directional_rules_request(
            NetworkAction::Deny,
            vec![rule(vec![peer("10.0.0.0/8", &[])], Vec::new())],
            vec![rule(vec![peer("10.1.2.3/32", &[])], Vec::new())],
        );

        let plan = EgressPlan::for_request(&req).expect("the rules are renderable");

        assert_eq!(
            v4(&plan),
            vec![
                "-o lo -j ACCEPT",
                HOST_LOOPBACK_DROP,
                "-d 10.1.2.3/32 -j DROP",
                "-d 10.0.0.0/8 -j ACCEPT",
                "-j DROP",
            ]
        );
    }

    /// "Omission matches both IP families", so a rule with no peers must reach
    /// both chains rather than silently applying to neither.
    #[test]
    fn a_rule_without_peers_covers_both_families() {
        let req = directional_rules_request(
            NetworkAction::Deny,
            vec![rule(
                Vec::new(),
                vec![port(NetworkProtocol::Tcp, Some(443), None)],
            )],
            Vec::new(),
        );

        let plan = EgressPlan::for_request(&req).expect("the rule is renderable");

        assert!(v4(&plan).contains(&"-p tcp -d 0.0.0.0/0 --dport 443 -j ACCEPT".to_string()));
        assert!(v6(&plan).contains(&"-p tcp -d ::/0 --dport 443 -j ACCEPT".to_string()));
    }

    /// A port range renders as one `--dport a:b` rather than fanning out into a
    /// rule per port, which would multiply against the peer list.
    #[test]
    fn a_port_range_renders_as_a_single_match() {
        let req = directional_rules_request(
            NetworkAction::Deny,
            vec![rule(
                vec![peer("192.0.2.1/32", &[])],
                vec![port(NetworkProtocol::Tcp, Some(8000), Some(8080))],
            )],
            Vec::new(),
        );

        let plan = EgressPlan::for_request(&req).expect("the range is renderable");

        assert!(
            v4(&plan).contains(&"-p tcp -d 192.0.2.1/32 --dport 8000:8080 -j ACCEPT".to_string())
        );
    }

    /// `any` with a port narrows to TCP and UDP — `--dport` needs a protocol
    /// match. See the #980 note in `lower_ports`.
    #[test]
    fn an_any_protocol_port_narrows_to_tcp_and_udp() {
        let req = directional_rules_request(
            NetworkAction::Deny,
            vec![rule(
                vec![peer("192.0.2.1/32", &[])],
                vec![port(NetworkProtocol::Any, Some(53), None)],
            )],
            Vec::new(),
        );

        let plan = EgressPlan::for_request(&req).expect("the selector is renderable");

        assert_eq!(
            v4(&plan),
            vec![
                "-o lo -j ACCEPT",
                HOST_LOOPBACK_DROP,
                "-p tcp -d 192.0.2.1/32 --dport 53 -j ACCEPT",
                "-p udp -d 192.0.2.1/32 --dport 53 -j ACCEPT",
                "-j DROP",
            ]
        );
    }

    /// A rule is a cross product of its peers and its ports.
    #[test]
    fn peers_and_ports_fan_out_together() {
        let req = directional_rules_request(
            NetworkAction::Deny,
            vec![rule(
                vec![peer("192.0.2.1/32", &[]), peer("198.51.100.0/24", &[])],
                vec![
                    port(NetworkProtocol::Tcp, Some(80), None),
                    port(NetworkProtocol::Tcp, Some(443), None),
                ],
            )],
            Vec::new(),
        );

        let plan = EgressPlan::for_request(&req).expect("the rule is renderable");

        assert_eq!(
            v4(&plan),
            vec![
                "-o lo -j ACCEPT",
                HOST_LOOPBACK_DROP,
                "-p tcp -d 192.0.2.1/32 --dport 80 -j ACCEPT",
                "-p tcp -d 192.0.2.1/32 --dport 443 -j ACCEPT",
                "-p tcp -d 198.51.100.0/24 --dport 80 -j ACCEPT",
                "-p tcp -d 198.51.100.0/24 --dport 443 -j ACCEPT",
                "-j DROP",
            ]
        );
    }

    /// An IPv6 peer belongs to the v6 chain, and an IPv4-mapped one is rewritten
    /// to v4 -- Linux puts a real IPv4 packet on the wire for a mapped address,
    /// so an `ip6tables` rule naming one would never match.
    #[test]
    fn a_mapped_peer_is_programmed_into_the_v4_chain() {
        let req = directional_rules_request(
            NetworkAction::Deny,
            vec![rule(
                vec![
                    peer("::ffff:192.0.2.0/120", &[]),
                    peer("2001:db8::/32", &[]),
                ],
                Vec::new(),
            )],
            Vec::new(),
        );

        let plan = EgressPlan::for_request(&req).expect("the peers are renderable");

        assert!(v4(&plan).contains(&"-d 192.0.2.0/24 -j ACCEPT".to_string()));
        assert!(v6(&plan).contains(&"-d 2001:db8::/32 -j ACCEPT".to_string()));
    }

    /// ICMP has no ports, so a port selector on it describes traffic no rule can
    /// match. Dropping the qualifier silently would install a wider rule.
    #[test]
    fn an_icmp_port_selector_is_refused() {
        let req = directional_rules_request(
            NetworkAction::Deny,
            vec![rule(
                vec![peer("192.0.2.1/32", &[])],
                vec![port(NetworkProtocol::Icmp, Some(8), None)],
            )],
            Vec::new(),
        );

        let error = EgressPlan::for_request(&req).expect_err("an ICMP port cannot be honored");

        assert!(
            error.contains("icmp"),
            "the rejection should name it: {error}"
        );
    }

    /// `ip6tables` has no `icmp` protocol: it rejects the token, and because a
    /// restore is one transaction, that failure installs *nothing* rather than
    /// degrading to a partial policy. A `to`-less ICMP rule fans into both
    /// families, so this is reachable from an ordinary config.
    #[test]
    fn an_icmp_rule_renders_icmpv6_in_the_v6_table() {
        let req = directional_rules_request(
            NetworkAction::Deny,
            vec![rule(
                Vec::new(),
                vec![port(NetworkProtocol::Icmp, None, None)],
            )],
            Vec::new(),
        );

        let plan = EgressPlan::for_request(&req).expect("an ICMP rule is renderable");

        assert!(
            v4(&plan).iter().any(|line| line.starts_with("-p icmp ")),
            "the V4 table keeps the V4 token: {:?}",
            v4(&plan)
        );
        assert!(
            v6(&plan).iter().any(|line| line.starts_with("-p icmpv6 ")),
            "the V6 table needs icmpv6 or the restore fails: {:?}",
            v6(&plan)
        );
        assert!(
            !v6(&plan).iter().any(|line| line.starts_with("-p icmp ")),
            "no V6 line may carry the V4-only token: {:?}",
            v6(&plan)
        );
    }

    /// An ICMP rule aimed at a V6 peer is the same hazard reached the other
    /// way: the family comes from the destination rather than the fan-out.
    #[test]
    fn an_icmp_rule_to_a_v6_peer_renders_icmpv6() {
        let req = directional_rules_request(
            NetworkAction::Deny,
            vec![rule(
                vec![peer("2001:db8::/32", &[])],
                vec![port(NetworkProtocol::Icmp, None, None)],
            )],
            Vec::new(),
        );

        let plan = EgressPlan::for_request(&req).expect("an ICMP rule is renderable");

        assert!(
            v6(&plan).contains(&"-p icmpv6 -d 2001:db8::/32 -j ACCEPT".to_string()),
            "{:?}",
            v6(&plan)
        );
    }

    /// The directional shape must refuse the same straddling block the legacy
    /// string path refuses.
    ///
    /// This was a real bypass: `Block::from_cidr` classified `::/0` as V6 and
    /// installed it into `ip6tables` alone. Linux emits IPv4-mapped
    /// destinations as IPv4 packets, so under `default: allow` a `deny ::/0`
    /// rule — which reads as "deny everything" — never matched IPv4 traffic
    /// and failed open. `RuleAddress::parse` had guarded this since before the
    /// directional shape existed; the new entry point simply skipped it.
    #[test]
    fn a_directional_block_straddling_the_mapped_range_is_refused() {
        for straddling in ["::/0", "::/64", "::ffff:0:0/95"] {
            let (address, prefix) = straddling.split_once('/').expect("a CIDR");
            let cidr = NetworkCidr {
                address: address.parse().expect("an IPv6 address"),
                prefix_length: prefix.parse().expect("a prefix"),
            };
            let req = directional_rules_request(
                NetworkAction::Allow,
                Vec::new(),
                vec![rule(
                    vec![NetworkPeer {
                        cidr,
                        except: Vec::new(),
                    }],
                    Vec::new(),
                )],
            );

            let error = EgressPlan::for_request(&req)
                .expect_err("a block that swallows the mapped range cannot be honored");
            assert!(
                error.contains("IPv4-mapped"),
                "the rejection should name the hazard for '{straddling}': {error}"
            );
        }
    }

    /// The guard must not overreach: a V6 block that misses the mapped range
    /// is ordinary IPv6 traffic and still has to render.
    #[test]
    fn a_directional_v6_block_clear_of_the_mapped_range_still_renders() {
        let req = directional_rules_request(
            NetworkAction::Deny,
            vec![rule(vec![peer("2001:db8::/32", &[])], Vec::new())],
            Vec::new(),
        );

        let plan = EgressPlan::for_request(&req).expect("an ordinary V6 block is renderable");
        assert!(v6(&plan).contains(&"-d 2001:db8::/32 -j ACCEPT".to_string()));
    }

    /// An inverted range matches nothing, so it is refused rather than
    /// installed as a rule that silently never fires.
    #[test]
    fn an_inverted_port_range_is_refused() {
        let req = directional_rules_request(
            NetworkAction::Deny,
            vec![rule(
                vec![peer("192.0.2.1/32", &[])],
                vec![port(NetworkProtocol::Tcp, Some(9000), Some(80))],
            )],
            Vec::new(),
        );

        EgressPlan::for_request(&req).expect_err("an inverted range cannot be honored");
    }

    /// The JSON parser refuses port 0, but `NetworkPort` is publicly
    /// constructible, so the backend refuses it too rather than rendering a
    /// `--dport 0` rule no packet can match.
    #[test]
    fn a_zero_port_is_refused() {
        for (start, end) in [(Some(0), None), (Some(80), Some(0)), (None, Some(0))] {
            let req = directional_rules_request(
                NetworkAction::Deny,
                vec![rule(
                    vec![peer("192.0.2.1/32", &[])],
                    vec![port(NetworkProtocol::Tcp, start, end)],
                )],
                Vec::new(),
            );

            EgressPlan::for_request(&req).expect_err("port 0 cannot be honored");
        }
    }

    /// The expansion ceiling exists so a pathological peer fails loudly instead
    /// of overflowing the restore transaction and installing nothing.
    #[test]
    fn an_oversized_exclusion_expansion_is_refused() {
        let excepts: Vec<String> = (0..64).map(|n| format!("10.{n}.0.1/32")).collect();
        let borrowed: Vec<&str> = excepts.iter().map(String::as_str).collect();

        let req = directional_rules_request(
            NetworkAction::Deny,
            vec![rule(vec![peer("10.0.0.0/8", &borrowed)], Vec::new())],
            Vec::new(),
        );

        let error = EgressPlan::for_request(&req).expect_err("the expansion exceeds the ceiling");

        assert!(
            error.contains("address blocks"),
            "the rejection should explain the expansion: {error}"
        );
    }

    /// A rule is a cross product of blocks and ports, and the wire contract
    /// bounds neither list, so a small policy can otherwise expand without
    /// limit. The total ceiling caps what the whole policy may materialize.
    #[test]
    fn an_oversized_cross_product_is_refused() {
        let ports: Vec<NetworkPort> = (0..MAX_EGRESS_RULES / 2)
            .map(|n| port(NetworkProtocol::Tcp, Some(n as u16 + 1), None))
            .collect();

        let req = directional_rules_request(
            NetworkAction::Deny,
            vec![rule(
                vec![peer("192.0.2.1/32", &[]), peer("192.0.2.2/32", &[])],
                ports,
            )],
            Vec::new(),
        );

        let error = EgressPlan::for_request(&req).expect_err("the product exceeds the ceiling");

        assert!(
            error.contains("firewall rules"),
            "the rejection should explain the product: {error}"
        );
    }

    /// The per-peer ceiling is reset for every peer, so it bounds one peer and
    /// not the policy. The rule ceiling has to accumulate, or a caller reaches
    /// the same expansion by splitting it across rules that each fit.
    #[test]
    fn the_rule_budget_is_a_total_across_rules() {
        let two_thirds = || -> Vec<NetworkPort> {
            (0..MAX_EGRESS_RULES * 2 / 3)
                .map(|n| port(NetworkProtocol::Tcp, Some(n as u16 + 1), None))
                .collect()
        };
        let one = || rule(vec![peer("192.0.2.1/32", &[])], two_thirds());
        let two = || rule(vec![peer("192.0.2.2/32", &[])], two_thirds());

        EgressPlan::for_request(&directional_rules_request(
            NetworkAction::Deny,
            vec![one()],
            Vec::new(),
        ))
        .expect("either rule fits on its own");

        EgressPlan::for_request(&directional_rules_request(
            NetworkAction::Deny,
            vec![one(), two()],
            Vec::new(),
        ))
        .expect_err("together they exceed the ceiling");
    }

    /// The ceiling is a limit, not a margin: a policy that lands exactly on it
    /// is still installed.
    #[test]
    fn a_policy_at_the_rule_budget_is_accepted() {
        // The host-loopback drop is lowered ahead of the caller's rules, so it
        // spends one of the budget.
        let ports: Vec<NetworkPort> = (1..MAX_EGRESS_RULES)
            .map(|n| port(NetworkProtocol::Tcp, Some(n as u16), None))
            .collect();

        let req = directional_rules_request(
            NetworkAction::Deny,
            vec![rule(vec![peer("192.0.2.1/32", &[])], ports)],
            Vec::new(),
        );

        let plan = EgressPlan::for_request(&req).expect("a policy on the ceiling is enforceable");

        assert_eq!(
            plan.rules.len(),
            MAX_EGRESS_RULES,
            "the policy should fill the budget exactly"
        );
    }

    /// `MAX_BLOCKS_PER_PEER` is reset for every peer, and the rule ceiling was
    /// only consulted once every peer had been expanded. The peer count itself
    /// is unbounded, so the budget has to stop the expansion rather than audit
    /// it after the full address vector exists.
    #[test]
    fn peer_expansion_stops_at_the_budget() {
        let mut peers: Vec<NetworkPeer> = (1..=8)
            .map(|n| peer(&format!("192.0.2.{n}/32"), &[]))
            .collect();
        // Refused by the mapped-range guard, and last: reaching it would prove
        // the expansion ran past the budget, since its refusal would be the
        // one reported.
        peers.push(peer("::/0", &[]));

        let error = lower_peers(&peers, 4).expect_err("the peers alone exceed the budget");

        assert!(
            error.contains("firewall rules"),
            "the budget should stop the expansion where it is exceeded: {error}"
        );
    }

    /// The reported failure: a mapped `blockedHosts` entry under
    /// `defaultPolicy: allow`. Classified as IPv6 it would be programmed into
    /// `ip6tables`, where it never matches the IPv4 packet Linux actually
    /// emits, and the v4 chain's terminal ACCEPT would let the traffic through.
    #[test]
    fn a_mapped_denylist_entry_is_programmed_on_the_family_that_carries_it() {
        let plan =
            EgressPlan::for_policy(&request(NetworkPolicy::Allow, &[], &["::ffff:192.0.2.5"]))
                .expect("a mapped denylist entry is enforceable");

        assert_eq!(
            v4(&plan),
            egress(&["-d 192.0.2.5 -j DROP"], "ACCEPT"),
            "the mapped entry must be programmed on the family that carries it"
        );
        assert_eq!(
            v6(&plan),
            egress(&[], "ACCEPT"),
            "programming it in ip6tables would never match, so the deny would fail open"
        );
    }

    /// D4: an explicit deny overrides a broader allow, which in an ordered
    /// chain means the deny has to be appended first.
    #[test]
    fn denies_precede_allows_so_the_narrower_deny_wins() {
        let plan = EgressPlan::for_policy(&request(
            NetworkPolicy::Block,
            &["0.0.0.0/0"],
            &["192.0.2.1"],
        ))
        .expect("an allow-with-exception policy is enforceable");

        assert_eq!(
            v4(&plan),
            egress(&["-d 192.0.2.1 -j DROP", "-d 0.0.0.0/0 -j ACCEPT"], "DROP")
        );
    }

    #[test]
    fn a_v6_rule_lands_only_in_the_ip6tables_payload() {
        let plan = EgressPlan::for_policy(&request(NetworkPolicy::Block, &["2001:db8::/32"], &[]))
            .expect("a v6 CIDR is enforceable");

        assert_eq!(v6(&plan), egress(&["-d 2001:db8::/32 -j ACCEPT"], "DROP"));
        assert_eq!(v4(&plan), egress(&[], "DROP"));
    }

    #[test]
    fn a_named_host_fails_the_whole_plan() {
        let error = EgressPlan::for_policy(&request(
            NetworkPolicy::Block,
            &["10.0.0.1", "api.github.com"],
            &[],
        ))
        .expect_err("one unenforceable entry invalidates the policy");
        assert!(error.contains("api.github.com"), "{error}");
    }

    #[test]
    fn the_proxy_plan_opens_exactly_one_endpoint() {
        let plan = EgressPlan::for_proxy(Ipv4Addr::new(10, 0, 2, 2), 3128);

        assert_eq!(
            v4(&plan),
            egress(&["-p tcp -d 10.0.2.2 --dport 3128 -j ACCEPT"], "DROP")
        );
        assert_eq!(v6(&plan), egress(&[], "DROP"));
    }

    /// Both hooks are the last lines of the transaction, so a built-in chain is
    /// only ever redirected to a chain that is already complete.
    #[test]
    fn the_hooks_are_committed_with_the_chains_they_jump_to() {
        let plan = EgressPlan::for_proxy(Ipv4Addr::new(10, 0, 2, 2), 3128);
        for family in [RuleFamily::V4, RuleFamily::V6] {
            let rendered = payload(&plan, family);
            let lines: Vec<&str> = rendered.lines().collect();

            assert_eq!(lines[0], "*filter");
            assert_eq!(lines[1], format!(":{EGRESS} - [0:0]"));
            assert_eq!(lines[2], format!(":{INGRESS} - [0:0]"));
            assert_eq!(lines[lines.len() - 3], format!("-A OUTPUT -j {EGRESS}"));
            assert_eq!(lines[lines.len() - 2], format!("-A INPUT -j {INGRESS}"));
            assert_eq!(lines[lines.len() - 1], "COMMIT");
        }
    }

    /// A family with no rules of its own still gets its terminal verdict, so
    /// IPv6 under an IPv4-only policy fails closed rather than being left open.
    #[test]
    fn a_policy_with_no_host_rules_still_closes_both_families() {
        let plan = EgressPlan::for_policy(&request(NetworkPolicy::Block, &[], &[]))
            .expect("a bare block policy is enforceable");

        assert_eq!(v4(&plan), egress(&[], "DROP"));
        assert_eq!(v6(&plan), egress(&[], "DROP"));
    }

    // ── Ingress ──────────────────────────────────────────────────────────────

    fn ingress_body(family: RuleFamily) -> Vec<String> {
        chain_body(
            &payload(
                &EgressPlan::for_proxy(Ipv4Addr::new(10, 0, 2, 2), 3128),
                family,
            ),
            INGRESS,
        )
    }

    /// The whole inbound chain, asserted as an ordered sequence because in a
    /// first-match chain a correct set of rules in the wrong order is a
    /// different policy.
    #[test]
    fn the_ingress_chain_denies_new_inbound_and_keeps_replies_flowing() {
        for family in [RuleFamily::V4, RuleFamily::V6] {
            assert_eq!(
                ingress_body(family),
                vec![
                    "-i lo -j ACCEPT".to_string(),
                    "-m state --state ESTABLISHED,RELATED -j ACCEPT".to_string(),
                    "-m state --state NEW -j DROP".to_string(),
                    "-j DROP".to_string(),
                ],
                "{family:?}"
            );
        }
    }

    /// The regression this chain could most easily cause. A terminal `DROP`
    /// applies to replies too, so without the connection-state accept ahead of
    /// it the sandbox would lose all networking rather than gain an inbound
    /// restriction -- and it has to come *before* the drops to be reached.
    #[test]
    fn replies_are_accepted_before_anything_is_dropped() {
        let body = ingress_body(RuleFamily::V4);
        let established = body
            .iter()
            .position(|rule| rule.contains("ESTABLISHED,RELATED"))
            .expect("replies must be accepted, or egress stops working");
        let first_drop = body
            .iter()
            .position(|rule| rule.contains("-j DROP"))
            .expect("the chain must drop something");

        assert!(established < first_drop, "{body:?}");
    }

    /// `defaultPolicy` governs egress. An open outbound posture must not open
    /// inbound as a side effect.
    #[test]
    fn an_allow_egress_posture_does_not_open_inbound() {
        let plan = EgressPlan::for_policy(&request(NetworkPolicy::Allow, &[], &[]))
            .expect("a bare allow policy is enforceable");
        let rendered =
            render_filter_payloads(&plan, &denied_ingress(), RuleFamily::V4, EGRESS, INGRESS)
                .concat();

        assert_eq!(chain_body(&rendered, EGRESS).last().unwrap(), "-j ACCEPT");
        assert_eq!(chain_body(&rendered, INGRESS).last().unwrap(), "-j DROP");
    }

    /// The mapping the rejection at `bwrap_command` currently guards. Asserted
    /// so lifting that rejection cannot silently produce the wrong posture.
    #[test]
    fn allowing_local_network_accepts_new_inbound_instead() {
        let mut request = ExecutionRequest::default();
        request.policy.allow_local_network = true;
        let plan = EgressPlan::for_proxy(Ipv4Addr::new(10, 0, 2, 2), 3128);
        let rendered = render_filter_payloads(
            &plan,
            &IngressPlan::for_policy(&request.policy),
            RuleFamily::V4,
            EGRESS,
            INGRESS,
        )
        .concat();
        let body = chain_body(&rendered, INGRESS);

        assert!(
            body.contains(&"-m state --state NEW -j ACCEPT".to_string()),
            "{body:?}"
        );
        assert_eq!(
            body.last().unwrap(),
            "-j DROP",
            "the terminal verdict closes the chain regardless: {body:?}"
        );
    }

    /// A policy large enough to exceed one `iptables-restore` transaction.
    ///
    /// Nothing else in the suite crosses `RESTORE_PAYLOAD_BUDGET`, which left
    /// both the mid-body split and the hooks-get-their-own-payload branch dead
    /// in test -- and that is the path that exists to stop a hook going live
    /// over a half-built chain.
    fn oversized_plan() -> EgressPlan {
        let blocked: Vec<String> = (0..2000)
            .map(|index| format!("198.51.{}.{}/32", index / 256, index % 256))
            .collect();
        let refs: Vec<&str> = blocked.iter().map(String::as_str).collect();
        EgressPlan::for_policy(&request(NetworkPolicy::Block, &[], &refs))
            .expect("literal CIDRs are enforceable")
    }

    #[test]
    fn a_large_policy_splits_across_restore_transactions() {
        let payloads = payloads(&oversized_plan(), RuleFamily::V4);

        assert!(
            payloads.len() > 1,
            "the policy must exceed one transaction for this test to mean anything"
        );
        for (index, payload) in payloads.iter().enumerate() {
            assert!(
                payload.len() <= RESTORE_PAYLOAD_BUDGET,
                "payload {index} is over budget at {} bytes; nf_tables would reject the \
                 whole table and install nothing",
                payload.len()
            );
            assert!(
                payload.starts_with("*filter\n"),
                "payload {index} must open the table"
            );
            assert!(
                payload.ends_with(COMMIT),
                "payload {index} must be a closed transaction; an unterminated one applies nothing"
            );
        }
    }

    /// Chains may be declared once. A later payload re-declaring them would
    /// flush the rules the earlier payloads just installed.
    #[test]
    fn only_the_first_payload_declares_the_chains() {
        let payloads = payloads(&oversized_plan(), RuleFamily::V4);

        assert!(
            payloads[0].contains(&format!(":{EGRESS} -")),
            "the first payload declares the chains: {}",
            &payloads[0][..payloads[0].len().min(120)]
        );
        for (index, payload) in payloads.iter().enumerate().skip(1) {
            assert!(
                !payload.contains(&format!(":{EGRESS} -")),
                "payload {index} re-declares {EGRESS}, which would flush what is already installed"
            );
        }
    }

    /// The invariant the split exists to protect: until the hooks are in, the
    /// chain is not reachable, so a partial apply leaves the policy unhooked
    /// rather than half-enforced.
    #[test]
    fn hooks_ride_only_in_the_final_payload() {
        let payloads = payloads(&oversized_plan(), RuleFamily::V4);
        let hook = format!("-A OUTPUT -j {EGRESS}");

        for (index, payload) in payloads.iter().enumerate() {
            let is_last = index + 1 == payloads.len();
            assert_eq!(
                payload.contains(&hook),
                is_last,
                "payload {index} of {} has the wrong hook posture: a hook in any earlier \
                 transaction would point OUTPUT at a chain that is still being built",
                payloads.len()
            );
        }
    }

    /// Every rule must survive the split, in order: the chain is first-match,
    /// so a dropped or reordered rule is a policy change.
    #[test]
    fn splitting_preserves_every_rule_and_its_order() {
        let plan = oversized_plan();
        let split = payloads(&plan, RuleFamily::V4).concat();

        let expected: Vec<String> = plan
            .chain_lines(RuleFamily::V4)
            .into_iter()
            .map(|line| format!("-A {EGRESS} {line}"))
            .collect();
        let actual: Vec<String> = split
            .lines()
            .filter(|line| line.starts_with(&format!("-A {EGRESS} ")))
            .map(str::to_string)
            .collect();

        assert_eq!(
            actual, expected,
            "the concatenated payloads must equal the unsplit chain body"
        );
    }

    /// The destination blocks a rule set lowers to, for one family. The
    /// host-loopback drop is skipped -- it is asserted on its own elsewhere.
    fn destinations(plan: &EgressPlan, family: RuleFamily) -> Vec<String> {
        plan.rules
            .iter()
            .filter(|rule| rule.address.family == family)
            .map(|rule| rule.address.text.clone())
            .filter(|text| text != "10.0.2.2/32")
            .collect()
    }

    /// Subtracting a block from itself leaves nothing, so the rule must vanish
    /// rather than degrade to its unexcluded parent -- which would install the
    /// exact opposite of what was asked for.
    #[test]
    fn an_exclusion_equal_to_its_peer_removes_the_rule() {
        let req = directional_rules_request(
            NetworkAction::Deny,
            vec![rule(
                vec![peer("192.0.2.0/24", &["192.0.2.0/24"])],
                Vec::new(),
            )],
            Vec::new(),
        );

        let plan = EgressPlan::for_request(&req).expect("a full exclusion is renderable");

        assert!(
            destinations(&plan, RuleFamily::V4).is_empty(),
            "nothing remains of the peer: {:?}",
            destinations(&plan, RuleFamily::V4)
        );
        assert_eq!(
            v4(&plan).last().unwrap(),
            "-j DROP",
            "and the terminal verdict still closes the chain"
        );
    }
    /// An exclusion outside its peer overlaps nothing, so the peer must survive
    /// whole. Subtraction that mishandled the disjoint case would carve a hole
    /// out of a block the caller never narrowed.
    #[test]
    fn a_disjoint_exclusion_leaves_the_peer_intact() {
        let req = directional_rules_request(
            NetworkAction::Deny,
            vec![rule(
                vec![peer("192.0.2.0/24", &["203.0.113.0/24"])],
                Vec::new(),
            )],
            Vec::new(),
        );

        let plan = EgressPlan::for_request(&req).expect("a disjoint exclusion is renderable");

        assert_eq!(destinations(&plan, RuleFamily::V4), vec!["192.0.2.0/24"]);
    }

    /// Multiple and nested exclusions exercise the recursion. The union of what
    /// remains must be the peer minus every exclusion, with no overlaps.
    #[test]
    fn multiple_and_nested_exclusions_subtract_together() {
        let req = directional_rules_request(
            NetworkAction::Deny,
            vec![rule(
                vec![peer(
                    "10.0.0.0/24",
                    &["10.0.0.0/26", "10.0.0.128/25", "10.0.0.64/28"],
                )],
                Vec::new(),
            )],
            Vec::new(),
        );

        let plan = EgressPlan::for_request(&req).expect("nested exclusions are renderable");
        let covered = covered_addresses(&plan, RuleFamily::V4);

        // 10.0.0.0/24 minus /26 (0-63), /25 (128-255) and /28 (64-79)
        // leaves exactly 10.0.0.80 - 10.0.0.127.
        let expected: Vec<u32> = (80..=127).map(|host| 0x0A000000 | host).collect();
        assert_eq!(
            covered, expected,
            "the remaining blocks must be the peer minus every exclusion, exactly once"
        );
    }

    /// Every address the plan's V4 rules cover, ascending, with duplicates kept
    /// so an overlapping split is visible rather than hidden by a set.
    fn covered_addresses(plan: &EgressPlan, family: RuleFamily) -> Vec<u32> {
        let mut covered = Vec::new();
        for text in destinations(plan, family) {
            let (address, prefix) = text.split_once('/').expect("rendered as a CIDR");
            let base: u32 = address
                .parse::<Ipv4Addr>()
                .expect("a V4 destination")
                .into();
            let prefix: u32 = prefix.parse().expect("a prefix");
            let count = 1u64 << (32 - prefix);
            covered.extend((0..count).map(|offset| base + offset as u32));
        }
        covered.sort_unstable();
        covered
    }

    /// Subtraction is family-generic, but only IPv4 was covered. IPv6 uses the
    /// same arithmetic over a 128-bit width, where an off-by-one in the width
    /// handling would not show up in any IPv4 case.
    #[test]
    fn an_ipv6_exclusion_subtracts_from_its_peer() {
        let req = directional_rules_request(
            NetworkAction::Deny,
            vec![rule(
                vec![peer("2001:db8::/32", &["2001:db8:8000::/33"])],
                Vec::new(),
            )],
            Vec::new(),
        );

        let plan = EgressPlan::for_request(&req).expect("an IPv6 exclusion is renderable");

        assert_eq!(
            destinations(&plan, RuleFamily::V6),
            vec!["2001:db8::/33"],
            "the surviving half is the peer's lower 33-bit block"
        );
    }

    /// Addresses and ports form a cross product: each surviving block must
    /// carry every port selector, or the carve-out would quietly widen or
    /// narrow the service the rule names.
    #[test]
    fn a_port_scoped_exclusion_applies_to_every_surviving_block() {
        let req = directional_rules_request(
            NetworkAction::Deny,
            vec![rule(
                vec![peer("192.0.2.0/24", &["192.0.2.128/25"])],
                vec![port(NetworkProtocol::Tcp, Some(443), None)],
            )],
            Vec::new(),
        );

        let plan = EgressPlan::for_request(&req).expect("a port-scoped exclusion is renderable");
        let lines: Vec<String> = v4(&plan)
            .into_iter()
            .filter(|line| line.contains("-d ") && !line.contains("10.0.2.2"))
            .collect();

        assert_eq!(
            lines,
            vec!["-p tcp -d 192.0.2.0/25 --dport 443 -j ACCEPT".to_string()],
            "the surviving block keeps the port selector"
        );
    }

    /// `ingress.hostLoopback` is bidirectional per the 0.8 contract, so a deny
    /// has to close container-to-host too -- under slirp, the gateway.
    #[test]
    fn a_directional_posture_closes_the_host_loopback_path() {
        let plan = EgressPlan::for_request(&directional_egress_request(NetworkAction::Allow))
            .expect("an allow posture is enforceable");

        assert!(
            v4(&plan).contains(&HOST_LOOPBACK_DROP.to_string()),
            "even an open egress posture must close the host path: {:?}",
            v4(&plan)
        );
    }

    /// The ordering *is* the enforcement: the chain is first-match, so a drop
    /// behind the caller's rules would lose to any allow covering the gateway.
    #[test]
    fn the_host_loopback_drop_outranks_a_covering_allow() {
        let req = directional_rules_request(
            NetworkAction::Deny,
            vec![rule(vec![peer("0.0.0.0/0", &[])], Vec::new())],
            Vec::new(),
        );

        let lines = v4(&EgressPlan::for_request(&req).expect("a bare allow is renderable"));
        let drop = lines
            .iter()
            .position(|line| line == HOST_LOOPBACK_DROP)
            .expect("the host path must be closed");
        let allow = lines
            .iter()
            .position(|line| line == "-d 0.0.0.0/0 -j ACCEPT")
            .expect("the caller's rule must still be installed");

        assert!(
            drop < allow,
            "an allow-all placed first would reopen the host path: {lines:?}"
        );
    }

    /// An omitted `ingress` section is not a way out: `hostLoopback` defaults
    /// to deny, so absence must enforce it too.
    #[test]
    fn an_absent_ingress_section_still_closes_the_host_path() {
        let mut req = directional_egress_request(NetworkAction::Allow);
        req.policy.network_ingress = None;

        let plan = EgressPlan::for_request(&req).expect("the posture is enforceable");

        assert!(
            v4(&plan).contains(&HOST_LOOPBACK_DROP.to_string()),
            "{:?}",
            v4(&plan)
        );
    }

    /// Proxy mode needs no separate rule: the endpoint is the only thing open
    /// and the chain closes on DROP. Asserted so that stays true.
    #[test]
    fn proxy_mode_opens_only_the_proxy_endpoint_on_the_gateway() {
        let plan = EgressPlan::for_proxy(Ipv4Addr::new(10, 0, 2, 2), 3128);

        assert_eq!(
            v4(&plan),
            egress(&["-p tcp -d 10.0.2.2 --dport 3128 -j ACCEPT"], "DROP"),
            "anything else to the host must fall through to the terminal drop"
        );
    }

    /// The legacy shape is untouched: no `ingress` section, and adding a drop
    /// there would silently change behavior for 0.6/0.7 callers.
    #[test]
    fn the_legacy_shape_gains_no_host_loopback_rule() {
        let plan = EgressPlan::for_policy(&request(NetworkPolicy::Allow, &["10.0.2.2/32"], &[]))
            .expect("a legacy allowlist is enforceable");

        assert_eq!(
            v4(&plan),
            egress(&["-d 10.0.2.2/32 -j ACCEPT"], "ACCEPT"),
            "pre-0.8 configs keep reaching the host exactly as before"
        );
    }

    /// `NetworkCidr` has public fields and only its `FromStr` validates, so a
    /// programmatic caller reaches the renderer with any prefix. Unchecked,
    /// `width - prefix` underflowed and panicked.
    #[test]
    fn a_prefix_wider_than_its_family_is_rejected_rather_than_overflowing() {
        for (address, prefix) in [("0.0.0.0", 33u8), ("10.0.0.0", 255), ("::", 129)] {
            let req = directional_rules_request(
                NetworkAction::Deny,
                vec![NetworkRule {
                    to: vec![NetworkPeer {
                        cidr: NetworkCidr {
                            address: address.parse().unwrap(),
                            prefix_length: prefix,
                        },
                        except: Vec::new(),
                    }],
                    ports: Vec::new(),
                }],
                Vec::new(),
            );

            let error = EgressPlan::for_request(&req)
                .expect_err("an out-of-range prefix must be refused, not rendered");
            assert!(
                error.contains("wider than its address family"),
                "unexpected message for {address}/{prefix}: {error}"
            );
        }
    }

    /// The check reads the *source* family: this rewrites to a v4 /33, which
    /// would look in range once mapped but is out of range as written.
    #[test]
    fn an_out_of_range_prefix_is_caught_before_mapped_rewriting() {
        let req = directional_rules_request(
            NetworkAction::Deny,
            vec![NetworkRule {
                to: vec![NetworkPeer {
                    cidr: NetworkCidr {
                        address: "::ffff:0:0".parse().unwrap(),
                        prefix_length: 129,
                    },
                    except: Vec::new(),
                }],
                ports: Vec::new(),
            }],
            Vec::new(),
        );

        let error = EgressPlan::for_request(&req).expect_err("129 is out of range for v6");
        assert!(error.contains("wider than its address family"), "{error}");
    }

    /// An out-of-range prefix inside `except` takes the same path.
    #[test]
    fn an_out_of_range_except_prefix_is_rejected_too() {
        let req = directional_rules_request(
            NetworkAction::Deny,
            vec![NetworkRule {
                to: vec![NetworkPeer {
                    cidr: NetworkCidr {
                        address: "10.0.0.0".parse().unwrap(),
                        prefix_length: 8,
                    },
                    except: vec![NetworkCidr {
                        address: "10.1.0.0".parse().unwrap(),
                        prefix_length: 40,
                    }],
                }],
                ports: Vec::new(),
            }],
            Vec::new(),
        );

        let error = EgressPlan::for_request(&req).expect_err("an except prefix is checked too");
        assert!(error.contains("wider than its address family"), "{error}");
    }

    /// The widest legitimate prefix for each family still renders.
    #[test]
    fn a_host_prefix_at_the_family_width_still_renders() {
        let req = directional_rules_request(
            NetworkAction::Deny,
            vec![rule(vec![peer("192.0.2.1/32", &[])], Vec::new())],
            Vec::new(),
        );

        assert!(v4(&EgressPlan::for_request(&req).expect("/32 is in range"))
            .contains(&"-d 192.0.2.1/32 -j ACCEPT".to_string()));
    }
}
