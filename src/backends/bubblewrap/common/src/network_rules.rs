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

use wxc_common::models::{ExecutionRequest, NetworkPolicy};

/// Which `iptables` binary carries a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuleFamily {
    V4,
    V6,
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

/// One installed rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EgressRule {
    verdict: RuleVerdict,
    address: RuleAddress,
    /// Protocol and destination port, when the rule narrows to one service.
    /// Only the proxy endpoint uses it; policy host lists carry no port.
    port: Option<(&'static str, u16)>,
}

impl EgressRule {
    /// The rule's `iptables-restore` line, without the leading `-A <chain>`.
    fn render(&self) -> String {
        match self.port {
            Some((protocol, port)) => format!(
                "-p {} -d {} --dport {} -j {}",
                protocol,
                self.address.text,
                port,
                self.verdict.target()
            ),
            None => format!("-d {} -j {}", self.address.text, self.verdict.target()),
        }
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

/// `iptables-restore` invocations the supervisor makes: one per family,
/// whatever the policy contains. The whole table arrives in a single
/// transaction, so this no longer grows with the rule count.
pub(crate) const RESTORE_INVOCATIONS: u32 = 2;

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
                port: Some(("tcp", port)),
            }],
            v4_terminal: RuleVerdict::Drop,
            v6_terminal: RuleVerdict::Drop,
        }
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
                port: None,
            });
        }
        for entry in &policy.allowed_hosts {
            rules.push(EgressRule {
                verdict: RuleVerdict::Accept,
                address: RuleAddress::parse(entry)?,
                port: None,
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
    /// The posture the request asks for.
    ///
    /// Only the deny posture is reachable on the private-namespace path today:
    /// `allowLocalNetwork: true` is refused before this point at schema 0.8+
    /// (see `bwrap_command::local_network_diagnostic_for_mode`) because
    /// honoring it needs slirp port forwarding and a port contract that the
    /// legacy schema cannot express. The mapping is written out in full anyway
    /// so the policy lives in one readable place and lifting that rejection is
    /// a change at the rejection, not here.
    pub(crate) fn for_request(request: &ExecutionRequest) -> Self {
        Self {
            new_inbound: if request.policy.allow_local_network {
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

/// The `iptables-restore` payload installing both directions for one family.
///
/// Everything travels in a single transaction: chain creation, both bodies and
/// both hooks. That keeps the cost of a policy independent of the caller's host
/// lists, and means a hook is never live over a partially built chain. If any
/// line is unsupported by the host kernel -- the `state` match without
/// `nf_conntrack`, say -- the whole transaction is rejected and nothing is
/// applied, which is what makes an unsupported host fail closed at launch
/// rather than run unenforced.
pub(crate) fn render_filter_payload(
    egress: &EgressPlan,
    ingress: &IngressPlan,
    family: RuleFamily,
    egress_chain: &'static str,
    ingress_chain: &'static str,
) -> String {
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

    let mut out = String::from("*filter\n");
    for section in &sections {
        out.push_str(&format!(":{} - [0:0]\n", section.chain));
    }
    for section in &sections {
        for line in &section.lines {
            out.push_str(&format!("-A {} {line}\n", section.chain));
        }
    }
    // Hooks last, so the built-in chains are only redirected once every custom
    // chain in this transaction is complete.
    for section in &sections {
        out.push_str(&format!("-A {} -j {}\n", section.hook, section.chain));
    }
    out.push_str("COMMIT\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::models::ContainerPolicy;

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

    fn payload(plan: &EgressPlan, family: RuleFamily) -> String {
        render_filter_payload(plan, &denied_ingress(), family, EGRESS, INGRESS)
    }

    fn denied_ingress() -> IngressPlan {
        IngressPlan::for_request(&ExecutionRequest::default())
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
            format!("{}-A C -d 192.0.2.5 -j DROP\n{}", head(), tail("ACCEPT")),
            "the mapped entry must be programmed on the family that carries it"
        );
        assert_eq!(
            v6(&plan),
            format!("{}{}", head(), tail("ACCEPT")),
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
            render_filter_payload(&plan, &denied_ingress(), RuleFamily::V4, EGRESS, INGRESS);

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
        let rendered = render_filter_payload(
            &plan,
            &IngressPlan::for_request(&request),
            RuleFamily::V4,
            EGRESS,
            INGRESS,
        );
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
}
