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
use std::net::{IpAddr, Ipv4Addr};

use wxc_common::models::{ExecutionRequest, NetworkPolicy};

/// Which `iptables` binary carries a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuleFamily {
    V4,
    V6,
}

impl RuleFamily {
    /// The field the supervisor reads to pick its binary.
    fn tag(self) -> &'static str {
        match self {
            Self::V4 => "4",
            Self::V6 => "6",
        }
    }
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
            Ok(IpAddr::V6(ip)) => Ok(Self {
                family: RuleFamily::V6,
                text: ip.to_string(),
            }),
            Err(_) => Err(name_rejected(trimmed)),
        }
    }

    /// Validate `address/prefix`, keeping the prefix within its family's width.
    fn parse_cidr(entry: &str, address: &str, prefix: &str) -> Result<Self, String> {
        let (family, canonical) = match address.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => (RuleFamily::V4, ip.to_string()),
            Ok(IpAddr::V6(ip)) => (RuleFamily::V6, ip.to_string()),
            Err(_) => return Err(name_rejected(entry)),
        };

        let width = match family {
            RuleFamily::V4 => 32,
            RuleFamily::V6 => 128,
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

        Ok(Self {
            family,
            text: format!("{canonical}/{bits}"),
        })
    }
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
    /// The supervisor's record format: `<family> <verdict> <address> <proto> <port>`.
    ///
    /// Five fixed fields keep the script's `read` trivial and its quoting
    /// total; `-` stands in for an absent protocol/port so the field count
    /// never varies.
    fn render(&self) -> String {
        let (protocol, port) = match self.port {
            Some((protocol, port)) => (protocol.to_string(), port.to_string()),
            None => ("-".to_string(), "-".to_string()),
        };
        format!(
            "{} {} {} {} {}",
            self.address.family.tag(),
            self.verdict.target(),
            self.address.text,
            protocol,
            port
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

/// `iptables` calls the supervisor makes regardless of rule count: per family a
/// chain creation, the loopback exemption, the terminal verdict, and the
/// `OUTPUT` hook.
pub(crate) const BASE_RULE_COMMANDS: u32 = 8;

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

    pub(crate) fn v4_terminal(&self) -> RuleVerdict {
        self.v4_terminal
    }

    pub(crate) fn v6_terminal(&self) -> RuleVerdict {
        self.v6_terminal
    }

    /// How many `iptables` calls installing this plan takes, used to size the
    /// rule-installation budget.
    pub(crate) fn command_count(&self) -> u32 {
        BASE_RULE_COMMANDS + self.rules.len() as u32
    }

    /// The rules file handed to the supervisor, one record per line.
    ///
    /// Empty when the plan is terminal-only; the supervisor's loop then runs
    /// zero times and the chain is just loopback plus the terminal verdict.
    pub(crate) fn render(&self) -> String {
        let mut out = String::new();
        for rule in &self.rules {
            out.push_str(&rule.render());
            out.push('\n');
        }
        out
    }
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

    #[test]
    fn a_block_policy_closes_both_families_and_accepts_its_allowlist() {
        let plan = EgressPlan::for_policy(&request(NetworkPolicy::Block, &["10.0.0.0/8"], &[]))
            .expect("a CIDR allowlist is enforceable");

        assert_eq!(plan.render(), "4 ACCEPT 10.0.0.0/8 - -\n");
        assert_eq!(plan.v4_terminal(), RuleVerdict::Drop);
        assert_eq!(plan.v6_terminal(), RuleVerdict::Drop);
    }

    #[test]
    fn an_allow_policy_keeps_both_families_open_and_drops_its_denylist() {
        let plan = EgressPlan::for_policy(&request(NetworkPolicy::Allow, &[], &["192.0.2.0/24"]))
            .expect("a CIDR denylist is enforceable");

        assert_eq!(plan.render(), "4 DROP 192.0.2.0/24 - -\n");
        assert_eq!(plan.v4_terminal(), RuleVerdict::Accept);
        assert_eq!(plan.v6_terminal(), RuleVerdict::Accept);
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
            plan.render(),
            "4 DROP 192.0.2.1 - -\n4 ACCEPT 0.0.0.0/0 - -\n"
        );
    }

    #[test]
    fn a_v6_rule_is_tagged_for_ip6tables() {
        let plan = EgressPlan::for_policy(&request(NetworkPolicy::Block, &["2001:db8::/32"], &[]))
            .expect("a v6 CIDR is enforceable");

        assert_eq!(plan.render(), "6 ACCEPT 2001:db8::/32 - -\n");
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

        assert_eq!(plan.render(), "4 ACCEPT 10.0.2.2 tcp 3128\n");
        assert_eq!(plan.v4_terminal(), RuleVerdict::Drop);
        assert_eq!(plan.v6_terminal(), RuleVerdict::Drop);
    }

    /// The budget must track the rule list, or a long allowlist would be given
    /// the same time as a single endpoint.
    #[test]
    fn the_command_count_grows_with_the_rule_list() {
        assert_eq!(
            EgressPlan::for_proxy(Ipv4Addr::new(10, 0, 2, 2), 3128).command_count(),
            BASE_RULE_COMMANDS + 1
        );

        let plan = EgressPlan::for_policy(&request(
            NetworkPolicy::Block,
            &["10.0.0.0/8", "192.0.2.0/24"],
            &["203.0.113.7"],
        ))
        .expect("a mixed policy is enforceable");
        assert_eq!(plan.command_count(), BASE_RULE_COMMANDS + 3);
    }

    #[test]
    fn a_policy_with_no_host_rules_renders_no_records() {
        let plan = EgressPlan::for_policy(&request(NetworkPolicy::Block, &[], &[]))
            .expect("a bare block policy is enforceable");

        assert!(plan.render().is_empty());
        assert_eq!(plan.command_count(), BASE_RULE_COMMANDS);
    }
}
