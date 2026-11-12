// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Policy enforced by the WSLC egress gateway.
//!
//! MXC renders a [`Policy`] as JSON in [`POLICY_ENV`] on the gateway's init
//! process when it creates the gateway, so the policy is fixed for the
//! container's lifetime. The gateway and MXC share these types, and the
//! gateway image ships with the binaries that render it, so the format has
//! no versioning.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

/// Environment variable holding the policy JSON.
pub const POLICY_ENV: &str = "MXC_GATEWAY_POLICY";

/// Name the workload uses for Windows loopback services.
pub const HOST_LOOPBACK_NAME: &str = "host.wslc.internal";

/// Range MXC assigns the gateway's networks from. The gateway never
/// relays to it, so MXC rejects egress rules entirely inside it.
pub const GATEWAY_SUBNETS: Cidr = Cidr::new(Ipv4Addr::new(10, 231, 0, 0), 16);

/// Never reachable through the filtering proxy, whatever the rules say.
const ALWAYS_DENIED: [Cidr; 6] = [
    Cidr::new(Ipv4Addr::new(0, 0, 0, 0), 8),
    GATEWAY_SUBNETS,
    Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8),
    Cidr::new(Ipv4Addr::new(169, 254, 0, 0), 16),
    Cidr::new(Ipv4Addr::new(224, 0, 0, 0), 4),
    Cidr::new(Ipv4Addr::new(240, 0, 0, 0), 4),
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Policy {
    /// The gateway's main address on the workload's network, serving DNS
    /// and the proxy.
    pub workload_address: Ipv4Addr,
    /// The gateway's address on its own network, where port-mapping
    /// listeners bind.
    pub egress_address: Ipv4Addr,
    pub proxy_port: u16,
    /// Forward DNS queries the gateway doesn't answer itself; otherwise
    /// refuse them.
    pub forward_dns: bool,
    pub egress: Egress,
    /// Relay TCP to Windows loopback through a second address; `None` refuses
    /// [`HOST_LOOPBACK_NAME`].
    pub host_loopback: Option<HostLoopback>,
    /// Relay the proxy port to this proxy instead of filtering.
    pub custom_proxy: Option<CustomProxy>,
    pub port_mappings: Vec<PortMapping>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Egress {
    pub default: Action,
    pub allow: Vec<Rule>,
    pub deny: Vec<Rule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
}

/// Matches TCP to any of `to`. `ports: None` matches every port; an empty
/// list matches none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Rule {
    pub to: Vec<Target>,
    pub ports: Option<Vec<PortRange>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Target {
    pub cidr: Cidr,
    pub except: Vec<Cidr>,
}

/// Inclusive TCP port range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostLoopback {
    pub relay_address: Ipv4Addr,
    pub prefix_length: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CustomProxy {
    /// Proxy hostname the workload uses; the gateway's DNS answers it with
    /// `workload_address`.
    pub name: Option<String>,
    /// Proxy address. `None` relays to [`HOST_LOOPBACK_NAME`].
    pub address: Option<Ipv4Addr>,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PortMapping {
    pub listen_port: u16,
    pub workload_address: Ipv4Addr,
    pub workload_port: u16,
}

/// IPv4 network, written as `a.b.c.d/n` with no host bits set.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    network: u32,
    prefix_length: u8,
}

impl Cidr {
    /// Host bits in `address` are cleared.
    pub const fn new(address: Ipv4Addr, prefix_length: u8) -> Self {
        assert!(prefix_length <= 32);
        let network = u32::from_be_bytes(address.octets()) & Self::mask(prefix_length);
        Self {
            network,
            prefix_length,
        }
    }

    const fn mask(prefix_length: u8) -> u32 {
        if prefix_length == 0 {
            0
        } else {
            u32::MAX << (32 - prefix_length)
        }
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & Self::mask(self.prefix_length) == self.network
    }

    /// Whether every address in `other` is in `self`.
    pub fn contains_network(&self, other: &Cidr) -> bool {
        other.prefix_length >= self.prefix_length && self.contains(Ipv4Addr::from(other.network))
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", Ipv4Addr::from(self.network), self.prefix_length)
    }
}

impl fmt::Debug for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for Cidr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (address, prefix_length) = s
            .split_once('/')
            .ok_or_else(|| format!("{s} is not a.b.c.d/n"))?;
        let address: Ipv4Addr = address
            .parse()
            .map_err(|_| format!("{s} has an invalid IPv4 address"))?;
        let prefix_length: u8 = prefix_length
            .parse()
            .ok()
            .filter(|n| *n <= 32)
            .ok_or_else(|| format!("{s} has an invalid prefix length"))?;
        let cidr = Cidr::new(address, prefix_length);
        if Ipv4Addr::from(cidr.network) != address {
            return Err(format!("{s} has host bits set"));
        }
        Ok(cidr)
    }
}

impl Serialize for Cidr {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Cidr {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

impl Rule {
    fn matches(&self, ip: Ipv4Addr, port: u16) -> bool {
        let to = self
            .to
            .iter()
            .any(|t| t.cidr.contains(ip) && !t.except.iter().any(|e| e.contains(ip)));
        let port = self
            .ports
            .as_ref()
            .is_none_or(|ports| ports.iter().any(|r| (r.start..=r.end).contains(&port)));
        to && port
    }
}

impl Egress {
    /// Deny rules win over allow rules; `default` applies when no rule
    /// matches. Returns the decision and what made it.
    pub fn check(&self, ip: Ipv4Addr, port: u16) -> (Action, &'static str) {
        if ALWAYS_DENIED.iter().any(|c| c.contains(ip)) {
            return (Action::Deny, "reserved range");
        }
        if self.deny.iter().any(|r| r.matches(ip, port)) {
            return (Action::Deny, "deny rule");
        }
        if self.allow.iter().any(|r| r.matches(ip, port)) {
            return (Action::Allow, "allow rule");
        }
        (self.default, "default")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(s: &str) -> Cidr {
        s.parse().unwrap()
    }

    fn rule(to: &[(&str, &[&str])], ports: Option<&[(u16, u16)]>) -> Rule {
        Rule {
            to: to
                .iter()
                .map(|(c, except)| Target {
                    cidr: cidr(c),
                    except: except.iter().map(|e| cidr(e)).collect(),
                })
                .collect(),
            ports: ports.map(|p| {
                p.iter()
                    .map(|&(start, end)| PortRange { start, end })
                    .collect()
            }),
        }
    }

    fn egress(default: Action, allow: Vec<Rule>, deny: Vec<Rule>) -> Egress {
        Egress {
            default,
            allow,
            deny,
        }
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn cidrs_parse_only_as_networks() {
        assert_eq!(cidr("10.1.0.0/16").to_string(), "10.1.0.0/16");
        assert_eq!(cidr("0.0.0.0/0").to_string(), "0.0.0.0/0");
        for bad in ["10.1.0.1/16", "10.1.0.0", "10.1.0.0/33", "::1/128", "x/8"] {
            assert!(bad.parse::<Cidr>().is_err(), "{bad} parsed");
        }
    }

    #[test]
    fn a_network_contains_only_networks_inside_it() {
        let subnets = GATEWAY_SUBNETS;
        assert!(subnets.contains_network(&cidr("10.231.4.0/24")));
        assert!(subnets.contains_network(&cidr("10.231.0.0/16")));
        assert!(!subnets.contains_network(&cidr("10.0.0.0/8")));
        assert!(!subnets.contains_network(&cidr("10.232.0.0/24")));
    }

    #[test]
    fn deny_rules_win_and_the_default_applies_when_nothing_matches() {
        let e = egress(
            Action::Deny,
            vec![rule(&[("10.0.0.0/8", &["10.9.0.0/16"])], None)],
            vec![rule(&[("10.5.0.0/16", &[])], None)],
        );
        assert_eq!(e.check(ip("10.1.2.3"), 443).0, Action::Allow);
        assert_eq!(e.check(ip("10.5.2.3"), 443), (Action::Deny, "deny rule"));
        assert_eq!(e.check(ip("10.9.2.3"), 443), (Action::Deny, "default"));
        assert_eq!(e.check(ip("8.8.8.8"), 443), (Action::Deny, "default"));

        let open = egress(
            Action::Allow,
            vec![],
            vec![rule(&[("8.8.8.8/32", &[])], None)],
        );
        assert_eq!(open.check(ip("1.1.1.1"), 80), (Action::Allow, "default"));
        assert_eq!(open.check(ip("8.8.8.8"), 80).0, Action::Deny);
    }

    #[test]
    fn port_ranges_are_inclusive_and_an_empty_list_matches_nothing() {
        let e = egress(
            Action::Deny,
            vec![
                rule(&[("1.0.0.0/8", &[])], Some(&[(80, 80), (8000, 8010)])),
                rule(&[("2.0.0.0/8", &[])], Some(&[])),
            ],
            vec![],
        );
        for (port, allowed) in [
            (80, true),
            (81, false),
            (8000, true),
            (8010, true),
            (8011, false),
        ] {
            assert_eq!(
                e.check(ip("1.2.3.4"), port).0 == Action::Allow,
                allowed,
                "port {port}"
            );
        }
        assert_eq!(e.check(ip("2.2.3.4"), 80).0, Action::Deny);
    }

    #[test]
    fn reserved_ranges_are_denied_even_when_allowed() {
        let e = egress(
            Action::Allow,
            vec![rule(&[("0.0.0.0/0", &[])], None)],
            vec![],
        );
        for reserved in [
            "0.1.2.3",
            "10.231.0.2",
            "127.0.0.1",
            "169.254.73.254",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert_eq!(
                e.check(ip(reserved), 80),
                (Action::Deny, "reserved range"),
                "{reserved}"
            );
        }
        assert_eq!(e.check(ip("10.230.0.2"), 80).0, Action::Allow);
    }

    #[test]
    fn the_policy_round_trips_and_rejects_unknown_fields() {
        let policy = Policy {
            workload_address: ip("10.231.1.2"),
            egress_address: ip("10.231.2.2"),
            proxy_port: 3128,
            forward_dns: true,
            egress: egress(
                Action::Deny,
                vec![rule(
                    &[("20.0.0.0/8", &["20.1.0.0/16"])],
                    Some(&[(443, 443)]),
                )],
                vec![],
            ),
            host_loopback: Some(HostLoopback {
                relay_address: ip("10.231.1.3"),
                prefix_length: 24,
            }),
            custom_proxy: None,
            port_mappings: vec![PortMapping {
                listen_port: 18080,
                workload_address: ip("10.231.1.4"),
                workload_port: 8080,
            }],
        };
        let json = serde_json::to_string(&policy).unwrap();
        assert!(json.contains(r#""cidr":"20.0.0.0/8""#), "{json}");
        assert_eq!(serde_json::from_str::<Policy>(&json).unwrap(), policy);

        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value["extra"] = true.into();
        assert!(serde_json::from_value::<Policy>(value).is_err());
    }
}
