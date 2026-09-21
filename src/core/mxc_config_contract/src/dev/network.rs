// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::num::NonZeroU16;

use super::primitives::{NonEmptyVec, OptionalField};

string_enum! {
    /// The action applied by a directional network policy.
    #[derive(Debug)]
    pub enum NetworkAction {
        /// Permit matching traffic.
        Allow => ["allow"],
        /// Drop matching traffic.
        Deny => ["deny"],
    }
}

string_enum! {
    /// The transport protocol a port selector matches.
    #[derive(Debug)]
    pub enum NetworkProtocol {
        /// Match TCP traffic.
        Tcp => ["tcp"],
        /// Match UDP traffic.
        Udp => ["udp"],
        /// Match ICMP traffic. ICMP takes no port.
        Icmp => ["icmp"],
        /// Match any transport protocol.
        Any => ["any"],
    }
}

/// A CIDR destination, optionally excluding narrower ranges within it.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkPeer {
    /// The IPv4 or IPv6 CIDR this destination matches.
    pub cidr: String,
    /// Optional CIDRs excluded from this destination.
    #[serde(default)]
    pub except: OptionalField<Vec<String>>,
}

/// A protocol and destination-port selector.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkPort {
    /// Optional destination port. Omission matches every port.
    #[serde(default)]
    pub port: OptionalField<NonZeroU16>,
    /// Optional inclusive end of a destination-port range. Requires `port`.
    #[serde(default)]
    pub end_port: OptionalField<NonZeroU16>,
    /// Optional transport protocol. Defaults to `any`.
    #[serde(default)]
    pub protocol: OptionalField<NetworkProtocol>,
}

/// One outbound rule, matching destinations and ports.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkRule {
    /// Optional destination CIDRs. Omission matches both IP families.
    #[serde(default)]
    pub to: OptionalField<NonEmptyVec<NetworkPeer>>,
    /// Optional destination protocols and ports. Omission matches all.
    #[serde(default)]
    pub ports: OptionalField<NonEmptyVec<NetworkPort>>,
}

/// Outbound network policy.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkEgress {
    /// Optional action applied when no explicit rule matches.
    #[serde(default)]
    pub default: OptionalField<NetworkAction>,
    /// Optional explicit allow rules.
    #[serde(default)]
    pub allow: OptionalField<Vec<NetworkRule>>,
    /// Optional explicit deny rules. Deny takes precedence over allow.
    #[serde(default)]
    pub deny: OptionalField<Vec<NetworkRule>>,
}

/// Inbound and host-loopback network policy.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkIngress {
    /// Optional default action for private-network inbound traffic.
    #[serde(default)]
    pub default: OptionalField<NetworkAction>,
    /// Optional bidirectional host-loopback connectivity action.
    #[serde(default)]
    pub host_loopback: OptionalField<NetworkAction>,
}

/// Network access policy shared by the stable containment backends.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Network {
    /// Optional outbound network rules.
    #[serde(default)]
    pub egress: OptionalField<NetworkEgress>,
    /// Optional inbound and host-loopback network rules.
    #[serde(default)]
    pub ingress: OptionalField<NetworkIngress>,
}
