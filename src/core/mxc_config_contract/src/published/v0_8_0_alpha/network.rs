// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::primitives::{NonEmptyVec, OptionalField, True};
use std::num::NonZeroU16;

string_enum! {
    /// The default outbound network policy.
    #[derive(Debug)]
    pub enum DefaultNetworkPolicy {
        /// Allow outbound network access by default.
        Allow => ["allow"],
        /// Block outbound network access by default.
        Block => ["block"],
    }
}

string_enum! {
    /// The mechanism used to enforce network policy.
    #[derive(Debug)]
    pub enum NetworkEnforcementMode {
        /// Enforce policy through containment capabilities.
        Capabilities => ["capabilities"],
        /// Enforce policy through host firewall rules.
        Firewall => ["firewall"],
        /// Enforce policy through both capabilities and firewall rules.
        Both => ["both"],
    }
}

/// One of the proxy configurations accepted by the `0.8.0-alpha` contract.
#[derive(Debug, serde::Deserialize)]
pub enum NetworkProxy {
    /// Connect to an existing proxy on a non-zero localhost TCP port.
    #[serde(rename = "localhost")]
    Localhost(NonZeroU16),
    /// Start and use MXC's built-in test proxy.
    #[serde(rename = "builtinTestServer")]
    BuiltinTestServer(True),
    /// Connect through the supplied proxy URL.
    #[serde(rename = "url")]
    Url(String),
}

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

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkPeer {
    pub cidr: String,
    #[serde(default)]
    pub except: OptionalField<Vec<String>>,
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

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkPort {
    #[serde(default)]
    pub port: OptionalField<NonZeroU16>,
    #[serde(default)]
    pub end_port: OptionalField<NonZeroU16>,
    #[serde(default)]
    pub protocol: OptionalField<NetworkProtocol>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkRule {
    /// Optional destination CIDRs. Omission matches both IP families.
    #[serde(default)]
    pub to: OptionalField<NonEmptyVec<NetworkPeer>>,
    /// Optional destination protocols and ports. Omission matches all.
    #[serde(default)]
    pub ports: OptionalField<NonEmptyVec<NetworkPort>>,
}

/// Network egress settings for the contained process.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkEgress {
    /// Optional default network posture.
    #[serde(default)]
    pub default: OptionalField<NetworkAction>,
    #[serde(default)]
    pub allow: OptionalField<Vec<NetworkRule>>,
    #[serde(default)]
    pub deny: OptionalField<Vec<NetworkRule>>,
}

/// Network ingress settings for the contained process.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkIngress {
    /// Optional default network posture.
    #[serde(default)]
    pub default: OptionalField<NetworkAction>,
    #[serde(default)]
    pub host_loopback: OptionalField<NetworkAction>,
}

/// Network access policy shared by the stable containment backends.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Network {
    /// Optional default network posture.
    #[serde(default)]
    pub default_policy: OptionalField<DefaultNetworkPolicy>,
    /// Optional network enforcement mechanism.
    #[serde(default)]
    pub enforcement_mode: OptionalField<NetworkEnforcementMode>,
    /// Optional hosts allowed when the default policy blocks access.
    #[serde(default)]
    pub allowed_hosts: OptionalField<Vec<String>>,
    /// Optional hosts blocked when the default policy allows access.
    #[serde(default)]
    pub blocked_hosts: OptionalField<Vec<String>>,
    /// Optional permission to bind and accept local network connections.
    #[serde(default)]
    pub allow_local_network: OptionalField<bool>,
    /// Optional proxy configuration.
    #[serde(default)]
    pub proxy: OptionalField<NetworkProxy>,
    /// Optional network egress rules.
    #[serde(default)]
    pub egress: OptionalField<NetworkEgress>,
    /// Optional network ingress rules.
    #[serde(default)]
    pub ingress: OptionalField<NetworkIngress>,
}
