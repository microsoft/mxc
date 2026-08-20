// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::num::NonZeroU16;

use super::primitives::{OptionalField, True};

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

/// One of the proxy configurations accepted by the `0.7.0-alpha` contract.
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

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkEgressAllowDenyTo {
    pub cidr: String,
    pub except: OptionalField<Vec<String>>,
}

string_enum! {
    /// The mechanism used to enforce network policy.
    #[derive(Debug)]
    pub enum NetworkEgressProtocol {
        /// Enforce policy through containment capabilities.
        Tcp => ["tcp"],
        /// Enforce policy through UDP.
        Udp => ["udp"],
        /// Enforce policy through ICMP
        Icmp => ["icmp"],
        /// Enforce policy through any
        Any => ["any"],
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkIngressAllowDenyPorts {
    pub port: OptionalField<NonZeroU16>,
    pub end_port: OptionalField<NonZeroU16>,
    pub protocol: OptionalField<NetworkEgressProtocol>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkEgressAllowDenyRules {
    /// Optional hostnames to allow or deny.
    #[serde(default)]
    pub to: OptionalField<Vec<NetworkEgressAllowDenyTo>>,
    /// Optional IP addresses to allow or deny.
    #[serde(default)]    
    pub ports: OptionalField<Vec<NetworkIngressAllowDenyPorts>>,
}

/// Network egress settings for the contained process.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkEgress {
    /// Optional default network posture.
    #[serde(default)]
    pub default: OptionalField<DefaultNetworkPolicy>,
    #[serde(default)]
    pub allow: OptionalField<Vec<NetworkEgressAllowDenyRules>>,
    #[serde(default)]
    pub deny: OptionalField<Vec<NetworkEgressAllowDenyRules>>,
}

/// Network ingress settings for the contained process.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkIngress {
    /// Optional default network posture.
    #[serde(default)]
    pub default: OptionalField<DefaultNetworkPolicy>,
    #[serde(default)]
    pub host_loopback: OptionalField<DefaultNetworkPolicy>,
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
