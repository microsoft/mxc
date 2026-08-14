// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::num::NonZeroU16;

use super::primitives::{OptionalField, True};

/// The default outbound network policy.
#[derive(Debug, serde::Deserialize)]
pub enum DefaultNetworkPolicy {
    /// Allow outbound network access by default.
    #[serde(rename = "allow")]
    Allow,
    /// Block outbound network access by default.
    #[serde(rename = "block")]
    Block,
}

/// The mechanism used to enforce network policy.
#[derive(Debug, serde::Deserialize)]
pub enum NetworkEnforcementMode {
    /// Enforce policy through containment capabilities.
    #[serde(rename = "capabilities")]
    Capabilities,
    /// Enforce policy through host firewall rules.
    #[serde(rename = "firewall")]
    Firewall,
    /// Enforce policy through both capabilities and firewall rules.
    #[serde(rename = "both")]
    Both,
}

/// One of the proxy configurations accepted by the `0.6.0-alpha` contract.
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
}
