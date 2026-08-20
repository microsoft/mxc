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

/// One of the proxy configurations accepted by the `0.8.0-alpha` contract.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
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
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
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
