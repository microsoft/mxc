// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Network policy authoring types and wire-format helpers.

/// Network proxy configuration, mirroring the SDK union type
/// `{ builtinTestServer: true } | { localhost: number } | { url: string }`.
#[derive(Debug, Clone)]
pub enum ProxySpec {
    /// Route through the built-in test proxy server.
    BuiltinTestServer,
    /// Route through `127.0.0.1:<port>`.
    Localhost(u16),
    /// Route through an explicit proxy URL.
    Url(String),
}

impl<'de> serde::Deserialize<'de> for ProxySpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Raw {
            #[serde(default)]
            builtin_test_server: Option<bool>,
            #[serde(default)]
            localhost: Option<u16>,
            #[serde(default)]
            url: Option<String>,
        }

        let raw = <Raw as serde::Deserialize>::deserialize(deserializer)?;
        match (raw.builtin_test_server, raw.localhost, raw.url) {
            (Some(true), None, None) => Ok(ProxySpec::BuiltinTestServer),
            (Some(false), None, None) => Err(serde::de::Error::custom(
                "network.proxy.builtinTestServer must be true; omit the proxy to disable it",
            )),
            (None, Some(port), None) => Ok(ProxySpec::Localhost(port)),
            (None, None, Some(url)) => Ok(ProxySpec::Url(url)),
            _ => Err(serde::de::Error::custom(
                "network.proxy must set exactly one of builtinTestServer, localhost, or url",
            )),
        }
    }
}

/// Network section of a [`SandboxPolicy`](super::SandboxPolicy).
///
/// The legacy fields preserve schema 0.6 and 0.7 authoring. The directional
/// fields model schema 0.8 and cannot be combined with the legacy fields.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct NetworkSection {
    pub allow_outbound: bool,
    pub allow_local_network: bool,
    pub allowed_hosts: Vec<String>,
    pub blocked_hosts: Vec<String>,
    pub proxy: Option<ProxySpec>,
    /// Schema 0.8 outbound network policy.
    pub egress: Option<NetworkEgressSection>,
    /// Schema 0.8 inbound and host-loopback network policy.
    pub ingress: Option<NetworkIngressSection>,
    /// Schema 0.8 runtime values supplied separately from sandbox policy.
    pub runtime_config: Option<RuntimeConfigSection>,
}

impl NetworkSection {
    pub(super) fn has_directional_fields(&self) -> bool {
        self.egress.is_some() || self.ingress.is_some() || self.runtime_config.is_some()
    }

    pub(super) fn has_legacy_fields(&self) -> bool {
        self.allow_outbound
            || self.allow_local_network
            || !self.allowed_hosts.is_empty()
            || !self.blocked_hosts.is_empty()
            || self.proxy.is_some()
    }
}

/// Allow or deny a network action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkAction {
    Allow,
    Deny,
}

/// Transport protocol selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Icmp,
    Any,
}

/// CIDR network peer.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPeerSection {
    pub cidr: String,
    pub except: Option<Vec<String>>,
}

/// Protocol and destination-port selector.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPortSection {
    pub protocol: Option<NetworkProtocol>,
    pub port: Option<u16>,
    pub end_port: Option<u16>,
}

/// Outbound network rule.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkRuleSection {
    pub to: Option<Vec<NetworkPeerSection>>,
    pub ports: Option<Vec<NetworkPortSection>>,
}

/// Schema 0.8 outbound network policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkEgressSection {
    pub default: Option<NetworkAction>,
    pub allow: Option<Vec<NetworkRuleSection>>,
    pub deny: Option<Vec<NetworkRuleSection>>,
}

/// Schema 0.8 inbound and host-loopback network policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkIngressSection {
    pub default: Option<NetworkAction>,
    pub host_loopback: Option<NetworkAction>,
}

/// Schema 0.8 runtime values supplied separately from sandbox policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeConfigSection {
    /// HTTP/S loopback proxy URL.
    pub network_proxy: Option<String>,
}

pub(super) fn proxy_to_wire(proxy: &ProxySpec) -> serde_json::Value {
    use serde_json::json;
    match proxy {
        ProxySpec::BuiltinTestServer => json!({ "builtinTestServer": true }),
        ProxySpec::Localhost(port) => json!({ "localhost": port }),
        ProxySpec::Url(url) => json!({ "url": url }),
    }
}

/// True when the network section carries any host allow/deny rules.
pub(super) fn has_host_rules(network: &serde_json::Value) -> bool {
    let non_empty = |key: &str| {
        network
            .get(key)
            .and_then(serde_json::Value::as_array)
            .is_some_and(|values| !values.is_empty())
    };
    non_empty("allowedHosts") || non_empty("blockedHosts")
}
