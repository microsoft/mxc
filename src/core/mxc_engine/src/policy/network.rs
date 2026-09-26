// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Network policy authoring types.

#[cfg(test)]
#[allow(dead_code)]
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum ProxySpec {
    BuiltinTestServer,
    Localhost(u16),
}

/// Network section of a [`SandboxPolicy`](super::SandboxPolicy).
///
/// The v1 high-level SDK exposes directional policy only. Exact legacy
/// configuration remains available through the raw configuration parser.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct NetworkSection {
    // Retained only for legacy internal tests that exercise historical
    // conversion behavior. They are absent from production builds.
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) allow_outbound: bool,
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) allow_local_network: bool,
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) allowed_hosts: Vec<String>,
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) blocked_hosts: Vec<String>,
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) proxy: Option<ProxySpec>,
    /// Outbound network policy.
    #[serde(default)]
    pub egress: Option<NetworkEgressSection>,
    /// Inbound and host-loopback network policy.
    #[serde(default)]
    pub ingress: Option<NetworkIngressSection>,
    /// Runtime values supplied separately from sandbox policy.
    #[serde(default)]
    pub runtime_config: Option<RuntimeConfigSection>,
}

/// Allow or deny a network action.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum NetworkAction {
    Allow,
    #[default]
    Deny,
}

/// Transport protocol selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Icmp,
    Any,
}

/// CIDR network peer.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct NetworkPeerSection {
    pub cidr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub except: Option<Vec<String>>,
}

impl NetworkPeerSection {
    /// Creates a peer matching `cidr` with no exclusions.
    pub fn new(cidr: impl Into<String>) -> Self {
        Self {
            cidr: cidr.into(),
            except: None,
        }
    }
}

/// Protocol and destination-port selector.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct NetworkPortSection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<NetworkProtocol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_port: Option<u16>,
}

/// Outbound network rule.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct NetworkRuleSection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<Vec<NetworkPeerSection>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ports: Option<Vec<NetworkPortSection>>,
}

/// Outbound network policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct NetworkEgressSection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<NetworkAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow: Option<Vec<NetworkRuleSection>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny: Option<Vec<NetworkRuleSection>>,
}

/// Inbound and host-loopback network policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct NetworkIngressSection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<NetworkAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_loopback: Option<NetworkAction>,
}

/// Runtime values supplied separately from sandbox policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RuntimeConfigSection {
    /// HTTP/S proxy URL. Host-process backends require localhost; WSLc requires
    /// a container-routable endpoint and does not filter egress through it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_proxy: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::NetworkAction;

    #[test]
    fn network_action_defaults_to_deny() {
        assert_eq!(NetworkAction::default(), NetworkAction::Deny);
    }
}
