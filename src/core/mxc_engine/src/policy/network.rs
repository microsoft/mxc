// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Network policy authoring types.

/// Network section of a [`SandboxPolicy`](super::SandboxPolicy).
///
/// The v1 high-level SDK exposes directional policy only. Exact legacy
/// configuration remains available through the raw configuration parser.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct NetworkSection {
    /// Outbound network policy.
    pub egress: Option<NetworkEgressSection>,
    /// Inbound and host-loopback network policy.
    pub ingress: Option<NetworkIngressSection>,
    /// Runtime values supplied separately from sandbox policy.
    pub runtime_config: Option<RuntimeConfigSection>,
}

/// Allow or deny a network action.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetworkAction {
    Allow,
    #[default]
    Deny,
}

/// Transport protocol selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Icmp,
    Any,
}

/// CIDR network peer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetworkPeerSection {
    pub cidr: String,
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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetworkPortSection {
    pub protocol: Option<NetworkProtocol>,
    pub port: Option<u16>,
    pub end_port: Option<u16>,
}

/// Outbound network rule.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetworkRuleSection {
    pub to: Option<Vec<NetworkPeerSection>>,
    pub ports: Option<Vec<NetworkPortSection>>,
}

/// Outbound network policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetworkEgressSection {
    pub default: Option<NetworkAction>,
    pub allow: Option<Vec<NetworkRuleSection>>,
    pub deny: Option<Vec<NetworkRuleSection>>,
}

/// Inbound and host-loopback network policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetworkIngressSection {
    pub default: Option<NetworkAction>,
    pub host_loopback: Option<NetworkAction>,
}

/// Runtime values supplied separately from sandbox policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RuntimeConfigSection {
    /// HTTP/S proxy URL. Host-process backends require localhost; WSLc requires
    /// a container-routable endpoint and does not filter egress through it.
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
