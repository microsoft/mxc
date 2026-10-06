// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Network policy authoring types.

/// Network section of a [`ContainerRequest`](crate::v1::ContainerRequest).
///
/// The V1 SDK exposes directional policy only.
#[derive(Debug, Clone, Default)]
pub struct NetworkPolicy {
    /// Outbound network policy.
    pub egress: Option<NetworkEgressPolicy>,
    /// Inbound and host-loopback network policy.
    pub ingress: Option<NetworkIngressPolicy>,
    /// Runtime values supplied separately from sandbox policy.
    pub runtime_config: Option<NetworkRuntimeConfig>,
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
pub struct NetworkPeerPolicy {
    pub cidr: String,
    pub except: Option<Vec<String>>,
}

impl NetworkPeerPolicy {
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
pub struct NetworkPortPolicy {
    pub protocol: Option<NetworkProtocol>,
    pub port: Option<u16>,
    pub end_port: Option<u16>,
}

/// Outbound network rule.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkRulePolicy {
    pub to: Option<Vec<NetworkPeerPolicy>>,
    pub ports: Option<Vec<NetworkPortPolicy>>,
}

/// Outbound network policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkEgressPolicy {
    pub default: Option<NetworkAction>,
    pub allow: Option<Vec<NetworkRulePolicy>>,
    pub deny: Option<Vec<NetworkRulePolicy>>,
}

/// Inbound and host-loopback network policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkIngressPolicy {
    pub default: Option<NetworkAction>,
    pub host_loopback: Option<NetworkAction>,
}

/// Runtime values supplied separately from sandbox policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkRuntimeConfig {
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
