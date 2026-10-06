// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared ProcessContainer network-policy helpers.

use crate::mxc_common::audit::{AuditEvent, AuditEventName, OperationStatus};
use crate::mxc_common::models::{ContainerPolicy, ContainmentBackend, NetworkAction, ProxyAddress};

pub(crate) const INTERNET_CLIENT_CAPABILITY: &str = "internetClient";
pub(crate) const PRIVATE_NETWORK_CAPABILITY: &str = "privateNetworkClientServer";
pub(crate) const CAPABILITIES_ENFORCEMENT_MODE: &str = "capabilities";
const POLICY_OWNED_NETWORK_CAPABILITIES: [&str; 4] = [
    INTERNET_CLIENT_CAPABILITY,
    "internetClientServer",
    PRIVATE_NETWORK_CAPABILITY,
    "networkLoopback",
];

pub(crate) fn allows_network_egress(policy: &ContainerPolicy) -> bool {
    policy
        .network_egress
        .as_ref()
        .is_some_and(|egress| egress.default == NetworkAction::Allow || !egress.allow.is_empty())
}

pub(crate) fn audit_egress_default(policy: &ContainerPolicy) -> &'static str {
    match policy
        .network_egress
        .as_ref()
        .map_or(NetworkAction::Deny, |egress| egress.default)
    {
        NetworkAction::Allow => "allow",
        NetworkAction::Deny => "block",
    }
}

pub(crate) fn network_policy_applied_record(
    policy: &ContainerPolicy,
    identity: &str,
    tier: &str,
    proxy_address: Option<&ProxyAddress>,
    status: OperationStatus,
) -> AuditEvent {
    AuditEvent::new(AuditEventName::NetworkPolicyApplied)
        .str("backend", ContainmentBackend::ProcessContainer.wire_name())
        .str("identity", identity)
        .str("tier", tier)
        .str("enforcement_mode", CAPABILITIES_ENFORCEMENT_MODE)
        .str("default_policy", audit_egress_default(policy))
        .u64(
            "proxy_port",
            proxy_address.map_or(0, |address| address.port as u64),
        )
        .u64("firewall_rules_created", 0)
        .bool("firewall_applied", false)
        .str("status", status.as_str())
}

pub(crate) fn ensure_capability(capabilities: &mut Vec<String>, capability: &str) {
    if !capabilities
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(capability))
    {
        capabilities.push(capability.to_string());
    }
}

pub(crate) fn add_default_network_capabilities(
    policy: &ContainerPolicy,
    capabilities: &mut Vec<String>,
) {
    if policy.network_egress.is_some() || policy.network_ingress.is_some() {
        capabilities.retain(|capability| {
            !POLICY_OWNED_NETWORK_CAPABILITIES
                .iter()
                .any(|owned| capability.eq_ignore_ascii_case(owned))
        });
    }

    if allows_network_egress(policy) {
        ensure_capability(capabilities, INTERNET_CLIENT_CAPABILITY);
    }

    if policy
        .network_ingress
        .as_ref()
        .is_some_and(|ingress| ingress.default == NetworkAction::Allow)
    {
        ensure_capability(capabilities, PRIVATE_NETWORK_CAPABILITY);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_common::models::{NetworkEgressPolicy, NetworkIngressPolicy};

    #[test]
    fn directional_egress_defaults_and_rules_select_capability() {
        let mut policy = ContainerPolicy {
            network_egress: Some(NetworkEgressPolicy {
                default: NetworkAction::Deny,
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(!allows_network_egress(&policy));

        policy.network_egress = Some(NetworkEgressPolicy {
            default: NetworkAction::Allow,
            ..Default::default()
        });
        assert!(allows_network_egress(&policy));

        policy.network_egress = Some(NetworkEgressPolicy {
            default: NetworkAction::Deny,
            allow: vec![Default::default()],
            ..Default::default()
        });
        assert!(allows_network_egress(&policy));
    }

    #[test]
    fn default_network_capabilities_are_deduplicated_case_insensitively() {
        let policy = ContainerPolicy {
            network_egress: Some(NetworkEgressPolicy {
                default: NetworkAction::Allow,
                ..Default::default()
            }),
            network_ingress: Some(NetworkIngressPolicy {
                default: NetworkAction::Allow,
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut capabilities = vec![
            "InternetClient".to_string(),
            "PRIVATENETWORKCLIENTSERVER".to_string(),
        ];

        add_default_network_capabilities(&policy, &mut capabilities);

        assert_eq!(capabilities.len(), 2);
    }

    #[test]
    fn directional_networking_uses_capabilities_for_both_directions() {
        let policy = ContainerPolicy {
            network_egress: Some(NetworkEgressPolicy {
                default: NetworkAction::Allow,
                ..Default::default()
            }),
            network_ingress: Some(NetworkIngressPolicy {
                default: NetworkAction::Allow,
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut capabilities = Vec::new();

        add_default_network_capabilities(&policy, &mut capabilities);

        assert_eq!(
            capabilities,
            vec![
                INTERNET_CLIENT_CAPABILITY.to_string(),
                PRIVATE_NETWORK_CAPABILITY.to_string()
            ]
        );
    }

    #[test]
    fn audit_default_describes_directional_egress_not_allowed_exceptions() {
        let mut policy = ContainerPolicy::default();
        assert_eq!(audit_egress_default(&policy), "block");

        policy.network_egress = Some(NetworkEgressPolicy {
            default: NetworkAction::Deny,
            allow: vec![Default::default()],
            ..Default::default()
        });
        assert_eq!(audit_egress_default(&policy), "block");

        policy.network_egress = Some(NetworkEgressPolicy {
            default: NetworkAction::Allow,
            ..Default::default()
        });
        assert_eq!(audit_egress_default(&policy), "allow");
    }

    #[test]
    fn directional_networking_replaces_caller_owned_network_capabilities() {
        let policy = ContainerPolicy {
            network_egress: Some(NetworkEgressPolicy {
                default: NetworkAction::Deny,
                ..Default::default()
            }),
            network_ingress: Some(NetworkIngressPolicy {
                default: NetworkAction::Allow,
                host_loopback: NetworkAction::Deny,
            }),
            ..Default::default()
        };
        let mut capabilities = vec![
            "InternetClient".to_string(),
            "internetClientServer".to_string(),
            "PRIVATEnetworkCLIENTserver".to_string(),
            "NetworkLoopback".to_string(),
            "registryRead".to_string(),
        ];

        add_default_network_capabilities(&policy, &mut capabilities);

        assert_eq!(
            capabilities,
            vec![
                "registryRead".to_string(),
                PRIVATE_NETWORK_CAPABILITY.to_string()
            ]
        );
    }

    #[test]
    fn omitted_network_sections_preserve_caller_owned_capabilities() {
        let policy = ContainerPolicy::default();
        let mut capabilities = vec![
            INTERNET_CLIENT_CAPABILITY.to_string(),
            "networkLoopback".to_string(),
        ];

        add_default_network_capabilities(&policy, &mut capabilities);

        assert_eq!(
            capabilities,
            vec![
                INTERNET_CLIENT_CAPABILITY.to_string(),
                "networkLoopback".to_string()
            ]
        );
    }
}
