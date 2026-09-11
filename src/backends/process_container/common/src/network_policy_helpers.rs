// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared ProcessContainer network-policy helpers.

use wxc_common::models::{ContainerPolicy, NetworkAction, NetworkEnforcementMode, NetworkPolicy};

pub(crate) const INTERNET_CLIENT_CAPABILITY: &str = "internetClient";
pub(crate) const PRIVATE_NETWORK_CAPABILITY: &str = "privateNetworkClientServer";
const POLICY_OWNED_NETWORK_CAPABILITIES: [&str; 4] = [
    INTERNET_CLIENT_CAPABILITY,
    "internetClientServer",
    PRIVATE_NETWORK_CAPABILITY,
    "networkLoopback",
];

pub(crate) fn allows_network_egress(policy: &ContainerPolicy) -> bool {
    policy.network_egress.as_ref().map_or(
        policy.default_network_policy == NetworkPolicy::Allow,
        |egress| egress.default == NetworkAction::Allow || !egress.allow.is_empty(),
    )
}

pub(crate) fn ensure_capability(capabilities: &mut Vec<String>, capability: &str) {
    if !capabilities
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(capability))
    {
        capabilities.push(capability.to_string());
    }
}

pub(crate) fn uses_network_capabilities(policy: &ContainerPolicy) -> bool {
    // Directional networking has no enforcementMode field. Its capability
    // gates are always required; the legacy mode applies only to legacy fields.
    policy.network_egress.is_some()
        || policy.network_ingress.is_some()
        || matches!(
            policy.network_enforcement_mode,
            NetworkEnforcementMode::Capabilities | NetworkEnforcementMode::Both
        )
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

    let uses_capabilities = uses_network_capabilities(policy);
    if uses_capabilities && allows_network_egress(policy) {
        ensure_capability(capabilities, INTERNET_CLIENT_CAPABILITY);
    }

    if uses_capabilities
        && policy
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
    use wxc_common::models::{NetworkEgressPolicy, NetworkIngressPolicy};

    #[test]
    fn directional_egress_default_overrides_legacy_default() {
        let mut policy = ContainerPolicy {
            default_network_policy: NetworkPolicy::Allow,
            network_egress: Some(NetworkEgressPolicy {
                default: NetworkAction::Deny,
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(!allows_network_egress(&policy));

        policy.default_network_policy = NetworkPolicy::Block;
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
            default_network_policy: NetworkPolicy::Allow,
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
    fn directional_networking_ignores_legacy_enforcement_mode() {
        let policy = ContainerPolicy {
            network_enforcement_mode: NetworkEnforcementMode::Firewall,
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
    fn legacy_networking_preserves_caller_owned_network_capabilities() {
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
