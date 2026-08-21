// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared ProcessContainer network-policy helpers.

use wxc_common::models::{ContainerPolicy, NetworkAction, NetworkEnforcementMode, NetworkPolicy};

pub(crate) const INTERNET_CLIENT_CAPABILITY: &str = "internetClient";
pub(crate) const PRIVATE_NETWORK_CAPABILITY: &str = "privateNetworkClientServer";

pub(crate) fn allows_network_egress(policy: &ContainerPolicy) -> bool {
    policy.network_egress.as_ref().map_or(
        policy.default_network_policy == NetworkPolicy::Allow,
        |egress| egress.default == NetworkAction::Allow,
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

pub(crate) fn add_default_network_capabilities(
    policy: &ContainerPolicy,
    capabilities: &mut Vec<String>,
) {
    let uses_capabilities = matches!(
        policy.network_enforcement_mode,
        NetworkEnforcementMode::Capabilities | NetworkEnforcementMode::Both
    );
    if uses_capabilities && allows_network_egress(policy) {
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
}
