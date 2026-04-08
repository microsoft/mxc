// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared policy helpers used by multiple containment runners.

use crate::models::{ContainerPolicy, NetworkEnforcementMode, NetworkPolicy};

/// Build the effective capability list from a container policy.
///
/// When network enforcement uses capabilities and the default policy is Allow,
/// ensures `internetClient` is present so the sandboxed process has network access.
pub fn resolve_capabilities(policy: &ContainerPolicy) -> Vec<String> {
    let mut caps = policy.capabilities.clone();
    let use_caps_for_network = matches!(
        policy.network_enforcement_mode,
        NetworkEnforcementMode::Capabilities | NetworkEnforcementMode::Both
    );
    if use_caps_for_network
        && policy.default_network_policy == NetworkPolicy::Allow
        && !caps.iter().any(|c| c == "internetClient")
    {
        caps.push("internetClient".to_string());
    }
    caps
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ContainerPolicy;

    #[test]
    fn adds_internet_client_when_caps_allow() {
        let policy = ContainerPolicy::default();
        let caps = resolve_capabilities(&policy);
        assert!(caps.contains(&"internetClient".to_string()));
    }

    #[test]
    fn does_not_duplicate_internet_client() {
        let policy = ContainerPolicy {
            capabilities: vec!["internetClient".to_string()],
            ..Default::default()
        };
        let caps = resolve_capabilities(&policy);
        assert_eq!(caps.iter().filter(|c| *c == "internetClient").count(), 1);
    }

    #[test]
    fn no_internet_client_when_network_blocked() {
        let policy = ContainerPolicy {
            default_network_policy: NetworkPolicy::Block,
            ..Default::default()
        };
        let caps = resolve_capabilities(&policy);
        assert!(!caps.contains(&"internetClient".to_string()));
    }

    #[test]
    fn no_internet_client_when_firewall_only() {
        let policy = ContainerPolicy {
            network_enforcement_mode: NetworkEnforcementMode::Firewall,
            ..Default::default()
        };
        let caps = resolve_capabilities(&policy);
        assert!(!caps.contains(&"internetClient".to_string()));
    }

    #[test]
    fn preserves_existing_capabilities() {
        let policy = ContainerPolicy {
            capabilities: vec!["registryRead".to_string(), "privateNetwork".to_string()],
            ..Default::default()
        };
        let caps = resolve_capabilities(&policy);
        assert!(caps.contains(&"registryRead".to_string()));
        assert!(caps.contains(&"privateNetwork".to_string()));
        assert!(caps.contains(&"internetClient".to_string()));
    }
}
