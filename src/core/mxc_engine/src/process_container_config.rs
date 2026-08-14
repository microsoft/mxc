// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ProcessContainer-specific authoring types and wire configuration.

use serde_json::json;

use crate::policy::SandboxPolicy;

/// Windows ProcessContainer settings carried by
/// [`Containment::ProcessContainer`](crate::Containment::ProcessContainer).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessContainer {
    /// Enforce least-privilege mode.
    pub least_privilege: bool,
    /// Additional AppContainer capabilities, such as `registryRead`.
    pub capabilities: Vec<String>,
}

pub(crate) fn apply_process_container_backend(
    config: &mut serde_json::Value,
    policy: &SandboxPolicy,
    process_container: &ProcessContainer,
) {
    config["containment"] = json!("processcontainer");
    config["processContainer"] = json!({
        "leastPrivilege": process_container.least_privilege,
        "capabilities": capabilities(policy, process_container),
        "ui": {
            "isolation": "container",
            "desktopSystemControl": false,
            "systemSettings": "none",
            "ime": false,
        },
    });

    if let Some(capture_denials) = &policy.capture_denials {
        config["processContainer"]["captureDenials"] = json!({
            "mode": capture_denials.mode.wire(),
            "outputPath": capture_denials.output_path,
            "retainEtl": capture_denials.retain_etl,
        });
    }

    if let Some(network_config) = config.get_mut("network") {
        let has_host_rules = policy.network.as_ref().is_some_and(|network| {
            !network.allowed_hosts.is_empty() || !network.blocked_hosts.is_empty()
        });
        network_config["enforcementMode"] = json!(if has_host_rules {
            "both"
        } else {
            "capabilities"
        });
    }
}

fn capabilities(policy: &SandboxPolicy, process_container: &ProcessContainer) -> Vec<String> {
    let mut capabilities = Vec::new();
    if let Some(network) = &policy.network {
        if network.allow_outbound {
            capabilities.push("internetClient".to_string());
        }
        if network.allow_local_network {
            capabilities.push("privateNetworkClientServer".to_string());
        }
    }

    for capability in &process_container.capabilities {
        if !capabilities
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(capability))
        {
            capabilities.push(capability.clone());
        }
    }
    capabilities
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::NetworkSection;

    fn minimal_policy() -> SandboxPolicy {
        SandboxPolicy {
            version: "0.7.0-alpha".to_string(),
            filesystem: None,
            network: None,
            ui: None,
            timeout_ms: None,
            capture_denials: None,
        }
    }

    #[test]
    fn merges_network_and_explicit_capabilities_case_insensitively() {
        let policy = SandboxPolicy {
            network: Some(NetworkSection {
                allow_outbound: true,
                allow_local_network: true,
                ..Default::default()
            }),
            ..minimal_policy()
        };
        let process_container = ProcessContainer {
            capabilities: vec!["INTERNETCLIENT".to_string(), "registryRead".to_string()],
            ..Default::default()
        };

        assert_eq!(
            capabilities(&policy, &process_container),
            vec![
                "internetClient",
                "privateNetworkClientServer",
                "registryRead"
            ]
        );
    }

    #[test]
    fn emits_only_the_process_container_authoring_shape() {
        let mut config = json!({
            "network": {
                "defaultPolicy": "block",
                "allowedHosts": [],
                "blockedHosts": [],
            }
        });

        apply_process_container_backend(
            &mut config,
            &minimal_policy(),
            &ProcessContainer::default(),
        );

        assert_eq!(config["containment"], "processcontainer");
        assert_eq!(
            config["processContainer"],
            json!({
                "leastPrivilege": false,
                "capabilities": [],
                "ui": {
                    "isolation": "container",
                    "desktopSystemControl": false,
                    "systemSettings": "none",
                    "ime": false,
                },
            })
        );
        assert_eq!(config["network"]["enforcementMode"], "capabilities");
    }
}
