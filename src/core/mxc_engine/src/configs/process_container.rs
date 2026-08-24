// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ProcessContainer-specific configuration types and wire mapping.

use crate::policy::network::{has_host_rules, NetworkFormat};
use crate::policy::{NetworkAction, SandboxPolicy};

/// How denial capture handles ungranted access checks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum CaptureDenialsMode {
    /// Keep the access denied and record the denial.
    #[default]
    Block,
    /// Allow the access and record what would have been denied.
    Allow,
}

impl CaptureDenialsMode {
    pub(crate) fn wire(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Allow => "allow",
        }
    }
}

/// ProcessContainer denial-capture settings.
///
/// Its presence enables capture: the runner records the sandboxed process's
/// ungranted access attempts and writes a JSON denials document, reported
/// through
/// [`SandboxOutputMetadata::capture_denials`](wxc_common::models::SandboxOutputMetadata).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
#[non_exhaustive]
pub struct CaptureDenialsSection {
    /// How each ungranted access check is handled while it is recorded.
    pub mode: CaptureDenialsMode,
    /// Absolute path for the JSON denials document.
    ///
    /// The runner stamps a per-run identifier into the file stem
    /// (`denials.json` -> `denials.<run-id>.json`) and reports the actual path.
    /// When `None`, a managed per-run temporary file is used. The parent
    /// directory must already exist.
    pub output_path: Option<String>,
    /// Preserve the sealed ETL trace and report its path in output metadata.
    pub retain_etl: bool,
}

/// ProcessContainer settings.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProcessContainerSection {
    /// Enable least-privilege process creation.
    pub least_privilege: bool,
    /// Enable deny-and-record AppContainer learning mode.
    pub learning_mode: bool,
    /// Additional AppContainer capability names.
    pub capabilities: Vec<String>,
    /// Optional denial-capture settings.
    pub capture_denials: Option<CaptureDenialsSection>,
    /// Optional BaseProcessContainer user-interface settings.
    pub ui: Option<ProcessContainerUiSection>,
    /// Optional ProcessContainer-specific network settings.
    pub network: Option<ProcessContainerNetworkSection>,
}

impl Default for ProcessContainerSection {
    fn default() -> Self {
        Self {
            least_privilege: false,
            learning_mode: false,
            capabilities: Vec::new(),
            capture_denials: None,
            ui: Some(ProcessContainerUiSection::default()),
            network: None,
        }
    }
}

/// ProcessContainer-specific network settings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProcessContainerNetworkSection {
    /// Package family name or AppContainer profile authorized as proxy peer.
    pub allowed_proxy_peer: Option<String>,
}

/// BaseProcessContainer user-interface settings.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProcessContainerUiSection {
    /// Desktop-resource isolation level.
    pub isolation: ProcessContainerUiIsolation,
    /// Permit desktop system control.
    pub desktop_system_control: bool,
    /// System-settings access level.
    pub system_settings: String,
    /// Permit Input Method Editor access.
    pub ime: bool,
}

impl Default for ProcessContainerUiSection {
    fn default() -> Self {
        Self {
            isolation: ProcessContainerUiIsolation::Container,
            desktop_system_control: false,
            system_settings: "none".to_string(),
            ime: false,
        }
    }
}

/// Desktop-resource isolation level for BaseProcessContainer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProcessContainerUiIsolation {
    Desktop,
    Handles,
    Atoms,
    #[default]
    Container,
}

impl ProcessContainerUiIsolation {
    fn wire(self) -> &'static str {
        match self {
            Self::Desktop => "desktop",
            Self::Handles => "handles",
            Self::Atoms => "atoms",
            Self::Container => "container",
        }
    }
}

pub(crate) fn apply(
    config: &mut serde_json::Value,
    policy: &SandboxPolicy,
    process_container: &ProcessContainerSection,
    network_format: NetworkFormat,
    containment: &str,
) -> Result<(), wxc_common::mxc_error::MxcError> {
    use serde_json::json;

    config["containment"] = json!(containment);

    let mut capabilities = process_container.capabilities.clone();
    if let Some(net) = &policy.network {
        let (allows_internet, allows_local_network) = match network_format {
            NetworkFormat::Legacy => (net.allow_outbound, net.allow_local_network),
            NetworkFormat::Directional => {
                let allows_internet = net.egress.as_ref().is_some_and(|egress| {
                    egress.default == Some(NetworkAction::Allow)
                        || egress.allow.as_ref().is_some_and(|rules| !rules.is_empty())
                });
                let allows_local_network = net
                    .ingress
                    .as_ref()
                    .is_some_and(|ingress| ingress.default == Some(NetworkAction::Allow));
                (allows_internet, allows_local_network)
            }
        };
        if allows_internet
            && !capabilities
                .iter()
                .any(|capability| capability.eq_ignore_ascii_case("internetClient"))
        {
            capabilities.push("internetClient".to_string());
        }
        if allows_local_network
            && !capabilities
                .iter()
                .any(|capability| capability.eq_ignore_ascii_case("privateNetworkClientServer"))
        {
            capabilities.push("privateNetworkClientServer".to_string());
        }
    }

    config["processContainer"] = json!({
        "leastPrivilege": process_container.least_privilege,
        "learningMode": process_container.learning_mode,
        "capabilities": capabilities,
    });
    if let Some(ui) = &process_container.ui {
        config["processContainer"]["ui"] = json!({
            "isolation": ui.isolation.wire(),
            "desktopSystemControl": ui.desktop_system_control,
            "systemSettings": ui.system_settings,
            "ime": ui.ime,
        });
    }
    if let Some(allowed_proxy_peer) = process_container
        .network
        .as_ref()
        .and_then(|network| network.allowed_proxy_peer.as_ref())
    {
        config["processContainer"]["network"] = json!({
            "allowedProxyPeer": allowed_proxy_peer,
        });
    }
    if let Some(capture_denials) = &process_container.capture_denials {
        config["processContainer"]["captureDenials"] = json!({
            "mode": capture_denials.mode.wire(),
            "outputPath": capture_denials.output_path,
            "retainEtl": capture_denials.retain_etl,
        });
    }
    if network_format == NetworkFormat::Legacy {
        if let Some(network) = config.get_mut("network") {
            let mode = if has_host_rules(network) {
                "both"
            } else {
                "capabilities"
            };
            network["enforcementMode"] = json!(mode);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{
        build_wire_config, NetworkEgressSection, NetworkIngressSection, NetworkSection,
        RuntimeConfigSection,
    };

    fn policy(network: Option<NetworkSection>) -> SandboxPolicy {
        SandboxPolicy {
            version: "0.8.0-alpha".to_string(),
            filesystem: None,
            network,
            ui: None,
            timeout_ms: None,
        }
    }

    #[test]
    fn maps_backend_specific_config() {
        let process_container = ProcessContainerSection {
            least_privilege: true,
            learning_mode: true,
            capabilities: vec!["registryRead".to_string()],
            capture_denials: Some(CaptureDenialsSection {
                mode: CaptureDenialsMode::Allow,
                output_path: Some("C:\\capture\\denials.json".to_string()),
                retain_etl: true,
            }),
            ui: Some(ProcessContainerUiSection {
                isolation: ProcessContainerUiIsolation::Atoms,
                desktop_system_control: true,
                system_settings: "read".to_string(),
                ime: true,
            }),
            network: Some(ProcessContainerNetworkSection {
                allowed_proxy_peer: Some("Contoso.Proxy_123".to_string()),
            }),
        };

        let config = build_wire_config(
            &policy(None),
            &crate::policy::Containment::ProcessContainer(process_container),
            Some("sdk-test"),
        )
        .expect("ProcessContainer config should build");

        assert_eq!(config["containment"], "processcontainer");
        assert_eq!(config["processContainer"]["leastPrivilege"], true);
        assert_eq!(config["processContainer"]["learningMode"], true);
        assert_eq!(
            config["processContainer"]["capabilities"],
            serde_json::json!(["registryRead"])
        );
        assert_eq!(config["processContainer"]["ui"]["isolation"], "atoms");
        assert_eq!(
            config["processContainer"]["network"]["allowedProxyPeer"],
            "Contoso.Proxy_123"
        );
        assert!(config.get("network").is_none());
        assert_eq!(
            config["processContainer"]["captureDenials"]["mode"],
            "allow"
        );
        assert_eq!(
            config["processContainer"]["captureDenials"]["retainEtl"],
            true
        );
    }

    #[test]
    fn maps_directional_network_config() {
        let network = NetworkSection {
            egress: Some(NetworkEgressSection {
                default: Some(NetworkAction::Deny),
                ..Default::default()
            }),
            ingress: Some(NetworkIngressSection {
                default: Some(NetworkAction::Deny),
                host_loopback: Some(NetworkAction::Allow),
            }),
            runtime_config: Some(RuntimeConfigSection {
                network_proxy: Some("http://127.0.0.1:8080".to_string()),
            }),
            ..Default::default()
        };
        let process_container = ProcessContainerSection {
            network: Some(ProcessContainerNetworkSection {
                allowed_proxy_peer: Some("Contoso.Proxy_123".to_string()),
            }),
            ..Default::default()
        };

        let config = build_wire_config(
            &policy(Some(network)),
            &crate::policy::Containment::ProcessContainer(process_container),
            None,
        )
        .expect("directional network config should build");

        assert_eq!(config["network"]["egress"]["default"], "deny");
        assert_eq!(config["network"]["ingress"]["hostLoopback"], "allow");
        assert_eq!(
            config["runtimeConfig"]["networkProxy"],
            "http://127.0.0.1:8080"
        );
        assert!(config["network"].get("defaultPolicy").is_none());
    }

    #[test]
    fn rejects_process_container_network_with_legacy_network_config() {
        let network = NetworkSection {
            allow_outbound: true,
            ..Default::default()
        };
        let process_container = ProcessContainerSection {
            network: Some(ProcessContainerNetworkSection {
                allowed_proxy_peer: Some("Contoso.Proxy_123".to_string()),
            }),
            ..Default::default()
        };

        let error = build_wire_config(
            &policy(Some(network)),
            &crate::policy::Containment::ProcessContainer(process_container),
            None,
        )
        .expect_err("legacy and ProcessContainer directional networking must not mix");

        assert!(error.message.contains("cannot be combined"));
    }
}
