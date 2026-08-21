// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ProcessContainer-specific policy authoring types and wire mapping.

use super::network::has_host_rules;
use super::SandboxPolicy;

/// ProcessContainer settings carried by
/// [`Containment::ProcessContainer`](super::Containment::ProcessContainer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessContainerSection {
    /// Enable least-privilege process creation.
    pub least_privilege: bool,
    /// Enable deny-and-record AppContainer learning mode.
    pub learning_mode: bool,
    /// Additional AppContainer capability names.
    pub capabilities: Vec<String>,
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
            ui: Some(ProcessContainerUiSection::default()),
            network: None,
        }
    }
}

/// ProcessContainer-specific network settings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessContainerNetworkSection {
    /// Package family name or AppContainer profile authorized as proxy peer.
    pub allowed_proxy_peer: Option<String>,
}

/// BaseProcessContainer user-interface settings.
#[derive(Debug, Clone, PartialEq, Eq)]
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

pub(super) fn apply(
    config: &mut serde_json::Value,
    policy: &SandboxPolicy,
    process_container: &ProcessContainerSection,
    containment: &str,
) {
    use serde_json::json;

    config["containment"] = json!(containment);

    let mut capabilities = process_container.capabilities.clone();
    if let Some(net) = &policy.network {
        if net.allow_outbound
            && !capabilities
                .iter()
                .any(|capability| capability.eq_ignore_ascii_case("internetClient"))
        {
            capabilities.push("internetClient".to_string());
        }
        if net.allow_local_network
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
    if let Some(capture_denials) = &policy.capture_denials {
        config["processContainer"]["captureDenials"] = json!({
            "mode": capture_denials.mode.wire(),
            "outputPath": capture_denials.output_path,
            "retainEtl": capture_denials.retain_etl,
        });
    }
    if let Some(network) = config.get_mut("network") {
        if network.get("egress").is_none() && network.get("ingress").is_none() {
            let mode = if has_host_rules(network) {
                "both"
            } else {
                "capabilities"
            };
            network["enforcementMode"] = json!(mode);
        }
    }
}
