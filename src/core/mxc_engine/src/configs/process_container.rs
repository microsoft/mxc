// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ProcessContainer-specific configuration types and wire mapping.

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

/// ProcessContainer denial-capture settings.
///
/// Its presence enables capture: the runner records the sandboxed process's
/// ungranted access attempts and writes a JSON denials document, reported
/// through
/// [`SandboxOutputMetadata::capture_denials`](wxc_common::models::SandboxOutputMetadata).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
#[non_exhaustive]
pub struct CaptureDenials {
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
pub struct ProcessContainer {
    /// Enable least-privilege process creation.
    pub least_privilege: bool,
    /// Enable deny-and-record AppContainer learning mode.
    pub learning_mode: bool,
    /// Additional AppContainer capability names.
    pub capabilities: Vec<String>,
    /// Optional denial-capture settings.
    pub capture_denials: Option<CaptureDenials>,
    /// Optional BaseProcessContainer user-interface settings.
    pub ui: Option<ProcessContainerUi>,
    /// Optional ProcessContainer-specific filesystem settings.
    pub filesystem: Option<ProcessContainerFilesystem>,
    /// Optional ProcessContainer-specific network settings.
    pub network: Option<ProcessContainerNetwork>,
}

impl Default for ProcessContainer {
    fn default() -> Self {
        Self {
            least_privilege: false,
            learning_mode: false,
            capabilities: Vec::new(),
            capture_denials: None,
            ui: Some(ProcessContainerUi::default()),
            filesystem: None,
            network: None,
        }
    }
}

/// ProcessContainer-specific filesystem settings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProcessContainerFilesystem {
    /// Paths that may be enumerated without granting file-content reads.
    pub enumerate_paths: Vec<String>,
}

/// ProcessContainer-specific network settings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProcessContainerNetwork {
    /// Package family name or AppContainer profile authorized as proxy peer.
    pub allowed_proxy_peer: Option<String>,
}

/// BaseProcessContainer user-interface settings.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProcessContainerUi {
    /// Desktop-resource isolation level.
    pub isolation: ProcessContainerUiIsolation,
    /// Permit desktop system control.
    pub desktop_system_control: bool,
    /// System-settings access level.
    pub system_settings: ProcessContainerSystemSettings,
    /// Permit Input Method Editor access.
    pub ime: bool,
}

impl Default for ProcessContainerUi {
    fn default() -> Self {
        Self {
            isolation: ProcessContainerUiIsolation::Container,
            desktop_system_control: false,
            system_settings: ProcessContainerSystemSettings::None,
            ime: false,
        }
    }
}

/// System-settings access level for BaseProcessContainer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProcessContainerSystemSettings {
    /// Permit system parameter and display-setting changes.
    All,
    /// Permit system parameter changes only.
    Parameters,
    /// Permit display-setting changes only.
    Display,
    /// Block system parameter and display-setting changes.
    #[default]
    None,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{
        build_request_with_containment, Containment, NetworkAction, NetworkEgressSection,
        NetworkIngressSection, NetworkSection, RuntimeConfigSection, SandboxPolicy,
    };
    use wxc_common::models::{
        CaptureDenialsMode as RuntimeCaptureDenialsMode, ContainmentBackend,
        NetworkEnforcementCompatibility,
    };

    const TEST_COMMAND: &str = "echo hello";

    fn policy_for_version(version: &str, network: Option<NetworkSection>) -> SandboxPolicy {
        SandboxPolicy {
            version: version.to_string(),
            filesystem: None,
            network,
            ui: None,
            timeout_ms: None,
        }
    }

    #[test]
    fn maps_backend_specific_config() {
        let output_path = std::env::temp_dir()
            .join("mxc-phase13-process-container-denials.json")
            .to_string_lossy()
            .into_owned();
        let process_container = ProcessContainer {
            least_privilege: true,
            learning_mode: true,
            capabilities: vec!["registryRead".to_string()],
            capture_denials: Some(CaptureDenials {
                mode: CaptureDenialsMode::Allow,
                output_path: Some(output_path.clone()),
                retain_etl: true,
            }),
            ui: Some(ProcessContainerUi {
                isolation: ProcessContainerUiIsolation::Atoms,
                desktop_system_control: true,
                system_settings: ProcessContainerSystemSettings::Parameters,
                ime: true,
            }),
            filesystem: Some(ProcessContainerFilesystem {
                enumerate_paths: vec!["C:\\tools".to_string()],
            }),
            network: None,
        };

        let request = build_request_with_containment(
            &policy_for_version("0.9.0-alpha", None),
            &Containment::ProcessContainer(process_container),
            TEST_COMMAND,
            Some("sdk-test"),
        )
        .expect("ProcessContainer request should build");

        let inner = &request.inner;
        assert_eq!(inner.source_contract, None);
        assert_eq!(
            inner.network_enforcement_compatibility,
            NetworkEnforcementCompatibility::Strict
        );
        assert_eq!(inner.containment, ContainmentBackend::ProcessContainer);
        assert!(inner.policy.least_privilege_mode);
        assert!(inner
            .policy
            .capabilities
            .iter()
            .any(|capability| capability == "registryRead"));
        assert!(inner
            .policy
            .capabilities
            .iter()
            .any(|capability| capability == "permissiveLearningMode"));
        assert!(!inner
            .policy
            .capabilities
            .iter()
            .any(|capability| capability == "learningModeLogging"));
        assert_eq!(inner.policy.base_process_ui.isolation, "atoms");
        assert!(inner.policy.base_process_ui.desktop_system_control);
        assert_eq!(inner.policy.base_process_ui.system_settings, "parameters");
        assert!(inner.policy.base_process_ui.ime);
        assert_eq!(inner.policy.enumerate_paths, vec!["C:\\tools"]);
        assert_eq!(inner.policy.allowed_proxy_peer, None);
        assert_eq!(
            inner
                .policy
                .capture_denials
                .as_ref()
                .map(|capture| capture.mode),
            Some(RuntimeCaptureDenialsMode::Allow)
        );
        assert_eq!(
            inner
                .policy
                .capture_denials
                .as_ref()
                .and_then(|capture| capture.output_path.as_deref()),
            Some(output_path.as_str())
        );
        assert!(inner
            .policy
            .capture_denials
            .as_ref()
            .is_some_and(|capture| capture.retain_etl));
    }

    #[test]
    fn maps_directional_network_config() {
        let network = NetworkSection {
            egress: Some(NetworkEgressSection {
                default: Some(NetworkAction::Deny),
                ..Default::default()
            }),
            ingress: Some(NetworkIngressSection {
                default: Some(NetworkAction::Allow),
                host_loopback: Some(NetworkAction::Deny),
            }),
            runtime_config: Some(RuntimeConfigSection {
                network_proxy: Some("http://127.0.0.1:8080".to_string()),
            }),
            ..Default::default()
        };
        let process_container = ProcessContainer {
            network: Some(ProcessContainerNetwork {
                allowed_proxy_peer: Some("Contoso.Proxy_123".to_string()),
            }),
            ..Default::default()
        };

        let request = build_request_with_containment(
            &policy_for_version("0.8.0-alpha", Some(network)),
            &Containment::ProcessContainer(process_container),
            TEST_COMMAND,
            None,
        )
        .expect("directional network request should build");

        assert_eq!(
            request
                .inner
                .policy
                .network_egress
                .as_ref()
                .map(|egress| egress.default),
            Some(wxc_common::models::NetworkAction::Deny)
        );
        assert_eq!(
            request
                .inner
                .policy
                .network_ingress
                .as_ref()
                .map(|ingress| (ingress.default, ingress.host_loopback)),
            Some((
                wxc_common::models::NetworkAction::Allow,
                wxc_common::models::NetworkAction::Deny
            ))
        );
        assert_eq!(
            request
                .inner
                .policy
                .network_proxy
                .address
                .as_ref()
                .and_then(|address| address.original_url.as_deref()),
            Some("http://127.0.0.1:8080")
        );
        assert_eq!(
            request.inner.policy.allowed_proxy_peer.as_deref(),
            Some("Contoso.Proxy_123")
        );
    }

    #[test]
    fn directional_network_adds_required_capabilities() {
        let network = NetworkSection {
            egress: Some(NetworkEgressSection {
                default: Some(NetworkAction::Allow),
                ..Default::default()
            }),
            ingress: Some(NetworkIngressSection {
                default: Some(NetworkAction::Allow),
                ..Default::default()
            }),
            ..Default::default()
        };

        let request = build_request_with_containment(
            &policy_for_version("0.8.0-alpha", Some(network)),
            &Containment::ProcessContainer(ProcessContainer::default()),
            TEST_COMMAND,
            None,
        )
        .expect("directional network request should build");

        assert!(request
            .inner
            .policy
            .capabilities
            .iter()
            .any(|capability| capability == "internetClient"));
        assert!(request
            .inner
            .policy
            .capabilities
            .iter()
            .any(|capability| capability == "privateNetworkClientServer"));
    }

    #[test]
    fn maps_capture_defaults_without_manufacturing_optional_values() {
        let process_container = ProcessContainer {
            capture_denials: Some(CaptureDenials::default()),
            ..Default::default()
        };

        let request = build_request_with_containment(
            &policy_for_version("0.8.0-alpha", None),
            &Containment::ProcessContainer(process_container),
            TEST_COMMAND,
            None,
        )
        .expect("schema 0.8 request should build");

        let capture = request.inner.policy.capture_denials.as_ref().unwrap();
        assert_eq!(capture.mode, RuntimeCaptureDenialsMode::Block);
        assert_eq!(capture.output_path, None);
        assert!(!capture.retain_etl);
    }

    #[test]
    fn rejects_v0_8_process_container_fields_for_legacy_schemas() {
        for (process_container, field) in [
            (
                ProcessContainer {
                    learning_mode: true,
                    ..Default::default()
                },
                "learningMode",
            ),
            (
                ProcessContainer {
                    capture_denials: Some(CaptureDenials::default()),
                    ..Default::default()
                },
                "captureDenials",
            ),
        ] {
            let error = build_request_with_containment(
                &policy_for_version("0.7.0-alpha", None),
                &Containment::ProcessContainer(process_container),
                TEST_COMMAND,
                None,
            )
            .expect_err("schema 0.7 must reject schema 0.8 ProcessContainer fields");

            assert!(error.message.contains(field), "{error:?}");
            assert!(error.message.contains("schema version 0.8"), "{error:?}");
        }
    }

    #[test]
    fn legacy_process_container_omits_v0_8_defaults() {
        let request = build_request_with_containment(
            &policy_for_version("0.7.0-alpha", None),
            &Containment::ProcessContainer(ProcessContainer::default()),
            TEST_COMMAND,
            None,
        )
        .expect("default ProcessContainer should remain valid for schema 0.7");

        assert!(request.inner.policy.capture_denials.is_none());
        assert!(!request
            .inner
            .policy
            .capabilities
            .iter()
            .any(|capability| capability == "learningModeLogging"));
    }

    #[test]
    fn rejects_process_container_network_with_legacy_network_config() {
        let network = NetworkSection {
            allow_outbound: true,
            ..Default::default()
        };
        let process_container = ProcessContainer {
            network: Some(ProcessContainerNetwork {
                allowed_proxy_peer: Some("Contoso.Proxy_123".to_string()),
            }),
            ..Default::default()
        };

        let error = build_request_with_containment(
            &policy_for_version("0.8.0-alpha", Some(network)),
            &Containment::ProcessContainer(process_container),
            TEST_COMMAND,
            None,
        )
        .expect_err("legacy and ProcessContainer directional networking must not mix");

        assert!(error.message.contains("cannot be combined"));
    }
}
