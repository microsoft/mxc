// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ProcessContainer-specific configuration types.

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
            network: None,
        }
    }
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
