// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::network::Network;
use super::primitives::{NonEmptyString, OptionalField};

/// The exact version marker accepted by this contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
pub enum Version {
    /// The published `0.6.0-alpha` contract.
    #[serde(rename = "0.6.0-alpha")]
    V0_6_0Alpha,
}

/// Stable containment selections available in `0.6.0-alpha`.
#[derive(Debug, serde::Deserialize)]
pub enum Containment {
    /// Select the host's native process-containment backend.
    #[serde(rename = "process")]
    Process,
    /// Select the Windows ProcessContainer backend.
    #[serde(rename = "processcontainer", alias = "appcontainer")]
    ProcessContainer,
    /// Select the Linux LXC backend.
    #[serde(rename = "lxc")]
    Lxc,
    /// Select the Linux Bubblewrap backend.
    #[serde(rename = "bubblewrap")]
    Bubblewrap,
}

/// Container lifecycle settings.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Lifecycle {
    /// Whether to destroy the container when execution ends.
    #[serde(default)]
    pub destroy_on_exit: OptionalField<bool>,
    /// Whether to preserve applied policy after execution ends.
    #[serde(default)]
    pub preserve_policy: OptionalField<bool>,
}

/// Process execution settings.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Process {
    /// The non-empty command line to execute.
    pub command_line: NonEmptyString,
    /// Optional working directory.
    #[serde(default)]
    pub cwd: OptionalField<String>,
    /// Optional environment entries encoded as `KEY=VALUE` strings.
    #[serde(default)]
    pub env: OptionalField<Vec<String>>,
    /// Optional execution timeout in milliseconds.
    #[serde(default)]
    pub timeout: OptionalField<u32>,
}

/// Filesystem access policy.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Filesystem {
    /// Optional paths granted read-write access.
    #[serde(default)]
    pub readwrite_paths: OptionalField<Vec<String>>,
    /// Optional paths granted read-only access.
    #[serde(default)]
    pub readonly_paths: OptionalField<Vec<String>>,
    /// Optional paths denied access.
    #[serde(default)]
    pub denied_paths: OptionalField<Vec<String>>,
}

/// Operator consent for containment fallback behavior.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Fallback {
    /// Whether the runtime may mutate host filesystem DACLs as a fallback.
    #[serde(default)]
    pub allow_dacl_mutation: OptionalField<bool>,
}

/// Clipboard access granted to the contained process.
#[derive(Debug, serde::Deserialize)]
pub enum UiClipboard {
    /// Deny clipboard reads and writes.
    #[serde(rename = "none")]
    None,
    /// Allow clipboard reads.
    #[serde(rename = "read")]
    Read,
    /// Allow clipboard writes.
    #[serde(rename = "write")]
    Write,
    /// Allow clipboard reads and writes.
    #[serde(rename = "all")]
    All,
}

/// Cross-platform user-interface policy.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Ui {
    /// Whether visible user interface is disabled.
    #[serde(default)]
    pub disable: OptionalField<bool>,
    /// Optional clipboard access level.
    #[serde(default)]
    pub clipboard: OptionalField<UiClipboard>,
    /// Whether keyboard and mouse input injection is allowed.
    #[serde(default)]
    pub injection: OptionalField<bool>,
}

/// Isolation level for ProcessContainer desktop resources.
#[derive(Debug, serde::Deserialize)]
pub enum ProcessContainerUiIsolation {
    /// Isolate the complete container user-interface environment.
    #[serde(rename = "container")]
    Container,
    /// Isolate desktop resources.
    #[serde(rename = "desktop")]
    Desktop,
    /// Isolate user-interface handles.
    #[serde(rename = "handles")]
    Handles,
    /// Isolate user-interface atoms.
    #[serde(rename = "atoms")]
    Atoms,
}

/// ProcessContainer-specific user-interface policy.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessContainerUi {
    /// Optional desktop-resource isolation level.
    #[serde(default)]
    pub isolation: OptionalField<ProcessContainerUiIsolation>,
    /// Whether desktop system control is allowed.
    #[serde(default)]
    pub desktop_system_control: OptionalField<bool>,
    /// Optional system-settings access level.
    #[serde(default)]
    pub system_settings: OptionalField<String>,
    /// Whether Input Method Editor access is allowed.
    #[serde(default)]
    pub ime: OptionalField<bool>,
}

/// ProcessContainer-specific settings.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessContainer {
    /// Whether least-privilege mode is enabled.
    #[serde(default)]
    pub least_privilege: OptionalField<bool>,
    /// Optional AppContainer capability names.
    #[serde(default)]
    pub capabilities: OptionalField<Vec<String>>,
    /// Optional ProcessContainer-specific user-interface policy.
    #[serde(default)]
    pub ui: OptionalField<ProcessContainerUi>,
}

/// Linux LXC distribution settings.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Lxc {
    /// The Linux distribution name.
    pub distribution: String,
    /// The distribution release.
    pub release: String,
}

/// A complete one-shot `0.6.0-alpha` configuration request.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    /// The exact contract version marker.
    pub version: Version,
    /// Optional externally assigned container identifier.
    #[serde(default)]
    pub container_id: OptionalField<String>,
    /// Optional containment selection.
    #[serde(default)]
    pub containment: OptionalField<Containment>,
    /// Optional lifecycle settings.
    #[serde(default)]
    pub lifecycle: OptionalField<Lifecycle>,
    /// The process to execute.
    pub process: Process,
    /// Optional filesystem policy.
    #[serde(default)]
    pub filesystem: OptionalField<Filesystem>,
    /// Optional fallback consent.
    #[serde(default)]
    pub fallback: OptionalField<Fallback>,
    /// Optional network policy.
    #[serde(default)]
    pub network: OptionalField<Network>,
    /// Optional cross-platform user-interface policy.
    #[serde(default)]
    pub ui: OptionalField<Ui>,
    /// Optional ProcessContainer settings.
    ///
    /// The legacy `appContainer` spelling is accepted as an alias.
    #[serde(alias = "appContainer", default)]
    pub process_container: OptionalField<ProcessContainer>,
    /// Optional LXC distribution settings.
    #[serde(default)]
    pub lxc: OptionalField<Lxc>,
}
