// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::network::Network;
use super::primitives::{NonEmptyString, OptionalField};

#[rustfmt::skip]
string_enum! {
/// The exact version marker accepted by this contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    /// The published `0.6.0-alpha` contract.
    V0_6_0Alpha => ["0.6.0-alpha"],
}
}

#[rustfmt::skip]
string_enum! {
/// Stable containment selections available in `0.6.0-alpha`.
#[derive(Debug)]
pub enum Containment {
    /// Select the host's native process-containment backend.
    Process => ["process"],
    /// Select the Windows ProcessContainer backend.
    ProcessContainer => ["processcontainer", "appcontainer"],
    /// Select the Linux LXC backend.
    Lxc => ["lxc"],
    /// Select the Linux Bubblewrap backend.
    Bubblewrap => ["bubblewrap"],
}
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

#[rustfmt::skip]
string_enum! {
/// Clipboard access granted to the contained process.
#[derive(Debug)]
pub enum UiClipboard {
    /// Deny clipboard reads and writes.
    None => ["none"],
    /// Allow clipboard reads.
    Read => ["read"],
    /// Allow clipboard writes.
    Write => ["write"],
    /// Allow clipboard reads and writes.
    All => ["all"],
}
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

#[rustfmt::skip]
string_enum! {
/// Isolation level for ProcessContainer desktop resources.
#[derive(Debug)]
pub enum ProcessContainerUiIsolation {
    /// Isolate the complete container user-interface environment.
    Container => ["container"],
    /// Isolate desktop resources.
    Desktop => ["desktop"],
    /// Isolate user-interface handles.
    Handles => ["handles"],
    /// Isolate user-interface atoms.
    Atoms => ["atoms"],
}
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
