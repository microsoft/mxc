// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::primitives::{NonEmptyString, OptionalField};

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

/// Telemetry settings.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Telemetry {
    /// Whether telemetry is enabled.
    #[serde(default)]
    pub enabled: OptionalField<bool>,
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

#[rustfmt::skip]
string_enum! {
/// Mode for capture denials
#[derive(Debug)]
pub enum CaptureDenialsMode {
    /// Access stays **denied** and the denial is recorded. Deny-by-default containment is preserved; this is the safe default.
    Block => ["block"],
    /// Access is **allowed** and recorded (audit mode). This relaxes deny-by-default for the run, so it is a security-sensitive choice and the runner emits a security warning.
    Allow => ["allow"],
}
}

/// Windows denial-capture settings.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureDenials {
    /// How each ungranted access is handled while it is recorded.
    #[serde(default)]
    pub mode: OptionalField<CaptureDenialsMode>,
    /// Optional destination for the generated denial report.
    #[serde(default)]
    pub output_path: OptionalField<String>,
    /// Whether to retain the sealed ETL trace after analysis. Retained traces
    /// can contain sensitive resource paths and identifiers; callers are
    /// responsible for deleting them.
    #[serde(default)]
    pub retain_etl: OptionalField<bool>,
}

/// ProcessContainer-specific settings.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessContainer {
    /// Whether least-privilege mode is enabled.
    #[serde(default)]
    pub least_privilege: OptionalField<bool>,
    /// Optional learning-mode (deny-and-record)
    #[serde(default)]
    pub learning_mode: OptionalField<bool>,
    /// Optional AppContainer capability names.
    #[serde(default)]
    pub capabilities: OptionalField<Vec<String>>,
    /// Optional capture-denials policy.
    #[serde(default)]
    pub capture_denials: OptionalField<CaptureDenials>,
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

#[rustfmt::skip]
string_enum! {
/// Launch method for macOS Seatbelt config.
#[derive(Debug)]
pub enum LaunchMethod {
    /// Launch the contained process directly through `exec`.
    Exec => ["exec"],
    /// Launch the contained application through macOS LaunchServices.
    Open => ["open"],
}
}

/// macOS Seatbelt backend settings.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Seatbelt {
    /// Optional override of the generated sandbox profile.
    #[serde(default)]
    pub profile_override: OptionalField<String>,
    /// Whether GUI application access is allowed.
    #[serde(default)]
    pub gui_access: OptionalField<bool>,
    /// Optional method used to launch the contained process.
    #[serde(default)]
    pub launch_method: OptionalField<LaunchMethod>,
    /// Whether the contained process may allocate nested pseudo-terminals.
    #[serde(default)]
    pub nested_pty: OptionalField<bool>,
    /// Whether macOS Keychain access is allowed.
    #[serde(default)]
    pub keychain_access: OptionalField<bool>,
    /// Additional Mach service global names the process may resolve.
    #[serde(default)]
    pub extra_mach_lookups: OptionalField<Vec<String>>,
}
