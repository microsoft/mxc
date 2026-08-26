// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::experimental::OneShotExperimental;
use super::network::Network;
use super::primitives::OptionalField;
use super::stable::{
    Fallback, Filesystem, Lifecycle, Lxc, Process, ProcessContainer, RuntimeConfig, Seatbelt, Ui,
};
use crate::dev::Version;

string_enum! {
    /// Containment selections available in `0.9.0-alpha`.
    #[derive(Debug)]
    pub enum Containment, schema_name = "OneShotContainment" {
        // Stable-candidate values.
        /// Select the host's native process-containment backend.
        Process => ["process"],
        /// Select the Windows ProcessContainer backend.
        ProcessContainer => ["processcontainer", "appcontainer"],
        /// Select the Linux LXC backend.
        Lxc => ["lxc"],
        /// Select the Linux Bubblewrap backend.
        Bubblewrap => ["bubblewrap"],
        /// Select the macOS Seatbelt backend.
        Seatbelt => ["seatbelt", "macos_sandbox"],

        // Development-only values.
        /// Select the host's VM-class containment backend.
        Vm => ["vm"],
        /// Select the Windows Sandbox backend.
        WindowsSandbox => ["windows_sandbox"],
        /// Select the NanVix micro-VM backend.
        Microvm => ["microvm"],
        /// Select the Hyperlight micro-VM backend.
        Hyperlight => ["hyperlight"],
        /// Select the WSL container backend.
        Wslc => ["wslc"],
        /// Select the Windows IsolationSession backend.
        IsolationSession => ["isolation_session"],
        /// Select the Apple Container backend.
        AppleContainer => ["apple_container"],
    }
}

/// A complete one-shot `0.9.0-alpha` configuration request.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema-gen", schemars(rename = "OneShotRequest"))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    /// Optional JSON Schema reference for editor validation.
    #[serde(rename = "$schema", default)]
    pub schema: OptionalField<String>,
    /// Optional human-readable annotation ignored by the runtime.
    #[serde(rename = "_comment", default)]
    pub comment: OptionalField<serde_json::Value>,
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
    /// The legacy `appContainer` spelling is accepted as an alias.
    #[serde(alias = "appContainer", default)]
    pub process_container: OptionalField<ProcessContainer>,
    /// Optional LXC distribution settings.
    #[serde(default)]
    pub lxc: OptionalField<Lxc>,
    /// Optional macOS Seatbelt configuration.
    #[serde(alias = "macos_sandbox", default)]
    pub seatbelt: OptionalField<Seatbelt>,
    /// Optional runtime configuration settings.
    #[serde(default)]
    pub runtime_config: OptionalField<RuntimeConfig>,
    /// Optional experimental settings.
    #[serde(default)]
    pub experimental: OptionalField<OneShotExperimental>,
}
