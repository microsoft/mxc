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
#[derive(Debug)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema-gen", schemars(rename = "OneShotRequest"))]
#[cfg_attr(
    feature = "schema-gen",
    serde(rename_all = "camelCase", deny_unknown_fields)
)]
pub struct Request {
    /// Optional JSON Schema reference for editor validation.
    #[cfg_attr(feature = "schema-gen", serde(rename = "$schema", default))]
    pub schema: OptionalField<String>,
    /// Optional human-readable annotation ignored by the runtime.
    #[cfg_attr(feature = "schema-gen", serde(rename = "_comment", default))]
    pub comment: OptionalField<serde_json::Value>,
    /// The exact contract version marker.
    pub version: Version,
    /// Optional externally assigned container identifier.
    #[cfg_attr(feature = "schema-gen", serde(default))]
    pub container_id: OptionalField<String>,
    /// Optional containment selection.
    #[cfg_attr(feature = "schema-gen", serde(default))]
    pub containment: OptionalField<Containment>,
    /// Optional lifecycle settings.
    #[cfg_attr(feature = "schema-gen", serde(default))]
    pub lifecycle: OptionalField<Lifecycle>,
    /// The process to execute.
    pub process: Process,
    /// Optional filesystem policy.
    #[cfg_attr(feature = "schema-gen", serde(default))]
    pub filesystem: OptionalField<Filesystem>,
    /// Optional fallback consent.
    #[cfg_attr(feature = "schema-gen", serde(default))]
    pub fallback: OptionalField<Fallback>,
    /// Optional network policy.
    #[cfg_attr(feature = "schema-gen", serde(default))]
    pub network: OptionalField<Network>,
    /// Optional cross-platform user-interface policy.
    #[cfg_attr(feature = "schema-gen", serde(default))]
    pub ui: OptionalField<Ui>,
    /// Optional ProcessContainer settings.
    /// The legacy `appContainer` spelling is accepted as an alias.
    #[cfg_attr(feature = "schema-gen", serde(alias = "appContainer", default))]
    pub process_container: OptionalField<ProcessContainer>,
    /// Optional LXC distribution settings.
    #[cfg_attr(feature = "schema-gen", serde(default))]
    pub lxc: OptionalField<Lxc>,
    /// Optional macOS Seatbelt configuration.
    #[cfg_attr(feature = "schema-gen", serde(alias = "macos_sandbox", default))]
    pub seatbelt: OptionalField<Seatbelt>,
    /// Optional runtime configuration settings.
    #[cfg_attr(feature = "schema-gen", serde(default))]
    pub runtime_config: OptionalField<RuntimeConfig>,
    /// Optional experimental settings.
    #[cfg_attr(feature = "schema-gen", serde(default))]
    pub experimental: OptionalField<OneShotExperimental>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UncheckedRequest {
    #[serde(rename = "$schema", default)]
    schema: OptionalField<String>,
    #[serde(rename = "_comment", default)]
    comment: OptionalField<serde_json::Value>,
    version: Version,
    #[serde(default)]
    container_id: OptionalField<String>,
    #[serde(default)]
    containment: OptionalField<Containment>,
    #[serde(default)]
    lifecycle: OptionalField<Lifecycle>,
    process: Process,
    #[serde(default)]
    filesystem: OptionalField<Filesystem>,
    #[serde(default)]
    fallback: OptionalField<Fallback>,
    #[serde(default)]
    network: OptionalField<Network>,
    #[serde(default)]
    ui: OptionalField<Ui>,
    #[serde(alias = "appContainer", default)]
    process_container: OptionalField<ProcessContainer>,
    #[serde(default)]
    lxc: OptionalField<Lxc>,
    #[serde(alias = "macos_sandbox", default)]
    seatbelt: OptionalField<Seatbelt>,
    #[serde(default)]
    runtime_config: OptionalField<RuntimeConfig>,
    #[serde(default)]
    experimental: OptionalField<OneShotExperimental>,
}

impl<'de> serde::Deserialize<'de> for Request {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let request = UncheckedRequest::deserialize(deserializer)?;
        if matches!(
            request.containment.as_ref(),
            Some(Containment::AppleContainer)
        ) && request
            .experimental
            .as_ref()
            .and_then(|experimental| experimental.apple_container.as_ref())
            .is_none()
        {
            return Err(D::Error::custom(
                "apple_container containment requires experimental.apple_container",
            ));
        }

        Ok(Self {
            schema: request.schema,
            comment: request.comment,
            version: request.version,
            container_id: request.container_id,
            containment: request.containment,
            lifecycle: request.lifecycle,
            process: request.process,
            filesystem: request.filesystem,
            fallback: request.fallback,
            network: request.network,
            ui: request.ui,
            process_container: request.process_container,
            lxc: request.lxc,
            seatbelt: request.seatbelt,
            runtime_config: request.runtime_config,
            experimental: request.experimental,
        })
    }
}
