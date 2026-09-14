// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Stable-candidate projections and profiles used by publication tooling.

use super::network::Network;
use super::primitives::OptionalField;
use super::stable::{
    Fallback, Filesystem, Lifecycle, Lxc, Process, ProcessContainer, RuntimeConfig, Seatbelt,
    Telemetry, Ui,
};
use super::{
    DeprovisionPhase, ExecPhase, IsolationSessionContainment, IsolationSessionNetwork,
    ProvisionPhase, StartPhase, StateAwareIsolationSession, StateAwareWslc, StopPhase, Version,
    WindowsSandboxContainment, WslcContainment,
};

/// A state-aware backend that may be selected by a publication profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateAwareBackend {
    /// Windows Sandbox state-aware lifecycle.
    WindowsSandbox,
    /// IsolationSession state-aware lifecycle.
    IsolationSession,
    /// WSL container state-aware lifecycle.
    Wslc,
}

impl StateAwareBackend {
    /// Returns the stable containment spelling used by generated metadata.
    pub const fn as_str(self) -> &'static str {
        match self {
            StateAwareBackend::WindowsSandbox => "windows_sandbox",
            StateAwareBackend::IsolationSession => "isolation_session",
            StateAwareBackend::Wslc => "wslc",
        }
    }
}

/// The exact request-root set to freeze when a development contract publishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicationProfile {
    /// Whether the stable one-shot root is included.
    pub one_shot: bool,
    /// Graduated state-aware provision backends. Selecting any backend also
    /// includes the shared start, exec, stop, and deprovision roots.
    pub state_aware_backends: &'static [StateAwareBackend],
}

/// Conservative v0.9 publication profile.
///
/// Backend graduation is decided only after the `experimental` block has been
/// removed and every selected provision field has a permanent stable location.
pub const V0_10_0_ALPHA_PUBLICATION_PROFILE: PublicationProfile = PublicationProfile {
    one_shot: true,
    state_aware_backends: &[],
};

string_enum! {
    /// Stable containment selections eligible for publication.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Containment, schema_name = "OneShotContainment" {
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
    }
}

/// Stable-candidate one-shot request copied into a published contract.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema-gen", schemars(rename = "OneShotRequest"))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OneShotRequest {
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
    /// Optional telemetry configuration.
    #[serde(default)]
    pub telemetry: OptionalField<Telemetry>,
}

/// Stable Windows Sandbox state-aware provision request.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "schema-gen",
    schemars(rename = "WindowsSandboxProvisionRequest")
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsSandboxProvisionRequest {
    /// Optional JSON Schema reference for editor validation.
    #[serde(rename = "$schema", default)]
    pub schema: OptionalField<String>,
    /// Optional human-readable annotation ignored by the runtime.
    #[serde(rename = "_comment", default)]
    pub comment: OptionalField<serde_json::Value>,
    /// The exact contract version marker.
    pub version: Version,
    /// Exact provision phase marker.
    pub phase: ProvisionPhase,
    /// Exact Windows Sandbox containment marker.
    pub containment: WindowsSandboxContainment,
    /// Optional filesystem policy.
    #[serde(default)]
    pub filesystem: OptionalField<Filesystem>,
    /// Optional telemetry configuration.
    #[serde(default)]
    pub telemetry: OptionalField<Telemetry>,
}

/// Stable-candidate IsolationSession state-aware provision request.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "schema-gen",
    schemars(rename = "IsolationSessionProvisionRequest")
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IsolationSessionProvisionRequest {
    /// Optional JSON Schema reference for editor validation.
    #[serde(rename = "$schema", default)]
    pub schema: OptionalField<String>,
    /// Optional human-readable annotation ignored by the runtime.
    #[serde(rename = "_comment", default)]
    pub comment: OptionalField<serde_json::Value>,
    /// The exact contract version marker.
    pub version: Version,
    /// Exact provision phase marker.
    pub phase: ProvisionPhase,
    /// Exact IsolationSession containment marker.
    pub containment: IsolationSessionContainment,
    /// Required unrestricted network posture.
    pub network: IsolationSessionNetwork,
    /// Optional telemetry configuration.
    #[serde(default)]
    pub telemetry: OptionalField<Telemetry>,
    /// Optional IsolationSession backend settings.
    #[serde(default)]
    pub isolation_session: OptionalField<StateAwareIsolationSession>,
}

/// Stable-candidate WSLC state-aware provision request.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema-gen", schemars(rename = "WslcProvisionRequest"))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WslcProvisionRequest {
    /// Optional JSON Schema reference for editor validation.
    #[serde(rename = "$schema", default)]
    pub schema: OptionalField<String>,
    /// Optional human-readable annotation ignored by the runtime.
    #[serde(rename = "_comment", default)]
    pub comment: OptionalField<serde_json::Value>,
    /// The exact contract version marker.
    pub version: Version,
    /// Exact provision phase marker.
    pub phase: ProvisionPhase,
    /// Exact WSLC containment marker.
    pub containment: WslcContainment,
    /// Optional filesystem policy.
    #[serde(default)]
    pub filesystem: OptionalField<Filesystem>,
    /// Optional network policy.
    #[serde(default)]
    pub network: OptionalField<Network>,
    /// Optional telemetry configuration.
    #[serde(default)]
    pub telemetry: OptionalField<Telemetry>,
    /// Optional WSLC backend settings.
    #[serde(default)]
    pub wslc: OptionalField<StateAwareWslc>,
}

/// Stable state-aware start request shared by published backends.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema-gen", schemars(rename = "StartRequest"))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartRequest {
    /// Optional JSON Schema reference for editor validation.
    #[serde(rename = "$schema", default)]
    pub schema: OptionalField<String>,
    /// Optional human-readable annotation ignored by the runtime.
    #[serde(rename = "_comment", default)]
    pub comment: OptionalField<serde_json::Value>,
    /// The exact contract version marker.
    pub version: Version,
    /// Exact start phase marker.
    pub phase: StartPhase,
    /// Identifier returned by the provision phase.
    pub sandbox_id: String,
    /// Optional telemetry configuration.
    #[serde(default)]
    pub telemetry: OptionalField<Telemetry>,
}

/// Stable state-aware exec request shared by published backends.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema-gen", schemars(rename = "ExecRequest"))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecRequest {
    /// Optional JSON Schema reference for editor validation.
    #[serde(rename = "$schema", default)]
    pub schema: OptionalField<String>,
    /// Optional human-readable annotation ignored by the runtime.
    #[serde(rename = "_comment", default)]
    pub comment: OptionalField<serde_json::Value>,
    /// The exact contract version marker.
    pub version: Version,
    /// Exact exec phase marker.
    pub phase: ExecPhase,
    /// Identifier of the sandbox to execute in.
    pub sandbox_id: String,
    /// Process to execute in the sandbox.
    pub process: Process,
    /// Optional per-execution network settings.
    #[serde(default)]
    pub network: OptionalField<Network>,
    /// Optional per-execution runtime values.
    #[serde(default)]
    pub runtime_config: OptionalField<RuntimeConfig>,
    /// Optional telemetry configuration.
    #[serde(default)]
    pub telemetry: OptionalField<Telemetry>,
}

/// Stable state-aware stop request shared by published backends.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema-gen", schemars(rename = "StopRequest"))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StopRequest {
    /// Optional JSON Schema reference for editor validation.
    #[serde(rename = "$schema", default)]
    pub schema: OptionalField<String>,
    /// Optional human-readable annotation ignored by the runtime.
    #[serde(rename = "_comment", default)]
    pub comment: OptionalField<serde_json::Value>,
    /// The exact contract version marker.
    pub version: Version,
    /// Exact stop phase marker.
    pub phase: StopPhase,
    /// Identifier returned by the provision phase.
    pub sandbox_id: String,
    /// Optional telemetry configuration.
    #[serde(default)]
    pub telemetry: OptionalField<Telemetry>,
}

/// Stable state-aware deprovision request shared by published backends.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema-gen", schemars(rename = "DeprovisionRequest"))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeprovisionRequest {
    /// Optional JSON Schema reference for editor validation.
    #[serde(rename = "$schema", default)]
    pub schema: OptionalField<String>,
    /// Optional human-readable annotation ignored by the runtime.
    #[serde(rename = "_comment", default)]
    pub comment: OptionalField<serde_json::Value>,
    /// The exact contract version marker.
    pub version: Version,
    /// Exact deprovision phase marker.
    pub phase: DeprovisionPhase,
    /// Identifier of the sandbox to deprovision.
    pub sandbox_id: String,
    /// Optional telemetry configuration.
    #[serde(default)]
    pub telemetry: OptionalField<Telemetry>,
}
