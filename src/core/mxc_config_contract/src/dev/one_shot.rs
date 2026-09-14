// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::development::{OneShotWindowsSandbox, OneShotWslc, TestFeature};
use super::network::Network;
use super::primitives::OptionalField;
use super::stable::{
    Fallback, Filesystem, Lifecycle, Lxc, Process, ProcessContainer, RuntimeConfig, Seatbelt,
    Telemetry, Ui,
};
use crate::dev::Version;

string_enum! {
    /// Containment selections available in `0.9.0-alpha`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    }
}

/// All development one-shot containments.
pub const ALL_ONE_SHOT_CONTAINMENTS: &[Containment] = &[
    Containment::Process,
    Containment::ProcessContainer,
    Containment::Lxc,
    Containment::Bubblewrap,
    Containment::Seatbelt,
    Containment::Vm,
    Containment::WindowsSandbox,
    Containment::Microvm,
    Containment::Hyperlight,
    Containment::Wslc,
    Containment::IsolationSession,
];

/// One-shot containments copied into a published contract.
pub const STABLE_CANDIDATE_CONTAINMENTS: &[Containment] = &[
    Containment::Process,
    Containment::ProcessContainer,
    Containment::Lxc,
    Containment::Bubblewrap,
    Containment::Seatbelt,
];

/// One-shot containments retained only by the mutable development contract.
pub const DEVELOPMENT_ONLY_CONTAINMENTS: &[Containment] = &[
    Containment::Vm,
    Containment::WindowsSandbox,
    Containment::Microvm,
    Containment::Hyperlight,
    Containment::Wslc,
    Containment::IsolationSession,
];

#[cfg(test)]
mod publication_tests {
    use super::*;

    #[test]
    fn containment_partition_is_complete_and_disjoint() {
        for containment in ALL_ONE_SHOT_CONTAINMENTS {
            let memberships = usize::from(STABLE_CANDIDATE_CONTAINMENTS.contains(containment))
                + usize::from(DEVELOPMENT_ONLY_CONTAINMENTS.contains(containment));
            assert_eq!(memberships, 1, "{containment:?}");
        }
        assert_eq!(
            STABLE_CANDIDATE_CONTAINMENTS.len() + DEVELOPMENT_ONLY_CONTAINMENTS.len(),
            ALL_ONE_SHOT_CONTAINMENTS.len()
        );
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
    /// Optional telemetry configuration.
    #[serde(default)]
    pub telemetry: OptionalField<Telemetry>,
    /// Optional placeholder development feature.
    #[serde(default)]
    pub test: OptionalField<TestFeature>,
    /// Optional one-shot Windows Sandbox settings.
    #[serde(default)]
    pub windows_sandbox: OptionalField<OneShotWindowsSandbox>,
    /// Optional one-shot WSLC settings.
    #[serde(default)]
    pub wslc: OptionalField<OneShotWslc>,
}
