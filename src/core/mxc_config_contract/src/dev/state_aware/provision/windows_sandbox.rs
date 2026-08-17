// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::dev::state_aware::provision::ProvisionPhase;
use crate::dev::{Filesystem, Telemetry};
use crate::dev::{OptionalField, Version};
use serde::Deserialize;

string_marker! {
    /// The `windows_sandbox` containment of the state-aware configuration contract.
    pub struct WindowsSandboxContainment => "windows_sandbox";
}

/// Experimental settings accepted by a Windows Sandbox provision request.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsSandboxExperimental {
    /// Optional telemetry override.
    #[serde(default)]
    pub telemetry: OptionalField<Telemetry>,
}

/// A complete state-aware `provision` request for windows_sandbox
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsSandboxProvisionRequest {
    /// Optional JSON Schema reference for editor validation.
    #[serde(rename = "$schema", default)]
    pub schema: OptionalField<String>,
    /// Optional human-readable annotation ignored by the runtime.
    #[serde(rename = "_comment", default)]
    pub comment: OptionalField<serde_json::Value>,
    /// Exact development contract version.
    pub version: Version,
    /// Exact `provision` phase marker.
    pub phase: ProvisionPhase,
    /// Exact `windows_sandbox` containment marker.
    pub containment: WindowsSandboxContainment,
    /// Optional filesystem policy.
    #[serde(default)]
    pub filesystem: OptionalField<Filesystem>,
    /// Optional closed experimental settings.
    #[serde(default)]
    pub experimental: OptionalField<WindowsSandboxExperimental>,
}
