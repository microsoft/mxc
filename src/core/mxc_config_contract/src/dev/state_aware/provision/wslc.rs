// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::dev::state_aware::provision::ProvisionPhase;
use crate::dev::{Filesystem, Network, PortMapping, Telemetry};
use crate::dev::{OptionalField, Version};
use serde::Deserialize;

string_marker! {
    /// The `wslc` containment of the state-aware configuration contract.
    pub struct WslcContainment => "wslc";
}

/// WSLC settings accepted during provisioning.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WslcProvision {
    /// Optional container image reference.
    #[serde(default)]
    pub image: OptionalField<String>,
    /// Optional path to a local container image archive.
    #[serde(default)]
    pub image_tar_path: OptionalField<String>,
    /// Optional host-to-container TCP port mappings. Per-container, so unlike
    /// the one-shot sizing knobs it is honored on the shared daemon session.
    #[serde(default)]
    pub port_mappings: OptionalField<Vec<PortMapping>>,
}

/// State-aware WSLC experimental settings.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StateAwareWslc {
    /// Optional provision-phase settings.
    #[serde(default)]
    pub provision: OptionalField<WslcProvision>,
}

/// Experimental settings accepted by a WSLC provision request.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WslcProvisionExperimental {
    /// Optional WSLC backend settings.
    #[serde(default)]
    pub wslc: OptionalField<StateAwareWslc>,
    /// Optional telemetry override.
    #[serde(default)]
    pub telemetry: OptionalField<Telemetry>,
}

/// A complete state-aware `provision` request for wslc
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WslcProvisionRequest {
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
    /// Exact `wslc` containment marker.
    pub containment: WslcContainment,
    /// Optional filesystem policy fixed at provision time.
    #[serde(default)]
    pub filesystem: OptionalField<Filesystem>,
    /// Optional network policy fixed at provision time.
    #[serde(default)]
    pub network: OptionalField<Network>,
    /// Optional closed experimental settings.
    #[serde(default)]
    pub experimental: OptionalField<WslcProvisionExperimental>,
}
