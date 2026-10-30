// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::mxc_contract::dev::state_aware::provision::ProvisionPhase;
use crate::mxc_contract::dev::{Filesystem, Kata, Network, Telemetry};
use crate::mxc_contract::dev::{OptionalField, Version};
use serde::Deserialize;

string_marker! {
    /// The `kata` containment of the state-aware configuration contract.
    pub struct KataContainment => "kata";
}

/// A complete state-aware `provision` request for kata.
///
/// Filesystem and network policy are fixed here and apply to every process the
/// sandbox runs later. The Kata backend enforces only a deny-all network.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KataProvisionRequest {
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
    /// Exact `kata` containment marker.
    pub containment: KataContainment,
    /// Optional filesystem policy.
    #[serde(default)]
    pub filesystem: OptionalField<Filesystem>,
    /// Optional network policy.
    #[serde(default)]
    pub network: OptionalField<Network>,
    /// Optional telemetry configuration.
    #[serde(default)]
    pub telemetry: OptionalField<Telemetry>,
    /// Guest root filesystem and hypervisor.
    pub kata: Kata,
}
