// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::mxc_contract::dev::state_aware::provision::ProvisionPhase;
use crate::mxc_contract::dev::{
    Filesystem, Network, OptionalField, RuntimeConfig, Telemetry, Version,
};
use serde::Deserialize;

string_marker! {
    /// The `microvm` containment of the state-aware configuration contract.
    pub struct MicroVmContainment => "microvm";
}

pub use crate::mxc_contract::dev::microvm::MicroVmProvision;

/// State-aware MicroVM settings.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StateAwareMicroVm {
    /// Image reference including its registry, fixed for this container's lifetime.
    pub image: crate::mxc_contract::dev::ImageReference,
    /// Optional provision-phase settings.
    #[serde(default)]
    pub provision: OptionalField<MicroVmProvision>,
}

/// A complete development provision request for the MicroVM backend.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MicroVmProvisionRequest {
    #[serde(rename = "$schema", default)]
    pub schema: OptionalField<String>,
    #[serde(rename = "_comment", default)]
    pub comment: OptionalField<serde_json::Value>,
    pub version: Version,
    pub phase: ProvisionPhase,
    pub containment: MicroVmContainment,
    #[serde(default)]
    pub filesystem: OptionalField<Filesystem>,
    #[serde(default)]
    pub network: OptionalField<Network>,
    #[serde(default)]
    pub runtime_config: OptionalField<RuntimeConfig>,
    #[serde(default)]
    pub telemetry: OptionalField<Telemetry>,
    pub microvm: StateAwareMicroVm,
}
