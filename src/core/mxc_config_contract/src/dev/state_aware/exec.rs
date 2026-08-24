// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::dev::experimental::Telemetry;
use crate::dev::{Network, Process};
use crate::dev::{OptionalField, Version};
use serde::Deserialize;

string_marker! {
    /// The `exec` phase of the state-aware configuration contract.
    pub struct ExecPhase => "exec";
}

/// Experimental settings accepted by the `exec` phase.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecExperimental {
    /// Optional telemetry override.
    #[serde(default)]
    pub telemetry: OptionalField<Telemetry>,
}

/// A complete state-aware `exec` request.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecRequest {
    /// Optional JSON Schema reference for editor validation.
    #[serde(rename = "$schema", default)]
    pub schema: OptionalField<String>,
    /// Optional human-readable annotation ignored by the runtime.
    #[serde(rename = "_comment", default)]
    pub comment: OptionalField<serde_json::Value>,
    /// Exact development contract version.
    pub version: Version,
    /// Exact `exec` phase marker.
    pub phase: ExecPhase,
    /// Identifier of the sandbox to execute in.
    pub sandbox_id: String,

    /// Optional correlation vector relayed from provision.
    #[serde(default)]
    pub correlation_vector: OptionalField<String>,

    /// Process to execute in the sandbox.
    pub process: Process,

    /// Optional per-execution network settings.
    #[serde(default)]
    pub network: OptionalField<Network>,

    /// Optional closed exec experimental settings.
    #[serde(default)]
    pub experimental: OptionalField<ExecExperimental>,
}
