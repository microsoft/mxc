// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::dev::{OptionalField, Telemetry, Version};
use serde::Deserialize;

string_marker! {
    /// The `start` phase of the state-aware configuration contract.
    pub struct StartPhase => "start";
}

/// Experimental settings accepted by the `start` phase.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartExperimental {}

/// A complete state-aware `start` request.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartRequest {
    /// Optional JSON Schema reference for editor validation.
    #[serde(rename = "$schema", default)]
    pub schema: OptionalField<String>,
    /// Optional human-readable annotation ignored by the runtime.
    #[serde(rename = "_comment", default)]
    pub comment: OptionalField<serde_json::Value>,
    /// Exact development contract version.
    pub version: Version,
    /// Exact `start` phase marker.
    pub phase: StartPhase,
    /// Identifier returned by the provision phase.
    pub sandbox_id: String,

    /// Optional telemetry configuration.
    #[serde(default)]
    pub telemetry: OptionalField<Telemetry>,

    /// Optional closed post-provision experimental settings.
    #[serde(default)]
    pub experimental: OptionalField<StartExperimental>,
}
