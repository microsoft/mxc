// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::dev::{OptionalField, Telemetry, Version};
use serde::Deserialize;

string_marker! {
    /// The `stop` phase of the state-aware configuration contract.
    pub struct StopPhase => "stop";
}

/// A complete state-aware `stop` request.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StopRequest {
    /// Optional JSON Schema reference for editor validation.
    #[serde(rename = "$schema", default)]
    pub schema: OptionalField<String>,
    /// Optional human-readable annotation ignored by the runtime.
    #[serde(rename = "_comment", default)]
    pub comment: OptionalField<serde_json::Value>,
    /// Exact development contract version.
    pub version: Version,
    /// Exact `stop` phase marker.
    pub phase: StopPhase,
    /// Identifier returned by the provision phase.
    pub sandbox_id: String,

    /// Optional telemetry configuration.
    #[serde(default)]
    pub telemetry: OptionalField<Telemetry>,
}
