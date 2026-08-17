// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::dev::experimental::Telemetry;
use crate::dev::{OptionalField, Version};
use serde::Deserialize;

string_marker! {
    /// The `start` phase of the state-aware configuration contract.
    pub struct StartPhase => "start";
}

/// Experimental settings accepted by the `start` phase.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartExperimental {
    /// Optional telemetry override.
    #[serde(default)]
    pub telemetry: OptionalField<Telemetry>,
}

/// A complete state-aware `start` request.
#[derive(Debug, Deserialize)]
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

    /// Optional correlation vector relayed from provision.
    #[serde(default)]
    pub correlation_vector: OptionalField<String>,

    /// Optional closed post-provision experimental settings.
    #[serde(default)]
    pub experimental: OptionalField<StartExperimental>,
}
