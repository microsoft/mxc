// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::mxc_contract::dev::state_aware::provision::WslcContainment;
use crate::mxc_contract::dev::{OptionalField, Telemetry, Version};
use serde::Deserialize;

string_marker! {
    pub struct DeprovisionSessionPhase => "deprovision-session";
}

/// Request to release an empty WSLc session.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WslcDeprovisionSessionRequest {
    /// JSON Schema URL for editor validation.
    #[serde(rename = "$schema", default)]
    pub schema: OptionalField<String>,

    /// Annotation ignored by the runtime.
    #[serde(rename = "_comment", default)]
    pub comment: OptionalField<serde_json::Value>,
    pub version: Version,
    pub phase: DeprovisionSessionPhase,
    pub containment: WslcContainment,

    /// Session identifier returned by provision-session.
    pub session_id: String,
    #[serde(default)]
    pub telemetry: OptionalField<Telemetry>,
}
