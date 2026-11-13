// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::mxc_contract::dev::state_aware::provision::WslcContainment;
use crate::mxc_contract::dev::{OptionalField, Telemetry, Version};
use serde::Deserialize;

string_marker! {
    pub struct ProvisionSessionPhase => "provision-session";
}

/// Utility VM sizing shared by every sandbox in the session.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WslcProvisionSession {
    /// Virtual CPUs available to the session's utility VM.
    #[serde(default)]
    pub cpu_count: OptionalField<u32>,

    /// Utility VM memory ceiling, in megabytes.
    #[serde(default)]
    pub memory_mb: OptionalField<u64>,

    /// Enable GPU passthrough for the session's utility VM.
    #[serde(default)]
    pub gpu: OptionalField<bool>,
}

/// WSLc settings for provisioning a shared utility VM.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StateAwareWslcSession {
    #[serde(default)]
    pub provision_session: OptionalField<WslcProvisionSession>,
}

/// Request to create a WSLc session.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WslcProvisionSessionRequest {
    /// JSON Schema URL for editor validation.
    #[serde(rename = "$schema", default)]
    pub schema: OptionalField<String>,

    /// Annotation ignored by the runtime.
    #[serde(rename = "_comment", default)]
    pub comment: OptionalField<serde_json::Value>,
    pub version: Version,
    pub phase: ProvisionSessionPhase,
    pub containment: WslcContainment,
    #[serde(default)]
    pub telemetry: OptionalField<Telemetry>,
    #[serde(default)]
    pub wslc: OptionalField<StateAwareWslcSession>,
}
