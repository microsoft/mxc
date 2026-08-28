// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::primitives::OptionalField;

/// Placeholder feature used to exercise experimental configuration plumbing.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TestFeature {
    /// The message for the test feature.
    #[serde(default)]
    pub message: OptionalField<String>,
}

/// One-shot telemetry override.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Telemetry {
    /// Whether telemetry is enabled.
    #[serde(default)]
    pub enabled: OptionalField<bool>,
}

/// Compatibility settings accepted for one-shot Windows Sandbox requests.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OneShotWindowsSandbox {
    /// Idle timeout before teardown, in milliseconds.
    #[serde(default)]
    pub idle_timeout_ms: OptionalField<u32>,
    /// Legacy idle-timeout field retained for compatibility.
    #[serde(default)]
    pub idle_timeout: OptionalField<u32>,
    /// Optional daemon named-pipe override.
    #[serde(default)]
    pub daemon_pipe_name: OptionalField<String>,
}

/// Experimental settings.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OneShotExperimental {
    /// Optional placeholder test feature.
    #[serde(default)]
    pub test: OptionalField<TestFeature>,
    /// Optional one-shot Windows Sandbox compatibility settings.
    #[serde(rename = "windows_sandbox", default)]
    pub windows_sandbox: OptionalField<OneShotWindowsSandbox>,
    /// Optional telemetry override.
    #[serde(default)]
    pub telemetry: OptionalField<Telemetry>,
}
