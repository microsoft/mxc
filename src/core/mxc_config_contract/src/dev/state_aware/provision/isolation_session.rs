// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::dev::state_aware::provision::ProvisionPhase;
use crate::dev::{OptionalField, Version};
use crate::dev::{Telemetry, True};
use serde::Deserialize;

string_marker! {
    /// The `isolation_session` containment of the state-aware configuration contract.
    pub struct IsolationSessionContainment => "isolation_session";
}

string_marker! {
    /// The exact `allow` default policy required by the IsolationSession network acknowledgment.
    pub struct IsolationSessionNetworkDefaultPolicy => "allow";
}

/// IsolationSession settings accepted during provisioning.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IsolationSessionProvision {
    /// Optional application identifier carried by the sandbox identity.
    #[serde(default)]
    pub app_id: OptionalField<String>,
}

/// State-aware IsolationSession experimental settings.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StateAwareIsolationSession {
    /// Optional provision-phase settings.
    #[serde(default)]
    pub provision: OptionalField<IsolationSessionProvision>,
}

/// Experimental settings accepted by an IsolationSession provision request.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IsolationSessionProvisionExperimental {
    /// Optional IsolationSession backend settings.
    #[serde(rename = "isolation_session", default)]
    pub isolation_session: OptionalField<StateAwareIsolationSession>,
    /// Optional telemetry override.
    #[serde(default)]
    pub telemetry: OptionalField<Telemetry>,
}

/// The exact unrestricted-network acknowledgment required when provisioning an IsolationSession.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IsolationSessionNetwork {
    /// Exact `allow` default network policy marker.
    pub default_policy: IsolationSessionNetworkDefaultPolicy,
    /// Required acknowledgment that local network access is allowed.
    pub allow_local_network: True,
}

/// A complete state-aware `provision` request for isolation_session
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IsolationSessionProvisionRequest {
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
    /// Exact `isolation_session` containment marker.
    pub containment: IsolationSessionContainment,
    /// Required unrestricted-network acknowledgment.
    pub network: IsolationSessionNetwork,
    /// Optional closed experimental settings.
    #[serde(default)]
    pub experimental: OptionalField<IsolationSessionProvisionExperimental>,
}
