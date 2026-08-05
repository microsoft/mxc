// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::dev::state_aware::provision::IsolationSessionUser;
use crate::dev::OptionalField;
use serde::Deserialize;

/// IsolationSession settings accepted at start.
///
/// The `sandboxId` returned by provision carries no Entra marker, so an
/// Entra-backed sandbox re-supplies the bundle here for the OS to validate
/// against the agent user it assigned at provision.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IsolationSessionStart {
    /// Optional Entra credentials for an Entra-backed sandbox.
    #[serde(default)]
    pub user: OptionalField<IsolationSessionUser>,
}

/// IsolationSession settings accepted by a start request.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartIsolationSession {
    /// Optional start-phase settings.
    #[serde(default)]
    pub start: OptionalField<IsolationSessionStart>,
}
