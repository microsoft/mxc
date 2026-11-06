// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::{AciSandboxGroupId, ImageReference, OptionalField};

/// Settings for running a create-and-run request in an Azure Container
/// Instances (ACI) sandbox.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OneShotAci {
    /// ARM resource ID of the sandbox group that creates the sandbox.
    pub sandbox_group: AciSandboxGroupId,
    /// Image reference including its registry, pulled by the ACI service.
    pub image: ImageReference,
    /// Optional sizing applied when creating the sandbox.
    #[serde(default)]
    pub provision: OptionalField<AciProvision>,
}

/// ACI sandbox sizing. An omitted value uses the service default.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AciProvision {
    /// Whole CPU cores. Zero is rejected by semantic validation.
    #[serde(default)]
    pub cpu: OptionalField<u32>,
    /// Whole GiB of memory. Zero is rejected by semantic validation.
    #[serde(default)]
    pub memory_gb: OptionalField<u32>,
}
