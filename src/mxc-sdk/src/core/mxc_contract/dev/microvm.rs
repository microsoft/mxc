// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::OptionalField;

/// MicroVM creation settings shared by create-and-run and provision requests.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MicroVmProvision {
    /// Guest memory in MiB. Zero is rejected by semantic validation.
    #[serde(default)]
    pub memory_mib: OptionalField<u32>,
}
