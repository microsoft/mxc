// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Neutral pre-normalization representation shared by state-aware parser paths.

use serde_json::Value;

use crate::wire;

/// Lossless intermediate state produced before runtime normalization.
pub(crate) struct StateAwareWireInput {
    pub config: wire::MxcConfig,
    pub experimental_raw: Option<Value>,
    pub source_text: Box<str>,
}
