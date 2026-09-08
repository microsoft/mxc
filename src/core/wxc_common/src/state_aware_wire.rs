// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Controlled input to state-aware common-field normalization.

use crate::error::WxcError;
use crate::state_aware_operation::StateAwareOperation;
use crate::wire;

/// Only the operation owns routing and backend configuration.
pub(crate) struct StateAwareInput {
    common: wire::MxcConfig,
    operation: StateAwareOperation,
}

impl StateAwareInput {
    pub(crate) fn new(
        common: wire::MxcConfig,
        operation: StateAwareOperation,
    ) -> Result<Self, WxcError> {
        let mut contradictory = Vec::new();
        if common.phase.is_some() {
            contradictory.push("phase");
        }
        if common.sandbox_id.is_some() {
            contradictory.push("sandboxId");
        }
        if common.containment.is_some() {
            contradictory.push("containment");
        }
        if common.experimental.is_some() {
            contradictory.push("experimental");
        }
        if common.container_id.is_some() {
            contradictory.push("containerId");
        }
        if common.fallback.is_some() {
            contradictory.push("fallback");
        }
        if common.seatbelt.is_some() {
            contradictory.push("seatbelt");
        }
        if common.process_container.is_some() {
            contradictory.push("processContainer");
        }
        if common.lxc.is_some() {
            contradictory.push("lxc");
        }
        if common.lifecycle.is_some() {
            contradictory.push("lifecycle");
        }
        if !contradictory.is_empty() {
            return Err(WxcError::ConfigParse(format!(
                "State-aware common input must not contain operation or one-shot field(s): {}",
                contradictory.join(", "),
            )));
        }
        Ok(Self { common, operation })
    }

    pub(crate) fn into_parts(self) -> (wire::MxcConfig, StateAwareOperation) {
        (self.common, self.operation)
    }
}
