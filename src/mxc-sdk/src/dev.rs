// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Caller-authored exact-JSON APIs.

mod one_shot;
mod state_aware;

pub use one_shot::{run_json, spawn_json, spawn_with_pty_json};
pub use state_aware::{
    deprovision_container_json, provision_container_json, run_in_container_json,
    spawn_in_container_json, spawn_in_container_with_pty_json, start_container_json,
    stop_container_json, validate_deprovision_json, validate_process_json, validate_provision_json,
    validate_start_json, validate_stop_json,
};

pub use crate::mxc_common::policy_failures::{
    PolicyFailureDetail, PolicyFailureResult, PolicyFailures,
};
use crate::sandbox::MxcPtySize;

/// Invocation controls for an exact-JSON operation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct JsonOptions<'a> {
    /// Authorize experimental backends separately from the JSON contract version.
    pub experimental: bool,
    /// Authorize safe restrictive changes from cumulative creation-policy
    /// failures. Supported only by native Windows ProcessContainer creation.
    pub policy_failures: Option<&'a PolicyFailures>,
}

impl JsonOptions<'_> {
    pub(crate) fn reject_creation_feedback(&self) -> Result<(), crate::mxc_engine::Error> {
        if self.policy_failures.is_some() {
            return Err(crate::mxc_engine::Error::new(
                crate::mxc_engine::ErrorCode::UnsupportedPhase,
                "policyFailures is supported only by Dev run_json and spawn_json creation",
            ));
        }
        Ok(())
    }
}

impl PolicyFailures {
    /// Serialize feedback for application-owned storage.
    ///
    /// A terminal over-limit native result can be stored but cannot be
    /// reapplied unchanged. Creation validates the stricter input limits.
    pub fn to_json(&self) -> Result<String, crate::mxc_engine::Error> {
        use crate::mxc_engine::{Error, ErrorCode};
        self.validate_storage()
            .map_err(|message| Error::new(ErrorCode::MalformedRequest, message))?;
        serde_json::to_string(self).map_err(|error| {
            Error::new(
                ErrorCode::BackendError,
                format!("cannot serialize policy failures: {error}"),
            )
        })
    }

    /// Restore feedback without interpreting it as policy approval.
    pub fn from_json(json: &str) -> Result<Self, crate::mxc_engine::Error> {
        Self::parse_stored(json).map_err(|message| {
            crate::mxc_engine::Error::new(crate::mxc_engine::ErrorCode::MalformedRequest, message)
        })
    }

    /// Copy typed cumulative feedback from an ordinary SDK error.
    ///
    /// The presence of feedback alone does not mean another retry is safe.
    /// Check the current error, terminal feedback errors, and application limits.
    pub fn from_error(
        error: &crate::mxc_engine::Error,
    ) -> Result<Option<Self>, crate::mxc_engine::Error> {
        use crate::mxc_engine::{Error, ErrorCode};
        let Some(value) = error
            .details
            .as_deref()
            .and_then(|details| details.get("policyFailures"))
        else {
            return Ok(None);
        };
        let feedback: Self = serde_json::from_value(value.clone()).map_err(|_| {
            Error::new(
                ErrorCode::BackendError,
                "native policy failures are malformed",
            )
        })?;
        feedback
            .validate_storage()
            .map_err(|message| Error::new(ErrorCode::BackendError, message))?;
        Ok(Some(feedback))
    }
}

/// Invocation controls for an exact-JSON terminal operation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PtyJsonOptions {
    /// Authorize experimental backends separately from the JSON contract version.
    pub experimental: bool,
    /// Initial terminal dimensions.
    pub size: MxcPtySize,
}
