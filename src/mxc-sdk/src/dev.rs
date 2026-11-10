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
pub use crate::mxc_common::policy_preparation::{
    PolicyChange, PolicyChangeOperation, PreparedPolicyRequest,
};
use crate::sandbox::MxcPtySize;

/// Invocation controls for an exact-JSON operation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JsonOptions {
    /// Authorize experimental backends separately from the JSON contract version.
    pub experimental: bool,
}

/// Controls for preparing a candidate request without creating a container.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PolicyPreparationOptions {
    /// Authorize experimental backends independently of the JSON contract version.
    pub experimental: bool,
}

/// Prepare a restrictive candidate, without creating an environment or workload.
///
/// Supported only for native Windows ProcessContainer create-and-run requests.
/// Inspect and accept, edit or reject the result before submitting the chosen
/// request through ordinary strict [`run_json`] or [`spawn_json`].
/// Unsupported or unsafe observations fail explicitly. Request input is limited
/// to 8 MiB, the complete result to 32 MiB, and its report to 4,096 changes.
pub fn prepare_policy_json(
    json: &str,
    failures: &PolicyFailures,
    options: PolicyPreparationOptions,
) -> Result<PreparedPolicyRequest, crate::mxc_engine::Error> {
    crate::mxc_engine::prepare_policy_json(json, failures, options.experimental)
}

impl PreparedPolicyRequest {
    /// Serialize the owned candidate and its structured changes for caller storage.
    pub fn to_json(&self) -> Result<String, crate::mxc_engine::Error> {
        self.validate().map_err(|message| {
            crate::mxc_engine::Error::new(crate::mxc_engine::ErrorCode::MalformedRequest, message)
        })?;
        serde_json::to_string(self).map_err(|_| {
            crate::mxc_engine::Error::new(
                crate::mxc_engine::ErrorCode::BackendError,
                "cannot serialize policy preparation",
            )
        })
    }

    /// Restore candidate data; this is not policy approval or creation validation.
    pub fn from_json(json: &str) -> Result<Self, crate::mxc_engine::Error> {
        Self::parse(json).map_err(|message| {
            crate::mxc_engine::Error::new(crate::mxc_engine::ErrorCode::MalformedRequest, message)
        })
    }
}

impl PolicyFailures {
    /// Merge owned observation batches without changing either input or truncating data.
    pub fn merged_with(&self, newer: &Self) -> Result<Self, crate::mxc_engine::Error> {
        use crate::mxc_engine::{Error, ErrorCode};
        self.validate_storage()
            .map_err(|message| Error::new(ErrorCode::MalformedRequest, message))?;
        newer
            .validate_storage()
            .map_err(|message| Error::new(ErrorCode::MalformedRequest, message))?;
        let mut merged = Self::default();
        for result in self.results.iter().chain(&newer.results) {
            if !merged.results.contains(result) {
                merged.results.push(result.clone());
            }
        }
        merged
            .validate_storage()
            .map_err(|message| Error::new(ErrorCode::MalformedRequest, message))?;
        Ok(merged)
    }

    /// Serialize policy failures for application-owned storage.
    ///
    /// A terminal over-limit native result can be stored but cannot be
    /// prepared unchanged. Preparation validates the stricter input limits.
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

    /// Restore policy failures without interpreting them as policy approval.
    pub fn from_json(json: &str) -> Result<Self, crate::mxc_engine::Error> {
        Self::parse_stored(json).map_err(|message| {
            crate::mxc_engine::Error::new(crate::mxc_engine::ErrorCode::MalformedRequest, message)
        })
    }

    /// Copy the observations from one SDK error.
    ///
    /// The presence of observations alone does not mean another attempt is safe.
    /// Check the current error, terminal policy-failure errors, and application limits.
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
        let malformed = || {
            Error::new(
                ErrorCode::BackendError,
                "native policy failures are malformed",
            )
        };
        let failures: Self = serde_json::from_value(value.clone()).map_err(|_| malformed())?;
        failures.validate_storage().map_err(|_| malformed())?;
        Ok(Some(failures))
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
