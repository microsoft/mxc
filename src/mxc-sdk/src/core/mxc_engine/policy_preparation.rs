// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Prepare ordinary request JSON without creating an environment or workload.

use crate::mxc_common::logger::{Logger, Mode};
use crate::mxc_common::models::ContainmentBackend;
use crate::mxc_common::mxc_error::MxcError;
use crate::mxc_common::policy_failures::PolicyFailures;
use crate::mxc_common::policy_preparation::{PreparedPolicyRequest, MAX_REQUEST_BYTES};

use super::Error;

#[cfg(test)]
#[path = "policy_preparation_tests.rs"]
mod tests;

pub(crate) fn prepare_policy_json(
    json: &str,
    failures: &PolicyFailures,
    experimental: bool,
) -> Result<PreparedPolicyRequest, Error> {
    if json.len() > MAX_REQUEST_BYTES {
        return Err(MxcError::malformed_request(
            "policy preparation request exceeds its byte limit",
        )
        .into());
    }
    failures.validate().map_err(MxcError::malformed_request)?;
    let mut logger = Logger::new(Mode::Buffer);
    let request = super::parse_one_shot_json(json, experimental, &mut logger).map_err(|error| {
        Error::new(
            error.code,
            "policy preparation requires a valid create-and-run request in a registered JSON contract",
        )
    })?;
    if !cfg!(target_os = "windows") || request.containment != ContainmentBackend::ProcessContainer {
        return Err(MxcError::unsupported_containment(
            "policy preparation requires native Windows ProcessContainer",
        )
        .into());
    }
    #[cfg(target_os = "windows")]
    {
        let result = crate::process_container_common::policy_projection::prepare_candidate(
            json,
            &request,
            failures,
            |candidate| {
                super::parse_one_shot_json(candidate, experimental, &mut Logger::new(Mode::Buffer))
                    .ok()
            },
        )?;
        result.validate().map_err(MxcError::policy_validation)?;
        Ok(result)
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err(MxcError::unsupported_containment(
            "policy preparation requires native Windows ProcessContainer",
        )
        .into())
    }
}
