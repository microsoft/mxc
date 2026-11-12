// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Prepare ordinary request JSON without creating an environment or workload.
//!
//! Every backend accepts empty observations and returns the request unchanged.
//! Non-empty observations route to the backend that produced their format;
//! native Windows ProcessContainer is currently the only one.

use crate::mxc_common::logger::{Logger, Mode};
use crate::mxc_common::models::ExecutionRequest;
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
    let result = if failures.results.is_empty() {
        PreparedPolicyRequest {
            request_json: json.to_owned(),
            changes: Vec::new(),
        }
    } else {
        prepare_backend_candidate(json, &request, failures, experimental)?
    };
    result.validate().map_err(MxcError::policy_validation)?;
    Ok(result)
}

#[cfg(target_os = "windows")]
fn prepare_backend_candidate(
    json: &str,
    request: &ExecutionRequest,
    failures: &PolicyFailures,
    experimental: bool,
) -> Result<PreparedPolicyRequest, MxcError> {
    use crate::mxc_common::models::ContainmentBackend;

    match request.containment {
        ContainmentBackend::ProcessContainer => {
            crate::process_container_common::policy_projection::prepare_candidate(
                json,
                request,
                failures,
                |candidate| {
                    super::parse_one_shot_json(
                        candidate,
                        experimental,
                        &mut Logger::new(Mode::Buffer),
                    )
                    .ok()
                },
            )
        }
        _ => Err(unsupported_observations()),
    }
}

#[cfg(not(target_os = "windows"))]
fn prepare_backend_candidate(
    _json: &str,
    _request: &ExecutionRequest,
    _failures: &PolicyFailures,
    _experimental: bool,
) -> Result<PreparedPolicyRequest, MxcError> {
    Err(unsupported_observations())
}

fn unsupported_observations() -> MxcError {
    MxcError::unsupported_containment(
        "the selected backend cannot apply these policy observations; currently only native Windows ProcessContainer produces and applies them",
    )
}
