// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::one_shot::{Containment as OneShotContainment, Request as OneShotRequest};
use super::state_aware::{probe_containment, Containment, ContainmentProbeError};
use super::state_aware::{probe_phase, Phase, PhaseProbeError};
use super::state_aware::{
    DeprovisionRequest, ExecRequest, ProvisionRequest, StartRequest, StopRequest,
};
use super::NetworkAction;

/// A validated request for the mutable `0.10.0-alpha` development contract.
#[derive(Debug)]
pub enum Request {
    /// A one-shot execution request with no lifecycle phase.
    OneShot(Box<OneShotRequest>),
    /// A state-aware provision request selected by its containment backend.
    Provision(ProvisionRequest),
    /// A state-aware start request.
    Start(StartRequest),
    /// A state-aware process-execution request.
    Exec(ExecRequest),
    /// A state-aware stop request.
    Stop(StopRequest),
    /// A state-aware deprovision request.
    Deprovision(DeprovisionRequest),
}

/// An error encountered while selecting or deserializing a development request.
#[derive(Debug, thiserror::Error)]
pub enum RequestParseError {
    /// The lifecycle phase declaration is malformed or unsupported.
    #[error("Invalid phase declaration")]
    Phase(#[from] PhaseProbeError),

    /// A provision request's containment declaration is malformed or unsupported.
    #[error("Invalid provision containment declaration")]
    Containment(#[from] ContainmentProbeError),

    /// The selected request contract rejected the complete document.
    #[error("Invalid {contract} request")]
    InvalidRequest {
        /// Human-readable name of the selected contract.
        contract: &'static str,
        /// Structured deserialization error from the selected contract.
        #[source]
        source: serde_json::Error,
    },

    /// The selected request is structurally valid but violates a cross-field constraint.
    #[error("Invalid {contract} request: {message}")]
    InvalidCombination {
        /// Human-readable name of the selected contract.
        contract: &'static str,
        /// Description of the violated cross-field constraint.
        message: &'static str,
    },
}

fn deserialize<T>(json: &str, contract: &'static str) -> Result<T, RequestParseError>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_str(json)
        .map_err(|source| RequestParseError::InvalidRequest { contract, source })
}

fn parse_provision(json: &str) -> Result<ProvisionRequest, RequestParseError> {
    match probe_containment(json)? {
        Containment::WindowsSandbox => {
            deserialize(json, "Windows Sandbox provision").map(ProvisionRequest::WindowsSandbox)
        }
        Containment::IsolationSession => {
            deserialize(json, "IsolationSession provision").map(ProvisionRequest::IsolationSession)
        }
        Containment::Wslc => deserialize(json, "WSLC provision").map(ProvisionRequest::Wslc),
    }
}

fn parse_one_shot(json: &str) -> Result<Request, RequestParseError> {
    let request: OneShotRequest = deserialize(json, "one-shot")?;
    validate_one_shot_request(&request)?;
    Ok(Request::OneShot(Box::new(request)))
}

/// Validates cross-field invariants on an already-deserialized exact one-shot
/// request.
///
/// # Errors
///
/// Returns [`RequestParseError::InvalidCombination`] when the selected
/// containment violates an exact-contract cross-field invariant. These checks
/// run before normalization; runtime backend capability validation occurs
/// later on the resulting execution request.
pub fn validate_one_shot_request(request: &OneShotRequest) -> Result<(), RequestParseError> {
    match request.containment.as_ref() {
        Some(OneShotContainment::IsolationSession) => {
            validate_isolation_session_one_shot_network(request)
        }
        _ => Ok(()),
    }
}

fn validate_isolation_session_one_shot_network(
    request: &OneShotRequest,
) -> Result<(), RequestParseError> {
    let has_canonical_network = request.network.as_ref().is_some_and(|network| {
        network.egress.as_ref().is_some_and(|egress| {
            matches!(egress.default.as_ref(), Some(NetworkAction::Allow))
                && egress.allow.as_ref().is_none()
                && egress.deny.as_ref().is_none()
        }) && network.ingress.as_ref().is_some_and(|ingress| {
            matches!(ingress.default.as_ref(), Some(NetworkAction::Allow))
                && matches!(ingress.host_loopback.as_ref(), Some(NetworkAction::Allow))
        })
    });
    let has_runtime_proxy = request
        .runtime_config
        .as_ref()
        .is_some_and(|runtime| runtime.network_proxy.as_ref().is_some());

    if !has_canonical_network || has_runtime_proxy {
        return Err(RequestParseError::InvalidCombination {
            contract: "one-shot",
            message: "IsolationSession requires an explicit network policy with \
                network.egress.default=allow, network.ingress.default=allow, and \
                network.ingress.hostLoopback=allow, without rules or runtimeConfig.networkProxy",
        });
    }
    Ok(())
}

/// Selects and deserializes one exact development request from raw JSON source.
///
/// An absent `phase` selects the one-shot contract. A present phase selects its
/// corresponding state-aware contract, with provision requests additionally
/// selected by their required `containment` declaration. The selected concrete
/// request still requires the exact `0.10.0-alpha` version marker.
///
/// # Errors
///
/// Returns [`RequestParseError::Phase`] when the phase declaration is malformed
/// or unsupported, [`RequestParseError::Containment`] when a provision
/// containment declaration is malformed or unsupported, and
/// [`RequestParseError::InvalidRequest`] when the selected concrete contract
/// rejects the document. Returns [`RequestParseError::InvalidCombination`] when
/// individually valid fields violate a request-level invariant.
pub fn parse_request(json: &str) -> Result<Request, RequestParseError> {
    match probe_phase(json)? {
        None => parse_one_shot(json),
        Some(Phase::Provision) => parse_provision(json).map(Request::Provision),
        Some(Phase::Start) => deserialize(json, "start").map(Request::Start),
        Some(Phase::Exec) => deserialize(json, "exec").map(Request::Exec),
        Some(Phase::Stop) => deserialize(json, "stop").map(Request::Stop),
        Some(Phase::Deprovision) => deserialize(json, "deprovision").map(Request::Deprovision),
    }
}
