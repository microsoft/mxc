// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::one_shot::{Containment as OneShotContainment, Request as OneShotRequest};
use super::state_aware::{probe_containment, Containment, ContainmentProbeError};
use super::state_aware::{probe_phase, Phase, PhaseProbeError};
use super::state_aware::{
    DeprovisionRequest, ExecRequest, ProvisionRequest, StartRequest, StopRequest,
    WslcDeprovisionSessionRequest, WslcProvisionSessionRequest,
};
use super::NetworkAction;

/// A validated request for the mutable `1.1.0-alpha` development contract.
#[derive(Debug)]
pub enum Request {
    /// A one-shot execution request with no lifecycle phase.
    OneShot(Box<OneShotRequest>),
    ProvisionSession(WslcProvisionSessionRequest),

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
    DeprovisionSession(WslcDeprovisionSessionRequest),
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
        Containment::MicroVm => {
            deserialize(json, "MicroVM provision").map(ProvisionRequest::MicroVm)
        }
        Containment::Wslc => deserialize(json, "WSLC provision").map(ProvisionRequest::Wslc),
    }
}

fn parse_session<T>(json: &str, contract: &'static str) -> Result<T, RequestParseError>
where
    T: serde::de::DeserializeOwned,
{
    match probe_containment(json)? {
        Containment::Wslc => deserialize(json, contract),
        other => Err(RequestParseError::Containment(
            ContainmentProbeError::UnsupportedContainment(other.as_str().to_string()),
        )),
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
    let selects_microvm = matches!(
        request.containment.as_ref(),
        Some(OneShotContainment::Microvm)
    );
    if selects_microvm != request.microvm.as_ref().is_some() {
        return Err(RequestParseError::InvalidCombination {
            contract: "one-shot",
            message: "microvm.image is required exactly when containment is microvm",
        });
    }
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

/// Parse an MXC request using the development contract.
pub fn parse_request(json: &str) -> Result<Request, RequestParseError> {
    match probe_phase(json)? {
        None => parse_one_shot(json),
        Some(Phase::ProvisionSession) => {
            parse_session(json, "WSLC provision-session").map(Request::ProvisionSession)
        }
        Some(Phase::Provision) => parse_provision(json).map(Request::Provision),
        Some(Phase::Start) => deserialize(json, "start").map(Request::Start),
        Some(Phase::Exec) => deserialize(json, "exec").map(Request::Exec),
        Some(Phase::Stop) => deserialize(json, "stop").map(Request::Stop),
        Some(Phase::Deprovision) => deserialize(json, "deprovision").map(Request::Deprovision),
        Some(Phase::DeprovisionSession) => {
            parse_session(json, "WSLC deprovision-session").map(Request::DeprovisionSession)
        }
    }
}
