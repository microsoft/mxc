// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::one_shot::Request as OneShotRequest;
use super::state_aware::{probe_containment, Containment, ContainmentProbeError};
use super::state_aware::{probe_phase, Phase, PhaseProbeError};
use super::state_aware::{
    DeprovisionRequest, ExecRequest, ProvisionRequest, StartRequest, StopRequest,
};

/// A validated request for the mutable `0.9.0-alpha` development contract.
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
        Containment::Wslc => {
            deserialize(json, "WSLC provision").map(|r| ProvisionRequest::Wslc(Box::new(r)))
        }
    }
}

/// Selects and deserializes one exact development request from raw JSON source.
///
/// An absent `phase` selects the one-shot contract. A present phase selects its
/// corresponding state-aware contract, with provision requests additionally
/// selected by their required `containment` declaration. The selected concrete
/// request still requires the exact `0.9.0-alpha` version marker.
///
/// # Errors
///
/// Returns [`RequestParseError::Phase`] when the phase declaration is malformed
/// or unsupported, [`RequestParseError::Containment`] when a provision
/// containment declaration is malformed or unsupported, and
/// [`RequestParseError::InvalidRequest`] when the selected concrete contract
/// rejects the document.
pub fn parse_request(json: &str) -> Result<Request, RequestParseError> {
    match probe_phase(json)? {
        None => deserialize(json, "one-shot")
            .map(Box::new)
            .map(Request::OneShot),
        Some(Phase::Provision) => parse_provision(json).map(Request::Provision),
        Some(Phase::Start) => deserialize(json, "start").map(Request::Start),
        Some(Phase::Exec) => deserialize(json, "exec").map(Request::Exec),
        Some(Phase::Stop) => deserialize(json, "stop").map(Request::Stop),
        Some(Phase::Deprovision) => deserialize(json, "deprovision").map(Request::Deprovision),
    }
}
