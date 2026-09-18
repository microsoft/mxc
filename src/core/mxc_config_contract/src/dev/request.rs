// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::one_shot::{Containment as OneShotContainment, Request as OneShotRequest};

/// A validated request for the mutable `0.9.0-alpha` development contract.
#[derive(Debug)]
pub enum Request {
    /// An operation-neutral configuration request.
    OneShot(Box<OneShotRequest>),
}

/// An error encountered while selecting or deserializing a development request.
#[derive(Debug, thiserror::Error)]
pub enum RequestParseError {
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
/// containment requires fields that the request omitted.
pub fn validate_one_shot_request(request: &OneShotRequest) -> Result<(), RequestParseError> {
    if request.process.as_ref().is_none() {
        return Err(RequestParseError::InvalidCombination {
            contract: "one-shot",
            message: "one-shot execution requires process.commandLine",
        });
    }
    if matches!(
        request.containment.as_ref(),
        Some(OneShotContainment::IsolationSession)
    ) && request.network.as_ref().is_none()
    {
        return Err(RequestParseError::InvalidCombination {
            contract: "one-shot",
            message: "IsolationSession requires an explicit network policy",
        });
    }
    if request
        .experimental
        .as_ref()
        .is_some_and(|experimental| experimental.isolation_session.as_ref().is_some())
    {
        return Err(RequestParseError::InvalidCombination {
            contract: "one-shot",
            message: "experimental.isolation_session is accepted only by lifecycle provision",
        });
    }
    Ok(())
}

/// Selects and deserializes one exact development request from raw JSON source.
///
/// Lifecycle operation and sandbox identity are API parameters rather than
/// configuration fields. This parser therefore accepts only the single
/// operation-neutral request shape and applies one-shot semantic validation.
///
/// # Errors
///
/// Returns [`RequestParseError::InvalidRequest`] when the contract rejects the
/// document. Returns [`RequestParseError::InvalidCombination`] when individually
/// valid fields violate a one-shot request invariant.
pub fn parse_request(json: &str) -> Result<Request, RequestParseError> {
    parse_one_shot(json)
}

/// Deserializes the operation-neutral development request without applying
/// one-shot-only semantic requirements.
pub fn parse_operation_request(json: &str) -> Result<OneShotRequest, RequestParseError> {
    deserialize(json, "operation")
}
