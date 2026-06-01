// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! State-aware wire-format error model and response envelope.
//!
//! `MxcError` is the typed Rust value returned from `StatefulSandboxBackend`
//! trait methods and dispatch. Backends construct it with a closed `MxcErrorCode`
//! plus a free-form message and optional `details`. The dispatcher serialises an
//! `Err(MxcError)` to the JSON `{"error": {...}}` envelope on stdout; success
//! values from non-exec phases serialise to `{"result": {...}}`.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Closed set of wire-format error codes. Matches the SDK's `ErrorCode` string
/// union one-for-one; serialised as snake_case strings on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MxcErrorCode {
    MalformedRequest,
    UnsupportedContainment,
    UnsupportedPhase,
    BackendUnavailable,
    MalformedId,
    StaleId,
    NotProvisioned,
    NotStarted,
    AlreadyStarted,
    AlreadyStopped,
    PolicyValidation,
    BackendError,
}

impl MxcErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MalformedRequest => "malformed_request",
            Self::UnsupportedContainment => "unsupported_containment",
            Self::UnsupportedPhase => "unsupported_phase",
            Self::BackendUnavailable => "backend_unavailable",
            Self::MalformedId => "malformed_id",
            Self::StaleId => "stale_id",
            Self::NotProvisioned => "not_provisioned",
            Self::NotStarted => "not_started",
            Self::AlreadyStarted => "already_started",
            Self::AlreadyStopped => "already_stopped",
            Self::PolicyValidation => "policy_validation",
            Self::BackendError => "backend_error",
        }
    }
}

impl std::fmt::Display for MxcErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Typed Rust equivalent of the SDK `MxcError`.
///
/// Constructed via `MxcError::new(code, message)` or one of the per-code
/// convenience constructors (e.g. `MxcError::stale_id("...")`); attach
/// structured failure information with `.with_details(json!({...}))`.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{code}: {message}")]
pub struct MxcError {
    pub code: MxcErrorCode,
    pub message: String,
    pub details: Option<Value>,
}

impl MxcError {
    pub fn new(code: MxcErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: None,
        }
    }

    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }

    pub fn to_envelope(&self) -> ErrorEnvelope {
        ErrorEnvelope {
            code: self.code.as_str().to_string(),
            message: self.message.clone(),
            details: self.details.clone(),
        }
    }
}

// Per-code convenience constructors. One per `MxcErrorCode` variant.
impl MxcError {
    pub fn malformed_request(message: impl Into<String>) -> Self {
        Self::new(MxcErrorCode::MalformedRequest, message)
    }
    pub fn unsupported_containment(message: impl Into<String>) -> Self {
        Self::new(MxcErrorCode::UnsupportedContainment, message)
    }
    pub fn unsupported_phase(message: impl Into<String>) -> Self {
        Self::new(MxcErrorCode::UnsupportedPhase, message)
    }
    pub fn backend_unavailable(message: impl Into<String>) -> Self {
        Self::new(MxcErrorCode::BackendUnavailable, message)
    }
    pub fn malformed_id(message: impl Into<String>) -> Self {
        Self::new(MxcErrorCode::MalformedId, message)
    }
    pub fn stale_id(message: impl Into<String>) -> Self {
        Self::new(MxcErrorCode::StaleId, message)
    }
    pub fn not_provisioned(message: impl Into<String>) -> Self {
        Self::new(MxcErrorCode::NotProvisioned, message)
    }
    pub fn not_started(message: impl Into<String>) -> Self {
        Self::new(MxcErrorCode::NotStarted, message)
    }
    pub fn already_started(message: impl Into<String>) -> Self {
        Self::new(MxcErrorCode::AlreadyStarted, message)
    }
    pub fn already_stopped(message: impl Into<String>) -> Self {
        Self::new(MxcErrorCode::AlreadyStopped, message)
    }
    pub fn policy_validation(message: impl Into<String>) -> Self {
        Self::new(MxcErrorCode::PolicyValidation, message)
    }
    pub fn backend_error(message: impl Into<String>) -> Self {
        Self::new(MxcErrorCode::BackendError, message)
    }
}

/// Wire shape of the `error` arm. `code` is a snake_case string from
/// `MxcErrorCode::as_str`; `details` is omitted from JSON when absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorEnvelope {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub details: Option<Value>,
}

/// Top-level non-exec response envelope: `{"result": <T>}` on success, or
/// `{"error": {...}}` on failure. `T` is per-phase (e.g. provision metadata,
/// or `()` for phases without a return body).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseEnvelope<T> {
    Result(T),
    Error(ErrorEnvelope),
}

impl<T> ResponseEnvelope<T> {
    pub fn from_error(err: &MxcError) -> Self {
        Self::Error(err.to_envelope())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn every_code_serialises_to_its_wire_string() {
        let cases = [
            (MxcErrorCode::MalformedRequest, "malformed_request"),
            (
                MxcErrorCode::UnsupportedContainment,
                "unsupported_containment",
            ),
            (MxcErrorCode::UnsupportedPhase, "unsupported_phase"),
            (MxcErrorCode::BackendUnavailable, "backend_unavailable"),
            (MxcErrorCode::MalformedId, "malformed_id"),
            (MxcErrorCode::StaleId, "stale_id"),
            (MxcErrorCode::NotProvisioned, "not_provisioned"),
            (MxcErrorCode::NotStarted, "not_started"),
            (MxcErrorCode::AlreadyStarted, "already_started"),
            (MxcErrorCode::AlreadyStopped, "already_stopped"),
            (MxcErrorCode::PolicyValidation, "policy_validation"),
            (MxcErrorCode::BackendError, "backend_error"),
        ];
        for (code, wire) in cases {
            assert_eq!(code.as_str(), wire);
            assert_eq!(code.to_string(), wire);
            let json = serde_json::to_value(code).unwrap();
            assert_eq!(json, Value::String(wire.to_string()));
            let parsed: MxcErrorCode = serde_json::from_value(json).unwrap();
            assert_eq!(parsed, code);
        }
    }

    #[test]
    fn convenience_constructors_set_correct_codes() {
        assert_eq!(
            MxcError::malformed_request("x").code,
            MxcErrorCode::MalformedRequest
        );
        assert_eq!(
            MxcError::unsupported_containment("x").code,
            MxcErrorCode::UnsupportedContainment
        );
        assert_eq!(
            MxcError::unsupported_phase("x").code,
            MxcErrorCode::UnsupportedPhase
        );
        assert_eq!(
            MxcError::backend_unavailable("x").code,
            MxcErrorCode::BackendUnavailable
        );
        assert_eq!(MxcError::malformed_id("x").code, MxcErrorCode::MalformedId);
        assert_eq!(MxcError::stale_id("x").code, MxcErrorCode::StaleId);
        assert_eq!(
            MxcError::not_provisioned("x").code,
            MxcErrorCode::NotProvisioned
        );
        assert_eq!(MxcError::not_started("x").code, MxcErrorCode::NotStarted);
        assert_eq!(
            MxcError::already_started("x").code,
            MxcErrorCode::AlreadyStarted
        );
        assert_eq!(
            MxcError::already_stopped("x").code,
            MxcErrorCode::AlreadyStopped
        );
        assert_eq!(
            MxcError::policy_validation("x").code,
            MxcErrorCode::PolicyValidation
        );
        assert_eq!(
            MxcError::backend_error("x").code,
            MxcErrorCode::BackendError
        );
    }

    #[test]
    fn error_to_envelope_carries_code_and_message() {
        let env = MxcError::stale_id("session expired").to_envelope();
        let json = serde_json::to_value(&env).unwrap();
        assert_eq!(
            json,
            json!({"code": "stale_id", "message": "session expired"})
        );
    }

    #[test]
    fn error_with_details_includes_details_in_envelope() {
        let err = MxcError::backend_error("hresult failure")
            .with_details(json!({"hresult": "0x80004005"}));
        let env = err.to_envelope();
        let json = serde_json::to_value(&env).unwrap();
        assert_eq!(
            json,
            json!({
                "code": "backend_error",
                "message": "hresult failure",
                "details": {"hresult": "0x80004005"},
            })
        );
    }

    #[test]
    fn error_envelope_round_trips_via_json() {
        let env = ErrorEnvelope {
            code: "stale_id".into(),
            message: "session expired".into(),
            details: Some(json!({"k": "v"})),
        };
        let s = serde_json::to_string(&env).unwrap();
        let back: ErrorEnvelope = serde_json::from_str(&s).unwrap();
        assert_eq!(env, back);
    }

    #[test]
    fn error_envelope_omits_details_when_none() {
        let env = ErrorEnvelope {
            code: "stale_id".into(),
            message: "x".into(),
            details: None,
        };
        let s = serde_json::to_string(&env).unwrap();
        assert!(!s.contains("details"));
    }

    #[test]
    fn response_envelope_result_serialises_with_result_key() {
        let env: ResponseEnvelope<&str> = ResponseEnvelope::Result("hello");
        let json = serde_json::to_value(&env).unwrap();
        assert_eq!(json, json!({"result": "hello"}));
    }

    #[test]
    fn response_envelope_error_serialises_with_error_key() {
        let inner = ErrorEnvelope {
            code: "stale_id".into(),
            message: "x".into(),
            details: None,
        };
        let env: ResponseEnvelope<()> = ResponseEnvelope::Error(inner.clone());
        let json = serde_json::to_value(&env).unwrap();
        assert_eq!(json, json!({"error": {"code": "stale_id", "message": "x"}}));
    }

    #[test]
    fn response_envelope_round_trips_via_json() {
        let inner = ErrorEnvelope {
            code: "backend_error".into(),
            message: "boom".into(),
            details: Some(json!({"x": 1})),
        };
        let env: ResponseEnvelope<()> = ResponseEnvelope::Error(inner);
        let s = serde_json::to_string(&env).unwrap();
        let back: ResponseEnvelope<()> = serde_json::from_str(&s).unwrap();
        assert_eq!(env, back);
    }

    #[test]
    fn response_envelope_from_error_wraps_via_to_envelope() {
        let err = MxcError::policy_validation("nope").with_details(json!({"field": "containment"}));
        let env: ResponseEnvelope<()> = ResponseEnvelope::from_error(&err);
        let json = serde_json::to_value(&env).unwrap();
        assert_eq!(
            json,
            json!({
                "error": {
                    "code": "policy_validation",
                    "message": "nope",
                    "details": {"field": "containment"},
                }
            })
        );
    }
}
