// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! State-aware request types — public domain output of the parser.
//!
//! `MxcRequest` is the bridge between parser and dispatcher: a one-shot call
//! produces `MxcRequest::OneShot(ExecutionRequest)`, a state-aware call produces
//! `MxcRequest::StateAware(ParsedStateAwareRequest)`. The parser narrows the
//! discriminator by presence of the wire-format `phase` field.
//!
//! `ParsedStateAwareRequest` bundles the inner `ExecutionRequest` (populated by
//! the same parser path one-shot uses for cross-cutting fields) with the
//! state-aware-only fields: `phase`, optional `containment`, optional
//! `sandbox_id`, and the raw JSON `experimental` block. The dispatcher
//! resolves the backend, deserialises the per-backend per-phase config from
//! `experimental_raw` via `deserialize_config<C>`, and asserts
//! `sandbox_id_required` for non-provision phases.

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::models::{ContainmentBackend, ExecutionRequest};
use crate::mxc_error::MxcError;

/// Lifecycle phase in a state-aware request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Phase {
    Provision,
    Start,
    Exec,
    Stop,
    Deprovision,
}

impl Phase {
    /// Wire-format string for the phase, matching the SDK's `Phase` union.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Provision => "provision",
            Self::Start => "start",
            Self::Exec => "exec",
            Self::Stop => "stop",
            Self::Deprovision => "deprovision",
        }
    }
}

impl std::fmt::Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<crate::wire::Phase> for Phase {
    fn from(p: crate::wire::Phase) -> Self {
        match p {
            crate::wire::Phase::Provision => Self::Provision,
            crate::wire::Phase::Start => Self::Start,
            crate::wire::Phase::Exec => Self::Exec,
            crate::wire::Phase::Stop => Self::Stop,
            crate::wire::Phase::Deprovision => Self::Deprovision,
        }
    }
}

/// Parsed state-aware request. Pairs the inner `ExecutionRequest` with the
/// state-aware-only wire fields the dispatcher consumes.
#[derive(Debug, Clone)]
pub struct ParsedStateAwareRequest {
    /// Domain model populated from the request's cross-cutting wire fields
    /// (`process`, `filesystem`, `network`, `ui`) — same path one-shot calls use.
    /// For non-exec phases the process-related fields (`script_code`,
    /// `working_directory`, `script_timeout`, `env`) are left at their default
    /// values; only exec carries process info on the wire.
    pub request: ExecutionRequest,
    pub phase: Phase,
    /// Present iff the request carried a `containment` field. Required for
    /// `provision`; for non-provision phases the dispatcher resolves the
    /// backend from the `sandbox_id` prefix instead.
    pub containment: Option<ContainmentBackend>,
    /// Present iff the request carried a `sandboxId` field. Required for all
    /// non-provision phases; absent for `provision`.
    pub sandbox_id: Option<String>,
    /// Raw `experimental` JSON object (un-narrowed). Shape:
    /// `{ <backend_key>: { <phase_name>: <typed-config>, ... }, ... }`.
    /// `deserialize_config<C>` navigates the two layers.
    pub experimental_raw: Option<Value>,
}

impl ParsedStateAwareRequest {
    /// Returns the typed per-phase config for the given backend, or `None` if
    /// the wire request does not carry one. Surfaces shape mismatches as
    /// `MxcError::MalformedRequest`.
    ///
    /// `backend_key` is the wire-format backend name (the `containment`
    /// string, e.g. "isolation_session") — typically pulled from a trait const
    /// at the dispatcher.
    pub fn deserialize_config<C: DeserializeOwned>(
        &self,
        backend_key: &str,
        phase_name: &str,
    ) -> Result<Option<C>, MxcError> {
        let Some(exp) = self.experimental_raw.as_ref() else {
            return Ok(None);
        };
        let Some(backend_obj) = exp.get(backend_key) else {
            return Ok(None);
        };
        let Some(phase_value) = backend_obj.get(phase_name) else {
            return Ok(None);
        };
        serde_json::from_value::<C>(phase_value.clone())
            .map(Some)
            .map_err(|e| {
                MxcError::malformed_request(format!(
                    "invalid config at experimental.{}.{}: {}",
                    backend_key, phase_name, e
                ))
            })
    }

    /// Returns the `sandbox_id` for non-provision phases. Surfaces a missing
    /// id as `MxcError::MalformedRequest` — the caller typically only invokes
    /// this on phases where the wire format requires it.
    pub fn sandbox_id_required(&self) -> Result<&str, MxcError> {
        self.sandbox_id.as_deref().ok_or_else(|| {
            MxcError::malformed_request(format!("phase {} requires a sandboxId", self.phase))
        })
    }
}

/// Public bridge between parser and dispatcher.
#[derive(Debug, Clone)]
pub enum MxcRequest {
    OneShot(ExecutionRequest),
    StateAware(ParsedStateAwareRequest),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_error::MxcErrorCode;
    use serde::Deserialize;
    use serde_json::json;

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct DummyStartConfig {
        configuration_id: String,
    }

    fn parsed_with_experimental(exp: Option<Value>, phase: Phase) -> ParsedStateAwareRequest {
        ParsedStateAwareRequest {
            request: ExecutionRequest::default(),
            phase,
            containment: None,
            sandbox_id: None,
            experimental_raw: exp,
        }
    }

    #[test]
    fn deserialize_config_returns_none_when_no_experimental_block() {
        let p = parsed_with_experimental(None, Phase::Start);
        let r = p
            .deserialize_config::<DummyStartConfig>("isolation_session", "start")
            .unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn deserialize_config_returns_none_when_backend_key_absent() {
        let p = parsed_with_experimental(Some(json!({})), Phase::Start);
        let r = p
            .deserialize_config::<DummyStartConfig>("isolation_session", "start")
            .unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn deserialize_config_returns_none_when_phase_absent() {
        let exp = json!({"isolation_session": {}});
        let p = parsed_with_experimental(Some(exp), Phase::Start);
        let r = p
            .deserialize_config::<DummyStartConfig>("isolation_session", "start")
            .unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn deserialize_config_round_trips_typed_config() {
        let exp = json!({
            "isolation_session": {
                "start": { "configuration_id": "small" }
            }
        });
        let p = parsed_with_experimental(Some(exp), Phase::Start);
        let r = p
            .deserialize_config::<DummyStartConfig>("isolation_session", "start")
            .unwrap()
            .expect("config should be present");
        assert_eq!(
            r,
            DummyStartConfig {
                configuration_id: "small".into(),
            }
        );
    }

    #[test]
    fn deserialize_config_rejects_shape_mismatch_as_malformed_request() {
        // Missing `configuration_id` — DummyStartConfig requires it.
        let exp = json!({
            "isolation_session": { "start": { "wrong_field": 42 } }
        });
        let p = parsed_with_experimental(Some(exp), Phase::Start);
        let err = p
            .deserialize_config::<DummyStartConfig>("isolation_session", "start")
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedRequest);
    }

    #[test]
    fn sandbox_id_required_returns_id_when_present() {
        let mut p = parsed_with_experimental(None, Phase::Start);
        p.sandbox_id = Some("iso:abcd1234".into());
        assert_eq!(p.sandbox_id_required().unwrap(), "iso:abcd1234");
    }

    #[test]
    fn sandbox_id_required_errors_when_absent() {
        let p = parsed_with_experimental(None, Phase::Start);
        let err = p.sandbox_id_required().unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedRequest);
    }
}
