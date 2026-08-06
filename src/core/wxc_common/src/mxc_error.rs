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
use std::fmt;

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

/// Structured detail for a failure that originated in an underlying platform
/// API.
///
/// Grouping these is what carries the envelope invariant: `native_code` and
/// `remediation` live beside `operation` rather than as independent optionals,
/// so a failure that names a status without naming the call it came from is
/// not something the normal construction path can produce. Build one with
/// [`ApiFailure::new`], which requires the operation up front, and add the
/// optional parts with the `with_*` builders. (The fields are `pub` for
/// destructuring, so a hand-rolled literal *can* still put an empty string in
/// `operation` — the type makes the invariant the easy path, not an enforced
/// one.) `MxcError` holds this boxed, so adding detail costs one pointer
/// rather than widening every `Result<_, MxcError>` in the codebase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiFailure {
    /// The API call that failed, namespaced by its interface — e.g.
    /// `IsoSessionOps.RunProcessWithOptionsAsync`. Kept low-cardinality and
    /// free of call parameters so it can be grouped in telemetry.
    pub operation: String,
    /// The underlying platform status as a string, e.g. `0x80070490`.
    pub native_code: Option<String>,
    /// The API's actionable "how to fix it" hint, when it supplies one.
    pub remediation: Option<String>,
}

impl ApiFailure {
    /// A failure that names its operation but carries no status or hint.
    pub fn new(operation: impl Into<String>) -> Self {
        Self {
            operation: operation.into(),
            native_code: None,
            remediation: None,
        }
    }

    pub fn with_native_code(mut self, native_code: impl Into<String>) -> Self {
        self.native_code = Some(native_code.into());
        self
    }

    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }
}

/// Typed Rust equivalent of the SDK `MxcError`.
///
/// Constructed via `MxcError::new(code, message)` or one of the per-code
/// convenience constructors (e.g. `MxcError::stale_id("...")`); attach
/// structured failure information with `with_details` or `with_api_failure`.
///
/// # Structured failure fields
///
/// An [`ApiFailure`] describes a failure that originated in an underlying
/// platform API. It is deliberately backend-neutral: `operation` names the
/// API call that failed, `native_code` carries the platform status as a
/// string (an HRESULT on Windows, an errno or equivalent elsewhere), and
/// `remediation` carries an actionable hint when the API supplies one. On the
/// wire these are flat siblings of `code` and `message`.
///
/// A failure MXC raises itself — a malformed request, a policy rejection, or
/// an internal failure with no API call in flight — leaves it unset and so
/// carries only `code` and `message`.
///
/// A new *backend-neutral* concept earns a field on `ApiFailure`;
/// *backend-specific* structured data belongs in `details`, which stays open
/// for that purpose.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MxcError {
    pub code: MxcErrorCode,
    pub message: String,
    pub details: Option<Value>,
    /// Present only when an underlying API operation was in flight.
    pub api_failure: Option<Box<ApiFailure>>,
}

/// Renders `code: message`, then the API detail in brackets when present —
/// e.g. `backend_error: The provision was not found. [IsoSessionOps.StopSessionAsync 0x80070490]`.
///
/// The bracketed suffix exists because `message` carries the API's own text
/// alone; without it a consumer that only logs the error (`error!("{e}")`,
/// `e.to_string()`) would lose the operation and status. This affects
/// **rendering only** — the wire envelope still carries `message` bare, with
/// the components in their own fields.
impl fmt::Display for MxcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)?;
        if let Some(api) = &self.api_failure {
            write!(f, " [{}", api.operation)?;
            if let Some(native_code) = &api.native_code {
                write!(f, " {native_code}")?;
            }
            f.write_str("]")?;
        }
        Ok(())
    }
}

impl std::error::Error for MxcError {}

impl MxcError {
    pub fn new(code: MxcErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: None,
            api_failure: None,
        }
    }

    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }

    /// Attaches the structured detail of an underlying API failure.
    pub fn with_api_failure(mut self, failure: ApiFailure) -> Self {
        self.api_failure = Some(Box::new(failure));
        self
    }

    /// The API call that failed, when one was in flight.
    pub fn operation(&self) -> Option<&str> {
        self.api_failure.as_ref().map(|f| f.operation.as_str())
    }

    /// The underlying platform status, when known. Never present without
    /// [`MxcError::operation`].
    pub fn native_code(&self) -> Option<&str> {
        self.api_failure
            .as_ref()
            .and_then(|f| f.native_code.as_deref())
    }

    /// The API's remediation hint, when it supplied one. Never present
    /// without [`MxcError::operation`].
    pub fn remediation(&self) -> Option<&str> {
        self.api_failure
            .as_ref()
            .and_then(|f| f.remediation.as_deref())
    }

    pub fn to_envelope(&self) -> ErrorEnvelope {
        ErrorEnvelope {
            code: self.code,
            message: self.message.clone(),
            details: self.details.clone(),
            operation: self.operation().map(str::to_string),
            native_code: self.native_code().map(str::to_string),
            remediation: self.remediation().map(str::to_string),
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

/// Wire shape of the `error` arm. `code` is a closed `MxcErrorCode` that
/// serialises to its snake_case wire string; every optional field is omitted
/// from JSON when absent.
///
/// See [`MxcError`] for the meaning of the structured failure fields and the
/// invariant relating them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ErrorEnvelope {
    pub code: MxcErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub details: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub operation: Option<String>,
    #[serde(
        rename = "nativeCode",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub native_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub remediation: Option<String>,
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
            code: MxcErrorCode::StaleId,
            message: "session expired".into(),
            details: Some(json!({"k": "v"})),
            operation: Some("IsoSessionOps.StopSessionAsync".into()),
            native_code: Some("0x80070490".into()),
            remediation: Some("Re-provision the sandbox.".into()),
        };
        let s = serde_json::to_string(&env).unwrap();
        let back: ErrorEnvelope = serde_json::from_str(&s).unwrap();
        assert_eq!(env, back);
    }

    #[test]
    fn error_envelope_omits_details_when_none() {
        let env = ErrorEnvelope {
            code: MxcErrorCode::StaleId,
            message: "x".into(),
            details: None,
            operation: None,
            native_code: None,
            remediation: None,
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
            code: MxcErrorCode::StaleId,
            message: "x".into(),
            details: None,
            operation: None,
            native_code: None,
            remediation: None,
        };
        let env: ResponseEnvelope<()> = ResponseEnvelope::Error(inner.clone());
        let json = serde_json::to_value(&env).unwrap();
        assert_eq!(json, json!({"error": {"code": "stale_id", "message": "x"}}));
    }

    #[test]
    fn response_envelope_round_trips_via_json() {
        let inner = ErrorEnvelope {
            code: MxcErrorCode::BackendError,
            message: "boom".into(),
            details: Some(json!({"x": 1})),
            operation: Some("IsoSessionOps.AddUserAsync".into()),
            native_code: Some("0x80004005".into()),
            remediation: None,
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

    // ── Structured failure fields ────────────────────────────────────────

    fn full_api_failure() -> ApiFailure {
        ApiFailure::new("IsoSessionOps.AddUserAsync")
            .with_native_code("0x80070490")
            .with_remediation("Re-provision the sandbox.")
    }

    #[test]
    fn new_leaves_structured_fields_unset() {
        let err = MxcError::backend_error("boom");
        assert_eq!(err.operation(), None);
        assert_eq!(err.native_code(), None);
        assert_eq!(err.remediation(), None);
    }

    #[test]
    fn structured_builders_set_their_fields() {
        let err = MxcError::backend_error("boom").with_api_failure(full_api_failure());
        assert_eq!(err.operation(), Some("IsoSessionOps.AddUserAsync"));
        assert_eq!(err.native_code(), Some("0x80070490"));
        assert_eq!(err.remediation(), Some("Re-provision the sandbox."));
    }

    /// `native_code` and `remediation` live inside `ApiFailure`, so the
    /// normal construction path cannot set them without an `operation` —
    /// the envelope invariant holds by construction rather than by
    /// convention.
    #[test]
    fn structured_detail_always_carries_an_operation() {
        let err = MxcError::backend_error("boom")
            .with_api_failure(ApiFailure::new("IsoSessionOps.AddUserAsync"));
        assert_eq!(err.operation(), Some("IsoSessionOps.AddUserAsync"));
        assert_eq!(err.native_code(), None);
        assert_eq!(err.remediation(), None);
    }

    // ── Display keeps the diagnostic detail a logger would otherwise lose ─

    /// `message` carries the API's own text alone, so a consumer that only
    /// logs the error would lose the operation and status. `Display`
    /// re-attaches them.
    #[test]
    fn display_appends_operation_and_native_code() {
        let err = MxcError::backend_error("The provision was not found.")
            .with_api_failure(full_api_failure());
        assert_eq!(
            err.to_string(),
            "backend_error: The provision was not found. \
             [IsoSessionOps.AddUserAsync 0x80070490]"
        );
    }

    /// A status that could not be read leaves `native_code` absent; the
    /// operation alone is still worth rendering.
    #[test]
    fn display_renders_operation_without_native_code() {
        let err = MxcError::backend_error("boom")
            .with_api_failure(ApiFailure::new("IsoSessionOps.AddUserAsync"));
        assert_eq!(
            err.to_string(),
            "backend_error: boom [IsoSessionOps.AddUserAsync]"
        );
    }

    /// A failure MXC raises itself has no API detail, so the rendering has
    /// nothing to append.
    #[test]
    fn display_without_api_failure_is_code_and_message_only() {
        assert_eq!(
            MxcError::policy_validation("appId must not contain control characters").to_string(),
            "policy_validation: appId must not contain control characters"
        );
    }

    /// `Display` is a rendering concern only — the wire `message` stays the
    /// bare API text, with the components in their own fields.
    #[test]
    fn display_enrichment_does_not_leak_into_the_envelope() {
        let env = MxcError::backend_error("The provision was not found.")
            .with_api_failure(full_api_failure())
            .to_envelope();
        assert_eq!(env.message, "The provision was not found.");
        assert!(!env.message.contains("IsoSessionOps"));
        assert!(!env.message.contains("0x80070490"));
    }

    #[test]
    fn to_envelope_copies_structured_fields_through() {
        let env = MxcError::backend_error("boom")
            .with_api_failure(full_api_failure())
            .to_envelope();
        assert_eq!(env.operation.as_deref(), Some("IsoSessionOps.AddUserAsync"));
        assert_eq!(env.native_code.as_deref(), Some("0x80070490"));
        assert_eq!(
            env.remediation.as_deref(),
            Some("Re-provision the sandbox.")
        );
    }

    /// The wire key is camelCase `nativeCode`, not the Rust field name
    /// `native_code`. The SDK reads `nativeCode`; a lost serde rename would
    /// silently strip the field from every consumer.
    #[test]
    fn native_code_serialises_as_camel_case_key() {
        let env = MxcError::backend_error("boom")
            .with_api_failure(
                ApiFailure::new("IsoSessionOps.AddUserAsync").with_native_code("0x80070490"),
            )
            .to_envelope();
        let s = serde_json::to_string(&env).unwrap();
        assert!(
            s.contains("\"nativeCode\""),
            "expected camelCase key in {s}"
        );
        assert!(!s.contains("native_code"), "found snake_case key in {s}");
    }

    #[test]
    fn structured_envelope_serialises_all_fields() {
        let env = MxcError::stale_id("agent user not found")
            .with_api_failure(
                ApiFailure::new("IsoSessionOps.StopSessionAsync")
                    .with_native_code("0x80070490")
                    .with_remediation("Re-provision the sandbox."),
            )
            .to_envelope();
        let json = serde_json::to_value(&env).unwrap();
        assert_eq!(
            json,
            json!({
                "code": "stale_id",
                "message": "agent user not found",
                "operation": "IsoSessionOps.StopSessionAsync",
                "nativeCode": "0x80070490",
                "remediation": "Re-provision the sandbox.",
            })
        );
    }

    #[test]
    fn envelope_omits_each_structured_field_when_unset() {
        // Only `operation` set: the other two must not appear at all.
        let env = MxcError::backend_error("boom")
            .with_api_failure(ApiFailure::new("IsoSessionOps.AddUserAsync"))
            .to_envelope();
        let s = serde_json::to_string(&env).unwrap();
        assert!(s.contains("\"operation\""));
        assert!(
            !s.contains("nativeCode"),
            "unset nativeCode leaked into {s}"
        );
        assert!(
            !s.contains("remediation"),
            "unset remediation leaked into {s}"
        );
    }

    /// An MXC-side rejection has no API call in flight, so it carries neither
    /// `operation` nor its refinements — see the invariant on `MxcError`.
    #[test]
    fn mxc_side_rejection_carries_no_structured_fields() {
        let json = serde_json::to_value(MxcError::policy_validation("bad").to_envelope()).unwrap();
        assert_eq!(json, json!({"code": "policy_validation", "message": "bad"}));
    }
}
