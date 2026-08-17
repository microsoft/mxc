// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The SDK's own error type — a crate-owned facade over the internal
//! `wxc_common` error, so the public API never exposes the foundation crate.

use wxc_common::mxc_error::{MxcError, MxcErrorCode};

/// Closed set of error codes the SDK can return. Mirrors the wire-format codes
/// (serialised as snake_case strings) one-for-one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
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

impl ErrorCode {
    /// The wire-format (snake_case) string for this code.
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

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<MxcErrorCode> for ErrorCode {
    fn from(code: MxcErrorCode) -> Self {
        match code {
            MxcErrorCode::MalformedRequest => Self::MalformedRequest,
            MxcErrorCode::UnsupportedContainment => Self::UnsupportedContainment,
            MxcErrorCode::UnsupportedPhase => Self::UnsupportedPhase,
            MxcErrorCode::BackendUnavailable => Self::BackendUnavailable,
            MxcErrorCode::MalformedId => Self::MalformedId,
            MxcErrorCode::StaleId => Self::StaleId,
            MxcErrorCode::NotProvisioned => Self::NotProvisioned,
            MxcErrorCode::NotStarted => Self::NotStarted,
            MxcErrorCode::AlreadyStarted => Self::AlreadyStarted,
            MxcErrorCode::AlreadyStopped => Self::AlreadyStopped,
            MxcErrorCode::PolicyValidation => Self::PolicyValidation,
            MxcErrorCode::BackendError => Self::BackendError,
        }
    }
}

/// An error returned by the SDK's fallible operations
/// ([`build_request`](crate::build_request) / [`spawn`](crate::spawn)).
///
/// The detail fields sit flat on the error, the same way the wire format, the
/// C ABI and the C# SDK carry them — one failure reads the same whichever of
/// the four surfaces a caller is holding.
///
/// Marked `#[non_exhaustive]`, as both the wire envelope and the internal error
/// this facades already are: read the fields, and build one with
/// [`Error::new`] rather than by literal, so a later field costs a downstream
/// crate nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Error {
    /// The closed error code.
    pub code: ErrorCode,
    /// A human-readable message.
    pub message: String,
    /// The API call that failed, namespaced by its interface and free of call
    /// parameters, so it can be grouped in telemetry. Absent when the failure
    /// was raised before any API call.
    pub operation: Option<String>,
    /// The underlying platform status, e.g. `0x80070490`. Only ever present
    /// alongside [`operation`](Self::operation): a status with no call to
    /// attribute it to is not something a producer can express.
    pub native_code: Option<String>,
    /// An actionable "how to fix it" hint, when the failure carries one.
    pub remediation: Option<String>,
}

impl Error {
    /// An error with no API detail — the shape for failures raised before any
    /// API call was made.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            operation: None,
            native_code: None,
            remediation: None,
        }
    }
}

/// Renders `code: message`, then the failing call and its status in brackets
/// when present — so a consumer that only logs the error does not silently lose
/// the diagnosis. Mirrors the internal type's rendering.
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)?;
        if let Some(operation) = &self.operation {
            write!(f, " [{operation}")?;
            if let Some(native_code) = &self.native_code {
                write!(f, " {native_code}")?;
            }
            write!(f, "]")?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {}

impl From<MxcError> for Error {
    fn from(error: MxcError) -> Self {
        let (operation, native_code, remediation) = match error.api_failure {
            Some(failure) => {
                let failure = *failure;
                (
                    Some(failure.operation),
                    failure.native_code,
                    failure.remediation,
                )
            }
            None => (None, None, None),
        };
        Self {
            code: error.code.into(),
            message: error.message,
            operation,
            native_code,
            remediation,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::mxc_error::{ApiFailure as InnerFailure, MxcError};

    /// The conversion carries the API detail across, rather than keeping only
    /// the code and message.
    ///
    /// The regression this pins: the facade used to copy `code`/`message` and
    /// drop `api_failure` on the floor, so every in-process caller — Rust SDK,
    /// FFI, and C# alike — lost the operation and platform status that the
    /// backend had already produced.
    #[test]
    fn the_conversion_preserves_the_api_detail() {
        let inner = MxcError::backend_error("The provision was not found.").with_api_failure(
            InnerFailure::new("IsoSessionOps.StopSessionAsync")
                .with_native_code("0x80070490")
                .with_remediation("Provision the session first."),
        );

        let error = Error::from(inner);

        assert_eq!(error.code, ErrorCode::BackendError);
        assert_eq!(error.message, "The provision was not found.");
        assert_eq!(
            error.operation.as_deref(),
            Some("IsoSessionOps.StopSessionAsync")
        );
        assert_eq!(error.native_code.as_deref(), Some("0x80070490"));
        assert_eq!(
            error.remediation.as_deref(),
            Some("Provision the session first.")
        );
    }

    /// A failure that names only its operation leaves the optional halves
    /// absent rather than empty — `None` and `Some("")` are different answers
    /// to "did the API supply a status?".
    #[test]
    fn an_operation_without_a_status_leaves_the_rest_absent() {
        let error = Error::from(
            MxcError::backend_error("boom").with_api_failure(InnerFailure::new("Iface.Call")),
        );

        assert_eq!(error.operation.as_deref(), Some("Iface.Call"));
        assert_eq!(error.native_code, None);
        assert_eq!(error.remediation, None);
    }

    /// An error raised before any API call carries no detail at all, whether it
    /// came through the conversion or was constructed directly.
    #[test]
    fn an_error_raised_before_any_api_call_carries_no_detail() {
        let converted = Error::from(MxcError::malformed_request("bad json"));

        assert_eq!(converted.operation, None);
        assert_eq!(converted.native_code, None);
        assert_eq!(converted.remediation, None);

        let constructed = Error::new(ErrorCode::BackendError, "x");

        assert_eq!(constructed.operation, None);
        assert_eq!(constructed.native_code, None);
        assert_eq!(constructed.remediation, None);
    }

    /// The flat shape admits a remediation with no operation. `Display` renders
    /// only the operation and status, so that combination has to come out as
    /// plain `code: message` rather than as an empty bracket.
    #[test]
    fn a_remediation_without_an_operation_renders_without_brackets() {
        let error = Error {
            remediation: Some("Supply a supported policy.".into()),
            ..Error::new(ErrorCode::PolicyValidation, "unsupported policy")
        };

        assert_eq!(error.to_string(), "policy_validation: unsupported policy");
    }

    /// Rendering keeps the operation and status visible, so a consumer that
    /// only logs `{e}` does not lose the diagnosis.
    #[test]
    fn display_keeps_the_operation_and_status_visible() {
        let with_status = Error::from(
            MxcError::backend_error("The provision was not found.").with_api_failure(
                InnerFailure::new("IsoSessionOps.StopSessionAsync").with_native_code("0x80070490"),
            ),
        );
        assert_eq!(
            with_status.to_string(),
            "backend_error: The provision was not found. \
             [IsoSessionOps.StopSessionAsync 0x80070490]"
        );

        // No status: the brackets carry the operation alone rather than a
        // dangling separator.
        let without_status = Error::from(
            MxcError::backend_error("nope").with_api_failure(InnerFailure::new("Iface.Call")),
        );
        assert_eq!(
            without_status.to_string(),
            "backend_error: nope [Iface.Call]"
        );

        // No detail at all: unchanged from before this change.
        assert_eq!(
            Error::from(MxcError::malformed_request("bad")).to_string(),
            "malformed_request: bad"
        );
    }
}
