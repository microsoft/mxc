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
/// ([`build_request`](crate::build_request) / [`spawn_sandbox`](crate::spawn_sandbox)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    /// The closed error code.
    pub code: ErrorCode,
    /// A human-readable message.
    pub message: String,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for Error {}

impl From<MxcError> for Error {
    fn from(error: MxcError) -> Self {
        Self {
            code: error.code.into(),
            message: error.message,
        }
    }
}
