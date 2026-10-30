// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The backend's error type, convertible to both result shapes the engine
//! uses: a [`ScriptResponse`] for create-and-run execution and an [`MxcError`]
//! for container lifecycle operations.

use std::fmt;

use crate::mxc_common::filesystem_object::FilesystemPolicyError;
use crate::mxc_common::models::{FailurePhase, ScriptResponse};
use crate::mxc_common::mxc_error::MxcError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KataError {
    /// The request asks for something the backend cannot honor. Nothing was
    /// created.
    Rejected(String),
    /// The host lacks a prerequisite: the Kata install, KVM, or root.
    Unavailable(String),
    /// Setting up or running the sandbox failed.
    Failed(String),
    /// A lifecycle operation named a sandbox that does not exist.
    Stale(String),
    /// The sandbox must be started first.
    NotStarted(String),
    /// The sandbox is already running.
    AlreadyStarted(String),
    /// The sandbox is not running.
    AlreadyStopped(String),
}

impl KataError {
    pub(crate) fn rejected(message: impl Into<String>) -> Self {
        Self::Rejected(message.into())
    }

    pub(crate) fn unavailable(message: impl Into<String>) -> Self {
        Self::Unavailable(message.into())
    }

    pub(crate) fn failed(message: impl Into<String>) -> Self {
        Self::Failed(message.into())
    }

    pub(crate) fn message(&self) -> &str {
        match self {
            Self::Rejected(m)
            | Self::Unavailable(m)
            | Self::Failed(m)
            | Self::Stale(m)
            | Self::NotStarted(m)
            | Self::AlreadyStarted(m)
            | Self::AlreadyStopped(m) => m,
        }
    }
}

impl fmt::Display for KataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for KataError {}

impl From<FilesystemPolicyError> for KataError {
    fn from(error: FilesystemPolicyError) -> Self {
        match error {
            FilesystemPolicyError::Policy(message) => Self::Rejected(message),
            FilesystemPolicyError::Host(message) => Self::Failed(message),
        }
    }
}

impl KataError {
    /// The result of a create-and-run request that failed with this error.
    pub(crate) fn into_response(self) -> ScriptResponse {
        match self {
            KataError::Rejected(message) => ScriptResponse::rejected(&message),
            KataError::Unavailable(message) => ScriptResponse {
                exit_code: -1,
                error_message: message,
                failure_phase: FailurePhase::BackendUnavailable,
                ..Default::default()
            },
            // Lifecycle state errors cannot arise from create-and-run
            // execution, which provisions and starts its own sandbox.
            KataError::Failed(message)
            | KataError::Stale(message)
            | KataError::NotStarted(message)
            | KataError::AlreadyStarted(message)
            | KataError::AlreadyStopped(message) => ScriptResponse {
                exit_code: -1,
                error_message: message,
                failure_phase: FailurePhase::LaunchFailed,
                ..Default::default()
            },
        }
    }
}

impl KataError {
    /// The error of a lifecycle operation that failed with this error.
    pub(crate) fn into_mxc_error(self) -> MxcError {
        match self {
            KataError::Rejected(message) => MxcError::policy_validation(message),
            KataError::Unavailable(message) => MxcError::backend_unavailable(message),
            KataError::Failed(message) => MxcError::backend_error(message),
            KataError::Stale(message) => MxcError::stale_id(message),
            KataError::NotStarted(message) => MxcError::not_started(message),
            KataError::AlreadyStarted(message) => MxcError::already_started(message),
            KataError::AlreadyStopped(message) => MxcError::already_stopped(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_common::mxc_error::MxcErrorCode;

    #[test]
    fn each_error_keeps_its_meaning_in_both_result_shapes() {
        let cases = [
            (
                KataError::rejected("no"),
                FailurePhase::Rejected,
                MxcErrorCode::PolicyValidation,
            ),
            (
                KataError::unavailable("no kvm"),
                FailurePhase::BackendUnavailable,
                MxcErrorCode::BackendUnavailable,
            ),
            (
                KataError::failed("boom"),
                FailurePhase::LaunchFailed,
                MxcErrorCode::BackendError,
            ),
        ];
        for (error, phase, code) in cases {
            let message = error.message().to_string();
            let response = error.clone().into_response();
            assert_eq!(response.failure_phase, phase);
            assert_eq!(response.error_message, message);
            let mxc = error.into_mxc_error();
            assert_eq!(mxc.code, code);
            assert_eq!(mxc.message, message);
        }
    }

    #[test]
    fn filesystem_policy_errors_map_to_rejected_and_failed() {
        assert_eq!(
            KataError::from(FilesystemPolicyError::Policy("bad".into())),
            KataError::rejected("bad")
        );
        assert_eq!(
            KataError::from(FilesystemPolicyError::Host("io".into())),
            KataError::failed("io")
        );
    }
}
