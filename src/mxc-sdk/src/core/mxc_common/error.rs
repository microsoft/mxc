// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use thiserror::Error;

use crate::mxc_common::mxc_error::{MxcError, MxcErrorCode};

#[derive(Debug, Error)]
pub enum WxcError {
    #[error("Configuration parse error: {0}")]
    ConfigParse(String),

    #[error(transparent)]
    StateAware(Box<MxcError>),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Process error: {0}")]
    Process(String),

    #[error("IO error: {0}")]
    Io(String),

    #[error("Firewall error: {0}")]
    Firewall(String),

    #[error("Filesystem policy error: {0}")]
    FilesystemPolicy(String),

    #[error("Initialization error: {0}")]
    Initialization(String),

    #[error("Network proxy error: {0}")]
    NetworkProxy(String),

    #[error("String conversion error: {0}")]
    StringConversion(String),
}

impl WxcError {
    pub(crate) fn into_state_aware(self) -> MxcError {
        match self {
            Self::StateAware(error) => *error,
            error => MxcError::malformed_request(error.to_string()),
        }
    }
}

impl From<MxcError> for WxcError {
    fn from(error: MxcError) -> Self {
        Self::StateAware(Box::new(error))
    }
}

impl From<serde_json::Error> for WxcError {
    fn from(err: serde_json::Error) -> Self {
        WxcError::ConfigParse(err.to_string())
    }
}

impl WxcError {
    /// The wire code this failure is reported under, grouped by who can act on
    /// it: the request, the host, or neither.
    pub fn error_code(&self) -> MxcErrorCode {
        match self {
            WxcError::StateAware(error) => error.code,
            WxcError::ConfigParse(_) | WxcError::StringConversion(_) => {
                MxcErrorCode::MalformedRequest
            }
            WxcError::Validation(_) => MxcErrorCode::PolicyValidation,
            WxcError::Process(_)
            | WxcError::Io(_)
            | WxcError::Firewall(_)
            | WxcError::FilesystemPolicy(_)
            | WxcError::Initialization(_)
            | WxcError::NetworkProxy(_) => MxcErrorCode::BackendError,
        }
    }

    /// Convert to the typed error carried on the wire, keeping the `Display`
    /// text as the message so the variant's prefix survives. A wrapped
    /// [`MxcError`] is returned unchanged.
    pub fn to_mxc_error(&self) -> MxcError {
        match self {
            WxcError::StateAware(error) => (**error).clone(),
            error => MxcError::new(error.error_code(), error.to_string()),
        }
    }
}

impl From<std::io::Error> for WxcError {
    fn from(err: std::io::Error) -> Self {
        WxcError::Io(err.to_string())
    }
}

#[cfg(target_os = "windows")]
pub const DENIED_PATHS_FEATURE_DISABLED_MSG: &str =
    "filesystem.deniedPaths cannot be enforced by the BaseContainer backend on this \
     OS build: it does not advertise PSE_SUPPORT_FS_DENY through \
     QueryProcessSecurityEnvironmentSupport. Run on a build with \
     BaseContainer deny support or remove filesystem.deniedPaths.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refused_policy_is_told_apart_from_a_host_fault() {
        assert_eq!(
            WxcError::Validation("denied".into()).error_code(),
            MxcErrorCode::PolicyValidation
        );
        assert_eq!(
            WxcError::Io("disk gone".into()).error_code(),
            MxcErrorCode::BackendError
        );
    }

    #[test]
    fn an_unreadable_request_is_malformed() {
        assert_eq!(
            WxcError::ConfigParse("bad json".into()).error_code(),
            MxcErrorCode::MalformedRequest
        );
    }

    #[test]
    fn conversion_keeps_the_variants_prefix_in_the_message() {
        let error = WxcError::Validation("portRange is empty".into()).to_mxc_error();
        assert_eq!(error.code, MxcErrorCode::PolicyValidation);
        assert_eq!(error.message, "Validation error: portRange is empty");
    }
}
