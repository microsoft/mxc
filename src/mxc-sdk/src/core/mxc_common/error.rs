// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use thiserror::Error;

use crate::mxc_common::mxc_error::{MxcError, MxcErrorCode};

#[derive(Debug, Error)]
pub enum WxcError {
    #[error("Configuration parse error: {0}")]
    ConfigParse(String),

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

    #[error("Filesystem policy error: bfscfg.exe is not available on this host")]
    BfsNotAvailable,

    #[error("Initialization error: {0}")]
    Initialization(String),

    #[error("Network proxy error: {0}")]
    NetworkProxy(String),

    #[error("String conversion error: {0}")]
    StringConversion(String),
}

impl From<serde_json::Error> for WxcError {
    fn from(err: serde_json::Error) -> Self {
        WxcError::ConfigParse(err.to_string())
    }
}

impl WxcError {
    /// The wire code this failure is reported under.
    ///
    /// The grouping is by *whose* problem it is, because that is what decides
    /// what the caller can do next: fix the request, fix the host, or report a
    /// bug. `BfsNotAvailable` is the one that is easy to get wrong -- nothing
    /// the caller writes makes `bfscfg.exe` appear, so it is a property of the
    /// host rather than a judgement of the policy.
    pub fn error_code(&self) -> MxcErrorCode {
        match self {
            WxcError::ConfigParse(_) | WxcError::StringConversion(_) => {
                MxcErrorCode::MalformedRequest
            }
            WxcError::Validation(_) => MxcErrorCode::PolicyValidation,
            WxcError::BfsNotAvailable => MxcErrorCode::BackendUnavailable,
            WxcError::Process(_)
            | WxcError::Io(_)
            | WxcError::Firewall(_)
            | WxcError::FilesystemPolicy(_)
            | WxcError::Initialization(_)
            | WxcError::NetworkProxy(_) => MxcErrorCode::BackendError,
        }
    }

    /// Convert to the typed error carried on the wire, keeping the `Display`
    /// text as the message so the variant's prefix survives.
    pub fn to_mxc_error(&self) -> MxcError {
        MxcError::new(self.error_code(), self.to_string())
    }
}

impl From<std::io::Error> for WxcError {
    fn from(err: std::io::Error) -> Self {
        WxcError::Io(err.to_string())
    }
}

#[cfg(target_os = "windows")]
pub const DENIED_PATHS_NOT_SUPPORTED_MSG: &str =
    "filesystem.deniedPaths is not supported by this AppContainer filesystem mode. \
     Paths are denied by default unless granted via readwritePaths or readonlyPaths. \
     Remove deniedPaths, or narrow readwritePaths/readonlyPaths to exclude the path \
     you wanted to deny.";

#[cfg(target_os = "windows")]
pub const DENIED_PATHS_FEATURE_DISABLED_MSG: &str =
    "filesystem.deniedPaths cannot be enforced by the BaseContainer backend on this \
     OS build: it does not advertise PSE_SUPPORT_FS_DENY through \
     QueryProcessSecurityEnvironmentSupport. Run on a build with \
     BaseContainer deny support, or use the ProcessContainer dispatcher so it can select \
     the AppContainer + DACL fallback (which enforces deniedPaths via DENY ACEs).";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_host_tool_is_not_reported_as_a_bad_policy() {
        assert_eq!(
            WxcError::BfsNotAvailable.error_code(),
            MxcErrorCode::BackendUnavailable
        );
        assert_eq!(
            WxcError::Validation("denied".into()).error_code(),
            MxcErrorCode::PolicyValidation
        );
    }

    #[test]
    fn an_unreadable_request_is_told_apart_from_a_refused_one() {
        assert_eq!(
            WxcError::ConfigParse("bad json".into()).error_code(),
            MxcErrorCode::MalformedRequest
        );
        assert_eq!(
            WxcError::Io("disk gone".into()).error_code(),
            MxcErrorCode::BackendError
        );
    }

    #[test]
    fn conversion_keeps_the_variants_prefix_in_the_message() {
        let error = WxcError::Validation("portRange is empty".into()).to_mxc_error();
        assert_eq!(error.code, MxcErrorCode::PolicyValidation);
        assert_eq!(error.message, "Validation error: portRange is empty");
    }
}
