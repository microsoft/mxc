// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use thiserror::Error;

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

impl From<std::io::Error> for WxcError {
    fn from(err: std::io::Error) -> Self {
        WxcError::Io(err.to_string())
    }
}

#[cfg(target_os = "windows")]
pub const DENIED_PATHS_NOT_SUPPORTED_MSG: &str =
    "filesystem.deniedPaths cannot be enforced by the AppContainer runner in BFS mode \
     without an external deny DACL. Route the request through the BaseContainer-fallback \
     dispatcher so deniedPaths are enforced natively (BaseContainer fs_deny) or via a \
     DACL-backed tier, or remove deniedPaths.";

#[cfg(target_os = "windows")]
pub const DENIED_PATHS_FEATURE_DISABLED_MSG: &str =
    "filesystem.deniedPaths cannot be enforced natively: the BaseContainer fs_deny capability \
     (Feature_BfsPolicyDeny) is not enabled on this OS. Route the request through the \
     BaseContainer-fallback dispatcher so deniedPaths can be enforced via a DACL-backed tier, \
     or remove deniedPaths.";

#[cfg(target_os = "windows")]
pub const HOST_LISTS_NOT_SUPPORTED_MSG: &str =
    "network.allowedHosts / network.blockedHosts are not yet supported on Windows. \
     Remove the host list(s) and rely on network.defaultPolicy (allow / block) or a \
     proxy instead.";
