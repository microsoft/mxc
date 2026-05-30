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

// ---- Shared error messages surfaced by the Windows AppContainer and ----
// ---- BaseContainer runners when a policy field is accepted by the   ----
// ---- schema but not yet honored by the runtime. Centralising the    ----
// ---- wording here keeps both runners in lockstep.                   ----

#[cfg(target_os = "windows")]
pub(crate) const DENIED_PATHS_NOT_SUPPORTED_MSG: &str =
    "filesystem.deniedPaths is not yet supported on Windows. Paths are denied by \
     default unless granted via readwritePaths or readonlyPaths. Remove deniedPaths, \
     or narrow readwritePaths/readonlyPaths to exclude the path you wanted to deny.";

#[cfg(target_os = "windows")]
pub(crate) const HOST_LISTS_NOT_SUPPORTED_MSG: &str =
    "network.allowedHosts / network.blockedHosts are not yet supported on Windows. \
     Remove the host list(s) and rely on defaultNetworkPolicy (allow / deny) or a \
     proxy instead.";
