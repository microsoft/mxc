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
    "filesystem.deniedPaths is not supported by this AppContainer filesystem mode. \
     Paths are denied by default unless granted via readwritePaths or readonlyPaths. \
     Remove deniedPaths, or narrow readwritePaths/readonlyPaths to exclude the path \
     you wanted to deny.";

#[cfg(target_os = "windows")]
pub const DENIED_PATHS_FEATURE_DISABLED_MSG: &str =
    "filesystem.deniedPaths cannot be enforced by the BaseContainer backend on this \
     OS build: it does not advertise the native deny-paths capability \
     (SANDBOX_CAP_FS_DENY via Experimental_QuerySandboxSupport). Run on a build with \
     BaseContainer deny support, or use the ProcessContainer dispatcher so it can select \
     the AppContainer + DACL fallback (which enforces deniedPaths via DENY ACEs).";

#[cfg(target_os = "windows")]
pub const HOST_LISTS_NOT_SUPPORTED_MSG: &str =
    "network.allowedHosts / network.blockedHosts are not yet supported on Windows. \
     Remove the host list(s) and rely on network.defaultPolicy (allow / block) or a \
     proxy instead.";

/// Shared by the parser and the Bubblewrap runner's `validate`, which reject
/// this combination independently: only JSON configs reach the parser, and only
/// one string can keep the two paths from drifting apart.
pub const BWRAP_PROXY_WITH_FIREWALL_MSG: &str =
    "Bubblewrap: network.proxy cannot be combined with \
     network.enforcementMode='firewall' or 'both'. They are competing \
     enforcement paths for the same egress posture: the cooperative env-var \
     proxy filters hosts at the proxy layer, while firewall mode filters by \
     address with iptables. Choose one.";
