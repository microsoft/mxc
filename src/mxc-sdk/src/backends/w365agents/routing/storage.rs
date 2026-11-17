// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(unix)]
#[path = "storage_unix.rs"]
mod platform;
#[cfg(windows)]
#[path = "storage_windows.rs"]
mod platform;

use super::{error, Identity};
use crate::mxc_common::mxc_error::MxcError;
use std::path::PathBuf;

pub(super) use platform::Directory;

fn root_path() -> Result<PathBuf, MxcError> {
    #[cfg(feature = "test-support")]
    if let Some(path) = std::env::var_os("MXC_W365_TEST_STATE_ROOT") {
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            return Err(error("routing_state_root", "fixture root must be absolute"));
        }
        #[cfg(unix)]
        let path = path
            .canonicalize()
            .map_err(|e| error("routing_state_root", e))?;
        return Ok(path.join("Microsoft").join("MXC").join("w365"));
    }
    #[cfg(windows)]
    let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    #[cfg(target_os = "linux")]
    let base = match std::env::var_os("XDG_DATA_HOME") {
        Some(path) => Some(PathBuf::from(path)),
        None => std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".local").join("share")),
    };
    #[cfg(target_os = "macos")]
    let base = std::env::var_os("HOME")
        .map(|p| PathBuf::from(p).join("Library").join("Application Support"));
    let base = base.filter(|p| p.is_absolute()).ok_or_else(|| {
        error(
            "routing_state_root",
            "cannot resolve an absolute per-user data directory",
        )
    })?;
    Ok(base.join("Microsoft").join("MXC").join("w365"))
}
