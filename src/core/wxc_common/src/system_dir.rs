// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resolve the Windows System directory via `GetSystemDirectoryW`.
//!
//! Security-critical: callers locate trusted system binaries (`wpr.exe`,
//! `WindowsSandbox.exe`) under this path, so it must come from the kernel, not
//! `%SystemRoot%`/`%SystemDirectory%`. UAC inherits an unelevated parent's
//! environment, so an env-derived path would let a standard user plant a fake
//! binary and spoof the result. `GetSystemDirectoryW` is published at process
//! creation and cannot be overridden by the env block.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Resolve the System directory via `GetSystemDirectoryW`, or `None` if the
/// call fails outright (return value 0 — a broken/stripped Windows install;
/// does not happen on a real install).
pub fn resolve_system_directory() -> Option<PathBuf> {
    use windows::Win32::System::SystemInformation::GetSystemDirectoryW;

    let mut buf = vec![0u16; 260];
    // SAFETY: `buf` is initialized and owned for the call; we read only the
    // returned prefix.
    let mut n = unsafe { GetSystemDirectoryW(Some(&mut buf)) };
    if n == 0 {
        return None;
    }
    // `n >= buf.len()`: buffer was too small and `n` is the required size
    // (including the NUL) — grow and retry once.
    if n as usize >= buf.len() {
        buf = vec![0u16; n as usize];
        n = unsafe { GetSystemDirectoryW(Some(&mut buf)) };
        if n == 0 || n as usize >= buf.len() {
            return None;
        }
    }
    Some(PathBuf::from(crate::string_util::from_wide(
        &buf[..n as usize],
    )))
}

/// Cached System directory, falling back to the (non-env-derived) literal
/// `C:\Windows\System32` only if `GetSystemDirectoryW` fails.
pub fn system_directory() -> &'static Path {
    static SYSTEM_DIR: OnceLock<PathBuf> = OnceLock::new();
    SYSTEM_DIR
        .get_or_init(|| {
            resolve_system_directory().unwrap_or_else(|| PathBuf::from(r"C:\Windows\System32"))
        })
        .as_path()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_directory_is_absolute_and_exists() {
        let dir = system_directory();
        assert!(dir.is_absolute(), "system dir must be absolute: {dir:?}");
        assert!(dir.exists(), "system dir must exist: {dir:?}");
    }
}
