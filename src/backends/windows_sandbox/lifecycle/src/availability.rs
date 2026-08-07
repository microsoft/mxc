// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows Sandbox host-availability probe (ports the SDK's
//! `isWindowsSandboxAvailable()`).
//!
//! Detects availability by the presence of `WindowsSandbox.exe`, which Windows
//! installs only when the `Containers-DisposableClientVM` feature is enabled. We
//! skip the SDK's DISM query: `dism /online` needs elevation and this probe only
//! runs unelevated, so it would always fall through to this same exe check.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub fn is_windows_sandbox_available() -> bool {
    system_directory().join("WindowsSandbox.exe").exists()
}

/// Resolved via `GetSystemDirectoryW`, not `%SystemRoot%`: UAC inherits an
/// unelevated parent's environment, so an env-derived path would let a standard
/// user plant a fake `WindowsSandbox.exe` and spoof availability (see
/// `src/host/plm/src/wpr_path.rs`). The literal fallback is not env-derived.
fn system_directory() -> &'static Path {
    static SYSTEM_DIR: OnceLock<PathBuf> = OnceLock::new();
    SYSTEM_DIR
        .get_or_init(|| {
            resolve_system_directory().unwrap_or_else(|| PathBuf::from(r"C:\Windows\System32"))
        })
        .as_path()
}

fn resolve_system_directory() -> Option<PathBuf> {
    use windows::Win32::System::SystemInformation::GetSystemDirectoryW;

    let mut buf = vec![0u16; 260];
    // SAFETY: `buf` is valid and owned for the call; we read only the returned prefix.
    let mut n = unsafe { GetSystemDirectoryW(Some(&mut buf)) };
    if n == 0 {
        return None;
    }
    // `n >= buf.len()`: buffer was too small and `n` is the required size — grow
    // and retry once.
    if n as usize >= buf.len() {
        buf = vec![0u16; n as usize];
        n = unsafe { GetSystemDirectoryW(Some(&mut buf)) };
        if n == 0 || n as usize >= buf.len() {
            return None;
        }
    }
    Some(PathBuf::from(wxc_common::string_util::from_wide(
        &buf[..n as usize],
    )))
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
