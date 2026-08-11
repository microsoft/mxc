// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows Sandbox host-availability probe (ports the SDK's
//! `isWindowsSandboxAvailable()`).
//!
//! Detects availability by the presence of `WindowsSandbox.exe`, which Windows
//! installs only when the `Containers-DisposableClientVM` feature is enabled. We
//! skip the SDK's DISM query: `dism /online` needs elevation and this probe only
//! runs unelevated, so it would always fall through to this same exe check.

use mxc_alpha_wxc_common::system_dir::system_directory;

pub fn is_windows_sandbox_available() -> bool {
    // `system_directory()` resolves via `GetSystemDirectoryW`, not
    // `%SystemRoot%`, so an unelevated user can't spoof the path.
    system_directory().join("WindowsSandbox.exe").exists()
}
