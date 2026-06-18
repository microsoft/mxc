// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `wxc-host-prep` — host-side setup operations for MXC containment
//! backends.
//!
//! Each subcommand performs a one-off privileged operation on the host
//! (DACL/SACL writes against well-known kernel objects). Elevation is
//! handled by the application manifest (`requireAdministrator`), so
//! the binary either runs elevated or fails to start. No hand-rolled
//! self-elevation; no `ShellExecuteExW(runas)` dance.
//!
//! Subcommands:
//!
//! * `prepare-system-drive` / `unprepare-system-drive` — metadata-only
//!   AppContainer-friendly ACEs on the system-drive root. See the
//!   `system_drive` module.
//! * `prepare-null-device` / `verify-null-device` / `dump-null-device` —
//!   reapply the `Feature_AgenticAppContainerBfsSupport`-equivalent
//!   security descriptor to `\Device\Null` on downlevel Windows
//!   builds. See the `null_device` module.

#[cfg(target_os = "windows")]
mod cli;
#[cfg(target_os = "windows")]
mod elevation_check;
#[cfg(target_os = "windows")]
mod learning_mode_shim;
#[cfg(target_os = "windows")]
mod log;
#[cfg(target_os = "windows")]
mod null_device;
#[cfg(target_os = "windows")]
mod system_drive;

#[cfg(target_os = "windows")]
fn main() {
    std::process::exit(cli::run());
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("wxc-host-prep is Windows-only.");
    std::process::exit(64);
}
