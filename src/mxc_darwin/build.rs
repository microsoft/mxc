// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script for mxc_darwin — embeds Windows version info into
//! `mxc-exec-mac.exe` when the crate happens to be compiled for a Windows
//! target (e.g. the workspace-wide `cargo build` lane on Windows). The
//! real Seatbelt backend only runs on macOS, but having proper file
//! properties on the stub Windows artifact keeps Explorer/AV tooling
//! happy. No-op on non-Windows targets.

fn main() {
    mxc_winres::embed_version_info("MXC macOS Seatbelt Executor", "mxc-exec-mac.exe");
    println!("cargo:rerun-if-changed=build.rs");
}
