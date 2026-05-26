// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script for wxc_windows_sandbox_guest — embeds Windows version
//! info into `wxc-windows-sandbox-guest.exe`. No-op on non-Windows targets.

fn main() {
    mxc_winres::embed_version_info("MXC Windows Sandbox Guest", "wxc-windows-sandbox-guest.exe");
    println!("cargo:rerun-if-changed=build.rs");
}
