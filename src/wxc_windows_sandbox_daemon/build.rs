// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script for wxc_windows_sandbox_daemon — embeds Windows version
//! info into `wxc-windows-sandbox-daemon.exe`. No-op on non-Windows targets.

fn main() {
    mxc_winres::embed_version_info(
        "Microsoft MXC Windows Sandbox Daemon",
        "wxc-windows-sandbox-daemon.exe",
    );
    println!("cargo:rerun-if-changed=build.rs");
}
