// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script for lxc — embeds Windows version info into `lxc-exec.exe`
//! when the crate happens to be compiled for a Windows target (e.g. the
//! workspace-wide `cargo build` lane on Windows). The real lxc backend
//! only runs on Linux, but having proper file properties on the stub
//! Windows artifact keeps Explorer/AV tooling happy. No-op on non-Windows
//! targets.

fn main() {
    mxc_winres::embed_version_info("MXC Linux Container Executor", "lxc-exec.exe");
    println!("cargo:rerun-if-changed=build.rs");
}
