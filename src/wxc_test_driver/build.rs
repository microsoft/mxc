// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script for wxc_test_driver — embeds Windows version info into
//! `wxc-test-driver.exe`. No-op on non-Windows targets.

fn main() {
    mxc_winres::embed_version_info("Microsoft MXC Test Driver", "wxc-test-driver.exe");
    println!("cargo:rerun-if-changed=build.rs");
}
