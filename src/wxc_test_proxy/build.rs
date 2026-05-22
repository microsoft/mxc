// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script for wxc_test_proxy — embeds Windows version info into
//! `wxc-test-proxy.exe`. No-op on non-Windows targets.

fn main() {
    mxc_winres::embed_version_info("Microsoft MXC Test Proxy", "wxc-test-proxy.exe");
    println!("cargo:rerun-if-changed=build.rs");
}
