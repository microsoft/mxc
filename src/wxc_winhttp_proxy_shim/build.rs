// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script for wxc_winhttp_proxy_shim — embeds Windows version info
//! into `winhttp-proxy-shim.exe`. No-op on non-Windows targets.

fn main() {
    mxc_winres::embed_version_info("MXC WinHTTP Proxy Shim", "winhttp-proxy-shim.exe");
    println!("cargo:rerun-if-changed=build.rs");
}
