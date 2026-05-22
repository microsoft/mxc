// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script for mxc_diagnostic_console — embeds Windows version info
//! into `mxc-diagnostic-console.exe`. No-op on non-Windows targets.

fn main() {
    mxc_winres::embed_version_info(
        "MXC Diagnostic Console",
        "mxc-diagnostic-console.exe",
    );
    println!("cargo:rerun-if-changed=build.rs");
}
