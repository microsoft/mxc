// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script for lxc — embeds Windows VersionInfo (no-op on non-Windows).

fn main() {
    mxc_build_common::embed_version_info("LXC container executor (Linux stub)", "lxc-exec.exe");

    // Delay-load winhvplatform.dll so WHP-less hosts don't crash before main().
    // CARGO_CFG_TARGET_* (not #[cfg]) because build.rs cfg gates are host, not target.
    #[cfg(feature = "hyperlight")]
    {
        let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
        let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
        if target_os == "windows" && target_arch == "x86_64" {
            println!("cargo:rustc-link-arg=/DELAYLOAD:winhvplatform.dll");
            println!("cargo:rustc-link-lib=delayimp");
        }
    }

    println!("cargo:rerun-if-changed=build.rs");
}
