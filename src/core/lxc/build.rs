// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script for lxc — embeds Windows VersionInfo (no-op on non-Windows)
//! and copies NanVix binaries next to the output executable when the
//! `microvm` feature is enabled.

fn main() {
    mxc_build_common::embed_version_info("LXC container executor (Linux stub)", "lxc-exec.exe");

    #[cfg(all(target_os = "linux", feature = "microvm"))]
    copy_nanvix_binaries();

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

#[cfg(all(target_os = "linux", feature = "microvm"))]
fn copy_nanvix_binaries() {
    use std::path::Path;

    let nanvix_bin_dir = match std::env::var("DEP_NANVIX_BINARIES_BIN_DIR") {
        Ok(dir) => dir,
        Err(_) => {
            eprintln!("lxc build.rs: DEP_NANVIX_BINARIES_BIN_DIR not set, skipping copy");
            return;
        }
    };

    // Stage the artifacts next to the executable and emit rerun triggers. All
    // of the staging logic (target-dir derivation, snapshot trust, copy/purge,
    // rerun emission) lives in the build-only `nanvix_build_common` crate.
    nanvix_build_common::stage_artifacts_next_to_exe(Path::new(&nanvix_bin_dir));
}
