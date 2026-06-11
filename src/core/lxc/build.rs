// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script for lxc — embeds Windows VersionInfo (no-op on non-Windows)
//! and copies NanVix binaries next to the output executable when the
//! `microvm` feature is enabled.

fn main() {
    mxc_build_common::embed_version_info("LXC container executor (Linux stub)", "lxc-exec.exe");

    #[cfg(all(target_os = "linux", feature = "microvm"))]
    copy_nanvix_binaries();

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

    // Cargo puts the output binary in OUT_DIR/../../.. (target/<profile>/)
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let target_dir = Path::new(&out_dir)
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent());

    let target_dir = match target_dir {
        Some(d) => d,
        None => {
            eprintln!("lxc build.rs: could not determine target dir from OUT_DIR");
            return;
        }
    };

    // WHP snapshots from a prefetched (externally supplied) directory are not
    // covered by checksums.json, so they must not be trusted/copied; the
    // producer reports this via `cargo:PREFETCHED`. Default to trusting
    // (online build) when the flag is absent.
    let trust_snapshots = std::env::var("DEP_NANVIX_BINARIES_PREFETCHED")
        .map(|v| v != "1")
        .unwrap_or(true);

    nanvix_common::copy_artifacts_to_target(
        Path::new(&nanvix_bin_dir),
        target_dir,
        trust_snapshots,
    );

    // Re-run when the source path changes and when the source artifacts
    // themselves change in place (e.g. an offline NANVIX_BIN prefetch dir
    // updated at the same path).
    nanvix_common::emit_rerun_for_copied_artifacts(Path::new(&nanvix_bin_dir));
    println!("cargo:rerun-if-env-changed=DEP_NANVIX_BINARIES_BIN_DIR");
    println!("cargo:rerun-if-env-changed=DEP_NANVIX_BINARIES_PREFETCHED");
}
