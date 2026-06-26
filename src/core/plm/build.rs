// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script for plm — embeds Windows VersionInfo and stages
//! `plm.wprp` next to the compiled `plm.exe`.

use std::path::{Path, PathBuf};

fn main() {
    mxc_build_common::embed_version_info("MXC permissive learning mode", "plm.exe");

    stage_wprp_next_to_exe();
}

fn stage_wprp_next_to_exe() {
    let wprp_src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("plm.wprp");
    println!("cargo:rerun-if-changed={}", wprp_src.display());

    let Some(target_dir) = target_bin_dir() else {
        println!(
            "cargo:warning=plm: could not derive target directory from OUT_DIR; skipping plm.wprp staging"
        );
        return;
    };

    if let Err(e) = std::fs::create_dir_all(&target_dir) {
        println!(
            "cargo:warning=plm: failed to create target dir {}: {e}",
            target_dir.display()
        );
        return;
    }

    let dst = target_dir.join("plm.wprp");
    if let Err(e) = std::fs::copy(&wprp_src, &dst) {
        panic!(
            "plm: failed to copy {} -> {}: {e}",
            wprp_src.display(),
            dst.display()
        );
    }
}

/// Cargo places the build script's `OUT_DIR` at
/// `target/<triple>/<profile>/build/<crate>-<hash>/out`, so the binary's
/// containing directory is three parents up.
fn target_bin_dir() -> Option<PathBuf> {
    let out_dir = std::env::var_os("OUT_DIR")?;
    Path::new(&out_dir)
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .map(Path::to_path_buf)
}
