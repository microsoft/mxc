// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script for wxc — copies NanVix binaries next to the output executable.

fn main() {
    #[cfg(all(windows, feature = "microvm"))]
    copy_nanvix_binaries();

    // Always emit rerun-if-changed so Cargo doesn't re-run unnecessarily.
    println!("cargo:rerun-if-changed=build.rs");
}

#[cfg(all(windows, feature = "microvm"))]
fn copy_nanvix_binaries() {
    use std::fs;
    use std::path::Path;

    let nanvix_bin_dir = match std::env::var("DEP_NANVIX_BINARIES_BIN_DIR") {
        Ok(dir) => dir,
        Err(_) => {
            eprintln!("wxc build.rs: DEP_NANVIX_BINARIES_BIN_DIR not set, skipping copy");
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
            eprintln!("wxc build.rs: could not determine target dir from OUT_DIR");
            return;
        }
    };

    let src_dir = Path::new(&nanvix_bin_dir);

    for name in nanvix_common::REQUIRED_BINARIES {
        let src = src_dir.join(name);
        let dst = target_dir.join(name);

        if src.exists() && (!dst.exists() || is_newer(&src, &dst)) {
            eprintln!(
                "wxc build.rs: copying {} -> {}",
                src.display(),
                dst.display()
            );
            if let Err(e) = fs::copy(&src, &dst) {
                // Remove partial copy to avoid leaving a dangling file
                let _ = fs::remove_file(&dst);
                eprintln!("wxc build.rs: WARNING: failed to copy {}: {}", name, e);
            }
        }
    }

    // Re-run when source binaries change (detected via nanvix_binaries rebuild)
    println!("cargo:rerun-if-env-changed=DEP_NANVIX_BINARIES_BIN_DIR");
}

#[cfg(all(windows, feature = "microvm"))]
fn is_newer(src: &std::path::Path, dst: &std::path::Path) -> bool {
    let src_time = src.metadata().and_then(|m| m.modified()).ok();
    let dst_time = dst.metadata().and_then(|m| m.modified()).ok();
    match (src_time, dst_time) {
        (Some(s), Some(d)) => s > d,
        _ => true,
    }
}
