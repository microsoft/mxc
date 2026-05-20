// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared constants and configuration types for NanVix micro-VM binaries.
//!
//! This crate is the single source of truth for binary filenames, release
//! configuration, and checksum data. It is consumed as a `[build-dependency]`
//! by `nanvix_binaries` (download) and `wxc` (copy to output dir).

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

/// All required NanVix binary filenames (flat, next to wxc-exec).
pub const REQUIRED_BINARIES: &[&str] = &["nanvixd.exe", "nanvix_rootfs.img", "python3.initrd"];

/// Subdirectory holding kernel binary (nanvixd expects `./bin/kernel.elf`).
pub const BIN_SUBDIR: &str = "bin";

/// Subdirectory holding WHP snapshot files.
pub const SNAPSHOTS_SUBDIR: &str = "snapshots";

/// Files that live in a `bin/` subdirectory (nanvixd expects ./bin/kernel.elf).
pub const BIN_SUBDIR_FILES: &[&str] = &["kernel.elf"];

/// Snapshot files that live in a `snapshots/` subdirectory next to the exe.
pub const SNAPSHOT_FILES: &[&str] = &["kernel.vmem", "kernel.whp.cbor"];

/// Binaries sourced from the `nanvix/nanvix-python` GitHub release.
pub const NANVIX_PYTHON_REPO_BINARIES: &[&str] = REQUIRED_BINARIES;

/// Release configuration loaded from `versions.json`.
#[derive(Debug, Deserialize)]
pub struct ReleaseConfig {
    /// Configuration for the `nanvix/nanvix-python` GitHub repo.
    pub nanvix_python: RepoConfig,
}

/// Configuration for a single upstream GitHub repo release.
#[derive(Debug, Deserialize)]
pub struct RepoConfig {
    /// Git tag of the pinned release (e.g., "v0.12.291").
    pub tag: String,
    /// Exact filename of the zip asset in the GitHub release.
    pub asset: String,
    /// List of binary filenames to extract from the zip.
    pub binaries: Vec<String>,
}

/// Load and deserialize a JSON file.
pub fn load_json<T: serde::de::DeserializeOwned>(path: &str) -> T {
    let content = std::fs::read_to_string(Path::new(path))
        .unwrap_or_else(|e| panic!("nanvix_common: failed to read {}: {}", path, e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("nanvix_common: failed to parse {}: {}", path, e))
}

/// Load checksums from `checksums.json`.
pub fn load_checksums(path: &str) -> HashMap<String, String> {
    load_json(path)
}

/// Construct a deterministic GitHub release download URL.
///
/// Format: `https://github.com/{repo}/releases/download/{tag}/{asset}`
pub fn github_download_url(repo: &str, tag: &str, asset: &str) -> String {
    format!(
        "https://github.com/{}/releases/download/{}/{}",
        repo, tag, asset
    )
}

/// Generate WHP snapshots by cold-booting nanvixd.
///
/// `snapshot_home` is used as the process working directory. nanvixd writes
/// snapshot files to `<cwd>/snapshots/`, so the resulting files end up at
/// `<snapshot_home>/snapshots/kernel.vmem` and `kernel.whp.cbor`.
///
/// `bin_dir` is the directory containing `kernel.elf` (passed as `-bin-dir`).
///
/// Returns `Ok(())` on success. On failure, returns a human-readable error
/// message suitable for both build scripts (which panic) and runtime callers
/// (which wrap in their own error type).
pub fn generate_snapshot(
    snapshot_home: &Path,
    nanvixd: &Path,
    bin_dir: &Path,
    ramfs: &Path,
    initrd: &Path,
) -> Result<(), String> {
    use std::process::{Command, Stdio};

    let output = Command::new(nanvixd)
        .current_dir(snapshot_home)
        .arg("-bin-dir")
        .arg(bin_dir)
        .arg("-ramfs")
        .arg(ramfs)
        .arg("-kernel-args")
        .arg("snapshot")
        .arg("--")
        .arg(initrd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("failed to run nanvixd for snapshot generation: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "snapshot generation failed (exit code: {})",
            output.status
        ));
    }

    let snap_dir = snapshot_home.join(SNAPSHOTS_SUBDIR);
    for name in SNAPSHOT_FILES {
        if !snap_dir.join(name).exists() {
            return Err(format!(
                "snapshot generation completed but '{}' not found in {:?}",
                name, snap_dir
            ));
        }
    }

    Ok(())
}

/// Copy NanVix artifacts from the build cache (`src_dir`) to the target
/// directory next to the output executable.
///
/// Copies flat binaries, `snapshots/` files, and `bin/` subdir files.
/// Skips files that are already up-to-date (based on modification time).
pub fn copy_artifacts_to_target(src_dir: &Path, target_dir: &Path) {
    use std::fs;

    // Flat binaries (nanvixd.exe, nanvix_rootfs.img, python3.initrd).
    for name in REQUIRED_BINARIES {
        let src = src_dir.join(name);
        let dst = target_dir.join(name);
        if src.exists() && (!dst.exists() || is_newer(&src, &dst)) {
            eprintln!("nanvix: copying {} -> {}", src.display(), dst.display());
            if let Err(e) = fs::copy(&src, &dst) {
                let _ = fs::remove_file(&dst);
                eprintln!("nanvix: WARNING: failed to copy {}: {}", name, e);
            }
        }
    }

    // Snapshot files (snapshots/kernel.vmem, snapshots/kernel.whp.cbor).
    let snapshots_src = src_dir.join(SNAPSHOTS_SUBDIR);
    let snapshots_dst = target_dir.join(SNAPSHOTS_SUBDIR);
    if snapshots_src.exists() {
        let _ = fs::create_dir_all(&snapshots_dst);
        for name in SNAPSHOT_FILES {
            let src = snapshots_src.join(name);
            let dst = snapshots_dst.join(name);
            if src.exists() && (!dst.exists() || is_newer(&src, &dst)) {
                eprintln!("nanvix: copying snapshots/{} -> {}", name, dst.display());
                if let Err(e) = fs::copy(&src, &dst) {
                    let _ = fs::remove_file(&dst);
                    eprintln!("nanvix: WARNING: failed to copy snapshots/{}: {}", name, e);
                }
            }
        }
    }

    // bin/ subdir files (kernel.elf) — nanvixd expects ./bin/kernel.elf.
    let bin_src = src_dir.join(BIN_SUBDIR);
    let bin_dst = target_dir.join(BIN_SUBDIR);
    if bin_src.exists() {
        let _ = fs::create_dir_all(&bin_dst);
        for name in BIN_SUBDIR_FILES {
            let src = bin_src.join(name);
            let dst = bin_dst.join(name);
            if src.exists() && (!dst.exists() || is_newer(&src, &dst)) {
                eprintln!("nanvix: copying bin/{} -> {}", name, dst.display());
                if let Err(e) = fs::copy(&src, &dst) {
                    let _ = fs::remove_file(&dst);
                    eprintln!("nanvix: WARNING: failed to copy bin/{}: {}", name, e);
                }
            }
        }
    }
}

fn is_newer(src: &Path, dst: &Path) -> bool {
    let src_time = src.metadata().and_then(|m| m.modified()).ok();
    let dst_time = dst.metadata().and_then(|m| m.modified()).ok();
    match (src_time, dst_time) {
        (Some(s), Some(d)) => s > d,
        _ => true,
    }
}
