// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script that downloads NanVix binaries from GitHub releases.
//!
//! Uses system tools (`curl.exe`, `tar.exe`, `certutil`) instead of Rust
//! crates. Zero HTTP/zip/crypto build-dependencies — only `nanvix_common`
//! for shared constants and serde-based config parsing.
//!
//! ## Configuration files
//!
//! - `versions.json` — pinned release tags and exact asset names
//! - `checksums.json` — SHA256 hashes for integrity verification
//!
//! ## Environment variables
//!
//! - `GITHUB_TOKEN` / `GH_TOKEN` — optional; increases API rate limit
//! - `NANVIX_BIN` — optional; path to a directory of pre-fetched NanVix
//!   binaries. When set, the build uses that directory directly and performs
//!   no network downloads, enabling fully offline builds where all dynamic
//!   build inputs are pre-fetched. The directory must already contain the
//!   required binaries (flat files plus the `bin/` subdirectory); checksums
//!   are still verified against `checksums.json`.
//!
//! ## Caching
//!
//! Binaries are cached in OUT_DIR (or read from `NANVIX_BIN` when set).
//! Checksums are verified whenever this build script runs (triggered by
//! changes to build.rs, versions.json, or checksums.json) to catch corrupted
//! or truncated files.
//!
//! # TODO(security): NanVix binaries are not ESRP-signed. Before shipping in
//! # official MXC releases, either extend ESRP to cover these binaries or
//! # establish an internal mirror with supply-chain controls.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use nanvix_common::{github_download_url, load_checksums, load_json, ReleaseConfig, RepoConfig};

fn main() {
    // The build script's output (`NANVIX_BIN_DIR` and whether the download /
    // verify path runs) depends on the `microvm` feature, surfaced here as the
    // `CARGO_FEATURE_MICROVM` env var. Declare it as a rerun trigger so toggling
    // the feature between builds re-runs this script instead of reusing stale
    // output.
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_MICROVM");

    // The expensive work in this build script — downloading NanVix release
    // assets and verifying their checksums via `certutil` — is only needed
    // when the micro-VM backend is actually being built. Gate it behind this
    // crate's `microvm` feature so that a default `cargo build` (which still
    // compiles this crate as a workspace member) performs no network or hashing
    // work. `wxc` and `lxc` enable `nanvix_binaries/microvm` through their own
    // `microvm` features.
    //
    // `NANVIX_BIN_DIR` must still be emitted in every configuration because
    // `lib.rs` references it via `env!`.
    if std::env::var_os("CARGO_FEATURE_MICROVM").is_none() {
        let out_dir = std::env::var("OUT_DIR").unwrap();
        println!("cargo:rustc-env=NANVIX_BIN_DIR={}", out_dir);
        println!("cargo:rerun-if-changed=build.rs");
        return;
    }

    // Check the TARGET platform (not host). NanVix binaries are only needed when
    // the output binary will run on Windows or Linux with KVM.
    let target = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target != "windows" && target != "linux" {
        let out_dir = std::env::var("OUT_DIR").unwrap();
        println!("cargo:rustc-env=NANVIX_BIN_DIR={}", out_dir);
        println!("cargo:rerun-if-changed=build.rs");
        return;
    }

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    // When `NANVIX_BIN` is set, use the caller-provided directory of
    // pre-fetched binaries and skip all network downloads. This enables fully
    // offline builds where every dynamic build input has been pre-fetched.
    // Otherwise, download into a subdirectory of OUT_DIR as before.
    let offline_bin_dir = std::env::var_os("NANVIX_BIN").map(PathBuf::from);
    let use_prefetched_binaries = offline_bin_dir.is_some();
    let bin_dir = match offline_bin_dir {
        Some(dir) => {
            if !dir.is_dir() {
                panic!(
                    "nanvix_binaries: NANVIX_BIN is set to '{}', but that directory \
                     does not exist. Point NANVIX_BIN at a directory containing the \
                     pre-fetched NanVix binaries.",
                    dir.display()
                );
            }
            // Canonicalize to an absolute path. The directory is emitted as
            // `cargo:BIN_DIR` and consumed by the `wxc`/`lxc` build scripts
            // (via `DEP_NANVIX_BINARIES_BIN_DIR`) to copy artifacts next to the
            // final executable. Those scripts run with a different working
            // directory, so a relative `NANVIX_BIN` would otherwise resolve
            // against the wrong directory and silently copy nothing.
            let dir = fs::canonicalize(&dir).unwrap_or_else(|e| {
                panic!(
                    "nanvix_binaries: failed to canonicalize NANVIX_BIN '{}': {}",
                    dir.display(),
                    e
                )
            });
            eprintln!(
                "nanvix_binaries: NANVIX_BIN set — using pre-fetched binaries from '{}' (offline)",
                dir.display()
            );
            dir
        }
        None => {
            let dir = out_dir.join("nanvix-binaries");
            fs::create_dir_all(&dir).expect("failed to create nanvix-binaries dir");
            dir
        }
    };

    let versions: ReleaseConfig = load_json("versions.json");
    let checksums: HashMap<String, String> = load_checksums("checksums.json", &target);

    if target == "linux" {
        // Linux: download tar.gz and extract Linux binaries.
        let asset = versions
            .nanvix_python
            .asset_linux
            .as_deref()
            .unwrap_or("microvm-standalone-256mb.tar.gz");
        let binaries: Vec<&str> = versions
            .nanvix_python
            .binaries_linux
            .as_ref()
            .map(|v| v.iter().map(|s| s.as_str()).collect())
            .unwrap_or_else(|| nanvix_common::REQUIRED_BINARIES.to_vec());

        let needs_download =
            !use_prefetched_binaries && needs_download_linux(&binaries, &bin_dir, &checksums);
        if needs_download {
            eprintln!(
                "nanvix_binaries: downloading nanvix/nanvix-python {} (Linux)...",
                versions.nanvix_python.tag
            );
            download_and_extract_linux(&versions.nanvix_python.tag, asset, &binaries, &bin_dir);
        } else if use_prefetched_binaries {
            eprintln!(
                "nanvix_binaries: offline — verifying pre-fetched Linux binaries in '{}'",
                bin_dir.display()
            );
        } else {
            eprintln!("nanvix_binaries: all Linux binaries cached and verified");
        }

        verify_checksums_linux(&binaries, &bin_dir, &checksums);
        verify_bin_subdir_checksums_linux(&bin_dir, &checksums);

        if use_prefetched_binaries {
            emit_rerun_for_offline_inputs(&bin_dir, &binaries);
        }
    } else {
        // Windows: original logic
        let all_binaries: Vec<&str> = versions
            .nanvix_python
            .binaries
            .iter()
            .map(|s| s.as_str())
            .collect();

        let needs_nanvix_python = !use_prefetched_binaries
            && needs_download(&versions.nanvix_python, &bin_dir, &checksums);

        if needs_nanvix_python {
            eprintln!(
                "nanvix_binaries: downloading nanvix/nanvix-python {}...",
                versions.nanvix_python.tag
            );
            download_and_extract(&versions.nanvix_python, "nanvix/nanvix-python", &bin_dir);
        } else if use_prefetched_binaries {
            eprintln!(
                "nanvix_binaries: offline — verifying pre-fetched binaries in '{}'",
                bin_dir.display()
            );
        } else {
            eprintln!("nanvix_binaries: all binaries cached and verified");
        }

        verify_checksums(&all_binaries, &bin_dir, &checksums);
        verify_bin_subdir_checksums(&bin_dir, &checksums);

        if use_prefetched_binaries {
            emit_rerun_for_offline_inputs(&bin_dir, &all_binaries);
        }

        // Generate host-local WHP snapshots at build time so even the first
        // runtime execution uses warm start. The runtime fallback in
        // nanvix_runner.rs handles the case where snapshots are missing.
        //
        // Skip on non-x86_64 hosts: `nanvixd.exe` is an x86_64 Windows binary
        // and launching it on (e.g.) ARM64 Windows fails with
        // STATUS_INVALID_IMAGE_FORMAT (0xc000007b). Snapshot pre-generation is
        // a warm-start cache only — the runtime fallback covers cold boot on
        // hosts where this build step is skipped.
        let host = std::env::var("HOST").unwrap_or_default();
        let host_is_x86_64 = host.starts_with("x86_64-");
        if !host_is_x86_64 {
            eprintln!(
                "nanvix_binaries: skipping host-local snapshot generation \
                 (host '{}' is not x86_64; nanvixd.exe cannot run here). \
                 Runtime will cold-boot on first use.",
                host
            );
        } else {
            let snapshots_dir = bin_dir.join(nanvix_common::SNAPSHOTS_SUBDIR);
            let snapshots_present = nanvix_common::SNAPSHOT_FILES
                .iter()
                .all(|name| snapshots_dir.join(name).exists());
            if snapshots_present {
                eprintln!("nanvix_binaries: host-local snapshots already present");
            } else if use_prefetched_binaries {
                // In offline mode the NANVIX_BIN directory is treated as an
                // immutable, pre-fetched input — it may be a read-only or
                // shared cache. Do not run nanvixd.exe to generate snapshots
                // into it. The runtime fallback in nanvix_runner.rs cold-boots
                // when snapshots are absent.
                eprintln!(
                    "nanvix_binaries: offline — snapshots absent in NANVIX_BIN; \
                     skipping generation (runtime will cold-boot on first use)."
                );
            } else {
                fs::create_dir_all(&snapshots_dir).expect("failed to create snapshots dir");
                eprintln!("nanvix_binaries: generating host-local snapshots (cold boot)...");
                generate_snapshots_locally(&bin_dir);
            }
        }
    }

    println!("cargo:rustc-env=NANVIX_BIN_DIR={}", bin_dir.display());
    println!("cargo:BIN_DIR={}", bin_dir.display());
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=versions.json");
    println!("cargo:rerun-if-changed=checksums.json");
    println!("cargo:rerun-if-env-changed=GITHUB_TOKEN");
    println!("cargo:rerun-if-env-changed=GH_TOKEN");
    println!("cargo:rerun-if-env-changed=NANVIX_BIN");
}

// -- Download logic ----------------------------------------------------------

/// Emit `cargo:rerun-if-changed` for every pre-fetched input file so that
/// replacing binaries in place under the same `NANVIX_BIN` path re-triggers
/// checksum verification (and the downstream `wxc`/`lxc` artifact copy). The
/// `rerun-if-env-changed=NANVIX_BIN` trigger only fires when the path value
/// changes, not when the directory's contents change.
fn emit_rerun_for_offline_inputs(bin_dir: &Path, binaries: &[&str]) {
    for name in binaries {
        println!("cargo:rerun-if-changed={}", bin_dir.join(name).display());
    }
    let bin_subdir = bin_dir.join(nanvix_common::BIN_SUBDIR);
    for name in nanvix_common::BIN_SUBDIR_FILES {
        println!("cargo:rerun-if-changed={}", bin_subdir.join(name).display());
    }
    // Track snapshots too: adding/removing/updating them under the same
    // NANVIX_BIN path must re-trigger the build (and the downstream copy/purge)
    // so the runtime never uses a stale or mismatched warm-start snapshot.
    let snapshots_subdir = bin_dir.join(nanvix_common::SNAPSHOTS_SUBDIR);
    for name in nanvix_common::SNAPSHOT_FILES {
        println!(
            "cargo:rerun-if-changed={}",
            snapshots_subdir.join(name).display()
        );
    }
}

fn needs_download(
    config: &RepoConfig,
    bin_dir: &Path,
    checksums: &HashMap<String, String>,
) -> bool {
    // Check flat binaries.
    let flat_missing = config.binaries.iter().any(|name| {
        let path = bin_dir.join(name);
        if !path.exists() {
            return true;
        }
        if let Some(expected) = checksums.get(name.as_str()) {
            certutil_sha256(&path) != *expected
        } else {
            false
        }
    });
    if flat_missing {
        return true;
    }

    // Check bin/ subdir files.
    let bin_subdir = bin_dir.join(nanvix_common::BIN_SUBDIR);
    for name in nanvix_common::BIN_SUBDIR_FILES {
        let path = bin_subdir.join(name);
        if !path.exists() {
            return true;
        }
        if let Some(expected) = checksums.get(*name) {
            if certutil_sha256(&path) != *expected {
                return true;
            }
        }
    }

    false
}

fn download_and_extract(config: &RepoConfig, repo: &str, bin_dir: &Path) {
    let url = github_download_url(repo, &config.tag, &config.asset);
    let zip_path = bin_dir.join(&config.asset);

    // Cleanup helper: remove zip on failure.
    let cleanup = |zip: &Path| {
        let _ = fs::remove_file(zip);
    };

    eprintln!("  downloading {}...", config.asset);
    if let Err(msg) = try_curl_download(&url, &zip_path) {
        cleanup(&zip_path);
        panic!("nanvix_binaries: {}", msg);
    }

    let size = zip_path.metadata().map(|m| m.len()).unwrap_or(0);
    eprintln!("  downloaded {} bytes, extracting...", size);

    let binaries: Vec<&str> = config.binaries.iter().map(|s| s.as_str()).collect();

    // Extract flat binaries (nanvixd.exe from bin/, rootfs + initrd from root).
    if let Err(msg) = try_tar_extract(&zip_path, bin_dir, &binaries) {
        cleanup(&zip_path);
        panic!("nanvix_binaries: {}", msg);
    }

    // Extract bin/ subdir files (kernel.elf stays in bin/ as nanvixd expects).
    let bin_subdir = bin_dir.join(nanvix_common::BIN_SUBDIR);
    fs::create_dir_all(&bin_subdir).expect("failed to create bin subdir");
    if let Err(msg) = try_tar_extract_bin_subdir(&zip_path, &bin_subdir) {
        cleanup(&zip_path);
        panic!("nanvix_binaries: {}", msg);
    }

    let _ = fs::remove_file(&zip_path);
}

// -- Snapshot generation -----------------------------------------------------

fn generate_snapshots_locally(bin_dir: &Path) {
    let nanvixd = bin_dir.join("nanvixd.exe");
    let ramfs = bin_dir.join("nanvix_rootfs.img");
    let initrd = bin_dir.join("python3.initrd");
    let bin_subdir = bin_dir.join(nanvix_common::BIN_SUBDIR);

    if !nanvixd.exists() || !ramfs.exists() || !initrd.exists() {
        panic!(
            "nanvix_binaries: cannot generate snapshots — required binaries missing:\n\
             \x20 nanvixd.exe: {}\n\
             \x20 nanvix_rootfs.img: {}\n\
             \x20 python3.initrd: {}",
            nanvixd.exists(),
            ramfs.exists(),
            initrd.exists()
        );
    }

    nanvix_common::generate_snapshot(bin_dir, &nanvixd, &bin_subdir, &ramfs, &initrd)
        .unwrap_or_else(|e| panic!("nanvix_binaries: {}", e));

    // Log generated file sizes.
    let snapshots_dir = bin_dir.join(nanvix_common::SNAPSHOTS_SUBDIR);
    for name in nanvix_common::SNAPSHOT_FILES {
        let path = snapshots_dir.join(name);
        let size = path.metadata().map(|m| m.len()).unwrap_or(0);
        eprintln!("  snapshots/{} -- generated ({} bytes)", name, size);
    }
}

// -- curl.exe ----------------------------------------------------------------

fn try_curl_download(url: &str, dest: &Path) -> Result<(), String> {
    let mut cmd = Command::new("curl");
    cmd.args([
        "--silent",
        "--show-error",
        "--fail",
        "--location",
        "--retry",
        "5",
        "--retry-delay",
        "5",
        "--retry-all-errors",
        "--output",
    ]);
    cmd.arg(dest);
    cmd.args(["--header", "User-Agent: mxc-nanvix-build/0.1"]);

    if let Some(token) = github_token() {
        cmd.arg("--header");
        cmd.arg(format!("Authorization: Bearer {}", token));
    }

    cmd.arg(url);

    let output = cmd.output().map_err(|e| {
        format!(
            "curl not found: {}\n\
             Ensure curl is in PATH.",
            e
        )
    })?;

    if !output.status.success() {
        return Err(format!(
            "curl failed for {}\n  exit code: {}\n  stderr: {}",
            url,
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(())
}

// -- tar.exe -----------------------------------------------------------------

fn try_tar_extract(zip_path: &Path, dest_dir: &Path, files: &[&str]) -> Result<(), String> {
    // The nanvix-python zip has a top-level directory with two sub-layouts:
    //   bin/nanvixd.exe  → strip 2 components
    //   nanvix_rootfs.img, python3.initrd → strip 1 component

    const ARCHIVE_PREFIX: &str = "microvm-standalone-256mb";
    const BIN_DIR_FILES: &[&str] = &["nanvixd.exe"];

    let (bin_files, root_files): (Vec<&&str>, Vec<&&str>) =
        files.iter().partition(|f| BIN_DIR_FILES.contains(f));

    // Pass 1: files under <prefix>/bin/ — strip 2 path components.
    if !bin_files.is_empty() {
        let mut cmd = Command::new("tar");
        cmd.arg("-xf").arg(zip_path).arg("-C").arg(dest_dir);
        cmd.args(["--strip-components", "2"]);
        for f in &bin_files {
            cmd.arg(format!("{}/bin/{}", ARCHIVE_PREFIX, f));
        }
        let output = cmd.output().map_err(|e| {
            format!(
                "tar.exe not found: {}\n\
                 tar.exe ships with Windows 10 1803+. Ensure it's in PATH.",
                e
            )
        })?;
        if !output.status.success() {
            return Err(format!(
                "tar extraction failed (bin files)\n  exit code: {}\n  stderr: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ));
        }
    }

    // Pass 2: files at <prefix>/ root — strip 1 path component.
    if !root_files.is_empty() {
        let mut cmd = Command::new("tar");
        cmd.arg("-xf").arg(zip_path).arg("-C").arg(dest_dir);
        cmd.args(["--strip-components", "1"]);
        for f in &root_files {
            cmd.arg(format!("{}/{}", ARCHIVE_PREFIX, f));
        }
        let output = cmd.output().map_err(|e| {
            format!(
                "tar.exe not found: {}\n\
                 tar.exe ships with Windows 10 1803+. Ensure it's in PATH.",
                e
            )
        })?;
        if !output.status.success() {
            return Err(format!(
                "tar extraction failed (root files)\n  exit code: {}\n  stderr: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ));
        }
    }

    for f in files {
        let path = dest_dir.join(f);
        if path.exists() {
            let size = path.metadata().map(|m| m.len()).unwrap_or(0);
            eprintln!("  {} -- extracted ({} bytes)", f, size);
        } else {
            return Err(format!("'{}' not found in zip after extraction", f));
        }
    }

    Ok(())
}

fn try_tar_extract_bin_subdir(zip_path: &Path, dest_dir: &Path) -> Result<(), String> {
    const ARCHIVE_PREFIX: &str = "microvm-standalone-256mb";

    for name in nanvix_common::BIN_SUBDIR_FILES {
        let mut cmd = Command::new("tar");
        cmd.arg("-xf").arg(zip_path).arg("-C").arg(dest_dir);
        cmd.args(["--strip-components", "2"]);
        cmd.arg(format!("{}/bin/{}", ARCHIVE_PREFIX, name));
        let output = cmd
            .output()
            .map_err(|e| format!("tar.exe not found: {}", e))?;
        if !output.status.success() {
            return Err(format!(
                "tar extraction failed (bin/{})\n  exit code: {}\n  stderr: {}",
                name,
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        let path = dest_dir.join(name);
        if path.exists() {
            let size = path.metadata().map(|m| m.len()).unwrap_or(0);
            eprintln!("  bin/{} -- extracted ({} bytes)", name, size);
        } else {
            return Err(format!("'bin/{}' not found in zip after extraction", name));
        }
    }

    Ok(())
}

// -- Helpers -----------------------------------------------------------------

fn github_token() -> Option<String> {
    std::env::var("GITHUB_TOKEN")
        .or_else(|_| std::env::var("GH_TOKEN"))
        .ok()
}

// -- certutil SHA256 ---------------------------------------------------------

fn certutil_sha256(path: &Path) -> String {
    let output = Command::new("certutil")
        .args(["-hashfile"])
        .arg(path)
        .arg("SHA256")
        .output()
        .unwrap_or_else(|e| {
            panic!("nanvix_binaries: failed to run certutil: {}", e);
        });

    if !output.status.success() {
        panic!(
            "nanvix_binaries: certutil -hashfile failed for {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // certutil output format:
    //   SHA256 hash of <file>:
    //   <hex hash>
    //   CertUtil: -hashfile command completed successfully.
    //
    // Use a lossy conversion because the localized header/footer lines are
    // emitted in the console's OEM code page (e.g. CP850 on French Windows),
    // not UTF-8 -- a strict `from_utf8` would panic on those bytes. The hash
    // line itself is pure ASCII hex, so it survives the lossy conversion. We
    // locate the hash by scanning for a 64-character hex line rather than
    // relying on a fixed line index, which keeps this locale-independent.
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .map(|line| line.trim().replace(' ', "").to_lowercase())
        .find(|line| line.len() == 64 && line.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap_or_else(|| panic!("nanvix_binaries: unexpected certutil output: {}", stdout))
}

fn verify_checksums(binaries: &[&str], bin_dir: &Path, checksums: &HashMap<String, String>) {
    for name in binaries {
        let path = bin_dir.join(name);
        if !path.exists() {
            panic!("nanvix_binaries: {} not found after download/extract", name);
        }

        if let Some(expected) = checksums.get(*name) {
            let actual = certutil_sha256(&path);
            if actual != *expected {
                panic!(
                    "nanvix_binaries: SHA256 mismatch for '{}'!\n\
                     \x20 expected: {}\n\
                     \x20 actual:   {}\n\
                     This may indicate a corrupted download or a NanVix version update.\n\
                     Update checksums.json with the new hashes.",
                    name, expected, actual
                );
            }
            eprintln!("  {} -- checksum OK", name);
        } else {
            panic!(
                "nanvix_binaries: '{}' has no entry in checksums.json — \
                 every binary must be hash-verified",
                name
            );
        }
    }
}

fn verify_bin_subdir_checksums(bin_dir: &Path, checksums: &HashMap<String, String>) {
    let bin_subdir = bin_dir.join(nanvix_common::BIN_SUBDIR);
    for name in nanvix_common::BIN_SUBDIR_FILES {
        let path = bin_subdir.join(name);
        if !path.exists() {
            panic!(
                "nanvix_binaries: bin/{} not found after download/extract",
                name
            );
        }

        if let Some(expected) = checksums.get(*name) {
            let actual = certutil_sha256(&path);
            if actual != *expected {
                panic!(
                    "nanvix_binaries: SHA256 mismatch for 'bin/{}'!\n\
                     \x20 expected: {}\n\
                     \x20 actual:   {}\n\
                     Update checksums.json with the new hashes.",
                    name, expected, actual
                );
            }
            eprintln!("  bin/{} -- checksum OK", name);
        } else {
            panic!(
                "nanvix_binaries: 'bin/{}' has no entry in checksums.json — \
                 every binary must be hash-verified",
                name
            );
        }
    }
}

// -- Linux-specific functions ------------------------------------------------

fn needs_download_linux(
    binaries: &[&str],
    bin_dir: &Path,
    checksums: &HashMap<String, String>,
) -> bool {
    // Check flat binaries.
    for name in binaries {
        let path = bin_dir.join(name);
        if !path.exists() {
            return true;
        }
        if let Some(expected) = checksums.get(*name) {
            if sha256sum(&path) != *expected {
                return true;
            }
        }
    }

    // Check bin/ subdir files.
    let bin_subdir = bin_dir.join(nanvix_common::BIN_SUBDIR);
    for name in nanvix_common::BIN_SUBDIR_FILES {
        let path = bin_subdir.join(name);
        if !path.exists() {
            return true;
        }
        if let Some(expected) = checksums.get(*name) {
            if sha256sum(&path) != *expected {
                return true;
            }
        }
    }

    false
}

fn download_and_extract_linux(tag: &str, asset: &str, binaries: &[&str], bin_dir: &Path) {
    let url = github_download_url("nanvix/nanvix-python", tag, asset);
    let tar_path = bin_dir.join(asset);

    let cleanup = |p: &Path| {
        let _ = fs::remove_file(p);
    };

    eprintln!("  downloading {}...", asset);
    if let Err(msg) = try_curl_download(&url, &tar_path) {
        cleanup(&tar_path);
        panic!("nanvix_binaries: {}", msg);
    }

    let size = tar_path.metadata().map(|m| m.len()).unwrap_or(0);
    eprintln!("  downloaded {} bytes, extracting...", size);

    // Extract flat binaries from <prefix>/ using tar on Linux.
    if let Err(msg) = try_tar_extract_linux(&tar_path, bin_dir, binaries) {
        cleanup(&tar_path);
        panic!("nanvix_binaries: {}", msg);
    }

    // Extract bin/ subdir files (kernel.elf, nanvixd.elf).
    let bin_subdir = bin_dir.join(nanvix_common::BIN_SUBDIR);
    fs::create_dir_all(&bin_subdir).expect("failed to create bin subdir");
    if let Err(msg) = try_tar_extract_bin_subdir_linux(&tar_path, &bin_subdir) {
        cleanup(&tar_path);
        panic!("nanvix_binaries: {}", msg);
    }

    let _ = fs::remove_file(&tar_path);
}

fn try_tar_extract_linux(tar_path: &Path, dest_dir: &Path, files: &[&str]) -> Result<(), String> {
    const ARCHIVE_PREFIX: &str = "microvm-standalone-256mb";

    // nanvixd.elf lives under <prefix>/bin/, other flat binaries under <prefix>/.
    let bin_dir_files: &[&str] = &["nanvixd.elf"];
    let (bin_files, root_files): (Vec<&&str>, Vec<&&str>) =
        files.iter().partition(|f| bin_dir_files.contains(f));

    // Pass 1: files under <prefix>/bin/ — strip 2 path components.
    if !bin_files.is_empty() {
        let mut cmd = Command::new("tar");
        cmd.arg("-xzf").arg(tar_path).arg("-C").arg(dest_dir);
        cmd.args(["--strip-components", "2"]);
        for f in &bin_files {
            cmd.arg(format!("{}/bin/{}", ARCHIVE_PREFIX, f));
        }
        let output = cmd.output().map_err(|e| format!("tar not found: {}", e))?;
        if !output.status.success() {
            return Err(format!(
                "tar extraction failed (bin files)\n  exit code: {}\n  stderr: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ));
        }
    }

    // Pass 2: files at <prefix>/ root — strip 1 path component.
    if !root_files.is_empty() {
        let mut cmd = Command::new("tar");
        cmd.arg("-xzf").arg(tar_path).arg("-C").arg(dest_dir);
        cmd.args(["--strip-components", "1"]);
        for f in &root_files {
            cmd.arg(format!("{}/{}", ARCHIVE_PREFIX, f));
        }
        let output = cmd.output().map_err(|e| format!("tar not found: {}", e))?;
        if !output.status.success() {
            return Err(format!(
                "tar extraction failed (root files)\n  exit code: {}\n  stderr: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ));
        }
    }

    for f in files {
        let path = dest_dir.join(f);
        if path.exists() {
            let size = path.metadata().map(|m| m.len()).unwrap_or(0);
            eprintln!("  {} -- extracted ({} bytes)", f, size);
        } else {
            return Err(format!("'{}' not found in archive after extraction", f));
        }
    }

    Ok(())
}

fn try_tar_extract_bin_subdir_linux(tar_path: &Path, dest_dir: &Path) -> Result<(), String> {
    const ARCHIVE_PREFIX: &str = "microvm-standalone-256mb";

    for name in nanvix_common::BIN_SUBDIR_FILES {
        let mut cmd = Command::new("tar");
        cmd.arg("-xzf").arg(tar_path).arg("-C").arg(dest_dir);
        cmd.args(["--strip-components", "2"]);
        cmd.arg(format!("{}/bin/{}", ARCHIVE_PREFIX, name));
        let output = cmd.output().map_err(|e| format!("tar not found: {}", e))?;
        if !output.status.success() {
            return Err(format!(
                "tar extraction failed (bin/{})\n  exit code: {}\n  stderr: {}",
                name,
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        let path = dest_dir.join(name);
        if path.exists() {
            let size = path.metadata().map(|m| m.len()).unwrap_or(0);
            eprintln!("  bin/{} -- extracted ({} bytes)", name, size);
        } else {
            return Err(format!(
                "'bin/{}' not found in archive after extraction",
                name
            ));
        }
    }

    Ok(())
}

/// Compute SHA256 hash using the `sha256sum` command (Linux).
fn sha256sum(path: &Path) -> String {
    let output = Command::new("sha256sum")
        .arg(path)
        .output()
        .unwrap_or_else(|e| {
            panic!("nanvix_binaries: failed to run sha256sum: {}", e);
        });

    if !output.status.success() {
        panic!(
            "nanvix_binaries: sha256sum failed for {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let stdout = String::from_utf8(output.stdout).expect("sha256sum output not UTF-8");
    stdout
        .split_whitespace()
        .next()
        .unwrap_or_else(|| panic!("nanvix_binaries: unexpected sha256sum output: {}", stdout))
        .to_lowercase()
}

fn verify_checksums_linux(binaries: &[&str], bin_dir: &Path, checksums: &HashMap<String, String>) {
    for name in binaries {
        let path = bin_dir.join(name);
        if !path.exists() {
            panic!("nanvix_binaries: {} not found after download/extract", name);
        }

        if let Some(expected) = checksums.get(*name) {
            let actual = sha256sum(&path);
            if actual != *expected {
                panic!(
                    "nanvix_binaries: SHA256 mismatch for '{}'!\n\
                     \x20 expected: {}\n\
                     \x20 actual:   {}\n\
                     This may indicate a corrupted download or a NanVix version update.\n\
                     Update checksums.json with the new hashes.",
                    name, expected, actual
                );
            }
            eprintln!("  {} -- checksum OK", name);
        } else {
            panic!(
                "nanvix_binaries: '{}' has no entry in checksums.json — \
                 every binary must be hash-verified",
                name
            );
        }
    }
}

fn verify_bin_subdir_checksums_linux(bin_dir: &Path, checksums: &HashMap<String, String>) {
    let bin_subdir = bin_dir.join(nanvix_common::BIN_SUBDIR);
    for name in nanvix_common::BIN_SUBDIR_FILES {
        let path = bin_subdir.join(name);
        if !path.exists() {
            panic!(
                "nanvix_binaries: bin/{} not found after download/extract",
                name
            );
        }

        if let Some(expected) = checksums.get(*name) {
            let actual = sha256sum(&path);
            if actual != *expected {
                panic!(
                    "nanvix_binaries: SHA256 mismatch for 'bin/{}'!\n\
                     \x20 expected: {}\n\
                     \x20 actual:   {}\n\
                     Update checksums.json with the new hashes.",
                    name, expected, actual
                );
            }
            eprintln!("  bin/{} -- checksum OK", name);
        } else {
            panic!(
                "nanvix_binaries: 'bin/{}' has no entry in checksums.json — \
                 every binary must be hash-verified",
                name
            );
        }
    }
}
