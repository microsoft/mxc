// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script that verifies the workspace's `windows` crate version matches
//! the version the generated bindings were produced for.
//!
//! Provenance is consumed from the **`Microsoft.Windows.AI.IsolationSession.SDK`
//! NuGet package** -- the same metadata-only package MXC builds against. The
//! `target_windows_crate` value is resolved in this order:
//!
//! 1. `ISOSESSION_SDK_PATH` env var -- a directory containing
//!    `GENERATION_INFO.toml` (directly or under `metadata\`). Set this to a
//!    local NuGet-cache extraction to skip nupkg unzip.
//! 2. The `*.nupkg` in `external/windows-sdk/isolation-session/`, unzipped into
//!    `OUT_DIR` (the package ships `metadata/GENERATION_INFO.toml`).
//! 3. A committed `external/windows-sdk/isolation-session/GENERATION_INFO.toml`
//!    fallback (first-time setup before the nupkg is present).
//!
//! The winmd in the package is the regeneration input only; an ordinary build
//! never touches it -- this script reads provenance and version-gates the
//! committed `bindings.rs`.

use std::path::{Path, PathBuf};

fn main() {
    let sdk_dir = sdk_external_dir();

    // Re-run when the provenance inputs change.
    println!("cargo:rerun-if-env-changed=ISOSESSION_SDK_PATH");
    println!(
        "cargo:rerun-if-changed={}",
        sdk_dir.join("GENERATION_INFO.toml").display()
    );
    if let Some(nupkg) = find_nupkg(&sdk_dir) {
        println!("cargo:rerun-if-changed={}", nupkg.display());
    }

    // Resolve the GENERATION_INFO.toml contents from the NuGet package (or its
    // overrides / fallback). If none can be found, skip the check -- this keeps
    // first-time setup and non-Windows hosts building.
    let contents = match resolve_generation_info(&sdk_dir) {
        Some(c) => c,
        None => return,
    };

    // Extract the expected windows crate version from the TOML.
    let expected = contents.lines().find_map(|line| {
        let line = line.trim();
        if line.starts_with("target_windows_crate") {
            line.split('=')
                .nth(1)
                .map(|v| v.trim().trim_matches('"').to_string())
        } else {
            None
        }
    });

    let Some(expected_version) = expected else {
        // No version constraint found — skip check.
        return;
    };

    // Read the actual windows crate version from Cargo.lock. In a workspace the
    // lock lives at the workspace root, not next to the crate, so walk ancestors.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let lock_path = match find_cargo_lock(Path::new(&manifest_dir)) {
        Some(p) => p,
        None => return,
    };

    let lock_contents = std::fs::read_to_string(&lock_path).unwrap_or_default();

    // Simple parser: find the [[package]] block for windows.
    let actual_version = lock_contents
        .split("[[package]]")
        .find(|block| {
            let has_name = block.lines().any(|l| l.trim() == "name = \"windows\"");
            // Exclude windows-* crates (windows-core, windows-sys, etc.)
            let not_prefixed = !block.lines().any(|l| {
                let t = l.trim();
                t.starts_with("name = \"windows-")
            });
            has_name && not_prefixed
        })
        .and_then(|block| {
            block.lines().find_map(|l| {
                let t = l.trim();
                if t.starts_with("version = ") {
                    Some(t.split('=').nth(1)?.trim().trim_matches('"').to_string())
                } else {
                    None
                }
            })
        });

    // Build a caret requirement from the major.minor of `expected_version`.
    // This matches "compatible with X.Y" — same loose-on-patch intent as the
    // prior `starts_with` check, but via a real semver parser so e.g. "0.6"
    // cannot silently accept "0.62".
    let parts: Vec<&str> = expected_version.split('.').take(2).collect();
    let req_pattern = if parts.len() == 2 {
        format!("^{}.{}", parts[0], parts[1])
    } else {
        return; // Unexpected format — skip check rather than fail loudly.
    };
    let Ok(req) = semver::VersionReq::parse(&req_pattern) else {
        return;
    };

    if let Some(actual) = actual_version {
        let Ok(actual_ver) = semver::Version::parse(&actual) else {
            return;
        };
        if !req.matches(&actual_ver) {
            panic!(
                "\n\n\
                 isolation_session_bindings: generated code targets windows crate {expected},\n\
                 but workspace has {actual}. Bindings must be regenerated.\n\
                 \n",
                expected = expected_version,
                actual = actual,
            );
        }
    }
}

/// `external/windows-sdk/isolation-session/` resolved by walking up from this
/// crate's manifest dir until the directory is found. Hard-coding a fixed
/// number of `..` is brittle (the crate has moved depth before); searching
/// ancestors is resilient to layout changes.
fn sdk_external_dir() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let rel = Path::new("external")
        .join("windows-sdk")
        .join("isolation-session");

    let start = PathBuf::from(&manifest_dir);
    for ancestor in start.ancestors() {
        let candidate = ancestor.join(&rel);
        if candidate.is_dir() {
            return candidate;
        }
    }

    // Fall back to the repo-root-relative location (…/mxc/external/…) so the
    // returned path is still meaningful for diagnostics even when absent.
    start.join("..").join("..").join("..").join("..").join(&rel)
}

/// Walks up from `start` to locate the `Cargo.lock` that governs this crate.
/// In a Cargo workspace the lock lives at the workspace root, not beside the
/// member crate, so a fixed-depth `..` is wrong.
fn find_cargo_lock(start: &Path) -> Option<PathBuf> {
    for ancestor in start.ancestors() {
        let candidate = ancestor.join("Cargo.lock");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Returns the first `*.nupkg` in `dir`, if any.
fn find_nupkg(dir: &Path) -> Option<PathBuf> {
    std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.extension()
                .map(|x| x.eq_ignore_ascii_case("nupkg"))
                .unwrap_or(false)
        })
}

/// Resolves the `GENERATION_INFO.toml` contents from (in priority order) the
/// `ISOSESSION_SDK_PATH` override, the NuGet package, or a committed fallback.
fn resolve_generation_info(sdk_dir: &Path) -> Option<String> {
    // 1. Explicit override directory.
    if let Ok(path) = std::env::var("ISOSESSION_SDK_PATH") {
        let base = PathBuf::from(path);
        let candidates = [
            base.join("metadata").join("GENERATION_INFO.toml"),
            base.join("GENERATION_INFO.toml"),
        ];
        for candidate in candidates {
            if let Ok(c) = std::fs::read_to_string(&candidate) {
                return Some(c);
            }
        }
    }

    // 2. Extract from the NuGet package (mirrors external/wslc-sdk/).
    if let Some(nupkg) = find_nupkg(sdk_dir) {
        match extract_generation_info(&nupkg) {
            Ok(c) => return Some(c),
            Err(e) => println!("cargo:warning=IsolationSession SDK: {}", e),
        }
    }

    // 3. Committed fallback (first-time setup before the nupkg is present).
    std::fs::read_to_string(sdk_dir.join("GENERATION_INFO.toml")).ok()
}

/// Unzips `metadata/GENERATION_INFO.toml` from the nupkg into `OUT_DIR` and
/// returns its contents.
fn extract_generation_info(nupkg: &Path) -> Result<String, String> {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").map_err(|e| e.to_string())?);
    let extract_dir = out_dir.join("isolation-session-sdk");
    let dst = extract_dir.join("GENERATION_INFO.toml");

    // Cache: reuse a prior extraction.
    if let Ok(c) = std::fs::read_to_string(&dst) {
        return Ok(c);
    }

    let file =
        std::fs::File::open(nupkg).map_err(|e| format!("cannot open {}: {}", nupkg.display(), e))?;
    let mut archive =
        zip::ZipArchive::new(file).map_err(|e| format!("cannot read nupkg as zip: {}", e))?;

    let mut entry = archive
        .by_name("metadata/GENERATION_INFO.toml")
        .map_err(|e| format!("metadata/GENERATION_INFO.toml not in nupkg: {}", e))?;

    let mut contents = String::new();
    std::io::Read::read_to_string(&mut entry, &mut contents)
        .map_err(|e| format!("cannot read GENERATION_INFO.toml from nupkg: {}", e))?;

    // Best-effort cache to OUT_DIR for subsequent builds.
    let _ = std::fs::create_dir_all(&extract_dir);
    let _ = std::fs::write(&dst, &contents);

    println!(
        "cargo:warning=IsolationSession SDK: provenance read from {}",
        nupkg.display()
    );

    Ok(contents)
}
