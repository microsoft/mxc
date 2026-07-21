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

use sha2::{Digest, Sha256};

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

    // An ISOSESSION_SDK_PATH override silently changes which provenance is read;
    // surface it so a stale/wrong local extraction is never invisible.
    if let Ok(path) = std::env::var("ISOSESSION_SDK_PATH") {
        if !path.trim().is_empty() {
            println!(
                "cargo:warning=IsolationSession SDK: provenance overridden by \
                 ISOSESSION_SDK_PATH='{}'",
                path
            );
        }
    }

    // Deliver the runtime shim assets (IsoSessionApp.dll + IsoSession.manifest)
    // from the SAME package that supplies the build-time metadata, so a single
    // NuGet reference is the sole source of truth -- no external copy from the
    // MSI folder. A metadata-only package is a silent no-op.
    stage_runtime_assets(&sdk_dir);

    // Resolve the GENERATION_INFO.toml contents from the NuGet package (or its
    // overrides / fallback). If none can be found, skip the check -- this keeps
    // first-time setup and non-Windows hosts building.
    let contents = match resolve_generation_info(&sdk_dir) {
        Some(c) => c,
        None => return,
    };

    // Bake the IsoSession runtime instance this build targets into the binary so
    // the runtime can verify it matches the installed runtime folder. Skip
    // silently when the provenance carries no instance (source-only builds).
    if let Some(instance) = parse_toml_value(&contents, "instance") {
        println!("cargo:rustc-env=ISOSESSION_INSTANCE={}", instance);
    }

    // Gate the committed NuGet for self-consistency: exactly one package, and
    // its filename / nuspec version / instance / winmd hash all agree. This is
    // what makes the baked ISOSESSION_INSTANCE trustworthy.
    validate_nupkg_consistency(&sdk_dir, &contents);

    // Extract the expected windows crate version from the TOML.
    let expected = parse_toml_value(&contents, "target_windows_crate");

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

/// Stages the runtime shim assets the consumer needs at run time --
/// `IsoSessionApp.dll` and its side-by-side `IsoSession.manifest` -- from the
/// SDK nupkg into the Cargo profile output dir, next to the built
/// `wxc-exec.exe`. This makes a single NuGet package reference deliver BOTH the
/// build-time metadata (consumed elsewhere in this script) and the runtime
/// asset, with no external copy from the MSI folder.
///
/// A metadata-only package (no `runtimes/` entries) is a silent no-op, so
/// pre-runtime-payload packages keep building unchanged. Non-Windows targets
/// are skipped (the payload is a Windows DLL).
fn stage_runtime_assets(sdk_dir: &Path) {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let Some(nupkg) = find_nupkg(sdk_dir) else {
        return;
    };

    // Cargo places the built binary in the profile dir. OUT_DIR is
    // `<profile>/build/<crate>-<hash>/out`, so the profile dir is 3 levels up.
    let Ok(out_dir) = std::env::var("OUT_DIR") else {
        return;
    };
    let Some(profile_dir) = Path::new(&out_dir).ancestors().nth(3) else {
        return;
    };

    let file = match std::fs::File::open(&nupkg) {
        Ok(f) => f,
        Err(e) => {
            println!(
                "cargo:warning=IsolationSession SDK: cannot open {} to stage runtime assets: {}",
                nupkg.display(),
                e
            );
            return;
        }
    };
    let mut archive = match zip::ZipArchive::new(file) {
        Ok(a) => a,
        Err(e) => {
            println!(
                "cargo:warning=IsolationSession SDK: cannot read {} as zip to stage runtime \
                 assets: {}",
                nupkg.display(),
                e
            );
            return;
        }
    };

    const RID_PREFIX: &str = "runtimes/win-x64/native/";
    for asset in ["IsoSessionApp.dll", "IsoSession.manifest"] {
        let entry_name = format!("{}{}", RID_PREFIX, asset);
        match read_entry_bytes(&mut archive, &entry_name) {
            Ok(bytes) => {
                let dst = profile_dir.join(asset);
                if let Err(e) = std::fs::write(&dst, &bytes) {
                    println!(
                        "cargo:warning=IsolationSession SDK: failed to stage {} -> {}: {}",
                        entry_name,
                        dst.display(),
                        e
                    );
                } else {
                    println!(
                        "cargo:warning=IsolationSession SDK: staged {} -> {}",
                        asset,
                        dst.display()
                    );
                }
            }
            // Metadata-only package: no runtime payload to stage.
            Err(_) => {}
        }
    }
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

    let file = std::fs::File::open(nupkg)
        .map_err(|e| format!("cannot open {}: {}", nupkg.display(), e))?;
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

/// Minimal line-based reader for a top-level `key = "value"` (or `key = value`)
/// entry in `GENERATION_INFO.toml`. Matches only the exact key (so `winmd`
/// does not match `winmd_sha256`/`winmd_preview`) and ignores comments.
fn parse_toml_value(contents: &str, key: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let line = line.trim();
        if line.starts_with('#') {
            return None;
        }
        let rest = line.strip_prefix(key)?.trim_start();
        let value = rest.strip_prefix('=')?;
        Some(value.trim().trim_matches('"').to_string())
    })
}

/// All `*.nupkg` files in `dir`, sorted for deterministic diagnostics.
fn all_nupkgs(dir: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .map(|x| x.eq_ignore_ascii_case("nupkg"))
                .unwrap_or(false)
        })
        .collect();
    found.sort();
    found
}

/// Extracts the inner text of the first `<tag>...</tag>` in `xml`.
fn xml_tag_value(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].trim().to_string())
}

/// Reads a zip entry's raw bytes by exact name.
fn read_entry_bytes(
    archive: &mut zip::ZipArchive<std::fs::File>,
    name: &str,
) -> Result<Vec<u8>, String> {
    let mut entry = archive
        .by_name(name)
        .map_err(|e| format!("{} not in nupkg: {}", name, e))?;
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut entry, &mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
}

/// Name of the first zip entry whose path ends with `suffix` (case-insensitive).
fn find_entry_by_suffix(
    archive: &mut zip::ZipArchive<std::fs::File>,
    suffix: &str,
) -> Option<String> {
    let suffix = suffix.to_ascii_lowercase();
    for i in 0..archive.len() {
        if let Ok(entry) = archive.by_index(i) {
            let name = entry.name().to_string();
            if name.to_ascii_lowercase().ends_with(&suffix) {
                return Some(name);
            }
        }
    }
    None
}

/// Lower-case hex of the SHA-256 of `bytes`.
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

/// Gates the committed NuGet for self-consistency so the baked
/// `ISOSESSION_INSTANCE` is provably the package's declared identity:
///
/// 1. exactly one `*.nupkg` in `sdk_dir` (panic on more than one);
/// 2. the package filename equals its canonical `{id}.{version}.nupkg`;
/// 3. the `GENERATION_INFO.toml` `instance` equals the nuspec version's minor
///    field (the package version is `0.<instance>.0`);
/// 4. the shipped winmd hashes to the recorded `winmd_sha256`.
///
/// No nupkg (fallback / `ISOSESSION_SDK_PATH` override build) -> no-op. Failures
/// `panic!` to hard-fail the build, since a package that disagrees with its own
/// provenance cannot be trusted to bind the right runtime.
fn validate_nupkg_consistency(sdk_dir: &Path, contents: &str) {
    // When ISOSESSION_SDK_PATH is set, `contents` came from the override
    // directory, not the committed nupkg in `sdk_dir`. Validating the committed
    // package against override provenance would falsely fail (e.g. an override
    // instance that differs from the committed package's version). The override
    // is a deliberate developer escape hatch, so skip the gate entirely.
    if std::env::var("ISOSESSION_SDK_PATH")
        .map(|p| !p.trim().is_empty())
        .unwrap_or(false)
    {
        return;
    }

    let nupkgs = all_nupkgs(sdk_dir);
    let nupkg = match nupkgs.len() {
        0 => return,
        1 => &nupkgs[0],
        n => panic!(
            "isolation_session_bindings: expected exactly one *.nupkg in {}, found {}: {:?}. \
             Remove the stale package(s) so the build targets a single, unambiguous SDK.",
            sdk_dir.display(),
            n,
            nupkgs
        ),
    };

    let file = match std::fs::File::open(nupkg) {
        Ok(f) => f,
        Err(e) => {
            println!(
                "cargo:warning=IsolationSession SDK: cannot open {} for validation: {}",
                nupkg.display(),
                e
            );
            return;
        }
    };
    let mut archive = match zip::ZipArchive::new(file) {
        Ok(a) => a,
        Err(e) => {
            println!(
                "cargo:warning=IsolationSession SDK: cannot read {} as zip for validation: {}",
                nupkg.display(),
                e
            );
            return;
        }
    };

    // (2)+(3): nuspec id/version vs filename, and instance vs version minor.
    if let Some(nuspec_name) = find_entry_by_suffix(&mut archive, ".nuspec") {
        let xml = match read_entry_bytes(&mut archive, &nuspec_name) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(e) => panic!(
                "isolation_session_bindings: cannot read {}: {}",
                nuspec_name, e
            ),
        };
        let id = xml_tag_value(&xml, "id").unwrap_or_else(|| {
            panic!(
                "isolation_session_bindings: <id> missing in {}",
                nuspec_name
            )
        });
        let version = xml_tag_value(&xml, "version").unwrap_or_else(|| {
            panic!(
                "isolation_session_bindings: <version> missing in {}",
                nuspec_name
            )
        });

        let file_name = nupkg
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let expected_file = format!("{}.{}.nupkg", id, version);
        if !file_name.eq_ignore_ascii_case(&expected_file) {
            panic!(
                "isolation_session_bindings: nupkg filename '{}' does not match its nuspec \
                 id+version (expected '{}'). The package may have been renamed or repacked.",
                file_name, expected_file
            );
        }

        if let Some(instance) = parse_toml_value(contents, "instance") {
            // The instance is a dotted runtime identity (e.g. "2026.06"); the
            // nuspec version encodes it dot-stripped in its minor field
            // (0.202606.0). Compare the two after removing the dots.
            let minor = version.split('.').nth(1).unwrap_or_default();
            let instance_key = instance.replace('.', "");
            if minor != instance_key {
                panic!(
                    "isolation_session_bindings: GENERATION_INFO.toml instance='{}' \
                     (dot-stripped '{}') but the nuspec version is '{}' (minor '{}'). \
                     Bump them in lockstep.",
                    instance, instance_key, version, minor
                );
            }
        }
    }

    // (4): winmd integrity against the recorded hash.
    if let (Some(winmd_name), Some(expected_hash)) = (
        parse_toml_value(contents, "winmd"),
        parse_toml_value(contents, "winmd_sha256"),
    ) {
        let entry_name = format!("metadata/{}", winmd_name);
        match read_entry_bytes(&mut archive, &entry_name) {
            Ok(bytes) => {
                let actual = sha256_hex(&bytes);
                if !actual.eq_ignore_ascii_case(&expected_hash) {
                    panic!(
                        "isolation_session_bindings: winmd '{}' sha256 {} does not match \
                         GENERATION_INFO.toml winmd_sha256 {}. The package is corrupt or its \
                         provenance is stale.",
                        entry_name, actual, expected_hash
                    );
                }
            }
            Err(e) => println!(
                "cargo:warning=IsolationSession SDK: cannot verify winmd hash ({}): {}",
                entry_name, e
            ),
        }
    }
}
