// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script that regenerates the IsolationSession Preview WinRT bindings
//! from the checked-in SDK nuget at compile time, so the crate is always built
//! directly against the pinned `Microsoft.Windows.AI.IsolationSession.SDK`
//! package rather than a committed snapshot.
//!
//! Pipeline: locate the single `*.nupkg` under
//! `external/windows-sdk/isolation-session/`, extract its Preview WinMD (a
//! nupkg is a zip), then run `windows-bindgen` over it into `$OUT_DIR/bindings.rs`
//! (included by `lib.rs`). The invocation mirrors the canonical OS-side
//! generator (`RustBindingsGenerator`).

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");

    // This crate lives at <repo>/src/backends/isolation_session/bindings, so
    // four `..` segments reach the repo root where `external/` lives.
    let sdk_dir = Path::new(&manifest_dir)
        .join("..")
        .join("..")
        .join("..")
        .join("..")
        .join("external")
        .join("windows-sdk")
        .join("isolation-session");

    let nupkg = find_nupkg(&sdk_dir).unwrap_or_else(|| {
        panic!(
            "isolation_session_bindings: no .nupkg found in {}",
            sdk_dir.display()
        )
    });

    // Rebuild whenever the pinned package or this script changes.
    println!("cargo:rerun-if-changed={}", nupkg.display());
    println!("cargo:rerun-if-changed=build.rs");

    // Extract the Preview WinMD from the nuget into OUT_DIR.
    let winmd_bytes = extract_preview_winmd(&nupkg);
    let winmd_path = Path::new(&out_dir).join("windows.ai.isolationsession.preview.winmd");
    fs::write(&winmd_path, &winmd_bytes)
        .unwrap_or_else(|e| panic!("write extracted winmd to {}: {e}", winmd_path.display()));

    let bindings_path = Path::new(&out_dir).join("bindings.rs");

    // Generate bindings for the IsolationSession Preview namespace only. The
    // literal "default" input combines the SDK WinMD with windows-bindgen's
    // bundled Windows metadata; "windows,skip-root,Windows.Foundation" maps the
    // Windows.Foundation dependencies (DateTime, TypedEventHandler) onto the
    // full `windows` crate (Foundation feature enabled in Cargo.toml). This
    // mirrors RustBindingsGenerator exactly.
    let warnings = windows_bindgen::bindgen([
        "--in",
        winmd_path.to_str().expect("winmd path is valid UTF-8"),
        "--in",
        "default",
        "--out",
        bindings_path.to_str().expect("out path is valid UTF-8"),
        "--filter",
        "Windows.AI.IsolationSession.Preview",
        "--reference",
        "windows,skip-root,Windows.Foundation",
        "--flat",
        "--implement",
    ]);

    let warning_text = format!("{warnings}");
    for line in warning_text.lines().filter(|l| !l.trim().is_empty()) {
        println!("cargo:warning=isosession-bindgen: {line}");
    }

    // windows-bindgen emits a leading `#![allow(...)]` inner attribute. That is
    // invalid once the file is `include!`-ed inside `mod bindings { ... }`
    // (an inner attribute cannot annotate the `include!` item macro). The
    // module already carries an equivalent OUTER `#[allow(...)]` in lib.rs, so
    // strip the generated leading inner-attribute block here.
    let generated = fs::read_to_string(&bindings_path)
        .unwrap_or_else(|e| panic!("read generated {}: {e}", bindings_path.display()));
    let cleaned = strip_leading_inner_attrs(&generated);
    fs::write(&bindings_path, cleaned)
        .unwrap_or_else(|e| panic!("rewrite cleaned {}: {e}", bindings_path.display()));
}

/// Drops leading `#![...]` inner-attribute blocks (single- or multi-line) from
/// the generated file, preserving leading comments/blank lines and copying the
/// rest of the body verbatim once the first real item is reached.
fn strip_leading_inner_attrs(src: &str) -> String {
    let mut result = String::with_capacity(src.len());
    let mut in_inner = false;
    let mut started_body = false;
    for line in src.lines() {
        if started_body {
            result.push_str(line);
            result.push('\n');
            continue;
        }
        if in_inner {
            if line.contains(']') {
                in_inner = false;
            }
            continue;
        }
        let trimmed = line.trim_start();
        if trimmed.starts_with("#![") {
            if !trimmed.contains(']') {
                in_inner = true;
            }
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with("//") {
            result.push_str(line);
            result.push('\n');
            continue;
        }
        started_body = true;
        result.push_str(line);
        result.push('\n');
    }
    result
}

/// Returns the single `*.nupkg` under `dir` (lexicographically last if several,
/// so a version bump that leaves an old package behind still picks the newest).
fn find_nupkg(dir: &Path) -> Option<PathBuf> {
    let mut hits: Vec<PathBuf> = fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.extension()
                .map(|x| x.eq_ignore_ascii_case("nupkg"))
                .unwrap_or(false)
        })
        .collect();
    hits.sort();
    hits.into_iter().next_back()
}

/// Extracts the `*preview.winmd` entry from the nuget (a zip archive),
/// tolerant of path-separator variations in the entry name.
fn extract_preview_winmd(nupkg: &Path) -> Vec<u8> {
    let file = fs::File::open(nupkg).unwrap_or_else(|e| panic!("open {}: {e}", nupkg.display()));
    let mut archive =
        zip::ZipArchive::new(file).unwrap_or_else(|e| panic!("read zip {}: {e}", nupkg.display()));

    let entry_name = (0..archive.len())
        .find_map(|i| {
            let name = archive.by_index(i).ok()?.name().to_string();
            if name.to_ascii_lowercase().ends_with("preview.winmd") {
                Some(name)
            } else {
                None
            }
        })
        .unwrap_or_else(|| {
            panic!(
                "isolation_session_bindings: no *preview.winmd entry in {}",
                nupkg.display()
            )
        });

    let mut entry = archive
        .by_name(&entry_name)
        .unwrap_or_else(|e| panic!("open zip entry {entry_name}: {e}"));
    let mut buf = Vec::new();
    entry
        .read_to_end(&mut buf)
        .unwrap_or_else(|e| panic!("read zip entry {entry_name}: {e}"));
    buf
}
