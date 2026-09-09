// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Selects the IsolationSession projection source for the requested build mode.
//!
//! Inbox builds use the committed OS-generated bindings and verify their
//! `windows` crate compatibility. Lifted builds restore the pinned SDK package
//! from NuGet.org and regenerate bindings from its Preview WinMD.

use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    #[cfg(feature = "lifted")]
    generate_lifted_bindings();

    #[cfg(not(feature = "lifted"))]
    verify_inbox_bindings_version();
}

#[cfg(feature = "lifted")]
fn generate_lifted_bindings() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
    let package = mxc_build_common::isolation_session_sdk::resolve_package()
        .unwrap_or_else(|e| panic!("IsolationSession SDK acquisition failed: {e}"));
    let winmd_bytes = mxc_build_common::isolation_session_sdk::read_entry(
        &package,
        "windows.ai.isolationsession.preview.winmd",
    )
    .unwrap_or_else(|e| panic!("IsolationSession SDK metadata extraction failed: {e}"));
    let winmd_path = Path::new(&out_dir).join("windows.ai.isolationsession.preview.winmd");
    std::fs::write(&winmd_path, &winmd_bytes)
        .unwrap_or_else(|e| panic!("write extracted WinMD to {}: {e}", winmd_path.display()));

    let bindings_path = Path::new(&out_dir).join("bindings.rs");
    let warnings = windows_bindgen::bindgen([
        "--in",
        winmd_path.to_str().expect("WinMD path is valid UTF-8"),
        "--in",
        "default",
        "--out",
        bindings_path
            .to_str()
            .expect("bindings path is valid UTF-8"),
        "--filter",
        "Windows.AI.IsolationSession.Preview",
        "--reference",
        "windows,skip-root,Windows.Foundation",
        "--flat",
        "--implement",
    ]);

    for line in format!("{warnings}")
        .lines()
        .filter(|line| !line.trim().is_empty())
    {
        println!("cargo:warning=isosession-bindgen: {line}");
    }

    let generated = std::fs::read_to_string(&bindings_path)
        .unwrap_or_else(|e| panic!("read generated {}: {e}", bindings_path.display()));
    std::fs::write(&bindings_path, strip_leading_inner_attrs(&generated))
        .unwrap_or_else(|e| panic!("rewrite cleaned {}: {e}", bindings_path.display()));
}

#[cfg(feature = "lifted")]
fn strip_leading_inner_attrs(source: &str) -> String {
    let mut result = String::with_capacity(source.len());
    let mut in_inner_attribute = false;
    let mut started_body = false;

    for line in source.lines() {
        if started_body {
            result.push_str(line);
            result.push('\n');
            continue;
        }
        if in_inner_attribute {
            if line.contains(']') {
                in_inner_attribute = false;
            }
            continue;
        }

        let trimmed = line.trim_start();
        if trimmed.starts_with("#![") {
            in_inner_attribute = !trimmed.contains(']');
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

#[cfg(not(feature = "lifted"))]
fn verify_inbox_bindings_version() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let info_path = Path::new(&manifest_dir)
        .join("..")
        .join("..")
        .join("..")
        .join("..")
        .join("external")
        .join("windows-sdk")
        .join("isolation-session")
        .join("GENERATION_INFO.toml");
    if !info_path.exists() {
        return;
    }

    let contents = std::fs::read_to_string(&info_path).unwrap_or_default();
    let Some(expected) = contents.lines().find_map(|line| {
        let line = line.trim();
        if line.starts_with("target_windows_crate") {
            line.split('=')
                .nth(1)
                .map(|value| value.trim().trim_matches('"').to_string())
        } else {
            None
        }
    }) else {
        return;
    };

    let lock_path = Path::new(&manifest_dir)
        .join("..")
        .join("..")
        .join("..")
        .join("Cargo.lock");
    let lock_contents = std::fs::read_to_string(lock_path).unwrap_or_default();
    let actual = lock_contents
        .split("[[package]]")
        .find(|block| {
            block
                .lines()
                .any(|line| line.trim() == "name = \"windows\"")
        })
        .and_then(|block| {
            block.lines().find_map(|line| {
                let line = line.trim();
                if line.starts_with("version = ") {
                    line.split('=')
                        .nth(1)
                        .map(|value| value.trim().trim_matches('"').to_string())
                } else {
                    None
                }
            })
        });

    let parts = expected.split('.').take(2).collect::<Vec<_>>();
    if parts.len() != 2 {
        return;
    }
    let Ok(requirement) = semver::VersionReq::parse(&format!("^{}.{}", parts[0], parts[1])) else {
        return;
    };

    if let Some(actual) = actual {
        let Ok(actual_version) = semver::Version::parse(&actual) else {
            return;
        };
        assert!(
            requirement.matches(&actual_version),
            "isolation_session_bindings: committed inbox bindings target windows crate \
             {expected}, but the workspace has {actual}; regenerate the inbox bindings"
        );
    }
}
