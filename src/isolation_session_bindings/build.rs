// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script that verifies the workspace's `windows` crate version matches
//! the version the generated bindings were produced for.

fn main() {
    // Path to the generation provenance file.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let info_path = std::path::Path::new(&manifest_dir)
        .join("..")
        .join("..")
        .join("external")
        .join("windows-sdk")
        .join("isolation-environment-session")
        .join("GENERATION_INFO.toml");

    // If the provenance file doesn't exist yet (e.g., first-time setup before
    // generation has been run), skip the check.
    if !info_path.exists() {
        return;
    }

    let contents = std::fs::read_to_string(&info_path).unwrap_or_default();

    // Extract the expected windows crate version from the TOML.
    let expected = contents
        .lines()
        .find_map(|line| {
            let line = line.trim();
            if line.starts_with("target_windows_crate") {
                line.split('=').nth(1).map(|v| {
                    v.trim().trim_matches('"').to_string()
                })
            } else {
                None
            }
        });

    let Some(expected_version) = expected else {
        // No version constraint found — skip check.
        return;
    };

    // Read the actual windows crate version from Cargo.lock.
    let lock_path = std::path::Path::new(&manifest_dir)
        .join("..")
        .join("Cargo.lock");

    if !lock_path.exists() {
        return;
    }

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

    if let Some(actual) = actual_version {
        if !actual.starts_with(&expected_version) {
            panic!(
                "\n\n\
                 isolation_session_bindings: generated code targets windows crate {expected},\n\
                 but workspace has {actual}. Regenerate bindings:\n\
                 \n\
                 cargo run --manifest-path tools/generate-isolation-session-bindings/Cargo.toml -- <winmd-path>\n\
                 \n",
                expected = expected_version,
                actual = actual,
            );
        }
    }
}
