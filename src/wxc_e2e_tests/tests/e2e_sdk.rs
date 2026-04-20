// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! SDK integration tests.
//!
//! Invokes `npm test` in the `sdk/` directory.
//! Skips gracefully when Node.js or the SDK build output is missing.

use std::process::Command;

use wxc_e2e_tests::{has_node, has_npm, repo_root};

#[test]
fn test_sdk() {
    if !has_node() {
        return;
    }
    if !has_npm() {
        return;
    }

    let sdk_dir = repo_root().join("sdk");
    let dist_dir = sdk_dir.join("dist");

    if !dist_dir.exists() {
        println!("SKIPPED: sdk/dist/ not found — run 'npm run build' in sdk/ first");
        return;
    }

    let output = Command::new("npm")
        .arg("test")
        .current_dir(&sdk_dir)
        .output()
        .expect("failed to execute npm test in sdk/");

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!(
            "SDK npm test failed with exit code {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            output.status.code(),
            stdout,
            stderr
        );
    }
}
