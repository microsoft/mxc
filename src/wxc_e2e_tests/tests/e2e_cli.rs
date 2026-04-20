// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CLI integration tests.
//!
//! Invokes `npm test` in the `cli/` directory.
//! Skips gracefully when Node.js or the CLI build output is missing.

use std::process::Command;

use wxc_e2e_tests::{has_node, has_npm, repo_root};

#[test]
fn test_cli() {
    if !has_node() {
        return;
    }
    if !has_npm() {
        return;
    }

    let cli_dir = repo_root().join("cli");
    let dist_dir = cli_dir.join("dist");

    if !dist_dir.exists() {
        println!("SKIPPED: cli/dist/ not found — run 'npm run build' in cli/ first");
        return;
    }

    let output = Command::new("npm")
        .arg("test")
        .current_dir(&cli_dir)
        .output()
        .expect("failed to execute npm test in cli/");

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!(
            "CLI npm test failed with exit code {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            output.status.code(),
            stdout,
            stderr
        );
    }
}
