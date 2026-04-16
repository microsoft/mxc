// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CLI integration tests.
//!
//! Invokes `npm test` in the `cli/` directory.
//! Skips gracefully when Node.js or the CLI build output is missing.

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent() // src/
        .and_then(|p| p.parent()) // repo root
        .expect("could not determine repo root")
        .to_path_buf()
}

fn node_available() -> bool {
    Command::new("node")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn npm_available() -> bool {
    Command::new("npm")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn test_cli() {
    if !node_available() {
        println!("SKIPPED: node not available");
        return;
    }
    if !npm_available() {
        println!("SKIPPED: npm not available");
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
