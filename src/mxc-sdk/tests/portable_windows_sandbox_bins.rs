// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(not(target_os = "windows"))]

use std::process::Command;

#[test]
fn windows_sandbox_binaries_reject_unsupported_hosts() {
    for (name, executable) in [
        (
            "wxc-windows-sandbox-daemon",
            env!("CARGO_BIN_EXE_wxc-windows-sandbox-daemon"),
        ),
        (
            "wxc-windows-sandbox-guest",
            env!("CARGO_BIN_EXE_wxc-windows-sandbox-guest"),
        ),
    ] {
        let output = Command::new(executable)
            .output()
            .unwrap_or_else(|error| panic!("failed to run {name}: {error}"));

        assert_eq!(
            output.status.code(),
            Some(64),
            "{name} unexpectedly succeeded"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("Windows-only"),
            "{name} did not explain the unsupported host"
        );
    }
}
