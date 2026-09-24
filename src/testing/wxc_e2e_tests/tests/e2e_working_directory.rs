// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use serde_json::json;
use wxc_e2e_tests::{has_platform_exec, run_platform_config_value};

#[test]
fn current_contract_rejects_relative_working_directory() {
    if !has_platform_exec() {
        return;
    }

    let command_line = if cfg!(target_os = "windows") {
        "cmd.exe /c echo unreachable"
    } else {
        "/bin/sh -c 'echo unreachable'"
    };
    let config = json!({
        "version": "0.9.0-alpha",
        "process": {
            "commandLine": command_line,
            "cwd": "relative/subdirectory"
        }
    });

    let output = run_platform_config_value("relative_working_directory", &config, &[], None);
    let combined = output.combined_output();

    assert!(
        output.code != Some(0),
        "relative cwd unexpectedly succeeded:\n{combined}"
    );
    assert!(
        combined.contains("process.cwd"),
        "rejection did not identify process.cwd:\n{combined}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn wslc_rejects_unmappable_working_directory_before_backend_startup() {
    if !has_platform_exec() {
        return;
    }

    let config = json!({
        "version": "0.9.0-alpha",
        "containment": "wslc",
        "process": {
            "commandLine": "echo unreachable",
            "cwd": "\\\\server\\share\\work"
        },
        "network": {
            "egress": { "default": "allow" },
            "ingress": {
                "default": "allow",
                "hostLoopback": "allow"
            }
        }
    });

    let output = run_platform_config_value("wslc_unmappable_working_directory", &config, &[], None);
    let combined = output.combined_output();

    assert!(
        output.code != Some(0),
        "unmappable WSLc cwd unexpectedly succeeded:\n{combined}"
    );
    assert!(
        combined.contains("process.cwd") && combined.contains("rooted local Windows drive path"),
        "rejection did not explain the WSLc cwd requirement:\n{combined}"
    );
    assert!(
        !combined.contains("[WSLC] Starting WSL Container runner"),
        "backend startup began before cwd rejection:\n{combined}"
    );
}
