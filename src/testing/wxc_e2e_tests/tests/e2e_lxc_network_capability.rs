// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(target_os = "linux")]

use serde_json::json;
use wxc_e2e_tests::{has_lxc_host, has_platform_exec, run_platform_config_value};

const CAP_NET_ADMIN: u64 = 1 << 12;

/// Whether the LXC capability prerequisites are present.
fn ready() -> bool {
    has_platform_exec() && has_lxc_host()
}

/// Read one capability mask out of the container's `/proc/self/status`.
fn capability_mask(status: &str, field: &str) -> u64 {
    status
        .lines()
        .find(|line| line.starts_with(field))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|mask| u64::from_str_radix(mask, 16).ok())
        .unwrap_or_else(|| panic!("the container reported no readable {field} line\n{status}"))
}

#[test]
fn workload_cannot_reconfigure_the_network() {
    if !ready() {
        return;
    }

    let config = json!({
        "version": "0.8.0-alpha",
        "containerId": "lxc-network-capability",
        "containment": "lxc",
        "process": { "commandLine": "sh -c \"cat /proc/self/status\"" },
        "lifecycle": { "destroyOnExit": true },
        "lxc": { "distribution": "alpine", "release": "3.23" }
    });

    let result = run_platform_config_value("lxc network capability", &config, &[], None);
    let status = result.combined_output();

    assert_eq!(
        result.code,
        Some(0),
        "lxc-exec did not run the container\n--- stderr ---\n{}",
        result.stderr
    );

    // The kernel writes these masks; the workload cannot forge them.  Effective
    // alone would not settle it: a process raises a permitted capability into
    // its effective set whenever it likes, and only a bounding-set drop
    // survives execve.
    for field in ["CapEff:", "CapPrm:", "CapBnd:"] {
        assert_eq!(
            capability_mask(&status, field) & CAP_NET_ADMIN,
            0,
            "{field} still carries CAP_NET_ADMIN; the workload can rewrite the firewall confining it\n{status}"
        );
    }
}
