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

/// Read one capability set out of `/proc/self/status`.
///
/// The kernel writes each set as a 64-bit hex mask on its own line.
fn capability_bits(status: &str, field: &str) -> u64 {
    let line = status
        .lines()
        .find(|line| line.starts_with(field))
        .unwrap_or_else(|| panic!("the container reported no {field} line\n{status}"));
    let mask = line[field.len()..].trim();
    u64::from_str_radix(mask, 16)
        .unwrap_or_else(|error| panic!("{field} is not a hex mask: {error}\n{line}"))
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
    assert_eq!(
        capability_bits(&status, "CapEff:") & CAP_NET_ADMIN,
        0,
        "the workload holds CAP_NET_ADMIN and can rewrite the firewall confining it\n{status}"
    );
    assert_eq!(
        capability_bits(&status, "CapBnd:") & CAP_NET_ADMIN,
        0,
        "the workload can regain CAP_NET_ADMIN through a setuid binary\n{status}"
    );
}
