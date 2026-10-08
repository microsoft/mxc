// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(target_os = "linux")]

#[path = "support/wxc_e2e_tests.rs"]
mod wxc_e2e_tests;
use serde_json::json;
use wxc_e2e_tests::{has_lxc_host, has_platform_exec, run_platform_config_value};

const CAP_NET_ADMIN: u64 = 1 << 12;
const CAP_NET_RAW: u64 = 1 << 13;

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

/// Read one decimal field out of the container's `/proc/self/status`.
fn status_number(status: &str, field: &str) -> u64 {
    status
        .lines()
        .find(|line| line.starts_with(field))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("the container reported no readable {field} line\n{status}"))
}

#[test]
fn workload_cannot_reconfigure_or_bypass_the_network() {
    if !ready() {
        return;
    }

    // The confinement only happens when chains exist.  This policy asks for a
    // firewall to bring it on.
    let config = json!({
        "version": "0.9.0-alpha",
        "containerId": "lxc-network-capability",
        "containment": "lxc",
        "process": { "commandLine": "sh -c \"cat /proc/self/status\"" },
        "lifecycle": { "destroyOnExit": true },
        "lxc": { "distribution": "alpine", "release": "3.23" },
        "network": {
            "egress": {
                "default": "deny",
                "allow": [
                    {
                        "to": [{ "cidr": "140.82.112.0/20" }],
                        "ports": [{ "protocol": "tcp", "port": 443 }]
                    }
                ]
            }
        }
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

        assert_ne!(
            capability_mask(&status, field) & CAP_NET_RAW,
            0,
            "{field} lost CAP_NET_RAW; an explicit `protocol: \"icmp\"` allow needs a raw socket\n{status}"
        );
    }

    // 2 is SECCOMP_MODE_FILTER.  The kernel writes this line too.  A filter
    // cannot be lifted once it is attached, and this one fails
    // socket(AF_PACKET, ...) with EPERM.
    assert_eq!(
        status_number(&status, "Seccomp:"),
        2,
        "the workload runs with no seccomp filter; AF_PACKET reaches the interface below the chains\n{status}"
    );
}
