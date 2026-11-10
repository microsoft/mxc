// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(target_os = "linux")]

#[path = "support/wxc_e2e_tests.rs"]
mod wxc_e2e_tests;
use serde_json::json;
use std::fs;
use std::process::Command;
use wxc_e2e_tests::{has_lxc_host, has_platform_exec, run_platform_config_value};

const CAP_NET_ADMIN: u64 = 1 << 12;
const CAP_NET_RAW: u64 = 1 << 13;

struct ContainerCleanup(String);

impl Drop for ContainerCleanup {
    fn drop(&mut self) {
        let config = json!({
            "version": "1.0.0",
            "containerId": &self.0,
            "containment": "lxc",
            "process": { "commandLine": "true" },
            "lifecycle": { "destroyOnExit": true, "preservePolicy": false },
            "lxc": { "distribution": "alpine", "release": "3.23" },
            "network": { "egress": { "default": "allow" } }
        });
        let result = run_platform_config_value("lxc capability cleanup", &config, &[], None);
        if !std::thread::panicking() {
            assert_eq!(
                result.code,
                Some(0),
                "MXC could not destroy the capability test container\n{}",
                result.combined_output()
            );
        }
    }
}

fn assert_network_capabilities(status: &str) {
    let effective = status
        .lines()
        .find(|line| line.starts_with("CapEff:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|mask| u64::from_str_radix(mask, 16).ok())
        .unwrap_or_else(|| panic!("no readable effective capability mask\n{status}"));

    assert_eq!(
        effective & (CAP_NET_ADMIN | CAP_NET_RAW),
        CAP_NET_ADMIN | CAP_NET_RAW,
        "a filtered guest lost CAP_NET_ADMIN or CAP_NET_RAW\n{status}"
    );
}

#[test]
fn filtered_guests_retain_network_administration_across_reuse() {
    if !has_platform_exec() || !has_lxc_host() {
        return;
    }

    let container = ContainerCleanup(format!("lxc-network-capability-{}", std::process::id()));
    for command in [
        "sh -c 'touch /mxc-capability-reuse; cat /proc/self/status'",
        "sh -c 'test -f /mxc-capability-reuse && cat /proc/self/status'",
    ] {
        let config = json!({
            "version": "1.0.0",
            "containerId": &container.0,
            "containment": "lxc",
            "process": { "commandLine": command },
            "lifecycle": { "destroyOnExit": false, "preservePolicy": true },
            "lxc": { "distribution": "alpine", "release": "3.23" },
            "network": {
                "egress": {
                    "default": "allow",
                    "deny": [{ "to": [{ "cidr": "198.51.100.2/32" }] }]
                }
            }
        });
        let result = run_platform_config_value("lxc container capabilities", &config, &[], None);
        assert_eq!(
            result.code,
            Some(0),
            "MXC could not create or reuse the filtered container\n{}",
            result.combined_output()
        );
        assert_network_capabilities(&result.combined_output());

        let init = Command::new("lxc-info")
            .args(["-n", &container.0, "-p", "-H"])
            .output()
            .expect("query the container init PID");
        assert!(
            init.status.success(),
            "could not query the running init: {init:?}"
        );
        let pid: u32 = String::from_utf8_lossy(&init.stdout)
            .trim()
            .parse()
            .expect("lxc-info must report a running init PID");
        let status = fs::read_to_string(format!("/proc/{pid}/status"))
            .expect("read init status from the host");
        assert_network_capabilities(&status);

        let attachment = Command::new("lxc-attach")
            .args(["-n", &container.0, "--", "cat", "/proc/self/status"])
            .output()
            .expect("read an ordinary attachment's status");
        assert!(
            attachment.status.success(),
            "an ordinary attachment could not read its status\n{}",
            String::from_utf8_lossy(&attachment.stderr)
        );
        assert_network_capabilities(&String::from_utf8_lossy(&attachment.stdout));
    }
}
