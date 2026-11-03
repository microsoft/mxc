// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(target_os = "linux")]

#[path = "support/wxc_e2e_tests.rs"]
mod wxc_e2e_tests;
use serde_json::json;
use std::path::Path;
use std::process::Command;
use wxc_e2e_tests::{
    has_lxc_host, has_platform_exec, run_executable, run_platform_config_value, TempDirs,
};

const CAP_NET_ADMIN: u64 = 1 << 12;
const CAP_NET_RAW: u64 = 1 << 13;
const NETWORK_CAPABILITIES: u64 = CAP_NET_ADMIN | CAP_NET_RAW;

/// Whether the LXC capability prerequisites are present.
fn ready() -> bool {
    if !has_platform_exec() || !has_lxc_host() {
        return false;
    }

    // SAFETY: `geteuid` is a thread-safe, side-effect-free libc call.
    if unsafe { libc::geteuid() } != 0 {
        let reason = "LXC network capability tests require root";
        if std::env::var("MXC_LXC_TESTS_REQUIRE_EXECUTION").is_ok_and(|value| value != "0") {
            panic!("strict mode: {reason}");
        }
        println!("SKIPPED: {reason}");
        return false;
    }
    true
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
fn workload_holds_neither_network_capability() {
    if !ready() {
        return;
    }

    let config = json!({
        "version": "0.9.0-alpha",
        "containerId": "lxc-network-capability",
        "containment": "lxc",
        "process": { "commandLine": "sh -c \"cat /proc/self/status\"" },
        "lifecycle": { "destroyOnExit": true },
        "lxc": { "distribution": "alpine", "release": "3.23" },

        // An allow rule puts the workload behind the firewall.
        "network": {
            "egress": {
                "default": "deny",
                "allow": [{ "to": [{ "cidr": "198.51.100.2/32" }] }]
            }
        }
    });

    let result = run_platform_config_value("lxc network capability", &config, &[], None);
    let status = result.combined_output();

    let held = capability_mask(&status, "CapEff:") | capability_mask(&status, "CapPrm:");

    assert_eq!(
        held & NETWORK_CAPABILITIES,
        0,
        "the workload still holds CAP_NET_ADMIN or CAP_NET_RAW\n{status}"
    );
}

#[test]
fn workload_cannot_regain_a_network_capability() {
    if !ready() {
        return;
    }

    let config = json!({
        "version": "0.9.0-alpha",
        "containerId": "lxc-capability-regain",
        "containment": "lxc",
        "process": { "commandLine": "sh -c \"cat /proc/self/status\"" },
        "lifecycle": { "destroyOnExit": true },
        "lxc": { "distribution": "alpine", "release": "3.23" },
        "network": {
            "egress": {
                "default": "deny",
                "allow": [{ "to": [{ "cidr": "198.51.100.2/32" }] }]
            }
        }
    });

    let result = run_platform_config_value("lxc capability regain", &config, &[], None);
    let status = result.combined_output();

    // An exec can only grant a capability that is in one of these sets.
    // https://man7.org/linux/man-pages/man7/capabilities.7.html
    let regainable = capability_mask(&status, "CapBnd:")
        | capability_mask(&status, "CapInh:")
        | capability_mask(&status, "CapAmb:");

    assert_eq!(
        regainable & NETWORK_CAPABILITIES,
        0,
        "an exec could hand the workload CAP_NET_ADMIN or CAP_NET_RAW back\n{status}"
    );
}

#[test]
fn workload_can_still_ping() {
    if !ready() {
        return;
    }

    let config = json!({
        "version": "0.9.0-alpha",
        "containerId": "lxc-ping-allowed",
        "containment": "lxc",
        "process": { "commandLine": "ping -c 1 127.0.0.1" },
        "lifecycle": { "destroyOnExit": true },
        "lxc": { "distribution": "ubuntu", "release": "noble" },
        "network": {
            "egress": {
                "default": "deny",
                "allow": [{ "to": [{ "cidr": "198.51.100.2/32" }] }]
            }
        }
    });

    let result = run_platform_config_value("lxc ping allowed", &config, &[], None);

    assert_eq!(
        result.code,
        Some(0),
        "the workload could not ping after the capability drop\n{}",
        result.combined_output()
    );
}

#[test]
fn workload_cannot_open_a_raw_or_packet_socket() {
    if !ready() {
        return;
    }

    const CONTAINER_ID: &str = "lxc-raw-socket-refusal";

    struct ContainerCleanup;

    impl Drop for ContainerCleanup {
        fn drop(&mut self) {
            if !Path::new("/var/lib/lxc").join(CONTAINER_ID).exists() {
                return;
            }

            let result = Command::new("lxc-destroy")
                .args(["--name", CONTAINER_ID, "--force"])
                .status();
            if !matches!(result, Ok(status) if status.success()) {
                if std::thread::panicking() {
                    eprintln!("failed to destroy test container {CONTAINER_ID}: {result:?}");
                } else {
                    panic!("failed to destroy test container {CONTAINER_ID}: {result:?}");
                }
            }
        }
    }

    assert!(
        !Path::new("/var/lib/lxc").join(CONTAINER_ID).exists(),
        "test container {CONTAINER_ID} already exists"
    );
    let _setup = TempDirs::create(&["lxc-raw-socket-refusal-setup"]);
    let setup_config = Path::new("lxc-raw-socket-refusal-setup").join("config");
    std::fs::write(
        &setup_config,
        concat!(
            "lxc.net.0.type = veth\n",
            "lxc.net.0.link = lxcbr0\n",
            "lxc.net.0.flags = up\n",
            "lxc.idmap = u 0 200000 65536\n",
            "lxc.idmap = g 0 200000 65536\n",
        ),
    )
    .expect("write the mapped container configuration");

    let architecture = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        architecture => architecture,
    };
    let _container = ContainerCleanup;
    let created = run_executable(
        "create mapped raw socket container",
        Path::new("lxc-create"),
        [
            "--name",
            CONTAINER_ID,
            "--config",
            setup_config.to_str().expect("UTF-8 setup path"),
            "--template",
            "download",
            "--",
            "--dist",
            "ubuntu",
            "--release",
            "noble",
            "--arch",
            architecture,
        ],
    );
    assert_eq!(
        created.code,
        Some(0),
        "could not create the mapped raw socket container\n{}",
        created.combined_output()
    );

    let probe = format!(
        "python3 -c 'print(\"uid_map\", *open(\"/proc/self/uid_map\").read().split())\n\
         print(\"gid_map\", *open(\"/proc/self/gid_map\").read().split())\n{}'",
        include_str!("support/raw_socket_probe.py")
    );

    // Use Ubuntu for python3.
    let config = json!({
        "version": "0.9.0-alpha",
        "containerId": CONTAINER_ID,
        "containment": "lxc",
        "process": { "commandLine": probe },
        "lifecycle": { "destroyOnExit": true },
        "lxc": { "distribution": "ubuntu", "release": "noble" },
        "network": {
            "egress": {
                "default": "deny",
                "allow": [{ "to": [{ "cidr": "198.51.100.2/32" }] }]
            }
        }
    });

    let result = run_platform_config_value("lxc raw socket refusal", &config, &[], None);
    let output = result.combined_output();

    assert!(
        output.lines().any(|line| line
            .split_whitespace()
            .eq(["uid_map", "0", "200000", "65536"]))
            && output.lines().any(|line| line
                .split_whitespace()
                .eq(["gid_map", "0", "200000", "65536"])),
        "the workload did not run with the required nonzero host root mappings\n{output}"
    );
    assert!(
        output.contains("raw EPERM") && output.contains("packet EPERM"),
        "the workload opened a raw or packet socket the capability drop must refuse\n{output}"
    );
}
