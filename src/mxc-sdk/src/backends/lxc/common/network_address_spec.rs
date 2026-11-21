// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::DHCP_EVENT_SCRIPT;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

#[path = "network_resolver_spec.rs"]
mod resolver;

fn run_callback(directory: &Path, event: &str, environment: &[(&str, &str)]) -> Output {
    let directory = directory
        .canonicalize()
        .expect("resolve DHCP callback fixture directory");
    let script = directory.join("dhcp-event.sh");
    let ip = directory.join("ip");
    fs::write(&script, DHCP_EVENT_SCRIPT).expect("write DHCP event callback");
    fs::write(
        &ip,
        r#"#!/bin/sh
printf '%s\t' "$@" >> "$IP_COMMANDS"
printf '\n' >> "$IP_COMMANDS"
exit 0
"#,
    )
    .expect("write fake ip executable");
    fs::set_permissions(&ip, fs::Permissions::from_mode(0o755)).expect("make fake ip executable");

    Command::new("/bin/sh")
        .arg(&script)
        .arg(event)
        .current_dir(&directory)
        .env_clear()
        .env("PATH", format!("{}:/usr/bin:/bin", directory.display()))
        .env("IP_COMMANDS", directory.join("ip-commands"))
        .envs([
            ("interface", "mxc-dhcp0"),
            ("ip", "10.0.3.15"),
            ("mask", "24"),
            ("lease", "120"),
            ("router", "10.0.3.1 10.0.3.2"),
            ("dns", ""),
            ("domain", ""),
            ("search", ""),
        ])
        .envs(environment.iter().copied())
        .output()
        .unwrap_or_else(|error| {
            panic!("run DHCP event={event:?}, environment={environment:?}: {error}")
        })
}

#[test]
fn bound_captures_address_prefix_and_first_gateway() {
    let root = tempfile::tempdir_in(".").expect("create DHCP callback fixture directory");
    let output = run_callback(root.path(), "bound", &[]);
    let address = fs::read_to_string(root.path().join("address")).expect("read captured address");
    let gateway = fs::read_to_string(root.path().join("gateway")).expect("read captured gateway");

    assert_eq!(
        (output.status.success(), address.as_str(), gateway.as_str()),
        (true, "10.0.3.15/24\n", "10.0.3.1\n"),
        "DHCP ip=10.0.3.15, mask=24, router='10.0.3.1 10.0.3.2' must capture \
         the address/prefix and first gateway; status={:?}, stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn bound_does_not_invoke_host_network_commands() {
    let root = tempfile::tempdir_in(".").expect("create DHCP callback fixture directory");
    let commands = root.path().join("ip-commands");
    fs::write(&commands, "").expect("initialize ip command log");
    let output = run_callback(
        root.path(),
        "bound",
        &[("dns", "192.0.2.53"), ("domain", "corp.example")],
    );
    let commands = fs::read_to_string(&commands).expect("read ip command log");

    assert_eq!(
        (output.status.success(), commands.as_str()),
        (true, ""),
        "DHCP bound ip=10.0.3.15, mask=24, router='10.0.3.1 10.0.3.2', \
         dns=192.0.2.53, domain=corp.example must capture without invoking ip; \
         status={:?}, stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn missing_required_lease_data_cannot_retain_ready_address() {
    for missing in ["ip", "mask", "router"] {
        let root = tempfile::tempdir_in(".").expect("create DHCP callback fixture directory");
        let address = root.path().join("address");
        fs::write(&address, "10.0.3.14/24\n").expect("write stale ready address");
        let output = run_callback(root.path(), "bound", &[(missing, "")]);

        assert_eq!(
            (output.status.success(), address.exists()),
            (false, false),
            "DHCP bound with {missing} empty must fail without retaining stale \
             address=10.0.3.14/24 readiness; status={:?}, stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn withdrawn_lease_removes_only_captured_artifacts() {
    for event in ["deconfig", "nak", "leasefail"] {
        let root = tempfile::tempdir_in(".").expect("create DHCP callback fixture directory");
        let address = root.path().join("address");
        let gateway = root.path().join("gateway");
        let resolver = root.path().join("resolv.conf");
        let commands = root.path().join("ip-commands");
        fs::write(&address, "10.0.3.15/24\n").expect("write ready address");
        fs::write(&gateway, "10.0.3.1\n").expect("write captured gateway");
        fs::write(&resolver, "nameserver 192.0.2.53\n").expect("write leased resolver");
        fs::write(&commands, "").expect("initialize ip command log");
        let output = run_callback(root.path(), event, &[]);
        let commands = fs::read_to_string(&commands).expect("read ip command log");

        assert_eq!(
            (
                output.status.success(),
                address.exists(),
                gateway.exists(),
                resolver.exists(),
                commands.as_str(),
            ),
            (true, false, false, false, ""),
            "DHCP event={event:?} must remove address=10.0.3.15/24, gateway=10.0.3.1, \
             and the resolver without invoking host-network commands; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
