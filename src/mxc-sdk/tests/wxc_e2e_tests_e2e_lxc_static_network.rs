// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(target_os = "linux")]

#[path = "support/wxc_e2e_tests.rs"]
mod wxc_e2e_tests;
use serde_json::json;
use std::fs;
use std::process::Command;
use wxc_e2e_tests::{has_lxc_host, has_platform_exec, run_platform_config_value};

#[test]
fn existing_containers_keep_their_static_network_configuration() {
    if !has_platform_exec() || !has_lxc_host() {
        return;
    }

    for (family, ipv4) in [("dual", true), ("ipv6", false)] {
        let name = format!("lxc-static-{family}-{}", std::process::id());
        let bridge = format!("mx{family}{}", std::process::id());
        let outcome = std::panic::catch_unwind(|| {
            let created = Command::new("lxc-create")
                .args([
                    "-n", &name, "-t", "download", "--", "-d", "alpine", "-r", "3.23", "-a",
                    "amd64",
                ])
                .output()
                .expect("create existing static-network container");
            assert!(
                created.status.success(),
                "static-network container creation failed: {created:?}"
            );
            let created = Command::new("ip")
                .args(["link", "add", &bridge, "type", "bridge"])
                .output()
                .expect("create custom bridge");
            assert!(
                created.status.success(),
                "custom bridge creation failed: {created:?}"
            );
            let activated = Command::new("ip")
                .args(["link", "set", &bridge, "up"])
                .output()
                .expect("activate custom bridge");
            assert!(
                activated.status.success(),
                "custom bridge activation failed: {activated:?}"
            );

            let definition = format!("/var/lib/lxc/{name}/config");
            let mut contents = fs::read_to_string(&definition).expect("read existing definition");
            contents.push_str(&format!(
                "\nlxc.net.0.link = {bridge}\n\
                 lxc.net.0.name = eth0\n\
                 lxc.net.0.ipv4.address =\n\
                 lxc.net.0.ipv4.gateway =\n\
                 lxc.net.0.ipv6.address =\n\
                 lxc.net.0.ipv6.gateway =\n\
                 lxc.net.0.ipv6.address = 2001:db8:1688::2/64\n\
                 lxc.net.0.ipv6.gateway = 2001:db8:1688::1\n"
            ));
            if ipv4 {
                contents.push_str(
                    "lxc.net.0.ipv4.address = 192.0.2.2/24\n\
                     lxc.net.0.ipv4.address = 192.0.2.3/24\n\
                     lxc.net.0.ipv4.gateway = 192.0.2.1\n",
                );
            }
            fs::write(&definition, contents).expect("configure existing static network");
            fs::write(
                format!("/var/lib/lxc/{name}/rootfs/etc/network/interfaces"),
                "auto lo\niface lo inet loopback\n",
            )
            .expect("leave static eth0 configuration to LXC instead of guest DHCP");
            let resolver = format!("/var/lib/lxc/{name}/rootfs/etc/resolv.conf");
            fs::remove_file(&resolver).expect("remove original resolver or symlink");
            fs::write(&resolver, "nameserver 2001:db8:1688::53\n").expect("write static resolver");
            let config = json!({
                "version": "0.9.0-alpha",
                "containerId": name,
                "containment": "lxc",
                "process": {
                    "commandLine": "sh -c 'ip address show dev eth0 && ip -4 route show default && ip -6 route show default && cat /etc/resolv.conf'"
                },
                "lifecycle": { "destroyOnExit": false },
                "lxc": { "distribution": "alpine", "release": "3.23" },
                "network": { "egress": { "default": "allow" } }
            });
            let result =
                run_platform_config_value("existing LXC static network", &config, &[], None);
            let output = result.combined_output();

            let mut expected = vec![
                "inet6 2001:db8:1688::2/64",
                "default via 2001:db8:1688::1",
                "nameserver 2001:db8:1688::53",
            ];
            if ipv4 {
                expected.extend([
                    "inet 192.0.2.2/24",
                    "inet 192.0.2.3/24",
                    "default via 192.0.2.1",
                ]);
            }
            assert!(
                result.code == Some(0)
                    && expected.iter().all(|value| output.contains(value))
                    && (ipv4 || !output.contains("inet ")),
                "{family} static networking lost its configured addresses, gateways, or resolver\n{output}"
            );
        });
        let destroyed = Command::new("lxc-destroy")
            .args(["-n", &name, "-f"])
            .output();
        let removed = Command::new("ip")
            .args(["link", "delete", &bridge])
            .output();
        outcome.expect("existing static-network fixture failed");
        assert!(
            destroyed
                .as_ref()
                .is_ok_and(|output| output.status.success())
                && removed.as_ref().is_ok_and(|output| output.status.success()),
            "static-network fixture cleanup failed: container={destroyed:?}, bridge={removed:?}"
        );
    }
}
