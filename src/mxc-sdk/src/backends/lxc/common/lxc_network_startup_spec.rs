// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::LxcContainer;
use std::fs;

#[test]
fn removing_network_capabilities_preserves_existing_restrictions() {
    let cases: &[(&str, &str, &[&str])] = &[
        ("", "sys_module net_admin", &["lxc.cap.drop = net_raw"]),
        ("", "sys_module 13", &["lxc.cap.drop = net_admin"]),
        ("", "sys_module 12 net_raw", &[]),
        (
            "net_admin chown 13 setuid",
            "sys_module",
            &["lxc.cap.keep =", "lxc.cap.keep = chown setuid"],
        ),
        (
            "014 chown 012 015 0xC 0xD +12 +13 setuid",
            "sys_module",
            &["lxc.cap.keep =", "lxc.cap.keep = chown 012 setuid"],
        ),
        (
            "net_admin net_raw 12 13",
            "sys_module",
            &["lxc.cap.keep =", "lxc.cap.keep = none"],
        ),
        ("chown setuid", "sys_module", &[]),
    ];

    for &(keep, drop, expected) in cases {
        let entries = LxcContainer::format_network_capability_removal(keep, drop);

        assert_eq!(
            entries.lines().map(str::trim).collect::<Vec<_>>(),
            expected,
            "keep={keep:?}, drop={drop:?}"
        );
    }
}

#[test]
fn reusing_startup_configuration_replaces_only_the_managed_block() {
    let root = tempfile::tempdir_in(".").expect("create test directory");
    let container_directory = root.path().join("network-startup");
    fs::create_dir(&container_directory).expect("create container directory");
    let config_path = container_directory.join("config");
    let preserved = concat!(
        "lxc.include = /usr/share/lxc/config/common.conf\n",
        "lxc.hook.start-host = /foreign-start-host\n",
        "lxc.cap.drop = sys_module\n",
    );
    fs::write(&config_path, preserved).expect("write container configuration");
    let container = LxcContainer::new(
        "network-startup",
        Some(root.path().to_str().expect("UTF-8 test directory")),
    );
    container
        .set_network_startup_config(&["lxc.hook.start-host = /old-network-hook".to_owned()])
        .expect("write initial network startup configuration");
    let entries = [
        "lxc.net.0.ipv4.address = 198.51.100.10/24".to_owned(),
        "lxc.hook.start-host = /current-network-hook".to_owned(),
    ];
    container
        .set_network_startup_config(&entries)
        .expect("replace network startup configuration");
    let expected = format!(
        "{preserved}# BEGIN MXC network startup\n{}\n# END MXC network startup\n",
        entries.join("\n")
    );
    let config = fs::read_to_string(&config_path).expect("read container configuration");

    assert_eq!(
        config
            .lines()
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>(),
        expected.lines().collect::<Vec<_>>(),
        "startup entries {entries:?} must replace the managed block without changing other config"
    );
}

#[test]
fn saved_mac_survives_startup_replacement_and_clearing() {
    let root = tempfile::tempdir_in(".").expect("create test directory");
    let container_directory = root.path().join("network-mac");
    fs::create_dir(&container_directory).expect("create container directory");
    let config_path = container_directory.join("config");
    fs::write(
        &config_path,
        concat!(
            "lxc.include = /usr/share/lxc/config/common.conf\n",
            "lxc.net.0.type = veth\n",
        ),
    )
    .expect("write container configuration");
    let container = LxcContainer::new(
        "network-mac",
        Some(root.path().to_str().expect("UTF-8 test directory")),
    );
    let mac = "02:16:3e:00:ab:cd";
    container
        .set_network_mac_address(mac)
        .expect("save network MAC");
    container
        .set_network_mac_address(mac)
        .expect("save the same network MAC again");
    container
        .set_network_startup_config(&["lxc.net.0.ipv4.address = 198.51.100.10/24".to_owned()])
        .expect("write network startup configuration");
    container
        .set_network_startup_config(&["lxc.net.0.ipv4.address = 198.51.100.20/24".to_owned()])
        .expect("replace network startup configuration");
    container
        .set_network_startup_config(&[])
        .expect("clear network startup configuration");
    let config = fs::read_to_string(&config_path).expect("read container configuration");
    let mut entries = config
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect::<Vec<_>>();
    entries.sort_unstable();

    assert_eq!(
        entries,
        [
            "lxc.include = /usr/share/lxc/config/common.conf",
            "lxc.net.0.hwaddr = 02:16:3e:00:ab:cd",
            "lxc.net.0.type = veth",
        ],
        "MAC {mac} must remain saved exactly once after startup settings are cleared, with other config unchanged"
    );
}
