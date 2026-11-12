// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use std::fs;
use std::net::Ipv4Addr;

#[test]
fn metadata_and_ipv6_leases_preserve_neighboring_ipv4_owners() {
    let root = tempfile::tempdir_in(".").expect("create lease fixture directory");
    let path = root.path().join("leases");
    let leases = concat!(
        "1700000000 00:16:3e:00:00:11 10.0.3.11 alpha *\n",
        "duid 00:01:00:01:aa:bb:cc:dd\n",
        "vendorclass 00:16:3e:00:00:11 ubuntu\n",
        "agent-info 00:16:3e:00:00:11 circuit-id\n",
        "1700000000 12345 2001:db8::11 beta 00:01:00:01:aa:bb\n",
        "1700000000 00:16:3e:00:00:12 10.0.3.12 gamma *\n",
    );
    fs::write(&path, leases).expect("write mixed lease records");

    assert_eq!(
        read_leases(&path),
        Ok(std::collections::HashMap::from([
            (Ipv4Addr::new(10, 0, 3, 11), "00:16:3e:00:00:11".to_owned()),
            (Ipv4Addr::new(10, 0, 3, 12), "00:16:3e:00:00:12".to_owned()),
        ])),
        "metadata and IPv6 records must not hide IPv4 address owners; leases={leases:?}"
    );
}

#[test]
fn malformed_ipv4_leases_are_not_an_empty_allocation_snapshot() {
    let root = tempfile::tempdir_in(".").expect("create lease fixture directory");
    let path = root.path().join("leases");

    for lease in [
        "1700000000 00:16:3e:00:00:11 10.0.3.11 alpha\n",
        "1700000000 00:16:3e:00:00:11 10.0.3.999 alpha *\n",
    ] {
        fs::write(&path, lease).expect("write malformed IPv4 lease");

        assert!(
            read_leases(&path).is_err(),
            "malformed IPv4 data must fail instead of making occupied addresses available; lease={lease:?}"
        );
    }
}

#[test]
fn missing_optional_network_defaults_do_not_hide_the_global_dhcp_configuration() {
    let root = tempfile::tempdir_in(".").expect("create host configuration fixture directory");
    let directory = root
        .path()
        .canonicalize()
        .expect("resolve fixture directory");
    let conffile = directory.join("dhcp.conf");
    fs::write(&conffile, "").expect("write DHCP configuration");
    fs::write(
        directory.join("lxc"),
        format!("LXC_DHCP_CONFILE='{}'\n", conffile.display()),
    )
    .expect("write global LXC defaults");
    let source = format!(
        concat!(
            "distrosysconfdir='{}'\n",
            "varrun='{}'\n",
            "USE_LXC_BRIDGE=true\n",
            "LXC_BRIDGE=lxcbr0\n",
            "LXC_ADDR=10.0.3.1\n",
            "LXC_NETMASK=255.255.255.0\n",
            "LXC_NETWORK=10.0.3.0/24\n",
            "LXC_DHCP_RANGE=10.0.3.2,10.0.3.254\n",
            "LXC_DHCP_CONFILE=''\n",
            "[ ! -f \"$distrosysconfdir/lxc\" ] || . \"$distrosysconfdir/lxc\"\n",
        ),
        directory.display(),
        directory.join("run").display(),
    );

    assert_eq!(
        read_host_configuration(
            Some("lxcbr0"),
            (directory.join("lxc-net-service"), source)
        )
        .map(|configuration| configuration.path),
        Ok(conffile.clone()),
        "the global DHCP conffile must work without an optional lxc-net file; conffile={conffile:?}"
    );
}

#[test]
fn global_dhcp_override_wins_after_sourcing_network_defaults() {
    let root = tempfile::tempdir_in(".").expect("create host configuration fixture directory");
    let directory = root
        .path()
        .canonicalize()
        .expect("resolve fixture directory");
    let earlier_conffile = directory.join("earlier-dhcp.conf");
    let conffile = directory.join("dhcp.conf");
    fs::write(&earlier_conffile, "").expect("write earlier DHCP configuration");
    fs::write(&conffile, "").expect("write final DHCP configuration");
    fs::write(
        directory.join("lxc-net"),
        format!("LXC_DHCP_CONFILE='{}'\n", earlier_conffile.display()),
    )
    .expect("write optional network defaults");
    fs::write(
        directory.join("lxc"),
        format!(
            ". \"$distrosysconfdir/lxc-net\"\nLXC_DHCP_CONFILE='{}'\n",
            conffile.display()
        ),
    )
    .expect("write global defaults with the final DHCP override");
    let source = format!(
        concat!(
            "distrosysconfdir='{}'\n",
            "varrun='{}'\n",
            "USE_LXC_BRIDGE=true\n",
            "LXC_BRIDGE=lxcbr0\n",
            "LXC_ADDR=10.0.3.1\n",
            "LXC_NETMASK=255.255.255.0\n",
            "LXC_NETWORK=10.0.3.0/24\n",
            "LXC_DHCP_RANGE=10.0.3.2,10.0.3.254\n",
            "LXC_DHCP_CONFILE=''\n",
            "[ ! -f \"$distrosysconfdir/lxc\" ] || . \"$distrosysconfdir/lxc\"\n",
        ),
        directory.display(),
        directory.join("run").display(),
    );

    assert_eq!(
        read_host_configuration(
            Some("lxcbr0"),
            (directory.join("lxc-net-service"), source)
        )
        .map(|configuration| configuration.path),
        Ok(conffile.clone()),
        "sourcing lxc-net again must not replace the global file's final DHCP conffile; conffile={conffile:?}"
    );
}
