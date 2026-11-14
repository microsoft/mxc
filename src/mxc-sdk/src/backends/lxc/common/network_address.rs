// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command;

use super::lxc_bindings::LxcContainer;

const DHCP_EVENT_SCRIPT: &str = include_str!("dhcp-event.sh");
const RESERVATION_SCRIPT: &str = include_str!("reserve-address.sh");

pub(crate) fn reserve(container: &LxcContainer, directory: &Path) -> Result<Vec<String>, String> {
    if container.config_value("lxc.net.0.type")? != "veth" {
        return Err("Networked LXC requires a veth interface on the local lxc-net bridge".into());
    }
    let bridge = container.config_value("lxc.net.0.link")?;
    let mac = container.config_value("lxc.net.0.hwaddr")?;
    let callback = directory.join("dhcp-event.sh");
    std::fs::write(&callback, DHCP_EVENT_SCRIPT)
        .map_err(|error| format!("Failed to write LXC DHCP callback: {error}"))?;

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&callback, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("Failed to protect LXC DHCP callback: {error}"))?;
    }

    let mut command = reservation_command(container, "reserve");
    command.arg(directory).arg(&bridge).arg(&mac);
    let output = command
        .output()
        .map_err(|error| format!("Failed to reserve LXC address: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "Failed to reserve LXC address: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let address = std::fs::read_to_string(directory.join("address"))
        .map_err(|error| format!("Failed to read acquired LXC address: {error}"))?;
    let (ip, prefix) = address
        .trim()
        .split_once('/')
        .ok_or("DHCP did not provide an LXC IPv4 address and prefix")?;
    let ip = ip
        .parse::<Ipv4Addr>()
        .map_err(|error| format!("DHCP provided an invalid LXC IPv4 address: {error}"))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|error| format!("DHCP provided an invalid LXC IPv4 prefix: {error}"))?;
    if !(1..=32).contains(&prefix) {
        return Err("DHCP provided an LXC IPv4 prefix outside 1..=32".into());
    }
    let gateway = std::fs::read_to_string(directory.join("gateway"))
        .map_err(|error| format!("Failed to read acquired LXC gateway: {error}"))?;
    let gateway = gateway
        .trim()
        .parse::<Ipv4Addr>()
        .map_err(|error| format!("DHCP provided an invalid LXC IPv4 gateway: {error}"))?;
    for (name, value) in [("address", ip), ("gateway", gateway)] {
        if value.is_unspecified()
            || value.is_loopback()
            || value.is_multicast()
            || value.is_broadcast()
        {
            return Err(format!(
                "DHCP provided an unusable LXC IPv4 {name}: {value}"
            ));
        }
    }

    let mask = u32::MAX << (32 - prefix);
    if ip == gateway || u32::from(ip) & mask != u32::from(gateway) & mask {
        return Err("DHCP provided an LXC gateway outside the acquired address's subnet".into());
    }
    if prefix < 31 {
        for value in [ip, gateway] {
            let host = u32::from(value) & !mask;
            if host == 0 || host == !mask {
                return Err(format!("DHCP provided an unusable LXC IPv4 host: {value}"));
            }
        }
    }

    Ok(vec![
        "lxc.net.0.ipv4.address =".into(),
        "lxc.net.0.ipv4.gateway =".into(),
        format!("lxc.net.0.ipv4.address = {ip}/{prefix}"),
        format!("lxc.net.0.ipv4.gateway = {gateway}"),
    ])
}

pub(crate) fn release(container: &LxcContainer) -> Result<(), String> {
    let output = reservation_command(container, "release")
        .output()
        .map_err(|error| format!("Failed to release LXC address reservation: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "Failed to release LXC address reservation: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(())
}

fn reservation_command(container: &LxcContainer, action: &str) -> Command {
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", RESERVATION_SCRIPT, "mxc-lxc-address", action])
        .arg(container.config_file_path())
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    command
}

#[cfg(all(test, target_os = "linux"))]
#[path = "network_address_spec.rs"]
mod tests;
