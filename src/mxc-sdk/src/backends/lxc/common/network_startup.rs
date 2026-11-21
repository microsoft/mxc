// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::path::{Path, PathBuf};

use crate::mxc_common::{logger::Logger, models::ContainerPolicy};

use super::{
    lxc_bindings::LxcContainer,
    network_address,
    network_ingress::IngressManager,
    network_iptables::{plan_network, EgressHookPoint, FirewallRuleArgs, NetworkIptablesManager},
};

#[cfg(test)]
#[path = "network_startup_spec.rs"]
mod tests;

pub(crate) fn configure(
    container: &LxcContainer,
    policy: &ContainerPolicy,
    logger: &mut Logger,
) -> Result<Option<PathBuf>, String> {
    container.drop_network_capabilities()?;
    container.set_network_startup_config(&[])?;
    let mut entries = Vec::new();
    let plan = plan_network(policy);
    let reserve_address = if plan.omits_interface() {
        false
    } else {
        let ipv4_addresses = container.config_value("lxc.net.0.ipv4.address")?;
        let ipv6_addresses = container.config_value("lxc.net.0.ipv6.address")?;
        ipv4_addresses.is_empty() && ipv6_addresses.is_empty()
    };

    let (egress, ingress, configure_resolver) = if plan.omits_interface() {
        (
            FirewallRuleArgs::default(),
            FirewallRuleArgs::default(),
            false,
        )
    } else {
        let mut egress = NetworkIptablesManager::startup_rules(container.name(), policy, logger)?;
        let mut ingress = IngressManager::startup_rules(container.name(), policy)?;
        let firewall = NetworkIptablesManager::new(container.name(), EgressHookPoint::Unhooked);

        if !firewall.ip6tables_probe_succeeded(logger) {
            // Opening an IPv6 socket also requests an unloaded IPv6 kernel module.
            let ipv6_disabled =
                match std::net::UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, 0)) {
                    #[cfg(target_os = "linux")]
                    Err(error) => error.raw_os_error() == Some(libc::EAFNOSUPPORT),
                    _ => false,
                };

            if !ipv6_disabled {
                return Err(
                    "Cannot start a networked container without a working IPv6 firewall".into(),
                );
            }

            egress.ipv6.clear();
            ingress.ipv6.clear();
        }

        let mut mac = container.config_value("lxc.net.0.hwaddr")?;
        if mac.is_empty() {
            let mut octets = [0u8; 6];
            getrandom::getrandom(&mut octets)
                .map_err(|error| format!("Failed to generate LXC hardware address: {error}"))?;

            // Use a locally administered unicast address.
            octets[0] = (octets[0] & 0xfc) | 0x02;
            mac = octets
                .iter()
                .map(|octet| format!("{octet:02x}"))
                .collect::<Vec<_>>()
                .join(":");
        }

        container.set_network_mac_address(&mac)?;
        let configure_resolver = if reserve_address {
            let mounts = container.config_value("lxc.mount.entry")?;
            let fstab = container.config_value("lxc.mount.fstab")?;
            !resolver_is_mounted(&mounts, &fstab)?
        } else {
            false
        };
        (egress, ingress, configure_resolver)
    };

    let directory = hook_directory(container);
    std::fs::create_dir_all(&directory)
        .map_err(|error| format!("Failed to create LXC network hook directory: {error}"))?;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("Failed to protect LXC network hook directory: {error}"))?;
    }

    for name in ["installed", "address", "gateway", "lease", "resolv.conf"] {
        match std::fs::remove_file(directory.join(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("Failed to clear LXC network hook result: {error}")),
        }
    }

    if reserve_address {
        entries.extend(network_address::reserve(container, &directory)?);
    }

    let status_path = directory.join("installed");
    let script_path = directory.join("start-host.sh");
    let script = build_start_host_script(
        &egress.ipv4,
        &egress.ipv6,
        &ingress.ipv4,
        &ingress.ipv6,
        &status_path,
    );
    std::fs::write(&script_path, script)
        .map_err(|error| format!("Failed to write LXC network hook: {error}"))?;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("Failed to make LXC network hook executable: {error}"))?;
    }

    entries.push(format!(
        "lxc.hook.start-host = \"{}\"",
        quote_shell_arg(&script_path.to_string_lossy())
    ));
    container.set_network_startup_config(&entries)?;
    Ok(configure_resolver.then(|| directory.join("resolv.conf")))
}

fn resolver_is_mounted(entries: &str, fstab: &str) -> Result<bool, String> {
    let fstab_contents = if fstab.is_empty() {
        String::new()
    } else {
        std::fs::read_to_string(fstab)
            .map_err(|error| format!("Failed to read LXC mount list {fstab}: {error}"))?
    };

    Ok(entries
        .lines()
        .chain(fstab_contents.lines())
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter_map(|line| line.split_whitespace().nth(1))
        .any(|target| {
            let target = target.trim_start_matches('/').trim_start_matches("./");
            target == "." || Path::new("etc/resolv.conf").starts_with(target)
        }))
}

pub(crate) fn installed_ipv6(container: &LxcContainer) -> Result<bool, String> {
    let status = std::fs::read_to_string(hook_directory(container).join("installed"))
        .map_err(|error| format!("LXC network start-host hook did not complete: {error}"))?;
    match status.trim() {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err("Invalid LXC network start-host hook result".into()),
    }
}

pub(crate) fn hook_directory(container: &LxcContainer) -> PathBuf {
    Path::new(&container.config_file_path())
        .parent()
        .expect("container config has a parent directory")
        .join(".mxc-network")
}

pub(crate) fn quote_shell_arg(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn append_rules(script: &mut String, binary: &str, rules: &[Vec<String>]) {
    for args in rules {
        script.push_str("run ");
        script.push_str(binary);
        for arg in args {
            script.push(' ');
            script.push_str(&quote_shell_arg(arg));
        }

        script.push('\n');
    }
}

fn build_start_host_script(
    egress_v4: &[Vec<String>],
    egress_v6: &[Vec<String>],
    ingress_v4: &[Vec<String>],
    ingress_v6: &[Vec<String>],
    status_path: &Path,
) -> String {
    let mut script = String::from(
        r#"#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
: "${LXC_PID:?LXC_PID is required}"

# Interpret group IDs in the container's user namespace without changing host mounts.
user_ns_args=
if ! [ "/proc/$LXC_PID/ns/user" -ef /proc/self/ns/user ]; then
    user_ns_args='-U --preserve-credentials --setuid 0 --setgid 0'
fi

# Limit datagram ping to the contiguous group mapping containing container root.
ping_groups=$(awk '$1 == 0 { end = $3 - 1; if (end > 2147483647) end = 2147483647; print "0 " end; found = 1; exit } END { if (!found) exit 1 }' "/proc/$LXC_PID/gid_map")
nsenter -t "$LXC_PID" $user_ns_args -n -- sysctl -q -w "net.ipv4.ping_group_range=$ping_groups"

"#,
    );

    if !egress_v4.is_empty()
        || !ingress_v4.is_empty()
        || !egress_v6.is_empty()
        || !ingress_v6.is_empty()
    {
        script.push_str(
            r#"
# Keep host credentials for the host's xtables lock file.
run() { nsenter -t "$LXC_PID" -n -- "$@"; }

"#,
        );
        append_rules(&mut script, "iptables", egress_v4);
        append_rules(&mut script, "iptables", ingress_v4);
        append_rules(&mut script, "ip6tables", egress_v6);
        append_rules(&mut script, "ip6tables", ingress_v6);
    }

    script.push_str(&format!(
        "\nprintf '%s\\n' '{}' > {}\n",
        u8::from(!egress_v6.is_empty() || !ingress_v6.is_empty()),
        quote_shell_arg(&status_path.to_string_lossy())
    ));
    script
}
