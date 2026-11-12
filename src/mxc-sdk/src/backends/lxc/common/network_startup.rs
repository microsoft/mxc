// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::path::{Path, PathBuf};

use crate::mxc_common::{logger::Logger, models::ContainerPolicy};

use super::{
    lxc_bindings::LxcContainer,
    network_address,
    network_ingress::IngressManager,
    network_iptables::{plan_network, FirewallRuleArgs, NetworkIptablesManager},
};

pub(crate) fn configure(
    container: &LxcContainer,
    policy: &ContainerPolicy,
    logger: &mut Logger,
) -> Result<Option<String>, String> {
    container.drop_network_capabilities()?;
    let mut entries = Vec::new();
    let (egress, ingress, resolver) = if plan_network(policy).omits_interface() {
        (
            FirewallRuleArgs::default(),
            FirewallRuleArgs::default(),
            None,
        )
    } else {
        let egress = NetworkIptablesManager::startup_rules(container.name(), policy, logger)?;
        let ingress = IngressManager::startup_rules(container.name(), policy)?;
        let bridge = container.config_value("lxc.net.0.link")?;
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
        let mounts = container.config_value("lxc.mount.entry")?;
        let fstab = container.config_value("lxc.mount.fstab")?;
        let configure_resolver = !resolver_is_mounted(&mounts, &fstab)?;
        let (address, gateway, resolver) =
            network_address::reserve(container.name(), &mac, &bridge, configure_resolver)?;
        entries.extend([
            "lxc.net.0.ipv4.address =".into(),
            format!("lxc.net.0.ipv4.address = {address}"),
            format!("lxc.net.0.ipv4.gateway = {gateway}"),
        ]);
        (egress, ingress, resolver)
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

    let status_path = directory.join("installed");
    match std::fs::remove_file(&status_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("Failed to clear LXC network hook result: {error}")),
    }
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
    Ok(resolver)
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

pub(crate) fn configure_resolver(container: &LxcContainer, resolver: &str) -> Result<(), String> {
    let command = format!(
        "set -eu; if [ -L /etc/resolv.conf ]; then rm /etc/resolv.conf; fi; \
         printf '%s' {} > /etc/resolv.conf; chmod 644 /etc/resolv.conf",
        quote_shell_arg(resolver)
    );
    let (code, _, stderr) = container.attach_capture(
        &command,
        "/",
        &[],
        true,
        Some(std::time::Duration::from_secs(10)),
    )?;
    if code != 0 {
        return Err(format!(
            "Failed to configure container DNS: {}",
            stderr.trim()
        ));
    }
    Ok(())
}

fn hook_directory(container: &LxcContainer) -> PathBuf {
    Path::new(&container.config_file_path())
        .parent()
        .expect("container config has a parent directory")
        .join(".mxc-network")
}

fn quote_shell_arg(value: &str) -> String {
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

ipv6=0
"#,
    );
    if !egress_v4.is_empty() || !ingress_v4.is_empty() {
        script.push_str(
            r#"
# Keep host credentials for the host's xtables lock file.
run() { nsenter -t "$LXC_PID" -n -- "$@"; }

# Refuse an IPv4-only firewall when the namespace can carry IPv6.
if run ip6tables -S >/dev/null 2>&1; then
    ipv6=1
elif [ -e "/proc/$LXC_PID/net/if_inet6" ] || [ ! -r "/proc/$LXC_PID/net" ]; then
    echo 'Cannot install the IPv6 firewall before container init' >&2
    exit 1
fi

"#,
        );
        append_rules(&mut script, "iptables", egress_v4);
        append_rules(&mut script, "iptables", ingress_v4);
        script.push_str("if [ \"$ipv6\" = 1 ]; then\n");
        append_rules(&mut script, "ip6tables", egress_v6);
        append_rules(&mut script, "ip6tables", ingress_v6);
        script.push_str("fi\n");
    }
    script.push_str(&format!(
        "\nprintf '%s\\n' \"$ipv6\" > {}\n",
        quote_shell_arg(&status_path.to_string_lossy())
    ));
    script
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn retained_fstab_mounts_preserve_the_resolver() {
        let root = tempfile::tempdir_in(".").expect("create mount fixture directory");
        let path = root.path().join("fstab");

        for target in ["etc", "/etc", "etc/resolv.conf", "/etc/resolv.conf"] {
            let fstab = format!("/host/config {target} none bind 0 0\n");
            fs::write(&path, &fstab).expect("write retained mount table");

            assert_eq!(
                resolver_is_mounted("", path.to_str().expect("UTF-8 mount table path")),
                Ok(true),
                "a retained mount covering the resolver must prevent replacing it; fstab={fstab:?}"
            );
        }
    }

    #[test]
    fn unrelated_mounts_and_comments_do_not_preserve_the_resolver() {
        let root = tempfile::tempdir_in(".").expect("create mount fixture directory");
        let path = root.path().join("fstab");
        let fstab = concat!(
            "\n",
            "# /host/config etc none bind 0 0\n",
            "/host/assets opt/assets none bind 0 0\n",
            "/host/config etc-backup none bind 0 0\n",
        );
        fs::write(&path, fstab).expect("write unrelated and commented mounts");
        let entries = "/host/resolv.conf opt/resolv.conf none bind 0 0";

        assert_eq!(
            resolver_is_mounted(entries, path.to_str().expect("UTF-8 mount table path")),
            Ok(false),
            "only actual mount targets covering the resolver count; entries={entries:?}, fstab={fstab:?}"
        );
    }

    #[test]
    fn unreadable_retained_fstab_is_an_error() {
        let root = tempfile::tempdir_in(".").expect("create mount fixture directory");
        let path = root.path().join("missing-fstab");

        assert!(
            resolver_is_mounted("", path.to_str().expect("UTF-8 mount table path")).is_err(),
            "an unreadable retained mount table must not be treated as having no resolver mount; path={path:?}"
        );
    }
}
