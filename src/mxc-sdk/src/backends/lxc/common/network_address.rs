// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(target_os = "linux")]
pub(crate) use linux::{release, reserve};

#[cfg(not(target_os = "linux"))]
pub(crate) fn reserve(
    _container_name: &str,
    _mac: &str,
    _bridge: &str,
    _configure_resolver: bool,
) -> Result<(String, String, Option<String>), String> {
    Err("LXC DHCP address reservations require Linux".to_string())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn release(_mac: &str) -> Result<(), String> {
    Err("LXC DHCP address reservations require Linux".to_string())
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::{HashMap, HashSet};
    use std::fs::{self, File, OpenOptions};
    use std::io::{ErrorKind, Write};
    use std::net::{IpAddr, Ipv4Addr};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::Duration;

    use nix::fcntl::{Flock, FlockArg};
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;
    use serde_json::Value;

    use crate::lxc_common::signal_cleanup::{check_startup_cancellation, with_startup_allocation};

    #[cfg(test)]
    mod tests {
        include!("network_address_spec.rs");
    }

    const DEFAULT_DNSMASQ_CONFIG: &str = "/etc/lxc/dnsmasq.conf";
    const OWNER_MARKER: &str = "# MXC-owned DHCP reservation: ";

    struct HostConfiguration {
        path: PathBuf,
        defaults_path: PathBuf,
        defaults_source: (PathBuf, String),
        defaults: Option<String>,
        network_defaults: Option<String>,
        pid_file: PathBuf,
        enabled: bool,
        range: Option<(Ipv4Addr, Ipv4Addr)>,
    }

    struct BridgeNetwork {
        gateway: Ipv4Addr,
        prefix: u8,
        first: u32,
        last: u32,
    }

    #[derive(Default)]
    struct DhcpRecords {
        addresses: HashMap<Ipv4Addr, usize>,
        hostnames: HashSet<String>,
        matching_macs: usize,
    }

    pub(crate) fn reserve(
        container_name: &str,
        mac: &str,
        bridge: &str,
        configure_resolver: bool,
    ) -> Result<(String, String, Option<String>), String> {
        with_startup_allocation(|| reserve_address(container_name, mac, bridge, configure_resolver))
    }

    fn reserve_address(
        container_name: &str,
        mac: &str,
        bridge: &str,
        configure_resolver: bool,
    ) -> Result<(String, String, Option<String>), String> {
        let mac = normalize_mac(mac)?;
        if bridge.is_empty()
            || bridge.len() > 15
            || !bridge
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
        {
            return Err(format!("Invalid LXC bridge name: {bridge:?}"));
        }
        let _lock = lock_reservations()?;
        check_startup_cancellation()?;
        let host = read_host_configuration(Some(bridge), read_lxc_net_defaults_source()?)?;
        let network = read_bridge_network(bridge, host.range)?;
        let lease_path = PathBuf::from(format!("/var/lib/misc/dnsmasq.{bridge}.leases"));
        let read_resolver = |address| {
            check_startup_cancellation()?;
            let resolver = configure_resolver
                .then(|| {
                    super::super::network_resolver::query_resolver(
                        &mac,
                        address,
                        network.gateway,
                        network.prefix,
                    )
                })
                .transpose();
            check_startup_cancellation()?;
            resolver
        };
        let original = read_optional(&host.path)?;
        let records = read_dhcp_records(&host.path, &mac)?;
        let owned = owned_reservation(original.as_deref().unwrap_or(""), &mac)?;

        if records.matching_macs != usize::from(owned.is_some()) {
            return Err(format!(
                "MAC {mac} already has a foreign or duplicate DHCP reservation"
            ));
        }

        // Reuse an owned reservation only after checking for address and lease conflicts.
        if let Some((address, _)) = owned {
            let value = u32::from(address);
            let mask = u32::MAX << (32 - network.prefix);
            if value & mask != u32::from(network.gateway) & mask
                || address == network.gateway
                || value & !mask == 0
                || value & !mask == !mask
                || records.addresses.get(&address) != Some(&1)
            {
                return Err(format!(
                    "MXC reservation {address} for {mac} conflicts with the bridge or another reservation"
                ));
            }
            if read_leases(&lease_path)?
                .get(&address)
                .is_some_and(|owner| !owner.eq_ignore_ascii_case(&mac))
            {
                return Err(format!(
                    "MXC reservation {address} is leased to another MAC"
                ));
            }
            if host.enabled {
                return Ok((
                    format!("{address}/{}", network.prefix),
                    network.gateway.to_string(),
                    read_resolver(address)?,
                ));
            }
        }
        let hostname = if dns_safe_hostname(container_name)
            && !records
                .hostnames
                .contains(&container_name.to_ascii_lowercase())
        {
            container_name.to_string()
        } else {
            format!("mxc-{}", mac.replace(':', ""))
        };
        if owned.is_none() && records.hostnames.contains(&hostname.to_ascii_lowercase()) {
            return Err(format!("DHCP hostname {hostname} is already reserved"));
        }

        // Reuse the owned address, or search the configured DHCP pool for a free one.
        let candidates = match owned {
            Some((address, _)) => u32::from(address)..=u32::from(address),
            None => network.first..=network.last,
        };
        for value in candidates {
            check_startup_cancellation()?;
            let address = Ipv4Addr::from(value);
            if owned.is_none()
                && (address == network.gateway
                    || records.addresses.contains_key(&address)
                    || read_leases(&lease_path)?.contains_key(&address)
                    || address_is_unavailable(bridge, address)?)
            {
                continue;
            }

            check_startup_cancellation()?;
            let mut changed_files = Vec::new();

            // Stop DHCP before rechecking leases and updating the reservation files.
            let result = (|| {
                stop_dnsmasq(&host.pid_file)?;
                check_startup_cancellation()?;
                change_network_service("stop")?;
                check_startup_cancellation()?;
                let leases = read_leases(&lease_path)?;
                if leases
                    .get(&address)
                    .is_some_and(|owner| owned.is_none() || !owner.eq_ignore_ascii_case(&mac))
                {
                    return Ok(None);
                }
                let current = read_optional(&host.path)?;
                if current != original
                    || read_optional(&host.defaults_path)? != host.defaults
                    || read_optional(&host.defaults_path.with_file_name("lxc-net"))?
                        != host.network_defaults
                    || read_lxc_net_defaults_source()? != host.defaults_source
                {
                    return Err(
                        "LXC DHCP configuration changed during address reservation".to_string()
                    );
                }
                let current_records = read_dhcp_records(&host.path, &mac)?;
                let expected = usize::from(owned.is_some());
                if current_records.matching_macs != expected
                    || current_records
                        .addresses
                        .get(&address)
                        .copied()
                        .unwrap_or(0)
                        != expected
                {
                    return Err(format!(
                        "DHCP reservation for {address} changed during allocation"
                    ));
                }

                // Add the reservation with an ownership marker for later cleanup.
                if owned.is_none() {
                    check_startup_cancellation()?;
                    let mut contents = current.as_deref().unwrap_or("").to_string();
                    if !contents.is_empty() && !contents.ends_with('\n') {
                        contents.push('\n');
                    }
                    contents.push_str(&format!(
                        "{OWNER_MARKER}{mac}\ndhcp-host={mac},{hostname},{address}\n"
                    ));
                    changed_files.push((host.path.clone(), current));
                    write_atomic(&host.path, &contents)?;
                }

                // Configure LXC to read the reservation file when it is not already enabled.
                if !host.enabled {
                    check_startup_cancellation()?;
                    let mut defaults = host.defaults.clone().unwrap_or_default();
                    if !defaults.ends_with('\n') {
                        defaults.push('\n');
                    }
                    defaults.push_str(&format!("LXC_DHCP_CONFILE={DEFAULT_DNSMASQ_CONFIG}\n"));
                    changed_files.push((host.defaults_path.clone(), host.defaults.clone()));
                    write_atomic(&host.defaults_path, &defaults)?;
                }
                check_startup_cancellation()?;
                Ok(Some((
                    format!("{address}/{}", network.prefix),
                    network.gateway.to_string(),
                )))
            })();

            // Restart the network service and restore files if the update or restart fails.
            match result {
                Err(error) => {
                    let rollback = restore_files(&changed_files);
                    let restart = change_network_service("start");
                    return Err(format!("{error}{rollback}{}", cleanup_error(restart)));
                }
                Ok(reservation) => {
                    if let Err(error) =
                        change_network_service("start").and_then(|()| check_startup_cancellation())
                    {
                        let rollback = restore_files(&changed_files);
                        let restart = change_network_service("start");
                        return Err(format!("{error}{rollback}{}", cleanup_error(restart)));
                    }

                    // Read resolver settings and restore changed files if startup was canceled.
                    if let Some(reservation) = reservation {
                        let resolver = read_resolver(address);
                        if let Err(error) = check_startup_cancellation() {
                            let rollback = restore_files(&changed_files);
                            let restart = change_network_service("start");
                            return Err(format!("{error}{rollback}{}", cleanup_error(restart)));
                        }
                        return resolver.map(|resolver| (reservation.0, reservation.1, resolver));
                    }
                }
            }
        }
        Err(format!(
            "No free IPv4 address is available on bridge {bridge}"
        ))
    }

    pub(crate) fn release(mac: &str) -> Result<(), String> {
        let mac = normalize_mac(mac)?;
        let _lock = lock_reservations()?;
        let host = read_host_configuration(None, read_lxc_net_defaults_source()?)?;
        let Some(contents) = read_optional(&host.path)? else {
            return Ok(());
        };
        let Some((_, marker_line)) = owned_reservation(&contents, &mac)? else {
            return Ok(());
        };
        let retained: String = contents
            .split_inclusive('\n')
            .enumerate()
            .filter_map(|(index, line)| {
                (index != marker_line && index != marker_line + 1).then_some(line)
            })
            .collect();
        write_atomic(&host.path, &retained)
    }

    fn normalize_mac(mac: &str) -> Result<String, String> {
        let parts: Vec<_> = mac.split(':').collect();
        if parts.len() != 6
            || parts
                .iter()
                .any(|part| part.len() != 2 || !part.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return Err(format!("Invalid LXC hardware address: {mac:?}"));
        }
        Ok(mac.to_ascii_lowercase())
    }

    fn dns_safe_hostname(name: &str) -> bool {
        !name.is_empty()
            && name.len() <= 63
            && !name.starts_with('-')
            && !name.ends_with('-')
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }

    fn lock_reservations() -> Result<Flock<File>, String> {
        let path = "/run/lock/mxc-lxc-network.lock";
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .map_err(|error| format!("Failed to open {path}: {error}"))?;
        Flock::lock(file, FlockArg::LockExclusive)
            .map_err(|(_, error)| format!("Failed to lock {path}: {error}"))
    }

    fn parse_script_path_setting(source: &str, key: &str) -> Result<PathBuf, String> {
        let prefix = format!("{key}=");
        let values: Vec<_> = source
            .lines()
            .filter_map(|line| line.trim().strip_prefix(&prefix))
            .collect();
        let [value] = values.as_slice() else {
            return Err(format!("Expected one literal {key} assignment in lxc-net"));
        };
        let value = value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .or_else(|| {
                value
                    .strip_prefix('\'')
                    .and_then(|value| value.strip_suffix('\''))
            })
            .unwrap_or(value);
        if !Path::new(value).is_absolute()
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_alphanumeric() && !b"/_.-".contains(&byte))
        {
            return Err(format!(
                "Unsupported {key} assignment in lxc-net: {value:?}"
            ));
        }
        Ok(PathBuf::from(value))
    }

    fn read_host_configuration(
        bridge: Option<&str>,
        defaults_source: (PathBuf, String),
    ) -> Result<HostConfiguration, String> {
        let directory = parse_script_path_setting(&defaults_source.1, "distrosysconfdir")?;
        let run_directory = parse_script_path_setting(&defaults_source.1, "varrun")?;
        let defaults_path = directory.join("lxc");
        let defaults = read_optional(&defaults_path)?;
        let network_defaults = read_optional(&directory.join("lxc-net"))?;

        // Read the trusted host shell configuration without interpolating container values.
        let output = Command::new("sh")
            .args([
                "-c",
                "LXC_BRIDGE=lxcbr0; LXC_DHCP_CONFILE=; \
                 LXC_DHCP_RANGE=10.0.3.2,10.0.3.254; USE_LXC_BRIDGE=true; \
                 varrun=$2; distrosysconfdir=$3; \
                 if [ -f \"$1\" ]; then . \"$1\" || exit $?; fi; \
                 printf '%s\\000%s\\000%s\\000%s\\000%s' \"${LXC_DHCP_CONFILE-}\" \
                 \"${LXC_DHCP_RANGE-}\" \"${LXC_BRIDGE-}\" \"${USE_LXC_BRIDGE-}\" \
                 \"$varrun/dnsmasq.pid\"",
                "mxc-lxc-network",
            ])
            .arg(&defaults_path)
            .arg(&run_directory)
            .arg(&directory)
            .output()
            .map_err(|error| format!("Failed to read LXC network settings with sh: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "Failed to evaluate {}: {}",
                defaults_path.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let values = String::from_utf8(output.stdout)
            .map_err(|error| format!("Invalid LXC network settings: {error}"))?;
        let values: Vec<_> = values.split('\0').collect();
        if values.len() != 5 {
            return Err(format!(
                "Unexpected output while reading {}",
                defaults_path.display()
            ));
        }
        if let Some(bridge) = bridge {
            if values[3] != "true" {
                return Err("lxc-net bridge management is disabled by USE_LXC_BRIDGE".to_string());
            }
            if values[2] != bridge {
                return Err(format!(
                    "Bridge {bridge} does not match the effective lxc-net bridge {:?}",
                    values[2]
                ));
            }
        }
        let enabled = !values[0].is_empty();
        let path = PathBuf::from(if enabled {
            values[0]
        } else {
            DEFAULT_DNSMASQ_CONFIG
        });
        if !path.is_absolute() || path == Path::new("/dev/null") {
            return Err(
                "LXC_DHCP_CONFILE must name a writable absolute configuration file".to_string(),
            );
        }
        let range = if bridge.is_none() || values[1].is_empty() {
            None
        } else {
            let mut fields = values[1].split(',');
            let first = fields
                .next()
                .and_then(|value| value.parse::<Ipv4Addr>().ok());
            let last = fields
                .next()
                .and_then(|value| value.parse::<Ipv4Addr>().ok());
            match (first, last) {
                (Some(first), Some(last)) if first <= last => Some((first, last)),
                _ => {
                    return Err(format!(
                        "Unsupported LXC_DHCP_RANGE in {}: {}",
                        defaults_path.display(),
                        values[1]
                    ))
                }
            }
        };
        Ok(HostConfiguration {
            path,
            defaults_path,
            defaults_source,
            defaults,
            network_defaults,
            pid_file: PathBuf::from(values[4]),
            enabled,
            range,
        })
    }

    fn read_lxc_net_defaults_source() -> Result<(PathBuf, String), String> {
        let mut path = match Command::new("systemctl")
            .args([
                "show",
                "--property=ExecStart",
                "--property=ExecStop",
                "--value",
                "lxc-net.service",
            ])
            .output()
        {
            Ok(output) if output.status.success() => {
                let commands = String::from_utf8(output.stdout)
                    .map_err(|error| format!("Invalid lxc-net service metadata: {error}"))?;
                let paths: Vec<_> = commands
                    .lines()
                    .filter(|line| !line.trim().is_empty())
                    .map(|line| {
                        line.trim()
                            .strip_prefix("{ path=")
                            .filter(|_| line.matches("{ path=").count() == 1)
                            .and_then(|value| value.split_once(" ;"))
                            .map(|(path, _)| PathBuf::from(path))
                    })
                    .collect();
                match paths.as_slice() {
                    [Some(start), Some(stop)]
                        if start == stop
                            && start.is_absolute()
                            && start.file_name().is_some_and(|name| name == "lxc-net") =>
                    {
                        start.clone()
                    }
                    _ => {
                        return Err(format!(
                            "Cannot identify one lxc-net script from installed service commands: {commands}"
                        ))
                    }
                }
            }
            Ok(output) => {
                return Err(format!(
                    "Failed to inspect installed lxc-net service: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ))
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                PathBuf::from("/etc/init.d/lxc-net")
            }
            Err(error) => {
                return Err(format!(
                    "Failed to inspect installed lxc-net service: {error}"
                ))
            }
        };
        let mut source = fs::read_to_string(&path)
            .map_err(|error| format!("Failed to read {}: {error}", path.display()))?;
        if !source
            .lines()
            .any(|line| line.trim().starts_with("distrosysconfdir="))
        {
            let commands: Vec<_> = source
                .lines()
                .map(str::split_whitespace)
                .filter_map(|mut fields| {
                    let program = fields.next()?;
                    let action = fields.next()?;
                    (Path::new(program).is_absolute()
                        && Path::new(program)
                            .file_name()
                            .is_some_and(|name| name == "lxc-net")
                        && matches!(action, "start" | "stop")
                        && fields.next().is_none())
                    .then_some((program, action))
                })
                .collect();
            match commands.as_slice() {
                [(start, "start"), (stop, "stop")] if start == stop => {
                    path = PathBuf::from(*start);
                    source = fs::read_to_string(&path)
                        .map_err(|error| format!("Failed to read {}: {error}", path.display()))?;
                }
                _ => {
                    return Err(format!(
                        "Cannot identify literal lxc-net defaults or matching start/stop commands in {}",
                        path.display()
                    ))
                }
            }
        }
        Ok((path, source))
    }

    fn read_bridge_network(
        bridge: &str,
        range: Option<(Ipv4Addr, Ipv4Addr)>,
    ) -> Result<BridgeNetwork, String> {
        let output = Command::new("ip")
            .args(["-j", "-4", "addr", "show", "dev", bridge])
            .output()
            .map_err(|error| format!("Failed to inspect bridge {bridge}: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "Failed to inspect bridge {bridge}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let interfaces: Vec<Value> = serde_json::from_slice(&output.stdout)
            .map_err(|error| format!("Invalid ip JSON for bridge {bridge}: {error}"))?;
        let addresses: Vec<_> = interfaces
            .iter()
            .filter_map(|interface| interface["addr_info"].as_array())
            .flatten()
            .filter(|address| address["family"] == "inet")
            .collect();
        if addresses.len() != 1 {
            return Err(format!("Bridge {bridge} must have exactly one IPv4 subnet"));
        }
        let gateway = addresses[0]["local"]
            .as_str()
            .and_then(|value| value.parse::<Ipv4Addr>().ok())
            .ok_or_else(|| format!("Bridge {bridge} has no usable IPv4 gateway"))?;
        let prefix = addresses[0]["prefixlen"]
            .as_u64()
            .filter(|prefix| (1..=30).contains(prefix))
            .ok_or_else(|| format!("Bridge {bridge} has no usable IPv4 prefix"))?
            as u8;
        let mask = u32::MAX << (32 - prefix);
        let subnet = u32::from(gateway) & mask;
        let broadcast = subnet | !mask;
        let (first, last) = range
            .map(|(first, last)| (u32::from(first), u32::from(last)))
            .unwrap_or((subnet + 1, broadcast - 1));
        if first <= subnet || last >= broadcast {
            return Err(format!(
                "LXC_DHCP_RANGE is outside bridge {bridge}'s usable IPv4 subnet"
            ));
        }
        Ok(BridgeNetwork {
            gateway,
            prefix,
            first,
            last,
        })
    }

    fn owned_reservation(contents: &str, mac: &str) -> Result<Option<(Ipv4Addr, usize)>, String> {
        let mut owned = None;
        let mut lines = contents.lines().enumerate();
        while let Some((index, line)) = lines.next() {
            if line.trim() != format!("{OWNER_MARKER}{mac}") {
                continue;
            }
            let fields: Vec<_> = lines
                .next()
                .and_then(|(_, line)| line.trim().strip_prefix("dhcp-host="))
                .unwrap_or("")
                .split(',')
                .map(str::trim)
                .collect();
            let address = fields
                .last()
                .and_then(|field| field.parse::<Ipv4Addr>().ok());
            match (fields.as_slice(), address) {
                ([owner, hostname, _], Some(address))
                    if owner.eq_ignore_ascii_case(mac) && dns_safe_hostname(hostname) =>
                {
                    if owned.replace((address, index)).is_some() {
                        return Err(format!("Multiple MXC reservations exist for {mac}"));
                    }
                }
                _ => return Err(format!("Malformed MXC DHCP reservation for {mac}")),
            }
        }
        Ok(owned)
    }

    fn read_dhcp_records(path: &Path, mac: &str) -> Result<DhcpRecords, String> {
        let mut records = DhcpRecords::default();
        if path.exists() {
            collect_dhcp_records(path, false, mac, &mut HashSet::new(), &mut records)?;
        }
        Ok(records)
    }

    fn collect_dhcp_records(
        path: &Path,
        hosts_file: bool,
        mac: &str,
        visited: &mut HashSet<PathBuf>,
        records: &mut DhcpRecords,
    ) -> Result<(), String> {
        let canonical = fs::canonicalize(path).map_err(|error| {
            format!(
                "Failed to resolve DHCP configuration {}: {error}",
                path.display()
            )
        })?;
        if !visited.insert(canonical.clone()) {
            return Ok(());
        }
        let contents = fs::read_to_string(&canonical).map_err(|error| {
            format!(
                "Failed to read DHCP configuration {}: {error}",
                path.display()
            )
        })?;
        for line in contents.lines() {
            let mut quoted = false;
            let mut escaped = false;
            let mut unquoted = String::new();
            for character in line.chars() {
                if escaped {
                    unquoted.push(character);
                    escaped = false;
                } else {
                    match character {
                        '\\' if quoted => escaped = true,
                        '"' => quoted = !quoted,
                        '#' if !quoted => break,
                        _ => unquoted.push(character),
                    }
                }
            }
            if quoted || escaped {
                return Err(format!("Unterminated quote in {}", path.display()));
            }
            let line = unquoted.trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = if hosts_file {
                ("dhcp-host", line)
            } else if let Some(pair) = line.split_once('=') {
                (pair.0.trim(), pair.1.trim())
            } else {
                continue;
            };
            match key {
                "dhcp-host" => {
                    for field in value.split(',').map(str::trim) {
                        if let Ok(address) = field.parse::<Ipv4Addr>() {
                            *records.addresses.entry(address).or_default() += 1;
                        } else if field.eq_ignore_ascii_case(mac) {
                            records.matching_macs += 1;
                        } else if dns_safe_hostname(field) {
                            records.hostnames.insert(field.to_ascii_lowercase());
                        }
                    }
                }
                "conf-file" | "dhcp-hostsfile" => {
                    if !Path::new(value).is_absolute() {
                        return Err(format!(
                            "DHCP configuration reference must be absolute: {value}"
                        ));
                    }
                    collect_dhcp_records(
                        Path::new(value),
                        key == "dhcp-hostsfile",
                        mac,
                        visited,
                        records,
                    )?;
                }
                "conf-dir" | "dhcp-hostsdir" => {
                    let mut fields = value.split(',');
                    let directory = Path::new(fields.next().unwrap_or(""));
                    if !directory.is_absolute() {
                        return Err(format!(
                            "DHCP configuration directory must be absolute: {value}"
                        ));
                    }
                    let filters: Vec<_> = fields.collect();
                    let entries = fs::read_dir(directory).map_err(|error| {
                        format!("Failed to read {}: {error}", directory.display())
                    })?;
                    for entry in entries {
                        let entry = entry
                            .map_err(|error| format!("Failed to read DHCP directory: {error}"))?;
                        let name = entry.file_name().to_string_lossy().into_owned();
                        if name.starts_with('.')
                            || name.starts_with('#')
                            || name.ends_with('~')
                            || name.ends_with('#')
                            || filters
                                .iter()
                                .any(|suffix| !suffix.starts_with('*') && name.ends_with(*suffix))
                            || (filters.iter().any(|suffix| suffix.starts_with('*'))
                                && !filters.iter().any(|suffix| {
                                    suffix
                                        .strip_prefix('*')
                                        .is_some_and(|suffix| name.ends_with(suffix))
                                }))
                        {
                            continue;
                        }
                        if entry.path().is_file() {
                            collect_dhcp_records(
                                &entry.path(),
                                key == "dhcp-hostsdir",
                                mac,
                                visited,
                                records,
                            )?;
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn read_leases(path: &Path) -> Result<HashMap<Ipv4Addr, String>, String> {
        let mut leases = HashMap::new();
        for line in read_optional(path)?.as_deref().unwrap_or("").lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields
                .first()
                .is_some_and(|kind| matches!(*kind, "duid" | "vendorclass" | "agent-info"))
            {
                continue;
            }
            if fields.len() != 5 {
                return Err(format!("Malformed DHCP lease in {}", path.display()));
            }
            let address = fields[2]
                .parse::<IpAddr>()
                .map_err(|error| format!("Malformed DHCP lease in {}: {error}", path.display()))?;
            if let IpAddr::V4(address) = address {
                leases.insert(address, fields[1].to_string());
            }
        }
        Ok(leases)
    }

    fn address_is_unavailable(bridge: &str, address: Ipv4Addr) -> Result<bool, String> {
        check_startup_cancellation()?;
        let address = address.to_string();

        // Send one echo request on the bridge and wait for neighbor resolution.
        let output = Command::new("ping")
            .args(["-n", "-I", bridge, "-c", "1", "-W", "4", &address])
            .output()
            .map_err(|error| format!("Failed to probe {address} with ping: {error}"))?;
        check_startup_cancellation()?;
        match output.status.code() {
            Some(0) => return Ok(true),
            Some(1) => {}
            _ => {
                return Err(format!(
                    "Ping probe for {address} failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ))
            }
        }

        let output = Command::new("ip")
            .args(["-j", "-4", "neigh", "show", "to", &address, "dev", bridge])
            .output()
            .map_err(|error| format!("Failed to inspect neighbor {address}: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "Failed to inspect neighbor {address}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let neighbors: Vec<Value> = serde_json::from_slice(&output.stdout)
            .map_err(|error| format!("Invalid ip neighbor JSON for {address}: {error}"))?;

        // Require failed ARP resolution rather than relying on ICMP silence.
        Ok(!neighbors.iter().any(|neighbor| {
            neighbor["dst"].as_str() == Some(address.as_str())
                && neighbor["lladdr"].is_null()
                && neighbor["state"].as_array().is_some_and(|states| {
                    states.iter().any(|state| state.as_str() == Some("FAILED"))
                })
        }))
    }

    fn stop_dnsmasq(pid_file: &Path) -> Result<(), String> {
        let Some(contents) = read_optional(pid_file)? else {
            return Ok(());
        };
        let pid = contents
            .trim()
            .parse::<i32>()
            .ok()
            .filter(|pid| *pid > 1)
            .map(Pid::from_raw)
            .ok_or_else(|| format!("Invalid dnsmasq PID in {}", pid_file.display()))?;
        match fs::read_to_string(format!("/proc/{pid}/comm")) {
            Ok(name) if name.trim() == "dnsmasq" => {
                match kill(pid, Signal::SIGTERM) {
                    Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
                    Err(error) => return Err(format!("Failed to stop dnsmasq {pid}: {error}")),
                }
                loop {
                    match kill(pid, None) {
                        Err(nix::errno::Errno::ESRCH) => break,
                        Ok(()) => {
                            std::thread::sleep(Duration::from_millis(20));
                        }
                        Err(error) => {
                            return Err(format!("Failed to wait for dnsmasq {pid}: {error}"))
                        }
                    }
                }
            }
            Ok(name) => {
                return Err(format!(
                    "{} names process {pid} ({:?}), not dnsmasq",
                    pid_file.display(),
                    name.trim()
                ))
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(format!("Failed to identify dnsmasq {pid}: {error}")),
        }
        match fs::remove_file(pid_file) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => {
                let recovery = change_network_service("restart");
                Err(format!(
                    "Failed to remove {}: {error}; DHCP service recovery: {recovery:?}",
                    pid_file.display()
                ))
            }
        }
    }

    fn change_network_service(action: &str) -> Result<(), String> {
        let output = Command::new("service")
            .args(["lxc-net", action])
            .output()
            .map_err(|error| format!("Failed to {action} lxc-net: {error}"))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "Failed to {action} lxc-net ({}): {} {}",
                output.status,
                String::from_utf8_lossy(&output.stdout).trim(),
                String::from_utf8_lossy(&output.stderr).trim(),
            ))
        }
    }

    fn read_optional(path: &Path) -> Result<Option<String>, String> {
        match fs::read_to_string(path) {
            Ok(contents) => Ok(Some(contents)),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("Failed to read {}: {error}", path.display())),
        }
    }

    fn write_atomic(path: &Path, contents: &str) -> Result<(), String> {
        let target = if path.exists() {
            fs::canonicalize(path)
                .map_err(|error| format!("Failed to resolve {}: {error}", path.display()))?
        } else {
            path.to_path_buf()
        };
        let parent = target
            .parent()
            .ok_or_else(|| format!("Invalid configuration path: {}", path.display()))?;
        let mut staged = tempfile::NamedTempFile::new_in(parent)
            .map_err(|error| format!("Failed to stage {}: {error}", path.display()))?;
        let permissions = match fs::metadata(&target) {
            Ok(metadata) => metadata.permissions(),
            Err(error) if error.kind() == ErrorKind::NotFound => fs::Permissions::from_mode(0o644),
            Err(error) => return Err(format!("Failed to inspect {}: {error}", path.display())),
        };
        staged
            .as_file()
            .set_permissions(permissions)
            .and_then(|()| staged.write_all(contents.as_bytes()))
            .and_then(|()| staged.as_file().sync_all())
            .map_err(|error| format!("Failed to write {}: {error}", path.display()))?;
        staged
            .persist(&target)
            .map_err(|error| format!("Failed to replace {}: {error}", path.display()))?;
        Ok(())
    }

    fn restore_files(files: &[(PathBuf, Option<String>)]) -> String {
        let mut failures = String::new();
        for (path, original) in files.iter().rev() {
            let result = match original {
                Some(contents) => write_atomic(path, contents),
                None => match fs::remove_file(path) {
                    Ok(()) => Ok(()),
                    Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
                    Err(error) => Err(format!("Failed to remove {}: {error}", path.display())),
                },
            };
            if let Err(error) = result {
                failures.push_str(&format!("; rollback failed: {error}"));
            }
        }
        failures
    }

    fn cleanup_error(result: Result<(), String>) -> String {
        match result {
            Ok(()) => String::new(),
            Err(error) => format!("; restoring lxc-net also failed: {error}"),
        }
    }
}
