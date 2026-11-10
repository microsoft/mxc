// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::lxc_bindings::LxcContainer;
use super::network_ingress::{IngressManager, ICMPV6_ALLOW_TYPES};
use super::network_iptables::NetworkIptablesManager;
use crate::mxc_common::logger::Logger;
use crate::mxc_common::models::ContainerPolicy;

const HOOK_BEGIN: &str = "# BEGIN MXC host network";
const HOOK_END: &str = "# END MXC host network";

#[derive(Default)]
struct NetworkConfig {
    interfaces: BTreeMap<u32, BTreeMap<String, String>>,
    kept_network_namespace: bool,
    shared_network_namespace: bool,
    cloned_network_namespace: Option<bool>,
}

impl NetworkConfig {
    fn read(path: &Path) -> Result<Self, String> {
        let mut config = Self::default();
        config.include(path, &mut Vec::new())?;
        if config.kept_network_namespace
            || config.shared_network_namespace
            || config.cloned_network_namespace == Some(false)
        {
            return Err("LXC host filtering does not support a shared network namespace".into());
        }
        Ok(config)
    }

    fn include(&mut self, path: &Path, stack: &mut Vec<PathBuf>) -> Result<(), String> {
        let canonical = path
            .canonicalize()
            .map_err(|error| format!("Cannot read LXC config {}: {error}", path.display()))?;
        if stack.contains(&canonical) {
            return Err(format!("Recursive LXC include: {}", path.display()));
        }
        stack.push(canonical);
        let contents = fs::read_to_string(path)
            .map_err(|error| format!("Cannot read LXC config {}: {error}", path.display()))?;
        for line in contents.lines() {
            let line = line.trim();
            if !line.starts_with("lxc.") {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(format!("Unsupported LXC configuration line: {line}"));
            };
            let key = key.trim();
            let value = value.trim();
            let value = if value.len() >= 2
                && ((value.starts_with('"') && value.ends_with('"'))
                    || (value.starts_with('\'') && value.ends_with('\'')))
            {
                &value[1..value.len() - 1]
            } else {
                value
            };
            if key == "lxc.include" && !value.is_empty() {
                let included = Path::new(value);
                if value.ends_with('/') || included.is_dir() {
                    let entries = match fs::read_dir(included) {
                        Ok(entries) => entries,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(error) => return Err(error.to_string()),
                    };
                    for entry in entries {
                        let entry = entry.map_err(|error| error.to_string())?;
                        if entry.path().extension().is_some_and(|ext| ext == "conf") {
                            self.include(&entry.path(), stack)?;
                        }
                    }
                } else {
                    self.include(included, stack)?;
                }
            } else if key == "lxc.namespace.share.net" {
                self.shared_network_namespace = !value.is_empty();
            } else if key == "lxc.namespace.keep" {
                if value.is_empty() {
                    self.kept_network_namespace = false;
                } else {
                    self.kept_network_namespace |=
                        value.split_whitespace().any(|name| name == "net");
                }
            } else if key == "lxc.namespace.clone" {
                if value.is_empty() {
                    self.cloned_network_namespace = None;
                } else {
                    *self.cloned_network_namespace.get_or_insert(false) |=
                        value.split_whitespace().any(|name| name == "net");
                }
            } else if key == "lxc.net" && value.is_empty() {
                self.interfaces.clear();
            } else if let Some(suffix) = key.strip_prefix("lxc.net.") {
                let Some((index, field)) = suffix.split_once('.') else {
                    return Err(format!("Unsupported LXC network key: {key}"));
                };
                let index = index.parse::<u32>().map_err(|_| {
                    format!("LXC host filtering requires numeric network indices: {key}")
                })?;
                self.interfaces
                    .entry(index)
                    .or_default()
                    .insert(field.to_string(), value.to_string());
            } else if key.starts_with("lxc.network") {
                return Err(
                    "LXC host filtering requires numeric lxc.net.<index> configuration".into(),
                );
            }
        }
        stack.pop();
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct InstalledPolicy {
    config: PathBuf,
    token: String,
    indices: Vec<u32>,
}

#[derive(Clone)]
pub(crate) struct HostNetwork {
    directory: PathBuf,
    _lock: Arc<File>,
    operations: Arc<Mutex<()>>,
}

impl HostNetwork {
    pub(crate) fn claim(container: &LxcContainer) -> Result<Self, String> {
        let root = Path::new(container.lxc_path());
        fs::create_dir_all(root).map_err(|error| error.to_string())?;
        let root = root.canonicalize().map_err(|error| error.to_string())?;
        let identity = format!("{}\0{}", root.display(), container.name());
        let digest: String = Sha256::digest(identity.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let directory = root.join(".mxc-network").join(digest);
        fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .map_err(|error| error.to_string())?;
        }
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(directory.join("lock"))
            .map_err(|error| error.to_string())?;
        lock.try_lock().map_err(|_| {
            format!(
                "LXC container '{}' is already owned by another run",
                container.name()
            )
        })?;
        Ok(Self {
            directory,
            _lock: Arc::new(lock),
            operations: Arc::new(Mutex::new(())),
        })
    }

    pub(crate) fn configure(
        &mut self,
        container: &LxcContainer,
        policy: &ContainerPolicy,
        no_interface: bool,
        logger: &mut Logger,
    ) -> Result<(), String> {
        self.remove()?;
        let _operation = self
            .operations
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let config_path = Path::new(container.lxc_path())
            .join(container.name())
            .join("config")
            .canonicalize()
            .map_err(|error| error.to_string())?;
        let config = NetworkConfig::read(&config_path)?;
        if no_interface {
            return Ok(());
        }
        if let Some(field) = IngressManager::permissive_inbound_field(policy) {
            return Err(format!(
                "{field} asks for permissive inbound, which is not yet implemented for the LXC firewall path"
            ));
        }
        let rules = NetworkIptablesManager::host_egress_rules(policy, logger)?;
        let mut interfaces = Vec::new();
        for (index, fields) in &config.interfaces {
            match fields.get("type").map(String::as_str) {
                Some("empty") => continue,
                Some("veth") => {}
                other => return Err(format!(
                    "LXC host filtering requires bridge-attached veth interfaces; lxc.net.{index}.type is {other:?}"
                )),
            }
            if fields
                .get("veth.mode")
                .is_some_and(|mode| mode != "bridge" && !mode.is_empty())
                || fields.get("link").is_none_or(String::is_empty)
            {
                return Err(format!(
                    "LXC host filtering requires lxc.net.{index} to attach to a bridge"
                ));
            }
            interfaces.push((*index, fields));
        }
        if interfaces.is_empty() {
            return Err(
                "LXC network policy needs at least one bridge-attached veth interface".into(),
            );
        }
        let token = uuid::Uuid::new_v4().simple().to_string();
        let installed = InstalledPolicy {
            config: config_path.clone(),
            token,
            indices: interfaces.iter().map(|(index, _)| *index).collect(),
        };
        fs::write(
            self.directory.join("policy.json"),
            serde_json::to_vec(&installed).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        let mut hooks = format!("\n{HOOK_BEGIN} {}\n", installed.token);
        for (index, fields) in interfaces {
            let script = self.directory.join(format!("up-{index}.sh"));
            let ready = self.directory.join(format!("up-{index}.ready"));
            let body = startup_script(
                &installed.token,
                index,
                &fields["link"],
                fields.get("script.up").map_or("", String::as_str),
                &ready,
                &rules,
            );
            fs::write(&script, body).map_err(|error| error.to_string())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&script, fs::Permissions::from_mode(0o700))
                    .map_err(|error| error.to_string())?;
            }
            hooks.push_str(&format!(
                "lxc.net.{index}.script.up = /bin/bash {}\n",
                shell_quote(&script.to_string_lossy())
            ));
        }
        hooks.push_str(&format!("{HOOK_END} {}\n", installed.token));
        let mut contents = fs::read_to_string(&config_path).map_err(|error| error.to_string())?;
        contents.push_str(&hooks);
        fs::write(config_path, contents).map_err(|error| error.to_string())
    }

    pub(crate) fn verify_started(&self) -> Result<(), String> {
        let Some(installed) = self.installed()? else {
            return Ok(());
        };
        for index in installed.indices {
            if !self.directory.join(format!("up-{index}.ready")).is_file() {
                return Err(format!(
                    "LXC host policy hook did not finish for interface {index}"
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn startup_failure(&self, reason: &str) -> String {
        let mut message = reason.to_string();
        if let Ok(Some(installed)) = self.installed() {
            for index in installed.indices {
                if let Ok(output) =
                    fs::read_to_string(self.directory.join(format!("up-{index}.log")))
                {
                    if !output.trim().is_empty() {
                        message
                            .push_str(&format!("\nHost network hook {index}: {}", output.trim()));
                    }
                }
            }
        }
        message
    }

    fn installed(&self) -> Result<Option<InstalledPolicy>, String> {
        let path = self.directory.join("policy.json");
        match fs::read(path) {
            Ok(contents) => serde_json::from_slice(&contents)
                .map(Some)
                .map_err(|error| format!("Cannot read owned LXC host policy: {error}")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.to_string()),
        }
    }

    pub(crate) fn remove(&mut self) -> Result<(), String> {
        let _operation = self
            .operations
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some(installed) = self.installed()? else {
            return Ok(());
        };
        #[cfg(test)]
        if let Some(result) =
            super::network_iptables::test_firewall::intercept("nft", &["remove-owned-host-policy"])
        {
            return result;
        }
        let tables = Command::new("nft")
            .args(["--json", "list", "tables"])
            .output()
            .map_err(|error| format!("Cannot inspect owned host firewall tables: {error}"))?;
        if !tables.status.success() {
            return Err(format!(
                "Cannot inspect owned host firewall tables: {}",
                String::from_utf8_lossy(&tables.stderr)
            ));
        }
        let tables: serde_json::Value =
            serde_json::from_slice(&tables.stdout).map_err(|error| error.to_string())?;
        let mut deletions = String::new();
        for index in &installed.indices {
            let table = format!("mxc_{}_{index}", installed.token);
            let exists = tables["nftables"].as_array().is_some_and(|entries| {
                entries.iter().any(|entry| {
                    entry["table"]["family"] == "bridge" && entry["table"]["name"] == table
                })
            });
            if exists {
                deletions.push_str(&format!("delete table bridge {table}\n"));
            }
        }
        if !deletions.is_empty() {
            let mut child = Command::new("nft")
                .args(["-f", "-"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|error| error.to_string())?;
            let written = child.stdin.take().unwrap().write_all(deletions.as_bytes());
            let output = child
                .wait_with_output()
                .map_err(|error| error.to_string())?;
            if !output.status.success() {
                return Err(format!(
                    "Cannot remove owned host firewall tables: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            written.map_err(|error| error.to_string())?;
        }
        match fs::read_to_string(&installed.config) {
            Ok(contents) => {
                fs::write(
                    &installed.config,
                    without_owned_hooks(&contents, &installed.token)?,
                )
                .map_err(|error| error.to_string())?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
        for index in installed.indices {
            for suffix in ["sh", "ready", "log"] {
                let path = self.directory.join(format!("up-{index}.{suffix}"));
                match fs::remove_file(path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.to_string()),
                }
            }
        }
        fs::remove_file(self.directory.join("policy.json")).map_err(|error| error.to_string())
    }
}

fn without_owned_hooks(contents: &str, token: &str) -> Result<String, String> {
    let begin = format!("{HOOK_BEGIN} {token}");
    let end = format!("{HOOK_END} {token}");
    let mut owned = false;
    let mut result = String::new();
    for line in contents.split_inclusive('\n') {
        let marker = line.trim_end_matches(['\r', '\n']);
        if marker == begin {
            owned = true;
        } else if marker == end {
            owned = false;
        } else if !owned {
            result.push_str(line);
        }
    }
    if owned {
        return Err("Incomplete MXC host network hook block".into());
    }
    Ok(result)
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn startup_script(
    token: &str,
    index: u32,
    bridge: &str,
    prior_hook: &str,
    ready: &Path,
    egress: &str,
) -> String {
    let prior = if prior_hook.is_empty() {
        String::new()
    } else {
        format!(
            "/bin/sh -c {} -- \"$@\"\n",
            shell_quote(&format!("{prior_hook} \"$@\""))
        )
    };
    let types = ICMPV6_ALLOW_TYPES.join(", ");
    format!(
        r#"#!/bin/bash
set -euo pipefail
exec > {log} 2>&1
{prior}export PATH=/usr/sbin:/usr/bin:/sbin:/bin
if [[ "${{LXC_HOOK_VERSION:-0}}" == 1 ]]; then
    peer="${{LXC_NET_PEER:?missing host veth peer}}"
else
    peer="${{6:?missing host veth peer}}"
fi
[[ "$peer" =~ ^[a-zA-Z0-9_.:-]{{1,15}}$ ]] || exit 1
bridge={bridge}
[[ -d "/sys/class/net/$bridge/bridge" ]] || {{ echo "MXC requires a Linux bridge: $bridge"; exit 1; }}
[[ "$(readlink -f "/sys/class/net/$peer/master")" == "$(readlink -f "/sys/class/net/$bridge")" ]] || {{ echo "MXC host peer $peer is not attached to $bridge"; exit 1; }}
replace=""
if nft list table bridge mxc_{token}_{index} >/dev/null 2>&1; then
    replace="delete table bridge mxc_{token}_{index}"
fi

# Publish both directions in one nftables transaction before guest init.
nft -f - <<MXC_NFT
$replace
table bridge mxc_{token}_{index} {{
    set dhcp4_transactions {{
        typeof @th,96,32;
        flags dynamic,timeout;
        timeout 30s;
        size 1024;
    }}
    set dhcp6_transactions {{
        typeof @th,72,24;
        flags dynamic,timeout;
        timeout 30s;
        size 1024;
    }}
    chain outgoing {{
        type filter hook prerouting priority -100; policy accept;
        iifname "$peer" jump egress
    }}
    chain incoming {{
        type filter hook postrouting priority 100; policy accept;
        oifname "$peer" jump ingress
    }}
    chain egress {{
        ether type arp accept
        ether type != {{ ip, ip6 }} drop
{egress}    }}
    chain ingress {{
        ether type arp accept
        ether type != {{ ip, ip6 }} drop
        ct direction reply ct state established,related accept
        ether type ip udp sport 67 udp dport 68 @th,96,32 @dhcp4_transactions accept
        ether type ip6 udp sport 547 udp dport 546 @th,72,24 @dhcp6_transactions accept
        ether type ip6 meta l4proto ipv6-icmp icmpv6 type {{ {types} }} accept
        drop
    }}
}}
MXC_NFT
printf '%s\n' "$peer" > {ready}
"#,
        bridge = shell_quote(bridge),
        ready = shell_quote(&ready.to_string_lossy()),
        log = shell_quote(&ready.with_extension("log").to_string_lossy()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_common::logger::Mode;

    fn container_config(contents: &str) -> (PathBuf, LxcContainer) {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("host-network-tests")
            .join(uuid::Uuid::new_v4().simple().to_string());
        fs::create_dir_all(root.join("guest")).unwrap();
        fs::write(root.join("guest/config"), contents).unwrap();
        let container = LxcContainer::new("guest", Some(root.to_str().unwrap()));
        (root, container)
    }

    #[test]
    fn includes_and_resets_determine_the_effective_numeric_interfaces() {
        let (root, _) = container_config("");
        let included = root.join("included.conf");
        fs::write(&included, "lxc.net.7.type = veth\nlxc.net.7.link = old\n").unwrap();
        let path = root.join("guest/config");
        fs::write(
            &path,
            format!(
                "lxc.include = {}\nlxc.net =\nlxc.net.3.type = veth\nlxc.net.3.link = bridge3\nlxc.net.9.type = empty\n",
                included.display()
            ),
        ).unwrap();

        let config = NetworkConfig::read(&path).unwrap();
        assert_eq!(
            config.interfaces.keys().copied().collect::<Vec<_>>(),
            [3, 9]
        );
        assert_eq!(config.interfaces[&3]["link"], "bridge3");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_directory_includes_are_optional_but_missing_file_includes_fail() {
        let (root, _) = container_config("");
        let path = root.join("guest/config");
        let missing = root.join("missing");
        fs::write(&path, format!("lxc.include = {}/\n", missing.display())).unwrap();
        assert!(NetworkConfig::read(&path).is_ok());

        fs::write(&path, format!("lxc.include = {}\n", missing.display())).unwrap();
        assert!(NetworkConfig::read(&path).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn directory_includes_read_conf_entries_and_ignore_unrelated_lines() {
        let (root, _) = container_config("");
        let directory = root.join("config.d");
        fs::create_dir(&directory).unwrap();
        fs::write(
            directory.join("network.conf"),
            "unrelated text\nlxc.net.4.type = veth\nlxc.net.4.link = bridge4\n",
        )
        .unwrap();
        fs::write(directory.join("ignored.txt"), "lxc.net.9.type = phys\n").unwrap();
        let path = root.join("guest/config");
        fs::write(&path, format!("lxc.include = {}\n", directory.display())).unwrap();
        let config = NetworkConfig::read(&path).unwrap();
        assert_eq!(config.interfaces.keys().copied().collect::<Vec<_>>(), [4]);
        assert_eq!(config.interfaces[&4]["link"], "bridge4");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn shared_and_kept_network_namespaces_are_independent() {
        let (root, _) = container_config("");
        let path = root.join("guest/config");
        for contents in [
            "lxc.namespace.keep = net\nlxc.namespace.share.net =\n",
            "lxc.namespace.share.net = 123\nlxc.namespace.keep =\n",
            "lxc.namespace.keep = net\nlxc.namespace.keep = mnt\n",
            "lxc.namespace.clone = mnt pid\n",
        ] {
            fs::write(&path, contents).unwrap();
            assert!(NetworkConfig::read(&path)
                .err()
                .unwrap()
                .contains("shared network"));
        }
        fs::write(&path, "lxc.namespace.keep = net\nlxc.namespace.keep =\n").unwrap();
        assert!(NetworkConfig::read(&path).is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unsupported_topologies_are_refused_without_installing_a_hook() {
        let (root, container) = container_config("");
        let path = root.join("guest/config");
        let mut network = HostNetwork::claim(&container).unwrap();
        let mut logger = Logger::new(Mode::Buffer);
        for contents in [
            "lxc.net.0.type = phys\nlxc.net.0.link = eth0\n",
            "lxc.net.0.type = veth\nlxc.net.0.link = lxcbr0\nlxc.net.0.veth.mode = router\n",
            "lxc.net.0.type = veth\n",
        ] {
            fs::write(&path, contents).unwrap();
            assert!(network
                .configure(&container, &ContainerPolicy::default(), false, &mut logger)
                .is_err());
            assert_eq!(fs::read_to_string(&path).unwrap(), contents);
            assert!(network.installed().unwrap().is_none());
        }
        drop(network);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn no_interface_needs_no_host_firewall_or_startup_hook() {
        let contents = "lxc.net.4.type = empty\n";
        let (root, container) = container_config(contents);
        let mut network = HostNetwork::claim(&container).unwrap();
        network
            .configure(
                &container,
                &ContainerPolicy::default(),
                true,
                &mut Logger::new(Mode::Buffer),
            )
            .unwrap();

        assert!(network.installed().unwrap().is_none());
        assert_eq!(
            fs::read_to_string(root.join("guest/config")).unwrap(),
            contents
        );
        network.remove().unwrap();
        drop(network);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dropping_the_author_preserves_the_script_and_original_user_hook() {
        let contents = "# BEGIN MXC host network user-managed\nlxc.hook.version = 1\nlxc.net.2.type = veth\nlxc.net.2.link = lxcbr0\nlxc.net.2.script.up = /user/hook --argument\n# END MXC host network user-managed\n";
        let (root, container) = container_config(contents);
        let mut network = HostNetwork::claim(&container).unwrap();
        network
            .configure(
                &container,
                &ContainerPolicy::default(),
                false,
                &mut Logger::new(Mode::Buffer),
            )
            .unwrap();
        let script = network.directory.join("up-2.sh");
        drop(network);

        let network = HostNetwork::claim(&container).unwrap();
        assert!(network.installed().unwrap().is_some());
        let configured = fs::read_to_string(root.join("guest/config")).unwrap();
        assert!(configured.starts_with(contents));
        assert!(fs::read_to_string(script)
            .unwrap()
            .contains("/user/hook --argument"));
        assert_eq!(
            without_owned_hooks(&configured, &network.installed().unwrap().unwrap().token)
                .unwrap()
                .trim_end(),
            contents.trim_end()
        );
        drop(network);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_second_author_cannot_claim_the_same_container() {
        let (root, container) = container_config("lxc.net.0.type = empty\n");
        let owner = HostNetwork::claim(&container).unwrap();
        assert!(HostNetwork::claim(&container).is_err());
        drop(owner);
        let next = HostNetwork::claim(&container).unwrap();
        drop(next);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn equivalent_storage_paths_cannot_claim_a_container_twice() {
        let (root, container) = container_config("lxc.net.0.type = empty\n");
        let owner = HostNetwork::claim(&container).unwrap();
        for path in [
            format!("{}/", root.display()),
            format!("{}/guest/..", root.display()),
        ] {
            let alias = LxcContainer::new("guest", Some(&path));
            assert!(
                HostNetwork::claim(&alias).is_err(),
                "equivalent storage path {path} acquired ownership of an already owned container"
            );
        }
        drop(owner);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn equivalent_storage_path_finds_retained_policy() {
        let (root, container) =
            container_config("lxc.net.0.type = veth\nlxc.net.0.link = lxcbr0\n");
        let mut network = HostNetwork::claim(&container).unwrap();
        network
            .configure(
                &container,
                &ContainerPolicy::default(),
                false,
                &mut Logger::new(Mode::Buffer),
            )
            .unwrap();
        let token = network.installed().unwrap().unwrap().token;
        drop(network);

        let path = format!("{}/", root.display());
        let alias = LxcContainer::new("guest", Some(&path));
        let retained = HostNetwork::claim(&alias).unwrap();
        assert_eq!(
            retained.installed().unwrap().map(|policy| policy.token),
            Some(token),
            "retained filtering was lost through equivalent storage path {path}"
        );
        drop(retained);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlink_storage_path_cannot_claim_an_owned_container() {
        let (root, container) = container_config("lxc.net.0.type = empty\n");
        let path = root.join("alias");
        std::os::unix::fs::symlink(&root, &path).unwrap();
        let alias = LxcContainer::new("guest", Some(path.to_str().unwrap()));
        let owner = HostNetwork::claim(&container).unwrap();
        assert!(
            HostNetwork::claim(&alias).is_err(),
            "symlink storage path acquired ownership of an already owned container"
        );
        drop(owner);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn generated_hooks_are_valid_bash_with_quoted_paths_and_user_arguments() {
        let script = startup_script(
            "12345678901234567890123456789012",
            3,
            "lxcbr0",
            "/user/hook --argument",
            Path::new("/policy path/it's-ready"),
            "ip daddr 203.0.113.0/24 meta l4proto tcp tcp dport 80-90 drop\naccept\n",
        );
        let mut child = Command::new("bash")
            .args(["-n"])
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(script.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
