// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Administrative control over which registries a runtime image pull may contact.

use std::fmt;

/// Machine-wide policy key, alongside the telemetry policy. Under
/// `SOFTWARE\Policies`, so only an administrator can write it — a standard user
/// cannot widen the allowlist.
const POLICY_SUBKEY: &str = r"SOFTWARE\Policies\Mxc";

/// `REG_MULTI_SZ` naming the registry hosts a pull may contact.
const POLICY_VALUE_NAME: &str = "WslcAllowedImageRegistries";

/// Registry a bare reference like `alpine:latest` resolves against.
const DEFAULT_REGISTRY: &str = "docker.io";

/// Test override, mirroring the telemetry policy's own hook, so the allowlist
/// can be exercised without writing to `HKLM`.
const POLICY_OVERRIDE_ENV: &str = "MXC_TEST_WSLC_REGISTRY_ALLOWLIST";

/// What administrative policy permits for runtime pulls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryPolicy {
    /// No policy is configured; any registry may be contacted.
    Unmanaged,
    /// Only these hosts may be contacted.
    Allowed(Vec<String>),
    /// A policy exists but could not be read, so nothing may be contacted.
    ///
    /// An administrator who misconfigured the value gets the block they were
    /// reaching for rather than the open default they were not.
    Unreadable,
}

impl RegistryPolicy {
    /// Whether `image` names a registry this machine may pull from.
    pub fn permits(&self, image: &str) -> bool {
        match self {
            RegistryPolicy::Unmanaged => true,
            RegistryPolicy::Unreadable => false,
            RegistryPolicy::Allowed(hosts) => {
                let host = registry_host(image);
                hosts.iter().any(|h| h.eq_ignore_ascii_case(host))
            }
        }
    }

    /// Why a pull was refused, for the caller's error message.
    pub fn refusal(&self, image: &str) -> String {
        match self {
            RegistryPolicy::Unreadable => format!(
                "WSLC image '{}' cannot be pulled: the administrative registry allowlist \
                 ({}\\{}) exists but could not be read, so no registry is permitted. \
                 Ask an administrator to correct it, or supply the image with \
                 wslc.imageTarPath.",
                image, POLICY_SUBKEY, POLICY_VALUE_NAME
            ),
            _ => format!(
                "WSLC image '{}' cannot be pulled: '{}' is not in the administrative \
                 registry allowlist ({}\\{}). Use a permitted registry, or supply the \
                 image with wslc.imageTarPath.",
                image,
                registry_host(image),
                POLICY_SUBKEY,
                POLICY_VALUE_NAME
            ),
        }
    }
}

impl fmt::Display for RegistryPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryPolicy::Unmanaged => f.write_str("unmanaged"),
            RegistryPolicy::Unreadable => f.write_str("unreadable"),
            RegistryPolicy::Allowed(hosts) => write!(f, "allowed: {}", hosts.join(", ")),
        }
    }
}

/// The registry host `image` resolves against.
///
/// A reference whose first path segment carries a dot, a colon, or is
/// `localhost` names a registry; anything else is a Docker Hub short name.
fn registry_host(image: &str) -> &str {
    match image.split_once('/') {
        Some((head, _)) if head.contains('.') || head.contains(':') || head == "localhost" => head,
        _ => DEFAULT_REGISTRY,
    }
}

/// Read the administrative allowlist.
pub fn get_policy() -> RegistryPolicy {
    if let Some(raw) = std::env::var_os(POLICY_OVERRIDE_ENV) {
        return parse_hosts(
            raw.to_string_lossy()
                .split(';')
                .map(|s| s.to_string())
                .collect(),
        );
    }
    platform::read()
}

/// Turn configured host entries into a policy, discarding blanks.
fn parse_hosts(hosts: Vec<String>) -> RegistryPolicy {
    let hosts: Vec<String> = hosts
        .into_iter()
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .collect();
    if hosts.is_empty() {
        // A configured-but-empty allowlist permits nothing, which is what an
        // administrator who set it that way asked for.
        RegistryPolicy::Unreadable
    } else {
        RegistryPolicy::Allowed(hosts)
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use super::{parse_hosts, RegistryPolicy, POLICY_SUBKEY, POLICY_VALUE_NAME};
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;

    pub(super) fn read() -> RegistryPolicy {
        let key = match RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(POLICY_SUBKEY) {
            Ok(k) => k,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return RegistryPolicy::Unmanaged,
            Err(_) => return RegistryPolicy::Unreadable,
        };
        match key.get_value::<Vec<String>, _>(POLICY_VALUE_NAME) {
            Ok(hosts) => parse_hosts(hosts),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => RegistryPolicy::Unmanaged,
            Err(_) => RegistryPolicy::Unreadable,
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod platform {
    use super::RegistryPolicy;

    pub(super) fn read() -> RegistryPolicy {
        RegistryPolicy::Unmanaged
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unmanaged_machine_permits_any_registry() {
        let policy = RegistryPolicy::Unmanaged;
        assert!(policy.permits("alpine:latest"));
        assert!(policy.permits("ghcr.io/owner/img:1"));
    }

    #[test]
    fn an_unreadable_policy_permits_nothing() {
        // An administrator who misconfigured the value gets the block they were
        // reaching for, not the open default.
        let policy = RegistryPolicy::Unreadable;
        assert!(!policy.permits("alpine:latest"));
        assert!(!policy.permits("ghcr.io/owner/img:1"));
    }

    #[test]
    fn an_allowlist_admits_only_its_own_hosts() {
        let policy = RegistryPolicy::Allowed(vec!["ghcr.io".to_string()]);
        assert!(policy.permits("ghcr.io/owner/img:1"));
        assert!(!policy.permits("quay.io/owner/img:1"));
    }

    #[test]
    fn a_host_is_matched_without_regard_to_case() {
        let policy = RegistryPolicy::Allowed(vec!["GHCR.IO".to_string()]);
        assert!(policy.permits("ghcr.io/owner/img:1"));
    }

    #[test]
    fn a_short_name_resolves_against_docker_hub() {
        assert_eq!(registry_host("alpine:latest"), "docker.io");
        assert_eq!(registry_host("library/alpine"), "docker.io");
        let policy = RegistryPolicy::Allowed(vec!["docker.io".to_string()]);
        assert!(policy.permits("alpine:latest"));
        assert!(policy.permits("library/alpine:3.21"));
    }

    #[test]
    fn a_registry_host_is_read_from_the_first_segment() {
        assert_eq!(registry_host("ghcr.io/owner/img:1"), "ghcr.io");
        assert_eq!(
            registry_host("mcr.microsoft.com/a/b:1"),
            "mcr.microsoft.com"
        );
        assert_eq!(registry_host("localhost:5000/img"), "localhost:5000");
        assert_eq!(registry_host("localhost/img"), "localhost");
    }

    #[test]
    fn an_allowlist_of_blanks_permits_nothing() {
        assert_eq!(
            parse_hosts(vec!["".to_string(), "  ".to_string()]),
            RegistryPolicy::Unreadable
        );
    }

    #[test]
    fn configured_hosts_are_trimmed() {
        assert_eq!(
            parse_hosts(vec!["  ghcr.io  ".to_string(), String::new()]),
            RegistryPolicy::Allowed(vec!["ghcr.io".to_string()])
        );
    }

    #[test]
    fn a_refusal_names_the_host_and_the_policy_value() {
        let policy = RegistryPolicy::Allowed(vec!["ghcr.io".to_string()]);
        let msg = policy.refusal("quay.io/owner/img:1");
        assert!(msg.contains("quay.io"));
        assert!(msg.contains(POLICY_VALUE_NAME));
        assert!(msg.contains("imageTarPath"));
    }
}
