// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Policy mapping — translates MXC's platform-agnostic `ContainerPolicy` into
//! WSLC SDK volume mounts and networking mode.
//!
//! This module contains pure functions with no SDK dependency, making it
//! fully unit-testable without the WSLC runtime.

use crate::wslc_bindings::WslcContainerNetworkingMode;

/// A resolved volume mount ready to be passed to `WslcSetContainerSettingsVolumes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeMount {
    /// Windows host path (e.g., `C:\workspace`).
    pub windows_path: String,
    /// Linux container path (e.g., `/mnt/c/workspace`).
    pub container_path: String,
    /// Whether the mount is read-only.
    pub read_only: bool,
}

/// Convert a Windows path to a WSL2 container mount path.
///
/// Applies the WSL2 convention: strip the drive letter, lowercase it,
/// and prefix with `/mnt/`. Forward slashes are used throughout.
///
/// Examples:
/// - `C:\workspace` → `/mnt/c/workspace`
/// - `D:\data\files` → `/mnt/d/data/files`
/// - `C:\` → `/mnt/c/`
///
/// Returns `None` if the path doesn't start with a drive letter (e.g., UNC paths).
pub fn windows_path_to_container_path(windows_path: &str) -> Option<String> {
    let path = windows_path.trim();
    if path.len() < 2 {
        return None;
    }

    let bytes = path.as_bytes();
    let drive = bytes[0];
    let separator = bytes[1];

    if !drive.is_ascii_alphabetic() || (separator != b':') {
        return None;
    }

    // After the colon, must be \, /, or end-of-string (bare "C:")
    if path.len() > 2 {
        let after_colon = bytes[2];
        if after_colon != b'\\' && after_colon != b'/' {
            return None;
        }
    }

    let drive_lower = (drive as char).to_ascii_lowercase();
    let rest = &path[2..];
    let rest_forward = rest.replace('\\', "/");

    Some(format!("/mnt/{}{}", drive_lower, rest_forward))
}

/// Build volume mounts from a container policy's filesystem paths.
///
/// - `readwrite_paths` → mounts with `read_only: false`
/// - `readonly_paths` → mounts with `read_only: true`
/// - `denied_paths` → not mounted (Linux container isolation means they're inaccessible)
///
/// Paths that don't have a valid drive letter are skipped with a warning-style message
/// in the returned errors vec.
pub fn build_volume_mounts(
    readwrite_paths: &[String],
    readonly_paths: &[String],
) -> (Vec<VolumeMount>, Vec<String>) {
    let mut mounts = Vec::new();
    let mut warnings = Vec::new();

    for path in readwrite_paths {
        match windows_path_to_container_path(path) {
            Some(container_path) => mounts.push(VolumeMount {
                windows_path: path.clone(),
                container_path,
                read_only: false,
            }),
            None => warnings.push(format!(
                "Skipping readwrite path '{}': not a valid Windows drive path",
                path
            )),
        }
    }

    for path in readonly_paths {
        match windows_path_to_container_path(path) {
            Some(container_path) => mounts.push(VolumeMount {
                windows_path: path.clone(),
                container_path,
                read_only: true,
            }),
            None => warnings.push(format!(
                "Skipping readonly path '{}': not a valid Windows drive path",
                path
            )),
        }
    }

    (mounts, warnings)
}

/// Map the network default policy to a WSLC networking mode.
///
/// The WSLC SDK provides two networking modes:
/// - `None` — no network interface, fully isolated
/// - `Bridged` — NAT networking through the WSL2 VM's virtual adapter
///
/// When `allowedHosts` or `blockedHosts` are present, networking must be
/// `Bridged` (so the container has connectivity), and per-host filtering
/// is enforced via iptables rules applied post-start.
///
/// - `Block` with no host rules → `None` (fully isolated)
/// - `Block` with `allowedHosts` → `Bridged` (iptables will restrict)
/// - `Allow` → `Bridged`
pub fn map_network_policy(is_block: bool, has_host_rules: bool) -> WslcContainerNetworkingMode {
    if is_block && !has_host_rules {
        WslcContainerNetworkingMode::None
    } else {
        WslcContainerNetworkingMode::Bridged
    }
}

/// Returns true if per-host network filtering is needed (requires iptables
/// exec after container start and `Privileged` flag).
///
/// Only returns true when the host list can refine the selected default policy:
/// - `Block` → only `allowed_hosts` matter (allowlist)
/// - `Allow` → only `blocked_hosts` matter (blocklist)
pub fn needs_host_filtering(
    is_default_block: bool,
    allowed_hosts: &[String],
    blocked_hosts: &[String],
) -> bool {
    if is_default_block {
        !allowed_hosts.is_empty()
    } else {
        !blocked_hosts.is_empty()
    }
}

/// Build iptables commands for per-host network filtering.
///
/// These rules are exec'd inside the container after start via
/// `WslcCreateContainerProcess`. The container must have the `Privileged`
/// flag set (grants root + NET_ADMIN capability) for iptables to work.
/// Images without iptables installed will not support per-host filtering.
///
/// When `defaultPolicy` is `Block` + `allowedHosts`:
///   - Default DROP all outbound
///   - ACCEPT to each allowed host
///   - ACCEPT established/related (for return traffic)
///   - ACCEPT loopback
///
/// When `defaultPolicy` is `Allow` + `blockedHosts`:
///   - DROP to each blocked host
///
/// Returns a shell command string to be exec'd inside the container.
pub fn build_iptables_rules(
    allowed_hosts: &[String],
    blocked_hosts: &[String],
    is_default_block: bool,
) -> Option<String> {
    if allowed_hosts.is_empty() && blocked_hosts.is_empty() {
        return None;
    }

    let mut rules = Vec::new();

    if is_default_block && !allowed_hosts.is_empty() {
        // Allow loopback and established connections first
        rules.push("iptables -A OUTPUT -o lo -j ACCEPT".to_string());
        rules.push("iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT".to_string());

        // Allow DNS (needed to resolve hostnames)
        rules.push("iptables -A OUTPUT -p udp --dport 53 -j ACCEPT".to_string());
        rules.push("iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT".to_string());

        // Allow each specified host
        for host in allowed_hosts {
            rules.push(format!("iptables -A OUTPUT -d {} -j ACCEPT", host));
        }

        // Default drop everything else
        rules.push("iptables -A OUTPUT -j DROP".to_string());
    } else if !is_default_block && !blocked_hosts.is_empty() {
        // Block specific hosts
        for host in blocked_hosts {
            rules.push(format!("iptables -A OUTPUT -d {} -j DROP", host));
        }
    }

    if rules.is_empty() {
        None
    } else {
        // Join with shell && so each rule must succeed before the next runs.
        // If any iptables command fails, the chain stops and the error propagates.
        Some(rules.join(" && "))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Path translation tests --

    #[test]
    fn path_c_drive_simple() {
        assert_eq!(
            windows_path_to_container_path(r"C:\workspace"),
            Some("/mnt/c/workspace".to_string())
        );
    }

    #[test]
    fn path_d_drive_nested() {
        assert_eq!(
            windows_path_to_container_path(r"D:\data\files\readme.txt"),
            Some("/mnt/d/data/files/readme.txt".to_string())
        );
    }

    #[test]
    fn path_drive_root_only() {
        assert_eq!(
            windows_path_to_container_path(r"C:\"),
            Some("/mnt/c/".to_string())
        );
    }

    #[test]
    fn path_uppercase_drive_lowered() {
        assert_eq!(
            windows_path_to_container_path(r"E:\Builds"),
            Some("/mnt/e/Builds".to_string())
        );
    }

    #[test]
    fn path_forward_slashes_preserved() {
        assert_eq!(
            windows_path_to_container_path("C:/workspace/src"),
            Some("/mnt/c/workspace/src".to_string())
        );
    }

    #[test]
    fn path_unc_returns_none() {
        assert_eq!(windows_path_to_container_path(r"\\server\share"), None);
    }

    #[test]
    fn path_empty_returns_none() {
        assert_eq!(windows_path_to_container_path(""), None);
    }

    #[test]
    fn path_relative_returns_none() {
        assert_eq!(windows_path_to_container_path("relative/path"), None);
    }

    // -- Volume mount tests --

    #[test]
    fn build_mounts_mixed_rw_ro() {
        let rw = vec![r"C:\workspace".to_string()];
        let ro = vec![r"D:\data".to_string()];
        let (mounts, warnings) = build_volume_mounts(&rw, &ro);

        assert!(warnings.is_empty());
        assert_eq!(mounts.len(), 2);
        assert_eq!(mounts[0].container_path, "/mnt/c/workspace");
        assert!(!mounts[0].read_only);
        assert_eq!(mounts[1].container_path, "/mnt/d/data");
        assert!(mounts[1].read_only);
    }

    #[test]
    fn build_mounts_skips_invalid_with_warning() {
        let rw = vec![r"\\server\share".to_string(), r"C:\valid".to_string()];
        let ro = vec![];
        let (mounts, warnings) = build_volume_mounts(&rw, &ro);

        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].container_path, "/mnt/c/valid");
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("\\\\server\\share"));
    }

    #[test]
    fn build_mounts_empty_paths() {
        let (mounts, warnings) = build_volume_mounts(&[], &[]);
        assert!(mounts.is_empty());
        assert!(warnings.is_empty());
    }

    // -- Network policy tests --

    #[test]
    fn network_block_no_hosts_maps_to_none() {
        assert_eq!(
            map_network_policy(true, false),
            WslcContainerNetworkingMode::None
        );
    }

    #[test]
    fn network_block_with_hosts_maps_to_bridged() {
        assert_eq!(
            map_network_policy(true, true),
            WslcContainerNetworkingMode::Bridged
        );
    }

    #[test]
    fn network_allow_maps_to_bridged() {
        assert_eq!(
            map_network_policy(false, false),
            WslcContainerNetworkingMode::Bridged
        );
    }

    // -- Host filtering tests --

    #[test]
    fn needs_host_filtering_empty() {
        assert!(!needs_host_filtering(true, &[], &[]));
        assert!(!needs_host_filtering(false, &[], &[]));
    }

    #[test]
    fn needs_host_filtering_block_with_allowed() {
        assert!(needs_host_filtering(true, &["1.2.3.4".to_string()], &[]));
    }

    #[test]
    fn needs_host_filtering_allow_with_blocked() {
        assert!(needs_host_filtering(false, &[], &["evil.com".to_string()]));
    }

    #[test]
    fn needs_host_filtering_block_with_blocked_only_is_false() {
        // block + blockedHosts makes no sense — blocking is already the default
        assert!(!needs_host_filtering(true, &[], &["evil.com".to_string()]));
    }

    #[test]
    fn needs_host_filtering_allow_with_allowed_only_is_false() {
        // allow + allowedHosts makes no sense — everything is already allowed
        assert!(!needs_host_filtering(false, &["1.2.3.4".to_string()], &[]));
    }

    // -- Path edge case tests --

    #[test]
    fn path_drive_relative_returns_none() {
        // C:folder (no separator after colon) is invalid
        assert_eq!(windows_path_to_container_path("C:folder"), None);
    }

    #[test]
    fn path_bare_drive_returns_some() {
        // C: (just drive letter + colon) is valid
        assert_eq!(
            windows_path_to_container_path("C:"),
            Some("/mnt/c".to_string())
        );
    }

    #[test]
    fn iptables_none_when_no_hosts() {
        assert!(build_iptables_rules(&[], &[], true).is_none());
        assert!(build_iptables_rules(&[], &[], false).is_none());
    }

    #[test]
    fn iptables_block_with_allowed_hosts() {
        let rules = build_iptables_rules(
            &["1.2.3.4".to_string(), "example.com".to_string()],
            &[],
            true,
        )
        .unwrap();
        assert!(rules.contains("iptables -A OUTPUT -o lo -j ACCEPT"));
        assert!(rules.contains("iptables -A OUTPUT -d 1.2.3.4 -j ACCEPT"));
        assert!(rules.contains("iptables -A OUTPUT -d example.com -j ACCEPT"));
        assert!(rules.contains("iptables -A OUTPUT -j DROP"));
    }

    #[test]
    fn iptables_allow_with_blocked_hosts() {
        let rules = build_iptables_rules(
            &[],
            &["evil.com".to_string(), "10.0.0.1".to_string()],
            false,
        )
        .unwrap();
        assert!(rules.contains("iptables -A OUTPUT -d evil.com -j DROP"));
        assert!(rules.contains("iptables -A OUTPUT -d 10.0.0.1 -j DROP"));
        assert!(!rules.contains("-j ACCEPT"));
    }
}
