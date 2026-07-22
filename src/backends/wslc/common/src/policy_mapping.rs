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
/// Returns an error if any path is not a valid local Windows drive path.
/// UNC paths (`\\server\share`) are explicitly rejected because the WSLC SDK
/// can only mount paths via the `/mnt/<drive>/` convention and has no mechanism
/// to project network shares into the container's filesystem namespace.
pub fn build_volume_mounts(
    readwrite_paths: &[String],
    readonly_paths: &[String],
) -> Result<Vec<VolumeMount>, String> {
    let mut mounts = Vec::new();

    for path in readwrite_paths {
        let container_path = windows_path_to_container_path(path).ok_or_else(|| {
            format!(
                "WSLC: readwritePaths entry '{}' is not a valid local drive path. \
                 Only paths starting with a drive letter (e.g. C:\\...) are supported; \
                 UNC paths (\\\\server\\share) cannot be mapped into a WSL container.",
                path
            )
        })?;
        mounts.push(VolumeMount {
            windows_path: path.clone(),
            container_path,
            read_only: false,
        });
    }

    for path in readonly_paths {
        let container_path = windows_path_to_container_path(path).ok_or_else(|| {
            format!(
                "WSLC: readonlyPaths entry '{}' is not a valid local drive path. \
                 Only paths starting with a drive letter (e.g. C:\\...) are supported; \
                 UNC paths (\\\\server\\share) cannot be mapped into a WSL container.",
                path
            )
        })?;
        mounts.push(VolumeMount {
            windows_path: path.clone(),
            container_path,
            read_only: true,
        });
    }

    Ok(mounts)
}

/// A Windows host path parsed for structural overlap comparison.
///
/// Parsing is platform-independent (no `std::path`, whose component semantics
/// vary by build target) so results match on Windows and Linux CI. The drive
/// prefix and root are kept distinct, and `.`/`..` are folded lexically (no disk
/// access) so a traversal spelling like `C:\a\sub\..` compares equal to `C:\a`.
#[derive(Debug, PartialEq, Eq)]
struct NormalizedPath {
    /// Lowercased drive prefix without separator (`Some("c:")`), or `None`.
    drive: Option<String>,
    /// Whether a separator follows the optional drive: distinguishes absolute
    /// `C:\a` from drive-relative `C:a`, and rooted `\a` from relative `a`.
    rooted: bool,
    /// Lexically folded, lowercased path components.
    components: Vec<String>,
}

impl NormalizedPath {
    /// Parse a Windows host path: split on `/` and `\`, case-fold (full Unicode),
    /// and fold `.`/`..`. A rooted path clamps `..` at the root (Windows
    /// semantics) so a traversal cannot escape into a different tree.
    fn parse(path: &str) -> Self {
        let lowered = path.trim().to_lowercase();
        let bytes = lowered.as_bytes();

        // Drive prefix = a leading `x:` (ASCII letter + colon).
        let (drive, rest) =
            if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
                (Some(lowered[..2].to_string()), &lowered[2..])
            } else {
                (None, lowered.as_str())
            };

        let rooted = rest.starts_with(['/', '\\']);

        let mut components: Vec<String> = Vec::new();
        for segment in rest.split(['/', '\\']).filter(|s| !s.is_empty()) {
            match segment {
                "." => {}
                ".." => {
                    if components.last().is_some_and(|last| last != "..") {
                        components.pop();
                    } else if !rooted {
                        // Relative path: a leading `..` needs a base to resolve,
                        // so retain it. Rooted paths clamp at the root instead.
                        components.push("..".to_string());
                    }
                }
                other => components.push(other.to_string()),
            }
        }

        NormalizedPath {
            drive,
            rooted,
            components,
        }
    }

    /// True when `self` (a mounted parent) strictly contains `child` (a denied
    /// path) — i.e. `child` resolves strictly deeper inside `self`'s tree.
    ///
    /// A whole-drive/root mount (`C:\`, `\`) contains every path sharing its
    /// drive anchor, including drive-relative spellings (`C:secrets`). An exact
    /// match is not "strictly deeper" and returns `false` (enforceable by simply
    /// not mounting the path). Comparison is per-component, so a partial-component
    /// match (`C:\project` vs `C:\project2`) is correctly rejected.
    fn contains_strictly(&self, child: &NormalizedPath) -> bool {
        if self.rooted && self.components.is_empty() {
            // Whole-drive mount: covers the entire drive, so any same-anchor path
            // is unenforceable. Exclude the identical root (exact match).
            return self.drive == child.drive && !(child.rooted && child.components.is_empty());
        }

        self.drive == child.drive
            && self.rooted == child.rooted
            && self.components.len() < child.components.len()
            && self
                .components
                .iter()
                .zip(child.components.iter())
                .all(|(ancestor, descendant)| ancestor == descendant)
    }
}

/// Reject configs where a `deniedPaths` entry is nested under a mounted
/// (`readwritePaths` / `readonlyPaths`) parent, which WSLC cannot enforce.
///
/// LXC and Bubblewrap mask such a deny by overlaying it (`/dev/null` or
/// `tmpfs`), but WSLC's flat volume-mount surface has no overlay/exclusion
/// primitive: a denied subtree under a mounted parent would remain fully
/// accessible through that parent mount. Rather than silently leaving it
/// accessible, reject the config with an actionable error.
///
/// Non-overlapping denied paths need no masking — WSLC simply does not mount
/// them, so they are implicitly enforced (unmounted = invisible) and pass. An
/// exact-path match between a denied path and a mounted path is likewise
/// enforceable (the path is not mounted) and is not treated as an overlap; such
/// exact same-string conflicts are already collapsed most-restrictive-wins at
/// parse time by `wxc_common`'s `normalize_filesystem_paths` (which runs for
/// every backend), and object-identity aliases (different spellings of the same
/// object via symlink/hard link/bind) are additionally tightened at the runner
/// by [`wxc_common::filesystem_object::normalize_object_conflicts`].
///
/// This is a **structural, lexical** pre-check (no disk access): paths are
/// parsed with drive prefix and root kept distinct, case-folded (full Unicode),
/// and `.`/`..` folded, so traversal spellings (`C:\proj\sub\..`), whole-drive
/// mounts (`C:\`, `\`), and drive-relative spellings (`C:secrets`) are caught.
/// It does **not** fold Unicode normalization forms, nor canonicalize on-disk
/// aliases: symlinks, junctions, hard links, 8.3 short names, or `\\?\` prefixes
/// that redirect a mounted subtree are not resolved here. Same-object aliasing
/// *between two policy entries* is tightened separately by the D6 pass
/// ([`wxc_common::filesystem_object::normalize_object_conflicts`]), which fails
/// closed on unresolvable paths when `deniedPaths` are present; but a mounted
/// parent whose subtree *reaches* a denied object via such an alias is covered
/// by neither layer (full canonicalization is deferred). Treat this as
/// defense-in-depth for the flat-mount overlay gap, not a traversal-and-alias
/// complete deny.
pub fn validate_denied_path_overlap(
    readwrite_paths: &[String],
    readonly_paths: &[String],
    denied_paths: &[String],
) -> Result<(), String> {
    if denied_paths.is_empty() {
        return Ok(());
    }

    for denied in denied_paths {
        let denied_path = NormalizedPath::parse(denied);

        for (mounted, list_name) in readwrite_paths
            .iter()
            .map(|path| (path, "readwritePaths"))
            .chain(readonly_paths.iter().map(|path| (path, "readonlyPaths")))
        {
            if NormalizedPath::parse(mounted).contains_strictly(&denied_path) {
                return Err(format!(
                    "WSLC: deniedPaths entry '{denied}' is nested under {list_name} entry \
                     '{mounted}'. WSLC mounts host paths as flat volumes and has no overlay \
                     primitive to mask a subtree of a mounted path, so this deny cannot be \
                     enforced — the path would remain accessible through the parent mount. \
                     Remove the denied path, or stop mounting its parent."
                ));
            }
        }
    }

    Ok(())
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

/// Validate that a host string is safe for use in an iptables command.
/// Accepts hostnames (a-z, 0-9, dots, hyphens) and IPv4/IPv6 addresses
/// (digits, dots, colons, brackets, slash for CIDR).
/// Rejects empty strings and anything containing shell metacharacters.
fn is_valid_host(host: &str) -> bool {
    !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-:[]/_".contains(&b))
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
///
/// Host values are validated to prevent shell command injection.
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
            if !is_valid_host(host) {
                continue;
            }
            rules.push(format!("iptables -A OUTPUT -d {} -j ACCEPT", host));
        }

        // Default drop everything else
        rules.push("iptables -A OUTPUT -j DROP".to_string());
    } else if !is_default_block && !blocked_hosts.is_empty() {
        // Block specific hosts
        for host in blocked_hosts {
            if !is_valid_host(host) {
                continue;
            }
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
        let mounts = build_volume_mounts(&rw, &ro).unwrap();

        assert_eq!(mounts.len(), 2);
        assert_eq!(mounts[0].container_path, "/mnt/c/workspace");
        assert!(!mounts[0].read_only);
        assert_eq!(mounts[1].container_path, "/mnt/d/data");
        assert!(mounts[1].read_only);
    }

    #[test]
    fn build_mounts_rejects_unc_readwrite() {
        let rw = vec![r"\\server\share".to_string()];
        let ro = vec![];
        let err = build_volume_mounts(&rw, &ro).unwrap_err();

        assert!(
            err.contains("\\\\server\\share"),
            "error should cite the path: {err}"
        );
        assert!(err.contains("UNC"), "error should mention UNC: {err}");
    }

    #[test]
    fn build_mounts_rejects_unc_readonly() {
        let rw = vec![];
        let ro = vec![r"\\nas\docs".to_string()];
        let err = build_volume_mounts(&rw, &ro).unwrap_err();

        assert!(
            err.contains("\\\\nas\\docs"),
            "error should cite the path: {err}"
        );
        assert!(
            err.contains("readonlyPaths"),
            "error should identify the field: {err}"
        );
    }

    #[test]
    fn build_mounts_rejects_unc_mixed_with_valid() {
        // Even if valid paths are present, a single UNC path fails the whole call.
        let rw = vec![r"\\server\share".to_string(), r"C:\valid".to_string()];
        let ro = vec![];
        let err = build_volume_mounts(&rw, &ro).unwrap_err();

        assert!(err.contains("\\\\server\\share"));
    }

    #[test]
    fn build_mounts_rejects_relative_path() {
        let rw = vec!["relative/path".to_string()];
        let ro = vec![];
        let err = build_volume_mounts(&rw, &ro).unwrap_err();

        assert!(err.contains("relative/path"));
    }

    #[test]
    fn build_mounts_empty_paths() {
        let mounts = build_volume_mounts(&[], &[]).unwrap();
        assert!(mounts.is_empty());
    }

    // -- Denied-path overlap validation tests --

    fn strings(paths: &[&str]) -> Vec<String> {
        paths.iter().map(|path| (*path).to_string()).collect()
    }

    #[test]
    fn overlap_rejects_denied_child_of_readwrite_parent() {
        let err = validate_denied_path_overlap(
            &strings(&[r"C:\project"]),
            &[],
            &strings(&[r"C:\project\secrets"]),
        )
        .unwrap_err();

        assert!(
            err.contains(r"C:\project\secrets"),
            "error should cite the denied path: {err}"
        );
        assert!(
            err.contains(r"C:\project"),
            "error should cite the parent mount: {err}"
        );
        assert!(
            err.contains("readwritePaths"),
            "error should identify the mounting list: {err}"
        );
    }

    #[test]
    fn overlap_rejects_denied_child_of_readonly_parent() {
        let err = validate_denied_path_overlap(
            &[],
            &strings(&[r"C:\data"]),
            &strings(&[r"C:\data\private\keys"]),
        )
        .unwrap_err();

        assert!(err.contains("readonlyPaths"), "{err}");
    }

    #[test]
    fn overlap_allows_non_overlapping_denied_path() {
        // Denied path shares no mounted ancestor — WSLC just never mounts it.
        validate_denied_path_overlap(&strings(&[r"C:\project"]), &[], &strings(&[r"D:\secrets"]))
            .expect("non-overlapping denied path must be accepted");
    }

    #[test]
    fn overlap_allows_exact_path_match() {
        // Exact match is enforceable by simply not mounting the path; it is not
        // a nested-under-parent overlap.
        validate_denied_path_overlap(&strings(&[r"C:\project"]), &[], &strings(&[r"C:\project"]))
            .expect("exact-path deny is enforceable and must be accepted");
    }

    #[test]
    fn overlap_ignores_partial_component_prefix() {
        // "C:\project2" is not a child of "C:\project" — component-wise compare.
        validate_denied_path_overlap(
            &strings(&[r"C:\project"]),
            &[],
            &strings(&[r"C:\project2\secrets"]),
        )
        .expect("partial-component prefix must not count as an overlap");
    }

    #[test]
    fn overlap_is_case_and_separator_insensitive() {
        // Windows paths are case-insensitive; mixed separators and casing must
        // still be detected as an overlap.
        let err = validate_denied_path_overlap(
            &strings(&[r"C:\Project"]),
            &[],
            &strings(&["c:/project/Secrets"]),
        )
        .unwrap_err();

        assert!(err.contains("cannot be enforced"), "{err}");
    }

    #[test]
    fn overlap_is_case_insensitive_for_non_ascii_components() {
        // NTFS folds non-ASCII case (C:\Ä == c:\ä), so a denied child differing
        // only by non-ASCII case from a mounted parent must still be rejected.
        let err =
            validate_denied_path_overlap(&strings(&["C:\\Ä"]), &[], &strings(&["c:\\ä\\secret"]))
                .unwrap_err();

        assert!(err.contains("cannot be enforced"), "{err}");
    }

    #[test]
    fn overlap_detects_child_of_mounted_drive_root() {
        // Mounting a whole drive means any denied subpath is unenforceable.
        let err =
            validate_denied_path_overlap(&strings(&[r"C:\"]), &[], &strings(&[r"C:\Windows"]))
                .unwrap_err();

        assert!(err.contains(r"C:\Windows"), "{err}");
    }

    #[test]
    fn overlap_allows_denied_parent_of_mounted_child() {
        // The reverse nesting is out of scope: the denied parent is simply not
        // mounted, and the explicit child mount is an intentional carve-out.
        validate_denied_path_overlap(
            &strings(&[r"C:\project\src"]),
            &[],
            &strings(&[r"C:\project"]),
        )
        .expect("denied ancestor of a mounted child is not this overlap case");
    }

    #[test]
    fn overlap_empty_denied_paths_is_ok() {
        validate_denied_path_overlap(&strings(&[r"C:\project"]), &strings(&[r"D:\data"]), &[])
            .expect("no denied paths means nothing to validate");
    }

    #[test]
    fn overlap_reports_first_offending_pair_across_lists() {
        // A denied path nested under a read-only mount is caught even when a
        // read-write mount is also present and unrelated.
        let err = validate_denied_path_overlap(
            &strings(&[r"D:\unrelated"]),
            &strings(&[r"C:\app"]),
            &strings(&[r"C:\app\config\token"]),
        )
        .unwrap_err();

        assert!(err.contains("readonlyPaths"), "{err}");
        assert!(err.contains(r"C:\app\config\token"), "{err}");
    }

    #[test]
    fn overlap_rejects_dotdot_traversal_in_denied_path() {
        // `C:\outside\..\project\secrets` lexically folds to `C:\project\secrets`,
        // which is under the mounted `C:\project`.
        let err = validate_denied_path_overlap(
            &strings(&[r"C:\project"]),
            &[],
            &strings(&[r"C:\outside\..\project\secrets"]),
        )
        .unwrap_err();

        assert!(err.contains("cannot be enforced"), "{err}");
    }

    #[test]
    fn overlap_rejects_dotdot_traversal_in_mounted_path() {
        // The mount `C:\project\sub\..` folds to `C:\project`, whose subtree
        // includes the denied `C:\project\secret`.
        let err = validate_denied_path_overlap(
            &strings(&[r"C:\project\sub\.."]),
            &[],
            &strings(&[r"C:\project\secret"]),
        )
        .unwrap_err();

        assert!(err.contains("cannot be enforced"), "{err}");
    }

    #[test]
    fn overlap_rejects_child_of_bare_root_mount() {
        // A drive-less root mount (`\`) covers the whole current drive, so any
        // same-anchor denied path under it is unenforceable.
        let err =
            validate_denied_path_overlap(&strings(&[r"\"]), &[], &strings(&[r"\project\secret"]))
                .unwrap_err();

        assert!(err.contains("cannot be enforced"), "{err}");
    }

    #[test]
    fn overlap_rejects_drive_relative_denied_under_full_drive() {
        // A whole-drive mount (`C:\`) covers even drive-relative spellings
        // (`C:secrets`), which resolve somewhere on the same drive.
        let err = validate_denied_path_overlap(&strings(&[r"C:\"]), &[], &strings(&[r"C:secrets"]))
            .unwrap_err();

        assert!(err.contains("cannot be enforced"), "{err}");
    }

    #[test]
    fn overlap_allows_absolute_vs_relative_no_false_positive() {
        // Rooted `\project` and relative `project\secret` have different anchors
        // (rooted vs not), so this is not a provable overlap and must be accepted.
        validate_denied_path_overlap(
            &strings(&[r"\project"]),
            &[],
            &strings(&[r"project\secret"]),
        )
        .expect("absolute mount vs relative deny must not be a false rejection");
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

    #[test]
    fn is_valid_host_accepts_valid_entries() {
        assert!(is_valid_host("example.com"));
        assert!(is_valid_host("192.168.1.1"));
        assert!(is_valid_host("10.0.0.0/8"));
        assert!(is_valid_host("my-host.example.com"));
        assert!(is_valid_host("::1"));
        assert!(is_valid_host("[::1]"));
        assert!(is_valid_host("2001:db8::1"));
    }

    #[test]
    fn is_valid_host_rejects_injection() {
        assert!(!is_valid_host(""));
        assert!(!is_valid_host("; rm -rf /"));
        assert!(!is_valid_host("host && echo pwned"));
        assert!(!is_valid_host("host | cat /etc/passwd"));
        assert!(!is_valid_host("$(whoami)"));
        assert!(!is_valid_host("host`id`"));
        assert!(!is_valid_host("host name with spaces"));
    }

    #[test]
    fn iptables_skips_invalid_hosts() {
        let rules = build_iptables_rules(
            &[],
            &[
                "good.com".to_string(),
                "; rm -rf /".to_string(),
                "10.0.0.1".to_string(),
            ],
            false,
        )
        .unwrap();
        assert!(rules.contains("good.com"));
        assert!(rules.contains("10.0.0.1"));
        assert!(!rules.contains("rm"));
    }
}
