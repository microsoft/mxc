// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Filesystem policy enforcement via LXC bind mounts.
//!
//! Maps the platform-agnostic `ContainerPolicy` filesystem paths to LXC
//! mount entries:
//! - `readwritePaths` → `bind,rw` mount
//! - `readonlyPaths` → `bind,ro` mount
//! - `deniedPaths` → masked (inaccessible inside container)

use std::collections::HashMap;
use std::path::Path;

use wxc_common::logger::Logger;
use wxc_common::models::{ContainerPolicy, MaskKind};
use wxc_common::path_specificity::{resolve_mount_order, FsIntent};

use crate::lxc_bindings::LxcContainer;

/// Validate that a path does not contain characters that could inject
/// additional LXC configuration directives. `char::is_whitespace` already
/// covers spaces, tabs, newlines, and carriage returns.
fn validate_path(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("Empty path is not allowed".to_string());
    }
    if path.chars().any(|c| c.is_whitespace()) {
        return Err(format!(
            "Path contains whitespace characters which could inject or break LXC config parsing: {:?}",
            path
        ));
    }

    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ObservedMaskPathKind {
    File,
    Dir,
    Symlink,
}

/// Inspect a denied path on the **host** filesystem to infer its mask kind.
///
/// Uses `symlink_metadata` so a symlink is classified as itself rather than
/// followed (avoids the TOCTOU-prone `is_file` heuristic). A missing path
/// yields `Ok(None)` so the caller can fall back to an explicit `type`.
///
/// This must observe the host path — not the container rootfs path, which does
/// not exist before mounts are applied — otherwise every host denied path would
/// resolve to `NotFound` and spuriously demand an explicit `type`.
fn observed_mask_path_kind(host_path: &Path) -> Result<Option<ObservedMaskPathKind>, String> {
    match std::fs::symlink_metadata(host_path) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_dir() {
                Ok(Some(ObservedMaskPathKind::Dir))
            } else if file_type.is_symlink() {
                Ok(Some(ObservedMaskPathKind::Symlink))
            } else {
                Ok(Some(ObservedMaskPathKind::File))
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(format!(
            "Unable to inspect denied path '{}': {}. Set deniedPaths entry to an object with explicit type \"file\" or \"dir\".",
            host_path.display(),
            err
        )),
    }
}

/// Trim trailing path separators from a denied-path key so an explicit `type`
/// is not dropped when the resolved mount path and the configured
/// `denied_path_kinds` key differ only by a trailing slash. A root-only path is
/// preserved rather than normalized to an empty string.
fn normalize_denied_key(path: &str) -> &str {
    let trimmed = path.trim_end_matches(['/', '\\']);
    if trimmed.is_empty() {
        path
    } else {
        trimmed
    }
}

/// Look up the explicit mask kind for a denied host path, tolerating a
/// trailing-separator mismatch between the resolved mount path and the
/// configured key. The exact match is tried first as a fast path.
fn lookup_mask_kind(
    denied_path_kinds: &HashMap<String, MaskKind>,
    host_path: &str,
) -> Option<MaskKind> {
    if let Some(kind) = denied_path_kinds.get(host_path) {
        return Some(*kind);
    }
    let normalized = normalize_denied_key(host_path);
    denied_path_kinds
        .iter()
        .find(|(key, _)| normalize_denied_key(key) == normalized)
        .map(|(_, kind)| *kind)
}

fn resolve_mask_kind(
    denied_path: &str,
    explicit: Option<MaskKind>,
    observed: Option<ObservedMaskPathKind>,
) -> Result<MaskKind, String> {
    if let Some(kind) = explicit {
        return Ok(kind);
    }

    match observed {
        Some(ObservedMaskPathKind::Dir) => Ok(MaskKind::Dir),
        Some(ObservedMaskPathKind::File | ObservedMaskPathKind::Symlink) => Ok(MaskKind::File),
        None => Err(format!(
            "Denied path '{}' does not exist and no mask type was specified. Use deniedPaths object form {{\"path\":\"{}\",\"type\":\"file\"}} or {{\"path\":\"{}\",\"type\":\"dir\"}}.",
            denied_path, denied_path, denied_path
        )),
    }
}

/// Configure filesystem bind mounts on the container based on the policy.
///
/// Adds `lxc.mount.entry` config items for each path in the policy.
pub fn configure_filesystem_mounts(
    container: &LxcContainer,
    policy: &ContainerPolicy,
    logger: &mut Logger,
) -> Result<(), String> {
    for mount in resolve_mount_order(policy) {
        let host_path = &mount.path;
        validate_path(host_path)?;
        let container_path = host_path.trim_start_matches('/');

        match mount.intent {
            FsIntent::ReadWrite => {
                let mount_entry =
                    format!("{} {} none bind,create=dir 0 0", host_path, container_path);
                logger.log_line(&format!(
                    "Adding rw bind mount: {} -> /{}",
                    host_path, container_path
                ));
                container.set_config_item("lxc.mount.entry", &mount_entry)?;
            }
            FsIntent::ReadOnly => {
                let mount_entry = format!(
                    "{} {} none bind,ro,create=dir 0 0",
                    host_path, container_path
                );
                logger.log_line(&format!(
                    "Adding ro bind mount: {} -> /{}",
                    host_path, container_path
                ));
                container.set_config_item("lxc.mount.entry", &mount_entry)?;
            }
            FsIntent::Denied => {
                let explicit = lookup_mask_kind(&policy.denied_path_kinds, host_path);
                let kind = resolve_mask_kind(
                    host_path,
                    explicit,
                    observed_mask_path_kind(Path::new(host_path))?,
                )?;

                let mount_entry = match kind {
                    MaskKind::File => {
                        format!("/dev/null {} none bind,ro,create=file 0 0", container_path)
                    }
                    MaskKind::Dir => {
                        format!("tmpfs {} tmpfs ro,size=0,create=dir 0 0", container_path)
                    }
                };
                let create_type = match kind {
                    MaskKind::File => "file",
                    MaskKind::Dir => "dir",
                };
                logger.log_line(&format!(
                    "Masking denied path: /{} ({})",
                    container_path, create_type
                ));
                container.set_config_item("lxc.mount.entry", &mount_entry)?;
            }
        }
    }

    Ok(())
}

/// Remove filesystem mount configuration.
///
/// For LXC, mounts are part of the container config and are automatically
/// cleaned up when the container is destroyed. This function is provided
/// for symmetry with the Windows `FileSystemBfsManager`.
pub fn remove_filesystem_mounts(_container: &LxcContainer, logger: &mut Logger) {
    logger.log_line("Filesystem mounts will be cleaned up with container destruction.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_trimming() {
        let path = "/mnt/shared";
        let container_path = path.trim_start_matches('/');
        assert_eq!(container_path, "mnt/shared");
    }

    #[test]
    fn test_empty_path_trimming() {
        let path = "";
        let container_path = path.trim_start_matches('/');
        assert_eq!(container_path, "");
    }

    #[test]
    fn test_validate_path_rejects_newlines() {
        assert!(validate_path("/tmp\nlxc.apparmor.profile = unconfined").is_err());
        assert!(validate_path("/tmp\rlxc.cap.drop =").is_err());
    }

    #[test]
    fn test_validate_path_rejects_empty() {
        assert!(validate_path("").is_err());
    }

    #[test]
    fn test_validate_path_rejects_whitespace_in_path() {
        assert!(validate_path("/home/user/data with spaces").is_err());
    }

    #[test]
    fn test_validate_path_accepts_normal() {
        assert!(validate_path("/mnt/shared").is_ok());
    }

    #[test]
    fn explicit_mask_kind_wins_over_observed_kind() {
        assert_eq!(
            resolve_mask_kind(
                "/etc/shadow",
                Some(MaskKind::File),
                Some(ObservedMaskPathKind::Dir)
            )
            .unwrap(),
            MaskKind::File
        );
        assert_eq!(
            resolve_mask_kind(
                "/var/lib/app",
                Some(MaskKind::Dir),
                Some(ObservedMaskPathKind::File)
            )
            .unwrap(),
            MaskKind::Dir
        );
    }

    #[test]
    fn observed_symlink_and_regular_file_use_file_mask() {
        assert_eq!(
            resolve_mask_kind(
                "/etc/alternatives/editor",
                None,
                Some(ObservedMaskPathKind::Symlink)
            )
            .unwrap(),
            MaskKind::File
        );
        assert_eq!(
            resolve_mask_kind("/etc/shadow", None, Some(ObservedMaskPathKind::File)).unwrap(),
            MaskKind::File
        );
    }

    #[test]
    fn observed_directory_uses_dir_mask() {
        assert_eq!(
            resolve_mask_kind("/var/lib/app", None, Some(ObservedMaskPathKind::Dir)).unwrap(),
            MaskKind::Dir
        );
    }

    #[test]
    fn missing_path_without_explicit_kind_errors() {
        let err = resolve_mask_kind("/missing/file", None, None).unwrap_err();
        assert!(err.contains("does not exist"));
        assert!(err.contains("type"));
    }

    #[test]
    fn observed_mask_path_kind_reports_host_dir_file_and_missing() {
        use std::fs;

        let base = std::env::temp_dir().join(format!(
            "mxc_observed_mask_kind_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let dir = base.join("a_dir");
        let file = base.join("a_file");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&file, b"x").unwrap();

        assert_eq!(
            observed_mask_path_kind(&dir).unwrap(),
            Some(ObservedMaskPathKind::Dir)
        );
        assert_eq!(
            observed_mask_path_kind(&file).unwrap(),
            Some(ObservedMaskPathKind::File)
        );
        assert_eq!(
            observed_mask_path_kind(&base.join("does_not_exist")).unwrap(),
            None
        );

        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn lookup_mask_kind_prefers_exact_match() {
        let mut kinds = HashMap::new();
        kinds.insert("/data/secret".to_string(), MaskKind::File);
        assert_eq!(
            lookup_mask_kind(&kinds, "/data/secret"),
            Some(MaskKind::File)
        );
    }

    #[test]
    fn lookup_mask_kind_tolerates_trailing_separator_mismatch() {
        // Configured key lacks the trailing slash the resolved mount path carries.
        let mut kinds = HashMap::new();
        kinds.insert("/data/secret".to_string(), MaskKind::Dir);
        assert_eq!(
            lookup_mask_kind(&kinds, "/data/secret/"),
            Some(MaskKind::Dir)
        );

        // Configured key carries a trailing slash the resolved mount path lacks.
        let mut kinds = HashMap::new();
        kinds.insert("/data/secret/".to_string(), MaskKind::File);
        assert_eq!(
            lookup_mask_kind(&kinds, "/data/secret"),
            Some(MaskKind::File)
        );
    }

    #[test]
    fn lookup_mask_kind_absent_returns_none() {
        let kinds = HashMap::new();
        assert_eq!(lookup_mask_kind(&kinds, "/data/secret"), None);
    }
}
