// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Filesystem policy enforcement via LXC bind mounts.
//!
//! Maps the platform-agnostic `ContainerPolicy` filesystem paths to LXC
//! mount entries:
//! - `readwritePaths` → `bind,rw` mount
//! - `readonlyPaths` → `bind,ro` mount
//! - `deniedPaths` → masked (inaccessible inside container)

use wxc_common::filesystem_resolve::{resolve_mount_order, FsIntent};
use wxc_common::logger::Logger;
use wxc_common::models::ContainerPolicy;

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

/// Classify a denied **host** path as a regular file, to pick the LXC mask type.
///
/// Denied paths are host paths, so the mask is decided from host reality rather
/// than from the container rootfs (which does not exist until mounts are
/// applied): a regular file is masked with a read-only `/dev/null` bind
/// (`create=file`) and everything else — a directory, a symlink, or a path that
/// does not exist on the host — with an empty read-only tmpfs (`create=dir`).
/// Uses `symlink_metadata` so a symlinked deny is never followed to an
/// unintended target when choosing the mask.
fn denied_path_is_file(host_path: &str) -> bool {
    std::fs::symlink_metadata(host_path)
        .map(|meta| meta.file_type().is_file())
        .unwrap_or(false)
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
                // Classify the denied path from the HOST path, not the container
                // rootfs path. Denied paths are host paths, and the rootfs path
                // (`<lxc_path>/<name>/rootfs/<container_path>`) does not exist
                // until mounts are applied, so inspecting it would always look
                // "missing" and mask every deny as a directory. Host reality
                // decides the `create=` type instead.
                let is_file = denied_path_is_file(host_path);

                // Use /dev/null bind mount for files, tmpfs for directories.
                let mount_entry = if is_file {
                    format!("/dev/null {} none bind,ro,create=file 0 0", container_path)
                } else {
                    format!("tmpfs {} tmpfs ro,size=0,create=dir 0 0", container_path)
                };
                let create_type = if is_file { "file" } else { "dir" };
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
    fn denied_path_is_file_reflects_host_reality() {
        use std::io::Write;
        let base = std::env::temp_dir();
        let unique = format!("mxc_lxc_denied_{}", std::process::id());
        let file_path = base.join(format!("{unique}.file"));
        let dir_path = base.join(format!("{unique}.dir"));
        let missing = base.join(format!("{unique}.missing"));

        let mut file = std::fs::File::create(&file_path).expect("create temp file");
        writeln!(file, "x").expect("write temp file");
        std::fs::create_dir_all(&dir_path).expect("create temp dir");

        // Regular host file → masked with /dev/null (create=file).
        assert!(denied_path_is_file(&file_path.to_string_lossy()));
        // Host directory → masked with an empty tmpfs (create=dir).
        assert!(!denied_path_is_file(&dir_path.to_string_lossy()));
        // Missing host path → not a file, so masked as an empty directory.
        assert!(!denied_path_is_file(&missing.to_string_lossy()));

        let _ = std::fs::remove_file(&file_path);
        let _ = std::fs::remove_dir_all(&dir_path);
    }
}
