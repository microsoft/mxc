// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Filesystem policy enforcement via LXC bind mounts.
//!
//! Maps the platform-agnostic `ContainerPolicy` filesystem paths to LXC
//! mount entries:
//! - `readwritePaths` → `bind,rw` mount
//! - `readonlyPaths` → `bind,ro` mount
//! - `deniedPaths` → not mounted (inaccessible inside container)

use wxc_common::logger::Logger;
use wxc_common::models::ContainerPolicy;

use crate::lxc_bindings::LxcContainer;

/// Validate that a path does not contain characters that could inject
/// additional LXC configuration directives (whitespace, newlines, carriage returns).
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
    if path.contains('\n') || path.contains('\r') {
        return Err(format!(
            "Path contains newline characters which could inject LXC config: {:?}",
            path
        ));
    }

    Ok(())
}

/// Configure filesystem bind mounts on the container based on the policy.
///
/// Adds `lxc.mount.entry` config items for each path in the policy.
pub fn configure_filesystem_mounts(
    container: &LxcContainer,
    policy: &ContainerPolicy,
    logger: &mut Logger,
) -> Result<(), String> {
    // Read-write bind mounts
    for host_path in &policy.readwrite_paths {
        validate_path(host_path)?;
        let container_path = host_path.trim_start_matches('/');
        let mount_entry = format!("{} {} none bind,create=dir 0 0", host_path, container_path);
        logger.log_line(&format!(
            "Adding rw bind mount: {} -> /{}",
            host_path, container_path
        ));
        container.set_config_item("lxc.mount.entry", &mount_entry)?;
    }

    // Read-only bind mounts
    for host_path in &policy.readonly_paths {
        validate_path(host_path)?;
        let container_path = host_path.trim_start_matches('/');
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

    // Denied paths: mount tmpfs over them to mask contents
    for host_path in &policy.denied_paths {
        validate_path(host_path)?;
        let container_path = host_path.trim_start_matches('/');

        // Determine if the path is a file or directory inside the container rootfs
        // so we use the correct LXC `create=` type for the mount entry.
        let lxc_base = container.config_path().unwrap_or("/var/lib/lxc");
        let rootfs_base = format!("{}/{}/rootfs", lxc_base, container.name());
        let full_path = format!("{}/{}", rootfs_base, container_path);

        // Use /dev/null bind mount for files, tmpfs for directories
        let is_file = std::path::Path::new(&full_path).is_file();
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
}
