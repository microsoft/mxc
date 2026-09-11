// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::path::{Component, Path, PathBuf};

use wxc_common::filesystem_resolve::{resolve_mount_order, FsIntent};
use wxc_common::logger::Logger;
use wxc_common::models::ContainerPolicy;

use crate::lxc_bindings::LxcContainer;

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

fn denied_path_is_file(host_path: &str) -> bool {
    std::fs::symlink_metadata(host_path)
        .map(|meta| meta.file_type().is_file())
        .unwrap_or(false)
}

/// Resolve every symlink in `path`, tolerating trailing components that do not
/// exist yet.
fn resolve_through_symlinks(path: &Path) -> Option<PathBuf> {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => result.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                result.pop();
            }
            Component::Normal(name) => {
                result.push(name);
                if let Ok(real) = std::fs::canonicalize(&result) {
                    result = real;
                }
            }
        }
    }
    if result.as_os_str().is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Resolve a denied host path to the real target to mask, because the kernel
/// refuses to mount over or through a symlink.
fn resolve_denied_host_path(host_path: &str) -> Result<String, String> {
    match resolve_through_symlinks(Path::new(host_path)) {
        Some(resolved) => {
            let real = resolved.to_str().ok_or_else(|| {
                format!(
                    "deniedPaths entry {:?} resolves to a non-UTF-8 host path that cannot be \
                     safely masked; refusing to start.",
                    host_path
                )
            })?;
            if std::fs::symlink_metadata(real)
                .map(|meta| meta.file_type().is_symlink())
                .unwrap_or(false)
            {
                return Err(format!(
                    "deniedPaths entry {:?} resolves to {:?}, which is still a symlink (dangling \
                     or unresolvable) and cannot be safely masked; refusing to start.",
                    host_path, real
                ));
            }
            Ok(real.to_owned())
        }
        None => Ok(host_path.to_owned()),
    }
}

/// Whether a re-bound mount is nested strictly inside the denied directory at
/// `container_path`, which decides whether its mask must be writable.
fn has_rebound_descendant(container_path: &str, rebound: &[String]) -> bool {
    let prefix = format!("{container_path}/");
    rebound.iter().any(|c| c.starts_with(&prefix))
}

/// The container-side forms of a re-bound path to compare against denied
/// directories: the path as written, and its symlink-resolved target.
fn rebound_comparison_paths(host_path: &str) -> Vec<String> {
    let original = host_path.trim_start_matches('/').to_string();
    let mut out = Vec::with_capacity(2);
    if let Some(resolved) = resolve_through_symlinks(Path::new(host_path)) {
        if let Some(resolved) = resolved.to_str() {
            let resolved = resolved.trim_start_matches('/').to_string();
            if resolved != original {
                out.push(resolved);
            }
        }
    }
    out.push(original);
    out
}

pub fn configure_filesystem_mounts(
    container: &LxcContainer,
    policy: &ContainerPolicy,
    logger: &mut Logger,
) -> Result<(), String> {
    let mounts = resolve_mount_order(policy);
    let mut entries: Vec<String> = Vec::new();

    let rebound_container_paths: Vec<String> = mounts
        .iter()
        .filter(|m| matches!(m.intent, FsIntent::ReadWrite | FsIntent::ReadOnly))
        .flat_map(|m| rebound_comparison_paths(&m.path))
        .collect();

    for mount in &mounts {
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
                entries.push(mount_entry);
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
                entries.push(mount_entry);
            }
            FsIntent::Denied => {
                let real_host = resolve_denied_host_path(host_path)?;
                if real_host != *host_path {
                    logger.log_line(&format!(
                        "Denied path {} resolves through a symlink; masking its real target {}",
                        host_path, real_host
                    ));
                }
                validate_path(&real_host)?;
                let container_path = real_host.trim_start_matches('/');

                // The container rootfs does not exist until mounts are applied,
                // so the mask type is read off the host path instead.
                let is_file = denied_path_is_file(&real_host);

                let mount_entry = if is_file {
                    format!("/dev/null {} none bind,ro,create=file 0 0", container_path)
                } else if has_rebound_descendant(container_path, &rebound_container_paths) {
                    // A read-only, zero-size tmpfs rejects the mkdir LXC needs
                    // to create the descendant's mountpoint, and the container
                    // aborts. `size=1m` holds empty mountpoint directories
                    // without letting sandboxed code exhaust host memory.
                    format!("tmpfs {} tmpfs size=1m,create=dir 0 0", container_path)
                } else {
                    format!("tmpfs {} tmpfs ro,size=0,create=dir 0 0", container_path)
                };
                let create_type = if is_file { "file" } else { "dir" };
                logger.log_line(&format!(
                    "Masking denied path: /{} ({})",
                    container_path, create_type
                ));
                entries.push(mount_entry);
            }
        }
    }

    container.set_filesystem_access_points(&entries)?;

    Ok(())
}

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
    fn has_rebound_descendant_detects_nested_rebind_only() {
        let rebound = vec![
            "mnt/msptest/data/secret_child".to_string(),
            "mnt/other/rw".to_string(),
        ];
        assert!(has_rebound_descendant("mnt/msptest/data", &rebound));
        assert!(!has_rebound_descendant("mnt/msptest/empty", &rebound));
        assert!(
            !has_rebound_descendant("mnt/msptest/dat", &rebound),
            "a shared string prefix is not a path boundary: `dat` must not match `data`"
        );
        assert!(
            !has_rebound_descendant("mnt/msptest/data/secret_child", &rebound),
            "an exact same-path entry is not a descendant and must not force a writable mask"
        );
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

        assert!(denied_path_is_file(&file_path.to_string_lossy()));
        assert!(!denied_path_is_file(&dir_path.to_string_lossy()));
        assert!(!denied_path_is_file(&missing.to_string_lossy()));

        let _ = std::fs::remove_file(&file_path);
        let _ = std::fs::remove_dir_all(&dir_path);
    }

    /// A denied symlink must be resolved to its real target before masking, so
    /// the mask never lands on the symlink node.
    #[cfg(unix)]
    #[test]
    fn resolve_denied_host_path_rewrites_symlink_to_real_target() {
        use std::os::unix::fs::symlink;

        let base = std::env::temp_dir().join(format!("mxc_lxc_symresolve_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let real_dir = base.join("real_dir");
        let real_file = base.join("real_file.txt");
        let link_to_dir = base.join("link_to_dir");
        let link_to_file = base.join("link_to_file");
        std::fs::create_dir_all(&real_dir).expect("create real dir");
        std::fs::write(&real_file, b"x").expect("create real file");
        symlink(&real_dir, &link_to_dir).expect("symlink to dir");
        symlink(&real_file, &link_to_file).expect("symlink to file");

        let resolved_dir = resolve_denied_host_path(link_to_dir.to_str().unwrap()).unwrap();
        assert_eq!(
            resolved_dir,
            real_dir.canonicalize().unwrap().to_str().unwrap()
        );
        assert!(
            !denied_path_is_file(&resolved_dir),
            "symlink->dir masks as dir"
        );

        let resolved_file = resolve_denied_host_path(link_to_file.to_str().unwrap()).unwrap();
        assert_eq!(
            resolved_file,
            real_file.canonicalize().unwrap().to_str().unwrap()
        );
        assert!(
            denied_path_is_file(&resolved_file),
            "symlink->file masks as file"
        );

        let plain = resolve_denied_host_path(real_file.to_str().unwrap()).unwrap();
        assert_eq!(
            plain,
            real_file.canonicalize().unwrap().to_str().unwrap(),
            "a path with no symlink component is returned as its canonical self"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// `..` must fold so the mask lands on the denied path the kernel would
    /// reach, not on a bystander.
    #[cfg(unix)]
    #[test]
    fn resolve_denied_host_path_folds_dotdot_under_symlinked_ancestor() {
        use std::os::unix::fs::symlink;

        let base = std::env::temp_dir().join(format!("mxc_lxc_dotdot_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let real = base.join("real");
        let link = base.join("link");
        std::fs::create_dir_all(&real).expect("create real dir");
        symlink(&real, &link).expect("symlink ancestor to real");

        let denied = format!("{}/missing/../secret", link.to_str().unwrap());
        let resolved = resolve_denied_host_path(&denied).unwrap();
        let expected = real.canonicalize().unwrap().join("secret");
        assert_eq!(
            resolved,
            expected.to_str().unwrap(),
            "`..` must fold so the mask targets the real denied path, not a bystander"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// A denied path that resolves to a dangling symlink must fail closed.
    #[cfg(unix)]
    #[test]
    fn resolve_denied_host_path_fails_closed_on_dangling_symlink() {
        use std::os::unix::fs::symlink;

        let base = std::env::temp_dir().join(format!("mxc_lxc_dangling_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("create base");
        let dangling = base.join("dangling");
        symlink(base.join("nonexistent_target"), &dangling).expect("create dangling symlink");

        let err = resolve_denied_host_path(dangling.to_str().unwrap())
            .expect_err("a dangling denied symlink must fail closed");
        assert!(
            err.contains("still a symlink"),
            "error must explain the residual symlink: {err}"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// A child re-bound through a symlinked ancestor is still a descendant of a
    /// denied parent masked at its resolved path.
    #[cfg(unix)]
    #[test]
    fn rebound_comparison_paths_detects_child_under_symlinked_denied_parent() {
        use std::os::unix::fs::symlink;

        let base = std::env::temp_dir().join(format!("mxc_lxc_rebound_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let real = base.join("real");
        let link = base.join("link");
        std::fs::create_dir_all(real.join("child")).expect("create real/child");
        symlink(&real, &link).expect("symlink link -> real");

        let denied = resolve_denied_host_path(link.to_str().unwrap()).unwrap();
        let denied_container = denied.trim_start_matches('/');

        let child = format!("{}/child", link.to_str().unwrap());
        let rebound = rebound_comparison_paths(&child);

        assert!(
            has_rebound_descendant(denied_container, &rebound),
            "resolved child must be seen as a descendant of the resolved denied parent: \
             denied={denied_container:?} rebound={rebound:?}"
        );

        let _ = std::fs::remove_dir_all(&base);
    }
}
