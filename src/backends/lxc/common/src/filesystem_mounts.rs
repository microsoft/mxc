// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Filesystem policy enforcement via LXC bind mounts.
//!
//! Maps the platform-agnostic `ContainerPolicy` filesystem paths to LXC
//! mount entries:
//! - `readwritePaths` → `bind,rw` mount
//! - `readonlyPaths` → `bind,ro` mount
//! - `deniedPaths` → masked (inaccessible inside container)

use std::path::{Component, Path, PathBuf};

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

/// Resolve every symlink in `path` (leaf and ancestors) to a real filesystem
/// path, tolerating trailing components that do not exist yet.
///
/// `std::fs::canonicalize` resolves symlinks at every level but requires the
/// **whole** path to exist. To also cover a denied path that does not yet exist
/// under a symlinked ancestor, this walks the components from the root:
/// every existing prefix is canonicalized (following symlinks exactly like the
/// kernel), while `.` and `..` in the not-yet-existent tail are folded
/// lexically. Folding `..` this way is safe because a component that does not
/// exist cannot be a symlink, so the result matches the target the kernel's
/// path resolution would reach. Returns `None` only for an empty path. Mirrors
/// the Bubblewrap backend's `resolve_through_symlinks` so both backends mask the
/// same real target.
///
/// A naive backward walk that collected `file_name()` silently dropped `..`
/// components (Rust returns `None` for a `..` file name) and reconstructed the
/// wrong target: `/link/missing/../secret` became `/real/missing/secret`
/// instead of `/real/secret`, so the mask landed on a bystander path and the
/// real denied target stayed exposed.
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
                // Canonicalize the prefix so far so symlinks are followed while
                // it still exists; once a component is missing, canonicalize
                // fails and the remaining tail is folded lexically above.
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

/// Resolve a denied host path to the real host target that must be masked.
///
/// A denied path is realised as a mask mount over the container-side path; if
/// that path is (or traverses) a symlink, LXC aborts, because the kernel refuses
/// to mount over — or through — a symlink (an anti-symlink-attack protection).
/// Masking the resolved real target hides the same object without tripping that
/// protection. This is the same reason the Bubblewrap backend resolves denied
/// paths (`resolve_denied_paths`) before masking.
///
/// Resolution goes through [`resolve_through_symlinks`], which canonicalizes
/// every existing prefix (following symlinks like the kernel) and folds a
/// not-yet-existing tail lexically. An existing, non-symlink path therefore
/// comes back in its canonical absolute form — not necessarily byte-identical to
/// the input; only a path that resolves to nothing (empty) is returned
/// unchanged.
///
/// Fails closed in two cases, because emitting the mask anyway would silently
/// mask the wrong path or abort `lxc-start` with an opaque error:
/// - the resolved path is not valid UTF-8 — the LXC config is a `String`
///   pipeline that cannot represent it faithfully, and a lossy replacement could
///   mask the wrong path and leave the target exposed; or
/// - the resolved path is *still* a symlink — a dangling or otherwise
///   unresolvable link. Masking over a symlink node aborts the container, and
///   unlike Bubblewrap (which tolerates a `/dev/null` bind over a symlink node)
///   the LXC mount pipeline cannot guarantee that, so refusing to start is the
///   safe, deterministic choice.
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
            // Fail closed if resolution left a symlink in place (a dangling or
            // otherwise unresolvable link): masking over/through it would abort
            // the container, so refuse to start rather than emit a broken mount.
            // A non-existent (but non-symlink) tail returns `Err` from
            // `symlink_metadata` and is treated as safe to mask as an empty dir.
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

/// Whether any re-bound (read-write or read-only) mount is nested strictly
/// inside the denied directory at `container_path`.
///
/// When a denied directory contains a re-bound descendant, LXC must create that
/// descendant's mountpoint **inside** the directory's mask before binding it. A
/// read-only, zero-size tmpfs rejects that `mkdir` and the container aborts, so
/// such a directory must instead be masked with a writable tmpfs (see the
/// `FsIntent::Denied` branch). `container_path` and `rebound` are both
/// leading-slash-trimmed container paths, so a trailing `/` on the prefix keeps
/// the match at a path boundary (`data` never matches `database`) and excludes
/// an exact same-path entry (which is not a descendant).
fn has_rebound_descendant(container_path: &str, rebound: &[String]) -> bool {
    let prefix = format!("{container_path}/");
    rebound.iter().any(|c| c.starts_with(&prefix))
}

/// Container-side comparison forms of a single re-bound (rw/ro) path: the path
/// as written, and — when it traverses a symlink — its symlink-resolved real
/// target. Both are leading-slash-trimmed for comparison against denied
/// directories in [`has_rebound_descendant`].
///
/// A denied directory is masked at its *resolved* path (see
/// [`resolve_denied_host_path`]). A child re-bound through a symlinked ancestor
/// (e.g. `readwritePaths: ["/mnt/x/link/child"]` under
/// `deniedPaths: ["/mnt/x/link"]`, where `link` is a host symlink visible via a
/// parent bind) physically lands *inside* that resolved mask, so the descendant
/// check must see the child's resolved form to select the writable mask and
/// avoid the read-only-tmpfs `mkdir` abort. Emitting the original form too keeps
/// the plain (no-symlink) case matching unchanged. Resolution here is
/// best-effort (comparison only): a path that cannot be resolved contributes
/// just its original form.
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

/// Configure filesystem bind mounts on the container based on the policy.
///
/// Adds `lxc.mount.entry` config items for each path in the policy.
pub fn configure_filesystem_mounts(
    container: &LxcContainer,
    policy: &ContainerPolicy,
    logger: &mut Logger,
) -> Result<(), String> {
    let mounts = resolve_mount_order(policy);

    // Container-side paths of every re-bound (rw/ro) mount, used to decide
    // whether a denied *directory* must be masked with a writable tmpfs so a
    // more-specific descendant's mountpoint can be created inside it. Mirrors
    // the Bubblewrap backend, which masks denied dirs with a writable `--tmpfs`.
    // Each mount contributes both its literal path and — when it traverses a
    // symlink — its resolved real target, because a denied directory is masked
    // at its resolved path; a child re-bound through a symlinked ancestor lands
    // inside that resolved mask and must still be detected as a descendant (see
    // `rebound_comparison_paths`).
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
                // Resolve the denied path through symlinks to its real host
                // target BEFORE masking. Masking mounts a tmpfs (dir) or a
                // /dev/null bind (file) over the container-side path; if that
                // path is a symlink, LXC aborts the container because the kernel
                // refuses to mount over/through a symlink. Masking the resolved
                // real target hides the same object without the abort. (The
                // Bubblewrap backend resolves denied paths for the same reason.)
                let real_host = resolve_denied_host_path(host_path)?;
                if real_host != *host_path {
                    logger.log_line(&format!(
                        "Denied path {} resolves through a symlink; masking its real target {}",
                        host_path, real_host
                    ));
                }
                validate_path(&real_host)?;
                let container_path = real_host.trim_start_matches('/');

                // Classify the denied path from the resolved HOST path, not the
                // container rootfs path. Denied paths are host paths, and the
                // rootfs path (`<lxc_path>/<name>/rootfs/<container_path>`) does
                // not exist until mounts are applied, so inspecting it would
                // always look "missing" and mask every deny as a directory.
                // Host reality decides the `create=` type instead.
                let is_file = denied_path_is_file(&real_host);

                // Use /dev/null bind mount for files, tmpfs for directories.
                let mount_entry = if is_file {
                    format!("/dev/null {} none bind,ro,create=file 0 0", container_path)
                } else if has_rebound_descendant(container_path, &rebound_container_paths) {
                    // A more-specific rw/ro path is re-bound INSIDE this denied
                    // directory (most-specific-wins). LXC must create that
                    // descendant's mountpoint inside this mask, which a
                    // read-only, zero-size tmpfs rejects (the mkdir fails with
                    // EROFS/ENOSPC and the container aborts). Use a writable
                    // tmpfs so the mountpoint can be created — the host directory
                    // stays hidden underneath, only the ephemeral tmpfs is
                    // writable, and the descendant bind lands on top of it. This
                    // mirrors the Bubblewrap backend's writable `--tmpfs`. Cap it
                    // at a small `size=1m`: the mask only needs to hold empty
                    // mountpoint directories, so bounding it prevents sandboxed
                    // code from exhausting host memory by writing into the
                    // ephemeral tmpfs.
                    format!("tmpfs {} tmpfs size=1m,create=dir 0 0", container_path)
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
    fn has_rebound_descendant_detects_nested_rebind_only() {
        let rebound = vec![
            "mnt/msptest/data/secret_child".to_string(),
            "mnt/other/rw".to_string(),
        ];
        // A denied parent that contains a re-bound child needs a writable mask.
        assert!(has_rebound_descendant("mnt/msptest/data", &rebound));
        // A denied directory with no nested re-bind keeps the tight mask.
        assert!(!has_rebound_descendant("mnt/msptest/empty", &rebound));
        // A shared string prefix that is not a path boundary is NOT a descendant
        // ("data" must not match "database").
        assert!(!has_rebound_descendant("mnt/msptest/dat", &rebound));
        // An exact same-path entry is not a descendant (same-path ties are
        // collapsed upstream and must not force a writable mask).
        assert!(!has_rebound_descendant(
            "mnt/msptest/data/secret_child",
            &rebound
        ));
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

    /// A denied *symlink* must be resolved to its real target before masking, so
    /// the mask never lands on the symlink node (which aborts the container).
    /// symlink->dir stays a directory mask; symlink->file becomes a file mask.
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

        // A denied symlink is rewritten to its real target, and the mask type is
        // chosen from that target (dir -> tmpfs, file -> /dev/null).
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

        // A path with no symlink component is returned as its canonical self.
        let plain = resolve_denied_host_path(real_file.to_str().unwrap()).unwrap();
        assert_eq!(plain, real_file.canonicalize().unwrap().to_str().unwrap());

        let _ = std::fs::remove_dir_all(&base);
    }

    /// A denied path that traverses `..` under a symlinked ancestor with a
    /// missing intermediate directory must fold the `..` and resolve to the
    /// real target the kernel would reach, so the mask lands on the denied path
    /// itself. Regression test for a `..`-dropping bug that reconstructed a
    /// bystander target (`/real/missing/secret`) and left the real denied path
    /// (`/real/secret`) exposed.
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

        // `<link>/missing/../secret`: `missing` does not exist and the `..`
        // cancels it, so the real target is `<real>/secret`.
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

    /// A denied path that resolves to a *dangling* symlink (its target does not
    /// exist) must fail closed: masking over the symlink node aborts the
    /// container, so refusing to start is the safe, deterministic outcome.
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

    /// A rw/ro child re-bound through a symlinked ancestor must contribute its
    /// symlink-resolved form so a denied parent masked at its resolved path still
    /// detects the descendant. Without the resolved form the prefix compare would
    /// miss it, (re)select the read-only `size=0` mask, and abort when LXC tries
    /// to create the child mountpoint inside it.
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

        // Denied parent "<base>/link" is masked at its resolved path "<base>/real".
        let denied = resolve_denied_host_path(link.to_str().unwrap()).unwrap();
        let denied_container = denied.trim_start_matches('/');

        // The rw child is referenced via the symlink: "<base>/link/child".
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
