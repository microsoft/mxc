// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-path symlink resolution for Linux backends and macOS Seatbelt.
//!
//! The Linux containment backends realise filesystem policy as bind mounts, and
//! bwrap cannot create a mount point when any component of the destination —
//! the leaf or an ancestor directory — is a pre-existing host symlink whose
//! parent is bound into the sandbox: the mount resolves through the host
//! symlink and fails with `ENOENT`, aborting the sandbox. Every path a backend
//! intends to mount over is therefore resolved to its real location first.
//!
//! Like [`crate::mxc_common::filesystem_object`] this does file I/O, so it
//! lives in `mxc_common` and is invoked by backend runners close to the point
//! of enforcement.

use std::path::{Component, Path, PathBuf};

/// The resolved path and the first failure encountered during traversal.
#[derive(Debug)]
pub(crate) struct SymlinkResolution {
    pub(crate) path: PathBuf,
    pub(crate) error: Option<std::io::Error>,
}

/// Resolve every symlink in `path` (leaf and ancestors) to a real filesystem
/// path, tolerating trailing components that do not exist yet.
///
/// `std::fs::canonicalize` resolves symlinks at every level but requires the
/// **whole** path to exist. To also cover not-yet-created denied paths under a
/// symlinked ancestor, this walks the components from the root: every existing
/// prefix is canonicalized (following symlinks exactly like the kernel), while
/// `.` and `..` in the not-yet-existent tail are folded lexically. Folding `..`
/// this way is safe because a component that does not exist cannot be a symlink,
/// so the result matches the target the kernel's path resolution would reach.
/// Returns `None` only for an empty path.
///
/// Unresolvable components are recorded in `error`, even if a later `..` removes
/// them. The path remains available for backends that can mask unresolved links.
///
/// A naive backward walk that collected `file_name()` silently dropped `..`
/// components (Rust returns `None` for a `..` file name) and reconstructed the
/// wrong target: `/link/missing/../secret` became `/real/missing/secret`
/// instead of `/real/secret`, so the mask landed on a bystander path and the
/// real denied target stayed exposed.
pub(crate) fn resolve_through_symlinks(path: &Path) -> Option<SymlinkResolution> {
    let mut result = PathBuf::new();
    let mut failure = None;
    let mut resolve_prefix = |prefix: &Path| {
        // macOS realpath can fold `file/..` (also inside link targets) without
        // checking that file is a directory, so let the kernel follow it first.
        let resolved = match std::fs::symlink_metadata(prefix) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
            Err(error) => Err(error),
            Ok(_) => std::fs::metadata(prefix).and_then(|_| std::fs::canonicalize(prefix)),
        };
        match resolved {
            Ok(real) => Some(real),
            Err(error) => {
                failure.get_or_insert(error);
                None
            }
        }
    };
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => result.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = resolve_prefix(&result.join(".."));
                result.pop();
            }
            Component::Normal(name) => {
                result.push(name);
                if let Some(real) = resolve_prefix(&result) {
                    result = real;
                }
            }
        }
    }
    if result.as_os_str().is_empty() {
        None
    } else {
        Some(SymlinkResolution {
            path: result,
            error: failure,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonicalized up front so a symlinked `TMPDIR` does not make every
    /// expectation below differ from what the walk returns.
    fn temp_root(dir: &tempfile::TempDir) -> PathBuf {
        std::fs::canonicalize(dir.path()).expect("tempdir canonicalizes")
    }

    #[test]
    fn a_leaf_symlink_resolves_to_its_target() {
        let dir = tempfile::tempdir().unwrap();
        let root = temp_root(&dir);
        let target = root.join("real.conf");
        std::fs::write(&target, b"x").unwrap();
        let link = root.join("link.conf");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let resolved = resolve_through_symlinks(&link).unwrap();
        assert!(resolved.error.is_none(), "{resolved:?}");
        assert_eq!(resolved.path, target);
    }

    /// The case a leaf-only walk misses: the destination still names a symlink
    /// directory, which is where bwrap refuses to create the mount point.
    #[test]
    fn a_symlinked_ancestor_resolves() {
        let dir = tempfile::tempdir().unwrap();
        let root = temp_root(&dir);
        std::fs::create_dir_all(root.join("real/sub")).unwrap();
        let file = root.join("real/sub/f.conf");
        std::fs::write(&file, b"x").unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();

        let resolved = resolve_through_symlinks(&root.join("link/sub/f.conf")).unwrap();
        assert!(resolved.error.is_none(), "{resolved:?}");
        assert_eq!(resolved.path, file);
    }

    /// `..` must be applied to the directory the symlink really points at.
    #[test]
    fn dotdot_folds_against_the_resolved_parent() {
        let dir = tempfile::tempdir().unwrap();
        let root = temp_root(&dir);
        std::fs::create_dir(root.join("real")).unwrap();
        let sibling = root.join("sibling.conf");
        std::fs::write(&sibling, b"x").unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();

        let resolved = resolve_through_symlinks(&root.join("link/../sibling.conf")).unwrap();
        assert!(resolved.error.is_none(), "{resolved:?}");
        assert_eq!(resolved.path, sibling);
    }

    /// A path whose tail does not exist yet still resolves its real ancestors,
    /// which is what lets a denied path be masked before it is created.
    #[test]
    fn a_missing_tail_keeps_the_resolved_ancestors() {
        let dir = tempfile::tempdir().unwrap();
        let root = temp_root(&dir);
        std::fs::create_dir(root.join("real")).unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();

        let resolved = resolve_through_symlinks(&root.join("link/absent.conf")).unwrap();
        assert!(resolved.error.is_none(), "{resolved:?}");
        assert_eq!(resolved.path, root.join("real/absent.conf"));
    }

    /// Unresolved link text remains available to mount backends.
    #[test]
    fn a_loop_yields_unresolved_text() {
        let dir = tempfile::tempdir().unwrap();
        let root = temp_root(&dir);
        let first = root.join("first");
        let second = root.join("second");
        std::os::unix::fs::symlink(&second, &first).unwrap();
        std::os::unix::fs::symlink(&first, &second).unwrap();

        let resolved = resolve_through_symlinks(&first).expect("a non-empty path resolves");
        assert!(resolved.error.is_some());
        assert!(
            std::fs::symlink_metadata(&resolved.path)
                .expect("the link node exists")
                .file_type()
                .is_symlink(),
            "a loop leaves the result a symlink: {resolved:?}"
        );
    }

    #[test]
    fn missing_prefix_and_parent_segments_do_not_hide_broken_links() {
        let dir = tempfile::tempdir().unwrap();
        let root = temp_root(&dir);
        for (name, target) in [("loop", "loop"), ("dangling", "missing-target")] {
            std::os::unix::fs::symlink(target, root.join(name)).unwrap();
            let path = root.join("missing/..").join(name).join("../secret");
            let resolved = resolve_through_symlinks(&path).unwrap();
            assert!(resolved.error.is_some(), "{resolved:?}");
            assert_eq!(resolved.path, root.join("secret"));
        }
    }

    #[test]
    fn parent_traversal_cannot_treat_a_file_as_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let root = temp_root(&dir);
        std::fs::write(root.join("file"), b"x").unwrap();
        let resolved = resolve_through_symlinks(&root.join("file/../secret")).unwrap();
        assert!(resolved.error.is_some(), "{resolved:?}");
        assert_eq!(resolved.path, root.join("secret"));
    }

    #[test]
    fn a_link_target_cannot_treat_a_file_as_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let root = temp_root(&dir);
        std::fs::write(root.join("file"), b"x").unwrap();
        std::fs::write(root.join("secret"), b"x").unwrap();
        std::os::unix::fs::symlink("file/../secret", root.join("link")).unwrap();
        for path in [root.join("link"), root.join("link/child")] {
            let resolved = resolve_through_symlinks(&path).unwrap();
            assert!(resolved.error.is_some(), "{resolved:?}");
        }
    }

    #[test]
    fn an_empty_path_has_no_target() {
        assert!(resolve_through_symlinks(Path::new("")).is_none());
    }
}
