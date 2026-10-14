// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Symlink resolution for host paths the Linux backends mount over.
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
/// A chain that loops or dangles leaves canonicalization unable to finish, so
/// the result is the lexical text and is still a symlink. Callers that are
/// about to mount over the result must check what they got.
///
/// A naive backward walk that collected `file_name()` silently dropped `..`
/// components (Rust returns `None` for a `..` file name) and reconstructed the
/// wrong target: `/link/missing/../secret` became `/real/missing/secret`
/// instead of `/real/secret`, so the mask landed on a bystander path and the
/// real denied target stayed exposed.
pub(crate) fn resolve_through_symlinks(path: &Path) -> Option<PathBuf> {
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

        assert_eq!(resolve_through_symlinks(&link), Some(target));
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

        assert_eq!(
            resolve_through_symlinks(&root.join("link/sub/f.conf")),
            Some(file)
        );
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

        assert_eq!(
            resolve_through_symlinks(&root.join("link/../sibling.conf")),
            Some(sibling)
        );
    }

    /// A path whose tail does not exist yet still resolves its real ancestors,
    /// which is what lets a denied path be masked before it is created.
    #[test]
    fn a_missing_tail_keeps_the_resolved_ancestors() {
        let dir = tempfile::tempdir().unwrap();
        let root = temp_root(&dir);
        std::fs::create_dir(root.join("real")).unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();

        assert_eq!(
            resolve_through_symlinks(&root.join("link/absent.conf")),
            Some(root.join("real/absent.conf"))
        );
    }

    /// Canonicalization cannot finish, so the caller is handed path text that
    /// is still a link rather than an error.
    #[test]
    fn a_loop_yields_unresolved_text() {
        let dir = tempfile::tempdir().unwrap();
        let root = temp_root(&dir);
        let first = root.join("first");
        let second = root.join("second");
        std::os::unix::fs::symlink(&second, &first).unwrap();
        std::os::unix::fs::symlink(&first, &second).unwrap();

        let resolved = resolve_through_symlinks(&first).expect("a non-empty path resolves");
        assert!(
            std::fs::symlink_metadata(&resolved)
                .expect("the link node exists")
                .file_type()
                .is_symlink(),
            "a loop leaves the result a symlink: {resolved:?}"
        );
    }

    #[test]
    fn an_empty_path_has_no_target() {
        assert_eq!(resolve_through_symlinks(Path::new("")), None);
    }
}
