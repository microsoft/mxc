// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Object-based filesystem-policy normalization (roadmap item D6 —
//! "object-based policy validation").
//!
//! The string-level [`crate::config_parser::normalize_filesystem_paths`] already
//! resolves *same path string* appearing in multiple lists via
//! most-restrictive-wins (`deny` > `readonly` > `readwrite`). This module
//! handles the harder case: two **different** path strings that resolve to the
//! **same filesystem object** (via bind mounts, symlinks, or hard links) but
//! carry conflicting intents — e.g. `readwritePaths: ["/mnt/storage/data"]` and
//! `deniedPaths: ["/data"]` where `/data` is a bind mount of the former. The
//! agent could reach the "denied" object through the read-write alias.
//!
//! Because Linux mount namespaces (and the WSLC SDK) are *path*-based, denying
//! one path to an object cannot deny another path to the same object (that's the
//! non-actionable "object-based enforcement" gap). The only thing we can do at
//! config time is **normalize**: detect aliases of the same object and tighten
//! every alias to the strictest intent among them, emitting a warning per
//! tightened path. We never reject — conflicting intents are resolved
//! deterministically.
//!
//! This does file I/O (`stat`/`CreateFile`), so — per design review — it lives
//! here in `wxc_common` and is invoked by each backend runner close to the
//! point of enforcement (NOT in `config_parser`, which stays string-only). This
//! both honors that separation and shrinks the TOCTOU window between the check
//! and the backend actually building its mounts.

use crate::logger::Logger;
use crate::models::ContainerPolicy;

/// Intent class for a policy path, ordered least → most restrictive so that
/// `max()` yields the strictest intent in a group of aliases.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Intent {
    ReadWrite,
    ReadOnly,
    Denied,
}

impl Intent {
    /// The JSON config list name this intent maps to (for diagnostics).
    fn list_name(self) -> &'static str {
        match self {
            Intent::ReadWrite => "readwritePaths",
            Intent::ReadOnly => "readonlyPaths",
            Intent::Denied => "deniedPaths",
        }
    }
}

/// Opaque identity of a filesystem object. Two paths with the same `ObjectId`
/// refer to the same underlying object even if reached via different names
/// (bind mount, symlink, or hard link).
#[cfg(unix)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct ObjectId {
    dev: u64,
    ino: u64,
}

#[cfg(windows)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct ObjectId {
    volume_serial: u64,
    file_id: u128,
}

#[cfg(not(any(unix, windows)))]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct ObjectId {
    _unused: u8,
}

/// Resolve a path to its filesystem-object identity, following symlinks so two
/// names for the same target collide. Returns `None` when the path cannot be
/// stat'd (missing, permission denied, etc.) — such paths are left untouched
/// (their existence is handled separately as an advisory warning).
#[cfg(unix)]
fn object_id(path: &str) -> Option<ObjectId> {
    use std::os::unix::fs::MetadataExt;
    // `metadata` follows symlinks, giving the target object's identity.
    let md = std::fs::metadata(path).ok()?;
    Some(ObjectId {
        dev: md.dev(),
        ino: md.ino(),
    })
}

#[cfg(windows)]
fn object_id(path: &str) -> Option<ObjectId> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FileIdInfo, GetFileInformationByHandleEx, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING,
    };

    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

    // FILE_READ_ATTRIBUTES is the minimum access GetFileInformationByHandleEx
    // (FileIdInfo) needs to read the object identity; a zero-access handle can
    // be rejected (ERROR_ACCESS_DENIED) on some filesystems. We deliberately do
    // NOT request data-read access. FILE_FLAG_BACKUP_SEMANTICS lets the same
    // call open directories as well as files. SAFETY: `wide` is a local
    // NUL-terminated buffer; all other pointers are NULL.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_READ_ATTRIBUTES.0,
            share,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    };
    let handle = match handle {
        Ok(h) if !h.is_invalid() => h,
        _ => return None,
    };

    let mut info = FILE_ID_INFO::default();
    // SAFETY: `handle` is valid; `info` is a correctly sized out-param.
    let rc = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            &mut info as *mut FILE_ID_INFO as *mut core::ffi::c_void,
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    };
    // SAFETY: `handle` came from a successful CreateFileW above.
    unsafe {
        let _ = CloseHandle(handle);
    }
    if rc.is_err() {
        return None;
    }
    Some(ObjectId {
        volume_serial: info.VolumeSerialNumber,
        file_id: u128::from_le_bytes(info.FileId.Identifier),
    })
}

#[cfg(not(any(unix, windows)))]
fn object_id(_path: &str) -> Option<ObjectId> {
    None
}

/// Detect cross-path object conflicts and return a tightened copy of `policy`.
///
/// For each set of policy paths that resolve to the same filesystem object but
/// carry differing intents, the looser-intent paths are moved into the strictest
/// intent's list (`deny` > `readonly` > `readwrite`) and a warning is logged for
/// each moved path. Paths that can't be stat'd are left as-is. This never
/// removes a path entirely or rejects the config; it only tightens intents.
///
/// Returns `Some(new_policy)` only when at least one path's intent was
/// tightened; returns `None` when there is nothing to change (the common case —
/// no symlink / hard-link / bind-mount aliases among the policy paths), so
/// callers can avoid cloning the request entirely.
///
/// Run this *after* the string-level normalization in `config_parser`, close to
/// where the backend builds its mounts.
pub fn normalize_object_conflicts(
    policy: &ContainerPolicy,
    logger: &mut Logger,
) -> Option<ContainerPolicy> {
    if policy.readwrite_paths.is_empty()
        && policy.readonly_paths.is_empty()
        && policy.denied_paths.is_empty()
    {
        return None;
    }

    use std::collections::{HashMap, HashSet};

    // Flatten every (path, intent) in a stable order: rw, then ro, then denied.
    let mut entries: Vec<(String, Intent)> = Vec::with_capacity(
        policy.readwrite_paths.len() + policy.readonly_paths.len() + policy.denied_paths.len(),
    );
    for p in &policy.readwrite_paths {
        entries.push((p.clone(), Intent::ReadWrite));
    }
    for p in &policy.readonly_paths {
        entries.push((p.clone(), Intent::ReadOnly));
    }
    for p in &policy.denied_paths {
        entries.push((p.clone(), Intent::Denied));
    }

    // Group entry indices by object identity (skip unstattable paths).
    let mut groups: HashMap<ObjectId, Vec<usize>> = HashMap::new();
    for (i, (path, _)) in entries.iter().enumerate() {
        if let Some(id) = object_id(path) {
            groups.entry(id).or_default().push(i);
        }
    }

    // Final intent per entry (defaults to its declared intent).
    let mut final_intent: Vec<Intent> = entries.iter().map(|(_, it)| *it).collect();
    let mut changed = false;

    for members in groups.values() {
        if members.len() < 2 {
            continue;
        }
        // Strictest intent among the aliases.
        let target = members.iter().map(|&i| entries[i].1).max().unwrap();
        if members.iter().all(|&i| entries[i].1 == target) {
            // All aliases already share the strictest intent — redundant, not a
            // conflict.
            continue;
        }
        // A representative alias already at the strictest intent (for the message).
        let rep = members
            .iter()
            .copied()
            .find(|&i| entries[i].1 == target)
            .unwrap();
        let rep_path = entries[rep].0.clone();
        for &i in members {
            if entries[i].1 < target {
                logger.log_line(&format!(
                    "Filesystem path '{}' ({}) and '{}' ({}) resolve to the same filesystem \
                     object; applying most-restrictive intent ({}) to '{}'",
                    entries[i].0,
                    entries[i].1.list_name(),
                    rep_path,
                    target.list_name(),
                    target.list_name(),
                    entries[i].0,
                ));
                final_intent[i] = target;
                changed = true;
            }
        }
    }

    // Nothing was tightened: no aliasing conflict, so the caller can keep using
    // the original policy without cloning.
    if !changed {
        return None;
    }

    // Rebuild the three lists from the resolved intents. Within each list,
    // entries keep first-seen order across the flattened rw → ro → denied
    // sequence — so a path tightened from rw to denied lands ahead of paths
    // originally in denied — de-duplicating within each list.
    let mut rw = Vec::new();
    let mut ro = Vec::new();
    let mut dn = Vec::new();
    let mut seen_rw = HashSet::new();
    let mut seen_ro = HashSet::new();
    let mut seen_dn = HashSet::new();
    for (i, (path, _)) in entries.into_iter().enumerate() {
        match final_intent[i] {
            Intent::ReadWrite => {
                if seen_rw.insert(path.clone()) {
                    rw.push(path);
                }
            }
            Intent::ReadOnly => {
                if seen_ro.insert(path.clone()) {
                    ro.push(path);
                }
            }
            Intent::Denied => {
                if seen_dn.insert(path.clone()) {
                    dn.push(path);
                }
            }
        }
    }
    let mut new_policy = policy.clone();
    new_policy.readwrite_paths = rw;
    new_policy.readonly_paths = ro;
    new_policy.denied_paths = dn;
    Some(new_policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logger::{Logger, Mode};

    fn policy(rw: &[&str], ro: &[&str], dn: &[&str]) -> ContainerPolicy {
        ContainerPolicy {
            readwrite_paths: rw.iter().map(|s| s.to_string()).collect(),
            readonly_paths: ro.iter().map(|s| s.to_string()).collect(),
            denied_paths: dn.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn empty_policy_is_noop() {
        let p = ContainerPolicy::default();
        let mut logger = Logger::new(Mode::Buffer);
        assert!(normalize_object_conflicts(&p, &mut logger).is_none());
    }

    #[test]
    fn missing_paths_left_untouched() {
        // Non-existent paths can't be stat'd, so no grouping / no change.
        let p = policy(
            &["/nonexistent/mxc-test-rw"],
            &["/nonexistent/mxc-test-ro"],
            &["/nonexistent/mxc-test-dn"],
        );
        let mut logger = Logger::new(Mode::Buffer);
        assert!(
            normalize_object_conflicts(&p, &mut logger).is_none(),
            "unstattable paths must not trigger a change"
        );
    }

    #[test]
    fn distinct_objects_with_different_intents_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::write(&a, b"a").unwrap();
        std::fs::write(&b, b"b").unwrap();
        let (a, b) = (a.to_str().unwrap(), b.to_str().unwrap());

        let p = policy(&[a], &[b], &[]);
        let mut logger = Logger::new(Mode::Buffer);
        // Distinct objects, no aliasing: nothing to tighten.
        assert!(normalize_object_conflicts(&p, &mut logger).is_none());
    }

    #[test]
    fn same_object_same_intent_is_not_a_conflict() {
        // Two distinct path strings to the same object via a hard link (works on
        // both Unix and Windows, and exercises the platform object_id grouping),
        // both read-write — redundant but not a conflict, so nothing moves.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, b"x").unwrap();
        let alias = dir.path().join("alias");
        std::fs::hard_link(&target, &alias).unwrap();

        let (t, a) = (target.to_str().unwrap(), alias.to_str().unwrap());
        let p = policy(&[t, a], &[], &[]);
        let mut logger = Logger::new(Mode::Buffer);
        // Same object, same intent: no tightening, so no new policy is produced.
        assert!(normalize_object_conflicts(&p, &mut logger).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_rw_and_denied_tightens_to_denied() {
        // `target` is RW, `link` (a symlink to it) is denied → both become denied.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, b"secret").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let (t, l) = (target.to_str().unwrap(), link.to_str().unwrap());

        let p = policy(&[t], &[], &[l]);
        let mut logger = Logger::new(Mode::Buffer);
        let out = normalize_object_conflicts(&p, &mut logger)
            .expect("rw+denied aliases of one object must produce a tightened policy");

        assert!(
            out.readwrite_paths.is_empty(),
            "rw alias of a denied object must be tightened to denied"
        );
        assert!(out.denied_paths.contains(&t.to_string()));
        assert!(out.denied_paths.contains(&l.to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn hardlink_rw_and_readonly_tightens_to_readonly() {
        // Hard link: two names, same inode. RW + RO → both read-only.
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        std::fs::write(&a, b"data").unwrap();
        let b = dir.path().join("b");
        std::fs::hard_link(&a, &b).unwrap();
        let (a, b) = (a.to_str().unwrap(), b.to_str().unwrap());

        let p = policy(&[a], &[b], &[]);
        let mut logger = Logger::new(Mode::Buffer);
        let out = normalize_object_conflicts(&p, &mut logger)
            .expect("rw+ro aliases of one object must produce a tightened policy");

        assert!(
            out.readwrite_paths.is_empty(),
            "rw alias of a read-only object must be tightened to read-only"
        );
        assert!(out.readonly_paths.contains(&a.to_string()));
        assert!(out.readonly_paths.contains(&b.to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn denied_wins_over_both_rw_and_ro_aliases() {
        // Three aliases of one object across all three lists → all denied.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("obj");
        std::fs::write(&target, b"x").unwrap();
        let l1 = dir.path().join("l1");
        let l2 = dir.path().join("l2");
        std::os::unix::fs::symlink(&target, &l1).unwrap();
        std::os::unix::fs::symlink(&target, &l2).unwrap();
        let (t, a, b) = (
            target.to_str().unwrap(),
            l1.to_str().unwrap(),
            l2.to_str().unwrap(),
        );

        // t = rw, a = ro, b = denied.
        let p = policy(&[t], &[a], &[b]);
        let mut logger = Logger::new(Mode::Buffer);
        let out = normalize_object_conflicts(&p, &mut logger)
            .expect("three aliases across all lists must produce a tightened policy");

        assert!(out.readwrite_paths.is_empty());
        assert!(out.readonly_paths.is_empty());
        assert_eq!(out.denied_paths.len(), 3);
    }
}
