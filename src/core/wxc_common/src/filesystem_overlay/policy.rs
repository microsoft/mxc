// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Policy → plan lowering.
//!
//! Walks the three vectors of a [`crate::models::ContainerPolicy`]
//! and decides which primitive should enforce each entry. The
//! decision tree is documented in
//! `~/.copilot/session-state/<id>/plan.md` §2.
//!
//! # Current (Phase C-1) policy
//!
//! After the empirical finding that BindFlt / UnionFS / WCIFS all
//! require admin (see plan §10 decision 4), the production path is
//! **ProjFS-only**. The classifier emits:
//!
//! - `OverlayPrimitive::ProjFsBranch { mode: ReadOnly, … }` for each
//!   entry in `readonly_paths`.
//! - `OverlayPrimitive::ProjFsBranch { mode: ReadWrite, … }` for
//!   each entry in `readwrite_paths`.
//! - For each entry in `denied_paths`, find a containing branch
//!   (canonical-path prefix) and append the denied path to that
//!   branch's `deny_subpaths`. Denied paths with no containing
//!   branch are structurally invisible already and produce no
//!   primitive.
//!
//! Nested rw/ro pairs (e.g. `readonly: C:\Users\u` overlapping with
//! `readwrite: C:\Users\u\scratch`) are rejected with
//! `OverlayError::Classify` until a Phase C-2 follow-on adds proper
//! composition.
//!
//! # Pureness
//!
//! `classify` is pure given its inputs (it does call
//! `fs::canonicalize` on each path; that's a filesystem op but
//! deterministic for a given on-disk state). It can be unit-tested
//! on Windows hosts with a `tempfile::tempdir` for the policy
//! paths.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::filesystem_overlay::error::OverlayError;
use crate::filesystem_overlay::plan::{BranchMode, OverlayPlan, OverlayPrimitive};
use crate::models::ContainerPolicy;

/// Context the classifier needs from the surrounding system.
#[derive(Debug, Clone)]
pub struct AcContext {
    /// AppContainer SID in `S-1-15-2-…` form.
    pub ac_sid: String,
    /// `true` when the `Client-ProjFS` optional feature is enabled
    /// on this host.
    pub projfs_available: bool,
    /// `true` when `BindFltApi.dll` loaded and the entry points
    /// resolved. (Empirically requires admin to actually install
    /// mappings; the classifier still gates emission of BindFlt
    /// primitives on this so non-admin hosts surface a clear
    /// "no BindFlt available" earlier.)
    pub bindflt_available: bool,
}

/// Classify a `ContainerPolicy` into a deterministic `OverlayPlan`.
pub fn classify(policy: &ContainerPolicy, ctx: &AcContext) -> Result<OverlayPlan, OverlayError> {
    if !ctx.projfs_available {
        return Err(OverlayError::PrimitiveUnavailable {
            primitive: "projfs",
            reason: "Client-ProjFS feature not enabled on this host".to_string(),
        });
    }

    // Each branch carries its host_path (canonical), branch_name,
    // mode, and the set of denied subpaths inside it.
    struct InProgressBranch {
        host_path: PathBuf,
        branch_name: String,
        mode: BranchMode,
        deny_subpaths: Vec<PathBuf>,
    }

    let mut branches: Vec<InProgressBranch> = Vec::new();
    let mut seen_branch_names: HashSet<String> = HashSet::new();

    // 1. Canonicalize and add rw/ro entries.
    for (paths, mode) in [
        (&policy.readwrite_paths, BranchMode::ReadWrite),
        (&policy.readonly_paths, BranchMode::ReadOnly),
    ] {
        for raw in paths {
            let p = PathBuf::from(raw);
            let canonical = std::fs::canonicalize(&p).map_err(|e| {
                OverlayError::Classify(format!("canonicalize({}): {e}", p.display()))
            })?;
            let branch_name = canonical
                .file_name()
                .ok_or_else(|| {
                    OverlayError::Classify(format!(
                        "policy path has no final component: {}",
                        canonical.display()
                    ))
                })?
                .to_string_lossy()
                .into_owned();
            let lower = branch_name.to_ascii_lowercase();
            if !seen_branch_names.insert(lower) {
                return Err(OverlayError::Classify(format!(
                    "branch name '{branch_name}' ambiguous; refusing to emit two ProjFS branches with the same leaf name (paths: {} and one earlier)",
                    canonical.display()
                )));
            }
            // Reject nested rw/ro pairs (e.g. ro:C:\Users\u and
            // rw:C:\Users\u\scratch). Phase C-2 will add proper
            // composition.
            for existing in &branches {
                if canonical_starts_with(&canonical, &existing.host_path)
                    || canonical_starts_with(&existing.host_path, &canonical)
                {
                    return Err(OverlayError::Classify(format!(
                        "policy paths {} and {} are nested; nested rw/ro composition is a Phase C-2 follow-up",
                        canonical.display(),
                        existing.host_path.display()
                    )));
                }
            }
            branches.push(InProgressBranch {
                host_path: canonical,
                branch_name,
                mode,
                deny_subpaths: Vec::new(),
            });
        }
    }

    // 2. For each denied path, find a containing branch and append.
    for raw in &policy.denied_paths {
        let p = PathBuf::from(raw);
        // Denied paths may not exist on disk yet (the user is
        // forbidding something the AC might try to create). Try to
        // canonicalize; if it fails, fall back to canonicalising the
        // deepest existing ancestor and appending the rest.
        let canonical = canonicalize_best_effort(&p);
        let mut placed = false;
        for branch in branches.iter_mut() {
            if canonical_starts_with(&canonical, &branch.host_path) {
                branch.deny_subpaths.push(canonical.clone());
                placed = true;
                break;
            }
        }
        // If the denied path isn't inside any branch, it's
        // structurally invisible already (no primitive projects it).
        let _ = placed;
    }

    // 3. Emit primitives in stable order: rw/ro by insertion order.
    let primitives = branches
        .into_iter()
        .map(|b| OverlayPrimitive::ProjFsBranch {
            host_path: b.host_path,
            branch_name: b.branch_name,
            mode: b.mode,
            deny_subpaths: b.deny_subpaths,
        })
        .collect();

    Ok(OverlayPlan { primitives })
}

/// Case-insensitive Windows-style "is `child` under `parent`?".
/// Both arguments should be canonicalised before this is called.
fn canonical_starts_with(child: &Path, parent: &Path) -> bool {
    let cs = path_components_lower(child);
    let ps = path_components_lower(parent);
    if ps.len() > cs.len() {
        return false;
    }
    for (i, c) in ps.iter().enumerate() {
        if cs[i] != *c {
            return false;
        }
    }
    true
}

fn path_components_lower(p: &Path) -> Vec<String> {
    p.components()
        .map(|c| c.as_os_str().to_string_lossy().to_ascii_lowercase())
        .collect()
}

/// Normalise a non-canonicalised path: convert forward slashes to
/// backslashes; lowercase the drive letter. Used as a fallback when
/// the path can't be canonicalised at all.
fn normalise_path(p: &Path) -> PathBuf {
    let s = p.to_string_lossy().replace('/', "\\");
    PathBuf::from(s)
}

/// Canonicalise as much of the path as exists. For a path
/// `C:\Users\u\does-not-exist\foo`, canonicalises `C:\Users\u` (the
/// deepest existing ancestor) and appends `does-not-exist\foo`. The
/// result is comparable with [`canonical_starts_with`] against
/// fully-canonical branch paths even when the leaf doesn't exist
/// on disk.
fn canonicalize_best_effort(p: &Path) -> PathBuf {
    if let Ok(c) = std::fs::canonicalize(p) {
        return c;
    }
    let mut current = p.to_path_buf();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    while !current.exists() {
        if let Some(name) = current.file_name() {
            tail.push(name.to_os_string());
        }
        if !current.pop() {
            // Walked off the top of the tree without finding an
            // existing prefix — return normalised input.
            return normalise_path(p);
        }
    }
    let mut canonical = match std::fs::canonicalize(&current) {
        Ok(c) => c,
        Err(_) => return normalise_path(p),
    };
    for t in tail.iter().rev() {
        canonical.push(t);
    }
    canonical
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> AcContext {
        AcContext {
            ac_sid: "S-1-15-2-test".into(),
            projfs_available: true,
            bindflt_available: false,
        }
    }

    #[test]
    fn empty_policy_yields_empty_plan() {
        let p = ContainerPolicy::default();
        let plan = classify(&p, &ctx()).expect("empty policy classifies cleanly");
        assert!(plan.primitives.is_empty());
    }

    #[test]
    fn projfs_unavailable_surfaces_primitive_unavailable() {
        let p = ContainerPolicy::default();
        let mut c = ctx();
        c.projfs_available = false;
        let err = classify(&p, &c).expect_err("projfs unavailable should fail");
        match err {
            OverlayError::PrimitiveUnavailable { primitive, .. } => {
                assert_eq!(primitive, "projfs");
            }
            other => panic!("expected PrimitiveUnavailable, got {other:?}"),
        }
    }

    #[test]
    fn ro_path_becomes_projfs_ro_branch() {
        let td = tempfile::tempdir().unwrap();
        let p = ContainerPolicy {
            readonly_paths: vec![td.path().to_string_lossy().into_owned()],
            ..Default::default()
        };
        let plan = classify(&p, &ctx()).expect("classify");
        assert_eq!(plan.primitives.len(), 1);
        match &plan.primitives[0] {
            OverlayPrimitive::ProjFsBranch {
                host_path,
                mode,
                deny_subpaths,
                ..
            } => {
                assert_eq!(*mode, BranchMode::ReadOnly);
                // canonicalize on Windows adds the `\\?\` prefix; check by suffix.
                let p_str = host_path.to_string_lossy();
                let want_suffix = td
                    .path()
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                assert!(p_str.ends_with(&want_suffix), "got {p_str}");
                assert!(deny_subpaths.is_empty());
            }
            other => panic!("expected ProjFsBranch, got {other:?}"),
        }
    }

    #[test]
    fn rw_and_ro_disjoint_paths_become_separate_branches() {
        let td_ro = tempfile::tempdir().unwrap();
        let td_rw = tempfile::tempdir().unwrap();
        let p = ContainerPolicy {
            readonly_paths: vec![td_ro.path().to_string_lossy().into_owned()],
            readwrite_paths: vec![td_rw.path().to_string_lossy().into_owned()],
            ..Default::default()
        };
        let plan = classify(&p, &ctx()).expect("classify");
        assert_eq!(plan.primitives.len(), 2);
        let modes: Vec<BranchMode> = plan
            .primitives
            .iter()
            .map(|p| match p {
                OverlayPrimitive::ProjFsBranch { mode, .. } => *mode,
                _ => panic!("non-ProjFs primitive"),
            })
            .collect();
        // RW first (insertion order matches the (paths, mode) tuple loop).
        assert_eq!(modes, vec![BranchMode::ReadWrite, BranchMode::ReadOnly]);
    }

    #[test]
    fn nested_rw_under_ro_is_rejected() {
        let td_outer = tempfile::tempdir().unwrap();
        let inner = td_outer.path().join("inner");
        std::fs::create_dir(&inner).unwrap();
        let p = ContainerPolicy {
            readonly_paths: vec![td_outer.path().to_string_lossy().into_owned()],
            readwrite_paths: vec![inner.to_string_lossy().into_owned()],
            ..Default::default()
        };
        let err = classify(&p, &ctx()).expect_err("nested entries rejected");
        match err {
            OverlayError::Classify(s) => assert!(s.contains("nested"), "got {s}"),
            other => panic!("expected Classify, got {other:?}"),
        }
    }

    #[test]
    fn denied_path_inside_branch_is_attached_to_that_branch() {
        let td = tempfile::tempdir().unwrap();
        let denied = td.path().join(".ssh");
        std::fs::create_dir(&denied).unwrap();
        let p = ContainerPolicy {
            readonly_paths: vec![td.path().to_string_lossy().into_owned()],
            denied_paths: vec![denied.to_string_lossy().into_owned()],
            ..Default::default()
        };
        let plan = classify(&p, &ctx()).expect("classify");
        assert_eq!(plan.primitives.len(), 1);
        match &plan.primitives[0] {
            OverlayPrimitive::ProjFsBranch { deny_subpaths, .. } => {
                assert_eq!(
                    deny_subpaths.len(),
                    1,
                    "denied path should land in branch deny_subpaths"
                );
                let d_str = deny_subpaths[0].to_string_lossy();
                assert!(d_str.ends_with(".ssh"), "got {d_str}");
            }
            other => panic!("expected ProjFsBranch, got {other:?}"),
        }
    }

    #[test]
    fn denied_path_outside_any_branch_is_silently_dropped() {
        let td = tempfile::tempdir().unwrap();
        let unrelated = tempfile::tempdir().unwrap();
        let denied = unrelated.path().join("nope");
        // Don't create it — the denied path doesn't need to exist.
        let p = ContainerPolicy {
            readonly_paths: vec![td.path().to_string_lossy().into_owned()],
            denied_paths: vec![denied.to_string_lossy().into_owned()],
            ..Default::default()
        };
        let plan = classify(&p, &ctx()).expect("classify");
        assert_eq!(plan.primitives.len(), 1);
        match &plan.primitives[0] {
            OverlayPrimitive::ProjFsBranch { deny_subpaths, .. } => {
                assert!(
                    deny_subpaths.is_empty(),
                    "denied path outside any branch should produce no primitive"
                );
            }
            other => panic!("expected ProjFsBranch, got {other:?}"),
        }
    }

    #[test]
    fn denied_nonexistent_path_inside_branch_still_attaches() {
        let td = tempfile::tempdir().unwrap();
        let denied = td.path().join("does-not-exist-yet");
        // Intentionally do not create `denied`.
        let p = ContainerPolicy {
            readonly_paths: vec![td.path().to_string_lossy().into_owned()],
            denied_paths: vec![denied.to_string_lossy().into_owned()],
            ..Default::default()
        };
        let plan = classify(&p, &ctx()).expect("classify");
        match &plan.primitives[0] {
            OverlayPrimitive::ProjFsBranch { deny_subpaths, .. } => {
                assert_eq!(deny_subpaths.len(), 1);
            }
            other => panic!("expected ProjFsBranch, got {other:?}"),
        }
    }

    #[test]
    fn ambiguous_branch_names_rejected() {
        let outer_a = tempfile::tempdir().unwrap();
        let outer_b = tempfile::tempdir().unwrap();
        // Force same leaf name in both.
        let a = outer_a.path().join("same-name");
        let b = outer_b.path().join("same-name");
        std::fs::create_dir(&a).unwrap();
        std::fs::create_dir(&b).unwrap();
        let p = ContainerPolicy {
            readonly_paths: vec![a.to_string_lossy().into_owned()],
            readwrite_paths: vec![b.to_string_lossy().into_owned()],
            ..Default::default()
        };
        let err = classify(&p, &ctx()).expect_err("ambiguous branch names rejected");
        match err {
            OverlayError::Classify(s) => assert!(s.contains("ambiguous"), "got {s}"),
            other => panic!("expected Classify, got {other:?}"),
        }
    }

    #[test]
    fn nonexistent_rw_path_surfaces_classify_error() {
        let p = ContainerPolicy {
            readwrite_paths: vec![r"C:\__definitely_not_a_real_path__\xyzzy".to_string()],
            ..Default::default()
        };
        let err = classify(&p, &ctx()).expect_err("nonexistent rw should fail");
        match err {
            OverlayError::Classify(s) => assert!(s.contains("canonicalize"), "got {s}"),
            other => panic!("expected Classify, got {other:?}"),
        }
    }

    #[test]
    fn canonical_starts_with_basic() {
        assert!(canonical_starts_with(
            Path::new(r"C:\Users\u\foo"),
            Path::new(r"C:\Users\u"),
        ));
        assert!(canonical_starts_with(
            Path::new(r"c:\users\u\foo"),
            Path::new(r"C:\USERS\u"),
        ));
        assert!(!canonical_starts_with(
            Path::new(r"C:\Users\v"),
            Path::new(r"C:\Users\u"),
        ));
        // Same path (degenerate "starts with").
        assert!(canonical_starts_with(
            Path::new(r"C:\Users\u"),
            Path::new(r"C:\Users\u"),
        ));
    }
}
