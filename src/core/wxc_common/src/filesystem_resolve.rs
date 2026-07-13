// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Filesystem-policy **most-specific-path-wins** mount ordering (roadmap D4).
//!
//! The Linux containment backends (Bubblewrap, LXC) realise the filesystem
//! policy as an ordered list of mounts, and the kernel applies "the last mount
//! at a path wins". Overlap between a `readwritePaths` / `readonlyPaths` /
//! `deniedPaths` entry and one of its ancestors or descendants is therefore
//! resolved by **emission order**, not by path specificity. Emitting the three
//! lists in a fixed category order (rw, then ro, then denied) gets some overlaps
//! right by luck and others wrong: e.g. `readwritePaths: ["/data/secrets"]` with
//! `deniedPaths: ["/data"]` emits the deep read-write bind first and then masks
//! the whole `/data` subtree over it, so the *less* specific intent wins.
//!
//! [`resolve_mount_order`] fixes this by returning the policy paths ordered so
//! that a **deeper (more specific) path is always emitted after — and therefore
//! overrides — any shallower ancestor** with a different intent. A backend then
//! emits its baseline / virtual filesystems first and walks this ordered list
//! last, so the most-specific policy intent wins at every path regardless of
//! which list it came from.
//!
//! This resolver only **reorders**; it does not drop or merge entries. Exact
//! same-path conflicts across lists (e.g. the same object in both `readonlyPaths`
//! and `deniedPaths`) are resolved upstream to the most-restrictive intent by
//! [`crate::filesystem_object::normalize_object_conflicts`], which every runner
//! calls before building its mounts — so no exact-duplicate same-path conflicts
//! reach this function.

use crate::models::ContainerPolicy;

/// The access intent a resolved mount carries into the backend, mapped from the
/// policy list the path came from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FsIntent {
    /// From `readwritePaths` — read+write bind.
    ReadWrite,
    /// From `readonlyPaths` — read-only bind.
    ReadOnly,
    /// From `deniedPaths` — masked (invisible) inside the sandbox.
    Denied,
}

/// A single policy path paired with its intent, ready for a backend to emit as a
/// mount. Ordered relative to its peers by [`resolve_mount_order`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ResolvedMount {
    /// The host path exactly as it appears in the policy (not normalized — the
    /// backend still owns path-to-mount translation).
    pub path: String,
    /// The intent this path was declared with.
    pub intent: FsIntent,
}

/// Number of path components in `path`, used as the specificity key: a deeper
/// path (more components) is more specific. Splits on both `/` and `\` and
/// ignores empty segments so a leading slash and any trailing slash do not skew
/// the count (`/data` and `/data/` are both depth 1; `/data/secrets` is depth 2).
fn specificity(path: &str) -> usize {
    path.split(['/', '\\']).filter(|s| !s.is_empty()).count()
}

/// Orders the policy's filesystem paths so that a more-specific (deeper) path is
/// always emitted **after** — and therefore overrides — a less-specific ancestor
/// with a different intent, for any backend that applies mounts in order with
/// "last at a path wins" semantics.
///
/// The sort is **stable** and ascending by specificity, so:
/// - shallower paths come first, deeper paths last (deepest wins);
/// - paths of equal depth keep their category order (read-write, then
///   read-only, then denied), matching the backends' historical emission order
///   so an exact-depth tie still resolves denied-over-ro-over-rw.
///
/// Assumes [`crate::filesystem_object::normalize_object_conflicts`] has already
/// collapsed any exact same-path conflicts; this function does not merge or drop
/// entries, it only reorders them.
pub fn resolve_mount_order(policy: &ContainerPolicy) -> Vec<ResolvedMount> {
    // Collect in category order (rw, ro, denied). A stable sort below preserves
    // this order for equal-depth ties, so denied still wins over ro over rw at
    // the same path depth — matching the backends' pre-resolver emission order.
    let mut mounts: Vec<ResolvedMount> = Vec::with_capacity(
        policy.readwrite_paths.len() + policy.readonly_paths.len() + policy.denied_paths.len(),
    );
    for path in &policy.readwrite_paths {
        mounts.push(ResolvedMount {
            path: path.clone(),
            intent: FsIntent::ReadWrite,
        });
    }
    for path in &policy.readonly_paths {
        mounts.push(ResolvedMount {
            path: path.clone(),
            intent: FsIntent::ReadOnly,
        });
    }
    for path in &policy.denied_paths {
        mounts.push(ResolvedMount {
            path: path.clone(),
            intent: FsIntent::Denied,
        });
    }

    mounts.sort_by_key(|m| specificity(&m.path));
    mounts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(rw: &[&str], ro: &[&str], denied: &[&str]) -> ContainerPolicy {
        ContainerPolicy {
            readwrite_paths: rw.iter().map(|s| s.to_string()).collect(),
            readonly_paths: ro.iter().map(|s| s.to_string()).collect(),
            denied_paths: denied.iter().map(|s| s.to_string()).collect(),
            ..ContainerPolicy::default()
        }
    }

    fn order(mounts: &[ResolvedMount]) -> Vec<(&str, FsIntent)> {
        mounts.iter().map(|m| (m.path.as_str(), m.intent)).collect()
    }

    #[test]
    fn deeper_denied_child_comes_after_shallower_rw_parent() {
        // rw /data, denied /data/secrets: the deep denied path must be emitted
        // last so it masks the subtree even though /data is read-write.
        let p = policy(&["/data"], &[], &["/data/secrets"]);
        let resolved = resolve_mount_order(&p);
        assert_eq!(
            order(&resolved),
            vec![
                ("/data", FsIntent::ReadWrite),
                ("/data/secrets", FsIntent::Denied),
            ]
        );
    }

    #[test]
    fn deeper_rw_child_comes_after_shallower_denied_parent() {
        // denied /data, rw /data/secrets: previously the /data tmpfs was emitted
        // last and shadowed the deep bind (less-specific won). The resolver must
        // now emit the deeper /data/secrets rw mount last so it wins.
        let p = policy(&["/data/secrets"], &[], &["/data"]);
        let resolved = resolve_mount_order(&p);
        assert_eq!(
            order(&resolved),
            vec![
                ("/data", FsIntent::Denied),
                ("/data/secrets", FsIntent::ReadWrite),
            ]
        );
    }

    #[test]
    fn three_level_nesting_orders_shallow_to_deep() {
        let p = policy(&["/a/b/c"], &["/a"], &["/a/b"]);
        let resolved = resolve_mount_order(&p);
        assert_eq!(
            order(&resolved),
            vec![
                ("/a", FsIntent::ReadOnly),
                ("/a/b", FsIntent::Denied),
                ("/a/b/c", FsIntent::ReadWrite),
            ]
        );
    }

    #[test]
    fn equal_depth_keeps_category_order_rw_ro_denied() {
        // Three sibling paths at the same depth: order is stable and follows the
        // category order so a same-depth tie resolves denied last (wins).
        let p = policy(&["/x"], &["/y"], &["/z"]);
        let resolved = resolve_mount_order(&p);
        assert_eq!(
            order(&resolved),
            vec![
                ("/x", FsIntent::ReadWrite),
                ("/y", FsIntent::ReadOnly),
                ("/z", FsIntent::Denied),
            ]
        );
    }

    #[test]
    fn trailing_slash_does_not_change_specificity() {
        // "/data/" and "/data" are the same depth; the deeper child still wins.
        let p = policy(&["/data/"], &[], &["/data/secrets"]);
        let resolved = resolve_mount_order(&p);
        assert_eq!(
            order(&resolved),
            vec![
                ("/data/", FsIntent::ReadWrite),
                ("/data/secrets", FsIntent::Denied),
            ]
        );
    }

    #[test]
    fn non_overlapping_paths_pass_through_by_depth() {
        // Unrelated paths: no overlap to resolve, just ordered shallow-to-deep.
        let p = policy(&["/srv/app/data"], &["/usr"], &["/opt/secret"]);
        let resolved = resolve_mount_order(&p);
        assert_eq!(
            order(&resolved),
            vec![
                ("/usr", FsIntent::ReadOnly),
                ("/opt/secret", FsIntent::Denied),
                ("/srv/app/data", FsIntent::ReadWrite),
            ]
        );
    }

    #[test]
    fn empty_policy_yields_no_mounts() {
        assert!(resolve_mount_order(&ContainerPolicy::default()).is_empty());
    }
}
