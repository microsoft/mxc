// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Filesystem-policy **most-specific-path-wins** mount ordering.
//!
//! The Linux containment backends (Bubblewrap, LXC) realise the filesystem
//! policy as an ordered list of mounts, and the kernel applies "the last mount
//! at a path wins". Overlap between a `readwritePaths` / `readonlyPaths` /
//! `deniedPaths` entry and one of its ancestors or descendants is therefore
//! resolved by **emission order**, not by path specificity.
//!
//! This module normalizes policy paths by component, collapses exact-path
//! conflicts with **most-restrictive-wins** (`denied` > `readonly` >
//! `readwrite`), and returns a **shallow-to-deep** plan so that a backend which
//! emits the plan in order has the deepest (most specific) intent win at every
//! path, regardless of which list it came from.

use crate::models::ContainerPolicy;

/// The access intent a resolved mount carries into the backend, mapped from the
/// policy list the path came from. Ordered least- to most-restrictive so an
/// exact same-path tie resolves most-restrictive-wins.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum FsIntent {
    /// From `readwritePaths` — read+write bind.
    ReadWrite,
    /// From `readonlyPaths` — read-only bind.
    ReadOnly,
    /// From `deniedPaths` — masked (invisible) inside the sandbox.
    Denied,
}

/// A single policy path paired with its intent, ready for a backend to emit as
/// a mount. Ordered relative to its peers by [`resolve_path_plan`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ResolvedMount {
    /// The host path exactly as it appears in the policy (not normalized — the
    /// backend still owns path-to-mount translation).
    pub path: String,
    /// The intent this path was declared with.
    pub intent: FsIntent,
}

/// A path split into its non-empty components, so `/data` and `/data/` compare
/// equal and `/data/secrets` is recognized as a descendant of `/data`. Splits on
/// both `/` and `\` so Windows-style host paths compare the same way.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
struct PathKey(Vec<String>);

impl PathKey {
    fn from_path(path: &str) -> Self {
        Self(
            path.split(['/', '\\'])
                .filter(|component| !component.is_empty())
                .map(str::to_string)
                .collect(),
        )
    }

    fn depth(&self) -> usize {
        self.0.len()
    }

    /// Test-only: whether `self` is an ancestor of (or equal to) `other`. Only
    /// the semantic-check oracle in the tests uses this, so it is gated to test
    /// builds to keep the production surface free of dead code.
    #[cfg(test)]
    fn is_prefix_of(&self, other: &Self) -> bool {
        self.0.len() <= other.0.len() && self.0.iter().zip(other.0.iter()).all(|(a, b)| a == b)
    }
}

#[derive(Clone, Debug)]
struct Candidate {
    path: String,
    key: PathKey,
    intent: FsIntent,
    sequence: usize,
}

/// Resolve the three policy lists into a single shallow-to-deep ordered plan.
///
/// Exact same-path conflicts are resolved *upstream* — the config parser's
/// string-level `normalize_filesystem_paths` and each runner's object-identity
/// `filesystem_object::normalize_object_conflicts` — so this function only
/// **orders**. It emits shallow-to-deep and, for any same-path entries that still
/// arrive, places the most-restrictive intent last, so a backend applying "the
/// last mount at a path wins" resolves the tie most-restrictive-wins.
pub fn resolve_path_plan(
    readwrite_paths: &[String],
    readonly_paths: &[String],
    denied_paths: &[String],
) -> Vec<ResolvedMount> {
    let mut candidates =
        Vec::with_capacity(readwrite_paths.len() + readonly_paths.len() + denied_paths.len());
    let mut sequence = 0;
    for (paths, intent) in [
        (readwrite_paths, FsIntent::ReadWrite),
        (readonly_paths, FsIntent::ReadOnly),
        (denied_paths, FsIntent::Denied),
    ] {
        for path in paths {
            candidates.push(Candidate {
                path: path.clone(),
                key: PathKey::from_path(path),
                intent,
                sequence,
            });
            sequence += 1;
        }
    }

    // Order shallow-to-deep so a backend that emits the plan in order lets the
    // deepest (most specific) intent win at every path. Equal-depth ties keep
    // their original category order (read-write, then read-only, then denied),
    // so an exact same-path duplicate that survives upstream normalization is
    // still resolved most-restrictive-wins by emission order: denied is added
    // last, sorts last among equal-depth peers, and a backend applying "the last
    // mount at a path wins" therefore lands on it.
    //
    // This resolver deliberately does *not* re-collapse exact same-path
    // conflicts — that is already done upstream and duplicating it here adds no
    // correctness: the config parser's `normalize_filesystem_paths` drops a
    // string-equal path from a looser list, and each runner's
    // `filesystem_object::normalize_object_conflicts` tightens same-object
    // aliases to the strictest intent before this runs.
    candidates.sort_by(|a, b| {
        a.key
            .depth()
            .cmp(&b.key.depth())
            .then_with(|| a.sequence.cmp(&b.sequence))
    });

    candidates
        .into_iter()
        .map(|candidate| ResolvedMount {
            path: candidate.path,
            intent: candidate.intent,
        })
        .collect()
}

/// Convenience wrapper over [`resolve_path_plan`] for a whole [`ContainerPolicy`].
pub fn resolve_mount_order(policy: &ContainerPolicy) -> Vec<ResolvedMount> {
    resolve_path_plan(
        &policy.readwrite_paths,
        &policy.readonly_paths,
        &policy.denied_paths,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(paths: &[&str]) -> Vec<String> {
        paths.iter().map(|path| (*path).to_string()).collect()
    }

    fn plan(rw: &[&str], ro: &[&str], denied: &[&str]) -> Vec<ResolvedMount> {
        resolve_path_plan(&strings(rw), &strings(ro), &strings(denied))
    }

    fn order(mounts: &[ResolvedMount]) -> Vec<(&str, FsIntent)> {
        mounts
            .iter()
            .map(|mount| (mount.path.as_str(), mount.intent))
            .collect()
    }

    /// Test oracle: the effective intent a resolved `plan` assigns to `path` —
    /// the intent of the deepest plan entry that is an ancestor of (or equal to)
    /// `path`, with most-restrictive-wins breaking an exact-depth tie. `None` if
    /// no entry covers the path. This models what a backend's "last mount at a
    /// path wins" ultimately resolves to, so tests can assert semantics instead
    /// of raw emission order.
    fn effective_intent(plan: &[ResolvedMount], path: &str) -> Option<FsIntent> {
        let query = PathKey::from_path(path);
        plan.iter()
            .filter_map(|mount| {
                let key = PathKey::from_path(&mount.path);
                key.is_prefix_of(&query)
                    .then_some((key.depth(), mount.intent))
            })
            .max_by(|(left_depth, left_intent), (right_depth, right_intent)| {
                left_depth
                    .cmp(right_depth)
                    .then_with(|| left_intent.cmp(right_intent))
            })
            .map(|(_, intent)| intent)
    }

    #[test]
    fn nested_paths_are_ordered_shallow_to_deep() {
        let resolved = plan(&["/workspace"], &["/workspace/.git"], &["/workspace/.env"]);
        assert_eq!(
            order(&resolved),
            vec![
                ("/workspace", FsIntent::ReadWrite),
                ("/workspace/.git", FsIntent::ReadOnly),
                ("/workspace/.env", FsIntent::Denied),
            ]
        );
        assert_eq!(
            effective_intent(&resolved, "/workspace/src/main.rs"),
            Some(FsIntent::ReadWrite)
        );
        assert_eq!(
            effective_intent(&resolved, "/workspace/.git/config"),
            Some(FsIntent::ReadOnly)
        );
        assert_eq!(
            effective_intent(&resolved, "/workspace/.env"),
            Some(FsIntent::Denied)
        );
    }

    #[test]
    fn exact_path_duplicates_emit_most_restrictive_last() {
        // Exact same-path conflicts are collapsed upstream (config-parser string
        // normalization + object-identity normalization), so the resolver no
        // longer re-collapses them. When identical paths do reach it, it orders
        // them so the most-restrictive intent is emitted LAST — a backend
        // applying "the last mount at a path wins" therefore lands on denied,
        // and the semantic oracle agrees.
        let resolved = plan(&["/workspace"], &["/workspace"], &["/workspace"]);
        assert_eq!(
            resolved
                .last()
                .map(|mount| (mount.path.as_str(), mount.intent)),
            Some(("/workspace", FsIntent::Denied))
        );
        assert_eq!(
            effective_intent(&resolved, "/workspace/file"),
            Some(FsIntent::Denied)
        );
    }

    #[test]
    fn readonly_emitted_after_readwrite_for_same_path() {
        // Same path in read-write and read-only: read-only is emitted last so it
        // wins by emission order, and the oracle resolves to read-only.
        let resolved = plan(&["/workspace/"], &["/workspace"], &[]);
        assert_eq!(
            resolved.last().map(|mount| mount.intent),
            Some(FsIntent::ReadOnly)
        );
        assert_eq!(
            effective_intent(&resolved, "/workspace/file"),
            Some(FsIntent::ReadOnly)
        );
    }

    #[test]
    fn trailing_slash_variants_resolve_most_restrictive_by_order() {
        // "/data" (read-write) and "/data/" (denied) are the same logical path
        // but differ by a trailing slash, so the upstream string-level
        // normalization does not merge them. The resolver does not collapse them
        // either (that would duplicate the upstream / object-identity
        // normalization); instead it emits denied last, so emission order yields
        // most-restrictive-wins and the semantic oracle agrees.
        let resolved = plan(&["/data"], &[], &["/data/"]);
        assert_eq!(
            resolved.last().map(|mount| mount.intent),
            Some(FsIntent::Denied)
        );
        assert_eq!(
            effective_intent(&resolved, "/data/file"),
            Some(FsIntent::Denied)
        );

        // Swap the trailing slash onto the read-write spelling: denied still
        // sorts last and wins.
        let resolved = plan(&["/data/"], &[], &["/data"]);
        assert_eq!(
            resolved.last().map(|mount| mount.intent),
            Some(FsIntent::Denied)
        );
    }

    #[test]
    fn siblings_do_not_override_each_other() {
        let resolved = plan(&["/workspace/src"], &["/workspace/docs"], &[]);
        assert_eq!(
            effective_intent(&resolved, "/workspace/src/lib.rs"),
            Some(FsIntent::ReadWrite)
        );
        assert_eq!(
            effective_intent(&resolved, "/workspace/docs/index.md"),
            Some(FsIntent::ReadOnly)
        );
        assert_eq!(
            effective_intent(&resolved, "/workspace/tests/test.rs"),
            None
        );
    }

    #[test]
    fn unrelated_paths_remain_independent() {
        let resolved = plan(&["/srv/app/data"], &["/usr"], &["/opt/secret"]);
        assert_eq!(
            order(&resolved),
            vec![
                ("/usr", FsIntent::ReadOnly),
                ("/opt/secret", FsIntent::Denied),
                ("/srv/app/data", FsIntent::ReadWrite),
            ]
        );
        assert_eq!(effective_intent(&resolved, "/var/log/app.log"), None);
    }

    #[test]
    fn deep_override_of_shallow_deny_wins_for_child_only() {
        let resolved = plan(&["/data/secrets"], &[], &["/data"]);
        assert_eq!(
            order(&resolved),
            vec![
                ("/data", FsIntent::Denied),
                ("/data/secrets", FsIntent::ReadWrite),
            ]
        );
        assert_eq!(effective_intent(&resolved, "/data"), Some(FsIntent::Denied));
        assert_eq!(
            effective_intent(&resolved, "/data/secrets/file"),
            Some(FsIntent::ReadWrite)
        );
    }

    #[test]
    fn component_prefix_does_not_match_partial_component() {
        let resolved = plan(&["/workspace"], &[], &[]);
        assert_eq!(effective_intent(&resolved, "/workspace2/file"), None);
    }

    #[test]
    fn backslash_paths_are_compared_by_components() {
        let resolved = plan(&["C:\\workspace"], &["C:\\workspace\\.git\\"], &[]);
        assert_eq!(
            effective_intent(&resolved, "C:\\workspace\\.git\\config"),
            Some(FsIntent::ReadOnly)
        );
    }

    #[test]
    fn empty_policy_yields_no_mounts() {
        assert!(plan(&[], &[], &[]).is_empty());
    }
}
