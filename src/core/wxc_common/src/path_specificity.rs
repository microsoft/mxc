// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Filesystem-policy most-specific-path-wins resolution.
//!
//! Backends such as LXC and Bubblewrap apply filesystem mount operations in
//! order. This module normalizes policy paths by component, collapses exact-path
//! conflicts with most-restrictive-wins (`denied` > `readonly` > `readwrite`),
//! and returns a shallow-to-deep plan so later mounts implement
//! most-specific-path-wins.

use crate::models::ContainerPolicy;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum FsIntent {
    ReadWrite,
    ReadOnly,
    Denied,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ResolvedMount {
    pub path: String,
    pub intent: FsIntent,
}

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

    candidates.sort_by(|a, b| {
        a.key
            .cmp(&b.key)
            .then_with(|| b.intent.cmp(&a.intent))
            .then_with(|| a.sequence.cmp(&b.sequence))
    });
    candidates.dedup_by(|a, b| {
        if a.key == b.key {
            if b.intent > a.intent {
                a.path = b.path.clone();
                a.intent = b.intent;
                a.sequence = b.sequence;
            }
            true
        } else {
            false
        }
    });
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

pub fn resolve_mount_order(policy: &ContainerPolicy) -> Vec<ResolvedMount> {
    resolve_path_plan(
        &policy.readwrite_paths,
        &policy.readonly_paths,
        &policy.denied_paths,
    )
}

pub fn effective_intent(plan: &[ResolvedMount], path: &str) -> Option<FsIntent> {
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
    fn exact_path_conflict_uses_most_restrictive_intent() {
        let resolved = plan(&["/workspace"], &["/workspace"], &["/workspace"]);
        assert_eq!(order(&resolved), vec![("/workspace", FsIntent::Denied)]);
        assert_eq!(
            effective_intent(&resolved, "/workspace/file"),
            Some(FsIntent::Denied)
        );
    }

    #[test]
    fn readonly_wins_exact_path_conflict_over_readwrite() {
        let resolved = plan(&["/workspace/"], &["/workspace"], &[]);
        assert_eq!(order(&resolved), vec![("/workspace", FsIntent::ReadOnly)]);
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
