// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The plan produced by `policy::classify` and consumed by
//! `OverlayManager::apply_policy`. An `OverlayPlan` is a deterministic
//! ordered list of [`OverlayPrimitive`]s that, when applied in order,
//! satisfy a [`crate::models::ContainerPolicy`].
//!
//! Each variant corresponds to one OS-level operation: a ProjFS
//! branch projection, a BindFlt tombstone, a BindFlt overlay. The
//! plan never mixes apply and restore — restore is a fresh walk of
//! the on-disk state file in reverse application order.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Read mode of a projected ProjFS branch or BindFlt overlay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BranchMode {
    /// Read-only — writes are vetoed.
    ReadOnly,
    /// Read-write — writes propagate to the host backing (or to a
    /// scratch root if `writeIsolation = "private"`).
    ReadWrite,
}

/// One OS-level operation in the plan. Variants are ordered by
/// stable apply order: ProjFS branches first (they bring host paths
/// into the AC's namespace), then BindFlt overlays / tombstones
/// (which carve out denies or redirect specific subtrees inside the
/// projection).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OverlayPrimitive {
    /// Project a host directory into the AC's projection root as
    /// a branch with the given mode. The branch name is the leaf
    /// component of the canonicalized host path (deduplicated by
    /// `policy::classify`).
    ProjFsBranch {
        /// Canonicalized host directory to project.
        host_path: PathBuf,
        /// Branch leaf name as it appears under the projection root.
        branch_name: String,
        /// RO or RW.
        mode: BranchMode,
    },

    /// Install a BindFlt tombstone that makes `path` appear
    /// non-existent to the AC, regardless of whether the host path
    /// exists or not.
    BindFltTombstone {
        /// The path the AC sees as "not found".
        path: PathBuf,
    },

    /// Install a BindFlt RO overlay binding `virt_path` to
    /// `target_path` with write veto.
    BindFltRoOverlay {
        /// Path the AC sees.
        virt_path: PathBuf,
        /// Host path serving content.
        target_path: PathBuf,
    },

    /// Install a BindFlt RW overlay binding `virt_path` to
    /// `target_path`. Writes go to `target_path` (passthrough) or
    /// to a per-run scratch directory (private, controlled by
    /// `writeIsolation = "private"`).
    BindFltRwOverlay {
        /// Path the AC sees.
        virt_path: PathBuf,
        /// Host path serving content.
        target_path: PathBuf,
        /// Scratch destination for writes when `writeIsolation =
        /// "private"`. `None` for passthrough.
        scratch: Option<PathBuf>,
    },
}

/// Ordered list of primitives forming an apply plan.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OverlayPlan {
    /// Apply in order.
    pub primitives: Vec<OverlayPrimitive>,
}

impl OverlayPlan {
    /// Human-readable summary suitable for logging / diagnostics.
    pub fn summarize(&self) -> OverlayPlanSummary {
        let mut projfs_branch_count = 0;
        let mut bindflt_mapping_count = 0;
        let mut primitive_descriptions = Vec::with_capacity(self.primitives.len());
        for p in &self.primitives {
            match p {
                OverlayPrimitive::ProjFsBranch {
                    branch_name, mode, ..
                } => {
                    projfs_branch_count += 1;
                    primitive_descriptions.push(format!(
                        "projfs[{}] branch={branch_name}",
                        match mode {
                            BranchMode::ReadOnly => "ro",
                            BranchMode::ReadWrite => "rw",
                        }
                    ));
                }
                OverlayPrimitive::BindFltTombstone { path } => {
                    bindflt_mapping_count += 1;
                    primitive_descriptions.push(format!("bindflt[deny] {}", path.display()));
                }
                OverlayPrimitive::BindFltRoOverlay { virt_path, .. } => {
                    bindflt_mapping_count += 1;
                    primitive_descriptions.push(format!("bindflt[ro] {}", virt_path.display()));
                }
                OverlayPrimitive::BindFltRwOverlay {
                    virt_path, scratch, ..
                } => {
                    bindflt_mapping_count += 1;
                    primitive_descriptions.push(format!(
                        "bindflt[rw{}] {}",
                        if scratch.is_some() { ",private" } else { "" },
                        virt_path.display()
                    ));
                }
            }
        }
        OverlayPlanSummary {
            projfs_branch_count,
            bindflt_mapping_count,
            primitive_descriptions,
        }
    }
}

/// Human-readable summary of an [`OverlayPlan`] for diagnostics and
/// for the `OverlayHandle` returned to the runner.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OverlayPlanSummary {
    /// Number of ProjFS branches in the plan.
    pub projfs_branch_count: usize,
    /// Number of BindFlt mappings (tombstone + RO + RW) in the plan.
    pub bindflt_mapping_count: usize,
    /// One line per primitive, in apply order.
    pub primitive_descriptions: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarize_empty_plan() {
        let p = OverlayPlan::default();
        let s = p.summarize();
        assert_eq!(s.projfs_branch_count, 0);
        assert_eq!(s.bindflt_mapping_count, 0);
        assert!(s.primitive_descriptions.is_empty());
    }

    #[test]
    fn summarize_mixed_plan() {
        let p = OverlayPlan {
            primitives: vec![
                OverlayPrimitive::ProjFsBranch {
                    host_path: PathBuf::from(r"C:\Users\test"),
                    branch_name: "test".into(),
                    mode: BranchMode::ReadOnly,
                },
                OverlayPrimitive::BindFltTombstone {
                    path: PathBuf::from(r"C:\Users\test\.ssh"),
                },
                OverlayPrimitive::BindFltRwOverlay {
                    virt_path: PathBuf::from(r"C:\Users\test\scratch"),
                    target_path: PathBuf::from(r"D:\scratch-backing"),
                    scratch: Some(PathBuf::from(r"D:\scratch-private")),
                },
            ],
        };
        let s = p.summarize();
        assert_eq!(s.projfs_branch_count, 1);
        assert_eq!(s.bindflt_mapping_count, 2);
        assert_eq!(s.primitive_descriptions.len(), 3);
        assert!(s.primitive_descriptions[0].starts_with("projfs[ro]"));
        assert!(s.primitive_descriptions[1].starts_with("bindflt[deny]"));
        assert!(s.primitive_descriptions[2].contains("rw,private"));
    }
}
