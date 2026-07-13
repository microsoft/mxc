// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Filesystem-policy enforcer based on ProjFS + BindFlt + minimal
//! placeholder DACL augmentation. Peer of [`crate::filesystem_dacl`].
//!
//! See `~/.copilot/session-state/<id>/plan.md` for the full design.
//! In one sentence: where `filesystem_dacl` modifies host DACLs to
//! make the AppContainer see the policy, `filesystem_overlay` shapes
//! the AC's namespace view instead — ProjFS projects host content
//! through provider callbacks that evaluate placeholder DACLs, and
//! BindFlt mappings tombstone or redirect entries inside the
//! namespace. Host DACLs are not touched.
//!
//! # Phase A.3 status
//!
//! Crash-safe state-file persistence is **live**. Every primitive's
//! intent is appended to a JSON state file under the overlay state
//! directory *before* the underlying ProjFS / BindFlt API call. On
//! drop, restore consumes the in-memory list LIFO and removes the
//! state file when empty. [`recover_orphaned_state`] scans the
//! state directory at startup, reaps state files owned by dead
//! processes (PID + image basename + creation FILETIME), and
//! quarantines unparseable ones.
//!
//! ProjFS path is live (Phase A.2 promotion). BindFlt sub-module is
//! still stubbed (returns `PrimitiveUnavailable`); arrives in Phase
//! B. `policy::classify` is still the Phase A.1 stub returning an
//! empty plan — the real per-entry classifier lands in Phase C.1.

pub mod bindflt;
pub mod error;
pub mod handle;
pub mod plan;
pub mod policy;
pub mod projfs;
pub mod recovery;
pub mod state;

#[cfg(test)]
pub(crate) mod test_support;

pub use error::OverlayError;
pub use handle::OverlayHandle;
pub use plan::{BranchMode, OverlayPlan, OverlayPlanSummary, OverlayPrimitive};
pub use policy::AcContext;
pub use recovery::{recover_orphaned_state, RecoveryReport};
pub use state::{AppliedRecord, StateFile};

use std::ffi::OsString;
use std::path::PathBuf;

use crate::models::ContainerPolicy;

/// Crash-safe manager for ProjFS + BindFlt filesystem policy
/// enforcement. Parallel to [`crate::filesystem_dacl::DaclManager`]
/// — same lifecycle, same restore semantics, same `Drop` discipline.
///
/// # State-file persistence
///
/// On the first primitive apply, the manager writes a
/// `<state_dir>/<run-id>.json` describing its intent. Every
/// subsequent apply rewrites it atomically (stage to `.tmp`, fsync,
/// rename). On clean restore the file is deleted; if any restore
/// step fails the file is rewritten preserving only the unrestored
/// entries so the next startup's [`recover_orphaned_state`] can
/// retry.
#[derive(Debug)]
pub struct OverlayManager {
    /// Unique id for this run (file name stem under the state dir).
    run_id: String,
    /// Where the state file lives. Created lazily on first apply.
    state_path: PathBuf,
    /// Owning process creation FILETIME, captured at construction.
    process_start_filetime: u64,
    /// The one active ProjFS projection, if any.
    applied_projfs: Option<projfs::ProjFsApplied>,
    /// BindFlt mappings successfully applied so far, in apply order.
    applied_bindflt: Vec<bindflt::BindFltApplied>,
    /// Mirror of the applied state in serialisable shape; kept in
    /// sync with `applied_projfs` / `applied_bindflt`.
    applied_records: Vec<AppliedRecord>,
    /// Non-fatal warnings accumulated during apply / restore.
    warnings: Vec<String>,
}

impl OverlayManager {
    /// Create a new manager. The state directory is created on the
    /// first successful apply, not at construction.
    pub fn new() -> Result<Self, OverlayError> {
        let run_id = generate_run_id();
        let state_path = state::state_dir()?.join(format!("{run_id}.json"));
        let process_start_filetime = state::process_creation_filetime()?;
        Ok(Self {
            run_id,
            state_path,
            process_start_filetime,
            applied_projfs: None,
            applied_bindflt: Vec::new(),
            applied_records: Vec::new(),
            warnings: Vec::new(),
        })
    }

    /// Apply the policy. Each primitive's [`AppliedRecord`] is
    /// appended to the state file **before** the underlying API
    /// call so [`recover_orphaned_state`] can clean up after a
    /// crash mid-apply.
    pub fn apply_policy(
        &mut self,
        ac_sid: &str,
        policy: &ContainerPolicy,
    ) -> Result<OverlayHandle, OverlayError> {
        let ctx = AcContext {
            ac_sid: ac_sid.to_string(),
            // Phase D will populate these from `fallback_detector::detect`.
            projfs_available: true,
            bindflt_available: true,
        };
        let plan = policy::classify(policy, &ctx)?;
        let summary = plan.summarize();

        let projfs_primitives: Vec<OverlayPrimitive> = plan
            .primitives
            .iter()
            .filter(|p| matches!(p, OverlayPrimitive::ProjFsBranch { .. }))
            .cloned()
            .collect();
        let bindflt_primitives: Vec<&OverlayPrimitive> = plan
            .primitives
            .iter()
            .filter(|p| !matches!(p, OverlayPrimitive::ProjFsBranch { .. }))
            .collect();

        let mut effective_cwd: Option<PathBuf> = None;
        let mut env_injections: Vec<(String, OsString)> = Vec::new();

        if !projfs_primitives.is_empty() {
            let projection_root = self.compute_projection_root(ac_sid);

            self.applied_records.push(AppliedRecord::ProjFsProjection {
                projection_root: projection_root.clone(),
                branches: projfs_primitives.clone(),
                ac_sid: ac_sid.to_string(),
            });
            if let Err(e) = self.persist_state() {
                self.applied_records.pop();
                return Err(e);
            }

            match projfs::apply_branches(&projfs_primitives, ac_sid, projection_root.clone()) {
                Ok(applied) => {
                    effective_cwd = Some(projection_root.clone());
                    env_injections.push((
                        "MXC_POLICY_ROOT".to_string(),
                        OsString::from(projection_root.as_os_str()),
                    ));
                    self.applied_projfs = Some(applied);
                }
                Err(e) => return Err(e),
            }
        }

        for primitive in bindflt_primitives {
            let virt_path = bindflt_virt_path_for(primitive);
            self.applied_records.push(AppliedRecord::BindFltMapping {
                primitive: primitive.clone(),
                virt_path,
                ac_sid: ac_sid.to_string(),
            });
            if let Err(e) = self.persist_state() {
                self.applied_records.pop();
                return Err(e);
            }

            match bindflt::apply_mapping(primitive, ac_sid) {
                Ok(applied) => {
                    self.applied_bindflt.push(applied);
                }
                Err(e) => return Err(e),
            }
        }

        Ok(OverlayHandle {
            effective_cwd,
            env_injections,
            plan_summary: summary,
        })
    }

    /// Restore everything applied by this manager. LIFO: BindFlt
    /// mappings unmap first, then the ProjFS projection tears down.
    /// Each successful restore drops its record from memory and the
    /// state file is rewritten (or deleted, if empty). Failed
    /// records are retained for retry on the next call /
    /// [`recover_orphaned_state`] pass.
    pub fn restore(&mut self) -> Result<(), OverlayError> {
        let mut remaining: Vec<AppliedRecord> = Vec::new();
        while let Some(record) = self.applied_records.pop() {
            let outcome = self.restore_one_record(&record);
            if let Err((e, ctx)) = outcome {
                self.warnings.push(format!("restore failed: {e} ({ctx})"));
                remaining.push(record);
            }
        }
        if remaining.is_empty() {
            if self.state_path.exists() {
                if let Err(e) = std::fs::remove_file(&self.state_path) {
                    return Err(OverlayError::StateIo(e));
                }
            }
        } else {
            remaining.reverse();
            self.applied_records = remaining;
            self.persist_state()?;
        }
        Ok(())
    }

    /// Warnings accumulated during apply / restore (non-fatal).
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// The state-file path for diagnostics / tests.
    pub fn state_path(&self) -> &PathBuf {
        &self.state_path
    }

    /// The run id for diagnostics / tests.
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    fn restore_one_record(&mut self, record: &AppliedRecord) -> Result<(), (OverlayError, String)> {
        match record {
            AppliedRecord::ProjFsProjection {
                projection_root, ..
            } => {
                if let Some(mut applied) = self.applied_projfs.take() {
                    projfs::restore(&mut applied).map_err(|e| {
                        (
                            e,
                            format!("projfs root={}", applied.projection_root.display()),
                        )
                    })
                } else if projection_root.exists() {
                    // No live session — best-effort clean the
                    // projection-root directory directly.
                    std::fs::remove_dir_all(projection_root).map_err(|e| {
                        (
                            OverlayError::ProjFs(format!(
                                "remove projection root {}: {e}",
                                projection_root.display()
                            )),
                            format!("projfs root={}", projection_root.display()),
                        )
                    })
                } else {
                    Ok(())
                }
            }
            AppliedRecord::BindFltMapping { virt_path, .. } => {
                let _ = virt_path;
                if let Some(applied) = self.applied_bindflt.pop() {
                    bindflt::restore_mapping(&applied).map_err(|e| {
                        (
                            e,
                            format!("bindflt virt_path={}", applied.virt_path.display()),
                        )
                    })
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Persist the current applied-records list to disk.
    fn persist_state(&self) -> Result<(), OverlayError> {
        let s = StateFile {
            run_id: self.run_id.clone(),
            pid: std::process::id(),
            image_name: state::current_image_basename(),
            started_at_filetime: self.process_start_filetime,
            applied: self.applied_records.clone(),
        };
        state::write_state_file(&self.state_path, &s)
    }

    /// Compute the projection root for this manager's run.
    fn compute_projection_root(&self, ac_sid: &str) -> PathBuf {
        if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
            let _ = ac_sid; // Reserved for Phase D AC-profile derivation.
            let base = PathBuf::from(local_appdata)
                .join("Microsoft")
                .join("MXC")
                .join("overlay-roots");
            return base.join(format!("projection-{}", self.run_id));
        }
        std::env::temp_dir().join(format!("mxc-overlay-projection-{}", self.run_id))
    }
}

impl Drop for OverlayManager {
    fn drop(&mut self) {
        if let Err(e) = self.restore() {
            eprintln!("OverlayManager drop: restore failed: {e}");
        }
    }
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

/// Derive the BindFlt virt-path used for `BfRemoveMappingEx` from a
/// plan primitive. For tombstones / overlays the virt path is the
/// `path` / `virt_path` field. Returns an empty path for variants
/// that have no natural virt-path concept.
fn bindflt_virt_path_for(primitive: &OverlayPrimitive) -> PathBuf {
    match primitive {
        OverlayPrimitive::BindFltTombstone { path } => path.clone(),
        OverlayPrimitive::BindFltRoOverlay { virt_path, .. }
        | OverlayPrimitive::BindFltRwOverlay { virt_path, .. } => virt_path.clone(),
        OverlayPrimitive::ProjFsBranch { .. } => PathBuf::new(),
    }
}

/// Generate a short, monotonic-enough run id. Same shape as
/// `filesystem_dacl::generate_run_id` so log readers don't have to
/// learn two formats.
fn generate_run_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in pid.to_le_bytes().iter().chain(nanos.to_le_bytes().iter()) {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    format!("pid-{pid}-{:016x}", h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem_overlay::plan::BranchMode;
    use crate::filesystem_overlay::test_support::ScopedStateDir;

    #[test]
    fn new_captures_self_filetime() {
        let _scope = ScopedStateDir::new();
        let mgr = OverlayManager::new().expect("constructor");
        assert!(mgr.process_start_filetime > 0);
    }

    #[test]
    fn apply_empty_policy_writes_no_state_file() {
        let _scope = ScopedStateDir::new();
        let mut mgr = OverlayManager::new().expect("constructor");
        let policy = ContainerPolicy::default();
        let handle = mgr
            .apply_policy("S-1-15-2-test", &policy)
            .expect("empty policy applies cleanly");
        assert!(handle.effective_cwd.is_none());
        assert!(handle.env_injections.is_empty());
        // Empty plan → no primitives → no state file.
        assert!(!mgr.state_path().exists());
    }

    #[test]
    fn restore_with_no_state_file_is_noop() {
        let _scope = ScopedStateDir::new();
        let mut mgr = OverlayManager::new().expect("constructor");
        mgr.restore().expect("idempotent");
        assert!(mgr.warnings().is_empty());
    }

    #[test]
    fn bindflt_virt_path_for_tombstone() {
        let p = OverlayPrimitive::BindFltTombstone {
            path: PathBuf::from(r"C:\fake"),
        };
        assert_eq!(bindflt_virt_path_for(&p), PathBuf::from(r"C:\fake"));
    }

    #[test]
    fn bindflt_virt_path_for_ro_overlay() {
        let p = OverlayPrimitive::BindFltRoOverlay {
            virt_path: PathBuf::from(r"C:\virt"),
            target_path: PathBuf::from(r"D:\target"),
        };
        assert_eq!(bindflt_virt_path_for(&p), PathBuf::from(r"C:\virt"));
    }

    #[test]
    fn bindflt_virt_path_for_rw_overlay() {
        let p = OverlayPrimitive::BindFltRwOverlay {
            virt_path: PathBuf::from(r"C:\virt"),
            target_path: PathBuf::from(r"D:\target"),
            scratch: Some(PathBuf::from(r"E:\scratch")),
        };
        assert_eq!(bindflt_virt_path_for(&p), PathBuf::from(r"C:\virt"));
    }

    #[test]
    fn run_id_is_unique_per_manager() {
        let _scope = ScopedStateDir::new();
        let a = OverlayManager::new().expect("a");
        std::thread::sleep(std::time::Duration::from_micros(2));
        let b = OverlayManager::new().expect("b");
        assert_ne!(a.run_id(), b.run_id());
    }

    /// End-to-end-ish for the persist-before-apply discipline:
    /// force a non-empty applied list, persist, then restore +
    /// confirm the state file is gone.
    #[test]
    fn persist_then_restore_clears_state_file() {
        let _scope = ScopedStateDir::new();
        let mut mgr = OverlayManager::new().expect("constructor");
        mgr.applied_records.push(AppliedRecord::ProjFsProjection {
            projection_root: std::env::temp_dir()
                .join(format!("mxc-overlay-test-proj-{}", mgr.run_id())),
            branches: vec![OverlayPrimitive::ProjFsBranch {
                host_path: PathBuf::from(r"C:\test"),
                branch_name: "test".into(),
                mode: BranchMode::ReadOnly,
                deny_subpaths: Vec::new(),
            }],
            ac_sid: "S-1-15-2-test".into(),
        });
        mgr.persist_state().expect("persist");
        assert!(mgr.state_path().exists());

        mgr.restore().expect("restore");
        assert!(!mgr.state_path().exists(), "state file should be removed");
        assert!(mgr.applied_records.is_empty());
    }
}
