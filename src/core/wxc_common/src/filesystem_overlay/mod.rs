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
//! # Phase A.1 status
//!
//! This commit lands **type scaffolding only**. `OverlayManager::new`
//! works (just records a run-id and a state-file path); `apply_policy`
//! invokes `policy::classify` which currently returns an empty plan,
//! so apply is a no-op. The ProjFS and BindFlt sub-modules expose
//! shape-only entry points that return
//! [`OverlayError::PrimitiveUnavailable`] until Phase A.2 and Phase B
//! respectively. Crash-safe state-file persistence lands in Phase A.3.
//!
//! Everything compiles; the unit tests assert the type shapes and the
//! Phase A.1 stub contract.

#![cfg(target_os = "windows")]

pub mod bindflt;
pub mod error;
pub mod handle;
pub mod plan;
pub mod policy;
pub mod projfs;
pub mod recovery;

pub use error::OverlayError;
pub use handle::OverlayHandle;
pub use plan::{BranchMode, OverlayPlan, OverlayPlanSummary, OverlayPrimitive};
pub use policy::AcContext;
pub use recovery::{recover_orphaned_state, RecoveryReport};

use std::path::PathBuf;

use crate::models::ContainerPolicy;

/// Crash-safe manager for ProjFS + BindFlt filesystem policy
/// enforcement. Parallel to [`crate::filesystem_dacl::DaclManager`]
/// — same lifecycle, same restore semantics, same `Drop` discipline.
///
/// Apply a policy with [`apply_policy`](Self::apply_policy); call
/// [`restore`](Self::restore) to undo. On drop,
/// [`restore`](Self::restore) is invoked best-effort.
#[derive(Debug)]
pub struct OverlayManager {
    /// Unique id for this run (file name stem under the state dir).
    run_id: String,
    /// Where the state file lives. Created lazily on first apply.
    state_path: PathBuf,
    /// Primitives successfully applied so far, in apply order.
    applied_projfs: Vec<projfs::ProjFsApplied>,
    /// BindFlt mappings successfully applied so far, in apply order.
    applied_bindflt: Vec<bindflt::BindFltApplied>,
    /// Non-fatal warnings accumulated during apply / restore.
    warnings: Vec<String>,
}

impl OverlayManager {
    /// Create a new manager. The state directory is created on the
    /// first successful apply, not at construction. A fresh `run_id`
    /// is generated up-front so it's stable across the manager's
    /// lifetime.
    pub fn new() -> Result<Self, OverlayError> {
        let run_id = generate_run_id();
        let state_path = state_dir()?.join(format!("{run_id}.json"));
        Ok(Self {
            run_id,
            state_path,
            applied_projfs: Vec::new(),
            applied_bindflt: Vec::new(),
            warnings: Vec::new(),
        })
    }

    /// Apply the policy. Returns an [`OverlayHandle`] the runner
    /// uses to set up the contained process (cwd, env vars).
    ///
    /// Phase A.1 stub: invokes `policy::classify` (empty plan in
    /// A.1) and returns an empty handle. Real apply lands in A.2+.
    pub fn apply_policy(
        &mut self,
        ac_sid: &str,
        policy: &ContainerPolicy,
    ) -> Result<OverlayHandle, OverlayError> {
        let ctx = AcContext {
            ac_sid: ac_sid.to_string(),
            // Phase A.1: these arrive from `fallback_detector::detect`
            // in Phase D. Defaulting to `true` here keeps the
            // `classify` call testable.
            projfs_available: true,
            bindflt_available: true,
        };
        let plan = policy::classify(policy, &ctx)?;
        let summary = plan.summarize();
        // Phase A.1: no primitives in the plan because `classify` is
        // a stub. Apply each primitive once the real classifier
        // lands.
        for primitive in &plan.primitives {
            match primitive {
                OverlayPrimitive::ProjFsBranch { .. } => {
                    let applied = projfs::apply_branch(primitive, ac_sid)?;
                    self.applied_projfs.push(applied);
                }
                OverlayPrimitive::BindFltTombstone { .. }
                | OverlayPrimitive::BindFltRoOverlay { .. }
                | OverlayPrimitive::BindFltRwOverlay { .. } => {
                    let applied = bindflt::apply_mapping(primitive, ac_sid)?;
                    self.applied_bindflt.push(applied);
                }
            }
        }
        Ok(OverlayHandle {
            effective_cwd: None,
            env_injections: Vec::new(),
            plan_summary: summary,
        })
    }

    /// Restore everything applied by this manager. LIFO: BindFlt
    /// mappings unmap first, then ProjFS branches stop. Per-entry
    /// failures go into `warnings`; only fatal state-file I/O
    /// surfaces as `Err`.
    pub fn restore(&mut self) -> Result<(), OverlayError> {
        while let Some(applied) = self.applied_bindflt.pop() {
            if let Err(e) = bindflt::restore_mapping(&applied) {
                self.warnings
                    .push(format!("bindflt restore failed: {e} ({applied:?})"));
            }
        }
        while let Some(applied) = self.applied_projfs.pop() {
            if let Err(e) = projfs::restore_branch(&applied) {
                self.warnings
                    .push(format!("projfs restore failed: {e} ({applied:?})"));
            }
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

/// Default state directory:
/// `%LOCALAPPDATA%\Microsoft\MXC\overlay-state`. Overridable via the
/// `MXC_OVERLAY_STATE_DIR` env var.
fn state_dir() -> Result<PathBuf, OverlayError> {
    if let Ok(override_dir) = std::env::var("MXC_OVERLAY_STATE_DIR") {
        return Ok(PathBuf::from(override_dir));
    }
    let local_appdata = std::env::var("LOCALAPPDATA").map_err(|_| {
        OverlayError::Apply("LOCALAPPDATA not set; cannot resolve state directory".into())
    })?;
    Ok(PathBuf::from(local_appdata)
        .join("Microsoft")
        .join("MXC")
        .join("overlay-state"))
}

/// Generate a short, monotonic-enough run id. Same shape as
/// `filesystem_dacl::generate_run_id`: PID + 8 hex chars of system
/// time micros (truncated).
fn generate_run_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let pid = std::process::id();
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0);
    format!("{pid}-{:08x}", micros & 0xFFFF_FFFF)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_succeeds_when_localappdata_set() {
        // Tests run with LOCALAPPDATA set on Windows; just verify
        // we can construct a manager and that the state path has the
        // expected shape.
        let mgr = OverlayManager::new().expect("constructor should succeed on Windows test host");
        assert!(mgr.run_id().contains('-'));
        assert!(mgr.state_path().to_string_lossy().ends_with(".json"));
    }

    #[test]
    fn new_respects_state_dir_override() {
        // Save / restore env var to avoid polluting other tests.
        let prev = std::env::var("MXC_OVERLAY_STATE_DIR").ok();
        std::env::set_var("MXC_OVERLAY_STATE_DIR", r"C:\overlay-test-override");
        let mgr = OverlayManager::new().expect("constructor with override");
        assert!(mgr.state_path().starts_with(r"C:\overlay-test-override"));
        match prev {
            Some(v) => std::env::set_var("MXC_OVERLAY_STATE_DIR", v),
            None => std::env::remove_var("MXC_OVERLAY_STATE_DIR"),
        }
    }

    #[test]
    fn apply_empty_policy_yields_empty_handle() {
        let mut mgr = OverlayManager::new().expect("constructor");
        let policy = ContainerPolicy::default();
        let handle = mgr
            .apply_policy("S-1-15-2-test", &policy)
            .expect("empty policy applies cleanly in Phase A.1 stub");
        assert!(handle.effective_cwd.is_none());
        assert!(handle.env_injections.is_empty());
        assert_eq!(handle.plan_summary.projfs_branch_count, 0);
        assert_eq!(handle.plan_summary.bindflt_mapping_count, 0);
    }

    #[test]
    fn restore_with_nothing_applied_is_a_noop() {
        let mut mgr = OverlayManager::new().expect("constructor");
        mgr.restore().expect("idempotent restore");
        assert!(mgr.warnings().is_empty());
    }

    #[test]
    fn run_id_is_unique_per_manager() {
        let a = OverlayManager::new().expect("a");
        std::thread::sleep(std::time::Duration::from_micros(2));
        let b = OverlayManager::new().expect("b");
        assert_ne!(a.run_id(), b.run_id());
    }
}
