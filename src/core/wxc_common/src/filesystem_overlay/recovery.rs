// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Orphan-state recovery for the overlay enforcer.
//!
//! Peer of [`crate::filesystem_dacl::recover_orphaned_state`]. Runs
//! at `wxc-exec` startup. The flow:
//!
//! 1. Enumerate `*.json` under the state directory (default
//!    `%LOCALAPPDATA%\Microsoft\MXC\overlay-state`).
//! 2. Parse each — quarantine any that fail to parse by renaming to
//!    `<file>.json.corrupt`.
//! 3. Check whether the owning process is still alive (PID + image
//!    basename + creation FILETIME). Active owners are left alone.
//! 4. For orphans, restore each `AppliedRecord` in reverse apply
//!    order:
//!    - `ProjFsProjection`: best-effort delete the projection root.
//!      ProjFS itself releases the virt instance when the owning
//!      process exits; only the on-disk placeholder tree needs
//!      explicit cleanup.
//!    - `BindFltMapping`: call `BfRemoveMappingEx` (Phase B; Phase
//!      A.3 returns a warning placeholder so the on-disk format is
//!      forward-compatible).
//! 5. Successfully restored entries are dropped from the file. If
//!    every entry was restored, the file is deleted. Otherwise the
//!    file is rewritten preserving the original owner identity so
//!    the next startup retries the failed entries.

use std::fs;
use std::io;

use crate::filesystem_overlay::error::OverlayError;
use crate::filesystem_overlay::state::{
    process_alive_with_image, read_state_file, state_dir, write_state_file, AppliedRecord,
    StateFile,
};

/// Aggregated outcome of [`recover_orphaned_state`].
#[derive(Debug, Default)]
pub struct RecoveryReport {
    /// Number of `*.json` state files inspected.
    pub files_processed: usize,
    /// Total `AppliedRecord` entries successfully restored across
    /// all orphan files.
    pub primitives_restored: usize,
    /// Per-file or per-primitive errors, formatted for logging.
    pub errors: Vec<String>,
}

/// Inspect the overlay state directory and reap entries owned by
/// dead processes. Idempotent; safe to call concurrently with live
/// `OverlayManager` instances (each instance owns its own
/// `<run-id>.json`).
pub fn recover_orphaned_state() -> Result<RecoveryReport, OverlayError> {
    let mut report = RecoveryReport::default();
    let dir = match state_dir() {
        Ok(d) => d,
        Err(_) => return Ok(report),
    };
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(report),
        Err(e) => return Err(OverlayError::StateIo(e)),
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        report.files_processed += 1;
        let state = match read_state_file(&path) {
            Ok(s) => s,
            Err(e) => {
                report
                    .errors
                    .push(format!("parse {}: {}", path.display(), e));
                let corrupt = path.with_extension("json.corrupt");
                if let Err(e2) = fs::rename(&path, &corrupt) {
                    report.errors.push(format!(
                        "quarantine {} -> {}: {}",
                        path.display(),
                        corrupt.display(),
                        e2
                    ));
                }
                continue;
            }
        };
        if process_alive_with_image(
            state.pid,
            &state.image_name,
            Some(state.started_at_filetime),
        ) {
            // Active owner — leave alone.
            continue;
        }
        reap_orphan(&path, state, &mut report);
    }

    Ok(report)
}

/// Restore one orphan state file. Records that fail to restore are
/// retained in a rewritten file; if all succeed, the file is removed.
fn reap_orphan(path: &std::path::Path, state: StateFile, report: &mut RecoveryReport) {
    let mut remaining: Vec<AppliedRecord> = Vec::new();
    for record in state.applied.iter().rev() {
        match restore_record(record) {
            Ok(()) => report.primitives_restored += 1,
            Err(e) => {
                report.errors.push(format!(
                    "restore record (pid {}): {} -- {:?}",
                    state.pid, e, record
                ));
                remaining.push(record.clone());
            }
        }
    }
    if remaining.is_empty() {
        if let Err(e) = fs::remove_file(path) {
            report
                .errors
                .push(format!("remove {}: {}", path.display(), e));
        }
    } else {
        remaining.reverse();
        let pending = StateFile {
            run_id: state.run_id,
            pid: state.pid,
            image_name: state.image_name,
            started_at_filetime: state.started_at_filetime,
            applied: remaining,
        };
        if let Err(e) = write_state_file(path, &pending) {
            report
                .errors
                .push(format!("rewrite {}: {}", path.display(), e));
        }
    }
}

/// Restore a single orphan record. Dispatches by variant.
fn restore_record(record: &AppliedRecord) -> Result<(), OverlayError> {
    match record {
        AppliedRecord::ProjFsProjection {
            projection_root, ..
        } => {
            // ProjFS releases the virt instance automatically when the
            // owning process exits; only the placeholder tree needs
            // explicit cleanup. Non-existence is success (some other
            // pass already cleaned it).
            if !projection_root.exists() {
                return Ok(());
            }
            // Bounded retry against transient
            // STATUS_VIRTUALIZATION_TEMPORARILY_UNAVAILABLE (369).
            const RETRIES: u32 = 10;
            const DELAY_MS: u64 = 100;
            let mut last: Option<io::Error> = None;
            for attempt in 0..RETRIES {
                match fs::remove_dir_all(projection_root) {
                    Ok(()) => return Ok(()),
                    Err(e) => {
                        let is_temp = e.raw_os_error() == Some(369);
                        last = Some(e);
                        if !is_temp {
                            break;
                        }
                        if attempt + 1 < RETRIES {
                            std::thread::sleep(std::time::Duration::from_millis(DELAY_MS));
                        }
                    }
                }
            }
            let e = last.expect("loop sets last on Err");
            Err(OverlayError::ProjFs(format!(
                "remove projection root {}: {e}",
                projection_root.display()
            )))
        }
        AppliedRecord::BindFltMapping {
            primitive,
            virt_path,
            ac_sid,
        } => {
            // Phase A.3 placeholder: Phase B will issue the actual
            // `BfRemoveMappingEx` call. Until then, surface a typed
            // error so the entry is retained in the state file and
            // a future Phase B run can reap it. This keeps the
            // on-disk shape forward-compatible.
            let _ = (primitive, ac_sid);
            Err(OverlayError::PrimitiveUnavailable {
                primitive: "bindflt",
                reason: format!(
                    "Phase B BfRemoveMappingEx not yet implemented; \
                     orphan mapping at {} retained for future recovery",
                    virt_path.display()
                ),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem_overlay::plan::{BranchMode, OverlayPrimitive};
    use crate::filesystem_overlay::state::{
        current_image_basename, process_creation_filetime, write_state_file,
    };
    use crate::filesystem_overlay::test_support::ScopedStateDir;

    #[test]
    fn recover_with_no_state_dir_is_clean() {
        // Use a fresh scope first so we hold the env-var mutex
        // serially with other tests, then redirect to a known-bad
        // path within this scope's lifetime.
        let _scope = ScopedStateDir::new();
        std::env::set_var(
            "MXC_OVERLAY_STATE_DIR",
            r"C:\__definitely_not_a_real_dir__\xyzzy",
        );
        let r = recover_orphaned_state().expect("no state dir is not an error");
        assert_eq!(r.files_processed, 0);
        assert_eq!(r.primitives_restored, 0);
        assert!(r.errors.is_empty());
    }

    #[test]
    fn recover_leaves_active_owner_alone() {
        let _scope = ScopedStateDir::new();
        let dir = state_dir().unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("alive.json");
        // Forge a state file owned by *this* process (alive, FILETIME
        // matches). Recovery must NOT touch it.
        let state = StateFile {
            run_id: "alive".into(),
            pid: std::process::id(),
            image_name: current_image_basename(),
            started_at_filetime: process_creation_filetime().unwrap(),
            applied: vec![AppliedRecord::ProjFsProjection {
                projection_root: std::env::temp_dir().join("never-touched-by-recovery"),
                branches: Vec::new(),
                ac_sid: "S-1-15-2-test".into(),
            }],
        };
        write_state_file(&file, &state).unwrap();

        let r = recover_orphaned_state().expect("recover");
        assert_eq!(r.files_processed, 1);
        assert_eq!(r.primitives_restored, 0);
        assert!(file.exists(), "alive owner's state must NOT be removed");
    }

    #[test]
    fn recover_reaps_dead_pid_projfs_record() {
        let _scope = ScopedStateDir::new();
        let dir = state_dir().unwrap();
        std::fs::create_dir_all(&dir).unwrap();

        // Build a "projection root" that's just an empty dir we can
        // sanity-check got removed.
        let fake_proj = std::env::temp_dir().join(format!(
            "mxc-overlay-recovery-test-proj-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(fake_proj.join("subdir")).unwrap();
        std::fs::write(fake_proj.join("subdir").join("x.txt"), b"x").unwrap();

        let file = dir.join("dead.json");
        let state = StateFile {
            run_id: "dead".into(),
            pid: 0xFFFF_FFFF, // PID this large is virtually guaranteed dead
            image_name: "no-such-process.exe".into(),
            started_at_filetime: 0xDEAD_BEEF,
            applied: vec![AppliedRecord::ProjFsProjection {
                projection_root: fake_proj.clone(),
                branches: vec![OverlayPrimitive::ProjFsBranch {
                    host_path: std::env::temp_dir().join("anywhere"),
                    branch_name: "anywhere".into(),
                    mode: BranchMode::ReadOnly,
                    deny_subpaths: Vec::new(),
                }],
                ac_sid: "S-1-15-2-test".into(),
            }],
        };
        write_state_file(&file, &state).unwrap();

        let r = recover_orphaned_state().expect("recover");
        assert_eq!(r.files_processed, 1);
        assert_eq!(r.primitives_restored, 1, "errors: {:?}", r.errors);
        assert!(!file.exists(), "state file should be removed after reap");
        assert!(
            !fake_proj.exists(),
            "fake projection root should be removed: {}",
            fake_proj.display()
        );
    }

    #[test]
    fn recover_retains_bindflt_record_until_phase_b() {
        let _scope = ScopedStateDir::new();
        let dir = state_dir().unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("dead-bindflt.json");
        let state = StateFile {
            run_id: "dead-bindflt".into(),
            pid: 0xFFFF_FFFF,
            image_name: "no-such-process.exe".into(),
            started_at_filetime: 0xDEAD_BEEF,
            applied: vec![AppliedRecord::BindFltMapping {
                primitive: OverlayPrimitive::BindFltTombstone {
                    path: std::path::PathBuf::from(r"C:\fake\tombstone"),
                },
                virt_path: std::path::PathBuf::from(r"C:\fake\tombstone"),
                ac_sid: "S-1-15-2-test".into(),
            }],
        };
        write_state_file(&file, &state).unwrap();

        let r = recover_orphaned_state().expect("recover");
        assert_eq!(r.files_processed, 1);
        assert_eq!(r.primitives_restored, 0);
        // BindFlt record is retained for a future Phase B recovery
        // pass; file MUST still exist (rewritten with the same
        // record set).
        assert!(file.exists(), "BindFlt entry should be retained");
        // And the error should mention bindflt.
        assert!(
            r.errors.iter().any(|e| e.contains("bindflt")),
            "expected bindflt-mentioning error; got {:?}",
            r.errors
        );
    }

    #[test]
    fn recover_quarantines_corrupt_state_file() {
        let _scope = ScopedStateDir::new();
        let dir = state_dir().unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("garbage.json");
        std::fs::write(&file, b"this is not json {").unwrap();

        let r = recover_orphaned_state().expect("recover");
        assert_eq!(r.files_processed, 1);
        assert!(!file.exists(), "corrupt file should be moved aside");
        let corrupt = dir.join("garbage.json.corrupt");
        assert!(corrupt.exists(), "quarantined file at {:?}", corrupt);
    }
}
