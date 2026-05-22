// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Crash-safe state-file persistence for `OverlayManager`.
//!
//! Mirrors the discipline in [`crate::filesystem_dacl`]:
//!
//! 1. **Persist before apply.** Each primitive's intent is appended to
//!    [`StateFile::applied`] and the file is written atomically
//!    *before* the underlying ProjFS / BindFlt API call. If apply
//!    succeeds we have full restore information on disk; if apply
//!    crashes mid-call, [`recover_orphaned_state`] on the next
//!    startup observes the record and cleans up.
//! 2. **Atomic writes.** Stage to `<path>.tmp`, then `fs::rename`
//!    (which is `MoveFileExW(..., MOVEFILE_REPLACE_EXISTING)` on
//!    Windows — atomic w.r.t. concurrent readers on the same volume).
//! 3. **PID-reuse defeat.** Every state file records the owning
//!    process's PID *and* its creation FILETIME (from
//!    `GetProcessTimes`). Recovery considers a state file orphaned
//!    only when the PID is dead, **or** the live PID's creation time
//!    differs from the recorded value.
//! 4. **Quarantine corrupt files.** Recovery renames an unparseable
//!    state file to `<path>.json.corrupt` so it doesn't trip the
//!    same error on every startup.
//!
//! State directory default: `%LOCALAPPDATA%\Microsoft\MXC\overlay-state`.
//! Override via `MXC_OVERLAY_STATE_DIR`.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use windows::core::PWSTR;
use windows::Win32::Foundation::{FILETIME, HANDLE};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetProcessTimes, OpenProcess, QueryFullProcessImageNameW,
    PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::filesystem_overlay::error::OverlayError;
use crate::filesystem_overlay::plan::OverlayPrimitive;

/// One thing the manager applied that needs undoing on restore.
/// Variants mirror the [`OverlayPrimitive`] kinds but carry the
/// extra bookkeeping recovery needs (e.g. projection-root path).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AppliedRecord {
    /// The whole ProjFS projection — one record per `OverlayManager`
    /// instance because ProjFS has exactly one virt session per
    /// projection root.
    ProjFsProjection {
        /// Directory the virt root was rooted at.
        projection_root: PathBuf,
        /// Branches that were registered with the virt session, in
        /// apply order. Used for diagnostics; recovery doesn't need
        /// to re-register them.
        branches: Vec<OverlayPrimitive>,
        /// AC SID that was passed to placeholder DACL construction.
        ac_sid: String,
    },
    /// One BindFlt mapping. Recovery calls the matching `Bf*` removal
    /// API for the `virt_path`. Filled in by Phase B; Phase A.3
    /// leaves the variant defined so the on-disk format is stable.
    BindFltMapping {
        /// The plan primitive that produced the mapping.
        primitive: OverlayPrimitive,
        /// Virt-path handle used to issue the removal call.
        virt_path: PathBuf,
        /// AC SID the mapping was scoped to (for `BfRemoveMappingEx`).
        ac_sid: String,
    },
}

/// On-disk shape of an overlay state file. Same persistence pattern
/// as [`crate::filesystem_dacl::StateFile`] — PID + image basename +
/// start FILETIME identify the owner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateFile {
    /// Unique id for this manager (file name stem).
    pub run_id: String,
    /// Owning process PID.
    pub pid: u32,
    /// Image basename (e.g. `wxc-exec.exe`) for orphan sanity check.
    pub image_name: String,
    /// Owning process *creation* time as a Windows FILETIME (100-ns
    /// intervals since 1601-01-01 UTC). Captured at manager
    /// construction. Recovery compares against the live PID's
    /// creation time to defeat PID reuse.
    pub started_at_filetime: u64,
    /// Every record we've successfully applied (or have committed to
    /// apply, in the persist-before-apply window).
    pub applied: Vec<AppliedRecord>,
}

/// Default state directory: `%LOCALAPPDATA%\Microsoft\MXC\overlay-state`.
/// Overridable via `MXC_OVERLAY_STATE_DIR`.
pub fn state_dir() -> Result<PathBuf, OverlayError> {
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

/// Process creation time of the *current* process as a Windows
/// FILETIME (100-ns intervals since 1601-01-01 UTC).
pub fn process_creation_filetime() -> Result<u64, OverlayError> {
    unsafe {
        let h = GetCurrentProcess();
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        GetProcessTimes(h, &mut creation, &mut exit, &mut kernel, &mut user)
            .map_err(|e| OverlayError::Apply(format!("GetProcessTimes(GetCurrentProcess): {e}")))?;
        Ok(((creation.dwHighDateTime as u64) << 32) | (creation.dwLowDateTime as u64))
    }
}

/// Basename of `current_exe()`, or `"wxc-exec.exe"` if the lookup
/// fails.
pub fn current_image_basename() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| {
            p.file_name()
                .and_then(|s| s.to_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "wxc-exec.exe".to_string())
}

/// Atomically write `state` to `path` via the staged-tmp+rename
/// pattern. See module-level docs for the durability story.
pub fn write_state_file(path: &Path, state: &StateFile) -> Result<(), OverlayError> {
    let json = serde_json::to_vec_pretty(state)
        .map_err(|e| OverlayError::StateParse(format!("serialize: {e}")))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = tmp_path_for(path);
    // Best-effort: remove any leftover tmp from a previous crashed
    // write so `create_new` doesn't surprise us.
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => {
            eprintln!(
                "OverlayManager: pre-write cleanup of {} failed ({e}); \
                 if subsequent create_new fails, this file is the obstruction",
                tmp.display()
            );
        }
    }
    {
        let mut f = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp)?;
        f.write_all(&json)?;
        f.sync_all()?;
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(OverlayError::StateIo(e));
    }
    Ok(())
}

/// Read a state file from disk.
pub fn read_state_file(path: &Path) -> Result<StateFile, OverlayError> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes)
        .map_err(|e| OverlayError::StateParse(format!("{}: {e}", path.display())))
}

fn tmp_path_for(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

/// Owned process handle that closes on drop.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }
}

/// Return `true` if `pid` is alive AND its image basename matches
/// `expected_image` AND (if `expected_start_filetime` is given) its
/// creation FILETIME matches. The FILETIME check defeats PID reuse.
///
/// Duplicates the equivalent helper in `filesystem_dacl`; merging
/// into a shared `wxc_common::process_liveness` module is a clean-up
/// task for a separate change.
pub fn process_alive_with_image(
    pid: u32,
    expected_image: &str,
    expected_start_filetime: Option<u64>,
) -> bool {
    if pid == 0 {
        return false;
    }
    let handle = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(h) if !h.is_invalid() => OwnedHandle(h),
        _ => return false,
    };
    let mut buf = [0u16; 1024];
    let mut sz: u32 = buf.len() as u32;
    let ok = unsafe {
        QueryFullProcessImageNameW(
            handle.0,
            PROCESS_NAME_FORMAT(0),
            PWSTR(buf.as_mut_ptr()),
            &mut sz,
        )
    };
    if ok.is_err() || sz == 0 {
        return false;
    }
    let full = String::from_utf16_lossy(&buf[..sz as usize]);
    let basename = std::path::Path::new(&full)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    if !basename.eq_ignore_ascii_case(expected_image) {
        return false;
    }
    let recorded = match expected_start_filetime {
        Some(0) | None => return true,
        Some(v) => v,
    };
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    let gpt =
        unsafe { GetProcessTimes(handle.0, &mut creation, &mut exit, &mut kernel, &mut user) };
    if gpt.is_err() {
        return false;
    }
    let live = ((creation.dwHighDateTime as u64) << 32) | (creation.dwLowDateTime as u64);
    live == recorded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem_overlay::plan::BranchMode;

    #[test]
    fn state_file_roundtrip_projfs() {
        let s = StateFile {
            run_id: "test-123".into(),
            pid: 4242,
            image_name: "wxc-exec.exe".into(),
            started_at_filetime: 0x01D9_1234_5678_9ABC,
            applied: vec![AppliedRecord::ProjFsProjection {
                projection_root: PathBuf::from(r"C:\Users\test\proj"),
                branches: vec![OverlayPrimitive::ProjFsBranch {
                    host_path: PathBuf::from(r"D:\src\repo"),
                    branch_name: "repo".into(),
                    mode: BranchMode::ReadOnly,
                }],
                ac_sid: "S-1-15-2-test".into(),
            }],
        };
        let td = tempfile::tempdir().unwrap();
        let p = td.path().join("test.json");
        write_state_file(&p, &s).expect("write");
        let back = read_state_file(&p).expect("read");
        assert_eq!(back.run_id, s.run_id);
        assert_eq!(back.pid, s.pid);
        assert_eq!(back.image_name, s.image_name);
        assert_eq!(back.started_at_filetime, s.started_at_filetime);
        assert_eq!(back.applied.len(), 1);
        match (&back.applied[0], &s.applied[0]) {
            (
                AppliedRecord::ProjFsProjection {
                    projection_root: ra,
                    branches: ba,
                    ac_sid: sa,
                },
                AppliedRecord::ProjFsProjection {
                    projection_root: rb,
                    branches: bb,
                    ac_sid: sb,
                },
            ) => {
                assert_eq!(ra, rb);
                assert_eq!(ba, bb);
                assert_eq!(sa, sb);
            }
            _ => panic!("variant mismatch"),
        }
    }

    #[test]
    fn write_then_read_is_atomic_no_stale_tmp() {
        let td = tempfile::tempdir().unwrap();
        let p = td.path().join("atomic.json");
        let s = StateFile {
            run_id: "a".into(),
            pid: 1,
            image_name: "x.exe".into(),
            started_at_filetime: 0,
            applied: Vec::new(),
        };
        write_state_file(&p, &s).expect("write");
        // The tmp must NOT linger after a successful rename.
        let tmp = tmp_path_for(&p);
        assert!(!tmp.exists(), "stale tmp at {}", tmp.display());
        assert!(p.exists());
    }

    #[test]
    fn process_alive_with_image_recognizes_self() {
        let me = std::process::id();
        let image = current_image_basename();
        let ft = process_creation_filetime().expect("self FILETIME");
        assert!(process_alive_with_image(me, &image, Some(ft)));
    }

    #[test]
    fn process_alive_with_image_rejects_zero_pid() {
        assert!(!process_alive_with_image(0, "anything.exe", None));
    }

    #[test]
    fn process_alive_with_image_rejects_mismatched_filetime() {
        let me = std::process::id();
        let image = current_image_basename();
        // Forge a FILETIME guaranteed to differ from the real one.
        let bogus = 0xDEAD_BEEF_DEAD_BEEFu64;
        assert!(!process_alive_with_image(me, &image, Some(bogus)));
    }

    #[test]
    fn read_state_file_rejects_garbage() {
        let td = tempfile::tempdir().unwrap();
        let p = td.path().join("bad.json");
        std::fs::write(&p, b"not json {").unwrap();
        let err = read_state_file(&p).unwrap_err();
        match err {
            OverlayError::StateParse(_) => {}
            other => panic!("expected StateParse, got {other:?}"),
        }
    }
}
