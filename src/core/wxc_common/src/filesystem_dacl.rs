// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Crash-safe DACL manager for the AppContainer + DACL tier (T3) and for
//! deny-ACE augmentation under T1/T2.
//!
//! See `docs/proposals/downlevel_support/basecontainer-fallback-plan-v2.md`.
//!
//! # Design
//!
//! - **Inheritable ACEs**: on directories we apply `OBJECT_INHERIT_ACE |
//!   CONTAINER_INHERIT_ACE`. We rely on `SetNamedSecurityInfoW` automatic
//!   propagation for both add AND remove — no manual descendant walk.
//! - **Crash safety**: every applied ACE is appended to a per-process state
//!   file under `%LOCALAPPDATA%\Microsoft\MXC\dacl-restore\<run-id>.json`
//!   *before* the Win32 apply call. On startup, [`recover_orphaned_state`]
//!   inspects every state file and reaps entries owned by dead processes.
//! - **Concurrency**: each path acquires a named mutex
//!   (`Local\Microsoft.MXC.Dacl.<hash16>`) for the duration of the
//!   scan/persist/apply sequence so two concurrent MXC instances on the
//!   same path serialize cleanly.
//! - **ACE-merge resilience**: `SetEntriesInAclW(GRANT)` coalesces rights
//!   for the same trustee into a single ACE. Before each apply we
//!   capture **every** explicit (non-inherited) ACE for our SID — of
//!   either type — into [`AppliedAce::prior_state`]. On restore we
//!   issue `REVOKE_ACCESS` for the SID (atomic strip of all our
//!   contributions, merged or otherwise) and then re-grant/deny each
//!   prior entry verbatim, restoring the host to its exact prior state.
//!
//! # State directory
//!
//! The default state directory is `%LOCALAPPDATA%\Microsoft\MXC\dacl-restore`.
//! Tests and specialized deployments can override this via the
//! `MXC_DACL_STATE_DIR` environment variable. The directory contains
//! up to three file species:
//!
//! - `<run-id>.json` — a fully written, owner-active state file.
//! - `<run-id>.json.tmp` — an in-progress atomic write; cleaned up at
//!   the start of the next write to the same path, otherwise harmless
//!   leftover from a crash mid-write.
//! - `<run-id>.json.corrupt` — quarantine of a state file that failed
//!   to parse during recovery, preserved for operator inspection.
//!
//! # Errors
//!
//! Apply paths surface [`DaclError`] on failure. [`DaclManager::restore`]
//! collects per-path failures into the manager's warning list and only
//! returns an outer error for catastrophic state-file I/O. Entries
//! whose Win32 restore failed are **retained** in the in-memory list
//! and on disk so a future `restore()` call or
//! [`recover_orphaned_state`] on the next startup can retry.
//!
//! # Drop
//!
//! [`DaclManager`] best-effort restores on drop; errors are swallowed and
//! logged to stderr.

// Note: the module-level `#[cfg(target_os = "windows")]` lives on the
// `mod filesystem_dacl;` declaration in `lib.rs`. Repeating it here as
// an inner `#![cfg(...)]` trips clippy's `duplicated_attributes` lint
// on toolchains 1.78+.

use std::ffi::c_void;
use std::fs;
use std::io::{self, Write};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_SUCCESS, FILETIME, HANDLE, HLOCAL, WAIT_ABANDONED,
    WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT, WIN32_ERROR,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSidToSidW, GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW,
    EXPLICIT_ACCESS_W, GRANT_ACCESS, SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
// DENY_ACCESS lives on ACCESS_MODE in windows 0.62
use windows::Win32::Security::Authorization::DENY_ACCESS;
use windows::Win32::Security::{
    AclSizeInformation, AddAccessAllowedAceEx, AddAccessDeniedAceEx, AddAce, EqualSid, GetAce,
    GetAclInformation, GetLengthSid, InitializeAcl, IsValidSid, ACCESS_ALLOWED_ACE,
    ACCESS_DENIED_ACE, ACE_FLAGS, ACE_HEADER, ACL, ACL_REVISION, ACL_SIZE_INFORMATION,
    CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, INHERITED_ACE, OBJECT_INHERIT_ACE,
    PSECURITY_DESCRIPTOR, PSID,
};
use windows::Win32::Storage::FileSystem::{
    DELETE, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
};
use windows::Win32::System::Threading::{
    CreateMutexW, GetCurrentProcess, GetProcessTimes, OpenProcess, QueryFullProcessImageNameW,
    ReleaseMutex, WaitForSingleObject, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
};

// -------------------------------------------------------------------------
// Access masks — single source of truth
// -------------------------------------------------------------------------
//
// These are the masks `DaclManager::grant_appcontainer_access` actually
// stamps onto host paths. Other modules (the dispatcher's
// `filter_paths_needing_grant`, the fallback detector's
// `ensure_path_grantable_for_ac` precheck) must observe the SAME
// values or they'll predict / filter against a different mask than
// what we apply, silently breaking the "skip per-run ACE when AC SID
// already has access" optimization and the WRITE_DAC precheck.
//
// Keep these as the only definitions in the crate; the constants
// are `pub(crate)` so dispatcher and fallback_detector can import
// them rather than re-derive the bit pattern.

/// Access mask granted on `readwritePaths` entries: read + write +
/// execute + delete. `FILE_GENERIC_EXECUTE` is required so the
/// AppContainer child can `SetCurrentDirectoryW` into the granted
/// directory (the API opens the target with `FILE_TRAVERSE`, which
/// is the same bit — `0x20` — as `FILE_EXECUTE` for files).
///
/// File-inheritance side-effect (deliberate): because the ACE is
/// applied with `OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE`, the
/// same bit propagates as `FILE_EXECUTE` to every file descendant.
/// We accept this: (a) workloads commonly need to execute helper
/// binaries they place under the scratch tree (compile-and-run
/// cycles, test harnesses, build outputs), (b) NTFS has no clean
/// primitive for "directory-only traverse, all-depth, with no
/// file-execute" — `FILE_TRAVERSE` and `FILE_EXECUTE` are the same
/// access right, distinguished only by the kernel's interpretation
/// per object type, so any per-type split requires walking the
/// tree at apply time, and (c) the AppContainer is already a
/// code-execution sandbox: the policy's `commandLine` runs an
/// attacker-chosen binary by design, and a compromised child can
/// already load arbitrary in-memory code without needing
/// `FILE_EXECUTE` on a host file.
pub const RW_MASK: u32 =
    FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | FILE_GENERIC_EXECUTE.0 | DELETE.0;

/// Access mask granted on `readonlyPaths` entries: read + execute.
/// `FILE_GENERIC_EXECUTE` is included for the same reason as the
/// rw mask — without it `chdir` into a granted read-only directory
/// fails with `ERROR_ACCESS_DENIED`.
///
/// Granting `FILE_EXECUTE` on file descendants of a read-only path
/// is also a feature, not just a side-effect: read-only grants are
/// the canonical way to expose tool install directories (e.g. a
/// per-user `python` or `node` install that doesn't inherit
/// `ALL APPLICATION PACKAGES` from `Program Files`) to the
/// AppContainer, and those tools must be loadable as executables.
/// Stripping `FILE_EXECUTE` from file ACEs here would break that
/// path.
pub const RO_MASK: u32 = FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0;

// Compile-time guarantee that the masks above keep their well-known
// shape. Any change to [`RW_MASK`] or [`RO_MASK`] that breaks one of
// these invariants fails to build, preventing silent drift inside
// the dispatcher's `filter_paths_needing_grant` and the detector's
// `ensure_path_grantable_for_ac` (both of which read the constants
// directly from this module).
const _: () = {
    assert!(
        RW_MASK == FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | FILE_GENERIC_EXECUTE.0 | DELETE.0
    );
    assert!(RO_MASK == FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0);
    assert!((RW_MASK & RO_MASK) == RO_MASK);
};

// -------------------------------------------------------------------------
// Public API
// -------------------------------------------------------------------------

/// Errors returned by [`DaclManager`] and helpers.
#[derive(Debug, thiserror::Error)]
pub enum DaclError {
    /// Caller passed a UNC network path; only local paths are supported.
    #[error("path is not local (network/UNC paths not supported): {0}")]
    NetworkPathRejected(PathBuf),
    /// The path could not be resolved by [`std::fs::canonicalize`].
    #[error("path does not exist: {0}")]
    PathNotFound(PathBuf),
    /// `WRITE_DAC` denied. Caller should have probed; surfaced for safety.
    #[error("WRITE_DAC denied on {path}: {reason}")]
    WriteDacDenied {
        /// Path that failed.
        path: PathBuf,
        /// Win32 error description.
        reason: String,
    },
    /// Generic Win32 error.
    #[error("Win32 error on {path}: {reason}")]
    Win32 {
        /// Path involved.
        path: PathBuf,
        /// Win32 error description.
        reason: String,
    },
    /// State file IO error.
    #[error("state file I/O error: {0}")]
    StateIo(#[from] io::Error),
    /// State file parse error.
    #[error("state file parse error: {0}")]
    StateParse(String),
    /// SID string could not be parsed.
    #[error("invalid SID string: {0}")]
    InvalidSid(String),
    /// Timed out waiting on the per-path serialization mutex. Another
    /// MXC instance is wedged or excessively slow on the same path.
    #[error("timed out acquiring DACL mutex on {path} after {timeout_ms} ms")]
    MutexTimeout {
        /// Path whose mutex could not be acquired.
        path: PathBuf,
        /// How long we waited before giving up, in milliseconds.
        timeout_ms: u32,
    },
}

/// Distinguishes allow vs deny ACEs we have applied.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AceType {
    /// Allow ACE.
    Allow,
    /// Deny ACE.
    Deny,
}

/// One explicit (non-inherited) ACE that existed on the target *before*
/// we applied. Used to faithfully reconstruct the pre-apply DACL on
/// restore, defeating `SetEntriesInAclW`'s rights-coalescing behaviour
/// for the same trustee.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct PriorAce {
    /// Whether this prior ACE was an explicit allow or deny.
    pub ace_type: AceType,
    /// Original access mask.
    pub access_mask: u32,
    /// Raw `AceFlags` byte. `INHERITED_ACE` is masked off at capture
    /// time since prior_state only ever holds explicit ACEs.
    pub inherit_flags: u8,
}

/// Persisted record of one applied ACE.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppliedAce {
    /// Canonicalized path the ACE was applied to.
    pub canonical_path: PathBuf,
    /// SID string in `S-1-15-...` form.
    pub sid_string: String,
    /// Win32 access mask.
    pub access_mask: u32,
    /// Allow or deny.
    pub ace_type: AceType,
    /// Whether `OI|CI` were set (directories only).
    pub inheritable: bool,
    /// All explicit (non-inherited) ACEs for our SID — of either allow
    /// or deny type — that existed on the target before we applied.
    /// On restore we issue `REVOKE_ACCESS` for the SID (atomic strip
    /// of all our contributions, including ones that got coalesced
    /// into a pre-existing ACE by `SetEntriesInAclW`) and re-grant
    /// or re-deny each prior entry with its original mask and
    /// inheritance bits. Empty means "no prior explicit ACEs for this
    /// SID" — restore reduces to a single `REVOKE`. Defaulted for
    /// backward compatibility with state files written prior to the
    /// introduction of this field.
    #[serde(default)]
    pub prior_state: Vec<PriorAce>,
}

/// Persistent state file written before each ACE is applied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateFile {
    /// Unique id for this manager (file name stem).
    pub run_id: String,
    /// Owning process PID.
    pub pid: u32,
    /// Image file name (e.g. `wxc-exec.exe`) for orphan check.
    pub image_name: String,
    /// Owning process *creation* time as a Windows FILETIME (100-ns
    /// intervals since 1601-01-01 UTC). Captured once at
    /// [`DaclManager::new`] from `GetProcessTimes(GetCurrentProcess())`.
    /// Recovery compares this against the live process's creation time
    /// (obtained via `GetProcessTimes`) before classifying the state
    /// file as active — this defeats PID reuse, where a crashed
    /// `wxc-exec.exe`'s PID is later recycled by another `wxc-exec.exe`
    /// instance.
    pub started_at_filetime: u64,
    /// All ACEs currently applied by this manager.
    pub applied: Vec<AppliedAce>,
}

/// Crash-safe manager for filesystem DACL augmentation.
///
/// Apply ACEs via [`grant_appcontainer_access`](Self::grant_appcontainer_access)
/// and [`add_deny_aces`](Self::add_deny_aces); call [`restore`](Self::restore)
/// to undo. On drop, [`restore`](Self::restore) is invoked best-effort.
#[derive(Debug)]
pub struct DaclManager {
    run_id: String,
    state_path: PathBuf,
    applied: Vec<AppliedAce>,
    warnings: Vec<String>,
    /// Process creation time captured at construction. Persisted into
    /// every state file so the orphan-recovery path can detect PID
    /// reuse.
    process_start_filetime: u64,
}

/// Aggregated outcome of [`recover_orphaned_state`].
#[derive(Debug, Default)]
pub struct RecoveryReport {
    /// Number of state files inspected.
    pub files_processed: usize,
    /// Total ACEs successfully removed across all orphan files.
    pub aces_restored: usize,
    /// ACEs pruned because their target path no longer exists. There is
    /// nothing to restore on a deleted file, so the entry is dropped rather
    /// than retained-and-retried forever (which would emit perpetual
    /// recovery errors). Counted separately from `aces_restored` so the
    /// diagnostic line stays honest.
    pub aces_pruned_missing: usize,
    /// Per-file or per-path errors, formatted for logging.
    pub errors: Vec<String>,
}

impl DaclManager {
    /// Create a new manager. The state directory is created if missing; a
    /// fresh `run_id` is generated and the (empty) state file is *not*
    /// written until the first ACE is applied.
    pub fn new() -> Result<Self, DaclError> {
        let state_dir = state_dir()?;
        fs::create_dir_all(&state_dir)?;
        let run_id = generate_run_id();
        let state_path = state_dir.join(format!("{run_id}.json"));
        let process_start_filetime = process_creation_filetime()?;
        Ok(Self {
            run_id,
            state_path,
            applied: Vec::new(),
            warnings: Vec::new(),
            process_start_filetime,
        })
    }

    /// Warnings accumulated during apply/restore (non-fatal issues).
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// T3: grant the AppContainer SID `rw` on `readwrite` paths and `ro` on
    /// `readonly` paths. Caller must have already probed `WRITE_DAC` (Phase
    /// 2 fallback detector).
    pub fn grant_appcontainer_access(
        &mut self,
        appcontainer_sid_str: &str,
        readwrite: &[PathBuf],
        readonly: &[PathBuf],
    ) -> Result<(), DaclError> {
        for p in readwrite {
            self.apply_one(appcontainer_sid_str, p, RW_MASK, AceType::Allow)?;
        }
        for p in readonly {
            self.apply_one(appcontainer_sid_str, p, RO_MASK, AceType::Allow)?;
        }
        Ok(())
    }

    /// T1/T2/T3: deny all access for the AppContainer SID on each path in
    /// `denied`.
    pub fn add_deny_aces(
        &mut self,
        appcontainer_sid_str: &str,
        denied: &[PathBuf],
    ) -> Result<(), DaclError> {
        // FILE_ALL_ACCESS = 0x1F01FF (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF)
        let deny_mask: u32 = 0x001F_01FF;
        for p in denied {
            self.apply_one(appcontainer_sid_str, p, deny_mask, AceType::Deny)?;
        }
        Ok(())
    }

    /// Idempotently remove every ACE this manager has applied. Per-path
    /// errors are recorded into [`warnings`](Self::warnings); only fatal
    /// state-file I/O surfaces as a `Result::Err`.
    ///
    /// Failures are **per entry**: a transient error on one path does
    /// not block the rest. Entries whose Win32 restore failed are
    /// retained in the in-memory list and the persisted state file so
    /// a future `restore()` call — or, if the process exits,
    /// [`recover_orphaned_state`] on the next startup — can retry.
    /// This guarantees we never silently lose track of host ACL
    /// changes after a transient failure.
    pub fn restore(&mut self) -> Result<(), DaclError> {
        // Process the in-memory list tail-first (LIFO restore: the
        // last ACE applied is the first removed). Failures go into
        // `remaining`; successes are dropped. After the loop we
        // restore retained entries to `self.applied` in their original
        // LIFO retry order.
        let mut remaining: Vec<AppliedAce> = Vec::new();
        while let Some(entry) = self.applied.pop() {
            match restore_one(&entry) {
                Ok(note) => {
                    if let Some(n) = note {
                        self.warnings.push(n);
                    }
                }
                Err(e) => {
                    self.warnings.push(format!(
                        "restore failed for {} (entry retained for retry): {}",
                        entry.canonical_path.display(),
                        e
                    ));
                    remaining.push(entry);
                }
            }
        }
        // Tail-first iteration pushed remaining entries in pop order
        // (newest first). Reversing yields the original apply order
        // so the next `restore()` again processes tail-first.
        remaining.reverse();
        self.applied = remaining;
        if self.applied.is_empty() {
            let _ = fs::remove_file(&self.state_path);
        } else {
            self.persist_state()?;
        }
        Ok(())
    }

    // -------- internals --------

    fn apply_one(
        &mut self,
        sid_str: &str,
        path: &Path,
        mask: u32,
        ace_type: AceType,
    ) -> Result<(), DaclError> {
        let canonical = canonicalize_local(path)?;
        let inheritable = fs::metadata(&canonical)
            .map_err(|e| DaclError::Win32 {
                path: canonical.clone(),
                reason: format!("metadata: {e}"),
            })?
            .is_dir();

        // Acquire the per-path mutex up-front so the scan-for-prior-
        // state, persist, and Win32 apply are all serialized against
        // other MXC instances on the same path. This eliminates the
        // race window in which an external writer could change the
        // DACL between our scan and our apply.
        let _guard = PathMutexGuard::acquire(&canonical)?;

        // Capture every explicit (non-inherited) ACE for our SID
        // before we touch the DACL. `SetEntriesInAclW(GRANT)` will
        // merge our requested rights into any existing explicit ACE
        // for the same trustee; recording the prior state here lets
        // restore subsequently issue `REVOKE_ACCESS` for the SID and
        // re-add each prior entry verbatim, leaving the host exactly
        // as it was found.
        let prior_state = scan_explicit_aces_for_sid(&canonical, sid_str)?;

        let entry = AppliedAce {
            canonical_path: canonical.clone(),
            sid_string: sid_str.to_string(),
            access_mask: mask,
            ace_type,
            inheritable,
            prior_state,
        };

        // 1. Persist before apply. If `apply_ace` succeeds we have
        //    full restore information on disk; if it crashes, recovery
        //    will issue REVOKE + regrant prior, which leaves the host
        //    unchanged because the apply never modified it.
        self.applied.push(entry.clone());
        if let Err(e) = self.persist_state() {
            self.applied.pop();
            return Err(e);
        }

        // 2. Apply (mutex still held). On failure we leave the entry
        //    in state so recovery can clean up any partial Win32
        //    effect.
        apply_ace(&entry)
    }

    fn persist_state(&self) -> Result<(), DaclError> {
        let state = StateFile {
            run_id: self.run_id.clone(),
            pid: std::process::id(),
            image_name: current_image_basename(),
            started_at_filetime: self.process_start_filetime,
            applied: self.applied.clone(),
        };
        write_state_file(&self.state_path, &state)
    }
}

impl Drop for DaclManager {
    fn drop(&mut self) {
        if let Err(e) = self.restore() {
            eprintln!("DaclManager drop: restore failed: {e}");
        }
    }
}

/// Scan the state directory and reap any state files whose owning process
/// is no longer alive.
///
/// Called unconditionally at MXC startup. Errors per file are aggregated
/// into [`RecoveryReport::errors`]; the function only returns `Err` on
/// fundamental state-directory I/O failures.
pub fn recover_orphaned_state() -> Result<RecoveryReport, DaclError> {
    let mut report = RecoveryReport::default();
    let dir = match state_dir() {
        Ok(d) => d,
        Err(_) => return Ok(report),
    };
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(report),
        Err(e) => return Err(DaclError::StateIo(e)),
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
                // Quarantine the unreadable file so a future startup
                // doesn't repeatedly trip the same error. We rename
                // rather than delete so an operator can investigate.
                // Note: `fs::rename` on Windows cannot cross volumes,
                // so the quarantine necessarily lands in the same
                // directory as the state file. That's fine today
                // because the state directory is unified by
                // `state_dir()`; if a future change splits state
                // across volumes the rename would silently fail and
                // the corrupt file would be retried on every startup.
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
            // Active owner (PID alive + image matches + creation
            // time matches recorded value) — leave alone.
            continue;
        }
        // Reap. Failed entries are retained so the next startup retries.
        let mut remaining: Vec<AppliedAce> = Vec::new();
        for ace in state.applied.iter().rev() {
            // Prune ACEs whose target no longer exists: there is nothing to
            // restore on a deleted file/dir, and retaining the entry would
            // make every future startup re-attempt the restore and fail with
            // PATH_NOT_FOUND forever. `try_exists() == Ok(false)`
            // is a confirmed "not there"; an `Err` (e.g. access denied) is
            // ambiguous, so we still attempt the restore in that case.
            if matches!(ace.canonical_path.try_exists(), Ok(false)) {
                report.aces_pruned_missing += 1;
                continue;
            }
            match restore_one(ace) {
                Ok(_) => report.aces_restored += 1,
                Err(e) => {
                    // Race: the target may have been deleted between the
                    // existence check above and the restore attempt. If it is
                    // now confirmed gone, prune rather than retain.
                    if matches!(ace.canonical_path.try_exists(), Ok(false)) {
                        report.aces_pruned_missing += 1;
                    } else {
                        report.errors.push(format!(
                            "restore {} (pid {}): {}",
                            ace.canonical_path.display(),
                            state.pid,
                            e
                        ));
                        remaining.push(ace.clone());
                    }
                }
            }
        }
        if remaining.is_empty() {
            if let Err(e) = fs::remove_file(&path) {
                report
                    .errors
                    .push(format!("remove {}: {}", path.display(), e));
            }
        } else {
            // Preserve the original owner identity so the next
            // startup still classifies the file as orphaned.
            remaining.reverse();
            let pending = StateFile {
                run_id: state.run_id,
                pid: state.pid,
                image_name: state.image_name,
                started_at_filetime: state.started_at_filetime,
                applied: remaining,
            };
            if let Err(e) = write_state_file(&path, &pending) {
                report
                    .errors
                    .push(format!("rewrite {}: {}", path.display(), e));
            }
        }
    }
    Ok(report)
}

// -------------------------------------------------------------------------
// State file
// -------------------------------------------------------------------------

fn state_dir() -> Result<PathBuf, DaclError> {
    // Test/deployment override: when `MXC_DACL_STATE_DIR` is set, use it
    // verbatim. This lets integration tests isolate themselves from the
    // default per-user directory (and from each other when combined
    // with a process-global mutex around the env var), and lets
    // operators relocate state for production deployments.
    if let Some(d) = std::env::var_os("MXC_DACL_STATE_DIR") {
        return Ok(PathBuf::from(d));
    }
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("USERPROFILE").map(|p| PathBuf::from(p).join("AppData").join("Local"))
        })
        .ok_or_else(|| {
            DaclError::StateIo(io::Error::new(
                io::ErrorKind::NotFound,
                "LOCALAPPDATA and USERPROFILE both unset",
            ))
        })?;
    Ok(base.join("Microsoft").join("MXC").join("dacl-restore"))
}

fn write_state_file(path: &Path, state: &StateFile) -> Result<(), DaclError> {
    let json = serde_json::to_vec_pretty(state)
        .map_err(|e| DaclError::StateParse(format!("serialize: {e}")))?;
    // Crash-safe write: stage to `<path>.tmp`, fsync, then atomically
    // replace the destination. On Windows, `fs::rename` maps to
    // `MoveFileExW(..., MOVEFILE_REPLACE_EXISTING)`, which is atomic
    // with respect to readers on the same volume. This guarantees that
    // recovery on the next startup observes either the prior complete
    // state or the new complete state, never a half-written file.
    //
    // Note: we do *not* fsync the directory entry containing tmp/path
    // after the rename. NTFS metadata journaling makes the rename
    // durable in practice; a fully durable cross-filesystem variant
    // would `FlushFileBuffers` on a backup-semantics handle to the
    // parent directory, which is left as a future enhancement if
    // non-NTFS deployments arise.
    let tmp = tmp_path_for(path);
    // Best-effort: remove any leftover tmp from a previous crashed
    // write so `create_new` doesn't surprise us. If removal fails for
    // any reason other than "not found", log it: a stale tmp owned by
    // another user (e.g. a previous elevated invocation) will block
    // `create_new` with `ERROR_FILE_EXISTS` and the resulting
    // `StateIo` error otherwise carries no hint about the obstructing
    // file.
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => {
            eprintln!(
                "DaclManager: pre-write cleanup of {} failed ({e}); \
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
        // Clean up tmp on failure so we don't accumulate garbage.
        let _ = fs::remove_file(&tmp);
        return Err(DaclError::StateIo(e));
    }
    Ok(())
}

fn tmp_path_for(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

fn read_state_file(path: &Path) -> Result<StateFile, DaclError> {
    // Retry on ERROR_SHARING_VIOLATION (Win32 32). A concurrent writer
    // mid `<path>.tmp` → `<path>` rename briefly holds the destination
    // open exclusively. Without retry the caller's parse-fallback path
    // would quarantine a perfectly-good state file to `.corrupt`,
    // permanently divorcing a live process from its real ACEs.
    //
    // ERROR_LOCK_VIOLATION (33) is also retried — antivirus on-access
    // scanners sometimes surface it transiently when an unrelated
    // process is still in the open-write-close window.
    use windows::Win32::Foundation::{ERROR_LOCK_VIOLATION, ERROR_SHARING_VIOLATION};
    const ATTEMPTS: u32 = 3;
    let mut last_err: Option<io::Error> = None;
    for i in 0..ATTEMPTS {
        match fs::read(path) {
            Ok(bytes) => {
                return serde_json::from_slice(&bytes)
                    .map_err(|e| DaclError::StateParse(format!("{}: {e}", path.display())));
            }
            Err(e) => {
                let transient = matches!(
                    e.raw_os_error().map(|c| c as u32),
                    Some(c) if c == ERROR_SHARING_VIOLATION.0 || c == ERROR_LOCK_VIOLATION.0
                );
                if !transient {
                    return Err(e.into());
                }
                last_err = Some(e);
                if i + 1 < ATTEMPTS {
                    // 20ms, 40ms — short enough to be invisible to
                    // human-driven scenarios; long enough for a
                    // typical rename to complete.
                    std::thread::sleep(std::time::Duration::from_millis(20u64 << i));
                }
            }
        }
    }
    Err(DaclError::StateIo(last_err.unwrap_or_else(|| {
        io::Error::other("read_state_file: retries exhausted on transient error")
    })))
}

fn generate_run_id() -> String {
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    // FNV-1a-style mix to add a touch of randomness from the time.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in pid.to_le_bytes().iter().chain(nanos.to_le_bytes().iter()) {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    format!("pid-{pid}-{:016x}", h)
}

fn current_image_basename() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| {
            p.file_name()
                .and_then(|s| s.to_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "wxc-exec.exe".to_string())
}

// -------------------------------------------------------------------------
// Path canonicalization
// -------------------------------------------------------------------------

/// Classify whether a path (already in its canonical / `\\?\`-prefixed
/// form, or a plain drive-letter path) refers to a local object. Returns
/// `Err(DaclError::NetworkPathRejected)` for UNC paths.
///
/// `fs::canonicalize` on Windows emits:
/// - `\\?\X:\...` for local drive-letter paths (Win32 file namespace).
/// - `\\?\UNC\server\share\...` for UNC paths.
///
/// We additionally allow `\\.\Volume{GUID}\...` and other DOS device
/// namespace paths (also local) even though `fs::canonicalize` does not
/// normally produce them — a caller may pass one in directly.
fn ensure_local_canonical_prefix(canonical: &Path) -> Result<(), DaclError> {
    let s = canonical.to_string_lossy();
    let bytes = s.as_bytes();
    // `\\?\UNC\...` is the canonical NT form for network/UNC paths. Match
    // case-insensitively on the `UNC` segment because some callers and
    // tools emit lower-case.
    if bytes.len() >= 8
        && &bytes[..4] == b"\\\\?\\"
        && bytes[4].eq_ignore_ascii_case(&b'U')
        && bytes[5].eq_ignore_ascii_case(&b'N')
        && bytes[6].eq_ignore_ascii_case(&b'C')
        && bytes[7] == b'\\'
    {
        return Err(DaclError::NetworkPathRejected(canonical.to_path_buf()));
    }
    // `\\?\X:\...` (Win32 file namespace) and `\\.\Volume{GUID}\...` (DOS
    // device namespace) are both local — accept them.
    if s.starts_with(r"\\?\") || s.starts_with(r"\\.\") {
        return Ok(());
    }
    // Anything else starting with `\\` is a raw UNC server path.
    if s.starts_with(r"\\") {
        return Err(DaclError::NetworkPathRejected(canonical.to_path_buf()));
    }
    Ok(())
}

fn canonicalize_local(path: &Path) -> Result<PathBuf, DaclError> {
    let canonical = match fs::canonicalize(path) {
        Ok(p) => p,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(DaclError::PathNotFound(path.to_path_buf()))
        }
        Err(e) => {
            return Err(DaclError::Win32 {
                path: path.to_path_buf(),
                reason: format!("canonicalize: {e}"),
            })
        }
    };
    ensure_local_canonical_prefix(&canonical)?;
    Ok(canonical)
}

// -------------------------------------------------------------------------
// Win32: SID parsing (RAII)
// -------------------------------------------------------------------------

/// Owned PSID returned by [`ConvertStringSidToSidW`]. Frees via `LocalFree`
/// on drop.
struct OwnedSid(PSID);

/// Maximum accepted length for a SID string. The longest well-formed SID
/// the Win32 SID grammar can produce is well under 200 characters (15
/// sub-authorities × ~10 digits + `S-1-` prefix and separators); we
/// generously cap at 256 to reject obviously-malformed inputs early
/// without engaging the Win32 parser on attacker-controlled gigabyte
/// strings.
const MAX_SID_STRING_LEN: usize = 256;

impl OwnedSid {
    fn parse(s: &str) -> Result<Self, DaclError> {
        if s.is_empty() {
            return Err(DaclError::InvalidSid("(empty)".to_string()));
        }
        if s.len() > MAX_SID_STRING_LEN {
            return Err(DaclError::InvalidSid(format!(
                "SID string too long ({} bytes, max {})",
                s.len(),
                MAX_SID_STRING_LEN
            )));
        }
        let wide: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
        let mut psid = PSID(ptr::null_mut());
        unsafe {
            ConvertStringSidToSidW(PCWSTR(wide.as_ptr()), &mut psid)
                .map_err(|e| DaclError::InvalidSid(format!("{s}: {e}")))?;
            if psid.0.is_null() || !IsValidSid(psid).as_bool() {
                if !psid.0.is_null() {
                    let _ = LocalFree(Some(HLOCAL(psid.0)));
                }
                return Err(DaclError::InvalidSid(s.to_string()));
            }
        }
        Ok(Self(psid))
    }

    fn as_psid(&self) -> PSID {
        self.0
    }
}

impl Drop for OwnedSid {
    fn drop(&mut self) {
        if !self.0 .0.is_null() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0 .0)));
            }
        }
    }
}

// SAFETY: `OwnedSid` wraps a `LocalAlloc`'d PSID whose underlying SID
// bytes are immutable after `parse()` returns (`ConvertStringSidToSidW`
// writes once, then we only ever read via `EqualSid` / `GetLengthSid`,
// both of which are documented reentrant). The pointer is never aliased
// to another writer. We use this purely for the process-lifetime SID
// cache in [`well_known_ac_sids`]; a per-stack OwnedSid still moves
// across thread boundaries safely because we never read past the
// allocation.
unsafe impl Send for OwnedSid {}
unsafe impl Sync for OwnedSid {}

/// Process-wide cache of the three well-known AppContainer-membership
/// SIDs. `compute_appcontainer_effective_access` used to re-parse these
/// from string form on every invocation — three `ConvertStringSidToSidW`
/// + `LocalAlloc` + matching `LocalFree` per call.
///
/// The cache is read-only after first init; OnceLock guarantees the
/// init closure runs exactly once. The cached `OwnedSid`s deliberately
/// live for the process lifetime (no `Drop` ever runs on them) — the
/// caller-side hot path becomes a pointer copy.
fn well_known_ac_sids() -> &'static [OwnedSid] {
    static CACHE: OnceLock<Vec<OwnedSid>> = OnceLock::new();
    CACHE
        .get_or_init(|| {
            WELL_KNOWN_AC_SIDS
                .iter()
                .map(|s| OwnedSid::parse(s).expect("well-known AC SID must parse"))
                .collect()
        })
        .as_slice()
}

// -------------------------------------------------------------------------
// Win32: per-path mutex (RAII)
// -------------------------------------------------------------------------

/// FNV-1a 64-bit hash. Sufficient for mutex-name uniqueness — not a
/// security boundary.
fn fnv1a64(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

fn mutex_name_for(canonical: &Path) -> String {
    let key = canonical.to_string_lossy().to_lowercase();
    let h = fnv1a64(&key);
    // 16 hex chars of the 64-bit hash.
    format!("Local\\Microsoft.MXC.Dacl.{:016x}", h)
}

struct PathMutexGuard {
    handle: HANDLE,
    acquired: bool,
}

/// Maximum wait, in milliseconds, for the per-path DACL mutex.
///
/// Concurrent MXC instances applying ACEs to the same path are expected to
/// serialize on the order of seconds at most. We pick 30 s as a generous
/// upper bound that still surfaces an actionable error if a peer has
/// deadlocked, rather than hanging the entire process indefinitely.
const PATH_MUTEX_WAIT_MS: u32 = 30_000;

impl PathMutexGuard {
    fn acquire(canonical: &Path) -> Result<Self, DaclError> {
        let name = mutex_name_for(canonical);
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let handle = unsafe { CreateMutexW(None, false, PCWSTR(wide.as_ptr())) }.map_err(|e| {
            DaclError::Win32 {
                path: canonical.to_path_buf(),
                reason: format!("CreateMutexW: {e}"),
            }
        })?;
        let wait = unsafe { WaitForSingleObject(handle, PATH_MUTEX_WAIT_MS) };
        // `WAIT_OBJECT_0` = acquired cleanly. `WAIT_ABANDONED` = previous
        // holder died without releasing; we still own the mutex and the
        // DACL state on disk is recovered by `recover_orphaned_state` on
        // startup, so accept it (but log a warning to stderr for
        // diagnosability).
        if wait == WAIT_OBJECT_0 {
            return Ok(Self {
                handle,
                acquired: true,
            });
        }
        if wait == WAIT_ABANDONED {
            eprintln!(
                "DaclManager: acquired abandoned mutex for {} (previous holder \
                terminated without releasing; orphan recovery will reconcile)",
                canonical.display()
            );
            return Ok(Self {
                handle,
                acquired: true,
            });
        }
        // Failure path: capture the reason before we close the handle.
        let err = if wait == WAIT_TIMEOUT {
            DaclError::MutexTimeout {
                path: canonical.to_path_buf(),
                timeout_ms: PATH_MUTEX_WAIT_MS,
            }
        } else if wait == WAIT_FAILED {
            let last = unsafe { GetLastError() };
            DaclError::Win32 {
                path: canonical.to_path_buf(),
                reason: format!("WaitForSingleObject failed: {last:?}"),
            }
        } else {
            DaclError::Win32 {
                path: canonical.to_path_buf(),
                reason: format!("WaitForSingleObject unexpected result: {wait:?}"),
            }
        };
        unsafe {
            let _ = CloseHandle(handle);
        }
        Err(err)
    }
}

impl Drop for PathMutexGuard {
    fn drop(&mut self) {
        unsafe {
            if self.acquired {
                let _ = ReleaseMutex(self.handle);
            }
            let _ = CloseHandle(self.handle);
        }
    }
}

// -------------------------------------------------------------------------
// Win32: apply / restore single ACE
// -------------------------------------------------------------------------

fn wide(p: &Path) -> Vec<u16> {
    p.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn trustee_for(sid: &OwnedSid) -> TRUSTEE_W {
    TRUSTEE_W {
        pMultipleTrustee: ptr::null_mut(),
        MultipleTrusteeOperation: windows::Win32::Security::Authorization::NO_MULTIPLE_TRUSTEE,
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_UNKNOWN,
        ptstrName: PWSTR(sid.as_psid().0 as *mut u16),
    }
}

/// Apply one explicit ACE to the target's DACL via
/// `SetEntriesInAclW(GRANT|DENY)` and `SetNamedSecurityInfoW`. The
/// per-path mutex is held by the caller (currently
/// [`DaclManager::apply_one`]) so that the scan-for-prior-state and
/// apply happen as a single critical section.
///
/// Note: `SetEntriesInAclW` coalesces rights for the same trustee. Any
/// pre-existing explicit ACE for our SID will be merged with ours into
/// a single ACE in the resulting DACL. The caller is responsible for
/// having captured the pre-merge state into
/// [`AppliedAce::prior_state`] so [`restore_one`] can correctly unwind
/// by issuing `REVOKE_ACCESS` plus a regrant of the captured state.
fn apply_ace(entry: &AppliedAce) -> Result<(), DaclError> {
    apply_explicit_ace(
        &entry.canonical_path,
        &entry.sid_string,
        entry.access_mask,
        entry.ace_type,
        entry.inheritable,
    )
}

/// Apply a single explicit ACE to `path`'s DACL without any restore
/// tracking. Used by [`apply_ace`] (which adds prior-state capture and
/// persistence on top) and by host-prep entry points that want a
/// persistent ACE outside the [`DaclManager`] lifecycle.
///
/// The caller is responsible for ensuring the process has `WRITE_DAC`
/// on the path. No state is recorded; the change persists across
/// process exit.
pub fn apply_explicit_ace(
    path: &Path,
    sid_str: &str,
    access_mask: u32,
    ace_type: AceType,
    inheritable: bool,
) -> Result<(), DaclError> {
    let sid = OwnedSid::parse(sid_str)?;

    let inheritance: u32 = if inheritable {
        OBJECT_INHERIT_ACE.0 | CONTAINER_INHERIT_ACE.0
    } else {
        0
    };
    let mode = match ace_type {
        AceType::Allow => GRANT_ACCESS,
        AceType::Deny => DENY_ACCESS,
    };
    let ea = EXPLICIT_ACCESS_W {
        grfAccessPermissions: access_mask,
        grfAccessMode: mode,
        grfInheritance: ACE_FLAGS(inheritance),
        Trustee: trustee_for(&sid),
    };

    let path_w = wide(path);
    let object_name = PCWSTR(path_w.as_ptr());

    let mut existing_dacl: *mut ACL = ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR(ptr::null_mut());
    let rc = unsafe {
        GetNamedSecurityInfoW(
            object_name,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut existing_dacl),
            None,
            &mut sd,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(win32_err(path, "GetNamedSecurityInfoW", rc));
    }

    let mut new_dacl: *mut ACL = ptr::null_mut();
    let rc = unsafe {
        SetEntriesInAclW(
            Some(&[ea]),
            Some(existing_dacl as *const ACL),
            &mut new_dacl,
        )
    };

    if rc != ERROR_SUCCESS {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(sd.0)));
        }
        return Err(win32_err(path, "SetEntriesInAclW", rc));
    }

    let rc = unsafe {
        SetNamedSecurityInfoW(
            object_name,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(new_dacl as *const ACL),
            None,
        )
    };

    unsafe {
        if !new_dacl.is_null() {
            let _ = LocalFree(Some(HLOCAL(new_dacl as *mut c_void)));
        }
        let _ = LocalFree(Some(HLOCAL(sd.0)));
    }

    if rc != ERROR_SUCCESS {
        if rc.0 == 5 {
            return Err(DaclError::WriteDacDenied {
                path: path.to_path_buf(),
                reason: format!("SetNamedSecurityInfoW: {rc:?}"),
            });
        }
        return Err(win32_err(path, "SetNamedSecurityInfoW", rc));
    }

    Ok(())
}

/// Revoke explicit ACEs on `path` for `sid_str` whose `(access_mask,
/// ace_type, inherit_flags)` tuple exactly matches the requested one.
/// Mirrors [`apply_explicit_ace`] in reverse: any non-matching
/// explicit ACE for the same SID — including those authored by other
/// tools (e.g. `icacls C:\ /grant "ALL APPLICATION PACKAGES":(R)`) —
/// is preserved.
///
/// Returns the count of ACEs removed. `Ok(0)` is the no-op case (no
/// matching ACE exists) and is *not* an error.
///
/// Implementation: scan the existing DACL for explicit ACEs attached
/// to the SID; partition into matches/keeps; if any matches, replace
/// all the SID's contributions with a single `REVOKE_ACCESS` + replay
/// of the keeps. Inherited ACEs are not touched.
pub fn revoke_specific_aces_for_sid(
    path: &Path,
    sid_str: &str,
    access_mask: u32,
    ace_type: AceType,
    inheritable: bool,
) -> Result<usize, DaclError> {
    // Compute the inherit-flags byte we'd have applied (matches the
    // logic in `apply_explicit_ace`). Inherited ACEs are masked off by
    // `scan_explicit_aces_for_sid` so the captured `inherit_flags`
    // contains only OI/CI/NP/IO bits.
    let expected_inherit_flags: u8 = if inheritable {
        (OBJECT_INHERIT_ACE.0 | CONTAINER_INHERIT_ACE.0) as u8
    } else {
        0
    };

    let priors = scan_explicit_aces_for_sid(path, sid_str)?;
    let mut keeps: Vec<PriorAce> = Vec::new();
    let mut removed = 0usize;
    for p in priors {
        if p.access_mask == access_mask
            && p.ace_type == ace_type
            && p.inherit_flags == expected_inherit_flags
        {
            removed += 1;
        } else {
            keeps.push(p);
        }
    }

    if removed == 0 {
        return Ok(0);
    }

    // Delegate to the manual-rebuild helper. Same reason as
    // `restore_one`: `SetEntriesInAclW(REVOKE_ACCESS)` doesn't
    // reliably remove explicit DENY ACEs on Windows 11 25H2, so we
    // rebuild the DACL by hand.
    replace_explicit_aces_for_sid(path, sid_str, &keeps)?;
    Ok(removed)
}

/// Restore the target's DACL to its pre-apply state by:
/// 1. acquiring the per-path mutex,
/// 2. delegating to [`replace_explicit_aces_for_sid`], which removes
///    every explicit ACE for our SID and re-adds the captured prior
///    entries.
///
/// We intentionally do **not** use `SetEntriesInAclW(REVOKE_ACCESS)`
/// here — on Windows 11 25H2 it fails to remove explicit
/// `ACCESS_DENIED` ACEs (see `deny_round_trip_leaves_no_residue`).
/// Manual ACL surgery via [`replace_explicit_aces_for_sid`] is the
/// reliable path.
///
/// Returns `Ok(Some(warning))` for idempotent no-ops (e.g. the target
/// had no DACL); `Ok(None)` on a fully applied restore.
fn restore_one(entry: &AppliedAce) -> Result<Option<String>, DaclError> {
    let _guard = PathMutexGuard::acquire(&entry.canonical_path)?;
    replace_explicit_aces_for_sid(&entry.canonical_path, &entry.sid_string, &entry.prior_state)?;
    Ok(None)
}

/// Scan the DACL on `canonical` and return every explicit
/// (non-inherited) ACE attached to `sid_str`, regardless of allow/deny
/// type. Called from [`DaclManager::apply_one`] under the per-path
/// mutex so the captured state is consistent with the subsequent
/// apply.
pub fn scan_explicit_aces_for_sid(
    canonical: &Path,
    sid_str: &str,
) -> Result<Vec<PriorAce>, DaclError> {
    let sid = OwnedSid::parse(sid_str)?;
    let path_w = wide(canonical);
    let object_name = PCWSTR(path_w.as_ptr());

    let mut existing_dacl: *mut ACL = ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR(ptr::null_mut());
    let rc = unsafe {
        GetNamedSecurityInfoW(
            object_name,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut existing_dacl),
            None,
            &mut sd,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(win32_err(canonical, "GetNamedSecurityInfoW", rc));
    }
    if existing_dacl.is_null() {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(sd.0)));
        }
        return Ok(Vec::new());
    }

    let mut info = ACL_SIZE_INFORMATION::default();
    let info_sz = std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32;
    let scan_res = unsafe {
        GetAclInformation(
            existing_dacl,
            &mut info as *mut _ as *mut c_void,
            info_sz,
            AclSizeInformation,
        )
    };
    if let Err(e) = scan_res {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(sd.0)));
        }
        return Err(win32_err_str(canonical, &format!("GetAclInformation: {e}")));
    }

    let mut prior: Vec<PriorAce> = Vec::new();
    let inherited_bit = INHERITED_ACE.0 as u8;
    for i in 0..info.AceCount {
        let mut ace_ptr: *mut c_void = ptr::null_mut();
        let gace = unsafe { GetAce(existing_dacl, i, &mut ace_ptr) };
        if gace.is_err() {
            continue;
        }
        let header = unsafe { &*(ace_ptr as *const ACE_HEADER) };
        if (header.AceFlags & inherited_bit) != 0 {
            continue;
        }
        let ace_type = match header.AceType {
            0x00 => AceType::Allow, // ACCESS_ALLOWED_ACE_TYPE
            0x01 => AceType::Deny,  // ACCESS_DENIED_ACE_TYPE
            _ => continue,          // ignore object/compound/audit ACEs
        };
        // ACCESS_ALLOWED_ACE and ACCESS_DENIED_ACE share layout up to
        // and including SidStart.
        let mask_and_sid = ace_ptr as *const ACCESS_ALLOWED_ACE;
        let ace_mask = unsafe { (*mask_and_sid).Mask };
        let ace_sid = PSID(unsafe { &(*mask_and_sid).SidStart } as *const _ as *mut c_void);
        if unsafe { EqualSid(ace_sid, sid.as_psid()).is_ok() } {
            prior.push(PriorAce {
                ace_type,
                access_mask: ace_mask,
                // Preserve all inheritance bits (OI, CI, NP, IO);
                // INHERITED_ACE filtered above so it's already 0 here.
                inherit_flags: header.AceFlags & !inherited_bit,
            });
        }
    }
    // Keep the import live (ACCESS_DENIED_ACE shares prefix with
    // ACCESS_ALLOWED_ACE; we cast both via the latter).
    let _ = std::mem::size_of::<ACCESS_DENIED_ACE>();
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sd.0)));
    }
    Ok(prior)
}

/// SIDs every AppContainer process token implicitly belongs to. A grant
/// to any of these is observed by every AppContainer the OS launches.
///
/// - `S-1-15-2-1` — `APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES`.
/// - `S-1-15-2-2` — `APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES`.
/// - `S-1-1-0`    — `Everyone`. AppContainer tokens DO retain Everyone;
///   they strip `Authenticated Users` and `Users`, so we deliberately
///   omit those.
const WELL_KNOWN_AC_SIDS: &[&str] = &["S-1-15-2-1", "S-1-15-2-2", "S-1-1-0"];

/// Walk the effective DACL on `path` and compute the access mask granted
/// to a process whose only relevant identities are the well-known
/// AppContainer-membership SIDs (`ALL APPLICATION PACKAGES`,
/// `ALL RESTRICTED APPLICATION PACKAGES`, and `Everyone`). Inherited
/// ACEs are included; per-container explicit grants on a specific
/// AppContainer SID are NOT — the caller is presumably deciding
/// whether such a grant is needed.
///
/// Walking is canonical: a `DENY` ACE matching one of these SIDs marks
/// bits as denied, and subsequent `ALLOW` ACEs can only add bits that
/// haven't been denied. This matches Windows' own access check for the
/// ALLOW path.
///
/// Returns 0 when the DACL is empty / NULL.
pub fn compute_appcontainer_effective_access(path: &Path) -> Result<u32, DaclError> {
    let well_known = well_known_ac_sids();

    let path_w = wide(path);
    let object_name = PCWSTR(path_w.as_ptr());
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR(ptr::null_mut());
    let rc = unsafe {
        GetNamedSecurityInfoW(
            object_name,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            &mut sd,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(win32_err(path, "GetNamedSecurityInfoW", rc));
    }
    if dacl.is_null() {
        // NULL DACL means full access for everyone, but per Microsoft
        // guidance we treat that as "trust nothing about it" and return
        // 0 — the caller will fall back to WRITE_DAC + apply.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(sd.0)));
        }
        return Ok(0);
    }

    let mut info = ACL_SIZE_INFORMATION::default();
    let info_sz = std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32;
    let scan_res = unsafe {
        GetAclInformation(
            dacl,
            &mut info as *mut _ as *mut c_void,
            info_sz,
            AclSizeInformation,
        )
    };
    if let Err(e) = scan_res {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(sd.0)));
        }
        return Err(win32_err_str(path, &format!("GetAclInformation: {e}")));
    }

    let mut allowed: u32 = 0;
    let mut denied: u32 = 0;
    for i in 0..info.AceCount {
        let mut ace_ptr: *mut c_void = ptr::null_mut();
        if unsafe { GetAce(dacl, i, &mut ace_ptr) }.is_err() {
            continue;
        }
        let header = unsafe { &*(ace_ptr as *const ACE_HEADER) };
        let ace_type = match header.AceType {
            0x00 => AceType::Allow,
            0x01 => AceType::Deny,
            _ => continue, // ignore object/compound/audit ACEs
        };
        let mask_and_sid = ace_ptr as *const ACCESS_ALLOWED_ACE;
        let ace_mask = unsafe { (*mask_and_sid).Mask };
        let ace_sid = PSID(unsafe { &(*mask_and_sid).SidStart } as *const _ as *mut c_void);
        let matches = well_known
            .iter()
            .any(|s| unsafe { EqualSid(ace_sid, s.as_psid()).is_ok() });
        if !matches {
            continue;
        }
        match ace_type {
            AceType::Deny => {
                // Bits this ACE denies that haven't been definitively
                // allowed yet become "denied" for the rest of the walk.
                denied |= ace_mask & !allowed;
            }
            AceType::Allow => {
                // Bits this ACE allows that haven't been denied yet
                // become "allowed" for the rest of the walk.
                allowed |= ace_mask & !denied;
            }
        }
    }
    // Keep the import live (ACCESS_DENIED_ACE shares prefix with
    // ACCESS_ALLOWED_ACE; we cast both via the latter).
    let _ = std::mem::size_of::<ACCESS_DENIED_ACE>();
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sd.0)));
    }
    Ok(allowed)
}

/// Read-only probe used by the fallback detector's Tier-3 host-prep
/// advice: returns `Some(true)` when BOTH well-known AppContainer
/// package SIDs (`S-1-15-2-1`, `S-1-15-2-2`) have a non-zero explicit
/// Allow ACE on `\Device\Null`, `Some(false)` when at least one is
/// missing, and `None` when the device's DACL could not be read (the
/// open or the security query failed).
///
/// This mirrors the symptom that `wxc-host-prep prepare-null-device`
/// fixes — AppContainer processes being unable to open `NUL` — without
/// requiring `SeSecurityPrivilege` (the SACL is never read) and without
/// taking a dependency on the `wxc_host_prep` crate. `Everyone`
/// (`S-1-1-0`) is deliberately NOT accepted as satisfying the check:
/// the kernel-default `\Device\Null` descriptor can grant `Everyone`
/// while still failing AppContainer access, so only the package SIDs
/// are probative. A NULL DACL (grants everyone everything) is treated
/// as "accessible".
pub fn null_device_appcontainer_grants() -> Option<bool> {
    use windows::Win32::Foundation::GENERIC_READ;
    use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING,
    };

    // `READ_CONTROL` is the only security-class right needed to read a
    // DACL; `GENERIC_READ` keeps the open symmetric with how the device
    // is normally opened (some drivers reject a security-class-only
    // open). We deliberately do NOT request WRITE_DAC / WRITE_OWNER /
    // ACCESS_SYSTEM_SECURITY — a normal, unprivileged token can read
    // the DACL, and asking for more could fail the open spuriously.
    const READ_CONTROL: u32 = 0x0002_0000;

    // `\\.\NUL` resolves through the I/O manager to `\Device\Null`.
    let path: Vec<u16> = "\\\\.\\NUL\0".encode_utf16().collect();
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

    // SAFETY: standard CreateFileW invocation; every pointer references
    // local data or is NULL.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            GENERIC_READ.0 | READ_CONTROL,
            share,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    };
    let handle = match handle {
        Ok(h) if !h.is_invalid() => h,
        _ => return None,
    };

    let mut dacl: *mut ACL = ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR(ptr::null_mut());
    // SAFETY: `handle` is a valid kernel-object handle opened with
    // READ_CONTROL; the out-params are owned locals.
    let rc = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            Some(&mut sd),
        )
    };
    // We have everything we need from the handle; close it regardless.
    // SAFETY: `handle` came from a successful CreateFileW above.
    unsafe {
        let _ = CloseHandle(handle);
    }
    if rc != ERROR_SUCCESS {
        return None;
    }
    if dacl.is_null() {
        // A NULL DACL grants everyone full access — the device is
        // reachable by AppContainer, so no prep is needed.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(sd.0)));
        }
        return Some(true);
    }

    let sids = match (OwnedSid::parse("S-1-15-2-1"), OwnedSid::parse("S-1-15-2-2")) {
        (Ok(a), Ok(b)) => [a, b],
        _ => {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(sd.0)));
            }
            return None;
        }
    };

    let mut info = ACL_SIZE_INFORMATION::default();
    let info_sz = std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32;
    if unsafe {
        GetAclInformation(
            dacl,
            &mut info as *mut _ as *mut c_void,
            info_sz,
            AclSizeInformation,
        )
    }
    .is_err()
    {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(sd.0)));
        }
        return None;
    }

    // Per package SID, whether it has a non-zero Allow grant.
    let mut granted = [false; 2];
    for i in 0..info.AceCount {
        let mut ace_ptr: *mut c_void = ptr::null_mut();
        if unsafe { GetAce(dacl, i, &mut ace_ptr) }.is_err() {
            continue;
        }
        let header = unsafe { &*(ace_ptr as *const ACE_HEADER) };
        // ACCESS_ALLOWED_ACE_TYPE only; deny / audit / object ACEs are
        // not "grants" and are ignored.
        if header.AceType != 0x00 {
            continue;
        }
        let allowed = ace_ptr as *const ACCESS_ALLOWED_ACE;
        let mask = unsafe { (*allowed).Mask };
        if mask == 0 {
            continue;
        }
        let ace_sid = PSID(unsafe { &(*allowed).SidStart } as *const _ as *mut c_void);
        for (idx, want) in sids.iter().enumerate() {
            if unsafe { EqualSid(ace_sid, want.as_psid()).is_ok() } {
                granted[idx] = true;
            }
        }
    }

    unsafe {
        let _ = LocalFree(Some(HLOCAL(sd.0)));
    }
    Some(granted[0] && granted[1])
}

/// Rebuild `path`'s DACL by dropping every explicit ACE whose trustee
/// is `sid_str`, then re-appending `replay` ACEs (also for `sid_str`)
/// in canonical order. Inherited ACEs and explicit ACEs for other
/// trustees are preserved verbatim.
///
/// This exists because `SetEntriesInAclW` with `REVOKE_ACCESS` on
/// Windows 11 25H2 **fails to remove explicit ACCESS_DENIED ACEs**
/// from the target DACL (see `deny_round_trip_leaves_no_residue`
/// regression test). The documented behaviour (REVOKE removes all
/// trustee ACEs) does not match observed behaviour. We work around
/// it by building a fresh ACL via `InitializeAcl` + `AddAce`, which
/// gives us deterministic control over what survives.
fn replace_explicit_aces_for_sid(
    path: &Path,
    sid_str: &str,
    replay: &[PriorAce],
) -> Result<(), DaclError> {
    let sid = OwnedSid::parse(sid_str)?;
    let path_w = wide(path);
    let object_name = PCWSTR(path_w.as_ptr());

    let mut existing_dacl: *mut ACL = ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR(ptr::null_mut());
    let rc = unsafe {
        GetNamedSecurityInfoW(
            object_name,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut existing_dacl),
            None,
            &mut sd,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(win32_err(path, "GetNamedSecurityInfoW", rc));
    }

    let result = replace_explicit_aces_for_sid_inner(path, &sid, existing_dacl, replay);

    unsafe {
        let _ = LocalFree(Some(HLOCAL(sd.0)));
    }
    result.and_then(|new_acl_dwords| {
        // `new_acl_dwords` is the freshly-built ACL buffer; we apply
        // it via `SetNamedSecurityInfoW` outside the inner helper so
        // the SD cleanup above can still run on the early-return path.
        let new_acl_ptr = new_acl_dwords.as_ptr() as *const ACL;
        let rc = unsafe {
            SetNamedSecurityInfoW(
                object_name,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(new_acl_ptr),
                None,
            )
        };
        if rc != ERROR_SUCCESS {
            if rc.0 == 5 {
                return Err(DaclError::WriteDacDenied {
                    path: path.to_path_buf(),
                    reason: format!("SetNamedSecurityInfoW: {rc:?}"),
                });
            }
            return Err(win32_err(path, "SetNamedSecurityInfoW", rc));
        }
        Ok(())
    })
}

/// Canonical-order bucket for an ACE. Smaller bucket = earlier slot
/// in the rebuilt DACL. Per MS guidance (`AddAce` docs / "Order of
/// ACEs in a DACL"):
///   0 — explicit ACCESS_DENIED (type 0x01)
///   1 — explicit ACCESS_ALLOWED (type 0x00)
///   2 — explicit other (object ACEs, audit, etc.)
///   3 — inherited (any type, in original order)
fn canonical_bucket(ace_type: u8, inherited: bool) -> u8 {
    if inherited {
        3
    } else {
        match ace_type {
            0x01 => 0,
            0x00 => 1,
            _ => 2,
        }
    }
}

/// The pure-rebuild half of [`replace_explicit_aces_for_sid`]:
/// walks the existing DACL, filters explicit ACEs for our SID, adds
/// replay ACEs, and returns a `Vec<u32>` whose bytes are the new ACL
/// (Vec<u32> guarantees 4-byte alignment, which `InitializeAcl`
/// requires). Returns an empty vec if there is no work and the
/// caller can short-circuit.
fn replace_explicit_aces_for_sid_inner(
    path: &Path,
    sid: &OwnedSid,
    existing_dacl: *mut ACL,
    replay: &[PriorAce],
) -> Result<Vec<u32>, DaclError> {
    // Entries we will emit into the rebuilt ACL. Either a verbatim
    // copy of an existing ACE (`Kept`) or one of the `replay` slice
    // entries materialized via `AddAccessAllowed/DeniedAceEx`.
    // `bucket` is the canonical-order sort key (see `canonical_bucket`).
    enum Entry<'a> {
        Kept {
            ptr: *mut c_void,
            size: u32,
            bucket: u8,
            order: u32,
        },
        Replay {
            prior: &'a PriorAce,
            bucket: u8,
            order: u32,
        },
    }

    let mut entries: Vec<Entry> = Vec::new();
    let mut keeps_bytes: u32 = 0;
    let mut next_order: u32 = 0;

    if !existing_dacl.is_null() {
        let mut info = ACL_SIZE_INFORMATION::default();
        let info_sz = std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32;
        unsafe {
            GetAclInformation(
                existing_dacl,
                &mut info as *mut _ as *mut c_void,
                info_sz,
                AclSizeInformation,
            )
            .map_err(|e| win32_err_str(path, &format!("GetAclInformation: {e}")))?;
        }
        let inherited_bit = INHERITED_ACE.0 as u8;
        for i in 0..info.AceCount {
            let mut ace_ptr: *mut c_void = ptr::null_mut();
            if unsafe { GetAce(existing_dacl, i, &mut ace_ptr) }.is_err() {
                continue;
            }
            let header = unsafe { &*(ace_ptr as *const ACE_HEADER) };
            let inherited = (header.AceFlags & inherited_bit) != 0;
            let mut drop_it = false;
            if !inherited && (header.AceType == 0x00 || header.AceType == 0x01) {
                // ACCESS_ALLOWED_ACE and ACCESS_DENIED_ACE share the
                // mask/SID layout. The SID immediately follows the
                // mask via the `SidStart` inline field.
                let ace_struct = ace_ptr as *const ACCESS_ALLOWED_ACE;
                let ace_sid = PSID(unsafe { &(*ace_struct).SidStart } as *const _ as *mut c_void);
                if unsafe { EqualSid(ace_sid, sid.as_psid()).is_ok() } {
                    drop_it = true;
                }
            }
            if !drop_it {
                entries.push(Entry::Kept {
                    ptr: ace_ptr,
                    size: header.AceSize as u32,
                    bucket: canonical_bucket(header.AceType, inherited),
                    order: next_order,
                });
                next_order += 1;
                keeps_bytes += header.AceSize as u32;
            }
        }
    }

    // Replay ACEs are by construction explicit (non-inherited) — we
    // only persist explicit prior ACEs for our SID. Bucket them as
    // explicit-deny / explicit-allow accordingly.
    for prior in replay {
        let ace_type_byte = match prior.ace_type {
            AceType::Allow => 0x00u8,
            AceType::Deny => 0x01u8,
        };
        entries.push(Entry::Replay {
            prior,
            bucket: canonical_bucket(ace_type_byte, false),
            order: next_order,
        });
        next_order += 1;
    }

    // Stable sort by (bucket, original order). Stability preserves the
    // original DACL ordering inside each bucket so byte layout doesn't
    // shuffle inherited or unrelated explicit ACEs.
    entries.sort_by_key(|e| match e {
        Entry::Kept { bucket, order, .. } | Entry::Replay { bucket, order, .. } => {
            (*bucket, *order)
        }
    });

    // Per-replay-ACE byte size: ACE_HEADER (4) + ACCESS_MASK (4) + SID
    // bytes. `ACCESS_ALLOWED_ACE`'s `SidStart` field is a `u32`
    // inline DWORD that's the first 4 bytes of the SID, so we add
    // `GetLengthSid` to that — but we also include the inline DWORD
    // size, then subtract the trailing padding. Simpler: ACE header
    // is 4 bytes; mask is 4; SID is `GetLengthSid` bytes — total is
    // 8 + GetLengthSid(sid).
    let sid_len: u32 = unsafe { GetLengthSid(sid.as_psid()) };
    let per_replay_size: u32 = 8 + sid_len;
    let replay_bytes: u32 = per_replay_size.saturating_mul(replay.len() as u32);

    let mut new_acl_size: u32 = std::mem::size_of::<ACL>() as u32 + keeps_bytes + replay_bytes;
    // ACL must be DWORD-aligned and ACL_SIZE_INFORMATION reports
    // sizes in multiples of `sizeof(DWORD)`. Round up to be safe.
    new_acl_size = (new_acl_size + 3) & !3;
    // InitializeAcl rejects a buffer too small to hold even an empty
    // ACL header (the documented minimum is `sizeof(ACL)`). The
    // arithmetic above already guarantees this, but the safety net
    // is cheap.
    let min_acl_size = std::mem::size_of::<ACL>() as u32;
    if new_acl_size < min_acl_size {
        new_acl_size = min_acl_size;
    }

    // Vec<u32> guarantees 4-byte alignment. The size we pass to
    // InitializeAcl is in bytes.
    let dwords = (new_acl_size as usize).div_ceil(4);
    let mut new_acl_buf: Vec<u32> = vec![0u32; dwords];
    let new_acl_ptr = new_acl_buf.as_mut_ptr() as *mut ACL;

    unsafe {
        InitializeAcl(new_acl_ptr, new_acl_size, ACL_REVISION)
            .map_err(|e| win32_err_str(path, &format!("InitializeAcl: {e}")))?;
    }

    // Emit ACEs in canonical (bucket-sorted) order. Both `AddAce` and
    // the typed `AddAccess{Allowed,Denied}AceEx` family append at the
    // tail of the ACL (despite the latter's name, they do NOT
    // canonicalize on insert), so we must drive the order ourselves.
    for entry in &entries {
        match entry {
            Entry::Kept { ptr, size, .. } => unsafe {
                AddAce(new_acl_ptr, ACL_REVISION, u32::MAX, *ptr, *size)
                    .map_err(|e| win32_err_str(path, &format!("AddAce(keep): {e}")))?;
            },
            Entry::Replay { prior, .. } => {
                let flags = ACE_FLAGS(prior.inherit_flags as u32);
                let res = unsafe {
                    match prior.ace_type {
                        AceType::Allow => AddAccessAllowedAceEx(
                            new_acl_ptr,
                            ACL_REVISION,
                            flags,
                            prior.access_mask,
                            sid.as_psid(),
                        ),
                        AceType::Deny => AddAccessDeniedAceEx(
                            new_acl_ptr,
                            ACL_REVISION,
                            flags,
                            prior.access_mask,
                            sid.as_psid(),
                        ),
                    }
                };
                res.map_err(|e| {
                    win32_err_str(path, &format!("AddAccess{:?}AceEx: {e}", prior.ace_type))
                })?;
            }
        }
    }

    Ok(new_acl_buf)
}

fn win32_err(path: &Path, op: &str, rc: WIN32_ERROR) -> DaclError {
    DaclError::Win32 {
        path: path.to_path_buf(),
        reason: format!("{op}: {rc:?}"),
    }
}

fn win32_err_str(path: &Path, msg: &str) -> DaclError {
    DaclError::Win32 {
        path: path.to_path_buf(),
        reason: msg.to_string(),
    }
}

// -------------------------------------------------------------------------
// Win32: process-alive check
// -------------------------------------------------------------------------

/// RAII wrapper around a `HANDLE` that auto-closes on drop. Used to
/// keep the multi-branch return paths in [`process_alive_with_image`]
/// from leaking the handle.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// Liveness probe for the orphan-recovery path.
///
/// Returns `true` if a process with `pid` is currently running, has
/// the expected image basename, **and** (when `expected_start_filetime`
/// is `Some` and non-zero) has a kernel-recorded process creation
/// time exactly equal to the recorded value. `GetProcessTimes`
/// returns a fixed kernel timestamp for the lifetime of a process, so
/// exact equality is the right test — any deviation means we are
/// looking at a different process that happens to share the recorded
/// PID.
///
/// Returns `false` if any check fails. The `None`/`Some(0)` arm
/// preserves PID-and-image-only liveness for legacy state files
/// written before [`StateFile::started_at_filetime`] was populated;
/// new state files always carry a meaningful creation time.
fn process_alive_with_image(
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

/// Process creation time of the *current* process as a Windows FILETIME
/// (100-ns intervals since 1601-01-01 UTC). `GetCurrentProcess` returns
/// a pseudo-handle that does not need closing.
fn process_creation_filetime() -> Result<u64, DaclError> {
    unsafe {
        let h = GetCurrentProcess();
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        GetProcessTimes(h, &mut creation, &mut exit, &mut kernel, &mut user).map_err(|e| {
            DaclError::Win32 {
                path: PathBuf::new(),
                reason: format!("GetProcessTimes(GetCurrentProcess): {e}"),
            }
        })?;
        Ok(((creation.dwHighDateTime as u64) << 32) | (creation.dwLowDateTime as u64))
    }
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Note: the analogous compile-time `const _: () = assert!(...)`
    // block at module level (above) covers RW_MASK/RO_MASK shape
    // invariants. Putting them there means a value drift fails the
    // build instead of silently passing tests on hosts where the
    // suite is filtered.

    #[test]
    fn state_file_roundtrip() {
        let s = StateFile {
            run_id: "pid-42-deadbeef".into(),
            pid: 42,
            image_name: "wxc-exec.exe".into(),
            started_at_filetime: 132_000_000_000_000_000,
            applied: vec![AppliedAce {
                canonical_path: PathBuf::from(r"\\?\C:\tmp\foo"),
                sid_string: "S-1-15-2-1-2-3-4-5-6-7".into(),
                access_mask: 0x12_3456,
                ace_type: AceType::Allow,
                inheritable: true,
                prior_state: vec![PriorAce {
                    ace_type: AceType::Allow,
                    access_mask: 0x01FF,
                    inherit_flags: (OBJECT_INHERIT_ACE.0 | CONTAINER_INHERIT_ACE.0) as u8,
                }],
            }],
        };
        let bytes = serde_json::to_vec(&s).unwrap();
        let parsed: StateFile = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.run_id, s.run_id);
        assert_eq!(parsed.pid, s.pid);
        assert_eq!(parsed.started_at_filetime, s.started_at_filetime);
        assert_eq!(parsed.applied.len(), 1);
        assert_eq!(parsed.applied[0].access_mask, 0x12_3456);
        assert_eq!(parsed.applied[0].ace_type, AceType::Allow);
        assert_eq!(parsed.applied[0].prior_state.len(), 1);
        assert_eq!(parsed.applied[0].prior_state[0].access_mask, 0x01FF);
    }

    /// Old state files written before the `prior_state` field existed
    /// (and possibly carrying a vestigial `pre_existing` field) must
    /// still deserialize cleanly.
    #[test]
    fn state_file_back_compat_no_prior_state_field() {
        // Hand-crafted JSON without `prior_state`. Older Phase 3 state
        // files also carried a `pre_existing` bool, which serde
        // silently ignores as an unknown field.
        let json = br#"{
            "run_id": "pid-1-old",
            "pid": 1,
            "image_name": "wxc-exec.exe",
            "started_at_filetime": 132000000000000000,
            "applied": [{
                "canonical_path": "\\\\?\\C:\\tmp\\foo",
                "sid_string": "S-1-1-0",
                "access_mask": 1,
                "ace_type": "Allow",
                "inheritable": false,
                "pre_existing": false
            }]
        }"#;
        let parsed: StateFile = serde_json::from_slice(json).expect("legacy state must parse");
        assert!(parsed.applied[0].prior_state.is_empty());
    }

    #[test]
    fn process_creation_time_is_after_unix_epoch_and_not_in_the_future() {
        let t = process_creation_filetime().expect("GetProcessTimes should succeed");
        // FILETIME ticks for the Unix epoch (1970-01-01 UTC).
        const UNIX_EPOCH_AS_FILETIME: u64 = 11_644_473_600 * 10_000_000;
        assert!(
            t > UNIX_EPOCH_AS_FILETIME,
            "process_creation_filetime ({t}) should be > Unix epoch ({UNIX_EPOCH_AS_FILETIME})"
        );
        // And must not be in the future. Compare against the system
        // time, allowing a generous 10s of slack for clock skew.
        let now_ft = unsafe {
            use windows::Win32::System::SystemInformation::GetSystemTimeAsFileTime;
            let ft = GetSystemTimeAsFileTime();
            ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64)
        };
        const TEN_SECONDS_TICKS: u64 = 10 * 10_000_000;
        assert!(
            t <= now_ft.saturating_add(TEN_SECONDS_TICKS),
            "process_creation_filetime ({t}) must not be after now ({now_ft})"
        );
    }

    #[test]
    fn ensure_local_canonical_prefix_accepts_local() {
        // Win32 file namespace (typical `fs::canonicalize` output).
        assert!(ensure_local_canonical_prefix(Path::new(r"\\?\C:\tmp\foo")).is_ok());
        // DOS device namespace — volume GUIDs, drives by name, etc.
        assert!(ensure_local_canonical_prefix(Path::new(
            r"\\.\Volume{12345678-1234-1234-1234-123456789abc}\foo"
        ))
        .is_ok());
        assert!(ensure_local_canonical_prefix(Path::new(r"\\.\C:\tmp\foo")).is_ok());
        // Plain drive-letter paths (callers may pass them directly).
        assert!(ensure_local_canonical_prefix(Path::new(r"C:\tmp\foo")).is_ok());
    }

    #[test]
    fn ensure_local_canonical_prefix_rejects_unc_namespace() {
        // The form `fs::canonicalize` emits for shares.
        let err = ensure_local_canonical_prefix(Path::new(r"\\?\UNC\server\share\foo"));
        assert!(matches!(err, Err(DaclError::NetworkPathRejected(_))));
        // Lower-case variant.
        let err = ensure_local_canonical_prefix(Path::new(r"\\?\unc\server\share\foo"));
        assert!(matches!(err, Err(DaclError::NetworkPathRejected(_))));
    }

    #[test]
    fn ensure_local_canonical_prefix_rejects_raw_unc() {
        // Bare `\\server\share\...` — not via NT namespace.
        let err = ensure_local_canonical_prefix(Path::new(r"\\server\share\foo"));
        assert!(matches!(err, Err(DaclError::NetworkPathRejected(_))));
    }

    #[test]
    fn mutex_name_is_deterministic_and_local_prefix() {
        let p = PathBuf::from(r"C:\tmp\foo");
        let n1 = mutex_name_for(&p);
        let n2 = mutex_name_for(&p);
        assert_eq!(n1, n2);
        assert!(n1.starts_with("Local\\Microsoft.MXC.Dacl."));
        // 16 hex chars of hash.
        assert_eq!(n1.len(), "Local\\Microsoft.MXC.Dacl.".len() + 16);
    }

    #[test]
    fn mutex_name_case_insensitive() {
        let a = mutex_name_for(&PathBuf::from(r"C:\Tmp\Foo"));
        let b = mutex_name_for(&PathBuf::from(r"c:\tmp\foo"));
        assert_eq!(a, b);
    }

    #[test]
    fn access_mask_layouts() {
        let rw = FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | FILE_GENERIC_EXECUTE.0 | DELETE.0;
        let ro = FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0;
        assert_ne!(rw, 0);
        assert_ne!(ro, 0);
        assert!(rw & ro == ro, "rw should be a superset of ro");
        // FILE_TRAVERSE = FILE_EXECUTE = 0x20 is part of FILE_GENERIC_EXECUTE.
        // Both masks must carry it so chdir into granted dirs works.
        assert!(rw & 0x20 == 0x20, "rw must grant FILE_TRAVERSE");
        assert!(ro & 0x20 == 0x20, "ro must grant FILE_TRAVERSE");
        // Deny mask = FILE_ALL_ACCESS (0x1F01FF).
        assert_eq!(0x001F_01FF & 0xFF_FFFF, 0x001F_01FF);
    }

    #[test]
    fn sid_parse_valid_and_invalid() {
        // Well-known SID: Everyone (S-1-1-0). AppContainer SIDs use the
        // same parser path so this proves it works.
        let ok = OwnedSid::parse("S-1-1-0");
        assert!(ok.is_ok(), "S-1-1-0 should parse: {:?}", ok.err());
        drop(ok);
        let err = OwnedSid::parse("not-a-sid");
        assert!(matches!(err, Err(DaclError::InvalidSid(_))));
    }

    #[test]
    fn sid_parse_rejects_empty_and_oversized() {
        let empty = OwnedSid::parse("");
        assert!(matches!(empty, Err(DaclError::InvalidSid(_))));
        // A pathologically long input must be rejected before reaching Win32.
        let huge = "S-1-".to_string() + &"1".repeat(MAX_SID_STRING_LEN);
        let err = OwnedSid::parse(&huge);
        assert!(matches!(err, Err(DaclError::InvalidSid(_))));
    }

    #[test]
    fn image_name_compare_case_insensitive() {
        let a = "wxc-exec.exe";
        let b = "WXC-EXEC.EXE";
        assert!(a.eq_ignore_ascii_case(b));
    }

    #[test]
    fn run_id_format() {
        let id = generate_run_id();
        assert!(id.starts_with("pid-"));
        // pid-<digits>-<16 hex>
        let parts: Vec<&str> = id.split('-').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[2].len(), 16);
        assert!(parts[2].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn recovery_ignores_active_pid() {
        // current process is alive with our image name and matching
        // creation time → should be classified live.
        let pid = std::process::id();
        let img = current_image_basename();
        let start = process_creation_filetime().unwrap();
        assert!(process_alive_with_image(pid, &img, Some(start)));
        // And the legacy `None`/`Some(0)` path falls back to PID-and-
        // image-only liveness.
        assert!(process_alive_with_image(pid, &img, None));
        assert!(process_alive_with_image(pid, &img, Some(0)));
    }

    #[test]
    fn recovery_detects_dead_pid() {
        // PID 0 is reserved (System Idle / not a normal process).
        assert!(!process_alive_with_image(0, "anything.exe", None));
        // A very large PID is essentially guaranteed not to be running.
        assert!(!process_alive_with_image(0x7FFF_FFFE, "wxc-exec.exe", None));
    }

    #[test]
    fn recovery_detects_pid_reuse_via_creation_time() {
        // Current process is alive, but the recorded start time is
        // wildly in the past → must be classified as orphaned (PID
        // reuse scenario).
        let pid = std::process::id();
        let img = current_image_basename();
        // Year 2000 in FILETIME ticks; any real wxc-exec creation
        // time will be vastly later.
        const Y2K_FILETIME: u64 = 125_911_584_000_000_000;
        assert!(!process_alive_with_image(pid, &img, Some(Y2K_FILETIME)));
    }

    #[test]
    fn recovery_detects_pid_reuse_off_by_one_tick() {
        // Exact-equality liveness: a creation time that differs by a
        // single FILETIME tick from the recorded value must already
        // be classified as orphaned. This guards against
        // re-introducing a fuzzy-match tolerance that would weaken
        // the PID-reuse defense.
        let pid = std::process::id();
        let img = current_image_basename();
        let real = process_creation_filetime().unwrap();
        assert!(!process_alive_with_image(
            pid,
            &img,
            Some(real.saturating_add(1))
        ));
        assert!(!process_alive_with_image(
            pid,
            &img,
            Some(real.saturating_sub(1))
        ));
    }

    // ---------------- integration tests -----------------
    //
    // These tests mutate filesystem ACLs on per-test temp directories
    // owned by the running user (no elevation required), and several
    // call into `recover_orphaned_state` which scans the entire state
    // directory. To make them safe to run as part of the default
    // `cargo test --workspace` suite — and to avoid interference with
    // a concurrent real `wxc-exec` on the same host — each test scopes
    // `MXC_DACL_STATE_DIR` to a fresh tempdir for its lifetime via
    // [`crate::test_env::ScopedStateDir`]. That helper acquires the
    // shared crate-wide `ENV_LOCK`, which also serializes against
    // `dispatcher::tests` and `fallback_detector::tests` so concurrent
    // tests don't race on `MXC_DACL_STATE_DIR` / `MXC_FORCE_TIER` /
    // `MXC_BFSCFG_PATH`.
    use crate::test_env::ScopedStateDir;

    #[test]
    fn state_dir_honors_env_override() {
        let _scope = ScopedStateDir::new();
        let dir = state_dir().unwrap();
        let env = std::env::var_os("MXC_DACL_STATE_DIR").unwrap();
        assert_eq!(dir, PathBuf::from(env));
    }

    /// Apply an allow ACE for `Everyone` on a temp dir and verify restore
    /// reverses it cleanly.
    #[test]
    fn apply_allow_then_restore_temp_dir() {
        let _scope = ScopedStateDir::new();
        let td = tempfile::tempdir().unwrap();
        let mut m = DaclManager::new().unwrap();
        m.grant_appcontainer_access("S-1-1-0", &[td.path().to_path_buf()], &[])
            .unwrap();
        // Now restore.
        m.restore().unwrap();
        assert!(m.applied.is_empty());
    }

    #[test]
    fn apply_deny_then_restore_temp_file() {
        let _scope = ScopedStateDir::new();
        let td = tempfile::tempdir().unwrap();
        let f = td.path().join("file.txt");
        std::fs::write(&f, b"x").unwrap();
        let mut m = DaclManager::new().unwrap();
        m.add_deny_aces("S-1-1-0", std::slice::from_ref(&f))
            .unwrap();
        m.restore().unwrap();
        assert!(m.applied.is_empty());
    }

    /// Apply a DENY ACE to a temp directory, restore, and assert the
    /// path's DACL has no residual explicit ACEs for our SID. This
    /// Walk every ACE in `path`'s DACL (regardless of trustee), returning
    /// `(ace_type_byte, inherited)` tuples in DACL order. Used by canonical-
    /// order assertions; replicates just enough of the existing scan to
    /// see all ACEs, not just our SID's.
    fn collect_full_dacl_order(path: &Path) -> Vec<(u8, bool)> {
        let path_w = wide(path);
        let object_name = PCWSTR(path_w.as_ptr());
        let mut dacl: *mut ACL = ptr::null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR(ptr::null_mut());
        let rc = unsafe {
            GetNamedSecurityInfoW(
                object_name,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut dacl),
                None,
                &mut sd,
            )
        };
        assert_eq!(rc, ERROR_SUCCESS, "GetNamedSecurityInfoW failed: {rc:?}");
        let mut out: Vec<(u8, bool)> = Vec::new();
        if !dacl.is_null() {
            let mut info = ACL_SIZE_INFORMATION::default();
            let info_sz = std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32;
            unsafe {
                GetAclInformation(
                    dacl,
                    &mut info as *mut _ as *mut c_void,
                    info_sz,
                    AclSizeInformation,
                )
                .expect("GetAclInformation");
            }
            let inherited_bit = INHERITED_ACE.0 as u8;
            for i in 0..info.AceCount {
                let mut ace_ptr: *mut c_void = ptr::null_mut();
                if unsafe { GetAce(dacl, i, &mut ace_ptr) }.is_err() {
                    continue;
                }
                let header = unsafe { &*(ace_ptr as *const ACE_HEADER) };
                let inherited = (header.AceFlags & inherited_bit) != 0;
                out.push((header.AceType, inherited));
            }
        }
        unsafe {
            let _ = LocalFree(Some(HLOCAL(sd.0)));
        }
        out
    }

    /// Assert that `aces` (output of `collect_full_dacl_order`) is in
    /// canonical order: no explicit ACE after any inherited ACE; no
    /// explicit DENY (0x01) after any explicit ALLOW (0x00). Object/
    /// audit ACEs (other AceType bytes) are tolerated but expected only
    /// in the explicit-other bucket between explicit ALLOW and inherited.
    fn assert_canonical_order(aces: &[(u8, bool)], label: &str) {
        let mut saw_inherited = false;
        let mut saw_explicit_allow = false;
        for (i, (ty, inh)) in aces.iter().enumerate() {
            if *inh {
                saw_inherited = true;
                continue;
            }
            assert!(
                !saw_inherited,
                "{label}: explicit ACE at index {i} appears AFTER an inherited ACE. order={aces:?}"
            );
            if *ty == 0x01 {
                assert!(
                    !saw_explicit_allow,
                    "{label}: explicit DENY at index {i} appears AFTER an explicit ALLOW. order={aces:?}"
                );
            } else if *ty == 0x00 {
                saw_explicit_allow = true;
            }
        }
    }

    /// Round-trip an explicit DENY through the surgical-ACL-rewrite
    /// path and assert no residue (zero count drift) AND canonical
    /// order at every observable step. Guards against:
    ///   (1) `SetEntriesInAclW(REVOKE_ACCESS)` quirk on Windows 25H2
    ///       where DENY ACEs survive a REVOKE; observed in the field
    ///       via Win25H2Safe-Tests Phase 3 / Phase 4 "denied ACL
    ///       restored" failures.
    ///   (2) `replace_explicit_aces_for_sid_inner` emitting ACEs in
    ///       non-canonical order, which Windows accepts but resolves
    ///       per first-match — making a DENY-after-ALLOW silently
    ///       resolve as ALLOW.
    #[test]
    fn deny_round_trip_leaves_no_residue() {
        let _scope = ScopedStateDir::new();
        let td = tempfile::tempdir().unwrap();
        // Use a deterministic AppContainer-shaped SID so we can grep
        // for it in the post-restore DACL. S-1-1-0 (Everyone) often
        // appears via inheritance and would create false positives.
        // S-1-15-2-1 (ALL APPLICATION PACKAGES) does NOT inherit
        // onto a temp dir under %TEMP%, so any explicit ACE we see
        // for it after restore is unambiguously residue from us.
        let sid_str = "S-1-15-2-1";

        // Capture the explicit-ACE count for `sid_str` before apply.
        let before = scan_explicit_aces_for_sid(td.path(), sid_str).expect("scan before");
        assert_canonical_order(&collect_full_dacl_order(td.path()), "before apply");

        // First: apply an explicit ALLOW for our SID. This seeds the
        // explicit-allow slot of the canonical layout.
        let mut allow_mgr = DaclManager::new().unwrap();
        allow_mgr
            .grant_appcontainer_access(sid_str, std::slice::from_ref(&td.path().to_path_buf()), &[])
            .unwrap();
        assert_canonical_order(&collect_full_dacl_order(td.path()), "after ALLOW apply");

        // Then: apply an explicit DENY for the same SID via a fresh
        // manager. The DENY must land in the explicit-deny slot —
        // BEFORE the existing explicit ALLOW — even though it's
        // appended last by the rebuild logic. This is exactly the C1
        // regression seam.
        let mut deny_mgr = DaclManager::new().unwrap();
        deny_mgr
            .add_deny_aces(sid_str, std::slice::from_ref(&td.path().to_path_buf()))
            .unwrap();
        let mid_order = collect_full_dacl_order(td.path());
        assert_canonical_order(&mid_order, "after DENY apply");

        // After apply: at least one explicit ACE for our SID (the
        // DENY and ALLOW we just added).
        let mid = scan_explicit_aces_for_sid(td.path(), sid_str).expect("scan mid");
        assert!(
            mid.len() > before.len(),
            "apply should have added explicit ACEs for {sid_str}: before={} mid={}",
            before.len(),
            mid.len()
        );

        // Restore in reverse order (last-in, first-out — what Drop
        // would do).
        deny_mgr.restore().unwrap();
        assert!(deny_mgr.applied.is_empty());
        assert_canonical_order(&collect_full_dacl_order(td.path()), "after DENY restore");

        allow_mgr.restore().unwrap();
        assert!(allow_mgr.applied.is_empty());

        // After full restore: explicit-ACE count must match pre-apply
        // and the DACL must still be canonical.
        let after = scan_explicit_aces_for_sid(td.path(), sid_str).expect("scan after");
        assert_eq!(
            after.len(),
            before.len(),
            "restore left {} explicit ACEs for {sid_str} (expected {}). Residue: {after:?}",
            after.len(),
            before.len()
        );
        assert_canonical_order(&collect_full_dacl_order(td.path()), "after full restore");
    }

    /// Pre-load a tempdir with N>16 unrelated explicit ACEs (each for
    /// a distinct AC-family SID), then run an explicit DENY for a
    /// separate SID through the surgical rewrite path. Asserts:
    ///   1. every seeded ACE is preserved (the kept-pass copies them
    ///      verbatim via `AddAce`).
    ///   2. canonical order is restored (the new DENY lands BEFORE
    ///      all the unrelated ALLOWs even though it was appended last
    ///      to the rebuild list — this is the C1 regression seam).
    ///   3. restore unwinds the DENY without disturbing any seeded
    ///      ACE.
    ///
    /// Uses N=20 to ensure we exercise multi-ACL byte arithmetic
    /// beyond any small-N short-circuit in `replace_explicit_aces_for_sid_inner`.
    #[test]
    fn replace_explicit_aces_preserves_unrelated_and_canonicalizes() {
        let _scope = ScopedStateDir::new();
        let td = tempfile::tempdir().unwrap();

        // Seed N distinct AC-family SIDs as ALLOW grants. The
        // `S-1-15-2-N` family parses to a valid PSID whether or not
        // any package on the host actually owns that SID; the DACL
        // accepts them as explicit ALLOW ACEs.
        const N: u32 = 20;
        let mut seed_managers: Vec<DaclManager> = Vec::new();
        for i in 100..(100 + N) {
            let sid = format!("S-1-15-2-{i}");
            let mut m = DaclManager::new().unwrap();
            m.grant_appcontainer_access(&sid, std::slice::from_ref(&td.path().to_path_buf()), &[])
                .unwrap();
            seed_managers.push(m);
        }

        // Snapshot per-SID explicit-ACE counts (each should be 1).
        let baseline: Vec<(String, usize)> = (100..(100 + N))
            .map(|i| {
                let sid = format!("S-1-15-2-{i}");
                let c = scan_explicit_aces_for_sid(td.path(), &sid).unwrap().len();
                (sid, c)
            })
            .collect();
        for (sid, c) in &baseline {
            assert_eq!(*c, 1, "seeded SID {sid} should have 1 explicit ACE");
        }

        // Apply a DENY for a SID that is NOT one of the seeded grants,
        // routing through `replace_explicit_aces_for_sid_inner` with
        // 20 explicit "keep" ACEs in the existing DACL.
        let our_sid = "S-1-15-2-9999";
        let mut deny_mgr = DaclManager::new().unwrap();
        deny_mgr
            .add_deny_aces(our_sid, std::slice::from_ref(&td.path().to_path_buf()))
            .unwrap();

        // 1 + 2: every seeded ACE preserved, canonical order holds.
        let mid_order = collect_full_dacl_order(td.path());
        assert_canonical_order(&mid_order, "after N=20 keep + 1 deny");
        for (sid, c) in &baseline {
            let after = scan_explicit_aces_for_sid(td.path(), sid).unwrap().len();
            assert_eq!(
                after, *c,
                "unrelated SID {sid} lost ACEs through rewrite: before={c} after={after}"
            );
        }
        let our_mid = scan_explicit_aces_for_sid(td.path(), our_sid).unwrap();
        assert!(
            our_mid.iter().any(|p| p.ace_type == AceType::Deny),
            "our DENY should be present in the rewritten DACL"
        );

        // 3: restore unwinds without disturbing seeded ACEs.
        deny_mgr.restore().unwrap();
        assert!(deny_mgr.applied.is_empty());
        assert_canonical_order(&collect_full_dacl_order(td.path()), "after restore");
        for (sid, c) in &baseline {
            let after = scan_explicit_aces_for_sid(td.path(), sid).unwrap().len();
            assert_eq!(after, *c, "restore disturbed seeded SID {sid}");
        }
        let our_after = scan_explicit_aces_for_sid(td.path(), our_sid).unwrap();
        assert!(
            our_after.is_empty(),
            "restore left residue for our SID: {our_after:?}"
        );

        // Clean up seeded grants (Drop would also do this, but
        // explicit restore lets us catch any panic before the
        // tempdir disappears).
        for mut m in seed_managers.into_iter().rev() {
            m.restore().ok();
        }
    }

    #[test]
    fn inheritance_propagation() {
        let _scope = ScopedStateDir::new();
        let td = tempfile::tempdir().unwrap();
        let sub = td.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        let f = sub.join("file.txt");
        std::fs::write(&f, b"x").unwrap();
        let mut m = DaclManager::new().unwrap();
        m.grant_appcontainer_access("S-1-1-0", &[td.path().to_path_buf()], &[])
            .unwrap();
        // We don't inspect the child's ACL programmatically here (that
        // would re-implement most of the apply path). The contract being
        // exercised is "no error on apply, no error on restore."
        m.restore().unwrap();
    }

    /// Apply twice to the same path with overlapping rights, then
    /// restore: must leave the target's DACL exactly as it was before
    /// either apply. Defeats the `SetEntriesInAclW` rights-coalescing
    /// leak that motivated [`AppliedAce::prior_state`].
    #[test]
    fn apply_overlapping_then_restore_does_not_leak_rights() {
        let _scope = ScopedStateDir::new();
        let td = tempfile::tempdir().unwrap();
        let target = td.path().to_path_buf();
        let everyone = "S-1-1-0";

        // First apply: READ. This creates a fresh explicit ACE.
        // Second apply via a *separate* manager: WRITE | DELETE. The
        // two grants merge in the DACL because they share the same
        // trustee. Restoring the second manager must therefore use
        // its `prior_state` (containing the first's READ ACE) to
        // unwind correctly — strip the merged ACE and re-add READ.
        let mut outer = DaclManager::new().unwrap();
        outer
            .grant_appcontainer_access(everyone, std::slice::from_ref(&target), &[])
            .unwrap();

        let mut inner = DaclManager::new().unwrap();
        inner
            .add_deny_aces(everyone, std::slice::from_ref(&target))
            .unwrap();

        // The inner manager must have captured the outer manager's
        // explicit allow ACE as its prior_state.
        let captured = &inner.applied.last().unwrap().prior_state;
        assert!(
            captured.iter().any(|p| p.ace_type == AceType::Allow),
            "inner.prior_state should contain outer's allow ACE: {captured:?}"
        );

        // Restore inner: REVOKE for the SID, regrant the captured
        // allow. The outer manager's view of the world should now be
        // consistent again.
        inner.restore().unwrap();

        // And tearing down outer should also succeed.
        outer.restore().unwrap();
    }

    #[test]
    fn crash_recovery_synthetic_dead_pid() {
        let _scope = ScopedStateDir::new();
        let td = tempfile::tempdir().unwrap();
        let target = td.path().join("victim");
        std::fs::create_dir(&target).unwrap();
        {
            let mut m = DaclManager::new().unwrap();
            m.grant_appcontainer_access("S-1-1-0", std::slice::from_ref(&target), &[])
                .unwrap();
            // Forge a state file with a dead PID so recovery picks it up.
            let dir = state_dir().unwrap();
            std::fs::create_dir_all(&dir).unwrap();
            let synthetic = dir.join("pid-2147483646-orphan.json");
            let s = StateFile {
                run_id: "pid-2147483646-orphan".into(),
                pid: 0x7FFF_FFFE,
                image_name: "wxc-exec.exe".into(),
                started_at_filetime: 0,
                applied: m.applied.clone(),
            };
            write_state_file(&synthetic, &s).unwrap();
            // Tell our manager not to also restore (to isolate the
            // recovery path).
            m.applied.clear();
        }
        let report = recover_orphaned_state().unwrap();
        assert!(report.files_processed >= 1);
    }

    #[test]
    fn recovery_prunes_ace_whose_target_is_gone() {
        use windows::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
        // A forged orphan (dead pid) whose single ACE targets a path that no
        // longer exists must be pruned — not retained and re-errored forever.
        let _scope = ScopedStateDir::new();
        let dir = state_dir().unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        let missing = dir.join("does-not-exist-victim");
        assert!(matches!(missing.try_exists(), Ok(false)));

        let synthetic = dir.join("pid-2147483646-missing.json");
        let s = StateFile {
            run_id: "pid-2147483646-missing".into(),
            pid: 0x7FFF_FFFE,
            image_name: "wxc-exec.exe".into(),
            started_at_filetime: 0,
            applied: vec![AppliedAce {
                canonical_path: missing,
                sid_string: "S-1-1-0".into(),
                access_mask: FILE_ALL_ACCESS.0,
                ace_type: AceType::Allow,
                inheritable: false,
                prior_state: Vec::new(),
            }],
        };
        write_state_file(&synthetic, &s).unwrap();

        let report = recover_orphaned_state().unwrap();
        assert!(
            report.aces_pruned_missing >= 1,
            "missing-target ACE should be pruned"
        );
        assert!(
            report.errors.is_empty(),
            "a pruned (missing-target) entry must not surface as an error: {:?}",
            report.errors
        );
        assert!(
            matches!(synthetic.try_exists(), Ok(false)),
            "a fully-pruned state file should be removed"
        );
    }

    #[test]
    fn drop_calls_restore() {
        let _scope = ScopedStateDir::new();
        let td = tempfile::tempdir().unwrap();
        {
            let mut m = DaclManager::new().unwrap();
            m.grant_appcontainer_access("S-1-1-0", &[td.path().to_path_buf()], &[])
                .unwrap();
            // No explicit restore — drop should clean up.
        }
    }

    #[test]
    fn nonexistent_path_errors_cleanly() {
        let _scope = ScopedStateDir::new();
        let mut m = DaclManager::new().unwrap();
        let err = m.grant_appcontainer_access(
            "S-1-1-0",
            &[PathBuf::from(r"C:\__definitely_not_a_real_path__\xyzzy")],
            &[],
        );
        assert!(matches!(err, Err(DaclError::PathNotFound(_))));
    }

    #[test]
    fn network_path_rejected_e2e() {
        let _scope = ScopedStateDir::new();
        let mut m = DaclManager::new().unwrap();
        let err = m.grant_appcontainer_access(
            "S-1-1-0",
            &[PathBuf::from(r"\\someserver\share\foo")],
            &[],
        );
        // The test's intent is "we never silently succeed on a UNC
        // path". The exact error variant depends on how
        // `fs::canonicalize` resolves `\\someserver\share\foo` on the
        // host running the test:
        //   * On dev boxes / agents with no DNS resolution for
        //     `someserver`, canonicalize returns
        //     `io::ErrorKind::NotFound` → `PathNotFound`.
        //   * On agents where canonicalize succeeds (rare but
        //     possible if the share actually exists or is being
        //     resolved by a redirector), our `ensure_local_canonical_
        //     prefix` rejects the UNC namespace → `NetworkPathRejected`.
        //   * On agents where DNS resolves `someserver` to an
        //     unreachable host or returns a non-NotFound Win32 error
        //     (e.g. `ERROR_BAD_NETPATH`, `ERROR_LOGON_FAILURE`),
        //     canonicalize returns a generic IO error that doesn't
        //     map to `NotFound` → `Win32 { reason: "canonicalize: …" }`.
        // All three are acceptable. The unit tests of
        // `ensure_local_canonical_prefix` above verify the
        // classification function deterministically.
        match &err {
            Err(DaclError::NetworkPathRejected(_))
            | Err(DaclError::PathNotFound(_))
            | Err(DaclError::Win32 { .. }) => {}
            other => panic!(
                "expected NetworkPathRejected | PathNotFound | Win32 for UNC path, got: {other:?}"
            ),
        }
    }

    /// A fresh temp dir has only user / SYSTEM / admin ACEs — none for
    /// the well-known AppContainer SIDs — so the effective AC access
    /// must be exactly 0.
    #[test]
    fn effective_ac_access_empty_on_plain_temp_dir() {
        let td = tempfile::tempdir().unwrap();
        let access = compute_appcontainer_effective_access(td.path())
            .expect("effective access should not error on a normal temp dir");
        assert_eq!(
            access, 0,
            "fresh temp dir should have no AC-group grants, got mask 0x{access:08x}"
        );
    }

    /// Stamp an explicit grant for `ALL APPLICATION PACKAGES`
    /// (S-1-15-2-1) on a temp dir, then verify the effective-access
    /// computation surfaces exactly that grant. Restores via the
    /// `DaclManager` Drop.
    #[test]
    fn effective_ac_access_picks_up_explicit_all_app_packages_grant() {
        let _scope = ScopedStateDir::new();
        let td = tempfile::tempdir().unwrap();
        let mask = FILE_GENERIC_READ.0; // RO grant; what installers typically stamp
        {
            let mut m = DaclManager::new().unwrap();
            m.grant_appcontainer_access("S-1-15-2-1", &[], &[td.path().to_path_buf()])
                .unwrap();
            let observed = compute_appcontainer_effective_access(td.path())
                .expect("effective access should not error after grant");
            assert!(
                observed & mask == mask,
                "expected effective mask to cover at least 0x{mask:08x}, got 0x{observed:08x}"
            );
            // Restore happens on drop.
        }
        // After restore: back to zero.
        let post = compute_appcontainer_effective_access(td.path())
            .expect("effective access after restore");
        assert_eq!(post, 0, "DaclManager Drop should have removed the ACE");
    }

    /// `S-1-5-32-545` (BUILTIN\Users) is not one of the SIDs every
    /// AppContainer token belongs to, so a grant to Users must NOT
    /// inflate the AppContainer's effective access.
    #[test]
    fn effective_ac_access_ignores_unrelated_sid_grants() {
        let _scope = ScopedStateDir::new();
        let td = tempfile::tempdir().unwrap();
        // Adding via DaclManager requires write-DAC, which we have on a
        // freshly-created temp dir. BUILTIN\Users (S-1-5-32-545) is on
        // most user-owned paths anyway, but we set it explicitly so the
        // test is robust to host-specific ACL layouts.
        let mut m = DaclManager::new().unwrap();
        m.grant_appcontainer_access("S-1-5-32-545", &[td.path().to_path_buf()], &[])
            .unwrap();
        let observed = compute_appcontainer_effective_access(td.path()).unwrap();
        assert_eq!(
            observed, 0,
            "BUILTIN\\Users grant should not affect AC effective access, got 0x{observed:08x}"
        );
    }
}
