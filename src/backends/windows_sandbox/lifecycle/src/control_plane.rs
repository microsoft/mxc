// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! State-aware control-plane primitives: the durable on-disk records that let
//! separate `wxc-exec` phase processes (provision / start / exec / stop /
//! deprovision) find and coordinate the single host-side daemon that holds the
//! live Windows Sandbox VM, plus the cross-process transition lock and the
//! PID-reuse-safe liveness check that make those coordinations correct.
//!
//! Two record kinds live under [`state_aware_root`] (`%TEMP%\wxc-wsb\state-aware`):
//!
//! - **Per-sandbox record** (`<token>\record.json`): the source of truth for a
//!   provisioned sandbox — its lifecycle [`SandboxState`] and the immutable
//!   filesystem-policy snapshot captured at provision. Written by `provision`,
//!   transitioned by `start` / `stop`, removed by `deprovision`.
//! - **Global daemon record** (`daemon.json`): present only while the single
//!   daemon is alive. Carries the daemon's PID (+ creation time for
//!   PID-reuse safety), the localhost IPC port, an auth `nonce`, and the
//!   `active_sandbox_id` it currently holds. This is both the discovery
//!   channel and the single-active-sandbox guard.
//!
//! All writes go through [`atomic_write_json`] (temp file + rename) so a crash
//! mid-write never leaves a half-written, unparseable record. Every record
//! carries a `schema_version` so a future format change can be detected rather
//! than silently misparsed.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Current on-disk record schema. Bump when the record shape changes
/// incompatibly; readers reject mismatches via [`check_schema`].
pub const RECORD_SCHEMA_VERSION: u32 = 1;

/// Name of the cross-process transition mutex. `Local\` keeps it scoped to the
/// current logon session, which is the right blast radius: state-aware WSB is a
/// single-user, single-instance backend.
const TRANSITION_MUTEX_NAME: &str = r"Local\wxc-wsb-stateaware-transition";

/// Lifecycle state of a provisioned state-aware sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SandboxState {
    /// Bookkeeping exists (record + policy snapshot); no daemon, no VM.
    Provisioned,
    /// The daemon is up and holds a live VM + guest connection.
    Started,
    /// The VM has been torn down; the record persists for a later `start`.
    Stopped,
}

/// A serialisable snapshot of one mapped folder, mirroring [`crate::vm::MappedFolder`]
/// but decoupled from it so the on-disk format is independent of the in-memory
/// type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappedFolderRecord {
    pub host: String,
    pub sandbox: String,
    pub read_only: bool,
}

/// Per-sandbox durable record (`<token>\record.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxRecord {
    pub schema_version: u32,
    pub sandbox_id: String,
    pub state: SandboxState,
    /// Filesystem-policy snapshot captured at provision and applied verbatim at
    /// every `start`. Immutable for the life of the sandbox.
    pub mapped_folders: Vec<MappedFolderRecord>,
}

impl SandboxRecord {
    /// Construct a freshly-provisioned record.
    pub fn new_provisioned(sandbox_id: String, mapped_folders: Vec<MappedFolderRecord>) -> Self {
        Self {
            schema_version: RECORD_SCHEMA_VERSION,
            sandbox_id,
            state: SandboxState::Provisioned,
            mapped_folders,
        }
    }
}

/// Global daemon record (`daemon.json`). Present iff a daemon is (or recently
/// was) alive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonRecord {
    pub schema_version: u32,
    /// Daemon process id.
    pub pid: u32,
    /// Daemon process creation time (Win32 `FILETIME`, 100ns ticks). Paired
    /// with `pid` to defeat PID reuse: a recycled PID will not match.
    pub pid_creation_time: u64,
    /// Localhost TCP port the daemon serves its line protocol on.
    pub ipc_port: u16,
    /// Shared secret the backend generated and passed to the daemon at spawn.
    /// Echoed here so the backend can (a) confirm this record belongs to the
    /// daemon it just spawned and (b) authenticate later IPC connects against a
    /// process squatting the port.
    pub nonce: String,
    /// The single sandbox this daemon currently holds.
    pub active_sandbox_id: String,
    /// `false` while the daemon is still booting the VM (record published
    /// *before* launch so the daemon occupies the single-instance slot from the
    /// moment it starts), `true` once the VM + guest are connected and ready to
    /// serve. The IPC port is bound and served even while `ready` is `false`, so
    /// a `STOP` can gracefully abort an in-flight boot.
    pub ready: bool,
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/// Root directory for all state-aware records: `%TEMP%\wxc-wsb\state-aware`.
pub fn state_aware_root() -> PathBuf {
    std::env::temp_dir().join("wxc-wsb").join("state-aware")
}

/// Per-sandbox scratch directory: `<root>\<token>`.
///
/// `token` is the tail of `sandbox_id` (`wsb:<token>`); callers pass the bare
/// token so the path stays free of the `:` separator.
pub fn sandbox_dir(token: &str) -> PathBuf {
    state_aware_root().join(token)
}

/// Per-sandbox record file: `<root>\<token>\record.json`.
pub fn sandbox_record_path(token: &str) -> PathBuf {
    sandbox_dir(token).join("record.json")
}

/// Global daemon record file: `<root>\daemon.json`.
pub fn daemon_record_path() -> PathBuf {
    state_aware_root().join("daemon.json")
}

// ---------------------------------------------------------------------------
// Atomic JSON read / write
// ---------------------------------------------------------------------------

/// Serialise `value` to `path` atomically: write a uniquely-named temp file in
/// the same directory, then rename it over `path`. The rename is atomic on
/// Windows (and replaces any existing file), so a reader sees either the old or
/// the new content, never a partial write.
pub fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .context("record path has no parent directory")?;
    std::fs::create_dir_all(parent).with_context(|| format!("create record dir {:?}", parent))?;

    let json = serde_json::to_vec_pretty(value).context("serialise record")?;
    let tmp = parent.join(format!("{}.tmp", uuid::Uuid::new_v4()));
    std::fs::write(&tmp, &json).with_context(|| format!("write temp record {:?}", tmp))?;

    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("rename {:?} -> {:?}", tmp, path));
    }
    Ok(())
}

/// Read and deserialise a JSON record. Returns `Ok(None)` if the file does not
/// exist; an `Err` for a present-but-unreadable / unparseable file.
pub fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>> {
    match std::fs::read_to_string(path) {
        Ok(s) => {
            let value =
                serde_json::from_str(&s).with_context(|| format!("parse record {:?}", path))?;
            Ok(Some(value))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("read record {:?}", path)),
    }
}

/// Reject a record whose schema does not match what this build understands.
pub fn check_schema(found: u32, what: &str) -> Result<()> {
    if found != RECORD_SCHEMA_VERSION {
        anyhow::bail!(
            "{} record schema {} is incompatible with supported schema {}",
            what,
            found,
            RECORD_SCHEMA_VERSION
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// PID-reuse-safe liveness
// ---------------------------------------------------------------------------

/// Return the creation time (Win32 `FILETIME`, 100ns ticks since 1601) of the
/// process with `pid`, or `None` if it does not exist / cannot be queried.
///
/// The creation time pins a PID to a specific process instance: a recycled PID
/// gets a new creation time, so comparing it defeats PID reuse.
#[cfg(windows)]
pub fn process_creation_time(pid: u32) -> Option<u64> {
    use windows::Win32::Foundation::{CloseHandle, FILETIME};
    use windows::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    if pid == 0 {
        return None;
    }
    // SAFETY: `pid` is a plain integer; the handle is closed on every path and
    // the FILETIME out-params are fully initialised before use.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        let ok = GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user).is_ok();
        let _ = CloseHandle(handle);
        if !ok {
            return None;
        }
        Some(((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64)
    }
}

#[cfg(not(windows))]
pub fn process_creation_time(_pid: u32) -> Option<u64> {
    None
}

/// True iff the daemon described by `record` is still the live process it
/// claims to be (PID exists AND its creation time matches the recorded one).
pub fn daemon_alive(record: &DaemonRecord) -> bool {
    process_creation_time(record.pid) == Some(record.pid_creation_time)
}

// ---------------------------------------------------------------------------
// Cross-process transition lock
// ---------------------------------------------------------------------------

/// RAII guard over the named transition mutex. While held, no other phase
/// process can enter a `start` / `stop` / `deprovision` transition, which
/// prevents split-brain (double-spawn, kill-wrong-target, contradictory record
/// writes). Released on drop.
#[cfg(windows)]
pub struct TransitionLock {
    handle: windows::Win32::Foundation::HANDLE,
    /// Whether we actually own the mutex (vs. failed to acquire). Only an owned
    /// mutex is released on drop.
    owned: bool,
}

#[cfg(windows)]
impl TransitionLock {
    /// Acquire the transition mutex, waiting up to `timeout`.
    pub fn acquire(timeout: std::time::Duration) -> Result<Self> {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{WAIT_ABANDONED, WAIT_OBJECT_0};
        use windows::Win32::System::Threading::{CreateMutexW, WaitForSingleObject};

        let name: Vec<u16> = TRANSITION_MUTEX_NAME
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        // SAFETY: `name` is a valid null-terminated UTF-16 buffer that outlives
        // the call; the returned handle is owned by `self` and closed on drop.
        let handle = unsafe { CreateMutexW(None, false, PCWSTR(name.as_ptr())) }
            .context("create transition mutex")?;

        let ms = timeout.as_millis().min(u32::MAX as u128) as u32;
        // SAFETY: `handle` is a valid mutex handle from `CreateMutexW`.
        let wait = unsafe { WaitForSingleObject(handle, ms) };
        if wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED {
            // WAIT_ABANDONED: a previous holder died without releasing. We now
            // own the mutex; the protected state is reconciled separately via
            // the records, so taking ownership here is correct.
            Ok(Self {
                handle,
                owned: true,
            })
        } else {
            // SAFETY: closing the handle we just created; we do not own the mutex.
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(handle);
            }
            anyhow::bail!("timed out acquiring transition lock after {:?}", timeout);
        }
    }
}

#[cfg(windows)]
impl Drop for TransitionLock {
    fn drop(&mut self) {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::ReleaseMutex;
        // SAFETY: `handle` is a valid mutex handle owned by `self`.
        unsafe {
            if self.owned {
                let _ = ReleaseMutex(self.handle);
            }
            let _ = CloseHandle(self.handle);
        }
    }
}

/// Generate a fresh random auth nonce for the daemon record.
pub fn generate_nonce() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

// ---------------------------------------------------------------------------
// Record convenience readers
// ---------------------------------------------------------------------------

/// Read the per-sandbox record for `token`, validating its schema. Returns
/// `Ok(None)` if the record does not exist.
pub fn read_sandbox_record(token: &str) -> Result<Option<SandboxRecord>> {
    let Some(record) = read_json::<SandboxRecord>(&sandbox_record_path(token))? else {
        return Ok(None);
    };
    check_schema(record.schema_version, "sandbox")?;
    Ok(Some(record))
}

/// Read the global daemon record, validating its schema. Returns `Ok(None)` if
/// the record does not exist. A present record does **not** imply the daemon is
/// alive — pair with [`daemon_alive`].
pub fn read_daemon_record() -> Result<Option<DaemonRecord>> {
    let Some(record) = read_json::<DaemonRecord>(&daemon_record_path())? else {
        return Ok(None);
    };
    check_schema(record.schema_version, "daemon")?;
    Ok(Some(record))
}

/// Read the daemon record only if it describes a process that is still alive.
/// A present-but-dead record (daemon crashed without cleanup) yields `None`.
pub fn live_daemon() -> Result<Option<DaemonRecord>> {
    match read_daemon_record()? {
        Some(record) if daemon_alive(&record) => Ok(Some(record)),
        _ => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Daemon IPC line protocol
// ---------------------------------------------------------------------------
//
// The daemon serves a trivial line protocol on `127.0.0.1:<ipc_port>`:
//   request  : `<VERB> <nonce>\n`
//   response : `OK\n` | `PONG\n` | `ERR <message>\n`
// The nonce authenticates the caller against a process that merely squats the
// localhost port. Exec is *not* part of the 4a protocol — it is stubbed at the
// backend layer and lands in 4b.

/// Liveness/echo verb. Response: `PONG`.
pub const IPC_PING: &str = "PING";
/// Teardown verb: the daemon tears down its VM and exits. Response: `OK`.
pub const IPC_STOP: &str = "STOP";
/// Success response token.
pub const IPC_OK: &str = "OK";
/// Ping success response token.
pub const IPC_PONG: &str = "PONG";
/// Error response prefix (`ERR <message>`).
pub const IPC_ERR: &str = "ERR";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_nested_under_root() {
        let root = state_aware_root();
        assert!(root.ends_with("state-aware"));
        assert_eq!(sandbox_dir("abc"), root.join("abc"));
        assert_eq!(
            sandbox_record_path("abc"),
            root.join("abc").join("record.json")
        );
        assert_eq!(daemon_record_path(), root.join("daemon.json"));
    }

    #[test]
    fn sandbox_record_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("record.json");
        let rec = SandboxRecord::new_provisioned(
            "wsb:deadbeef".to_string(),
            vec![MappedFolderRecord {
                host: r"C:\work".to_string(),
                sandbox: r"C:\work".to_string(),
                read_only: false,
            }],
        );
        atomic_write_json(&path, &rec).unwrap();
        let back: SandboxRecord = read_json(&path).unwrap().unwrap();
        assert_eq!(back, rec);
        assert_eq!(back.state, SandboxState::Provisioned);
    }

    #[test]
    fn daemon_record_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.json");
        let rec = DaemonRecord {
            schema_version: RECORD_SCHEMA_VERSION,
            pid: 1234,
            pid_creation_time: 42,
            ipc_port: 49500,
            nonce: "abc123".to_string(),
            active_sandbox_id: "wsb:deadbeef".to_string(),
            ready: true,
        };
        atomic_write_json(&path, &rec).unwrap();
        let back: DaemonRecord = read_json(&path).unwrap().unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn read_json_missing_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nope.json");
        let back: Option<SandboxRecord> = read_json(&path).unwrap();
        assert!(back.is_none());
    }

    #[test]
    fn atomic_write_overwrites_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("record.json");
        let mut rec = SandboxRecord::new_provisioned("wsb:x".to_string(), Vec::new());
        atomic_write_json(&path, &rec).unwrap();
        rec.state = SandboxState::Started;
        atomic_write_json(&path, &rec).unwrap();
        let back: SandboxRecord = read_json(&path).unwrap().unwrap();
        assert_eq!(back.state, SandboxState::Started);
        // No stray temp files left behind.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp files leaked: {:?}", leftovers);
    }

    #[test]
    fn check_schema_rejects_mismatch() {
        assert!(check_schema(RECORD_SCHEMA_VERSION, "sandbox").is_ok());
        assert!(check_schema(RECORD_SCHEMA_VERSION + 1, "sandbox").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn current_process_is_alive_with_matching_creation_time() {
        let pid = std::process::id();
        let ct = process_creation_time(pid).expect("current process should have a creation time");
        let rec = DaemonRecord {
            schema_version: RECORD_SCHEMA_VERSION,
            pid,
            pid_creation_time: ct,
            ipc_port: 1,
            nonce: "n".to_string(),
            active_sandbox_id: "wsb:x".to_string(),
            ready: true,
        };
        assert!(daemon_alive(&rec));
    }

    #[cfg(windows)]
    #[test]
    fn wrong_creation_time_is_not_alive() {
        let pid = std::process::id();
        let ct = process_creation_time(pid).unwrap();
        let rec = DaemonRecord {
            schema_version: RECORD_SCHEMA_VERSION,
            pid,
            pid_creation_time: ct ^ 0xFFFF,
            ipc_port: 1,
            nonce: "n".to_string(),
            active_sandbox_id: "wsb:x".to_string(),
            ready: true,
        };
        assert!(!daemon_alive(&rec));
    }

    #[cfg(windows)]
    #[test]
    fn dead_pid_has_no_creation_time() {
        // PID 0 is never a queryable user process.
        assert_eq!(process_creation_time(0), None);
    }

    #[cfg(windows)]
    #[test]
    fn transition_lock_acquire_release_reacquire() {
        use std::time::Duration;
        {
            let _lock = TransitionLock::acquire(Duration::from_secs(5)).unwrap();
        }
        // Dropped above; a second acquire must succeed promptly.
        let _lock2 = TransitionLock::acquire(Duration::from_secs(5)).unwrap();
    }
}
