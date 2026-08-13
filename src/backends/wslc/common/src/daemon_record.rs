// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! On-disk daemon discovery record, process-liveness helpers, and the
//! phase-transition lock for state-aware WSLc.
//!
//! Unlike Windows Sandbox — where `provision` is pure bookkeeping and a daemon
//! is spawned lazily at `start`, so per-sandbox state must persist on disk — the
//! WSLc daemon *is* the source of truth for sandbox state: `provision` boots the
//! shared session and creates the container inside the daemon, and the WSLc SDK
//! has no cross-process re-attach. If the daemon dies, every container dies with
//! it and clients re-provision. Consequently the only durable artifact is the
//! [`DaemonRecord`] (how to find and authenticate the live daemon); per-sandbox
//! Provisioned/Started/Stopped state lives in the daemon's in-memory refcounted
//! `sandbox_id -> container` map, never on disk.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Schema version of the on-disk [`DaemonRecord`]. Bump on any incompatible
/// change to the record shape.
pub const RECORD_SCHEMA_VERSION: u32 = 1;

/// Named mutex serialising daemon spawn + teardown across phase processes, so
/// two concurrent phase processes cannot both spawn a daemon (or race a spawn
/// against a teardown). `Local\` scope: these unelevated per-user processes lack
/// `SeCreateGlobalPrivilege`, and cross-session sharing is unsupported by design.
#[cfg(windows)]
const TRANSITION_MUTEX_NAME: &str = r"Local\mxc-wslc-stateaware-transition";

// ---------------------------------------------------------------------------
// Daemon discovery record
// ---------------------------------------------------------------------------

/// Global per-user daemon record (`daemon.json`). Present iff a daemon is (or
/// recently was) alive. A present record does **not** imply the daemon is alive
/// — pair with [`daemon_alive`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonRecord {
    pub schema_version: u32,
    /// Daemon process id.
    pub pid: u32,
    /// Daemon process creation time (Win32 `FILETIME`, 100ns ticks). Paired with
    /// `pid` to defeat PID reuse: a recycled PID will not match.
    pub pid_creation_time: u64,
    /// Named-pipe path the daemon serves its control protocol on
    /// (e.g. `\\.\pipe\mxc-wslc-<unique>`). The pipe's SDDL restricts access to
    /// the owning user, so no separate auth secret is required.
    pub pipe_name: String,
    /// `false` while the daemon is booting the session; `true` once it is ready
    /// to accept requests.
    pub ready: bool,
    /// Control-protocol wire version this daemon speaks
    /// (see [`crate::daemon_protocol::PROTOCOL_VERSION`]). Absent (pre-versioning)
    /// records default to `0`, i.e. incompatible.
    #[serde(default)]
    pub protocol_version: u32,
}

impl DaemonRecord {
    /// True iff this daemon speaks this build's control-protocol version. A
    /// mismatch means a different mxc install left it running: it must not be
    /// driven with mismatched framing.
    pub fn protocol_compatible(&self) -> bool {
        self.protocol_version == crate::daemon_protocol::PROTOCOL_VERSION
    }
}

// ---------------------------------------------------------------------------
// Record root + path derivation
// ---------------------------------------------------------------------------

/// Environment variable that overrides [`state_aware_root`] at runtime. Set by
/// cross-process integration tests — and inherited by the daemon they spawn —
/// to isolate the discovery record from a developer's real per-user daemon.
/// Unset in production.
pub const STATE_ROOT_ENV_VAR: &str = "MXC_WSLC_STATE_ROOT";

/// Root directory for state-aware WSLc records. `temp_dir()` is per-user on
/// Windows (`%TEMP%`), giving the per-user isolation the design requires.
pub fn state_aware_root() -> PathBuf {
    #[cfg(test)]
    {
        if let Some(p) = test_root::get() {
            return p;
        }
    }
    // Runtime override, honored by both the phase process and the daemon it
    // spawns (which inherits the environment). Lets cross-process integration
    // tests point discovery at a throwaway root. Unset in production.
    if let Some(dir) = std::env::var_os(STATE_ROOT_ENV_VAR) {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    std::env::temp_dir().join("mxc-wslc").join("state-aware")
}

/// Global daemon record file: `<root>\daemon.json`.
pub fn daemon_record_path() -> PathBuf {
    state_aware_root().join("daemon.json")
}

/// Create and secure the record root before reading trusted state from it.
pub fn secure_record_root() -> Result<()> {
    ensure_secure_dir(&state_aware_root())
}

/// Required prefix for a daemon control pipe. A trusted record must name a pipe
/// with this prefix; anything else is treated as a planted/hostile record.
pub const PIPE_NAME_PREFIX: &str = r"\\.\pipe\mxc-wslc-";

/// Derive a fresh, unique named-pipe path for a daemon instance. The pipe's ACL
/// (not the name) enforces access control, so uniqueness only needs to avoid
/// collision with a concurrent stale-but-not-yet-reaped daemon.
pub fn mint_pipe_name() -> String {
    format!("{PIPE_NAME_PREFIX}{}", uuid::Uuid::new_v4().simple())
}

// ---------------------------------------------------------------------------
// Atomic, owner-only JSON record IO
// ---------------------------------------------------------------------------

/// Serialise a JSON record through an atomic same-directory rename, securing the
/// parent directory and the temp file owner-only before publishing.
pub fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .context("record path has no parent directory")?;

    // Secure every directory we introduce (not just the leaf) before creating
    // the temp file: an attacker owning an intermediate dir could otherwise swap
    // the leaf via a rename, and a later DACL change would not revoke an
    // attacker's already-open handle.
    ensure_secure_dir(parent).with_context(|| format!("secure record dir {parent:?}"))?;

    let json = serde_json::to_vec_pretty(value).context("serialise record")?;
    let tmp = parent.join(format!("{}.tmp", uuid::Uuid::new_v4()));
    std::fs::write(&tmp, &json).with_context(|| format!("write temp record {tmp:?}"))?;

    if let Err(e) = set_owner_only_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("secure record DACL {tmp:?}"));
    }

    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("rename {tmp:?} -> {path:?}"));
    }
    Ok(())
}

/// Read and deserialise a JSON record. Returns `Ok(None)` if the file does not
/// exist; `Err` for a present-but-unreadable / unparseable file.
pub fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>> {
    match std::fs::read_to_string(path) {
        Ok(s) => {
            let value =
                serde_json::from_str(&s).with_context(|| format!("parse record {path:?}"))?;
            Ok(Some(value))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("read record {path:?}")),
    }
}

/// Reject a record whose schema does not match what this build understands.
pub fn check_schema(found: u32) -> Result<()> {
    if found != RECORD_SCHEMA_VERSION {
        anyhow::bail!(
            "daemon record schema {found} is incompatible with supported schema {RECORD_SCHEMA_VERSION}"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Daemon record convenience readers / writers
// ---------------------------------------------------------------------------

/// Read the global daemon record, validating its schema. Returns `Ok(None)` if
/// the record does not exist.
pub fn read_daemon_record() -> Result<Option<DaemonRecord>> {
    let path = daemon_record_path();
    // Verify the record file and its directory chain are owned by the current
    // user before trusting the contents; a shared-`%TEMP%` attacker could
    // otherwise plant a record redirecting us to a hostile pipe.
    verify_record_trust(&path)?;
    let Some(record) = read_json::<DaemonRecord>(&path)? else {
        return Ok(None);
    };
    check_schema(record.schema_version)?;
    validate_pipe_name(&record.pipe_name)?;
    Ok(Some(record))
}

/// Reject a record naming any pipe outside the daemon's namespace, so a planted
/// record cannot redirect a phase process to an arbitrary endpoint.
fn validate_pipe_name(name: &str) -> Result<()> {
    if !name.starts_with(PIPE_NAME_PREFIX) {
        anyhow::bail!("daemon record names an unexpected pipe {name:?}; refusing to connect");
    }
    Ok(())
}

/// Read the daemon record only if it describes a process that is still alive. A
/// present-but-dead record (daemon crashed without cleanup) yields `None`.
pub fn live_daemon() -> Result<Option<DaemonRecord>> {
    match read_daemon_record()? {
        Some(record) if daemon_alive(&record) => Ok(Some(record)),
        _ => Ok(None),
    }
}

/// Atomically write the global daemon record.
pub fn write_daemon_record(record: &DaemonRecord) -> Result<()> {
    atomic_write_json(&daemon_record_path(), record)
}

/// Remove the global daemon record, treating `NotFound` as success.
pub fn remove_daemon_record() -> std::io::Result<()> {
    match std::fs::remove_file(daemon_record_path()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// True iff the daemon described by `record` is still the live process it claims
/// to be: a process with its PID is currently running AND its creation time
/// matches the recorded one.
pub fn daemon_alive(record: &DaemonRecord) -> bool {
    running_process_creation_time(record.pid) == Some(record.pid_creation_time)
}

// ---------------------------------------------------------------------------
// Filesystem DACL helpers (owner-only), Windows + portable stub
// ---------------------------------------------------------------------------

/// Apply an inheritable owner-only DACL to `dir`, and reject a directory owned
/// by another user (who would retain implicit `WRITE_DAC`).
#[cfg(windows)]
pub fn set_owner_only_dir(dir: &Path) -> Result<()> {
    wxc_common::filesystem_dacl::set_owner_only_dacl(dir, true)
        .map_err(|e| anyhow::Error::new(e).context(format!("secure dir {dir:?}")))?;
    let owned = wxc_common::filesystem_dacl::owner_is_self(dir)
        .map_err(|e| anyhow::Error::new(e).context(format!("read owner of {dir:?}")))?;
    if !owned {
        anyhow::bail!(
            "refusing to use {dir:?}: it is owned by another user (cross-user tampering risk). \
             Remove it and retry."
        );
    }
    Ok(())
}

/// Non-Windows no-op.
#[cfg(not(windows))]
pub fn set_owner_only_dir(_dir: &Path) -> Result<()> {
    Ok(())
}

/// Create and owner-secure a directory and every component we introduce beneath
/// the system temp dir (not just the leaf), then verify current-user ownership.
#[cfg(windows)]
pub fn ensure_secure_dir(dir: &Path) -> Result<()> {
    for component in dirs_to_secure(dir) {
        std::fs::create_dir_all(&component).with_context(|| format!("create dir {component:?}"))?;
        set_owner_only_dir(&component)?;
    }
    Ok(())
}

/// Non-Windows directory creation.
#[cfg(not(windows))]
pub fn ensure_secure_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create dir {dir:?}"))
}

/// The directory components to secure for `dir`, shallowest first: every strict
/// descendant of the system temp dir up to and including `dir`. If `dir` is not
/// under the temp dir, only `dir` itself is secured.
#[cfg(windows)]
fn dirs_to_secure(dir: &Path) -> Vec<PathBuf> {
    let base = std::env::temp_dir();
    if !dir.starts_with(&base) {
        return vec![dir.to_path_buf()];
    }
    let mut chain = Vec::new();
    let mut cur = Some(dir);
    while let Some(p) = cur {
        if p == base {
            break;
        }
        chain.push(p.to_path_buf());
        cur = p.parent();
    }
    chain.reverse();
    chain
}

/// Verify `path` and its securable directory chain are owned by the current
/// user before their contents are trusted. Absent files (and dirs) pass, since
/// there is then nothing to trust.
#[cfg(windows)]
fn verify_record_trust(path: &Path) -> Result<()> {
    let check = |p: &Path| -> Result<()> {
        if !p.exists() {
            return Ok(());
        }
        let owned = wxc_common::filesystem_dacl::owner_is_self(p)
            .map_err(|e| anyhow::Error::new(e).context(format!("read owner of {p:?}")))?;
        if !owned {
            anyhow::bail!(
                "refusing to trust {p:?}: it is owned by another user (cross-user tampering risk)"
            );
        }
        Ok(())
    };
    if let Some(parent) = path.parent() {
        for component in dirs_to_secure(parent) {
            check(&component)?;
        }
    }
    check(path)
}

/// Non-Windows no-op.
#[cfg(not(windows))]
fn verify_record_trust(_path: &Path) -> Result<()> {
    Ok(())
}

/// Apply an owner-only DACL to an existing file.
#[cfg(windows)]
fn set_owner_only_file(path: &Path) -> Result<()> {
    wxc_common::filesystem_dacl::set_owner_only_dacl(path, false)
        .map_err(|e| anyhow::Error::new(e).context(format!("secure file {path:?}")))
}

/// Non-Windows no-op.
#[cfg(not(windows))]
fn set_owner_only_file(_path: &Path) -> Result<()> {
    Ok(())
}

// ---------------------------------------------------------------------------
// Process creation-time liveness, Windows + portable stub
// ---------------------------------------------------------------------------

/// Creation time of `pid` while the process is still running. A retained handle
/// keeps an exited process queryable, so this also checks the handle's signalled
/// state and returns `None` for an exited-but-retained process.
#[cfg(windows)]
pub fn running_process_creation_time(pid: u32) -> Option<u64> {
    use windows::Win32::Foundation::{CloseHandle, FILETIME, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SYNCHRONIZE,
    };

    if pid == 0 {
        return None;
    }
    // SAFETY: `pid` is a plain integer; the handle is closed on every path and
    // the FILETIME out-params are fully initialised before use.
    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            false,
            pid,
        )
        .ok()?;
        let exited = WaitForSingleObject(handle, 0) == WAIT_OBJECT_0;
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        let ok = GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user).is_ok();
        let _ = CloseHandle(handle);
        if !ok || exited {
            return None;
        }
        Some(((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64)
    }
}

/// Non-Windows stub.
#[cfg(not(windows))]
pub fn running_process_creation_time(_pid: u32) -> Option<u64> {
    None
}

/// Creation time of `pid` regardless of running state (used at daemon startup to
/// stamp its own record). Returns `None` for pid 0 or a query failure.
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

/// Non-Windows stub.
#[cfg(not(windows))]
pub fn process_creation_time(_pid: u32) -> Option<u64> {
    None
}

// ---------------------------------------------------------------------------
// Transition lock (named mutex), Windows + portable stub
// ---------------------------------------------------------------------------

/// RAII guard over the named transition mutex. While held, no other phase
/// process can spawn or tear down the daemon, which prevents double-spawn and
/// spawn/teardown races. Released on drop.
#[cfg(windows)]
pub struct TransitionLock {
    handle: windows::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl TransitionLock {
    /// Acquire the transition mutex, waiting up to `timeout`. `Err` on either
    /// contention (timeout) or a real create/wait failure.
    pub fn acquire(timeout: std::time::Duration) -> Result<Self> {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{
            CloseHandle, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT,
        };
        use windows::Win32::System::Threading::{CreateMutexW, WaitForSingleObject};

        let wide: Vec<u16> = TRANSITION_MUTEX_NAME
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        // SAFETY: `wide` is a valid null-terminated UTF-16 buffer that outlives
        // the call; the returned handle is owned by `self` and closed on drop.
        let handle = unsafe { CreateMutexW(None, false, PCWSTR(wide.as_ptr())) }
            .context("create transition mutex")?;

        let ms = timeout.as_millis().min(u32::MAX as u128) as u32;
        // SAFETY: `handle` is a valid mutex handle from `CreateMutexW`.
        let wait = unsafe { WaitForSingleObject(handle, ms) };
        if wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED {
            // WAIT_ABANDONED: a prior holder died without releasing. We now own
            // the mutex; protected state is reconciled separately via the daemon
            // record + process-identity liveness, so taking ownership is correct.
            Ok(Self { handle })
        } else {
            // SAFETY: closing the handle we just created; we do not own the mutex.
            unsafe {
                let _ = CloseHandle(handle);
            }
            if wait == WAIT_TIMEOUT {
                anyhow::bail!(
                    "timed out acquiring transition lock after {timeout:?} (another phase process \
                     is spawning or tearing down the daemon)"
                );
            }
            anyhow::bail!("waiting on transition mutex failed (wait result {wait:?})");
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
            let _ = ReleaseMutex(self.handle);
            let _ = CloseHandle(self.handle);
        }
    }
}

/// Non-Windows stub: the transition mutex is a Windows-only concept.
#[cfg(not(windows))]
pub struct TransitionLock;

#[cfg(not(windows))]
impl TransitionLock {
    pub fn acquire(_timeout: std::time::Duration) -> Result<Self> {
        Ok(Self)
    }
}

// ---------------------------------------------------------------------------
// Test-only record-root override
// ---------------------------------------------------------------------------

#[cfg(test)]
mod test_root {
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};

    static OVERRIDE: OnceLock<Mutex<Option<PathBuf>>> = OnceLock::new();
    fn slot() -> &'static Mutex<Option<PathBuf>> {
        OVERRIDE.get_or_init(|| Mutex::new(None))
    }
    pub fn set(p: Option<PathBuf>) {
        *slot().lock().expect("test_root mutex poisoned") = p;
    }
    pub fn get() -> Option<PathBuf> {
        slot().lock().expect("test_root mutex poisoned").clone()
    }
}

/// Redirect [`state_aware_root`] for a test.
#[cfg(test)]
pub fn set_state_aware_root_for_test(path: Option<PathBuf>) {
    test_root::set(path);
}

/// Serialises tests that override [`state_aware_root`].
#[cfg(test)]
pub static STATE_AWARE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record() -> DaemonRecord {
        DaemonRecord {
            schema_version: RECORD_SCHEMA_VERSION,
            pid: std::process::id(),
            pid_creation_time: 123,
            pipe_name: mint_pipe_name(),
            ready: true,
            protocol_version: crate::daemon_protocol::PROTOCOL_VERSION,
        }
    }

    #[test]
    fn daemon_record_roundtrips_on_disk() {
        let _guard = STATE_AWARE_TEST_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        set_state_aware_root_for_test(Some(dir.path().to_path_buf()));

        let record = sample_record();
        write_daemon_record(&record).unwrap();
        let read = read_daemon_record().unwrap().unwrap();
        assert_eq!(read, record);

        remove_daemon_record().unwrap();
        assert!(read_daemon_record().unwrap().is_none());

        set_state_aware_root_for_test(None);
    }

    #[test]
    fn read_missing_daemon_record_is_none() {
        let _guard = STATE_AWARE_TEST_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        set_state_aware_root_for_test(Some(dir.path().to_path_buf()));
        assert!(read_daemon_record().unwrap().is_none());
        set_state_aware_root_for_test(None);
    }

    #[test]
    fn read_rejects_record_with_foreign_pipe_name() {
        let _guard = STATE_AWARE_TEST_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        set_state_aware_root_for_test(Some(dir.path().to_path_buf()));

        let json = format!(
            r#"{{"schema_version":{RECORD_SCHEMA_VERSION},"pid":1,"pid_creation_time":2,
               "pipe_name":"\\\\.\\pipe\\evil","ready":true,"protocol_version":{}}}"#,
            crate::daemon_protocol::PROTOCOL_VERSION
        );
        std::fs::write(daemon_record_path(), json).unwrap();
        assert!(read_daemon_record().is_err());

        set_state_aware_root_for_test(None);
    }

    #[test]
    fn check_schema_rejects_mismatch() {
        assert!(check_schema(RECORD_SCHEMA_VERSION).is_ok());
        assert!(check_schema(RECORD_SCHEMA_VERSION + 1).is_err());
    }

    #[test]
    fn protocol_compatible_matches_current_and_rejects_others() {
        let mut record = sample_record();
        assert!(record.protocol_compatible());
        record.protocol_version = crate::daemon_protocol::PROTOCOL_VERSION + 1;
        assert!(!record.protocol_compatible());
    }

    #[test]
    fn daemon_record_without_protocol_version_reads_as_incompatible() {
        // A pre-versioning record omits `protocol_version`; serde `default` makes
        // it 0, which is never the current version.
        let json = format!(
            r#"{{"schema_version":{RECORD_SCHEMA_VERSION},"pid":1,"pid_creation_time":2,
               "pipe_name":"\\\\.\\pipe\\x","ready":true}}"#
        );
        let record: DaemonRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record.protocol_version, 0);
        assert!(!record.protocol_compatible());
    }

    #[test]
    fn atomic_write_overwrites_existing() {
        let _guard = STATE_AWARE_TEST_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        set_state_aware_root_for_test(Some(dir.path().to_path_buf()));

        let mut record = sample_record();
        write_daemon_record(&record).unwrap();
        record.ready = false;
        write_daemon_record(&record).unwrap();
        assert!(!read_daemon_record().unwrap().unwrap().ready);

        set_state_aware_root_for_test(None);
    }

    #[test]
    fn mint_pipe_name_is_unique_and_well_formed() {
        let a = mint_pipe_name();
        let b = mint_pipe_name();
        assert_ne!(a, b);
        assert!(a.starts_with(r"\\.\pipe\mxc-wslc-"));
    }

    #[cfg(windows)]
    #[test]
    fn current_process_is_alive_with_matching_creation_time() {
        let pid = std::process::id();
        let ct = process_creation_time(pid).expect("own creation time");
        let record = DaemonRecord {
            schema_version: RECORD_SCHEMA_VERSION,
            pid,
            pid_creation_time: ct,
            pipe_name: mint_pipe_name(),
            ready: true,
            protocol_version: crate::daemon_protocol::PROTOCOL_VERSION,
        };
        assert!(daemon_alive(&record));
    }

    #[cfg(windows)]
    #[test]
    fn wrong_creation_time_is_not_alive() {
        let pid = std::process::id();
        let record = DaemonRecord {
            schema_version: RECORD_SCHEMA_VERSION,
            pid,
            pid_creation_time: 0xDEAD_BEEF,
            pipe_name: mint_pipe_name(),
            ready: true,
            protocol_version: crate::daemon_protocol::PROTOCOL_VERSION,
        };
        assert!(!daemon_alive(&record));
    }

    #[cfg(windows)]
    #[test]
    fn dead_pid_has_no_running_creation_time() {
        // PID 0 is never a valid queryable user process.
        assert_eq!(running_process_creation_time(0), None);
    }

    #[cfg(windows)]
    #[test]
    fn transition_lock_acquire_release_reacquire() {
        let lock = TransitionLock::acquire(std::time::Duration::from_secs(1)).unwrap();
        drop(lock);
        // Re-acquire after release must succeed.
        let _lock = TransitionLock::acquire(std::time::Duration::from_secs(1)).unwrap();
    }
}
