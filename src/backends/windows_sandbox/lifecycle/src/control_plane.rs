// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Durable records and locks for the state-aware Windows Sandbox daemon.
//!
//! Records live under [`state_aware_root`]. Each write is atomic and
//! schema-versioned so crashes and future format changes fail closed.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub mod os;
pub use os::*;

/// Current on-disk record schema. Bump when the record shape changes
/// incompatibly; readers reject mismatches via [`check_schema`].
pub const RECORD_SCHEMA_VERSION: u32 = 1;

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

/// Identity of a single Windows Sandbox host process: its PID paired with its
/// creation time (Win32 `FILETIME`, 100ns ticks). The creation time pins the
/// PID to a specific process instance so PID reuse cannot cause a false match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmProcId {
    pub pid: u32,
    pub creation_time: u64,
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
    /// `false` while the daemon is booting; `true` once the VM is ready.
    pub ready: bool,
    /// Positive ownership proof for reclaiming an orphaned VM.
    #[serde(default)]
    pub vm_processes: Vec<VmProcId>,
}

/// Startup action for an already-running VM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupAction {
    Proceed,
    /// A stale record proves the running VM is ours; reclaim it before launch.
    ReclaimOrphan {
        proof: Vec<VmProcId>,
    },
    /// Tear down an unprovable VM (the live snapshot is the kill set).
    ForceReclaimForeign {
        snapshot: Vec<VmProcId>,
    },
    /// A VM is running, but ownership is not proven.
    RefuseForeign,
}

/// Reclaim only when a stale record's proof intersects the live VM process set.
///
/// With `force_reclaim`, an otherwise-unprovable live VM is torn down instead
/// (see [`force_reclaim_requested`]).
pub fn classify_startup(
    prior: Option<&DaemonRecord>,
    current_vm: &[VmProcId],
    force_reclaim: bool,
) -> StartupAction {
    if current_vm.is_empty() {
        return StartupAction::Proceed;
    }
    if let Some(prior) = prior {
        let ours = prior
            .vm_processes
            .iter()
            .any(|recorded| current_vm.contains(recorded));
        if ours {
            return StartupAction::ReclaimOrphan {
                proof: prior.vm_processes.clone(),
            };
        }
    }
    if force_reclaim {
        return StartupAction::ForceReclaimForeign {
            snapshot: current_vm.to_vec(),
        };
    }
    StartupAction::RefuseForeign
}

/// `--force-reclaim`: authorises tearing down a running Windows Sandbox VM that
/// mxc cannot prove it launched, using the live process snapshot as the kill
/// set, instead of refusing and wedging the machine-wide singleton. Precedence:
/// it never overrides a proven reclaim, an active run, or a probe failure, and
/// cannot manufacture liveness (an empty snapshot still proceeds). DANGER: with
/// no proof, it may also kill a foreign or manually-launched sandbox.
///
/// Transported via the `WXC_WSB_FORCE_RECLAIM` env var so it reaches both the
/// in-process one-shot reconcile and the detached daemon (which inherits the
/// launcher's env).
pub fn force_reclaim_requested() -> bool {
    std::env::var_os(FORCE_RECLAIM_ENV_VAR).is_some()
}

/// Env var backing [`force_reclaim_requested`].
pub const FORCE_RECLAIM_ENV_VAR: &str = "WXC_WSB_FORCE_RECLAIM";

/// How far VM ownership has progressed within one daemon process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmOwnership {
    NotLaunched,
    /// Launch issued, but success not observed; cleanup must not tear down.
    LaunchInFlight,
    /// Launch succeeded, but host-process proof is not available yet.
    LaunchSucceededNoProof,
    /// Launch succeeded and host-process proof was captured.
    Owned(Vec<VmProcId>),
}

/// Cleanup action derived from ownership state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanupAction {
    Noop,
    /// Ownership is unproven; leave any VM alone.
    LeakUnowned,
    /// Tear down using the provided proof seed.
    Teardown(Vec<VmProcId>),
}

/// Map ownership state to the daemon exit cleanup action.
pub fn decide_cleanup(ownership: &VmOwnership) -> CleanupAction {
    match ownership {
        VmOwnership::NotLaunched => CleanupAction::Noop,
        VmOwnership::LaunchInFlight => CleanupAction::LeakUnowned,
        VmOwnership::LaunchSucceededNoProof => CleanupAction::Teardown(Vec::new()),
        VmOwnership::Owned(pids) => CleanupAction::Teardown(pids.clone()),
    }
}

/// Compute the process identities safe to terminate for a proven VM owner.
///
/// # Windows Sandbox singleton invariant
///
/// Windows Sandbox is a **machine-wide singleton**: at most one VM runs per
/// host. So when our recorded proof still intersects the live `WindowsSandbox*`
/// snapshot, the one running VM is provably *ours*, and every process in the
/// snapshot — including post-launch helpers not in the proof seed — belongs to
/// it. Widening the kill set to the whole snapshot therefore reaps our full
/// process tree without reaching another user's VM, since a second concurrent
/// VM cannot exist.
///
/// Widening is gated strictly on that intersection (PID+creation-time, so PID
/// reuse cannot forge a hit): with no live proof PID we return only the proof
/// and never adopt snapshot processes, keeping a foreign sandbox out of the
/// kill set. The unproven `--force-reclaim` path in `teardown.rs` is the one
/// deliberate opt-in exception.
pub fn plan_kill_set(ownership: &VmOwnership, snapshot: &[VmProcId]) -> Option<Vec<VmProcId>> {
    match ownership {
        VmOwnership::NotLaunched | VmOwnership::LaunchInFlight => None,
        VmOwnership::Owned(proof) => {
            // Intersection proves the live VM is ours (see the singleton
            // invariant above); only then widen to catch post-launch helpers.
            let proof_confirms_our_vm_is_live = proof.iter().any(|p| snapshot.contains(p));
            if proof_confirms_our_vm_is_live {
                let mut kill = proof.clone();
                for p in snapshot {
                    if !kill.contains(p) {
                        kill.push(*p);
                    }
                }
                Some(kill)
            } else {
                Some(proof.clone())
            }
        }
        VmOwnership::LaunchSucceededNoProof => {
            if snapshot.is_empty() {
                None
            } else {
                Some(snapshot.to_vec())
            }
        }
    }
}

/// Teardown result controlling whether durable ownership records may be removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TeardownOutcome {
    /// All host processes exited; the durable record may be removed.
    ConfirmedGone,
    /// Processes remain after the timeout; preserve the record.
    StillRunning(Vec<VmProcId>),
    /// Liveness could not be determined; preserve the record.
    ProbeFailed,
}

/// Cleanup decision when a sandbox record exists without a live daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StaleDaemonCleanup {
    /// No live VM and no stale record (or stale record matches sandbox_id
    /// with no live processes). Phase may advance normally.
    NoLiveVm,
    /// Stale daemon's proof intersects the live VM; safe to reclaim.
    Reclaim { proof: Vec<VmProcId> },
    /// Live VM exists but is foreign; refuse and surface its PIDs.
    RefuseForeign { live: Vec<VmProcId> },
    /// Liveness probe failed; refuse to act on unknown state.
    RefuseProbeFailed,
    /// Stale record names a different sandbox; refuse so we never act on
    /// another sandbox's records.
    RefuseSandboxIdMismatch { stale_active: String },
}

/// Classify stale-daemon cleanup without touching the host.
///
/// A sandbox-id mismatch is checked first so one sandbox can never authorise
/// cleanup of another. `live == None` means the liveness probe failed.
pub fn classify_stale_daemon_cleanup(
    stale: Option<&DaemonRecord>,
    sandbox_id: &str,
    live: Option<&[VmProcId]>,
) -> StaleDaemonCleanup {
    if let Some(stale) = stale {
        if stale.active_sandbox_id != sandbox_id {
            return StaleDaemonCleanup::RefuseSandboxIdMismatch {
                stale_active: stale.active_sandbox_id.clone(),
            };
        }
    }
    let live = match live {
        None => return StaleDaemonCleanup::RefuseProbeFailed,
        Some(l) => l,
    };
    if live.is_empty() {
        return StaleDaemonCleanup::NoLiveVm;
    }
    if let Some(stale) = stale {
        let intersects = stale.vm_processes.iter().any(|p| live.contains(p));
        if intersects {
            return StaleDaemonCleanup::Reclaim {
                proof: stale.vm_processes.clone(),
            };
        }
    }
    StaleDaemonCleanup::RefuseForeign {
        live: live.to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/// Root directory for state-aware records.
pub fn state_aware_root() -> PathBuf {
    #[cfg(test)]
    {
        if let Some(p) = test_root::get() {
            return p;
        }
    }
    std::env::temp_dir().join("wxc-wsb").join("state-aware")
}

/// Create and secure the record root before reading trusted state from it.
pub fn secure_record_root() -> Result<()> {
    os::ensure_secure_dir(&state_aware_root())
}

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

/// Serialise a JSON record through an atomic same-directory rename.
pub fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .context("record path has no parent directory")?;
    std::fs::create_dir_all(parent).with_context(|| format!("create record dir {:?}", parent))?;

    // Secure the directory before creating the temp file. A later DACL change
    // would not revoke an attacker's already-open handle to a nonce-bearing file.
    os::set_owner_only_dir(parent).with_context(|| format!("secure record dir {:?}", parent))?;

    let json = serde_json::to_vec_pretty(value).context("serialise record")?;
    let tmp = parent.join(format!("{}.tmp", uuid::Uuid::new_v4()));
    std::fs::write(&tmp, &json).with_context(|| format!("write temp record {:?}", tmp))?;

    // Belt-and-braces: also secure the file and fail closed before publishing it.
    if let Err(e) = os::set_owner_only_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("secure record DACL {:?}", tmp));
    }

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
// Daemon liveness
// ---------------------------------------------------------------------------

/// True iff the daemon described by `record` is still the live process it
/// claims to be: a process with its PID is **currently running** AND its
/// creation time matches the recorded one. Uses the liveness-aware
/// [`running_process_creation_time`] so a terminated daemon whose object
/// lingers behind a retained handle is correctly reported as gone rather than
/// blocking a fresh daemon from reclaiming the slot.
pub fn daemon_alive(record: &DaemonRecord) -> bool {
    running_process_creation_time(record.pid) == Some(record.pid_creation_time)
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

// Record helpers retain the atomic-write and owner-only-DACL contract.

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

/// Atomically write the per-sandbox `record` for `token` to disk.
pub fn write_sandbox_record(token: &str, record: &SandboxRecord) -> Result<()> {
    atomic_write_json(&sandbox_record_path(token), record)
}

/// Remove the per-sandbox directory, treating `NotFound` as success.
pub fn remove_sandbox_dir(token: &str) -> std::io::Result<()> {
    match std::fs::remove_dir_all(sandbox_dir(token)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

// Daemon line protocol on `127.0.0.1:<ipc_port>`:
//   request  : `<VERB> <nonce>\n`
//   response : `OK\n` | `PONG\n` | `ERR <message>\n`
// `EXEC` continues into a binary frame stream after its status line.

/// Liveness/echo verb. Response: `PONG`.
pub const IPC_PING: &str = "PING";
/// Teardown verb: the daemon tears down its VM and exits. Response: `OK`.
pub const IPC_STOP: &str = "STOP";
/// Exec verb: after `EXEC <nonce>\n` the client sends a framed `ExecStart`
/// request and the daemon replies with a status line then a binary frame
/// stream (see [`crate::ipc_exec`]). Admission response: `OK` or `ERR <msg>`.
pub const IPC_EXEC: &str = "EXEC";
/// Success response token.
pub const IPC_OK: &str = "OK";
/// Ping success response token.
pub const IPC_PONG: &str = "PONG";
/// Error response prefix (`ERR <message>`).
pub const IPC_ERR: &str = "ERR";
/// Exec-admission reason token: another exec already holds the single-flight
/// guest slot. Emitted by the daemon as `ERR busy`, matched by the client.
pub const IPC_ERR_BUSY: &str = "busy";
/// Exec-admission reason token: the guest slot exists but is still booting.
/// Emitted by the daemon as `ERR not ready`, matched by the client.
pub const IPC_ERR_NOT_READY: &str = "not ready";

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
            vm_processes: vec![VmProcId {
                pid: 5678,
                creation_time: 99,
            }],
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

    fn daemon_record_with(vm_processes: Vec<VmProcId>) -> DaemonRecord {
        DaemonRecord {
            schema_version: RECORD_SCHEMA_VERSION,
            pid: 1,
            pid_creation_time: 1,
            ipc_port: 1,
            nonce: "n".to_string(),
            active_sandbox_id: "wsb:x".to_string(),
            ready: true,
            vm_processes,
        }
    }

    #[test]
    fn classify_no_vm_proceeds() {
        let prior = daemon_record_with(vec![VmProcId {
            pid: 10,
            creation_time: 100,
        }]);
        assert_eq!(
            classify_startup(Some(&prior), &[], false),
            StartupAction::Proceed
        );
        assert_eq!(classify_startup(None, &[], false), StartupAction::Proceed);
    }

    #[test]
    fn classify_vm_no_prior_refuses() {
        let current = [VmProcId {
            pid: 10,
            creation_time: 100,
        }];
        assert_eq!(
            classify_startup(None, &current, false),
            StartupAction::RefuseForeign
        );
    }

    #[test]
    fn classify_vm_empty_prior_processes_refuses() {
        let prior = daemon_record_with(Vec::new());
        let current = [VmProcId {
            pid: 10,
            creation_time: 100,
        }];
        assert_eq!(
            classify_startup(Some(&prior), &current, false),
            StartupAction::RefuseForeign
        );
    }

    #[test]
    fn classify_disjoint_set_refuses() {
        let prior = daemon_record_with(vec![VmProcId {
            pid: 10,
            creation_time: 100,
        }]);
        // Same pid but different creation time must NOT match (PID reuse).
        let current = [VmProcId {
            pid: 10,
            creation_time: 999,
        }];
        assert_eq!(
            classify_startup(Some(&prior), &current, false),
            StartupAction::RefuseForeign
        );
    }

    #[test]
    fn classify_force_reclaim_tears_down_unprovable_vm() {
        let current = [
            VmProcId {
                pid: 10,
                creation_time: 100,
            },
            VmProcId {
                pid: 11,
                creation_time: 101,
            },
        ];
        assert_eq!(
            classify_startup(None, &current, true),
            StartupAction::ForceReclaimForeign {
                snapshot: current.to_vec()
            }
        );
    }

    #[test]
    fn classify_force_reclaim_cannot_manufacture_liveness() {
        assert_eq!(classify_startup(None, &[], true), StartupAction::Proceed);
    }

    #[test]
    fn classify_force_reclaim_does_not_override_proven_reclaim() {
        let shared = VmProcId {
            pid: 10,
            creation_time: 100,
        };
        let prior = daemon_record_with(vec![shared]);
        let current = [shared];
        // A proven reclaim path is already safe; force must not change it.
        assert_eq!(
            classify_startup(Some(&prior), &current, true),
            StartupAction::ReclaimOrphan {
                proof: vec![shared]
            }
        );
    }

    #[test]
    fn classify_intersecting_set_reclaims() {
        let shared = VmProcId {
            pid: 10,
            creation_time: 100,
        };
        let other_prior = VmProcId {
            pid: 11,
            creation_time: 101,
        };
        let prior = daemon_record_with(vec![shared, other_prior]);
        // current has one process not in prior plus the shared one.
        let current = [
            VmProcId {
                pid: 20,
                creation_time: 200,
            },
            shared,
        ];
        // Reclaim returns the PRIOR proof (used to seed plan_kill_set), not
        // the live snapshot. Seeding with the snapshot would promote any
        // foreign WindowsSandbox* process observed at startup into "proof".
        assert_eq!(
            classify_startup(Some(&prior), &current, false),
            StartupAction::ReclaimOrphan {
                proof: vec![shared, other_prior]
            }
        );
    }

    // ----- plan_kill_set: pure kill planner --------------------------------

    fn pid(p: u32, ct: u64) -> VmProcId {
        VmProcId {
            pid: p,
            creation_time: ct,
        }
    }

    #[test]
    fn plan_kill_set_not_launched_is_none_regardless_of_snapshot() {
        assert_eq!(plan_kill_set(&VmOwnership::NotLaunched, &[]), None);
        assert_eq!(
            plan_kill_set(&VmOwnership::NotLaunched, &[pid(1, 1), pid(2, 2)]),
            None
        );
    }

    #[test]
    fn plan_kill_set_launch_in_flight_is_none_regardless_of_snapshot() {
        // Critical safety property: an in-flight launch is ambiguous (a
        // foreign VM could have won the contest) so we must never kill
        // anything, even if WindowsSandbox* processes are visible.
        assert_eq!(plan_kill_set(&VmOwnership::LaunchInFlight, &[]), None);
        assert_eq!(
            plan_kill_set(&VmOwnership::LaunchInFlight, &[pid(1, 1)]),
            None
        );
    }

    #[test]
    fn plan_kill_set_owned_with_empty_snapshot_returns_proof() {
        // The recorded proof may be dead PIDs but `terminate_processes`
        // checks creation_time, so killing already-dead identities is a no-op.
        // Critically we DO NOT enumerate-kill on empty snapshot in `Owned`.
        let proof = vec![pid(10, 100), pid(11, 101)];
        assert_eq!(
            plan_kill_set(&VmOwnership::Owned(proof.clone()), &[]),
            Some(proof)
        );
    }

    #[test]
    fn plan_kill_set_owned_intersect_unions_proof_and_snapshot() {
        let shared = pid(10, 100);
        let proof_only = pid(11, 101);
        let snapshot_only = pid(20, 200);
        let proof = vec![shared, proof_only];
        let snapshot = vec![snapshot_only, shared];
        let kill = plan_kill_set(&VmOwnership::Owned(proof), &snapshot).unwrap();
        // Order: proof first, snapshot extras appended.
        assert_eq!(kill, vec![shared, proof_only, snapshot_only]);
    }

    #[test]
    fn plan_kill_set_owned_disjoint_returns_only_proof() {
        // No proof PID intersects the snapshot: the live VM isn't ours, so we
        // never widen — a foreign/other-user sandbox is left untouched. We still
        // return the proof (a dead-recorded-PID kill is a safe no-op via
        // PID+creation_time matching).
        let proof = vec![pid(10, 100)];
        let foreign = vec![pid(99, 999)];
        assert_eq!(
            plan_kill_set(&VmOwnership::Owned(proof.clone()), &foreign),
            Some(proof)
        );
    }

    #[test]
    fn plan_kill_set_owned_pid_match_but_different_creation_time_is_disjoint() {
        // PID reuse defence: same PID, different creation_time is NOT a
        // match. Must return only the recorded proof, never the snapshot's
        // recycled-PID identity.
        let proof = vec![pid(10, 100)];
        let snapshot = vec![pid(10, 999)];
        assert_eq!(
            plan_kill_set(&VmOwnership::Owned(proof.clone()), &snapshot),
            Some(proof)
        );
    }

    #[test]
    fn plan_kill_set_launch_succeeded_no_proof_empty_snapshot_is_none() {
        // No proof and no live VM: nothing to kill. The narrow
        // "VM never produced visible processes" wedge is accepted here.
        assert_eq!(
            plan_kill_set(&VmOwnership::LaunchSucceededNoProof, &[]),
            None
        );
    }

    #[test]
    fn plan_kill_set_launch_succeeded_no_proof_with_snapshot_enumerates() {
        // The caller reaches this state only on a launch() Ok while holding
        // the host VM-slot mutex; by single-instance + the mutex the snapshot
        // is ours. This is the empty-proof recovery path: an intersection-only
        // kill would miss it because there is no proof to intersect.
        let snapshot = vec![pid(10, 100), pid(11, 101)];
        assert_eq!(
            plan_kill_set(&VmOwnership::LaunchSucceededNoProof, &snapshot),
            Some(snapshot)
        );
    }

    // ----- classify_stale_daemon_cleanup -----------------------------------

    fn stale_with(active: &str, vm_processes: Vec<VmProcId>) -> DaemonRecord {
        DaemonRecord {
            schema_version: RECORD_SCHEMA_VERSION,
            pid: 1,
            pid_creation_time: 1,
            ipc_port: 1,
            nonce: "n".to_string(),
            active_sandbox_id: active.to_string(),
            ready: true,
            vm_processes,
        }
    }

    #[test]
    fn stale_cleanup_no_stale_record_no_live_is_no_live_vm() {
        assert_eq!(
            classify_stale_daemon_cleanup(None, "wsb:x", Some(&[])),
            StaleDaemonCleanup::NoLiveVm
        );
    }

    #[test]
    fn stale_cleanup_probe_failed_refuses() {
        assert_eq!(
            classify_stale_daemon_cleanup(None, "wsb:x", None),
            StaleDaemonCleanup::RefuseProbeFailed
        );
        // Probe-failed wins even when a stale record exists.
        let stale = stale_with("wsb:x", vec![pid(10, 100)]);
        assert_eq!(
            classify_stale_daemon_cleanup(Some(&stale), "wsb:x", None),
            StaleDaemonCleanup::RefuseProbeFailed
        );
    }

    #[test]
    fn stale_cleanup_sandbox_id_mismatch_refuses_before_anything_else() {
        // Even with an intersecting live VM, a mismatched stale record must
        // refuse: cleanup of sandbox A must NEVER reclaim sandbox B's orphan.
        let stale = stale_with("wsb:b", vec![pid(10, 100)]);
        let live = vec![pid(10, 100)];
        assert_eq!(
            classify_stale_daemon_cleanup(Some(&stale), "wsb:a", Some(&live)),
            StaleDaemonCleanup::RefuseSandboxIdMismatch {
                stale_active: "wsb:b".to_string()
            }
        );
        // Mismatch even fires on an empty live set so the operator gets a
        // clear diagnostic (the alternative is "looks fine, advance state"
        // which silently corrupts cross-sandbox bookkeeping).
        assert_eq!(
            classify_stale_daemon_cleanup(Some(&stale), "wsb:a", Some(&[])),
            StaleDaemonCleanup::RefuseSandboxIdMismatch {
                stale_active: "wsb:b".to_string()
            }
        );
    }

    #[test]
    fn stale_cleanup_matching_record_empty_live_is_no_live_vm() {
        let stale = stale_with("wsb:x", vec![pid(10, 100)]);
        assert_eq!(
            classify_stale_daemon_cleanup(Some(&stale), "wsb:x", Some(&[])),
            StaleDaemonCleanup::NoLiveVm
        );
    }

    #[test]
    fn stale_cleanup_intersection_reclaims_with_prior_proof() {
        let shared = pid(10, 100);
        let proof = vec![shared, pid(11, 101)];
        let stale = stale_with("wsb:x", proof.clone());
        let live = vec![shared, pid(20, 200)];
        assert_eq!(
            classify_stale_daemon_cleanup(Some(&stale), "wsb:x", Some(&live)),
            StaleDaemonCleanup::Reclaim { proof }
        );
    }

    #[test]
    fn stale_cleanup_empty_stale_proof_with_live_refuses_foreign() {
        // The empty-proof wedge surface in stop/deprovision: a daemon died before
        // capture_launch_proof populated vm_processes; a live VM exists but
        // we have no positive proof it is ours. RefuseForeign (no sole-claim
        // weakening of the positive-proof invariant).
        let stale = stale_with("wsb:x", Vec::new());
        let live = vec![pid(10, 100)];
        assert_eq!(
            classify_stale_daemon_cleanup(Some(&stale), "wsb:x", Some(&live)),
            StaleDaemonCleanup::RefuseForeign { live }
        );
    }

    #[test]
    fn stale_cleanup_disjoint_live_refuses_foreign() {
        let stale = stale_with("wsb:x", vec![pid(10, 100)]);
        let live = vec![pid(20, 200)];
        assert_eq!(
            classify_stale_daemon_cleanup(Some(&stale), "wsb:x", Some(&live)),
            StaleDaemonCleanup::RefuseForeign { live }
        );
    }

    #[test]
    fn stale_cleanup_pid_match_creation_time_diff_refuses() {
        // PID reuse defence at the stop/deprovision orphan-cleanup site.
        let stale = stale_with("wsb:x", vec![pid(10, 100)]);
        let live = vec![pid(10, 999)];
        assert_eq!(
            classify_stale_daemon_cleanup(Some(&stale), "wsb:x", Some(&live)),
            StaleDaemonCleanup::RefuseForeign { live }
        );
    }

    #[test]
    fn stale_cleanup_no_stale_record_with_live_refuses_foreign() {
        // No record at all but a live VM: definitely not ours.
        let live = vec![pid(10, 100)];
        assert_eq!(
            classify_stale_daemon_cleanup(None, "wsb:x", Some(&live)),
            StaleDaemonCleanup::RefuseForeign { live }
        );
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
            vm_processes: Vec::new(),
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
            vm_processes: Vec::new(),
        };
        assert!(!daemon_alive(&rec));
    }

    #[cfg(windows)]
    #[test]
    fn dead_pid_has_no_creation_time() {
        // PID 0 is never a queryable user process.
        assert_eq!(process_creation_time(0), None);
        assert_eq!(running_process_creation_time(0), None);
    }

    #[cfg(windows)]
    #[test]
    fn running_creation_time_matches_plain_for_live_self() {
        let pid = std::process::id();
        assert_eq!(
            running_process_creation_time(pid),
            process_creation_time(pid)
        );
        assert!(running_process_creation_time(pid).is_some());
    }

    #[cfg(windows)]
    #[test]
    fn running_creation_time_excludes_terminated_but_handle_retained() {
        use std::process::{Command, Stdio};
        // A long-lived child we control. `std::process::Child` retains the
        // process handle until `wait()`, so after we kill it the kernel object
        // lingers and `OpenProcess`-by-PID still resolves it — exactly the
        // "crashed launcher whose parent kept a handle" case that wedged
        // reclaim.
        let mut child = Command::new("cmd")
            .args(["/C", "ping -n 999 127.0.0.1"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn child");
        let pid = child.id();

        // While alive both probes agree.
        let ct = process_creation_time(pid).expect("live child has a creation time");
        assert_eq!(running_process_creation_time(pid), Some(ct));

        // Terminate but DELIBERATELY do not `wait()`: `child` keeps the handle.
        child.kill().expect("kill child");
        // The process handle becomes signalled shortly after termination.
        for _ in 0..100 {
            if running_process_creation_time(pid).is_none() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }

        // The lingering terminated object still resolves a creation time via the
        // plain probe...
        assert_eq!(
            process_creation_time(pid),
            Some(ct),
            "terminated-but-handle-retained object should still resolve a creation time"
        );
        // ...but the liveness-aware probe correctly reports it as gone.
        assert_eq!(
            running_process_creation_time(pid),
            None,
            "a terminated process must not be reported as running"
        );

        let _ = child.wait();
    }

    #[cfg(windows)]
    #[test]
    fn enumerate_finds_current_process_by_image_prefix() {
        // The test runner's own image name is a stable, present process. Use a
        // short prefix of its file stem and assert the Toolhelp32 snapshot finds
        // our PID with a matching creation time.
        let exe = std::env::current_exe().unwrap();
        let stem = exe.file_stem().unwrap().to_string_lossy().into_owned();
        let prefix: String = stem.chars().take(6).collect();

        let pids = enumerate_pids_with_prefix(&prefix).unwrap();
        assert!(
            pids.contains(&std::process::id()),
            "expected snapshot for prefix {prefix:?} to contain our pid {}, got {pids:?}",
            std::process::id()
        );

        let procs = enumerate_processes_with_prefix(&prefix).unwrap();
        let ours = procs
            .iter()
            .find(|p| p.pid == std::process::id())
            .expect("our process should be enumerated with an identity");
        assert_eq!(ours.creation_time, process_creation_time(ours.pid).unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn enumerate_unmatched_prefix_is_empty() {
        let pids = enumerate_pids_with_prefix("zzz_no_such_process_prefix_zzz").unwrap();
        assert!(pids.is_empty(), "unexpected matches: {pids:?}");
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

    #[test]
    fn decide_cleanup_not_launched_is_noop() {
        assert_eq!(
            decide_cleanup(&VmOwnership::NotLaunched),
            CleanupAction::Noop
        );
    }

    #[test]
    fn decide_cleanup_launch_in_flight_leaks() {
        // Critical safety property: an in-flight (unproven) launch must NEVER
        // tear anything down (a foreign VM may have won the contest).
        assert_eq!(
            decide_cleanup(&VmOwnership::LaunchInFlight),
            CleanupAction::LeakUnowned
        );
    }

    #[test]
    fn decide_cleanup_launch_succeeded_no_proof_tears_down_by_enumeration() {
        // launch() returned Ok -> the VM is ours; tear it down even without
        // recorded proof, via an empty seed that teardown_owned enumerates.
        assert_eq!(
            decide_cleanup(&VmOwnership::LaunchSucceededNoProof),
            CleanupAction::Teardown(Vec::new())
        );
    }

    #[test]
    fn decide_cleanup_owned_tears_down_recorded() {
        let pids = vec![
            VmProcId {
                pid: 10,
                creation_time: 100,
            },
            VmProcId {
                pid: 20,
                creation_time: 200,
            },
        ];
        assert_eq!(
            decide_cleanup(&VmOwnership::Owned(pids.clone())),
            CleanupAction::Teardown(pids)
        );
    }

    #[test]
    fn terminate_empty_targets_kills_nothing() {
        assert_eq!(terminate_processes(&[]), 0);
    }

    #[cfg(windows)]
    #[test]
    fn terminate_kills_recorded_process() {
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/c", "pause"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        let creation_time = process_creation_time(pid).expect("creation time");
        let killed = terminate_processes(&[VmProcId { pid, creation_time }]);
        assert_eq!(killed, 1);
        // `terminate_processes` only requests termination; the test reaps the child.
        let status = child.wait().unwrap();
        assert!(!status.success());
    }

    #[cfg(windows)]
    #[test]
    fn terminate_skips_creation_time_mismatch() {
        // Spawn a child, but record a deliberately-wrong creation time so the
        // PID-reuse guard refuses to kill it.
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/c", "pause"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        let real = process_creation_time(pid).expect("creation time");
        let wrong = real.wrapping_add(1);
        let killed = terminate_processes(&[VmProcId {
            pid,
            creation_time: wrong,
        }]);
        assert_eq!(killed, 0, "must not kill a PID whose creation time differs");
        // The child is still alive; clean it up directly.
        let _ = child.kill();
        let _ = child.wait();
    }

    /// Ensure atomic writes protect the parent before creating the temp file.
    #[cfg(windows)]
    #[test]
    fn atomic_write_protects_parent_directory() {
        use std::os::windows::ffi::OsStrExt;
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HLOCAL};
        use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
        use windows::Win32::Security::{
            GetSecurityDescriptorControl, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
            SE_DACL_PROTECTED,
        };

        let dir = tempfile::tempdir().unwrap();
        // A nested parent that `atomic_write_json` must create + secure itself,
        // so it cannot accidentally pass by inheriting a protected tempdir.
        let parent = dir.path().join("nested");
        let path = parent.join("daemon.json");
        let rec = daemon_record_with(vec![VmProcId {
            pid: 5,
            creation_time: 7,
        }]);
        atomic_write_json(&path, &rec).unwrap();

        let mut wide: Vec<u16> = parent.as_os_str().encode_wide().collect();
        wide.push(0);
        let mut sd = PSECURITY_DESCRIPTOR::default();
        let rc = unsafe {
            GetNamedSecurityInfoW(
                PCWSTR(wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                None,
                None,
                &mut sd,
            )
        };
        assert_eq!(rc, ERROR_SUCCESS, "GetNamedSecurityInfoW failed: {rc:?}");

        let mut control = 0u16;
        let mut revision = 0u32;
        let got = unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) };
        let protected = (control & SE_DACL_PROTECTED.0) != 0;
        unsafe {
            let _ = LocalFree(Some(HLOCAL(sd.0)));
        }
        got.expect("GetSecurityDescriptorControl");
        assert!(
            protected,
            "record parent dir must have a PROTECTED DACL (got control bits {control:#06x})"
        );
    }
}
