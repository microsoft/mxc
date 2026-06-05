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

/// Name of the host-global "WSB VM slot" mutex. The host permits a single
/// running Windows Sandbox VM; whoever owns that VM (a one-shot run for its
/// whole lifetime, or a state-aware daemon for its whole lifetime) holds this
/// mutex. It serialises VM ownership **across both modes** so a one-shot and a
/// state-aware daemon can never both believe they launched the singleton VM
/// (which would let the survivor's teardown kill the other's VM). `Local\`
/// keeps it scoped to the current logon session, matching the single-user
/// design.
pub const HOST_VM_MUTEX_NAME: &str = r"Local\wxc-wsb-vm";

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
    /// `false` while the daemon is still booting the VM (record published
    /// *before* launch so the daemon occupies the single-instance slot from the
    /// moment it starts), `true` once the VM + guest are connected and ready to
    /// serve. The IPC port is bound and served even while `ready` is `false`, so
    /// a `STOP` can gracefully abort an in-flight boot.
    pub ready: bool,
    /// Identities of the Windows Sandbox host processes this daemon launched,
    /// captured once the VM is up. Empty until `ready` is `true`.
    ///
    /// This is the *positive ownership proof* used by a later daemon's startup
    /// reconcile: an orphaned VM is only reclaimed (torn down) when the running
    /// sandbox processes intersect this recorded set. A present record alone is
    /// never sufficient — without an intersection the VM is treated as foreign
    /// and left untouched. `#[serde(default)]` keeps older records readable.
    #[serde(default)]
    pub vm_processes: Vec<VmProcId>,
}

/// What a freshly-starting daemon should do about any Windows Sandbox VM it
/// finds already running. Produced by the pure [`classify_startup`] so the
/// decision is unit-testable without a real VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupAction {
    /// No VM is running (or none that matters): launch normally.
    Proceed,
    /// A running VM is provably ours (a prior daemon's recorded process
    /// identities intersect the live set): tear it down, then launch.
    ReclaimOrphan,
    /// A running VM exists but ownership is *not* positively proven: refuse to
    /// disturb it (it may be a user's manually-opened sandbox).
    RefuseForeign,
}

/// Decide what to do about an already-running Windows Sandbox VM at daemon
/// startup, given the prior global daemon record (if any) and the set of
/// currently-running sandbox host processes.
///
/// Reclaim is intentionally conservative: it requires a *positive* identity
/// intersection between the prior record's `vm_processes` and the live set.
/// Anything else — no record, an empty `vm_processes` (e.g. a daemon that
/// crashed before the VM became ready), or a disjoint set — yields
/// [`StartupAction::RefuseForeign`] so we never kill a VM we cannot prove is
/// ours.
///
/// The caller is responsible for first rejecting the case where `prior`
/// describes a *live* daemon (another daemon already owns the slot); by the
/// time this runs, `prior` is expected to be stale/dead.
pub fn classify_startup(prior: Option<&DaemonRecord>, current_vm: &[VmProcId]) -> StartupAction {
    if current_vm.is_empty() {
        return StartupAction::Proceed;
    }
    if let Some(prior) = prior {
        let ours = prior
            .vm_processes
            .iter()
            .any(|recorded| current_vm.contains(recorded));
        if ours {
            return StartupAction::ReclaimOrphan;
        }
    }
    StartupAction::RefuseForeign
}

/// How far VM ownership has progressed within a single daemon process. The
/// cleanup path consults this (via [`decide_cleanup`]) so it never tears down a
/// VM it cannot prove it owns.
///
/// The crucial distinction is between a launch that is still *in flight* (we
/// cannot prove a VM is ours — a foreign VM could have won the single-instance
/// contest and made our launch fail) and a launch that *returned `Ok`* (the OS
/// single-instance guarantee plus startup reconcile mean the running VM is
/// definitely ours, even if its host processes have not been enumerated yet).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmOwnership {
    /// No VM launch was ever issued by this daemon.
    NotLaunched,
    /// A launch was *issued* but has not yet been observed to succeed (the
    /// `launch()` call is in flight, or it errored, or the daemon stopped
    /// before it returned). Ambiguous: a foreign VM could have raced in and
    /// caused our launch to fail, so cleanup must NOT tear anything down.
    LaunchInFlight,
    /// `launch()` returned `Ok` — the running VM is ours by the single-instance
    /// invariant — but no host-process proof was captured yet (slow boot).
    /// Cleanup may tear down whatever sandbox VM is live (it is ours), but the
    /// durable record carries no reclaim proof, so a crash here is a known
    /// (shrinking) wedge window.
    LaunchSucceededNoProof,
    /// This daemon holds a launched VM and captured its host-process
    /// identities. Cleanup may tear exactly these down (with a snapshot
    /// fallback for any host process the proof missed).
    Owned(Vec<VmProcId>),
}

/// What the daemon cleanup path should do, derived purely from ownership state
/// so the decision is unit-testable without a real VM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanupAction {
    /// Nothing was launched: do nothing.
    Noop,
    /// A launch is in flight but ownership is unprovable: leave any VM alone
    /// (fail safe) and let the operator or the next startup reconcile deal with
    /// it. Never kill in this state.
    LeakUnowned,
    /// Tear down the sandbox VM, seeding the kill set with `Vec<VmProcId>`
    /// (possibly empty). `teardown_owned` additionally snapshots the live
    /// sandbox processes at teardown start — safe because the caller only
    /// reaches a `Teardown` action when it provably holds the single-instance
    /// VM — so an empty seed (launch-succeeded-but-no-proof) still tears the VM
    /// down by enumeration.
    Teardown(Vec<VmProcId>),
}

/// Map an [`VmOwnership`] to the cleanup action the daemon should take on exit.
pub fn decide_cleanup(ownership: &VmOwnership) -> CleanupAction {
    match ownership {
        VmOwnership::NotLaunched => CleanupAction::Noop,
        VmOwnership::LaunchInFlight => CleanupAction::LeakUnowned,
        // Launch succeeded → the VM is ours; tear it down by enumeration even
        // without recorded proof (empty seed).
        VmOwnership::LaunchSucceededNoProof => CleanupAction::Teardown(Vec::new()),
        VmOwnership::Owned(pids) => CleanupAction::Teardown(pids.clone()),
    }
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

/// Lock a directory MXC owns down to an owner-only, inheritable DACL so files
/// created underneath are not cross-user readable/tamperable on a shared temp
/// dir. Thin `anyhow` wrapper over
/// [`wxc_common::filesystem_dacl::set_owner_only_dacl`].
#[cfg(windows)]
pub fn set_owner_only_dir(dir: &Path) -> Result<()> {
    wxc_common::filesystem_dacl::set_owner_only_dacl(dir, true)
        .map_err(|e| anyhow::Error::new(e).context(format!("secure dir {dir:?}")))
}

/// No-op stub for non-Windows: the DACL primitives are Windows-only, and the
/// state-aware Windows Sandbox backend that calls them does not run on other
/// platforms. The stub exists so the rest of this crate (pure decision logic +
/// path helpers + record I/O) stays buildable as part of `cargo check
/// --workspace` on Linux/macOS.
#[cfg(not(windows))]
pub fn set_owner_only_dir(_dir: &Path) -> Result<()> {
    Ok(())
}

/// Stamp a single file (already created) with the owner-only DACL. Used as
/// belt-and-suspenders on the temp record file inside [`atomic_write_json`];
/// see the comment there for why this is needed even when the parent dir
/// already has an inheritable owner-only DACL. No-op on non-Windows so the
/// crate compiles as part of `cargo check --workspace`.
#[cfg(windows)]
fn set_owner_only_file(path: &Path) -> Result<()> {
    wxc_common::filesystem_dacl::set_owner_only_dacl(path, false)
        .map_err(|e| anyhow::Error::new(e).context(format!("secure file {path:?}")))
}

#[cfg(not(windows))]
fn set_owner_only_file(_path: &Path) -> Result<()> {
    Ok(())
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

    // Lock the record DIRECTORY down to an owner-only, inheritable DACL BEFORE
    // creating the temp file, so the temp file inherits owner-only from the
    // instant it exists. Without this, the temp file would first materialise
    // under the parent's default (possibly cross-user-readable) ACL — e.g. the
    // global daemon record lives directly under %TEMP%\wxc-wsb\state-aware,
    // which is C:\Windows\Temp for a service account. A cross-user attacker
    // polling the dir could open the `<uuid>.tmp` with FILE_SHARE_READ and
    // RETAIN that handle past a later per-file DACL change (Windows does not
    // revoke existing opens on a DACL replacement), reading the persisted auth
    // nonce after the rename. Securing the parent first closes that window.
    // Fail closed: never write a nonce-bearing record into an unsecured dir.
    set_owner_only_dir(parent).with_context(|| format!("secure record dir {:?}", parent))?;

    let json = serde_json::to_vec_pretty(value).context("serialise record")?;
    let tmp = parent.join(format!("{}.tmp", uuid::Uuid::new_v4()));
    std::fs::write(&tmp, &json).with_context(|| format!("write temp record {:?}", tmp))?;

    // Belt-and-suspenders: stamp the file itself owner-only too (the parent
    // DACL already makes the inherited ACL owner-only; this also strips any
    // inherited ACE should the parent ever not be inheritable). Fail closed: on
    // error, discard the temp file rather than publish an unsecured record.
    if let Err(e) = set_owner_only_file(&tmp) {
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

/// Creation time of `pid` **only if the process is currently running**.
///
/// Returns `None` when the PID cannot be opened, its times cannot be read, or —
/// crucially — the process has already *terminated*. A terminated process whose
/// kernel object is kept alive by a retained parent handle still opens by PID
/// and `GetProcessTimes` reports its *original* creation time, so a plain
/// open+times probe would mistake a crashed-but-handle-retained launcher for a
/// live one (e.g. a one-shot `wxc-exec` killed while its SDK/shell parent still
/// holds a handle). The signalled (exited) state is therefore excluded
/// explicitly via a zero-timeout wait.
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
        // A process handle becomes signalled the moment the process exits. A
        // zero-timeout wait that returns `WAIT_OBJECT_0` therefore means the
        // process has already terminated (even if its object lingers); anything
        // else (`WAIT_TIMEOUT`) means it is still running.
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

#[cfg(not(windows))]
pub fn running_process_creation_time(_pid: u32) -> Option<u64> {
    None
}

/// Enumerate the PIDs of all running processes whose image name starts
/// (case-insensitively) with `name_prefix`, via a single Toolhelp32 snapshot.
///
/// This replaces shelling out to PowerShell `Get-Process`: it is fast, has no
/// external dependency, and takes one atomic snapshot of the process list —
/// the right substrate for ownership-proof and liveness decisions. Returns
/// `Err` only if the snapshot itself could not be taken, so callers gating a
/// destructive decision can treat `Err` as "unknown" and fail safe.
#[cfg(windows)]
pub fn enumerate_pids_with_prefix(name_prefix: &str) -> Result<Vec<u32>> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    fn wide_to_string(wide: &[u16]) -> String {
        let len = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
        String::from_utf16_lossy(&wide[..len])
    }

    let prefix_lower = name_prefix.to_lowercase();
    let mut pids = Vec::new();

    // SAFETY: the snapshot handle is closed on every return path; the
    // PROCESSENTRY32W is fully initialised (dwSize set) before the first/next
    // calls, and the szExeFile out-param is a fixed-size array.
    unsafe {
        let snapshot =
            CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).context("CreateToolhelp32Snapshot")?;

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        let mut ok = Process32FirstW(snapshot, &mut entry).is_ok();
        while ok {
            let name = wide_to_string(&entry.szExeFile);
            if name.to_lowercase().starts_with(&prefix_lower) {
                pids.push(entry.th32ProcessID);
            }
            ok = Process32NextW(snapshot, &mut entry).is_ok();
        }

        let _ = CloseHandle(snapshot);
    }

    Ok(pids)
}

#[cfg(not(windows))]
pub fn enumerate_pids_with_prefix(_name_prefix: &str) -> Result<Vec<u32>> {
    Ok(Vec::new())
}

/// Enumerate the identities (PID + creation time) of all running processes
/// whose image name starts (case-insensitively) with `name_prefix`.
///
/// Built on [`enumerate_pids_with_prefix`] for the snapshot, then pairs each
/// PID with its creation time so the result is PID-reuse-safe. A process that
/// exits between the snapshot and the creation-time query is simply dropped.
pub fn enumerate_processes_with_prefix(name_prefix: &str) -> Result<Vec<VmProcId>> {
    let mut procs = Vec::new();
    for pid in enumerate_pids_with_prefix(name_prefix)? {
        if let Some(creation_time) = process_creation_time(pid) {
            procs.push(VmProcId { pid, creation_time });
        }
    }
    Ok(procs)
}

/// Terminate exactly the processes in `targets`, verifying each one's live
/// creation time still matches before killing so a recycled PID is never hit.
/// Returns the number of processes actually terminated.
///
/// This never enumerates or kills by image name — it can only touch processes
/// explicitly recorded as ours — so it cannot disturb a VM this host did not
/// launch. It is the scoped replacement for `taskkill /F /IM WindowsSandbox*`.
#[cfg(windows)]
pub fn terminate_processes(targets: &[VmProcId]) -> usize {
    use windows::Win32::Foundation::{CloseHandle, FILETIME};
    use windows::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, TerminateProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_TERMINATE,
    };

    let mut killed = 0usize;
    for target in targets {
        if target.pid == 0 {
            continue;
        }
        // SAFETY: `pid` is a plain integer; the handle is closed on every path
        // and the FILETIME out-params are fully initialised before use.
        unsafe {
            // Open FIRST, then verify the creation time on the SAME handle we
            // will terminate through. A process handle pins one specific process
            // instance, so the OS cannot recycle the PID to a different live
            // process between the identity check and the kill (the previous
            // check-by-PID-then-open-by-PID sequence had exactly that TOCTOU
            // window: a recycled PID could resolve `OpenProcess` to a foreign
            // process that `TerminateProcess` would then kill).
            let Ok(handle) = OpenProcess(
                PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                target.pid,
            ) else {
                continue;
            };
            let mut creation = FILETIME::default();
            let mut exit = FILETIME::default();
            let mut kernel = FILETIME::default();
            let mut user = FILETIME::default();
            let times_ok =
                GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user).is_ok();
            let ct = ((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64;
            if times_ok && ct == target.creation_time && TerminateProcess(handle, 1).is_ok() {
                killed += 1;
            }
            let _ = CloseHandle(handle);
        }
    }
    killed
}

#[cfg(not(windows))]
pub fn terminate_processes(_targets: &[VmProcId]) -> usize {
    0
}

/// True iff the daemon described by `record` is still the live process it
/// claims to be: a process with its PID is **currently running** AND its
/// creation time matches the recorded one. Uses the liveness-aware
/// [`running_process_creation_time`] so a terminated daemon whose object
/// lingers behind a retained handle is correctly reported as gone rather than
/// blocking a fresh daemon from reclaiming the slot.
pub fn daemon_alive(record: &DaemonRecord) -> bool {
    running_process_creation_time(record.pid) == Some(record.pid_creation_time)
}

// ---------------------------------------------------------------------------
// Cross-process transition lock
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Cross-process named mutexes
// ---------------------------------------------------------------------------

/// Acquire a Windows named mutex, waiting up to `timeout`. Returns the handle
/// and whether we own it (always `true` on success; the handle must be released
/// + closed on drop). Shared by [`TransitionLock`] and [`HostVmLock`].
#[cfg(windows)]
fn named_mutex_acquire(
    name: &str,
    timeout: std::time::Duration,
) -> Result<windows::Win32::Foundation::HANDLE> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{WAIT_ABANDONED, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{CreateMutexW, WaitForSingleObject};

    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

    // SAFETY: `wide` is a valid null-terminated UTF-16 buffer that outlives the
    // call; the returned handle is owned by the caller and closed on drop.
    let handle = unsafe { CreateMutexW(None, false, PCWSTR(wide.as_ptr())) }
        .context("create named mutex")?;

    let ms = timeout.as_millis().min(u32::MAX as u128) as u32;
    // SAFETY: `handle` is a valid mutex handle from `CreateMutexW`.
    let wait = unsafe { WaitForSingleObject(handle, ms) };
    if wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED {
        // WAIT_ABANDONED: a previous holder died without releasing. We now own
        // the mutex; the protected state is reconciled separately via records /
        // process-identity proof, so taking ownership here is correct.
        Ok(handle)
    } else {
        // SAFETY: closing the handle we just created; we do not own the mutex.
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(handle);
        }
        anyhow::bail!("timed out acquiring named mutex {name:?} after {timeout:?}");
    }
}

/// Release (if owned) and close a named-mutex handle. Shared drop helper.
#[cfg(windows)]
fn named_mutex_release(handle: windows::Win32::Foundation::HANDLE, owned: bool) {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::ReleaseMutex;
    // SAFETY: `handle` is a valid mutex handle owned by the caller.
    unsafe {
        if owned {
            let _ = ReleaseMutex(handle);
        }
        let _ = CloseHandle(handle);
    }
}

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
        let handle = named_mutex_acquire(TRANSITION_MUTEX_NAME, timeout)?;
        Ok(Self {
            handle,
            owned: true,
        })
    }
}

#[cfg(windows)]
impl Drop for TransitionLock {
    fn drop(&mut self) {
        named_mutex_release(self.handle, self.owned);
    }
}

/// RAII guard over the host-global WSB VM-slot mutex ([`HOST_VM_MUTEX_NAME`]).
/// Held for the entire lifetime that a process owns the host's single Windows
/// Sandbox VM (a one-shot run, or a state-aware daemon), so the two modes can
/// never both launch / own the singleton VM concurrently. Released on drop.
#[cfg(windows)]
pub struct HostVmLock {
    handle: windows::Win32::Foundation::HANDLE,
    owned: bool,
}

#[cfg(windows)]
impl HostVmLock {
    /// Acquire the host VM-slot mutex, waiting up to `timeout`. On timeout the
    /// slot is owned by another VM owner (a concurrent one-shot or a live
    /// state-aware daemon) — the caller should surface this as "busy".
    pub fn acquire(timeout: std::time::Duration) -> Result<Self> {
        let handle = named_mutex_acquire(HOST_VM_MUTEX_NAME, timeout)?;
        Ok(Self {
            handle,
            owned: true,
        })
    }
}

#[cfg(windows)]
impl Drop for HostVmLock {
    fn drop(&mut self) {
        named_mutex_release(self.handle, self.owned);
    }
}

/// Non-Windows stub: the host VM mutex is a Windows-only concept.
#[cfg(not(windows))]
pub struct HostVmLock;

#[cfg(not(windows))]
impl HostVmLock {
    pub fn acquire(_timeout: std::time::Duration) -> Result<Self> {
        Ok(Self)
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
// The daemon serves a line protocol on `127.0.0.1:<ipc_port>`:
//   request  : `<VERB> <nonce>\n`
//   response : `OK\n` | `PONG\n` | `ERR <message>\n`
// The nonce authenticates the caller against a process that merely squats the
// localhost port. The `EXEC` verb continues into a binary frame stream after
// its status line (see [`crate::ipc_exec`]).

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
        assert_eq!(classify_startup(Some(&prior), &[]), StartupAction::Proceed);
        assert_eq!(classify_startup(None, &[]), StartupAction::Proceed);
    }

    #[test]
    fn classify_vm_no_prior_refuses() {
        let current = [VmProcId {
            pid: 10,
            creation_time: 100,
        }];
        assert_eq!(
            classify_startup(None, &current),
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
            classify_startup(Some(&prior), &current),
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
            classify_startup(Some(&prior), &current),
            StartupAction::RefuseForeign
        );
    }

    #[test]
    fn classify_intersecting_set_reclaims() {
        let shared = VmProcId {
            pid: 10,
            creation_time: 100,
        };
        let prior = daemon_record_with(vec![
            shared,
            VmProcId {
                pid: 11,
                creation_time: 101,
            },
        ]);
        // current has one process not in prior plus the shared one.
        let current = [
            VmProcId {
                pid: 20,
                creation_time: 200,
            },
            shared,
        ];
        assert_eq!(
            classify_startup(Some(&prior), &current),
            StartupAction::ReclaimOrphan
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
        // Spawn a long-lived child, record its identity, terminate it.
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
        // The child must actually be reaped.
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

    /// Regression guard for the daemon.json temp-write nonce-disclosure fix:
    /// `atomic_write_json` must lock the record DIRECTORY to an owner-only,
    /// PROTECTED DACL *before* it ever writes the plaintext `<uuid>.tmp`. We
    /// assert the post-condition that survives that ordering: the parent dir's
    /// DACL has `SE_DACL_PROTECTED` set (inherited ACEs stripped). A freshly
    /// `create_dir_all`'d directory inherits its parent's (non-protected) ACL,
    /// so if the `set_owner_only_dir(parent)` call were removed this assertion
    /// would fail.
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
