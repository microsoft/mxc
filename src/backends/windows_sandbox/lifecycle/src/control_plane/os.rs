// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Win32 FFI primitives the state-aware control plane is built on: DACL
//! stamping, PID-reuse-safe process times, scoped image-prefix process
//! enumeration / termination, and the two cross-process named-mutex
//! RAII guards (transition lock + host VM slot lock).
//!
//! This module is a pure code-move out of the historic [`super`] module
//! to keep the decision-logic layer (`plan_kill_set`,
//! `classify_startup`, `classify_stale_daemon_cleanup`, record schemas
//! and CRUD) navigable: those were getting buried under several hundred
//! lines of `unsafe` Win32 plumbing. Every public item is re-exported
//! from [`super`] via `pub use os::*;` so existing call sites
//! (`control_plane::process_creation_time`, etc.) keep compiling
//! unchanged.
//!
//! No behavioural change vs. the pre-split file; tests, callers, and
//! non-Windows stubs are preserved byte-for-byte.

use std::path::Path;

use anyhow::{Context, Result};

use super::VmProcId;

/// Name of the cross-process transition mutex. `Local\` keeps it scoped to the
/// current logon session, which is the right blast radius: state-aware WSB is a
/// single-user, single-instance backend.
///
/// **Same-user scope (review M2):** the mutex name is fixed and the
/// object is created without an explicit security descriptor, so
/// another process running under the same user account can pre-create
/// it (or hold it) and deny service. This is consistent with the
/// `windows_sandbox_common::auth` threat model — same-user processes
/// are inside the trust boundary on the single-user developer-
/// workstation target this backend is designed for, and a same-user
/// attacker has many cheaper DoS levers than mutex squatting.
const TRANSITION_MUTEX_NAME: &str = r"Local\wxc-wsb-stateaware-transition";

/// Name of the host-global "WSB VM slot" mutex. The host permits a single
/// running Windows Sandbox VM; whoever owns that VM (a one-shot run for its
/// whole lifetime, or a state-aware daemon for its whole lifetime) holds this
/// mutex. It serialises VM ownership **across both modes** so a one-shot and a
/// state-aware daemon can never both believe they launched the singleton VM
/// (which would let the survivor's teardown kill the other's VM). `Local\`
/// keeps it scoped to the current logon session, matching the single-user
/// design.
///
/// Same-user squatting scope: identical to [`TRANSITION_MUTEX_NAME`]
/// above — a same-user process can pre-create or hold this mutex to
/// deny service. Out of scope for the same single-user threat-model
/// reason.
pub const HOST_VM_MUTEX_NAME: &str = r"Local\wxc-wsb-vm";

// ---------------------------------------------------------------------------
// Filesystem DACL helpers
// ---------------------------------------------------------------------------

/// Stamp `dir` with an owner-only, inheritable DACL so any files / subdirs
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
/// belt-and-suspenders on the temp record file inside
/// [`super::atomic_write_json`]; see the comment there for why this is needed
/// even when the parent dir already has an inheritable owner-only DACL. No-op
/// on non-Windows so the crate compiles as part of `cargo check --workspace`.
///
/// `pub(crate)` rather than `pub`: the only legitimate caller is
/// [`super::atomic_write_json`], which is a sibling in the same crate. There is
/// no use case for an external crate to stamp ad-hoc files, and keeping the
/// surface narrow avoids accidentally inviting one.
#[cfg(windows)]
pub(crate) fn set_owner_only_file(path: &Path) -> Result<()> {
    wxc_common::filesystem_dacl::set_owner_only_dacl(path, false)
        .map_err(|e| anyhow::Error::new(e).context(format!("secure file {path:?}")))
}

#[cfg(not(windows))]
pub(crate) fn set_owner_only_file(_path: &Path) -> Result<()> {
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

// ---------------------------------------------------------------------------
// Scoped image-prefix process enumeration / termination
// ---------------------------------------------------------------------------

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
