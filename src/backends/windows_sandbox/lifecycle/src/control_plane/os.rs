// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Win32 DACL, process, and named-mutex primitives for the control plane.

use std::path::Path;

use anyhow::{Context, Result};

use super::VmProcId;

/// Per-session transition mutex. Same-user denial of service is within the
/// backend's trust boundary.
const TRANSITION_MUTEX_NAME: &str = r"Local\wxc-wsb-stateaware-transition";

/// Per-session mutex for the host's single Windows Sandbox VM slot.
///
/// One-shot and state-aware owners hold it for the VM lifetime so neither can
/// tear down the other's VM. `Global\` is unsuitable because these unelevated
/// processes lack `SeCreateGlobalPrivilege`; cross-session use is unsupported.
pub const HOST_VM_MUTEX_NAME: &str = r"Local\wxc-wsb-vm";

// ---------------------------------------------------------------------------
// Filesystem DACL helpers
// ---------------------------------------------------------------------------

/// Apply an inheritable owner-only DACL and reject directories owned by another
/// user, who would retain implicit `WRITE_DAC`.
#[cfg(windows)]
pub fn set_owner_only_dir(dir: &Path) -> Result<()> {
    wxc_common::filesystem_dacl::set_owner_only_dacl(dir, true)
        .map_err(|e| anyhow::Error::new(e).context(format!("secure dir {dir:?}")))?;
    // A foreign owner could use implicit WRITE_DAC to defeat the new ACL.
    let owned = wxc_common::filesystem_dacl::owner_is_self(dir)
        .map_err(|e| anyhow::Error::new(e).context(format!("read owner of {dir:?}")))?;
    if !owned {
        anyhow::bail!(
            "refusing to use {dir:?}: it is owned by another user (cross-user tampering risk on \
             a shared temp directory). Remove it and retry."
        );
    }
    Ok(())
}

/// Non-Windows no-op.
#[cfg(not(windows))]
pub fn set_owner_only_dir(_dir: &Path) -> Result<()> {
    Ok(())
}

/// Create and secure a directory before reading trusted state from it.
#[cfg(windows)]
pub fn ensure_secure_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create dir {dir:?}"))?;
    set_owner_only_dir(dir)
}

/// Non-Windows directory creation.
#[cfg(not(windows))]
pub fn ensure_secure_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create dir {dir:?}"))
}

/// Apply an owner-only DACL to an existing file.
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

/// Creation time of `pid` only while the process is still running.
///
/// A retained handle keeps an exited process queryable, so this also checks the
/// handle's signalled state.
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
        // Process handles become signalled on exit.
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
/// Fast, with no external dependency, and takes one atomic snapshot of the
/// process list — the right substrate for ownership-proof and liveness
/// decisions. Returns
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
            // process between the identity check and the kill. Checking by PID
            // and then re-opening by PID would leave a TOCTOU window: a recycled
            // PID could resolve `OpenProcess` to a foreign process that
            // `TerminateProcess` would then kill.
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

/// Try to acquire the named mutex, distinguishing contention from failure.
/// Returns the owned handle on success (closed on drop), `Ok(None)` when the
/// wait times out because another owner holds it (the caller may treat this as
/// "busy"), and `Err` for a create/wait failure, which is not contention.
#[cfg(windows)]
fn named_mutex_try_acquire(
    name: &str,
    timeout: std::time::Duration,
) -> Result<Option<windows::Win32::Foundation::HANDLE>> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT};
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
        Ok(Some(handle))
    } else if wait == WAIT_TIMEOUT {
        // Contention: another owner holds the mutex. Not an error.
        // SAFETY: closing the handle we just created; we do not own the mutex.
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(handle);
        }
        Ok(None)
    } else {
        // WAIT_FAILED or any other unexpected result is a real failure.
        // SAFETY: closing the handle we just created; we do not own the mutex.
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(handle);
        }
        anyhow::bail!("waiting on named mutex {name:?} failed (wait result {wait:?})");
    }
}

/// Acquire the named mutex, returning `Err` on either contention (timeout) or a
/// real failure. Callers that need to distinguish the two use
/// [`named_mutex_try_acquire`].
#[cfg(windows)]
fn named_mutex_acquire(
    name: &str,
    timeout: std::time::Duration,
) -> Result<windows::Win32::Foundation::HANDLE> {
    match named_mutex_try_acquire(name, timeout)? {
        Some(handle) => Ok(handle),
        None => anyhow::bail!("timed out acquiring named mutex {name:?} after {timeout:?}"),
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

    /// Try to acquire the host VM-slot mutex. `Ok(None)` means it is held by
    /// another VM owner ("busy"); `Err` is a real create/wait failure, not busy.
    pub fn try_acquire(timeout: std::time::Duration) -> Result<Option<Self>> {
        Ok(
            named_mutex_try_acquire(HOST_VM_MUTEX_NAME, timeout)?.map(|handle| Self {
                handle,
                owned: true,
            }),
        )
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

    pub fn try_acquire(_timeout: std::time::Duration) -> Result<Option<Self>> {
        Ok(Some(Self))
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn named_mutex_try_acquire_reports_contention_as_none_not_err() {
        use std::sync::mpsc;
        use std::time::Duration;

        // Unique name per run so the test never collides with a real host VM
        // mutex or a concurrent test run.
        let name = format!("Local\\mxc-test-mutex-{}", uuid::Uuid::new_v4());
        let (held_tx, held_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();

        // A separate thread must own the mutex: a named mutex is recursive per
        // thread, so the same thread could re-acquire it without contending.
        let holder_name = name.clone();
        let holder = std::thread::spawn(move || {
            let handle = named_mutex_try_acquire(&holder_name, Duration::from_secs(5))
                .expect("holder: create should succeed")
                .expect("holder: should acquire the free mutex");
            held_tx.send(()).unwrap();
            release_rx.recv().ok();
            named_mutex_release(handle, true);
        });

        held_rx.recv().expect("holder should signal ownership");

        // The mutex is genuinely held elsewhere: contention must be Ok(None)
        // (busy), never Err. Err is reserved for real create/wait failures.
        let contended = named_mutex_try_acquire(&name, Duration::from_millis(50))
            .expect("a contended acquire must not error");
        assert!(contended.is_none(), "expected None (busy), got a handle");

        release_tx.send(()).unwrap();
        holder.join().unwrap();

        // Once released, a fresh try must succeed (Ok(Some)).
        let reacquired = named_mutex_try_acquire(&name, Duration::from_secs(5))
            .expect("create should succeed")
            .expect("mutex should be free after the holder released it");
        named_mutex_release(reacquired, true);
    }
}
