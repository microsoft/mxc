// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Descendant-tracking Job Object for the learning-mode feature.
//!
//! # Why this exists
//!
//! ETW's `EVENT_FILTER_TYPE_PID` filter does not follow descendants
//! of the filtered process. A workload that spawns children
//! (`cargo build`, `npm run`, `cmd /c …`) escapes the ETW filter
//! and its denials never reach the consumer. The summary line
//! reports `childProcessesObserved` so the SDK can warn the user,
//! but the denials themselves are lost.
//!
//! This module is the first piece of the fix. It wraps the workload
//! in a Job Object with the breakaway-OK limit **unset**, which
//! means:
//!
//! - The kernel kills any descendant that tries to escape the job
//!   with `CREATE_BREAKAWAY_FROM_JOB`.
//! - Descendants of the workload are automatically members of the
//!   same job (kernel-enforced; no race window between spawn and
//!   assignment).
//! - The kernel posts a `JOB_OBJECT_MSG_NEW_PROCESS` notification
//!   to a registered I/O Completion Port (IOCP) every time a
//!   process joins the job. [`DescendantTrackingJob::subscribe_to_new_processes`]
//!   wires that IOCP up; the runner calls it with a callback that
//!   (Phase C) will ask the shim to extend the running ETW
//!   session's `EVENT_FILTER_TYPE_PID` list to cover the new PID.
//!
//! # Race window
//!
//! Between the kernel firing `JOB_OBJECT_MSG_NEW_PROCESS` and the
//! runner extending the ETW filter, the new descendant can run
//! unaudited code. In practice this window is small (typically
//! milliseconds) and is dominated by NT image-loader work
//! (`ntdll!LdrpInitializeProcess`, DLL loads) which the workload
//! cannot influence. Real applications do non-trivial setup
//! before their first audited filesystem / registry access, so
//! the window is usually empty.
//!
//! For workloads where this is unacceptable (e.g. a child that
//! reads a sensitive file in the first few syscalls), Phase D
//! will optionally suspend the new descendant from the
//! notification thread until the filter update lands. Not in
//! Phase B.
//!
//! # Lifetime / ownership
//!
//! The runner creates a `DescendantTrackingJob`, calls
//! [`DescendantTrackingJob::attach_root`] with the workload's
//! process handle before resuming the (suspended) workload, then
//! (optionally) calls [`DescendantTrackingJob::subscribe_to_new_processes`]
//! to start the IOCP listener. The job is dropped on the runner's
//! scope exit; drop joins the listener thread and closes the IOCP.
//! Once a process is assigned to a job the kernel keeps it there
//! for the process lifetime regardless of whether the job HANDLE
//! is still open in the creator — so dropping the wrapper does not
//! relax the restrictions on the running workload or its descendants.

use core::ffi::c_void;
use std::mem::size_of;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread::JoinHandle;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, NTSTATUS};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectAssociateCompletionPortInformation,
    SetInformationJobObject, JOBOBJECT_ASSOCIATE_COMPLETION_PORT,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::SystemServices::{
    JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO, JOB_OBJECT_MSG_EXIT_PROCESS, JOB_OBJECT_MSG_NEW_PROCESS,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_SUSPEND_RESUME};
use windows::Win32::System::IO::{
    CreateIoCompletionPort, GetQueuedCompletionStatus, PostQueuedCompletionStatus, OVERLAPPED,
};

use crate::session::SessionError;

/// Sentinel completion key used to wake the IOCP listener thread
/// on Drop. Chosen to be obviously not a real PID and not collide
/// with the job's own completion key.
const SHUTDOWN_KEY: usize = 0xDEAD_BEEF_DEAD_BEEFusize;

/// Completion key the kernel uses when posting job notifications.
/// The exact value doesn't matter; the kernel uses whatever we pass
/// in `JOBOBJECT_ASSOCIATE_COMPLETION_PORT.CompletionKey`.
const JOB_COMPLETION_KEY: usize = 0xC0DE_C0DE_C0DE_C0DEusize;

/// `HANDLE` newtype that's `Send`. The standard `HANDLE` wraps
/// `*mut c_void`, which Rust conservatively treats as non-Send.
/// IOCP handles are explicitly designed to be used from multiple
/// threads (that's the whole point of an IOCP), so it's safe to
/// move the bare handle value into the listener thread.
#[derive(Copy, Clone)]
struct SendHandle(HANDLE);
// SAFETY: see the type-level doc-comment.
unsafe impl Send for SendHandle {}

/// RAII wrapper around an anonymous Job Object used to scope the
/// learning-mode capture to a sandbox-tree (root workload +
/// descendants).
///
/// See the module-level docs for the design rationale.
pub struct DescendantTrackingJob {
    handle: HANDLE,
    root_pid: Option<u32>,
    listener: Option<ListenerState>,
}

/// State tracked alongside the optional IOCP listener thread. None
/// when [`subscribe_to_new_processes`] has not been called.
struct ListenerState {
    iocp: HANDLE,
    thread: Option<JoinHandle<()>>,
    stop_flag: Arc<AtomicBool>,
}

impl DescendantTrackingJob {
    /// Create a fresh, anonymous, unrestricted Job Object.
    ///
    /// The job has no limits set on construction; in particular,
    /// `JOB_OBJECT_LIMIT_BREAKAWAY_OK` is **unset** (the default),
    /// which is exactly what we want — descendants of a process in
    /// the job cannot escape via `CREATE_BREAKAWAY_FROM_JOB`.
    pub fn new() -> Result<Self, SessionError> {
        // SAFETY: CreateJobObjectW with NULL security attributes and
        // NULL name returns an unnamed job HANDLE owned by the caller.
        let handle = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
            .map_err(|e| SessionError::JobObject(format!("CreateJobObjectW: {e}")))?;
        Ok(Self {
            handle,
            root_pid: None,
            listener: None,
        })
    }

    /// Assign the root workload to the job.
    ///
    /// Must be called while the workload is suspended (the
    /// captureDenials flow already spawns `CREATE_SUSPENDED` so this
    /// happens before any user code runs). Once assigned, every
    /// descendant the workload spawns is automatically a member of
    /// the same job.
    ///
    /// `pid` is the workload's PID; the IOCP listener uses it to
    /// distinguish the root's `JOB_OBJECT_MSG_NEW_PROCESS`
    /// notification (which the caller does not care about) from
    /// genuine descendants (which the caller does).
    ///
    /// # Safety
    ///
    /// `process_handle` must be a valid Win32 process handle with
    /// `PROCESS_SET_QUOTA | PROCESS_TERMINATE` access (the standard
    /// `PROCESS_INFORMATION.hProcess` from `CreateProcess*` already
    /// has both).
    pub fn attach_root(&mut self, process_handle: HANDLE, pid: u32) -> Result<(), SessionError> {
        // SAFETY: caller guarantees `process_handle` is a valid
        // handle with the required access mask. `self.handle` was
        // produced by `CreateJobObjectW`.
        unsafe { AssignProcessToJobObject(self.handle, process_handle) }
            .map_err(|e| SessionError::JobObject(format!("AssignProcessToJobObject: {e}")))?;
        self.root_pid = Some(pid);
        Ok(())
    }

    /// Returns the underlying job HANDLE. Used by Phase D / Phase C
    /// consumers if they need to inspect job state directly.
    #[allow(dead_code)]
    pub fn handle(&self) -> HANDLE {
        self.handle
    }

    /// Subscribe to descendant-spawn notifications.
    ///
    /// Creates an I/O Completion Port, associates it with the job,
    /// and spawns a background thread that loops on
    /// `GetQueuedCompletionStatus` and invokes `on_new_pid(pid)`
    /// for every `JOB_OBJECT_MSG_NEW_PROCESS` notification **except**
    /// the one for the root workload (which the caller already
    /// knows about).
    ///
    /// Must be called after [`attach_root`] (so the root PID is
    /// known and can be filtered out). Calling twice returns
    /// `SessionError::JobObject` — the listener is single-shot per
    /// job lifetime.
    ///
    /// The thread exits cleanly when the job hits
    /// `JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO` (last process in the
    /// job exited) or when the `DescendantTrackingJob` is dropped
    /// (Drop posts a sentinel completion key that breaks the loop).
    pub fn subscribe_to_new_processes<F>(&mut self, on_new_pid: F) -> Result<(), SessionError>
    where
        F: Fn(u32) + Send + 'static,
    {
        if self.listener.is_some() {
            return Err(SessionError::JobObject(
                "subscribe_to_new_processes called twice on the same job".into(),
            ));
        }
        let root_pid = self.root_pid.ok_or_else(|| {
            SessionError::JobObject("subscribe_to_new_processes called before attach_root".into())
        })?;

        // 1. Create the IOCP. ExistingCompletionPort=None,
        //    NumberOfConcurrentThreads=1 (single-listener worker).
        // SAFETY: standard Win32 IOCP creation.
        let iocp = unsafe { CreateIoCompletionPort(HANDLE(-1isize as *mut c_void), None, 0, 1) }
            .map_err(|e| SessionError::JobObject(format!("CreateIoCompletionPort: {e}")))?;

        // 2. Associate the IOCP with the job. The kernel will now
        //    post JOB_OBJECT_MSG_* notifications to this IOCP.
        let assoc = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
            CompletionKey: JOB_COMPLETION_KEY as *mut c_void,
            CompletionPort: iocp,
        };
        // SAFETY: `self.handle` is a valid job. `assoc` lives long
        // enough for the syscall. SetInformationJobObject copies
        // the struct into kernel state.
        unsafe {
            SetInformationJobObject(
                self.handle,
                JobObjectAssociateCompletionPortInformation,
                &assoc as *const _ as *const c_void,
                size_of::<JOBOBJECT_ASSOCIATE_COMPLETION_PORT>() as u32,
            )
        }
        .map_err(|e| {
            // Best-effort: close the IOCP we just created since we
            // won't be using it.
            unsafe {
                let _ = CloseHandle(iocp);
            }
            SessionError::JobObject(format!(
                "SetInformationJobObject(JobObjectAssociateCompletionPortInformation): {e}"
            ))
        })?;

        // 3. Spawn the worker thread. It owns `on_new_pid`.
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_thread = Arc::clone(&stop_flag);
        let iocp_for_thread = SendHandle(iocp);

        let thread = std::thread::Builder::new()
            .name("descendant-tracking-iocp".into())
            .spawn(move || {
                listener_loop(iocp_for_thread, root_pid, stop_flag_thread, on_new_pid);
            })
            .map_err(|e| SessionError::JobObject(format!("spawn listener thread: {e}")))?;

        self.listener = Some(ListenerState {
            iocp,
            thread: Some(thread),
            stop_flag,
        });
        Ok(())
    }
}

/// Body of the IOCP listener thread. Loops on
/// `GetQueuedCompletionStatus`, dispatches `JOB_OBJECT_MSG_NEW_PROCESS`
/// to the caller's callback (filtering out the root PID), and exits
/// on `JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO` or the shutdown sentinel.
fn listener_loop<F>(iocp_send: SendHandle, root_pid: u32, stop_flag: Arc<AtomicBool>, on_new_pid: F)
where
    F: Fn(u32) + Send + 'static,
{
    let iocp = iocp_send.0;
    loop {
        if stop_flag.load(Ordering::SeqCst) {
            return;
        }

        let mut number_of_bytes: u32 = 0;
        let mut completion_key: usize = 0;
        let mut overlapped: *mut OVERLAPPED = std::ptr::null_mut();

        // SAFETY: standard IOCP wait. INFINITE blocks until a packet
        // arrives or the IOCP is closed; on close, the call returns
        // an error which we treat as exit-loop.
        let ok = unsafe {
            GetQueuedCompletionStatus(
                iocp,
                &mut number_of_bytes,
                &mut completion_key,
                &mut overlapped,
                u32::MAX, // INFINITE
            )
        };
        if ok.is_err() {
            // IOCP closed or other terminal error — listener exits.
            return;
        }

        if completion_key == SHUTDOWN_KEY {
            return;
        }
        if completion_key != JOB_COMPLETION_KEY {
            // Spurious packet; ignore.
            continue;
        }

        // For job-associated notifications, `number_of_bytes` is the
        // message ID (JOB_OBJECT_MSG_*) and the `overlapped` pointer
        // holds the PID of the process that triggered it (cast).
        let msg_id = number_of_bytes;
        let pid = overlapped as usize as u32;

        match msg_id {
            JOB_OBJECT_MSG_NEW_PROCESS => {
                if pid != root_pid {
                    // Phase D: suspend the descendant before calling
                    // the user callback (which extends the ETW filter
                    // via the shim RPC), then resume. This tightens
                    // the race window between "process joins job" and
                    // "ETW filter covers the process" — code that
                    // would otherwise run unaudited during the
                    // ~milliseconds the RPC takes is held at zero
                    // instructions executed.
                    //
                    // The kernel posts JOB_OBJECT_MSG_NEW_PROCESS as
                    // the process is being created; there's still a
                    // tiny window before user-mode wakes up to handle
                    // it, during which the process can run a few
                    // syscalls (NT image loader work, before any
                    // user-mode code). Eliminating that final window
                    // requires either a kernel driver or DLL
                    // injection — out of scope.
                    let guard = SuspendedDescendant::open(pid);
                    on_new_pid(pid);
                    drop(guard); // Resume + close handle, in this order.
                }
            }
            JOB_OBJECT_MSG_EXIT_PROCESS => {
                // No-op for Phase B. Phase E may want to remove the
                // PID from the ETW filter or fold the descendant's
                // denials into a "child denials" bucket.
            }
            JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO => {
                // Workload tree fully exited. Listener exits.
                return;
            }
            _ => {
                // Other JOB_OBJECT_MSG_* (memory limit, time limit,
                // etc.) — uninteresting for descendant tracking.
            }
        }
    }
}

impl Drop for DescendantTrackingJob {
    fn drop(&mut self) {
        // 1. Tear down the listener thread (if any).
        if let Some(mut listener) = self.listener.take() {
            listener.stop_flag.store(true, Ordering::SeqCst);
            // Post a sentinel completion so the thread wakes from
            // its INFINITE wait and notices the flag. The packet is
            // discarded by the worker on receipt.
            // SAFETY: `listener.iocp` is a valid IOCP HANDLE we own.
            unsafe {
                let _ = PostQueuedCompletionStatus(listener.iocp, 0, SHUTDOWN_KEY, None);
            }
            if let Some(thread) = listener.thread.take() {
                let _ = thread.join();
            }
            // SAFETY: IOCP HANDLE we created in
            // `subscribe_to_new_processes`. Worker thread has joined.
            unsafe {
                let _ = CloseHandle(listener.iocp);
            }
        }

        // 2. Close the job HANDLE. The kernel keeps the job alive as
        //    long as a process is still assigned, so closing here
        //    does not relax restrictions on running workloads.
        // SAFETY: `self.handle` was produced by `CreateJobObjectW`
        // and has not been closed elsewhere.
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

// SAFETY: a Win32 HANDLE is just a kernel-object pointer; sharing it
// across threads is safe as long as the Win32 APIs that consume it
// are themselves thread-safe (they are, for the calls we make).
unsafe impl Send for DescendantTrackingJob {}
unsafe impl Sync for DescendantTrackingJob {}

// -----------------------------------------------------------------------
// Phase D: NtSuspendProcess / NtResumeProcess
// -----------------------------------------------------------------------
//
// We need to freeze the descendant at zero instructions executed during
// the small window the shim takes to extend the ETW filter. The cleanest
// Win32 primitive is the pair `NtSuspendProcess` /
// `NtResumeProcess` in ntdll: they take a process HANDLE and
// suspend/resume **all** of its threads atomically. The pair is not
// declared in any official public header (it's a hidden NT API used by
// debuggers and process freezers like Process Explorer), but it has been
// stable since Vista and is documented widely enough.
//
// Loaded once via `GetProcAddress` and cached for the listener thread's
// lifetime.

type NtSuspendProcessFn = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
type NtResumeProcessFn = unsafe extern "system" fn(HANDLE) -> NTSTATUS;

struct NtProcessControl {
    suspend: NtSuspendProcessFn,
    resume: NtResumeProcessFn,
}

// SAFETY: function pointers into ntdll.dll are stable for the process
// lifetime; ntdll is always loaded.
unsafe impl Send for NtProcessControl {}
unsafe impl Sync for NtProcessControl {}

static NT_PROCESS_CONTROL: OnceLock<Option<NtProcessControl>> = OnceLock::new();

/// Resolves `NtSuspendProcess` + `NtResumeProcess` from ntdll. Returns
/// `None` if either symbol cannot be found (extremely rare; would mean
/// a very stripped-down NT kernel).
fn nt_process_control() -> Option<&'static NtProcessControl> {
    NT_PROCESS_CONTROL
        .get_or_init(|| {
            // SAFETY: ntdll.dll is always loaded in every Windows process.
            unsafe {
                let module = GetModuleHandleW(windows::core::w!("ntdll.dll")).ok()?;
                let suspend_ptr = GetProcAddress(module, windows::core::s!("NtSuspendProcess"))?;
                let resume_ptr = GetProcAddress(module, windows::core::s!("NtResumeProcess"))?;
                Some(NtProcessControl {
                    suspend: std::mem::transmute::<
                        unsafe extern "system" fn() -> isize,
                        NtSuspendProcessFn,
                    >(suspend_ptr),
                    resume: std::mem::transmute::<
                        unsafe extern "system" fn() -> isize,
                        NtResumeProcessFn,
                    >(resume_ptr),
                })
            }
        })
        .as_ref()
}

/// RAII guard that holds a descendant process suspended for the lifetime
/// of the guard. `Drop` resumes the process and closes the handle.
///
/// If `open` fails (process already exited, access denied, etc.), the
/// guard is still constructed but holds nothing — `Drop` is a no-op.
/// This keeps the listener's hot path simple: it just constructs the
/// guard, calls the user callback (extend the ETW filter), and lets
/// `Drop` clean up. A failed-to-suspend descendant degrades the
/// race-window mitigation but doesn't break the rest of the flow.
struct SuspendedDescendant {
    handle: Option<HANDLE>,
}

impl SuspendedDescendant {
    fn open(pid: u32) -> Self {
        let Some(ctrl) = nt_process_control() else {
            // ntdll lookup failed; cannot suspend. Degrade silently —
            // the IOCP callback still runs, just without the
            // race-window mitigation.
            return Self { handle: None };
        };

        // SAFETY: standard OpenProcess. Bare PROCESS_SUSPEND_RESUME
        // access is the minimum the Nt suspend/resume pair needs.
        let handle = match unsafe { OpenProcess(PROCESS_SUSPEND_RESUME, false, pid) } {
            Ok(h) => h,
            Err(e) => {
                eprintln!(
                    "[learning_mode_windows] suspend race-mitigation: OpenProcess({pid}) \
                     failed: {e}; descendant may run unaudited briefly"
                );
                return Self { handle: None };
            }
        };

        // SAFETY: `handle` is a valid process handle with
        // PROCESS_SUSPEND_RESUME access. `ctrl.suspend` is the
        // resolved ntdll function pointer.
        let status = unsafe { (ctrl.suspend)(handle) };
        if status.0 < 0 {
            eprintln!(
                "[learning_mode_windows] suspend race-mitigation: NtSuspendProcess({pid}) \
                 returned NTSTATUS {:#X}; descendant may run unaudited briefly",
                status.0
            );
            // Close the handle — we won't be resuming since the
            // suspend failed.
            unsafe {
                let _ = CloseHandle(handle);
            }
            return Self { handle: None };
        }

        Self {
            handle: Some(handle),
        }
    }
}

impl Drop for SuspendedDescendant {
    fn drop(&mut self) {
        let Some(handle) = self.handle.take() else {
            return;
        };
        // SAFETY: handle is owned by this guard and only released here.
        // `ctrl.resume` is valid; we already verified ntdll on the
        // suspend path.
        if let Some(ctrl) = nt_process_control() {
            unsafe {
                let status = (ctrl.resume)(handle);
                if status.0 < 0 {
                    eprintln!(
                        "[learning_mode_windows] suspend race-mitigation: NtResumeProcess \
                         returned NTSTATUS {:#X}; descendant may be stuck suspended",
                        status.0
                    );
                }
            }
        }
        unsafe {
            let _ = CloseHandle(handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn create_drop_is_clean() {
        let job = DescendantTrackingJob::new().expect("create");
        assert!(!job.handle().is_invalid());
        drop(job);
    }

    #[test]
    fn subscribe_requires_attach_root_first() {
        let mut job = DescendantTrackingJob::new().expect("create");
        let err = job
            .subscribe_to_new_processes(|_pid| {})
            .expect_err("should fail without attach_root");
        let msg = format!("{err}");
        assert!(msg.contains("attach_root"), "got: {msg}");
    }

    #[test]
    fn subscribe_then_drop_joins_listener_cleanly() {
        // Smoke test: attach the current process to a fresh job
        // (effectively a no-op for descendants since we don't spawn
        // any), subscribe with a no-op callback, then drop. The
        // Drop impl must signal + join the listener thread without
        // deadlocking.
        use windows::Win32::System::Threading::GetCurrentProcess;
        let mut job = DescendantTrackingJob::new().expect("create");
        // SAFETY: GetCurrentProcess returns a pseudo-handle, safe
        // for AssignProcessToJobObject. The test process is now
        // job-managed for the duration of the test — that's fine
        // because dropping the job only closes our handle; the
        // kernel keeps the job alive as long as the process
        // remains assigned, and the process is unaffected.
        let cur_pid = std::process::id();
        let cur_handle = unsafe { GetCurrentProcess() };
        // attach_root may fail if the test process is already in a
        // job (e.g. running under cargo test harness that uses
        // jobs). In that case skip the subscribe test.
        if job.attach_root(cur_handle, cur_pid).is_err() {
            return;
        }
        let _received: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let recv = Arc::clone(&_received);
        job.subscribe_to_new_processes(move |pid| {
            recv.lock().unwrap().push(pid);
        })
        .expect("subscribe");
        drop(job);
    }
}
