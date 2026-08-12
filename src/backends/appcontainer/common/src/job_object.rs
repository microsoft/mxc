// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! RAII wrapper around a Windows Job Object used to apply UI restrictions
//! (`JOB_OBJECT_UILIMIT_*`) to a child process and any descendants it creates,
//! plus the Windows-specific encoder that maps a platform-agnostic
//! [`wxc_common::ui_policy::EffectiveUiRestrictions`] to the corresponding bitmask.
//!
//! The wrapper owns the underlying job HANDLE and closes it on drop. Jobs are
//! configured with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, so an abandoned
//! sandbox cannot outlive the process that owns its enforcement state.

use core::ffi::c_void;
use std::collections::HashMap;
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use learning_mode_core::ProcessLifetime;
use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectAssociateCompletionPortInformation,
    JobObjectBasicUIRestrictions, JobObjectExtendedLimitInformation, SetInformationJobObject,
    TerminateJobObject, JOBOBJECT_ASSOCIATE_COMPLETION_PORT, JOBOBJECT_BASIC_UI_RESTRICTIONS,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_UILIMIT,
    JOB_OBJECT_UILIMIT_DESKTOP, JOB_OBJECT_UILIMIT_DISPLAYSETTINGS, JOB_OBJECT_UILIMIT_EXITWINDOWS,
    JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES, JOB_OBJECT_UILIMIT_READCLIPBOARD,
    JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
};
use windows::Win32::System::SystemServices::{
    JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS, JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO,
    JOB_OBJECT_MSG_EXIT_PROCESS, JOB_OBJECT_MSG_NEW_PROCESS, JOB_OBJECT_UILIMIT_IME,
};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
};
use windows::Win32::System::IO::{
    CreateIoCompletionPort, GetQueuedCompletionStatus, PostQueuedCompletionStatus, OVERLAPPED,
};
use windows_core::PCWSTR;

use wxc_common::error::WxcError;
use wxc_common::ui_policy::EffectiveUiRestrictions;

/// Helper for loading `RtlGetVersion` from `ntdll.dll` to get the true
/// (unshimmed) OS version. `GetVersionExW` lies on post-8.1 builds due
/// to the compatibility shim.
mod version_detect {
    use std::mem::size_of;

    use windows::Win32::Foundation::NTSTATUS;
    use windows::Win32::System::SystemInformation::OSVERSIONINFOW;

    type RtlGetVersionFn = unsafe extern "system" fn(version_info: *mut OSVERSIONINFOW) -> NTSTATUS;

    /// Returns the real OS build number by calling `RtlGetVersion` from
    /// `ntdll.dll`. Falls back to `u32::MAX` if the symbol cannot be
    /// resolved or the call fails. `u32::MAX` is deliberately treated as
    /// "modern" by capability gating so an indeterminate probe fails secure
    /// (the more restrictive flag is kept rather than silently dropped).
    pub(super) fn get_os_build_number() -> u32 {
        // SAFETY: ntdll.dll is always loaded in every Windows process.
        // `GetModuleHandleW` with "ntdll.dll" returns the existing module
        // handle without incrementing a reference count.
        unsafe {
            let module = windows::Win32::System::LibraryLoader::GetModuleHandleW(
                windows::core::w!("ntdll.dll"),
            );
            let module = match module {
                Ok(h) => h,
                Err(_) => return u32::MAX,
            };
            let proc = windows::Win32::System::LibraryLoader::GetProcAddress(
                module,
                windows::core::s!("RtlGetVersion"),
            );
            let proc = match proc {
                Some(p) => p,
                None => return u32::MAX,
            };
            let rtl_get_version: RtlGetVersionFn = std::mem::transmute(proc);
            let mut info = OSVERSIONINFOW {
                dwOSVersionInfoSize: size_of::<OSVERSIONINFOW>() as u32,
                ..Default::default()
            };
            let status = rtl_get_version(&mut info);
            if status.is_ok() {
                info.dwBuildNumber
            } else {
                u32::MAX
            }
        }
    }
}

/// `JOB_OBJECT_UILIMIT_INJECTION` from `winnt.h`. The `windows` crate
/// does not emit this constant; if a future release adds it, the local
/// definition can be removed and the import above extended.
const JOB_OBJECT_UILIMIT_INJECTION: u32 = 0x0000_0200;
const TRACKER_STOP_MESSAGE: u32 = u32::MAX;
const MAX_TRACKED_PROCESSES: usize = 4096;

/// Every `JOB_OBJECT_UILIMIT_*` bit this module's encoder
/// ([`to_job_object_uilimit_mask`]) can emit. Acts as the universe for the
/// capability intersection performed by [`supported_ui_limit_mask`]. Must
/// stay in sync with the encoder — the `encoder_known_bit_positions` test
/// pins the all-restrictions mask to this value.
const ALL_DEFINED_UI_LIMITS: u32 = 0x0000_03FF;

/// Minimum OS build that supports `JOB_OBJECT_UILIMIT_IME` (0x100).
/// This flag is empirically accepted on Windows 11 22H2 (22621) and later
/// — confirmed on 22631 (23H2) — but rejected with `ERROR_INVALID_PARAMETER`
/// on Windows Server 2022 (20348). Its exact introduction build between 20348
/// and 22631 is unconfirmed, so it is gated at the 22H2 boundary: builds below
/// it conservatively omit the flag (UI-limit support is monotonic — once a
/// build accepts the flag, every later build does too — so this never hands
/// the kernel a flag it would reject).
const MIN_BUILD_FOR_IME_LIMIT: u32 = 22621;

/// Minimum OS build that supports `JOB_OBJECT_UILIMIT_INJECTION` (0x200).
/// Windows 11 26100 (24H2) introduced this flag; earlier builds reject it
/// with `ERROR_INVALID_PARAMETER`, so it is excluded from the supported
/// UI-limit set on those builds.
const MIN_BUILD_FOR_INJECTION_LIMIT: u32 = 26100;

/// Cached OS build number (queried once via `RtlGetVersion`).
static OS_BUILD_NUMBER: OnceLock<u32> = OnceLock::new();

/// Returns the current OS build number, caching the result for the process
/// lifetime. Returns `u32::MAX` when the build cannot be determined, which
/// capability gating treats as "modern" so detection failures fail secure.
pub fn os_build_number() -> u32 {
    *OS_BUILD_NUMBER.get_or_init(version_detect::get_os_build_number)
}

/// Returns `true` when the current OS build can enforce
/// `JOB_OBJECT_UILIMIT_INJECTION` (input-injection blocking). Introduced in
/// build 26100; an unknown build is reported as supported (fail secure).
pub fn input_injection_blocking_supported() -> bool {
    os_build_number() >= MIN_BUILD_FOR_INJECTION_LIMIT
}

/// Pure capability map: given an OS build number, returns the subset of
/// encoder-defined `JOB_OBJECT_UILIMIT_*` flags the kernel can enforce on
/// that build. `JOB_OBJECT_UILIMIT_IME` and `JOB_OBJECT_UILIMIT_INJECTION`
/// are build-gated; all other flags are universally supported.
fn supported_ui_limit_mask_for_build(build: u32) -> u32 {
    let mut supported = ALL_DEFINED_UI_LIMITS;
    if build < MIN_BUILD_FOR_IME_LIMIT {
        supported &= !JOB_OBJECT_UILIMIT_IME;
    }
    if build < MIN_BUILD_FOR_INJECTION_LIMIT {
        supported &= !JOB_OBJECT_UILIMIT_INJECTION;
    }
    supported
}

#[inline(always)]
fn has_ui_limit(mask: u32, flag: u32) -> bool {
    (mask & flag) == flag
}

fn supported_ui_restrictions_for_build(build: u32) -> EffectiveUiRestrictions {
    let supported = supported_ui_limit_mask_for_build(build);
    EffectiveUiRestrictions {
        block_clipboard_read: has_ui_limit(supported, JOB_OBJECT_UILIMIT_READCLIPBOARD.0),
        block_clipboard_write: has_ui_limit(supported, JOB_OBJECT_UILIMIT_WRITECLIPBOARD.0),
        block_input_injection: has_ui_limit(supported, JOB_OBJECT_UILIMIT_INJECTION),
        block_input_method_changes: has_ui_limit(supported, JOB_OBJECT_UILIMIT_IME),
        block_external_ui_objects: has_ui_limit(supported, JOB_OBJECT_UILIMIT_HANDLES.0),
        block_global_ui_namespace: has_ui_limit(supported, JOB_OBJECT_UILIMIT_GLOBALATOMS.0),
        block_desktop_switching: has_ui_limit(supported, JOB_OBJECT_UILIMIT_DESKTOP.0),
        block_logoff_or_shutdown: has_ui_limit(supported, JOB_OBJECT_UILIMIT_EXITWINDOWS.0),
        block_system_parameter_changes: has_ui_limit(
            supported,
            JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS.0,
        ),
        block_display_settings_changes: has_ui_limit(
            supported,
            JOB_OBJECT_UILIMIT_DISPLAYSETTINGS.0,
        ),
    }
}

/// Returns the subset of encoder-defined `JOB_OBJECT_UILIMIT_*` flags the
/// current OS build can enforce. The effective restriction mask applied to a
/// job is always `requested & supported`, so the kernel is never handed a
/// flag it would reject.
pub fn supported_ui_limit_mask() -> u32 {
    supported_ui_limit_mask_for_build(os_build_number())
}

/// Returns the platform-agnostic UI restrictions the current OS build can
/// enforce. Reported to callers via `wxc-exec --probe`.
pub fn supported_ui_restrictions() -> EffectiveUiRestrictions {
    supported_ui_restrictions_for_build(os_build_number())
}

/// Encode platform-agnostic UI restrictions as the `JOB_OBJECT_UILIMIT_*`
/// bitmask consumed by `SetInformationJobObject(JobObjectBasicUIRestrictions)`
/// and by the BaseContainer SandboxSpec `ui_restrictions` field.
pub fn to_job_object_uilimit_mask(r: &EffectiveUiRestrictions) -> u32 {
    let mut mask: u32 = 0;
    if r.block_external_ui_objects {
        mask |= JOB_OBJECT_UILIMIT_HANDLES.0;
    }
    if r.block_clipboard_read {
        mask |= JOB_OBJECT_UILIMIT_READCLIPBOARD.0;
    }
    if r.block_clipboard_write {
        mask |= JOB_OBJECT_UILIMIT_WRITECLIPBOARD.0;
    }
    if r.block_system_parameter_changes {
        mask |= JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS.0;
    }
    if r.block_display_settings_changes {
        mask |= JOB_OBJECT_UILIMIT_DISPLAYSETTINGS.0;
    }
    if r.block_global_ui_namespace {
        mask |= JOB_OBJECT_UILIMIT_GLOBALATOMS.0;
    }
    if r.block_desktop_switching {
        mask |= JOB_OBJECT_UILIMIT_DESKTOP.0;
    }
    if r.block_logoff_or_shutdown {
        mask |= JOB_OBJECT_UILIMIT_EXITWINDOWS.0;
    }
    if r.block_input_method_changes {
        mask |= JOB_OBJECT_UILIMIT_IME;
    }
    if r.block_input_injection {
        mask |= JOB_OBJECT_UILIMIT_INJECTION;
    }
    mask
}

/// RAII wrapper for an unnamed Windows Job Object configured for UI
/// restrictions. The job HANDLE is closed when this value is dropped.
pub struct UiJobObject {
    handle: HANDLE,
    tracker: Option<JobProcessTracker>,
}

impl UiJobObject {
    /// Creates an unnamed Job Object owned by the current process.
    pub fn new() -> Result<Self, WxcError> {
        Self::new_inner(false)
    }

    /// Creates a Job Object that records exact process lifetimes.
    ///
    /// The WPR fallback uses these kernel job notifications to scope a
    /// host-wide ETL trace to the sandbox process tree without trusting a
    /// caller-supplied PID list.
    pub fn new_tracked() -> Result<Self, WxcError> {
        Self::new_inner(true)
    }

    fn new_inner(track_processes: bool) -> Result<Self, WxcError> {
        // SAFETY: CreateJobObjectW with NULL security attributes and NULL name
        // is documented to either return a valid HANDLE or an error.
        let handle = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
            .map_err(|e| WxcError::Process(format!("CreateJobObjectW: {e}")))?;
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if let Err(error) = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &limits as *const _ as *const c_void,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } {
            unsafe {
                let _ = CloseHandle(handle);
            }
            return Err(WxcError::Process(format!(
                "SetInformationJobObject(KILL_ON_JOB_CLOSE): {error}"
            )));
        }
        let tracker = if track_processes {
            match JobProcessTracker::new(handle) {
                Ok(tracker) => Some(tracker),
                Err(error) => {
                    unsafe {
                        let _ = CloseHandle(handle);
                    }
                    return Err(error);
                }
            }
        } else {
            None
        };
        Ok(Self { handle, tracker })
    }

    /// Applies the given UI restrictions via `JobObjectBasicUIRestrictions`.
    /// Passing `EffectiveUiRestrictions::default()` clears all UI restrictions
    /// and is a valid no-op call.
    ///
    /// The mask actually applied is `requested & supported_ui_limit_mask()`:
    /// flags the current OS build cannot enforce (e.g.
    /// `JOB_OBJECT_UILIMIT_INJECTION` on builds older than 26100) are dropped
    /// so the call never fails with `ERROR_INVALID_PARAMETER`. Which flags a
    /// host can enforce is reported by `wxc-exec --probe`.
    pub fn set_ui_limits(&self, restrictions: &EffectiveUiRestrictions) -> Result<(), WxcError> {
        let mask = to_job_object_uilimit_mask(restrictions) & supported_ui_limit_mask();

        let info = JOBOBJECT_BASIC_UI_RESTRICTIONS {
            UIRestrictionsClass: JOB_OBJECT_UILIMIT(mask),
        };
        // SAFETY: `info` is a valid, fully-initialized struct living on the
        // stack for the duration of the call. The size matches the struct
        // type that JobObjectBasicUIRestrictions expects.
        unsafe {
            SetInformationJobObject(
                self.handle,
                JobObjectBasicUIRestrictions,
                &info as *const _ as *const c_void,
                size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
            )
        }
        .map_err(|e| WxcError::Process(format!("SetInformationJobObject(UI): {e}")))
    }

    /// Assigns the given process handle to this job. The process and any
    /// future descendants will inherit the job's UI restrictions.
    pub fn assign_process(&self, process_handle: HANDLE) -> Result<(), WxcError> {
        // SAFETY: Both handles must be valid for the duration of the call;
        // this is the caller's responsibility for `process_handle`.
        unsafe { AssignProcessToJobObject(self.handle, process_handle) }
            .map_err(|e| WxcError::Process(format!("AssignProcessToJobObject: {e}")))
    }

    /// Terminate every process currently assigned to this job (the sandboxed
    /// child and all of its descendants) with the given exit code. Used to
    /// tree-kill a running sandbox. Best-effort: errors are ignored since the
    /// processes may already have exited.
    pub fn terminate(&self, exit_code: u32) {
        // SAFETY: `self.handle` is a valid job handle owned by this struct.
        unsafe {
            let _ = TerminateJobObject(self.handle, exit_code);
        }
    }

    /// Stops process tracking and returns all completed process lifetimes.
    ///
    /// Call this only after the job has been terminated and the root process
    /// reaped, so all queued exit notifications precede the tracker stop
    /// marker.
    pub fn finish_process_tracking(&mut self) -> Result<Vec<ProcessLifetime>, WxcError> {
        self.tracker
            .take()
            .ok_or_else(|| WxcError::Process("job process tracking is not enabled".to_string()))?
            .finish()
    }
}

impl Drop for UiJobObject {
    fn drop(&mut self) {
        self.tracker.take();
        if !self.handle.is_invalid() {
            // SAFETY: `self.handle` was produced by CreateJobObjectW and has
            // not been closed elsewhere — `UiJobObject` owns it.
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

struct TrackedProcess {
    handle: OwnedHandle,
    start_filetime: u64,
}

struct ProcessTrackerState {
    active: HashMap<u32, TrackedProcess>,
    completed: Vec<ProcessLifetime>,
    active_process_zero: bool,
    error: Option<String>,
}

impl ProcessTrackerState {
    fn new() -> Self {
        Self {
            active: HashMap::new(),
            completed: Vec::new(),
            active_process_zero: false,
            error: None,
        }
    }

    fn fail(&mut self, message: impl Into<String>) {
        if self.error.is_none() {
            self.error = Some(message.into());
        }
    }

    fn process_started(&mut self, pid: u32) {
        self.active_process_zero = false;
        if self.active.len() + self.completed.len() >= MAX_TRACKED_PROCESSES {
            self.fail(format!(
                "sandbox job exceeded the {MAX_TRACKED_PROCESSES}-process tracking limit"
            ));
            return;
        }
        if self.active.contains_key(&pid) {
            self.fail(format!(
                "sandbox job reported duplicate process start for PID {pid}"
            ));
            return;
        }
        let handle = match unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                false,
                pid,
            )
        } {
            Ok(handle) => handle,
            Err(error) => {
                self.fail(format!(
                    "failed to open job process {pid} for lifetime tracking: {error}"
                ));
                return;
            }
        };
        match process_times(handle) {
            Ok((start_filetime, _)) => {
                let handle = unsafe { OwnedHandle::from_raw_handle(handle.0) };
                self.active.insert(
                    pid,
                    TrackedProcess {
                        handle,
                        start_filetime,
                    },
                );
            }
            Err(error) => {
                unsafe {
                    let _ = CloseHandle(handle);
                }
                self.fail(format!(
                    "failed to read creation time for job process {pid}: {error}"
                ));
            }
        }
    }

    fn process_exited(&mut self, pid: u32) {
        let Some(process) = self.active.remove(&pid) else {
            if self.completed.iter().any(|lifetime| lifetime.pid == pid) {
                return;
            }
            self.fail(format!(
                "sandbox job reported process exit without a tracked start for PID {pid}"
            ));
            return;
        };
        let times = process_times(HANDLE(process.handle.as_raw_handle()));
        match times {
            Ok((_, end_filetime)) if end_filetime >= process.start_filetime => {
                self.completed.push(ProcessLifetime {
                    pid,
                    start_filetime: process.start_filetime,
                    end_filetime,
                });
            }
            Ok((_, end_filetime)) => self.fail(format!(
                "job process {pid} exited before its recorded creation time \
                         (start {}, end {end_filetime})",
                process.start_filetime
            )),
            Err(error) => self.fail(format!(
                "failed to read exit time for job process {pid}: {error}"
            )),
        }
    }

    fn all_processes_exited(&mut self) {
        self.active_process_zero = true;
        let pids = self.active.keys().copied().collect::<Vec<_>>();
        for pid in pids {
            self.process_exited(pid);
        }
    }
}

#[cfg(test)]
mod process_tracker_tests {
    use super::*;

    #[test]
    fn completed_processes_count_toward_tracking_limit() {
        let mut state = ProcessTrackerState::new();
        state.completed = vec![
            ProcessLifetime {
                pid: 1,
                start_filetime: 1,
                end_filetime: 2,
            };
            MAX_TRACKED_PROCESSES
        ];

        state.process_started(2);

        assert!(state.active.is_empty());
        assert!(state.error.as_deref().is_some_and(|error| {
            error.contains("exceeded") && error.contains(&MAX_TRACKED_PROCESSES.to_string())
        }));
    }
}

struct JobProcessTracker {
    completion_port: HANDLE,
    state: Arc<Mutex<ProcessTrackerState>>,
    worker: Option<JoinHandle<()>>,
}

impl JobProcessTracker {
    fn new(job: HANDLE) -> Result<Self, WxcError> {
        let completion_port = unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, None, 0, 1) }
            .map_err(|error| {
            WxcError::Process(format!("CreateIoCompletionPort(job tracker): {error}"))
        })?;
        let association = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
            CompletionKey: ptr::null_mut(),
            CompletionPort: completion_port,
        };
        if let Err(error) = unsafe {
            SetInformationJobObject(
                job,
                JobObjectAssociateCompletionPortInformation,
                &association as *const _ as *const c_void,
                size_of::<JOBOBJECT_ASSOCIATE_COMPLETION_PORT>() as u32,
            )
        } {
            unsafe {
                let _ = CloseHandle(completion_port);
            }
            return Err(WxcError::Process(format!(
                "SetInformationJobObject(completion port): {error}"
            )));
        }

        let state = Arc::new(Mutex::new(ProcessTrackerState::new()));
        let worker_state = Arc::clone(&state);
        let raw_port = completion_port.0 as usize;
        let worker = std::thread::spawn(move || {
            process_job_notifications(HANDLE(raw_port as *mut c_void), &worker_state);
        });
        Ok(Self {
            completion_port,
            state,
            worker: Some(worker),
        })
    }

    fn finish(mut self) -> Result<Vec<ProcessLifetime>, WxcError> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let state = self
                .state
                .lock()
                .map_err(|_| WxcError::Process("job tracker state was poisoned".to_string()))?;
            if (state.active_process_zero && state.active.is_empty()) || state.error.is_some() {
                break;
            }
            drop(state);
            if Instant::now() >= deadline {
                return Err(WxcError::Process(
                    "timed out waiting for the sandbox job to report zero active processes"
                        .to_string(),
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        self.stop_worker();
        let mut state = self
            .state
            .lock()
            .map_err(|_| WxcError::Process("job tracker state was poisoned".to_string()))?;
        if !state.active.is_empty() {
            return Err(WxcError::Process(format!(
                "job tracker stopped with {} process(es) still active",
                state.active.len()
            )));
        }
        if let Some(error) = state.error.take() {
            return Err(WxcError::Process(error));
        }
        Ok(std::mem::take(&mut state.completed))
    }

    fn stop_worker(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = unsafe {
                PostQueuedCompletionStatus(self.completion_port, TRACKER_STOP_MESSAGE, 0, None)
            };
            if worker.join().is_err() {
                if let Ok(mut state) = self.state.lock() {
                    state.fail("job process tracker thread panicked");
                }
            }
        }
    }
}

impl Drop for JobProcessTracker {
    fn drop(&mut self) {
        self.stop_worker();
        if !self.completion_port.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.completion_port);
            }
        }
    }
}

fn process_job_notifications(port: HANDLE, state: &Arc<Mutex<ProcessTrackerState>>) {
    loop {
        let mut message = 0u32;
        let mut completion_key = 0usize;
        let mut overlapped: *mut OVERLAPPED = ptr::null_mut();
        let result = unsafe {
            GetQueuedCompletionStatus(
                port,
                &mut message,
                &mut completion_key,
                &mut overlapped,
                u32::MAX,
            )
        };
        if let Err(error) = result {
            if let Ok(mut state) = state.lock() {
                state.fail(format!("job process tracker wait failed: {error}"));
            }
            return;
        }
        if message == TRACKER_STOP_MESSAGE {
            return;
        }
        let pid = overlapped as usize as u32;
        let Ok(mut state) = state.lock() else {
            return;
        };
        match message {
            JOB_OBJECT_MSG_NEW_PROCESS => state.process_started(pid),
            JOB_OBJECT_MSG_EXIT_PROCESS | JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS => {
                state.process_exited(pid);
            }
            JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO => state.all_processes_exited(),
            _ => {}
        }
    }
}

fn process_times(process: HANDLE) -> Result<(u64, u64), windows_core::Error> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) }?;
    Ok((filetime_to_u64(creation), filetime_to_u64(exit)))
}

fn filetime_to_u64(value: FILETIME) -> u64 {
    (u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::io::AsRawHandle;
    use std::process::Command;
    use std::time::{Duration, Instant};

    #[test]
    fn create_set_limits_drop() {
        let job = UiJobObject::new().expect("create");
        // Empty restrictions: should still succeed.
        job.set_ui_limits(&EffectiveUiRestrictions::default())
            .expect("set zero limits");
        // Apply a real restriction.
        job.set_ui_limits(&EffectiveUiRestrictions {
            block_global_ui_namespace: true,
            ..Default::default()
        })
        .expect("set global-namespace block");
        drop(job);
    }

    #[test]
    fn tracked_job_records_process_lifetime() {
        let mut job = UiJobObject::new_tracked().expect("create tracked job");
        let mut child = Command::new("cmd.exe")
            .args(["/C", "ping -n 999 127.0.0.1 >nul"])
            .spawn()
            .expect("spawn child");
        job.assign_process(HANDLE(child.as_raw_handle()))
            .expect("assign child");

        job.terminate(1);
        child.wait().expect("wait for terminated child");
        let lifetimes = job
            .finish_process_tracking()
            .expect("finish process tracking");

        assert_eq!(lifetimes.len(), 1);
        assert_eq!(lifetimes[0].pid, child.id());
        assert!(lifetimes[0].start_filetime > 0);
        assert!(lifetimes[0].end_filetime >= lifetimes[0].start_filetime);
    }

    #[test]
    fn dropping_job_terminates_assigned_process() {
        let job = UiJobObject::new().expect("create job");
        let mut child = Command::new("cmd.exe")
            .args(["/C", "ping -n 999 127.0.0.1 >nul"])
            .spawn()
            .expect("spawn child");
        job.assign_process(HANDLE(child.as_raw_handle()))
            .expect("assign child");

        drop(job);
        let deadline = Instant::now() + Duration::from_secs(10);
        while child.try_wait().expect("query child").is_none() {
            assert!(
                Instant::now() < deadline,
                "job-owned process survived job-handle close"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    #[test]
    fn encoder_known_bit_positions() {
        // Sanity-check that the encoder produces the documented winnt.h
        // bit positions. If the `windows` crate ever changes its
        // representation, this catches it.
        let r = EffectiveUiRestrictions {
            block_external_ui_objects: true,
            block_clipboard_read: true,
            block_clipboard_write: true,
            block_system_parameter_changes: true,
            block_display_settings_changes: true,
            block_global_ui_namespace: true,
            block_desktop_switching: true,
            block_logoff_or_shutdown: true,
            block_input_method_changes: true,
            block_input_injection: true,
        };
        assert_eq!(to_job_object_uilimit_mask(&r), 0x03FF);
    }

    #[test]
    fn encoder_empty() {
        assert_eq!(
            to_job_object_uilimit_mask(&EffectiveUiRestrictions::default()),
            0
        );
    }

    #[test]
    fn encoder_individual_flags() {
        assert_eq!(
            to_job_object_uilimit_mask(&EffectiveUiRestrictions {
                block_external_ui_objects: true,
                ..Default::default()
            }),
            0x0001
        );
        assert_eq!(
            to_job_object_uilimit_mask(&EffectiveUiRestrictions {
                block_input_injection: true,
                ..Default::default()
            }),
            0x0200
        );
        assert_eq!(
            to_job_object_uilimit_mask(&EffectiveUiRestrictions {
                block_input_method_changes: true,
                ..Default::default()
            }),
            0x0100
        );
    }

    #[test]
    fn set_ui_limits_with_injection_succeeds_on_any_build() {
        // Regardless of OS build, set_ui_limits must never fail due to the
        // injection flag — the capability intersection drops it on downlevel.
        let job = UiJobObject::new().expect("create");
        job.set_ui_limits(&EffectiveUiRestrictions {
            block_input_injection: true,
            ..Default::default()
        })
        .expect("should succeed on any build");
    }

    #[test]
    fn set_ui_limits_all_flags_succeeds_on_any_build() {
        // The full ui.disable=true mask must succeed on any OS build.
        let job = UiJobObject::new().expect("create");
        let restrictions = EffectiveUiRestrictions {
            block_external_ui_objects: true,
            block_clipboard_read: true,
            block_clipboard_write: true,
            block_system_parameter_changes: true,
            block_display_settings_changes: true,
            block_global_ui_namespace: true,
            block_desktop_switching: true,
            block_logoff_or_shutdown: true,
            block_input_method_changes: true,
            block_input_injection: true,
        };
        job.set_ui_limits(&restrictions).expect("should succeed");
    }

    #[test]
    fn supported_mask_strips_injection_on_downlevel() {
        // Pre-26100 builds cannot enforce input-injection blocking, so it is
        // excluded from the supported set; all other flags remain.
        let mask = supported_ui_limit_mask_for_build(22631);
        assert_eq!(mask & JOB_OBJECT_UILIMIT_INJECTION, 0);
        assert_eq!(mask, ALL_DEFINED_UI_LIMITS & !JOB_OBJECT_UILIMIT_INJECTION);
        assert_eq!(mask, 0x01FF);
    }

    #[test]
    fn supported_mask_strips_ime_on_pre_22h2() {
        // Builds older than 22621 (e.g. Server 2022 = 20348) reject the IME
        // flag, so it is excluded along with injection; the classic
        // JOB_OBJECT_UILIMIT_ALL (0xFF) set remains.
        let mask = supported_ui_limit_mask_for_build(20348);
        assert_eq!(mask & JOB_OBJECT_UILIMIT_IME, 0);
        assert_eq!(mask & JOB_OBJECT_UILIMIT_INJECTION, 0);
        assert_eq!(
            mask,
            ALL_DEFINED_UI_LIMITS & !JOB_OBJECT_UILIMIT_IME & !JOB_OBJECT_UILIMIT_INJECTION
        );
        assert_eq!(mask, 0x00FF);
    }

    #[test]
    fn supported_restrictions_match_downlevel_mask() {
        let restrictions = supported_ui_restrictions_for_build(20348);
        assert!(restrictions.block_clipboard_read);
        assert!(restrictions.block_clipboard_write);
        assert!(restrictions.block_external_ui_objects);
        assert!(restrictions.block_display_settings_changes);
        assert!(!restrictions.block_input_injection);
        assert!(!restrictions.block_input_method_changes);
    }

    #[test]
    fn supported_mask_keeps_ime_on_22h2() {
        // Build 22621 (22H2) and later support the IME flag.
        let mask = supported_ui_limit_mask_for_build(22621);
        assert_eq!(mask & JOB_OBJECT_UILIMIT_IME, JOB_OBJECT_UILIMIT_IME);
    }

    #[test]
    fn supported_mask_keeps_injection_on_uplevel() {
        // Build 26100 (24H2) and later support the injection flag.
        let mask = supported_ui_limit_mask_for_build(26100);
        assert_eq!(
            mask & JOB_OBJECT_UILIMIT_INJECTION,
            JOB_OBJECT_UILIMIT_INJECTION
        );
        assert_eq!(mask, ALL_DEFINED_UI_LIMITS);
        assert_eq!(mask, 0x03FF);
    }

    #[test]
    fn supported_mask_fails_secure_on_unknown_build() {
        // An undetermined build (u32::MAX sentinel) keeps the more restrictive
        // flag rather than silently dropping it.
        let mask = supported_ui_limit_mask_for_build(u32::MAX);
        assert_eq!(
            mask & JOB_OBJECT_UILIMIT_INJECTION,
            JOB_OBJECT_UILIMIT_INJECTION
        );
        assert!(
            input_injection_blocking_supported()
                || os_build_number() < MIN_BUILD_FOR_INJECTION_LIMIT
        );
    }

    #[test]
    fn os_build_number_is_reasonable() {
        let build = os_build_number();
        // Any Windows 10+ build number should be >= 10240.
        assert!(build >= 10240, "unexpected build number: {build}");
    }
}
