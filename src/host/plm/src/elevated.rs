// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Restricted UAC boundary for PLM's WPR control operations.
//!
//! The public `plm.exe` process remains unelevated. It creates a unique local
//! named pipe, launches a hidden child through `runas`, authenticates that
//! pipe's client PID against the returned process handle, and accepts only the
//! bounded protocol in [`crate::elevated_protocol`]. The child accepts no
//! filesystem paths: it uses the embedded WPR profile and creates its own
//! random temporary directory for profile and ETL files.

use anyhow::{Context, Result};
use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::c_void;
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;
use std::ptr;
use std::sync::atomic::AtomicIsize;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use learning_mode_core::{AnalysisResult, ProcessLifetime};
use learning_mode_windows::{
    EtlDenialAnalyzer, JobMembershipSnapshot, JobProcessMembership, MAX_JOB_PROCESS_LIFETIMES,
};
use windows::core::{BOOL, PCWSTR};
use windows::Win32::Foundation::{
    CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, ERROR_BROKEN_PIPE, ERROR_CANCELLED,
    ERROR_NO_DATA, ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING, ERROR_PIPE_NOT_CONNECTED, FILETIME,
    HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Security::{
    GetLengthSid, GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{
    FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_FIRST_PIPE_INSTANCE,
};
use windows::Win32::System::JobObjects::{
    IsProcessInJob, JobObjectAssociateCompletionPortInformation,
    JobObjectBasicAccountingInformation, QueryInformationJobObject, SetInformationJobObject,
    TerminateJobObject, JOBOBJECT_ASSOCIATE_COMPLETION_PORT,
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
    PeekNamedPipe, PIPE_NOWAIT, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
};
use windows::Win32::System::SystemInformation::GetSystemTimePreciseAsFileTime;
use windows::Win32::System::SystemServices::{
    JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS, JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO,
    JOB_OBJECT_MSG_EXIT_PROCESS, JOB_OBJECT_MSG_NEW_PROCESS,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetExitCodeProcess, GetProcessId, GetProcessTimes,
    OpenProcess, OpenProcessToken, TerminateProcess, WaitForSingleObject, PROCESS_DUP_HANDLE,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
};
use windows::Win32::System::IO::{
    CreateIoCompletionPort, GetQueuedCompletionStatus, PostQueuedCompletionStatus, OVERLAPPED,
};
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};

use crate::elevated_protocol::{
    read_attach_handles, read_header, write_attach_handles, write_header, ResponseKind,
    ATTACH_HANDLES_LEN, HEADER_LEN, MAX_ANALYSIS_BYTES, MAX_ERROR_BYTES, MAX_TRACE_BYTES,
};
use crate::secure_scratch::{ProfileGuard, RecoveryMarker, SecureScratch};

const PIPE_PREFIX: &str = r"\\.\pipe\mxc-plm-elevated-";
const WAIT_TIMEOUT_DURATION: Duration = Duration::from_secs(10 * 60);
const ATTACH_HANDOFF_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const TRANSFER_POLL_INTERVAL: Duration = Duration::from_millis(1);
const SW_HIDE: i32 = 0;
const HANDSHAKE_READY: u8 = 0xa5;
const CONTROL_STOP: u8 = 1;
const CONTROL_STOP_AND_ANALYZE: u8 = 2;
const CONTROL_STOP_AND_DISCARD: u8 = 3;
const CONTROL_ATTACH_JOB: u8 = 4;
const TRACKER_STOP_MESSAGE: u32 = u32::MAX;
static GUARDIAN_SINGLETON: AtomicIsize = AtomicIsize::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GuardControl {
    Stop,
    StopAndAnalyze,
    StopAndDiscard,
    AttachJob,
}

fn attest_job_process(job: HANDLE, pid: u32) -> Result<(OwnedHandle, u64)> {
    let process = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            false,
            pid,
        )
    }
    .with_context(|| format!("failed to open job process PID {pid}"))?;
    let process = OwnedHandle(process);
    if unsafe { GetProcessId(process.0) } != pid {
        anyhow::bail!("opened process identity changed while attesting PID {pid}");
    }
    let mut in_job = BOOL::default();
    unsafe { IsProcessInJob(process.0, Some(job), &mut in_job) }
        .with_context(|| format!("failed to verify job membership for PID {pid}"))?;
    if !in_job.as_bool() {
        anyhow::bail!("PID {pid} was not a member of the guarded sandbox job");
    }
    let (creation_filetime, _) = process_times(process.0)
        .with_context(|| format!("failed to query creation time for PID {pid}"))?;
    if creation_filetime == 0 {
        anyhow::bail!("PID {pid} has an invalid creation time");
    }
    Ok((process, creation_filetime))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PipeState {
    Data(u32),
    Empty,
    Closed(u32),
}

fn parse_guard_control(value: u8) -> Result<GuardControl> {
    match value {
        CONTROL_STOP => Ok(GuardControl::Stop),
        CONTROL_STOP_AND_ANALYZE => Ok(GuardControl::StopAndAnalyze),
        CONTROL_STOP_AND_DISCARD => Ok(GuardControl::StopAndDiscard),
        CONTROL_ATTACH_JOB => Ok(GuardControl::AttachJob),
        _ => anyhow::bail!("invalid guarded PLM control message {value}"),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Start,
    Attach,
    Stop,
    Discard,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GuardAction {
    None,
    Preserve,
    RejectStart,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GuardState {
    AwaitingReadiness,
    Ready,
    OwnerExitedDuringStart,
    Armed,
    Disarmed,
    Abandoned,
}

#[derive(Debug)]
struct GuardLifecycle {
    state: GuardState,
}

impl GuardLifecycle {
    fn new() -> Self {
        Self {
            state: GuardState::AwaitingReadiness,
        }
    }

    fn ready(&mut self, owner_alive: bool) -> GuardAction {
        match (self.state, owner_alive) {
            (GuardState::AwaitingReadiness, true) => {
                self.state = GuardState::Ready;
                GuardAction::None
            }
            (GuardState::AwaitingReadiness, false) => {
                self.state = GuardState::OwnerExitedDuringStart;
                GuardAction::RejectStart
            }
            _ => GuardAction::RejectStart,
        }
    }

    fn on_owner_exit(&mut self) -> GuardAction {
        match self.state {
            GuardState::Ready => {
                self.state = GuardState::OwnerExitedDuringStart;
                GuardAction::None
            }
            GuardState::Armed => {
                self.state = GuardState::Abandoned;
                GuardAction::Preserve
            }
            _ => GuardAction::None,
        }
    }

    fn on_start_succeeded(&mut self) -> GuardAction {
        match self.state {
            GuardState::Ready => {
                self.state = GuardState::Armed;
                GuardAction::None
            }
            GuardState::OwnerExitedDuringStart => {
                self.state = GuardState::Abandoned;
                GuardAction::Preserve
            }
            _ => GuardAction::RejectStart,
        }
    }

    fn disarm(&mut self) -> GuardAction {
        match self.state {
            GuardState::Armed => {
                self.state = GuardState::Disarmed;
                GuardAction::None
            }
            GuardState::Abandoned => GuardAction::Preserve,
            _ => GuardAction::RejectStart,
        }
    }

    fn on_pipe_break(&mut self) -> GuardAction {
        match self.state {
            GuardState::Armed => {
                self.state = GuardState::Abandoned;
                GuardAction::Preserve
            }
            _ => GuardAction::None,
        }
    }

    fn abandon_started_trace(&mut self) -> GuardAction {
        match self.state {
            GuardState::Ready | GuardState::OwnerExitedDuringStart | GuardState::Armed => {
                self.state = GuardState::Abandoned;
                GuardAction::Preserve
            }
            _ => GuardAction::None,
        }
    }

    fn defer_cleanup(&mut self) {
        if self.state == GuardState::Armed {
            self.state = GuardState::Abandoned;
        }
    }
}

struct GuardedOwner {
    owner: OwnedHandle,
    job_tracker: Option<JobProcessTracker>,
    recovery_marker: RecoveryMarker,
    _singleton: SingletonGuard,
    lifecycle: GuardLifecycle,
}

impl GuardedOwner {
    fn open(owner: OwnedHandle) -> Result<Self> {
        let singleton = SingletonGuard::acquire()?;
        let recovery_marker = RecoveryMarker::acquire()?;
        let mut guarded = Self {
            owner,
            job_tracker: None,
            recovery_marker,
            _singleton: singleton,
            lifecycle: GuardLifecycle::new(),
        };
        if guarded.lifecycle.ready(!guarded.has_exited()?) != GuardAction::None {
            anyhow::bail!("guarded PLM owner exited before WPR start");
        }
        Ok(guarded)
    }

    fn has_exited(&self) -> Result<bool> {
        match unsafe { WaitForSingleObject(self.owner.0, 0) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            wait => anyhow::bail!("guarded PLM owner liveness check failed with {}", wait.0),
        }
    }

    fn finish_start(&mut self) -> Result<()> {
        if self.has_exited()? {
            self.lifecycle.on_owner_exit();
        }
        match self.lifecycle.on_start_succeeded() {
            GuardAction::None => {}
            GuardAction::Preserve => {
                self.preserve_uncertain_trace();
                anyhow::bail!("guarded PLM owner exited during WPR start");
            }
            GuardAction::RejectStart => {
                anyhow::bail!("guarded PLM start reached an invalid lifecycle state")
            }
        }
        if self.has_exited()? {
            if self.lifecycle.on_owner_exit() == GuardAction::Preserve {
                self.preserve_uncertain_trace();
            }
            anyhow::bail!("guarded PLM owner exited immediately after WPR start");
        }
        Ok(())
    }

    fn wait_for_control(&mut self, pipe: &mut std::fs::File) -> Result<()> {
        loop {
            let owner_exited = match self.has_exited() {
                Ok(exited) => exited,
                Err(error) => return Err(self.fail_after_monitor_error(error)),
            };
            if owner_exited {
                if self.lifecycle.on_owner_exit() == GuardAction::Preserve {
                    self.preserve_uncertain_trace();
                }
                anyhow::bail!("guarded PLM owner exited before stop");
            }

            if let Some(error) = self.tracker_failure()? {
                return self.stop_and_discard_after_tracker_failure(pipe, error);
            }

            let state = match pipe_state(pipe) {
                Ok(state) => state,
                Err(error) => return Err(self.fail_after_monitor_error(error)),
            };
            match state {
                PipeState::Empty => {
                    std::thread::sleep(POLL_INTERVAL);
                    continue;
                }
                PipeState::Closed(error) => {
                    self.preserve_after_pipe_break();
                    anyhow::bail!(
                        "guarded PLM control pipe closed before stop (PeekNamedPipe error {error})"
                    );
                }
                PipeState::Data(_) => {}
            }

            let mut control = [0u8; 1];
            match pipe.read(&mut control) {
                Ok(1) => match parse_guard_control(control[0]) {
                    Ok(GuardControl::Stop) => {
                        return run_guarded_stop(pipe, self, StopDisposition::Trace);
                    }
                    Ok(GuardControl::StopAndAnalyze) => {
                        return run_guarded_stop(pipe, self, StopDisposition::Analyze);
                    }
                    Ok(GuardControl::StopAndDiscard) => {
                        return run_guarded_stop(pipe, self, StopDisposition::Discard);
                    }
                    Ok(GuardControl::AttachJob) => {
                        let deadline = Instant::now() + ATTACH_HANDOFF_TIMEOUT;
                        let handles =
                            read_attach_handles_polling(pipe, deadline, || self.has_exited());
                        let (job_handle, root_process_handle) = match handles {
                            Ok(handles) => handles,
                            Err(error) => {
                                self.preserve_after_pipe_break();
                                return Err(error).context(
                                    "failed to receive guarded WPR sandbox attach handles",
                                );
                            }
                        };
                        let response_result =
                            match self.attach_process_tree(job_handle, root_process_handle) {
                                Ok(()) => write_header(pipe, ResponseKind::Success, 0)
                                    .and_then(|_| pipe.flush())
                                    .context("failed to acknowledge guarded WPR job attachment"),
                                Err(error) => write_error_response(pipe, &error),
                            };
                        if let Err(error) = response_result {
                            self.preserve_after_pipe_break();
                            return Err(error);
                        }
                    }
                    Err(error) => {
                        self.preserve_after_pipe_break();
                        return Err(error);
                    }
                },
                Ok(0) => {
                    std::thread::sleep(POLL_INTERVAL);
                }
                Ok(_) => unreachable!("one-byte control read returned too many bytes"),
                Err(error) => {
                    self.preserve_after_pipe_break();
                    return Err(error).context("guarded PLM control pipe failed before stop");
                }
            }
        }
    }

    fn preserve_after_pipe_break(&mut self) {
        if self.lifecycle.on_pipe_break() == GuardAction::Preserve {
            self.preserve_uncertain_trace();
        }
    }

    fn attach_process_tree(
        &mut self,
        source_job_handle: usize,
        source_root_process_handle: usize,
    ) -> Result<()> {
        if self.job_tracker.is_some() {
            anyhow::bail!("guarded WPR sandbox process tree is already attached");
        }
        self.job_tracker = Some(JobProcessTracker::duplicate_and_attach(
            self.owner.0,
            source_job_handle,
            source_root_process_handle,
        )?);
        Ok(())
    }

    fn finish_job_tracking(&mut self) -> Result<JobMembershipSnapshot> {
        self.job_tracker
            .take()
            .context("guarded WPR stop/analyze requires an attached sandbox process tree")?
            .finish()
    }

    fn tracker_failure(&self) -> Result<Option<String>> {
        self.job_tracker
            .as_ref()
            .map(JobProcessTracker::failure)
            .transpose()
            .map(Option::flatten)
    }

    fn stop_and_discard_after_tracker_failure(
        &mut self,
        pipe: &mut std::fs::File,
        _tracker_error: String,
    ) -> Result<()> {
        let failure = self
            .job_tracker
            .take()
            .context("guarded WPR tracker failure lost its process-tree state")?
            .finish_failure()?;
        if let Some(termination_error) = failure.termination_error {
            let error = anyhow::anyhow!(
                "guarded WPR process tracking failed and the sandbox job could not be terminated; \
                 the trace was left for guarded recovery: {}; {termination_error}",
                failure.message
            );
            self.preserve_after_start_error();
            write_error_response(pipe, &error)?;
            return Err(error);
        }

        // The tracker worker has terminated the attested sandbox job. Stop
        // retaining process handles before sealing and deleting the raw
        // host-wide trace; no analysis is safe once process scoping failed.
        let error = anyhow::anyhow!(
            "guarded WPR process tracking failed; the sandbox job was terminated and its trace \
             was discarded: {}",
            failure.message
        );
        let result = (|| {
            crate::wpr_path::verify_wpr_present().map_err(anyhow::Error::msg)?;
            let scratch = SecureScratch::new()?;
            run_monitored_wpr_stop(pipe, self, scratch.trace_path())?;
            self.mark_stopped()?;
            write_header(pipe, ResponseKind::Stopped, 0)
                .and_then(|_| pipe.flush())
                .context("failed to return elevated PLM WPR-stopped milestone")?;
            write_error_response(pipe, &error)
        })();
        if let Err(stop_error) = result {
            self.preserve_after_start_error();
            let combined = error.context(format!(
                "additionally failed to stop and discard the guarded WPR trace: {stop_error:#}"
            ));
            write_error_response(pipe, &combined)?;
            return Err(combined);
        }
        Err(error)
    }

    fn preserve_after_start_error(&mut self) {
        if self.lifecycle.abandon_started_trace() == GuardAction::Preserve {
            self.preserve_uncertain_trace();
        }
    }

    fn mark_stopped(&mut self) -> Result<()> {
        match self.lifecycle.disarm() {
            GuardAction::None => Ok(()),
            GuardAction::Preserve => anyhow::bail!("guarded cleanup won the stop race"),
            GuardAction::RejectStart => {
                anyhow::bail!("guarded PLM stop arrived in an invalid state")
            }
        }
    }

    fn preserve_uncertain_trace(&mut self) {
        self.recovery_marker.preserve();
    }

    fn fail_after_monitor_error(&mut self, error: anyhow::Error) -> anyhow::Error {
        if self.lifecycle.abandon_started_trace() == GuardAction::Preserve {
            self.preserve_uncertain_trace();
        }
        error.context(
            "guarded PLM monitoring failed; preserved recovery marker and left WPR state \
             untouched to avoid cancelling an unrelated host recording",
        )
    }
}

impl Operation {
    fn as_arg(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Attach => "attach",
            Self::Stop => "stop",
            Self::Discard => "discard",
        }
    }
}

struct OwnedHandle(HANDLE);

// SAFETY: Windows kernel handles are process-global. Ownership remains unique,
// and all access is synchronized by the tracker mutex when moved to its worker.
unsafe impl Send for OwnedHandle {}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

struct TrackedMembership {
    pid: u32,
    process: OwnedHandle,
    creation_filetime: u64,
    start_sequence: usize,
    start_observed_filetime: u64,
    end_sequence: Option<usize>,
    end_observed_filetime: Option<u64>,
}

struct ProcessTrackerState {
    attached_filetime: u64,
    root_pid: u32,
    root_active: bool,
    root_start_notification_seen: bool,
    root_exit_notification_seen: bool,
    active: HashMap<u32, usize>,
    processes: Vec<TrackedMembership>,
    notification_sequence: usize,
    active_process_zero_filetime: Option<u64>,
    error: Option<String>,
    termination_error: Option<String>,
}

impl ProcessTrackerState {
    fn new(attached_filetime: u64, root_pid: u32) -> Self {
        Self {
            attached_filetime,
            root_pid,
            root_active: true,
            root_start_notification_seen: false,
            root_exit_notification_seen: false,
            active: HashMap::new(),
            processes: Vec::new(),
            notification_sequence: 0,
            active_process_zero_filetime: None,
            error: None,
            termination_error: None,
        }
    }

    fn fail(&mut self, message: impl Into<String>) {
        if self.error.is_none() {
            self.error = Some(message.into());
        }
    }

    fn process_started<F>(&mut self, pid: u32, observed_filetime: u64, attest: F)
    where
        F: FnOnce() -> Result<(OwnedHandle, u64)>,
    {
        self.active_process_zero_filetime = None;
        if pid == self.root_pid && self.root_active && !self.root_start_notification_seen {
            self.root_start_notification_seen = true;
            return;
        }
        if self.error.is_some() {
            return;
        }
        if self.processes.len() >= MAX_JOB_PROCESS_LIFETIMES - 1 {
            self.fail(format!(
                "sandbox job exceeded the {MAX_JOB_PROCESS_LIFETIMES}-process tracking limit"
            ));
            return;
        }
        if self.active.contains_key(&pid) {
            self.fail(format!(
                "sandbox job reported duplicate process start for PID {pid}"
            ));
            return;
        }
        let (process, creation_filetime) = match attest() {
            Ok(attestation) => attestation,
            Err(error) => {
                self.fail(format!(
                    "failed to attest job process generation for PID {pid}: {error:#}"
                ));
                return;
            }
        };
        let index = self.processes.len();
        let start_sequence = self.take_notification_sequence();
        self.processes.push(TrackedMembership {
            pid,
            process,
            creation_filetime,
            start_sequence,
            start_observed_filetime: observed_filetime,
            end_sequence: None,
            end_observed_filetime: None,
        });
        self.active.insert(pid, index);
    }

    fn process_exited(&mut self, pid: u32, observed_filetime: u64) {
        if pid == self.root_pid && self.root_active && !self.root_exit_notification_seen {
            self.root_active = false;
            self.root_exit_notification_seen = true;
            return;
        }
        if pid == self.root_pid
            && self.root_exit_notification_seen
            && !self.active.contains_key(&pid)
        {
            return;
        }
        let index = if let Some(index) = self.active.remove(&pid) {
            index
        } else if let Some(index) = self
            .processes
            .iter()
            .rposition(|process| process.pid == pid && process.end_sequence.is_none())
        {
            index
        } else {
            if self
                .processes
                .iter()
                .any(|process| process.pid == pid && process.end_observed_filetime.is_some())
            {
                return;
            }
            self.fail(format!(
                "sandbox job reported process exit without a tracked start for PID {pid}"
            ));
            return;
        };
        let end_sequence = self.take_notification_sequence();
        let process = &mut self.processes[index];
        process.end_sequence = Some(end_sequence);
        process.end_observed_filetime = Some(
            process
                .end_observed_filetime
                .map_or(observed_filetime, |active_zero| {
                    active_zero.min(observed_filetime)
                }),
        );
    }

    fn all_processes_exited(&mut self, observed_filetime: u64) {
        self.root_active = false;
        for (_, index) in self.active.drain() {
            self.processes[index].end_observed_filetime = Some(observed_filetime);
        }
        self.active_process_zero_filetime = Some(observed_filetime);
    }

    fn take_notification_sequence(&mut self) -> usize {
        let sequence = self.notification_sequence;
        self.notification_sequence += 1;
        sequence
    }
}

struct JobProcessTracker {
    job: OwnedHandle,
    root_process: OwnedHandle,
    root_pid: u32,
    root_creation_filetime: u64,
    completion_port: OwnedHandle,
    state: Arc<Mutex<ProcessTrackerState>>,
    worker: Option<JoinHandle<()>>,
}

struct TrackerFailure {
    message: String,
    termination_error: Option<String>,
}

impl JobProcessTracker {
    fn duplicate_and_attach(
        owner: HANDLE,
        source_job_handle: usize,
        source_root_process_handle: usize,
    ) -> Result<Self> {
        let job = duplicate_owner_handle(owner, source_job_handle)
            .context("failed to duplicate sandbox job from the authenticated owner")?;
        let root_process = duplicate_owner_handle(owner, source_root_process_handle)
            .context("failed to duplicate sandbox root process from the authenticated owner")?;
        let root_pid = unsafe { GetProcessId(root_process.0) };
        if root_pid == 0 {
            anyhow::bail!(
                "failed to identify the sandbox root process duplicated from the authenticated owner"
            );
        }
        let mut in_job = BOOL::default();
        unsafe { IsProcessInJob(root_process.0, Some(job.0), &mut in_job) }
            .context("failed to verify sandbox root process job membership")?;
        if !in_job.as_bool() {
            anyhow::bail!(
                "authenticated owner's sandbox root process handle is not in the supplied job"
            );
        }
        let (root_creation_filetime, root_exit_filetime) = process_times(root_process.0)
            .context("failed to attest sandbox root process creation time")?;
        if root_creation_filetime == 0 || root_exit_filetime != 0 {
            anyhow::bail!("sandbox root process was not a live process when guarded WPR attached");
        }
        let completion_port = unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, None, 0, 1) }
            .context("failed to create guarded WPR job completion port")?;
        let completion_port = OwnedHandle(completion_port);
        let association = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
            CompletionKey: ptr::null_mut(),
            CompletionPort: completion_port.0,
        };
        let attached_filetime = current_filetime();
        unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectAssociateCompletionPortInformation,
                &association as *const _ as *const c_void,
                size_of::<JOBOBJECT_ASSOCIATE_COMPLETION_PORT>() as u32,
            )
        }
        .context("failed to associate the elevated guardian with the sandbox job")?;

        let state = Arc::new(Mutex::new(ProcessTrackerState::new(
            attached_filetime,
            root_pid,
        )));
        let worker_state = Arc::clone(&state);
        let raw_port = completion_port.0 .0 as usize;
        let raw_job = job.0 .0 as usize;
        let worker = std::thread::Builder::new()
            .name("plm-job-tracker".to_string())
            .spawn(move || {
                process_job_notifications(
                    HANDLE(raw_port as *mut c_void),
                    HANDLE(raw_job as *mut c_void),
                    &worker_state,
                );
            })
            .context("failed to start guarded WPR job tracker")?;
        Ok(Self {
            job,
            root_process,
            root_pid,
            root_creation_filetime,
            completion_port,
            state,
            worker: Some(worker),
        })
    }

    fn finish(mut self) -> Result<JobMembershipSnapshot> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("guarded WPR job tracker state was poisoned"))?;
            if (state.active_process_zero_filetime.is_some() && state.active.is_empty())
                || state.error.is_some()
            {
                break;
            }
            drop(state);
            if Instant::now() >= deadline {
                anyhow::bail!(
                    "timed out waiting for the sandbox job to report zero active processes"
                );
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        self.stop_worker();
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("guarded WPR job tracker state was poisoned"))?;
        if !state.active.is_empty() {
            anyhow::bail!(
                "guarded WPR job tracker stopped with {} process(es) still active",
                state.active.len()
            );
        }
        if let Some(error) = state.error.take() {
            anyhow::bail!("{error}");
        }
        let completed_filetime = state
            .active_process_zero_filetime
            .context("guarded WPR sandbox job never reported zero active processes")?;
        let (_, root_exit_filetime) = process_times(self.root_process.0)
            .context("failed to attest sandbox root process exit time after WPR stop")?;
        if root_exit_filetime == 0 {
            anyhow::bail!("sandbox root process has no kernel-attested exit time after WPR stop");
        }
        if root_exit_filetime < self.root_creation_filetime
            || root_exit_filetime > completed_filetime
        {
            anyhow::bail!("sandbox root process has an invalid kernel-attested lifetime");
        }
        let processes = std::mem::take(&mut state.processes)
            .into_iter()
            .map(|process| {
                let (_, exit_filetime) = process_times(process.process.0).with_context(|| {
                    format!("failed to attest exit time for job process {}", process.pid)
                })?;
                if exit_filetime == 0
                    || exit_filetime < process.creation_filetime
                    || exit_filetime > completed_filetime
                {
                    anyhow::bail!(
                        "job process {} has an invalid kernel-attested lifetime",
                        process.pid
                    );
                }
                Ok(JobProcessMembership {
                    pid: process.pid,
                    creation_filetime: process.creation_filetime,
                    exit_filetime,
                    start_sequence: process.start_sequence,
                    start_observed_filetime: process.start_observed_filetime,
                    end_sequence: process.end_sequence,
                    end_observed_filetime: process.end_observed_filetime.context(format!(
                        "job process {} has no exit observation time",
                        process.pid
                    ))?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let total_processes = query_total_processes(self.job.0)?;
        let retained_processes = u32::try_from(processes.len() + 1)
            .context("retained sandbox process count does not fit job accounting")?;
        if total_processes != retained_processes {
            anyhow::bail!(
                "sandbox job accounting reported {total_processes} process generation(s), but \
                 guarded tracking retained {retained_processes}; completion-port notifications \
                 were lost or inconsistent"
            );
        }
        Ok(JobMembershipSnapshot {
            root_process: ProcessLifetime {
                pid: self.root_pid,
                start_filetime: self.root_creation_filetime,
                end_filetime: root_exit_filetime,
            },
            attached_filetime: state.attached_filetime,
            completed_filetime,
            total_processes,
            notification_count: state.notification_sequence,
            processes,
        })
    }

    fn failure(&self) -> Result<Option<String>> {
        self.state
            .lock()
            .map(|state| state.error.clone())
            .map_err(|_| anyhow::anyhow!("guarded WPR job tracker state was poisoned"))
    }

    fn finish_failure(mut self) -> Result<TrackerFailure> {
        self.stop_worker();
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("guarded WPR job tracker state was poisoned"))?;
        Ok(TrackerFailure {
            message: state
                .error
                .take()
                .context("guarded WPR job tracker failure was not retained")?,
            termination_error: state.termination_error.take(),
        })
    }

    fn stop_worker(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = unsafe {
                PostQueuedCompletionStatus(self.completion_port.0, TRACKER_STOP_MESSAGE, 0, None)
            };
            if worker.join().is_err() {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.fail("guarded WPR job tracker thread panicked");
            }
        }
    }
}

impl Drop for JobProcessTracker {
    fn drop(&mut self) {
        self.stop_worker();
    }
}

fn duplicate_owner_handle(owner: HANDLE, source_handle: usize) -> Result<OwnedHandle> {
    let mut duplicated = HANDLE::default();
    unsafe {
        DuplicateHandle(
            owner,
            HANDLE(source_handle as *mut c_void),
            GetCurrentProcess(),
            &mut duplicated,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
    }?;
    Ok(OwnedHandle(duplicated))
}

fn process_times(process: HANDLE) -> Result<(u64, u64)> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) }?;
    Ok((filetime_value(creation), filetime_value(exit)))
}

fn query_total_processes(job: HANDLE) -> Result<u32> {
    let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
    unsafe {
        QueryInformationJobObject(
            Some(job),
            JobObjectBasicAccountingInformation,
            &mut accounting as *mut _ as *mut c_void,
            size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
            None,
        )
    }
    .context("failed to query sandbox job process accounting")?;
    Ok(accounting.TotalProcesses)
}

fn filetime_value(value: FILETIME) -> u64 {
    (u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime)
}

fn process_job_notifications(port: HANDLE, job: HANDLE, state: &Arc<Mutex<ProcessTrackerState>>) {
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
            fail_tracker_and_terminate_job(
                job,
                state,
                format!("guarded WPR job tracker wait failed: {error}"),
            );
            return;
        }
        if message == TRACKER_STOP_MESSAGE {
            return;
        }
        let pid = overlapped as usize as u32;
        let observed_filetime = current_filetime();
        let Ok(mut tracker_state) = state.lock() else {
            return;
        };
        let was_failed = tracker_state.error.is_some();
        match message {
            JOB_OBJECT_MSG_NEW_PROCESS => {
                tracker_state
                    .process_started(pid, observed_filetime, || attest_job_process(job, pid));
            }
            JOB_OBJECT_MSG_EXIT_PROCESS | JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS => {
                tracker_state.process_exited(pid, observed_filetime);
            }
            JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO => {
                tracker_state.all_processes_exited(observed_filetime);
            }
            _ => {}
        }
        let newly_failed = !was_failed && tracker_state.error.is_some();
        drop(tracker_state);
        if newly_failed {
            terminate_failed_tracker_job(job, state);
        }
    }
}

fn fail_tracker_and_terminate_job(
    job: HANDLE,
    state: &Arc<Mutex<ProcessTrackerState>>,
    message: String,
) {
    let newly_failed = match state.lock() {
        Ok(mut state) => {
            let newly_failed = state.error.is_none();
            state.fail(message);
            newly_failed
        }
        Err(_) => true,
    };
    if newly_failed {
        terminate_failed_tracker_job(job, state);
    }
}

fn terminate_failed_tracker_job(job: HANDLE, state: &Arc<Mutex<ProcessTrackerState>>) {
    if let Err(error) = unsafe { TerminateJobObject(job, u32::MAX) } {
        if let Ok(mut state) = state.lock() {
            let termination_error =
                format!("failed to terminate sandbox job after tracker failure: {error}");
            state.termination_error = Some(termination_error);
        }
    }
}

fn current_filetime() -> u64 {
    filetime_value(unsafe { GetSystemTimePreciseAsFileTime() })
}

/// Live authenticated connection to the elevated START child.
///
/// [`Self::cancel`] closes an armed session and reports that WPR state may
/// require administrator recovery. Unexpected teardown never issues the
/// host-wide `wpr -cancel`, because it cannot atomically prove that the active
/// recording is still PLM's. [`Self::stop`] asks the retained child to stop WPR
/// and transfer the ETL, avoiding a second elevation prompt.
pub struct GuardedSession {
    pipe: Option<std::fs::File>,
    process: OwnedHandle,
    disarmed: bool,
}

// SAFETY: `GuardedSession` only holds a Windows process HANDLE (via
// `OwnedHandle`) and a pipe `File`, both of which are process-wide and safe to
// use from any thread — Windows HANDLEs have no thread affinity. This lets
// callers (e.g. `mxc_engine`'s `GuardedCaptureSession` adapter) store the
// session behind a `Box<dyn ... + Send>` DI boundary.
unsafe impl Send for GuardedSession {}

impl std::fmt::Debug for GuardedSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GuardedSession")
            .field("connected", &self.pipe.is_some())
            .field("disarmed", &self.disarmed)
            .finish_non_exhaustive()
    }
}

impl GuardedSession {
    pub fn attach_process_tree(
        &mut self,
        job_handle: usize,
        root_process_handle: usize,
    ) -> Result<()> {
        if self.disarmed {
            anyhow::bail!("guarded PLM session is already stopped");
        }
        let mut encoded_handles = Vec::new();
        write_attach_handles(&mut encoded_handles, job_handle, root_process_handle)
            .context("failed to encode guarded WPR sandbox attach handles")?;
        let mut pipe = self
            .pipe
            .take()
            .context("guarded PLM control connection is already closed")?;
        let result = pipe
            .write_all(&[CONTROL_ATTACH_JOB])
            .and_then(|_| pipe.write_all(&encoded_handles))
            .and_then(|_| pipe.flush())
            .context("failed to send guarded WPR sandbox attach handles")
            .and_then(|_| {
                read_response(
                    &mut pipe,
                    self.process.0,
                    Operation::Attach,
                    None,
                    Instant::now() + WAIT_TIMEOUT_DURATION,
                    || Ok(()),
                )
            });
        self.pipe = Some(pipe);
        result
    }

    pub fn cancel(&mut self) -> Result<()> {
        let abandoned = !self.disarmed;
        if abandoned {
            self.pipe.take();
            self.disarmed = true;
        }
        let exit_code = wait_for_child_termination(self.process.0, WAIT_TIMEOUT_DURATION).context(
            "guarded PLM session could not confirm guardian termination after abandoning WPR state",
        )?;
        if abandoned {
            eprintln!(
                "[plm] guarded session ended without an explicit stop (guardian exit code \
                 {exit_code}); the recovery marker was preserved and WPR state was left untouched"
            );
        }
        Ok(())
    }

    pub fn stop(&mut self, trace_destination: &Path) -> Result<()> {
        if self.disarmed {
            anyhow::bail!("guarded PLM session is already stopped");
        }
        let mut pipe = self
            .pipe
            .take()
            .context("guarded PLM control connection is already closed")?;
        send_control_unless_response_pending(&mut pipe, CONTROL_STOP)
            .context("failed to send guarded PLM STOP")?;

        let stopped = std::cell::Cell::new(false);
        let deadline = Instant::now() + WAIT_TIMEOUT_DURATION;
        let result = read_response(
            &mut pipe,
            self.process.0,
            Operation::Stop,
            Some(trace_destination),
            deadline,
            || {
                stopped.set(true);
                Ok(())
            },
        );
        if stopped.get() {
            self.disarmed = true;
            drop(pipe);
            let wait_result = wait_for_child_exit(
                self.process.0,
                deadline.saturating_duration_since(Instant::now()),
            );
            result?;
            wait_result
        } else {
            self.pipe = Some(pipe);
            result
        }
    }

    pub fn discard(&mut self) -> Result<()> {
        if self.disarmed {
            anyhow::bail!("guarded PLM session is already stopped");
        }
        let mut pipe = self
            .pipe
            .take()
            .context("guarded PLM control connection is already closed")?;
        send_control_unless_response_pending(&mut pipe, CONTROL_STOP_AND_DISCARD)
            .context("failed to send guarded PLM discard STOP")?;

        let stopped = std::cell::Cell::new(false);
        let deadline = Instant::now() + WAIT_TIMEOUT_DURATION;
        let result = read_response(
            &mut pipe,
            self.process.0,
            Operation::Discard,
            None,
            deadline,
            || {
                stopped.set(true);
                Ok(())
            },
        );
        if stopped.get() {
            self.disarmed = true;
            drop(pipe);
            let wait_result = wait_for_child_exit(
                self.process.0,
                deadline.saturating_duration_since(Instant::now()),
            );
            result?;
            wait_result
        } else {
            self.pipe = Some(pipe);
            result
        }
    }

    pub fn stop_analyzed(&mut self) -> Result<AnalysisResult> {
        if self.disarmed {
            anyhow::bail!("guarded PLM session is already stopped");
        }
        let mut pipe = self
            .pipe
            .take()
            .context("guarded PLM control connection is already closed")?;
        send_control_unless_response_pending(&mut pipe, CONTROL_STOP_AND_ANALYZE)
            .context("failed to send guarded PLM analyzed STOP")?;

        let stopped = std::cell::Cell::new(false);
        let deadline = Instant::now() + WAIT_TIMEOUT_DURATION;
        let result = read_analysis_response(&mut pipe, self.process.0, deadline, || {
            stopped.set(true);
            Ok(())
        });
        if stopped.get() {
            self.disarmed = true;
            drop(pipe);
            let wait_result = wait_for_child_exit(
                self.process.0,
                deadline.saturating_duration_since(Instant::now()),
            );
            let analysis = result?;
            wait_result?;
            Ok(analysis)
        } else {
            self.pipe = Some(pipe);
            result
        }
    }
}

fn send_control_unless_response_pending(pipe: &mut std::fs::File, control: u8) -> Result<()> {
    if guardian_terminal_response_pending(pipe)? {
        return Ok(());
    }
    pipe.write_all(&[control])
        .and_then(|_| pipe.flush())
        .context("failed to write guarded PLM control byte")
}

fn guardian_terminal_response_pending(pipe: &std::fs::File) -> Result<bool> {
    match pipe_state(pipe)? {
        PipeState::Empty => return Ok(false),
        PipeState::Closed(error) => anyhow::bail!(
            "guarded PLM control pipe closed before stop (PeekNamedPipe error {error})"
        ),
        PipeState::Data(_) => {}
    }

    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let mut header = [0u8; HEADER_LEN];
        let mut bytes_read = 0u32;
        let mut available = 0u32;
        unsafe {
            PeekNamedPipe(
                HANDLE(pipe.as_raw_handle()),
                Some(header.as_mut_ptr().cast()),
                HEADER_LEN as u32,
                Some(&mut bytes_read),
                Some(&mut available),
                None,
            )
        }
        .context("failed to inspect pending guarded PLM response")?;

        if bytes_read as usize >= HEADER_LEN {
            let response = read_header(&mut header.as_slice())
                .context("invalid unsolicited guarded PLM response")?;
            return match response.kind {
                ResponseKind::Stopped | ResponseKind::Error => Ok(true),
                kind => anyhow::bail!(
                    "unexpected unsolicited guarded PLM {kind:?} response before stop"
                ),
            };
        }
        if available == 0 {
            return Ok(false);
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "timed out waiting for the pending guarded PLM response header \
                 ({bytes_read}/{HEADER_LEN} bytes available)"
            );
        }
        std::thread::sleep(TRANSFER_POLL_INTERVAL);
    }
}

impl Drop for GuardedSession {
    fn drop(&mut self) {
        if self.disarmed {
            return;
        }
        self.pipe.take();
        let _ = wait_for_child_exit(self.process.0, WAIT_TIMEOUT_DURATION);
    }
}

thread_local! {
    static CURRENT_GUARDED_SESSION: RefCell<Option<GuardedSession>> = const {
        RefCell::new(None)
    };
}

/// Compatibility entry point used by interactive `plm log`.
pub fn invoke_guarded_start(owner_pid: u32) -> Result<()> {
    CURRENT_GUARDED_SESSION.with(|slot| {
        if slot.borrow().is_some() {
            anyhow::bail!("a guarded PLM session is already active on this thread");
        }
        let session = start_guarded_session(owner_pid)?;
        *slot.borrow_mut() = Some(session);
        Ok(())
    })
}

pub fn stop_current_guarded_start(trace_destination: &Path) -> Result<()> {
    CURRENT_GUARDED_SESSION.with(|slot| {
        let mut session = slot
            .borrow_mut()
            .take()
            .context("no guarded PLM session is active on this thread")?;
        let result = session.stop(trace_destination);
        if result.is_err() && !session.disarmed {
            *slot.borrow_mut() = Some(session);
        }
        result
    })
}

pub fn cancel_current_guarded_start() -> Result<()> {
    CURRENT_GUARDED_SESSION.with(|slot| {
        let Some(mut session) = slot.borrow_mut().take() else {
            return Ok(());
        };
        session.cancel()
    })
}

pub fn start_guarded_session(owner_pid: u32) -> Result<GuardedSession> {
    let executable = std::env::current_exe().context("failed to resolve plm.exe path")?;
    start_guarded_session_with_executable(&executable, owner_pid)
}

pub fn start_guarded_session_with_executable(
    executable: &Path,
    owner_pid: u32,
) -> Result<GuardedSession> {
    if owner_pid == 0 {
        anyhow::bail!("guarded elevated start requires a non-zero owner PID");
    }
    let (mut pipe, process, deadline) =
        launch_connected_child(executable, Operation::Start, Some(owner_pid))?;
    if let Err(error) = read_response(
        &mut pipe,
        process.0,
        Operation::Start,
        None,
        deadline,
        || Ok(()),
    ) {
        drop(pipe);
        let _ = wait_for_child_exit(process.0, WAIT_TIMEOUT_DURATION);
        return Err(error);
    }
    Ok(GuardedSession {
        pipe: Some(pipe),
        process,
        disarmed: false,
    })
}

fn launch_connected_child(
    executable: &Path,
    operation: Operation,
    owner_pid: Option<u32>,
) -> Result<(std::fs::File, OwnedHandle, Instant)> {
    let pipe_name = new_pipe_name()?;
    let pipe = OwnedHandle(create_pipe(&pipe_name)?);
    if operation != Operation::Start || owner_pid.is_none() {
        anyhow::bail!("only guarded elevated start may launch a PLM child");
    }
    let process = OwnedHandle(launch_elevated_child(
        executable, operation, &pipe_name, owner_pid,
    )?);
    let child_pid = unsafe { GetProcessId(process.0) };
    if child_pid == 0 {
        anyhow::bail!("GetProcessId failed for elevated PLM child");
    }

    let deadline = Instant::now() + WAIT_TIMEOUT_DURATION;
    connect_authenticated_client(pipe.0, process.0, child_pid, deadline)?;

    // SAFETY: the pipe handle is valid and uniquely owned. Prevent OwnedHandle
    // from closing it a second time after File assumes ownership.
    let pipe_raw = pipe.0 .0;
    std::mem::forget(pipe);
    let mut pipe_file = unsafe { std::fs::File::from_raw_handle(pipe_raw) };
    pipe_file
        .write_all(&[HANDSHAKE_READY])
        .and_then(|_| pipe_file.flush())
        .context("failed to complete PLM control-pipe readiness handshake")?;
    Ok((pipe_file, process, deadline))
}

fn wait_for_child_termination(process: HANDLE, timeout: Duration) -> Result<u32> {
    let wait_ms = timeout.as_millis().min(u32::MAX as u128) as u32;
    let wait = unsafe { WaitForSingleObject(process, wait_ms) };
    if wait == WAIT_TIMEOUT {
        anyhow::bail!("elevated PLM child did not exit within the timeout");
    }
    if wait == WAIT_FAILED {
        anyhow::bail!("WaitForSingleObject failed for elevated PLM child");
    }
    let mut exit_code = 0u32;
    unsafe { GetExitCodeProcess(process, &mut exit_code) }
        .context("GetExitCodeProcess failed for elevated PLM child")?;
    Ok(exit_code)
}

fn wait_for_child_exit(process: HANDLE, timeout: Duration) -> Result<()> {
    let exit_code = wait_for_child_termination(process, timeout)?;
    if exit_code != 0 {
        anyhow::bail!("elevated PLM child exited with code {exit_code}");
    }
    Ok(())
}

/// Entry point for the hidden elevated mode.
pub fn run_child(
    operation: Operation,
    pipe_name: &str,
    server_pid: u32,
    owner_pid: Option<u32>,
) -> Result<()> {
    validate_pipe_name(pipe_name)?;
    if server_pid == 0 {
        anyhow::bail!("invalid elevated PLM server PID");
    }
    if !is_process_elevated()? {
        anyhow::bail!("internal PLM control mode requires elevation");
    }

    let mut pipe = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(pipe_name)
        .with_context(|| format!("failed to connect to PLM control pipe {pipe_name}"))?;
    if owner_pid != Some(server_pid) {
        anyhow::bail!("guarded PLM owner PID must match the authenticated pipe server PID");
    }
    let owner = authenticate_server(&pipe, server_pid)?;
    let mut ready = [0u8; 1];
    pipe.read_exact(&mut ready)
        .context("failed to receive PLM control-pipe readiness")?;
    if ready[0] != HANDSHAKE_READY {
        anyhow::bail!("invalid PLM control-pipe readiness byte");
    }
    if operation != Operation::Start || owner_pid.is_none() {
        anyhow::bail!("elevated start requires a guarded owner PID");
    }
    run_guarded_start_child(&mut pipe, owner)
}

struct SingletonGuard;

impl SingletonGuard {
    fn acquire() -> Result<Self> {
        use crate::coordination::singleton::{try_acquire, AcquireError};

        match try_acquire(&GUARDIAN_SINGLETON) {
            Ok(_) => Ok(Self),
            Err(AcquireError::AlreadyHeld) => anyhow::bail!(
                "another PLM trace is already in progress (Global\\Mxc_Plm_Audit held)"
            ),
            Err(AcquireError::CreateFailed(error)) => {
                Err(error).context("failed to acquire Global\\Mxc_Plm_Audit in elevated PLM child")
            }
            Err(AcquireError::UntrustedExisting) => {
                anyhow::bail!("Global\\Mxc_Plm_Audit already exists with an untrusted owner")
            }
            Err(AcquireError::SecurityQueryFailed(error)) => {
                anyhow::bail!("failed to validate Global\\Mxc_Plm_Audit security: {error:?}")
            }
        }
    }
}

impl Drop for SingletonGuard {
    fn drop(&mut self) {
        crate::coordination::singleton::release(&GUARDIAN_SINGLETON);
    }
}

fn run_guarded_start_child(pipe: &mut std::fs::File, owner_handle: OwnedHandle) -> Result<()> {
    let mut owner = match GuardedOwner::open(owner_handle) {
        Ok(owner) => owner,
        Err(error) => {
            write_error_response(pipe, &error)?;
            return Err(error);
        }
    };
    if let Err(error) = start_owned_trace(&mut owner) {
        write_error_response(pipe, &error)?;
        return Err(error);
    }
    if let Err(error) = owner.finish_start() {
        owner.preserve_after_start_error();
        write_error_response(pipe, &error)?;
        return Err(error);
    }
    if let Err(error) = write_header(pipe, ResponseKind::Success, 0).and_then(|_| pipe.flush()) {
        owner.preserve_after_pipe_break();
        return Err(error).context("failed to return guarded PLM start success");
    }
    owner.wait_for_control(pipe)
}

fn start_owned_trace(owner: &mut GuardedOwner) -> Result<()> {
    let stale = owner.recovery_marker.is_stale();
    match run_start() {
        Ok(()) => {
            owner.recovery_marker.recovered();
            Ok(())
        }
        Err(error) if crate::start::may_have_changed_wpr_state(&error) => {
            owner.recovery_marker.preserve();
            Err(error).context(
                "WPR start failed after the control process launched; preserved the recovery \
                 marker because the host trace state may have changed",
            )
        }
        Err(error) if stale => Err(error).context(
            "WPR start failed while a protected stale-recovery marker exists; \
             refusing to cancel an unverified WPR session",
        ),
        Err(error) => Err(error),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StopDisposition {
    Trace,
    Analyze,
    Discard,
}

fn read_attach_handles_polling(
    pipe: &mut std::fs::File,
    deadline: Instant,
    mut owner_exited: impl FnMut() -> Result<bool>,
) -> Result<(usize, usize)> {
    let mut payload = [0u8; ATTACH_HANDLES_LEN];
    let mut offset = 0;
    while offset < payload.len() {
        if Instant::now() >= deadline {
            anyhow::bail!("timed out receiving guarded WPR sandbox attach handles");
        }
        if owner_exited()? {
            anyhow::bail!("guarded PLM owner exited during sandbox handle attachment");
        }
        match pipe_state(pipe)? {
            PipeState::Empty => std::thread::sleep(TRANSFER_POLL_INTERVAL),
            PipeState::Closed(error) => anyhow::bail!(
                "guarded PLM control pipe closed during sandbox handle attachment \
                 (PeekNamedPipe error {error})"
            ),
            PipeState::Data(available) => {
                let amount = (payload.len() - offset).min(available as usize);
                let read = pipe
                    .read(&mut payload[offset..offset + amount])
                    .context("failed to read guarded WPR sandbox attach handles")?;
                if read == 0 {
                    std::thread::sleep(TRANSFER_POLL_INTERVAL);
                } else {
                    offset += read;
                }
            }
        }
    }
    read_attach_handles(&mut payload.as_slice())
        .context("invalid guarded WPR sandbox attach handles")
}

fn run_guarded_stop(
    pipe: &mut std::fs::File,
    owner: &mut GuardedOwner,
    disposition: StopDisposition,
) -> Result<()> {
    let result = run_guarded_stop_with_stopped(pipe, owner, disposition);
    if let Err(error) = result {
        owner.preserve_after_start_error();
        write_error_response(pipe, &error)?;
        return Err(error);
    }
    Ok(())
}

fn run_guarded_stop_with_stopped(
    pipe: &mut std::fs::File,
    owner: &mut GuardedOwner,
    disposition: StopDisposition,
) -> Result<()> {
    crate::wpr_path::verify_wpr_present().map_err(anyhow::Error::msg)?;
    let scratch = SecureScratch::new()?;
    run_monitored_wpr_stop(pipe, owner, scratch.trace_path())?;
    owner.mark_stopped()?;
    write_header(pipe, ResponseKind::Stopped, 0)
        .and_then(|_| pipe.flush())
        .context("failed to return elevated PLM WPR-stopped milestone")?;
    match disposition {
        StopDisposition::Discard => write_header(pipe, ResponseKind::Success, 0)
            .and_then(|_| pipe.flush())
            .context("failed to return elevated PLM discard success"),
        StopDisposition::Analyze => {
            let membership = owner.finish_job_tracking()?;
            write_analysis_response(pipe, &scratch, &membership)
        }
        StopDisposition::Trace => write_trace_response(pipe, &scratch),
    }
}

fn run_monitored_wpr_stop(
    _pipe: &mut std::fs::File,
    owner: &mut GuardedOwner,
    trace_path: &Path,
) -> Result<()> {
    owner.recovery_marker.preserve();
    let mut command = crate::wpr_path::wpr_command();
    let resolved = command.get_program().to_string_lossy().into_owned();
    command.arg("-stop").arg(trace_path);
    let result = crate::start::run_wpr_command(command, "stop", &resolved, WAIT_TIMEOUT_DURATION);
    let lifecycle = &mut owner.lifecycle;
    let recovery_marker = &mut owner.recovery_marker;
    let _output = handle_wpr_stop_result(result, lifecycle, || recovery_marker.preserve())?;
    owner.recovery_marker.recovered();
    Ok(())
}

fn handle_wpr_stop_result(
    result: Result<std::process::Output>,
    lifecycle: &mut GuardLifecycle,
    preserve_marker: impl FnOnce(),
) -> Result<std::process::Output> {
    match result {
        Ok(output) if output.status.success() => Ok(output),
        Ok(output) => {
            lifecycle.defer_cleanup();
            preserve_marker();
            Err(crate::start::describe_wpr_failure("stop", &output))
        }
        Err(error) => {
            lifecycle.defer_cleanup();
            preserve_marker();
            Err(error).context("wpr -stop failed; deferred cleanup to the next guardian")
        }
    }
}

fn write_error_response(pipe: &mut std::fs::File, error: &anyhow::Error) -> Result<()> {
    let message = format!("{error:#}");
    let bytes = message.as_bytes();
    let len = (bytes.len() as u64).min(MAX_ERROR_BYTES);
    write_header(pipe, ResponseKind::Error, len)
        .and_then(|_| pipe.write_all(&bytes[..len as usize]))
        .and_then(|_| pipe.flush())
        .context("failed to return guarded PLM error over the pipe")
}

fn run_start() -> Result<()> {
    crate::wpr_path::verify_wpr_present().map_err(anyhow::Error::msg)?;
    let scratch = SecureScratch::new()?;
    let profile_guard: ProfileGuard =
        scratch.write_and_seal_profile(crate::profile_gen::EMBEDDED_WPRP.as_bytes())?;
    crate::start::start_plm_trace(scratch.profile_path())?;
    drop(profile_guard);
    drop(scratch);
    Ok(())
}

fn write_trace_response(pipe: &mut std::fs::File, scratch: &SecureScratch) -> Result<()> {
    let (mut trace_file, len) = scratch.open_trace()?;
    if len > MAX_TRACE_BYTES {
        anyhow::bail!(
            "captured ETL is {len} bytes, exceeding the {} byte transfer limit",
            MAX_TRACE_BYTES
        );
    }

    write_header(pipe, ResponseKind::Trace, len)?;
    copy_exact_len(&mut trace_file, pipe, len)?;
    pipe.flush().context("failed to flush elevated PLM trace")
}

fn write_analysis_response(
    pipe: &mut std::fs::File,
    scratch: &SecureScratch,
    membership: &JobMembershipSnapshot,
) -> Result<()> {
    let analysis = EtlDenialAnalyzer
        .analyze_for_job_membership(scratch.trace_path(), membership)
        .context("failed to decode guarded WPR trace for the sandbox process tree")?;
    let payload =
        serde_json::to_vec(&analysis).context("failed to serialize guarded WPR analysis")?;
    let len = payload.len() as u64;
    if len > MAX_ANALYSIS_BYTES {
        anyhow::bail!(
            "guarded WPR analysis is {len} bytes, exceeding the {MAX_ANALYSIS_BYTES} byte limit"
        );
    }
    write_header(pipe, ResponseKind::Analysis, len)?;
    pipe.write_all(&payload)?;
    pipe.flush().context("failed to flush guarded WPR analysis")
}

fn copy_exact_len(reader: &mut impl Read, writer: &mut impl Write, len: u64) -> Result<()> {
    let copied = std::io::copy(&mut reader.take(len), writer)
        .context("failed to transfer elevated PLM trace")?;
    if copied != len {
        anyhow::bail!(
            "elevated PLM trace ended after {copied} bytes, before the expected {len} bytes"
        );
    }
    Ok(())
}

fn authenticate_server(pipe: &std::fs::File, expected_pid: u32) -> Result<OwnedHandle> {
    let mut actual_pid = 0u32;
    unsafe { GetNamedPipeServerProcessId(HANDLE(pipe.as_raw_handle()), &mut actual_pid) }
        .context("GetNamedPipeServerProcessId failed")?;
    if actual_pid != expected_pid {
        anyhow::bail!(
            "PLM control pipe server PID mismatch: expected {expected_pid}, got {actual_pid}"
        );
    }

    let owner = unsafe {
        OpenProcess(
            PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE,
            false,
            actual_pid,
        )
    }
    .context("failed to bind guarded PLM owner process after pipe authentication")?;
    let owner = OwnedHandle(owner);
    validate_same_requesting_user(owner.0)?;
    Ok(owner)
}

fn validate_same_requesting_user(owner: HANDLE) -> Result<()> {
    let owner_sid = process_user_sid(owner).context("failed to resolve guarded PLM owner SID")?;
    let elevated_sid = process_user_sid(unsafe { GetCurrentProcess() })
        .context("failed to resolve elevated PLM guardian SID")?;
    validate_matching_sids(&owner_sid, &elevated_sid)
}

fn validate_matching_sids(owner_sid: &[u8], elevated_sid: &[u8]) -> Result<()> {
    if owner_sid != elevated_sid {
        anyhow::bail!(
            "guarded PLM requires the invoking and elevating Windows identities to match; \
             over-the-shoulder elevation is rejected because the system-wide ETL is returned \
             to the invoking user"
        );
    }
    Ok(())
}

fn process_user_sid(process: HANDLE) -> Result<Vec<u8>> {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }
        .context("OpenProcessToken failed")?;
    let token = OwnedHandle(token);
    let mut required = 0u32;
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut required) };
    if required == 0 {
        anyhow::bail!("GetTokenInformation(TokenUser) returned no required size");
    }
    let mut buffer = vec![0u8; required as usize];
    unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            required,
            &mut required,
        )
    }
    .context("GetTokenInformation(TokenUser) failed")?;
    let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let sid_len = unsafe { GetLengthSid(token_user.User.Sid) } as usize;
    if sid_len == 0 {
        anyhow::bail!("GetLengthSid returned zero for guarded PLM identity");
    }
    Ok(unsafe { std::slice::from_raw_parts(token_user.User.Sid.0.cast::<u8>(), sid_len) }.to_vec())
}

fn pipe_state(pipe: &std::fs::File) -> Result<PipeState> {
    let mut available = 0u32;
    match unsafe {
        PeekNamedPipe(
            HANDLE(pipe.as_raw_handle()),
            None,
            0,
            None,
            Some(&mut available),
            None,
        )
    } {
        Ok(()) if available == 0 => Ok(PipeState::Empty),
        Ok(()) => Ok(PipeState::Data(available)),
        Err(error) => {
            let raw = (error.code().0 as u32) & 0xffff;
            if raw == ERROR_NO_DATA.0 {
                Ok(PipeState::Empty)
            } else if raw == ERROR_BROKEN_PIPE.0 || raw == ERROR_PIPE_NOT_CONNECTED.0 {
                Ok(PipeState::Closed(raw))
            } else {
                Err(error).context("failed to inspect guarded PLM control pipe")
            }
        }
    }
}

fn is_process_elevated() -> Result<bool> {
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
        .context("OpenProcessToken failed")?;
    let token = OwnedHandle(token);
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0u32;
    unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            Some(std::ptr::from_mut(&mut elevation).cast()),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    }
    .context("GetTokenInformation(TokenElevation) failed")?;
    Ok(elevation.TokenIsElevated != 0)
}

fn read_response(
    pipe: &mut std::fs::File,
    process: HANDLE,
    operation: Operation,
    trace_destination: Option<&Path>,
    deadline: Instant,
    on_stopped: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let first_header = read_header_polling(pipe, process, deadline)?;
    let (header, stopped) = accept_response_headers(first_header, operation, on_stopped, || {
        read_header_polling(pipe, process, deadline)
    })?;
    match header.kind {
        ResponseKind::Success if operation != Operation::Stop => Ok(()),
        ResponseKind::Success => anyhow::bail!("elevated stop returned no ETL payload"),
        ResponseKind::Trace if operation == Operation::Stop && stopped => {
            let destination = trace_destination.context("missing unelevated trace destination")?;
            let parent = destination.parent().unwrap_or_else(|| Path::new("."));
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create trace output directory {}",
                    parent.display()
                )
            })?;
            let mut temporary = tempfile::NamedTempFile::new_in(parent).with_context(|| {
                format!(
                    "failed to create unelevated trace temp file in {}",
                    parent.display()
                )
            })?;
            copy_exact_polling(
                pipe,
                temporary.as_file_mut(),
                process,
                header.payload_len,
                deadline,
            )?;
            temporary
                .as_file_mut()
                .sync_all()
                .context("failed to flush unelevated trace temp file")?;
            temporary
                .persist(destination)
                .map_err(|error| error.error)
                .with_context(|| {
                    format!("failed to persist trace output {}", destination.display())
                })?;
            Ok(())
        }
        ResponseKind::Trace if operation == Operation::Stop => {
            anyhow::bail!("elevated stop returned ETL before the WPR-stopped milestone")
        }
        ResponseKind::Trace => anyhow::bail!("unexpected ETL payload for elevated {operation:?}"),
        ResponseKind::Analysis => {
            anyhow::bail!("unexpected filtered-analysis payload for elevated {operation:?}")
        }
        ResponseKind::Error => {
            let mut message = vec![0u8; header.payload_len as usize];
            read_exact_polling(pipe, &mut message, process, deadline)?;
            anyhow::bail!(
                "elevated PLM {operation:?} failed: {}",
                String::from_utf8_lossy(&message)
            )
        }
        ResponseKind::Stopped => unreachable!("duplicate stopped milestone handled above"),
    }
}

fn read_analysis_response(
    pipe: &mut std::fs::File,
    process: HANDLE,
    deadline: Instant,
    on_stopped: impl FnOnce() -> Result<()>,
) -> Result<AnalysisResult> {
    let first_header = read_header_polling(pipe, process, deadline)?;
    let (header, stopped) =
        accept_response_headers(first_header, Operation::Stop, on_stopped, || {
            read_header_polling(pipe, process, deadline)
        })?;
    match header.kind {
        ResponseKind::Analysis if stopped => {
            let mut payload = vec![0u8; header.payload_len as usize];
            read_exact_polling(pipe, &mut payload, process, deadline)?;
            serde_json::from_slice(&payload)
                .context("elevated guarded WPR returned invalid filtered analysis")
        }
        ResponseKind::Analysis => {
            anyhow::bail!("elevated stop returned analysis before the WPR-stopped milestone")
        }
        ResponseKind::Error => {
            let mut message = vec![0u8; header.payload_len as usize];
            read_exact_polling(pipe, &mut message, process, deadline)?;
            anyhow::bail!(
                "elevated guarded WPR analysis failed: {}",
                String::from_utf8_lossy(&message)
            )
        }
        ResponseKind::Trace => {
            anyhow::bail!("elevated guarded WPR analysis returned a raw ETL payload")
        }
        ResponseKind::Success => {
            anyhow::bail!("elevated guarded WPR analysis returned no payload")
        }
        ResponseKind::Stopped => unreachable!("duplicate stopped milestone handled above"),
    }
}

fn accept_response_headers(
    first_header: crate::elevated_protocol::ResponseHeader,
    operation: Operation,
    on_stopped: impl FnOnce() -> Result<()>,
    read_next: impl FnOnce() -> Result<crate::elevated_protocol::ResponseHeader>,
) -> Result<(crate::elevated_protocol::ResponseHeader, bool)> {
    if first_header.kind == ResponseKind::Stopped {
        if operation != Operation::Stop && operation != Operation::Discard {
            anyhow::bail!("unexpected WPR-stopped milestone for elevated {operation:?}");
        }
        on_stopped().context("failed to handle PLM WPR-stopped milestone")?;
        let header = read_next()?;
        if header.kind == ResponseKind::Stopped {
            anyhow::bail!("elevated stop returned a duplicate WPR-stopped milestone");
        }
        Ok((header, true))
    } else {
        Ok((first_header, false))
    }
}

fn read_header_polling(
    pipe: &mut std::fs::File,
    process: HANDLE,
    deadline: Instant,
) -> Result<crate::elevated_protocol::ResponseHeader> {
    let mut bytes = [0u8; HEADER_LEN];
    read_exact_polling(pipe, &mut bytes, process, deadline)?;
    read_header(&mut bytes.as_slice()).context("invalid elevated PLM response header")
}

fn copy_exact_polling(
    pipe: &mut std::fs::File,
    output: &mut impl Write,
    process: HANDLE,
    mut remaining: u64,
    deadline: Instant,
) -> Result<()> {
    let mut buffer = vec![0u8; 1024 * 1024];
    while remaining != 0 {
        let amount = remaining.min(buffer.len() as u64) as usize;
        let read = read_some_polling(pipe, &mut buffer[..amount], process, deadline)?;
        if read == 0 {
            anyhow::bail!("elevated PLM pipe closed before the ETL transfer completed");
        }
        output
            .write_all(&buffer[..read])
            .context("failed to write unelevated ETL output")?;
        remaining -= read as u64;
    }
    Ok(())
}

fn read_exact_polling(
    pipe: &mut std::fs::File,
    mut buffer: &mut [u8],
    process: HANDLE,
    deadline: Instant,
) -> Result<()> {
    while !buffer.is_empty() {
        let read = read_some_polling(pipe, buffer, process, deadline)?;
        if read == 0 {
            anyhow::bail!("elevated PLM pipe closed before the response completed");
        }
        buffer = &mut buffer[read..];
    }
    Ok(())
}

fn read_some_polling(
    pipe: &mut std::fs::File,
    buffer: &mut [u8],
    process: HANDLE,
    deadline: Instant,
) -> Result<usize> {
    loop {
        match pipe_state(pipe)? {
            PipeState::Empty => {
                ensure_child_running(process, deadline)?;
                std::thread::sleep(TRANSFER_POLL_INTERVAL);
            }
            PipeState::Closed(_) => return Ok(0),
            PipeState::Data(available) => {
                let amount = buffer.len().min(available as usize);
                let read = pipe
                    .read(&mut buffer[..amount])
                    .context("failed to read elevated PLM response")?;
                if read != 0 {
                    return Ok(read);
                }
                ensure_child_running(process, deadline)?;
                std::thread::sleep(TRANSFER_POLL_INTERVAL);
            }
        }
    }
}

fn connect_authenticated_client(
    pipe: HANDLE,
    process: HANDLE,
    expected_pid: u32,
    deadline: Instant,
) -> Result<()> {
    loop {
        match unsafe { ConnectNamedPipe(pipe, None) } {
            Ok(()) => break,
            Err(error) => {
                let raw = (error.code().0 as u32) & 0xffff;
                if raw == ERROR_PIPE_CONNECTED.0 {
                    break;
                }
                if raw != ERROR_PIPE_LISTENING.0 {
                    return Err(error).context("ConnectNamedPipe failed");
                }
                ensure_child_running(process, deadline)?;
                std::thread::sleep(POLL_INTERVAL);
            }
        }
    }
    let mut actual_pid = 0u32;
    unsafe { GetNamedPipeClientProcessId(pipe, &mut actual_pid) }
        .context("GetNamedPipeClientProcessId failed")?;
    if actual_pid != expected_pid {
        unsafe {
            let _ = TerminateProcess(process, 1);
        }
        anyhow::bail!(
            "PLM control pipe client PID mismatch: expected {expected_pid}, got {actual_pid}"
        );
    }
    Ok(())
}

fn ensure_child_running(process: HANDLE, deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        anyhow::bail!("timed out waiting for elevated PLM response");
    }
    match unsafe { WaitForSingleObject(process, 0) } {
        WAIT_TIMEOUT => Ok(()),
        WAIT_OBJECT_0 => anyhow::bail!("elevated PLM child exited before completing its response"),
        WAIT_FAILED => anyhow::bail!("WaitForSingleObject failed for elevated PLM child"),
        other => anyhow::bail!("unexpected elevated PLM child wait result {}", other.0),
    }
}

fn create_pipe(pipe_name: &str) -> Result<HANDLE> {
    let wide = to_wide(pipe_name);
    const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
    let open_mode = FILE_FLAGS_AND_ATTRIBUTES(PIPE_ACCESS_DUPLEX) | FILE_FLAG_FIRST_PIPE_INSTANCE;
    let pipe = unsafe {
        CreateNamedPipeW(
            PCWSTR(wide.as_ptr()),
            open_mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            1024 * 1024,
            1024 * 1024,
            0,
            None,
        )
    };
    if pipe == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error()).context(
            "CreateNamedPipeW failed (the unique first-instance pipe may have been squatted)",
        );
    }
    Ok(pipe)
}

fn launch_elevated_child(
    executable: &Path,
    operation: Operation,
    pipe_name: &str,
    owner_pid: Option<u32>,
) -> Result<HANDLE> {
    let working_directory = executable
        .parent()
        .context("elevated PLM executable path has no parent directory")?;
    let parameters = build_internal_parameters(
        operation,
        pipe_name,
        unsafe { GetCurrentProcessId() },
        owner_pid,
    );
    let verb = to_wide("runas");
    let executable = to_wide(executable.as_os_str());
    let parameters = to_wide(parameters);
    let working_directory = to_wide(working_directory.as_os_str());
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(executable.as_ptr()),
        lpParameters: PCWSTR(parameters.as_ptr()),
        lpDirectory: PCWSTR(working_directory.as_ptr()),
        nShow: SW_HIDE,
        ..Default::default()
    };
    if let Err(error) = unsafe { ShellExecuteExW(&mut info) } {
        let raw = (error.code().0 as u32) & 0xffff;
        if raw == ERROR_CANCELLED.0 {
            anyhow::bail!("UAC prompt was cancelled");
        }
        return Err(error).context("ShellExecuteExW(runas) failed for PLM control child");
    }
    if info.hProcess.is_invalid() {
        anyhow::bail!("ShellExecuteExW returned no elevated PLM process handle");
    }
    Ok(info.hProcess)
}

fn build_internal_parameters(
    operation: Operation,
    pipe_name: &str,
    server_pid: u32,
    owner_pid: Option<u32>,
) -> String {
    let mut parameters = format!(
        "__elevated {} --pipe-name {} --server-pid {server_pid}",
        operation.as_arg(),
        quote_arg(pipe_name)
    );
    if let Some(owner_pid) = owner_pid {
        parameters.push_str(&format!(" --owner-pid {owner_pid}"));
    }
    parameters
}

fn new_pipe_name() -> Result<String> {
    let mut random = [0u8; 16];
    getrandom::getrandom(&mut random)
        .map_err(|error| anyhow::anyhow!("failed to generate PLM pipe nonce: {error}"))?;
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!("{PIPE_PREFIX}{suffix}"))
}

fn validate_pipe_name(pipe_name: &str) -> Result<()> {
    let Some(suffix) = pipe_name.strip_prefix(PIPE_PREFIX) else {
        anyhow::bail!("invalid PLM control pipe prefix");
    };
    if suffix.len() != 32 || !suffix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        anyhow::bail!("invalid PLM control pipe nonce");
    }
    Ok(())
}

fn quote_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"', '\n']) {
        return arg.to_string();
    }
    let mut output = String::with_capacity(arg.len() + 2);
    output.push('"');
    let mut backslashes = 0usize;
    for character in arg.chars() {
        if character == '\\' {
            backslashes += 1;
        } else {
            if character == '"' {
                output.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
            } else {
                output.extend(std::iter::repeat_n('\\', backslashes));
            }
            backslashes = 0;
            output.push(character);
        }
    }
    output.extend(std::iter::repeat_n('\\', backslashes * 2));
    output.push('"');
    output
}

fn to_wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value
        .as_ref()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::process::ExitStatusExt;

    #[test]
    fn guarded_start_requires_readiness_before_start() {
        let mut lifecycle = GuardLifecycle::new();

        assert_eq!(lifecycle.on_start_succeeded(), GuardAction::RejectStart);
        assert_eq!(lifecycle.state, GuardState::AwaitingReadiness);
        assert_eq!(lifecycle.ready(true), GuardAction::None);
        assert_eq!(lifecycle.on_start_succeeded(), GuardAction::None);
        assert_eq!(lifecycle.state, GuardState::Armed);
    }

    #[test]
    fn owner_already_dead_rejects_start_without_cleanup() {
        let mut lifecycle = GuardLifecycle::new();

        assert_eq!(lifecycle.ready(false), GuardAction::RejectStart);
        assert_eq!(lifecycle.state, GuardState::OwnerExitedDuringStart);
        assert_eq!(lifecycle.on_pipe_break(), GuardAction::None);
    }

    #[test]
    fn owner_death_during_start_preserves_recovery_state() {
        let mut lifecycle = GuardLifecycle::new();
        assert_eq!(lifecycle.ready(true), GuardAction::None);
        assert_eq!(lifecycle.on_owner_exit(), GuardAction::None);
        assert_eq!(lifecycle.on_start_succeeded(), GuardAction::Preserve);
        assert_eq!(lifecycle.state, GuardState::Abandoned);
    }

    #[test]
    fn owner_death_after_start_preserves_recovery_state_once() {
        let mut lifecycle = armed_lifecycle();

        assert_eq!(lifecycle.on_owner_exit(), GuardAction::Preserve);
        assert_eq!(lifecycle.on_owner_exit(), GuardAction::None);
    }

    #[test]
    fn stopped_state_prevents_abandonment_and_post_stop_interference() {
        let mut lifecycle = armed_lifecycle();

        assert_eq!(lifecycle.disarm(), GuardAction::None);
        assert_eq!(lifecycle.on_owner_exit(), GuardAction::None);
        assert_eq!(lifecycle.on_pipe_break(), GuardAction::None);
        assert_eq!(lifecycle.state, GuardState::Disarmed);
    }

    #[test]
    fn stop_failure_leaves_guard_armed() {
        let mut lifecycle = armed_lifecycle();

        // A failed stop never marks the lifecycle stopped.
        assert_eq!(lifecycle.state, GuardState::Armed);
        assert_eq!(lifecycle.on_pipe_break(), GuardAction::Preserve);
    }

    #[test]
    fn uncertain_stop_defers_cleanup_without_late_interference() {
        let mut lifecycle = armed_lifecycle();

        lifecycle.defer_cleanup();
        assert_eq!(lifecycle.state, GuardState::Abandoned);
        assert_eq!(lifecycle.abandon_started_trace(), GuardAction::None);
        assert_eq!(lifecycle.on_pipe_break(), GuardAction::None);
    }

    #[test]
    fn wpr_stop_failures_abandon_lifecycle_and_preserve_marker() {
        let failures = [
            Err(anyhow::anyhow!("simulated stop failure")),
            Ok(std::process::Output {
                status: std::process::ExitStatus::from_raw(42),
                stdout: b"stop stdout".to_vec(),
                stderr: b"stop stderr".to_vec(),
            }),
        ];

        for failure in failures {
            let mut lifecycle = GuardLifecycle::new();
            assert_eq!(lifecycle.ready(true), GuardAction::None);
            assert_eq!(lifecycle.on_start_succeeded(), GuardAction::None);
            let marker_preserved = std::cell::Cell::new(false);

            handle_wpr_stop_result(failure, &mut lifecycle, || marker_preserved.set(true))
                .unwrap_err();

            assert_eq!(lifecycle.state, GuardState::Abandoned);
            assert!(marker_preserved.get());
        }
    }

    #[test]
    fn stopped_milestone_callback_precedes_second_header_read() {
        use crate::elevated_protocol::ResponseHeader;

        let events = RefCell::new(Vec::new());
        let (header, stopped) = accept_response_headers(
            ResponseHeader {
                kind: ResponseKind::Stopped,
                payload_len: 0,
            },
            Operation::Stop,
            || {
                events.borrow_mut().push("stopped");
                Ok(())
            },
            || {
                events.borrow_mut().push("trace");
                Ok(ResponseHeader {
                    kind: ResponseKind::Trace,
                    payload_len: 42,
                })
            },
        )
        .unwrap();
        assert!(stopped);
        assert_eq!(header.kind, ResponseKind::Trace);
        assert_eq!(*events.borrow(), ["stopped", "trace"]);
    }

    #[test]
    fn trace_before_stopped_is_not_accepted_as_a_stopped_response() {
        use crate::elevated_protocol::ResponseHeader;

        let callback_called = std::cell::Cell::new(false);
        let (header, stopped) = accept_response_headers(
            ResponseHeader {
                kind: ResponseKind::Trace,
                payload_len: 42,
            },
            Operation::Stop,
            || {
                callback_called.set(true);
                Ok(())
            },
            || anyhow::bail!("must not read another header"),
        )
        .unwrap();
        assert!(!stopped);
        assert_eq!(header.kind, ResponseKind::Trace);
        assert!(!callback_called.get());
    }

    #[test]
    fn stopped_callback_failure_prevents_second_header_read() {
        use crate::elevated_protocol::ResponseHeader;

        let read_next = std::cell::Cell::new(false);
        let error = accept_response_headers(
            ResponseHeader {
                kind: ResponseKind::Stopped,
                payload_len: 0,
            },
            Operation::Stop,
            || anyhow::bail!("stopped milestone handling failed"),
            || {
                read_next.set(true);
                Ok(ResponseHeader {
                    kind: ResponseKind::Trace,
                    payload_len: 42,
                })
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("WPR-stopped milestone"));
        assert!(!read_next.get());
    }

    #[test]
    fn stopped_milestone_is_rejected_for_non_stop_operations() {
        use crate::elevated_protocol::ResponseHeader;

        let error = accept_response_headers(
            ResponseHeader {
                kind: ResponseKind::Stopped,
                payload_len: 0,
            },
            Operation::Start,
            || Ok(()),
            || anyhow::bail!("must not read another header"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("unexpected WPR-stopped"));
    }

    #[test]
    fn duplicate_stopped_milestone_is_rejected() {
        use crate::elevated_protocol::ResponseHeader;

        let error = accept_response_headers(
            ResponseHeader {
                kind: ResponseKind::Stopped,
                payload_len: 0,
            },
            Operation::Stop,
            || Ok(()),
            || {
                Ok(ResponseHeader {
                    kind: ResponseKind::Stopped,
                    payload_len: 0,
                })
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("duplicate"));
    }

    #[test]
    fn pipe_break_preserves_recovery_state_once() {
        let mut lifecycle = armed_lifecycle();

        assert_eq!(lifecycle.on_pipe_break(), GuardAction::Preserve);
        assert_eq!(lifecycle.on_pipe_break(), GuardAction::None);
    }

    #[test]
    fn control_protocol_accepts_only_supported_stop_modes() {
        assert_eq!(
            parse_guard_control(CONTROL_STOP).unwrap(),
            GuardControl::Stop
        );
        assert_eq!(
            parse_guard_control(CONTROL_STOP_AND_ANALYZE).unwrap(),
            GuardControl::StopAndAnalyze
        );
        assert_eq!(
            parse_guard_control(CONTROL_STOP_AND_DISCARD).unwrap(),
            GuardControl::StopAndDiscard
        );
        assert_eq!(
            parse_guard_control(CONTROL_ATTACH_JOB).unwrap(),
            GuardControl::AttachJob
        );
        for invalid in [0, 5, u8::MAX] {
            assert!(parse_guard_control(invalid).is_err());
        }
    }

    #[test]
    fn completed_processes_count_toward_guardian_tracking_limit() {
        fn fake_attestation(pid: u32) -> Result<(OwnedHandle, u64)> {
            Ok((OwnedHandle(HANDLE::default()), u64::from(pid) + 1))
        }

        let mut state = ProcessTrackerState::new(1, 0);
        for pid in 1..MAX_JOB_PROCESS_LIFETIMES as u32 {
            state.process_started(pid, 2, || fake_attestation(pid));
            state.process_exited(pid, 3);
        }

        state.process_started(u32::MAX, 4, || fake_attestation(u32::MAX));

        assert!(state.active.is_empty());
        assert_eq!(state.processes.len(), MAX_JOB_PROCESS_LIFETIMES - 1);
        assert!(state.error.as_deref().is_some_and(|error| {
            error.contains("exceeded") && error.contains(&MAX_JOB_PROCESS_LIFETIMES.to_string())
        }));
    }

    #[test]
    fn terminal_tracker_failure_skips_further_process_attestation() {
        let mut state = ProcessTrackerState::new(1, 0);
        state.fail("terminal tracker failure");
        let attested = std::cell::Cell::new(false);

        state.process_started(1, 2, || {
            attested.set(true);
            Ok((OwnedHandle(HANDLE::default()), 2))
        });

        assert!(!attested.get());
        assert!(state.processes.is_empty());
        assert_eq!(state.error.as_deref(), Some("terminal tracker failure"));
    }

    #[test]
    fn tracker_failure_terminates_the_attested_job() {
        use windows::Win32::System::JobObjects::{AssignProcessToJobObject, CreateJobObjectW};

        let job = OwnedHandle(unsafe { CreateJobObjectW(None, PCWSTR::null()) }.unwrap());
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "ping -n 999 127.0.0.1 >nul"])
            .spawn()
            .unwrap();
        unsafe { AssignProcessToJobObject(job.0, HANDLE(child.as_raw_handle())) }.unwrap();

        let state = Arc::new(Mutex::new(ProcessTrackerState::new(1, child.id())));
        fail_tracker_and_terminate_job(job.0, &state, "terminal tracker failure".to_string());

        assert_eq!(
            unsafe { WaitForSingleObject(HANDLE(child.as_raw_handle()), 5_000) },
            WAIT_OBJECT_0,
            "tracker failure must terminate the sandbox job promptly"
        );
        child.wait().unwrap();
        assert!(state
            .lock()
            .unwrap()
            .error
            .as_deref()
            .is_some_and(|error| error.contains("terminal tracker failure")));
    }

    #[test]
    fn root_notifications_are_optional_and_not_double_counted() {
        for include_start in [false, true] {
            let mut state = ProcessTrackerState::new(1, 42);
            if include_start {
                state.process_started(42, 2, || Ok((OwnedHandle(HANDLE::default()), 1)));
            }
            state.process_exited(42, 3);
            state.all_processes_exited(4);

            assert!(state.processes.is_empty());
            assert_eq!(state.notification_sequence, 0);
            assert!(state.active.is_empty());
            assert_eq!(state.active_process_zero_filetime, Some(4));
        }
    }

    #[test]
    fn guardian_attests_root_handle_and_reconciles_optional_root_notifications() {
        use windows::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, TerminateJobObject,
        };

        let job = OwnedHandle(unsafe { CreateJobObjectW(None, PCWSTR::null()) }.unwrap());
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "ping -n 999 127.0.0.1 >nul"])
            .spawn()
            .unwrap();
        unsafe { AssignProcessToJobObject(job.0, HANDLE(child.as_raw_handle())) }.unwrap();

        let tracker = JobProcessTracker::duplicate_and_attach(
            unsafe { GetCurrentProcess() },
            job.0 .0 as usize,
            child.as_raw_handle() as usize,
        )
        .unwrap();
        unsafe { TerminateJobObject(job.0, 1) }.unwrap();
        child.wait().unwrap();

        let membership = tracker.finish().unwrap();
        assert_eq!(membership.root_process.pid, child.id());
        assert!(membership.processes.is_empty());
        assert_eq!(membership.total_processes, 1);
        assert!(membership.root_process.end_filetime >= membership.root_process.start_filetime);
        assert!(membership.completed_filetime >= membership.attached_filetime);
    }

    #[test]
    fn guardian_rejects_root_handle_from_a_different_job() {
        use windows::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, TerminateJobObject,
        };

        let actual_job = OwnedHandle(unsafe { CreateJobObjectW(None, PCWSTR::null()) }.unwrap());
        let unrelated_job = OwnedHandle(unsafe { CreateJobObjectW(None, PCWSTR::null()) }.unwrap());
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "ping -n 999 127.0.0.1 >nul"])
            .spawn()
            .unwrap();
        unsafe { AssignProcessToJobObject(actual_job.0, HANDLE(child.as_raw_handle())) }.unwrap();

        let error = match JobProcessTracker::duplicate_and_attach(
            unsafe { GetCurrentProcess() },
            unrelated_job.0 .0 as usize,
            child.as_raw_handle() as usize,
        ) {
            Ok(_) => panic!("a root process from another job must be rejected"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("not in the supplied job"));
        unsafe { TerminateJobObject(actual_job.0, 1) }.unwrap();
        child.wait().unwrap();
    }

    fn connected_pipe_pair() -> (std::fs::File, std::fs::File) {
        let pipe_name = new_pipe_name().unwrap();
        let server = OwnedHandle(create_pipe(&pipe_name).unwrap());
        let client_name = pipe_name.clone();
        let client_thread = std::thread::spawn(move || {
            for _ in 0..100 {
                match std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&client_name)
                {
                    Ok(client) => return client,
                    Err(_) => std::thread::sleep(POLL_INTERVAL),
                }
            }
            panic!("client did not connect to test pipe");
        });

        for _ in 0..100 {
            match unsafe { ConnectNamedPipe(server.0, None) } {
                Ok(()) => break,
                Err(error) => {
                    let raw = (error.code().0 as u32) & 0xffff;
                    if raw == ERROR_PIPE_CONNECTED.0 {
                        break;
                    }
                    assert_eq!(raw, ERROR_PIPE_LISTENING.0);
                    std::thread::sleep(POLL_INTERVAL);
                }
            }
        }

        let client = client_thread.join().unwrap();
        let raw = server.0 .0;
        std::mem::forget(server);
        let server_file = unsafe { std::fs::File::from_raw_handle(raw) };
        (client, server_file)
    }

    #[test]
    fn empty_connected_pipe_is_not_reported_as_closed() {
        let (mut client, mut server_file) = connected_pipe_pair();
        assert_eq!(pipe_state(&client).unwrap(), PipeState::Empty);

        server_file.write_all(&[CONTROL_STOP]).unwrap();
        server_file.flush().unwrap();
        assert_eq!(pipe_state(&client).unwrap(), PipeState::Data(1));

        let mut control = [0u8; 1];
        client.read_exact(&mut control).unwrap();
        assert_eq!(control[0], CONTROL_STOP);

        drop(server_file);
        for _ in 0..100 {
            if matches!(pipe_state(&client).unwrap(), PipeState::Closed(_)) {
                return;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        panic!("closed test pipe remained connected");
    }

    #[test]
    fn pending_guardian_response_suppresses_a_new_control_byte() {
        let (mut client, mut server) = connected_pipe_pair();
        write_header(&mut server, ResponseKind::Stopped, 0).unwrap();
        server.flush().unwrap();

        send_control_unless_response_pending(&mut client, CONTROL_STOP_AND_ANALYZE).unwrap();

        assert_eq!(pipe_state(&server).unwrap(), PipeState::Empty);
        assert_eq!(
            read_header(&mut client).unwrap().kind,
            ResponseKind::Stopped
        );
    }

    #[test]
    fn unrelated_pending_response_does_not_suppress_a_control_byte() {
        let (mut client, mut server) = connected_pipe_pair();
        write_header(&mut server, ResponseKind::Success, 0).unwrap();
        server.flush().unwrap();

        let error = send_control_unless_response_pending(&mut client, CONTROL_STOP_AND_ANALYZE)
            .unwrap_err();

        assert!(error.to_string().contains("unexpected unsolicited"));
        assert_eq!(pipe_state(&server).unwrap(), PipeState::Empty);
    }

    #[test]
    fn empty_guardian_pipe_receives_the_requested_control_byte() {
        let (mut client, mut server) = connected_pipe_pair();

        send_control_unless_response_pending(&mut client, CONTROL_STOP_AND_ANALYZE).unwrap();

        let mut control = [0u8; 1];
        server.read_exact(&mut control).unwrap();
        assert_eq!(control[0], CONTROL_STOP_AND_ANALYZE);
    }

    #[test]
    fn partial_attach_payload_times_out_without_blocking() {
        let (mut client, mut server_file) = connected_pipe_pair();
        server_file.write_all(b"MXCATT01").unwrap();
        server_file.flush().unwrap();

        let started = Instant::now();
        let error =
            read_attach_handles_polling(&mut client, started + Duration::from_millis(25), || {
                Ok(false)
            })
            .expect_err("partial attach payload must time out");

        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    fn armed_lifecycle() -> GuardLifecycle {
        let mut lifecycle = GuardLifecycle::new();
        assert_eq!(lifecycle.ready(true), GuardAction::None);
        assert_eq!(lifecycle.on_start_succeeded(), GuardAction::None);
        lifecycle
    }

    #[test]
    fn validates_only_random_local_plm_pipe_names() {
        assert!(
            validate_pipe_name(r"\\.\pipe\mxc-plm-elevated-00112233445566778899aabbccddeeff")
                .is_ok()
        );
        for invalid in [
            r"\\server\pipe\mxc-plm-elevated-00112233445566778899aabbccddeeff",
            r"\\.\pipe\other-00112233445566778899aabbccddeeff",
            r"\\.\pipe\mxc-plm-elevated-short",
            r"\\.\pipe\mxc-plm-elevated-00112233445566778899aabbccddee/g",
        ] {
            assert!(validate_pipe_name(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn current_process_matches_its_own_requesting_identity() {
        validate_same_requesting_user(unsafe { GetCurrentProcess() }).unwrap();
    }

    #[test]
    fn different_requesting_identity_is_rejected() {
        let error = validate_matching_sids(&[1, 2, 3], &[1, 2, 4]).unwrap_err();

        assert!(error
            .to_string()
            .contains("invoking and elevating Windows identities to match"));
    }

    #[test]
    fn abandoning_session_accepts_clean_and_error_guardian_exits() {
        for expected_exit_code in [0, 42] {
            let mut child = std::process::Command::new("cmd.exe")
                .args(["/d", "/c", &format!("exit {expected_exit_code}")])
                .spawn()
                .unwrap();
            let handle = unsafe {
                OpenProcess(
                    PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                    false,
                    child.id(),
                )
            }
            .unwrap();
            let mut session = GuardedSession {
                pipe: None,
                process: OwnedHandle(handle),
                disarmed: false,
            };

            session.cancel().unwrap();
            assert!(session.disarmed);
            assert_eq!(child.wait().unwrap().code(), Some(expected_exit_code));
        }
    }

    #[test]
    fn cancel_confirms_guardian_exit_even_after_session_is_disarmed() {
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "ping.exe -n 2 127.0.0.1 >nul"])
            .spawn()
            .unwrap();
        assert!(child.try_wait().unwrap().is_none());
        let handle = unsafe {
            OpenProcess(
                PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                child.id(),
            )
        }
        .unwrap();
        let mut session = GuardedSession {
            pipe: None,
            process: OwnedHandle(handle),
            disarmed: true,
        };

        session.cancel().unwrap();

        assert!(child.try_wait().unwrap().is_some());
    }

    #[test]
    fn guarded_start_command_contains_no_filesystem_path_argument() {
        let pipe = r"\\.\pipe\mxc-plm-elevated-00112233445566778899aabbccddeeff";
        let parameters = build_internal_parameters(Operation::Start, pipe, 42, Some(84));
        assert!(parameters.starts_with("__elevated start"));
        assert!(parameters.contains("--pipe-name"));
        assert!(parameters.contains("--server-pid 42"));
        assert!(parameters.contains("--owner-pid 84"));
        assert!(!parameters.contains("trace-output"));
        assert!(!parameters.contains("wprp"));
        assert!(!parameters.contains("log-dir"));
        assert!(!parameters.contains("config-path"));
    }

    #[test]
    fn guarded_start_command_contains_only_pipe_and_pid_coordinates() {
        let pipe = r"\\.\pipe\mxc-plm-elevated-00112233445566778899aabbccddeeff";
        let parameters = build_internal_parameters(Operation::Start, pipe, 42, Some(84));
        assert!(parameters.contains("--server-pid 42"));
        assert!(parameters.contains("--owner-pid 84"));
        assert!(!parameters.contains("trace-output"));
        assert!(!parameters.contains("wprp"));
    }

    #[test]
    fn quotes_windows_arguments_without_losing_trailing_backslashes() {
        assert_eq!(quote_arg("plain"), "plain");
        assert_eq!(
            quote_arg(r"C:\path with spaces\"),
            r#""C:\path with spaces\\""#
        );
        assert_eq!(quote_arg(r#"a"b"#), r#""a\"b""#);
    }

    #[test]
    fn copies_exact_trace_length() {
        let mut input = std::io::Cursor::new(b"trace-and-trailing-data");
        let mut output = Vec::new();

        copy_exact_len(&mut input, &mut output, 5).unwrap();

        assert_eq!(output, b"trace");
        assert_eq!(input.position(), 5);
    }

    #[test]
    fn rejects_short_trace_copy() {
        let mut input = std::io::Cursor::new(b"short");
        let mut output = Vec::new();

        let error = copy_exact_len(&mut input, &mut output, 6).unwrap_err();

        assert!(error
            .to_string()
            .contains("ended after 5 bytes, before the expected 6 bytes"));
        assert_eq!(output, b"short");
    }
}
