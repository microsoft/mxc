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
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::AtomicIsize;
use std::time::{Duration, Instant};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_BROKEN_PIPE, ERROR_CANCELLED, ERROR_NO_DATA, ERROR_PIPE_CONNECTED,
    ERROR_PIPE_LISTENING, ERROR_PIPE_NOT_CONNECTED, HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Storage::FileSystem::{
    FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_FIRST_PIPE_INSTANCE,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
    PeekNamedPipe, PIPE_NOWAIT, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetExitCodeProcess, GetProcessId, OpenProcess,
    OpenProcessToken, TerminateProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE,
};
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};

use crate::elevated_protocol::{
    read_header, write_header, ResponseKind, HEADER_LEN, MAX_ERROR_BYTES, MAX_TRACE_BYTES,
};
use crate::secure_scratch::{ProfileGuard, RecoveryMarker, SecureScratch};

const PIPE_PREFIX: &str = r"\\.\pipe\mxc-plm-elevated-";
const WAIT_TIMEOUT_DURATION: Duration = Duration::from_secs(10 * 60);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const SW_HIDE: i32 = 0;
const HANDSHAKE_READY: u8 = 0xa5;
const CONTROL_STOP: u8 = 1;
static GUARDIAN_SINGLETON: AtomicIsize = AtomicIsize::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GuardControl {
    Stop,
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
        _ => anyhow::bail!("invalid guarded PLM control message {value}"),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Start,
    Stop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GuardAction {
    None,
    Cancel,
    RejectStart,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GuardState {
    AwaitingReadiness,
    Ready,
    OwnerExitedDuringStart,
    Armed,
    Disarmed,
    Cancelled,
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
                self.state = GuardState::Cancelled;
                GuardAction::Cancel
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
                self.state = GuardState::Cancelled;
                GuardAction::Cancel
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
            GuardState::Cancelled => GuardAction::Cancel,
            _ => GuardAction::RejectStart,
        }
    }

    fn on_pipe_break(&mut self) -> GuardAction {
        match self.state {
            GuardState::Armed => {
                self.state = GuardState::Cancelled;
                GuardAction::Cancel
            }
            _ => GuardAction::None,
        }
    }

    fn cancel_started_trace(&mut self) -> GuardAction {
        match self.state {
            GuardState::Ready | GuardState::OwnerExitedDuringStart | GuardState::Armed => {
                self.state = GuardState::Cancelled;
                GuardAction::Cancel
            }
            _ => GuardAction::None,
        }
    }

    fn defer_cleanup(&mut self) {
        if self.state == GuardState::Armed {
            self.state = GuardState::Cancelled;
        }
    }
}

struct GuardedOwner {
    owner: OwnedHandle,
    _singleton: SingletonGuard,
    recovery_marker: RecoveryMarker,
    lifecycle: GuardLifecycle,
}

impl GuardedOwner {
    fn open(owner_pid: u32) -> Result<Self> {
        let singleton = SingletonGuard::acquire()?;
        let recovery_marker = RecoveryMarker::acquire()?;
        let owner = match unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, owner_pid) } {
            Ok(owner) => OwnedHandle(owner),
            Err(error) => {
                return Err(error).context("failed to open guarded PLM owner process");
            }
        };
        let mut guarded = Self {
            owner,
            _singleton: singleton,
            recovery_marker,
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
            GuardAction::Cancel => {
                self.cancel_after_owner_exit()
                    .context("failed to cancel PLM trace after owner exit during start")?;
                anyhow::bail!("guarded PLM owner exited during WPR start");
            }
            GuardAction::RejectStart => {
                anyhow::bail!("guarded PLM start reached an invalid lifecycle state")
            }
        }
        if self.has_exited()? {
            if self.lifecycle.on_owner_exit() == GuardAction::Cancel {
                self.cancel_after_owner_exit()
                    .context("failed to cancel PLM trace after owner exit following start")?;
            }
            anyhow::bail!("guarded PLM owner exited immediately after WPR start");
        }
        Ok(())
    }

    fn wait_for_control(&mut self, pipe: &mut std::fs::File) -> Result<()> {
        loop {
            if self.has_exited()? {
                if self.lifecycle.on_owner_exit() == GuardAction::Cancel {
                    self.cancel_after_owner_exit()
                        .context("failed to cancel PLM trace after guarded owner exit")?;
                }
                anyhow::bail!("guarded PLM owner exited before stop");
            }

            match pipe_state(pipe)? {
                PipeState::Empty => {
                    std::thread::sleep(POLL_INTERVAL);
                    continue;
                }
                PipeState::Closed(error) => {
                    self.cancel_for_pipe_break()?;
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
                        return run_guarded_stop(pipe, self);
                    }
                    Err(error) => {
                        self.cancel_for_pipe_break()?;
                        return Err(error);
                    }
                },
                Ok(0) => {
                    std::thread::sleep(POLL_INTERVAL);
                }
                Ok(_) => unreachable!("one-byte control read returned too many bytes"),
                Err(error) => {
                    self.cancel_for_pipe_break()?;
                    return Err(error).context("guarded PLM control pipe failed before stop");
                }
            }
        }
    }

    fn cancel_for_pipe_break(&mut self) -> Result<()> {
        if self.lifecycle.on_pipe_break() != GuardAction::Cancel {
            return Ok(());
        }
        cancel_trace(&mut self.recovery_marker)
    }

    fn cancel_after_start_error(&mut self) {
        if self.lifecycle.cancel_started_trace() == GuardAction::Cancel {
            let _ = cancel_trace(&mut self.recovery_marker);
        }
    }

    fn mark_stopped(&mut self) -> Result<()> {
        match self.lifecycle.disarm() {
            GuardAction::None => Ok(()),
            GuardAction::Cancel => anyhow::bail!("guarded cleanup won the stop race"),
            GuardAction::RejectStart => {
                anyhow::bail!("guarded PLM stop arrived in an invalid state")
            }
        }
    }

    fn cancel_after_owner_exit(&mut self) -> Result<()> {
        cancel_trace(&mut self.recovery_marker)
    }
}

impl Operation {
    fn as_arg(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
        }
    }
}

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

/// Live authenticated connection to the elevated START child.
///
/// [`Self::cancel`] closes an armed session and reports whether the child
/// successfully cancelled the trace. Dropping remains a last-resort cleanup
/// path for unwinding. [`Self::stop`] asks the same retained child to stop WPR
/// and transfer the ETL, avoiding a second elevation prompt.
pub struct GuardedSession {
    pipe: Option<std::fs::File>,
    process: OwnedHandle,
    disarmed: bool,
}

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
    pub fn cancel(&mut self) -> Result<()> {
        if self.disarmed {
            return Ok(());
        }
        self.pipe.take();
        self.disarmed = true;
        wait_for_child_exit(self.process.0, WAIT_TIMEOUT_DURATION)
            .context("guarded PLM cancellation failed")
    }

    pub fn stop(&mut self, trace_destination: &Path) -> Result<()> {
        if self.disarmed {
            anyhow::bail!("guarded PLM session is already stopped");
        }
        let mut pipe = self
            .pipe
            .take()
            .context("guarded PLM control connection is already closed")?;
        pipe.write_all(&[CONTROL_STOP])
            .context("failed to send guarded PLM STOP")?;
        pipe.flush().context("failed to flush guarded PLM STOP")?;

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

fn wait_for_child_exit(process: HANDLE, timeout: Duration) -> Result<()> {
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
    authenticate_server(&pipe, server_pid)?;
    let mut ready = [0u8; 1];
    pipe.read_exact(&mut ready)
        .context("failed to receive PLM control-pipe readiness")?;
    if ready[0] != HANDSHAKE_READY {
        anyhow::bail!("invalid PLM control-pipe readiness byte");
    }
    if operation != Operation::Start || owner_pid.is_none() {
        anyhow::bail!("elevated start requires a guarded owner PID");
    }
    run_guarded_start_child(
        &mut pipe,
        owner_pid.context("guarded start owner PID disappeared")?,
    )
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

fn run_guarded_start_child(pipe: &mut std::fs::File, owner_pid: u32) -> Result<()> {
    let mut owner = match GuardedOwner::open(owner_pid) {
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
        owner.cancel_after_start_error();
        write_error_response(pipe, &error)?;
        return Err(error);
    }
    if let Err(error) = write_header(pipe, ResponseKind::Success, 0).and_then(|_| pipe.flush()) {
        let _ = owner.cancel_for_pipe_break();
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
        Err(error) if stale => Err(error).context(
            "WPR start failed while a protected stale-recovery marker exists; \
             refusing to cancel an unverified WPR session",
        ),
        Err(error) => Err(error),
    }
}

fn cancel_trace(marker: &mut RecoveryMarker) -> Result<()> {
    marker.preserve();
    crate::start::cancel_existing_wpr_trace()?;
    marker.recovered();
    Ok(())
}

fn run_guarded_stop(pipe: &mut std::fs::File, owner: &mut GuardedOwner) -> Result<()> {
    let result = run_guarded_stop_with_stopped(pipe, owner);
    if let Err(error) = result {
        owner.cancel_after_start_error();
        write_error_response(pipe, &error)?;
        return Err(error);
    }
    Ok(())
}

fn run_guarded_stop_with_stopped(pipe: &mut std::fs::File, owner: &mut GuardedOwner) -> Result<()> {
    crate::wpr_path::verify_wpr_present().map_err(anyhow::Error::msg)?;
    let scratch = SecureScratch::new()?;
    run_monitored_wpr_stop(pipe, owner, scratch.trace_path())?;
    owner.mark_stopped()?;
    write_header(pipe, ResponseKind::Stopped, 0)
        .and_then(|_| pipe.flush())
        .context("failed to return elevated PLM WPR-stopped milestone")?;
    write_trace_response(pipe, &scratch)
}

fn run_monitored_wpr_stop(
    pipe: &mut std::fs::File,
    owner: &mut GuardedOwner,
    trace_path: &Path,
) -> Result<()> {
    let mut command = crate::wpr_path::wpr_command();
    let resolved = command.get_program().to_string_lossy().into_owned();
    let mut child = command
        .arg("-stop")
        .arg(trace_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| anyhow::anyhow!("failed to spawn wpr -stop ({resolved}): {error}"))?;
    let stdout = child
        .stdout
        .take()
        .context("failed to capture wpr -stop stdout")?;
    let stderr = child
        .stderr
        .take()
        .context("failed to capture wpr -stop stderr")?;
    let stdout_reader = spawn_output_reader(stdout);
    let stderr_reader = spawn_output_reader(stderr);
    let deadline = Instant::now() + WAIT_TIMEOUT_DURATION;
    // Once STOP is accepted, finish it even if the owner or pipe disappears.
    // Killing an in-flight `wpr -stop` and then cancelling could race a newly
    // started unrelated WPR session after the original stop already succeeded.
    let mut stop_unattended = false;

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                terminate_child(&mut child);
                owner.lifecycle.defer_cleanup();
                owner.recovery_marker.preserve();
                return Err(error).context("failed to poll wpr -stop");
            }
        }
        if !stop_unattended {
            match owner.has_exited() {
                Ok(true) => stop_unattended = true,
                Ok(false) => {}
                Err(_) => stop_unattended = true,
            }

            match pipe_state(pipe) {
                Ok(PipeState::Empty) => {}
                Ok(PipeState::Data(_) | PipeState::Closed(_)) | Err(_) => stop_unattended = true,
            }
        }
        if Instant::now() >= deadline {
            terminate_child(&mut child);
            owner.lifecycle.defer_cleanup();
            owner.recovery_marker.preserve();
            anyhow::bail!("timed out waiting for wpr -stop; deferred cleanup to the next guardian");
        }
        std::thread::sleep(POLL_INTERVAL);
    };

    let stdout = join_output_reader(stdout_reader, "stdout")?;
    let stderr = join_output_reader(stderr_reader, "stderr")?;
    if !status.success() {
        return Err(crate::start::describe_wpr_failure(
            "stop",
            &std::process::Output {
                status,
                stdout,
                stderr,
            },
        ));
    }
    Ok(())
}

fn spawn_output_reader(
    mut stream: impl Read + Send + 'static,
) -> std::thread::JoinHandle<std::io::Result<Vec<u8>>> {
    std::thread::spawn(move || {
        let mut output = Vec::new();
        stream.read_to_end(&mut output)?;
        Ok(output)
    })
}

fn join_output_reader(
    reader: std::thread::JoinHandle<std::io::Result<Vec<u8>>>,
    stream: &str,
) -> Result<Vec<u8>> {
    reader
        .join()
        .map_err(|_| anyhow::anyhow!("wpr -stop {stream} reader panicked"))?
        .with_context(|| format!("failed to read wpr -stop {stream}"))
}

fn terminate_child(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
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

fn authenticate_server(pipe: &std::fs::File, expected_pid: u32) -> Result<()> {
    let mut actual_pid = 0u32;
    unsafe { GetNamedPipeServerProcessId(HANDLE(pipe.as_raw_handle()), &mut actual_pid) }
        .context("GetNamedPipeServerProcessId failed")?;
    if actual_pid != expected_pid {
        anyhow::bail!(
            "PLM control pipe server PID mismatch: expected {expected_pid}, got {actual_pid}"
        );
    }

    Ok(())
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

fn accept_response_headers(
    first_header: crate::elevated_protocol::ResponseHeader,
    operation: Operation,
    on_stopped: impl FnOnce() -> Result<()>,
    read_next: impl FnOnce() -> Result<crate::elevated_protocol::ResponseHeader>,
) -> Result<(crate::elevated_protocol::ResponseHeader, bool)> {
    if first_header.kind == ResponseKind::Stopped {
        if operation != Operation::Stop {
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
    let mut buffer = vec![0u8; 64 * 1024];
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
                std::thread::sleep(POLL_INTERVAL);
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
                std::thread::sleep(POLL_INTERVAL);
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
            64 * 1024,
            64 * 1024,
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
    fn owner_already_dead_rejects_start_without_cancel() {
        let mut lifecycle = GuardLifecycle::new();

        assert_eq!(lifecycle.ready(false), GuardAction::RejectStart);
        assert_eq!(lifecycle.state, GuardState::OwnerExitedDuringStart);
        assert_eq!(lifecycle.on_pipe_break(), GuardAction::None);
    }

    #[test]
    fn owner_death_during_start_cancels_after_start() {
        let mut lifecycle = GuardLifecycle::new();

        assert_eq!(lifecycle.ready(true), GuardAction::None);
        assert_eq!(lifecycle.on_owner_exit(), GuardAction::None);
        assert_eq!(lifecycle.on_start_succeeded(), GuardAction::Cancel);
        assert_eq!(lifecycle.state, GuardState::Cancelled);
    }

    #[test]
    fn owner_death_after_start_cancels_once() {
        let mut lifecycle = armed_lifecycle();

        assert_eq!(lifecycle.on_owner_exit(), GuardAction::Cancel);
        assert_eq!(lifecycle.on_owner_exit(), GuardAction::None);
    }

    #[test]
    fn stopped_state_prevents_cancel_and_post_stop_interference() {
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
        assert_eq!(lifecycle.on_pipe_break(), GuardAction::Cancel);
    }

    #[test]
    fn uncertain_stop_defers_cleanup_without_late_cancel() {
        let mut lifecycle = armed_lifecycle();

        lifecycle.defer_cleanup();
        assert_eq!(lifecycle.state, GuardState::Cancelled);
        assert_eq!(lifecycle.cancel_started_trace(), GuardAction::None);
        assert_eq!(lifecycle.on_pipe_break(), GuardAction::None);
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
    fn pipe_break_cancels_armed_session_once() {
        let mut lifecycle = armed_lifecycle();

        assert_eq!(lifecycle.on_pipe_break(), GuardAction::Cancel);
        assert_eq!(lifecycle.on_pipe_break(), GuardAction::None);
    }

    #[test]
    fn control_protocol_accepts_only_stop() {
        assert_eq!(
            parse_guard_control(CONTROL_STOP).unwrap(),
            GuardControl::Stop
        );
        for invalid in [0, 2, u8::MAX] {
            assert!(parse_guard_control(invalid).is_err());
        }
    }

    #[test]
    fn empty_connected_pipe_is_not_reported_as_closed() {
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

        let mut client = client_thread.join().unwrap();
        assert_eq!(pipe_state(&client).unwrap(), PipeState::Empty);

        let raw = server.0 .0;
        std::mem::forget(server);
        let mut server_file = unsafe { std::fs::File::from_raw_handle(raw) };
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
