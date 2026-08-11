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
use std::time::{Duration, Instant};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_CANCELLED, ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING, HANDLE,
    INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Storage::FileSystem::{
    FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_FIRST_PIPE_INSTANCE,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
    PIPE_NOWAIT, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetExitCodeProcess, GetProcessId, OpenProcess,
    OpenProcessToken, TerminateProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE,
};
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};

use crate::elevated_protocol::{
    read_header, write_header, ResponseKind, HEADER_LEN, MAX_ERROR_BYTES, MAX_TRACE_BYTES,
};
use crate::secure_scratch::{ProfileGuard, SecureScratch};

const PIPE_PREFIX: &str = r"\\.\pipe\mxc-plm-elevated-";
const WAIT_TIMEOUT_DURATION: Duration = Duration::from_secs(10 * 60);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const ERROR_NO_DATA: i32 = 232;
const SW_HIDE: i32 = 0;
const CONTROL_DISARM: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GuardControl {
    Disarm,
}

fn parse_guard_control(value: u8) -> Result<GuardControl> {
    match value {
        CONTROL_DISARM => Ok(GuardControl::Disarm),
        _ => anyhow::bail!("invalid guarded PLM control message {value}"),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Start,
    Stop,
    Cancel,
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
}

struct GuardedOwner {
    owner: OwnedHandle,
    lifecycle: GuardLifecycle,
}

impl GuardedOwner {
    fn open(owner_pid: u32) -> Result<Self> {
        let owner = OwnedHandle(
            unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, owner_pid) }
                .context("failed to open guarded PLM owner process")?,
        );
        let mut guarded = Self {
            owner,
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
                cancel_after_owner_exit()
                    .context("failed to cancel PLM trace after owner exit during start")?;
                anyhow::bail!("guarded PLM owner exited during WPR start");
            }
            GuardAction::RejectStart => {
                anyhow::bail!("guarded PLM start reached an invalid lifecycle state")
            }
        }
        if self.has_exited()? {
            if self.lifecycle.on_owner_exit() == GuardAction::Cancel {
                cancel_after_owner_exit()
                    .context("failed to cancel PLM trace after owner exit following start")?;
            }
            anyhow::bail!("guarded PLM owner exited immediately after WPR start");
        }
        Ok(())
    }

    fn wait_for_disarm(&mut self, pipe: &mut std::fs::File) -> Result<()> {
        loop {
            if self.has_exited()? {
                if self.lifecycle.on_owner_exit() == GuardAction::Cancel {
                    cancel_after_owner_exit()
                        .context("failed to cancel PLM trace after guarded owner exit")?;
                }
                anyhow::bail!("guarded PLM owner exited before disarm");
            }

            let mut control = [0u8; 1];
            match pipe.read(&mut control) {
                Ok(1) => {
                    if let Err(error) = parse_guard_control(control[0]) {
                        self.cancel_for_pipe_break()?;
                        return Err(error);
                    }
                    match self.lifecycle.disarm() {
                        GuardAction::None => return Ok(()),
                        GuardAction::Cancel => {
                            anyhow::bail!("guarded PLM cleanup won the disarm race")
                        }
                        GuardAction::RejectStart => {
                            anyhow::bail!("guarded PLM disarm arrived in an invalid state")
                        }
                    }
                }
                Ok(0) => {
                    self.cancel_for_pipe_break()?;
                    anyhow::bail!("guarded PLM control pipe closed before disarm");
                }
                Ok(_) => unreachable!("one-byte control read returned too many bytes"),
                Err(error) if error.raw_os_error() == Some(ERROR_NO_DATA) => {
                    std::thread::sleep(POLL_INTERVAL);
                }
                Err(error) => {
                    self.cancel_for_pipe_break()?;
                    return Err(error).context("guarded PLM control pipe failed before disarm");
                }
            }
        }
    }

    fn cancel_for_pipe_break(&mut self) -> Result<()> {
        if self.lifecycle.on_pipe_break() != GuardAction::Cancel {
            return Ok(());
        }
        if self.has_exited()? {
            cancel_after_owner_exit()
        } else {
            crate::start::cancel_existing_wpr_trace()
        }
    }

    fn cancel_after_start_error(&mut self) {
        if self.lifecycle.cancel_started_trace() == GuardAction::Cancel {
            let _ = crate::start::cancel_existing_wpr_trace();
        }
    }
}

impl Operation {
    fn as_arg(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Cancel => "cancel",
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
/// Dropping an armed session closes the control pipe and waits for the child
/// to cancel the trace. Call [`Self::disarm`] only after stop and ETL transfer
/// have both succeeded.
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
    pub fn disarm(&mut self) -> Result<()> {
        if self.disarmed {
            return Ok(());
        }
        let pipe = self
            .pipe
            .as_mut()
            .context("guarded PLM control connection is already closed")?;
        pipe.write_all(&[CONTROL_DISARM])
            .context("failed to send guarded PLM DISARM")?;
        pipe.flush().context("failed to flush guarded PLM DISARM")?;
        wait_for_child_exit(self.process.0, WAIT_TIMEOUT_DURATION)?;
        self.pipe.take();
        self.disarmed = true;
        Ok(())
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

/// Invoke a fixed elevated operation. `trace_destination` is consumed only by
/// the unelevated parent and is never placed on the elevated command line.
pub fn invoke(operation: Operation, trace_destination: Option<&Path>) -> Result<()> {
    let executable = std::env::current_exe().context("failed to resolve plm.exe path")?;
    invoke_with_executable(&executable, operation, trace_destination)
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

pub fn disarm_current_guarded_start() -> Result<()> {
    CURRENT_GUARDED_SESSION.with(|slot| {
        let mut session = slot
            .borrow_mut()
            .take()
            .context("no guarded PLM session is active on this thread")?;
        session.disarm()
    })
}

pub fn cancel_current_guarded_start() {
    CURRENT_GUARDED_SESSION.with(|slot| drop(slot.borrow_mut().take()));
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
    if let Err(error) = read_response(&mut pipe, process.0, Operation::Start, None, deadline) {
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

fn invoke_with_executable(
    executable: &Path,
    operation: Operation,
    trace_destination: Option<&Path>,
) -> Result<()> {
    match (operation, trace_destination) {
        (Operation::Stop, Some(_)) | (Operation::Start | Operation::Cancel, None) => {}
        (Operation::Stop, None) => anyhow::bail!("elevated stop requires a trace destination"),
        (_, Some(_)) => anyhow::bail!("only elevated stop accepts a trace destination"),
    }

    let (mut pipe, process, deadline) = launch_connected_child(executable, operation, None)?;
    let result = read_response(&mut pipe, process.0, operation, trace_destination, deadline);
    drop(pipe);
    let wait_result = wait_for_child_exit(
        process.0,
        deadline.saturating_duration_since(Instant::now()),
    );
    result?;
    wait_result
}

fn launch_connected_child(
    executable: &Path,
    operation: Operation,
    owner_pid: Option<u32>,
) -> Result<(std::fs::File, OwnedHandle, Instant)> {
    let pipe_name = new_pipe_name()?;
    let pipe = OwnedHandle(create_pipe(&pipe_name)?);
    if owner_pid.is_some() && operation != Operation::Start {
        anyhow::bail!("only elevated start accepts a guarded owner PID");
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
    let pipe_file = unsafe { std::fs::File::from_raw_handle(pipe_raw) };
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
    if owner_pid.is_some() && operation != Operation::Start {
        anyhow::bail!("guarded owner PID is valid only for elevated start");
    }

    if operation == Operation::Start {
        if let Some(owner_pid) = owner_pid {
            return run_guarded_start_child(&mut pipe, owner_pid);
        }
    }

    let operation_result = match operation {
        Operation::Start => run_start(),
        Operation::Stop => run_stop(&mut pipe),
        Operation::Cancel => run_cancel(),
    };

    match operation_result {
        Ok(()) if operation != Operation::Stop => {
            let response_result =
                write_header(&mut pipe, ResponseKind::Success, 0).and_then(|_| pipe.flush());
            if let Err(error) = response_result {
                if operation == Operation::Start {
                    let _ = crate::start::cancel_existing_wpr_trace();
                }
                return Err(error).context("failed to return elevated PLM success");
            }
            Ok(())
        }
        Ok(()) => Ok(()),
        Err(error) => {
            let message = format!("{error:#}");
            let bytes = message.as_bytes();
            let len = (bytes.len() as u64).min(MAX_ERROR_BYTES);
            let send_result = write_header(&mut pipe, ResponseKind::Error, len)
                .and_then(|_| pipe.write_all(&bytes[..len as usize]))
                .and_then(|_| pipe.flush());
            if let Err(send_error) = send_result {
                return Err(error).context(format!(
                    "also failed to return elevated PLM error over the pipe: {send_error}"
                ));
            }
            Err(error)
        }
    }
}

fn run_guarded_start_child(pipe: &mut std::fs::File, owner_pid: u32) -> Result<()> {
    let mut owner = GuardedOwner::open(owner_pid)?;
    if let Err(error) = run_start() {
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
    owner.wait_for_disarm(pipe)
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

fn run_stop(pipe: &mut std::fs::File) -> Result<()> {
    crate::wpr_path::verify_wpr_present().map_err(anyhow::Error::msg)?;
    let scratch = SecureScratch::new()?;
    crate::stop::stop_plm_trace(scratch.trace_path())?;
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

fn run_cancel() -> Result<()> {
    crate::wpr_path::verify_wpr_present().map_err(anyhow::Error::msg)?;
    crate::start::cancel_existing_wpr_trace()
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
) -> Result<()> {
    let header = read_header_polling(pipe, process, deadline)?;
    match header.kind {
        ResponseKind::Success if operation != Operation::Stop => Ok(()),
        ResponseKind::Success => anyhow::bail!("elevated stop returned no ETL payload"),
        ResponseKind::Trace if operation == Operation::Stop => {
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
        ResponseKind::Trace => anyhow::bail!("unexpected ETL payload for elevated {operation:?}"),
        ResponseKind::Error => {
            let mut message = vec![0u8; header.payload_len as usize];
            read_exact_polling(pipe, &mut message, process, deadline)?;
            anyhow::bail!(
                "elevated PLM {operation:?} failed: {}",
                String::from_utf8_lossy(&message)
            )
        }
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
        match pipe.read(buffer) {
            Ok(read) => return Ok(read),
            Err(error) if error.raw_os_error() == Some(ERROR_NO_DATA) => {
                ensure_child_running(process, deadline)?;
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(error) => return Err(error).context("failed to read elevated PLM response"),
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
    let parameters = build_internal_parameters(
        operation,
        pipe_name,
        unsafe { GetCurrentProcessId() },
        owner_pid,
    );
    let verb = to_wide("runas");
    let executable = to_wide(executable.as_os_str());
    let parameters = to_wide(parameters);
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(executable.as_ptr()),
        lpParameters: PCWSTR(parameters.as_ptr()),
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

fn cancel_after_owner_exit() -> Result<()> {
    use crate::coordination::singleton::{try_acquire, AcquireError};
    use std::sync::atomic::AtomicIsize;
    let singleton = AtomicIsize::new(0);
    match try_acquire(&singleton) {
        Ok(()) => {}
        Err(AcquireError::AlreadyHeld) => {
            // A new owner won the abandoned-mutex race. Its WPR session may
            // already be active, so this child must never cancel it.
            return Ok(());
        }
        Err(AcquireError::CreateFailed(error)) => {
            return Err(error).context("guarded PLM singleton acquisition failed")
        }
    }
    let result = crate::start::cancel_existing_wpr_trace();
    crate::coordination::singleton::release(&singleton);
    result
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
    fn explicit_disarm_prevents_cancel_and_post_stop_interference() {
        let mut lifecycle = armed_lifecycle();

        assert_eq!(lifecycle.disarm(), GuardAction::None);
        assert_eq!(lifecycle.on_owner_exit(), GuardAction::None);
        assert_eq!(lifecycle.on_pipe_break(), GuardAction::None);
        assert_eq!(lifecycle.state, GuardState::Disarmed);
    }

    #[test]
    fn stop_failure_leaves_guard_armed() {
        let mut lifecycle = armed_lifecycle();

        // A failed stop sends no DISARM.
        assert_eq!(lifecycle.state, GuardState::Armed);
        assert_eq!(lifecycle.on_pipe_break(), GuardAction::Cancel);
    }

    #[test]
    fn pipe_break_cancels_armed_session_once() {
        let mut lifecycle = armed_lifecycle();

        assert_eq!(lifecycle.on_pipe_break(), GuardAction::Cancel);
        assert_eq!(lifecycle.on_pipe_break(), GuardAction::None);
    }

    #[test]
    fn control_protocol_accepts_only_one_byte_disarm() {
        assert_eq!(
            parse_guard_control(CONTROL_DISARM).unwrap(),
            GuardControl::Disarm
        );
        for invalid in [0, 2, u8::MAX] {
            assert!(parse_guard_control(invalid).is_err());
        }
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
    fn internal_command_contains_no_filesystem_path_argument() {
        let pipe = r"\\.\pipe\mxc-plm-elevated-00112233445566778899aabbccddeeff";
        for operation in [Operation::Start, Operation::Stop, Operation::Cancel] {
            let parameters = build_internal_parameters(operation, pipe, 42, None);
            assert!(parameters.starts_with("__elevated "));
            assert!(parameters.contains("--pipe-name"));
            assert!(parameters.contains("--server-pid 42"));
            assert!(!parameters.contains("trace-output"));
            assert!(!parameters.contains("wprp"));
            assert!(!parameters.contains("log-dir"));
            assert!(!parameters.contains("config-path"));
            assert!(!parameters.contains("owner-pid"));
        }
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
