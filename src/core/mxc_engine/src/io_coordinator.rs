// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Native I/O coordination for event-loop language bindings.
//!
//! The coordinator owns every blocking sandbox operation on native threads.
//! Callers interact through bounded, non-blocking queues, so they never park
//! an event-loop thread in an OS read, write, wait, kill, or destructor.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel::{
    bounded, select, unbounded, Receiver, RecvTimeoutError, Sender, TryRecvError, TrySendError,
};
use wxc_common::models::SandboxOutputMetadata;
use wxc_common::sandbox_process::{SandboxProcess, StreamCloser};

use crate::{spawn, Error, SandboxRequest};

const OUTPUT_CHUNK_BYTES: usize = 16 * 1024;
const OUTPUT_QUEUE_CHUNKS: usize = 16;
const STDIN_QUEUE_BYTES: usize = 256 * 1024;
const STDIN_QUEUE_COMMANDS: usize = 16;
const CONTROL_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// The current state of a coordinated output stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoReadState {
    /// No output is currently available.
    Pending,
    /// Bytes were copied into the caller's buffer.
    Data(usize),
    /// The output stream reached end-of-file.
    Eof,
}

/// A non-blocking snapshot of the coordinated process state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoProcessStatus {
    /// Whether the process is still running.
    pub running: bool,
    /// The terminal exit code. This is meaningful only when `running` is false.
    pub exit_code: i32,
    /// Whether the configured deadline terminated the process.
    pub timed_out: bool,
}

/// Failures produced by coordinator operations after a sandbox has spawned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoCoordinatorError {
    /// The requested stream or coordinator operation is no longer available.
    Closed,
    /// The underlying sandbox operation failed.
    Backend,
}

#[derive(Debug, Clone, Copy)]
struct TerminalResult {
    exit_code: i32,
    timed_out: bool,
}

#[derive(Default)]
struct ProcessState {
    result: Option<TerminalResult>,
    failed: bool,
    warnings: Vec<String>,
    output_metadata: Option<SandboxOutputMetadata>,
}

#[derive(Clone, Copy)]
enum ControlCommand {
    Kill,
    CloseStdout,
    CloseStderr,
    Shutdown,
}

enum StdinCommand {
    Write { id: u32, bytes: Vec<u8> },
    Flush { id: u32 },
}

#[derive(Default)]
struct StdinState {
    results: HashMap<u32, Result<usize, ()>>,
    pending: HashSet<u32>,
    queued_bytes: usize,
    closed: bool,
    aborted: bool,
}

struct StdinCoordinator {
    commands: Sender<StdinCommand>,
    state: Mutex<StdinState>,
    next_id: AtomicU32,
    available: bool,
}

impl StdinCoordinator {
    fn unavailable() -> Arc<Self> {
        let (commands, _) = bounded(0);
        Arc::new(Self {
            commands,
            state: Mutex::new(StdinState {
                closed: true,
                ..StdinState::default()
            }),
            next_id: AtomicU32::new(1),
            available: false,
        })
    }

    fn start(writer: Option<Box<dyn Write + Send>>) -> Arc<Self> {
        let Some(writer) = writer else {
            return Self::unavailable();
        };
        let (commands, receiver) = bounded(STDIN_QUEUE_COMMANDS);
        let coordinator = Arc::new(Self {
            commands,
            state: Mutex::new(StdinState::default()),
            next_id: AtomicU32::new(1),
            available: true,
        });
        let worker = Arc::clone(&coordinator);
        thread::spawn(move || run_stdin(writer, receiver, worker));
        coordinator
    }

    fn start_write(&self, bytes: &[u8]) -> Result<Option<u32>, IoCoordinatorError> {
        if !self.available {
            return Err(IoCoordinatorError::Closed);
        }
        let mut state = lock_unpoisoned(&self.state);
        if state.closed {
            return Err(IoCoordinatorError::Closed);
        }
        if state.results.len() >= STDIN_QUEUE_COMMANDS {
            return Ok(None);
        }
        if bytes.len() > STDIN_QUEUE_BYTES
            || state.queued_bytes.saturating_add(bytes.len()) > STDIN_QUEUE_BYTES
        {
            return Ok(None);
        }

        let id = self.next_operation_id();
        state.queued_bytes += bytes.len();
        let command = StdinCommand::Write {
            id,
            bytes: bytes.to_vec(),
        };
        match self.commands.try_send(command) {
            Ok(()) => {
                state.pending.insert(id);
                Ok(Some(id))
            }
            Err(TrySendError::Full(_)) => {
                state.queued_bytes -= bytes.len();
                Ok(None)
            }
            Err(TrySendError::Disconnected(_)) => {
                state.queued_bytes -= bytes.len();
                Err(IoCoordinatorError::Closed)
            }
        }
    }

    fn start_flush(&self) -> Result<Option<u32>, IoCoordinatorError> {
        if !self.available {
            return Err(IoCoordinatorError::Closed);
        }
        let mut state = lock_unpoisoned(&self.state);
        if state.closed {
            return Err(IoCoordinatorError::Closed);
        }
        if state.results.len() >= STDIN_QUEUE_COMMANDS {
            return Ok(None);
        }
        let id = self.next_operation_id();
        state.pending.insert(id);
        match self.commands.try_send(StdinCommand::Flush { id }) {
            Ok(()) => Ok(Some(id)),
            Err(TrySendError::Full(_)) => {
                state.pending.remove(&id);
                Ok(None)
            }
            Err(TrySendError::Disconnected(_)) => {
                state.pending.remove(&id);
                Err(IoCoordinatorError::Closed)
            }
        }
    }

    fn poll(&self, id: u32) -> Option<Result<usize, IoCoordinatorError>> {
        lock_unpoisoned(&self.state)
            .results
            .remove(&id)
            .map(|result| result.map_err(|()| IoCoordinatorError::Backend))
    }

    fn close(&self) {
        let mut state = lock_unpoisoned(&self.state);
        state.closed = true;
    }

    fn abort(&self) {
        let mut state = lock_unpoisoned(&self.state);
        state.closed = true;
        state.aborted = true;
        let pending: Vec<_> = state.pending.drain().collect();
        state
            .results
            .extend(pending.into_iter().map(|id| (id, Err(()))));
    }

    fn next_operation_id(&self) -> u32 {
        loop {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            if id != 0 {
                return id;
            }
        }
    }
}

enum OutputMessage {
    Data(Vec<u8>),
    Eof,
    Error,
}

#[derive(Default)]
struct OutputReadState {
    front: Option<(Vec<u8>, usize)>,
    terminal: Option<Result<(), ()>>,
    closed: bool,
}

struct OutputCoordinator {
    messages: Receiver<OutputMessage>,
    cancel: Sender<()>,
    read_state: Mutex<OutputReadState>,
    control: Option<Sender<ControlCommand>>,
    close_command: ControlCommand,
    available: bool,
}

impl OutputCoordinator {
    fn unavailable(close_command: ControlCommand) -> Arc<Self> {
        let (_, messages) = bounded(0);
        let (cancel, _) = bounded(0);
        Arc::new(Self {
            messages,
            cancel,
            read_state: Mutex::new(OutputReadState::default()),
            control: None,
            close_command,
            available: false,
        })
    }

    fn start(
        reader: Option<Box<dyn Read + Send>>,
        control: Sender<ControlCommand>,
        close_command: ControlCommand,
    ) -> Arc<Self> {
        let Some(reader) = reader else {
            return Self::unavailable(close_command);
        };
        let (message_sender, messages) = bounded(OUTPUT_QUEUE_CHUNKS);
        let (cancel, cancel_receiver) = bounded(1);
        let coordinator = Arc::new(Self {
            messages,
            cancel,
            read_state: Mutex::new(OutputReadState::default()),
            control: Some(control),
            close_command,
            available: true,
        });
        thread::spawn(move || run_output(reader, message_sender, cancel_receiver));
        coordinator
    }

    fn try_read(&self, buffer: &mut [u8]) -> Result<IoReadState, IoCoordinatorError> {
        if !self.available {
            return Ok(IoReadState::Eof);
        }
        if buffer.is_empty() {
            return Ok(IoReadState::Pending);
        }

        let mut state = lock_unpoisoned(&self.read_state);
        if state.closed {
            return Ok(IoReadState::Eof);
        }
        if let Some(read) = copy_front(&mut state, buffer) {
            return Ok(IoReadState::Data(read));
        }
        if let Some(terminal) = state.terminal {
            return terminal
                .map(|()| IoReadState::Eof)
                .map_err(|()| IoCoordinatorError::Backend);
        }

        match self.messages.try_recv() {
            Ok(OutputMessage::Data(bytes)) => {
                state.front = Some((bytes, 0));
                Ok(IoReadState::Data(
                    copy_front(&mut state, buffer).unwrap_or(0),
                ))
            }
            Ok(OutputMessage::Eof) => {
                state.terminal = Some(Ok(()));
                Ok(IoReadState::Eof)
            }
            Ok(OutputMessage::Error) => {
                state.terminal = Some(Err(()));
                Err(IoCoordinatorError::Backend)
            }
            Err(TryRecvError::Empty) => Ok(IoReadState::Pending),
            Err(TryRecvError::Disconnected) => {
                state.terminal = Some(Ok(()));
                Ok(IoReadState::Eof)
            }
        }
    }

    fn close(&self) {
        {
            let mut state = lock_unpoisoned(&self.read_state);
            if state.closed {
                return;
            }
            state.closed = true;
            state.front = None;
        }
        let _ = self.cancel.try_send(());
        if let Some(control) = &self.control {
            let _ = control.send(self.close_command);
        }
    }
}

fn copy_front(state: &mut OutputReadState, buffer: &mut [u8]) -> Option<usize> {
    let (bytes, offset) = state.front.as_mut()?;
    let remaining = &bytes[*offset..];
    let read = remaining.len().min(buffer.len());
    buffer[..read].copy_from_slice(&remaining[..read]);
    *offset += read;
    if *offset == bytes.len() {
        state.front = None;
    }
    Some(read)
}

struct SharedCoordinator {
    id: u32,
    process: Mutex<ProcessState>,
    control: Sender<ControlCommand>,
    stdin: Arc<StdinCoordinator>,
    stdout: Arc<OutputCoordinator>,
    stderr: Arc<OutputCoordinator>,
    kill_requested: AtomicBool,
    shutdown_requested: AtomicBool,
}

impl SharedCoordinator {
    fn request_shutdown(&self) {
        if self.shutdown_requested.swap(true, Ordering::AcqRel) {
            return;
        }
        self.stdin.abort();
        self.stdout.close();
        self.stderr.close();
        let _ = self.control.send(ControlCommand::Shutdown);
    }
}

/// Coordinates a streaming sandbox for non-blocking event-loop access.
pub struct IoCoordinator {
    shared: Arc<SharedCoordinator>,
}

impl std::fmt::Debug for IoCoordinator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IoCoordinator")
            .field("id", &self.shared.id)
            .finish_non_exhaustive()
    }
}

impl Drop for IoCoordinator {
    fn drop(&mut self) {
        self.shared.request_shutdown();
    }
}

impl IoCoordinator {
    /// Return the child process identifier.
    pub fn id(&self) -> u32 {
        self.shared.id
    }

    /// Report whether stdin is available.
    pub fn has_stdin(&self) -> bool {
        self.shared.stdin.available
    }

    /// Report whether stdout is available.
    pub fn has_stdout(&self) -> bool {
        self.shared.stdout.available
    }

    /// Report whether stderr is available.
    pub fn has_stderr(&self) -> bool {
        self.shared.stderr.available
    }

    /// Poll process completion without blocking.
    pub fn poll_process(&self) -> Result<IoProcessStatus, IoCoordinatorError> {
        let state = lock_unpoisoned(&self.shared.process);
        if let Some(result) = state.result {
            return Ok(IoProcessStatus {
                running: false,
                exit_code: result.exit_code,
                timed_out: result.timed_out,
            });
        }
        if state.failed {
            return Err(IoCoordinatorError::Backend);
        }
        Ok(IoProcessStatus {
            running: true,
            exit_code: 0,
            timed_out: false,
        })
    }

    /// Queue a process-tree kill.
    pub fn request_kill(&self) -> Result<(), IoCoordinatorError> {
        if self.shared.kill_requested.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        self.shared.control.send(ControlCommand::Kill).map_err(|_| {
            self.shared.kill_requested.store(false, Ordering::Release);
            IoCoordinatorError::Closed
        })
    }

    /// Request process and stream shutdown.
    pub fn request_shutdown(&self) {
        self.shared.request_shutdown();
    }

    /// Try to copy queued stdout bytes without blocking.
    pub fn try_read_stdout(&self, buffer: &mut [u8]) -> Result<IoReadState, IoCoordinatorError> {
        self.shared.stdout.try_read(buffer)
    }

    /// Try to copy queued stderr bytes without blocking.
    pub fn try_read_stderr(&self, buffer: &mut [u8]) -> Result<IoReadState, IoCoordinatorError> {
        self.shared.stderr.try_read(buffer)
    }

    /// Close and discard stdout.
    pub fn close_stdout(&self) {
        self.shared.stdout.close();
    }

    /// Close and discard stderr.
    pub fn close_stderr(&self) {
        self.shared.stderr.close();
    }

    /// Queue a bounded stdin write.
    pub fn start_write(&self, bytes: &[u8]) -> Result<Option<u32>, IoCoordinatorError> {
        self.shared.stdin.start_write(bytes)
    }

    /// Queue a stdin flush.
    pub fn start_flush(&self) -> Result<Option<u32>, IoCoordinatorError> {
        self.shared.stdin.start_flush()
    }

    /// Poll a queued stdin operation.
    pub fn poll_stdin(&self, operation: u32) -> Option<Result<usize, IoCoordinatorError>> {
        self.shared.stdin.poll(operation)
    }

    /// Close stdin after already accepted writes complete.
    pub fn close_stdin(&self) {
        self.shared.stdin.close();
    }

    /// Return the latest sandbox warnings.
    pub fn warnings(&self) -> Vec<String> {
        lock_unpoisoned(&self.shared.process).warnings.clone()
    }

    /// Return structured output metadata after terminal completion.
    pub fn output_metadata(&self) -> Option<SandboxOutputMetadata> {
        lock_unpoisoned(&self.shared.process)
            .output_metadata
            .clone()
    }
}

/// Spawn a sandbox under native I/O coordination.
pub fn spawn_io(request: &SandboxRequest) -> Result<IoCoordinator, Error> {
    let timeout_ms = (request.inner.script_timeout > 0).then_some(request.inner.script_timeout);
    let process = spawn(request)?;
    Ok(coordinate_io(process, timeout_ms))
}

/// Wrap an already-spawned sandbox process in native I/O coordination.
///
/// State-aware exec and one-shot execution use the same process/stream
/// ownership once their backend-specific dispatch has produced a handle.
pub fn coordinate_io(
    mut process: Box<dyn SandboxProcess>,
    timeout_ms: Option<u32>,
) -> IoCoordinator {
    let timeout_ms = timeout_ms.filter(|timeout| *timeout > 0);
    let id = process.id();
    let warnings = process.warnings();
    let stdout_closer = process.stdout_closer();
    let stderr_closer = process.stderr_closer();
    let (control_tx, control_rx) = unbounded();
    let stdin = StdinCoordinator::start(process.take_stdin());
    let stdout = OutputCoordinator::start(
        process.take_stdout(),
        control_tx.clone(),
        ControlCommand::CloseStdout,
    );
    let stderr = OutputCoordinator::start(
        process.take_stderr(),
        control_tx.clone(),
        ControlCommand::CloseStderr,
    );
    let shared = Arc::new(SharedCoordinator {
        id,
        process: Mutex::new(ProcessState {
            warnings,
            ..ProcessState::default()
        }),
        control: control_tx,
        stdin,
        stdout,
        stderr,
        kill_requested: AtomicBool::new(false),
        shutdown_requested: AtomicBool::new(false),
    });
    let control_shared = Arc::clone(&shared);
    thread::spawn(move || {
        run_control(
            process,
            timeout_ms,
            control_rx,
            stdout_closer,
            stderr_closer,
            control_shared,
        )
    });
    IoCoordinator { shared }
}

fn run_control(
    mut process: Box<dyn SandboxProcess>,
    timeout_ms: Option<u32>,
    commands: Receiver<ControlCommand>,
    stdout_closer: Option<Box<dyn StreamCloser>>,
    stderr_closer: Option<Box<dyn StreamCloser>>,
    shared: Arc<SharedCoordinator>,
) {
    let started_at = Instant::now();
    loop {
        if shared.shutdown_requested.load(Ordering::Acquire) {
            shutdown_process(
                &mut process,
                &shared,
                stdout_closer.as_deref(),
                stderr_closer.as_deref(),
            );
            return;
        }

        match commands.recv_timeout(CONTROL_POLL_INTERVAL) {
            Ok(ControlCommand::Kill) => {
                if process.kill().is_err() && !finish_after_kill_race(&mut *process, &shared) {
                    lock_unpoisoned(&shared.process).failed = true;
                }
                shared.kill_requested.store(false, Ordering::Release);
            }
            Ok(ControlCommand::CloseStdout) => close_stream(stdout_closer.as_deref()),
            Ok(ControlCommand::CloseStderr) => close_stream(stderr_closer.as_deref()),
            Ok(ControlCommand::Shutdown) | Err(RecvTimeoutError::Disconnected) => {
                shutdown_process(
                    &mut process,
                    &shared,
                    stdout_closer.as_deref(),
                    stderr_closer.as_deref(),
                );
                return;
            }
            Err(RecvTimeoutError::Timeout) => {}
        }

        match process.try_wait() {
            Ok(Some(_)) => {
                finish_process(&mut *process, &shared, false);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                finish_process(&mut *process, &shared, true);
                break;
            }
            Err(_) => {
                lock_unpoisoned(&shared.process).failed = true;
                break;
            }
            Ok(None) => {}
        }

        if timeout_ms
            .is_some_and(|timeout| started_at.elapsed() >= Duration::from_millis(timeout.into()))
        {
            match process.try_wait() {
                Ok(Some(_)) => finish_process(&mut *process, &shared, false),
                Ok(None) => {
                    if process.kill().is_err() {
                        if !finish_after_kill_race(&mut *process, &shared) {
                            lock_unpoisoned(&shared.process).failed = true;
                        }
                    } else {
                        finish_process(&mut *process, &shared, true);
                    }
                }
                Err(_) => lock_unpoisoned(&shared.process).failed = true,
            }
            break;
        }
    }
    run_terminal_control(commands, stdout_closer, stderr_closer);
}

fn shutdown_process(
    process: &mut Box<dyn SandboxProcess>,
    shared: &SharedCoordinator,
    stdout_closer: Option<&dyn StreamCloser>,
    stderr_closer: Option<&dyn StreamCloser>,
) {
    close_stream(stdout_closer);
    close_stream(stderr_closer);
    if process.kill().is_ok() {
        finish_process(&mut **process, shared, false);
    } else if !finish_after_kill_race(&mut **process, shared) {
        lock_unpoisoned(&shared.process).failed = true;
    }
}

fn finish_after_kill_race(process: &mut dyn SandboxProcess, shared: &SharedCoordinator) -> bool {
    match process.try_wait() {
        Ok(Some(_)) => {
            finish_process(process, shared, false);
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
            finish_process(process, shared, true);
            true
        }
        Ok(None) | Err(_) => false,
    }
}

fn run_terminal_control(
    commands: Receiver<ControlCommand>,
    stdout_closer: Option<Box<dyn StreamCloser>>,
    stderr_closer: Option<Box<dyn StreamCloser>>,
) {
    while let Ok(command) = commands.recv() {
        match command {
            ControlCommand::CloseStdout => close_stream(stdout_closer.as_deref()),
            ControlCommand::CloseStderr => close_stream(stderr_closer.as_deref()),
            ControlCommand::Shutdown => {
                close_stream(stdout_closer.as_deref());
                close_stream(stderr_closer.as_deref());
                return;
            }
            ControlCommand::Kill => {}
        }
    }
}

fn close_stream(closer: Option<&dyn StreamCloser>) {
    if let Some(closer) = closer {
        closer.close();
    }
}

fn finish_process(
    process: &mut dyn SandboxProcess,
    shared: &SharedCoordinator,
    forced_timeout: bool,
) {
    let result = process.wait();
    let warnings = process.warnings();
    let output_metadata = process.output_metadata().cloned();
    let mut state = lock_unpoisoned(&shared.process);
    state.warnings = warnings;
    state.output_metadata = output_metadata;
    match result {
        Ok(exit_code) => {
            state.result = Some(TerminalResult {
                exit_code,
                timed_out: forced_timeout,
            });
        }
        Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
            state.result = Some(TerminalResult {
                exit_code: -1,
                timed_out: true,
            });
        }
        Err(_) => state.failed = true,
    }
}

fn run_output(
    mut reader: Box<dyn Read + Send>,
    messages: Sender<OutputMessage>,
    cancel: Receiver<()>,
) {
    let mut buffer = vec![0_u8; OUTPUT_CHUNK_BYTES];
    loop {
        let message = match reader.read(&mut buffer) {
            Ok(0) => OutputMessage::Eof,
            Ok(read) => OutputMessage::Data(buffer[..read].to_vec()),
            Err(_) => OutputMessage::Error,
        };
        let terminal = !matches!(message, OutputMessage::Data(_));
        select! {
            send(messages, message) -> result => {
                if result.is_err() || terminal {
                    return;
                }
            }
            recv(cancel) -> _ => return,
        }
    }
}

fn run_stdin(
    mut writer: Box<dyn Write + Send>,
    commands: Receiver<StdinCommand>,
    coordinator: Arc<StdinCoordinator>,
) {
    loop {
        let command = match commands.recv_timeout(CONTROL_POLL_INTERVAL) {
            Ok(command) => command,
            Err(RecvTimeoutError::Timeout) => {
                let state = lock_unpoisoned(&coordinator.state);
                if state.closed && commands.is_empty() {
                    return;
                }
                drop(state);
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => return,
        };
        let (id, result) = match command {
            StdinCommand::Write { id, bytes } => {
                let mut state = lock_unpoisoned(&coordinator.state);
                state.queued_bytes -= bytes.len();
                if state.aborted {
                    continue;
                }
                drop(state);
                let len = bytes.len();
                (id, writer.write_all(&bytes).map(|()| len).map_err(|_| ()))
            }
            StdinCommand::Flush { id } => {
                if lock_unpoisoned(&coordinator.state).aborted {
                    continue;
                }
                (id, writer.flush().map(|()| 0).map_err(|_| ()))
            }
        };
        let mut state = lock_unpoisoned(&coordinator.state);
        if state.pending.remove(&id) {
            state.results.insert(id, result);
        }
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn output_poll_distinguishes_pending_data_and_eof() {
        let (control, _commands) = unbounded();
        let output = OutputCoordinator::start(
            Some(Box::new(Cursor::new(b"hello".to_vec()))),
            control,
            ControlCommand::CloseStdout,
        );
        let mut buffer = [0_u8; 16];
        let mut observed = Vec::new();
        for _ in 0..100 {
            match output.try_read(&mut buffer).unwrap() {
                IoReadState::Pending => thread::sleep(Duration::from_millis(1)),
                IoReadState::Data(read) => observed.extend_from_slice(&buffer[..read]),
                IoReadState::Eof => break,
            }
        }
        assert_eq!(observed, b"hello");
        assert_eq!(output.try_read(&mut buffer), Ok(IoReadState::Eof));
    }

    #[test]
    fn stdin_queue_applies_byte_backpressure() {
        let stdin = StdinCoordinator::start(Some(Box::new(Vec::<u8>::new())));
        let oversized = vec![0_u8; STDIN_QUEUE_BYTES + 1];
        assert_eq!(stdin.start_write(&oversized), Ok(None));
    }

    #[test]
    fn stdin_close_prevents_later_operations() {
        let stdin = StdinCoordinator::start(Some(Box::new(Vec::<u8>::new())));
        stdin.close();
        assert_eq!(stdin.start_write(b"late"), Err(IoCoordinatorError::Closed));
        assert_eq!(stdin.start_flush(), Err(IoCoordinatorError::Closed));
    }

    #[test]
    fn stdin_abort_fails_pending_operations_immediately() {
        let (commands, _receiver) = bounded(STDIN_QUEUE_COMMANDS);
        let stdin = StdinCoordinator {
            commands,
            state: Mutex::new(StdinState::default()),
            next_id: AtomicU32::new(1),
            available: true,
        };
        let operation = stdin.start_write(b"pending").unwrap().unwrap();
        stdin.abort();
        assert_eq!(
            stdin.poll(operation),
            Some(Err(IoCoordinatorError::Backend))
        );
    }

    #[test]
    fn closing_output_reports_eof_immediately() {
        let (control, _commands) = unbounded();
        let output = OutputCoordinator::start(
            Some(Box::new(Cursor::new(Vec::<u8>::new()))),
            control,
            ControlCommand::CloseStdout,
        );
        output.close();
        assert_eq!(output.try_read(&mut [0_u8; 1]), Ok(IoReadState::Eof));
    }
}
