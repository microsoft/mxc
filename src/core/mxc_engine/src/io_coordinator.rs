// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Native I/O coordination for event-loop language bindings.
//!
//! The coordinator owns every blocking sandbox operation on native threads.
//! Callers interact through bounded, non-blocking queues, so they never park
//! an event-loop thread in an OS read, write, wait, kill, or destructor.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
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
const MAX_CONSECUTIVE_PROCESS_ERRORS: usize = 100;

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
    terminal_failed: bool,
    error_pending: bool,
    error_reported: bool,
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
    closer: Option<Arc<dyn StreamCloser>>,
    available: bool,
}

impl StdinCoordinator {
    fn unavailable() -> (Arc<Self>, Option<JoinHandle<()>>) {
        let (commands, _) = bounded(0);
        (
            Arc::new(Self {
                commands,
                state: Mutex::new(StdinState {
                    closed: true,
                    ..StdinState::default()
                }),
                next_id: AtomicU32::new(1),
                closer: None,
                available: false,
            }),
            None,
        )
    }

    fn start(
        writer: Option<Box<dyn Write + Send>>,
        closer: Option<Arc<dyn StreamCloser>>,
    ) -> (Arc<Self>, Option<JoinHandle<()>>) {
        let Some(writer) = writer else {
            return Self::unavailable();
        };
        let (commands, receiver) = bounded(STDIN_QUEUE_COMMANDS);
        let coordinator = Arc::new(Self {
            commands,
            state: Mutex::new(StdinState::default()),
            next_id: AtomicU32::new(1),
            closer,
            available: true,
        });
        let worker = Arc::clone(&coordinator);
        let panic_worker = Arc::clone(&coordinator);
        let handle = thread::spawn(move || {
            if catch_unwind(AssertUnwindSafe(|| run_stdin(writer, receiver, worker))).is_err() {
                panic_worker.abort();
            }
        });
        (coordinator, Some(handle))
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

        let id = self.next_operation_id()?;
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
        let id = self.next_operation_id()?;
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
        {
            let mut state = lock_unpoisoned(&self.state);
            state.closed = true;
            state.aborted = true;
            let pending: Vec<_> = state.pending.drain().collect();
            state
                .results
                .extend(pending.into_iter().map(|id| (id, Err(()))));
        }
        close_stream(self.closer.as_deref());
    }

    fn next_operation_id(&self) -> Result<u32, IoCoordinatorError> {
        self.next_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| match id {
                0 => None,
                u32::MAX => Some(0),
                _ => Some(id + 1),
            })
            .map_err(|_| IoCoordinatorError::Closed)
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
    fn unavailable(close_command: ControlCommand) -> (Arc<Self>, Option<JoinHandle<()>>) {
        let (_, messages) = bounded(0);
        let (cancel, _) = bounded(0);
        (
            Arc::new(Self {
                messages,
                cancel,
                read_state: Mutex::new(OutputReadState::default()),
                control: None,
                close_command,
                available: false,
            }),
            None,
        )
    }

    fn start(
        reader: Option<Box<dyn Read + Send>>,
        control: Sender<ControlCommand>,
        close_command: ControlCommand,
    ) -> (Arc<Self>, Option<JoinHandle<()>>) {
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
        let handle = thread::spawn(move || run_output(reader, message_sender, cancel_receiver));
        (coordinator, Some(handle))
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
    workers: Mutex<Vec<JoinHandle<()>>>,
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
        for worker in lock_unpoisoned(&self.workers).drain(..) {
            let _ = worker.join();
        }
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
        let mut state = lock_unpoisoned(&self.shared.process);
        if let Some(result) = state.result {
            return Ok(IoProcessStatus {
                running: false,
                exit_code: result.exit_code,
                timed_out: result.timed_out,
            });
        }
        if state.error_pending {
            state.error_pending = false;
            return Err(IoCoordinatorError::Backend);
        }
        if state.terminal_failed {
            return Err(IoCoordinatorError::Backend);
        }
        Ok(IoProcessStatus {
            running: true,
            exit_code: 0,
            timed_out: false,
        })
    }

    /// Report whether process monitoring reached a terminal state.
    pub fn process_is_terminal(&self) -> bool {
        let state = lock_unpoisoned(&self.shared.process);
        state.result.is_some() || state.terminal_failed
    }

    /// Report whether every native worker has exited and been joined.
    pub fn workers_finished(&self) -> bool {
        let mut workers = lock_unpoisoned(&self.workers);
        if workers.iter().any(|worker| !worker.is_finished()) {
            return false;
        }
        for worker in workers.drain(..) {
            let _ = worker.join();
        }
        true
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
    let stdout_closer: Option<Arc<dyn StreamCloser>> = process.stdout_closer().map(Arc::from);
    let stderr_closer: Option<Arc<dyn StreamCloser>> = process.stderr_closer().map(Arc::from);
    let stdin_closer: Option<Arc<dyn StreamCloser>> = process.stdin_closer().map(Arc::from);
    let stdin = process.take_stdin();
    // A blocking write must be interruptible so shutdown cannot wait forever.
    let stdin = if stdin_closer.is_some() { stdin } else { None };
    let (control_tx, control_rx) = unbounded();
    let (stdin, stdin_worker) = StdinCoordinator::start(stdin, stdin_closer);
    let (stdout, stdout_worker) = OutputCoordinator::start(
        process.take_stdout(),
        control_tx.clone(),
        ControlCommand::CloseStdout,
    );
    let (stderr, stderr_worker) = OutputCoordinator::start(
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
    let panic_shared = Arc::clone(&shared);
    let control_worker = thread::spawn(move || {
        let mut process = process;
        if catch_unwind(AssertUnwindSafe(|| {
            run_control(
                &mut process,
                timeout_ms,
                control_rx,
                stdout_closer.clone(),
                stderr_closer.clone(),
                control_shared,
            )
        }))
        .is_err()
        {
            close_stream(stdout_closer.as_deref());
            close_stream(stderr_closer.as_deref());
            panic_shared.stdin.abort();
            panic_shared.stdout.close();
            panic_shared.stderr.close();
            let mut state = lock_unpoisoned(&panic_shared.process);
            state.terminal_failed = true;
            state
                .warnings
                .push("streaming coordinator control thread panicked".to_string());
        }
    });
    let workers = [stdin_worker, stdout_worker, stderr_worker]
        .into_iter()
        .flatten()
        .chain(std::iter::once(control_worker))
        .collect();
    IoCoordinator {
        shared,
        workers: Mutex::new(workers),
    }
}

fn run_control(
    process: &mut Box<dyn SandboxProcess>,
    timeout_ms: Option<u32>,
    commands: Receiver<ControlCommand>,
    stdout_closer: Option<Arc<dyn StreamCloser>>,
    stderr_closer: Option<Arc<dyn StreamCloser>>,
    shared: Arc<SharedCoordinator>,
) {
    let started_at = Instant::now();
    let mut consecutive_process_errors = 0;
    loop {
        if shared.shutdown_requested.load(Ordering::Acquire) {
            if shutdown_process(
                process,
                &shared,
                stdout_closer.as_deref(),
                stderr_closer.as_deref(),
            ) {
                return;
            }
            if record_consecutive_process_error(&shared, &mut consecutive_process_errors) {
                fail_process_control(&shared, stdout_closer.as_deref(), stderr_closer.as_deref());
                return;
            }
            thread::sleep(CONTROL_POLL_INTERVAL);
            continue;
        }

        match commands.recv_timeout(CONTROL_POLL_INTERVAL) {
            Ok(ControlCommand::Kill) => {
                let finished = match process.kill() {
                    Ok(()) => {
                        consecutive_process_errors = 0;
                        false
                    }
                    Err(_) => {
                        let finished = finish_after_kill_race(&mut **process, &shared);
                        if !finished
                            && record_consecutive_process_error(
                                &shared,
                                &mut consecutive_process_errors,
                            )
                        {
                            fail_process_control(
                                &shared,
                                stdout_closer.as_deref(),
                                stderr_closer.as_deref(),
                            );
                            return;
                        }
                        finished
                    }
                };
                shared.kill_requested.store(false, Ordering::Release);
                if finished {
                    break;
                }
            }
            Ok(ControlCommand::CloseStdout) => close_stream(stdout_closer.as_deref()),
            Ok(ControlCommand::CloseStderr) => close_stream(stderr_closer.as_deref()),
            Ok(ControlCommand::Shutdown) | Err(RecvTimeoutError::Disconnected) => {
                shared.shutdown_requested.store(true, Ordering::Release);
                if shutdown_process(
                    process,
                    &shared,
                    stdout_closer.as_deref(),
                    stderr_closer.as_deref(),
                ) {
                    return;
                }
                continue;
            }
            Err(RecvTimeoutError::Timeout) => {}
        }

        match process.try_wait() {
            Ok(Some(_)) => {
                finish_process(&mut **process, &shared, false);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                finish_process(&mut **process, &shared, true);
                break;
            }
            Err(_) => {
                if record_consecutive_process_error(&shared, &mut consecutive_process_errors) {
                    fail_process_control(
                        &shared,
                        stdout_closer.as_deref(),
                        stderr_closer.as_deref(),
                    );
                    return;
                }
            }
            Ok(None) => consecutive_process_errors = 0,
        }

        if timeout_ms
            .is_some_and(|timeout| started_at.elapsed() >= Duration::from_millis(timeout.into()))
        {
            let finished = match process.try_wait() {
                Ok(Some(_)) => {
                    finish_process(&mut **process, &shared, false);
                    true
                }
                Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                    finish_process(&mut **process, &shared, true);
                    true
                }
                Ok(None) => {
                    consecutive_process_errors = 0;
                    terminate_for_timeout(&mut **process, &shared)
                }
                Err(_) => terminate_for_timeout(&mut **process, &shared),
            };
            if finished {
                break;
            }
            if record_consecutive_process_error(&shared, &mut consecutive_process_errors) {
                fail_process_control(&shared, stdout_closer.as_deref(), stderr_closer.as_deref());
                return;
            }
        }
    }
    run_terminal_control(commands, stdout_closer, stderr_closer);
}

fn terminate_for_timeout(process: &mut dyn SandboxProcess, shared: &SharedCoordinator) -> bool {
    if process.kill_for_timeout().is_err() {
        if finish_after_kill_race(process, shared) {
            true
        } else {
            record_process_error(shared);
            false
        }
    } else {
        finish_process(process, shared, true);
        true
    }
}

fn shutdown_process(
    process: &mut Box<dyn SandboxProcess>,
    shared: &SharedCoordinator,
    stdout_closer: Option<&dyn StreamCloser>,
    stderr_closer: Option<&dyn StreamCloser>,
) -> bool {
    close_stream(stdout_closer);
    close_stream(stderr_closer);
    if process.kill().is_ok() {
        finish_process(&mut **process, shared, false);
        true
    } else if finish_after_kill_race(&mut **process, shared) {
        true
    } else {
        record_process_error(shared);
        false
    }
}

fn record_process_error(shared: &SharedCoordinator) {
    let mut state = lock_unpoisoned(&shared.process);
    if !state.error_reported {
        state.error_pending = true;
        state.error_reported = true;
    }
}

fn record_consecutive_process_error(
    shared: &SharedCoordinator,
    consecutive_process_errors: &mut usize,
) -> bool {
    record_process_error(shared);
    *consecutive_process_errors += 1;
    *consecutive_process_errors >= MAX_CONSECUTIVE_PROCESS_ERRORS
}

fn fail_process_control(
    shared: &SharedCoordinator,
    stdout_closer: Option<&dyn StreamCloser>,
    stderr_closer: Option<&dyn StreamCloser>,
) {
    close_stream(stdout_closer);
    close_stream(stderr_closer);
    shared.stdin.abort();
    shared.stdout.close();
    shared.stderr.close();
    let mut state = lock_unpoisoned(&shared.process);
    state.terminal_failed = true;
    state
        .warnings
        .push("streaming coordinator stopped after repeated backend errors".to_string());
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
    stdout_closer: Option<Arc<dyn StreamCloser>>,
    stderr_closer: Option<Arc<dyn StreamCloser>>,
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
    shared.stdin.abort();
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
        Err(_) => state.terminal_failed = true,
    }
}

fn run_output(
    mut reader: Box<dyn Read + Send>,
    messages: Sender<OutputMessage>,
    cancel: Receiver<()>,
) {
    let mut buffer = vec![0_u8; OUTPUT_CHUNK_BYTES];
    loop {
        let message = match catch_unwind(AssertUnwindSafe(|| reader.read(&mut buffer))) {
            Ok(Ok(0)) => OutputMessage::Eof,
            Ok(Ok(read)) => OutputMessage::Data(buffer[..read].to_vec()),
            Ok(Err(_)) | Err(_) => OutputMessage::Error,
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
    use std::collections::VecDeque;
    use std::io::Cursor;
    use std::sync::atomic::AtomicUsize;

    enum PollStep {
        Running,
        Exited(i32),
        Failed,
        TimedOut,
        Blocked(Arc<AtomicBool>),
        Panic,
    }

    struct ScriptedProcess {
        polls: VecDeque<PollStep>,
        kills: VecDeque<bool>,
        wait_count: Arc<AtomicUsize>,
        kill_count: Arc<AtomicUsize>,
        stdin: Option<Box<dyn Write + Send>>,
        stdout: Option<Box<dyn Read + Send>>,
        stdin_close_flag: Option<Arc<AtomicBool>>,
        stdout_close_flag: Option<Arc<AtomicBool>>,
    }

    struct PanicReader;

    impl Read for PanicReader {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            panic!("read panic")
        }
    }

    struct PanicWriter;

    struct GatedReader {
        released: Arc<AtomicBool>,
    }

    struct GatedWriter {
        entered: Arc<AtomicBool>,
        released: Arc<AtomicBool>,
    }

    struct FlagCloser {
        released: Arc<AtomicBool>,
    }

    struct BlockingCloser {
        entered: Sender<()>,
        release: Receiver<()>,
    }

    impl StreamCloser for FlagCloser {
        fn close(&self) {
            self.released.store(true, Ordering::SeqCst);
        }
    }

    impl StreamCloser for BlockingCloser {
        fn close(&self) {
            let _ = self.entered.send(());
            let _ = self.release.recv();
        }
    }

    impl Read for GatedReader {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            while !self.released.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(1));
            }
            Ok(0)
        }
    }

    impl Write for PanicWriter {
        fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
            panic!("write panic")
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Write for GatedWriter {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.entered.store(true, Ordering::SeqCst);
            while !self.released.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(1));
            }
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl SandboxProcess for ScriptedProcess {
        fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>> {
            self.stdin.take()
        }

        fn stdin_closer(&self) -> Option<Box<dyn StreamCloser>> {
            self.stdin_close_flag.as_ref().map(|released| {
                Box::new(FlagCloser {
                    released: Arc::clone(released),
                }) as Box<dyn StreamCloser>
            })
        }

        fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
            self.stdout.take()
        }

        fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>> {
            None
        }

        fn stdout_closer(&self) -> Option<Box<dyn StreamCloser>> {
            self.stdout_close_flag.as_ref().map(|released| {
                Box::new(FlagCloser {
                    released: Arc::clone(released),
                }) as Box<dyn StreamCloser>
            })
        }

        fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
            if let Some(PollStep::Blocked(gate)) = self.polls.front() {
                if !gate.load(Ordering::SeqCst) {
                    return Ok(None);
                }
                self.polls.pop_front();
                return Ok(None);
            }
            if matches!(self.polls.front(), Some(PollStep::Panic)) {
                panic!("poll panic");
            }
            match self.polls.pop_front().unwrap_or(PollStep::Running) {
                PollStep::Running => Ok(None),
                PollStep::Exited(code) => Ok(Some(code)),
                PollStep::Failed => Err(std::io::Error::other("poll failed")),
                PollStep::TimedOut => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "process timed out",
                )),
                PollStep::Blocked(_) => unreachable!(),
                PollStep::Panic => unreachable!(),
            }
        }

        fn id(&self) -> u32 {
            42
        }

        fn kill(&mut self) -> std::io::Result<()> {
            self.kill_count.fetch_add(1, Ordering::SeqCst);
            if self.kills.pop_front().unwrap_or(true) {
                Ok(())
            } else {
                Err(std::io::Error::other("kill failed"))
            }
        }

        fn wait(&mut self) -> std::io::Result<i32> {
            self.wait_count.fetch_add(1, Ordering::SeqCst);
            Ok(7)
        }
    }

    fn scripted_process(
        polls: impl IntoIterator<Item = PollStep>,
        kills: impl IntoIterator<Item = bool>,
    ) -> (Box<dyn SandboxProcess>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let wait_count = Arc::new(AtomicUsize::new(0));
        let kill_count = Arc::new(AtomicUsize::new(0));
        (
            Box::new(ScriptedProcess {
                polls: polls.into_iter().collect(),
                kills: kills.into_iter().collect(),
                wait_count: Arc::clone(&wait_count),
                kill_count: Arc::clone(&kill_count),
                stdin: None,
                stdout: None,
                stdin_close_flag: None,
                stdout_close_flag: None,
            }),
            wait_count,
            kill_count,
        )
    }

    fn wait_for_terminal(coordinator: &IoCoordinator) -> IoProcessStatus {
        for _ in 0..200 {
            match coordinator.poll_process() {
                Ok(status) if !status.running => return status,
                Ok(_) | Err(_) => thread::sleep(Duration::from_millis(1)),
            }
        }
        panic!("coordinator did not reach a terminal state");
    }

    #[test]
    fn output_poll_distinguishes_pending_data_and_eof() {
        let (control, _commands) = unbounded();
        let (output, _worker) = OutputCoordinator::start(
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
        let (stdin, _worker) = StdinCoordinator::start(Some(Box::new(Vec::<u8>::new())), None);
        let oversized = vec![0_u8; STDIN_QUEUE_BYTES + 1];
        assert_eq!(stdin.start_write(&oversized), Ok(None));
    }

    #[test]
    fn stdin_queue_applies_command_backpressure() {
        let (commands, _receiver) = bounded(STDIN_QUEUE_COMMANDS);
        let stdin = StdinCoordinator {
            commands,
            state: Mutex::new(StdinState::default()),
            next_id: AtomicU32::new(1),
            available: true,
            closer: None,
        };

        for _ in 0..STDIN_QUEUE_COMMANDS {
            assert!(stdin.start_write(&[]).unwrap().is_some());
        }
        assert_eq!(stdin.start_write(&[]), Ok(None));
    }

    #[test]
    fn stdin_operation_ids_stop_after_exhaustion() {
        let (commands, _receiver) = bounded(1);
        let stdin = StdinCoordinator {
            commands,
            state: Mutex::new(StdinState::default()),
            next_id: AtomicU32::new(u32::MAX),
            available: true,
            closer: None,
        };

        assert_eq!(stdin.next_operation_id(), Ok(u32::MAX));
        assert_eq!(stdin.next_operation_id(), Err(IoCoordinatorError::Closed));
    }

    #[test]
    fn stdin_close_prevents_later_operations() {
        let (stdin, _worker) = StdinCoordinator::start(Some(Box::new(Vec::<u8>::new())), None);
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
            closer: None,
        };
        let operation = stdin.start_write(b"pending").unwrap().unwrap();
        stdin.abort();
        assert_eq!(
            stdin.poll(operation),
            Some(Err(IoCoordinatorError::Backend))
        );
    }

    #[test]
    fn stdin_abort_rejects_writes_before_closing_the_backend() {
        let (commands, _receiver) = bounded(STDIN_QUEUE_COMMANDS);
        let (entered_tx, entered_rx) = bounded(1);
        let (release_tx, release_rx) = bounded(1);
        let stdin = Arc::new(StdinCoordinator {
            commands,
            state: Mutex::new(StdinState::default()),
            next_id: AtomicU32::new(1),
            available: true,
            closer: Some(Arc::new(BlockingCloser {
                entered: entered_tx,
                release: release_rx,
            })),
        });
        let aborting_stdin = Arc::clone(&stdin);
        let aborter = thread::spawn(move || aborting_stdin.abort());

        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let result = stdin.start_write(b"late");
        release_tx.send(()).unwrap();
        aborter.join().unwrap();
        assert_eq!(result, Err(IoCoordinatorError::Closed));
    }

    #[test]
    fn closing_output_reports_eof_immediately() {
        let (control, _commands) = unbounded();
        let (output, _worker) = OutputCoordinator::start(
            Some(Box::new(Cursor::new(Vec::<u8>::new()))),
            control,
            ControlCommand::CloseStdout,
        );
        output.close();
        assert_eq!(output.try_read(&mut [0_u8; 1]), Ok(IoReadState::Eof));
    }

    #[test]
    fn output_poll_preserves_partial_chunk_offsets() {
        let (messages, receiver) = bounded(1);
        messages
            .send(OutputMessage::Data((0_u8..100).collect()))
            .unwrap();
        let (cancel, _cancel_receiver) = bounded(1);
        let output = OutputCoordinator {
            messages: receiver,
            cancel,
            read_state: Mutex::new(OutputReadState::default()),
            control: None,
            close_command: ControlCommand::CloseStdout,
            available: true,
        };
        let mut observed = Vec::new();
        let mut buffer = [0_u8; 30];

        for expected in [30, 30, 30, 10] {
            let read = match output.try_read(&mut buffer).unwrap() {
                IoReadState::Data(read) => read,
                state => panic!("expected data, got {state:?}"),
            };
            assert_eq!(read, expected);
            observed.extend_from_slice(&buffer[..read]);
        }

        assert_eq!(observed, (0_u8..100).collect::<Vec<_>>());
    }

    #[test]
    fn output_reader_error_is_reported() {
        let (messages, receiver) = bounded(1);
        messages.send(OutputMessage::Error).unwrap();
        let (cancel, _cancel_receiver) = bounded(1);
        let output = OutputCoordinator {
            messages: receiver,
            cancel,
            read_state: Mutex::new(OutputReadState::default()),
            control: None,
            close_command: ControlCommand::CloseStdout,
            available: true,
        };

        assert_eq!(
            output.try_read(&mut [0_u8; 1]),
            Err(IoCoordinatorError::Backend)
        );
    }

    #[test]
    fn output_reader_panic_is_reported() {
        let (control, _commands) = unbounded();
        let (output, _worker) = OutputCoordinator::start(
            Some(Box::new(PanicReader)),
            control,
            ControlCommand::CloseStdout,
        );

        for _ in 0..200 {
            match output.try_read(&mut [0_u8; 1]) {
                Err(IoCoordinatorError::Backend) => return,
                Ok(IoReadState::Pending) => thread::sleep(Duration::from_millis(1)),
                state => panic!("expected backend error, got {state:?}"),
            }
        }
        panic!("reader panic was not reported");
    }

    #[test]
    fn stdin_writer_panic_fails_pending_operation() {
        let (stdin, _worker) = StdinCoordinator::start(Some(Box::new(PanicWriter)), None);
        let operation = stdin.start_write(b"panic").unwrap().unwrap();

        for _ in 0..200 {
            match stdin.poll(operation) {
                Some(Err(IoCoordinatorError::Backend)) => return,
                None => thread::sleep(Duration::from_millis(1)),
                result => panic!("expected backend error, got {result:?}"),
            }
        }
        panic!("writer panic did not fail the pending operation");
    }

    #[test]
    fn kill_race_finishes_process_once() {
        let (process, wait_count, _) = scripted_process([PollStep::Exited(7)], [false]);
        let coordinator = coordinate_io(process, None);

        coordinator.request_kill().unwrap();

        assert_eq!(
            wait_for_terminal(&coordinator),
            IoProcessStatus {
                running: false,
                exit_code: 7,
                timed_out: false,
            }
        );
        assert_eq!(wait_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn transient_poll_error_does_not_end_process_monitoring() {
        let release_exit = Arc::new(AtomicBool::new(false));
        let (process, wait_count, _) = scripted_process(
            [
                PollStep::Failed,
                PollStep::Blocked(Arc::clone(&release_exit)),
                PollStep::Exited(7),
            ],
            [],
        );
        let coordinator = coordinate_io(process, None);
        let mut observed_error = false;

        for _ in 0..200 {
            match coordinator.poll_process() {
                Err(IoCoordinatorError::Backend) => {
                    observed_error = true;
                    release_exit.store(true, Ordering::SeqCst);
                }
                Ok(status) if !status.running => break,
                Ok(_) => {}
                Err(IoCoordinatorError::Closed) => unreachable!(),
            }
            thread::sleep(Duration::from_millis(1));
        }

        assert!(observed_error);
        assert_eq!(wait_for_terminal(&coordinator).exit_code, 7);
        assert_eq!(wait_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn shutdown_retries_kill_until_process_is_reaped() {
        let (process, wait_count, kill_count) =
            scripted_process([PollStep::Running], [false, true]);
        let coordinator = coordinate_io(process, None);

        coordinator.request_shutdown();

        assert_eq!(wait_for_terminal(&coordinator).exit_code, 7);
        assert_eq!(kill_count.load(Ordering::SeqCst), 2);
        assert_eq!(wait_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn persistent_shutdown_errors_do_not_block_worker_completion() {
        let (process, _, kill_count) = scripted_process(
            std::iter::repeat_with(|| PollStep::Failed).take(MAX_CONSECUTIVE_PROCESS_ERRORS),
            std::iter::repeat_n(false, MAX_CONSECUTIVE_PROCESS_ERRORS),
        );
        let coordinator = coordinate_io(process, None);

        coordinator.request_shutdown();

        for _ in 0..2_000 {
            if coordinator.workers_finished() {
                assert_eq!(
                    kill_count.load(Ordering::SeqCst),
                    MAX_CONSECUTIVE_PROCESS_ERRORS
                );
                return;
            }
            thread::sleep(Duration::from_millis(1));
        }
        panic!("persistent backend errors kept the control worker alive");
    }

    #[test]
    fn terminal_process_rejects_late_stdin() {
        let wait_count = Arc::new(AtomicUsize::new(0));
        let process = Box::new(ScriptedProcess {
            polls: [PollStep::Exited(7)].into_iter().collect(),
            kills: VecDeque::new(),
            wait_count,
            kill_count: Arc::new(AtomicUsize::new(0)),
            stdin: Some(Box::new(Vec::<u8>::new())),
            stdout: None,
            stdin_close_flag: None,
            stdout_close_flag: None,
        });
        let coordinator = coordinate_io(process, None);

        assert_eq!(wait_for_terminal(&coordinator).exit_code, 7);
        assert_eq!(
            coordinator.start_write(b"late"),
            Err(IoCoordinatorError::Closed)
        );
    }

    #[test]
    fn process_exit_interrupts_an_in_flight_stdin_write() {
        let entered = Arc::new(AtomicBool::new(false));
        let released = Arc::new(AtomicBool::new(false));
        let process = Box::new(ScriptedProcess {
            polls: [PollStep::Blocked(Arc::clone(&entered)), PollStep::Exited(7)]
                .into_iter()
                .collect(),
            kills: VecDeque::new(),
            wait_count: Arc::new(AtomicUsize::new(0)),
            kill_count: Arc::new(AtomicUsize::new(0)),
            stdin: Some(Box::new(GatedWriter {
                entered: Arc::clone(&entered),
                released: Arc::clone(&released),
            })),
            stdout: None,
            stdin_close_flag: Some(Arc::clone(&released)),
            stdout_close_flag: None,
        });
        let coordinator = coordinate_io(process, None);
        let operation = coordinator.start_write(b"blocked").unwrap().unwrap();

        assert_eq!(wait_for_terminal(&coordinator).exit_code, 7);
        assert!(released.load(Ordering::SeqCst));
        assert!(coordinator.poll_stdin(operation).is_some());
        coordinator.request_shutdown();
        for _ in 0..200 {
            if coordinator.workers_finished() {
                return;
            }
            thread::sleep(Duration::from_millis(1));
        }
        panic!("stdin closer did not release the blocked worker");
    }

    #[test]
    fn backend_without_stdin_closer_does_not_expose_stdin() {
        let release_exit = Arc::new(AtomicBool::new(false));
        let process = Box::new(ScriptedProcess {
            polls: [
                PollStep::Blocked(Arc::clone(&release_exit)),
                PollStep::Exited(7),
            ]
            .into_iter()
            .collect(),
            kills: VecDeque::new(),
            wait_count: Arc::new(AtomicUsize::new(0)),
            kill_count: Arc::new(AtomicUsize::new(0)),
            stdin: Some(Box::new(Vec::<u8>::new())),
            stdout: None,
            stdin_close_flag: None,
            stdout_close_flag: None,
        });
        let coordinator = coordinate_io(process, None);

        assert_eq!(
            coordinator.start_write(b"unsupported"),
            Err(IoCoordinatorError::Closed)
        );

        release_exit.store(true, Ordering::SeqCst);
        assert_eq!(wait_for_terminal(&coordinator).exit_code, 7);
    }

    #[test]
    fn coordinator_deadline_kills_and_reports_timeout() {
        let (process, wait_count, kill_count) = scripted_process([PollStep::Running], [true]);
        let coordinator = coordinate_io(process, Some(1));

        assert_eq!(
            wait_for_terminal(&coordinator),
            IoProcessStatus {
                running: false,
                exit_code: 7,
                timed_out: true,
            }
        );
        assert_eq!(kill_count.load(Ordering::SeqCst), 1);
        assert_eq!(wait_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn coordinator_deadline_kills_after_poll_failure() {
        let (process, wait_count, kill_count) =
            scripted_process([PollStep::Failed, PollStep::Failed], [true]);
        let coordinator = coordinate_io(process, Some(1));

        assert_eq!(
            wait_for_terminal(&coordinator),
            IoProcessStatus {
                running: false,
                exit_code: 7,
                timed_out: true,
            }
        );
        assert_eq!(kill_count.load(Ordering::SeqCst), 1);
        assert_eq!(wait_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn coordinator_deadline_accepts_timeout_from_recheck() {
        let (process, wait_count, kill_count) =
            scripted_process([PollStep::Running, PollStep::TimedOut], []);
        let coordinator = coordinate_io(process, Some(1));

        assert_eq!(
            wait_for_terminal(&coordinator),
            IoProcessStatus {
                running: false,
                exit_code: 7,
                timed_out: true,
            }
        );
        assert_eq!(kill_count.load(Ordering::SeqCst), 0);
        assert_eq!(wait_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn repeated_control_thread_panic_reports_terminal_failure() {
        let (process, _, _) = scripted_process([PollStep::Panic], []);
        let coordinator = coordinate_io(process, None);

        for _ in 0..200 {
            if coordinator.process_is_terminal() {
                assert_eq!(coordinator.poll_process(), Err(IoCoordinatorError::Backend));
                return;
            }
            thread::sleep(Duration::from_millis(1));
        }
        panic!("control thread panic did not reach terminal failure");
    }

    #[test]
    fn shutdown_waits_for_all_native_workers() {
        let released = Arc::new(AtomicBool::new(false));
        let process = Box::new(ScriptedProcess {
            polls: [PollStep::Exited(7)].into_iter().collect(),
            kills: VecDeque::new(),
            wait_count: Arc::new(AtomicUsize::new(0)),
            kill_count: Arc::new(AtomicUsize::new(0)),
            stdin: None,
            stdout: Some(Box::new(GatedReader {
                released: Arc::clone(&released),
            })),
            stdin_close_flag: None,
            stdout_close_flag: None,
        });
        let coordinator = coordinate_io(process, None);

        assert_eq!(wait_for_terminal(&coordinator).exit_code, 7);
        coordinator.request_shutdown();
        assert!(!coordinator.workers_finished());

        released.store(true, Ordering::SeqCst);
        for _ in 0..200 {
            if coordinator.workers_finished() {
                return;
            }
            thread::sleep(Duration::from_millis(1));
        }
        panic!("coordinator reported shutdown before every worker exited");
    }

    #[test]
    fn control_panic_closes_blocked_output_worker() {
        let released = Arc::new(AtomicBool::new(false));
        let process = Box::new(ScriptedProcess {
            polls: [PollStep::Panic].into_iter().collect(),
            kills: VecDeque::new(),
            wait_count: Arc::new(AtomicUsize::new(0)),
            kill_count: Arc::new(AtomicUsize::new(0)),
            stdin: None,
            stdout: Some(Box::new(GatedReader {
                released: Arc::clone(&released),
            })),
            stdin_close_flag: None,
            stdout_close_flag: Some(Arc::clone(&released)),
        });
        let coordinator = coordinate_io(process, None);

        for _ in 0..200 {
            if coordinator.process_is_terminal() && coordinator.workers_finished() {
                assert!(released.load(Ordering::SeqCst));
                return;
            }
            thread::sleep(Duration::from_millis(1));
        }
        panic!("control panic did not close and join the output worker");
    }
}
