// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Native process lifecycle coordination for event-loop language bindings.
//!
//! Stdio ownership is transferred to the language runtime as native endpoints.
//! This module retains only process lifecycle responsibilities: timeout
//! enforcement, kill, reaping, warnings, metadata, and terminal status.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crossbeam_channel::{unbounded, Receiver, RecvTimeoutError, Sender};
use wxc_common::models::SandboxOutputMetadata;
use wxc_common::sandbox_process::{NativeStdio, SandboxProcess};

use crate::{spawn, Error, ErrorCode, SandboxRequest};

const CONTROL_POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_CONSECUTIVE_PROCESS_ERRORS: usize = 100;

/// A non-blocking snapshot of a coordinated process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoProcessStatus {
    /// Whether the process is still running.
    pub running: bool,
    /// The terminal exit code. Meaningful only when `running` is false.
    pub exit_code: i32,
    /// Whether the configured deadline terminated the process.
    pub timed_out: bool,
}

/// Failures produced by lifecycle operations after a sandbox has spawned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoCoordinatorError {
    /// The coordinator no longer accepts commands.
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
    error_reported: bool,
    warnings: Vec<String>,
    output_metadata: Option<SandboxOutputMetadata>,
}

#[derive(Clone, Copy)]
enum ControlCommand {
    Kill,
    Shutdown,
}

struct SharedCoordinator {
    id: u32,
    process: Mutex<ProcessState>,
    stdio: Mutex<Option<NativeStdio>>,
    control: Sender<ControlCommand>,
    kill_requested: AtomicBool,
    shutdown_requested: AtomicBool,
}

impl SharedCoordinator {
    fn request_shutdown(&self) {
        if !self.shutdown_requested.swap(true, Ordering::AcqRel) {
            let _ = self.control.send(ControlCommand::Shutdown);
        }
    }
}

/// Coordinates a sandbox process without transporting its stdio bytes.
pub struct IoCoordinator {
    shared: Arc<SharedCoordinator>,
    worker: Mutex<Option<JoinHandle<()>>>,
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
        if let Some(worker) = lock_unpoisoned(&self.worker).take() {
            let _ = worker.join();
        }
    }
}

impl IoCoordinator {
    /// Return the child process identifier.
    pub fn id(&self) -> u32 {
        self.shared.id
    }

    /// Transfer the native stdio endpoints exactly once.
    pub fn take_native_stdio(&self) -> Option<NativeStdio> {
        lock_unpoisoned(&self.shared.stdio).take()
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

    /// Report whether the native lifecycle worker has exited and been joined.
    pub fn workers_finished(&self) -> bool {
        let mut worker = lock_unpoisoned(&self.worker);
        if worker.as_ref().is_some_and(|worker| !worker.is_finished()) {
            return false;
        }
        if let Some(worker) = worker.take() {
            let _ = worker.join();
        }
        true
    }

    /// Queue a process-tree kill.
    pub fn request_kill(&self) -> Result<(), IoCoordinatorError> {
        if self.process_is_terminal() || self.shared.kill_requested.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        self.shared.control.send(ControlCommand::Kill).or_else(|_| {
            self.shared.kill_requested.store(false, Ordering::Release);
            if self.process_is_terminal() {
                Ok(())
            } else {
                Err(IoCoordinatorError::Closed)
            }
        })
    }

    /// Request process shutdown.
    pub fn request_shutdown(&self) {
        self.shared.request_shutdown();
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

/// Spawn a sandbox under native lifecycle coordination.
pub fn spawn_io(request: &SandboxRequest) -> Result<IoCoordinator, Error> {
    let timeout_ms = (request.inner.script_timeout > 0).then_some(request.inner.script_timeout);
    coordinate_io(spawn(request)?, timeout_ms)
}

/// Wrap an already-spawned process under native lifecycle coordination.
pub fn coordinate_io(
    mut process: Box<dyn SandboxProcess>,
    timeout_ms: Option<u32>,
) -> Result<IoCoordinator, Error> {
    let stdio = process
        .take_native_stdio()
        .map_err(|error| Error::new(ErrorCode::BackendError, error.to_string()))?
        .filter(|stdio| !stdio.is_empty())
        .ok_or_else(|| {
            Error::new(
                ErrorCode::UnsupportedContainment,
                "the selected backend does not expose transferable native stdio endpoints",
            )
        })?;
    Ok(start_coordinator(process, stdio, timeout_ms))
}

fn start_coordinator(
    process: Box<dyn SandboxProcess>,
    stdio: NativeStdio,
    timeout_ms: Option<u32>,
) -> IoCoordinator {
    let id = process.id();
    let warnings = process.warnings();
    let (control_tx, control_rx) = unbounded();
    let shared = Arc::new(SharedCoordinator {
        id,
        process: Mutex::new(ProcessState {
            warnings,
            ..ProcessState::default()
        }),
        stdio: Mutex::new(Some(stdio)),
        control: control_tx,
        kill_requested: AtomicBool::new(false),
        shutdown_requested: AtomicBool::new(false),
    });
    let worker_shared = Arc::clone(&shared);
    let panic_shared = Arc::clone(&shared);
    let worker = thread::spawn(move || {
        let mut process = process;
        if catch_unwind(AssertUnwindSafe(|| {
            run_control(
                &mut process,
                timeout_ms.filter(|timeout| *timeout > 0),
                control_rx,
                worker_shared,
            );
        }))
        .is_err()
        {
            let mut state = lock_unpoisoned(&panic_shared.process);
            state.terminal_failed = true;
            state
                .warnings
                .push("sandbox lifecycle coordinator thread panicked".to_string());
        }
    });
    IoCoordinator {
        shared,
        worker: Mutex::new(Some(worker)),
    }
}

fn run_control(
    process: &mut Box<dyn SandboxProcess>,
    timeout_ms: Option<u32>,
    commands: Receiver<ControlCommand>,
    shared: Arc<SharedCoordinator>,
) {
    let started_at = Instant::now();
    let mut consecutive_process_errors = 0;
    loop {
        if shared.shutdown_requested.load(Ordering::Acquire) {
            if shutdown_process(process, &shared) {
                return;
            }
            if record_consecutive_process_error(&shared, &mut consecutive_process_errors) {
                fail_process_control(&shared);
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
                            fail_process_control(&shared);
                            return;
                        }
                        finished
                    }
                };
                shared.kill_requested.store(false, Ordering::Release);
                if finished {
                    return;
                }
            }
            Ok(ControlCommand::Shutdown) | Err(RecvTimeoutError::Disconnected) => {
                shared.shutdown_requested.store(true, Ordering::Release);
                continue;
            }
            Err(RecvTimeoutError::Timeout) => {}
        }

        match process.try_wait() {
            Ok(Some(_)) => {
                finish_process(&mut **process, &shared, false);
                return;
            }
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                finish_process(&mut **process, &shared, true);
                return;
            }
            Err(_) => {
                if record_consecutive_process_error(&shared, &mut consecutive_process_errors) {
                    fail_process_control(&shared);
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
                return;
            }
            if record_consecutive_process_error(&shared, &mut consecutive_process_errors) {
                fail_process_control(&shared);
                return;
            }
        }
    }
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

fn shutdown_process(process: &mut Box<dyn SandboxProcess>, shared: &SharedCoordinator) -> bool {
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
        Err(_) => state.terminal_failed = true,
    }
}

fn record_process_error(shared: &SharedCoordinator) {
    let mut state = lock_unpoisoned(&shared.process);
    if !state.error_reported {
        state.error_reported = true;
        state
            .warnings
            .push("sandbox lifecycle monitoring encountered a transient backend error".to_string());
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

fn fail_process_control(shared: &SharedCoordinator) {
    let mut state = lock_unpoisoned(&shared.process);
    state.terminal_failed = true;
    state
        .warnings
        .push("sandbox lifecycle coordinator stopped after repeated backend errors".to_string());
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
    use std::sync::atomic::AtomicUsize;

    enum PollStep {
        Running,
        Exited(i32),
    }

    struct ScriptedProcess {
        polls: VecDeque<PollStep>,
        exit_code: i32,
        kill_count: Arc<AtomicUsize>,
        timeout_kill_count: Arc<AtomicUsize>,
    }

    impl SandboxProcess for ScriptedProcess {
        fn take_stdin(&mut self) -> Option<Box<dyn std::io::Write + Send>> {
            None
        }

        fn take_stdout(&mut self) -> Option<Box<dyn std::io::Read + Send>> {
            None
        }

        fn take_stderr(&mut self) -> Option<Box<dyn std::io::Read + Send>> {
            None
        }

        fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
            if self.exit_code == -1 {
                return Ok(Some(-1));
            }
            Ok(match self.polls.pop_front().unwrap_or(PollStep::Running) {
                PollStep::Running => None,
                PollStep::Exited(code) => {
                    self.exit_code = code;
                    Some(code)
                }
            })
        }

        fn wait(&mut self) -> std::io::Result<i32> {
            Ok(self.exit_code)
        }

        fn id(&self) -> u32 {
            42
        }

        fn kill(&mut self) -> std::io::Result<()> {
            self.kill_count.fetch_add(1, Ordering::Relaxed);
            self.exit_code = -1;
            Ok(())
        }

        fn kill_for_timeout(&mut self) -> std::io::Result<()> {
            self.timeout_kill_count.fetch_add(1, Ordering::Relaxed);
            self.exit_code = -1;
            Ok(())
        }
    }

    fn empty_stdio() -> NativeStdio {
        NativeStdio {
            stdin: None,
            stdout: None,
            stderr: None,
        }
    }

    fn wait_for_terminal(coordinator: &IoCoordinator) -> IoProcessStatus {
        for _ in 0..200 {
            if let Ok(status) = coordinator.poll_process() {
                if !status.running {
                    return status;
                }
            }
            thread::sleep(Duration::from_millis(1));
        }
        panic!("coordinator did not reach a terminal state");
    }

    #[test]
    fn native_stdio_is_transferred_once() {
        let process = Box::new(ScriptedProcess {
            polls: VecDeque::from([PollStep::Exited(0)]),
            exit_code: 0,
            kill_count: Arc::new(AtomicUsize::new(0)),
            timeout_kill_count: Arc::new(AtomicUsize::new(0)),
        });
        let coordinator = start_coordinator(process, empty_stdio(), None);

        assert!(coordinator.take_native_stdio().is_some());
        assert!(coordinator.take_native_stdio().is_none());
    }

    #[test]
    fn terminal_exit_is_reported() {
        let process = Box::new(ScriptedProcess {
            polls: VecDeque::from([PollStep::Running, PollStep::Exited(23)]),
            exit_code: 0,
            kill_count: Arc::new(AtomicUsize::new(0)),
            timeout_kill_count: Arc::new(AtomicUsize::new(0)),
        });
        let coordinator = start_coordinator(process, empty_stdio(), None);

        assert_eq!(
            wait_for_terminal(&coordinator),
            IoProcessStatus {
                running: false,
                exit_code: 23,
                timed_out: false,
            }
        );
    }

    #[test]
    fn kill_is_serialized_through_the_control_thread() {
        let kill_count = Arc::new(AtomicUsize::new(0));
        let process = Box::new(ScriptedProcess {
            polls: VecDeque::new(),
            exit_code: 0,
            kill_count: Arc::clone(&kill_count),
            timeout_kill_count: Arc::new(AtomicUsize::new(0)),
        });
        let coordinator = start_coordinator(process, empty_stdio(), None);

        coordinator.request_kill().expect("kill should be accepted");
        assert_eq!(wait_for_terminal(&coordinator).exit_code, -1);
        assert_eq!(kill_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn timeout_uses_timeout_kill_and_marks_the_result() {
        let timeout_kill_count = Arc::new(AtomicUsize::new(0));
        let process = Box::new(ScriptedProcess {
            polls: VecDeque::new(),
            exit_code: 0,
            kill_count: Arc::new(AtomicUsize::new(0)),
            timeout_kill_count: Arc::clone(&timeout_kill_count),
        });
        let coordinator = start_coordinator(process, empty_stdio(), Some(1));

        let status = wait_for_terminal(&coordinator);
        assert_eq!(status.exit_code, -1);
        assert!(status.timed_out);
        assert_eq!(timeout_kill_count.load(Ordering::Relaxed), 1);
    }
}
