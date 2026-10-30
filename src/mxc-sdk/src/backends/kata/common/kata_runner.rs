// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Create-and-run execution in a Kata microVM.
//!
//! [`KataBackend`] implements [`SandboxBackend`]: it validates the request,
//! provisions and starts a sandbox that lives for this request, and runs the
//! command as a process in it. The executors reach it through `Runner`, which
//! gives run-to-completion, and the SDK through `spawn`, which gives live
//! streams. Either way the sandbox is stopped and released when the handle
//! finishes or is dropped.

use std::fs::File;
use std::io::{self, PipeWriter, Read, Write};
use std::os::fd::OwnedFd;
use std::time::{Duration, Instant};

use crate::kata_common::error::KataError;
use crate::kata_common::execution::{Execution, ExitOutcome, KillScope, Pump, StdinWriter};
use crate::kata_common::host::{self, Install};
use crate::kata_common::policy::{self, Plan};
use crate::kata_common::sandbox::Ephemeral;
use crate::mxc_common::interruptible_reader::{InterruptibleReader, ReadCanceller};
use crate::mxc_common::logger::Logger;
use crate::mxc_common::models::{ExecutionRequest, ScriptResponse};
use crate::mxc_common::sandbox_process::{
    boxed_closer, cancel_and_join_discard, spawn_discard, take_boxed_read, take_boxed_write,
    SandboxBackend, SandboxProcess, StdioMode, StreamCloser,
};
use crate::mxc_common::validator::{validate_common, NetworkPolicySupport};

/// How long output may keep arriving after the process exits, when it goes to
/// this process's own streams.
const OUTPUT_GRACE: Duration = Duration::from_secs(5);

/// Accepts a request and finds what it needs on the host.
///
/// Policy problems are reported before host problems, and nothing is created.
fn prepare(request: &ExecutionRequest, logger: &mut Logger) -> Result<(Plan, Install), KataError> {
    let config = policy::kata_config(request)?;
    let plan = policy::plan(request, config, &host::process_env, logger)?;
    let install = host::locate_installed(plan.hypervisor).map_err(KataError::unavailable)?;
    host::check_prerequisites().map_err(KataError::unavailable)?;
    Ok((plan, install))
}

/// The Kata Containers backend.
#[derive(Debug, Default)]
pub struct KataBackend;

impl KataBackend {
    pub fn new() -> Self {
        Self
    }
}

impl SandboxBackend for KataBackend {
    fn network_policy_support(&self) -> NetworkPolicySupport {
        policy::network_support()
    }

    fn validate(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        // The shared network check runs inside `prepare`, as the trait asks.
        prepare(
            request,
            &mut Logger::new(crate::mxc_common::logger::Mode::Buffer),
        )
        .map(drop)
        .map_err(KataError::into_response)
    }

    fn spawn(
        &mut self,
        request: &ExecutionRequest,
        logger: &mut Logger,
        stdio: StdioMode,
    ) -> Result<Box<dyn SandboxProcess>, ScriptResponse> {
        validate_common(request)?;
        if matches!(stdio, StdioMode::Pty(_)) {
            return Err(ScriptResponse::rejected(
                "the kata backend does not support a pseudo-terminal yet; use piped standard \
                 streams",
            ));
        }
        let (plan, install) = prepare(request, logger).map_err(KataError::into_response)?;
        let state_root = host::state_dir(&host::process_env);
        logger.log_line(&format!(
            "Starting a Kata sandbox on {} with rootfs {}",
            plan.hypervisor.wire_name(),
            plan.rootfs.display()
        ));
        let process = KataProcess::start(request, &plan, &install, &state_root, stdio)
            .map_err(KataError::into_response)?;
        Ok(Box::new(process))
    }
}

fn duplicate_standard_stream(fd: i32) -> io::Result<File> {
    // SAFETY: the standard descriptors are valid for the borrow's duration.
    let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
    borrowed.try_clone_to_owned().map(File::from)
}

/// The sandboxed process of one create-and-run request.
pub struct KataProcess {
    exec: Execution,
    stdin: Option<PipeWriter>,
    stdout: Option<InterruptibleReader>,
    stderr: Option<InterruptibleReader>,
    stdout_canceller: Option<ReadCanceller>,
    stderr_canceller: Option<ReadCanceller>,
    /// Present in `Inherit` mode, where the process's output goes to this
    /// process's own streams.
    output_pumps: Vec<Pump>,
    /// Feeds the process's input: from the caller's pipe, or this process's stdin.
    stdin_pump: Option<Pump>,
    deadline: Option<Instant>,
    timed_out: bool,
    exit: Option<i32>,
    shim_pid: u32,
    warnings: Vec<String>,
    finished: bool,
    /// Last, so the process is killed and released before the sandbox goes.
    ephemeral: Ephemeral,
}

impl KataProcess {
    fn start(
        request: &ExecutionRequest,
        plan: &Plan,
        install: &Install,
        state_root: &std::path::Path,
        stdio: StdioMode,
    ) -> Result<Self, KataError> {
        let mut ephemeral = Ephemeral::create(plan, install, state_root)?;
        let shim_pid = ephemeral.sandbox().shim_pid().unwrap_or(0);
        let mut exec = ephemeral.sandbox().exec(request, KillScope::Sandbox)?;
        let streams = (exec.take_stdin(), exec.take_stdout(), exec.take_stderr());
        let mut process = Self {
            exec,
            stdin: None,
            stdout: None,
            stderr: None,
            stdout_canceller: None,
            stderr_canceller: None,
            output_pumps: Vec::new(),
            stdin_pump: None,
            // The deadline starts when the command does, not when the VM boots.
            deadline: (request.script_timeout > 0)
                .then(|| Instant::now() + Duration::from_millis(u64::from(request.script_timeout))),
            timed_out: false,
            exit: None,
            shim_pid,
            warnings: Vec::new(),
            finished: false,
            ephemeral,
        };
        // A failure here drops `process`, which kills the command and releases
        // the sandbox.
        process.attach_streams(streams, stdio)?;
        Ok(process)
    }

    fn attach_streams(
        &mut self,
        (stdin, stdout, stderr): (Option<StdinWriter>, Option<OwnedFd>, Option<OwnedFd>),
        stdio: StdioMode,
    ) -> Result<(), KataError> {
        let io_error = |what: &str, e: io::Error| {
            KataError::failed(format!("preparing the {what} stream: {e}"))
        };
        match stdio {
            StdioMode::Pipes => {
                // A pipe, so a write cannot outlive the process.
                if let Some(writer) = stdin {
                    let (write_end, pump) = Pump::pipe(writer).map_err(|e| io_error("stdin", e))?;
                    self.stdin = Some(write_end);
                    self.stdin_pump = Some(pump);
                }
                for (slot, canceller, source, name) in [
                    (
                        &mut self.stdout,
                        &mut self.stdout_canceller,
                        stdout,
                        "stdout",
                    ),
                    (
                        &mut self.stderr,
                        &mut self.stderr_canceller,
                        stderr,
                        "stderr",
                    ),
                ] {
                    if let Some(source) = source {
                        let reader =
                            InterruptibleReader::new(source).map_err(|e| io_error(name, e))?;
                        *canceller = Some(reader.canceller());
                        *slot = Some(reader);
                    }
                }
            }
            StdioMode::Inherit => {
                for (source, standard, name) in [(stdout, 1, "stdout"), (stderr, 2, "stderr")] {
                    if let Some(source) = source {
                        let target =
                            duplicate_standard_stream(standard).map_err(|e| io_error(name, e))?;
                        self.output_pumps
                            .push(Pump::start(source, target).map_err(|e| io_error(name, e))?);
                    }
                }
                if let Some(writer) = stdin {
                    self.stdin_pump =
                        Some(Pump::start(io::stdin(), writer).map_err(|e| io_error("stdin", e))?);
                }
            }
            StdioMode::Pty(_) => unreachable!("rejected before the sandbox is created"),
        }
        Ok(())
    }

    /// Ends the process's streams and releases the sandbox. Runs once.
    fn finish(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        if let Some(pump) = self.stdin_pump.take() {
            pump.stop();
        }
        for pump in self.output_pumps.drain(..) {
            pump.finish(OUTPUT_GRACE);
        }
        self.exec.release();
        let failures = self.ephemeral.teardown();
        self.warnings
            .extend(failures.into_iter().map(|f| format!("Kata cleanup: {f}")));
    }

    fn timed_out_error() -> io::Error {
        io::Error::new(io::ErrorKind::TimedOut, "Kata: script timed out")
    }
}

impl SandboxProcess for KataProcess {
    fn warnings(&self) -> Vec<String> {
        self.warnings.clone()
    }

    fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>> {
        take_boxed_write(&mut self.stdin)
    }

    fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
        take_boxed_read(&mut self.stdout)
    }

    fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>> {
        take_boxed_read(&mut self.stderr)
    }

    fn stdout_closer(&self) -> Option<Box<dyn StreamCloser>> {
        boxed_closer(&self.stdout_canceller)
    }

    fn stderr_closer(&self) -> Option<Box<dyn StreamCloser>> {
        boxed_closer(&self.stderr_canceller)
    }

    fn try_wait(&mut self) -> io::Result<Option<i32>> {
        if let Some(code) = self.exit {
            return Ok(Some(code));
        }
        if self.timed_out {
            return Err(Self::timed_out_error());
        }
        if self.deadline.is_some_and(|d| Instant::now() >= d) {
            // `wait` kills the process and reports the timeout.
            return self.wait().map(Some);
        }
        match self.exec.try_wait() {
            Ok(Some(code)) => {
                self.exit = Some(code);
                self.finish();
                Ok(Some(code))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(io::Error::other(e.to_string())),
        }
    }

    /// The shim's pid: the sandbox's guest processes have no host pid.
    fn id(&self) -> u32 {
        self.shim_pid
    }

    fn kill(&mut self) -> io::Result<()> {
        self.exec
            .kill()
            .map_err(|e| io::Error::other(e.to_string()))
    }

    fn wait(&mut self) -> io::Result<i32> {
        if let Some(code) = self.exit {
            return Ok(code);
        }
        if self.timed_out {
            return Err(Self::timed_out_error());
        }
        // A stdin nobody took ends here, so the command is not left waiting
        // for input.
        self.stdin = None;
        // Output nobody took is read and discarded so the command cannot block
        // on a full FIFO.
        let stdout_drain = spawn_discard(self.stdout.take());
        let stderr_drain = spawn_discard(self.stderr.take());

        let result = match self.exec.wait(self.deadline) {
            Ok(ExitOutcome::Exited(code)) => {
                self.exit = Some(code);
                Ok(code)
            }
            Ok(ExitOutcome::TimedOut) => {
                self.timed_out = true;
                Err(Self::timed_out_error())
            }
            Err(e) => Err(io::Error::other(e.to_string())),
        };

        cancel_and_join_discard(stdout_drain, &self.stdout_canceller);
        cancel_and_join_discard(stderr_drain, &self.stderr_canceller);
        self.finish();
        result
    }
}

impl Drop for KataProcess {
    fn drop(&mut self) {
        if !self.finished {
            // Stop the command first so its output streams end and the pumps
            // can finish; `finish` then releases the sandbox.
            let _ = self.exec.kill();
            self.finish();
        }
    }
}
