// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Streaming WSLC backend — the handle-based counterpart of
//! [`WSLContainerRunner`]'s run-to-completion `ScriptRunner`.
//!
//! Implementing [`SandboxBackend`] for the same runner lets the Rust SDK
//! (`mxc-sdk`, via `mxc_engine`) spawn a WSL container and drive it live: read
//! its stdout/stderr while it runs, wait for it with the request's timeout, and
//! kill it.
//!
//! Both this and the run-to-completion runner share one lifecycle
//! implementation (`start_container`); they differ only in where the WSLC SDK's
//! output callbacks send their bytes.
//!
//! # What WSLC can and cannot stream
//!
//! - **stdout / stderr** — the SDK pushes them to callbacks, which this module
//!   forwards to an in-memory stream per handle (see [`crate::wslc_common::stream_buffer`]);
//!   the caller reads the other end. Native-stdio callers receive synthesized
//!   OS pipes pumped from those streams because the SDK exposes bytes rather
//!   than pipe handles. Each exposed output needs its own blocking pump because
//!   the SDK offers no waitable or overlapped read primitive; the cost is
//!   therefore bounded at two threads per native-streaming sandbox.
//! - **stdin** — [`take_stdin`](SandboxProcess::take_stdin) returns the write
//!   end of the container process's stdin pipe. [`wait`](SandboxProcess::wait)
//!   closes it if the caller never took it, so a command reading stdin sees
//!   end-of-file.
//! - **[`id`](SandboxProcess::id)** — the process lives inside the WSL VM and
//!   has no host process id, so this is always `0`.

use std::io::{Read, Write};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::OnceLock;

use crate::mxc_common::logger::{Logger, Mode};
use crate::mxc_common::models::{ExecutionRequest, ScriptResponse};
use crate::mxc_common::process_util::{
    create_local_pipe, InterruptiblePipeReader, InterruptiblePipeWriter, PipeWriteCanceller,
    PipeWriter,
};
use crate::mxc_common::sandbox_process::{
    boxed_closer, cancel_and_join_discard, spawn_discard, take_boxed_read, take_boxed_write,
    NativeStdio, OwnedPipe, SandboxBackend, SandboxProcess, StdioMode, StreamCloser,
};
use crate::mxc_common::script_runner::ScriptRunner;
use crate::mxc_common::validator::validate_common;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle as StdOwnedHandle};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{HANDLE, HMODULE, WAIT_OBJECT_0};
use windows::Win32::System::LibraryLoader::{
    GetModuleHandleExW, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_PIN,
};
use windows::Win32::System::Threading::{CreateEventW, SetEvent, WaitForMultipleObjects};

use crate::wslc_common::error::WslcError;
use crate::wslc_common::stream_buffer::{StreamCanceller, StreamReader};
use crate::wslc_common::wsl_container_runner::{
    InitStdin, OutputMode, StartedContainer, WSLContainerRunner,
};
use crate::wslc_common::wslc_bindings::WslcSignal;

impl SandboxBackend for WSLContainerRunner {
    fn validate(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        ScriptRunner::validate_runner(self, request)
    }

    fn spawn(
        &mut self,
        request: &ExecutionRequest,
        logger: &mut Logger,
        stdio: StdioMode,
    ) -> Result<Box<dyn SandboxProcess>, ScriptResponse> {
        if matches!(stdio, StdioMode::Pty(_)) {
            return Err(ScriptResponse::rejected(
                "WSLC does not support caller-controlled PTY spawning",
            ));
        }
        // The run-to-completion path gets these through `ScriptRunner::run`;
        // the streaming path bypasses that, so — like every other
        // `SandboxBackend` — apply them here. Beyond rejecting an empty
        // command, this is what enforces the central testing-features gate on
        // `network.proxy.builtinTestServer`.
        validate_common(request)?;
        self.validate(request)?;

        // SAFETY: `start_container` drives the WSLC SDK over raw FFI; it owns
        // every buffer it passes in and returns RAII guards for every handle it
        // opens, so the returned value is self-contained.
        let stdin = match stdio {
            StdioMode::Pipes if self.piped_stdin => InitStdin::Piped,
            _ => InitStdin::Closed,
        };
        let started =
            unsafe { self.start_container(request, logger, OutputMode::Stream(stdio), stdin) }?;
        let mut process = WslcSandboxProcess::new(started);
        process.watch_exit().map_err(|error| {
            WslcError::Runtime(format!(
                "could not watch the WSL container process for exit: {error}"
            ))
            .into_response()
        })?;
        Ok(Box::new(process))
    }
}

/// Closes a process's stdin when its exit event signals, so a write started
/// before any wait is released as soon as the process exits.
struct ExitWatch {
    stop: StdOwnedHandle,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ExitWatch {
    fn start(exit_event: StdOwnedHandle, stdin: Box<dyn StreamCloser>) -> std::io::Result<Self> {
        // SAFETY: creates a new unnamed manual-reset event.
        let stop = unsafe { CreateEventW(None, true, false, PCWSTR::null()) }
            .map_err(std::io::Error::other)?;

        // SAFETY: `CreateEventW` returned a new handle that nothing else owns.
        let stop = unsafe { StdOwnedHandle::from_raw_handle(stop.0) };
        let watched_stop = stop.try_clone()?;
        let thread = std::thread::Builder::new()
            .name("mxc-wslc-exit-watch".to_string())
            .spawn(move || {
                let events = [
                    HANDLE(exit_event.as_raw_handle()),
                    HANDLE(watched_stop.as_raw_handle()),
                ];

                // SAFETY: this thread owns both handles for the whole wait.
                let signalled = unsafe { WaitForMultipleObjects(&events, false, u32::MAX) };
                if signalled == WAIT_OBJECT_0 {
                    stdin.close();
                }
            })?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for ExitWatch {
    fn drop(&mut self) {
        // SAFETY: `stop` is a live event handle.
        let _ = unsafe { SetEvent(HANDLE(self.stop.as_raw_handle())) };
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The `ErrorKind::TimedOut` error [`SandboxProcess::wait`] reports when the
/// request's `scriptTimeout` elapsed and the container was torn down.
fn timeout_error(timeout_ms: u32) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("Process timed out after {timeout_ms}ms and was terminated"),
    )
}

/// The error reported when the deadline elapsed but the kill could **not** be
/// confirmed.
///
/// Deliberately *not* `ErrorKind::TimedOut`: the public
/// `mxc_sdk::v1::MxcProcess::wait` maps that kind onto `WaitResult::TimedOut`, a
/// success value whose contract is that the process tree *was* killed — which
/// would silently restore the very claim this case exists to avoid, discarding
/// the message with it. Being unable to establish the sandbox's state is a
/// genuine failure, so it surfaces as one and reaches the caller as `Err`.
fn unconfirmed_termination_error(timeout_ms: u32) -> std::io::Error {
    std::io::Error::other(format!(
        "Process timed out after {timeout_ms}ms; the container could not be confirmed terminated \
         and may still be running (call wait() to retry the teardown)"
    ))
}

/// A running WSL container's init process.
struct WslcSandboxProcess {
    started: StartedContainer,
    stdin: Option<InterruptiblePipeWriter>,
    stdin_canceller: Option<PipeWriteCanceller>,
    stdout: Option<StreamReader>,
    stderr: Option<StreamReader>,
    stdout_canceller: Option<StreamCanceller>,
    stderr_canceller: Option<StreamCanceller>,
    /// Pump handles are retained but deliberately not joined: after process
    /// exit they may still be delivering queued bytes to caller-owned pipes,
    /// and joining would block if the caller left a full pipe unread.
    native_output_pumps: Vec<std::thread::JoinHandle<()>>,
    /// Copies the caller's native stdin pipe into the process; joined by `wait`
    /// once the process has exited and its stdin is closed.
    native_stdin_pump: Option<StdinPump>,
    /// Closes stdin when the process exits; present only when stdin is piped.
    exit_watch: Option<ExitWatch>,
    /// A stdin forwarding failure found by `wait`, reported by every later
    /// `wait` and `try_wait` in place of the exit code.
    stdin_failure: Option<String>,
    /// Exit code cached by the first successful wait, so repeat waits are
    /// idempotent (and don't re-run teardown).
    exit: Option<i32>,
    /// Set once the wait deadline elapsed *and* the kill was confirmed, so
    /// `TimedOut` is reported stickily rather than a later-observed exit code.
    /// Deliberately narrower than [`deadline_elapsed`](Self::deadline_elapsed):
    /// this flag is what promises the process was terminated, so it must never
    /// be set on an unconfirmed kill.
    timed_out: bool,
    /// Set once the wait deadline elapsed, whether or not the kill that follows
    /// could be confirmed. Records only that the deadline is spent, so a repeat
    /// `wait` resumes at confirmation instead of blocking out another full one.
    deadline_elapsed: bool,
    /// Set once the container has been *confirmed* torn down, so `Drop` doesn't
    /// repeat it — and, just as importantly, still retries when teardown failed
    /// or could not be confirmed. Tracked separately from `exit`: a caller that
    /// only ever polls [`try_wait`](SandboxProcess::try_wait) learns the exit
    /// code without any teardown having run.
    torn_down: bool,
    /// Diagnostics from the SDK calls made after the spawn returned; only its
    /// warnings reach the caller.
    logger: Logger,
}

// SAFETY: the WSLC handles inside `StartedContainer` are opaque SDK pointers,
// not COM interface pointers the caller marshals: `init_and_load_sdk` enters the
// *multithreaded* apartment (`COINIT_MULTITHREADED`), so the SDK's objects live
// in the MTA and the SDK itself invokes our I/O and exit callbacks on its own
// internal threads — it is free-threaded by design.
//
// `CoInitializeEx` is nonetheless per-thread, so moving this handle to a thread
// that never initialized COM would otherwise leave the SDK on the stack of an
// apartment-less thread. Every entry point that calls the SDK joins the MTA for
// the duration via `ComApartment`, mirroring `process_container_common`'s guard:
// `StartedContainer`'s `wait_for_exit` / `destroy` / `stop` / `exit_code`, and
// — because a `Send` handle can be *dropped* on such a thread too — the
// `Drop` impls of the `WslcSessionGuard` / `WslcContainerGuard` /
// `WslcProcessGuard` handles it owns. No apartment state or interface pointer
// is cached across calls, so setup and teardown may run on different threads.
//
// The invariant holds with no exception: where an apartment cannot be
// established at all, every one of those paths declines to call the SDK rather
// than proceeding without one — leaking the handle (the guards, which have no
// error channel) or reporting the failure (`destroy`).
//
// The handle is *moved* between threads, never shared (`Sync` is deliberately
// not claimed), so at most one thread calls into the SDK at a time.
unsafe impl Send for WslcSandboxProcess {}

/// What an earlier wait already established about this process's outcome, which
/// every later `wait` / `try_wait` must keep reporting.
///
/// Extracted so the two entry points cannot drift: the trait's promise is that
/// once a run is reported as timed out, no later status query downgrades it to
/// an exit code — and a timeout *kills* the container, so the raw SDK exit code
/// is always available to be mistakenly reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Settled {
    /// The deadline elapsed and the kill was confirmed.
    TimedOut,
    /// The deadline elapsed, but the kill could not be confirmed. Still a
    /// timeout — the deadline is spent — with the termination unproven.
    DeadlineUnconfirmed,
    /// The process exited on its own and teardown completed.
    Exited(i32),
    /// Nothing established yet; ask the container.
    Pending,
}

/// Decide the sticky outcome from the flags an earlier wait set.
///
/// `deadline_elapsed` and `exit` are mutually exclusive by construction (the
/// first is only set on the timeout path, the second only on the normal one),
/// so the order these are tested in does not matter.
fn settled_outcome(timed_out: bool, deadline_elapsed: bool, exit: Option<i32>) -> Settled {
    if timed_out {
        Settled::TimedOut
    } else if deadline_elapsed {
        Settled::DeadlineUnconfirmed
    } else if let Some(code) = exit {
        Settled::Exited(code)
    } else {
        Settled::Pending
    }
}

impl WslcSandboxProcess {
    fn new(mut started: StartedContainer) -> Self {
        let pipes = started.pipes.take();
        let (stdout, stderr) = match pipes {
            Some(pipes) => (Some(pipes.stdout), Some(pipes.stderr)),
            None => (None, None),
        };
        let stdin = started.stdin.take();
        Self {
            stdin_canceller: stdin.as_ref().map(InterruptiblePipeWriter::canceller),
            stdin,
            stdout_canceller: stdout.as_ref().map(|r| r.canceller()),
            stderr_canceller: stderr.as_ref().map(|r| r.canceller()),
            stdout,
            stderr,
            native_output_pumps: Vec::new(),
            native_stdin_pump: None,
            exit_watch: None,
            stdin_failure: None,
            started,
            exit: None,
            timed_out: false,
            deadline_elapsed: false,
            torn_down: false,
            logger: Logger::new(Mode::Buffer),
        }
    }

    /// This handle's [`Settled`] outcome so far.
    fn settled(&self) -> Settled {
        settled_outcome(self.timed_out, self.deadline_elapsed, self.exit)
    }

    /// Start closing stdin when the process exits, if it has a stdin to close.
    fn watch_exit(&mut self) -> std::io::Result<()> {
        if self.stdin.is_none() {
            return Ok(());
        }
        if let Some(event) = self
            .started
            .duplicate_exit_event()
            .map_err(std::io::Error::other)?
        {
            self.exit_watch = Some(ExitWatch::start(event, self.started.stdin_closer())?);
        }
        Ok(())
    }

    /// The result for a process that exited with `code`, unless its stdin
    /// forwarding failed.
    fn exited(&self, code: i32) -> std::io::Result<i32> {
        match &self.stdin_failure {
            Some(failure) => Err(std::io::Error::other(failure.clone())),
            None => Ok(code),
        }
    }

    /// Complete the timeout path: confirm the sandboxed process is really gone,
    /// tear the container down, and only then make `TimedOut` sticky.
    ///
    /// `wait_for_exit`'s timeout branch only *asks* the container to stop
    /// (`SIGTERM`, short grace, HRESULT ignored), so reaching it proves nothing
    /// about whether the process died — while returning `TimedOut` promises it
    /// was terminated. Every failure here therefore leaves both `timed_out` and
    /// `torn_down` unset, so the promise is never made on an unconfirmed kill
    /// and a later `wait` (or `Drop`) retries instead.
    fn finish_timed_out(&mut self) -> std::io::Result<i32> {
        self.started
            .confirm_terminated(&mut self.logger)
            .map_err(std::io::Error::other)?;
        self.started
            .destroy(&mut self.logger)
            .map_err(std::io::Error::other)?;
        self.torn_down = true;
        self.timed_out = true;
        Err(timeout_error(self.started.timeout_ms))
    }
}

pub(crate) struct PreparedNativeOutput {
    reader: Option<OwnedPipe>,
    start: Option<SyncSender<StreamReader>>,
    pump: Option<std::thread::JoinHandle<()>>,
}

impl PreparedNativeOutput {
    pub(crate) fn activate(
        mut self,
        source: StreamReader,
    ) -> std::io::Result<(OwnedPipe, std::thread::JoinHandle<()>)> {
        let start = self
            .start
            .take()
            .ok_or_else(|| std::io::Error::other("native output pump is already active"))?;
        start
            .send(source)
            .map_err(|_| std::io::Error::other("native output pump stopped before activation"))?;
        let reader = self
            .reader
            .take()
            .ok_or_else(|| std::io::Error::other("native output reader is unavailable"))?;
        let pump = self
            .pump
            .take()
            .ok_or_else(|| std::io::Error::other("native output pump is unavailable"))?;
        Ok((reader, pump))
    }
}

impl Drop for PreparedNativeOutput {
    fn drop(&mut self) {
        self.start.take();
        if let Some(pump) = self.pump.take() {
            let _ = pump.join();
        }
    }
}

/// Keep the module containing output pump code loaded for the process lifetime.
///
/// Native pipe readers outlive the sandbox handle, so an active pump may still
/// return from a blocking write after `mxc_sandbox_free` has completed.
fn pin_output_pump_module() -> std::io::Result<()> {
    static MODULE_PIN: OnceLock<Result<(), String>> = OnceLock::new();

    MODULE_PIN
        .get_or_init(|| {
            let mut module = HMODULE::default();
            // SAFETY: FROM_ADDRESS interprets the pointer as an address within
            // the current module rather than as a string. PIN keeps that module
            // loaded until process exit, so detached pumps can finish safely.
            unsafe {
                GetModuleHandleExW(
                    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                    PCWSTR(pin_output_pump_module as *const () as *const u16),
                    &mut module,
                )
            }
            .map_err(|error| format!("failed to pin the WSLC output-pump module: {error}"))
        })
        .as_ref()
        .map_err(|error| std::io::Error::other(error.clone()))
        .copied()
}

/// Prepare a native pipe and an idle output pump before detaching a WSLC stream.
///
/// WSLC exposes stdout and stderr as callback-backed streams rather than
/// transferable OS handles. The pump copies each stream into a local pipe so
/// FFI consumers can adopt its native read endpoint.
///
/// A shared worker cannot safely drain both callback streams: each read may
/// block independently, and failing to drain either stream can stall the
/// container. Keep the explicit one-pump-per-output tradeoff until the WSLC SDK
/// exposes a waitable or cancellable asynchronous read primitive.
pub(crate) fn prepare_native_output() -> std::io::Result<PreparedNativeOutput> {
    pin_output_pump_module()?;
    let (reader, writer) = create_local_pipe().map_err(std::io::Error::other)?;
    let mut destination = PipeWriter::new(writer);
    let (start, source) = sync_channel::<StreamReader>(1);
    let pump = std::thread::Builder::new()
        .name("mxc-wslc-output-pump".to_string())
        .spawn(move || {
            let Ok(mut source) = source.recv() else {
                return;
            };
            // A closed native read end reports BrokenPipe and ends the pump.
            // Dropping `source` then abandons the callback queue so it cannot
            // grow after the caller has stopped consuming this stream.
            let _ = std::io::copy(&mut source, &mut destination);
        })?;
    Ok(PreparedNativeOutput {
        reader: Some(reader.try_into_std_owned_handle()?),
        start: Some(start),
        pump: Some(pump),
    })
}

/// Hand the caller the write end of a local pipe that a pump copies into
/// `stdin`, registering a closer that ends the pump so the caller's next write
/// fails once the process is gone. The pump returns any failure other than
/// the process's stdin closing.
fn bridge_native_stdin(
    mut stdin: impl Write + Send + 'static,
    register_closer: impl FnOnce(Box<dyn StreamCloser>),
) -> std::io::Result<(OwnedPipe, StdinPump)> {
    pin_output_pump_module()?;
    let (read, write) = create_local_pipe().map_err(std::io::Error::other)?;
    let mut reader = InterruptiblePipeReader::new(read);
    let caller_end = write.try_into_std_owned_handle()?;
    register_closer(Box::new(reader.canceller()));
    let pump = std::thread::Builder::new()
        .name("mxc-wslc-stdin-pump".to_string())
        .spawn(move || match std::io::copy(&mut reader, &mut stdin) {
            Err(error) if error.kind() != std::io::ErrorKind::BrokenPipe => Err(error),
            _ => Ok(()),
        })?;
    Ok((caller_end, pump))
}

type StdinPump = std::thread::JoinHandle<std::io::Result<()>>;

/// Wait for a stdin pump whose pipes are already closed, describing any
/// failure it hit.
fn stdin_pump_failure(pump: StdinPump) -> Option<String> {
    let error = match pump.join() {
        Ok(Ok(())) => return None,
        Ok(Err(error)) => error.to_string(),
        Err(_) => "the stdin pump panicked".to_string(),
    };
    Some(format!(
        "forwarding stdin to the WSL container failed, so the command may not have received \
         all of its input: {error}"
    ))
}

impl SandboxProcess for WslcSandboxProcess {
    fn warnings(&self) -> Vec<String> {
        self.logger.warnings().to_vec()
    }

    fn take_native_stdio(&mut self) -> std::io::Result<Option<NativeStdio>> {
        if self.stdin.is_none() && self.stdout.is_none() && self.stderr.is_none() {
            return Ok(None);
        }

        // Allocate pipes and start idle workers before detaching either source,
        // so setup failure leaves the ordinary stream API untouched.
        let stdout_pipe = self
            .stdout
            .as_ref()
            .map(|_| prepare_native_output())
            .transpose()?;
        let stderr_pipe = self
            .stderr
            .as_ref()
            .map(|_| prepare_native_output())
            .transpose()?;

        // Bridge stdin first: it is the step that can fail after taking a
        // stream, and the output streams are still untouched if it does.
        let stdin = match self.stdin.take() {
            Some(writer) => {
                let (caller_end, pump) =
                    bridge_native_stdin(writer, |closer| self.started.add_stdin_closer(closer))?;
                self.native_stdin_pump = Some(pump);
                Some(caller_end)
            }
            None => None,
        };
        self.stdin_canceller.take();

        let stdout = match (self.stdout.take(), stdout_pipe) {
            (Some(source), Some(pipe)) => {
                let (reader, pump) = pipe.activate(source)?;
                self.native_output_pumps.push(pump);
                Some(reader)
            }
            _ => None,
        };
        let stderr = match (self.stderr.take(), stderr_pipe) {
            (Some(source), Some(pipe)) => {
                let (reader, pump) = pipe.activate(source)?;
                self.native_output_pumps.push(pump);
                Some(reader)
            }
            _ => None,
        };

        self.stdout_canceller.take();
        self.stderr_canceller.take();

        Ok(Some(NativeStdio {
            stdin,
            stdout,
            stderr,
        }))
    }

    fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>> {
        take_boxed_write(&mut self.stdin)
    }

    fn stdin_closer(&self) -> Option<Box<dyn StreamCloser>> {
        boxed_closer(&self.stdin_canceller)
    }

    fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
        take_boxed_read(&mut self.stdout)
    }

    fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>> {
        take_boxed_read(&mut self.stderr)
    }

    fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
        // The settled outcome is checked exactly as in `wait`. Without this,
        // the timeout path — which kills the container — leaves `has_exited()`
        // true below, so a caller that saw `wait` fail with `TimedOut` would
        // get `Ok(Some(<kill code>))` from a later poll: two contradictory
        // answers, with the timeout silently downgraded to a normal exit.
        match self.settled() {
            Settled::TimedOut => return Err(timeout_error(self.started.timeout_ms)),
            // `try_wait` is non-blocking, so confirmation cannot be retried
            // here the way `wait` retries it — but an exit code would still be
            // the wrong answer for a spent deadline.
            Settled::DeadlineUnconfirmed => {
                return Err(unconfirmed_termination_error(self.started.timeout_ms))
            }
            // A cached code means `wait` already ran the full teardown.
            Settled::Exited(code) => return self.exited(code).map(Some),
            Settled::Pending => {}
        }
        if !self.started.has_exited() {
            // The exit event can signal long before the SDK's exit callback,
            // and a poller must not wait out that gap.
            if !self.started.exit_signalled() {
                return Ok(None);
            }
            self.started.close_stdin();
        }
        // Deliberately *not* cached into `self.exit`: `wait` treats a cached
        // code as proof that it already drained the streams, destroyed the
        // container, and set `torn_down`, so caching here would make a later
        // `wait` skip teardown entirely — and would mask a prior timeout,
        // turning a `TimedOut` into a normal exit. Re-querying is a cheap
        // SDK call.
        // SAFETY: `started` owns live process and SDK handles.
        unsafe { self.started.exit_code() }
            .map_err(std::io::Error::other)
            .map(Some)
    }

    /// Always `0` — the sandboxed process runs inside the WSL VM and has no
    /// host process id.
    fn id(&self) -> u32 {
        0
    }

    fn kill(&mut self) -> std::io::Result<()> {
        // WSLC has no per-process signal API: stopping the container terminates
        // the init process and everything it spawned — the tree kill the trait
        // asks for. `0` means "don't wait for a graceful stop".
        let stopped = self
            .started
            .stop(WslcSignal::WSLC_SIGNAL_SIGKILL, 0)
            .map_err(std::io::Error::other);
        self.started.close_stdin();
        stopped
    }

    fn wait(&mut self) -> std::io::Result<i32> {
        match self.settled() {
            // Sticky: a confirmed timeout must keep being reported as one,
            // never as a later-observed exit code.
            Settled::TimedOut => return Err(timeout_error(self.started.timeout_ms)),
            Settled::Exited(code) => return self.exited(code),
            // An earlier call already burned the deadline but could not confirm
            // the kill. Resume at the confirmation step: re-entering
            // `wait_for_exit` would block for another full deadline, while
            // reporting `TimedOut` outright would promise a kill that never
            // happened.
            Settled::DeadlineUnconfirmed => return self.finish_timed_out(),
            Settled::Pending => {}
        }

        // A command reading a stdin the caller never took would otherwise wait
        // for input that cannot arrive.
        self.stdin.take();

        // Drain the streams the caller did not take, concurrently with the
        // wait, so unread output can't accumulate for the life of the process
        // (see the trait's pipe-deadlock contract — here the buffer is
        // in-memory and unbounded, so the cost of not draining is memory rather
        // than a stalled child). A stream the caller *did* take is left alone.
        let stdout_drain = spawn_discard(self.stdout.take());
        let stderr_drain = spawn_discard(self.stderr.take());

        let waited = self.started.wait_for_exit(&mut self.logger);

        // Release the drain readers we own first, whichever way the wait went:
        // firing their canceller can't truncate anything the caller is reading
        // (`cancel_and_join_discard` only fires for a stream we drained), and
        // joining them here keeps a later error return from leaving threads
        // parked on a read.
        cancel_and_join_discard(stdout_drain, &self.stdout_canceller);
        cancel_and_join_discard(stderr_drain, &self.stderr_canceller);

        // Deliberately before `close_streams`: `wait_for_exit` can fail while
        // the process is still running (a failed apartment, or
        // `WslcGetProcessExitEvent`), and closing the SDK-side writers then
        // would EOF a caller-taken reader and discard every later callback for
        // a process that is still producing output.
        let (exit_code, outcome) = waited.map_err(|response| {
            std::io::Error::other(if response.error_message.is_empty() {
                "waiting for the WSL container process failed".to_string()
            } else {
                response.error_message
            })
        })?;

        // The process is gone (or was killed): close the SDK-side write ends so
        // every reader — ours and the caller's — sees EOF once it has consumed
        // what was already buffered.
        self.started.close_streams();

        if outcome.timed_out() {
            // Records only that the deadline elapsed. Even
            // `WaitOutcome::TimedOutTerminated` goes through `finish_timed_out`,
            // whose `confirm_terminated` short-circuits on an already-confirmed
            // exit — so the confirmed case costs nothing and the unconfirmed one
            // gets the retry it needs.
            self.deadline_elapsed = true;
            return self.finish_timed_out();
        }

        // The exit callback fired, so the process is confirmed gone and only the
        // container object can still leak. `torn_down` therefore tracks whether
        // teardown actually succeeded, leaving `Drop` to retry it if not.
        self.torn_down = self.started.destroy(&mut self.logger).is_ok();
        self.exit = Some(exit_code);

        // Bounded: the wait closed both pipes the pump uses.
        self.stdin_failure = self.native_stdin_pump.take().and_then(stdin_pump_failure);
        self.exited(exit_code)
    }

    fn stdout_closer(&self) -> Option<Box<dyn StreamCloser>> {
        boxed_closer(&self.stdout_canceller)
    }

    fn stderr_closer(&self) -> Option<Box<dyn StreamCloser>> {
        boxed_closer(&self.stderr_canceller)
    }
}

impl Drop for WslcSandboxProcess {
    /// A handle dropped before [`wait`](SandboxProcess::wait) tore the container
    /// down still owns one — possibly still running: stop it (and, when the
    /// request asked for it, delete it) rather than leaking a VM-backed sandbox.
    fn drop(&mut self) {
        if self.torn_down {
            return;
        }
        self.stdin.take();
        // Settles the container and blocks on the exit callback before the
        // fields it owns are released — the SDK must have stopped calling back
        // before the `IoContext` is freed and the DLL unloaded.
        let mut logger = Logger::new(Mode::Buffer);
        self.started.quiesce(&mut logger);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wslc_common::wsl_container_runner::START_CONTAINER_BANNER;
    use std::fs::File;
    use std::io::Read;
    use std::time::Duration;

    /// The banner is what makes this host-independent: on a host that *has*
    /// `wslcsdk.dll`, a guard moved after `start_container` would leak a
    /// container and still return the same message. `start_container` writes the
    /// banner first, so an untouched buffer proves it was never entered.
    #[test]
    fn spawn_rejects_policy_before_touching_the_wslc_sdk() {
        let request = ExecutionRequest {
            containment: crate::mxc_common::models::ContainmentBackend::Wslc,
            script_code: "echo hi".to_string(),
            policy: crate::mxc_common::models::ContainerPolicy {
                ui_specified: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut logger = Logger::new(Mode::Buffer);
        let mut runner = WSLContainerRunner::new(&crate::mxc_common::models::WslcConfig::default());

        let err = runner
            .spawn(&request, &mut logger, StdioMode::Pipes)
            .err()
            .expect("a rejected policy must not produce a live container");
        assert!(
            err.error_message.contains("ui section is not supported"),
            "the refusal must come from the policy gate, not from bring-up: {}",
            err.error_message
        );
        assert_eq!(
            err.failure_phase,
            crate::mxc_common::models::FailurePhase::Rejected
        );
        assert!(
            !logger.get_buffer().contains(START_CONTAINER_BANNER),
            "guard must run before `start_container`; logger: {}",
            logger.get_buffer()
        );
    }

    /// Regression for #902 on the streaming path: an unmappable cwd is refused
    /// before `start_container`, rather than dropped once the container exists.
    #[test]
    fn spawn_rejects_unmappable_working_directory_before_touching_the_wslc_sdk() {
        let request = ExecutionRequest {
            containment: crate::mxc_common::models::ContainmentBackend::Wslc,
            script_code: "pwd".to_string(),
            working_directory: "/workspace".to_string(),
            ..Default::default()
        };
        let mut logger = Logger::new(Mode::Buffer);
        let mut runner = WSLContainerRunner::new(&crate::mxc_common::models::WslcConfig::default());

        let err = runner
            .spawn(&request, &mut logger, StdioMode::Pipes)
            .err()
            .expect("an unmappable cwd must not produce a live container");
        assert!(
            err.error_message.contains("\"/workspace\""),
            "the refusal must name the cwd: {}",
            err.error_message
        );
        assert_eq!(
            err.failure_phase,
            crate::mxc_common::models::FailurePhase::Rejected
        );
        assert!(
            !logger.get_buffer().contains(START_CONTAINER_BANNER),
            "guard must run before `start_container`; logger: {}",
            logger.get_buffer()
        );
    }

    /// The exact contradiction the streaming contract forbids: a timed-out run
    /// is killed, so the container *has* an exit code to report — and reporting
    /// it would turn `wait`'s `Err(TimedOut)` into a later `Ok(Some(137))`.
    /// Both entry points read this one decision, so they cannot disagree.
    #[test]
    fn a_confirmed_timeout_is_never_downgraded_to_an_exit_code() {
        assert_eq!(
            settled_outcome(true, true, None),
            Settled::TimedOut,
            "a confirmed timeout stays a timeout"
        );
        // Even with an exit code somehow recorded, the timeout still wins.
        assert_eq!(
            settled_outcome(true, true, Some(137)),
            Settled::TimedOut,
            "a recorded exit code must not mask a confirmed timeout"
        );
    }

    /// A deadline that elapsed but whose kill could not be confirmed is still a
    /// timeout — never an exit code — but it is reported apart from the
    /// confirmed case so nothing claims a termination that was not shown.
    #[test]
    fn an_unconfirmed_deadline_is_distinct_from_a_confirmed_timeout() {
        assert_eq!(
            settled_outcome(false, true, None),
            Settled::DeadlineUnconfirmed,
        );
        assert_ne!(
            settled_outcome(false, true, None),
            Settled::TimedOut,
            "an unconfirmed kill must not report as a completed termination"
        );
    }

    #[test]
    fn a_normal_exit_is_reported_once_teardown_cached_it() {
        assert_eq!(settled_outcome(false, false, Some(0)), Settled::Exited(0));
        assert_eq!(settled_outcome(false, false, Some(3)), Settled::Exited(3));
    }

    #[test]
    fn a_fresh_handle_has_nothing_settled_yet() {
        assert_eq!(settled_outcome(false, false, None), Settled::Pending);
    }

    /// The safety property behind both entry points: once the deadline has
    /// elapsed, *no* combination of flags may answer "exited normally". This is
    /// what stops a killed container's exit code from masking the timeout.
    #[test]
    fn a_spent_deadline_never_yields_an_exit_code() {
        for timed_out in [false, true] {
            for exit in [None, Some(0), Some(137)] {
                let outcome = settled_outcome(timed_out, true, exit);
                assert!(
                    !matches!(outcome, Settled::Exited(_)),
                    "a spent deadline (timed_out={timed_out}, exit={exit:?}) must not report an \
                     exit code, got {outcome:?}"
                );
            }
        }
    }

    /// Only a *confirmed* kill may carry `ErrorKind::TimedOut`.
    ///
    /// `mxc_sdk::v1::MxcProcess::wait` turns that kind into `WaitResult::TimedOut`, a
    /// success value promising the process tree was killed — and drops the
    /// message doing it. An unconfirmed kill must therefore not use that kind,
    /// or the distinction would be erased at the public API boundary.
    #[test]
    fn only_a_confirmed_kill_uses_the_timedout_error_kind() {
        let confirmed = timeout_error(1500);
        let unconfirmed = unconfirmed_termination_error(1500);

        assert_eq!(confirmed.kind(), std::io::ErrorKind::TimedOut);
        assert_ne!(
            unconfirmed.kind(),
            std::io::ErrorKind::TimedOut,
            "an unconfirmed kill must not be convertible into WaitOutcome::TimedOut"
        );

        assert!(confirmed.to_string().contains("1500ms"));
        assert!(unconfirmed.to_string().contains("1500ms"));
        assert!(
            confirmed.to_string().contains("was terminated"),
            "the confirmed message states the termination"
        );
        assert!(
            !unconfirmed.to_string().contains("was terminated"),
            "the unconfirmed message must not claim a termination it did not prove"
        );
        assert!(
            unconfirmed.to_string().contains("may still be running"),
            "the unconfirmed message must say the container may still be running"
        );
    }

    #[test]
    fn native_output_bridge_delivers_bytes_and_eof() {
        let (writer, reader) = crate::wslc_common::stream_buffer::stream_pair();
        let pipe = prepare_native_output().expect("create native output pipe");
        let (native_reader, pump) = pipe.activate(reader).expect("activate output pump");
        let mut native_reader = File::from(native_reader);

        writer.write(b"hello from wslc");
        writer.close();

        let mut output = Vec::new();
        native_reader
            .read_to_end(&mut output)
            .expect("read bridged output");
        pump.join().expect("output pump");
        assert_eq!(output, b"hello from wslc");
    }

    #[test]
    fn native_output_bridge_preserves_large_output_after_delayed_read() {
        let expected = vec![b'x'; 1024 * 1024];
        let (writer, reader) = crate::wslc_common::stream_buffer::stream_pair();
        let pipe = prepare_native_output().expect("create native output pipe");
        let (native_reader, pump) = pipe.activate(reader).expect("activate output pump");
        let mut native_reader = File::from(native_reader);

        writer.write(&expected);
        writer.close();
        std::thread::sleep(Duration::from_millis(50));

        let mut output = Vec::new();
        native_reader
            .read_to_end(&mut output)
            .expect("read bridged output");
        pump.join().expect("output pump");
        assert_eq!(output, expected);
    }

    #[test]
    fn dropping_native_reader_ends_the_output_pump() {
        let (writer, reader) = crate::wslc_common::stream_buffer::stream_pair();
        let pipe = prepare_native_output().expect("create native output pipe");
        let (native_reader, pump) = pipe.activate(reader).expect("activate output pump");
        drop(native_reader);

        writer.write(b"unobserved output");
        writer.close();

        pump.join().expect("output pump");
    }

    #[test]
    fn dropping_unactivated_native_output_joins_idle_pump() {
        let pipe = prepare_native_output().expect("prepare native output");
        drop(pipe);
    }

    fn file_pipe() -> (File, File) {
        let (read, write) = create_local_pipe().expect("create pipe");
        (
            File::from(read.try_into_std_owned_handle().unwrap()),
            File::from(write.try_into_std_owned_handle().unwrap()),
        )
    }

    fn read_to_end_within(mut reader: File) -> Vec<u8> {
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut received = Vec::new();
            let _ = reader.read_to_end(&mut received);
            let _ = done_tx.send(received);
        });
        done_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the reader never saw end-of-file")
    }

    #[test]
    fn bridged_stdin_delivers_bytes_and_eof_when_the_caller_closes_it() {
        let (process_reader, process_writer) = file_pipe();
        let mut closers = Vec::new();
        let (caller, _pump) =
            bridge_native_stdin(InterruptiblePipeWriter::new(process_writer), |closer| {
                closers.push(closer)
            })
            .expect("bridge stdin");
        let mut caller = File::from(caller);

        caller.write_all(b"through the bridge").unwrap();
        drop(caller);

        assert_eq!(read_to_end_within(process_reader), b"through the bridge");
        assert_eq!(closers.len(), 1);
    }

    #[test]
    fn closing_bridged_stdin_ends_a_caller_write_blocked_on_a_full_pipe() {
        let (_process_reader, process_writer) = file_pipe();
        let process_stdin = InterruptiblePipeWriter::new(process_writer);
        let mut closers: Vec<Box<dyn StreamCloser>> = vec![Box::new(process_stdin.canceller())];
        let (caller, _pump) = bridge_native_stdin(process_stdin, |closer| closers.push(closer))
            .expect("bridge stdin");
        let mut caller = File::from(caller);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = done_tx.send(caller.write_all(&vec![0; 16 * 1024 * 1024]));
        });
        assert!(
            done_rx.recv_timeout(Duration::from_millis(500)).is_err(),
            "the write should be blocked behind a process that is not reading"
        );

        for closer in &closers {
            closer.close();
        }

        let written = done_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the caller's write was never released");
        assert!(
            written.is_err(),
            "the abandoned input must not be reported as delivered"
        );
    }

    #[test]
    fn closing_an_idle_bridged_stdin_closes_the_process_stdin() {
        let (process_reader, process_writer) = file_pipe();
        let process_stdin = InterruptiblePipeWriter::new(process_writer);
        let mut closers: Vec<Box<dyn StreamCloser>> = vec![Box::new(process_stdin.canceller())];
        let (_caller, _pump) = bridge_native_stdin(process_stdin, |closer| closers.push(closer))
            .expect("bridge stdin");

        for closer in &closers {
            closer.close();
        }

        assert!(read_to_end_within(process_reader).is_empty());
    }

    struct FailingStdin(std::io::ErrorKind);

    impl Write for FailingStdin {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(self.0, "stdin broke"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn bridged_write_failure(kind: std::io::ErrorKind) -> Option<String> {
        let (caller, pump) = bridge_native_stdin(FailingStdin(kind), |_| {}).expect("bridge stdin");
        let mut caller = File::from(caller);
        let _ = caller.write_all(b"lost input");
        drop(caller);
        stdin_pump_failure(pump)
    }

    #[test]
    fn a_failed_write_through_bridged_stdin_is_reported() {
        let failure = bridged_write_failure(std::io::ErrorKind::Other).expect("a failure");

        assert!(
            failure.contains("forwarding stdin to the WSL container failed")
                && failure.contains("stdin broke"),
            "{failure}"
        );
    }

    #[test]
    fn a_process_stdin_that_closed_is_not_a_bridged_stdin_failure() {
        assert_eq!(bridged_write_failure(std::io::ErrorKind::BrokenPipe), None);
    }

    struct RecordingCloser(std::sync::mpsc::Sender<()>);

    impl StreamCloser for RecordingCloser {
        fn close(&self) {
            let _ = self.0.send(());
        }
    }

    fn manual_event() -> StdOwnedHandle {
        let event = unsafe { CreateEventW(None, true, false, PCWSTR::null()) }.unwrap();
        unsafe { StdOwnedHandle::from_raw_handle(event.0) }
    }

    #[test]
    fn an_exit_watch_closes_stdin_when_the_process_exits() {
        let exit_event = manual_event();
        let (closed_tx, closed_rx) = std::sync::mpsc::channel();
        let _watch = ExitWatch::start(
            exit_event.try_clone().unwrap(),
            Box::new(RecordingCloser(closed_tx)),
        )
        .unwrap();

        unsafe { SetEvent(HANDLE(exit_event.as_raw_handle())) }.unwrap();

        closed_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("stdin was not closed when the process exited");
    }

    #[test]
    fn dropping_an_exit_watch_ends_it_without_closing_stdin() {
        let (closed_tx, closed_rx) = std::sync::mpsc::channel();
        let watch = ExitWatch::start(manual_event(), Box::new(RecordingCloser(closed_tx))).unwrap();

        drop(watch);

        assert!(
            closed_rx.try_recv().is_err(),
            "stdin was closed without an exit"
        );
    }
}
