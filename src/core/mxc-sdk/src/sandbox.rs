// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The SDK's sandbox handle — a crate-owned facade over the internal
//! `wxc_common` streaming handle, so the public API never exposes the
//! foundation crate's traits.

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::state_aware_sdk::{
    lifecycle_sdk_input, ExecRequest, LifecycleResult, OperationOptions, ProvisionRequest,
    ProvisionResult, SandboxId, StateAwareResult, ValidationResult,
};
use crate::Error;
pub use wxc_common::models::{
    CaptureDenialsErrorOutput, CaptureDenialsOutput, SandboxOutputMetadata,
};
use wxc_common::sandbox_process::{NativeStdio, SandboxProcess, StreamCloser as InnerCloser};
use wxc_common::state_aware_backend::ExecOutcome;
use wxc_common::state_aware_operation::StateAwareOperation;

fn run_typed_state_aware(
    input: wxc_common::sdk_input::SdkStateAwareInput,
    options: OperationOptions,
    dry_run: bool,
) -> Result<StateAwareResult, Error> {
    mxc_engine::run_typed_state_aware_request(input, options.experimental, dry_run)
        .map(StateAwareResult::from_engine)
}

/// Provision a sandbox from typed Rust policy.
pub fn provision(
    request: ProvisionRequest,
    options: OperationOptions,
) -> Result<ProvisionResult, Error> {
    let input = request
        .into_sdk_input(options.telemetry_opt_in)
        .map_err(Error::from)?;
    run_typed_state_aware(input, options, false)?
        .into_provision()
        .map_err(Error::from)
}

/// Validate a provision request without creating a sandbox.
pub fn validate_provision(
    request: ProvisionRequest,
    options: OperationOptions,
) -> Result<ValidationResult, Error> {
    let input = request
        .into_sdk_input(options.telemetry_opt_in)
        .map_err(Error::from)?;
    run_typed_state_aware(input, options, true)?
        .into_validation()
        .map_err(Error::from)
}

/// Start an existing sandbox.
pub fn start(sandbox_id: &SandboxId, options: OperationOptions) -> Result<LifecycleResult, Error> {
    let input = lifecycle_sdk_input(sandbox_id, options.telemetry_opt_in, |sandbox_id| {
        StateAwareOperation::Start { sandbox_id }
    })
    .map_err(Error::from)?;
    run_typed_state_aware(input, options, false)?
        .into_lifecycle()
        .map_err(Error::from)
}

/// Validate a start request without starting the sandbox.
pub fn validate_start(
    sandbox_id: &SandboxId,
    options: OperationOptions,
) -> Result<ValidationResult, Error> {
    let input = lifecycle_sdk_input(sandbox_id, options.telemetry_opt_in, |sandbox_id| {
        StateAwareOperation::Start { sandbox_id }
    })
    .map_err(Error::from)?;
    run_typed_state_aware(input, options, true)?
        .into_validation()
        .map_err(Error::from)
}

/// Stop an existing sandbox.
pub fn stop(sandbox_id: &SandboxId, options: OperationOptions) -> Result<LifecycleResult, Error> {
    let input = lifecycle_sdk_input(sandbox_id, options.telemetry_opt_in, |sandbox_id| {
        StateAwareOperation::Stop { sandbox_id }
    })
    .map_err(Error::from)?;
    run_typed_state_aware(input, options, false)?
        .into_lifecycle()
        .map_err(Error::from)
}

/// Validate a stop request without stopping the sandbox.
pub fn validate_stop(
    sandbox_id: &SandboxId,
    options: OperationOptions,
) -> Result<ValidationResult, Error> {
    let input = lifecycle_sdk_input(sandbox_id, options.telemetry_opt_in, |sandbox_id| {
        StateAwareOperation::Stop { sandbox_id }
    })
    .map_err(Error::from)?;
    run_typed_state_aware(input, options, true)?
        .into_validation()
        .map_err(Error::from)
}

/// Deprovision an existing sandbox.
pub fn deprovision(
    sandbox_id: &SandboxId,
    options: OperationOptions,
) -> Result<LifecycleResult, Error> {
    let input = lifecycle_sdk_input(sandbox_id, options.telemetry_opt_in, |sandbox_id| {
        StateAwareOperation::Deprovision { sandbox_id }
    })
    .map_err(Error::from)?;
    run_typed_state_aware(input, options, false)?
        .into_lifecycle()
        .map_err(Error::from)
}

/// Validate a deprovision request without changing the sandbox.
pub fn validate_deprovision(
    sandbox_id: &SandboxId,
    options: OperationOptions,
) -> Result<ValidationResult, Error> {
    let input = lifecycle_sdk_input(sandbox_id, options.telemetry_opt_in, |sandbox_id| {
        StateAwareOperation::Deprovision { sandbox_id }
    })
    .map_err(Error::from)?;
    run_typed_state_aware(input, options, true)?
        .into_validation()
        .map_err(Error::from)
}

/// Execute in an existing sandbox and return a live streaming handle.
pub fn exec(
    sandbox_id: &SandboxId,
    request: ExecRequest,
    options: OperationOptions,
) -> Result<Sandbox, Error> {
    let input = request
        .into_sdk_input(sandbox_id, options.telemetry_opt_in)
        .map_err(Error::from)?;
    mxc_engine::exec_typed_state_aware_request(input, options.experimental).map(Sandbox::new)
}

/// Execute in an existing sandbox attached to this process's stdio.
pub fn exec_attached(
    sandbox_id: &SandboxId,
    request: ExecRequest,
    options: OperationOptions,
) -> Result<WaitOutcome, Error> {
    let input = request
        .into_sdk_input(sandbox_id, options.telemetry_opt_in)
        .map_err(Error::from)?;
    mxc_engine::exec_typed_state_aware_attached_request(input, options.experimental).map(
        |outcome| match outcome {
            ExecOutcome::Exited(code) => WaitOutcome::Exited(code),
            ExecOutcome::TimedOut => WaitOutcome::TimedOut,
        },
    )
}

/// Validate an exec request without running a workload.
pub fn validate_exec(
    sandbox_id: &SandboxId,
    request: ExecRequest,
    options: OperationOptions,
) -> Result<ValidationResult, Error> {
    let input = request
        .into_sdk_input(sandbox_id, options.telemetry_opt_in)
        .map_err(Error::from)?;
    run_typed_state_aware(input, options, true)?
        .into_validation()
        .map_err(Error::from)
}

/// The outcome of waiting on a [`Sandbox`] (see [`Sandbox::wait`]).
///
/// An ordinary exit and a timeout are both represented here as success
/// outcomes; [`Sandbox::wait`] reserves its `Err` for an actual OS / wait
/// failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    /// The process exited with this code. On Unix a process terminated by a
    /// signal (rather than exiting normally) surfaces as `Exited(-1)`.
    Exited(i32),
    /// The request's `scriptTimeout` elapsed while the process was running, and
    /// the process is no longer running.
    ///
    /// **Deadline spent, and the process is gone.** Whether it was killed or
    /// exited on its own a moment past the deadline is not distinguished: both
    /// missed the deadline the caller asked for, and reporting the exit code
    /// one of them happened to produce would hide that.
    ///
    /// How far "gone" reaches depends on the backend. A process-spawning
    /// backend kills the whole tree. A backend whose only primitive is the
    /// foreground process — the state-aware `exec` path over IsolationSession —
    /// confirms that process, and a descendant the workload backgrounded is
    /// reclaimed when the sandbox is stopped and deprovisioned rather than here.
    ///
    /// That state-aware route is reachable from this crate once the caller
    /// passes the `experimental` opt-in to
    /// [`exec_sandbox`](crate::exec_sandbox) and the backend is compiled in via
    /// this crate's `isolation_session` feature, which forwards to the engine.
    /// Both refusals are
    /// [`ErrorCode::BackendUnavailable`](crate::ErrorCode::BackendUnavailable).
    TimedOut,
}

/// The captured result of running a [`Sandbox`] to completion via
/// [`wait_with_output`](Sandbox::wait_with_output).
#[derive(Debug, Clone)]
pub struct Output {
    /// How the process finished.
    pub outcome: WaitOutcome,
    /// Policy and operational warnings from the sandbox, such as security
    /// warnings, network rules that cannot carry traffic, or a cleanup step
    /// that failed after the workload exited.
    pub warnings: Vec<String>,
    /// Everything the child wrote to stdout.
    pub stdout: Vec<u8>,
    /// Everything the child wrote to stderr.
    pub stderr: Vec<u8>,
    /// Structured outputs produced by optional sandbox features.
    pub output_metadata: Option<SandboxOutputMetadata>,
}

/// A live sandboxed process, returned by [`spawn_sandbox`](crate::v1::spawn_sandbox)
/// and [`exec_sandbox`](crate::exec_sandbox).
///
/// Stream the child's stdio with the `take_*` accessors, wait for it, or kill
/// it. No pty is allocated — the streams are ordinary pipes. Any stdout/stderr
/// the caller does not `take_*` is drained and discarded by [`wait`](Self::wait).
pub struct Sandbox {
    inner: Box<dyn SandboxProcess>,
    stdio_access: StdioAccess,
}

/// A live sandboxed process attached to an MXC-owned pseudo-terminal.
///
/// The public wrapper keeps MXC's process-tree lifecycle and backend details
/// behind a stable terminal-oriented API.
pub struct MxcPtyProcess {
    process: SharedPtyProcess,
    reader_taken: Arc<AtomicBool>,
    writer_taken: Arc<AtomicBool>,
    reader_closers: Arc<Mutex<Vec<StreamCloser>>>,
}

impl std::fmt::Debug for MxcPtyProcess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MxcPtyProcess")
            .field("id", &self.id())
            .finish_non_exhaustive()
    }
}

type SharedPtyProcess = Arc<Mutex<Box<dyn SandboxProcess>>>;

#[derive(Clone)]
struct PtyReaderCloserGroup(Arc<Mutex<Vec<StreamCloser>>>);

impl InnerCloser for PtyReaderCloserGroup {
    fn close(&self) {
        let closers = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for closer in closers.iter() {
            closer.close();
        }
    }
}

impl MxcPtyProcess {
    pub(crate) fn new(process: Box<dyn SandboxProcess>) -> Result<Self, Error> {
        if !process.is_pty() {
            return Err(Error::new(
                crate::ErrorCode::BackendError,
                "the selected backend returned a non-PTY process for a PTY spawn",
            ));
        }
        let process = Arc::new(Mutex::new(process));
        let reader_taken = Arc::new(AtomicBool::new(false));
        let writer_taken = Arc::new(AtomicBool::new(false));
        Ok(Self {
            process,
            reader_taken,
            writer_taken,
            reader_closers: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// The OS process id, or `0` when the backend exposes no host process id.
    pub fn id(&self) -> u32 {
        self.lock_process().id()
    }

    /// Warnings collected during spawn and teardown.
    pub fn warnings(&self) -> Vec<String> {
        self.lock_process().warnings()
    }

    /// Structured output available after terminal teardown completes.
    pub fn output_metadata(&self) -> Option<SandboxOutputMetadata> {
        self.lock_process().output_metadata().cloned()
    }

    /// Non-blocking exit check.
    pub fn try_wait(&self) -> std::io::Result<Option<i32>> {
        self.lock_process().try_wait()
    }

    /// Kill the sandboxed process tree.
    pub fn kill(&self) -> std::io::Result<()> {
        self.lock_process().kill()
    }

    /// Mark the process timed out and kill it using the backend's timeout path.
    pub fn kill_for_timeout(&self) -> std::io::Result<()> {
        self.lock_process().kill_for_timeout()
    }

    /// Wait for the sandboxed process to exit.
    ///
    /// If the caller has not taken the PTY writer, this closes it first so an
    /// interactive workload waiting for input can observe EOF. Untaken output
    /// is drained while the workload runs, then cancelled after the foreground
    /// process exits so a descendant retaining the PTY cannot hang this call.
    pub fn wait(&self) -> std::io::Result<WaitOutcome> {
        if !self.writer_taken.load(Ordering::Acquire) {
            drop(self.take_writer()?);
        }
        let output_drain = if self.reader_taken.load(Ordering::Acquire) {
            None
        } else {
            let (mut reader, closer) = self.clone_reader_with_closer()?;
            Some((
                std::thread::spawn(move || {
                    let _ = std::io::copy(&mut reader, &mut std::io::sink());
                }),
                closer,
            ))
        };

        loop {
            let terminal = match self.lock_process().try_wait() {
                Ok(Some(_)) => true,
                Ok(None) => false,
                Err(error) if error.kind() == std::io::ErrorKind::TimedOut => true,
                Err(error) => return Err(error),
            };
            if terminal {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        // `try_wait` established that this is non-blocking now. Calling the
        // backend's final wait performs its terminal bookkeeping and teardown
        // without holding the process mutex across the workload's lifetime.
        let result = match self.lock_process().wait() {
            Ok(code) => Ok(WaitOutcome::Exited(code)),
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => Ok(WaitOutcome::TimedOut),
            Err(error) => Err(error),
        };
        if let Some((drain, closer)) = output_drain {
            if let Some(closer) = closer {
                closer.close();
                let _ = drain.join();
            } else if drain.is_finished() {
                let _ = drain.join();
            }
        }
        result
    }

    /// Clone a reader for the PTY's merged output stream.
    pub fn try_clone_reader(&self) -> std::io::Result<Box<dyn Read + Send>> {
        let (reader, closer) = self.clone_reader_with_closer()?;
        if let Some(closer) = closer {
            self.reader_closers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(closer);
        }
        self.reader_taken.store(true, Ordering::Release);
        Ok(reader)
    }

    /// A closer that unblocks reads from cloned PTY output readers.
    pub fn stdout_closer(&self) -> Option<StreamCloser> {
        if self
            .reader_closers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty()
        {
            return None;
        }
        Some(StreamCloser::new(Box::new(PtyReaderCloserGroup(
            Arc::clone(&self.reader_closers),
        ))))
    }

    /// Take the PTY input writer. This may succeed only once.
    pub fn take_writer(&self) -> std::io::Result<Box<dyn Write + Send>> {
        let writer = self.lock_process().pty_take_writer()?;
        self.writer_taken.store(true, Ordering::Release);
        Ok(writer)
    }

    /// Resize the PTY.
    pub fn resize(&self, size: MxcPtySize) -> std::io::Result<()> {
        size.validate().map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, error.message)
        })?;
        self.lock_process().pty_resize(size.into())
    }

    /// Return the current PTY dimensions.
    pub fn size(&self) -> std::io::Result<MxcPtySize> {
        self.lock_process().pty_size().map(Into::into)
    }

    /// Transfer native PTY input/output endpoints when the backend supports it.
    ///
    /// `stdin` is the PTY input writer and `stdout` is its merged output reader;
    /// `stderr` is always absent.
    #[doc(hidden)]
    pub fn take_native_stdio(&mut self) -> std::io::Result<Option<NativeStdio>> {
        let stdio = self.lock_process().take_native_stdio()?;
        if let Some(stdio) = &stdio {
            if stdio.stdin.is_some() {
                self.writer_taken.store(true, Ordering::Release);
            }
            if stdio.stdout.is_some() {
                self.reader_taken.store(true, Ordering::Release);
            }
        }
        Ok(stdio)
    }

    fn lock_process(&self) -> std::sync::MutexGuard<'_, Box<dyn SandboxProcess>> {
        self.process
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn clone_reader_with_closer(
        &self,
    ) -> std::io::Result<(Box<dyn Read + Send>, Option<StreamCloser>)> {
        let (reader, closer) = self.lock_process().pty_clone_reader_with_closer()?;
        Ok((reader, closer.map(StreamCloser::new)))
    }
}

/// Dimensions of an [`MxcPtyProcess`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MxcPtySize {
    pub rows: u16,
    pub cols: u16,
    pub pixel_width: u16,
    pub pixel_height: u16,
}

impl MxcPtySize {
    /// Validate dimensions against the supported PTY backend range.
    pub fn validate(self) -> Result<(), Error> {
        wxc_common::sandbox_process::PtySize::from(self)
            .validate()
            .map_err(Error::from)
    }
}

impl Default for MxcPtySize {
    fn default() -> Self {
        Self {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        }
    }
}

impl From<MxcPtySize> for wxc_common::sandbox_process::PtySize {
    fn from(size: MxcPtySize) -> Self {
        Self {
            rows: size.rows,
            cols: size.cols,
            pixel_width: size.pixel_width,
            pixel_height: size.pixel_height,
        }
    }
}

impl From<wxc_common::sandbox_process::PtySize> for MxcPtySize {
    fn from(size: wxc_common::sandbox_process::PtySize) -> Self {
        Self {
            rows: size.rows,
            cols: size.cols,
            pixel_width: size.pixel_width,
            pixel_height: size.pixel_height,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum StdioAccess {
    /// No stdio ownership has been transferred from the sandbox.
    #[default]
    Untouched,
    /// One or more Rust streams were taken; remaining streams may be taken individually.
    Individual,
    /// All available native endpoints were transferred; individual access is disabled.
    Native,
}

impl Sandbox {
    pub(crate) fn new(inner: Box<dyn SandboxProcess>) -> Self {
        Self {
            inner,
            stdio_access: StdioAccess::Untouched,
        }
    }

    /// Policy and operational warnings from this sandbox, such as security
    /// warnings, network rules that cannot carry traffic, or a cleanup step
    /// that failed after the workload exited.
    pub fn warnings(&self) -> Vec<String> {
        self.inner.warnings()
    }

    /// Structured outputs available after a terminal wait completes.
    pub fn output_metadata(&self) -> Option<&SandboxOutputMetadata> {
        self.inner.output_metadata()
    }

    /// Take the child's stdin pipe. Returns `None` after the first call.
    pub fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>> {
        if self.stdio_access == StdioAccess::Native {
            return None;
        }
        let stream = self.inner.take_stdin();
        if stream.is_some() {
            self.stdio_access = StdioAccess::Individual;
        }
        stream
    }

    /// Take the child's stdout pipe. Returns `None` after the first call.
    pub fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
        if self.stdio_access == StdioAccess::Native {
            return None;
        }
        let stream = self.inner.take_stdout();
        if stream.is_some() {
            self.stdio_access = StdioAccess::Individual;
        }
        stream
    }

    /// Take the child's stderr pipe. Returns `None` after the first call.
    pub fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>> {
        if self.stdio_access == StdioAccess::Native {
            return None;
        }
        let stream = self.inner.take_stderr();
        if stream.is_some() {
            self.stdio_access = StdioAccess::Individual;
        }
        stream
    }

    #[doc(hidden)]
    pub fn take_native_stdio(&mut self) -> std::io::Result<Option<NativeStdio>> {
        match self.stdio_access {
            StdioAccess::Individual => {
                return Err(std::io::Error::other(
                    "native stdio must be taken before taking individual streams",
                ));
            }
            StdioAccess::Native => return Ok(None),
            StdioAccess::Untouched => {}
        }
        let stdio = self.inner.take_native_stdio()?;
        if stdio.is_some() {
            self.stdio_access = StdioAccess::Native;
        }
        Ok(stdio)
    }

    /// A [`StreamCloser`] that unblocks a parked blocking read on stdout without
    /// killing the child. `None` if stdout was not piped.
    pub fn stdout_closer(&self) -> Option<StreamCloser> {
        self.inner.stdout_closer().map(StreamCloser::new)
    }

    /// As [`stdout_closer`](Self::stdout_closer), for stderr.
    pub fn stderr_closer(&self) -> Option<StreamCloser> {
        self.inner.stderr_closer().map(StreamCloser::new)
    }

    /// Non-blocking exit check: `Some(code)` if the child has exited.
    pub fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
        self.inner.try_wait()
    }

    /// The child's process id.
    pub fn id(&self) -> u32 {
        self.inner.id()
    }

    /// Kill the child.
    pub fn kill(&mut self) -> std::io::Result<()> {
        self.inner.kill()
    }

    /// Request timeout termination and permanently classify a later successful
    /// terminal observation as timed out. Call only after the deadline elapsed.
    #[doc(hidden)]
    pub fn kill_for_timeout(&mut self) -> std::io::Result<()> {
        self.inner.kill_for_timeout()
    }

    /// Wait for the child to exit, draining and discarding any untaken
    /// stdout/stderr so it can't block on a full pipe.
    ///
    /// Returns [`WaitOutcome::Exited`] with the exit code, or
    /// [`WaitOutcome::TimedOut`] if the request's `scriptTimeout` elapsed. `Err`
    /// is reserved for an actual OS / wait failure.
    pub fn wait(&mut self) -> std::io::Result<WaitOutcome> {
        match self.inner.wait() {
            Ok(code) => Ok(WaitOutcome::Exited(code)),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Ok(WaitOutcome::TimedOut),
            Err(e) => Err(e),
        }
    }

    /// Wait for the child to exit, capturing its stdout and stderr.
    ///
    /// The safe alternative to [`take_stdout`](Self::take_stdout) +
    /// [`take_stderr`](Self::take_stderr): it drains both streams **concurrently**
    /// on separate threads, so an output-heavy child can't deadlock (reading one
    /// stream to EOF before the other can). Consumes the handle.
    ///
    /// `Err` is reserved for an actual OS / wait failure; a timeout is reported
    /// as [`Output`] with `outcome: WaitOutcome::TimedOut` and whatever each
    /// stream produced.
    pub fn wait_with_output(mut self) -> std::io::Result<Output> {
        fn capture(stream: Option<Box<dyn Read + Send>>) -> std::thread::JoinHandle<Vec<u8>> {
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                if let Some(mut stream) = stream {
                    let _ = stream.read_to_end(&mut buf);
                }
                buf
            })
        }

        // Take both streams before waiting so `wait` won't discard them, and
        // read each on its own thread so the child never blocks on a full pipe.
        let stdout = capture(self.inner.take_stdout());
        let stderr = capture(self.inner.take_stderr());
        let outcome = self.wait()?;
        // Sampled after the wait: a backend whose teardown runs there reports
        // its failures here.
        let warnings = self.inner.warnings();
        let output_metadata = self.inner.output_metadata().cloned();
        Ok(Output {
            outcome,
            warnings,
            stdout: stdout.join().unwrap_or_default(),
            stderr: stderr.join().unwrap_or_default(),
            output_metadata,
        })
    }
}

/// Closes one of a [`Sandbox`]'s streams, unblocking a read parked on it without
/// killing the process. Obtained from [`Sandbox::stdout_closer`] /
/// [`Sandbox::stderr_closer`].
#[derive(Clone)]
pub struct StreamCloser {
    inner: Arc<dyn InnerCloser>,
}

impl StreamCloser {
    fn new(inner: Box<dyn InnerCloser>) -> Self {
        Self {
            inner: Arc::from(inner),
        }
    }

    /// Close the stream, making any read currently parked on it return.
    pub fn close(&self) {
        self.inner.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::Condvar;

    struct FakeProcess {
        warnings: Vec<String>,
        wait_warning: Option<String>,
        output_metadata: Option<SandboxOutputMetadata>,
        stdout: Option<Box<dyn Read + Send>>,
    }

    struct NativeOnlyFake;

    struct FakePtyProcess {
        resized_to: Arc<Mutex<Vec<wxc_common::sandbox_process::PtySize>>>,
    }

    struct BlockingReader(Arc<(Mutex<bool>, Condvar)>);

    impl Read for BlockingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            let (closed, wake) = &*self.0;
            let mut closed = closed
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            while !*closed {
                closed = wake
                    .wait(closed)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
            Ok(0)
        }
    }

    struct BlockingReaderCloser(Arc<(Mutex<bool>, Condvar)>);

    impl InnerCloser for BlockingReaderCloser {
        fn close(&self) {
            let (closed, wake) = &*self.0;
            *closed
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = true;
            wake.notify_all();
        }
    }

    struct KillablePtyProcess {
        running: Arc<AtomicBool>,
        reader_state: Arc<(Mutex<bool>, Condvar)>,
    }

    impl SandboxProcess for KillablePtyProcess {
        fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>> {
            None
        }

        fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
            None
        }

        fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>> {
            None
        }

        fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
            Ok((!self.running.load(Ordering::Acquire)).then_some(0))
        }

        fn id(&self) -> u32 {
            1
        }

        fn kill(&mut self) -> std::io::Result<()> {
            self.running.store(false, Ordering::Release);
            Ok(())
        }

        fn wait(&mut self) -> std::io::Result<i32> {
            Ok(0)
        }

        fn is_pty(&self) -> bool {
            true
        }

        fn pty_clone_reader(&self) -> std::io::Result<Box<dyn Read + Send>> {
            Ok(Box::new(BlockingReader(Arc::clone(&self.reader_state))))
        }

        fn pty_clone_reader_with_closer(
            &self,
        ) -> std::io::Result<(Box<dyn Read + Send>, Option<Box<dyn InnerCloser>>)> {
            Ok((
                Box::new(BlockingReader(Arc::clone(&self.reader_state))),
                Some(Box::new(BlockingReaderCloser(Arc::clone(
                    &self.reader_state,
                )))),
            ))
        }

        fn pty_take_writer(&self) -> std::io::Result<Box<dyn Write + Send>> {
            Ok(Box::new(std::io::sink()))
        }
    }

    impl SandboxProcess for FakePtyProcess {
        fn warnings(&self) -> Vec<String> {
            Vec::new()
        }

        fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>> {
            None
        }

        fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
            None
        }

        fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>> {
            None
        }

        fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
            Ok(None)
        }

        fn id(&self) -> u32 {
            1
        }

        fn kill(&mut self) -> std::io::Result<()> {
            Ok(())
        }

        fn wait(&mut self) -> std::io::Result<i32> {
            Ok(0)
        }

        fn is_pty(&self) -> bool {
            true
        }

        fn pty_clone_reader(&self) -> std::io::Result<Box<dyn Read + Send>> {
            Ok(Box::new(std::io::empty()))
        }

        fn pty_take_writer(&self) -> std::io::Result<Box<dyn Write + Send>> {
            Ok(Box::new(std::io::sink()))
        }

        fn pty_resize(&self, size: wxc_common::sandbox_process::PtySize) -> std::io::Result<()> {
            self.resized_to
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(size);
            Ok(())
        }

        fn pty_size(&self) -> std::io::Result<wxc_common::sandbox_process::PtySize> {
            Ok(wxc_common::sandbox_process::PtySize::default())
        }
    }

    impl SandboxProcess for NativeOnlyFake {
        fn warnings(&self) -> Vec<String> {
            Vec::new()
        }

        fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>> {
            panic!("individual stdin must not be delegated after native transfer")
        }

        fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
            panic!("individual stdout must not be delegated after native transfer")
        }

        fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>> {
            panic!("individual stderr must not be delegated after native transfer")
        }

        fn take_native_stdio(&mut self) -> std::io::Result<Option<NativeStdio>> {
            Ok(Some(NativeStdio {
                stdin: None,
                stdout: None,
                stderr: None,
            }))
        }

        fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
            Ok(Some(0))
        }

        fn id(&self) -> u32 {
            1
        }

        fn kill(&mut self) -> std::io::Result<()> {
            Ok(())
        }

        fn wait(&mut self) -> std::io::Result<i32> {
            Ok(0)
        }
    }

    impl SandboxProcess for FakeProcess {
        fn warnings(&self) -> Vec<String> {
            self.warnings.clone()
        }

        fn output_metadata(&self) -> Option<&SandboxOutputMetadata> {
            self.output_metadata.as_ref()
        }

        fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>> {
            None
        }

        fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
            self.stdout.take()
        }

        fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>> {
            None
        }

        fn take_native_stdio(&mut self) -> std::io::Result<Option<NativeStdio>> {
            panic!("native stdio must not be delegated after taking a stream")
        }

        fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
            Ok(Some(0))
        }

        fn id(&self) -> u32 {
            1
        }

        fn kill(&mut self) -> std::io::Result<()> {
            Ok(())
        }

        fn wait(&mut self) -> std::io::Result<i32> {
            if let Some(warning) = self.wait_warning.take() {
                self.warnings.push(warning);
            }
            Ok(0)
        }
    }

    #[test]
    fn sandbox_and_output_expose_security_warnings() {
        let warning = "permissive mode weakens containment".to_string();
        let wait_warning = "telemetry emission failed".to_string();
        let sandbox = Sandbox::new(Box::new(FakeProcess {
            warnings: vec![warning.clone()],
            wait_warning: Some(wait_warning.clone()),
            output_metadata: Some(SandboxOutputMetadata {
                capture_denials: Some(CaptureDenialsOutput {
                    kind: CaptureDenialsOutput::KIND.to_string(),
                    output_path: "denials.json".to_string(),
                    exit_code: 0,
                    total_denials: 2,
                    denied_resources_truncated: false,
                    etl_path: None,
                }),
                capture_denials_error: None,
            }),
            stdout: None,
        }));

        assert_eq!(sandbox.warnings(), [warning.as_str()]);

        let output = sandbox.wait_with_output().expect("wait succeeds");
        assert_eq!(output.warnings, [warning, wait_warning]);
        assert_eq!(
            output
                .output_metadata
                .unwrap()
                .capture_denials
                .unwrap()
                .total_denials,
            2
        );
    }

    #[test]
    fn native_stdio_is_rejected_after_an_individual_stream_is_taken() {
        let mut sandbox = Sandbox::new(Box::new(FakeProcess {
            warnings: Vec::new(),
            wait_warning: None,
            output_metadata: None,
            stdout: Some(Box::new(std::io::Cursor::new(Vec::<u8>::new()))),
        }));

        assert!(sandbox.take_stdout().is_some());
        let error = sandbox
            .take_native_stdio()
            .expect_err("mixed stream ownership must be rejected");

        assert_eq!(
            error.to_string(),
            "native stdio must be taken before taking individual streams"
        );
    }

    #[test]
    fn individual_streams_are_not_delegated_after_native_stdio_is_taken() {
        let mut sandbox = Sandbox::new(Box::new(NativeOnlyFake));

        assert!(sandbox
            .take_native_stdio()
            .expect("native stdio transfer succeeds")
            .is_some());
        assert!(sandbox.take_stdin().is_none());
        assert!(sandbox.take_stdout().is_none());
        assert!(sandbox.take_stderr().is_none());
        assert!(sandbox
            .take_native_stdio()
            .expect("repeated native transfer is empty")
            .is_none());
    }

    #[test]
    fn pty_resize_validates_before_delegating_to_the_backend() {
        let resized_to = Arc::new(Mutex::new(Vec::new()));
        let terminal = MxcPtyProcess::new(Box::new(FakePtyProcess {
            resized_to: Arc::clone(&resized_to),
        }))
        .expect("fake PTY process is accepted");

        let error = terminal
            .resize(MxcPtySize {
                rows: 0,
                ..MxcPtySize::default()
            })
            .expect_err("invalid dimensions must fail");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(resized_to
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty());
    }

    #[test]
    fn pty_wait_can_be_killed_while_output_is_held_open() {
        let running = Arc::new(AtomicBool::new(true));
        let reader_state = Arc::new((Mutex::new(false), Condvar::new()));
        let terminal = Arc::new(
            MxcPtyProcess::new(Box::new(KillablePtyProcess {
                running: Arc::clone(&running),
                reader_state: Arc::clone(&reader_state),
            }))
            .expect("fake PTY process is accepted"),
        );

        let waiter = {
            let terminal = Arc::clone(&terminal);
            std::thread::spawn(move || terminal.wait())
        };
        std::thread::sleep(Duration::from_millis(25));
        terminal.kill().expect("kill is not blocked by wait");

        assert_eq!(
            waiter.join().expect("wait thread does not panic").unwrap(),
            WaitOutcome::Exited(0)
        );
        assert!(
            *reader_state
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            "the automatic output drain must be cancelled after process completion"
        );
    }
}
