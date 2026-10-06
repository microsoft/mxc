// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The SDK's sandbox handle â€” a crate-owned facade over the internal
//! `wxc_common` streaming handle, so the public API never exposes the
//! foundation crate's traits.

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::options::{
    DeprovisionOptions, ProvisionOptions, SpawnInContainerOptions, SpawnInContainerWithPtyOptions,
    StartOptions, StopOptions,
};
use crate::state_aware_sdk::{
    lifecycle_sdk_input, ContainerId, ExecutionRequest, LifecycleResult, ProvisionRequest,
    ProvisionResult, StateAwareResult, ValidationResult,
};
use crate::Error;
pub use wxc_common::models::{
    CaptureDenialsErrorOutput as CaptureDenialsError, CaptureDenialsOutput as CaptureDenialsResult,
    SandboxOutputMetadata as ExecutionMetadata,
};
use wxc_common::sandbox_process::{NativeStdio, SandboxProcess, StreamCloser as InnerCloser};
use wxc_common::state_aware_backend::ExecOutcome;
use wxc_common::state_aware_operation::StateAwareOperation;

fn run_typed_state_aware(
    input: wxc_common::sdk_input::SdkStateAwareInput,
    experimental: bool,
    dry_run: bool,
) -> Result<StateAwareResult, Error> {
    mxc_engine::run_typed_state_aware_request(input, experimental, dry_run)
        .map(StateAwareResult::from_engine)
}

/// Provision a container from typed Rust policy.
pub fn provision(
    request: ProvisionRequest,
    options: ProvisionOptions,
) -> Result<ProvisionResult, Error> {
    let input = request
        .into_sdk_input(options.telemetry)
        .map_err(Error::from)?;
    run_typed_state_aware(input, options.experimental, false)?
        .into_provision()
        .map_err(Error::from)
}

/// Validate a provision request without creating a container.
pub fn validate_provision(
    request: ProvisionRequest,
    options: ProvisionOptions,
) -> Result<ValidationResult, Error> {
    let input = request
        .into_sdk_input(options.telemetry)
        .map_err(Error::from)?;
    run_typed_state_aware(input, options.experimental, true)?
        .into_validation()
        .map_err(Error::from)
}

/// Start an existing container.
pub fn start(container_id: &ContainerId, options: StartOptions) -> Result<LifecycleResult, Error> {
    let input = lifecycle_sdk_input(container_id, options.telemetry, |sandbox_id| {
        StateAwareOperation::Start { sandbox_id }
    })
    .map_err(Error::from)?;
    run_typed_state_aware(input, options.experimental, false)?
        .into_lifecycle()
        .map_err(Error::from)
}

/// Validate a start request without starting the container.
pub fn validate_start(
    container_id: &ContainerId,
    options: StartOptions,
) -> Result<ValidationResult, Error> {
    let input = lifecycle_sdk_input(container_id, options.telemetry, |sandbox_id| {
        StateAwareOperation::Start { sandbox_id }
    })
    .map_err(Error::from)?;
    run_typed_state_aware(input, options.experimental, true)?
        .into_validation()
        .map_err(Error::from)
}

/// Stop an existing container.
pub fn stop(container_id: &ContainerId, options: StopOptions) -> Result<LifecycleResult, Error> {
    let input = lifecycle_sdk_input(container_id, options.telemetry, |sandbox_id| {
        StateAwareOperation::Stop { sandbox_id }
    })
    .map_err(Error::from)?;
    run_typed_state_aware(input, options.experimental, false)?
        .into_lifecycle()
        .map_err(Error::from)
}

/// Validate a stop request without stopping the container.
pub fn validate_stop(
    container_id: &ContainerId,
    options: StopOptions,
) -> Result<ValidationResult, Error> {
    let input = lifecycle_sdk_input(container_id, options.telemetry, |sandbox_id| {
        StateAwareOperation::Stop { sandbox_id }
    })
    .map_err(Error::from)?;
    run_typed_state_aware(input, options.experimental, true)?
        .into_validation()
        .map_err(Error::from)
}

/// Deprovision an existing container.
pub fn deprovision(
    container_id: &ContainerId,
    options: DeprovisionOptions,
) -> Result<LifecycleResult, Error> {
    let input = lifecycle_sdk_input(container_id, options.telemetry, |sandbox_id| {
        StateAwareOperation::Deprovision { sandbox_id }
    })
    .map_err(Error::from)?;
    run_typed_state_aware(input, options.experimental, false)?
        .into_lifecycle()
        .map_err(Error::from)
}

/// Validate a deprovision request without changing the container.
pub fn validate_deprovision(
    container_id: &ContainerId,
    options: DeprovisionOptions,
) -> Result<ValidationResult, Error> {
    let input = lifecycle_sdk_input(container_id, options.telemetry, |sandbox_id| {
        StateAwareOperation::Deprovision { sandbox_id }
    })
    .map_err(Error::from)?;
    run_typed_state_aware(input, options.experimental, true)?
        .into_validation()
        .map_err(Error::from)
}

/// Spawn a workload in an existing container and return a live process.
pub fn spawn_in_container(
    container_id: &ContainerId,
    request: ExecutionRequest,
    options: SpawnInContainerOptions,
) -> Result<MxcProcess, Error> {
    let input = request
        .into_sdk_input(container_id, options.telemetry)
        .map_err(Error::from)?;
    mxc_engine::exec_typed_state_aware_request(input, options.experimental).map(MxcProcess::new)
}

/// Spawn a workload in an existing container with a caller-controlled PTY.
pub fn spawn_in_container_with_pty(
    container_id: &ContainerId,
    request: ExecutionRequest,
    options: SpawnInContainerWithPtyOptions,
) -> Result<MxcPtyProcess, Error> {
    options.size.validate()?;
    let input = request
        .into_sdk_input(container_id, options.telemetry)
        .map_err(Error::from)?;
    mxc_engine::exec_typed_state_aware_pty_request(input, options.experimental, options.size.into())
        .and_then(MxcPtyProcess::new)
}

/// Validate an execution request without running a workload.
pub fn validate_process(
    container_id: &ContainerId,
    request: ExecutionRequest,
    options: SpawnInContainerOptions,
) -> Result<ValidationResult, Error> {
    let input = request
        .into_sdk_input(container_id, options.telemetry)
        .map_err(Error::from)?;
    run_typed_state_aware(input, options.experimental, true)?
        .into_validation()
        .map_err(Error::from)
}

#[expect(
    dead_code,
    reason = "Attached exec is reserved but not exposed by the SDK yet"
)]
fn exec_in_attached(
    container_id: &ContainerId,
    request: ExecutionRequest,
    options: SpawnInContainerOptions,
) -> Result<WaitResult, Error> {
    let input = request
        .into_sdk_input(container_id, options.telemetry)
        .map_err(Error::from)?;
    mxc_engine::exec_typed_state_aware_attached_request(input, options.experimental).map(
        |outcome| match outcome {
            ExecOutcome::Exited(code) => WaitResult::Exited(code),
            ExecOutcome::TimedOut => WaitResult::TimedOut,
        },
    )
}

/// The outcome of waiting on a [`MxcProcess`] (see [`MxcProcess::wait`]).
///
/// An ordinary exit and a timeout are both represented here as success
/// outcomes; [`MxcProcess::wait`] reserves its `Err` for an actual OS / wait
/// failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitResult {
    /// The process exited with this code. On Unix a process terminated by a
    /// signal (rather than exiting normally) surfaces as `Exited(-1)`.
    Exited(i32),
    /// The request's timeout elapsed while the process was running, and
    /// the process is no longer running.
    ///
    /// **Deadline spent, and the process is gone.** Whether it was killed or
    /// exited on its own a moment past the deadline is not distinguished: both
    /// missed the deadline the caller asked for, and reporting the exit code
    /// one of them happened to produce would hide that.
    ///
    /// How far "gone" reaches depends on the backend. A process-spawning
    /// backend kills the whole tree. A backend whose only primitive is the
    /// foreground process â€” the state-aware `exec` path over IsolationSession â€”
    /// confirms that process, and a descendant the workload backgrounded is
    /// reclaimed when the container is stopped and deprovisioned rather than here.
    ///
    /// That lifecycle route is reachable through
    /// [`spawn_in_container`](crate::v1::container::spawn_in_container) when the
    /// backend is compiled in via this crate's `isolation_session` feature.
    /// IsolationSession requires no runtime experimental opt-in.
    TimedOut,
}

/// The captured result of running a [`MxcProcess`] to completion via
/// [`wait_with_output`](MxcProcess::wait_with_output).
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// How the process finished.
    pub outcome: WaitResult,
    /// Policy and operational warnings from the container, such as security
    /// warnings, network rules that cannot carry traffic, or a cleanup step
    /// that failed after the workload exited.
    pub warnings: Vec<String>,
    /// Everything the child wrote to stdout.
    pub stdout: Vec<u8>,
    /// Everything the child wrote to stderr.
    pub stderr: Vec<u8>,
    /// Structured outputs produced by optional container features.
    pub output_metadata: Option<ExecutionMetadata>,
}

/// A live container process, returned by [`spawn`](crate::v1::spawn)
/// and [`spawn_in_container`](crate::v1::container::spawn_in_container).
///
/// Stream the child's stdio with the `take_*` accessors, wait for it, or kill
/// it. No pty is allocated â€” the streams are ordinary pipes. Any stdout/stderr
/// the caller does not `take_*` is drained and discarded by [`wait`](Self::wait).
pub struct MxcProcess {
    inner: Box<dyn SandboxProcess>,
    stdio_access: StdioAccess,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum StdioAccess {
    /// No stdio ownership has been transferred from the container process.
    #[default]
    Untouched,
    /// One or more Rust streams were taken; remaining streams may be taken individually.
    Individual,
    /// All available native endpoints were transferred; individual access is disabled.
    Native,
}

impl MxcProcess {
    pub(crate) fn new(inner: Box<dyn SandboxProcess>) -> Self {
        Self {
            inner,
            stdio_access: StdioAccess::Untouched,
        }
    }

    /// Policy and operational warnings from this container, such as security
    /// warnings, network rules that cannot carry traffic, or a cleanup step
    /// that failed after the workload exited.
    pub fn warnings(&self) -> Vec<String> {
        self.inner.warnings()
    }

    /// Structured outputs available after a terminal wait completes.
    pub fn output_metadata(&self) -> Option<&ExecutionMetadata> {
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
    /// Returns [`WaitResult::Exited`] with the exit code, or
    /// [`WaitResult::TimedOut`] if the request's `scriptTimeout` elapsed. `Err`
    /// is reserved for an actual OS / wait failure.
    pub fn wait(&mut self) -> std::io::Result<WaitResult> {
        match self.inner.wait() {
            Ok(code) => Ok(WaitResult::Exited(code)),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Ok(WaitResult::TimedOut),
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
    /// `Err` reports an OS / wait or output-read failure; a timeout is reported
    /// as [`ExecutionResult`] with `outcome: WaitResult::TimedOut` and whatever each
    /// stream captured before cancellation. Timeout and wait failures cancel
    /// outstanding reads so descendants retaining pipe ends cannot block capture.
    pub fn wait_with_output(mut self) -> std::io::Result<ExecutionResult> {
        fn capture(
            stream: Option<Box<dyn Read + Send>>,
        ) -> std::thread::JoinHandle<std::io::Result<Vec<u8>>> {
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                if let Some(mut stream) = stream {
                    stream.read_to_end(&mut buf)?;
                }
                Ok(buf)
            })
        }

        // Take both streams before waiting so `wait` won't discard them, and
        // read each on its own thread so the child never blocks on a full pipe.
        let stdout_closer = self.stdout_closer();
        let stderr_closer = self.stderr_closer();
        let stdout = capture(self.inner.take_stdout());
        let stderr = capture(self.inner.take_stderr());
        let outcome = self.wait();
        // Sampled after the wait: a backend whose teardown runs there reports
        // its failures here.
        let warnings = self.inner.warnings();
        let output_metadata = self.inner.output_metadata().cloned();
        // Some backends keep their original pipe ends until the process object
        // is released. Drop it before joining readers so they can observe EOF.
        drop(self);
        // A timed-out descendant may retain a write end even after the
        // foreground process has exited. Stop capture rather than wait for it.
        if !matches!(outcome, Ok(WaitResult::Exited(_))) {
            if let Some(closer) = stdout_closer {
                closer.close();
            }
            if let Some(closer) = stderr_closer {
                closer.close();
            }
        }
        let stdout = stdout
            .join()
            .unwrap_or_else(|_| Err(std::io::Error::other("stdout capture thread panicked")));
        let stderr = stderr
            .join()
            .unwrap_or_else(|_| Err(std::io::Error::other("stderr capture thread panicked")));
        Ok(ExecutionResult {
            outcome: outcome?,
            warnings,
            stdout: stdout?,
            stderr: stderr?,
            output_metadata,
        })
    }
}

/// A live container process attached to a caller-controlled pseudo-terminal.
pub struct MxcPtyProcess {
    process: Arc<Mutex<Box<dyn SandboxProcess>>>,
    reader_taken: AtomicBool,
    writer_taken: AtomicBool,
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
        Ok(Self {
            process: Arc::new(Mutex::new(process)),
            reader_taken: AtomicBool::new(false),
            writer_taken: AtomicBool::new(false),
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
    pub fn output_metadata(&self) -> Option<ExecutionMetadata> {
        self.lock_process().output_metadata().cloned()
    }

    /// Non-blocking exit check.
    pub fn try_wait(&self) -> std::io::Result<Option<i32>> {
        self.lock_process().try_wait()
    }

    /// Kill the container process tree.
    pub fn kill(&self) -> std::io::Result<()> {
        self.lock_process().kill()
    }

    /// Mark the process timed out and kill it using the backend's timeout path.
    pub fn kill_for_timeout(&self) -> std::io::Result<()> {
        self.lock_process().kill_for_timeout()
    }

    /// Wait for the container process to exit, draining untaken terminal output.
    ///
    /// Untaken input requests canonical-mode terminal EOF. Raw-mode applications
    /// must use their own completion protocol. Output draining is cancelled after
    /// the foreground process exits so descendants cannot keep this call waiting.
    pub fn wait(&self) -> std::io::Result<WaitResult> {
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

        let result = match self.lock_process().wait() {
            Ok(code) => Ok(WaitResult::Exited(code)),
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => Ok(WaitResult::TimedOut),
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

/// Closes one of a [`MxcProcess`]'s streams, unblocking a read parked on it without
/// killing the process. Obtained from [`MxcProcess::stdout_closer`] /
/// [`MxcProcess::stderr_closer`].
pub struct StreamCloser {
    inner: Box<dyn InnerCloser>,
}

impl StreamCloser {
    fn new(inner: Box<dyn InnerCloser>) -> Self {
        Self { inner }
    }

    /// Close the stream, making any read currently parked on it return.
    pub fn close(&self) {
        self.inner.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeProcess {
        warnings: Vec<String>,
        wait_warning: Option<String>,
        output_metadata: Option<ExecutionMetadata>,
        stdout: Option<Box<dyn Read + Send>>,
        release_output: Option<std::sync::mpsc::Sender<()>>,
        output_closer: Option<std::sync::mpsc::Sender<()>>,
        timed_out: bool,
    }

    impl Drop for FakeProcess {
        fn drop(&mut self) {
            if let Some(release) = self.release_output.take() {
                let _ = release.send(());
            }
        }
    }

    struct ReleaseBoundReader {
        release: std::sync::mpsc::Receiver<()>,
        tail: std::io::Cursor<Vec<u8>>,
        released: bool,
    }

    impl Read for ReleaseBoundReader {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            if !self.released {
                self.release
                    .recv_timeout(std::time::Duration::from_secs(2))
                    .map_err(std::io::Error::other)?;
                self.released = true;
            }
            self.tail.read(output)
        }
    }

    struct OutputCloser(std::sync::mpsc::Sender<()>);

    impl InnerCloser for OutputCloser {
        fn close(&self) {
            let _ = self.0.send(());
        }
    }

    struct FailedReader;

    impl Read for FailedReader {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("capture read failed"))
        }
    }

    struct NativeOnlyFake;

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

        fn output_metadata(&self) -> Option<&ExecutionMetadata> {
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

        fn stdout_closer(&self) -> Option<Box<dyn InnerCloser>> {
            self.output_closer
                .as_ref()
                .map(|sender| Box::new(OutputCloser(sender.clone())) as Box<dyn InnerCloser>)
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
            if self.timed_out {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "workload timed out",
                ));
            }
            Ok(0)
        }
    }

    #[test]
    fn sandbox_and_output_expose_security_warnings() {
        let warning = "permissive mode weakens containment".to_string();
        let wait_warning = "telemetry emission failed".to_string();
        let sandbox = MxcProcess::new(Box::new(FakeProcess {
            warnings: vec![warning.clone()],
            wait_warning: Some(wait_warning.clone()),
            output_metadata: Some(ExecutionMetadata {
                capture_denials: Some(CaptureDenialsResult {
                    kind: CaptureDenialsResult::KIND.to_string(),
                    output_path: "denials.json".to_string(),
                    exit_code: 0,
                    total_denials: 2,
                    denied_resources_truncated: false,
                    etl_path: None,
                }),
                capture_denials_error: None,
            }),
            stdout: None,
            release_output: None,
            output_closer: None,
            timed_out: false,
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
    fn captured_output_releases_backend_pipe_owners_before_joining_readers() {
        let (release, released) = std::sync::mpsc::channel();
        let sandbox = MxcProcess::new(Box::new(FakeProcess {
            warnings: vec!["native warning".to_string()],
            wait_warning: Some("completion warning".to_string()),
            output_metadata: None,
            stdout: Some(Box::new(ReleaseBoundReader {
                release: released,
                tail: std::io::Cursor::new(b"buffered tail".to_vec()),
                released: false,
            })),
            release_output: Some(release),
            output_closer: None,
            timed_out: false,
        }));
        let output = sandbox.wait_with_output().expect("captured output");
        assert_eq!(output.stdout, b"buffered tail");
        assert_eq!(output.outcome, WaitResult::Exited(0));
        assert_eq!(output.warnings, ["native warning", "completion warning"]);
    }

    #[test]
    fn captured_timeout_closes_reads_retained_by_descendants() {
        let (close, closed) = std::sync::mpsc::channel();
        let sandbox = MxcProcess::new(Box::new(FakeProcess {
            warnings: Vec::new(),
            wait_warning: None,
            output_metadata: None,
            stdout: Some(Box::new(ReleaseBoundReader {
                release: closed,
                tail: std::io::Cursor::new(Vec::new()),
                released: false,
            })),
            release_output: None,
            output_closer: Some(close),
            timed_out: true,
        }));
        let output = sandbox.wait_with_output().expect("timeout capture");
        assert_eq!(output.outcome, WaitResult::TimedOut);
        assert!(output.stdout.is_empty());
    }

    #[test]
    fn captured_read_failure_is_not_returned_as_successful_output() {
        let sandbox = MxcProcess::new(Box::new(FakeProcess {
            warnings: Vec::new(),
            wait_warning: None,
            output_metadata: None,
            stdout: Some(Box::new(FailedReader)),
            release_output: None,
            output_closer: None,
            timed_out: false,
        }));
        let error = sandbox.wait_with_output().expect_err("read must fail");
        assert_eq!(error.to_string(), "capture read failed");
    }

    #[test]
    fn native_stdio_is_rejected_after_an_individual_stream_is_taken() {
        let mut sandbox = MxcProcess::new(Box::new(FakeProcess {
            warnings: Vec::new(),
            wait_warning: None,
            output_metadata: None,
            stdout: Some(Box::new(std::io::Cursor::new(Vec::<u8>::new()))),
            release_output: None,
            output_closer: None,
            timed_out: false,
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
        let mut sandbox = MxcProcess::new(Box::new(NativeOnlyFake));

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
}
