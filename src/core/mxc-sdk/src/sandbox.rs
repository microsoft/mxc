// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The SDK's sandbox handle — a crate-owned facade over the internal
//! `wxc_common` streaming handle, so the public API never exposes the
//! foundation crate's traits.

use std::io::{Read, Write};

pub use wxc_common::models::{
    CaptureDenialsErrorOutput, CaptureDenialsOutput, SandboxOutputMetadata,
};
use wxc_common::sandbox_process::{SandboxProcess, StreamCloser as InnerCloser};

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
    /// Everything the child wrote to stderr. Empty for a pty-backed backend
    /// such as LXC, where terminal output is merged into [`stdout`](Self::stdout).
    pub stderr: Vec<u8>,
    /// Structured outputs produced by optional sandbox features.
    pub output_metadata: Option<SandboxOutputMetadata>,
}

/// A live sandboxed process, returned by [`spawn_sandbox`](crate::spawn_sandbox)
/// and [`exec_sandbox`](crate::exec_sandbox).
///
/// Stream the child's stdio with the `take_*` accessors, wait for it, or kill
/// it. Most backends expose ordinary pipes. LXC exposes a pty so the inner
/// workload retains a true terminal; its stderr is merged into stdout. Any
/// stdout/stderr the caller does not `take_*` is drained and discarded by
/// [`wait`](Self::wait).
pub struct Sandbox {
    inner: Box<dyn SandboxProcess>,
}

impl Sandbox {
    pub(crate) fn new(inner: Box<dyn SandboxProcess>) -> Self {
        Self { inner }
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
        self.inner.take_stdin()
    }

    /// Take the child's stdout pipe. Returns `None` after the first call.
    pub fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
        self.inner.take_stdout()
    }

    /// Take the child's stderr pipe. Returns `None` after the first call.
    pub fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>> {
        self.inner.take_stderr()
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
        let stdout_closer = self.inner.stdout_closer();
        let stderr_closer = self.inner.stderr_closer();
        let stdout = capture(self.inner.take_stdout());
        let stderr = capture(self.inner.take_stderr());
        let wait_result = self.wait();
        // The foreground process is terminal now. A descendant may still hold
        // an inherited output handle open, so release the capture reads before
        // joining them. Both capture threads have been draining concurrently
        // throughout the foreground wait, preserving its output.
        if let Some(closer) = stdout_closer {
            closer.close();
        }
        if let Some(closer) = stderr_closer {
            closer.close();
        }
        let stdout = stdout.join().unwrap_or_default();
        let stderr = stderr.join().unwrap_or_default();
        let outcome = wait_result?;
        // Sampled after the wait: a backend whose teardown runs there reports
        // its failures here.
        let warnings = self.inner.warnings();
        let output_metadata = self.inner.output_metadata().cloned();
        Ok(Output {
            outcome,
            warnings,
            stdout,
            stderr,
            output_metadata,
        })
    }
}

/// Closes one of a [`Sandbox`]'s streams, unblocking a read parked on it without
/// killing the process. Obtained from [`Sandbox::stdout_closer`] /
/// [`Sandbox::stderr_closer`].
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
    use std::collections::VecDeque;
    use std::sync::{Arc, Condvar, Mutex};

    struct FakeProcess {
        warnings: Vec<String>,
        wait_warning: Option<String>,
        output_metadata: Option<SandboxOutputMetadata>,
    }

    #[derive(Default)]
    struct HeldOutputState {
        bytes: VecDeque<u8>,
        closed: bool,
    }

    #[derive(Default)]
    struct HeldOutput {
        state: Mutex<HeldOutputState>,
        ready: Condvar,
    }

    struct HeldOutputReader(Arc<HeldOutput>);

    impl Read for HeldOutputReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            let mut state = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
            while state.bytes.is_empty() && !state.closed {
                state = self.0.ready.wait(state).unwrap_or_else(|e| e.into_inner());
            }
            state.bytes.read(buf)
        }
    }

    #[derive(Clone)]
    struct HeldOutputCloser(Arc<HeldOutput>);

    impl InnerCloser for HeldOutputCloser {
        fn close(&self) {
            let mut state = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
            state.closed = true;
            self.0.ready.notify_all();
        }
    }

    struct HeldOutputProcess {
        output: Arc<HeldOutput>,
        reader: Option<HeldOutputReader>,
    }

    impl HeldOutputProcess {
        fn new() -> Self {
            let output = Arc::new(HeldOutput::default());
            Self {
                reader: Some(HeldOutputReader(Arc::clone(&output))),
                output,
            }
        }
    }

    impl SandboxProcess for HeldOutputProcess {
        fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>> {
            None
        }

        fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
            self.reader
                .take()
                .map(|reader| Box::new(reader) as Box<dyn Read + Send>)
        }

        fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>> {
            None
        }

        fn stdout_closer(&self) -> Option<Box<dyn InnerCloser>> {
            Some(Box::new(HeldOutputCloser(Arc::clone(&self.output))))
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
            let mut state = self.output.state.lock().unwrap_or_else(|e| e.into_inner());
            state.bytes.extend(b"foreground output");
            self.output.ready.notify_all();
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
            None
        }

        fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>> {
            None
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
    fn wait_with_output_closes_descendant_held_stream_after_foreground_wait() {
        let sandbox = Sandbox::new(Box::new(HeldOutputProcess::new()));
        let output = sandbox
            .wait_with_output()
            .expect("capture should not wait for a descendant-held output handle");

        assert_eq!(output.outcome, WaitOutcome::Exited(0));
        assert_eq!(output.stdout, b"foreground output");
    }
}
