// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The SDK's sandbox handle — a crate-owned facade over the internal
//! `wxc_common` streaming handle, so the public API never exposes the
//! foundation crate's traits.

use std::io::{Read, Write};

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
    /// The request's `scriptTimeout` elapsed before the process exited; the
    /// process and its whole tree were killed.
    TimedOut,
}

/// The captured result of running a [`Sandbox`] to completion via
/// [`wait_with_output`](Sandbox::wait_with_output).
#[derive(Debug, Clone)]
pub struct Output {
    /// How the process finished.
    pub outcome: WaitOutcome,
    /// Security warnings emitted while applying the sandbox policy.
    pub warnings: Vec<String>,
    /// Everything the child wrote to stdout.
    pub stdout: Vec<u8>,
    /// Everything the child wrote to stderr.
    pub stderr: Vec<u8>,
}

/// A live sandboxed process, returned by [`spawn_sandbox`](crate::spawn_sandbox).
///
/// Stream the child's stdio with the `take_*` accessors, wait for it, or kill
/// it (and its whole tree). No pty is allocated — the streams are ordinary
/// pipes. Any stdout/stderr the caller does not `take_*` is drained and
/// discarded by [`wait`](Self::wait).
pub struct Sandbox {
    inner: Box<dyn SandboxProcess>,
}

impl Sandbox {
    pub(crate) fn new(inner: Box<dyn SandboxProcess>) -> Self {
        Self { inner }
    }

    /// Security warnings emitted while applying the sandbox policy.
    pub fn warnings(&self) -> &[String] {
        self.inner.warnings()
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

    /// Kill the child and its process tree.
    pub fn kill(&mut self) -> std::io::Result<()> {
        self.inner.kill()
    }

    /// Wait for the child to exit, draining and discarding any untaken
    /// stdout/stderr so it can't block on a full pipe.
    ///
    /// Returns [`WaitOutcome::Exited`] with the exit code, or
    /// [`WaitOutcome::TimedOut`] if the request's `scriptTimeout` elapsed (the
    /// process and its tree are killed first). `Err` is reserved for an actual
    /// OS / wait failure.
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
    /// stream produced before the tree was killed.
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
        let warnings = self.inner.warnings().to_vec();
        let stdout = capture(self.inner.take_stdout());
        let stderr = capture(self.inner.take_stderr());
        let outcome = self.wait()?;
        Ok(Output {
            outcome,
            warnings,
            stdout: stdout.join().unwrap_or_default(),
            stderr: stderr.join().unwrap_or_default(),
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

    struct FakeProcess {
        warnings: Vec<String>,
    }

    impl SandboxProcess for FakeProcess {
        fn warnings(&self) -> &[String] {
            &self.warnings
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
            Ok(0)
        }
    }

    #[test]
    fn sandbox_and_output_expose_security_warnings() {
        let warning = "permissive mode weakens containment".to_string();
        let sandbox = Sandbox::new(Box::new(FakeProcess {
            warnings: vec![warning.clone()],
        }));

        assert_eq!(sandbox.warnings(), [warning.as_str()]);

        let output = sandbox.wait_with_output().expect("wait succeeds");
        assert_eq!(output.warnings, [warning]);
    }
}
