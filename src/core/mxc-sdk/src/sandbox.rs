// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The SDK's sandbox handle — a crate-owned facade over the internal
//! `wxc_common` streaming handle, so the public API never exposes the
//! foundation crate's traits.

use std::io::{Read, Write};

use wxc_common::sandbox_process::{SandboxProcess, StreamCloser as InnerCloser};

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
    /// stdout/stderr so it can't block on a full pipe. Returns the exit code
    /// (`io::ErrorKind::TimedOut` if a `timeout` elapsed first).
    pub fn wait(&mut self) -> std::io::Result<i32> {
        self.inner.wait()
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
