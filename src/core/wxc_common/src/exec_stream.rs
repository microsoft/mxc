// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Adapter that presents a state-aware [`ExecHandle`] as a streaming
//! [`SandboxProcess`], so the library / FFI streaming path can drive an `exec`
//! phase live (read stdout/stderr, feed stdin, wait, kill) exactly like a
//! spawned one-shot sandbox.
//!
//! [`ExecHandle`] carries the agent's raw stdout / stderr / stdin pipe handles
//! plus a `waiter` closure (blocks until the process exits, yielding its exit
//! code) and a `terminator` closure (kills it). [`ExecSandboxProcess`] wraps the
//! non-null pipe handles as owned readers/writers and runs the `waiter` on a
//! background thread so exit can be observed both blockingly (via
//! [`wait`](SandboxProcess::wait)) and non-blockingly (via
//! [`try_wait`](SandboxProcess::try_wait)).
//!
//! # Pipe-handle ownership
//!
//! Unlike the run-to-completion relay ([`relay_exec_to_stdio`]), which never
//! touches the pipe fields, this adapter **takes ownership** of any non-null
//! pipe handle in the [`ExecHandle`] and closes it when the corresponding
//! stream is dropped. A backend that returns real pipe handles for streaming
//! must therefore hand them to this adapter (not also close them itself). The
//! only in-tree state-aware backend today (IsolationSession) relays internally
//! and returns null pipe handles, so its streams are simply absent here.
//!
//! [`relay_exec_to_stdio`]: crate::state_aware_dispatch

use std::io::{Read, Write};
use std::thread::JoinHandle;

use crate::mxc_error::MxcError;
use crate::sandbox_process::SandboxProcess;
use crate::state_aware_backend::{ExecHandle, PipeHandle};

/// A streaming [`SandboxProcess`] backed by a state-aware [`ExecHandle`].
pub struct ExecSandboxProcess {
    stdout: Option<Box<dyn Read + Send>>,
    stderr: Option<Box<dyn Read + Send>>,
    stdin: Option<Box<dyn Write + Send>>,
    /// The background thread running the handle's `waiter`. Taken and joined by
    /// the first [`wait`](SandboxProcess::wait) / successful
    /// [`try_wait`](SandboxProcess::try_wait).
    waiter: Option<JoinHandle<Result<i32, MxcError>>>,
    /// Kills the process tree. Taken by the first [`kill`](SandboxProcess::kill)
    /// or by `Drop`.
    terminator: Option<Box<dyn FnOnce() + Send>>,
    /// Cached exit code once the waiter has been joined, so repeat waits are
    /// idempotent.
    exit: Option<i32>,
}

impl ExecSandboxProcess {
    /// Wrap an [`ExecHandle`] as a streaming process handle. Spawns a background
    /// thread to run the handle's `waiter` so exit can be polled.
    pub fn from_exec_handle(handle: ExecHandle) -> Self {
        let ExecHandle {
            stdout,
            stderr,
            stdin,
            waiter,
            terminator,
        } = handle;

        let waiter_thread = std::thread::spawn(waiter);

        Self {
            stdout: wrap_read(stdout),
            stderr: wrap_read(stderr),
            stdin: wrap_write(stdin),
            waiter: Some(waiter_thread),
            terminator: Some(terminator),
            exit: None,
        }
    }

    /// Join the waiter thread, caching and returning its exit code.
    fn join_waiter(&mut self) -> std::io::Result<i32> {
        if let Some(code) = self.exit {
            return Ok(code);
        }
        let handle = self
            .waiter
            .take()
            .ok_or_else(|| std::io::Error::other("exec waiter already consumed"))?;
        let code = handle
            .join()
            .map_err(|_| std::io::Error::other("exec waiter thread panicked"))?
            .map_err(|e: MxcError| std::io::Error::other(e.message))?;
        self.exit = Some(code);
        Ok(code)
    }
}

impl SandboxProcess for ExecSandboxProcess {
    fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>> {
        self.stdin.take()
    }

    fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
        self.stdout.take()
    }

    fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>> {
        self.stderr.take()
    }

    fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
        if let Some(code) = self.exit {
            return Ok(Some(code));
        }
        match &self.waiter {
            Some(handle) if handle.is_finished() => self.join_waiter().map(Some),
            Some(_) => Ok(None),
            None => Ok(self.exit),
        }
    }

    fn id(&self) -> u32 {
        // An ExecHandle does not carry the agent process id; the state-aware
        // backend owns the process lifecycle behind its `waiter`/`terminator`.
        0
    }

    fn kill(&mut self) -> std::io::Result<()> {
        if let Some(terminator) = self.terminator.take() {
            terminator();
        }
        Ok(())
    }

    fn wait(&mut self) -> std::io::Result<i32> {
        self.join_waiter()
    }
}

impl Drop for ExecSandboxProcess {
    fn drop(&mut self) {
        // Kill the process (if not already) so the waiter thread cannot block
        // forever, then join it to avoid detaching a thread that borrows the
        // backend's process object.
        if let Some(terminator) = self.terminator.take() {
            terminator();
        }
        if let Some(handle) = self.waiter.take() {
            let _ = handle.join();
        }
    }
}

// ---------------------------------------------------------------------------
// Platform pipe-handle → std stream wrapping
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn wrap_read(handle: PipeHandle) -> Option<Box<dyn Read + Send>> {
    use std::os::windows::io::FromRawHandle;
    if handle.0.is_null() {
        return None;
    }
    // SAFETY: a non-null exec pipe handle is a valid readable pipe whose
    // ownership this adapter assumes (see the module-level ownership note).
    let file = unsafe { std::fs::File::from_raw_handle(handle.0 as _) };
    Some(Box::new(file))
}

#[cfg(target_os = "windows")]
fn wrap_write(handle: PipeHandle) -> Option<Box<dyn Write + Send>> {
    use std::os::windows::io::FromRawHandle;
    if handle.0.is_null() {
        return None;
    }
    // SAFETY: a non-null exec pipe handle is a valid writable pipe whose
    // ownership this adapter assumes (see the module-level ownership note).
    let file = unsafe { std::fs::File::from_raw_handle(handle.0 as _) };
    Some(Box::new(file))
}

#[cfg(not(target_os = "windows"))]
fn wrap_read(handle: PipeHandle) -> Option<Box<dyn Read + Send>> {
    use std::os::unix::io::FromRawFd;
    if handle < 0 {
        return None;
    }
    // SAFETY: a non-negative exec pipe fd is a valid readable pipe whose
    // ownership this adapter assumes (see the module-level ownership note).
    let file = unsafe { std::fs::File::from_raw_fd(handle) };
    Some(Box::new(file))
}

#[cfg(not(target_os = "windows"))]
fn wrap_write(handle: PipeHandle) -> Option<Box<dyn Write + Send>> {
    use std::os::unix::io::FromRawFd;
    if handle < 0 {
        return None;
    }
    // SAFETY: a non-negative exec pipe fd is a valid writable pipe whose
    // ownership this adapter assumes (see the module-level ownership note).
    let file = unsafe { std::fs::File::from_raw_fd(handle) };
    Some(Box::new(file))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_aware_backend::null_pipe_handle;
    use std::sync::mpsc;

    /// An ExecHandle with null pipes (the IsolationSession shape) exposes no
    /// streams and yields the waiter's exit code.
    #[test]
    fn null_pipes_expose_no_streams_and_return_exit_code() {
        let handle = ExecHandle {
            stdout: null_pipe_handle(),
            stderr: null_pipe_handle(),
            stdin: null_pipe_handle(),
            waiter: Box::new(|| Ok(7)),
            terminator: Box::new(|| {}),
        };
        let mut proc = ExecSandboxProcess::from_exec_handle(handle);
        assert!(proc.take_stdout().is_none());
        assert!(proc.take_stderr().is_none());
        assert!(proc.take_stdin().is_none());
        assert_eq!(proc.id(), 0);
        assert_eq!(proc.wait().unwrap(), 7);
        // Idempotent.
        assert_eq!(proc.wait().unwrap(), 7);
        assert_eq!(proc.try_wait().unwrap(), Some(7));
    }

    /// `kill` invokes the terminator exactly once.
    #[test]
    fn kill_invokes_terminator_once() {
        let (tx, rx) = mpsc::channel();
        let handle = ExecHandle {
            stdout: null_pipe_handle(),
            stderr: null_pipe_handle(),
            stdin: null_pipe_handle(),
            // Block the waiter until killed, so kill drives the outcome.
            waiter: Box::new(|| Ok(0)),
            terminator: Box::new(move || {
                let _ = tx.send(());
            }),
        };
        let mut proc = ExecSandboxProcess::from_exec_handle(handle);
        proc.kill().unwrap();
        proc.kill().unwrap(); // second kill is a no-op
                              // Exactly one terminator signal.
        assert!(rx.recv().is_ok());
        assert!(rx.try_recv().is_err());
    }
}
