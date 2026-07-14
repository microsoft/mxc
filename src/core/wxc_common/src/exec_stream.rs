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
//! [`ExecHandle`]'s contract is that pipe-handle ownership stays with the
//! backend's underlying process object. So this adapter does **not** take the
//! raw handles: it **duplicates** each non-null pipe handle
//! ([`try_clone_to_owned`]) and wraps the *duplicate* as an owned reader/writer.
//! The adapter closes only its duplicates on drop; the backend's originals (and
//! its `waiter`/`terminator`, which may also reference them) are untouched — so
//! there is no double-close even for a backend that keeps and closes its own
//! pipe ends. The only in-tree state-aware backend today (IsolationSession)
//! relays internally and returns null pipe handles, so its streams are simply
//! absent here.
//!
//! [`try_clone_to_owned`]: std::os::windows::io::BorrowedHandle::try_clone_to_owned

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
    dup_handle_to_file(handle).map(|f| Box::new(f) as Box<dyn Read + Send>)
}

#[cfg(target_os = "windows")]
fn wrap_write(handle: PipeHandle) -> Option<Box<dyn Write + Send>> {
    dup_handle_to_file(handle).map(|f| Box::new(f) as Box<dyn Write + Send>)
}

/// Duplicate a non-null Windows pipe `HANDLE` into an owned [`File`], leaving
/// the caller's original handle untouched. Returns `None` for a null handle or
/// if duplication fails.
#[cfg(target_os = "windows")]
fn dup_handle_to_file(handle: PipeHandle) -> Option<std::fs::File> {
    use std::os::windows::io::BorrowedHandle;
    if handle.0.is_null() {
        return None;
    }
    // SAFETY: a non-null exec pipe handle is valid for the borrow; we only
    // duplicate it (DuplicateHandle) and never take ownership of the original.
    let borrowed = unsafe { BorrowedHandle::borrow_raw(handle.0 as _) };
    borrowed.try_clone_to_owned().ok().map(std::fs::File::from)
}

#[cfg(not(target_os = "windows"))]
fn wrap_read(handle: PipeHandle) -> Option<Box<dyn Read + Send>> {
    dup_fd_to_file(handle).map(|f| Box::new(f) as Box<dyn Read + Send>)
}

#[cfg(not(target_os = "windows"))]
fn wrap_write(handle: PipeHandle) -> Option<Box<dyn Write + Send>> {
    dup_fd_to_file(handle).map(|f| Box::new(f) as Box<dyn Write + Send>)
}

/// Duplicate a non-negative pipe fd into an owned [`File`] (via `dup`), leaving
/// the caller's original fd untouched. Returns `None` for an invalid fd or if
/// duplication fails.
#[cfg(not(target_os = "windows"))]
fn dup_fd_to_file(handle: PipeHandle) -> Option<std::fs::File> {
    use std::os::fd::BorrowedFd;
    if handle < 0 {
        return None;
    }
    // SAFETY: a non-negative exec pipe fd is valid for the borrow; we only
    // duplicate it (dup) and never take ownership of the original.
    let borrowed = unsafe { BorrowedFd::borrow_raw(handle) };
    borrowed.try_clone_to_owned().ok().map(std::fs::File::from)
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

    // Build a PipeHandle from a live pipe end's raw handle/fd (the adapter
    // duplicates it, so the original stays owned by the test).
    #[cfg(target_os = "windows")]
    fn reader_handle(r: &std::io::PipeReader) -> PipeHandle {
        use std::os::windows::io::AsRawHandle;
        windows::Win32::Foundation::HANDLE(r.as_raw_handle() as _)
    }
    #[cfg(target_os = "windows")]
    fn writer_handle(w: &std::io::PipeWriter) -> PipeHandle {
        use std::os::windows::io::AsRawHandle;
        windows::Win32::Foundation::HANDLE(w.as_raw_handle() as _)
    }
    #[cfg(not(target_os = "windows"))]
    fn reader_handle(r: &std::io::PipeReader) -> PipeHandle {
        use std::os::fd::AsRawFd;
        r.as_raw_fd()
    }
    #[cfg(not(target_os = "windows"))]
    fn writer_handle(w: &std::io::PipeWriter) -> PipeHandle {
        use std::os::fd::AsRawFd;
        w.as_raw_fd()
    }

    /// A real stdout pipe is streamed through the adapter: the adapter reads a
    /// *duplicate*, so the caller's original handle is unaffected and there is
    /// no double-close.
    #[test]
    fn real_stdout_pipe_is_streamed_via_duplicate() {
        use std::io::{Read, Write};

        let (reader, mut writer) = std::io::pipe().expect("pipe");
        writer.write_all(b"exec-stream-ok").unwrap();
        drop(writer); // close the write end so the reader sees EOF

        let handle = ExecHandle {
            stdout: reader_handle(&reader),
            stderr: null_pipe_handle(),
            stdin: null_pipe_handle(),
            waiter: Box::new(|| Ok(0)),
            terminator: Box::new(|| {}),
        };
        let mut proc = ExecSandboxProcess::from_exec_handle(handle);
        // The adapter duplicated the handle; the test's original can now drop.
        drop(reader);

        let mut out = proc.take_stdout().expect("stdout should be present");
        let mut buf = String::new();
        out.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "exec-stream-ok");
        assert_eq!(proc.wait().unwrap(), 0);
    }

    /// A real stdin pipe is fed through the adapter's writer (a duplicate).
    #[test]
    fn real_stdin_pipe_accepts_writes_via_duplicate() {
        use std::io::{Read, Write};

        let (mut reader, writer) = std::io::pipe().expect("pipe");

        let handle = ExecHandle {
            stdout: null_pipe_handle(),
            stderr: null_pipe_handle(),
            stdin: writer_handle(&writer),
            waiter: Box::new(|| Ok(0)),
            terminator: Box::new(|| {}),
        };
        let mut proc = ExecSandboxProcess::from_exec_handle(handle);
        drop(writer); // original write end closed; adapter owns a duplicate

        {
            let mut stdin = proc.take_stdin().expect("stdin should be present");
            stdin.write_all(b"fed-via-adapter").unwrap();
            stdin.flush().unwrap();
        } // drop the adapter's writer -> EOF on the read end

        let mut buf = String::new();
        reader.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "fed-via-adapter");
        assert_eq!(proc.wait().unwrap(), 0);
    }
}
