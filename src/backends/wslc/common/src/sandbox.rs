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
//!   forwards to an in-memory stream per handle (see [`crate::stream_buffer`]);
//!   the caller reads the other end.
//! - **stdin** — the WSLC SDK exposes no process-input API, so
//!   [`take_stdin`](SandboxProcess::take_stdin) always returns `None`.
//! - **[`id`](SandboxProcess::id)** — the process lives inside the WSL VM and
//!   has no host process id, so this is always `0`.

use std::io::{Read, Write};

use wxc_common::logger::{Logger, Mode};
use wxc_common::models::{ExecutionRequest, ScriptResponse};
use wxc_common::sandbox_process::{
    boxed_closer, cancel_and_join_discard, spawn_discard, take_boxed_read, SandboxBackend,
    SandboxProcess, StdioMode, StreamCloser,
};
use wxc_common::validator::validate_common;

use crate::stream_buffer::{StreamCanceller, StreamReader};
use crate::wsl_container_runner::{OutputMode, StartedContainer, WSLContainerRunner};
use crate::wslc_bindings::WslcSignal;

impl SandboxBackend for WSLContainerRunner {
    fn spawn(
        &mut self,
        request: &ExecutionRequest,
        logger: &mut Logger,
        stdio: StdioMode,
    ) -> Result<Box<dyn SandboxProcess>, ScriptResponse> {
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
        let started = unsafe { self.start_container(request, logger, OutputMode::Stream(stdio)) }?;
        Ok(Box::new(WslcSandboxProcess::new(started)))
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

/// A running WSL container's init process.
struct WslcSandboxProcess {
    started: StartedContainer,
    stdout: Option<StreamReader>,
    stderr: Option<StreamReader>,
    stdout_canceller: Option<StreamCanceller>,
    stderr_canceller: Option<StreamCanceller>,
    /// Exit code cached by the first successful wait, so repeat waits are
    /// idempotent (and don't re-run teardown).
    exit: Option<i32>,
    /// Set once the first wait timed out, so repeat waits keep reporting the
    /// timeout instead of re-waiting on an already-destroyed container.
    timed_out: bool,
    /// Set once the container has been torn down, so `Drop` doesn't repeat it.
    /// Tracked separately from `exit`: a caller that only ever polls
    /// [`try_wait`](SandboxProcess::try_wait) learns the exit code without any
    /// teardown having run.
    torn_down: bool,
    /// Diagnostics from the SDK calls this handle makes after the spawn
    /// returned. The streaming contract has nowhere to flush them — the spawn
    /// itself already logged through the caller's logger — so they are
    /// buffered and dropped with the handle.
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
// apartment-less thread. Every entry point that calls the SDK
// (`StartedContainer`'s `wait_for_exit` / `destroy` / `stop` / `exit_code`)
// therefore joins the MTA for the duration via `ComApartment`, mirroring
// `appcontainer_common`'s guard. No apartment state or interface pointer is
// cached across calls, so setup and teardown may run on different threads.
//
// The handle is *moved* between threads, never shared (`Sync` is deliberately
// not claimed), so at most one thread calls into the SDK at a time.
unsafe impl Send for WslcSandboxProcess {}

impl WslcSandboxProcess {
    fn new(mut started: StartedContainer) -> Self {
        let pipes = started.pipes.take();
        let (stdout, stderr) = match pipes {
            Some(pipes) => (Some(pipes.stdout), Some(pipes.stderr)),
            None => (None, None),
        };
        Self {
            stdout_canceller: stdout.as_ref().map(|r| r.canceller()),
            stderr_canceller: stderr.as_ref().map(|r| r.canceller()),
            stdout,
            stderr,
            started,
            exit: None,
            timed_out: false,
            torn_down: false,
            logger: Logger::new(Mode::Buffer),
        }
    }
}

impl SandboxProcess for WslcSandboxProcess {
    /// Always `None`: the WSLC SDK has no API to write to a container process's
    /// stdin.
    fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>> {
        None
    }

    fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
        take_boxed_read(&mut self.stdout)
    }

    fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>> {
        take_boxed_read(&mut self.stderr)
    }

    fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
        // A cached code means `wait` already ran the full teardown; reuse it.
        if let Some(code) = self.exit {
            return Ok(Some(code));
        }
        if !self.started.has_exited() {
            return Ok(None);
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
        self.started
            .stop(WslcSignal::SigKill, 0)
            .map_err(std::io::Error::other)
    }

    fn wait(&mut self) -> std::io::Result<i32> {
        // A prior timeout is checked first so it stays sticky: `wait` must keep
        // reporting `TimedOut` rather than a later-observed exit code.
        if self.timed_out {
            return Err(timeout_error(self.started.timeout_ms));
        }
        if let Some(code) = self.exit {
            return Ok(code);
        }

        // Drain the streams the caller did not take, concurrently with the
        // wait, so unread output can't accumulate for the life of the process
        // (see the trait's pipe-deadlock contract — here the buffer is
        // in-memory and unbounded, so the cost of not draining is memory rather
        // than a stalled child). A stream the caller *did* take is left alone.
        let stdout_drain = spawn_discard(self.stdout.take());
        let stderr_drain = spawn_discard(self.stderr.take());

        let waited = self.started.wait_for_exit(&mut self.logger);

        // The process is gone (or was killed): close the SDK-side write ends so
        // every reader — ours and the caller's — sees EOF once it has consumed
        // what was already buffered.
        self.started.close_streams();
        // Only cancel a read *we* own; a caller-taken stream may still be being
        // read, and cancelling it would truncate their output.
        cancel_and_join_discard(stdout_drain, &self.stdout_canceller);
        cancel_and_join_discard(stderr_drain, &self.stderr_canceller);

        let (exit_code, timed_out) = waited.map_err(|response| {
            std::io::Error::other(if response.error_message.is_empty() {
                "waiting for the WSL container process failed".to_string()
            } else {
                response.error_message
            })
        })?;

        self.started.destroy(&mut self.logger);
        self.torn_down = true;

        if timed_out {
            self.timed_out = true;
            return Err(timeout_error(self.started.timeout_ms));
        }
        self.exit = Some(exit_code);
        Ok(exit_code)
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
        // Harmless once the process has already exited: the container is simply
        // signalled again before being deleted.
        let _ = self.started.stop(WslcSignal::SigKill, 0);
        self.started.close_streams();
        // Releasing the SDK handles and unloading `wslcsdk.dll` is only safe
        // once the SDK has stopped calling back into us, which it guarantees
        // from the exit callback onwards. `wait_for_exit` establishes that on
        // the normal path; do the same here rather than tearing down under a
        // possibly-live callback.
        self.started.wait_for_exit_callback();
        let mut logger = Logger::new(Mode::Buffer);
        self.started.destroy(&mut logger);
    }
}
