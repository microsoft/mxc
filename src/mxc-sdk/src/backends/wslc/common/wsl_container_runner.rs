// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! WSL Container runner — implements `ScriptRunner` for the WSLC SDK backend.
//!
//! Orchestrates the full lifecycle:
//! `WslcGetMissingComponents → Session → Image check → Process settings → Container → Start →
//!  I/O capture → Exit code → ScriptResponse`
//!
//! RAII guards ensure cleanup even on error paths.
//!
//! [`start_container`](WSLContainerRunner::start_container) owns everything up
//! to and including "container started, init process in hand" and is shared by
//! both execution models: the run-to-completion [`ScriptRunner`] here, and the
//! streaming [`SandboxBackend`](crate::mxc_common::sandbox_process::SandboxBackend) in
//! [`crate::sandbox`]. They differ only in where the SDK's I/O callbacks send
//! their bytes — see [`IoSink`].

use std::ffi::c_void;
use std::fmt::Write;
use std::io::Read;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use crate::mxc_common::logger::{Logger, Mode};
use crate::mxc_common::models::{ExecutionRequest, ScriptResponse, WslcConfig};
use crate::mxc_common::mxc_error::MxcError;
use crate::mxc_common::sandbox_process::StdioMode;
use crate::mxc_common::script_runner::ScriptRunner;
use crate::mxc_common::string_util::{to_wide, CoTaskMemPWSTR};
use crate::mxc_common::validator::validate_network_policy_support;

use crate::wslc_common::container_steps::{self, sdk_error};
use crate::wslc_common::error::WslcError;
use crate::wslc_common::image;
use crate::wslc_common::policy;
use crate::wslc_common::policy_mapping;
use crate::wslc_common::process_env;
use crate::wslc_common::sdk_init;
use crate::wslc_common::stream_buffer::{stream_pair, StreamReader, StreamWriter};
use crate::wslc_common::wslc_bindings::*;

/// Where the bytes the WSLC SDK hands us in its stdout/stderr callbacks go.
///
/// The WSLC SDK never exposes the container's pipe ends — it pushes output to
/// registered callbacks — so this is the one place the two execution models
/// diverge: run-to-completion accumulates the bytes for the `ScriptResponse`,
/// streaming hands them to the caller's live reader (or to the host's stdio).
enum IoSink {
    /// Accumulate in memory for [`WSLContainerRunner::collect_output`].
    Buffer(Mutex<Vec<u8>>),
    /// Hand to a reader: either the caller's ([`StdioMode::Pipes`]) or an
    /// [`inherit_pump`] forwarding to the host's stdio ([`StdioMode::Inherit`]).
    Stream(StreamWriter),
}

impl IoSink {
    /// Forward one callback chunk.
    ///
    /// This runs on an SDK callback thread, and that same thread delivers the
    /// process-exit callback teardown waits for, so a sink must not stall it:
    /// both sinks only take a short-lived lock, never OS I/O. That is why the
    /// host-stdio (`Inherit`) case is *also* a `Stream` — writing straight
    /// through to `stdout` here would block this thread whenever the host's
    /// pipe is full, and the exit callback would then never arrive. A
    /// [`inherit_pump`] thread does that blocking write instead.
    fn write(&self, bytes: &[u8]) {
        match self {
            IoSink::Buffer(buffer) => lock(buffer).extend_from_slice(bytes),
            IoSink::Stream(writer) => writer.write(bytes),
        }
    }

    /// End the stream so a reader sees EOF once it has drained what is
    /// buffered. Idempotent, and a no-op for the buffer sink.
    fn close(&self) {
        if let IoSink::Stream(writer) = self {
            writer.close();
        }
    }

    /// The bytes captured so far, lossily decoded. Always empty for the
    /// streaming sink — the caller (or the pump) consumed those bytes live.
    fn captured(&self) -> String {
        match self {
            IoSink::Buffer(buffer) => String::from_utf8_lossy(&lock(buffer)).to_string(),
            IoSink::Stream(_) => String::new(),
        }
    }
}

/// Drain `reader` to one of the host's own streams until EOF, on a thread of
/// its own.
///
/// [`StdioMode::Inherit`] means "the sandboxed process writes the host's
/// stdout/stderr", and those are blocking handles: whoever writes them stalls
/// whenever the host stops draining its end. Doing that on the SDK's callback
/// thread would stall the process-exit callback with it — deadlocking teardown
/// against a pipe only the host can drain — so the blocking write happens here,
/// where stalling costs nothing but this thread. Teardown joins these after the
/// container is settled, so a slow host delays only the final flush.
///
/// Write errors end the pump: a host stream that has gone away (a closed pipe)
/// cannot recover, and there is nowhere to report it from — the same reason the
/// callback path drops them.
fn inherit_pump(mut reader: StreamReader, host: HostStream) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        // Locked per chunk rather than for the whole pump: the host's stdio is
        // shared (the logger writes it too), so holding the lock for the life
        // of the container would block everything else on the host.
        pump(&mut reader, |bytes| match host {
            HostStream::Stdout => write_through(std::io::stdout().lock(), bytes),
            HostStream::Stderr => write_through(std::io::stderr().lock(), bytes),
        })
    })
}

/// Drain `reader` into `write_chunk` until the stream ends.
///
/// Split out from [`inherit_pump`] so the loop can be driven against a sink a
/// test controls — in particular one that blocks, which is the case that must
/// not reach an SDK callback thread.
fn pump(reader: &mut StreamReader, mut write_chunk: impl FnMut(&[u8]) -> std::io::Result<()>) {
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf) {
            // EOF, or a stream that cannot be read again: either way, done.
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if write_chunk(&buf[..n]).is_err() {
                    return;
                }
            }
        }
    }
}

/// Which host stream an [`inherit_pump`] drains into.
#[derive(Clone, Copy)]
enum HostStream {
    Stdout,
    Stderr,
}

/// Write one chunk straight through to a host stream, flushing it so output
/// appears as the container produces it.
fn write_through(mut sink: impl std::io::Write, bytes: &[u8]) -> std::io::Result<()> {
    sink.write_all(bytes)?;
    sink.flush()
}

/// How long to wait for the SDK's exit callback, which is what guarantees all
/// output has been flushed and no further callback can arrive. Bounded so a
/// misbehaving runtime can't park teardown forever.
const EXIT_CALLBACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// VM/session boot budget, in milliseconds. This is the deadline for bringing
/// the WSL session up, and is deliberately independent of the per-command
/// `scriptTimeout` (the command runtime deadline is enforced separately at the
/// wait, see [`wait_timeout_ms`]). A short `scriptTimeout` must not be able to
/// abort a cold VM boot.
const SESSION_BOOT_TIMEOUT_MS: u32 = 180_000;

/// How long to wait for an abandoned pull before giving up on its session.
const PULL_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Lock a mutex, tolerating poisoning: every mutex here guards plain output
/// state with no invariant a panicking writer could break.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// Callback context: where each stream's bytes go, plus the process-exit
/// signal the SDK fires once all I/O has been flushed.
struct IoContext {
    stdout: IoSink,
    stderr: IoSink,
    exited: (Mutex<bool>, Condvar),
}

/// How a started container's output is delivered.
#[derive(Clone, Copy)]
pub(crate) enum OutputMode {
    /// Capture in memory, returned in the `ScriptResponse` (run-to-completion).
    Capture,
    /// Stream: hand the caller live pipes ([`StdioMode::Pipes`]) or write
    /// through to the host's own stdio ([`StdioMode::Inherit`]).
    Stream(StdioMode),
}

impl IoContext {
    /// Build the context for `mode`, along with whatever else that mode needs
    /// wired up (see [`IoWiring`]).
    fn new(mode: OutputMode) -> (Self, IoWiring) {
        let (stdout, stderr, wiring) = match mode {
            OutputMode::Capture => (
                IoSink::Buffer(Mutex::new(Vec::new())),
                IoSink::Buffer(Mutex::new(Vec::new())),
                IoWiring::default(),
            ),
            // Inherit is a `Stream` too, drained by a pump thread rather than
            // by the caller — see `inherit_pump` for why the SDK's callback
            // thread must not write the host's stdio itself.
            OutputMode::Stream(StdioMode::Inherit) => {
                let (stdout_writer, stdout_reader) = stream_pair();
                let (stderr_writer, stderr_reader) = stream_pair();
                (
                    IoSink::Stream(stdout_writer),
                    IoSink::Stream(stderr_writer),
                    IoWiring {
                        pipes: None,
                        pumps: vec![
                            inherit_pump(stdout_reader, HostStream::Stdout),
                            inherit_pump(stderr_reader, HostStream::Stderr),
                        ],
                    },
                )
            }
            OutputMode::Stream(StdioMode::Pipes) => {
                let (stdout_writer, stdout_reader) = stream_pair();
                let (stderr_writer, stderr_reader) = stream_pair();
                (
                    IoSink::Stream(stdout_writer),
                    IoSink::Stream(stderr_writer),
                    IoWiring {
                        pipes: Some(StreamPipes {
                            stdout: stdout_reader,
                            stderr: stderr_reader,
                        }),
                        pumps: Vec::new(),
                    },
                )
            }
            OutputMode::Stream(StdioMode::Pty(_)) => {
                unreachable!("PTY mode is rejected before WSLC I/O setup")
            }
        };
        (
            Self {
                stdout,
                stderr,
                exited: (Mutex::new(false), Condvar::new()),
            },
            wiring,
        )
    }

    /// Close both streaming sinks, EOF-ing any reader the caller holds.
    /// Idempotent — the exit callback normally gets there first.
    fn close_streams(&self) {
        self.stdout.close();
        self.stderr.close();
    }

    /// Block until the SDK's exit callback has fired, up to
    /// [`EXIT_CALLBACK_TIMEOUT`]. Returns whether it fired.
    ///
    /// The predicate loop is load-bearing, not ceremony: a condvar wakeup may be
    /// spurious, and callers treat `false` as "the SDK is done calling back" —
    /// closing the streams (truncating output still being flushed) and releasing
    /// the SDK handles.
    fn wait_for_exit_callback(&self) -> bool {
        let (mutex, cvar) = &self.exited;
        let exited = mutex.lock().unwrap_or_else(|e| e.into_inner());
        let (exited, _) = cvar
            .wait_timeout_while(exited, EXIT_CALLBACK_TIMEOUT, |exited| !*exited)
            .unwrap_or_else(|e| e.into_inner());
        *exited
    }
}

/// Wait for the SDK's exit callback on `io_ctx`, and if it never fires, make the
/// callback context immortal.
///
/// The exit callback is the SDK's only signal that it has stopped invoking
/// `io_callback` / `exit_callback`, both of which dereference the
/// `Arc<IoContext>` handed over as a raw pointer. When the wait times out that
/// guarantee never held, yet the caller is about to release everything — so a
/// delayed callback would read freed memory. Leaking one `Arc` reference keeps
/// the context alive for the life of the process, which is a bounded cost and
/// strictly preferable to a use-after-free on a pathological shutdown.
/// (`wslcsdk.dll` itself is never unloaded, for the same reason — see
/// `WslcSdk::load`.)
///
/// Returns whether the callback was observed.
fn await_callbacks_quiesced(io_ctx: &Arc<IoContext>) -> bool {
    if io_ctx.wait_for_exit_callback() {
        return true;
    }
    std::mem::forget(Arc::clone(io_ctx));
    false
}

/// How a wait ended — and, when the deadline fired, whether the SDK could be
/// made to *prove* the process is gone.
///
/// A timeout stop is only ever a request: `WslcStopContainer`'s HRESULT says
/// the call was accepted, not that the process died. The SDK's exit callback is
/// the only positive proof, so "timed out" and "timed out and was terminated"
/// are deliberately different answers — reporting the second when only the
/// first holds is how a caller ends up believing sandboxed code was killed
/// while it is still running.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum WaitOutcome {
    /// The process exited on its own, within the deadline.
    Exited,
    /// The deadline elapsed and the exit callback confirmed the process is gone.
    TimedOutTerminated,
    /// The deadline elapsed and the exit callback never arrived, even after the
    /// `SIGKILL` escalation: the container may still be running.
    TimedOutUnconfirmed,
}

impl WaitOutcome {
    /// Whether the deadline fired, however it ended.
    pub(crate) fn timed_out(self) -> bool {
        !matches!(self, WaitOutcome::Exited)
    }
}

/// The caller-side read ends of a [`StdioMode::Pipes`] context.
pub(crate) struct StreamPipes {
    pub(crate) stdout: StreamReader,
    pub(crate) stderr: StreamReader,
}

/// Everything an [`IoContext`] needs alongside itself, which varies by
/// [`OutputMode`]: read ends for the caller, or pump threads for the host.
#[derive(Default)]
struct IoWiring {
    /// Caller-side read ends ([`StdioMode::Pipes`] only).
    pipes: Option<StreamPipes>,
    /// Forwarders draining to the host's stdio ([`StdioMode::Inherit`] only),
    /// joined by teardown once the streams are closed.
    pumps: Vec<std::thread::JoinHandle<()>>,
}

/// RAII guard that reclaims an Arc<IoContext> from a raw pointer on drop.
/// Prevents leaking the Arc reference count on early returns.
struct IoCtxRawGuard {
    ptr: *mut c_void,
}

impl IoCtxRawGuard {
    fn new(ptr: *mut c_void) -> Self {
        Self { ptr }
    }
}

impl Drop for IoCtxRawGuard {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: `ptr` came from `Arc::into_raw` on an `Arc<IoContext>` and
            // is reclaimed exactly once, here.
            unsafe {
                let _ = Arc::from_raw(self.ptr as *const IoContext);
            }
        }
    }
}

/// Callback invoked by the WSLC SDK for stdout/stderr data.
///
/// # Safety
/// `context` must be a valid pointer obtained from `Arc::into_raw(Arc<IoContext>)`.
/// The `Arc` is kept alive in `run_internal` via `IoCtxRawGuard` (which reclaims it
/// on drop), so the pointer remains valid for the duration of all callbacks.
/// The SDK guarantees `data` is valid for `data_size` bytes during the callback.
unsafe extern "C" fn io_callback(
    io_handle: WslcProcessIOHandle,
    data: *const BYTE,
    data_size: u32,
    context: *mut c_void,
) {
    if context.is_null() || data.is_null() || data_size == 0 {
        return;
    }
    let ctx = &*(context as *const IoContext);
    let bytes = std::slice::from_raw_parts(data, data_size as usize);
    match io_handle {
        WslcProcessIOHandle::WSLC_PROCESS_IO_HANDLE_STDOUT => ctx.stdout.write(bytes),
        WslcProcessIOHandle::WSLC_PROCESS_IO_HANDLE_STDERR => ctx.stderr.write(bytes),
        _ => {}
    }
}

/// Callback invoked when the process exits and all I/O has been flushed.
/// Per SDK docs: "Once this callback is invoked, any registered IO callbacks
/// will no longer be called." This guarantees buffers are complete — and makes
/// this the point at which a streaming caller's readers can safely be EOF'd.
///
/// # Safety
/// Same lifetime requirements as `io_callback` — `context` must be a valid
/// pointer from `Arc::into_raw(Arc<IoContext>)`, kept alive by `IoCtxRawGuard`.
unsafe extern "C" fn exit_callback(_exit_code: i32, context: *mut c_void) {
    if context.is_null() {
        return;
    }
    let ctx = &*(context as *const IoContext);
    // No further I/O callbacks can arrive, so closing the streaming pipes' write
    // ends here is what ends a caller's `read` with EOF.
    ctx.close_streams();
    let (lock, cvar) = &ctx.exited;
    let mut exited = lock.lock().unwrap_or_else(|e| e.into_inner());
    *exited = true;
    cvar.notify_all();
}

/// WSL Container script runner using the WSLC SDK.
pub struct WSLContainerRunner {
    config: WslcConfig,
}

impl WSLContainerRunner {
    pub fn new(config: &WslcConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }
}

impl ScriptRunner for WSLContainerRunner {
    /// Reject policies WSLc cannot enforce, before any container is created.
    /// Mirrors the config parser so requests reaching the engine directly
    /// (an already-built `ExecutionRequest`, bypassing the parser) fail here
    /// instead of late in `execute` on the broken in-container iptables path.
    fn validate_runner(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        reject_unsupported_lifecycle(request)?;
        policy_mapping::container_working_directory(&request.working_directory)
            .map_err(|msg| WslcError::Rejected(msg).into_response())?;
        policy::reject_ui_policy(request).map_err(as_wslc_rejection)?;
        // The shared validator returns an untagged response; retag it so its
        // rejections reach SDK callers as `policy_validation` like the checks above.
        validate_network_policy_support(request, policy::network_policy_support())
            .map_err(|resp| WslcError::Rejected(resp.error_message).into_response())?;
        policy::validate_directional_network(request).map_err(as_wslc_rejection)?;
        policy::reject_proxy_credentials_in_argv(request).map_err(as_wslc_rejection)?;
        Ok(())
    }

    fn execute(&mut self, request: &ExecutionRequest, logger: &mut Logger) -> ScriptResponse {
        unsafe { self.run_internal(request, logger) }
    }
}

/// Retag a shared [`policy`] rejection so it reaches SDK callers as
/// `policy_validation` with the same message the state-aware surface emits.
fn as_wslc_rejection(err: MxcError) -> ScriptResponse {
    WslcError::Rejected(err.message).into_response()
}

/// The first line [`WSLContainerRunner::start_container`] writes, before any
/// SDK call. Tests assert its absence to prove a rejection aborted early.
pub(crate) const START_CONTAINER_BANNER: &str = "[WSLC] Starting WSL Container runner";

/// Refuses the `lifecycle` settings the one-shot surface cannot honour.
///
/// Value-based, not presence-based: the default `destroyOnExit: true` is
/// honoured. `false` cannot be, because [`StartedContainer`] owns the
/// [`WslcSessionGuard`] whose `Drop` ends the session-scoped container either
/// way. The state-aware surface needs no counterpart — the parser rejects the
/// whole `lifecycle` section there.
fn reject_unsupported_lifecycle(request: &ExecutionRequest) -> Result<(), ScriptResponse> {
    if !request.lifecycle.destroy_on_exit {
        return Err(WslcError::Rejected(
            "WSLc: lifecycle.destroyOnExit=false is not supported by the one-shot WSLc surface. \
             The container is scoped to a session this process owns, and terminating that \
             session at the end of the run removes the container regardless of the AutoRemove \
             flag. Omit the field (or set it to true), or use the state-aware lifecycle, whose \
             daemon holds the session open across phases."
                .to_string(),
        )
        .into_response());
    }
    if request.lifecycle.preserve_policy {
        return Err(WslcError::Rejected(
            "WSLc: lifecycle.preservePolicy=true is not supported. WSLc installs no persistent \
             host-side filesystem or network enforcement — mounts and the container networking \
             mode belong to the container itself — so there is no policy to preserve past the \
             run."
                .to_string(),
        )
        .into_response());
    }
    Ok(())
}

impl WSLContainerRunner {
    /// Configure session settings and create the session.
    /// Returns the session guard (RAII).
    /// Keeps owned string data alive through session creation.
    ///
    /// # Safety
    /// `sdk` must contain valid, currently-loaded function pointers.
    /// COM must already be initialized on this thread.
    unsafe fn create_session(
        &self,
        sdk: &'static WslcSdk,
        request: &ExecutionRequest,
        logger: &mut Logger,
    ) -> Result<WslcSessionGuard, ScriptResponse> {
        let session_name: Vec<u16> = to_wide(&request.container_id);
        let storage_path_str = self.config.storage_path.clone().unwrap_or_else(|| {
            std::env::temp_dir()
                .join("mxc-wslc-sessions")
                .to_string_lossy()
                .to_string()
        });
        let storage_path_wide: Vec<u16> = to_wide(&storage_path_str);

        let mut settings = std::mem::zeroed::<WslcSessionSettings>();
        let hr = sdk.WslcInitSessionSettings(
            session_name.as_ptr(),
            storage_path_wide.as_ptr(),
            &mut settings,
        );
        if hr != S_OK {
            return Err(sdk_error("WslcInitSessionSettings failed", hr, ""));
        }

        if let Some(cpu) = self.config.cpu_count {
            let hr = sdk.WslcSetSessionSettingsCpuCount(&mut settings, cpu);
            if hr != S_OK {
                return Err(sdk_error("WslcSetSessionSettingsCpuCount failed", hr, ""));
            }
        }
        if let Some(mem_mb) = self.config.memory_mb {
            let mem_mb = match u32::try_from(mem_mb) {
                Ok(v) => v,
                Err(_) => {
                    return Err(WslcError::Rejected(format!(
                        "Invalid config: memory_mb value {} exceeds maximum {} MB",
                        mem_mb,
                        u32::MAX
                    ))
                    .into_response());
                }
            };
            let hr = sdk.WslcSetSessionSettingsMemory(&mut settings, mem_mb);
            if hr != S_OK {
                return Err(sdk_error("WslcSetSessionSettingsMemory failed", hr, ""));
            }
        }
        let hr = sdk.WslcSetSessionSettingsTimeout(&mut settings, SESSION_BOOT_TIMEOUT_MS);
        if hr != S_OK {
            return Err(sdk_error("WslcSetSessionSettingsTimeout failed", hr, ""));
        }
        if self.config.gpu {
            let hr = sdk.WslcSetSessionSettingsFeatureFlags(
                &mut settings,
                WslcSessionFeatureFlags::WSLC_SESSION_FEATURE_FLAG_ENABLE_GPU,
            );
            if hr != S_OK {
                return Err(sdk_error(
                    "WslcSetSessionSettingsFeatureFlags failed",
                    hr,
                    "",
                ));
            }
        }

        // Create session while string data is still alive
        let mut session: WslcSession = ptr::null_mut();
        let mut err_msg = CoTaskMemPWSTR::null();
        let hr = sdk.WslcCreateSession(&mut settings, &mut session, err_msg.as_mut_ptr());
        if hr != S_OK {
            let msg = err_msg.to_string_lossy();
            return Err(sdk_error("WslcCreateSession failed", hr, &msg));
        }
        let _ = writeln!(logger, "[WSLC] Session created");

        Ok(WslcSessionGuard::from_raw(
            session,
            sdk.terminate_session_fn(),
            sdk.release_session_fn(),
        ))
    }

    /// Wait for process exit with timeout enforcement.
    /// Returns (exit_code, timed_out).
    ///
    /// `wait_ms` is the deadline in milliseconds; `u32::MAX` waits forever.
    /// Shared by the run-to-completion and streaming paths.
    ///
    /// # Safety
    /// `sdk` must contain valid function pointers. `process_guard` and
    /// `container_guard` must hold live handles from this session.
    unsafe fn wait_for_process(
        sdk: &'static WslcSdk,
        process_guard: &WslcProcessGuard,
        container_guard: &WslcContainerGuard,
        io_ctx: &Arc<IoContext>,
        wait_ms: u32,
        logger: &mut Logger,
    ) -> Result<(i32, WaitOutcome), ScriptResponse> {
        let mut exit_event: HANDLE = ptr::null_mut();
        let hr = sdk.WslcGetProcessExitEvent(process_guard.as_raw(), &mut exit_event);
        if hr != S_OK {
            return Err(sdk_error("WslcGetProcessExitEvent failed", hr, ""));
        }

        let mut timed_out = false;
        // Whether the *event* said the process ended. Tracked apart from the
        // callback confirmation below because they are separate pieces of
        // evidence, and reporting an exit requires at least one of them: with
        // neither, `WslcGetProcessExitCode` happily returns `STILL_ACTIVE` for a
        // container that is very much still running.
        let mut exit_signalled = false;
        if !exit_event.is_null() {
            let wait_result = windows::Win32::System::Threading::WaitForSingleObject(
                windows::Win32::Foundation::HANDLE(exit_event),
                wait_ms,
            );
            if wait_result == windows::Win32::Foundation::WAIT_OBJECT_0 {
                exit_signalled = true;
            } else if wait_result == windows::Win32::Foundation::WAIT_TIMEOUT {
                timed_out = true;
                let _ = writeln!(
                    logger,
                    "[WSLC] Execution timeout ({}ms) reached — stopping container",
                    wait_ms
                );
                let mut err_msg = CoTaskMemPWSTR::null();
                let _ = sdk.WslcStopContainer(
                    container_guard.as_raw(),
                    WslcSignal::WSLC_SIGNAL_SIGTERM,
                    2,
                    err_msg.as_mut_ptr(),
                );
                drop(err_msg);
            } else {
                // `WAIT_FAILED`, `WAIT_ABANDONED`, or anything else: the wait
                // told us nothing about the process, so neither "exited" nor
                // "timed out" can be claimed. Fail rather than guess.
                let last_error = windows::Win32::Foundation::GetLastError();
                return Err(WslcError::Runtime(format!(
                    "waiting on the WSLC process exit event failed: WaitForSingleObject returned \
                     0x{:08X} (GetLastError 0x{:08X})",
                    wait_result.0, last_error.0
                ))
                .into_response());
            }
        }

        // Wait for exit callback to fire — guarantees all I/O is flushed, and
        // is the only proof the process is actually gone.
        let mut confirmed = await_callbacks_quiesced(io_ctx);
        if !confirmed {
            if timed_out {
                // The `SIGTERM` above was only a request, and it plainly did not
                // land: the process is still running and still producing output.
                // Escalate *before* the backstop close below, so that output is
                // not cut off from a process we are about to kill anyway.
                let _ = writeln!(
                    logger,
                    "[WSLC] Container did not stop after the timeout SIGTERM — escalating to \
                     SIGKILL"
                );
                let mut err_msg = CoTaskMemPWSTR::null();
                let _ = sdk.WslcStopContainer(
                    container_guard.as_raw(),
                    WslcSignal::WSLC_SIGNAL_SIGKILL,
                    0,
                    err_msg.as_mut_ptr(),
                );
                drop(err_msg);
            }
            // Re-checked after the escalation: only a callback that still has
            // not fired forces the context leak.
            confirmed = await_callbacks_quiesced(io_ctx);
            if !confirmed {
                let _ = writeln!(
                    logger,
                    "[WSLC] Warning: exit callback did not fire within {}s; leaking the callback \
                     context so a late callback cannot touch freed memory",
                    EXIT_CALLBACK_TIMEOUT.as_secs()
                );
            }
        }

        // Backstop for the streaming path: the exit callback normally closes the
        // pipes, but if it never fired (the warning above) a caller blocked on a
        // `read` would otherwise hang forever. No-op once already closed. Only
        // output from a process that outlived even the escalation above can be
        // cut off here, which is the lesser of the two failures.
        io_ctx.close_streams();

        let mut exit_code: i32 = -1;
        let hr = sdk.WslcGetProcessExitCode(process_guard.as_raw(), &mut exit_code);
        if hr != S_OK && !timed_out {
            return Err(sdk_error("WslcGetProcessExitCode failed", hr, ""));
        }
        let outcome = match (timed_out, confirmed) {
            // Reported only on positive evidence the process ended: the exit
            // event signalling, or the SDK's exit callback. Without either --
            // a null exit event and no callback -- `exit_code` is meaningless.
            (false, _) if exit_signalled || confirmed => {
                let _ = writeln!(logger, "[WSLC] Process exited with code {}", exit_code);
                WaitOutcome::Exited
            }
            (false, _) => {
                return Err(WslcError::Runtime(
                    "the WSLC process never reported an exit: no exit event was available and the \
                     SDK's exit callback did not fire, so the container may still be running"
                        .to_string(),
                )
                .into_response());
            }
            (true, true) => {
                let _ = writeln!(logger, "[WSLC] Process killed after timeout");
                WaitOutcome::TimedOutTerminated
            }
            // Neither the SIGTERM nor the SIGKILL above produced an exit
            // callback, so nothing here shows the process died. Callers must
            // not claim it was terminated.
            (true, false) => {
                let _ = writeln!(
                    logger,
                    "[WSLC] Warning: the container could not be confirmed terminated after the \
                     timeout"
                );
                WaitOutcome::TimedOutUnconfirmed
            }
        };

        Ok((exit_code, outcome))
    }

    /// Collect captured I/O and build the final ScriptResponse.
    fn collect_output(
        io_ctx: &IoContext,
        exit_code: i32,
        outcome: WaitOutcome,
        wait_ms: u32,
        logger: &mut Logger,
    ) -> ScriptResponse {
        let stdout = io_ctx.stdout.captured();
        let stderr = io_ctx.stderr.captured();

        if !stdout.is_empty() {
            let _ = writeln!(logger, "[WSLC] Captured {} bytes stdout", stdout.len());
        }
        if !stderr.is_empty() {
            let _ = writeln!(logger, "[WSLC] Captured {} bytes stderr", stderr.len());
        }

        ScriptResponse {
            exit_code: if outcome.timed_out() { -1 } else { exit_code },
            standard_out: stdout,
            standard_err: stderr,
            // The unconfirmed wording is not pedantry: the stop is only ever a
            // request, so claiming a termination the SDK never confirmed can
            // tell a caller their sandboxed code is dead while it is running.
            error_message: match outcome {
                WaitOutcome::Exited => String::new(),
                WaitOutcome::TimedOutTerminated => {
                    format!("Process timed out after {}ms and was terminated", wait_ms)
                }
                WaitOutcome::TimedOutUnconfirmed => format!(
                    "Process timed out after {}ms; the container could not be confirmed \
                     terminated and may still be running",
                    wait_ms
                ),
            },
            ..Default::default()
        }
    }

    /// Orchestrates the full WSLC lifecycle.
    /// Orchestrates the WSLC lifecycle up to a *started* container: preflight
    /// validation, session, image, process/container settings, start, iptables,
    /// and the init-process handle. The caller decides what happens next — wait
    /// to completion ([`Self::run_internal`]) or stream
    /// (the [`SandboxBackend`](crate::mxc_common::sandbox_process::SandboxBackend) impl
    /// in [`crate::sandbox`]).
    ///
    /// `output` selects where the SDK's output callbacks send their bytes; the
    /// caller-side read ends (if any) come back on [`StartedContainer::pipes`].
    ///
    /// Helpers handle phases that don't involve dangling-pointer risks;
    /// pointer-heavy SDK configuration stays inline to keep owned string
    /// data alive for the duration needed.
    ///
    /// # Safety
    /// Calls into the WSLC SDK via raw FFI. Owned buffers backing pointers
    /// passed to the SDK (cmdline, env, mounts, etc.) must remain alive
    /// until the SDK call that consumes them returns — every such buffer is a
    /// local of this function, and the SDK consumes them by the time
    /// `WslcCreateContainer` returns here. RAII guards (`WslcSessionGuard`,
    /// `WslcContainerGuard`, `WslcProcessGuard`, `IoCtxRawGuard`) ensure handles
    /// and reference counts are released on every exit path.
    pub(crate) unsafe fn start_container(
        &self,
        request: &ExecutionRequest,
        logger: &mut Logger,
        output: OutputMode,
    ) -> Result<StartedContainer, ScriptResponse> {
        let _ = writeln!(logger, "{START_CONTAINER_BANNER}");

        // WSLc provision-time filesystem-policy gate (D6 normalization → D3
        // delegation → denied-path overlap), shared verbatim with the
        // state-aware provision path via `policy_mapping::apply_provision_policy_gate`
        // so the two runners cannot drift. Only clone the request when
        // normalization actually tightened something; any failure is surfaced on
        // the streaming logger and returned as a `ScriptResponse` error.
        let normalized;
        let request = match policy_mapping::apply_provision_policy_gate(request, logger) {
            Ok(Some(policy)) => {
                normalized = ExecutionRequest {
                    policy,
                    ..request.clone()
                };
                &normalized
            }
            Ok(None) => request,
            Err(msg) => {
                let _ = writeln!(logger, "[WSLC] {}", msg);
                return Err(WslcError::Rejected(msg).into_response());
            }
        };

        // -- Init: COM + SDK + preflight --
        let sdk = sdk_init::init_and_load_sdk(logger)?;

        // -- Session (configure + create in one step to keep string data alive) --
        let session_guard = self.create_session(sdk, request, logger)?;

        // -- Image resolution --
        // An isolated sandbox gets no registry fetch on its behalf; the pull
        // would run on the host's network before the container exists.
        let registry = if policy::network_is_isolated(request) {
            image::RegistryAccess::Denied
        } else {
            image::RegistryAccess::Allowed
        };
        let resolved = image::resolve_image(
            sdk,
            session_guard.as_raw(),
            &self.config.image,
            self.config.image_tar_path.as_deref(),
            self.config.storage_path.as_deref(),
            registry,
            "[WSLC]",
            logger,
        );
        if let Err(e) = resolved {
            // An abandoned pull is still using this session, so releasing it
            // here would free memory the SDK holds.
            if !image::wait_for_pulls_in_flight(PULL_DRAIN_TIMEOUT) {
                std::mem::forget(session_guard);
            }
            return Err(e);
        }

        // -- Process settings --
        // String data (script_cstr, env_cstrings, _cwd_cstr) must stay alive
        // until after WslcCreateContainer, so this stays inline.
        let mut process_settings = std::mem::zeroed::<WslcProcessSettings>();
        let hr = sdk.WslcInitProcessSettings(&mut process_settings);
        if hr != S_OK {
            return Err(sdk_error("WslcInitProcessSettings failed", hr, ""));
        }

        // Register I/O callbacks to capture stdout/stderr.
        // We use Arc so the callback context stays alive even if the function
        // returns early (e.g., container creation fails after callbacks are
        // registered). The SDK may still invoke callbacks on its internal
        // threads; Arc ensures the memory isn't freed until all references
        // (including the one held by the SDK via raw pointer) are dropped.
        let (io_ctx, io_wiring) = IoContext::new(output);
        let io_ctx = Arc::new(io_ctx);
        // Give the SDK an Arc reference via raw pointer. We must reconstruct
        // the Arc later to avoid leaking the reference count.
        let io_ctx_for_sdk = Arc::clone(&io_ctx);
        let io_ctx_raw = Arc::into_raw(io_ctx_for_sdk) as *mut c_void;
        let io_ctx_guard = IoCtxRawGuard::new(io_ctx_raw);

        let callbacks = WslcProcessCallbacks {
            onStdOut: Some(io_callback),
            onStdErr: Some(io_callback),
            onExit: Some(exit_callback),
        };
        let hr = sdk.WslcSetProcessSettingsCallbacks(&mut process_settings, &callbacks, io_ctx_raw);
        if hr != S_OK {
            return Err(sdk_error("WslcSetProcessSettingsCallbacks failed", hr, ""));
        }

        // Route cooperative HTTP clients through the caller-managed proxy:
        // WSLc has no IP-level enforcement hook, so any destination filtering
        // belongs to the proxy. Inject HTTP(S)_PROXY after scrubbing caller
        // proxy variables.
        // See crate::mxc_common::proxy_env.
        let effective_env: Vec<String> = if request.policy.network_proxy.is_enabled() {
            // A directly constructed request must retain its proxy URL so the
            // guest receives a routable endpoint instead of an empty setting.
            let proxy_url = match request
                .policy
                .network_proxy
                .address
                .as_ref()
                .and_then(|addr| addr.original_url.clone())
            {
                Some(url) => url,
                None => {
                    return Err(WslcError::Rejected(
                        "WSLC: runtimeConfig.networkProxy requires a URL-backed proxy address. \
                         For directly constructed requests, use ProxyAddress::from_url so \
                         the guest can receive HTTP(S)_PROXY."
                            .to_string(),
                    )
                    .into_response());
                }
            };
            let _ = writeln!(
                logger,
                "[WSLC] Cooperative network proxy configured: {}",
                crate::mxc_common::proxy_env::redact_proxy_url(&proxy_url)
            );
            crate::mxc_common::proxy_env::apply_cooperative_proxy_env(
                request.env_entries(),
                &proxy_url,
            )
        } else {
            request.env_entries().to_vec()
        };

        // These buffers must outlive WslcCreateContainer: the SDK stores the
        // pointers into process_settings (it does not copy), and reads them at
        // container-create time. Dropping them earlier causes a use-after-free
        // (0xC0000005).
        let _command = container_steps::set_command_line_and_env(
            sdk,
            &mut process_settings,
            process_env::EnvScope::of(request),
            &effective_env,
            &request.script_code,
        )?;

        // `validate_runner` has already rejected an unmappable cwd; the `Err`
        // arm keeps this direct entry point fail-closed as well.
        let _cwd_cstr;
        match policy_mapping::container_working_directory(&request.working_directory) {
            Ok(Some(container_cwd)) => {
                _cwd_cstr = format!("{}\0", container_cwd);
                let hr = sdk.WslcSetProcessSettingsWorkingDirectory(
                    &mut process_settings,
                    _cwd_cstr.as_bytes().as_ptr() as PCSTR,
                );
                if hr != S_OK {
                    return Err(sdk_error(
                        "WslcSetProcessSettingsWorkingDirectory failed",
                        hr,
                        "",
                    ));
                }
            }
            Ok(None) => {}
            Err(msg) => return Err(WslcError::Rejected(msg).into_response()),
        }

        // -- Container settings --
        // Volume and image string data must stay alive until WslcCreateContainer.
        let image_name = &self.config.image;
        let image_cstr = format!("{}\0", image_name);
        let mut container_settings = std::mem::zeroed::<WslcContainerSettings>();
        let hr = sdk.WslcInitContainerSettings(
            image_cstr.as_bytes().as_ptr() as PCSTR,
            &mut container_settings,
        );
        if hr != S_OK {
            return Err(sdk_error("WslcInitContainerSettings failed", hr, ""));
        }

        // -- Port mappings (host<->container) --
        // Apply before networking mode so the SDK has the complete picture
        // when the container is created. Empty list = no forwarding (default).
        // The parser rejects `"udp"` up front: the C header declares
        // `WSLC_PORT_PROTOCOL_UDP = 1` but the shipped runtime returns
        // `E_NOTIMPL` when UDP is actually requested. The protocol match below
        // therefore only ever sees `"tcp"` today, but the explicit branch is
        // retained so this code keeps compiling cleanly if/when the parser
        // starts accepting UDP after an SDK update.
        // Built at function scope: these arrays must outlive
        // `WslcCreateContainer` below, which is the call that actually consumes
        // the pointers handed to `WslcSetContainerSettingsPortMappings`.
        let mappings: Vec<WslcContainerPortMapping> = self
            .config
            .port_mappings
            .iter()
            .map(|pm| WslcContainerPortMapping {
                windowsPort: pm.windows_port,
                containerPort: pm.container_port,
                protocol: if pm.protocol == "udp" {
                    WslcPortProtocol::WSLC_PORT_PROTOCOL_UDP
                } else {
                    WslcPortProtocol::WSLC_PORT_PROTOCOL_TCP
                },
                // Default bind address (typically loopback/0.0.0.0 per
                // SDK config). Not exposed in the MXC config today.
                windowsAddress: ptr::null_mut(),
            })
            .collect();
        if !mappings.is_empty() {
            let hr = sdk.WslcSetContainerSettingsPortMappings(
                &mut container_settings,
                mappings.as_ptr(),
                mappings.len() as u32,
            );
            if hr != S_OK {
                return Err(sdk_error(
                    "WslcSetContainerSettingsPortMappings failed",
                    hr,
                    "",
                ));
            }
            let _ = writeln!(
                logger,
                "[WSLC] {} port mapping(s) configured",
                mappings.len()
            );
        }
        let mounts = match policy_mapping::build_volume_mounts(
            &request.policy.readwrite_paths,
            &request.policy.readonly_paths,
        ) {
            Ok(m) => m,
            Err(e) => {
                let _ = writeln!(logger, "[WSLC] {}", e);
                return Err(WslcError::Rejected(e).into_response());
            }
        };

        // Keep owned data alive for volume pointers
        let wide_paths: Vec<(Vec<u16>, Vec<u8>)> = mounts
            .iter()
            .map(|m| {
                let win: Vec<u16> = to_wide(&m.windows_path);
                let ctr: Vec<u8> = format!("{}\0", m.container_path).into_bytes();
                (win, ctr)
            })
            .collect();

        // Built at function scope alongside `wide_paths`: these structs point
        // into `wide_paths` and must outlive `WslcCreateContainer` below.
        let volumes: Vec<WslcContainerVolume> = wide_paths
            .iter()
            .zip(mounts.iter())
            .map(|((win, ctr), m)| WslcContainerVolume {
                windowsPath: win.as_ptr(),
                containerPath: ctr.as_ptr() as PCSTR,
                readOnly: if m.read_only { 1 } else { 0 },
            })
            .collect();
        if !volumes.is_empty() {
            let hr = sdk.WslcSetContainerSettingsVolumes(
                &mut container_settings,
                volumes.as_ptr(),
                volumes.len() as u32,
            );
            if hr != S_OK {
                return Err(sdk_error("WslcSetContainerSettingsVolumes failed", hr, ""));
            }
            let _ = writeln!(
                logger,
                "[WSLC] {} volume mount(s) configured",
                volumes.len()
            );
        }

        let is_default_block = policy::network_is_isolated(request);
        let net_mode = policy_mapping::map_network_policy(is_default_block);
        let hr = sdk.WslcSetContainerSettingsNetworkingMode(&mut container_settings, net_mode);
        if hr != S_OK {
            return Err(sdk_error(
                "WslcSetContainerSettingsNetworkingMode failed",
                hr,
                "",
            ));
        }
        let _ = writeln!(logger, "[WSLC] Networking mode: {:?}", net_mode);

        let mut flags = WslcContainerFlags::WSLC_CONTAINER_FLAG_NONE;
        if request.lifecycle.destroy_on_exit {
            flags |= WslcContainerFlags::WSLC_CONTAINER_FLAG_AUTO_REMOVE;
        }
        if self.config.gpu {
            flags |= WslcContainerFlags::WSLC_CONTAINER_FLAG_ENABLE_GPU;
        }
        let hr = sdk.WslcSetContainerSettingsFlags(&mut container_settings, flags);
        if hr != S_OK {
            return Err(sdk_error("WslcSetContainerSettingsFlags failed", hr, ""));
        }

        let hr =
            sdk.WslcSetContainerSettingsInitProcess(&mut container_settings, &mut process_settings);
        if hr != S_OK {
            return Err(sdk_error(
                "WslcSetContainerSettingsInitProcess failed",
                hr,
                "",
            ));
        }

        // -- Create & start container --
        let mut container: WslcContainer = ptr::null_mut();
        let mut err_msg = CoTaskMemPWSTR::null();
        let hr = sdk.WslcCreateContainer(
            session_guard.as_raw(),
            &container_settings,
            &mut container,
            err_msg.as_mut_ptr(),
        );
        if hr != S_OK {
            let msg = err_msg.to_string_lossy();
            return Err(sdk_error("WslcCreateContainer failed", hr, &msg));
        }
        let container_guard = WslcContainerGuard::from_raw(container, sdk.release_container_fn());
        let _ = writeln!(logger, "[WSLC] Container created");

        err_msg = CoTaskMemPWSTR::null();
        let hr = sdk.WslcStartContainer(
            container_guard.as_raw(),
            WslcContainerStartFlags::WSLC_CONTAINER_START_FLAG_ATTACH,
            err_msg.as_mut_ptr(),
        );
        if hr != S_OK {
            let msg = err_msg.to_string_lossy();
            return Err(sdk_error("WslcStartContainer failed", hr, &msg));
        }
        let _ = writeln!(logger, "[WSLC] Container started");

        // From here the container is live and the SDK is delivering callbacks
        // into `io_ctx`. A bare `return Err(..)` would drop the locals in
        // reverse declaration order — freeing the callback context (`io_ctx` /
        // `io_ctx_guard`) *before* the session is terminated and the DLL
        // unloaded — so a late callback could dereference freed memory. Every
        // failure past this point therefore quiesces the container first.
        let post_start = Self::attach_init_process(sdk, &container_guard);
        let process_guard = match post_start {
            Ok(guard) => guard,
            Err(e) => {
                Self::quiesce_started_container(
                    sdk,
                    &container_guard,
                    &io_ctx,
                    request.lifecycle.destroy_on_exit,
                    logger,
                );
                return Err(e);
            }
        };

        Ok(StartedContainer {
            process_guard,
            container_guard,
            session_guard,
            io_ctx_guard,
            io_ctx,
            sdk,
            pipes: io_wiring.pipes,
            pumps: Mutex::new(io_wiring.pumps),
            settled: AtomicBool::new(false),
            destroy_on_exit: request.lifecycle.destroy_on_exit,
            timeout_ms: wait_timeout_ms(request),
        })
    }

    /// Take the container's init process handle. Split out so every failure
    /// between "container started" and "handle in hand" funnels through one
    /// caller-side cleanup path.
    ///
    /// # Safety
    /// `sdk` must hold valid function pointers and `container` a live handle.
    unsafe fn attach_init_process(
        sdk: &'static WslcSdk,
        container: &WslcContainerGuard,
    ) -> Result<WslcProcessGuard, ScriptResponse> {
        let mut process: WslcProcess = ptr::null_mut();
        let hr = sdk.WslcGetContainerInitProcess(container.as_raw(), &mut process);
        if hr != S_OK {
            return Err(sdk_error("WslcGetContainerInitProcess failed", hr, ""));
        }
        Ok(WslcProcessGuard::from_raw(
            process,
            sdk.release_process_fn(),
        ))
    }

    /// Stop a started container and block until the SDK's exit callback has
    /// fired, so no further callback can reference the context the caller is
    /// about to drop. Best-effort: every step's failure is ignored, because the
    /// caller is already unwinding a more meaningful error.
    ///
    /// # Safety
    /// `sdk` must hold valid function pointers and `container` a live handle.
    unsafe fn quiesce_started_container(
        sdk: &'static WslcSdk,
        container: &WslcContainerGuard,
        io_ctx: &Arc<IoContext>,
        destroy_on_exit: bool,
        logger: &mut Logger,
    ) {
        let mut err_msg = CoTaskMemPWSTR::null();
        let _ = sdk.WslcStopContainer(
            container.as_raw(),
            WslcSignal::WSLC_SIGNAL_SIGKILL,
            5,
            err_msg.as_mut_ptr(),
        );
        drop(err_msg);

        io_ctx.close_streams();
        if !await_callbacks_quiesced(io_ctx) {
            let _ = writeln!(
                logger,
                "[WSLC] Warning: exit callback did not fire within {}s while cleaning up a \
                 failed start; leaking the callback context",
                EXIT_CALLBACK_TIMEOUT.as_secs()
            );
        }

        if destroy_on_exit {
            let mut err_msg = CoTaskMemPWSTR::null();
            let _ = sdk.WslcDeleteContainer(
                container.as_raw(),
                WslcDeleteContainerFlags::WSLC_DELETE_CONTAINER_FLAG_FORCE,
                err_msg.as_mut_ptr(),
            );
            drop(err_msg);
        }
    }

    /// Run to completion: start the container, wait for the init process, tear
    /// it down, and return the captured output.
    ///
    /// # Safety
    /// Calls into the WSLC SDK via raw FFI — see
    /// [`start_container`](Self::start_container).
    unsafe fn run_internal(
        &self,
        request: &ExecutionRequest,
        logger: &mut Logger,
    ) -> ScriptResponse {
        let started = match self.start_container(request, logger, OutputMode::Capture) {
            Ok(started) => started,
            Err(response) => return response,
        };

        // -- Wait for exit --
        let (exit_code, outcome) = match started.wait_for_exit(logger) {
            Ok(r) => r,
            Err(e) => {
                // `wait_for_exit` can fail while the container is still running
                // (a failed apartment, or `WslcGetProcessExitEvent`). Returning
                // straight away would drop `started`, freeing the callback
                // context and unloading the DLL under live callbacks, so settle
                // the container first.
                started.quiesce(logger);
                return e;
            }
        };

        // The run-to-completion path reports through `ScriptResponse`, which is
        // built from the process's own result; a teardown failure is logged by
        // `destroy` rather than replacing that result.
        let _ = started.destroy(logger);

        Self::collect_output(
            &started.io_ctx,
            exit_code,
            outcome,
            started.timeout_ms,
            logger,
        )
    }
}

/// The wait deadline in milliseconds for `request`; `u32::MAX` means "wait
/// forever" (the request carries `0` for no timeout).
fn wait_timeout_ms(request: &ExecutionRequest) -> u32 {
    if request.script_timeout > 0 {
        request.script_timeout
    } else {
        u32::MAX
    }
}

/// A started WSLC container plus everything needed to wait on, stream, and tear
/// down its init process.
///
/// Field order is the drop order and matters: the process, container, and
/// session handles are released first, then the SDK callback context. `sdk` is
/// a borrow of the process-wide, never-unloaded instance
/// ([`WslcSdk::shared`]), so it carries no drop-order significance.
pub(crate) struct StartedContainer {
    process_guard: WslcProcessGuard,
    container_guard: WslcContainerGuard,
    /// Held for its `Drop`, which terminates and releases the WSLC session.
    #[allow(dead_code, reason = "RAII guard: terminates the session on drop")]
    session_guard: WslcSessionGuard,
    /// Held for its `Drop`, which reclaims the `Arc<IoContext>` reference handed
    /// to the SDK by raw pointer.
    #[allow(
        dead_code,
        reason = "RAII guard: reclaims the callback context on drop"
    )]
    io_ctx_guard: IoCtxRawGuard,
    io_ctx: Arc<IoContext>,
    sdk: &'static WslcSdk,
    /// Caller-side read ends, present only for [`StdioMode::Pipes`].
    pub(crate) pipes: Option<StreamPipes>,
    /// Host-stdio forwarders, present only for [`StdioMode::Inherit`]. Joined
    /// by [`join_pumps`](Self::join_pumps) once the streams are closed, so the
    /// container's last output reaches the host before teardown returns.
    /// `Mutex` only so the `&self` teardown methods can take them.
    pumps: Mutex<Vec<std::thread::JoinHandle<()>>>,
    /// Whether teardown has already run, so [`Drop`] knows not to repeat it —
    /// and, crucially, knows to *run* it when an unwind skipped it.
    settled: AtomicBool,
    /// Whether the container is stopped and deleted after the process exits.
    pub(crate) destroy_on_exit: bool,
    /// Wait deadline in milliseconds; `u32::MAX` waits forever.
    pub(crate) timeout_ms: u32,
}

impl Drop for StartedContainer {
    /// Settle a container no teardown path reached — in practice, one abandoned
    /// by a **panic** unwinding past it.
    ///
    /// Without this, unwinding drops the fields below in declaration order:
    /// the guards close the SDK handles and the `IoContext` is freed while the
    /// SDK may still be invoking callbacks that write through it. Every normal
    /// path already tears down explicitly (and marks the container settled), so
    /// this only fires when something skipped them.
    fn drop(&mut self) {
        if self.settled.load(Ordering::Acquire) {
            return;
        }
        // No error channel and no caller logger here, so the diagnostics are
        // buffered and dropped with `self`; the alternative is a use-after-free.
        let mut logger = Logger::new(Mode::Buffer);
        self.quiesce(&mut logger);
    }
}

impl StartedContainer {
    /// Wait for the init process to exit, enforcing the request's timeout
    /// (stopping the container when it fires). Returns `(exit_code, timed_out)`.
    pub(crate) fn wait_for_exit(
        &self,
        logger: &mut Logger,
    ) -> Result<(i32, WaitOutcome), ScriptResponse> {
        // The handle is `Send`, so this may run on a thread that never entered
        // the apartment `init_and_load_sdk` established; join it for the call.
        let _com = ComApartment::enter().map_err(|e| WslcError::Host(e).into_response())?;
        // SAFETY: `self` owns live process / container handles and a live SDK.
        unsafe {
            WSLContainerRunner::wait_for_process(
                self.sdk,
                &self.process_guard,
                &self.container_guard,
                &self.io_ctx,
                self.timeout_ms,
                logger,
            )
        }
    }

    /// Stop the container and block until the SDK's exit callback has fired,
    /// then tear it down — the teardown for any path that abandons a *started*
    /// container without a completed wait (an error return, or a handle dropped
    /// mid-run).
    ///
    /// The exit callback is the SDK's guarantee that no further callback will
    /// arrive, which must hold before this container's fields drop: they free
    /// the `IoContext` those callbacks write through and then unload the DLL.
    /// The happy path reaches the same guarantee via
    /// [`wait_for_exit`](Self::wait_for_exit) followed by
    /// [`destroy`](Self::destroy).
    pub(crate) fn quiesce(&self, logger: &mut Logger) {
        // Force-stop: this only runs when the run is already being abandoned,
        // so there is no `destroyOnExit: false` container left to keep alive.
        // `0` means "don't wait for a graceful stop".
        let _ = self.stop(WslcSignal::WSLC_SIGNAL_SIGKILL, 0);
        self.close_streams();
        if !await_callbacks_quiesced(&self.io_ctx) {
            let _ = writeln!(
                logger,
                "[WSLC] Warning: exit callback did not fire within {}s while abandoning a \
                 started container; leaking the callback context",
                EXIT_CALLBACK_TIMEOUT.as_secs()
            );
        }
        // Best-effort by construction: this is the last-resort path (an
        // abandoned run, or `Drop`), so there is no caller left to hand a
        // failure to. `destroy` logs it.
        let _ = self.destroy(logger);
    }

    /// Wait for the host-stdio forwarders to finish.
    ///
    /// Only [`StdioMode::Inherit`] has any, and they end as soon as their
    /// stream is closed and drained — so this is where the container's last
    /// output reaches the host. Deliberately *after* the container is settled:
    /// a host that has stopped draining its own stdout then delays only this
    /// final flush, never the SDK teardown that a callback-thread write would
    /// have stalled.
    fn join_pumps(&self) {
        for pump in lock(&self.pumps).drain(..) {
            let _ = pump.join();
        }
    }

    /// Stop and delete the container when the request asked for it. The session
    /// is terminated by `WslcSessionGuard`'s `Drop`.
    ///
    /// Returns the failure rather than swallowing it: a container that would
    /// not stop or delete still holds a VM-backed sandbox, which the streaming
    /// path turns into a retry from `Drop` instead of a silent leak.
    pub(crate) fn destroy(&self, logger: &mut Logger) -> Result<(), String> {
        // No apartment, no SDK calls — the same rule the handle guards' `Drop`
        // impls follow. Stopping the container matters (it is a live VM, not
        // just an in-process handle), but calling the SDK apartment-less is
        // precisely what the `Send` soundness argument rules out, and it would
        // most likely fail anyway. Reported so the caller learns the container
        // leaked rather than believing it was destroyed.
        let _com = match ComApartment::enter() {
            Ok(com) => com,
            Err(e) => {
                let msg =
                    format!("{e}; skipped container teardown to avoid an apartment-less SDK call");
                let _ = writeln!(logger, "[WSLC] Cleanup failed: {msg}");
                return Err(msg);
            }
        };
        let mut failure: Option<String> = None;
        if self.destroy_on_exit {
            // SAFETY: the guards hold live handles for `self`'s lifetime and
            // `sdk`'s function pointers are valid while it is alive.
            unsafe {
                let mut err_msg = CoTaskMemPWSTR::null();
                let hr = self.sdk.WslcStopContainer(
                    self.container_guard.as_raw(),
                    WslcSignal::WSLC_SIGNAL_SIGTERM,
                    10,
                    err_msg.as_mut_ptr(),
                );
                if hr != S_OK {
                    let msg = err_msg.to_string_lossy();
                    failure = Some(format!(
                        "WslcStopContainer failed: {msg} (HRESULT 0x{:08X})",
                        hr as u32
                    ));
                }
                drop(err_msg);

                // Attempted even after a failed stop: the delete is forced, so
                // it is the better chance of not leaking the container.
                let mut err_msg = CoTaskMemPWSTR::null();
                let hr = self.sdk.WslcDeleteContainer(
                    self.container_guard.as_raw(),
                    WslcDeleteContainerFlags::WSLC_DELETE_CONTAINER_FLAG_FORCE,
                    err_msg.as_mut_ptr(),
                );
                if hr != S_OK && failure.is_none() {
                    let msg = err_msg.to_string_lossy();
                    failure = Some(format!(
                        "WslcDeleteContainer failed: {msg} (HRESULT 0x{:08X})",
                        hr as u32
                    ));
                }
                drop(err_msg);
            }
        }

        // Teardown has now run, whether or not it succeeded: `Drop` must not
        // repeat the stop/delete, and the streaming path tracks a *failed*
        // teardown through its own `torn_down` flag so it can retry deliberately.
        self.settled.store(true, Ordering::Release);
        // The streams are done, so the forwarders can finish flushing to the
        // host now that the container itself is settled.
        self.close_streams();
        self.join_pumps();

        // Session termination is handled by WslcSessionGuard's Drop impl.
        match failure {
            Some(e) => {
                let _ = writeln!(logger, "[WSLC] Cleanup failed: {e}");
                Err(e)
            }
            None => {
                let _ = writeln!(logger, "[WSLC] Cleanup complete");
                Ok(())
            }
        }
    }

    /// Confirm the init process is really gone, escalating to `SIGKILL` when it
    /// is not — the teardown the timeout path owes its caller.
    ///
    /// [`wait_for_exit`](Self::wait_for_exit)'s timeout branch only *asks* the
    /// container to stop (`SIGTERM` with a two-second grace, HRESULT ignored),
    /// so reaching it proves nothing about whether the sandboxed process died.
    /// Since `SandboxProcess::wait` reporting `TimedOut` promises it was
    /// terminated, that promise is either made true here or reported as unkept.
    ///
    /// The SDK's exit callback is the only positive proof, so a kill that
    /// cannot be observed is an error rather than an assumption.
    pub(crate) fn confirm_terminated(&self, logger: &mut Logger) -> Result<(), String> {
        if self.has_exited() {
            return Ok(());
        }
        let _ = writeln!(
            logger,
            "[WSLC] Container still live after the timeout stop request; escalating to SIGKILL"
        );
        // `0`: the graceful grace period already elapsed in `wait_for_process`.
        self.stop(WslcSignal::WSLC_SIGNAL_SIGKILL, 0)?;
        if !await_callbacks_quiesced(&self.io_ctx) {
            return Err(format!(
                "the WSL container did not report its process exiting within {}s of SIGKILL, so \
                 the timed-out process cannot be confirmed terminated",
                EXIT_CALLBACK_TIMEOUT.as_secs()
            ));
        }
        Ok(())
    }

    /// Signal the container's processes, for
    /// [`SandboxProcess::kill`](crate::mxc_common::sandbox_process::SandboxProcess::kill).
    /// `timeout_secs` is how long the SDK waits for a graceful stop.
    pub(crate) fn stop(&self, signal: WslcSignal, timeout_secs: u32) -> Result<(), String> {
        let _com = ComApartment::enter()?;
        // SAFETY: as `destroy` — live container handle, live SDK.
        unsafe {
            let mut err_msg = CoTaskMemPWSTR::null();
            let hr = self.sdk.WslcStopContainer(
                self.container_guard.as_raw(),
                signal,
                timeout_secs,
                err_msg.as_mut_ptr(),
            );
            if hr != S_OK {
                let msg = err_msg.to_string_lossy();
                return Err(format!(
                    "WslcStopContainer failed: {msg} (HRESULT 0x{:08X})",
                    hr as u32
                ));
            }
        }
        Ok(())
    }

    /// Whether the SDK's exit callback has fired (the process is gone and all
    /// its output has been flushed).
    pub(crate) fn has_exited(&self) -> bool {
        *lock(&self.io_ctx.exited.0)
    }

    /// The init process's exit code. Only meaningful once
    /// [`has_exited`](Self::has_exited) is true.
    ///
    /// # Safety
    /// Requires a live process handle and SDK, which `self` owns.
    pub(crate) unsafe fn exit_code(&self) -> Result<i32, String> {
        let _com = ComApartment::enter()?;
        let mut exit_code: i32 = -1;
        let hr = self
            .sdk
            .WslcGetProcessExitCode(self.process_guard.as_raw(), &mut exit_code);
        if hr != S_OK {
            return Err(format!(
                "WslcGetProcessExitCode failed (HRESULT 0x{:08X})",
                hr as u32
            ));
        }
        Ok(exit_code)
    }

    /// EOF any streaming reader the caller still holds.
    pub(crate) fn close_streams(&self) {
        self.io_ctx.close_streams();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_rejects_denied_path_overlap_before_sdk_load() {
        // Wiring guard: a deniedPaths entry nested under a mounted parent must be
        // rejected at the pre-flight overlap check (run_internal, before SDK
        // load), so no container is ever started. The pure-function unit tests
        // in policy_mapping do not cover this call-site ordering. Uses
        // non-existent paths so D6 (Absent) and delegation (unknown) pass through
        // to the overlap check.
        let request = ExecutionRequest {
            containment: crate::mxc_common::models::ContainmentBackend::Wslc,
            policy: crate::mxc_common::models::ContainerPolicy {
                readwrite_paths: vec![r"C:\mxc-nonexistent-parent".to_string()],
                denied_paths: vec![r"C:\mxc-nonexistent-parent\secrets".to_string()],
                ..Default::default()
            },
            script_code: "echo hi".to_string(),
            ..Default::default()
        };

        let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
        let mut runner = WSLContainerRunner::new(&WslcConfig::default());
        let response = runner.execute(&request, &mut logger);

        assert_eq!(response.exit_code, -1, "overlap must fail the run");
        assert!(
            response.error_message.contains("cannot be enforced"),
            "expected the overlap error, got: {}",
            response.error_message
        );
    }

    #[test]
    fn run_rejects_denied_alias_via_junction() {
        // Tier-2 wiring guard: a deniedPaths entry that only lands inside a
        // mounted parent AFTER junction resolution must still be rejected at the
        // pre-flight overlap check. Tier 1 (lexical) cannot see this alias; tier
        // 2 canonicalizes on disk. Uses a real directory junction (no admin).
        use std::process::Command;

        let tmp = tempfile::TempDir::new().unwrap();
        let real = tmp.path().join("real");
        let secret = real.join("secret");
        std::fs::create_dir_all(&secret).unwrap();
        let link = tmp.path().join("link");

        let status = Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&link)
            .arg(&real)
            .status()
            .unwrap();
        if !status.success() {
            eprintln!("skipping run_rejects_denied_alias_via_junction: mklink /J failed");
            return;
        }

        let request = ExecutionRequest {
            containment: crate::mxc_common::models::ContainmentBackend::Wslc,
            policy: crate::mxc_common::models::ContainerPolicy {
                readwrite_paths: vec![real.to_string_lossy().into_owned()],
                denied_paths: vec![link.join("secret").to_string_lossy().into_owned()],
                ..Default::default()
            },
            script_code: "echo hi".to_string(),
            ..Default::default()
        };

        let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
        let mut runner = WSLContainerRunner::new(&WslcConfig::default());
        let response = runner.execute(&request, &mut logger);

        assert_eq!(
            response.exit_code, -1,
            "junction-aliased deny must fail the run"
        );
        assert!(
            response.error_message.contains("cannot be enforced"),
            "expected the overlap error, got: {}",
            response.error_message
        );
    }

    #[test]
    fn run_rejects_absent_denied_leaf_via_junction() {
        // Finding B: a not-yet-created deny under a junctioned mount. The leaf
        // does not exist, so tier 2 must resolve the deepest existing ancestor
        // (the junction) and re-append the missing tail before comparing.
        use std::process::Command;

        let tmp = tempfile::TempDir::new().unwrap();
        let real = tmp.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = tmp.path().join("link");

        let status = Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&link)
            .arg(&real)
            .status()
            .unwrap();
        if !status.success() {
            eprintln!("skipping run_rejects_absent_denied_leaf_via_junction: mklink /J failed");
            return;
        }

        let request = ExecutionRequest {
            containment: crate::mxc_common::models::ContainmentBackend::Wslc,
            policy: crate::mxc_common::models::ContainerPolicy {
                readwrite_paths: vec![real.to_string_lossy().into_owned()],
                // `real\newsecret` never created — only reachable via the junction.
                denied_paths: vec![link.join("newsecret").to_string_lossy().into_owned()],
                ..Default::default()
            },
            script_code: "echo hi".to_string(),
            ..Default::default()
        };

        let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
        let mut runner = WSLContainerRunner::new(&WslcConfig::default());
        let response = runner.execute(&request, &mut logger);

        assert_eq!(
            response.exit_code, -1,
            "absent junction-aliased deny must fail the run"
        );
        assert!(
            response.error_message.contains("cannot be enforced"),
            "expected the overlap error, got: {}",
            response.error_message
        );
    }

    #[test]
    fn both_surfaces_reject_directional_host_filtering() {
        let request = ExecutionRequest {
            containment: crate::mxc_common::models::ContainmentBackend::Wslc,
            policy: crate::mxc_common::models::ContainerPolicy {
                network_egress: Some(crate::mxc_common::models::NetworkEgressPolicy {
                    allow: vec![Default::default()],
                    ..Default::default()
                }),
                ..Default::default()
            },
            ..Default::default()
        };

        let one_shot = WSLContainerRunner::new(&WslcConfig::default())
            .validate_runner(&request)
            .unwrap_err();
        assert_eq!(
            one_shot.failure_phase,
            crate::mxc_common::models::FailurePhase::Rejected
        );
        assert!(one_shot.error_message.contains("network.egress"));

        let state_aware =
            crate::wslc_common::policy::validate_provision_policy(&request).unwrap_err();
        assert_eq!(
            state_aware.code,
            crate::mxc_common::mxc_error::MxcErrorCode::PolicyValidation
        );
        assert!(
            state_aware.message.contains("allow/deny rules"),
            "got: {}",
            state_aware.message
        );
    }

    #[test]
    fn validate_runner_tags_shared_validator_rejections() {
        // The shared network validator builds untagged responses; WSLc retags them
        // so callers get `policy_validation` rather than an opaque backend error.
        let mut request = ExecutionRequest {
            containment: crate::mxc_common::models::ContainmentBackend::Wslc,
            ..Default::default()
        };
        request.policy.network_egress = Some(crate::mxc_common::models::NetworkEgressPolicy {
            default: crate::mxc_common::models::NetworkAction::Allow,
            ..Default::default()
        });
        let runner = WSLContainerRunner::new(&WslcConfig::default());
        let err = runner.validate_runner(&request).unwrap_err();
        assert!(err.error_message.contains("network.egress.default"));
        assert_eq!(
            err.failure_phase,
            crate::mxc_common::models::FailurePhase::Rejected
        );
    }

    #[test]
    fn validate_runner_accepts_bare_defaults() {
        // Both supported all-or-nothing postures are enforceable.
        for action in [
            crate::mxc_common::models::NetworkAction::Allow,
            crate::mxc_common::models::NetworkAction::Deny,
        ] {
            let request = ExecutionRequest {
                containment: crate::mxc_common::models::ContainmentBackend::Wslc,
                policy: crate::mxc_common::models::ContainerPolicy {
                    network_egress: Some(crate::mxc_common::models::NetworkEgressPolicy {
                        default: action,
                        ..Default::default()
                    }),
                    network_ingress: Some(crate::mxc_common::models::NetworkIngressPolicy {
                        default: action,
                        host_loopback: action,
                    }),
                    ..Default::default()
                },
                ..Default::default()
            };
            let runner = WSLContainerRunner::new(&WslcConfig::default());
            assert!(runner.validate_runner(&request).is_ok());
        }
    }

    #[test]
    fn validate_runner_rejects_supplied_ui() {
        let request = ExecutionRequest {
            containment: crate::mxc_common::models::ContainmentBackend::Wslc,
            policy: crate::mxc_common::models::ContainerPolicy {
                ui: crate::mxc_common::models::UiPolicy::default(),
                ui_specified: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let runner = WSLContainerRunner::new(&WslcConfig::default());
        let err = runner.validate_runner(&request).unwrap_err();
        assert!(
            err.error_message.contains("ui section is not supported"),
            "got: {}",
            err.error_message
        );
        assert_eq!(
            err.failure_phase,
            crate::mxc_common::models::FailurePhase::Rejected
        );
    }

    #[test]
    fn validate_runner_accepts_absent_ui() {
        let request = ExecutionRequest {
            containment: crate::mxc_common::models::ContainmentBackend::Wslc,
            ..Default::default()
        };
        assert!(!request.policy.ui_specified);
        let runner = WSLContainerRunner::new(&WslcConfig::default());
        assert!(runner.validate_runner(&request).is_ok());
    }

    /// `destroyOnExit: true` matches what one-shot does; `false` and
    /// `preservePolicy: true` do not. The accepted value is the near-miss a
    /// blanket `lifecycle` rejection would swallow.
    #[test]
    fn validate_runner_rejects_the_lifecycle_settings_one_shot_cannot_honour() {
        let runner = WSLContainerRunner::new(&WslcConfig::default());

        let accepted = ExecutionRequest {
            containment: crate::mxc_common::models::ContainmentBackend::Wslc,
            lifecycle: crate::mxc_common::models::LifecycleConfig {
                destroy_on_exit: true,
                preserve_policy: false,
            },
            ..Default::default()
        };
        assert!(
            runner.validate_runner(&accepted).is_ok(),
            "destroyOnExit=true is what one-shot does and must stay accepted"
        );

        for (lifecycle, needle) in [
            (
                crate::mxc_common::models::LifecycleConfig {
                    destroy_on_exit: false,
                    preserve_policy: false,
                },
                "destroyOnExit=false",
            ),
            (
                crate::mxc_common::models::LifecycleConfig {
                    destroy_on_exit: true,
                    preserve_policy: true,
                },
                "preservePolicy",
            ),
        ] {
            let request = ExecutionRequest {
                containment: crate::mxc_common::models::ContainmentBackend::Wslc,
                lifecycle,
                ..Default::default()
            };
            let err = runner.validate_runner(&request).unwrap_err();
            assert!(
                err.error_message.contains(needle),
                "expected {needle}; got: {}",
                err.error_message
            );
            assert_eq!(
                err.failure_phase,
                crate::mxc_common::models::FailurePhase::Rejected
            );
        }
    }

    /// A rejection must abort the request rather than tear a container down
    /// after building one. `SandboxBackend::spawn`'s half is in `sandbox.rs`.
    #[test]
    fn validate_runner_rejects_before_any_container_work() {
        let request = ExecutionRequest {
            containment: crate::mxc_common::models::ContainmentBackend::Wslc,
            script_code: "echo hi".to_string(),
            policy: crate::mxc_common::models::ContainerPolicy {
                ui_specified: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let runner = WSLContainerRunner::new(&WslcConfig::default());
        let err = runner.validate_runner(&request).unwrap_err();
        assert_eq!(
            err.failure_phase,
            crate::mxc_common::models::FailurePhase::Rejected,
            "a policy refusal is a rejection, not a runtime failure"
        );
    }

    fn request_with_cwd(cwd: &str) -> ExecutionRequest {
        ExecutionRequest {
            containment: crate::mxc_common::models::ContainmentBackend::Wslc,
            script_code: "pwd".to_string(),
            working_directory: cwd.to_string(),
            ..Default::default()
        }
    }

    /// Regression for #902: a cwd that cannot be mapped under `/mnt/<drive>`
    /// used to be dropped silently, running the workload in the container's
    /// default directory. It must now fail the launch and name the value.
    #[test]
    fn validate_runner_rejects_unmappable_working_directory() {
        let runner = WSLContainerRunner::new(&WslcConfig::default());
        for cwd in ["/workspace", "sub", "C:work", r"\\server\share"] {
            let err = runner
                .validate_runner(&request_with_cwd(cwd))
                .expect_err("an unmappable cwd must be rejected");
            assert_eq!(
                err.failure_phase,
                crate::mxc_common::models::FailurePhase::Rejected,
                "cwd {cwd:?}"
            );
            assert!(
                err.error_message.contains(&format!("{cwd:?}")),
                "the error must name the value {cwd:?}: {}",
                err.error_message
            );
        }
    }

    #[test]
    fn validate_runner_accepts_mappable_or_omitted_working_directory() {
        let runner = WSLContainerRunner::new(&WslcConfig::default());
        for cwd in [r"C:\work", "C:/work", "", "   "] {
            assert!(
                runner.validate_runner(&request_with_cwd(cwd)).is_ok(),
                "cwd {cwd:?} must be accepted"
            );
        }
    }

    // -- Host-stdio forwarding (`StdioMode::Inherit`) --------------------

    /// The regression this whole indirection exists for: the SDK's callback
    /// thread must not do the host's blocking I/O, because that same thread
    /// delivers the process-exit callback teardown waits on.
    ///
    /// The sink here never returns, standing in for a host that has stopped
    /// draining its stdout. Writing through it from the callback path — which
    /// is what `IoSink::Inherit` used to do — would park this test.
    #[test]
    fn callback_writes_do_not_block_on_a_stalled_host_sink() {
        let (writer, mut reader) = stream_pair();
        let sink = IoSink::Stream(writer);

        let released = Arc::new((Mutex::new(false), Condvar::new()));
        let pump_gate = Arc::clone(&released);
        let pump_thread = std::thread::spawn(move || {
            pump(&mut reader, |_| {
                // Blocks exactly like a write to a full host pipe.
                let (mutex, cvar) = &*pump_gate;
                let mut done = mutex.lock().unwrap();
                while !*done {
                    done = cvar.wait(done).unwrap();
                }
                Ok(())
            })
        });

        let start = std::time::Instant::now();
        for _ in 0..64 {
            sink.write(&[b'x'; 64 * 1024]);
        }
        sink.close();
        let elapsed = start.elapsed();

        // Let the pump go so the test doesn't leak a parked thread.
        {
            let (mutex, cvar) = &*released;
            *mutex.lock().unwrap() = true;
            cvar.notify_all();
        }
        pump_thread.join().expect("pump thread");

        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "callback-path writes must not block on a stalled host sink, took {elapsed:?}"
        );
    }

    #[test]
    fn pump_forwards_every_chunk_then_ends_at_eof() {
        let (writer, mut reader) = stream_pair();
        writer.write(b"first ");
        writer.write(b"second");
        writer.close();

        let mut seen = Vec::new();
        pump(&mut reader, |bytes| {
            seen.extend_from_slice(bytes);
            Ok(())
        });

        assert_eq!(seen, b"first second", "pump must forward the whole stream");
    }

    /// A host stream that has gone away (a closed pipe) cannot recover, so the
    /// pump must give up rather than spin on a stream that is still open.
    #[test]
    fn pump_stops_when_the_host_sink_errors() {
        let (writer, mut reader) = stream_pair();
        writer.write(b"delivered");
        writer.write(b"dropped");
        // Deliberately left open: only the sink error may end the pump.

        let mut writes = 0usize;
        pump(&mut reader, |_| {
            writes += 1;
            Err(std::io::Error::other("host stream closed"))
        });

        assert_eq!(writes, 1, "pump must stop at the first sink error");
    }

    /// `Inherit` must not hand read ends to the caller (they belong to the
    /// pumps), and `Pipes` must not spawn pumps (the caller drains those).
    #[test]
    fn io_wiring_matches_the_output_mode() {
        let (_ctx, capture) = IoContext::new(OutputMode::Capture);
        assert!(capture.pipes.is_none(), "capture has no caller pipes");
        assert!(capture.pumps.is_empty(), "capture has no host pumps");

        let (ctx, inherit) = IoContext::new(OutputMode::Stream(StdioMode::Inherit));
        assert!(inherit.pipes.is_none(), "inherit keeps its readers");
        assert_eq!(inherit.pumps.len(), 2, "inherit pumps stdout and stderr");
        // Close so the pumps end, then join them rather than leaking threads.
        ctx.close_streams();
        for pump in inherit.pumps {
            pump.join().expect("inherit pump");
        }

        let (_ctx, pipes) = IoContext::new(OutputMode::Stream(StdioMode::Pipes));
        assert!(pipes.pipes.is_some(), "pipes hands the caller its readers");
        assert!(pipes.pumps.is_empty(), "pipes has no host pumps");
    }

    // -- Timeout reporting ------------------------------------------------

    /// The run-to-completion path must not claim a termination the SDK never
    /// confirmed: a stop is only a request, so an unconfirmed timeout leaves
    /// sandboxed code possibly still running and the message has to say so.
    #[test]
    fn an_unconfirmed_timeout_does_not_claim_the_process_was_terminated() {
        let (ctx, _) = IoContext::new(OutputMode::Capture);
        let mut logger = Logger::new(Mode::Buffer);

        let confirmed = WSLContainerRunner::collect_output(
            &ctx,
            0,
            WaitOutcome::TimedOutTerminated,
            1500,
            &mut logger,
        );
        let unconfirmed = WSLContainerRunner::collect_output(
            &ctx,
            0,
            WaitOutcome::TimedOutUnconfirmed,
            1500,
            &mut logger,
        );

        assert!(confirmed.error_message.contains("was terminated"));
        assert!(
            !unconfirmed.error_message.contains("was terminated"),
            "an unconfirmed timeout must not claim a termination, got: {}",
            unconfirmed.error_message
        );
        assert!(
            unconfirmed.error_message.contains("may still be running"),
            "an unconfirmed timeout must say the container may still be running, got: {}",
            unconfirmed.error_message
        );
        // Both are still timeouts, so both fail the run.
        assert_eq!(confirmed.exit_code, -1);
        assert_eq!(unconfirmed.exit_code, -1);
    }

    #[test]
    fn a_normal_exit_reports_its_code_and_no_error() {
        let (ctx, _) = IoContext::new(OutputMode::Capture);
        let mut logger = Logger::new(Mode::Buffer);

        let response =
            WSLContainerRunner::collect_output(&ctx, 42, WaitOutcome::Exited, 1500, &mut logger);

        assert_eq!(response.exit_code, 42);
        assert!(response.error_message.is_empty());
        assert!(!WaitOutcome::Exited.timed_out());
        assert!(WaitOutcome::TimedOutTerminated.timed_out());
        assert!(WaitOutcome::TimedOutUnconfirmed.timed_out());
    }

    /// `Capture` keeps the bytes for the `ScriptResponse`; the streaming sink
    /// must report none, since the caller (or a pump) consumed them live.
    #[test]
    fn only_the_capture_sink_reports_captured_bytes() {
        let buffer = IoSink::Buffer(Mutex::new(Vec::new()));
        buffer.write(b"captured");
        assert_eq!(buffer.captured(), "captured");

        let (writer, _reader) = stream_pair();
        let stream = IoSink::Stream(writer);
        stream.write(b"streamed");
        assert_eq!(stream.captured(), "", "streamed bytes are not re-reported");
    }

    #[test]
    fn prerequisite_error_for_wsl_package_missing() {
        let message =
            sdk_init::prerequisite_error(WslcComponentFlags::WSLC_COMPONENT_FLAG_WSL_PACKAGE);

        assert!(message.contains("WslPackage"));
        assert!(message.contains("2.9.9"));
        assert!(message.contains("wsl --update --pre-release"));
        assert!(!message.contains("Virtual Machine Platform"));
    }

    #[test]
    fn prerequisite_error_for_virtual_machine_platform_missing() {
        let message = sdk_init::prerequisite_error(
            WslcComponentFlags::WSLC_COMPONENT_FLAG_VIRTUAL_MACHINE_PLATFORM,
        );

        assert!(message.contains("VirtualMachinePlatform"));
        assert!(message.contains("Virtual Machine Platform"));
        assert!(!message.contains("wsl --update"));
    }

    #[test]
    fn prerequisite_error_for_combined_missing_components() {
        let combined = WslcComponentFlags::WSLC_COMPONENT_FLAG_VIRTUAL_MACHINE_PLATFORM
            | WslcComponentFlags::WSLC_COMPONENT_FLAG_WSL_PACKAGE;
        let message = sdk_init::prerequisite_error(combined);

        assert!(message.contains("VirtualMachinePlatform"));
        assert!(message.contains("WslPackage"));
        assert!(message.contains("wsl --update"));
        assert!(message.contains("Virtual Machine Platform"));
    }

    #[test]
    fn prerequisite_error_for_sdk_needs_update() {
        let message =
            sdk_init::prerequisite_error(WslcComponentFlags::WSLC_COMPONENT_FLAG_SDK_NEEDS_UPDATE);

        assert_eq!(
            message,
            "WSLC runtime unavailable. Missing components: SdkNeedsUpdate (0x4). \
             Please update MXC — the WSLc SDK it ships is too old for your installed \
             version of WSL."
        );
        assert!(message.contains("SdkNeedsUpdate"));
        assert!(message.contains("update MXC"));
        // The user's WSL is fine (and newer) — no install/update advice for it.
        assert!(!message.contains("ensure WSL2 and the WSLC SDK are installed"));
        assert!(!message.contains("wsl --update"));
        assert!(!message.contains("Virtual Machine Platform"));
    }

    #[test]
    fn prerequisite_error_for_sdk_update_combined_with_another_component() {
        let combined = WslcComponentFlags::WSLC_COMPONENT_FLAG_SDK_NEEDS_UPDATE
            | WslcComponentFlags::WSLC_COMPONENT_FLAG_VIRTUAL_MACHINE_PLATFORM;
        let message = sdk_init::prerequisite_error(combined);

        assert!(message.contains("update MXC"));
        assert!(message.contains("Virtual Machine Platform"));
        assert!(!message.contains("ensure WSL2 and the WSLC SDK are installed"));
    }

    #[test]
    fn prerequisite_error_falls_back_for_unrecognized_components() {
        // An unknown future bit still has to produce actionable text.
        let message = sdk_init::prerequisite_error(WslcComponentFlags(0x8000));

        assert!(message.contains("ensure WSL2 and the WSLC SDK are installed"));
    }
}
