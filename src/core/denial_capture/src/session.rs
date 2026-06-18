// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Client-side `ScopedTraceSession` — the bridge from `wxc-exec` (and
//! other callers) to `mxc-denial-shim` for per-PID denial capture.
//!
//! Phase 3 split:
//! - **3.1 (this commit):** RPC handshake with the shim. `open_via_shim`
//!   connects to the well-known pipe, sends `OpenDenialSessionRequest`,
//!   reads `OpenDenialSessionResponse`, returns a `ScopedTraceSession`
//!   holding the session name. The actual ETW consumer (`OpenTraceW` +
//!   `ProcessTrace` worker + TDH decoding) lands in Phase 3.2.
//! - **3.2 (follow-up):** `start_collector()` opens the ETW session by
//!   name, spawns a `ProcessTrace` worker thread, decodes
//!   `AccessCheckLog` / `LearningModeViolation` events via TDH into
//!   `DenialEvent` values.
//! - **3.3 (follow-up):** stop + drain semantics + bounded buffer +
//!   truncated flag.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use thiserror::Error;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, OpenTraceW, ProcessTrace, CONTROLTRACE_HANDLE, EVENT_RECORD,
    EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, PROCESSTRACE_HANDLE, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME, WNODE_FLAG_TRACED_GUID,
};

use crate::extractors::{build_denial_from_access_check, build_denial_from_learning_mode};
use crate::model::DenialEvent;
use crate::tdh_decode::decode_event_parts;
use crate::wire::{
    OpenDenialSessionRequest, OpenDenialSessionResponse, PIPE_NAME, PROTOCOL_VERSION,
};

/// LearningModeViolation event ID from Kernel-General.
const LEARNING_MODE_VIOLATION_EVENT_ID: u16 = 27;

/// Cap on the number of captured events per session. Bounds memory
/// growth from a malicious workload that triggers millions of denials.
/// The CollectorHandle's `truncated` flag is set when the cap is hit.
const MAX_CAPTURED_EVENTS: usize = 10_000;

/// Shared state between the ETW callback and the consumer thread.
///
/// The callback is invoked from inside `ProcessTrace` on a thread the
/// ETW infrastructure owns. We retrieve a pointer to this struct from
/// `EVENT_RECORD.UserContext` (which we populated via
/// `EVENT_TRACE_LOGFILEW.Context`).
struct CallbackContext {
    target_pid: u32,
    events: Mutex<Vec<DenialEvent>>,
    truncated: AtomicBool,
    /// Optional sender: when set, the callback also pushes a public
    /// `DeniedResource` view of each captured event into this channel so
    /// a consumer thread (e.g. the runner's stderr NDJSON writer) can
    /// stream events to the caller in real time. `try_send` semantics --
    /// a backed-up channel drops events rather than blocking the
    /// callback (which would back-pressure ETW itself).
    event_stream: Option<std::sync::mpsc::Sender<crate::model::DeniedResource>>,
}

/// Owns a running ETW consumer. Returned by
/// `ScopedTraceSession::start_collector`. Stop + drain via
/// `stop_and_drain`.
pub struct CollectorHandle {
    /// Trace handle returned by `OpenTraceW`. Closing it makes
    /// `ProcessTrace` return.
    trace_handle: PROCESSTRACE_HANDLE,
    /// Background worker that ran `ProcessTrace`.
    worker: Option<JoinHandle<()>>,
    /// Context shared with the worker's ETW callback. Boxed so its
    /// address is stable; pointer handed to ETW via
    /// `EVENT_TRACE_LOGFILEW.Context`.
    context: Box<CallbackContext>,
    /// Session name so we can `ControlTraceW(STOP)` it at drain time.
    session_name: String,
}

impl CollectorHandle {
    /// Stops the consumer and returns the captured denials.
    ///
    /// Order matters: we call `ControlTraceW(STOP)` first so the ETW
    /// session shuts down and ProcessTrace can return cleanly, then
    /// `CloseTrace` to release our consumer handle, then join the
    /// worker thread. Finally we drain the shared event buffer.
    ///
    /// The returned `truncated` flag is the OR of three signals:
    ///   1. The in-process callback buffer cap was hit (workload
    ///      generated more denials than `MAX_BUFFERED_DENIALS`).
    ///   2. The ETW kernel buffer lost events between providers and
    ///      our consumer (`EVENT_TRACE_PROPERTIES.EventsLost`).
    ///   3. The kernel dropped whole real-time buffers under
    ///      pressure (`LogBuffersLost` / `RealTimeBuffersLost`).
    ///
    /// SDK consumers see the truncation flag on the summary line
    /// and treat it as "the denial list may be incomplete." Without
    /// the kernel-side checks, a workload that exploded faster than
    /// our consumer could drain the kernel buffer would silently
    /// report a partial list with `truncated: false` -- worse than
    /// useless because the consumer would treat the partial list
    /// as the full story.
    pub fn stop_and_drain(mut self) -> (Vec<DenialEvent>, bool) {
        // Stop the controller-side session. This triggers RUNDOWN +
        // makes ProcessTrace return. The returned stats tell us how
        // many events the kernel dropped before we saw them.
        let kernel_stats = stop_session_by_name(&self.session_name);

        // Close the consumer side. Safe to call even if ProcessTrace
        // already returned; idempotent in practice.
        unsafe {
            let _ = CloseTrace(self.trace_handle);
        }

        if let Some(jh) = self.worker.take() {
            let _ = jh.join();
        }

        // Now no more callbacks can fire — context is exclusive to us.
        let callback_truncated = self.context.truncated.load(Ordering::SeqCst);
        let events = std::mem::take(&mut *self.context.events.lock().unwrap());

        let kernel_lost_any =
            kernel_stats.events_lost > 0 || kernel_stats.buffers_lost > 0;
        let truncated = callback_truncated || kernel_lost_any;

        if kernel_lost_any {
            eprintln!(
                "[denial_capture] ETW kernel buffer loss: events_lost={}, buffers_lost={} \
                 (session={}, callback_truncated={}); SDK summary will report truncated=true",
                kernel_stats.events_lost,
                kernel_stats.buffers_lost,
                self.session_name,
                callback_truncated,
            );
        }

        (events, truncated)
    }
}

impl Drop for CollectorHandle {
    fn drop(&mut self) {
        // If stop_and_drain wasn't called (panic path, etc.) we still
        // need to tear down the ETW session and reclaim the worker.
        // Lifetime stats are discarded here -- the caller bailed
        // out, there's no longer anyone to report truncation to.
        if self.worker.is_some() {
            let _ = stop_session_by_name(&self.session_name);
            unsafe {
                let _ = CloseTrace(self.trace_handle);
            }
            if let Some(jh) = self.worker.take() {
                let _ = jh.join();
            }
        }
    }
}

/// Lifetime stats reported by `ControlTraceW(STOP)`. We track the
/// two fields that indicate the kernel dropped denial events before
/// we saw them — surfaced through `CollectorHandle::stop_and_drain`'s
/// `truncated` flag so the SDK consumer can warn the user "your
/// list of denials is incomplete."
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct SessionStopStats {
    /// `EVENT_TRACE_PROPERTIES.EventsLost`: events the provider
    /// generated but couldn't deliver to any consumer (free-buffer
    /// pool exhausted, etc.).
    pub events_lost: u32,
    /// `EVENT_TRACE_PROPERTIES.LogBuffersLost +
    ///  RealTimeBuffersLost`: whole buffers the kernel had to drop
    /// because our consumer fell behind under load. Summed because
    /// either form represents data we can never see.
    pub buffers_lost: u32,
}

/// Issues `ControlTraceW(STOP)` for a session by name and returns
/// the kernel-side loss counters from the populated properties
/// block. Best-effort; errors are logged and the stats default to
/// zero (the conservative answer: "no known loss" rather than
/// "loss happened" since we couldn't confirm either way).
fn stop_session_by_name(name: &str) -> SessionStopStats {
    let mut name_wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

    // Minimal stop-only properties block. The control API requires a
    // properties buffer big enough to hold the LoggerName at offset
    // sizeof(EVENT_TRACE_PROPERTIES).
    #[repr(C)]
    struct StopProps {
        base: EVENT_TRACE_PROPERTIES,
        name_buf: [u16; 256],
    }
    let mut props: StopProps = unsafe { core::mem::zeroed() };
    props.base.Wnode.BufferSize = core::mem::size_of::<StopProps>() as u32;
    props.base.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props.base.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props.base.LoggerNameOffset = core::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;

    // SAFETY: props has valid layout and outlives the call;
    // name_wide is null-terminated UTF-16.
    let status = unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            PCWSTR(name_wide.as_mut_ptr()),
            &mut props as *mut _ as *mut EVENT_TRACE_PROPERTIES,
            EVENT_TRACE_CONTROL_STOP,
        )
    };
    if status != WIN32_ERROR(0) {
        eprintln!(
            "[denial_capture] ControlTraceW(STOP) for {name} returned {:#X}",
            status.0
        );
        return SessionStopStats::default();
    }

    // ControlTraceW(STOP) populates EVENT_TRACE_PROPERTIES with the
    // session's lifetime stats. `LogBuffersLost` covers file-mode
    // sessions; `RealTimeBuffersLost` covers real-time sessions
    // (which we use). Reading both is harmless and future-proofs
    // against a future code change that flips the session mode.
    SessionStopStats {
        events_lost: props.base.EventsLost,
        buffers_lost: props
            .base
            .LogBuffersLost
            .saturating_add(props.base.RealTimeBuffersLost),
    }
}

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("could not connect to denial shim pipe `{0}`: {1}")]
    PipeConnect(String, std::io::Error),

    #[error("write to denial shim pipe failed: {0}")]
    PipeWrite(std::io::Error),

    #[error("read from denial shim pipe failed: {0}")]
    PipeRead(std::io::Error),

    #[error("denial shim returned empty response")]
    EmptyResponse,

    #[error("could not parse denial shim response: {0}")]
    ParseResponse(serde_json::Error),

    #[error("denial shim returned error: {code} — {message}")]
    ShimError { code: String, message: String },

    #[error("could not serialize request: {0}")]
    SerializeRequest(serde_json::Error),

    #[error("OpenTraceW(`{0}`) failed: Win32 error {1}")]
    OpenTrace(String, u32),
}

/// `FILE_FLAG_OVERLAPPED` is not set; we want blocking sync I/O for the
/// short request/response handshake.
const PIPE_OPEN_TIMEOUT: Duration = Duration::from_secs(5);

/// `ERROR_PIPE_BUSY` from winnt.h. When all pipe instances are busy,
/// `OpenOptions::open` returns this and the canonical Win32 retry path
/// is to wait briefly and try again.
const ERROR_PIPE_BUSY: i32 = 231;

/// A handle to the privileged ETW session created by the shim.
///
/// Returned by `open_via_shim`. Call `start_collector` to begin
/// consuming events from the kernel.
#[derive(Debug, Clone)]
pub struct ScopedTraceSession {
    /// Symbolic ETW session name; consumed by `OpenTraceW`.
    pub session_name: String,
    /// PID this session is scoped to. Retained for diagnostics + so
    /// the callback can tag captured events.
    pub target_pid: u32,
}

impl ScopedTraceSession {
    /// Opens the ETW session by name, spawns a `ProcessTrace` worker
    /// thread, and starts collecting denial events into a bounded
    /// in-process buffer.
    ///
    /// Returns a `CollectorHandle`. Call `stop_and_drain` on it when
    /// the workload exits to retrieve the captured events.
    pub fn start_collector(&self) -> Result<CollectorHandle, SessionError> {
        self.start_collector_with_stream(None)
    }

    /// Like `start_collector` but additionally sends each captured
    /// `DeniedResource` into the provided channel as it arrives. The
    /// caller is responsible for running a consumer that reads the
    /// `Receiver` end. When the returned `CollectorHandle` is dropped
    /// (or `stop_and_drain` is called) the sender is dropped and the
    /// consumer's `recv()` returns `Err` -- the consumer should exit
    /// its loop on that signal.
    pub fn start_collector_with_stream(
        &self,
        event_stream: Option<std::sync::mpsc::Sender<crate::model::DeniedResource>>,
    ) -> Result<CollectorHandle, SessionError> {
        // Allocate the callback context. It MUST outlive all callbacks,
        // so we Box it and hand its raw pointer to ETW.
        let context = Box::new(CallbackContext {
            target_pid: self.target_pid,
            events: Mutex::new(Vec::new()),
            truncated: AtomicBool::new(false),
            event_stream,
        });
        let context_ptr: *mut CallbackContext = Box::as_ref(&context) as *const _ as *mut _;

        let mut name_wide: Vec<u16> = self
            .session_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { core::mem::zeroed() };
        logfile.LoggerName = PWSTR(name_wide.as_mut_ptr());
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(event_record_callback);
        logfile.Context = context_ptr.cast();

        // SAFETY: logfile and name_wide outlive the OpenTraceW call;
        // the EventRecordCallback function pointer is valid.
        let trace_handle = unsafe { OpenTraceW(&mut logfile) };
        // OpenTraceW returns INVALID_PROCESSTRACE_HANDLE (u64::MAX) on
        // failure.
        if trace_handle.Value == u64::MAX {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1) as u32;
            return Err(SessionError::OpenTrace(self.session_name.clone(), err));
        }

        // Spawn the worker. ProcessTrace blocks until the session is
        // stopped (via ControlTraceW STOP) or the trace handle is
        // closed.
        let session_name_for_thread = self.session_name.clone();
        let trace_handle_bits = trace_handle.Value;
        let worker = thread::Builder::new()
            .name(format!("etw-consume-{session_name_for_thread}"))
            .spawn(move || {
                let handle = PROCESSTRACE_HANDLE {
                    Value: trace_handle_bits,
                };
                let handles = [handle];
                // SAFETY: handles is valid for the call. ProcessTrace
                // blocks until CloseTrace or controller stop.
                let status = unsafe { ProcessTrace(&handles, None, None) };
                // ERROR_CANCELLED (1223) is the normal "session was
                // stopped" path; everything else is interesting.
                if status != WIN32_ERROR(0) && status.0 != 1223 {
                    eprintln!(
                        "[denial_capture] ProcessTrace returned Win32 {:#X}",
                        status.0
                    );
                }
            })
            .expect("spawn etw-consume thread");

        Ok(CollectorHandle {
            trace_handle,
            worker: Some(worker),
            context,
            session_name: self.session_name.clone(),
        })
    }
}

/// ETW event-record callback. Invoked by the ETW infrastructure inside
/// `ProcessTrace` for every captured event.
///
/// # Safety
/// `event_record` is a valid pointer from the ETW infrastructure for
/// the duration of the call. We read `UserContext` to retrieve our
/// `CallbackContext`; the pointer's lifetime is guaranteed by the
/// `CollectorHandle` (we only drop the Box after joining this thread).
unsafe extern "system" fn event_record_callback(event_record: *mut EVENT_RECORD) {
    if event_record.is_null() {
        return;
    }
    let event = unsafe { &*event_record };
    let context_ptr = event.UserContext as *const CallbackContext;
    if context_ptr.is_null() {
        return;
    }
    let context = unsafe { &*context_ptr };

    let event_pid = event.EventHeader.ProcessId;

    // Defense in depth: the kernel-side PID filter should already have
    // dropped events for other processes, but check anyway in case the
    // provider ignored the filter.
    if event_pid != context.target_pid {
        return;
    }

    let parts = match unsafe { decode_event_parts(event_record) } {
        Some(p) => p,
        None => return,
    };

    // EventHeader.TimeStamp is a FILETIME-shaped value (100ns intervals
    // since 1601-01-01 UTC). The windows-rs binding types it as i64;
    // cast to u64 since FILETIME values are non-negative in practice
    // (we'd have to be capturing events from 1601 BC for the sign bit
    // to matter).
    let filetime = event.EventHeader.TimeStamp as u64;

    let denial = if parts.event_id == LEARNING_MODE_VIOLATION_EVENT_ID {
        build_denial_from_learning_mode(&parts, event_pid, filetime)
    } else {
        build_denial_from_access_check(&parts, event_pid, filetime)
    };

    let Some(denial) = denial else {
        return;
    };

    let mut events = match context.events.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(), // poisoned; carry on
    };
    if events.len() >= MAX_CAPTURED_EVENTS {
        context.truncated.store(true, Ordering::SeqCst);
        return;
    }
    events.push(denial.clone());
    drop(events); // release the lock before the stream send

    // Stream the public-form view to the caller's consumer thread,
    // if one is attached. `send` returns `Err` only when the receiver
    // is dropped -- we just discard those, since the consumer
    // exiting cleanly is the normal teardown path.
    if let Some(ref tx) = context.event_stream {
        let _ = tx.send(denial.into_resource());
    }
}

/// Opens a privileged ETW session via the `mxc-denial-shim` service.
///
/// Returns once the shim has acknowledged the request with a session
/// name. The caller is responsible for stopping the session
/// (`ControlTraceW(STOP)`) when its workload exits. Phase 3.2 will
/// own that via `ScopedTraceSession::stop_and_drain()`.
///
/// `package_sid` is forwarded to the shim if provided; the shim
/// currently ignores it (Phase 3 follow-up to wire up the PACKAGE_ID
/// filter).
pub fn open_via_shim(
    target_pid: u32,
    package_sid: Option<&str>,
) -> Result<ScopedTraceSession, SessionError> {
    let pipe_path = PIPE_NAME;

    // Connect — retry on ERROR_PIPE_BUSY up to PIPE_OPEN_TIMEOUT.
    let mut pipe = open_pipe_with_retry(pipe_path)?;

    let request = OpenDenialSessionRequest {
        protocol_version: PROTOCOL_VERSION,
        target_pid,
        package_sid: package_sid.map(str::to_string),
    };
    let request_bytes = serde_json::to_vec(&request).map_err(SessionError::SerializeRequest)?;

    pipe.write_all(&request_bytes)
        .map_err(SessionError::PipeWrite)?;
    pipe.flush().map_err(SessionError::PipeWrite)?;

    // The shim writes its response and immediately disconnects. The
    // Win32 error codes for "the other end closed cleanly after
    // sending data" are ERROR_BROKEN_PIPE (109) and
    // ERROR_NO_PROCESS_IS_ON_OTHER_END_OF_THE_PIPE (233). std's
    // `read_to_end` surfaces both as errors and discards any bytes
    // read in that call, so we hand-roll a tolerant drain loop:
    // accept bytes already in the buffer, treat 109/233 as EOF.
    let response_bytes = read_until_eof_or_disconnect(&mut pipe)?;

    if response_bytes.is_empty() {
        return Err(SessionError::EmptyResponse);
    }

    let parsed: OpenDenialSessionResponse =
        serde_json::from_slice(&response_bytes).map_err(SessionError::ParseResponse)?;

    match parsed {
        OpenDenialSessionResponse::Ok { session_name } => Ok(ScopedTraceSession {
            session_name,
            target_pid,
        }),
        OpenDenialSessionResponse::Error { code, message } => {
            Err(SessionError::ShimError { code, message })
        }
    }
}

fn open_pipe_with_retry(path: &str) -> Result<std::fs::File, SessionError> {
    let start = Instant::now();
    loop {
        match OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(0) // no FILE_FLAG_OVERLAPPED
            .open(path)
        {
            Ok(f) => return Ok(f),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                if start.elapsed() >= PIPE_OPEN_TIMEOUT {
                    return Err(SessionError::PipeConnect(path.to_string(), e));
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(SessionError::PipeConnect(path.to_string(), e)),
        }
    }
}

/// `ERROR_BROKEN_PIPE` and `ERROR_NO_PROCESS_IS_ON_OTHER_END_OF_THE_PIPE`.
/// Both indicate the server side closed cleanly; for a one-shot RPC
/// that's the expected post-response state and shouldn't be a failure.
const ERROR_BROKEN_PIPE: i32 = 109;
const ERROR_NO_PROCESS_IS_ON_PIPE: i32 = 233;

/// Drains `pipe` until EOF or a clean-disconnect error code. Returns
/// the bytes successfully read so far; only propagates errors that are
/// *not* the server-side-closed-cleanly codes.
fn read_until_eof_or_disconnect(pipe: &mut std::fs::File) -> Result<Vec<u8>, SessionError> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 1024];
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) => return Ok(buf),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) => {
                let code = e.raw_os_error();
                if matches!(
                    code,
                    Some(ERROR_BROKEN_PIPE) | Some(ERROR_NO_PROCESS_IS_ON_PIPE)
                ) {
                    return Ok(buf);
                }
                return Err(SessionError::PipeRead(e));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // open_via_shim hits a real Windows service over a named pipe; we
    // can't exercise it inside `cargo test` on a developer box without a
    // pre-installed + running shim. The handshake logic is unit-tested
    // indirectly via the wire-format tests in `wire.rs`; live behavior
    // is validated against the VM via the Phase 2 smoke tests.

    #[test]
    fn session_error_displays_shim_error_with_code_and_message() {
        let e = SessionError::ShimError {
            code: "win32Failure".to_string(),
            message: "StartTraceW: Win32 error 0x5".to_string(),
        };
        let s = format!("{e}");
        assert!(s.contains("win32Failure"));
        assert!(s.contains("StartTraceW: Win32 error 0x5"));
    }

    #[test]
    fn scoped_trace_session_carries_target_pid() {
        let s = ScopedTraceSession {
            session_name: "mxc-denials-abc".to_string(),
            target_pid: 1234,
        };
        assert_eq!(s.target_pid, 1234);
        assert_eq!(s.session_name, "mxc-denials-abc");
    }
}
