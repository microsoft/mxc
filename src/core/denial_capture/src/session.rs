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
use std::thread;
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::wire::{
    OpenDenialSessionRequest, OpenDenialSessionResponse, PIPE_NAME, PROTOCOL_VERSION,
};

/// `FILE_FLAG_OVERLAPPED` is not set; we want blocking sync I/O for the
/// short request/response handshake.
const PIPE_OPEN_TIMEOUT: Duration = Duration::from_secs(5);

/// `ERROR_PIPE_BUSY` from winnt.h. When all pipe instances are busy,
/// `OpenOptions::open` returns this and the canonical Win32 retry path
/// is to wait briefly and try again.
const ERROR_PIPE_BUSY: i32 = 231;

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
}

/// A handle to the privileged ETW session created by the shim.
///
/// Phase 3.1 only stores the session name. Phase 3.2 adds the
/// `OpenTraceW` consumer side.
#[derive(Debug, Clone)]
pub struct ScopedTraceSession {
    /// Symbolic ETW session name; consumed by `OpenTraceW`.
    pub session_name: String,
    /// PID this session is scoped to. Retained for diagnostics.
    pub target_pid: u32,
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

    // Read until EOF (shim disconnects after writing the response).
    let mut response_bytes = Vec::with_capacity(512);
    pipe.read_to_end(&mut response_bytes)
        .map_err(SessionError::PipeRead)?;

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
