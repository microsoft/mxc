// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Wire protocol shared between `wxc-exec` (client) and `mxc-learning-mode-shim`
//! (server).
//!
//! The protocol is request/response over a named pipe. Both sides use
//! newline-delimited JSON for messages. The shim accepts one request per
//! connection, returns a response, and closes the connection.
//!
//! Default pipe name: `\\.\pipe\mxc-learning-mode-shim`.

use serde::{Deserialize, Serialize};

/// The default named-pipe path the shim listens on.
pub const PIPE_NAME: &str = r"\\.\pipe\mxc-learning-mode-shim";

/// Current protocol version. Bumped on incompatible changes; the server
/// rejects requests carrying a different version.
pub const PROTOCOL_VERSION: u32 = 1;

/// Client → server: ask the shim to open a privileged ETW session scoped
/// to a target sandboxed PID and (optionally) an AppContainer package SID.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenDenialSessionRequest {
    /// Wire-format protocol version. Must equal `PROTOCOL_VERSION`.
    pub protocol_version: u32,
    /// PID of the sandboxed child process.
    pub target_pid: u32,
    /// Optional AppContainer LowBox SID in SDDL form. When present, the
    /// shim adds an `EVENT_FILTER_TYPE_PACKAGE_ID` filter alongside the
    /// PID filter.
    pub package_sid: Option<String>,
}

/// Server → client: result of `OpenDenialSessionRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum OpenDenialSessionResponse {
    /// The privileged ETW session was created. The caller can now call
    /// `OpenTraceW(session_name)` to start consuming events. The caller
    /// is also responsible for stopping the session via `ControlTraceW(STOP)`
    /// when its workload exits — the shim grants the caller's user SID
    /// session-control rights via `EventAccessControl` at create time.
    ///
    /// (Earlier iterations of this protocol returned a duplicated
    /// `TRACEHANDLE`. ETW handles are not kernel handles and cannot be
    /// duplicated across processes; the cross-process contract is the
    /// session name + ACL grant, which is what this variant carries.)
    #[serde(rename_all = "camelCase")]
    Ok {
        /// Symbolic session name used by `OpenTraceW`.
        session_name: String,
    },
    /// The shim refused or failed to open the session. `code` carries a
    /// stable string discriminator for SDK display; `message` is human
    /// readable.
    #[serde(rename_all = "camelCase")]
    Error {
        /// Stable error code. See `ERROR_*` constants in this module.
        code: String,
        /// Human-readable message.
        message: String,
    },
}

/// Stable error codes the shim emits in `OpenDenialSessionResponse::Error`.
pub mod error_code {
    /// Request payload was malformed or unparseable.
    pub const BAD_REQUEST: &str = "badRequest";
    /// Wire-format version did not match `PROTOCOL_VERSION`.
    pub const VERSION_MISMATCH: &str = "versionMismatch";
    /// Caller is not authorized to open denial sessions (failed pipe ACL
    /// check, missing entitlement, etc.).
    pub const UNAUTHORIZED: &str = "unauthorized";
    /// Privileged Win32 call failed (e.g. `StartTraceW`,
    /// `EnableTraceEx2`, `DuplicateHandle`).
    pub const WIN32_FAILURE: &str = "win32Failure";
    /// The shim hasn't implemented this code path yet (used by the
    /// skeleton that ships before the full ETW work lands).
    pub const NOT_IMPLEMENTED: &str = "notImplemented";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip() {
        let req = OpenDenialSessionRequest {
            protocol_version: PROTOCOL_VERSION,
            target_pid: 12345,
            package_sid: Some("S-1-15-2-1".to_string()),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: OpenDenialSessionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.target_pid, parsed.target_pid);
        assert_eq!(req.package_sid, parsed.package_sid);
        assert_eq!(req.protocol_version, parsed.protocol_version);
    }

    #[test]
    fn response_ok_serializes_with_status_tag() {
        let resp = OpenDenialSessionResponse::Ok {
            session_name: "mxc-denials-1234".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"status\":\"ok\""), "got {json}");
        assert!(json.contains("\"sessionName\":\"mxc-denials-1234\""));
    }

    #[test]
    fn response_error_round_trip() {
        let resp = OpenDenialSessionResponse::Error {
            code: error_code::NOT_IMPLEMENTED.to_string(),
            message: "ETW path not yet wired".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: OpenDenialSessionResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            OpenDenialSessionResponse::Error { code, message } => {
                assert_eq!(code, error_code::NOT_IMPLEMENTED);
                assert_eq!(message, "ETW path not yet wired");
            }
            _ => panic!("expected Error variant"),
        }
    }
}
