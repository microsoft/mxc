// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Wire protocol shared between `wxc-exec` (client) and `mxc-learning-mode-shim`
//! (server).
//!
//! The protocol is request/response over a named pipe. Both sides use
//! newline-delimited JSON for messages. The shim accepts one request per
//! connection, returns a response, and closes the connection.
//!
//! Two request kinds are defined:
//!
//! - [`ShimRequest::OpenDenialSession`] — creates a fresh privileged ETW
//!   session scoped to a target PID. Used once per `wxc-exec` invocation
//!   at workload-spawn time.
//! - [`ShimRequest::ExtendDenialSession`] — extends the PID filter of an
//!   already-open session with the full new list. Used by the runner's
//!   IOCP listener every time the workload spawns a descendant.
//!
//! Default pipe name: `\\.\pipe\mxc-learning-mode-shim`.

use serde::{Deserialize, Serialize};

/// The default named-pipe path the shim listens on.
pub const PIPE_NAME: &str = r"\\.\pipe\mxc-learning-mode-shim";

/// Current protocol version. Bumped on incompatible changes; the server
/// rejects requests carrying a different version.
///
/// - **1** → only `OpenDenialSessionRequest` understood; the request was
///   serialised at the top level (no enum wrapper).
/// - **2** → all requests wrapped in a [`ShimRequest`] enum so the shim
///   can dispatch on the variant. Adds
///   [`ShimRequest::ExtendDenialSession`].
pub const PROTOCOL_VERSION: u32 = 2;

/// Wrapper enum for every request the shim accepts. The discriminator
/// is a `kind` field at the top of the JSON object; serde routes to the
/// matching variant.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ShimRequest {
    /// Create a fresh denial-capture session.
    OpenDenialSession(OpenDenialSessionRequest),
    /// Extend the PID filter of an already-open session.
    ExtendDenialSession(ExtendDenialSessionRequest),
}

/// Wrapper enum for every response the shim sends. The discriminator is
/// the original `status` tag for backwards-compat with the
/// `OpenDenialSession` shape, plus a `kind` tag so callers know which
/// request shape the response is paired with.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ShimResponse {
    OpenDenialSession(OpenDenialSessionResponse),
    ExtendDenialSession(ExtendDenialSessionResponse),
}

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

/// Client → server: replace the PID filter on an already-open denial
/// session with `pids`. Used to add new descendants to the filter as
/// the runner's IOCP listener observes them.
///
/// The protocol is **idempotent and stateless**: the caller sends the
/// full new PID list every time (root PID + all known descendants), and
/// the shim replaces the filter as-is. The shim does not track which
/// PIDs have been added previously — the kernel's filter is the
/// source of truth.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtendDenialSessionRequest {
    /// Wire-format protocol version. Must equal `PROTOCOL_VERSION`.
    pub protocol_version: u32,
    /// Name returned by the `OpenDenialSessionResponse::Ok` for this
    /// session.
    pub session_name: String,
    /// Complete new PID list. The shim REPLACES the filter (not
    /// appends), so the caller must include the root PID and every
    /// previously-added descendant.
    pub pids: Vec<u32>,
}

/// Server → client: result of `ExtendDenialSessionRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum ExtendDenialSessionResponse {
    /// The PID filter was updated. Subsequent ETW events from any of
    /// the listed PIDs reach the session.
    Ok,
    /// The shim could not update the filter. `code` is a stable
    /// discriminator (see `error_code`); `message` is human readable.
    #[serde(rename_all = "camelCase")]
    Error { code: String, message: String },
}

/// Stable error codes the shim emits in error responses.
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
    /// Caller referred to a session name the shim cannot resolve.
    pub const UNKNOWN_SESSION: &str = "unknownSession";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_request_round_trip() {
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
    fn open_response_ok_serializes_with_status_tag() {
        let resp = OpenDenialSessionResponse::Ok {
            session_name: "mxc-denials-1234".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"status\":\"ok\""), "got {json}");
        assert!(json.contains("\"sessionName\":\"mxc-denials-1234\""));
    }

    #[test]
    fn open_response_error_round_trip() {
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

    #[test]
    fn shim_request_wrapper_dispatches_on_kind() {
        let open = ShimRequest::OpenDenialSession(OpenDenialSessionRequest {
            protocol_version: PROTOCOL_VERSION,
            target_pid: 42,
            package_sid: None,
        });
        let json = serde_json::to_string(&open).unwrap();
        assert!(
            json.contains("\"kind\":\"openDenialSession\""),
            "got {json}"
        );
        let parsed: ShimRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            ShimRequest::OpenDenialSession(r) => assert_eq!(r.target_pid, 42),
            _ => panic!("expected OpenDenialSession variant"),
        }
    }

    #[test]
    fn extend_request_round_trip() {
        let req = ExtendDenialSessionRequest {
            protocol_version: PROTOCOL_VERSION,
            session_name: "mxc-denials-abcd".to_string(),
            pids: vec![100, 200, 300],
        };
        let wrapped = ShimRequest::ExtendDenialSession(req.clone());
        let json = serde_json::to_string(&wrapped).unwrap();
        assert!(
            json.contains("\"kind\":\"extendDenialSession\""),
            "got {json}"
        );
        assert!(json.contains("\"pids\":[100,200,300]"));
        let parsed: ShimRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            ShimRequest::ExtendDenialSession(r) => {
                assert_eq!(r.session_name, req.session_name);
                assert_eq!(r.pids, req.pids);
            }
            _ => panic!("expected ExtendDenialSession variant"),
        }
    }

    #[test]
    fn extend_response_ok_serializes_compactly() {
        let resp = ShimResponse::ExtendDenialSession(ExtendDenialSessionResponse::Ok);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            json.contains("\"kind\":\"extendDenialSession\""),
            "got {json}"
        );
        assert!(json.contains("\"status\":\"ok\""), "got {json}");
    }
}
