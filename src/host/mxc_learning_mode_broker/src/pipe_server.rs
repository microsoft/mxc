// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Named-pipe server that hosts the `OpenDenialSession` RPC.
//!
//! Accepts connections, parses a single [`BrokerRequest`] from the pipe, writes a
//! single [`BrokerResponse`], then disconnects.
//!
//! Connections are handled serially in the accept loop thread.
//!
//! Pipe ACL: scoped to interactive-logon users. The broker runs as
//! `LocalService` and would be vulnerable to confused-deputy attacks if
//! the pipe were world-accessible.

use std::collections::HashMap;
use std::error::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_MORE_DATA, ERROR_NO_DATA, ERROR_PIPE_CONNECTED,
    HANDLE, HLOCAL, INVALID_HANDLE_VALUE,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{
    FlushFileBuffers, ReadFile, WriteFile, FILE_FLAGS_AND_ATTRIBUTES, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_MESSAGE,
    PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

use learning_mode_broker_protocol::{
    error_code, BrokerRequest, BrokerResponse, ExtendDenialSessionRequest,
    ExtendDenialSessionResponse, OpenDenialSessionRequest, OpenDenialSessionResponse, PIPE_NAME,
    PROTOCOL_VERSION,
};

use crate::caller_context::{self, CallerContext};

/// Maps session names to the SID that opened them. Populated by
/// `handle_open` and consulted by `handle_extend` to enforce that
/// only the original creator can extend a session's PID filter.
/// Without this, any interactive user could enumerate session names
/// (e.g. via `logman query -ets`) and call `ExtendDenialSession` to
/// add their own PID to someone else's filter.
type OwnershipMap = Arc<Mutex<HashMap<String, String>>>;

/// Shape of the security descriptor in SDDL form.
///
/// - `D:` — discretionary ACL
/// - `(A;;GA;;;LS)` — Allow Generic All to the broker's own account,
///   `NT AUTHORITY\LocalService` (well-known SID `LS` = `S-1-5-19`). The
///   broker is the pipe owner and re-creates a fresh instance for every
///   connection, which requires `FILE_CREATE_PIPE_INSTANCE`; the object
///   owner only receives `READ_CONTROL | WRITE_DAC` implicitly, so this
///   explicit ACE is required for the accept loop to create instances
///   beyond the first.
/// - `(A;;0x12019b;;;IU)` — Interactive Users (well-known SID `IU` =
///   `S-1-5-4`) get exactly the rights needed to connect and exchange
///   messages — `FILE_GENERIC_READ | FILE_GENERIC_WRITE` **minus**
///   `FILE_CREATE_PIPE_INSTANCE` (0x4). Withholding create-instance stops
///   an unprivileged interactive user from standing up a competing
///   instance of our well-known pipe (pipe-squatting / confused deputy).
///   NOTE: clients must therefore open the pipe with this explicit access
///   mask (not `GENERIC_WRITE`, whose named-pipe generic mapping *includes*
///   `FILE_CREATE_PIPE_INSTANCE`), or `CreateFile` fails with access denied.
/// - `(A;;GA;;;BA)` — Allow Generic All to Built-in Administrators
///   (allows `wxc-host-prep` / diagnostic tooling running elevated).
const PIPE_SDDL: &str = "D:(A;;GA;;;LS)(A;;0x12019b;;;IU)(A;;GA;;;BA)";

const PIPE_BUFFER_SIZE: u32 = 8 * 1024;

/// Hard cap on a single reassembled request. Message-mode reads can span
/// multiple `ReadFile` calls (`ERROR_MORE_DATA`) when a request exceeds
/// `PIPE_BUFFER_SIZE`; this bounds how much an untrusted caller can send
/// before we reject with `BAD_REQUEST`, preventing unbounded allocation.
const MAX_REQUEST_SIZE: usize = 256 * 1024;

/// Runs the pipe accept loop until the process is signaled to stop. Used
/// by the `--debug` mode where there's no SCM stop signal — Ctrl-C kills
/// the process.
pub fn run_until_signal() -> Result<(), Box<dyn Error>> {
    let stop_flag = Arc::new(AtomicBool::new(false));
    run_until_stop_flag(stop_flag)
}

/// Runs the pipe accept loop until `stop_flag` is set.
///
/// Connections are handled **serially** in the same thread. The
/// prototype's actual workload is one `OpenDenialSessionRequest` per
/// `wxc-exec --capture-denials` invocation: there is no benefit to
/// concurrent handling, and an earlier per-connection-thread design
/// left the next pipe instance unable to accept new clients (the
/// accept-loop iteration completed before the worker's
/// `DisconnectNamedPipe` ran, and Windows wouldn't match a new client
/// to the listening instance). Synchronous handling sidesteps that
/// entirely. If we ever need to support concurrent requests we should
/// move to overlapped I/O with a proper completion port, not naive
/// thread-per-connection.
pub fn run_until_stop_flag(stop_flag: Arc<AtomicBool>) -> Result<(), Box<dyn Error>> {
    let mut first = true;
    let ownership: OwnershipMap = Arc::new(Mutex::new(HashMap::new()));

    while !stop_flag.load(Ordering::SeqCst) {
        let pipe = create_pipe_instance(first)?;
        first = false;

        // ConnectNamedPipe blocks until a client connects. On stop the
        // control handler sets `stop_flag` and calls `wake_accept_loop`,
        // which makes a throwaway self-connection to unblock this call so
        // `Stop`/`Shutdown` returns promptly instead of hanging until the
        // next real client.
        let connect_result = unsafe { ConnectNamedPipe(pipe, None) };

        // Successful connection: Ok(()) OR Err(ERROR_PIPE_CONNECTED)
        // (client raced us between create and connect — still a valid
        // connection).
        let connected = match connect_result {
            Ok(()) => true,
            Err(e) if e.code() == ERROR_PIPE_CONNECTED.to_hresult() => true,
            Err(e) => {
                eprintln!("[mxc-learning-mode-broker] ConnectNamedPipe failed: {e}");
                unsafe {
                    let _ = CloseHandle(pipe);
                }
                if stop_flag.load(Ordering::SeqCst) {
                    break;
                }
                thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        debug_assert!(connected);

        // If we were unblocked by the shutdown self-connection, don't try
        // to service it — disconnect and exit the loop.
        if stop_flag.load(Ordering::SeqCst) {
            unsafe {
                let _ = DisconnectNamedPipe(pipe);
                let _ = CloseHandle(pipe);
            }
            break;
        }

        // Handle the request synchronously, then disconnect + close +
        // loop back to create a fresh instance.
        if let Err(e) = handle_connection(pipe, &ownership) {
            eprintln!("[mxc-learning-mode-broker] handler error: {e}");
        }
        unsafe {
            let _ = DisconnectNamedPipe(pipe);
            let _ = CloseHandle(pipe);
        }
    }

    Ok(())
}

/// Wakes a thread blocked in `ConnectNamedPipe` inside the accept loop by
/// making a throwaway client connection to our own pipe. Paired with the
/// stop flag, this lets `Stop`/`Shutdown` return promptly instead of
/// hanging until the next real client connects.
///
/// Best-effort: any error is ignored. If the accept loop is between
/// iterations (not yet blocked) the connection may not land, but the loop
/// re-checks the stop flag on its next iteration regardless.
pub fn wake_accept_loop() {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;

    // SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION so the server's
    // `ImpersonateNamedPipeClient` succeeds cleanly on the wake path.
    const SECURITY_SQOS_PRESENT: u32 = 0x0010_0000;
    const SECURITY_IMPERSONATION: u32 = 0x0002_0000;

    for _ in 0..5 {
        match OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION)
            .open(PIPE_NAME)
        {
            Ok(f) => {
                drop(f);
                return;
            }
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn handle_connection(pipe: HANDLE, ownership: &OwnershipMap) -> Result<(), Box<dyn Error>> {
    // Identify the caller *before* reading the request so a malformed
    // or oversized message can't bypass the security check.
    let caller = match caller_context::from_pipe(pipe) {
        Ok(c) => c,
        Err(e) => {
            // Without a verified identity we can't safely service this
            // connection. Reply with a generic permission error and
            // drop the connection.
            let resp = BrokerResponse::OpenDenialSession(OpenDenialSessionResponse::Error {
                code: error_code::UNAUTHORIZED.to_string(),
                message: format!("caller identification failed: {e}"),
            });
            let body = serde_json::to_vec(&resp)?;
            let mut written = 0u32;
            unsafe {
                let _ = WriteFile(pipe, Some(&body), Some(&mut written), None);
                let _ = FlushFileBuffers(pipe);
            }
            return Err(format!("caller_context: {e}").into());
        }
    };

    // Message-mode pipe: a single logical request may still span multiple
    // `ReadFile` calls if it exceeds `PIPE_BUFFER_SIZE` — each partial read
    // returns `ERROR_MORE_DATA` until the final chunk. Reassemble the full
    // message, bounded by `MAX_REQUEST_SIZE`, so an oversized request yields
    // a structured `BAD_REQUEST` instead of a dropped connection.
    let mut buf = vec![0u8; PIPE_BUFFER_SIZE as usize];
    let mut message: Vec<u8> = Vec::new();

    loop {
        let mut bytes_read = 0u32;
        let read_ok = unsafe { ReadFile(pipe, Some(&mut buf), Some(&mut bytes_read), None) };
        message.extend_from_slice(&buf[..bytes_read as usize]);

        if read_ok.is_ok() {
            break;
        }

        let last = unsafe { GetLastError() };
        match last {
            ERROR_NO_DATA => {
                // Client closed without sending — nothing to reply to.
                return Ok(());
            }
            ERROR_MORE_DATA => {
                if message.len() > MAX_REQUEST_SIZE {
                    // Refuse oversized requests with a structured error
                    // rather than silently dropping the connection.
                    let resp =
                        BrokerResponse::OpenDenialSession(OpenDenialSessionResponse::Error {
                            code: error_code::BAD_REQUEST.to_string(),
                            message: format!("request exceeds maximum of {MAX_REQUEST_SIZE} bytes"),
                        });
                    if let Ok(body) = serde_json::to_vec(&resp) {
                        let mut written = 0u32;
                        unsafe {
                            let _ = WriteFile(pipe, Some(&body), Some(&mut written), None);
                            let _ = FlushFileBuffers(pipe);
                        }
                    }
                    return Ok(());
                }
                // More chunks pending — keep reading.
            }
            _ => return Err(format!("ReadFile failed: {last:?}").into()),
        }
    }

    let response = handle_request(&message, &caller, pipe, ownership);
    let response_bytes = serde_json::to_vec(&response)?;

    let mut written = 0u32;
    unsafe {
        WriteFile(pipe, Some(&response_bytes), Some(&mut written), None)
            .map_err(|e| format!("WriteFile failed: {e}"))?;
        let _ = FlushFileBuffers(pipe);
    }

    Ok(())
}

/// Handles a parsed request: dispatches on the [`BrokerRequest`] variant.
/// For `OpenDenialSession`, creates an ETW session via the privileged
/// `etw_session` module and returns its name. For `ExtendDenialSession`,
/// updates the running session's PID filter.
///
/// On any failure tears down (or refuses to extend) without leaking ETW
/// slots.
fn handle_request(
    bytes: &[u8],
    caller: &CallerContext,
    pipe: HANDLE,
    ownership: &OwnershipMap,
) -> BrokerResponse {
    let req: BrokerRequest = match serde_json::from_slice(bytes) {
        Ok(r) => r,
        Err(e) => {
            return BrokerResponse::OpenDenialSession(OpenDenialSessionResponse::Error {
                code: error_code::BAD_REQUEST.to_string(),
                message: format!("malformed request: {e}"),
            });
        }
    };

    match req {
        BrokerRequest::OpenDenialSession(open_req) => {
            BrokerResponse::OpenDenialSession(handle_open(open_req, caller, pipe, ownership))
        }
        BrokerRequest::ExtendDenialSession(ext_req) => {
            BrokerResponse::ExtendDenialSession(handle_extend(ext_req, caller, pipe, ownership))
        }
    }
}

fn handle_open(
    req: OpenDenialSessionRequest,
    caller: &CallerContext,
    pipe: HANDLE,
    ownership: &OwnershipMap,
) -> OpenDenialSessionResponse {
    if req.protocol_version != PROTOCOL_VERSION {
        return OpenDenialSessionResponse::Error {
            code: error_code::VERSION_MISMATCH.to_string(),
            message: format!(
                "client protocol version {} does not match server {PROTOCOL_VERSION}",
                req.protocol_version
            ),
        };
    }

    // Security check #1: under the caller's impersonation token, the
    // caller must be able to OpenProcess the target. This delegates
    // "who can audit whom" to Windows' own ACL system, which already
    // models sandboxed-workload tokens correctly.
    if !caller_context::caller_can_query_pid(pipe, req.target_pid) {
        return OpenDenialSessionResponse::Error {
            code: error_code::UNAUTHORIZED.to_string(),
            message: format!(
                "caller cannot open target PID {} (no PROCESS_QUERY_LIMITED_INFORMATION access)",
                req.target_pid
            ),
        };
    }

    match crate::etw_session::create_denial_session(req.target_pid, req.package_sid.as_deref()) {
        Ok(session) => {
            let name = session.name.clone();
            // Record session ownership so a later ExtendDenialSession
            // can only be honoured for the same caller SID.
            if let Ok(mut map) = ownership.lock() {
                map.insert(name.clone(), caller.sid.clone());
            }
            // Phase 2.2: broker hands ownership of the session lifecycle
            // to the caller. By dropping `session` here without calling
            // `.stop()` we leave the ETW session active in the kernel —
            // intentional. The caller's `wxc-exec` invocation owns
            // `ControlTraceW(STOP)` at workload exit. If the caller
            // crashes the session leaks until the next reboot; tracked
            // as an open issue in the prototype plan.
            std::mem::forget(session);
            OpenDenialSessionResponse::Ok { session_name: name }
        }
        Err(e) => OpenDenialSessionResponse::Error {
            code: error_code::WIN32_FAILURE.to_string(),
            message: format!(
                "failed to create denial session for PID {}: {}",
                req.target_pid, e
            ),
        },
    }
}

fn handle_extend(
    req: ExtendDenialSessionRequest,
    caller: &CallerContext,
    pipe: HANDLE,
    ownership: &OwnershipMap,
) -> ExtendDenialSessionResponse {
    if req.protocol_version != PROTOCOL_VERSION {
        return ExtendDenialSessionResponse::Error {
            code: error_code::VERSION_MISMATCH.to_string(),
            message: format!(
                "client protocol version {} does not match server {PROTOCOL_VERSION}",
                req.protocol_version
            ),
        };
    }

    if req.pids.is_empty() {
        return ExtendDenialSessionResponse::Error {
            code: error_code::BAD_REQUEST.to_string(),
            message: "extendDenialSession requires a non-empty pids list".into(),
        };
    }

    // Security check #2: the SID that opened this session must match
    // the SID extending it. Without this, an attacker who enumerated
    // session names (e.g. via `logman query -ets`) could call
    // ExtendDenialSession to add their PID to someone else's filter
    // and observe their denials.
    let recorded_sid = ownership
        .lock()
        .ok()
        .and_then(|m| m.get(&req.session_name).cloned());
    match recorded_sid {
        Some(sid) if sid == caller.sid => {}
        Some(_) => {
            return ExtendDenialSessionResponse::Error {
                code: error_code::UNAUTHORIZED.to_string(),
                message: format!("caller is not the owner of session `{}`", req.session_name),
            };
        }
        None => {
            return ExtendDenialSessionResponse::Error {
                code: error_code::UNKNOWN_SESSION.to_string(),
                message: format!(
                    "session `{}` is not known to this broker instance",
                    req.session_name
                ),
            };
        }
    }

    // Security check #3: each PID being added to the filter must be
    // queryable by the caller. Same rationale as the open check.
    if !caller_context::caller_can_query_all_pids(pipe, &req.pids) {
        return ExtendDenialSessionResponse::Error {
            code: error_code::UNAUTHORIZED.to_string(),
            message:
                "one or more PIDs in the extend request are not accessible to the caller's token"
                    .into(),
        };
    }

    match crate::etw_session::extend_denial_session(&req.session_name, &req.pids) {
        Ok(()) => ExtendDenialSessionResponse::Ok,
        Err(e) => {
            // Distinguish "session doesn't exist" (caller passed a bad
            // name) from generic Win32 failures so SDK consumers can
            // surface a clearer error.
            let code = if e.code == windows::Win32::Foundation::ERROR_WMI_INSTANCE_NOT_FOUND.0 {
                error_code::UNKNOWN_SESSION
            } else {
                error_code::WIN32_FAILURE
            };
            ExtendDenialSessionResponse::Error {
                code: code.to_string(),
                message: format!(
                    "failed to extend denial session `{}` to {} PID(s): {}",
                    req.session_name,
                    req.pids.len(),
                    e
                ),
            }
        }
    }
}

fn create_pipe_instance(first: bool) -> Result<HANDLE, Box<dyn Error>> {
    let name_wide: Vec<u16> = PIPE_NAME.encode_utf16().chain(std::iter::once(0)).collect();

    // Build a SECURITY_DESCRIPTOR from the SDDL string. The descriptor is
    // owned by the OS allocator (LocalAlloc); we hand its pointer to
    // SECURITY_ATTRIBUTES for the lifetime of CreateNamedPipeW. The pipe
    // handle gets its own copy at creation, so the SDDL allocation can
    // be freed after.
    let sddl_wide: Vec<u16> = PIPE_SDDL.encode_utf16().chain(std::iter::once(0)).collect();
    let mut psd = PSECURITY_DESCRIPTOR::default();

    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_wide.as_ptr()),
            SDDL_REVISION_1,
            &mut psd,
            None,
        )
        .map_err(|e| format!("SDDL conversion failed: {e}"))?;
    }

    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: psd.0,
        bInheritHandle: false.into(),
    };

    // `PIPE_ACCESS_DUPLEX` because we read the request and write the
    // response on the same handle. `FILE_FLAG_FIRST_PIPE_INSTANCE` on the
    // first instance only — prevents another process from squatting on
    // our well-known pipe name.
    let mut open_mode = FILE_FLAGS_AND_ATTRIBUTES(PIPE_ACCESS_DUPLEX.0);
    if first {
        // FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000.
        open_mode = FILE_FLAGS_AND_ATTRIBUTES(open_mode.0 | 0x0008_0000);
    }

    let handle = unsafe {
        CreateNamedPipeW(
            PCWSTR(name_wide.as_ptr()),
            open_mode,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            PIPE_BUFFER_SIZE,
            PIPE_BUFFER_SIZE,
            0,
            Some(&sa),
        )
    };

    // Free the SDDL-derived SD now that the pipe has its own copy.
    // ConvertStringSecurityDescriptorToSecurityDescriptorW allocates the
    // descriptor with LocalAlloc; release it with LocalFree once
    // CreateNamedPipeW has captured its own copy into the pipe object.
    if !psd.0.is_null() {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(psd.0)));
        }
    }

    if handle == INVALID_HANDLE_VALUE {
        let last = unsafe { GetLastError() };
        return Err(format!("CreateNamedPipeW failed: {last:?}").into());
    }

    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use learning_mode_broker_protocol::{
        BrokerRequest, ExtendDenialSessionRequest, OpenDenialSessionRequest, PROTOCOL_VERSION,
    };

    fn extract_open(resp: BrokerResponse) -> OpenDenialSessionResponse {
        match resp {
            BrokerResponse::OpenDenialSession(r) => r,
            other => panic!("expected OpenDenialSession variant, got {other:?}"),
        }
    }

    fn extract_extend(resp: BrokerResponse) -> ExtendDenialSessionResponse {
        match resp {
            BrokerResponse::ExtendDenialSession(r) => r,
            other => panic!("expected ExtendDenialSession variant, got {other:?}"),
        }
    }

    /// Synthetic caller context for unit tests. Real callers come from
    /// `caller_context::from_pipe`.
    fn test_caller() -> CallerContext {
        CallerContext {
            pid: std::process::id(),
            sid: "S-1-5-21-test-caller".to_string(),
        }
    }

    /// Dummy pipe handle for unit tests that don't exercise the
    /// impersonate-then-OpenProcess check (those are covered on the
    /// VM since they need a real impersonation token).
    fn dummy_pipe() -> HANDLE {
        HANDLE::default()
    }

    fn empty_ownership() -> OwnershipMap {
        Arc::new(Mutex::new(HashMap::new()))
    }

    #[test]
    fn handle_request_rejects_bad_json() {
        match extract_open(handle_request(
            b"not json at all",
            &test_caller(),
            dummy_pipe(),
            &empty_ownership(),
        )) {
            OpenDenialSessionResponse::Error { code, .. } => {
                assert_eq!(code, error_code::BAD_REQUEST);
            }
            _ => panic!("expected Error variant"),
        }
    }

    #[test]
    fn handle_open_rejects_version_mismatch() {
        let req = BrokerRequest::OpenDenialSession(OpenDenialSessionRequest {
            protocol_version: PROTOCOL_VERSION + 99,
            target_pid: 1,
            package_sid: None,
        });
        let bytes = serde_json::to_vec(&req).unwrap();
        match extract_open(handle_request(
            &bytes,
            &test_caller(),
            dummy_pipe(),
            &empty_ownership(),
        )) {
            OpenDenialSessionResponse::Error { code, .. } => {
                assert_eq!(code, error_code::VERSION_MISMATCH);
            }
            _ => panic!("expected Error variant"),
        }
    }

    #[test]
    fn handle_open_rejects_inaccessible_target_pid() {
        // PID 0 (the idle process) can't be opened by anyone. With a
        // dummy pipe handle the impersonation will also fail-closed,
        // so we expect a UNAUTHORIZED error.
        let req = BrokerRequest::OpenDenialSession(OpenDenialSessionRequest {
            protocol_version: PROTOCOL_VERSION,
            target_pid: 0,
            package_sid: None,
        });
        let bytes = serde_json::to_vec(&req).unwrap();
        match extract_open(handle_request(
            &bytes,
            &test_caller(),
            dummy_pipe(),
            &empty_ownership(),
        )) {
            OpenDenialSessionResponse::Error { code, .. } => {
                assert_eq!(code, error_code::UNAUTHORIZED);
            }
            _ => panic!("expected Error variant for inaccessible PID"),
        }
    }

    #[test]
    fn handle_extend_rejects_version_mismatch() {
        let req = BrokerRequest::ExtendDenialSession(ExtendDenialSessionRequest {
            protocol_version: PROTOCOL_VERSION + 99,
            session_name: "mxc-denials-xxx".into(),
            pids: vec![1, 2],
        });
        let bytes = serde_json::to_vec(&req).unwrap();
        match extract_extend(handle_request(
            &bytes,
            &test_caller(),
            dummy_pipe(),
            &empty_ownership(),
        )) {
            ExtendDenialSessionResponse::Error { code, .. } => {
                assert_eq!(code, error_code::VERSION_MISMATCH);
            }
            _ => panic!("expected Error variant"),
        }
    }

    #[test]
    fn handle_extend_rejects_empty_pid_list() {
        let req = BrokerRequest::ExtendDenialSession(ExtendDenialSessionRequest {
            protocol_version: PROTOCOL_VERSION,
            session_name: "mxc-denials-xxx".into(),
            pids: vec![],
        });
        let bytes = serde_json::to_vec(&req).unwrap();
        match extract_extend(handle_request(
            &bytes,
            &test_caller(),
            dummy_pipe(),
            &empty_ownership(),
        )) {
            ExtendDenialSessionResponse::Error { code, .. } => {
                assert_eq!(code, error_code::BAD_REQUEST);
            }
            _ => panic!("expected Error variant"),
        }
    }

    #[test]
    fn handle_extend_rejects_unknown_session() {
        let req = BrokerRequest::ExtendDenialSession(ExtendDenialSessionRequest {
            protocol_version: PROTOCOL_VERSION,
            session_name: "mxc-denials-i-was-never-opened".into(),
            pids: vec![std::process::id()],
        });
        let bytes = serde_json::to_vec(&req).unwrap();
        match extract_extend(handle_request(
            &bytes,
            &test_caller(),
            dummy_pipe(),
            &empty_ownership(),
        )) {
            ExtendDenialSessionResponse::Error { code, .. } => {
                assert_eq!(code, error_code::UNKNOWN_SESSION);
            }
            _ => panic!("expected Error variant for unknown session"),
        }
    }

    #[test]
    fn handle_extend_rejects_different_caller_sid() {
        let ownership = empty_ownership();
        ownership.lock().unwrap().insert(
            "mxc-denials-shared".to_string(),
            "S-1-5-21-other-user".to_string(),
        );
        let req = BrokerRequest::ExtendDenialSession(ExtendDenialSessionRequest {
            protocol_version: PROTOCOL_VERSION,
            session_name: "mxc-denials-shared".into(),
            pids: vec![std::process::id()],
        });
        let bytes = serde_json::to_vec(&req).unwrap();
        match extract_extend(handle_request(
            &bytes,
            &test_caller(),
            dummy_pipe(),
            &ownership,
        )) {
            ExtendDenialSessionResponse::Error { code, message } => {
                assert_eq!(code, error_code::UNAUTHORIZED);
                assert!(
                    message.contains("not the owner"),
                    "unexpected message: {message}"
                );
            }
            _ => panic!("expected Error for SID mismatch"),
        }
    }
}
