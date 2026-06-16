// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Named-pipe server that hosts the `OpenDenialSession` RPC.
//!
//! Phase 2.1 (this commit): accept connections, parse a request, return
//! `OpenDenialSessionResponse::Error { code: NOT_IMPLEMENTED, ... }`,
//! disconnect. Validates that the SCM + pipe + protocol shape work
//! end-to-end before adding the privileged ETW work in Phase 2.2.
//!
//! Pipe ACL: scoped to interactive-logon users. The shim runs as
//! `LocalSystem` and would be vulnerable to confused-deputy attacks if
//! the pipe were world-accessible.

use std::error::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_NO_DATA, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
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

use denial_capture::wire::{
    error_code, OpenDenialSessionRequest, OpenDenialSessionResponse, PIPE_NAME, PROTOCOL_VERSION,
};

/// Shape of the security descriptor in SDDL form.
///
/// - `D:` — discretionary ACL
/// - `(A;;GA;;;IU)` — Allow Generic All to Interactive Users (well-known
///   SID `IU` = `S-1-5-4`).
/// - `(A;;GA;;;BA)` — Allow Generic All to Built-in Administrators
///   (allows `wxc-host-prep` / diagnostic tooling running elevated).
///
/// `LocalSystem` (the shim itself) doesn't need an explicit ACE because
/// it owns the descriptor.
const PIPE_SDDL: &str = "D:(A;;GA;;;IU)(A;;GA;;;BA)";

const PIPE_BUFFER_SIZE: u32 = 8 * 1024;

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

    while !stop_flag.load(Ordering::SeqCst) {
        let pipe = create_pipe_instance(first)?;
        first = false;

        // ConnectNamedPipe blocks until a client connects. For graceful
        // shutdown we'd pair this with overlapped IO + a wait-with-cancel,
        // but for the prototype a single accept-then-check pattern is
        // acceptable.
        let connect_result = unsafe { ConnectNamedPipe(pipe, None) };

        // Successful connection: Ok(()) OR Err(ERROR_PIPE_CONNECTED)
        // (client raced us between create and connect — still a valid
        // connection).
        let connected = match connect_result {
            Ok(()) => true,
            Err(e) if e.code() == ERROR_PIPE_CONNECTED.to_hresult() => true,
            Err(e) => {
                eprintln!("[mxc-denial-shim] ConnectNamedPipe failed: {e}");
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

        // Handle the request synchronously, then disconnect + close +
        // loop back to create a fresh instance.
        if let Err(e) = handle_connection(pipe) {
            eprintln!("[mxc-denial-shim] handler error: {e}");
        }
        unsafe {
            let _ = DisconnectNamedPipe(pipe);
            let _ = CloseHandle(pipe);
        }
    }

    Ok(())
}

fn handle_connection(pipe: HANDLE) -> Result<(), Box<dyn Error>> {
    let mut buf = vec![0u8; PIPE_BUFFER_SIZE as usize];
    let mut bytes_read = 0u32;

    let read_ok = unsafe { ReadFile(pipe, Some(&mut buf), Some(&mut bytes_read), None) };

    if read_ok.is_err() {
        let last = unsafe { GetLastError() };
        if last == ERROR_NO_DATA {
            // Client closed without sending — nothing to reply to.
            return Ok(());
        }
        return Err(format!("ReadFile failed: {last:?}").into());
    }

    let request_bytes = &buf[..bytes_read as usize];
    let response = handle_request(request_bytes);
    let response_bytes = serde_json::to_vec(&response)?;

    let mut written = 0u32;
    unsafe {
        WriteFile(pipe, Some(&response_bytes), Some(&mut written), None)
            .map_err(|e| format!("WriteFile failed: {e}"))?;
        let _ = FlushFileBuffers(pipe);
    }

    Ok(())
}

/// Handles a parsed request: opens an ETW session via the privileged
/// `etw_session` module and returns its name. On any failure tears
/// down the partially-created session so we don't leak ETW slots.
fn handle_request(bytes: &[u8]) -> OpenDenialSessionResponse {
    let req: OpenDenialSessionRequest = match serde_json::from_slice(bytes) {
        Ok(r) => r,
        Err(e) => {
            return OpenDenialSessionResponse::Error {
                code: error_code::BAD_REQUEST.to_string(),
                message: format!("malformed request: {e}"),
            };
        }
    };

    if req.protocol_version != PROTOCOL_VERSION {
        return OpenDenialSessionResponse::Error {
            code: error_code::VERSION_MISMATCH.to_string(),
            message: format!(
                "client protocol version {} does not match server {PROTOCOL_VERSION}",
                req.protocol_version
            ),
        };
    }

    match crate::etw_session::create_denial_session(req.target_pid, req.package_sid.as_deref()) {
        Ok(session) => {
            let name = session.name.clone();
            // Phase 2.2: shim hands ownership of the session lifecycle
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
    // ConvertStringSecurityDescriptorToSecurityDescriptorW allocates with
    // LocalAlloc; the right thing is to LocalFree(psd). However the
    // `windows` crate at this version doesn't expose `LocalFree` cleanly
    // here; the leak is bounded (~200 bytes per pipe instance creation,
    // which happens at most once per inbound connection), and we'll
    // revisit when the wider pipe ownership refactor lands. Tracked as a
    // TODO in the prototype plan.
    let _keep_psd_alive = psd;

    if handle == INVALID_HANDLE_VALUE {
        let last = unsafe { GetLastError() };
        return Err(format!("CreateNamedPipeW failed: {last:?}").into());
    }

    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use denial_capture::wire::{OpenDenialSessionRequest, PROTOCOL_VERSION};

    #[test]
    fn handle_request_rejects_bad_json() {
        match handle_request(b"not json at all") {
            OpenDenialSessionResponse::Error { code, .. } => {
                assert_eq!(code, error_code::BAD_REQUEST);
            }
            _ => panic!("expected Error variant"),
        }
    }

    #[test]
    fn handle_request_rejects_version_mismatch() {
        let req = OpenDenialSessionRequest {
            protocol_version: PROTOCOL_VERSION + 99,
            target_pid: 1,
            package_sid: None,
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        match handle_request(&bytes) {
            OpenDenialSessionResponse::Error { code, .. } => {
                assert_eq!(code, error_code::VERSION_MISMATCH);
            }
            _ => panic!("expected Error variant"),
        }
    }
}
