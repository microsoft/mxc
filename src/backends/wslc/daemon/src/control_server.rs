// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Named-pipe control server: accepts phase-process connections, decodes one
//! [`DaemonRequest`] per connection, dispatches it to the WSLc worker via a
//! [`SessionHandle`], and writes back a [`DaemonResponse`] (plus a
//! [`StreamFrame`] stream for exec).
//!
//! One request per connection keeps the framing trivial and matches how the
//! state-aware client drives each lifecycle phase as a discrete call. Exec is
//! the exception: after an `Ok` admission it enters the [`StreamFrame`] data
//! phase (live stdio) until a terminal `Exit` / `Error`.
//!
//! SECURITY: every pipe instance is created with a protected DACL that grants
//! access to only the current user and Local SYSTEM (mirroring the owner-only
//! DACL stamped on the daemon's on-disk record), so no other Windows user can
//! connect to the control plane.

use std::ffi::c_void;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::Notify;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use wslc_common::daemon_protocol::{
    encode_frame, DaemonRequest, DaemonResponse, StreamFrame, MAX_FRAME_SIZE,
};

use crate::session_manager::{SessionHandle, WorkerError};

/// Bind the first pipe instance and build the owner-only security descriptor.
///
/// Called synchronously before the daemon record is published so a client never
/// discovers a `ready` record for a pipe that is not yet listening.
pub fn bind(pipe_name: &str) -> Result<(OwnerOnlySecurity, NamedPipeServer)> {
    let security = OwnerOnlySecurity::new().context("build owner-only pipe security")?;
    let first = create_secured_instance(pipe_name, &security, true)?;
    Ok((security, first))
}

/// Run the accept loop until `shutdown` is notified.
///
/// Keeps one un-connected server instance listening; when it connects, hand it
/// to a task and create the next instance so the next client is never refused.
/// `active_clients` tracks in-flight requests so the idle watchdog does not tear
/// the daemon down mid-request; `activity` is a monotonic connection counter the
/// watchdog compares across polls to catch bursts that start and finish between
/// two of its samples.
pub async fn run(
    session: SessionHandle,
    pipe_name: String,
    security: OwnerOnlySecurity,
    first_instance: NamedPipeServer,
    active_clients: Arc<AtomicUsize>,
    activity: Arc<AtomicU64>,
    shutdown: Arc<Notify>,
) -> Result<()> {
    let mut server = first_instance;

    loop {
        tokio::select! {
            connect = server.connect() => {
                if let Err(e) = connect {
                    eprintln!("[wslc-daemon] pipe connect error: {e}");
                    server = create_secured_instance(&pipe_name, &security, false)?;
                    continue;
                }
                let connected = server;
                // Create the next instance before servicing this one.
                server = create_secured_instance(&pipe_name, &security, false)?;
                let session = session.clone();
                let active = active_clients.clone();
                // Record the connection so an idle streak that spans this
                // request is invalidated even if it completes between polls.
                activity.fetch_add(1, Ordering::SeqCst);
                active.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    if let Err(e) = handle_client(connected, session).await {
                        eprintln!("[wslc-daemon] client connection error: {e:#}");
                    }
                    active.fetch_sub(1, Ordering::SeqCst);
                });
            }
            _ = shutdown.notified() => break,
        }
    }
    Ok(())
}

/// Create one named-pipe server instance carrying the owner-only DACL.
fn create_secured_instance(
    pipe_name: &str,
    security: &OwnerOnlySecurity,
    first: bool,
) -> Result<NamedPipeServer> {
    let mut attrs = security.attributes();
    // SAFETY: `attrs` is a valid SECURITY_ATTRIBUTES whose security descriptor
    // is owned by `security` and outlives this call.
    let server = unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .create_with_security_attributes_raw(
                pipe_name,
                &mut attrs as *mut SECURITY_ATTRIBUTES as *mut c_void,
            )
    }?;
    Ok(server)
}

/// Owns a `PSECURITY_DESCRIPTOR` describing a protected DACL that grants the
/// current user and Local SYSTEM full access, and nothing else.
pub(crate) struct OwnerOnlySecurity {
    psd: PSECURITY_DESCRIPTOR,
}

// SAFETY: `psd` is a self-contained LocalAlloc'd security descriptor with no
// thread affinity; ownership can move across threads freely.
unsafe impl Send for OwnerOnlySecurity {}

impl OwnerOnlySecurity {
    fn new() -> Result<Self> {
        let sid = current_user_sid_string()?;
        let sddl = format!("D:P(A;;FA;;;{sid})(A;;FA;;;SY)");
        let mut wide: Vec<u16> = sddl.encode_utf16().collect();
        wide.push(0);

        let mut psd = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
        // SAFETY: `wide` is a NUL-terminated UTF-16 SDDL string; `psd` receives a
        // LocalAlloc'd descriptor freed in `Drop`.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &mut psd,
                None,
            )
        }
        .context("ConvertStringSecurityDescriptorToSecurityDescriptorW")?;
        if psd.0.is_null() {
            bail!("ConvertStringSecurityDescriptorToSecurityDescriptorW returned NULL");
        }
        Ok(Self { psd })
    }

    /// A `SECURITY_ATTRIBUTES` referencing the owned descriptor. The returned
    /// value borrows `self`; keep `self` alive while it is in use.
    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.psd.0,
            bInheritHandle: false.into(),
        }
    }
}

impl Drop for OwnerOnlySecurity {
    fn drop(&mut self) {
        if !self.psd.0.is_null() {
            // SAFETY: `psd` was allocated by
            // `ConvertStringSecurityDescriptorToSecurityDescriptorW`, which
            // documents `LocalFree` as the matching deallocator.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.psd.0)));
            }
        }
    }
}

/// Resolve the current process token's user SID as an SDDL string (e.g. `S-1-5-...`).
fn current_user_sid_string() -> Result<String> {
    // SAFETY: standard token-query sequence; every raw pointer is backed by a
    // live local, and both the token handle and the LocalAlloc'd SID string are
    // released before returning.
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .context("OpenProcessToken")?;

        // First call sizes the buffer (expected to fail with insufficient buffer).
        let mut len = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
        let mut buf = vec![0u8; len as usize];
        let info = GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut c_void),
            len,
            &mut len,
        );
        let _ = CloseHandle(token);
        info.context("GetTokenInformation(TokenUser)")?;

        let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut sid_wstr = PWSTR::null();
        ConvertSidToStringSidW(token_user.User.Sid, &mut sid_wstr)
            .context("ConvertSidToStringSidW")?;
        let sid = sid_wstr
            .to_string()
            .context("SID string was not valid UTF-16")?;
        let _ = LocalFree(Some(HLOCAL(sid_wstr.0 as *mut c_void)));
        Ok(sid)
    }
}

/// Service exactly one request on a freshly-connected pipe instance.
async fn handle_client(mut pipe: NamedPipeServer, session: SessionHandle) -> Result<()> {
    let request: DaemonRequest = read_frame(&mut pipe).await?;
    match request {
        DaemonRequest::Ping => {
            write_frame(&mut pipe, &DaemonResponse::Pong).await?;
        }
        DaemonRequest::Provision(config) => {
            let resp = match session.provision(config).await {
                Ok(sandbox_id) => DaemonResponse::Provisioned { sandbox_id },
                Err(e) => worker_err_response(e),
            };
            write_frame(&mut pipe, &resp).await?;
        }
        DaemonRequest::Start(config) => {
            let resp = ok_or_err(session.start(config).await);
            write_frame(&mut pipe, &resp).await?;
        }
        DaemonRequest::Stop(config) => {
            let resp = ok_or_err(session.stop(config).await);
            write_frame(&mut pipe, &resp).await?;
        }
        DaemonRequest::Deprovision(config) => {
            let resp = ok_or_err(session.deprovision(config).await);
            write_frame(&mut pipe, &resp).await?;
        }
        DaemonRequest::Exec(config) => {
            handle_exec(pipe, session, config).await?;
        }
    }
    Ok(())
}

/// Exec: validate-then-admit, then stream the run's outcome as [`StreamFrame`]s.
///
/// The sandbox is validated (exists + started) *before* the `Ok` admission is
/// written, and — critically — admission is **atomic** with the start of the
/// run on the worker thread (see [`SessionHandle::exec`]): the worker validates
/// and begins running within one command handler, so no `Stop`/`Deprovision`
/// can invalidate the checked state between the admission and the run. An
/// unknown/not-started sandbox therefore comes back as a pre-admission typed
/// [`DaemonResponse::Err`] rather than a post-admission stream `Error` frame.
///
/// TODO(fill-in): bidirectional live stdio (client `Stdin` frames -> process,
/// process stdout/stderr -> `Stdout`/`Stderr` frames). The skeleton runs the
/// command to completion and emits only the terminal frame.
async fn handle_exec(
    mut pipe: NamedPipeServer,
    session: SessionHandle,
    config: wslc_common::daemon_protocol::ExecConfig,
) -> Result<()> {
    // Await the worker's admission decision before writing anything: a rejected
    // exec is a pre-admission typed error, never a post-admission stream frame.
    let done = match session.exec(config).await {
        Ok(done) => done,
        Err(e) => {
            write_frame(&mut pipe, &worker_err_response(e)).await?;
            return Ok(());
        }
    };
    write_frame(&mut pipe, &DaemonResponse::Ok).await?;
    let terminal = match done.await {
        Ok(Ok(code)) => StreamFrame::Exit { code },
        Ok(Err(e)) => StreamFrame::Error {
            message: e.to_string(),
        },
        Err(_) => StreamFrame::Error {
            message: "WSLc worker dropped the exec reply channel".to_string(),
        },
    };
    write_frame(&mut pipe, &terminal).await?;
    Ok(())
}

/// Map a worker `Result<()>` to an `Ok` / typed `Err` response.
fn ok_or_err(result: Result<(), WorkerError>) -> DaemonResponse {
    match result {
        Ok(()) => DaemonResponse::Ok,
        Err(e) => worker_err_response(e),
    }
}

/// Build a [`DaemonResponse::Err`] carrying the worker error's protocol `kind`.
fn worker_err_response(e: WorkerError) -> DaemonResponse {
    DaemonResponse::Err {
        kind: e.kind(),
        message: e.to_string(),
    }
}

/// Read one length-prefixed frame and deserialise it.
async fn read_frame<T: DeserializeOwned>(pipe: &mut NamedPipeServer) -> Result<T> {
    let mut len_buf = [0u8; 4];
    pipe.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_FRAME_SIZE {
        bail!("incoming frame length {len} exceeds maximum {MAX_FRAME_SIZE}");
    }
    let mut body = vec![0u8; len];
    pipe.read_exact(&mut body).await?;
    Ok(serde_json::from_slice(&body)?)
}

/// Serialise `msg` and write it as a length-prefixed frame.
async fn write_frame<T: Serialize>(pipe: &mut NamedPipeServer, msg: &T) -> Result<()> {
    let frame = encode_frame(msg)?;
    pipe.write_all(&frame).await?;
    pipe.flush().await?;
    Ok(())
}
