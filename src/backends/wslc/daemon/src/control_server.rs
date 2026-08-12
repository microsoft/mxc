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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::{oneshot, Semaphore};
use tokio::task::JoinSet;
use tokio::time::timeout;
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

use wslc_common::container_steps::OutStream;
use wslc_common::daemon_protocol::{
    encode_frame, DaemonRequest, DaemonResponse, StreamFrame, MAX_FRAME_SIZE,
};

use crate::session_manager::{ExecStream, SessionHandle, WorkerError};

/// Upper bound on concurrently-serviced client connections. At capacity the
/// accept loop applies backpressure (a new connection waits for a slot) instead
/// of spawning an unbounded number of handler tasks.
const MAX_CONCURRENT_CLIENTS: usize = 128;

/// Deadline for a freshly-connected client to send its first (request) frame. A
/// client that connects and then stalls must not pin a handler task — and a
/// concurrency slot — indefinitely.
const FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(30);

/// Bound on how long shutdown waits for in-flight handlers to finish before
/// abandoning them, so a wedged handler cannot block daemon exit forever.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Bounded-backoff retry budget for recreating a control-pipe instance after a
/// transient create failure (handle/resource exhaustion). A single transient
/// hiccup must not tear the daemon — and every live sandbox — down; only a
/// failure that persists past the whole budget is treated as fatal.
const INSTANCE_RETRY_ATTEMPTS: u32 = 5;
const INSTANCE_RETRY_BACKOFF: Duration = Duration::from_millis(50);
const INSTANCE_RETRY_MAX_BACKOFF: Duration = Duration::from_millis(500);

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
/// the daemon down mid-request. Concurrency is bounded by a semaphore, and on
/// shutdown all in-flight handlers are drained before returning so the caller
/// can release the WSLc session without racing a live handler. `activity` is a
/// monotonic connection counter the watchdog compares across polls to catch
/// bursts that start and finish between two of its samples.
pub async fn run(
    session: SessionHandle,
    pipe_name: String,
    security: OwnerOnlySecurity,
    first_instance: NamedPipeServer,
    signals: crate::DaemonSignals,
) -> Result<()> {
    let crate::DaemonSignals {
        active_clients,
        activity,
        shutdown,
        draining,
    } = signals;
    let mut server = first_instance;
    let limiter = Arc::new(Semaphore::new(MAX_CONCURRENT_CLIENTS));
    let mut clients: JoinSet<()> = JoinSet::new();

    // A create-instance failure that persists past its retry budget is fatal:
    // we can no longer listen for new clients. Record it, break, then drain and
    // surface it after in-flight handlers finish — never mid-loop, so an already
    // accepted client is not abandoned.
    let mut fatal: Option<anyhow::Error> = None;

    loop {
        tokio::select! {
            // Bias toward shutdown: once the watchdog signals, prefer tearing
            // down over accepting a connection that raced the final idle sample.
            biased;

            _ = shutdown.notified() => break,
            connect = server.connect() => {
                if let Err(e) = connect {
                    eprintln!("[wslc-daemon] pipe connect error: {e}");
                    match create_secured_instance_retry(&pipe_name, &security).await {
                        Ok(next) => server = next,
                        Err(e) => {
                            fatal = Some(e.context("recreate control pipe after connect error"));
                            break;
                        }
                    }
                    continue;
                }
                // The watchdog may have entered the draining state after its
                // final sample but before this connection arrived. Refuse it
                // rather than provision into a session that is about to be
                // released, handing the client an ID that teardown invalidates.
                // The client re-spawns a fresh daemon once our record is gone.
                if draining.load(Ordering::SeqCst) {
                    break;
                }
                let connected = server;
                // Record the connection so an idle streak that spans this
                // request is invalidated even if it completes between polls.
                activity.fetch_add(1, Ordering::SeqCst);

                // Recreate the next listening instance before servicing this one
                // so the next client is not refused. Transient failures are
                // retried with bounded backoff rather than tearing the whole
                // daemon down on a single accept-capacity hiccup.
                let next = create_secured_instance_retry(&pipe_name, &security).await;

                // Service the accepted client regardless of whether we managed to
                // recreate the next instance, so a fatal recreate failure below
                // does not abandon a connection we already accepted.
                spawn_client_handler(
                    &mut clients,
                    &limiter,
                    &session,
                    &active_clients,
                    connected,
                )
                .await;

                match next {
                    Ok(n) => server = n,
                    Err(e) => {
                        fatal = Some(e.context("recreate control pipe instance"));
                        break;
                    }
                }
            }
            // Reap finished handlers so the JoinSet does not accumulate.
            Some(_) = clients.join_next() => {}
        }
    }

    // Drain in-flight handlers so the caller never releases the session/worker
    // while a handler is still using it. Abandon anything past the deadline so a
    // wedged handler cannot block daemon exit forever.
    if timeout(DRAIN_TIMEOUT, async {
        while clients.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        eprintln!("[wslc-daemon] drain timed out; abandoning in-flight client handlers");
        clients.shutdown().await;
    }

    match fatal {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Acquire a concurrency slot (backpressure at capacity) and spawn a task to
/// service one accepted client connection, tracking it in `active_clients` for
/// the idle watchdog.
async fn spawn_client_handler(
    clients: &mut JoinSet<()>,
    limiter: &Arc<Semaphore>,
    session: &SessionHandle,
    active_clients: &Arc<AtomicUsize>,
    connected: NamedPipeServer,
) {
    // Bound concurrency: acquire a slot before spawning. At capacity this awaits
    // a free slot (backpressure) rather than spawning an unbounded task. The
    // semaphore is never closed, so acquire cannot fail.
    let permit = Semaphore::acquire_owned(limiter.clone())
        .await
        .expect("client semaphore is never closed");

    let session = session.clone();
    let active = active_clients.clone();
    active.fetch_add(1, Ordering::SeqCst);
    clients.spawn(async move {
        let _permit = permit;
        if let Err(e) = handle_client(connected, session).await {
            eprintln!("[wslc-daemon] client connection error: {e:#}");
        }
        active.fetch_sub(1, Ordering::SeqCst);
    });
}

/// Recreate a listening pipe instance, retrying transient failures with bounded
/// backoff so one accept-capacity/handle-exhaustion hiccup does not tear the
/// daemon — and every live sandbox — down. Only a failure that persists past the
/// whole budget is returned as an error.
async fn create_secured_instance_retry(
    pipe_name: &str,
    security: &OwnerOnlySecurity,
) -> Result<NamedPipeServer> {
    let mut backoff = INSTANCE_RETRY_BACKOFF;
    for attempt in 1..=INSTANCE_RETRY_ATTEMPTS {
        match create_secured_instance(pipe_name, security, false) {
            Ok(server) => return Ok(server),
            Err(e) if attempt < INSTANCE_RETRY_ATTEMPTS => {
                eprintln!(
                    "[wslc-daemon] pipe instance create failed \
                     (attempt {attempt}/{INSTANCE_RETRY_ATTEMPTS}): {e:#}; retrying in {backoff:?}"
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(INSTANCE_RETRY_MAX_BACKOFF);
            }
            Err(e) => return Err(e).context("pipe instance create exhausted retries"),
        }
    }
    unreachable!("the loop returns on the final attempt")
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

// SAFETY: the descriptor is immutable after construction — `attributes()` only
// copies the pointer into a `SECURITY_ATTRIBUTES` and the OS reads (never
// mutates) it, and the sole `LocalFree` happens in `Drop` on the owning thread.
// Shared `&OwnerOnlySecurity` access across threads (e.g. held across an await
// in the accept loop) is therefore race-free.
unsafe impl Sync for OwnerOnlySecurity {}

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
    // Bound the wait for the request frame so a client that connects and then
    // stalls cannot pin this handler (and its concurrency slot) indefinitely.
    let request: DaemonRequest = timeout(FIRST_FRAME_TIMEOUT, read_frame(&mut pipe))
        .await
        .context("timed out waiting for the client's first frame")??;
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

/// Exec: validate-then-admit, then stream the run's stdout/stderr live as
/// [`StreamFrame`]s, followed by a terminal frame.
///
/// The sandbox is validated (exists + started) *before* the `Ok` admission is
/// written, and — critically — admission is **atomic** with the start of the
/// run on the worker thread (see [`SessionHandle::exec`]): the worker validates
/// and begins running within one command handler, so no `Stop`/`Deprovision`
/// can invalidate the checked state between the admission and the run. An
/// unknown/not-started sandbox therefore comes back as a pre-admission typed
/// [`DaemonResponse::Err`] rather than a post-admission stream `Error` frame.
///
/// Output streaming (process -> `Stdout`/`Stderr`) is live. Client `Stdin`
/// frames are NOT forwarded: the WSLc SDK consumes all process IO handles once
/// any `WslcSetProcessSettingsCallbacks` is registered (the callback path this
/// live output streaming depends on), so `WslcGetProcessIOHandle(STDIN)` is
/// unavailable. Piped stdin would require a handle-mode rearchitecture (no
/// callbacks; `ReadFile` threads for stdout/stderr + `WriteFile` for stdin) and
/// is deferred to Tier 2 (see the 2c plan).
async fn handle_exec(
    mut pipe: NamedPipeServer,
    session: SessionHandle,
    config: wslc_common::daemon_protocol::ExecConfig,
) -> Result<()> {
    // Await the worker's admission decision before writing anything: a rejected
    // exec is a pre-admission typed error, never a post-admission stream frame.
    write_exec_result(&mut pipe, session.exec(config).await).await
}

/// Turn an exec **admission** outcome into the client's frame sequence, generic
/// over the transport so the protocol can be exercised over an in-memory duplex
/// in tests. On rejection it writes a single typed [`DaemonResponse::Err`]; on
/// admission it writes `Ok`, then pumps live `Stdout`/`Stderr` frames as output
/// arrives, and finally writes exactly one terminal [`StreamFrame`] — `Exit` on
/// success, `Error` on a run failure or a dropped completion channel.
async fn write_exec_result<S: AsyncWrite + Unpin>(
    pipe: &mut S,
    admission: Result<ExecStream, WorkerError>,
) -> Result<()> {
    let ExecStream {
        done,
        mut output,
        overflowed,
    } = match admission {
        Ok(stream) => stream,
        Err(e) => {
            write_frame(pipe, &worker_err_response(e)).await?;
            return Ok(());
        }
    };
    write_frame(pipe, &DaemonResponse::Ok).await?;

    // Pump live output until the run completes, then write exactly one terminal
    // frame. The select is **biased toward `done`** so a completed run always
    // makes progress to termination: on the deliberate kill/leak path the sink's
    // sender stays alive and can keep producing forever, and a biased-toward-
    // output loop would let that continuously non-empty queue starve the ready
    // `done` branch — the terminal frame would never be written and the client
    // would stream forever. While the run is in flight `done` is not ready, so
    // the fall-through streams live output as it arrives.
    //
    // Once `done` resolves we `close()` the receiver (so any leaked producer can
    // enqueue nothing further), drain only the already-queued bounded tail with
    // non-blocking `try_recv`, and terminate. On the normal path the run has
    // already stopped producing, so that tail is exactly the remaining real
    // output; the sink's sender also drops as the run returns, so `output` may
    // instead close first — the `None` arm handles that and awaits the exit code.
    let mut done = done;
    let terminal = loop {
        tokio::select! {
            biased;
            result = &mut done => {
                output.close();
                while let Ok(chunk) = output.try_recv() {
                    write_frame(pipe, &output_frame(chunk)).await?;
                }
                break terminal_frame(result, &overflowed);
            }
            chunk = output.recv() => match chunk {
                Some(chunk) => {
                    write_frame(pipe, &output_frame(chunk)).await?;
                }
                // Senders dropped before `done` fired (normal path): the run has
                // completed and every chunk is flushed. Await the exit code.
                None => break terminal_frame(done.await, &overflowed),
            },
        }
    };
    write_frame(pipe, &terminal).await?;
    Ok(())
}

/// Map a live-output chunk to its wire frame.
fn output_frame((kind, data): (OutStream, Vec<u8>)) -> StreamFrame {
    match kind {
        OutStream::Stdout => StreamFrame::Stdout { data },
        OutStream::Stderr => StreamFrame::Stderr { data },
    }
}

/// Choose the exec's terminal [`StreamFrame`]. A latched `overflowed` means the
/// sink had to drop live output because the client did not drain the daemon's
/// bounded queue fast enough, so a would-be clean [`StreamFrame::Exit`] is
/// reported as a truncation [`StreamFrame::Error`] instead — the client must not
/// treat a short stream as a successful, complete run. A genuine run failure
/// (already an `Error`) is strictly more informative and passes through
/// unchanged.
fn terminal_frame(
    result: Result<Result<i32, WorkerError>, oneshot::error::RecvError>,
    overflowed: &AtomicBool,
) -> StreamFrame {
    match exit_terminal(result) {
        StreamFrame::Exit { .. } if overflowed.load(Ordering::Relaxed) => StreamFrame::Error {
            message: "WSLc: live output was truncated — the client did not read the exec stream \
                      fast enough and the daemon's bounded output queue overflowed"
                .to_string(),
        },
        other => other,
    }
}

/// Map a completed exec's result (or a dropped completion channel) to its
/// terminal [`StreamFrame`].
fn exit_terminal(
    result: Result<Result<i32, WorkerError>, oneshot::error::RecvError>,
) -> StreamFrame {
    match result {
        Ok(Ok(code)) => StreamFrame::Exit { code },
        Ok(Err(e)) => StreamFrame::Error {
            message: e.to_string(),
        },
        Err(_) => StreamFrame::Error {
            message: "WSLc worker dropped the exec reply channel".to_string(),
        },
    }
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
async fn read_frame<S: AsyncRead + Unpin, T: DeserializeOwned>(pipe: &mut S) -> Result<T> {
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
async fn write_frame<S: AsyncWrite + Unpin, T: Serialize>(pipe: &mut S, msg: &T) -> Result<()> {
    let frame = encode_frame(msg)?;
    pipe.write_all(&frame).await?;
    pipe.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;
    use tokio::sync::mpsc;
    use wslc_common::daemon_protocol::ErrKind;

    /// Admit an exec whose output channel is already closed (no live output),
    /// so `write_exec_result` goes straight from `Ok` to the terminal frame.
    fn admitted_no_output(
        done: oneshot::Receiver<Result<i32, WorkerError>>,
    ) -> Result<ExecStream, WorkerError> {
        let (tx, output) = mpsc::channel(16);
        drop(tx);
        Ok(ExecStream {
            done,
            output,
            overflowed: Arc::new(AtomicBool::new(false)),
        })
    }

    /// A rejected admission (unknown sandbox) round-trips as a single typed
    /// `DaemonResponse::Err { NotProvisioned }` through frame encode → transport
    /// → decode, with no terminal frame following it.
    #[tokio::test]
    async fn exec_rejection_round_trips_as_typed_error() {
        let (mut server, mut client) = duplex(64 * 1024);
        let admission = Err(WorkerError::NotProvisioned("wslc:nope".to_string()));

        write_exec_result(&mut server, admission).await.unwrap();
        drop(server);

        let resp: DaemonResponse = read_frame(&mut client).await.unwrap();
        match resp {
            DaemonResponse::Err { kind, message } => {
                assert_eq!(kind, ErrKind::NotProvisioned);
                assert!(message.contains("wslc:nope"), "message was {message:?}");
            }
            other => panic!("expected a typed Err response, got {other:?}"),
        }
        // A rejected exec is a single frame: nothing else follows.
        assert!(read_frame::<_, StreamFrame>(&mut client).await.is_err());
    }

    /// The `NotStarted` admission contract has an SDK-free regression here: a
    /// provisioned-but-not-started sandbox surfaces as a typed pre-admission
    /// error, exercised without constructing a real container handle.
    #[tokio::test]
    async fn exec_not_started_round_trips_as_typed_error() {
        let (mut server, mut client) = duplex(64 * 1024);
        let admission = Err(WorkerError::NotStarted("wslc:cold".to_string()));

        write_exec_result(&mut server, admission).await.unwrap();
        drop(server);

        let resp: DaemonResponse = read_frame(&mut client).await.unwrap();
        assert_eq!(
            resp,
            DaemonResponse::Err {
                kind: ErrKind::NotStarted,
                message: "sandbox wslc:cold is not started".to_string(),
            }
        );
    }

    /// Dropping the completion sender after admission must produce exactly one
    /// terminal `StreamFrame::Error` — never a hang or a malformed stream.
    #[tokio::test]
    async fn dropped_completion_channel_yields_single_error_terminal() {
        let (mut server, mut client) = duplex(64 * 1024);
        let (done_tx, done_rx) = oneshot::channel::<Result<i32, WorkerError>>();
        drop(done_tx);

        write_exec_result(&mut server, admitted_no_output(done_rx))
            .await
            .unwrap();
        drop(server);

        let admit: DaemonResponse = read_frame(&mut client).await.unwrap();
        assert_eq!(admit, DaemonResponse::Ok);
        let terminal: StreamFrame = read_frame(&mut client).await.unwrap();
        match terminal {
            StreamFrame::Error { message } => {
                assert!(
                    message.contains("dropped the exec reply channel"),
                    "message was {message:?}"
                );
            }
            other => panic!("expected a terminal Error frame, got {other:?}"),
        }
        // Exactly one terminal frame is emitted.
        assert!(read_frame::<_, StreamFrame>(&mut client).await.is_err());
    }

    /// A successful run writes admission `Ok` then a single `Exit` terminal
    /// carrying the process exit code.
    #[tokio::test]
    async fn successful_exec_writes_ok_then_exit() {
        let (mut server, mut client) = duplex(64 * 1024);
        let (done_tx, done_rx) = oneshot::channel::<Result<i32, WorkerError>>();
        done_tx.send(Ok(7)).unwrap();

        write_exec_result(&mut server, admitted_no_output(done_rx))
            .await
            .unwrap();
        drop(server);

        let admit: DaemonResponse = read_frame(&mut client).await.unwrap();
        assert_eq!(admit, DaemonResponse::Ok);
        let terminal: StreamFrame = read_frame(&mut client).await.unwrap();
        assert_eq!(terminal, StreamFrame::Exit { code: 7 });
    }

    /// Live output is streamed as `Stdout`/`Stderr` frames — in the order the
    /// worker enqueued them — before the terminal `Exit`, so the client sees the
    /// run's output incrementally rather than as one buffered blob.
    #[tokio::test]
    async fn live_output_streams_before_exit() {
        let (mut server, mut client) = duplex(64 * 1024);
        let (done_tx, done_rx) = oneshot::channel::<Result<i32, WorkerError>>();
        let (out_tx, output) = mpsc::channel(16);

        // Enqueue interleaved output, then the exit code, then close the channel
        // (mirrors the worker: the sink's sender drops as the run returns).
        out_tx
            .try_send((OutStream::Stdout, b"hello ".to_vec()))
            .unwrap();
        out_tx
            .try_send((OutStream::Stderr, b"warn".to_vec()))
            .unwrap();
        out_tx
            .try_send((OutStream::Stdout, b"world".to_vec()))
            .unwrap();
        done_tx.send(Ok(0)).unwrap();
        drop(out_tx);

        write_exec_result(
            &mut server,
            Ok(ExecStream {
                done: done_rx,
                output,
                overflowed: Arc::new(AtomicBool::new(false)),
            }),
        )
        .await
        .unwrap();
        drop(server);

        let admit: DaemonResponse = read_frame(&mut client).await.unwrap();
        assert_eq!(admit, DaemonResponse::Ok);
        assert_eq!(
            read_frame::<_, StreamFrame>(&mut client).await.unwrap(),
            StreamFrame::Stdout {
                data: b"hello ".to_vec()
            }
        );
        assert_eq!(
            read_frame::<_, StreamFrame>(&mut client).await.unwrap(),
            StreamFrame::Stderr {
                data: b"warn".to_vec()
            }
        );
        assert_eq!(
            read_frame::<_, StreamFrame>(&mut client).await.unwrap(),
            StreamFrame::Stdout {
                data: b"world".to_vec()
            }
        );
        assert_eq!(
            read_frame::<_, StreamFrame>(&mut client).await.unwrap(),
            StreamFrame::Exit { code: 0 }
        );
        assert!(read_frame::<_, StreamFrame>(&mut client).await.is_err());
    }

    /// Leak path: the run completes (`done` fires) while the sink's sender is
    /// still alive and would keep producing. `write_exec_result` must close the
    /// receiver, flush only what was already queued, and write the terminal
    /// frame — it must not stream chunks enqueued after completion nor hang.
    #[tokio::test]
    async fn leak_path_drains_queued_then_terminates() {
        let (mut server, mut client) = duplex(64 * 1024);
        let (done_tx, done_rx) = oneshot::channel::<Result<i32, WorkerError>>();
        let (out_tx, output) = mpsc::channel(16);

        // Two chunks already queued, the run reports its exit, and the sender is
        // deliberately kept alive (the leaked `IoContext`).
        out_tx
            .try_send((OutStream::Stdout, b"queued".to_vec()))
            .unwrap();
        out_tx
            .try_send((OutStream::Stderr, b"tail".to_vec()))
            .unwrap();
        done_tx.send(Ok(3)).unwrap();

        write_exec_result(
            &mut server,
            Ok(ExecStream {
                done: done_rx,
                output,
                overflowed: Arc::new(AtomicBool::new(false)),
            }),
        )
        .await
        .unwrap();

        // A post-completion enqueue attempt must fail because the receiver was
        // closed, proving a leaked producer cannot extend the stream.
        assert!(out_tx
            .try_send((OutStream::Stdout, b"after".to_vec()))
            .is_err());
        drop(server);

        let admit: DaemonResponse = read_frame(&mut client).await.unwrap();
        assert_eq!(admit, DaemonResponse::Ok);
        assert_eq!(
            read_frame::<_, StreamFrame>(&mut client).await.unwrap(),
            StreamFrame::Stdout {
                data: b"queued".to_vec()
            }
        );
        assert_eq!(
            read_frame::<_, StreamFrame>(&mut client).await.unwrap(),
            StreamFrame::Stderr {
                data: b"tail".to_vec()
            }
        );
        assert_eq!(
            read_frame::<_, StreamFrame>(&mut client).await.unwrap(),
            StreamFrame::Exit { code: 3 }
        );
        assert!(read_frame::<_, StreamFrame>(&mut client).await.is_err());
    }

    /// Starvation regression: completion (`done`) must terminate the stream even
    /// when a leaked producer keeps the queue continuously non-empty. A task
    /// enqueues forever while `done` is already resolved; because the select is
    /// biased toward `done`, the handler closes the receiver, drains the bounded
    /// tail, and writes the terminal frame instead of streaming the infinite
    /// producer forever. (A biased-toward-output loop would hang here.)
    #[tokio::test]
    async fn continuous_producer_does_not_starve_terminal() {
        let (mut server, mut client) = duplex(64 * 1024);
        let (done_tx, done_rx) = oneshot::channel::<Result<i32, WorkerError>>();
        // Small queue so a fast producer keeps it perpetually non-empty.
        let (out_tx, output) = mpsc::channel(4);

        // Completion is already ready before the handler runs.
        done_tx.send(Ok(5)).unwrap();
        // A producer that keeps enqueuing (the leaked `IoContext` on the kill
        // path). It races the handler; `send` errors once the receiver closes,
        // ending the task — so this never leaks past the test.
        let producer = tokio::spawn(async move {
            loop {
                if out_tx
                    .send((OutStream::Stdout, b"x".to_vec()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        // Must complete (not hang). A generous timeout guards a regression to a
        // starving loop, which would never return.
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            write_exec_result(
                &mut server,
                Ok(ExecStream {
                    done: done_rx,
                    output,
                    overflowed: Arc::new(AtomicBool::new(false)),
                }),
            ),
        )
        .await
        .expect("write_exec_result must terminate, not starve on continuous output");
        result.unwrap();
        drop(server);
        let _ = producer.await;

        // The stream ends with a single `Exit` terminal after some prefix of
        // `Stdout` frames; it must not stream indefinitely.
        let admit: DaemonResponse = read_frame(&mut client).await.unwrap();
        assert_eq!(admit, DaemonResponse::Ok);
        let mut saw_exit = false;
        while let Ok(frame) = read_frame::<_, StreamFrame>(&mut client).await {
            match frame {
                StreamFrame::Stdout { .. } => {}
                StreamFrame::Exit { code } => {
                    assert_eq!(code, 5);
                    saw_exit = true;
                    break;
                }
                other => panic!("unexpected frame: {other:?}"),
            }
        }
        assert!(saw_exit, "the stream must end with an Exit terminal");
    }

    /// Overflow regression: when the sink latched `overflowed` (it dropped live
    /// output because the client did not drain fast enough), the terminal frame
    /// must be a truncation `Error` — never a clean `Exit` the client would
    /// mistake for a complete run.
    #[tokio::test]
    async fn overflow_yields_truncation_error_terminal() {
        let (mut server, mut client) = duplex(64 * 1024);
        let (done_tx, done_rx) = oneshot::channel::<Result<i32, WorkerError>>();
        let (out_tx, output) = mpsc::channel(16);

        // Some output made it through before the drop, then a clean exit, but the
        // sink signalled truncation.
        out_tx
            .try_send((OutStream::Stdout, b"partial".to_vec()))
            .unwrap();
        done_tx.send(Ok(0)).unwrap();
        drop(out_tx);
        let overflowed = Arc::new(AtomicBool::new(true));

        write_exec_result(
            &mut server,
            Ok(ExecStream {
                done: done_rx,
                output,
                overflowed,
            }),
        )
        .await
        .unwrap();
        drop(server);

        let admit: DaemonResponse = read_frame(&mut client).await.unwrap();
        assert_eq!(admit, DaemonResponse::Ok);
        assert_eq!(
            read_frame::<_, StreamFrame>(&mut client).await.unwrap(),
            StreamFrame::Stdout {
                data: b"partial".to_vec()
            }
        );
        let terminal: StreamFrame = read_frame(&mut client).await.unwrap();
        match terminal {
            StreamFrame::Error { message } => {
                assert!(message.contains("truncated"), "message was {message:?}");
            }
            other => panic!("expected a truncation Error terminal, got {other:?}"),
        }
        assert!(read_frame::<_, StreamFrame>(&mut client).await.is_err());
    }
}
