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

use mxc_sdk::wslc_common::container_steps::OutStream;
use mxc_sdk::wslc_common::daemon_protocol::{
    encode_frame, DaemonRequest, DaemonResponse, DeprovisionConfig, ExecTerminal, StreamFrame,
    MAX_EXEC_ID_BYTES, MAX_FRAME_SIZE,
};

use crate::session_manager::{ExecSlotGuard, ExecStream, SessionHandle, WorkerError};

/// Exec streams admitted at once; a further request is refused rather than
/// queued behind a workload of unknown duration.
///
/// Each admitted exec owns a bounded live-output queue of
/// `LIVE_OUTPUT_CHANNEL_CAPACITY` x `LIVE_OUTPUT_MAX_CHUNK_BYTES`, and a
/// streaming exec captures nothing alongside it, so this bound holds the
/// persistent per-user daemon near 128 MB of live output against clients that
/// never drain.
const MAX_CONCURRENT_EXECS: usize = 8;

/// Client capacity beyond the exec cap, so lifecycle work is still serviced
/// while every exec slot is occupied.
///
/// A lifecycle command naming a container with a run in flight parks on the
/// worker and holds its slot for the whole wait, so this bounds how many such
/// waits can be outstanding.
const CONTROL_CLIENT_HEADROOM: usize = 8;

/// Upper bound on concurrently-serviced client connections. Connections beyond
/// this bound are refused without blocking the accept loop.
const MAX_CONCURRENT_CLIENTS: usize = MAX_CONCURRENT_EXECS + CONTROL_CLIENT_HEADROOM;

/// Connections admitted for cancellation alone once [`MAX_CONCURRENT_CLIENTS`]
/// is reached, one per exec that could need cancelling.
///
/// Cancellation is the only way to end a run with no timeout, and the one
/// request that never waits on the worker, so it keeps capacity that lifecycle
/// work cannot consume.
const CANCEL_LANE_SLOTS: usize = MAX_CONCURRENT_EXECS;

/// Deadline for a freshly-connected client to send its first (request) frame. A
/// client that connects and then stalls must not pin a handler task — and a
/// concurrency slot — indefinitely.
const FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(30);

/// Deadline for a cancel-lane client to send its first frame, so a stalled
/// connection cannot hold a cancellation slot for the general one.
const LANE_FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(2);

/// Upper bound on a cancel-lane request frame, large enough for every
/// `cancel_exec` the protocol admits: [`MAX_EXEC_ID_BYTES`] caps an
/// identifier's decoded length, not the escaped length it occupies on the wire.
const LANE_MAX_FRAME_BYTES: usize = 2 * MAX_EXEC_ID_BYTES * JSON_MAX_ESCAPE_BYTES + 256;

/// Longest JSON escape a single byte of an identifier can produce, a control
/// character with no short form becoming `\u00XX`.
const JSON_MAX_ESCAPE_BYTES: usize = 6;

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
    let client_limiter = Arc::new(Semaphore::new(MAX_CONCURRENT_CLIENTS));
    let cancel_limiter = Arc::new(Semaphore::new(CANCEL_LANE_SLOTS));
    let exec_limiter = Arc::new(Semaphore::new(MAX_CONCURRENT_EXECS));
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
                    &client_limiter,
                    &cancel_limiter,
                    &exec_limiter,
                    &session,
                    &active_clients,
                    connected,
                );

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

/// Spawn a bounded task to service one accepted client connection.
///
/// A connection that arrives once the general bound is reached is admitted into
/// the cancellation lane instead, where it is serviced only if it carries a
/// [`DaemonRequest::CancelExec`].
fn spawn_client_handler(
    clients: &mut JoinSet<()>,
    client_limiter: &Arc<Semaphore>,
    cancel_limiter: &Arc<Semaphore>,
    exec_limiter: &Arc<Semaphore>,
    session: &SessionHandle,
    active_clients: &Arc<AtomicUsize>,
    connected: NamedPipeServer,
) {
    let (permit, cancel_only) = match client_limiter.clone().try_acquire_owned() {
        Ok(permit) => (permit, false),
        Err(_) => match cancel_limiter.clone().try_acquire_owned() {
            Ok(permit) => (permit, true),
            // The connection is already accepted, so dropping it is the only
            // bounded refusal path that cannot stall the accept loop.
            Err(_) => return,
        },
    };

    let session = session.clone();
    let exec_limiter = Arc::clone(exec_limiter);
    let active = active_clients.clone();
    active.fetch_add(1, Ordering::SeqCst);
    clients.spawn(async move {
        let _permit = permit;
        if let Err(e) = handle_client(connected, session, exec_limiter, cancel_only).await {
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

/// Attempts to release a sandbox whose id never reached its caller, and the
/// wait between them. The container holds the idle watchdog open, so a
/// transient SDK failure is worth retrying rather than logging once.
const UNDELIVERED_RELEASE_ATTEMPTS: u32 = 3;
const UNDELIVERED_RELEASE_BACKOFF: Duration = Duration::from_secs(2);

/// Deprovision a sandbox whose `Provisioned` reply could not be delivered.
///
/// Nobody else can: the id exists only here, so this is its last owner.
async fn release_undelivered_sandbox(session: &SessionHandle, sandbox_id: &str) {
    for attempt in 1..=UNDELIVERED_RELEASE_ATTEMPTS {
        let config = DeprovisionConfig {
            sandbox_id: sandbox_id.to_string(),
        };
        match session.deprovision(config).await {
            Ok(()) => {
                eprintln!(
                    "[wslc-daemon] released {sandbox_id}: its provision reply never \
                     reached the client"
                );
                return;
            }
            Err(e) if attempt == UNDELIVERED_RELEASE_ATTEMPTS => {
                eprintln!(
                    "[wslc-daemon] could not release {sandbox_id} after \
                     {UNDELIVERED_RELEASE_ATTEMPTS} attempts: {e}. It was retired from the live \
                     count and will be deleted when the daemon shuts down."
                );

                // Nothing can reach this sandbox, so counting it would hold the
                // daemon open for a client that will never call back.
                session.retire(sandbox_id.to_string()).await.ok();
            }
            Err(e) => {
                eprintln!("[wslc-daemon] release of {sandbox_id} failed ({e}); retrying");
                tokio::time::sleep(UNDELIVERED_RELEASE_BACKOFF).await;
            }
        }
    }
}

/// Write a provision reply, releasing the sandbox if the reply did not land.
///
/// An id that never reaches its caller names a container nobody can
/// deprovision, and its entry holds the idle watchdog's count above zero.
///
/// `release` is a parameter so this path can be tested without a live session.
async fn deliver_provision_reply<S, F, Fut>(
    pipe: &mut S,
    resp: &DaemonResponse,
    release: F,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let delivered = write_frame(pipe, resp).await;
    if let (Err(_), DaemonResponse::Provisioned { sandbox_id }) = (&delivered, resp) {
        release(sandbox_id.clone()).await;
    }
    delivered
}

/// Service exactly one request on a freshly-connected pipe instance.
///
/// `cancel_only` marks a connection admitted into the cancellation lane because
/// the general client bound was reached; anything other than a
/// [`DaemonRequest::CancelExec`] is refused there, and its request frame is held
/// to a lane-sized bound and deadline.
async fn handle_client<S>(
    mut pipe: S,
    session: SessionHandle,
    exec_limiter: Arc<Semaphore>,
    cancel_only: bool,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Bound the wait for the request frame so a client that connects and then
    // stalls cannot pin this handler (and its concurrency slot) indefinitely.
    let (deadline, max_frame) = if cancel_only {
        (LANE_FIRST_FRAME_TIMEOUT, LANE_MAX_FRAME_BYTES)
    } else {
        (FIRST_FRAME_TIMEOUT, MAX_FRAME_SIZE)
    };
    let request: DaemonRequest = timeout(deadline, read_frame_capped(&mut pipe, max_frame))
        .await
        .context("timed out waiting for the client's first frame")??;
    if cancel_only && !matches!(request, DaemonRequest::CancelExec(_)) {
        write_frame(
            &mut pipe,
            &DaemonResponse::Err {
                kind: mxc_sdk::wslc_common::daemon_protocol::ErrKind::Busy,
                message: "WSLc daemon client capacity is exhausted".to_string(),
            },
        )
        .await?;
        return Ok(());
    }
    match request {
        DaemonRequest::Ping => {
            write_frame(&mut pipe, &DaemonResponse::Pong).await?;
        }
        DaemonRequest::Provision(config) => {
            let resp = match session.provision(config).await {
                Ok(sandbox_id) => DaemonResponse::Provisioned { sandbox_id },
                Err(e) => worker_err_response(e),
            };
            deliver_provision_reply(&mut pipe, &resp, |sandbox_id| {
                let session = &session;
                async move { release_undelivered_sandbox(session, &sandbox_id).await }
            })
            .await?;
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
            let Ok(exec_permit) = exec_limiter.try_acquire_owned() else {
                write_frame(
                    &mut pipe,
                    &DaemonResponse::Err {
                        kind: mxc_sdk::wslc_common::daemon_protocol::ErrKind::Busy,
                        message: "WSLc daemon exec capacity is exhausted".to_string(),
                    },
                )
                .await?;
                return Ok(());
            };
            handle_exec(pipe, session, config, exec_permit).await?;
        }
        DaemonRequest::CancelExec(config) => {
            session.cancel_exec(&config.exec_id, &config.run_token);
            write_frame(&mut pipe, &DaemonResponse::Ok).await?;
        }
    }
    Ok(())
}

/// Exec: validate-then-admit, then stream the run's stdout/stderr live as
/// [`StreamFrame`]s, followed by a terminal frame.
///
/// The sandbox is validated (exists + started) *before* the `Ok` admission is
/// written, and — critically — admission is **atomic** with the claim the
/// worker takes on the container (see [`SessionHandle::exec`]): the worker
/// validates, claims the container and hands the run to a thread of its own
/// without yielding. A later `Stop`/`Deprovision` naming that container parks
/// behind the claim and a later `Exec` is refused with `Busy`, so neither can
/// invalidate the checked state. An unknown, not-started or already-busy
/// sandbox therefore comes back as a pre-admission typed
/// [`DaemonResponse::Err`] rather than a post-admission stream `Error` frame.
///
/// The exec permit is shared with the run, so capacity frees only once the run
/// has reported back and this handler has finished writing.
///
/// Output streaming (process -> `Stdout`/`Stderr`) is live. Client `Stdin`
/// frames are NOT forwarded: the WSLc SDK consumes all process IO handles once
/// any `WslcSetProcessSettingsCallbacks` is registered (the callback path this
/// live output streaming depends on), so `WslcGetProcessIOHandle(STDIN)` is
/// unavailable. Piped stdin would require a handle-mode rearchitecture (no
/// callbacks; `ReadFile` threads for stdout/stderr + `WriteFile` for stdin) and
/// is deferred; stdin forwarding is tracked in issue #804.
async fn handle_exec<S>(
    mut pipe: S,
    session: SessionHandle,
    config: mxc_sdk::wslc_common::daemon_protocol::ExecConfig,
    exec_permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let exec_id = config.exec_id.clone();
    let run_token = config.run_token.clone();
    let slot: ExecSlotGuard = Arc::new(exec_permit);

    // Await the worker's admission decision before writing anything: a rejected
    // exec is a pre-admission typed error, never a post-admission stream frame.
    let admission = session.exec(config, Some(slot.clone())).await;
    let delivered = write_exec_result(&mut pipe, admission).await;

    if delivered.is_err() {
        // The run outlives this handler on a thread of its own, so without a
        // kill a client could disconnect in a loop and leave runs going.
        session.cancel_exec(&exec_id, &run_token);
    }

    drop(slot);
    delivered
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
        registration: _registration,
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
    let (notice, terminal) = loop {
        tokio::select! {
            biased;
            result = &mut done => {
                output.close();
                while let Ok(chunk) = output.try_recv() {
                    write_frame(pipe, &output_frame(chunk)).await?;
                }
                break terminal_frames(result, &overflowed);
            }
            chunk = output.recv() => match chunk {
                Some(chunk) => {
                    write_frame(pipe, &output_frame(chunk)).await?;
                }
                // Senders dropped before `done` fired (normal path): the run has
                // completed and every chunk is flushed. Await the exit code.
                None => break terminal_frames(done.await, &overflowed),
            },
        }
    };
    if let Some(notice) = notice {
        write_frame(pipe, &notice).await?;
    }
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

/// Choose the exec's terminal [`StreamFrame`], and the notice that precedes it
/// when the sink had to drop live output.
///
/// Truncation travels ahead of the terminal rather than replacing it: every
/// terminal carries something the client cannot reconstruct — an exit code, or
/// why the run ended.
fn terminal_frames(
    result: Result<Result<ExecTerminal, WorkerError>, oneshot::error::RecvError>,
    overflowed: &AtomicBool,
) -> (Option<StreamFrame>, StreamFrame) {
    let terminal = exit_terminal(result);
    if overflowed.load(Ordering::Relaxed) {
        (Some(StreamFrame::Truncated), terminal)
    } else {
        (None, terminal)
    }
}

/// Map a completed exec's result (or a dropped completion channel) to its
/// terminal [`StreamFrame`].
fn exit_terminal(
    result: Result<Result<ExecTerminal, WorkerError>, oneshot::error::RecvError>,
) -> StreamFrame {
    match result {
        Ok(Ok(ExecTerminal::Exited(code))) => StreamFrame::Exit { code },
        Ok(Ok(ExecTerminal::TimedOut)) => StreamFrame::TimedOut,
        Ok(Ok(ExecTerminal::Cancelled)) => StreamFrame::Cancelled,
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
#[cfg(test)]
async fn read_frame<S: AsyncRead + Unpin, T: DeserializeOwned>(pipe: &mut S) -> Result<T> {
    read_frame_capped(pipe, MAX_FRAME_SIZE).await
}

/// Read one length-prefixed frame, refusing a declared length above `max`
/// before allocating for it.
async fn read_frame_capped<S: AsyncRead + Unpin, T: DeserializeOwned>(
    pipe: &mut S,
    max: usize,
) -> Result<T> {
    let mut len_buf = [0u8; 4];
    pipe.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > max {
        bail!("incoming frame length {len} exceeds maximum {max}");
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
    use crate::session_manager::{
        register_exec, spawn, LIVE_OUTPUT_CHANNEL_CAPACITY, LIVE_OUTPUT_MAX_CHUNK_BYTES,
    };
    use mxc_sdk::wslc_common::daemon_protocol::{
        CancelExecConfig, ErrKind, ExecConfig, ProvisionConfig,
    };
    use tokio::io::duplex;
    use tokio::sync::mpsc;

    fn test_registration() -> Arc<crate::session_manager::ExecRegistration> {
        let active_execs = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let cancellation = Arc::new(AtomicBool::new(false));
        Arc::new(register_exec(&active_execs, "test-exec", "test-run", &cancellation).unwrap())
    }

    /// A streaming exec's output memory is its live-output queue alone, so the
    /// cap is what holds the daemon's worst case down.
    #[test]
    fn the_exec_cap_bounds_worst_case_live_output_memory() {
        let per_exec = LIVE_OUTPUT_CHANNEL_CAPACITY * LIVE_OUTPUT_MAX_CHUNK_BYTES;
        let worst_case = MAX_CONCURRENT_EXECS * per_exec;

        assert_eq!(per_exec, 16 * 1024 * 1024);
        assert_eq!(worst_case, 128 * 1024 * 1024);
        assert_eq!(MAX_CONCURRENT_CLIENTS, 16);
    }

    /// Cancellation is the only way to end a run with no timeout, so it must
    /// survive a client bound that parked lifecycle work has filled.
    #[tokio::test]
    async fn the_cancel_lane_outlives_exhausted_client_capacity() {
        let session = spawn().unwrap();
        let client_limiter = Arc::new(Semaphore::new(MAX_CONCURRENT_CLIENTS));
        let cancel_limiter = Arc::new(Semaphore::new(CANCEL_LANE_SLOTS));

        // Every general slot taken, as when each exec has a lifecycle command
        // parked behind it.
        let mut held = Vec::new();
        for _ in 0..MAX_CONCURRENT_CLIENTS {
            held.push(client_limiter.clone().try_acquire_owned().unwrap());
        }
        assert!(client_limiter.clone().try_acquire_owned().is_err());

        // Every in-flight exec must stay cancellable, so the requirement is the
        // exec cap.
        let mut lane = Vec::new();
        for _ in 0..MAX_CONCURRENT_EXECS {
            lane.push(
                cancel_limiter
                    .clone()
                    .try_acquire_owned()
                    .expect("every in-flight exec must still be cancellable"),
            );
        }

        for permit in lane {
            let (mut client, server) = duplex(64 * 1024);
            write_frame(
                &mut client,
                &DaemonRequest::CancelExec(CancelExecConfig {
                    exec_id: "stuck".to_string(),
                    run_token: "stuck-run".to_string(),
                }),
            )
            .await
            .unwrap();

            handle_client(server, session.clone(), Arc::new(Semaphore::new(0)), true)
                .await
                .unwrap();

            let response: DaemonResponse = read_frame(&mut client).await.unwrap();
            assert_eq!(response, DaemonResponse::Ok);
            drop(permit);
        }

        session.shutdown().await.unwrap();
    }

    /// The cancel lane carries cancellations only; anything else is refused
    /// with a typed error.
    #[tokio::test]
    async fn the_cancel_lane_refuses_non_cancel_requests() {
        let session = spawn().unwrap();
        let (mut client, server) = duplex(64 * 1024);
        write_frame(
            &mut client,
            &DaemonRequest::Stop(mxc_sdk::wslc_common::daemon_protocol::StopConfig {
                sandbox_id: "wslc:test".to_string(),
            }),
        )
        .await
        .unwrap();

        handle_client(server, session.clone(), Arc::new(Semaphore::new(0)), true)
            .await
            .unwrap();

        let response: DaemonResponse = read_frame(&mut client).await.unwrap();
        assert_eq!(
            response,
            DaemonResponse::Err {
                kind: ErrKind::Busy,
                message: "WSLc daemon client capacity is exhausted".to_string(),
            }
        );
        session.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn exhausted_exec_capacity_returns_busy() {
        let session = spawn().unwrap();
        let exec_limiter = Arc::new(Semaphore::new(1));
        let _permit = exec_limiter.clone().acquire_owned().await.unwrap();
        let (mut client, server) = duplex(64 * 1024);
        write_frame(
            &mut client,
            &DaemonRequest::Exec(ExecConfig {
                exec_id: "exec-busy".to_string(),
                run_token: "run-busy".to_string(),
                sandbox_id: "wslc:test".to_string(),
                script_code: "echo hi".to_string(),
                working_directory: String::new(),
                env: Vec::new(),
                env_scope: mxc_sdk::wslc_common::process_env::EnvScope::Merge,
                timeout_ms: 0,
            }),
        )
        .await
        .unwrap();

        handle_client(server, session.clone(), exec_limiter, false)
            .await
            .unwrap();

        let response: DaemonResponse = read_frame(&mut client).await.unwrap();
        assert_eq!(
            response,
            DaemonResponse::Err {
                kind: ErrKind::Busy,
                message: "WSLc daemon exec capacity is exhausted".to_string(),
            }
        );
        session.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn an_undelivered_exec_is_cancelled_so_its_run_cannot_outlive_the_permit() {
        use crate::session_manager::register_exec;

        let session = crate::session_manager::spawn().unwrap();
        let cancellation = Arc::new(AtomicBool::new(false));
        let registration = register_exec(
            session.active_execs(),
            "orphan-1",
            "orphan-run-1",
            &cancellation,
        )
        .unwrap();

        let limiter = Arc::new(Semaphore::new(MAX_CONCURRENT_EXECS));
        let permit = limiter.clone().try_acquire_owned().unwrap();
        let delivered = handle_exec(
            BrokenPipe,
            session.clone(),
            mxc_sdk::wslc_common::daemon_protocol::ExecConfig {
                exec_id: "orphan-1".to_string(),
                run_token: "orphan-run-1".to_string(),
                sandbox_id: "wslc:does-not-exist".to_string(),
                script_code: "sleep 600".to_string(),
                working_directory: String::new(),
                env: Vec::new(),
                env_scope: mxc_sdk::wslc_common::process_env::EnvScope::Merge,
                timeout_ms: 0,
            },
            permit,
        )
        .await;

        assert!(delivered.is_err(), "the broken pipe must fail delivery");
        assert!(
            cancellation.load(Ordering::Acquire),
            "a run the client can no longer read must be cancelled rather than \
             left going"
        );
        drop(registration);
        session.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn an_exec_slot_outlives_a_handler_that_is_still_writing() {
        let session = spawn().unwrap();
        let limiter = Arc::new(Semaphore::new(1));
        let permit = limiter.clone().try_acquire_owned().unwrap();

        // One byte of pipe, never drained, so the handler cannot finish writing.
        let (server, mut client) = duplex(1);
        let handler = tokio::spawn(handle_exec(
            server,
            session.clone(),
            ExecConfig {
                exec_id: "exec-writing".to_string(),
                run_token: "run-writing".to_string(),
                sandbox_id: "wslc:never-provisioned".to_string(),
                script_code: "echo hi".to_string(),
                working_directory: String::new(),
                env: Vec::new(),
                env_scope: mxc_sdk::wslc_common::process_env::EnvScope::Merge,
                timeout_ms: 0,
            },
            permit,
        ));

        // One byte proves the handler is into its frame, and the rest of that
        // frame cannot fit behind it.
        let mut first = [0u8; 1];
        client.read_exact(&mut first).await.unwrap();
        assert_eq!(
            limiter.available_permits(),
            0,
            "a handler still writing to its client must not free its exec slot"
        );

        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.unwrap();
        handler.await.unwrap().unwrap();
        assert_eq!(
            limiter.available_permits(),
            1,
            "the slot must come back once the handler has finished writing"
        );
        session.shutdown().await.unwrap();
    }

    /// A pipe name unique to this test run, so tests do not collide on one
    /// instance.
    fn test_pipe_name() -> String {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        format!(
            r"\\.\pipe\mxc-wslc-lane-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        )
    }

    /// Route one accepted connection through the router with every general slot
    /// taken, and hand back the client end of it.
    async fn connection_past_general_capacity(
        session: &SessionHandle,
        clients: &mut JoinSet<()>,
        cancel_limiter: &Arc<Semaphore>,
    ) -> tokio::net::windows::named_pipe::NamedPipeClient {
        let name = test_pipe_name();
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&name)
            .unwrap();
        let client = tokio::net::windows::named_pipe::ClientOptions::new()
            .open(&name)
            .unwrap();
        server.connect().await.unwrap();

        let client_limiter = Arc::new(Semaphore::new(1));
        let _held = client_limiter.clone().try_acquire_owned().unwrap();
        spawn_client_handler(
            clients,
            &client_limiter,
            cancel_limiter,
            &Arc::new(Semaphore::new(MAX_CONCURRENT_EXECS)),
            session,
            &Arc::new(AtomicUsize::new(0)),
            server,
        );
        client
    }

    #[tokio::test]
    async fn a_cancellation_survives_a_lane_saturated_by_stalled_connections() {
        // Well past the lane's deadline and well inside the general one, so
        // only a lane-sized deadline gets a cancellation through in time.
        const CANCEL_BUDGET: Duration = Duration::from_secs(10);

        let session = spawn().unwrap();
        let cancel_limiter = Arc::new(Semaphore::new(CANCEL_LANE_SLOTS));
        let mut clients = JoinSet::new();

        // Every lane slot taken by a connection that sends a length prefix and
        // then nothing, so each one is mid-frame rather than idle.
        let mut stalled = Vec::new();
        for _ in 0..CANCEL_LANE_SLOTS {
            let mut client =
                connection_past_general_capacity(&session, &mut clients, &cancel_limiter).await;
            client.write_all(&300u32.to_le_bytes()).await.unwrap();
            stalled.push(client);
        }

        let started = std::time::Instant::now();
        let mut cancelled = false;
        while started.elapsed() < CANCEL_BUDGET {
            let mut client =
                connection_past_general_capacity(&session, &mut clients, &cancel_limiter).await;
            if write_frame(
                &mut client,
                &DaemonRequest::CancelExec(CancelExecConfig {
                    exec_id: "stuck".to_string(),
                    run_token: "stuck-run".to_string(),
                }),
            )
            .await
            .is_ok()
            {
                if let Ok(DaemonResponse::Ok) = read_frame::<_, DaemonResponse>(&mut client).await {
                    cancelled = true;
                    break;
                }
            }
        }

        assert!(
            cancelled,
            "a cancellation behind stalled lane connections took longer than \
             {CANCEL_BUDGET:?}"
        );
        clients.shutdown().await;
        session.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn an_escaped_cancellation_still_fits_the_lane() {
        // Each byte escapes to its longest JSON form, at the longest identifier
        // the protocol admits.
        let escaped = "\u{1}".repeat(MAX_EXEC_ID_BYTES);
        assert_eq!(escaped.len(), MAX_EXEC_ID_BYTES);

        let frame = encode_frame(&DaemonRequest::CancelExec(CancelExecConfig {
            exec_id: escaped.clone(),
            run_token: escaped.clone(),
        }))
        .unwrap();
        assert!(
            frame.len() - 4 <= LANE_MAX_FRAME_BYTES,
            "a {} byte cancellation does not fit the lane's {LANE_MAX_FRAME_BYTES} byte bound",
            frame.len() - 4
        );

        let session = spawn().unwrap();
        let cancel_limiter = Arc::new(Semaphore::new(1));
        let mut clients = JoinSet::new();
        let mut client =
            connection_past_general_capacity(&session, &mut clients, &cancel_limiter).await;

        write_frame(
            &mut client,
            &DaemonRequest::CancelExec(CancelExecConfig {
                exec_id: escaped.clone(),
                run_token: escaped,
            }),
        )
        .await
        .unwrap();

        let response: DaemonResponse = read_frame(&mut client).await.unwrap();
        assert_eq!(
            response,
            DaemonResponse::Ok,
            "the lane must carry every cancellation the protocol admits"
        );
        clients.shutdown().await;
        session.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn a_connection_past_general_capacity_refuses_a_non_cancellation() {
        let session = spawn().unwrap();
        let cancel_limiter = Arc::new(Semaphore::new(1));
        let mut clients = JoinSet::new();
        let mut client =
            connection_past_general_capacity(&session, &mut clients, &cancel_limiter).await;

        write_frame(
            &mut client,
            &DaemonRequest::Exec(ExecConfig {
                exec_id: "exec-lane".to_string(),
                run_token: "run-lane".to_string(),
                sandbox_id: "wslc:test".to_string(),
                script_code: "echo hi".to_string(),
                working_directory: String::new(),
                env: Vec::new(),
                env_scope: mxc_sdk::wslc_common::process_env::EnvScope::Merge,
                timeout_ms: 0,
            }),
        )
        .await
        .unwrap();

        let response: DaemonResponse = read_frame(&mut client).await.unwrap();
        assert_eq!(
            response,
            DaemonResponse::Err {
                kind: ErrKind::Busy,
                message: "WSLc daemon client capacity is exhausted".to_string(),
            }
        );
        clients.shutdown().await;
        session.shutdown().await.unwrap();
    }

    /// Cancellation is the only way to end a run with no timeout.
    #[tokio::test]
    async fn a_connection_past_general_capacity_still_serves_a_cancellation() {
        let session = spawn().unwrap();
        let cancel_limiter = Arc::new(Semaphore::new(1));
        let mut clients = JoinSet::new();
        let mut client =
            connection_past_general_capacity(&session, &mut clients, &cancel_limiter).await;

        write_frame(
            &mut client,
            &DaemonRequest::CancelExec(CancelExecConfig {
                exec_id: "unknown-exec".to_string(),
                run_token: "unknown-run".to_string(),
            }),
        )
        .await
        .unwrap();

        let response: DaemonResponse = read_frame(&mut client).await.unwrap();
        assert_eq!(response, DaemonResponse::Ok);
        clients.shutdown().await;
        session.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn a_stalled_lane_connection_gives_up_its_slot_quickly() {
        let session = spawn().unwrap();
        let (_client, server) = duplex(64 * 1024);

        let started = std::time::Instant::now();
        let outcome =
            handle_client(server, session.clone(), Arc::new(Semaphore::new(0)), true).await;
        let waited = started.elapsed();

        assert!(
            outcome.is_err(),
            "a client that sends nothing must not be serviced"
        );
        assert!(
            waited < FIRST_FRAME_TIMEOUT,
            "a stalled lane connection held its slot for {waited:?}, the general deadline"
        );
        session.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn an_oversized_lane_frame_is_refused_before_it_is_allocated() {
        // Trivial for the general bound, so only a lane-sized bound refuses it.
        const MODEST_FRAME_BYTES: usize = 64 * 1024;

        let session = spawn().unwrap();
        let (mut client, server) = duplex(64 * 1024);

        // A length prefix alone: a lane that accepted this would wait for a
        // body that never comes.
        client
            .write_all(&(MODEST_FRAME_BYTES as u32).to_le_bytes())
            .await
            .unwrap();

        let outcome =
            handle_client(server, session.clone(), Arc::new(Semaphore::new(0)), true).await;

        let message = outcome
            .expect_err("an oversized lane frame must be refused")
            .to_string();
        assert!(
            message.contains("exceeds maximum"),
            "a {MODEST_FRAME_BYTES}-byte frame must exceed the lane's bound of \
             {LANE_MAX_FRAME_BYTES}, got {message:?}"
        );
        session.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn a_general_connection_keeps_the_full_frame_bound() {
        let session = spawn().unwrap();
        let (mut client, server) = duplex(64 * 1024);

        // Serviced concurrently so the body below cannot outgrow the pipe
        // buffer with nothing draining it.
        let handler = tokio::spawn(handle_client(
            server,
            session.clone(),
            Arc::new(Semaphore::new(0)),
            false,
        ));

        let past_lane = LANE_MAX_FRAME_BYTES * 2;
        client
            .write_all(&(past_lane as u32).to_le_bytes())
            .await
            .unwrap();
        client.write_all(&vec![b' '; past_lane]).await.unwrap();

        let message = handler
            .await
            .unwrap()
            .expect_err("whitespace is not a request")
            .to_string();
        assert!(
            !message.contains("exceeds maximum"),
            "a general connection must not be held to the lane's bound, got {message:?}"
        );
        session.shutdown().await.unwrap();
    }

    /// A writer that always fails, standing in for a client that has gone.
    struct BrokenPipe;

    impl AsyncWrite for BrokenPipe {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn an_undelivered_provisioned_reply_releases_that_sandbox() {
        let released = std::cell::RefCell::new(Vec::new());
        let resp = DaemonResponse::Provisioned {
            sandbox_id: "wslc:abc".to_string(),
        };

        let outcome = deliver_provision_reply(&mut BrokenPipe, &resp, |id| {
            released.borrow_mut().push(id);
            std::future::ready(())
        })
        .await;

        assert!(outcome.is_err(), "a failed write must not report success");
        assert_eq!(released.into_inner(), vec!["wslc:abc".to_string()]);
    }

    #[tokio::test]
    async fn an_undelivered_error_reply_releases_nothing() {
        let released = std::cell::RefCell::new(Vec::new());
        let resp = DaemonResponse::Err {
            kind: ErrKind::Backend,
            message: "provision failed".to_string(),
        };

        let outcome = deliver_provision_reply(&mut BrokenPipe, &resp, |id| {
            released.borrow_mut().push(id);
            std::future::ready(())
        })
        .await;

        assert!(outcome.is_err(), "a failed write must not report success");
        assert!(
            released.into_inner().is_empty(),
            "an error reply names no sandbox to release"
        );
    }

    #[tokio::test]
    async fn a_delivered_provisioned_reply_releases_nothing() {
        let released = std::cell::RefCell::new(Vec::new());
        let resp = DaemonResponse::Provisioned {
            sandbox_id: "wslc:abc".to_string(),
        };
        let (mut client, mut server) = duplex(64 * 1024);

        let outcome = deliver_provision_reply(&mut server, &resp, |id| {
            released.borrow_mut().push(id);
            std::future::ready(())
        })
        .await;

        assert!(outcome.is_ok(), "the write succeeded");
        assert!(
            released.into_inner().is_empty(),
            "a delivered id has an owner; releasing it would destroy a live sandbox"
        );
        let echoed: DaemonResponse = read_frame(&mut client).await.unwrap();
        assert_eq!(echoed, resp);
    }

    /// A client that disappears before reading its reply must surface as an
    /// error from the handler, which is what triggers releasing the sandbox its
    /// id would have named.
    #[tokio::test]
    async fn a_vanished_client_fails_the_provision_handler() {
        let session = spawn().unwrap();
        let exec_limiter = Arc::new(Semaphore::new(1));
        let (mut client, server) = duplex(64 * 1024);
        write_frame(
            &mut client,
            &DaemonRequest::Provision(ProvisionConfig {
                image: "alpine:latest".to_string(),
                image_tar_path: None,
                volumes: Vec::new(),
                network: Default::default(),
                port_mappings: Vec::new(),
            }),
        )
        .await
        .unwrap();
        drop(client);

        let outcome = handle_client(server, session.clone(), exec_limiter, false).await;
        assert!(
            outcome.is_err(),
            "an undelivered reply must not be reported as a served request"
        );

        // Whichever way provision went, no sandbox may be left behind: a minted
        // id was released above, and a failure minted none.
        assert_eq!(session.container_count().await.unwrap(), 0);
        session.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn cancel_exec_request_dispatches_successfully() {
        let session = spawn().unwrap();
        let exec_limiter = Arc::new(Semaphore::new(1));
        let (mut client, server) = duplex(64 * 1024);
        write_frame(
            &mut client,
            &DaemonRequest::CancelExec(CancelExecConfig {
                exec_id: "unknown-exec".to_string(),
                run_token: "unknown-run".to_string(),
            }),
        )
        .await
        .unwrap();

        handle_client(server, session.clone(), exec_limiter, false)
            .await
            .unwrap();

        let response: DaemonResponse = read_frame(&mut client).await.unwrap();
        assert_eq!(response, DaemonResponse::Ok);
        session.shutdown().await.unwrap();
    }

    /// Admit an exec whose output channel is already closed (no live output),
    /// so `write_exec_result` goes straight from `Ok` to the terminal frame.
    fn admitted_no_output(
        done: oneshot::Receiver<Result<ExecTerminal, WorkerError>>,
    ) -> Result<ExecStream, WorkerError> {
        let (tx, output) = mpsc::channel(16);
        drop(tx);
        Ok(ExecStream {
            done,
            output,
            overflowed: Arc::new(AtomicBool::new(false)),
            registration: test_registration(),
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
        let (done_tx, done_rx) = oneshot::channel::<Result<ExecTerminal, WorkerError>>();
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
        let (done_tx, done_rx) = oneshot::channel::<Result<ExecTerminal, WorkerError>>();
        done_tx.send(Ok(ExecTerminal::Exited(7))).unwrap();

        write_exec_result(&mut server, admitted_no_output(done_rx))
            .await
            .unwrap();
        drop(server);

        let admit: DaemonResponse = read_frame(&mut client).await.unwrap();
        assert_eq!(admit, DaemonResponse::Ok);
        let terminal: StreamFrame = read_frame(&mut client).await.unwrap();
        assert_eq!(terminal, StreamFrame::Exit { code: 7 });
    }

    #[tokio::test]
    async fn exec_id_stays_registered_until_terminal_delivery() {
        let active_execs = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let cancellation = Arc::new(AtomicBool::new(false));
        let registration =
            Arc::new(register_exec(&active_execs, "exec-1", "run-1", &cancellation).unwrap());
        let worker_registration = Arc::clone(&registration);
        let (mut server, mut client) = duplex(1);
        let (done_tx, done_rx) = oneshot::channel::<Result<ExecTerminal, WorkerError>>();
        done_tx.send(Ok(ExecTerminal::Exited(0))).unwrap();
        let (output_tx, output) = mpsc::channel(1);
        drop(output_tx);

        let writer = tokio::spawn(async move {
            write_exec_result(
                &mut server,
                Ok(ExecStream {
                    done: done_rx,
                    output,
                    overflowed: Arc::new(AtomicBool::new(false)),
                    registration,
                }),
            )
            .await
        });

        assert_eq!(
            read_frame::<_, DaemonResponse>(&mut client).await.unwrap(),
            DaemonResponse::Ok
        );
        drop(worker_registration);
        tokio::task::yield_now().await;

        let replacement = Arc::new(AtomicBool::new(false));
        let error = register_exec(&active_execs, "exec-1", "run-2", &replacement).unwrap_err();
        assert_eq!(error.kind(), ErrKind::Rejected);

        assert_eq!(
            read_frame::<_, StreamFrame>(&mut client).await.unwrap(),
            StreamFrame::Exit { code: 0 }
        );
        writer.await.unwrap().unwrap();

        let replacement_registration =
            register_exec(&active_execs, "exec-1", "run-2", &replacement).unwrap();
        drop(replacement_registration);
    }

    #[tokio::test]
    async fn timeout_writes_a_typed_terminal_frame() {
        let (mut server, mut client) = duplex(64 * 1024);
        let (done_tx, done_rx) = oneshot::channel::<Result<ExecTerminal, WorkerError>>();
        done_tx.send(Ok(ExecTerminal::TimedOut)).unwrap();

        write_exec_result(&mut server, admitted_no_output(done_rx))
            .await
            .unwrap();

        assert_eq!(
            read_frame::<_, DaemonResponse>(&mut client).await.unwrap(),
            DaemonResponse::Ok
        );
        assert_eq!(
            read_frame::<_, StreamFrame>(&mut client).await.unwrap(),
            StreamFrame::TimedOut
        );
    }

    #[tokio::test]
    async fn cancellation_writes_a_typed_terminal_frame() {
        let (mut server, mut client) = duplex(64 * 1024);
        let (done_tx, done_rx) = oneshot::channel::<Result<ExecTerminal, WorkerError>>();
        done_tx.send(Ok(ExecTerminal::Cancelled)).unwrap();

        write_exec_result(&mut server, admitted_no_output(done_rx))
            .await
            .unwrap();

        assert_eq!(
            read_frame::<_, DaemonResponse>(&mut client).await.unwrap(),
            DaemonResponse::Ok
        );
        assert_eq!(
            read_frame::<_, StreamFrame>(&mut client).await.unwrap(),
            StreamFrame::Cancelled
        );
    }

    /// Live output is streamed as `Stdout`/`Stderr` frames — in the order the
    /// worker enqueued them — before the terminal `Exit`, so the client sees the
    /// run's output incrementally rather than as one buffered blob.
    #[tokio::test]
    async fn live_output_streams_before_exit() {
        let (mut server, mut client) = duplex(64 * 1024);
        let (done_tx, done_rx) = oneshot::channel::<Result<ExecTerminal, WorkerError>>();
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
        done_tx.send(Ok(ExecTerminal::Exited(0))).unwrap();
        drop(out_tx);

        write_exec_result(
            &mut server,
            Ok(ExecStream {
                done: done_rx,
                output,
                overflowed: Arc::new(AtomicBool::new(false)),
                registration: test_registration(),
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
        let (done_tx, done_rx) = oneshot::channel::<Result<ExecTerminal, WorkerError>>();
        let (out_tx, output) = mpsc::channel(16);

        // Two chunks already queued, the run reports its exit, and the sender is
        // deliberately kept alive (the leaked `IoContext`).
        out_tx
            .try_send((OutStream::Stdout, b"queued".to_vec()))
            .unwrap();
        out_tx
            .try_send((OutStream::Stderr, b"tail".to_vec()))
            .unwrap();
        done_tx.send(Ok(ExecTerminal::Exited(3))).unwrap();

        write_exec_result(
            &mut server,
            Ok(ExecStream {
                done: done_rx,
                output,
                overflowed: Arc::new(AtomicBool::new(false)),
                registration: test_registration(),
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
        let (done_tx, done_rx) = oneshot::channel::<Result<ExecTerminal, WorkerError>>();
        // Small queue so a fast producer keeps it perpetually non-empty.
        let (out_tx, output) = mpsc::channel(4);

        // Completion is already ready before the handler runs.
        done_tx.send(Ok(ExecTerminal::Exited(5))).unwrap();
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
                    registration: test_registration(),
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

    /// Overflow regression: the client must be told, and must still receive the
    /// exit code the process produced.
    #[tokio::test]
    async fn overflow_precedes_a_clean_exit_without_replacing_it() {
        let (mut server, mut client) = duplex(64 * 1024);
        let (done_tx, done_rx) = oneshot::channel::<Result<ExecTerminal, WorkerError>>();
        let (out_tx, output) = mpsc::channel(16);

        // Some output made it through before the drop, then a clean exit, but the
        // sink signalled truncation.
        out_tx
            .try_send((OutStream::Stdout, b"partial".to_vec()))
            .unwrap();
        done_tx.send(Ok(ExecTerminal::Exited(0))).unwrap();
        drop(out_tx);
        let overflowed = Arc::new(AtomicBool::new(true));

        write_exec_result(
            &mut server,
            Ok(ExecStream {
                done: done_rx,
                output,
                overflowed,
                registration: test_registration(),
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
        assert_eq!(terminal, StreamFrame::Truncated);
        assert_eq!(
            read_frame::<_, StreamFrame>(&mut client).await.unwrap(),
            StreamFrame::Exit { code: 0 }
        );
        assert!(read_frame::<_, StreamFrame>(&mut client).await.is_err());
    }

    #[tokio::test]
    async fn overflow_precedes_a_timeout_terminal_without_replacing_it() {
        assert_eq!(
            overflowed_frames(ExecTerminal::TimedOut).await,
            (Some(StreamFrame::Truncated), StreamFrame::TimedOut)
        );
    }

    #[tokio::test]
    async fn overflow_precedes_a_cancellation_terminal_without_replacing_it() {
        assert_eq!(
            overflowed_frames(ExecTerminal::Cancelled).await,
            (Some(StreamFrame::Truncated), StreamFrame::Cancelled)
        );
    }

    #[tokio::test]
    async fn a_clean_run_emits_no_truncation_notice() {
        let (mut server, mut client) = duplex(64 * 1024);
        let (done_tx, done_rx) = oneshot::channel::<Result<ExecTerminal, WorkerError>>();
        let (out_tx, output) = mpsc::channel(16);
        done_tx.send(Ok(ExecTerminal::TimedOut)).unwrap();
        drop(out_tx);

        write_exec_result(
            &mut server,
            Ok(ExecStream {
                done: done_rx,
                output,
                overflowed: Arc::new(AtomicBool::new(false)),
                registration: test_registration(),
            }),
        )
        .await
        .unwrap();
        drop(server);

        let admit: DaemonResponse = read_frame(&mut client).await.unwrap();
        assert_eq!(admit, DaemonResponse::Ok);
        assert_eq!(
            read_frame::<_, StreamFrame>(&mut client).await.unwrap(),
            StreamFrame::TimedOut
        );
        assert!(read_frame::<_, StreamFrame>(&mut client).await.is_err());
    }

    async fn overflowed_frames(terminal: ExecTerminal) -> (Option<StreamFrame>, StreamFrame) {
        let (mut server, mut client) = duplex(64 * 1024);
        let (done_tx, done_rx) = oneshot::channel::<Result<ExecTerminal, WorkerError>>();
        let (out_tx, output) = mpsc::channel(16);
        done_tx.send(Ok(terminal)).unwrap();
        drop(out_tx);

        write_exec_result(
            &mut server,
            Ok(ExecStream {
                done: done_rx,
                output,
                overflowed: Arc::new(AtomicBool::new(true)),
                registration: test_registration(),
            }),
        )
        .await
        .unwrap();
        drop(server);

        let admit: DaemonResponse = read_frame(&mut client).await.unwrap();
        assert_eq!(admit, DaemonResponse::Ok);
        let first: StreamFrame = read_frame(&mut client).await.unwrap();
        let second: StreamFrame = read_frame(&mut client).await.unwrap();
        assert!(read_frame::<_, StreamFrame>(&mut client).await.is_err());
        (Some(first), second)
    }
}
