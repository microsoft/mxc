//! Nonce-authenticated control protocol server for the state-aware daemon.
//!
//! Serves a line protocol on the daemon's localhost IPC port:
//!   request  : `<VERB> <nonce>\n`
//!   response : `OK\n` | `PONG\n` | `ERR <message>\n`
//!
//! The nonce authenticates the caller against a process that merely squats the
//! localhost port. Verbs:
//!   * `PING` — liveness (replies `PONG`).
//!   * `STOP` — tear down + exit (replies `OK`, then signals shutdown).
//!   * `EXEC` — run one command on the held guest, streaming stdout/stderr back
//!     as [`ipc_exec`] frames (see [`handle_exec`]).
//!
//! Each accepted connection is handled on its **own task** so a long-running
//! `EXEC` can never block a concurrent `STOP` or `PING`. `STOP` never touches
//! the guest mutex, and the daemon's teardown never waits on an in-flight exec
//! task — so a hung command cannot wedge shutdown.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Notify, Semaphore};
use tokio::time::timeout;

use windows_sandbox_lifecycle::bridge::{
    reconnect_data_streams, stream_exec_on_guest, write_exit_frame, GuestConnection,
};
use windows_sandbox_lifecycle::control_plane::{
    IPC_ERR, IPC_ERR_BUSY, IPC_ERR_NOT_READY, IPC_EXEC, IPC_PING, IPC_STOP,
};
use windows_sandbox_lifecycle::ipc_exec::{self, ExecStart, MAX_IPC_FRAME};

use windows_sandbox_common::auth::Nonce as GuestNonce;

/// Maximum time to wait for a client to send its request line.
///
/// This bounds a single misbehaving *client connection* only. It is NOT a
/// sandbox idle watchdog: a provisioned-and-started sandbox is held until an
/// explicit `STOP` (`stop` / `deprovision`) and is never torn down by elapsed
/// idle time. Keeping that invariant means a long-lived sandbox can sit idle
/// between exec phases without being reclaimed out from under the caller.
const CLIENT_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum time to wait for the framed `ExecStart` request after the `EXEC`
/// auth line.
const EXEC_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Hard cap on the pre-auth request line length. Bounds the memory a hostile
/// local process can force the daemon to allocate by writing a long line and
/// then idling: without this cap, `read_line` would grow its `String` until
/// the [`CLIENT_READ_TIMEOUT`] elapsed (review D1). The legitimate verbs
/// (`PING`/`STOP`/`EXEC`) plus a space plus the IPC nonce + newline are well
/// under 256 bytes; 1 KiB leaves comfortable headroom and is still trivial
/// memory if every concurrent connection used the full budget.
const MAX_AUTH_LINE_BYTES: u64 = 1024;

/// Bound on the number of pre-auth client connections handled concurrently.
/// Each connection's `handle_client` task can sit on `read_line` for up to
/// [`CLIENT_READ_TIMEOUT`] waiting for input; without a cap, a burst of slow
/// or idle localhost connections accumulates tasks, sockets, and per-task
/// stacks indefinitely, crowding out real EXEC/STOP traffic (review D2). The
/// permit is held only until the client's verb is dispatched (after the
/// `EXEC`/`STOP`/`PING` branch is entered) so a long-running EXEC does not
/// hold a pre-auth slot.
const MAX_CONCURRENT_PREAUTH: usize = 32;

/// How long an incoming pre-auth connection waits for a [`MAX_CONCURRENT_PREAUTH`]
/// permit before being dropped (review H4). The previous design used
/// `try_acquire_owned()` and instant-dropped the 33rd concurrent connection;
/// a legitimate burst from `make -j` or a CI batch that briefly exceeded the
/// cap therefore surfaced as a spurious backend error with no retry on the
/// client side. Permits are released in milliseconds for normal traffic
/// (auth read + verb dispatch only -- EXEC drops the permit before the long
/// child wait), so a short bounded wait absorbs realistic bursts while still
/// dropping a sustained slow-loris flood that would otherwise pile up.
const PREAUTH_PERMIT_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Monotonic source of per-exec correlation ids (unique within this daemon).
static EXEC_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The daemon's single held guest connection, shared between the boot path
/// (which fills it in) and the EXEC handler (which borrows it for the duration
/// of one execution).
pub enum GuestSlot {
    /// The VM has not finished booting / connecting yet. `EXEC` → `ERR not ready`.
    Booting,
    /// A live, reusable guest connection plus the address it was reached at.
    Ready {
        /// The four-channel guest connection.
        conn: GuestConnection,
        /// Address the guest agent was reached at (for stream reconnection).
        addr: std::net::SocketAddr,
    },
    /// The connection was lost or left in an indeterminate state by a failed
    /// exec or reconnect. Every subsequent `EXEC` deterministically returns
    /// `ERR <reason>`; `STOP`/teardown still work.
    Poisoned(String),
}

impl std::fmt::Debug for GuestSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuestSlot::Booting => write!(f, "Booting"),
            GuestSlot::Ready { addr, .. } => write!(f, "Ready {{ addr: {addr} }}"),
            GuestSlot::Poisoned(reason) => write!(f, "Poisoned({reason:?})"),
        }
    }
}

/// Pure admission decision for an incoming EXEC against the held single-flight
/// slot. Extracted so the security-sensitive "what does EXEC see right now"
/// state machine is unit-testable without spinning up real TCP / a real guest
/// (review F2 / addresses F2-stretch from the review's testability axis).
///
/// `slot_held_elsewhere` is `true` when the EXEC handler could not acquire the
/// slot's mutex non-blockingly (another EXEC is mid-stream on this sandbox).
/// `slot_state` is the slot's current variant; only inspected when the mutex
/// IS free.
///
/// The mapping is deliberately exhaustive and ordering-stable:
///   1. Busy beats any inspection of the slot state (we must not poison /
///      misclassify a slot we cannot read).
///   2. Otherwise the slot variant directly determines the response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionDecision {
    /// Single-flight slot is acquired and the connection is Ready: admit the
    /// EXEC. The caller writes `OK\n` and proceeds.
    Admit,
    /// Another EXEC currently holds the slot mutex. The caller writes
    /// `ERR busy\n` and returns. No state is mutated.
    Busy,
    /// Slot is free but the guest hasn't finished booting / connecting.
    /// Caller writes `ERR not ready\n`.
    NotReady,
    /// Slot is free but a prior exec / reconnect failure left the guest in
    /// an indeterminate state. Carries the human-readable reason verbatim
    /// so the operator can correlate logs. Caller writes
    /// `ERR <reason>\n` (and does NOT alter the poisoned state).
    Poisoned(String),
}

/// Pure single-flight admission classifier. See [`AdmissionDecision`].
pub fn classify_admission(slot_state: &GuestSlot, slot_held_elsewhere: bool) -> AdmissionDecision {
    if slot_held_elsewhere {
        return AdmissionDecision::Busy;
    }
    match slot_state {
        GuestSlot::Ready { .. } => AdmissionDecision::Admit,
        GuestSlot::Booting => AdmissionDecision::NotReady,
        GuestSlot::Poisoned(reason) => AdmissionDecision::Poisoned(reason.clone()),
    }
}

/// Serve the control protocol until an authenticated `STOP` arrives (or the
/// `shutdown` notify fires). Returns once the daemon should tear down. Each
/// client is dispatched to its own task so no verb can be head-of-line blocked
/// by an in-flight exec.
///
/// `guest_nonce` is the per-launch authentication nonce for the
/// daemon-to-guest TCP channel (distinct from `nonce` above, which auths
/// IPC callers to *this* daemon). It is re-presented on every
/// post-StreamsReady data-stream reconnect so a cross-user hijacker
/// cannot steal a per-exec stream (review C2; see the
/// `windows_sandbox_common::auth` module for the same-user-trusted
/// scope of both nonces).
pub async fn run(
    listener: TcpListener,
    nonce: String,
    shutdown: Arc<Notify>,
    guest: Arc<Mutex<GuestSlot>>,
    guest_nonce: Arc<GuestNonce>,
) -> Result<()> {
    let nonce = Arc::new(nonce);
    // Pre-auth concurrency cap (review D2). Bounds the number of unauthenticated
    // client tasks the daemon will spawn at once; excess connections are
    // dropped immediately rather than queued so a slow-loris burst cannot
    // accumulate tasks, sockets, and read buffers.
    let preauth_permits = Arc::new(Semaphore::new(MAX_CONCURRENT_PREAUTH));
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted.context("accept IPC client")?;
                // Bounded-wait acquire (review H4): wait up to
                // PREAUTH_PERMIT_WAIT for a permit so a transient
                // make-j-style burst that briefly exceeds
                // MAX_CONCURRENT_PREAUTH does not surface as a spurious
                // backend error on the client. If the wait expires the
                // connection is dropped to bound FD pressure under a
                // sustained slow-loris flood. The Semaphore is never
                // closed in this daemon's lifetime, so acquire_owned()
                // cannot resolve to Err during the wait.
                let permits = preauth_permits.clone();
                let acquire_result = tokio::time::timeout(
                    PREAUTH_PERMIT_WAIT,
                    permits.acquire_owned(),
                )
                .await;
                let permit = match acquire_result {
                    Ok(Ok(p)) => p,
                    Ok(Err(_)) => {
                        // Semaphore::acquire_owned only Errs on closed,
                        // which we never do.
                        eprintln!(
                            "[wsb-daemon] BUG: pre-auth semaphore closed; dropping {peer}"
                        );
                        drop(stream);
                        continue;
                    }
                    Err(_) => {
                        eprintln!(
                            "[wsb-daemon] pre-auth slot wait timed out after {:?}; dropping \
                             incoming IPC client {peer} ({MAX_CONCURRENT_PREAUTH} concurrent \
                             pre-auth tasks still in flight)",
                            PREAUTH_PERMIT_WAIT
                        );
                        drop(stream);
                        continue;
                    }
                };
                let nonce = nonce.clone();
                let guest = guest.clone();
                let shutdown = shutdown.clone();
                let guest_nonce = guest_nonce.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, &nonce, &guest, &shutdown, &guest_nonce, permit).await {
                        eprintln!("[wsb-daemon] IPC client error: {e:#}");
                    }
                });
            }
            _ = shutdown.notified() => break,
        }
    }
    Ok(())
}

/// Read one request line, authenticate it, and dispatch on the verb.
///
/// `permit` is the pre-auth concurrency token (review D2). It is held for the
/// auth read + verb-prefix dispatch only; long-running EXECs explicitly drop
/// it before entering [`handle_exec`] so a single exec does not hold a
/// pre-auth slot for the duration of a command.
async fn handle_client(
    stream: TcpStream,
    nonce: &str,
    guest: &Arc<Mutex<GuestSlot>>,
    shutdown: &Arc<Notify>,
    guest_nonce: &GuestNonce,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    // Cap the pre-auth read at MAX_AUTH_LINE_BYTES (review D1). Without this
    // bound, read_line grows its String for up to CLIENT_READ_TIMEOUT seconds
    // for any client that sends a long line and then idles - a trivial memory
    // sink against the persistent daemon. The cap is generous (1 KiB) so a
    // legitimate (~80-byte) verb-plus-nonce line is never truncated; an over-
    // long line is treated the same as malformed input and rejected.
    let mut line_bytes: Vec<u8> = Vec::with_capacity(128);
    let read_result = timeout(CLIENT_READ_TIMEOUT, async {
        let mut limited = (&mut reader).take(MAX_AUTH_LINE_BYTES);
        limited.read_until(b'\n', &mut line_bytes).await
    })
    .await
    .context("client read timed out")?
    .context("read client request")?;
    if read_result == 0 {
        return Ok(());
    }
    // A line that reached the cap without terminating with '\n' is treated as
    // malformed: do not waste the writer / a slot on it.
    let hit_cap = line_bytes.len() as u64 >= MAX_AUTH_LINE_BYTES && !line_bytes.ends_with(b"\n");
    if hit_cap {
        writer.write_all(b"ERR request too large\n").await.ok();
        return Ok(());
    }
    let line = match std::str::from_utf8(&line_bytes) {
        Ok(s) => s,
        Err(_) => {
            writer.write_all(b"ERR not utf8\n").await.ok();
            return Ok(());
        }
    };

    let trimmed = line.trim();
    let mut parts = trimmed.splitn(2, ' ');
    let verb = parts.next().unwrap_or("");
    let supplied = parts.next().unwrap_or("");

    if supplied != nonce {
        writer.write_all(b"ERR auth\n").await.ok();
        return Ok(());
    }

    if verb == IPC_PING {
        writer.write_all(b"PONG\n").await.ok();
        Ok(())
    } else if verb == IPC_STOP {
        // Reply before notifying so the client sees the ack. STOP intentionally
        // never touches the guest mutex: shutdown must not be blocked by an
        // in-flight exec.
        writer.write_all(b"OK\n").await.ok();
        shutdown.notify_one();
        Ok(())
    } else if verb == IPC_EXEC {
        // Release the pre-auth concurrency slot (review D2) before entering
        // the (potentially long-running) exec path: an EXEC of a multi-minute
        // command must not pin a pre-auth slot for the duration of the
        // command. Single-flight admission inside handle_exec independently
        // ensures only one exec runs at a time per sandbox.
        drop(permit);
        handle_exec(reader, writer, guest, guest_nonce).await
    } else {
        writer.write_all(b"ERR unknown command\n").await.ok();
        Ok(())
    }
}

/// Handle an `EXEC` after the auth line: read the framed [`ExecStart`], acquire
/// the single-flight guest slot, emit a status line, and (on admission) stream
/// the guest's output back as [`ipc_exec`] frames.
async fn handle_exec(
    mut reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    guest: &Arc<Mutex<GuestSlot>>,
    guest_nonce: &GuestNonce,
) -> Result<()> {
    let req = match timeout(EXEC_REQUEST_TIMEOUT, read_exec_start(&mut reader)).await {
        Ok(Ok(req)) => req,
        Ok(Err(e)) => {
            writer
                .write_all(format!("{IPC_ERR} bad request: {e}\n").as_bytes())
                .await
                .ok();
            return Ok(());
        }
        Err(_) => {
            writer
                .write_all(format!("{IPC_ERR} request timed out\n").as_bytes())
                .await
                .ok();
            return Ok(());
        }
    };

    // Single-flight: a non-blocking lock acquire + classify_admission to
    // map the slot state to a typed AdmissionDecision (review F2). The
    // try_lock failure and the slot-variant inspection happen at the same
    // observation point so the wire response always reflects the post-lock
    // truth.
    let slot_guard = guest.try_lock();
    let decision = match &slot_guard {
        Ok(slot) => classify_admission(slot, false),
        Err(_) => AdmissionDecision::Busy,
    };
    match decision {
        AdmissionDecision::Busy => {
            writer
                .write_all(format!("{IPC_ERR} {IPC_ERR_BUSY}\n").as_bytes())
                .await
                .ok();
            return Ok(());
        }
        AdmissionDecision::NotReady => {
            writer
                .write_all(format!("{IPC_ERR} {IPC_ERR_NOT_READY}\n").as_bytes())
                .await
                .ok();
            return Ok(());
        }
        AdmissionDecision::Poisoned(reason) => {
            writer
                .write_all(format!("{IPC_ERR} {reason}\n").as_bytes())
                .await
                .ok();
            return Ok(());
        }
        AdmissionDecision::Admit => {}
    }
    // SAFETY-ish: we hit Admit only when slot_guard is Ok AND slot was Ready;
    // unwrap is therefore infallible. We take the connection out of the slot
    // so we can borrow it mutably across exec await points; the placeholder
    // is only observable if this task is dropped mid-exec (process teardown).
    let mut slot = slot_guard.expect("slot_guard Ok matched on Admit branch");
    let taken = std::mem::replace(
        &mut *slot,
        GuestSlot::Poisoned("exec interrupted".to_string()),
    );
    let (mut conn, addr) = match taken {
        GuestSlot::Ready { conn, addr } => (conn, addr),
        // Unreachable: classify_admission(Ready) -> Admit is the only path
        // that reaches here. Other variants returned earlier above.
        other => unreachable!(
            "classify_admission admitted a non-Ready slot variant: {:?}",
            other
        ),
    };

    // Admitted. Send the OK status line before any binary frames.
    if let Err(e) = writer.write_all(b"OK\n").await {
        // The client vanished before we ran anything; the guest is untouched,
        // so restore the slot as Ready for the next caller.
        *slot = GuestSlot::Ready { conn, addr };
        return Err(anyhow::Error::new(e).context("write OK status"));
    }

    let exec_id = format!("exec-{}", EXEC_COUNTER.fetch_add(1, Ordering::Relaxed));
    match stream_exec_on_guest(&mut conn, &exec_id, &req, &mut reader, &mut writer).await {
        Ok(outcome) => {
            // Whether or not the IPC client survived, the guest ran to a clean
            // boundary; re-establish the data streams for the next exec and
            // restore the slot. Only AFTER releasing the single-flight lock do we
            // signal the client that the exec finished — so a back-to-back exec
            // never races the slot-release window (finding #77).
            let reconnect =
                reconnect_data_streams(&mut conn, addr, outcome.control_residual, guest_nonce)
                    .await;
            match &reconnect {
                Ok(()) => *slot = GuestSlot::Ready { conn, addr },
                Err(e) => *slot = GuestSlot::Poisoned(format!("stream reconnect failed: {e}")),
            }
            drop(slot);

            if outcome.ipc_alive {
                match write_exit_frame(&mut writer, outcome.exit_code, &outcome.error_message).await
                {
                    Ok(true) => {}
                    Ok(false) => eprintln!(
                        "[wsb-daemon] exec {exec_id}: client disconnected before exit frame"
                    ),
                    Err(e) => {
                        eprintln!("[wsb-daemon] exec {exec_id}: failed to encode exit frame: {e:#}")
                    }
                }
            } else {
                eprintln!(
                    "[wsb-daemon] exec {exec_id}: client disconnected mid-stream; guest reused"
                );
            }

            if let Err(e) = reconnect {
                eprintln!(
                    "[wsb-daemon] exec {exec_id}: completed (exit {}); stream reconnect failed, \
                     sandbox poisoned for future execs: {e:#}",
                    outcome.exit_code
                );
            }
        }
        Err(e) => {
            *slot = GuestSlot::Poisoned(format!("exec failed: {e}"));
            eprintln!("[wsb-daemon] exec {exec_id}: failed: {e:#}");
        }
    }
    Ok(())
}

/// Read the framed `ExecStart` request (4-byte LE length prefix + JSON) that
/// follows the `EXEC <nonce>` line on the same connection.
async fn read_exec_start<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<ExecStart> {
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .context("read ExecStart length prefix")?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_IPC_FRAME {
        anyhow::bail!("ExecStart frame too large: {len} bytes");
    }
    let mut payload = vec![0u8; len];
    reader
        .read_exact(&mut payload)
        .await
        .context("read ExecStart payload")?;
    ipc_exec::decode_exec_start(&payload).context("decode ExecStart")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener as TokioTcpListener;
    use windows_sandbox_common::auth::generate_nonce;

    // ===== F2: pure single-flight admission classifier tests =================

    #[test]
    fn classify_busy_when_lock_held_elsewhere_beats_any_state() {
        // The Busy branch must fire even when the slot itself is Ready /
        // Booting / Poisoned. Verified for every variant we can build
        // (Booting and Poisoned; Ready needs live sockets, see ready_slot
        // comment).
        assert_eq!(
            classify_admission(&GuestSlot::Booting, true),
            AdmissionDecision::Busy
        );
        assert_eq!(
            classify_admission(&GuestSlot::Poisoned("anything".into()), true),
            AdmissionDecision::Busy
        );
    }

    #[test]
    fn classify_booting_yields_not_ready() {
        assert_eq!(
            classify_admission(&GuestSlot::Booting, false),
            AdmissionDecision::NotReady
        );
    }

    #[test]
    fn classify_poisoned_propagates_reason_verbatim() {
        let decision = classify_admission(
            &GuestSlot::Poisoned("stream reconnect failed: timeout".to_string()),
            false,
        );
        assert_eq!(
            decision,
            AdmissionDecision::Poisoned("stream reconnect failed: timeout".to_string())
        );
    }

    #[test]
    fn classify_poisoned_does_not_admit_even_with_empty_reason() {
        let decision = classify_admission(&GuestSlot::Poisoned(String::new()), false);
        match decision {
            AdmissionDecision::Poisoned(r) => assert_eq!(r, ""),
            other => panic!("expected Poisoned with empty reason, got {other:?}"),
        }
    }

    // ===== F1: daemon control_server integration tests =======================
    //
    // These spin up `control_server::run` against an in-process tokio
    // TcpListener and drive it with handcrafted client connections so the
    // nonce auth / pre-auth bound / pre-auth concurrency / malformed-EXEC
    // surface is covered without the daemon binary, the guest agent, or a
    // real Windows Sandbox VM.
    //
    // We never put the guest slot into Ready (which would require live
    // sockets); EXEC tests therefore expect `ERR not ready` and assert that
    // admission ran on the right state.

    async fn bind_listener() -> (TokioTcpListener, SocketAddr) {
        let l = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        (l, addr)
    }

    async fn read_to_string(stream: &mut tokio::net::TcpStream) -> String {
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf)).await;
        String::from_utf8(buf).unwrap_or_default()
    }

    /// Drive `run` in a background task with a freshly bound listener and a
    /// known nonce, then return the bound address plus a shutdown notify the
    /// caller can use to stop the server when the test is done.
    async fn spawn_test_server(
        starting_slot: GuestSlot,
    ) -> (SocketAddr, Arc<Notify>, tokio::task::JoinHandle<Result<()>>) {
        let (listener, addr) = bind_listener().await;
        let nonce = "test-nonce-deadbeef".to_string();
        let shutdown = Arc::new(Notify::new());
        let guest = Arc::new(Mutex::new(starting_slot));
        let guest_nonce = Arc::new(generate_nonce());
        let server_shutdown = shutdown.clone();
        let handle =
            tokio::spawn(
                async move { run(listener, nonce, server_shutdown, guest, guest_nonce).await },
            );
        // Give the listener a tick to start polling. Without this, the very
        // first connect_to_string can race the accept.
        tokio::time::sleep(Duration::from_millis(20)).await;
        (addr, shutdown, handle)
    }

    #[tokio::test]
    async fn ping_with_correct_nonce_yields_pong() {
        let (addr, shutdown, handle) = spawn_test_server(GuestSlot::Booting).await;

        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(b"PING test-nonce-deadbeef\n").await.unwrap();
        s.shutdown().await.ok();
        assert_eq!(read_to_string(&mut s).await, "PONG\n");

        shutdown.notify_one();
        // Server may keep running until next accept; give it a chance to exit.
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn missing_nonce_yields_err_auth() {
        let (addr, shutdown, handle) = spawn_test_server(GuestSlot::Booting).await;

        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        // No nonce after the verb.
        s.write_all(b"PING\n").await.unwrap();
        s.shutdown().await.ok();
        assert_eq!(read_to_string(&mut s).await, "ERR auth\n");

        shutdown.notify_one();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn bad_nonce_yields_err_auth() {
        let (addr, shutdown, handle) = spawn_test_server(GuestSlot::Booting).await;

        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(b"PING wrong-nonce\n").await.unwrap();
        s.shutdown().await.ok();
        assert_eq!(read_to_string(&mut s).await, "ERR auth\n");

        shutdown.notify_one();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn oversized_pre_auth_line_yields_err_request_too_large() {
        let (addr, shutdown, handle) = spawn_test_server(GuestSlot::Booting).await;

        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Write 2 KiB without a newline - exceeds MAX_AUTH_LINE_BYTES (1024).
        // The daemon should respond with the bounded-read rejection and close.
        let payload = vec![b'A'; (MAX_AUTH_LINE_BYTES as usize) * 2];
        s.write_all(&payload).await.unwrap();
        s.shutdown().await.ok();
        let resp = read_to_string(&mut s).await;
        assert_eq!(
            resp, "ERR request too large\n",
            "expected bounded-read rejection; got {resp:?}"
        );

        shutdown.notify_one();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn unknown_verb_yields_err_unknown_command() {
        let (addr, shutdown, handle) = spawn_test_server(GuestSlot::Booting).await;

        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(b"WHATEVER test-nonce-deadbeef\n")
            .await
            .unwrap();
        s.shutdown().await.ok();
        assert_eq!(read_to_string(&mut s).await, "ERR unknown command\n");

        shutdown.notify_one();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn exec_against_booting_slot_yields_err_not_ready() {
        let (addr, shutdown, handle) = spawn_test_server(GuestSlot::Booting).await;

        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Send the auth line, then a valid ExecStart frame. The server's
        // admission classifier sees GuestSlot::Booting and must respond with
        // `ERR not ready` after consuming the request frame.
        s.write_all(b"EXEC test-nonce-deadbeef\n").await.unwrap();
        let start = ExecStart {
            script_code: "echo hi".to_string(),
            working_directory: String::new(),
            timeout_ms: 5_000,
        };
        let bytes = ipc_exec::encode_exec_start(&start).unwrap();
        s.write_all(&bytes).await.unwrap();
        s.shutdown().await.ok();
        let resp = read_to_string(&mut s).await;
        assert_eq!(
            resp,
            format!("{IPC_ERR} {IPC_ERR_NOT_READY}\n"),
            "got {resp:?}"
        );

        shutdown.notify_one();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn exec_against_poisoned_slot_propagates_reason() {
        let (addr, shutdown, handle) = spawn_test_server(GuestSlot::Poisoned(
            "stream reconnect failed: synthetic".to_string(),
        ))
        .await;

        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(b"EXEC test-nonce-deadbeef\n").await.unwrap();
        let start = ExecStart {
            script_code: "echo hi".to_string(),
            working_directory: String::new(),
            timeout_ms: 5_000,
        };
        let bytes = ipc_exec::encode_exec_start(&start).unwrap();
        s.write_all(&bytes).await.unwrap();
        s.shutdown().await.ok();
        let resp = read_to_string(&mut s).await;
        assert_eq!(
            resp,
            format!("{IPC_ERR} stream reconnect failed: synthetic\n"),
            "got {resp:?}"
        );

        shutdown.notify_one();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn malformed_exec_frame_yields_err_bad_request() {
        let (addr, shutdown, handle) = spawn_test_server(GuestSlot::Booting).await;

        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(b"EXEC test-nonce-deadbeef\n").await.unwrap();
        // Send a bogus length prefix that's not followed by valid JSON.
        // The length is well under MAX_IPC_FRAME so the daemon won't reject
        // on size; instead it should fail to decode the JSON and reply with
        // `ERR bad request: ...`.
        s.write_all(&5u32.to_le_bytes()).await.unwrap();
        s.write_all(b"badjs").await.unwrap();
        s.shutdown().await.ok();
        let resp = read_to_string(&mut s).await;
        assert!(
            resp.starts_with(&format!("{IPC_ERR} bad request:")),
            "expected ERR bad request prefix, got {resp:?}"
        );

        shutdown.notify_one();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn stop_with_correct_nonce_replies_ok_and_shuts_down() {
        let (addr, shutdown, handle) = spawn_test_server(GuestSlot::Booting).await;

        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(b"STOP test-nonce-deadbeef\n").await.unwrap();
        s.shutdown().await.ok();
        assert_eq!(read_to_string(&mut s).await, "OK\n");

        // STOP fires the shutdown notify; server loop should exit
        // promptly without needing our manual notify.
        let result = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("server should exit within timeout after STOP");
        result.expect("join").expect("server returned Ok");
        let _ = shutdown;
    }

    #[tokio::test]
    async fn concurrent_exec_returns_err_busy() {
        // Drive two concurrent EXECs against a Booting slot. The slot mutex
        // is contended only during admission; even with Booting, the
        // try_lock pattern means we cannot reliably produce a `Busy` from
        // the outside without a Ready slot whose handler holds the lock for
        // a long time.
        //
        // Instead we hand-test the busy path by holding the mutex from a
        // separate task before sending the EXEC. The classifier sees
        // slot_held_elsewhere=true and returns Busy regardless of state.
        let (listener, addr) = bind_listener().await;
        let nonce = "test-nonce-deadbeef".to_string();
        let shutdown = Arc::new(Notify::new());
        let guest = Arc::new(Mutex::new(GuestSlot::Booting));
        let guest_nonce = Arc::new(generate_nonce());

        // Hold the mutex from this test thread so the EXEC handler's
        // try_lock fails. Use the same Arc so the contention is real.
        let holder = guest.clone();
        let server_shutdown = shutdown.clone();
        let handle =
            tokio::spawn(
                async move { run(listener, nonce, server_shutdown, guest, guest_nonce).await },
            );
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Acquire the slot lock and HOLD it for the duration of the EXEC.
        let _held = holder.lock().await;

        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(b"EXEC test-nonce-deadbeef\n").await.unwrap();
        let start = ExecStart {
            script_code: "echo hi".to_string(),
            working_directory: String::new(),
            timeout_ms: 5_000,
        };
        let bytes = ipc_exec::encode_exec_start(&start).unwrap();
        s.write_all(&bytes).await.unwrap();
        s.shutdown().await.ok();
        let resp = read_to_string(&mut s).await;
        assert_eq!(
            resp,
            format!("{IPC_ERR} {IPC_ERR_BUSY}\n"),
            "expected ERR busy when slot is held elsewhere; got {resp:?}"
        );

        drop(_held);
        shutdown.notify_one();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test(start_paused = true)]
    async fn pre_auth_concurrency_cap_drops_after_wait_timeout() {
        // Saturate MAX_CONCURRENT_PREAUTH (32) slots with slow-loris clients
        // that never send a newline, then attempt one more connection. The
        // 33rd connection now waits up to PREAUTH_PERMIT_WAIT for a permit
        // (review H4 -- was instant-drop); under the saturating fixture the
        // wait elapses and the daemon drops the excess. Fast-forwards
        // virtual time so the test stays sub-second despite the 5s
        // production wait.
        let (addr, shutdown, handle) = spawn_test_server(GuestSlot::Booting).await;

        // Open MAX_CONCURRENT_PREAUTH slow-loris connections and hold them.
        let mut held: Vec<tokio::net::TcpStream> = Vec::new();
        for _ in 0..MAX_CONCURRENT_PREAUTH {
            let s = tokio::net::TcpStream::connect(addr).await.unwrap();
            held.push(s);
        }

        // Yield to let the daemon spin up handler tasks for all 32.
        tokio::task::yield_now().await;

        // The 33rd connection sits on `acquire_owned()` because all
        // permits are held. Connect, then advance virtual time past
        // PREAUTH_PERMIT_WAIT and read to EOF -- the daemon should drop
        // the socket once the wait timeout fires.
        let mut excess = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Bump time a small amount past the production wait.
        tokio::time::advance(PREAUTH_PERMIT_WAIT + Duration::from_millis(100)).await;
        let resp = read_to_string(&mut excess).await;
        assert_eq!(
            resp, "",
            "excess connection should be dropped after PREAUTH_PERMIT_WAIT; got {resp:?}"
        );

        drop(held);
        shutdown.notify_one();
        let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
    }

    #[tokio::test(start_paused = true)]
    async fn pre_auth_burst_within_wait_window_succeeds() {
        // Review H4 regression: a brief burst that briefly exceeds
        // MAX_CONCURRENT_PREAUTH must NOT surface as a backend error. The
        // 33rd connection waits up to PREAUTH_PERMIT_WAIT; if even a
        // single held connection is released within that window, the 33rd
        // wins a permit and the daemon proceeds with the auth read
        // instead of dropping. We assert "proceeds" by sending a
        // verb-less line and observing the daemon's `ERR unknown` reply
        // -- the pre-fix code would have closed the socket silently
        // (empty read).
        let (addr, shutdown, handle) = spawn_test_server(GuestSlot::Booting).await;

        // Saturate the cap with slow-loris clients we *will* release.
        let mut held: Vec<tokio::net::TcpStream> = Vec::new();
        for _ in 0..MAX_CONCURRENT_PREAUTH {
            held.push(tokio::net::TcpStream::connect(addr).await.unwrap());
        }
        tokio::task::yield_now().await;

        let mut excess = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Release one held connection well inside the wait window. The
        // dropped TcpStream causes the daemon-side handle_client task to
        // return, which releases its permit; the 33rd connection's
        // acquire_owned() then completes and handle_client runs.
        tokio::time::advance(Duration::from_millis(50)).await;
        held.pop();
        // Yield repeatedly so the daemon's released-permit -> excess-wakes
        // chain has time to schedule under paused time.
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }

        // Send a verb-less line so the daemon's auth-first guard
        // dispatches and replies with ERR unknown. (The point is just
        // that *something* came back -- the connection was not silently
        // dropped.)
        excess
            .write_all(b"junkverb fake-nonce\n")
            .await
            .expect("write should succeed once handler is reading");
        excess.shutdown().await.ok();
        let resp = read_to_string(&mut excess).await;
        assert!(
            !resp.is_empty(),
            "burst within wait window must reach the daemon's auth path, got empty (= silent drop)"
        );

        drop(held);
        shutdown.notify_one();
        let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
    }
}
