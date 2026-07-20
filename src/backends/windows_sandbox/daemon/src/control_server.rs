//! Nonce-authenticated localhost control server for the state-aware daemon.
//!
//! Supports `PING`, `STOP`, and single-flight `EXEC`; each connection runs in
//! its own task so long executions do not block liveness or shutdown requests.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, MutexGuard, Notify, Semaphore};
use tokio::time::timeout;

use windows_sandbox_lifecycle::bridge::{
    reconnect_data_streams, stream_exec_on_guest, write_exit_frame, GuestConnection,
};
use windows_sandbox_lifecycle::control_plane::{
    IPC_ERR, IPC_ERR_BUSY, IPC_ERR_NOT_READY, IPC_EXEC, IPC_PING, IPC_STOP,
};
use windows_sandbox_lifecycle::ipc_exec;

use windows_sandbox_common::auth::Nonce as GuestNonce;

/// Maximum time to wait for a client request line.
const CLIENT_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum time to wait for the framed `ExecStart` request after the `EXEC`
/// auth line.
const EXEC_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Hard cap on the pre-auth request line length.
const MAX_AUTH_LINE_BYTES: u64 = 1024;

/// Bound on concurrent pre-auth client connections.
const MAX_CONCURRENT_PREAUTH: usize = 32;

/// Bounded wait for a pre-auth concurrency permit before dropping a connection.
const PREAUTH_PERMIT_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Monotonic source of per-exec correlation ids (unique within this daemon).
static EXEC_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The daemon's single held guest connection.
pub enum GuestSlot {
    Booting,
    Ready {
        conn: GuestConnection,
        addr: std::net::SocketAddr,
    },
    /// The held guest connection was lost or left indeterminate by a failed
    /// exec or a post-exec data-stream reconnect. This is terminal for the
    /// sandbox's session: there is no path back to `Ready`, because the daemon
    /// cannot safely re-establish its single held guest connection mid-session.
    /// Every subsequent `EXEC` fails fast with the recorded reason; the caller
    /// must `stop`/`deprovision` and re-provision. `STOP`/teardown still work.
    Unusable(String),
}

struct ReleasedGuestSlot(());

fn restore_and_release_guest_slot(
    mut slot: MutexGuard<'_, GuestSlot>,
    next: GuestSlot,
) -> ReleasedGuestSlot {
    *slot = next;
    drop(slot);
    ReleasedGuestSlot(())
}

async fn write_released_exit_frame(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    _released: ReleasedGuestSlot,
    exit_code: i32,
    error_message: &str,
) -> Result<bool> {
    write_exit_frame(writer, exit_code, error_message).await
}

impl std::fmt::Debug for GuestSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuestSlot::Booting => write!(f, "Booting"),
            GuestSlot::Ready { addr, .. } => write!(f, "Ready {{ addr: {addr} }}"),
            GuestSlot::Unusable(reason) => write!(f, "Unusable({reason:?})"),
        }
    }
}

/// Pure admission decision for an incoming EXEC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionDecision {
    Admit,
    Busy,
    NotReady,
    Unusable(String),
}

/// Pure single-flight admission classifier. See [`AdmissionDecision`].
pub fn classify_admission(slot_state: &GuestSlot, slot_held_elsewhere: bool) -> AdmissionDecision {
    if slot_held_elsewhere {
        return AdmissionDecision::Busy;
    }
    match slot_state {
        GuestSlot::Ready { .. } => AdmissionDecision::Admit,
        GuestSlot::Booting => AdmissionDecision::NotReady,
        GuestSlot::Unusable(reason) => AdmissionDecision::Unusable(reason.clone()),
    }
}

/// Serve the control protocol until authenticated STOP/shutdown.
pub async fn run(
    listener: TcpListener,
    nonce: String,
    shutdown: Arc<Notify>,
    guest: Arc<Mutex<GuestSlot>>,
    guest_nonce: Arc<GuestNonce>,
) -> Result<()> {
    let nonce = Arc::new(nonce);
    let preauth_permits = Arc::new(Semaphore::new(MAX_CONCURRENT_PREAUTH));
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(sp) => sp,
                    Err(e) => {
                        // A transient accept() failure (e.g. a client that reset
                        // between the kernel completing the connection and our
                        // accept, or a momentary resource shortage) must not tear
                        // down the IPC server and, with it, the running sandbox.
                        // Log and keep serving; an authenticated STOP is the only
                        // intended way out of this loop.
                        eprintln!(
                            "[wsb-daemon] transient IPC accept error (continuing): {e:#}"
                        );
                        continue;
                    }
                };
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
        handle_exec(reader, writer, guest, guest_nonce, permit).await
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
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<()> {
    let req = match timeout(
        EXEC_REQUEST_TIMEOUT,
        ipc_exec::read_exec_start_async(&mut reader),
    )
    .await
    {
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
        AdmissionDecision::Unusable(reason) => {
            writer
                .write_all(format!("{IPC_ERR} {reason}\n").as_bytes())
                .await
                .ok();
            return Ok(());
        }
        AdmissionDecision::Admit => {}
    }
    let mut slot = slot_guard.expect("slot_guard Ok matched on Admit branch");
    let taken = std::mem::replace(
        &mut *slot,
        GuestSlot::Unusable("exec interrupted".to_string()),
    );
    let (mut conn, addr) = match taken {
        GuestSlot::Ready { conn, addr } => (conn, addr),
        other => unreachable!(
            "classify_admission admitted a non-Ready slot variant: {:?}",
            other
        ),
    };

    if let Err(e) = writer.write_all(b"OK\n").await {
        // The client vanished before we ran anything; the guest is untouched,
        // so restore the slot as Ready for the next caller.
        *slot = GuestSlot::Ready { conn, addr };
        return Err(anyhow::Error::new(e).context("write OK status"));
    }

    drop(permit);

    let exec_id = format!("exec-{}", EXEC_COUNTER.fetch_add(1, Ordering::Relaxed));
    match stream_exec_on_guest(&mut conn, &exec_id, &req, &mut reader, &mut writer).await {
        Ok(outcome) => {
            let reconnect =
                reconnect_data_streams(&mut conn, addr, outcome.control_residual, guest_nonce)
                    .await;
            let next_slot = match &reconnect {
                Ok(()) => GuestSlot::Ready { conn, addr },
                Err(e) => GuestSlot::Unusable(format!("stream reconnect failed: {e}")),
            };
            let released = restore_and_release_guest_slot(slot, next_slot);

            if outcome.ipc_alive {
                match write_released_exit_frame(
                    &mut writer,
                    released,
                    outcome.exit_code,
                    &outcome.error_message,
                )
                .await
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
                let _ = released;
            }

            if let Err(e) = reconnect {
                eprintln!(
                    "[wsb-daemon] exec {exec_id}: completed (exit {}); stream reconnect failed, \
                     sandbox left unusable for future execs: {e:#}",
                    outcome.exit_code
                );
            }
        }
        Err(e) => {
            *slot = GuestSlot::Unusable(format!("exec failed: {e}"));
            eprintln!("[wsb-daemon] exec {exec_id}: failed: {e:#}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener as TokioTcpListener;
    use windows_sandbox_common::auth::generate_nonce;
    use windows_sandbox_lifecycle::ipc_exec::ExecStart;

    #[tokio::test]
    async fn released_guest_slot_is_unlocked() {
        let guest = Mutex::new(GuestSlot::Booting);
        let slot = guest.lock().await;

        let _released =
            restore_and_release_guest_slot(slot, GuestSlot::Unusable("test".to_string()));

        assert!(guest.try_lock().is_ok());
    }

    // ===== pure single-flight admission classifier tests ====================

    #[test]
    fn classify_busy_when_lock_held_elsewhere_beats_any_state() {
        // The Busy branch must fire even when the slot itself is Ready /
        // Booting / Unusable. Verified for every variant we can build
        // (Booting and Unusable; Ready needs live sockets, see ready_slot
        // comment).
        assert_eq!(
            classify_admission(&GuestSlot::Booting, true),
            AdmissionDecision::Busy
        );
        assert_eq!(
            classify_admission(&GuestSlot::Unusable("anything".into()), true),
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
    fn classify_unusable_propagates_reason_verbatim() {
        let decision = classify_admission(
            &GuestSlot::Unusable("stream reconnect failed: timeout".to_string()),
            false,
        );
        assert_eq!(
            decision,
            AdmissionDecision::Unusable("stream reconnect failed: timeout".to_string())
        );
    }

    #[test]
    fn classify_unusable_does_not_admit_even_with_empty_reason() {
        let decision = classify_admission(&GuestSlot::Unusable(String::new()), false);
        match decision {
            AdmissionDecision::Unusable(r) => assert_eq!(r, ""),
            other => panic!("expected Unusable with empty reason, got {other:?}"),
        }
    }

    // ===== daemon control_server integration tests ===========================
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
        let guest_nonce = Arc::new(generate_nonce().expect("generate nonce"));
        let server_shutdown = shutdown.clone();
        let handle =
            tokio::spawn(
                async move { run(listener, nonce, server_shutdown, guest, guest_nonce).await },
            );
        // No sleep needed here. `TcpListener::bind` has already
        // succeeded synchronously on `127.0.0.1:0`; the OS keeps incoming
        // SYNs in the listen backlog (default ~128) until the spawned
        // `run` task calls `accept`, so the test's first
        // `TcpStream::connect` cannot race the accept loop -- it
        // succeeds at the TCP layer either way and gets serviced as
        // soon as the accept catches up.
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
    async fn exec_against_unusable_slot_propagates_reason() {
        let (addr, shutdown, handle) = spawn_test_server(GuestSlot::Unusable(
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
        let guest_nonce = Arc::new(generate_nonce().expect("generate nonce"));

        // Hold the mutex from this test thread so the EXEC handler's
        // try_lock fails. Use the same Arc so the contention is real.
        let holder = guest.clone();
        let server_shutdown = shutdown.clone();
        let handle =
            tokio::spawn(
                async move { run(listener, nonce, server_shutdown, guest, guest_nonce).await },
            );
        // Same reasoning as the spawn_test_server helper above:
        // the OS TCP backlog already absorbs the immediate connect, so
        // we don't need to give the spawned `run` task a head start.

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
        // instead of being dropped instantly; under the saturating fixture the
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
        // Regression coverage: a brief burst that briefly exceeds
        // MAX_CONCURRENT_PREAUTH must NOT surface as a backend error. The
        // 33rd connection waits up to PREAUTH_PERMIT_WAIT; if even a
        // single held connection is released within that window, the 33rd
        // wins a permit and the daemon proceeds with the auth read
        // instead of dropping. We assert "proceeds" by sending a verb-less
        // line and observing the daemon's `ERR unknown` reply; an instant-drop
        // would instead close the socket silently (empty read).
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
