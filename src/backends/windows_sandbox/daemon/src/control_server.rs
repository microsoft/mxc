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
use tokio::sync::{Mutex, Notify};
use tokio::time::timeout;

use windows_sandbox_lifecycle::bridge::{
    reconnect_data_streams, stream_exec_on_guest, GuestConnection,
};
use windows_sandbox_lifecycle::control_plane::{IPC_EXEC, IPC_PING, IPC_STOP};
use windows_sandbox_lifecycle::ipc_exec::{self, ExecStart, MAX_IPC_FRAME};

/// Maximum time to wait for a client to send its request line.
const CLIENT_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum time to wait for the framed `ExecStart` request after the `EXEC`
/// auth line.
const EXEC_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

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

/// Serve the control protocol until an authenticated `STOP` arrives (or the
/// `shutdown` notify fires). Returns once the daemon should tear down. Each
/// client is dispatched to its own task so no verb can be head-of-line blocked
/// by an in-flight exec.
pub async fn run(
    listener: TcpListener,
    nonce: String,
    shutdown: Arc<Notify>,
    guest: Arc<Mutex<GuestSlot>>,
) -> Result<()> {
    let nonce = Arc::new(nonce);
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _peer) = accepted.context("accept IPC client")?;
                let nonce = nonce.clone();
                let guest = guest.clone();
                let shutdown = shutdown.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, &nonce, &guest, &shutdown).await {
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
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    timeout(CLIENT_READ_TIMEOUT, reader.read_line(&mut line))
        .await
        .context("client read timed out")?
        .context("read client request")?;

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
        handle_exec(reader, writer, guest).await
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
) -> Result<()> {
    let req = match timeout(EXEC_REQUEST_TIMEOUT, read_exec_start(&mut reader)).await {
        Ok(Ok(req)) => req,
        Ok(Err(e)) => {
            writer
                .write_all(format!("ERR bad request: {e}\n").as_bytes())
                .await
                .ok();
            return Ok(());
        }
        Err(_) => {
            writer.write_all(b"ERR request timed out\n").await.ok();
            return Ok(());
        }
    };

    // Single-flight: a non-blocking lock acquire. A busy slot means another
    // exec is already running on this sandbox.
    let mut slot = match guest.try_lock() {
        Ok(slot) => slot,
        Err(_) => {
            writer.write_all(b"ERR busy\n").await.ok();
            return Ok(());
        }
    };

    // Take the connection out so we can borrow it mutably across the await
    // points. The placeholder is only observable if this task is dropped
    // mid-exec (e.g. process teardown), in which case the daemon is exiting.
    let taken = std::mem::replace(
        &mut *slot,
        GuestSlot::Poisoned("exec interrupted".to_string()),
    );
    let (mut conn, addr) = match taken {
        GuestSlot::Ready { conn, addr } => (conn, addr),
        GuestSlot::Booting => {
            *slot = GuestSlot::Booting;
            writer.write_all(b"ERR not ready\n").await.ok();
            return Ok(());
        }
        GuestSlot::Poisoned(reason) => {
            let msg = format!("ERR {reason}\n");
            *slot = GuestSlot::Poisoned(reason);
            writer.write_all(msg.as_bytes()).await.ok();
            return Ok(());
        }
    };

    // Admitted. Send the OK status line before any binary frames.
    if let Err(e) = writer.write_all(b"OK\n").await {
        // The client vanished before we ran anything; the guest is untouched,
        // so restore the slot as Ready for the next caller.
        *slot = GuestSlot::Ready { conn, addr };
        return Err(anyhow::Error::new(e).context("write OK status"));
    }

    let exec_id = format!("exec-{}", EXEC_COUNTER.fetch_add(1, Ordering::Relaxed));
    match stream_exec_on_guest(&mut conn, &exec_id, &req, &mut writer).await {
        Ok(outcome) => {
            // Whether or not the IPC client survived, the guest ran to a clean
            // boundary; re-establish the data streams for the next exec.
            match reconnect_data_streams(&mut conn, addr, outcome.control_residual).await {
                Ok(()) => {
                    *slot = GuestSlot::Ready { conn, addr };
                    if !outcome.ipc_alive {
                        eprintln!(
                            "[wsb-daemon] exec {exec_id}: client disconnected mid-stream; \
                             guest reused"
                        );
                    }
                }
                Err(e) => {
                    *slot = GuestSlot::Poisoned(format!("stream reconnect failed: {e}"));
                    eprintln!("[wsb-daemon] exec {exec_id}: reconnect failed: {e:#}");
                }
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
