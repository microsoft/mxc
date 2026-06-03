//! Nonce-authenticated control protocol server for the state-aware daemon.
//!
//! Serves a trivial line protocol on the daemon's localhost IPC port:
//!   request  : `<VERB> <nonce>\n`
//!   response : `OK\n` | `PONG\n` | `ERR <message>\n`
//!
//! The nonce authenticates the caller against a process that merely squats the
//! localhost port. Only two verbs exist in this phase: `PING` (liveness) and
//! `STOP` (tear down + exit). Exec lands in Phase 4b.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::time::timeout;

use windows_sandbox_lifecycle::control_plane::{IPC_PING, IPC_STOP};

/// Maximum time to wait for a client to send its request line.
const CLIENT_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Outcome of handling a single client connection.
enum Handled {
    /// A valid, authenticated STOP — the daemon should shut down.
    Stop,
    /// Anything else (ping, auth failure, unknown verb).
    Continue,
}

/// Serve the control protocol until an authenticated STOP arrives (or the
/// `shutdown` notify fires). Returns once the daemon should tear down.
pub async fn run(listener: TcpListener, nonce: String, shutdown: Arc<Notify>) -> Result<()> {
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _peer) = accepted.context("accept IPC client")?;
                match handle_client(stream, &nonce).await {
                    Ok(Handled::Stop) => break,
                    Ok(Handled::Continue) => {}
                    Err(e) => eprintln!("[wsb-daemon] IPC client error: {e:#}"),
                }
            }
            _ = shutdown.notified() => break,
        }
    }
    Ok(())
}

/// Read one request line, authenticate it, and reply.
async fn handle_client(stream: tokio::net::TcpStream, nonce: &str) -> Result<Handled> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    timeout(CLIENT_READ_TIMEOUT, reader.read_line(&mut line))
        .await
        .context("client read timed out")?
        .context("read client request")?;

    let line = line.trim();
    let mut parts = line.splitn(2, ' ');
    let verb = parts.next().unwrap_or("");
    let supplied = parts.next().unwrap_or("");

    if supplied != nonce {
        writer.write_all(b"ERR auth\n").await.ok();
        return Ok(Handled::Continue);
    }

    if verb == IPC_PING {
        writer.write_all(b"PONG\n").await.ok();
        Ok(Handled::Continue)
    } else if verb == IPC_STOP {
        writer.write_all(b"OK\n").await.ok();
        Ok(Handled::Stop)
    } else {
        writer.write_all(b"ERR unknown command\n").await.ok();
        Ok(Handled::Continue)
    }
}
