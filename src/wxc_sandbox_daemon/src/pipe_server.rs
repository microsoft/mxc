//! Named-pipe server for wxc-exec clients.
//!
//! Listens on `\\.\pipe\<name>` and handles execution requests from wxc-exec.
//! Each request triggers sandbox launch (if not already running), connection
//! to the guest, and relaying the execution.

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

use crate::tcp_bridge;
use crate::{DaemonState, rendezvous, sandbox_vm};

/// Run the named-pipe server loop.
///
/// This is a simplified implementation that uses a TCP listener on localhost
/// as the "named pipe" transport.  A future iteration will use actual Win32
/// named pipes via `tokio::net::windows::named_pipe`.
pub async fn run(pipe_name: &str, state: Arc<Mutex<DaemonState>>) -> Result<()> {
    // For now, use a localhost TCP port as the IPC channel.  The port is
    // deterministic from the pipe name to allow wxc-exec to find us.
    let port = pipe_name_to_port(pipe_name);
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .with_context(|| format!("bind daemon IPC on 127.0.0.1:{}", port))?;
    eprintln!("[daemon] IPC listening on 127.0.0.1:{}", port);

    loop {
        let (stream, peer) = listener.accept().await.context("accept IPC client")?;
        eprintln!("[daemon] client connected from {}", peer);

        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, state).await {
                eprintln!("[daemon] client error: {:#}", e);
            }
        });
    }
}

/// Handle a single wxc-exec client connection.
///
/// Protocol (line-based, simple):
///   Client → Daemon: `EXEC <json-request>\n`
///   Daemon → Client: `RESULT <exit-code> <error-message>\n`
async fn handle_client(
    stream: tokio::net::TcpStream,
    state: Arc<Mutex<DaemonState>>,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    reader
        .read_line(&mut line)
        .await
        .context("read client request")?;

    let line = line.trim();
    if !line.starts_with("EXEC ") {
        writer
            .write_all(b"ERROR unknown command\n")
            .await
            .ok();
        return Ok(());
    }
    let json_payload = &line["EXEC ".len()..];

    // Parse the execution request.
    let req: ClientExecRequest = serde_json::from_str(json_payload)
        .context("parse client exec request")?;

    // Ensure sandbox is running and we have a guest connection.
    ensure_sandbox_ready(&state).await?;

    // Update activity timestamp.
    {
        let mut s = state.lock().await;
        s.last_activity = std::time::Instant::now();
    }

    // Execute on the guest.
    let (exit_code, error_message) = {
        let mut s = state.lock().await;
        let conn = s
            .guest_connection
            .as_mut()
            .context("no guest connection")?;

        let exec_id = uuid::Uuid::new_v4().to_string();
        tcp_bridge::execute_on_guest(
            conn,
            &exec_id,
            &req.script_code,
            &req.working_directory,
            req.timeout_ms,
            &[],
        )
        .await?
    };

    // Send result back to wxc-exec client.
    let response = format!("RESULT {} {}\n", exit_code, error_message);
    writer.write_all(response.as_bytes()).await.ok();

    // Update activity timestamp.
    {
        let mut s = state.lock().await;
        s.last_activity = std::time::Instant::now();
    }

    Ok(())
}

/// Ensure the sandbox VM is running and we have a guest connection.
async fn ensure_sandbox_ready(state: &Arc<Mutex<DaemonState>>) -> Result<()> {
    let mut s = state.lock().await;

    if s.guest_connection.is_some() {
        return Ok(());
    }

    // Determine paths.
    let exe_dir = std::env::current_exe()
        .context("current_exe")?
        .parent()
        .context("exe parent dir")?
        .to_path_buf();

    let agent_dir = exe_dir.clone();
    let rendezvous_dir = std::env::temp_dir().join("wxc-sandbox-rendezvous");
    std::fs::create_dir_all(&rendezvous_dir)
        .context("create rendezvous dir")?;

    // Clean up stale rendezvous file.
    rendezvous::cleanup(&rendezvous_dir).await?;

    if !s.sandbox_running {
        // Generate .wsb and launch sandbox.
        let temp_dir = std::env::temp_dir().join("wxc-sandbox-config");
        std::fs::create_dir_all(&temp_dir).context("create .wsb config dir")?;

        let wsb_path = sandbox_vm::generate_wsb(&agent_dir, &rendezvous_dir, &temp_dir)?;
        sandbox_vm::launch(&wsb_path).await?;
        s.sandbox_running = true;
        eprintln!("[daemon] sandbox VM launched");
    }

    // Drop the lock while we poll for rendezvous (can take 15-20s).
    drop(s);

    let guest_addr = rendezvous::wait_for_rendezvous(
        &rendezvous_dir,
        std::time::Duration::from_secs(120),
        std::time::Duration::from_millis(500),
    )
    .await
    .context("rendezvous failed")?;

    // Connect to the guest agent.
    let conn = tcp_bridge::connect_to_guest(
        guest_addr,
        std::time::Duration::from_secs(30),
    )
    .await
    .context("connect to guest agent")?;

    let mut s = state.lock().await;
    s.guest_connection = Some(conn);

    Ok(())
}

/// Deterministic port derived from the pipe name, in the ephemeral range.
fn pipe_name_to_port(name: &str) -> u16 {
    let hash: u32 = name.bytes().fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));
    // Map to port range 49152-65535 (IANA ephemeral range).
    let range = 65535 - 49152;
    49152 + (hash % range) as u16
}

/// Client execution request (JSON sent over the IPC channel).
#[derive(serde::Deserialize)]
struct ClientExecRequest {
    script_code: String,
    #[serde(default)]
    working_directory: String,
    #[serde(default)]
    timeout_ms: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_name_to_port_is_deterministic() {
        let p1 = pipe_name_to_port("wxc-sandbox");
        let p2 = pipe_name_to_port("wxc-sandbox");
        assert_eq!(p1, p2);
        assert!(p1 >= 49152);
    }

    #[test]
    fn pipe_name_to_port_varies_with_name() {
        let p1 = pipe_name_to_port("wxc-sandbox");
        let p2 = pipe_name_to_port("other-pipe");
        assert_ne!(p1, p2);
    }
}
