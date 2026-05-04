//! Named-pipe server for wxc-exec clients.
//!
//! Listens on `\\.\pipe\<name>` and handles execution requests from wxc-exec.
//! Each request triggers sandbox launch (if not already running), connection
//! to the guest, and relaying the execution.

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{Mutex, Notify};

use crate::tcp_bridge;
use crate::{rendezvous, sandbox_vm, DaemonState};
use wxc_common::sandbox_protocol::DaemonResult;

/// Maximum number of sandbox launch attempts before giving up.
const MAX_LAUNCH_ATTEMPTS: u32 = 3;

/// Backoff delay (seconds) between sandbox launch retries.
const LAUNCH_BACKOFF_SECS: [u64; 3] = [0, 10, 20];

/// Maximum time (seconds) to wait for the guest agent's rendezvous file.
/// First VM boot can take 3-5+ minutes; 360s covers worst-case cold starts.
const RENDEZVOUS_TIMEOUT_SECS: u64 = 360;

/// Polling interval (milliseconds) when checking for the rendezvous file.
const RENDEZVOUS_POLL_INTERVAL_MS: u64 = 500;

/// Maximum time (seconds) to connect to the guest agent after rendezvous.
const GUEST_CONNECT_TIMEOUT_SECS: u64 = 30;

/// Run the named-pipe server loop.
///
/// This is a simplified implementation that uses a TCP listener on localhost
/// as the "named pipe" transport.  A future iteration will use actual Win32
/// named pipes via `tokio::net::windows::named_pipe`.
pub async fn run(
    pipe_name: &str,
    state: Arc<Mutex<DaemonState>>,
    shutdown: Arc<Notify>,
) -> Result<()> {
    // For now, use a localhost TCP port as the IPC channel.  The port is
    // deterministic from the pipe name to allow wxc-exec to find us.
    let port = pipe_name_to_port(pipe_name);
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .with_context(|| format!("bind daemon IPC on 127.0.0.1:{}", port))?;
    eprintln!("[daemon] IPC listening on 127.0.0.1:{}", port);

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, peer) = result.context("accept IPC client")?;
                eprintln!("[daemon] client connected from {}", peer);

                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, state).await {
                        eprintln!("[daemon] client error: {:#}", e);
                    }
                });
            }
            _ = shutdown.notified() => {
                eprintln!("[daemon] shutdown signal received, stopping pipe server");
                break;
            }
        }
    }

    Ok(())
}

/// Handle a single wxc-exec client connection.
///
/// Protocol (line-based, simple):
///   Client → Daemon: `EXEC <json-request>\n`
///   Daemon → Client: `RESULT <exit-code> <stdout-base64> <stderr-base64> <error-message>\n`
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
        writer.write_all(b"ERROR unknown command\n").await.ok();
        return Ok(());
    }
    let json_payload = &line["EXEC ".len()..];

    // Parse the execution request.
    let req: ClientExecRequest =
        serde_json::from_str(json_payload).context("parse client exec request")?;

    match execute_request(&req, &state).await {
        Ok(response) => {
            writer.write_all(response.as_bytes()).await.ok();
        }
        Err(e) => {
            let error_response = format!("ERROR {:#}\n", e);
            writer.write_all(error_response.as_bytes()).await.ok();
        }
    }

    // Update activity timestamp.
    {
        let mut s = state.lock().await;
        s.last_activity = std::time::Instant::now();
    }

    Ok(())
}

/// Execute the client request and return the formatted response line.
async fn execute_request(
    req: &ClientExecRequest,
    state: &Arc<Mutex<DaemonState>>,
) -> Result<String> {
    // Ensure sandbox is running and we have a guest connection.
    ensure_sandbox_ready(state).await?;

    // Update activity timestamp.
    {
        let mut locked = state.lock().await;
        locked.last_activity = std::time::Instant::now();
    }

    // Execute on the guest and reconnect data streams for the next
    // execution.  Both operations must run under a single lock acquisition
    // so that a concurrent client cannot send a new EXEC (or consume the
    // StreamsReady message) while we are between execute and reconnect.
    let mut locked = state.lock().await;
    let addr = locked.guest_addr.context("no guest address")?;
    let conn = locked
        .guest_connection
        .as_mut()
        .context("no guest connection")?;

    let exec_id = uuid::Uuid::new_v4().to_string();
    let result = tcp_bridge::execute_on_guest(
        conn,
        &exec_id,
        &req.script_code,
        &req.working_directory,
        req.timeout_ms,
        &[],
    )
    .await?;

    // Reconnect data streams for the next execution. The guest will
    // re-accept 3 new data connections and signal StreamsReady.
    if let Err(err) =
        tcp_bridge::reconnect_data_streams(conn, addr, result.control_residual).await
    {
        eprintln!("[daemon] failed to reconnect data streams: {:#}", err);
        // Full reset so the next request tears down and relaunches
        // rather than waiting for a rendezvous that won't appear.
        locked.guest_connection = None;
        locked.guest_addr = None;
        locked.sandbox_running = false;
    }
    drop(locked);

    Ok(DaemonResult {
        exit_code: result.exit_code,
        stdout: result.stdout,
        stderr: result.stderr,
        error_message: result.error_message,
    }
    .to_line())
}

/// Ensure the sandbox VM is running and we have a guest connection.
///
/// Retries once on failure — tears down the sandbox and relaunches.
///
/// Updates `last_activity` before starting work so the idle watchdog
/// does not fire during the multi-minute VM boot + rendezvous.
async fn ensure_sandbox_ready(state: &Arc<Mutex<DaemonState>>) -> Result<()> {
    {
        let mut s = state.lock().await;
        s.last_activity = std::time::Instant::now();
        if s.guest_connection.is_some() {
            return Ok(());
        }
    }

    // Determine paths (only needed once).
    let exe_dir = std::env::current_exe()
        .context("current_exe")?
        .parent()
        .context("exe parent dir")?
        .to_path_buf();

    let guest_dir = exe_dir.clone();
    let rendezvous_dir = std::env::temp_dir().join("wxc-sandbox-rendezvous");
    std::fs::create_dir_all(&rendezvous_dir).context("create rendezvous dir")?;

    let python_dir = sandbox_vm::find_host_python()
        .context("Python is required on the host for sandbox execution")?;
    eprintln!("[daemon] host Python found at {:?}", python_dir);

    let temp_dir = std::env::temp_dir().join("wxc-sandbox-config");
    std::fs::create_dir_all(&temp_dir).context("create .wsb config dir")?;

    for attempt in 1..=MAX_LAUNCH_ATTEMPTS {
        match try_launch_and_connect(state, &guest_dir, &rendezvous_dir, &python_dir, &temp_dir)
            .await
        {
            Ok(()) => return Ok(()),
            Err(e) if attempt < MAX_LAUNCH_ATTEMPTS => {
                eprintln!(
                    "[daemon] sandbox attempt {}/{} failed: {:#}, retrying after {}s...",
                    attempt, MAX_LAUNCH_ATTEMPTS, e, LAUNCH_BACKOFF_SECS[attempt as usize]
                );

                // Reset state so the next attempt does a fresh launch.
                {
                    let mut locked = state.lock().await;
                    locked.sandbox_running = false;
                    locked.guest_connection = None;
                    locked.guest_addr = None;
                }
                sandbox_vm::teardown().await;
                rendezvous::cleanup(&rendezvous_dir).await?;

                // Backoff before next attempt.
                let wait = std::time::Duration::from_secs(LAUNCH_BACKOFF_SECS[attempt as usize]);
                if !wait.is_zero() {
                    tokio::time::sleep(wait).await;
                }
            }
            Err(e) => {
                // Final attempt failed — reset state and propagate error.
                {
                    let mut locked = state.lock().await;
                    locked.sandbox_running = false;
                    locked.guest_connection = None;
                    locked.guest_addr = None;
                }
                return Err(e).context(format!(
                    "sandbox failed after {} attempts",
                    MAX_LAUNCH_ATTEMPTS
                ));
            }
        }
    }

    unreachable!()
}

/// Single attempt to launch the sandbox and connect to the guest agent.
async fn try_launch_and_connect(
    state: &Arc<Mutex<DaemonState>>,
    guest_dir: &std::path::Path,
    rendezvous_dir: &std::path::Path,
    python_dir: &std::path::Path,
    temp_dir: &std::path::Path,
) -> Result<()> {
    {
        let mut s = state.lock().await;

        rendezvous::cleanup(rendezvous_dir).await?;

        if !s.sandbox_running {
            sandbox_vm::teardown().await;

            let wsb_path =
                sandbox_vm::generate_wsb(guest_dir, rendezvous_dir, python_dir, temp_dir)?;
            sandbox_vm::launch(&wsb_path).await?;
            s.sandbox_running = true;
            eprintln!("[daemon] sandbox VM launched");
        }
    }

    // Poll for rendezvous without holding the lock (can take 2-5+ minutes
    // for the first VM boot).  Refresh last_activity so the idle watchdog
    // does not fire while we wait.
    {
        let mut s = state.lock().await;
        s.last_activity = std::time::Instant::now();
    }
    let guest_addr = rendezvous::wait_for_rendezvous(
        rendezvous_dir,
        std::time::Duration::from_secs(RENDEZVOUS_TIMEOUT_SECS),
        std::time::Duration::from_millis(RENDEZVOUS_POLL_INTERVAL_MS),
    )
    .await
    .context("rendezvous failed")?;

    // Connect to the guest agent.  Refresh activity again after the
    // potentially long rendezvous wait.
    let conn = tcp_bridge::connect_to_guest(
        guest_addr,
        std::time::Duration::from_secs(GUEST_CONNECT_TIMEOUT_SECS),
    )
    .await
    .context("connect to guest agent")?;

    let mut locked = state.lock().await;
    locked.guest_connection = Some(conn);
    locked.guest_addr = Some(guest_addr);
    locked.last_activity = std::time::Instant::now();

    Ok(())
}

/// Deterministic port derived from the pipe name, in the ephemeral range.
///
/// TODO: Change to a more robust approach like bind to port 0 (OS-assigned)
/// and communicate the actual port via a file or registry key.
fn pipe_name_to_port(name: &str) -> u16 {
    let hash: u32 = name
        .bytes()
        .fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));
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
        let p1 = pipe_name_to_port("wxc-windows-sandbox");
        let p2 = pipe_name_to_port("wxc-windows-sandbox");
        assert_eq!(p1, p2);
        assert!(p1 >= 49152);
    }

    #[test]
    fn pipe_name_to_port_varies_with_name() {
        let p1 = pipe_name_to_port("wxc-windows-sandbox");
        let p2 = pipe_name_to_port("other-pipe");
        assert_ne!(p1, p2);
    }
}
