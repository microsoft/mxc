//! TCP bridge to the guest agent.
//!
//! Establishes four outbound TCP connections to the guest agent and provides
//! the bridge for relaying control/stdin/stdout/stderr.

use std::net::SocketAddr;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use wxc_common::sandbox_protocol::{
    decode_message, encode_message, ControlMessage, DecodeResult, ExecRequest,
};

/// Four TCP connections to the guest agent.
pub struct GuestConnection {
    pub control: TcpStream,
    pub stdin_stream: TcpStream,
    pub stdout_stream: TcpStream,
    pub stderr_stream: TcpStream,
}

/// Result of executing a script on the guest agent.
pub struct ExecResult {
    /// Process exit code (negative values indicate error/timeout).
    pub exit_code: i32,
    /// Optional error message from the agent.
    pub error_message: String,
    /// Captured stdout bytes from the child process.
    pub stdout: Vec<u8>,
    /// Captured stderr bytes from the child process.
    pub stderr: Vec<u8>,
    /// Any bytes read from the control channel beyond the EXIT frame.
    /// May contain a StreamsReady message that arrived in the same read.
    pub control_residual: Vec<u8>,
}

/// Connect to the guest agent at `addr`, establishing all 4 channels.
/// Waits for the `Ready` message on the control channel before returning.
pub async fn connect_to_guest(
    addr: SocketAddr,
    timeout: std::time::Duration,
) -> Result<GuestConnection> {
    let connect = |label: &'static str| async move {
        tokio::time::timeout(timeout, TcpStream::connect(addr))
            .await
            .with_context(|| format!("timeout connecting {} to {}", label, addr))?
            .with_context(|| format!("connect {} to {}", label, addr))
    };

    let control = connect("control").await?;
    let stdin_stream = connect("stdin").await?;
    let stdout_stream = connect("stdout").await?;
    let stderr_stream = connect("stderr").await?;

    eprintln!("[daemon] 4 TCP connections established to {}", addr);

    // Wait for the READY message from the agent.
    let mut conn = GuestConnection {
        control,
        stdin_stream,
        stdout_stream,
        stderr_stream,
    };
    wait_for_ready(&mut conn.control, timeout).await?;

    Ok(conn)
}

/// Read from the control channel until a `Ready` message arrives.
async fn wait_for_ready(control: &mut TcpStream, timeout: std::time::Duration) -> Result<()> {
    let mut buf = Vec::with_capacity(256);
    let mut tmp = [0u8; 256];
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let remaining = deadline - tokio::time::Instant::now();
        let n = tokio::time::timeout(remaining, control.read(&mut tmp))
            .await
            .context("timeout waiting for Ready")?
            .context("read control for Ready")?;
        if n == 0 {
            anyhow::bail!("control connection closed before Ready");
        }
        buf.extend_from_slice(&tmp[..n]);

        match decode_message(&buf).context("decode Ready")? {
            DecodeResult::Message {
                message: ControlMessage::Ready,
                consumed,
            } => {
                buf.drain(..consumed);
                eprintln!("[daemon] received Ready from guest agent");
                return Ok(());
            }
            DecodeResult::Message { message, .. } => {
                anyhow::bail!("expected Ready, got {:?}", message);
            }
            DecodeResult::Incomplete => {
                continue;
            }
        }
    }
}

/// Send an EXEC request to the guest and relay stdin/stdout/stderr.
pub async fn execute_on_guest(
    conn: &mut GuestConnection,
    exec_id: &str,
    script_code: &str,
    working_directory: &str,
    timeout_ms: u32,
    host_stdin: &[u8],
) -> Result<ExecResult> {
    // Send EXEC command.
    let exec_msg = ControlMessage::Exec(ExecRequest {
        exec_id: exec_id.to_string(),
        script_code: script_code.to_string(),
        working_directory: working_directory.to_string(),
        timeout_ms,
    });
    let frame = encode_message(&exec_msg).context("encode EXEC")?;
    conn.control.write_all(&frame).await.context("send EXEC")?;

    // Write stdin data to guest.
    if !host_stdin.is_empty() {
        conn.stdin_stream
            .write_all(host_stdin)
            .await
            .context("write stdin to guest")?;
    }
    // Shut down the write half to signal EOF.
    conn.stdin_stream
        .shutdown()
        .await
        .context("shutdown stdin")?;

    // Read stdout and stderr concurrently.
    let stdout_task = {
        let stream = &mut conn.stdout_stream;
        async move {
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await.map(|_| buf)
        }
    };
    let stderr_task = {
        let stream = &mut conn.stderr_stream;
        async move {
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await.map(|_| buf)
        }
    };

    // Wait for the EXIT notification on the control channel.
    // Returns (exit_code, error_message, residual_bytes) where residual
    // is anything read past the EXIT frame.
    let exit_task = async {
        let mut buf = Vec::with_capacity(256);
        let mut tmp = [0u8; 4096];
        loop {
            let bytes_read = conn.control.read(&mut tmp).await.context("read control")?;
            if bytes_read == 0 {
                anyhow::bail!("control closed before EXIT");
            }
            buf.extend_from_slice(&tmp[..bytes_read]);

            match decode_message(&buf).context("decode control")? {
                DecodeResult::Message {
                    message: ControlMessage::Exit(exit),
                    consumed,
                } => {
                    buf.drain(..consumed);
                    return Ok((exit.exit_code, exit.error_message, buf));
                }
                DecodeResult::Message {
                    message: ControlMessage::Pong,
                    consumed,
                } => {
                    buf.drain(..consumed);
                    continue;
                }
                DecodeResult::Message { message, .. } => {
                    anyhow::bail!("unexpected control message: {:?}", message);
                }
                DecodeResult::Incomplete => continue,
            }
        }
    };

    // Run stdout/stderr reads concurrently with exit notification.
    let (stdout_result, stderr_result, exit_result) =
        tokio::join!(stdout_task, stderr_task, exit_task);

    let stdout = stdout_result.unwrap_or_default();
    let stderr = stderr_result.unwrap_or_default();
    let (exit_code, error_message, control_residual) = exit_result?;

    Ok(ExecResult {
        exit_code,
        error_message,
        stdout,
        stderr,
        control_residual,
    })
}

/// Wait for `StreamsReady` from the agent, then connect 3 new data streams.
///
/// After an EXEC completes the agent re-accepts stdin/stdout/stderr on its
/// listener and signals `StreamsReady` on the control channel.  This function
/// waits for that signal and then establishes 3 fresh TCP connections.
///
/// `control_residual` is any bytes already read from the control channel
/// beyond the EXIT frame (they may contain the StreamsReady message).
pub async fn reconnect_data_streams(
    conn: &mut GuestConnection,
    addr: SocketAddr,
    control_residual: Vec<u8>,
) -> Result<()> {
    let mut buf = control_residual;
    let mut tmp = [0u8; 256];
    let timeout = std::time::Duration::from_secs(60);
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        // First try to decode from what we already have.
        loop {
            match decode_message(&buf).context("decode StreamsReady")? {
                DecodeResult::Message {
                    message: ControlMessage::StreamsReady,
                    consumed,
                } => {
                    buf.drain(..consumed);
                    eprintln!("[daemon] received StreamsReady, reconnecting data streams");

                    let connect_timeout = std::time::Duration::from_secs(30);
                    let connect = |label: &'static str| {
                        let target = addr;
                        async move {
                            tokio::time::timeout(connect_timeout, TcpStream::connect(target))
                                .await
                                .with_context(|| {
                                    format!("timeout reconnecting {} to {}", label, target)
                                })?
                                .with_context(|| format!("reconnect {} to {}", label, target))
                        }
                    };

                    conn.stdin_stream = connect("stdin").await?;
                    conn.stdout_stream = connect("stdout").await?;
                    conn.stderr_stream = connect("stderr").await?;

                    eprintln!("[daemon] data streams reconnected to {}", addr);
                    return Ok(());
                }
                DecodeResult::Message {
                    message: ControlMessage::Pong,
                    consumed,
                } => {
                    buf.drain(..consumed);
                    continue;
                }
                DecodeResult::Message { message, consumed } => {
                    eprintln!(
                        "[daemon] skipping unexpected message while waiting for StreamsReady: {:?}",
                        message
                    );
                    buf.drain(..consumed);
                    continue;
                }
                DecodeResult::Incomplete => break,
            }
        }

        // Need more data from the control channel.
        let remaining = deadline - tokio::time::Instant::now();
        let bytes_read = tokio::time::timeout(remaining, conn.control.read(&mut tmp))
            .await
            .context("timeout waiting for StreamsReady")?
            .context("read control for StreamsReady")?;
        if bytes_read == 0 {
            anyhow::bail!("control closed before StreamsReady");
        }
        buf.extend_from_slice(&tmp[..bytes_read]);
    }
}
