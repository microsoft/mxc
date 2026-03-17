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

/// Connect to the guest agent at `addr`, establishing all 4 channels.
/// Waits for the `Ready` message on the control channel before returning.
pub async fn connect_to_guest(
    addr: SocketAddr,
    timeout: std::time::Duration,
) -> Result<GuestConnection> {
    let connect = |label: &'static str| {
        let addr = addr;
        async move {
            tokio::time::timeout(timeout, TcpStream::connect(addr))
                .await
                .with_context(|| format!("timeout connecting {} to {}", label, addr))?
                .with_context(|| format!("connect {} to {}", label, addr))
        }
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
///
/// Returns the exit code from the guest agent's Exit notification.
pub async fn execute_on_guest(
    conn: &mut GuestConnection,
    exec_id: &str,
    script_code: &str,
    working_directory: &str,
    timeout_ms: u32,
    host_stdin: &[u8],
) -> Result<(i32, String)> {
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
    let exit_task = async {
        let mut buf = Vec::with_capacity(256);
        let mut tmp = [0u8; 4096];
        loop {
            let n = conn.control.read(&mut tmp).await.context("read control")?;
            if n == 0 {
                anyhow::bail!("control closed before EXIT");
            }
            buf.extend_from_slice(&tmp[..n]);

            match decode_message(&buf).context("decode control")? {
                DecodeResult::Message {
                    message: ControlMessage::Exit(exit),
                    ..
                } => return Ok((exit.exit_code, exit.error_message)),
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

    let _stdout = stdout_result.unwrap_or_default();
    let _stderr = stderr_result.unwrap_or_default();
    let (exit_code, error_message) = exit_result?;

    Ok((exit_code, error_message))
}
