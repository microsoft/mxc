//! TCP bridge to the guest agent.
//!
//! Establishes four outbound TCP connections to the guest agent and provides
//! the bridge for relaying control/stdin/stdout/stderr.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use windows_sandbox_common::auth::{self, ChannelRole, Nonce};
use windows_sandbox_common::sandbox_protocol::{
    decode_message, encode_message, validate_preamble, ControlMessage, DecodeResult, ExecRequest,
    PREAMBLE_LEN,
};

use crate::ipc_exec::{self, ExecStart, FrameKind};

const STREAMS_READY_TIMEOUT_SECS: Duration = Duration::from_secs(60);

const RECONNECT_TIMEOUT_SECS: Duration = Duration::from_secs(30);

const IPC_WRITE_TIMEOUT_SECS: Duration = Duration::from_secs(30);

const POST_EXIT_DRAIN_SECS: Duration = Duration::from_secs(15);

const PREAMBLE_HANDSHAKE_TIMEOUT_SECS: Duration = Duration::from_secs(10);

/// Per-stream cap on captured guest output in the one-shot protocol. The guest
/// is untrusted, so unbounded buffering lets a runaway script OOM the host.
const MAX_CAPTURED_OUTPUT_BYTES: usize = 64 * 1024 * 1024;

/// Grace added to the guest's own `timeout_ms` to form the host watchdog
/// deadline: covers guest process teardown and final output drain. If the guest
/// freezes and never reports, the host stops waiting after `timeout_ms + grace`.
const HOST_WATCHDOG_GRACE: Duration = Duration::from_secs(30);

/// Host watchdog deadline for one guest execution. `None` for an infinite guest
/// budget (`u32::MAX`, the normalized "no timeout"); otherwise `timeout_ms +
/// grace`, saturating against overflow.
fn host_watchdog_deadline(timeout_ms: u32, grace: Duration) -> Option<Duration> {
    if timeout_ms == u32::MAX {
        None
    } else {
        Some(Duration::from_millis(u64::from(timeout_ms)).saturating_add(grace))
    }
}

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
    /// Control bytes read beyond the exit frame.
    pub control_residual: Vec<u8>,
}

/// Connect to the guest agent and wait for `Ready`.
///
/// Each connection begins with the launch nonce and a [`ChannelRole`] byte.
pub async fn connect_to_guest(
    addr: SocketAddr,
    timeout: std::time::Duration,
    nonce: &Nonce,
) -> Result<GuestConnection> {
    let connect = |role: ChannelRole| async move {
        let label = role.label();
        let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
            .await
            .with_context(|| format!("timeout connecting {} to {}", label, addr))?
            .with_context(|| format!("connect {} to {}", label, addr))?;
        tokio::time::timeout(timeout, auth::write_nonce(&mut stream, nonce, role))
            .await
            .with_context(|| format!("timeout writing nonce on {} to {}", label, addr))?
            .with_context(|| format!("write nonce on {} to {}", label, addr))?;
        Ok::<TcpStream, anyhow::Error>(stream)
    };

    let control = connect(ChannelRole::Control).await?;
    let stdin_stream = connect(ChannelRole::Stdin).await?;
    let stdout_stream = connect(ChannelRole::Stdout).await?;
    let stderr_stream = connect(ChannelRole::Stderr).await?;

    eprintln!("[daemon] 4 TCP connections established to {}", addr);

    let mut conn = GuestConnection {
        control,
        stdin_stream,
        stdout_stream,
        stderr_stream,
    };
    let handshake_timeout = timeout.min(PREAMBLE_HANDSHAKE_TIMEOUT_SECS);
    read_and_validate_preamble(&mut conn.control, handshake_timeout).await?;
    wait_for_ready(&mut conn.control, timeout).await?;

    Ok(conn)
}

/// Read the fixed 8-byte control preamble and validate magic + version.
async fn read_and_validate_preamble(
    control: &mut TcpStream,
    timeout: std::time::Duration,
) -> Result<()> {
    let mut preamble = [0u8; PREAMBLE_LEN];
    tokio::time::timeout(timeout, control.read_exact(&mut preamble))
        .await
        .context("timeout reading guest preamble")?
        .context("read guest preamble")?;
    let version = validate_preamble(&preamble).map_err(|e| {
        anyhow::anyhow!(
            "guest protocol handshake failed: {} (refusing connection)",
            e
        )
    })?;
    eprintln!("[daemon] guest protocol handshake ok (version {})", version);
    Ok(())
}

/// Read from the control channel until a `Ready` message arrives.
async fn wait_for_ready(control: &mut TcpStream, timeout: std::time::Duration) -> Result<()> {
    let mut buf = Vec::with_capacity(256);
    let mut tmp = [0u8; 256];
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .unwrap_or(Duration::ZERO);
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
    execute_on_guest_with_grace(
        conn,
        exec_id,
        script_code,
        working_directory,
        timeout_ms,
        host_stdin,
        HOST_WATCHDOG_GRACE,
    )
    .await
}

/// [`execute_on_guest`] with an explicit host-watchdog grace period, for tests.
async fn execute_on_guest_with_grace(
    conn: &mut GuestConnection,
    exec_id: &str,
    script_code: &str,
    working_directory: &str,
    timeout_ms: u32,
    host_stdin: &[u8],
    grace: Duration,
) -> Result<ExecResult> {
    let exec_msg = ControlMessage::Exec(ExecRequest {
        exec_id: exec_id.to_string(),
        script_code: script_code.to_string(),
        working_directory: working_directory.to_string(),
        timeout_ms,
    });
    let frame = encode_message(&exec_msg).context("encode EXEC")?;
    conn.control.write_all(&frame).await.context("send EXEC")?;

    // Pump stdin concurrently with output to avoid filling opposing TCP windows.
    // BrokenPipe is non-fatal because commands may exit without consuming stdin.
    let stdin_task = {
        let stream = &mut conn.stdin_stream;
        async move {
            if !host_stdin.is_empty() {
                if let Err(e) = stream.write_all(host_stdin).await {
                    return Some(anyhow::Error::new(e).context("write stdin to guest"));
                }
            }
            // Shut down the write half to signal EOF.
            stream
                .shutdown()
                .await
                .err()
                .map(|e| anyhow::Error::new(e).context("shutdown stdin"))
        }
    };

    let stdout_task = drain_capped_stream(&mut conn.stdout_stream, "stdout");
    let stderr_task = drain_capped_stream(&mut conn.stderr_stream, "stderr");

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

            // Drain all complete messages before reading more data.
            loop {
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
                        // Continue inner loop to decode the next message.
                    }
                    DecodeResult::Message { message, .. } => {
                        anyhow::bail!("unexpected control message: {:?}", message);
                    }
                    DecodeResult::Incomplete => break,
                }
            }
        }
    };

    // Concurrently pump stdin/stdout/stderr and the exit notification, bounded
    // by a host watchdog so a frozen guest (or one that never closes its data
    // streams) cannot hang the host indefinitely.
    let joined = async { tokio::join!(stdin_task, stdout_task, stderr_task, exit_task) };
    let (
        stdin_err,
        (stdout, stdout_truncated, stdout_err),
        (stderr, stderr_truncated, stderr_err),
        exit_result,
    ) = match host_watchdog_deadline(timeout_ms, grace) {
        Some(deadline) => match tokio::time::timeout(deadline, joined).await {
            Ok(joined) => joined,
            Err(_) => {
                eprintln!(
                    "[daemon] WARNING: guest did not report completion within the host watchdog \
                     ({timeout_ms}ms guest timeout + {}s grace); the sandbox may be frozen",
                    grace.as_secs()
                );
                return Ok(ExecResult {
                    exit_code: -1,
                    error_message: format!(
                        "guest did not report completion within the host watchdog ({timeout_ms}ms \
                         guest timeout + {}s grace); the sandbox may be frozen",
                        grace.as_secs()
                    ),
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    control_residual: Vec::new(),
                });
            }
        },
        None => joined.await,
    };

    if let Some(e) = stdin_err {
        eprintln!("[daemon] WARNING: forwarding stdin to guest failed (continuing): {e:#}");
    }

    let (exit_code, mut error_message, control_residual) = exit_result?;

    // A read error on stdout/stderr means the captured output may be truncated.
    // Do NOT present a truncated run as a clean success: if the guest reported
    // exit 0 but a data channel errored mid-stream, surface a transport error
    // (preserving the bytes already captured) instead of silently returning
    // empty/partial output with exit 0. A non-zero exit already signals
    // failure, so the bytes are returned as-is in that case.
    if exit_code == 0 {
        if let Some(e) = stdout_err.or(stderr_err) {
            return Ok(ExecResult {
                exit_code: -1,
                error_message: format!(
                    "transport error draining guest output (captured {} stdout / {} stderr \
                     byte(s) before the error): {e}",
                    stdout.len(),
                    stderr.len()
                ),
                stdout,
                stderr,
                control_residual,
            });
        }
    }

    // Never present a capped run as a clean, complete capture.
    if stdout_truncated || stderr_truncated {
        let which = match (stdout_truncated, stderr_truncated) {
            (true, true) => "stdout and stderr",
            (true, false) => "stdout",
            (false, true) => "stderr",
            (false, false) => unreachable!(),
        };
        eprintln!(
            "[daemon] WARNING: guest {which} exceeded the {MAX_CAPTURED_OUTPUT_BYTES}-byte capture \
             cap and was truncated; use the state-aware backend (which streams) for large output."
        );
        let note = format!(
            "guest {which} exceeded the {MAX_CAPTURED_OUTPUT_BYTES}-byte capture cap and was \
             truncated"
        );
        error_message = if error_message.is_empty() {
            note
        } else {
            format!("{error_message}; {note}")
        };
    }

    Ok(ExecResult {
        exit_code,
        error_message,
        stdout,
        stderr,
        control_residual,
    })
}

/// Drain one guest data stream into a buffer capped at
/// [`MAX_CAPTURED_OUTPUT_BYTES`], returning the bytes, a truncation flag, and
/// any transport error. Reads continue to EOF past the cap (excess discarded).
async fn drain_capped_stream<R>(
    stream: &mut R,
    label: &str,
) -> (Vec<u8>, bool, Option<anyhow::Error>)
where
    R: tokio::io::AsyncRead + Unpin,
{
    drain_capped_stream_with_cap(stream, label, MAX_CAPTURED_OUTPUT_BYTES).await
}

/// [`drain_capped_stream`] with an explicit cap for testing.
async fn drain_capped_stream_with_cap<R>(
    stream: &mut R,
    label: &str,
    cap: usize,
) -> (Vec<u8>, bool, Option<anyhow::Error>)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let mut seen: u64 = 0;
    let mut truncated = false;
    loop {
        let r = stream.read(&mut tmp).await;
        match classify_data_read(r, seen, label) {
            Ok(Some(n)) => {
                seen += n as u64;
                if buf.len() < cap {
                    let take = (cap - buf.len()).min(n);
                    buf.extend_from_slice(&tmp[..take]);
                    if take < n {
                        truncated = true;
                    }
                } else {
                    truncated = true;
                }
            }
            Ok(None) => break,
            Err(e) => return (buf, truncated, Some(e)),
        }
    }
    (buf, truncated, None)
}

/// Wait for `StreamsReady`, then reconnect stdin/stdout/stderr.
pub async fn reconnect_data_streams(
    conn: &mut GuestConnection,
    addr: SocketAddr,
    control_residual: Vec<u8>,
    nonce: &Nonce,
) -> Result<()> {
    let mut buf = control_residual;
    let mut tmp = [0u8; 256];
    let timeout = STREAMS_READY_TIMEOUT_SECS;
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        loop {
            match decode_message(&buf).context("decode StreamsReady")? {
                DecodeResult::Message {
                    message: ControlMessage::StreamsReady,
                    consumed,
                } => {
                    buf.drain(..consumed);
                    eprintln!("[daemon] received StreamsReady, reconnecting data streams");

                    let connect_timeout = RECONNECT_TIMEOUT_SECS;
                    let connect = |role: ChannelRole| {
                        let target = addr;
                        async move {
                            let label = role.label();
                            let mut stream =
                                tokio::time::timeout(connect_timeout, TcpStream::connect(target))
                                    .await
                                    .with_context(|| {
                                        format!("timeout reconnecting {} to {}", label, target)
                                    })?
                                    .with_context(|| {
                                        format!("reconnect {} to {}", label, target)
                                    })?;
                            tokio::time::timeout(
                                connect_timeout,
                                auth::write_nonce(&mut stream, nonce, role),
                            )
                            .await
                            .with_context(|| format!("timeout writing reconnect nonce on {label}"))?
                            .with_context(|| {
                                format!("write reconnect nonce on {label} to {target}")
                            })?;
                            Ok::<TcpStream, anyhow::Error>(stream)
                        }
                    };

                    let (stdin_stream, stdout_stream, stderr_stream) = tokio::try_join!(
                        connect(ChannelRole::Stdin),
                        connect(ChannelRole::Stdout),
                        connect(ChannelRole::Stderr),
                    )?;
                    conn.stdin_stream = stdin_stream;
                    conn.stdout_stream = stdout_stream;
                    conn.stderr_stream = stderr_stream;

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
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .unwrap_or(Duration::ZERO);
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

/// Outcome of a streamed execution on the guest.
pub struct StreamExecOutcome {
    /// Control-channel bytes read past the `Exit` frame (may contain the
    /// guest's `StreamsReady`). Hand this to [`reconnect_data_streams`].
    pub control_residual: Vec<u8>,
    /// `false` if the IPC writer (the exec-phase client) errored mid-stream and
    /// was abandoned. The guest execution still ran to completion and the guest
    /// connection is left in a clean, reusable state; only the client relay was
    /// lost.
    pub ipc_alive: bool,
    /// The child's exit code, as reported by the guest `Exit` message. The
    /// caller writes the terminal exit frame after restoring/releasing the
    /// single-flight guest slot.
    pub exit_code: i32,
    /// The guest's error message accompanying the exit (empty on success).
    pub error_message: String,
}

/// Run one guest execution and stream stdout/stderr to the IPC client.
///
/// The terminal exit frame is written separately after the guest slot is
/// restored for reuse.
pub async fn stream_exec_on_guest<R, W>(
    conn: &mut GuestConnection,
    exec_id: &str,
    req: &ExecStart,
    ipc_reader: &mut R,
    ipc: &mut W,
) -> Result<StreamExecOutcome>
where
    R: tokio::io::AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let exec_msg = ControlMessage::Exec(ExecRequest {
        exec_id: exec_id.to_string(),
        script_code: req.script_code.clone(),
        working_directory: req.working_directory.clone(),
        timeout_ms: req.timeout_ms,
    });
    let frame = encode_message(&exec_msg).context("encode EXEC")?;
    conn.control.write_all(&frame).await.context("send EXEC")?;

    let control = &mut conn.control;
    let stdout = &mut conn.stdout_stream;
    let stderr = &mut conn.stderr_stream;
    let stdin_out = &mut conn.stdin_stream;

    let mut ipc_alive = true;
    let mut stdout_done = false;
    let mut stderr_done = false;
    let mut stdin_in_done = false;
    let mut stdin_out_closed = false;
    let mut stdout_seen: u64 = 0;
    let mut stderr_seen: u64 = 0;
    let mut exit: Option<(i32, String)> = None;
    let mut post_exit_deadline: Option<tokio::time::Instant> = None;
    let mut ctrl_buf: Vec<u8> = Vec::with_capacity(256);
    let mut so = [0u8; 8192];
    let mut se = [0u8; 8192];
    let mut cb = [0u8; 4096];

    while !(stdout_done && stderr_done && exit.is_some()) {
        tokio::select! {
            r = stdout.read(&mut so), if !stdout_done => {
                match classify_data_read(r, stdout_seen, "stdout")? {
                    None => {
                        stdout_done = true;
                    }
                    Some(n) => {
                        stdout_seen += n as u64;
                        if ipc_alive
                            && !write_data_frame_split(ipc, FrameKind::Stdout, &so[..n]).await
                        {
                            ipc_alive = false;
                        }
                    }
                }
            }
            r = stderr.read(&mut se), if !stderr_done => {
                match classify_data_read(r, stderr_seen, "stderr")? {
                    None => {
                        stderr_done = true;
                    }
                    Some(n) => {
                        stderr_seen += n as u64;
                        if ipc_alive
                            && !write_data_frame_split(ipc, FrameKind::Stderr, &se[..n]).await
                        {
                            ipc_alive = false;
                        }
                    }
                }
            }
            r = ipc_exec::read_frame_async(ipc_reader), if !stdin_in_done => {
                match r {
                    Ok(None) => {
                        stdin_in_done = true;
                        if !stdin_out_closed {
                            let _ = stdin_out.shutdown().await;
                            stdin_out_closed = true;
                        }
                    }
                    Ok(Some(frame)) if frame.kind == Some(FrameKind::Stdin) => {
                        if !frame.payload.is_empty() && !stdin_out_closed {
                            if let Err(e) = stdin_out.write_all(&frame.payload).await {
                                eprintln!(
                                    "[daemon] guest stdin write failed: {e}; closing stdin and \
                                     continuing exec"
                                );
                                let _ = stdin_out.shutdown().await;
                                stdin_out_closed = true;
                            }
                        }
                    }
                    Ok(Some(frame)) => {
                        eprintln!(
                            "[daemon] ignoring unexpected IPC frame kind {} during exec",
                            frame.raw_kind
                        );
                    }
                    Err(e) => {
                        eprintln!("[daemon] IPC stdin reader errored: {e}; closing guest stdin");
                        stdin_in_done = true;
                        if !stdin_out_closed {
                            let _ = stdin_out.shutdown().await;
                            stdin_out_closed = true;
                        }
                    }
                }
            }
            r = control.read(&mut cb), if exit.is_none() => {
                let n = r.context("read guest control")?;
                if n == 0 {
                    anyhow::bail!("guest control closed before Exit");
                }
                ctrl_buf.extend_from_slice(&cb[..n]);
                loop {
                    match decode_message(&ctrl_buf).context("decode control")? {
                        DecodeResult::Message {
                            message: ControlMessage::Exit(e),
                            consumed,
                        } => {
                            ctrl_buf.drain(..consumed);
                            exit = Some((e.exit_code, e.error_message));
                            post_exit_deadline =
                                Some(tokio::time::Instant::now() + POST_EXIT_DRAIN_SECS);
                            if !stdin_out_closed {
                                let _ = stdin_out.shutdown().await;
                                stdin_out_closed = true;
                            }
                            stdin_in_done = true;
                            break;
                        }
                        DecodeResult::Message {
                            message: ControlMessage::Pong,
                            consumed,
                        } => {
                            ctrl_buf.drain(..consumed);
                        }
                        DecodeResult::Message { message, consumed } => {
                            eprintln!("[daemon] unexpected control during exec: {message:?}");
                            ctrl_buf.drain(..consumed);
                        }
                        DecodeResult::Incomplete => break,
                    }
                }
            }
            _ = async {
                match post_exit_deadline {
                    Some(d) => tokio::time::sleep_until(d).await,
                    None => std::future::pending::<()>().await,
                }
            }, if exit.is_some() && !(stdout_done && stderr_done) => {
                eprintln!(
                    "[daemon] post-exit drain timed out after {:?}; abandoning stdout/stderr (possible leaked guest descendant holding the pipes)",
                    POST_EXIT_DRAIN_SECS
                );
                stdout_done = true;
                stderr_done = true;
            }
        }
    }

    let (exit_code, error_message) = match exit {
        Some(e) => e,
        None => anyhow::bail!("internal: exec loop ended without an exit notification"),
    };

    Ok(StreamExecOutcome {
        control_residual: ctrl_buf,
        ipc_alive,
        exit_code,
        error_message,
    })
}

/// Write the terminal exit frame to the IPC client.
///
/// Write the final exit frame after the guest slot is reusable.
pub async fn write_exit_frame<W>(ipc: &mut W, exit_code: i32, error_message: &str) -> Result<bool>
where
    W: AsyncWrite + Unpin,
{
    let frame =
        ipc_exec::encode_exit_frame(exit_code, error_message).context("encode exit frame")?;
    let ok = write_ipc(ipc, &frame).await
        && matches!(
            tokio::time::timeout(IPC_WRITE_TIMEOUT_SECS, ipc.flush()).await,
            Ok(Ok(()))
        );
    Ok(ok)
}

/// Classify a data-stream (`stdout`/`stderr`) read result.
fn classify_data_read(r: std::io::Result<usize>, seen: u64, label: &str) -> Result<Option<usize>> {
    use std::io::ErrorKind;
    match r {
        Ok(0) => Ok(None),
        Ok(n) => Ok(Some(n)),
        Err(e)
            if seen == 0
                && matches!(
                    e.kind(),
                    ErrorKind::ConnectionReset
                        | ErrorKind::ConnectionAborted
                        | ErrorKind::BrokenPipe
                ) =>
        {
            eprintln!(
                "[daemon] guest {label} reset with no data ({:?}); treating as EOF",
                e.kind()
            );
            Ok(None)
        }
        Err(e) => {
            Err(anyhow::Error::new(e).context(format!("read guest {label} after {seen} bytes")))
        }
    }
}

/// Write a frame to the IPC client with a bounded timeout.
async fn write_ipc<W>(ipc: &mut W, frame: &[u8]) -> bool
where
    W: AsyncWrite + Unpin,
{
    matches!(
        tokio::time::timeout(IPC_WRITE_TIMEOUT_SECS, ipc.write_all(frame),).await,
        Ok(Ok(()))
    )
}

/// Write a data frame without allocating a combined header+payload buffer.
async fn write_data_frame_split<W>(ipc: &mut W, kind: FrameKind, payload: &[u8]) -> bool
where
    W: AsyncWrite + Unpin,
{
    let header = ipc_exec::frame_header(kind, payload.len());
    let combined = async {
        ipc.write_all(&header).await?;
        ipc.write_all(payload).await?;
        Ok::<(), std::io::Error>(())
    };
    matches!(
        tokio::time::timeout(IPC_WRITE_TIMEOUT_SECS, combined).await,
        Ok(Ok(()))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};
    use std::net::SocketAddr;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use windows_sandbox_common::auth::generate_nonce;
    use windows_sandbox_common::sandbox_protocol::{encode_message, encode_preamble};

    #[test]
    fn classify_data_read_clean_eof_is_none() {
        assert_eq!(classify_data_read(Ok(0), 0, "stdout").unwrap(), None);
        // A clean FIN is EOF even after bytes were observed.
        assert_eq!(classify_data_read(Ok(0), 42, "stdout").unwrap(), None);
    }

    #[test]
    fn classify_data_read_some_bytes_passes_through() {
        assert_eq!(classify_data_read(Ok(7), 0, "stderr").unwrap(), Some(7));
        assert_eq!(classify_data_read(Ok(3), 100, "stderr").unwrap(), Some(3));
    }

    #[test]
    fn classify_data_read_reset_with_no_data_is_eof() {
        // The narrow defensive case: a reset-class error before any byte was
        // seen is treated as EOF (RST racing ahead of FIN on the zero-output
        // path).
        for kind in [
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::BrokenPipe,
        ] {
            let r = Err(Error::new(kind, "reset"));
            assert_eq!(
                classify_data_read(r, 0, "stdout").unwrap(),
                None,
                "reset kind {kind:?} with no bytes should be EOF"
            );
        }
    }

    #[test]
    fn classify_data_read_reset_after_bytes_is_error() {
        // Once any byte was relayed, a reset must be a hard error so we never
        // silently truncate output.
        let r = Err(Error::new(ErrorKind::ConnectionReset, "reset"));
        assert!(classify_data_read(r, 1, "stdout").is_err());
    }

    #[test]
    fn classify_data_read_other_error_is_error_regardless_of_seen() {
        let r = Err(Error::new(ErrorKind::NotConnected, "nope"));
        assert!(classify_data_read(r, 0, "stderr").is_err());
        let r = Err(Error::new(ErrorKind::NotConnected, "nope"));
        assert!(classify_data_read(r, 5, "stderr").is_err());
    }

    #[tokio::test]
    async fn drain_capped_stream_captures_full_output_under_cap() {
        let payload = vec![b'x'; 1000];
        let mut src: &[u8] = &payload;
        let (buf, truncated, err) =
            drain_capped_stream_with_cap(&mut src, "stdout", 64 * 1024).await;
        assert!(err.is_none());
        assert!(!truncated);
        assert_eq!(buf, payload);
    }

    #[tokio::test]
    async fn drain_capped_stream_truncates_output_over_cap() {
        let cap = 4096usize;
        let payload = vec![b'y'; cap * 8];
        let mut src: &[u8] = &payload;
        let (buf, truncated, err) = drain_capped_stream_with_cap(&mut src, "stdout", cap).await;
        assert!(err.is_none());
        assert!(truncated);
        assert_eq!(buf.len(), cap);
        assert!(buf.iter().all(|&b| b == b'y'));
    }

    #[tokio::test]
    async fn drain_capped_stream_truncates_exactly_at_boundary() {
        let cap = 8192usize;
        let exact = vec![b'z'; cap];
        let mut exact_src: &[u8] = &exact;
        let (buf, truncated, _) = drain_capped_stream_with_cap(&mut exact_src, "stderr", cap).await;
        assert_eq!(buf.len(), cap);
        assert!(!truncated);

        let over = vec![b'z'; cap + 1];
        let mut over_src: &[u8] = &over;
        let (buf, truncated, _) = drain_capped_stream_with_cap(&mut over_src, "stderr", cap).await;
        assert_eq!(buf.len(), cap);
        assert!(truncated);
    }

    #[tokio::test]
    async fn write_exit_frame_emits_single_decodable_exit_frame() {
        // The terminal exit frame is written by the caller (after releasing
        // the single-flight slot). Verify the extracted helper
        // emits exactly one decodable exit frame and reports the client alive.
        let mut buf: Vec<u8> = Vec::new();
        let alive = write_exit_frame(&mut buf, 7, "boom").await.unwrap();
        assert!(alive, "an in-memory writer never errors");

        let mut cur = std::io::Cursor::new(buf);
        let frame = ipc_exec::read_frame(&mut cur)
            .unwrap()
            .expect("one exit frame");
        assert_eq!(frame.kind, Some(FrameKind::Exit));
        let exit: ipc_exec::ExecExit = serde_json::from_slice(&frame.payload).unwrap();
        assert_eq!(exit.exit_code, 7);
        assert_eq!(exit.error_message, "boom");
        assert!(
            ipc_exec::read_frame(&mut cur).unwrap().is_none(),
            "no trailing frames after the terminal exit frame"
        );
    }

    #[test]
    fn host_watchdog_deadline_infinite_is_none() {
        // u32::MAX = "no timeout": no watchdog.
        assert_eq!(
            host_watchdog_deadline(u32::MAX, Duration::from_secs(30)),
            None
        );
    }

    #[test]
    fn host_watchdog_deadline_finite_adds_grace() {
        assert_eq!(
            host_watchdog_deadline(5_000, Duration::from_secs(30)),
            Some(Duration::from_millis(5_000) + Duration::from_secs(30))
        );
    }

    #[tokio::test]
    async fn host_watchdog_fires_when_guest_never_reports_exit() {
        // The fake guest handshakes but never sends EXIT nor closes its data
        // streams; without the watchdog this would block forever. `_fake` keeps
        // the sockets open for the call.
        let nonce = generate_nonce().expect("generate nonce");
        let (addr, fake_rx) = spawn_fake_guest(nonce.clone()).await;
        let mut conn = connect_to_guest(addr, Duration::from_secs(5), &nonce)
            .await
            .expect("connect_to_guest must succeed");
        let _fake = fake_rx
            .await
            .expect("fake-guest oneshot")
            .expect("fake-guest accept");

        let result = execute_on_guest_with_grace(
            &mut conn,
            "exec-frozen",
            "sleep forever",
            "",
            200,
            b"",
            Duration::from_millis(100),
        )
        .await
        .expect("execute_on_guest returns Ok with a watchdog result");

        assert_eq!(result.exit_code, -1);
        assert!(
            result.error_message.contains("host watchdog"),
            "unexpected watchdog message: {}",
            result.error_message
        );
    }

    // In-process guest for bridge and reconnect integration tests.

    struct FakeGuestSide {
        control: tokio::net::TcpStream,
        stdin: tokio::net::TcpStream,
        stdout: tokio::net::TcpStream,
        stderr: tokio::net::TcpStream,
        #[allow(dead_code)]
        listener: TcpListener,
        #[allow(dead_code)]
        addr: SocketAddr,
    }

    /// Spawn an authenticated fake guest that pairs sockets by declared role.
    async fn spawn_fake_guest(
        nonce: windows_sandbox_common::auth::Nonce,
    ) -> (
        SocketAddr,
        oneshot::Receiver<Result<FakeGuestSide, std::io::Error>>,
    ) {
        use windows_sandbox_common::auth::ChannelRole;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let result: Result<FakeGuestSide, std::io::Error> = async {
                let accept_one = || async {
                    let (mut s, _) = listener.accept().await?;
                    let mut buf = [0u8; windows_sandbox_common::auth::NONCE_LEN_IN_BYTES];
                    s.read_exact(&mut buf).await?;
                    let got = windows_sandbox_common::auth::Nonce::from_bytes(&buf)
                        .expect("read_exact filled the nonce buffer");
                    if !nonce.constant_time_eq(&got) {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "bad nonce on fake-guest accept",
                        ));
                    }
                    let mut role_buf = [0u8; 1];
                    s.read_exact(&mut role_buf).await?;
                    let role = ChannelRole::from_wire(role_buf[0]).ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("unknown channel role 0x{:02x}", role_buf[0]),
                        )
                    })?;
                    Ok::<(tokio::net::TcpStream, ChannelRole), std::io::Error>((s, role))
                };
                let mut control: Option<tokio::net::TcpStream> = None;
                let mut stdin_stream: Option<tokio::net::TcpStream> = None;
                let mut stdout_stream: Option<tokio::net::TcpStream> = None;
                let mut stderr_stream: Option<tokio::net::TcpStream> = None;
                for _ in 0..4 {
                    let (s, role) = accept_one().await?;
                    let slot = match role {
                        ChannelRole::Control => &mut control,
                        ChannelRole::Stdin => &mut stdin_stream,
                        ChannelRole::Stdout => &mut stdout_stream,
                        ChannelRole::Stderr => &mut stderr_stream,
                    };
                    if slot.is_some() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("duplicate role {:?} on fake-guest accept", role),
                        ));
                    }
                    *slot = Some(s);
                }
                let mut control = control.expect("control role declared");
                let stdin = stdin_stream.expect("stdin role declared");
                let stdout = stdout_stream.expect("stdout role declared");
                let stderr = stderr_stream.expect("stderr role declared");
                control.write_all(&encode_preamble()).await?;
                let ready = encode_message(&ControlMessage::Ready).expect("encode Ready");
                control.write_all(&ready).await?;
                Ok(FakeGuestSide {
                    control,
                    stdin,
                    stdout,
                    stderr,
                    listener,
                    addr,
                })
            }
            .await;
            let _ = tx.send(result);
        });
        (addr, rx)
    }

    #[tokio::test]
    async fn stream_exec_relays_stdout_stderr_exit_to_ipc_client() {
        let nonce = generate_nonce().expect("generate nonce");
        let (addr, fake_rx) = spawn_fake_guest(nonce.clone()).await;
        let mut conn = connect_to_guest(addr, Duration::from_secs(5), &nonce)
            .await
            .expect("connect_to_guest must succeed");
        let mut fake = fake_rx
            .await
            .expect("fake-guest oneshot")
            .expect("fake-guest accept");

        let mut ipc_reader: &[u8] = b"";
        let mut ipc_writer: Vec<u8> = Vec::new();
        let req = ExecStart {
            script_code: "echo hi".to_string(),
            working_directory: String::new(),
            timeout_ms: 5_000,
        };

        let fake_side = async {
            let mut buf = [0u8; 4096];
            let _ = fake.control.read(&mut buf).await;
            fake.stdout.write_all(b"hi").await.unwrap();
            fake.stdout.shutdown().await.ok();
            fake.stderr.write_all(b"warn").await.unwrap();
            fake.stderr.shutdown().await.ok();
            let exit = encode_message(&ControlMessage::Exit(
                windows_sandbox_common::sandbox_protocol::ExitNotification {
                    exec_id: "exec-test".to_string(),
                    exit_code: 0,
                    error_message: String::new(),
                },
            ))
            .unwrap();
            fake.control.write_all(&exit).await.unwrap();
            fake
        };

        let host_side = stream_exec_on_guest(
            &mut conn,
            "exec-test",
            &req,
            &mut ipc_reader,
            &mut ipc_writer,
        );

        let (_fake_back, outcome) = tokio::join!(fake_side, host_side);
        let outcome = outcome.expect("stream_exec_on_guest");
        assert_eq!(outcome.exit_code, 0);
        assert_eq!(outcome.error_message, "");
        assert!(outcome.ipc_alive);

        let mut cur = std::io::Cursor::new(ipc_writer);
        let mut stdout_seen = Vec::new();
        let mut stderr_seen = Vec::new();
        while let Some(frame) = ipc_exec::read_frame(&mut cur).unwrap() {
            match frame.kind {
                Some(FrameKind::Stdout) => stdout_seen.extend_from_slice(&frame.payload),
                Some(FrameKind::Stderr) => stderr_seen.extend_from_slice(&frame.payload),
                other => panic!("unexpected frame kind during stream test: {other:?}"),
            }
        }
        assert_eq!(stdout_seen, b"hi");
        assert_eq!(stderr_seen, b"warn");
    }

    #[tokio::test]
    async fn stream_exec_forwards_frame_stdin_to_guest() {
        let nonce = generate_nonce().expect("generate nonce");
        let (addr, fake_rx) = spawn_fake_guest(nonce.clone()).await;
        let mut conn = connect_to_guest(addr, Duration::from_secs(5), &nonce)
            .await
            .unwrap();
        let mut fake = fake_rx.await.unwrap().unwrap();

        let (mut ipc_writer_side, mut ipc_reader_side) = tokio::io::duplex(4096);
        let stdin_frame = ipc_exec::encode_frame(FrameKind::Stdin, b"input data");
        ipc_writer_side.write_all(&stdin_frame).await.unwrap();
        drop(ipc_writer_side); // EOF on the IPC reader

        let mut ipc_out: Vec<u8> = Vec::new();
        let req = ExecStart {
            script_code: "cat".to_string(),
            working_directory: String::new(),
            timeout_ms: 5_000,
        };

        let fake_side = async {
            let mut buf = [0u8; 4096];
            let _ = fake.control.read(&mut buf).await;
            // Read whatever lands on fake stdin (forwarded by daemon).
            let mut stdin_recv = Vec::new();
            // Bound the read so a regression where stdin never closes does
            // not hang the test forever.
            let _ = tokio::time::timeout(
                Duration::from_secs(2),
                fake.stdin.read_to_end(&mut stdin_recv),
            )
            .await;
            // Close stdout/stderr cleanly so the host's exec drain exits.
            fake.stdout.shutdown().await.ok();
            fake.stderr.shutdown().await.ok();
            let exit = encode_message(&ControlMessage::Exit(
                windows_sandbox_common::sandbox_protocol::ExitNotification {
                    exec_id: "exec-stdin".to_string(),
                    exit_code: 0,
                    error_message: String::new(),
                },
            ))
            .unwrap();
            fake.control.write_all(&exit).await.unwrap();
            stdin_recv
        };

        let host_side = stream_exec_on_guest(
            &mut conn,
            "exec-stdin",
            &req,
            &mut ipc_reader_side,
            &mut ipc_out,
        );

        let (stdin_recv, outcome) = tokio::join!(fake_side, host_side);
        outcome.expect("stream_exec_on_guest");
        assert_eq!(
            stdin_recv, b"input data",
            "guest stdin must receive forwarded bytes"
        );
    }

    #[tokio::test]
    async fn stream_exec_survives_ipc_client_disconnect_mid_stream() {
        // If the IPC client (wxc-exec) disconnects mid-stream the guest
        // execution must still run to completion and the connection must
        // stay in a clean reusable state. ipc_alive should be false but
        // exit_code populated normally. Review robustness contract on
        // stream_exec_on_guest.
        let nonce = generate_nonce().expect("generate nonce");
        let (addr, fake_rx) = spawn_fake_guest(nonce.clone()).await;
        let mut conn = connect_to_guest(addr, Duration::from_secs(5), &nonce)
            .await
            .unwrap();
        let mut fake = fake_rx.await.unwrap().unwrap();

        let (ipc_client_side, ipc_server_side) = tokio::io::duplex(64);
        // Daemon writes flow to `ipc_server_side`'s write half (which the
        // client would read). When we drop ipc_client_side, the daemon's
        // write returns EOF.
        let (server_read, mut server_write) = tokio::io::split(ipc_server_side);
        let mut empty_reader: &[u8] = b"";

        let req = ExecStart {
            script_code: "long-running".to_string(),
            working_directory: String::new(),
            timeout_ms: 5_000,
        };

        let fake_side = async {
            let mut buf = [0u8; 4096];
            let _ = fake.control.read(&mut buf).await;
            // Spew enough stdout that the daemon's write to the (now-
            // disconnected) IPC writer fails. 64 KiB exceeds the duplex
            // buffer many times over.
            for _ in 0..16 {
                fake.stdout.write_all(&[b'x'; 4096]).await.ok();
            }
            fake.stdout.shutdown().await.ok();
            fake.stderr.shutdown().await.ok();
            let exit = encode_message(&ControlMessage::Exit(
                windows_sandbox_common::sandbox_protocol::ExitNotification {
                    exec_id: "exec-disco".to_string(),
                    exit_code: 0,
                    error_message: String::new(),
                },
            ))
            .unwrap();
            fake.control.write_all(&exit).await.unwrap();
        };

        drop(ipc_client_side);
        drop(server_read);

        let host_side = stream_exec_on_guest(
            &mut conn,
            "exec-disco",
            &req,
            &mut empty_reader,
            &mut server_write,
        );

        let (_fake, outcome) = tokio::join!(fake_side, host_side);
        let outcome = outcome.expect("stream_exec_on_guest must still complete");
        assert!(
            !outcome.ipc_alive,
            "ipc_alive must be false after client disconnect"
        );
        assert_eq!(outcome.exit_code, 0);
    }
}
