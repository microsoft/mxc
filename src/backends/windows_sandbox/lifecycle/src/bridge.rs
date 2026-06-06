//! TCP bridge to the guest agent.
//!
//! Establishes four outbound TCP connections to the guest agent and provides
//! the bridge for relaying control/stdin/stdout/stderr.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use windows_sandbox_common::auth::{self, Nonce};
use windows_sandbox_common::sandbox_protocol::{
    decode_message, encode_message, validate_preamble, ControlMessage, DecodeResult, ExecRequest,
    PREAMBLE_LEN,
};

use crate::ipc_exec::{self, ExecStart, FRAME_STDERR, FRAME_STDOUT};

/// Maximum time (seconds) to wait for the guest's StreamsReady message.
const STREAMS_READY_TIMEOUT_SECS: u64 = 60;

/// Maximum time (seconds) for each data stream reconnection attempt.
const RECONNECT_TIMEOUT_SECS: u64 = 30;

/// Maximum time to wait on a single write to the IPC client before treating it
/// as dead. Bounds head-of-line blocking: a client that stops reading (e.g. its
/// own stdout pipe is blocked) must never stall the loop that drains the guest,
/// or the guest child could wedge and the connection never reach a clean
/// boundary. On timeout we drop the client (`ipc_alive = false`) and keep
/// draining the guest to a clean reuse point.
const IPC_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Defense-in-depth backstop: once the guest has reported `Exit`, bound how long
/// we keep waiting for stdout/stderr to reach EOF before abandoning the drain
/// and freeing the slot. The guest is the primary guarantor of liveness (it
/// reaps its child's process tree and always sends `Exit` plus closes its data
/// sockets); this only covers a guest that sent `Exit` yet failed to close the
/// data sockets. Set longer than the guest's own drain grace so the guest-side
/// mechanism fires first and this almost never trips. When it does fire, the
/// abandoned data sockets are discarded by the next exec's reconnect, so no
/// subsequent exec is corrupted.
const POST_EXIT_DRAIN: Duration = Duration::from_secs(15);

/// Dedicated budget for reading the fixed 8-byte guest protocol preamble, which
/// the agent writes immediately after accepting the control connection. Bounded
/// independently of the caller's (minutes-long) VM-ready timeout so a peer that
/// accepts the socket but never speaks cannot pin the connect path: it fails
/// fast instead. Generous enough to tolerate a loaded host where the kernel
/// accepts the TCP backlog slightly before the userspace agent services it.
const PREAMBLE_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Four TCP connections to the guest agent.
///
/// TODO: These TCP connections are unencrypted. Verify if this is a concern.
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
///
/// `nonce` is the per-launch authentication token that the host wrote to
/// the rendezvous folder's `nonce.bin` before launching the VM, and that
/// the guest read + deleted at boot. Each TCP connection's first
/// [`auth::NONCE_LEN`] bytes are this nonce; the guest verifies it
/// (constant-time compare) and drops the connection on mismatch — closing
/// the local-process hijack window the previous "accept-by-order" design
/// left open (review finding C2).
pub async fn connect_to_guest(
    addr: SocketAddr,
    timeout: std::time::Duration,
    nonce: &Nonce,
) -> Result<GuestConnection> {
    let connect = |label: &'static str| async move {
        let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
            .await
            .with_context(|| format!("timeout connecting {} to {}", label, addr))?
            .with_context(|| format!("connect {} to {}", label, addr))?;
        // Authenticate immediately so a local-process accept-race that
        // beats the legitimate connect is detected before any protocol
        // bytes are exchanged. Bounded by the same `timeout` budget.
        tokio::time::timeout(timeout, auth::write_nonce(&mut stream, nonce))
            .await
            .with_context(|| format!("timeout writing nonce on {} to {}", label, addr))?
            .with_context(|| format!("write nonce on {} to {}", label, addr))?;
        Ok::<TcpStream, anyhow::Error>(stream)
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
    // Validate the protocol preamble before any framed messages so we fail
    // fast (with a clear error) on a version/identity mismatch. The preamble
    // is read under a dedicated short budget (not the caller's VM-ready
    // timeout) so a silent peer cannot pin the connect path for minutes.
    let handshake_timeout = timeout.min(PREAMBLE_HANDSHAKE_TIMEOUT);
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
///
/// `nonce` is the same per-launch nonce passed to [`connect_to_guest`];
/// each reconnected data stream re-authenticates with it so a local-
/// process hijacker cannot steal a per-exec data stream either (the
/// hijack threat is identical at boot and at reconnect — review C2).
pub async fn reconnect_data_streams(
    conn: &mut GuestConnection,
    addr: SocketAddr,
    control_residual: Vec<u8>,
    nonce: &Nonce,
) -> Result<()> {
    let mut buf = control_residual;
    let mut tmp = [0u8; 256];
    let timeout = std::time::Duration::from_secs(STREAMS_READY_TIMEOUT_SECS);
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

                    let connect_timeout = std::time::Duration::from_secs(RECONNECT_TIMEOUT_SECS);
                    let connect = |label: &'static str| {
                        let target = addr;
                        async move {
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
                                auth::write_nonce(&mut stream, nonce),
                            )
                            .await
                            .with_context(|| format!("timeout writing reconnect nonce on {label}"))?
                            .with_context(|| {
                                format!("write reconnect nonce on {label} to {target}")
                            })?;
                            Ok::<TcpStream, anyhow::Error>(stream)
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
    /// caller writes the terminal exit frame (via [`write_exit_frame`]) **after**
    /// restoring/releasing the single-flight guest slot.
    pub exit_code: i32,
    /// The guest's error message accompanying the exit (empty on success).
    pub error_message: String,
}

/// Run one execution on the guest, streaming its stdout/stderr **live** to the
/// `ipc` writer as length-prefixed [`crate::ipc_exec`] frames, and return the
/// guest's terminal exit payload (`exit_code`/`error_message`) in the
/// [`StreamExecOutcome`].
///
/// The terminal exit frame is intentionally **not** written here. The caller
/// must first restore/release the single-flight guest slot and then call
/// [`write_exit_frame`], so that a client observing its terminal result implies
/// the sandbox is already free for the next exec (finding #77).
///
/// Unlike [`execute_on_guest`] (which buffers output for the one-shot path),
/// this relays bytes as they arrive so a long-running or chatty command shows
/// progress immediately, which is required for state-aware exec parity with the
/// other backends.
///
/// Robustness contract (see the daemon's single-flight handler): the guest's
/// stdout and stderr are drained to EOF and the control channel is read until
/// `Exit` **regardless** of whether the IPC client is still connected — if the
/// client disconnects mid-stream, output frames are simply dropped (`ipc_alive`
/// becomes `false`) but the guest protocol is still advanced to a clean
/// boundary so the connection can be reused for the next exec. The exit payload
/// is returned only after stdout EOF + stderr EOF + the guest `Exit`, so no
/// output is ever truncated.
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
    // Send the EXEC command on the control channel.
    let exec_msg = ControlMessage::Exec(ExecRequest {
        exec_id: exec_id.to_string(),
        script_code: req.script_code.clone(),
        working_directory: req.working_directory.clone(),
        timeout_ms: req.timeout_ms,
    });
    let frame = encode_message(&exec_msg).context("encode EXEC")?;
    conn.control.write_all(&frame).await.context("send EXEC")?;

    // Disjoint mutable borrows of the four channels so `select!` can poll
    // them concurrently. Note: stdin is NOT shutdown up-front — review C4.
    // Instead the select! loop drains FRAME_STDIN frames from `ipc_reader`
    // and writes their payloads onto `conn.stdin_stream` as they arrive. A
    // clean EOF on `ipc_reader` triggers a graceful `stdin_stream.shutdown()`
    // so commands reading stdin see EOF and do not block until timeout.
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
                    None => stdout_done = true,
                    Some(n) => {
                        stdout_seen += n as u64;
                        if ipc_alive {
                            let f = ipc_exec::encode_frame(FRAME_STDOUT, &so[..n]);
                            if !write_ipc(ipc, &f).await {
                                ipc_alive = false;
                            }
                        }
                    }
                }
            }
            r = stderr.read(&mut se), if !stderr_done => {
                match classify_data_read(r, stderr_seen, "stderr")? {
                    None => stderr_done = true,
                    Some(n) => {
                        stderr_seen += n as u64;
                        if ipc_alive {
                            let f = ipc_exec::encode_frame(FRAME_STDERR, &se[..n]);
                            if !write_ipc(ipc, &f).await {
                                ipc_alive = false;
                            }
                        }
                    }
                }
            }
            r = ipc_exec::read_frame_async(ipc_reader), if !stdin_in_done => {
                match r {
                    Ok(None) => {
                        // IPC client closed its half cleanly: signal guest
                        // stdin EOF so commands reading stdin can exit.
                        stdin_in_done = true;
                        if !stdin_out_closed {
                            let _ = stdin_out.shutdown().await;
                            stdin_out_closed = true;
                        }
                    }
                    Ok(Some(frame)) if frame.kind == ipc_exec::FRAME_STDIN => {
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
                        // Tolerate unexpected frame kinds from the client
                        // (e.g. a forward-compatible client speaking a newer
                        // frame type). Skip the payload, keep draining.
                        eprintln!(
                            "[daemon] ignoring unexpected IPC frame kind {} during exec",
                            frame.kind
                        );
                    }
                    Err(e) => {
                        // A malformed / oversized / abrupt-close IPC frame:
                        // stop forwarding stdin but keep draining the guest
                        // to completion so the slot is freed cleanly.
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
                            // Arm the post-exit drain backstop: bound how long
                            // we wait for stdout/stderr EOF now that the child
                            // has reported completion. Also close guest stdin
                            // if the client never sent EOF; the child has
                            // already exited so any further stdin is moot.
                            post_exit_deadline =
                                Some(tokio::time::Instant::now() + POST_EXIT_DRAIN);
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
                            // StreamsReady should not precede Exit, but stay
                            // tolerant of reordering rather than wedging.
                            eprintln!("[daemon] unexpected control during exec: {message:?}");
                            ctrl_buf.drain(..consumed);
                        }
                        DecodeResult::Incomplete => break,
                    }
                }
            }
            // Post-exit drain backstop. Once the guest has reported `Exit`, only
            // wait a bounded time for stdout/stderr to EOF; if a leaked guest
            // descendant still holds the pipes (and the guest somehow failed to
            // close its data sockets), abandon the drain so the slot is freed.
            _ = async {
                match post_exit_deadline {
                    Some(d) => tokio::time::sleep_until(d).await,
                    None => std::future::pending::<()>().await,
                }
            }, if exit.is_some() && !(stdout_done && stderr_done) => {
                eprintln!(
                    "[daemon] post-exit drain timed out after {:?}; abandoning stdout/stderr (possible leaked guest descendant holding the pipes)",
                    POST_EXIT_DRAIN
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

    // The terminal exit frame is intentionally NOT written here. The caller must
    // first restore/release the single-flight guest slot and then call
    // [`write_exit_frame`], so that a client observing its terminal result
    // implies the sandbox is already free for the next exec (finding #77).
    Ok(StreamExecOutcome {
        control_residual: ctrl_buf,
        ipc_alive,
        exit_code,
        error_message,
    })
}

/// Write the terminal exit frame to the IPC client.
///
/// Call this only **after** the guest slot has been restored and the
/// single-flight lock released, so that a client observing its terminal result
/// implies the sandbox is already free for the next exec (finding #77). Returns
/// `true` if the frame was written and flushed (client still alive), `false`
/// otherwise.
pub async fn write_exit_frame<W>(ipc: &mut W, exit_code: i32, error_message: &str) -> Result<bool>
where
    W: AsyncWrite + Unpin,
{
    let frame =
        ipc_exec::encode_exit_frame(exit_code, error_message).context("encode exit frame")?;
    let ok = write_ipc(ipc, &frame).await
        && matches!(
            tokio::time::timeout(IPC_WRITE_TIMEOUT, ipc.flush()).await,
            Ok(Ok(()))
        );
    Ok(ok)
}

/// Classify a data-stream (`stdout`/`stderr`) read result.
///
/// Returns `Ok(None)` for end-of-stream, `Ok(Some(n))` for `n > 0` bytes, and
/// `Err` for a genuine read failure.
///
/// End-of-stream normally arrives as a clean `Ok(0)` (FIN). The guest also
/// gracefully half-closes its data sockets, so a clean EOF is expected. As a
/// narrow defensive measure we additionally treat a reset-class error
/// (`ConnectionReset`/`ConnectionAborted`/`BrokenPipe`) as EOF **only when no
/// bytes were ever observed on that stream** — i.e. the zero-output case where
/// an abortive socket close (RST) can race ahead of a FIN on Windows. If any
/// bytes were already relayed, a reset is treated as a hard error rather than
/// silently truncating output.
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

/// Write a frame to the IPC client with a bounded timeout. Returns `true` on a
/// fully-flushed write, `false` if the write errored or timed out (the caller
/// then stops relaying but keeps draining the guest).
async fn write_ipc<W>(ipc: &mut W, frame: &[u8]) -> bool
where
    W: AsyncWrite + Unpin,
{
    matches!(
        tokio::time::timeout(IPC_WRITE_TIMEOUT, ipc.write_all(frame)).await,
        Ok(Ok(()))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

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
    async fn write_exit_frame_emits_single_decodable_exit_frame() {
        // The terminal exit frame is now written by the caller (after releasing
        // the single-flight slot, finding #77). Verify the extracted helper
        // emits exactly one decodable FRAME_EXIT and reports the client alive.
        let mut buf: Vec<u8> = Vec::new();
        let alive = write_exit_frame(&mut buf, 7, "boom").await.unwrap();
        assert!(alive, "an in-memory writer never errors");

        let mut cur = std::io::Cursor::new(buf);
        let frame = ipc_exec::read_frame(&mut cur)
            .unwrap()
            .expect("one exit frame");
        assert_eq!(frame.kind, ipc_exec::FRAME_EXIT);
        let exit: ipc_exec::ExecExit = serde_json::from_slice(&frame.payload).unwrap();
        assert_eq!(exit.exit_code, 7);
        assert_eq!(exit.error_message, "boom");
        assert!(
            ipc_exec::read_frame(&mut cur).unwrap().is_none(),
            "no trailing frames after the terminal exit frame"
        );
    }
}
