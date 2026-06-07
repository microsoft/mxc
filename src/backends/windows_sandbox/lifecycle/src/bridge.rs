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
/// the **cross-user** hijack window the previous "accept-by-order" design
/// left open (review finding C2). See [`auth`] for the full threat model
/// and what this protection does and does NOT cover (same-user processes
/// remain trusted, consistent with the rest of the Windows Sandbox
/// backend's security model).
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
        // Authenticate AND declare the channel role immediately. The role
        // tag lets the guest assign each accepted socket by identity
        // rather than by accept order — the previous positional-only
        // protocol broke on intermittent Hyper-V vNIC accept-queue
        // reordering (see ChannelRole docs and `accept_one_authed` on the
        // guest). Bounded by the same `timeout` budget.
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
/// each reconnected data stream re-authenticates with it so a cross-
/// user hijacker cannot steal a per-exec data stream either (the
/// threat is identical at boot and at reconnect — review C2; see the
/// [`auth`] module for the same-user-trusted scope).
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

                    conn.stdin_stream = connect(ChannelRole::Stdin).await?;
                    conn.stdout_stream = connect(ChannelRole::Stdout).await?;
                    conn.stderr_stream = connect(ChannelRole::Stderr).await?;

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
                    None => {
                        stdout_done = true;
                    }
                    Some(n) => {
                        stdout_seen += n as u64;
                        if ipc_alive
                            && !write_data_frame_split(ipc, FRAME_STDOUT, &so[..n]).await
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
                            && !write_data_frame_split(ipc, FRAME_STDERR, &se[..n]).await
                        {
                            ipc_alive = false;
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

/// Write a data frame to the IPC client as two back-to-back `write_all`s
/// (header then payload) without materialising a fresh `Vec` per chunk.
///
/// Each stdout/stderr read produces a frame; the previous implementation
/// allocated a `5 + payload.len()` buffer per call via `encode_frame`,
/// copied the 5-byte header, copied the payload, then handed it to
/// `write_ipc`. On large-output workloads (8 KiB reads) the hot path was
/// "allocate + copy + write" per chunk — review D3. Splitting the write
/// into header + payload removes both the per-chunk allocation and the
/// full payload memcpy; the kernel coalesces the two writes on localhost
/// (and TCP coalesces them on any path).
///
/// Returns the same `true`/`false` contract as [`write_ipc`]. The two
/// writes share a single timeout budget; an interrupted write between
/// header and payload poisons the frame stream, but the caller already
/// treats any `false` return as "stop relaying" and reuses neither side.
async fn write_data_frame_split<W>(ipc: &mut W, kind: u8, payload: &[u8]) -> bool
where
    W: AsyncWrite + Unpin,
{
    let mut header = [0u8; 5];
    header[0] = kind;
    header[1..5].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    let combined = async {
        ipc.write_all(&header).await?;
        ipc.write_all(payload).await?;
        Ok::<(), std::io::Error>(())
    };
    matches!(
        tokio::time::timeout(IPC_WRITE_TIMEOUT, combined).await,
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

    // ===== F3: bridge stream/reconnect integration tests =====================
    //
    // These spin up an in-process "fake guest" that accepts the 4 channels
    // (nonce-verified, preamble + Ready emitted), then drive
    // stream_exec_on_guest and reconnect_data_streams end-to-end against
    // hand-controlled stdout/stderr/exit frames. They exercise the entire
    // bridge stream path WITHOUT a real Windows Sandbox VM or guest binary.

    struct FakeGuestSide {
        control: tokio::net::TcpStream,
        stdin: tokio::net::TcpStream,
        stdout: tokio::net::TcpStream,
        stderr: tokio::net::TcpStream,
        // Held by tests that want to drive a reconnect after Exit; current
        // tests don't reconnect, but keeping the listener and addr alive
        // means the fake guest survives the first exec for future
        // reconnect-failure tests.
        #[allow(dead_code)]
        listener: TcpListener,
        #[allow(dead_code)]
        addr: SocketAddr,
    }

    /// Spawn an in-process fake guest: bind a listener, accept 4 connections,
    /// verify the per-launch nonce + decode the channel role tag on each, then
    /// send the preamble + Ready frame on whichever socket was tagged as
    /// `control`. Returns the listening address (for the host's
    /// `connect_to_guest` call) and a oneshot receiver that yields the
    /// server-side handles so the test can drive the fake guest's outputs.
    ///
    /// Pairing is by **declared role**, not accept order — matching the real
    /// guest's `listener::accept_connections` after the role-tag protocol
    /// change. The test fake's "pair by role" stays even when accept order
    /// would happen to match, so the tests catch any regression where the
    /// host stops emitting the role byte.
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
                // Accept 4 connections, each presenting the nonce as the
                // first NONCE_LEN bytes and a 1-byte role tag immediately
                // after. Assign each socket to the slot matching its
                // declared role.
                let accept_one = || async {
                    let (mut s, _) = listener.accept().await?;
                    let mut buf = [0u8; windows_sandbox_common::auth::NONCE_LEN];
                    s.read_exact(&mut buf).await?;
                    let got = windows_sandbox_common::auth::Nonce::from_bytes(&buf)
                        .expect("read_exact filled NONCE_LEN");
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
                // Send preamble + Ready so the host's connect_to_guest
                // handshake completes.
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
        // End-to-end: drive stream_exec_on_guest against the fake guest;
        // simulate a child that writes "hi" to stdout, "warn" to stderr,
        // then exits 0. Verify the IPC writer side sees the corresponding
        // FRAME_STDOUT / FRAME_STDERR frames (no FRAME_EXIT — that is
        // written by the caller after releasing the single-flight slot).
        let nonce = generate_nonce();
        let (addr, fake_rx) = spawn_fake_guest(nonce.clone()).await;
        let mut conn = connect_to_guest(addr, Duration::from_secs(5), &nonce)
            .await
            .expect("connect_to_guest must succeed");
        let mut fake = fake_rx
            .await
            .expect("fake-guest oneshot")
            .expect("fake-guest accept");

        // Spawn the host->guest driver in a task so we can concurrently
        // act as the guest on `fake`.
        let mut ipc_reader: &[u8] = b""; // no FRAME_STDIN frames in this test
        let mut ipc_writer: Vec<u8> = Vec::new();
        let req = ExecStart {
            script_code: "echo hi".to_string(),
            working_directory: String::new(),
            timeout_ms: 5_000,
        };

        // Drain the EXEC frame the host sends on conn.control inside a
        // concurrent task. Then have the fake guest emit stdout/stderr/exit
        // before stream_exec_on_guest can complete.
        let fake_side = async {
            // Read & discard the EXEC frame on control.
            let mut buf = [0u8; 4096];
            let _ = fake.control.read(&mut buf).await;
            // Emit stdout bytes; close write half to signal EOF.
            fake.stdout.write_all(b"hi").await.unwrap();
            fake.stdout.shutdown().await.ok();
            // Emit stderr bytes; close write half.
            fake.stderr.write_all(b"warn").await.unwrap();
            fake.stderr.shutdown().await.ok();
            // Send the guest's Exit message on control.
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

        // Decode the IPC writer's frames and check stdout/stderr arrived.
        let mut cur = std::io::Cursor::new(ipc_writer);
        let mut stdout_seen = Vec::new();
        let mut stderr_seen = Vec::new();
        while let Some(frame) = ipc_exec::read_frame(&mut cur).unwrap() {
            match frame.kind {
                ipc_exec::FRAME_STDOUT => stdout_seen.extend_from_slice(&frame.payload),
                ipc_exec::FRAME_STDERR => stderr_seen.extend_from_slice(&frame.payload),
                other => panic!("unexpected frame kind during stream test: {other}"),
            }
        }
        assert_eq!(stdout_seen, b"hi");
        assert_eq!(stderr_seen, b"warn");
    }

    #[tokio::test]
    async fn stream_exec_forwards_frame_stdin_to_guest() {
        // Verify the new C4 stdin forwarding: host sends FRAME_STDIN frames
        // on the IPC reader, daemon writes their payload onto
        // conn.stdin_stream, and the fake guest sees those bytes on its
        // stdin TcpStream.
        let nonce = generate_nonce();
        let (addr, fake_rx) = spawn_fake_guest(nonce.clone()).await;
        let mut conn = connect_to_guest(addr, Duration::from_secs(5), &nonce)
            .await
            .unwrap();
        let mut fake = fake_rx.await.unwrap().unwrap();

        // Build the IPC reader: a duplex stream where the test writes
        // FRAME_STDIN frames and stream_exec_on_guest reads them.
        let (mut ipc_writer_side, mut ipc_reader_side) = tokio::io::duplex(4096);
        // Write a FRAME_STDIN frame carrying "input data" then close the
        // writer half so the daemon sees clean EOF.
        let stdin_frame = ipc_exec::encode_frame(ipc_exec::FRAME_STDIN, b"input data");
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
        let nonce = generate_nonce();
        let (addr, fake_rx) = spawn_fake_guest(nonce.clone()).await;
        let mut conn = connect_to_guest(addr, Duration::from_secs(5), &nonce)
            .await
            .unwrap();
        let mut fake = fake_rx.await.unwrap().unwrap();

        // Build a duplex IPC writer whose READ half we'll drop early to
        // simulate client disconnect.
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

        // Drop the client side immediately to simulate disconnect.
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
