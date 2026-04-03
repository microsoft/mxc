//! Script execution and stdio bridging.
//!
//! Receives EXEC commands on the control channel, spawns child processes,
//! and bridges their stdin/stdout/stderr over TCP to the host daemon.

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;

use wxc_common::sandbox_protocol::{
    decode_message, encode_message, ControlMessage, DecodeResult, ExecRequest, ExitNotification,
};

/// Main command loop.  Reads control messages from the host and executes
/// scripts until the control connection is closed.  After each execution,
/// re-accepts fresh data connections so the next EXEC has usable streams.
///
/// TODO: Multi-exec reuses the same VM, so a previous script's side
/// effects (files, processes, registry, env changes) persist. Consider
/// killing orphan processes and cleaning temp directories between
/// executions to limit cross-execution state leakage.
pub async fn run_command_loop(
    mut control: TcpStream,
    stdin_stream: TcpStream,
    stdout_stream: TcpStream,
    stderr_stream: TcpStream,
    listener: &TcpListener,
) -> Result<()> {
    // Signal readiness to the host.
    let ready_frame = encode_message(&ControlMessage::Ready).context("encode Ready")?;
    control
        .write_all(&ready_frame)
        .await
        .context("send Ready")?;

    let mut current_stdin = stdin_stream;
    let mut current_stdout = stdout_stream;
    let mut current_stderr = stderr_stream;

    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];

    loop {
        // Read from control channel.
        let bytes_read = control.read(&mut tmp).await.context("read control")?;
        if bytes_read == 0 {
            eprintln!("[guest] control connection closed");
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..bytes_read]);

        // Try to decode a complete message.
        loop {
            match decode_message(&buf).context("decode control message")? {
                DecodeResult::Incomplete => break,
                DecodeResult::Message { message, consumed } => {
                    buf.drain(..consumed);
                    match message {
                        ControlMessage::Exec(req) => {
                            eprintln!("[guest] exec {}: {}", req.exec_id, req.script_code);

                            handle_exec(
                                &req,
                                &mut control,
                                current_stdin,
                                current_stdout,
                                current_stderr,
                            )
                            .await?;

                            // Re-accept fresh data connections for the next
                            // execution. The listener is already bound so the
                            // daemon's connects queue in the TCP backlog.
                            let (new_stdin, new_stdout, new_stderr) =
                                reconnect_streams(&mut control, listener).await?;
                            current_stdin = new_stdin;
                            current_stdout = new_stdout;
                            current_stderr = new_stderr;
                        }
                        ControlMessage::Ping => {
                            let frame =
                                encode_message(&ControlMessage::Pong).context("encode Pong")?;
                            control.write_all(&frame).await.context("send Pong")?;
                        }
                        other => {
                            eprintln!("[guest] unexpected message: {:?}", other);
                        }
                    }
                }
            }
        }
    }
}

/// Execute a single EXEC request: run the script, send Exit on control.
async fn handle_exec(
    req: &ExecRequest,
    control: &mut TcpStream,
    stdin_stream: TcpStream,
    stdout_stream: TcpStream,
    stderr_stream: TcpStream,
) -> Result<()> {
    let result = execute_script(
        &req.script_code,
        &req.working_directory,
        req.timeout_ms,
        stdin_stream,
        stdout_stream,
        stderr_stream,
    )
    .await;

    let (exit_code, error_message) = match result {
        Ok(code) => (code, String::new()),
        Err(err) => (-1, format!("{:#}", err)),
    };

    let exit_msg = ControlMessage::Exit(ExitNotification {
        exec_id: req.exec_id.clone(),
        exit_code,
        error_message,
    });
    let frame = encode_message(&exit_msg).context("encode Exit")?;
    control.write_all(&frame).await.context("send Exit")?;

    eprintln!(
        "[guest] exec {} finished with code {}",
        req.exec_id, exit_code
    );
    Ok(())
}

/// Signal StreamsReady and accept fresh data connections for the next EXEC.
async fn reconnect_streams(
    control: &mut TcpStream,
    listener: &TcpListener,
) -> Result<(TcpStream, TcpStream, TcpStream)> {
    let ready_frame =
        encode_message(&ControlMessage::StreamsReady).context("encode StreamsReady")?;
    control
        .write_all(&ready_frame)
        .await
        .context("send StreamsReady")?;
    eprintln!("[guest] StreamsReady sent, accepting new data connections");

    let streams = crate::listener::accept_data_connections(listener)
        .await
        .context("re-accept data connections")?;
    eprintln!("[guest] new data connections accepted, ready for next exec");
    Ok(streams)
}

/// Spawn a child process and bridge its stdio over the TCP streams.
async fn execute_script(
    script_code: &str,
    working_directory: &str,
    timeout_ms: u32,
    stdin_stream: TcpStream,
    stdout_stream: TcpStream,
    stderr_stream: TcpStream,
) -> Result<i32> {
    // Use raw_arg to pass the script literally to cmd.exe.
    // Rust's standard arg() escaping conflicts with cmd.exe's quoting rules,
    // so we pass /C normally and the script code unescaped.
    let mut cmd = Command::new("cmd.exe");
    cmd.arg("/C");
    cmd.raw_arg(script_code);

    if !working_directory.is_empty() {
        cmd.current_dir(working_directory);
    }

    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().context("spawn child process")?;

    // Take child stdio handles.
    let child_stdin = child.stdin.take();
    let child_stdout = child.stdout.take();
    let child_stderr = child.stderr.take();

    // Bridge stdin: TCP → child
    let stdin_task = tokio::spawn(async move {
        if let (mut tcp, Some(mut child_in)) = (stdin_stream, child_stdin) {
            if let Err(err) = tokio::io::copy(&mut tcp, &mut child_in).await {
                eprintln!("[guest] stdin bridge error: {}", err);
            }
        }
    });

    // Bridge stdout: child → TCP
    let stdout_task = tokio::spawn(async move {
        if let (mut tcp, Some(mut child_out)) = (stdout_stream, child_stdout) {
            if let Err(err) = tokio::io::copy(&mut child_out, &mut tcp).await {
                eprintln!("[guest] stdout bridge error: {}", err);
            }
        }
    });

    // Bridge stderr: child → TCP
    let stderr_task = tokio::spawn(async move {
        if let (mut tcp, Some(mut child_err)) = (stderr_stream, child_stderr) {
            if let Err(err) = tokio::io::copy(&mut child_err, &mut tcp).await {
                eprintln!("[guest] stderr bridge error: {}", err);
            }
        }
    });

    // Wait for the child with an optional timeout.
    let exit_status = if timeout_ms == 0 {
        child.wait().await.context("wait for child")?
    } else {
        let duration = std::time::Duration::from_millis(timeout_ms as u64);
        match tokio::time::timeout(duration, child.wait()).await {
            Ok(Ok(status)) => status,
            Ok(Err(err)) => anyhow::bail!("wait failed: {}", err),
            Err(_) => {
                if let Err(err) = child.kill().await {
                    eprintln!("[guest] failed to kill timed-out process: {}", err);
                }
                anyhow::bail!("process timed out after {}ms", timeout_ms);
            }
        }
    };

    // Wait for bridge tasks to complete (they'll finish when the child exits
    // and its stdio handles are closed). Task join errors indicate panics
    // in the bridge tasks, which should not happen but we log them.
    let (stdin_result, stdout_result, stderr_result) =
        tokio::join!(stdin_task, stdout_task, stderr_task);
    if let Err(err) = stdin_result {
        eprintln!("[guest] stdin bridge task failed: {}", err);
    }
    if let Err(err) = stdout_result {
        eprintln!("[guest] stdout bridge task failed: {}", err);
    }
    if let Err(err) = stderr_result {
        eprintln!("[guest] stderr bridge task failed: {}", err);
    }

    Ok(exit_status.code().unwrap_or(-1))
}
