//! Script execution and stdio bridging.
//!
//! Receives EXEC commands on the control channel, spawns child processes,
//! and bridges their stdin/stdout/stderr over TCP to the host daemon.

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::Command;

use wxc_common::sandbox_protocol::{
    ControlMessage, DecodeResult, ExitNotification, decode_message, encode_message,
};

/// Main command loop.  Reads control messages from the host and executes
/// scripts until the control connection is closed.
pub async fn run_command_loop(
    mut control: TcpStream,
    stdin_stream: TcpStream,
    stdout_stream: TcpStream,
    stderr_stream: TcpStream,
) -> Result<()> {
    // Signal readiness to the host.
    let ready_frame = encode_message(&ControlMessage::Ready)
        .context("encode Ready")?;
    control.write_all(&ready_frame).await.context("send Ready")?;

    // Wrap stdio streams in Option so we can take ownership per execution.
    let mut stdin_stream = Some(stdin_stream);
    let mut stdout_stream = Some(stdout_stream);
    let mut stderr_stream = Some(stderr_stream);

    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];

    loop {
        // Read from control channel.
        let n = control.read(&mut tmp).await.context("read control")?;
        if n == 0 {
            eprintln!("[agent] control connection closed");
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);

        // Try to decode a complete message.
        loop {
            match decode_message(&buf).context("decode control message")? {
                DecodeResult::Incomplete => break,
                DecodeResult::Message { message, consumed } => {
                    buf.drain(..consumed);
                    match message {
                        ControlMessage::Exec(req) => {
                            eprintln!("[agent] exec {}: {}", req.exec_id, req.script_code);

                            let result = execute_script(
                                &req.script_code,
                                &req.working_directory,
                                req.timeout_ms,
                                stdin_stream.take(),
                                stdout_stream.take(),
                                stderr_stream.take(),
                            )
                            .await;

                            let (exit_code, error_message) = match result {
                                Ok(code) => (code, String::new()),
                                Err(e) => (-1, format!("{:#}", e)),
                            };

                            let exit_msg = ControlMessage::Exit(ExitNotification {
                                exec_id: req.exec_id.clone(),
                                exit_code,
                                error_message,
                            });
                            let frame = encode_message(&exit_msg).context("encode Exit")?;
                            control.write_all(&frame).await.context("send Exit")?;

                            eprintln!("[agent] exec {} finished with code {}", req.exec_id, exit_code);
                        }
                        ControlMessage::Ping => {
                            let frame = encode_message(&ControlMessage::Pong)
                                .context("encode Pong")?;
                            control.write_all(&frame).await.context("send Pong")?;
                        }
                        other => {
                            eprintln!("[agent] unexpected message: {:?}", other);
                        }
                    }
                }
            }
        }
    }
}

/// Spawn a child process and bridge its stdio over the TCP streams.
async fn execute_script(
    script_code: &str,
    working_directory: &str,
    timeout_ms: u32,
    stdin_stream: Option<TcpStream>,
    stdout_stream: Option<TcpStream>,
    stderr_stream: Option<TcpStream>,
) -> Result<i32> {
    // Parse the command line.  We use cmd.exe /C to handle complex commands
    // the same way the AppContainer backend uses CreateProcessW with a
    // command-line string.
    let mut cmd = Command::new("cmd.exe");
    cmd.arg("/C").arg(script_code);

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
        if let (Some(mut tcp), Some(mut child_in)) = (stdin_stream, child_stdin) {
            let _ = tokio::io::copy(&mut tcp, &mut child_in).await;
        }
    });

    // Bridge stdout: child → TCP
    let stdout_task = tokio::spawn(async move {
        if let (Some(mut tcp), Some(mut child_out)) = (stdout_stream, child_stdout) {
            let _ = tokio::io::copy(&mut child_out, &mut tcp).await;
        }
    });

    // Bridge stderr: child → TCP
    let stderr_task = tokio::spawn(async move {
        if let (Some(mut tcp), Some(mut child_err)) = (stderr_stream, child_stderr) {
            let _ = tokio::io::copy(&mut child_err, &mut tcp).await;
        }
    });

    // Wait for the child with an optional timeout.
    let exit_status = if timeout_ms == 0 {
        child.wait().await.context("wait for child")?
    } else {
        let duration = std::time::Duration::from_millis(timeout_ms as u64);
        match tokio::time::timeout(duration, child.wait()).await {
            Ok(Ok(status)) => status,
            Ok(Err(e)) => anyhow::bail!("wait failed: {}", e),
            Err(_) => {
                let _ = child.kill().await;
                anyhow::bail!("process timed out after {}ms", timeout_ms);
            }
        }
    };

    // Wait for bridge tasks to complete (they'll finish when the child exits
    // and its stdio handles are closed).
    let _ = tokio::join!(stdin_task, stdout_task, stderr_task);

    Ok(exit_status.code().unwrap_or(-1))
}
