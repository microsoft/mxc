//! Script execution and stdio bridging.
//!
//! Receives EXEC commands on the control channel, spawns child processes,
//! and bridges their stdin/stdout/stderr over TCP to the host daemon.

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;

use windows_sandbox_common::sandbox_protocol::{
    decode_message, encode_message, encode_preamble, ControlMessage, DecodeResult, ExecRequest,
    ExitNotification,
};

use crate::job::Job;

/// Backstop budget for stdio bridge drain after child exit.
const BRIDGE_DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

/// Main command loop.
pub async fn run_command_loop(
    mut control: TcpStream,
    stdin_stream: TcpStream,
    stdout_stream: TcpStream,
    stderr_stream: TcpStream,
    listener: &TcpListener,
    expected_nonce: &windows_sandbox_common::auth::Nonce,
) -> Result<()> {
    // Announce the protocol magic + version so the host can fail fast on a
    // version/identity mismatch before any framed messages are exchanged.
    control
        .write_all(&encode_preamble())
        .await
        .context("send preamble")?;

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
        let bytes_read = control.read(&mut tmp).await.context("read control")?;
        if bytes_read == 0 {
            eprintln!("[guest] control connection closed");
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..bytes_read]);

        loop {
            match decode_message(&buf).context("decode control message")? {
                DecodeResult::Incomplete => break,
                DecodeResult::Message { message, consumed } => {
                    buf.drain(..consumed);
                    match message {
                        ControlMessage::Exec(req) => {
                            // Do not log raw script_code; it may contain secrets.
                            eprintln!(
                                "[guest] exec {} ({} bytes)",
                                req.exec_id,
                                req.script_code.len()
                            );

                            handle_exec(
                                &req,
                                &mut control,
                                current_stdin,
                                current_stdout,
                                current_stderr,
                            )
                            .await?;

                            let (new_stdin, new_stdout, new_stderr) =
                                reconnect_streams(&mut control, listener, expected_nonce).await?;
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
    expected_nonce: &windows_sandbox_common::auth::Nonce,
) -> Result<(TcpStream, TcpStream, TcpStream)> {
    let ready_frame =
        encode_message(&ControlMessage::StreamsReady).context("encode StreamsReady")?;
    control
        .write_all(&ready_frame)
        .await
        .context("send StreamsReady")?;
    eprintln!("[guest] StreamsReady sent, accepting new data connections");

    let streams = crate::listener::accept_data_connections(listener, expected_nonce)
        .await
        .context("re-accept data connections")?;
    eprintln!("[guest] new data connections accepted, ready for next exec");
    Ok(streams)
}

/// Forcibly terminate a process and descendants.
async fn kill_process_tree(pid: Option<u32>) {
    let Some(pid) = pid else {
        eprintln!("[guest] cannot tree-kill: child pid unavailable");
        return;
    };
    let killed = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        Command::new("taskkill")
            .args(["/T", "/F", "/PID", &pid.to_string()])
            .kill_on_drop(true)
            .output(),
    )
    .await;
    match killed {
        Ok(Ok(out)) if out.status.success() => {}
        Ok(Ok(out)) => eprintln!(
            "[guest] taskkill tree-kill of pid {} returned {}: {}",
            pid,
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Ok(Err(err)) => eprintln!("[guest] failed to run taskkill for pid {}: {}", pid, err),
        Err(_) => eprintln!("[guest] taskkill for pid {} timed out after 5s", pid),
    }
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
    // raw_arg preserves cmd.exe quoting.
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
    let child_pid = child.id();

    // Best-effort job object cleanup for child descendants.
    let job = match Job::new() {
        Ok(j) => {
            if let Some(pid) = child_pid {
                if let Err(err) = j.assign(pid) {
                    eprintln!("[guest] could not assign child to job (continuing): {err:#}");
                }
            }
            Some(j)
        }
        Err(err) => {
            eprintln!("[guest] could not create job object (continuing): {err:#}");
            None
        }
    };

    // Take child stdio handles.
    let child_stdin = child.stdin.take();
    let child_stdout = child.stdout.take();
    let child_stderr = child.stderr.take();

    // Bridge stdin: TCP → child
    let mut stdin_task = tokio::spawn(async move {
        if let (mut tcp, Some(mut child_in)) = (stdin_stream, child_stdin) {
            let _ = tcp.set_nodelay(true);
            if let Err(err) = tokio::io::copy(&mut tcp, &mut child_in).await {
                eprintln!("[guest] stdin bridge error: {}", err);
            }
        }
    });

    // Bridge stdout: child → TCP
    let mut stdout_task = tokio::spawn(async move {
        if let (mut tcp, Some(mut child_out)) = (stdout_stream, child_stdout) {
            let _ = tcp.set_nodelay(true);
            if let Err(err) = tokio::io::copy(&mut child_out, &mut tcp).await {
                eprintln!("[guest] stdout bridge error: {}", err);
            }
            if let Err(err) = tcp.shutdown().await {
                eprintln!("[guest] stdout shutdown error: {}", err);
            }
        }
    });

    // Bridge stderr: child → TCP
    let mut stderr_task = tokio::spawn(async move {
        if let (mut tcp, Some(mut child_err)) = (stderr_stream, child_stderr) {
            let _ = tcp.set_nodelay(true);
            if let Err(err) = tokio::io::copy(&mut child_err, &mut tcp).await {
                eprintln!("[guest] stderr bridge error: {}", err);
            }
            if let Err(err) = tcp.shutdown().await {
                eprintln!("[guest] stderr shutdown error: {}", err);
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
                match &job {
                    Some(j) => j.terminate(),
                    None => kill_process_tree(child_pid).await,
                }
                if let Err(err) = child.kill().await {
                    eprintln!("[guest] failed to kill timed-out process: {}", err);
                }
                anyhow::bail!("process timed out after {}ms", timeout_ms);
            }
        }
    };

    if let Some(j) = &job {
        j.terminate();
    }

    // Bound the drain so a pipe-holding descendant cannot wedge the guest.
    let drain = tokio::time::timeout(BRIDGE_DRAIN_GRACE, async {
        tokio::join!(&mut stdin_task, &mut stdout_task, &mut stderr_task)
    })
    .await;
    match drain {
        Ok((stdin_result, stdout_result, stderr_result)) => {
            if let Err(err) = stdin_result {
                eprintln!("[guest] stdin bridge task failed: {}", err);
            }
            if let Err(err) = stdout_result {
                eprintln!("[guest] stdout bridge task failed: {}", err);
            }
            if let Err(err) = stderr_result {
                eprintln!("[guest] stderr bridge task failed: {}", err);
            }
        }
        Err(_) => {
            eprintln!(
                "[guest] bridge drain timed out after {:?}; aborting stdio relay (possible leaked descendant holding the pipes)",
                BRIDGE_DRAIN_GRACE
            );
            stdin_task.abort();
            stdout_task.abort();
            stderr_task.abort();
        }
    }

    Ok(exit_status.code().unwrap_or(-1))
}
