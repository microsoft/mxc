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

/// Backstop budget for draining the stdio bridge tasks after the child exits.
///
/// On the success path the child has already exited, so its buffered output
/// should drain and the pipes EOF promptly once we reap any leaked descendants
/// via the Job Object. If a descendant nonetheless escaped the job and still
/// holds the pipes (or the host is slow to read), we abandon the relay after
/// this budget so the guest always reaches the `Exit` send and the reused guest
/// is not wedged. Generous so it does not truncate legitimate output under
/// normal backpressure.
const BRIDGE_DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

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
    expected_nonce: &windows_sandbox_common::auth::Nonce,
) -> Result<()> {
    // Announce the protocol magic + version so the host can fail fast on a
    // version/identity mismatch before any framed messages are exchanged.
    control
        .write_all(&encode_preamble())
        .await
        .context("send preamble")?;

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

/// Forcibly terminate a process and all of its descendants.
///
/// Uses `taskkill /T /F`, which walks the process tree, so workloads that
/// spawn their own children (the common case) are fully cleaned up rather than
/// leaking grandchildren into the reused guest.
async fn kill_process_tree(pid: Option<u32>) {
    let Some(pid) = pid else {
        eprintln!("[guest] cannot tree-kill: child pid unavailable");
        return;
    };
    // Bound the taskkill so a wedged taskkill (e.g. a descendant in
    // un-interruptible I/O) cannot hang the guest's exec teardown forever. The
    // job-object KILL_ON_JOB_CLOSE reap is the primary cleanup; this is a
    // best-effort belt-and-suspenders sweep. `kill_on_drop(true)` so that on a
    // timeout the orphaned taskkill.exe is reaped when the future is dropped
    // rather than lingering until VM teardown.
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
    let child_pid = child.id();

    // Assign the child to a Job Object so we can reliably reap its entire
    // descendant tree later (see `job` module). Best-effort: if job creation or
    // assignment fails we fall back to the bounded bridge drain below for
    // liveness, and (on timeout) to killing the child directly.
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
            if let Err(err) = tokio::io::copy(&mut tcp, &mut child_in).await {
                eprintln!("[guest] stdin bridge error: {}", err);
            }
        }
    });

    // Bridge stdout: child → TCP
    let mut stdout_task = tokio::spawn(async move {
        if let (mut tcp, Some(mut child_out)) = (stdout_stream, child_stdout) {
            if let Err(err) = tokio::io::copy(&mut child_out, &mut tcp).await {
                eprintln!("[guest] stdout bridge error: {}", err);
            }
            // Half-close gracefully so the host observes a clean EOF (FIN)
            // rather than an abortive reset (RST) when the socket is dropped.
            // Dropping a socket with no graceful shutdown can deliver an RST to
            // the host, which would otherwise abort an exec that completed
            // normally (notably for zero-output commands).
            if let Err(err) = tcp.shutdown().await {
                eprintln!("[guest] stdout shutdown error: {}", err);
            }
        }
    });

    // Bridge stderr: child → TCP
    let mut stderr_task = tokio::spawn(async move {
        if let (mut tcp, Some(mut child_err)) = (stderr_stream, child_stderr) {
            if let Err(err) = tokio::io::copy(&mut child_err, &mut tcp).await {
                eprintln!("[guest] stderr bridge error: {}", err);
            }
            // Half-close gracefully so the host observes a clean EOF (see the
            // stdout bridge above).
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
                // Reap the whole process tree, not just the launched `cmd.exe`.
                // The script typically spawns descendants (the actual workload);
                // because the guest is reused across execs, leaked grandchildren
                // would otherwise persist into later executions. Prefer the Job
                // Object (reliable, no PID-reuse race); fall back to taskkill if
                // the job was unavailable.
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

    // Success path: the child (cmd.exe) has exited, but it may have left
    // background descendants that inherited the stdout/stderr pipe write
    // handles. An exec owns its process tree: in a reused disposable sandbox we
    // reap those descendants so (a) their inherited pipe write-ends close,
    // letting the bridge tasks below reach EOF instead of hanging forever, and
    // (b) they do not leak into the next exec. We use the Job Object here
    // because taskkill-by-PID is unreliable once cmd.exe has exited (broken tree
    // linkage, possible PID reuse). If the job was unavailable, we rely on the
    // bounded drain backstop below for liveness.
    if let Some(j) = &job {
        j.terminate();
    }

    // Wait for the bridge tasks to flush remaining output and reach EOF. They
    // normally finish promptly now that the child has exited and (above) its
    // descendants have been reaped. As a liveness backstop, bound the wait: if
    // a descendant escaped the job and still holds the pipes, abort the relay so
    // we always reach the `Exit` send below and the reused guest is not wedged.
    // Aborting drops the bridge tasks' TCP sockets, which the host observes as a
    // stream close.
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
