// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Deadline-bounded subprocess capture shared by the host probes.
//!
//! Both probe sites — the `bwrap --version` gate and the private-network
//! dependency walk — must run a short-lived command and be *certain* to return
//! by a deadline. Two obvious approaches don't hold:
//!
//! * A pipe reports EOF only once *every* write end closes, so a backgrounded
//!   descendant that inherited it blocks the read past the deadline, and killing
//!   the direct child does not help.
//! * A file fixes that but bounds only how much output is *read* — a wedged
//!   descendant keeps writing to the unlinked inode.
//!
//! So the child gets its own process group, its pipes are drained by readers
//! that `poll()` against the deadline, and the group is `SIGKILL`ed on timeout
//! *and* once the leader exits — bounding what the child can write, not just
//! what we agree to read. The leader stays unreaped until both readers finish so
//! its PID cannot be recycled out from under the group sweep.

use std::io::{self, Read};
#[cfg(target_os = "linux")]
use std::process::Child;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::process::CommandExt;

/// Cap on how much of a probe's output is retained. Exceeding it means the
/// command is not the one we thought we were running.
pub(crate) const MAX_PROBE_OUTPUT_BYTES: usize = 64 * 1024;

const INITIAL_WAIT_POLL_INTERVAL: Duration = Duration::from_millis(1);
const MAX_WAIT_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Ceiling on reaping a child we have just tried to kill.
///
/// `SIGKILL` is uncatchable, so a successful kill is reaped almost instantly;
/// this only bounds the case where the signal never landed.
const REAP_TIMEOUT: Duration = Duration::from_millis(250);
const REAP_POLL_INTERVAL: Duration = Duration::from_millis(1);

/// One captured stream, plus whether it outgrew [`MAX_PROBE_OUTPUT_BYTES`].
///
/// Truncation is reported, not silently accepted: a partly-read banner is not
/// one a probe can reason about.
#[derive(Debug)]
pub(crate) struct CapturedOutput {
    pub(crate) bytes: Vec<u8>,
    pub(crate) truncated: bool,
}

/// A probe command that ran to completion within its deadline.
#[derive(Debug)]
pub(crate) struct CapturedProcess {
    pub(crate) status: ExitStatus,
    pub(crate) stdout: CapturedOutput,
    pub(crate) stderr: CapturedOutput,
    /// Failure from sweeping the process group after the leader exited.
    ///
    /// Not folded into the error: a completed command is authoritative, and
    /// some setuid installations refuse to signal their own post-exit group
    /// with `EPERM`. A cleanup diagnostic must not invalidate a real answer.
    pub(crate) cleanup_error: Option<io::Error>,
}

/// Which wait stage failed, so a caller can phrase the failure precisely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WaitStage {
    /// Polling for the child's exit.
    Waiting,
    /// Collecting the exit status of an already-exited child. Linux only, where
    /// the leader stays unreaped until the readers finish.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Reaping,
}

impl WaitStage {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Waiting => "waiting for",
            Self::Reaping => "reaping",
        }
    }
}

/// Why a bounded probe did not produce a [`CapturedProcess`].
///
/// Carries causes, not prose: each probe site words its own diagnostics.
#[derive(Debug)]
pub(crate) enum ProbeFailure {
    /// The command could not be started. Callers classify this themselves —
    /// `ENOENT` means something different for a PATH lookup than for an
    /// absolute path.
    Spawn(io::Error),
    /// The deadline expired. `cleanup_error` is set when terminating the group
    /// also failed, i.e. the probe is abandoning a process it could not prove
    /// it stopped.
    TimedOut { cleanup_error: Option<io::Error> },
    /// Waiting on the child itself failed.
    Wait { stage: WaitStage, error: io::Error },
    /// The probe's own plumbing failed — not a statement about the host.
    Internal(String),
}

/// Run `command` to completion, bounded by `deadline`.
///
/// `command` supplies the program and arguments; stdio, process group and
/// termination are owned here so every probe gets identical semantics. Returns
/// only once the child is reaped and both readers have finished.
pub(crate) fn run_bounded(
    command: &mut Command,
    deadline: Instant,
) -> Result<CapturedProcess, ProbeFailure> {
    if Instant::now() >= deadline {
        return Err(ProbeFailure::TimedOut {
            cleanup_error: None,
        });
    }

    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // A dedicated group is what reaches every descendant, not just the child
    // we spawned.
    #[cfg(unix)]
    command.process_group(0);

    let mut child = command.spawn().map_err(ProbeFailure::Spawn)?;
    let process_group = child.id();

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ProbeFailure::Internal("stdout pipe was not captured".to_string()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| ProbeFailure::Internal("stderr pipe was not captured".to_string()))?;
    let (stdout_reader, stdout_rx) = match spawn_reader(stdout, deadline) {
        Ok(reader) => reader,
        Err(err) => {
            terminate_and_reap(&mut child, process_group);
            return Err(ProbeFailure::Internal(format!(
                "failed to start stdout reader: {err}"
            )));
        }
    };
    let (stderr_reader, stderr_rx) = match spawn_reader(stderr, deadline) {
        Ok(reader) => reader,
        Err(err) => {
            terminate_and_reap(&mut child, process_group);
            let _ = stdout_reader.join();
            return Err(ProbeFailure::Internal(format!(
                "failed to start stderr reader: {err}"
            )));
        }
    };

    let mut status = None;
    let mut stdout = None;
    let mut stderr = None;
    #[cfg(target_os = "linux")]
    let mut group_cleanup_error: Option<io::Error> = None;
    #[cfg(target_os = "linux")]
    let mut leader_exited = false;
    let mut poll_interval = INITIAL_WAIT_POLL_INTERVAL;
    loop {
        if let Err(err) = receive_reader(&stdout_rx, &mut stdout)
            .and_then(|_| receive_reader(&stderr_rx, &mut stderr))
        {
            terminate_and_reap(&mut child, process_group);
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(err);
        }

        #[cfg(target_os = "linux")]
        if status.is_none() && !leader_exited {
            match child_exited_without_reaping(&child) {
                Ok(true) => {
                    // Keep the exited leader unreaped until both readers have
                    // closed. Its reserved PID keeps the process-group ID from
                    // being recycled while descendant cleanup is still possible.
                    group_cleanup_error = terminate_probe_group(process_group).err();
                    leader_exited = true;
                }
                Ok(false) => {}
                Err(error) => {
                    terminate_and_reap(&mut child, process_group);
                    drop(stdout_reader);
                    drop(stderr_reader);
                    return Err(ProbeFailure::Wait {
                        stage: WaitStage::Waiting,
                        error,
                    });
                }
            }
        }

        #[cfg(target_os = "linux")]
        if leader_exited && stdout.is_some() && stderr.is_some() {
            // Safe to block: `child_exited_without_reaping` already observed the
            // exit with `WNOWAIT`, so the zombie is waiting to be collected.
            match child.wait() {
                Ok(exit_status) => status = Some(exit_status),
                Err(error) => {
                    drop(stdout_reader);
                    drop(stderr_reader);
                    return Err(ProbeFailure::Wait {
                        stage: WaitStage::Reaping,
                        error,
                    });
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        if status.is_none() {
            match child.try_wait() {
                Ok(Some(exit_status)) => status = Some(exit_status),
                Ok(None) => {}
                Err(error) => {
                    terminate_and_reap(&mut child, process_group);
                    drop(stdout_reader);
                    drop(stderr_reader);
                    return Err(ProbeFailure::Wait {
                        stage: WaitStage::Waiting,
                        error,
                    });
                }
            }
        }

        if status.is_some() && stdout.is_some() && stderr.is_some() {
            let status = status.take().expect("checked above");
            let stdout = stdout.take().expect("checked above");
            let stderr = stderr.take().expect("checked above");
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            #[cfg(target_os = "linux")]
            let cleanup_error = group_cleanup_error.take();
            #[cfg(not(target_os = "linux"))]
            let cleanup_error = None;
            return Ok(CapturedProcess {
                status,
                stdout,
                stderr,
                cleanup_error,
            });
        }

        if Instant::now() < deadline {
            thread::sleep(poll_interval.min(deadline.saturating_duration_since(Instant::now())));
            poll_interval = poll_interval.saturating_mul(2).min(MAX_WAIT_POLL_INTERVAL);
            continue;
        }

        let kill_error = terminate_and_reap(&mut child, process_group);
        let _ = stdout_reader.join();
        let _ = stderr_reader.join();
        #[cfg(target_os = "linux")]
        let kill_error = kill_error.or(group_cleanup_error);
        return Err(ProbeFailure::TimedOut {
            cleanup_error: kill_error,
        });
    }
}

/// Whether the child has exited without consuming its zombie entry.
///
/// `WNOWAIT` observes the exit while leaving the PID reserved, so the
/// process-group id stays ours until the readers are done with it.
#[cfg(target_os = "linux")]
fn child_exited_without_reaping(child: &Child) -> io::Result<bool> {
    use nix::sys::wait::{waitid, Id, WaitPidFlag, WaitStatus};
    use nix::unistd::Pid;

    let flags = WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT;
    match waitid(Id::Pid(Pid::from_raw(child.id() as i32)), flags) {
        Ok(WaitStatus::StillAlive) => Ok(false),
        Ok(_) => Ok(true),
        Err(err) => Err(io::Error::from_raw_os_error(err as i32)),
    }
}

#[cfg(any(not(unix), test))]
pub(crate) fn read_bounded(mut reader: impl Read) -> io::Result<CapturedOutput> {
    let mut bytes = Vec::new();
    let mut truncated = false;
    let mut buffer = [0_u8; 4096];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let remaining = MAX_PROBE_OUTPUT_BYTES.saturating_sub(bytes.len());
        let retained = read.min(remaining);
        bytes.extend_from_slice(&buffer[..retained]);
        truncated |= retained < read;
    }
    Ok(CapturedOutput { bytes, truncated })
}

#[cfg(unix)]
fn spawn_reader(
    reader: impl Read + AsRawFd + Send + 'static,
    deadline: Instant,
) -> io::Result<(
    thread::JoinHandle<()>,
    mpsc::Receiver<io::Result<CapturedOutput>>,
)> {
    let (sender, receiver) = mpsc::channel();
    let handle = thread::Builder::new()
        .name("mxc-probe-reader".to_string())
        .spawn(move || {
            let _ = sender.send(read_bounded_until(reader, deadline));
        })?;
    Ok((handle, receiver))
}

#[cfg(not(unix))]
fn spawn_reader(
    reader: impl Read + Send + 'static,
    _deadline: Instant,
) -> io::Result<(
    thread::JoinHandle<()>,
    mpsc::Receiver<io::Result<CapturedOutput>>,
)> {
    let (sender, receiver) = mpsc::channel();
    let handle = thread::Builder::new()
        .name("mxc-probe-reader".to_string())
        .spawn(move || {
            let _ = sender.send(read_bounded(reader));
        })?;
    Ok((handle, receiver))
}

/// Drain `reader` until EOF, the cap, or `deadline`.
///
/// The `poll()` bounds a descendant that inherited the write end: a plain
/// `read` would block until every writer closes.
#[cfg(unix)]
pub(crate) fn read_bounded_until(
    mut reader: impl Read + AsRawFd,
    deadline: Instant,
) -> io::Result<CapturedOutput> {
    let mut bytes = Vec::new();
    let mut truncated = false;
    let mut buffer = [0_u8; 4096];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "probe output remained open past the deadline",
            ));
        }
        let timeout_ms = remaining.as_millis().min(i32::MAX as u128) as i32;
        let mut descriptor = nix::libc::pollfd {
            fd: reader.as_raw_fd(),
            events: nix::libc::POLLIN | nix::libc::POLLHUP | nix::libc::POLLERR,
            revents: 0,
        };
        // SAFETY: `descriptor` points to one initialized pollfd for this call.
        let result = unsafe { nix::libc::poll(&mut descriptor, 1, timeout_ms) };
        if result == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "probe output remained open past the deadline",
            ));
        }
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }

        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let remaining_capacity = MAX_PROBE_OUTPUT_BYTES.saturating_sub(bytes.len());
        let retained = read.min(remaining_capacity);
        bytes.extend_from_slice(&buffer[..retained]);
        truncated |= retained < read;
    }
    Ok(CapturedOutput { bytes, truncated })
}

fn receive_reader(
    receiver: &mpsc::Receiver<io::Result<CapturedOutput>>,
    output: &mut Option<CapturedOutput>,
) -> Result<(), ProbeFailure> {
    if output.is_none() {
        match receiver.try_recv() {
            Ok(result) => {
                *output = Some(result.map_err(|err| {
                    if err.kind() == io::ErrorKind::TimedOut {
                        ProbeFailure::TimedOut {
                            cleanup_error: None,
                        }
                    } else {
                        ProbeFailure::Internal(format!("failed reading probe output: {err}"))
                    }
                })?);
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err(ProbeFailure::Internal(
                    "probe output reader disconnected".to_string(),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn terminate_probe_tree(child: &mut std::process::Child, process_group: u32) -> io::Result<()> {
    let child_result = child.kill();
    let group_result = terminate_probe_group(process_group);
    match (child_result, group_result) {
        (_, Err(err)) | (Err(err), Ok(())) => Err(err),
        (Ok(()), Ok(())) => Ok(()),
    }
}

#[cfg(unix)]
fn terminate_probe_group(process_group: u32) -> io::Result<()> {
    use nix::errno::Errno;
    use nix::sys::signal::{killpg, Signal};
    use nix::unistd::Pid;

    match killpg(Pid::from_raw(process_group as i32), Signal::SIGKILL) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(err) => Err(io::Error::from_raw_os_error(err as i32)),
    }
}

#[cfg(not(unix))]
fn terminate_probe_tree(child: &mut std::process::Child, _process_group: u32) -> io::Result<()> {
    child.kill()
}

/// Terminate the probe's process group, then reap the leader without blocking
/// past [`REAP_TIMEOUT`].
///
/// The reap must be bounded, not unconditional. A `SIGKILL` can fail to land —
/// a setuid probe can refuse it with `EPERM` — and the child is then still
/// running, so a plain `wait()` would block until it chose to exit. That is
/// unbounded on exactly the paths that already gave up on a deadline, which
/// would defeat the guarantee this module exists to provide. An unreaped child
/// is the lesser harm: the caller keeps its deadline and gets the error naming
/// what could not be stopped.
fn terminate_and_reap(child: &mut std::process::Child, process_group: u32) -> Option<io::Error> {
    let kill_error = terminate_probe_tree(child, process_group).err();
    reap_bounded(child);
    kill_error
}

/// Collect `child`'s exit status, giving up after [`REAP_TIMEOUT`].
///
/// Split from [`terminate_and_reap`] so the bound is testable against a child
/// that is still running — the case a successful kill never produces.
fn reap_bounded(child: &mut std::process::Child) {
    let deadline = Instant::now() + REAP_TIMEOUT;
    loop {
        match child.try_wait() {
            // Reaped, or unreapable and waiting cannot help.
            Ok(Some(_)) | Err(_) => break,
            Ok(None) if Instant::now() >= deadline => break,
            Ok(None) => thread::sleep(REAP_POLL_INTERVAL),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_reader_drains_but_does_not_retain_excess_output() {
        let input = vec![b'x'; MAX_PROBE_OUTPUT_BYTES + 17];
        let captured = read_bounded(std::io::Cursor::new(input)).unwrap();
        assert_eq!(captured.bytes.len(), MAX_PROBE_OUTPUT_BYTES);
        assert!(captured.truncated);
    }

    #[cfg(unix)]
    #[test]
    fn bounded_reader_times_out_when_the_writer_stays_open() {
        use std::os::unix::net::UnixStream;

        let (reader, _writer) = UnixStream::pair().unwrap();
        let error =
            read_bounded_until(reader, Instant::now() + Duration::from_millis(100)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("remained open"));
    }

    #[test]
    fn an_expired_deadline_does_not_spawn_anything() {
        // A command that fails to spawn: reaching the spawn would surface as
        // `Spawn` rather than `TimedOut`.
        let mut command = Command::new("mxc-probe-command-that-does-not-exist");
        let error = run_bounded(&mut command, Instant::now() - Duration::from_secs(1)).unwrap_err();
        assert!(matches!(
            error,
            ProbeFailure::TimedOut {
                cleanup_error: None
            }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn captures_stdout_and_stderr_separately() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf out; printf err >&2; exit 3"]);
        let captured =
            run_bounded(&mut command, Instant::now() + Duration::from_secs(5)).expect("runs");
        assert_eq!(captured.status.code(), Some(3));
        assert_eq!(captured.stdout.bytes, b"out");
        assert_eq!(captured.stderr.bytes, b"err");
        assert!(!captured.stdout.truncated);
    }

    /// The failure mode the file-backed capture could not bound: a descendant
    /// inherits the pipes and outlives the direct child.
    #[cfg(target_os = "linux")]
    #[test]
    fn returns_while_a_descendant_still_holds_the_pipes_open() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "(while true; do :; done) &\nprintf banner"]);

        let started = Instant::now();
        let captured =
            run_bounded(&mut command, Instant::now() + Duration::from_secs(5)).expect("runs");
        assert_eq!(captured.stdout.bytes, b"banner");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "must not wait for the descendant, took {:?}",
            started.elapsed()
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_wedged_command_times_out_rather_than_hanging() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "while true; do :; done"]);

        let started = Instant::now();
        let error = run_bounded(&mut command, Instant::now() + Duration::from_millis(250))
            .expect_err("must time out");
        assert!(matches!(error, ProbeFailure::TimedOut { .. }));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    /// The reap after a kill must be bounded, not unconditional. A `SIGKILL`
    /// that never lands leaves the child running, and a plain `wait()` would
    /// then block forever on exactly the path that already gave up on a
    /// deadline. Drive that by reaping a child nothing has killed.
    #[cfg(unix)]
    #[test]
    fn reaping_a_live_child_gives_up_instead_of_blocking() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn");

        let started = Instant::now();
        reap_bounded(&mut child);
        let elapsed = started.elapsed();

        assert!(
            elapsed < REAP_TIMEOUT * 4,
            "the reap must stay bounded, took {elapsed:?}"
        );
        // The child outlived the reap, which is the point being asserted.
        assert!(matches!(child.try_wait(), Ok(None)));

        let _ = child.kill();
        let _ = child.wait();
    }

    #[cfg(unix)]
    #[test]
    fn output_past_the_cap_is_reported_as_truncated() {
        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            &format!(
                "dd if=/dev/zero bs=1024 count={} 2>/dev/null",
                (MAX_PROBE_OUTPUT_BYTES / 1024) + 8
            ),
        ]);
        let captured =
            run_bounded(&mut command, Instant::now() + Duration::from_secs(10)).expect("runs");
        assert_eq!(captured.stdout.bytes.len(), MAX_PROBE_OUTPUT_BYTES);
        assert!(captured.stdout.truncated);
    }

    #[test]
    fn a_missing_command_reports_the_spawn_error() {
        let mut command = Command::new("mxc-probe-command-that-does-not-exist");
        let error = run_bounded(&mut command, Instant::now() + Duration::from_secs(5)).unwrap_err();
        match error {
            ProbeFailure::Spawn(err) => assert_eq!(err.kind(), io::ErrorKind::NotFound),
            other => panic!("expected a spawn failure, got {other:?}"),
        }
    }
}
