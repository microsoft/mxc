// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `mxc_pty` — shared pty bridge for the unix-side MXC backends.
//!
//! Both the Linux LXC backend (`lxc_common::lxc_bindings::attach_run`) and
//! the macOS Seatbelt backend (`seatbelt_common::seatbelt_runner`) need to
//! run a child process attached to a freshly-allocated pty so the inner
//! shell sees a real TTY (`isatty(0/1/2) -> true`) and the host can stream
//! output as it arrives. The two implementations were ~95% the same code;
//! this crate is the deduplicated home for that pty plumbing.

use std::process::Command;
use std::time::Duration;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use nix::sys::signal::Signal;

/// Placeholder `Signal` on non-unix targets so the public type signature
/// of [`PtyOptions`] is the same on every host. Constructing one is
/// pointless because [`run_with_pty`] is a stub on those targets.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Signal {}

/// Knobs the caller can tweak when bridging a child through a pty.
#[derive(Clone, Debug)]
pub struct PtyOptions {
    /// Maximum wall-clock time to wait for the child to exit. `None`
    /// means wait forever; `Some(d)` polls `try_wait` every
    /// [`POLL_INTERVAL`](Self::POLL_INTERVAL) until the deadline passes,
    /// at which point the child is killed and [`PtyOutcome::TimedOut`]
    /// is returned.
    pub timeout: Option<Duration>,

    /// How long to wait for the inner process to print its first byte
    /// before forwarding host stdin to the pty master. The delay matters
    /// because an interactive shell calls `tcsetattr` during readline
    /// init, which can flush bytes the parent buffered in the pty before
    /// the shell got there. Set to `Duration::ZERO` to forward stdin
    /// immediately.
    pub ready_wait: Duration,

    /// Signals to unblock in the child via `pthread_sigmask` inside
    /// `pre_exec`. Use this when the parent process blocks signals
    /// (e.g. for a sigwait-based watchdog) and that mask would otherwise
    /// be inherited across `fork`+`exec`.
    pub unblock_signals: &'static [Signal],
}

impl PtyOptions {
    /// Default poll interval used by [`run_with_pty`] when a timeout is
    /// configured. Exposed so callers that want to validate timeouts
    /// (e.g. reject `script_timeout` values smaller than the poll
    /// granularity) can match against the same constant.
    pub const POLL_INTERVAL: Duration = Duration::from_millis(500);
}

impl Default for PtyOptions {
    fn default() -> Self {
        Self {
            timeout: None,
            ready_wait: Duration::from_secs(5),
            unblock_signals: &[],
        }
    }
}

/// Result of a successful pty bridge.
///
/// "Successful" here means the bridge itself worked — i.e. we managed to
/// spawn the child and wait on it. The child's own exit status is carried
/// inside [`PtyOutcome::Exited`].
#[derive(Debug)]
pub enum PtyOutcome {
    /// Child terminated before the timeout (or no timeout was set).
    Exited(std::process::ExitStatus),
    /// `timeout` elapsed before the child exited; the child has been
    /// killed and reaped before this variant is returned.
    TimedOut,
}

/// Spawn `command` attached to a freshly-allocated pty pair and bridge
/// it to the host's stdin/stdout/stderr.
///
/// The slave end becomes the child's stdin/stdout/stderr; the master end
/// stays in this process and is forwarded to/from the host fds on
/// background threads. All of the child's output has therefore been
/// streamed to the host stdio by the time this function returns;
/// callers needing captured output should write it to a file in cwd
/// and read it back from there.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn run_with_pty(mut command: Command, options: PtyOptions) -> Result<PtyOutcome, String> {
    use std::io::{Read, Write};
    use std::process::Stdio;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Instant;

    use nix::pty::openpty;

    let pty_pair = openpty(None, None).map_err(|e| format!("openpty failed: {}", e))?;

    // Three duplicates of the slave fd so each Stdio takes ownership of
    // its own handle; otherwise std::process::Stdio::from would consume
    // the single OwnedFd and the rest of the spawn calls would fail.
    let slave_in: Stdio = pty_pair
        .slave
        .try_clone()
        .map_err(|e| format!("dup slave for stdin: {}", e))?
        .into();
    let slave_out: Stdio = pty_pair
        .slave
        .try_clone()
        .map_err(|e| format!("dup slave for stdout: {}", e))?
        .into();
    let slave_err: Stdio = pty_pair.slave.into();

    command.stdin(slave_in).stdout(slave_out).stderr(slave_err);

    // Drop the inherited controlling terminal in the child and make the
    // slave end of our pty its new controlling tty. Without this the
    // child detects that it has a controlling tty (the outer pty from
    // node-pty) and forwards the inner pty's I/O to `/dev/tty` directly,
    // bypassing the slave fds we wired into stdio. Our master would
    // then see no data at all.
    //
    // `unblock_signals` reverses any sigmask the parent installed (e.g.
    // signal_cleanup's sigwait-blocked set) so the child doesn't
    // silently ignore Ctrl-C / termination.
    let unblock_signals = options.unblock_signals;
    // SAFETY: the closure runs after fork, before exec. Only
    // async-signal-safe operations are used: `setsid`, `ioctl`, and
    // `pthread_sigmask` (via nix's `SigSet::thread_unblock`). No
    // allocation or non-reentrant libc calls.
    unsafe {
        use std::os::unix::process::CommandExt;
        command.pre_exec(move || {
            // Become a new session leader, detaching from the inherited
            // controlling terminal.
            nix::unistd::setsid().map_err(std::io::Error::from)?;
            // ioctl on fd 0 (the slave we just dup2'd in via stdin) to
            // make it the new controlling tty. Errors are non-fatal
            // because setsid above already cleared the ctty state, which
            // is what actually matters for the child.
            let _ = libc::ioctl(0, libc::TIOCSCTTY as _, 0);

            if !unblock_signals.is_empty() {
                let mut mask = nix::sys::signal::SigSet::empty();
                for sig in unblock_signals {
                    mask.add(*sig);
                }
                mask.thread_unblock().map_err(std::io::Error::from)?;
            }
            Ok(())
        });
    }

    let mut child = command
        .spawn()
        .map_err(|e| format!("failed to spawn child: {}", e))?;

    drop(command);

    // The child inherited all three slave handles and the parent's
    // copies have been moved into Stdio. The slave will be fully closed
    // when the child exits, which makes our master read return EOF.
    let master: std::fs::File = pty_pair.master.into();
    let mut master_writer = master
        .try_clone()
        .map_err(|e| format!("dup master: {}", e))?;
    let mut master_reader = master;

    // Output forwarder: master -> host stdout. Signals "ready" on the
    // first byte from inside the child so the input forwarder doesn't
    // race the inner shell's `tcsetattr` init.
    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    let output_thread = thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let mut signaled = false;
        let mut stdout = std::io::stdout();
        loop {
            match master_reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if !signaled {
                        let _ = ready_tx.send(());
                        signaled = true;
                    }
                    let _ = stdout.write_all(&buf[..n]);
                    let _ = stdout.flush();
                }
                Err(_) => break,
            }
        }
    });

    // Cap the wait so a wedged shell doesn't block the stdin forwarder
    // forever; the child itself still runs to completion below.
    if !options.ready_wait.is_zero() {
        let _ = ready_rx.recv_timeout(options.ready_wait);
    }

    // Input forwarder: host stdin -> master. Detached; exits when stdin
    // closes (which happens when our parent closes the outer pty).
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let mut stdin = std::io::stdin();
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if master_writer.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let outcome = match options.timeout {
        None => {
            let status = child.wait().map_err(|e| format!("wait: {}", e))?;
            PtyOutcome::Exited(status)
        }
        Some(timeout) => {
            let deadline = Instant::now() + timeout;
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => break PtyOutcome::Exited(status),
                    Ok(None) => {
                        if Instant::now() >= deadline {
                            let _ = child.kill();
                            let _ = child.wait();
                            break PtyOutcome::TimedOut;
                        }
                        thread::sleep(PtyOptions::POLL_INTERVAL);
                    }
                    Err(e) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(format!("try_wait: {}", e));
                    }
                }
            }
        }
    };

    // Drain remaining output before returning. The slave fds are closed
    // on child exit, so master_reader hits EOF and the thread exits.
    let _ = output_thread.join();

    Ok(outcome)
}

/// Stub for the workspace-wide clippy lane that runs on Windows.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn run_with_pty(_command: Command, _options: PtyOptions) -> Result<PtyOutcome, String> {
    Err("mxc_pty::run_with_pty is only supported on Linux and macOS".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_options() {
        let opts = PtyOptions::default();
        assert!(opts.timeout.is_none());
        assert_eq!(opts.ready_wait, Duration::from_secs(5));
        assert!(opts.unblock_signals.is_empty());
    }

    #[test]
    fn poll_interval_is_500ms() {
        assert_eq!(PtyOptions::POLL_INTERVAL, Duration::from_millis(500));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn echo_runs_under_pty() {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg("echo hello-from-pty");
        let outcome = run_with_pty(cmd, PtyOptions::default()).expect("bridge spawns");
        match outcome {
            PtyOutcome::Exited(status) => assert!(status.success()),
            PtyOutcome::TimedOut => panic!("echo should not time out"),
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn timeout_kills_long_running_child() {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg("sleep 30");
        let opts = PtyOptions {
            timeout: Some(Duration::from_millis(750)),
            ..PtyOptions::default()
        };
        let outcome = run_with_pty(cmd, opts).expect("bridge spawns");
        assert!(matches!(outcome, PtyOutcome::TimedOut));
    }
}
