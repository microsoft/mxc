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
    /// before forwarding host stdin to the pty primary. The delay matters
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
/// The secondary end becomes the child's stdin/stdout/stderr; the primary
/// end stays in this process and is forwarded to/from the host fds on
/// background threads. All of the child's output has therefore been
/// streamed to the host stdio by the time this function returns;
/// callers needing captured output should write it to a file in cwd
/// and read it back from there.
///
/// When fd 0 is itself a tty (i.e. the executor binary is being driven
/// by a parent that wrapped it in a pty — the common case for the
/// `mxc-sdk` host), we put that outer secondary into raw mode for the
/// duration of the bridge. Without this, the kernel termios on the
/// outer pty echoes back any bytes the host writes to its primary and
/// renders control chars as `^X` on the way through, which corrupts
/// any TUI the inner child renders (e.g. terminal palette query
/// responses get echoed instead of forwarded as input).
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn run_with_pty(mut command: Command, options: PtyOptions) -> Result<PtyOutcome, String> {
    use std::io::{Read, Write};
    use std::os::unix::io::AsRawFd;
    use std::process::Stdio;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Instant;

    use nix::pty::openpty;

    // Put our own stdin (the outer pty secondary, if any) into raw mode so
    // input bytes pass through to the inner pty without local echo or
    // canonical-mode line buffering. The guard restores the original
    // termios on drop — important because mxc-exec-mac continues to
    // print to stdout after `run_with_pty` returns.
    let _outer_raw_guard = RawSecondaryGuard::install(std::io::stdin().as_raw_fd());

    // Inherit the outer pty's window size so the inner child renders at
    // the host terminal's actual dimensions instead of macOS' default
    // 0×0 (which silently breaks any TUI). When fd 0 is not a tty (CI,
    // pipe, file redirect) we leave the inner pty at its kernel
    // default — interactive TUIs aren't useful in that case anyway.
    let outer_winsize = unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_col > 0 && ws.ws_row > 0 {
            Some(ws)
        } else {
            None
        }
    };
    let inner_winsize = outer_winsize.map(|ws| nix::pty::Winsize {
        ws_row: ws.ws_row,
        ws_col: ws.ws_col,
        ws_xpixel: ws.ws_xpixel,
        ws_ypixel: ws.ws_ypixel,
    });

    let pty_pair =
        openpty(inner_winsize.as_ref(), None).map_err(|e| format!("openpty failed: {}", e))?;

    // The `nix::pty` crate exposes the POSIX field names `.master` and
    // `.slave` on `PtyPair`. We refer to those ends as primary and
    // secondary in our own variables and prose below.

    // Three duplicates of the secondary fd so each Stdio takes ownership of
    // its own handle; otherwise std::process::Stdio::from would consume
    // the single OwnedFd and the rest of the spawn calls would fail.
    let secondary_in: Stdio = pty_pair
        .slave
        .try_clone()
        .map_err(|e| format!("dup secondary for stdin: {}", e))?
        .into();
    let secondary_out: Stdio = pty_pair
        .slave
        .try_clone()
        .map_err(|e| format!("dup secondary for stdout: {}", e))?
        .into();
    let secondary_err: Stdio = pty_pair.slave.into();

    command
        .stdin(secondary_in)
        .stdout(secondary_out)
        .stderr(secondary_err);

    // Drop the inherited controlling terminal in the child and make the
    // secondary end of our pty its new controlling tty. Without this the
    // child detects that it has a controlling tty (the outer pty from
    // node-pty) and forwards the inner pty's I/O to `/dev/tty` directly,
    // bypassing the secondary fds we wired into stdio. Our primary would
    // then see no data at all.
    //
    // `unblock_signals` reverses any sigmask the parent installed (e.g.
    // signal_cleanup's sigwait-blocked set) so the child doesn't
    // silently ignore Ctrl-C / termination. SIGWINCH is unblocked
    // defensively in case anyone in the parent process had it blocked;
    // execve(2) resets the handler to default ("ignore" for SIGWINCH on
    // both Linux and macOS) but preserves the inherited signal mask, so
    // a child process running e.g. node will install its own SIGWINCH
    // handler and depend on the signal not being masked.
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
            // ioctl on fd 0 (the secondary we just dup2'd in via stdin) to
            // make it the new controlling tty. Errors are non-fatal
            // because setsid above already cleared the ctty state, which
            // is what actually matters for the child.
            let _ = libc::ioctl(0, libc::TIOCSCTTY as _, 0);

            let mut mask = nix::sys::signal::SigSet::empty();
            mask.add(nix::sys::signal::Signal::SIGWINCH);
            for sig in unblock_signals {
                mask.add(*sig);
            }
            mask.thread_unblock().map_err(std::io::Error::from)?;
            Ok(())
        });
    }

    let mut child = command
        .spawn()
        .map_err(|e| format!("failed to spawn child: {}", e))?;

    drop(command);

    // The child inherited all three secondary handles and the parent's
    // copies have been moved into Stdio. The secondary will be fully closed
    // when the child exits, which makes our primary read return EOF.
    let primary: std::fs::File = pty_pair.master.into();
    let mut primary_writer = primary
        .try_clone()
        .map_err(|e| format!("dup primary: {}", e))?;
    let mut primary_reader = primary;

    // Resize forwarder: when the host's terminal resizes, the kernel
    // delivers SIGWINCH to us (because our fd 0 is the outer pty
    // secondary). Read the new size off fd 0 and push it to the inner pty
    // primary via TIOCSWINSZ — that delivers SIGWINCH to the inner
    // child, so TUIs reflow correctly. Hand the forwarder its own
    // dup of the primary so the resize fd isn't tied to the lifetime
    // of `primary_writer` (which the input-forwarder thread can drop
    // mid-session); the forwarder leaks its dup for the rest of the
    // process, the same lifetime as the signal handler that targets it.
    let winch_primary = primary_writer
        .try_clone()
        .map_err(|e| format!("dup primary for sigwinch forwarder: {}", e))?;
    let _winch_thread = spawn_sigwinch_forwarder(winch_primary);

    // Output forwarder: primary -> host stdout. Signals "ready" on the
    // first byte from inside the child so the input forwarder doesn't
    // race the inner shell's `tcsetattr` init.
    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    let output_thread = thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let mut signaled = false;
        let mut stdout = std::io::stdout();
        loop {
            match primary_reader.read(&mut buf) {
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

    // The overall timeout starts the moment the child is spawned, not
    // after the readiness wait completes; otherwise a 5s ready_wait on
    // a 5s-timeout job would silently double the budget.
    let deadline = options.timeout.map(|t| Instant::now() + t);

    // Cap the readiness wait at whatever's left in the deadline so we
    // don't sleep past it for a child that never prints anything.
    let ready_budget = match deadline {
        Some(d) => options
            .ready_wait
            .min(d.saturating_duration_since(Instant::now())),
        None => options.ready_wait,
    };
    if !ready_budget.is_zero() {
        let _ = ready_rx.recv_timeout(ready_budget);
    }

    // Input forwarder: host stdin -> primary. Detached; exits when stdin
    // closes (which happens when our parent closes the outer pty).
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let mut stdin = std::io::stdin();
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if primary_writer.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let outcome = match deadline {
        None => {
            let status = child.wait().map_err(|e| format!("wait: {}", e))?;
            PtyOutcome::Exited(status)
        }
        Some(deadline) => loop {
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
        },
    };

    // Drain remaining output before returning. The secondary fds are closed
    // on child exit, so primary_reader hits EOF and the thread exits.
    let _ = output_thread.join();

    Ok(outcome)
}

/// Background thread that watches for SIGWINCH on the outer pty
/// (delivered to *some* thread because fd 0 is the outer secondary) and
/// forwards the new window size to the inner pty primary via TIOCSWINSZ.
///
/// Uses the self-pipe pattern: an async-signal-safe SIGWINCH handler
/// writes one byte to a pipe, and a dedicated thread reads from the
/// pipe and does the ioctl dance. This works regardless of which
/// thread the kernel picks to deliver the signal to (sigwait alone is
/// not enough — pthread_sigmask only changes the calling thread's
/// mask, so other threads created by the runtime can swallow SIGWINCH
/// first and our sigwait blocks forever).
///
/// Best-effort: if any of the setup steps fail we just skip resize
/// propagation and the inner stays at its initial size.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn spawn_sigwinch_forwarder(primary: std::fs::File) -> Option<std::thread::JoinHandle<()>> {
    use std::os::unix::io::AsRawFd;

    let (read_end, write_end) = nix::unistd::pipe().ok()?;
    let read_fd = read_end.as_raw_fd();
    let write_fd = write_end.as_raw_fd();
    let primary_fd = primary.as_raw_fd();
    // Leak so the fds outlive every reader/writer in the process. The
    // signal handler targets `write_fd` for the rest of the process,
    // and `primary_fd` is what we ioctl into on every resize — closing
    // either would race.
    std::mem::forget(read_end);
    std::mem::forget(write_end);
    std::mem::forget(primary);

    // Make the write end non-blocking so the signal handler can't
    // deadlock on a full pipe (the comment on `sigwinch_handler` already
    // assumes EAGAIN-on-full, but without O_NONBLOCK write(2) would
    // actually block inside the handler instead of dropping the wakeup).
    // Best-effort: if fcntl fails we stay in blocking mode — same as the
    // previous behavior, no regression.
    unsafe {
        let flags = libc::fcntl(write_fd, libc::F_GETFL);
        if flags >= 0 {
            let _ = libc::fcntl(write_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }

    SIGWINCH_PIPE_WRITE_FD.store(write_fd, std::sync::atomic::Ordering::Release);

    // SIGWINCH's default action is "ignore", so without an installed
    // handler the kernel drops the signal entirely. SA_RESTART so we
    // don't break unrelated syscalls.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = sigwinch_handler as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = libc::SA_RESTART;
        if libc::sigaction(libc::SIGWINCH, &sa, std::ptr::null_mut()) != 0 {
            return None;
        }
    }

    Some(std::thread::spawn(move || {
        let mut buf = [0u8; 64];
        loop {
            // Read at least one byte; coalesce bursts.
            let n = unsafe { libc::read(read_fd, buf.as_mut_ptr() as *mut _, buf.len()) };
            if n <= 0 {
                return;
            }
            unsafe {
                let mut ws: libc::winsize = std::mem::zeroed();
                if libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) != 0 {
                    continue;
                }
                // Inner pty gone — exit the thread.
                if libc::ioctl(primary_fd, libc::TIOCSWINSZ, &ws) != 0 {
                    return;
                }
            }
        }
    }))
}

/// Write end of the SIGWINCH self-pipe. Set once during forwarder
/// installation; the handler reads this and write()s 1 byte.
#[cfg(any(target_os = "linux", target_os = "macos"))]
static SIGWINCH_PIPE_WRITE_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

/// Async-signal-safe SIGWINCH handler. The only syscall used is write(2),
/// which is on the AS-safe list. Errors are intentionally ignored — if
/// the pipe is full (64 bytes pending and reader hasn't drained) we just
/// drop the redundant wakeup.
#[cfg(any(target_os = "linux", target_os = "macos"))]
extern "C" fn sigwinch_handler(_sig: libc::c_int) {
    let fd = SIGWINCH_PIPE_WRITE_FD.load(std::sync::atomic::Ordering::Acquire);
    if fd < 0 {
        return;
    }
    let byte: u8 = 1;
    unsafe {
        let _ = libc::write(fd, &byte as *const _ as *const _, 1);
    }
}

/// RAII guard that puts an outer pty secondary fd into raw mode on creation
/// and restores the original termios on drop. Used by [`run_with_pty`]
/// when our own stdin is itself a pty secondary (i.e. the executor is
/// running under a host-allocated pty), so that input bytes round-trip
/// to the inner child's pty cleanly without local echo or `^X`-style
/// control-char rendering corrupting the inner TUI.
///
/// Doing nothing (and dropping cleanly) is the right behaviour when
/// stdin is not a tty (piped input, redirected from a file, etc.) or
/// when termios calls fail — the inner child still works, just without
/// the raw-mode passthrough.
#[cfg(any(target_os = "linux", target_os = "macos"))]
struct RawSecondaryGuard {
    fd: std::os::unix::io::RawFd,
    original: nix::sys::termios::Termios,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl RawSecondaryGuard {
    fn install(fd: std::os::unix::io::RawFd) -> Option<Self> {
        use nix::sys::termios::{cfmakeraw, tcgetattr, tcsetattr, SetArg};
        // SAFETY: `isatty` is async-signal-safe and only touches the
        // process's own fd table.
        if unsafe { libc::isatty(fd) } == 0 {
            return None;
        }
        // nix's tcgetattr takes anything implementing AsFd.
        let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
        let original = tcgetattr(borrowed).ok()?;
        let mut raw = original.clone();
        cfmakeraw(&mut raw);
        if tcsetattr(borrowed, SetArg::TCSANOW, &raw).is_err() {
            return None;
        }
        Some(Self { fd, original })
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for RawSecondaryGuard {
    fn drop(&mut self) {
        use nix::sys::termios::{tcsetattr, SetArg};
        let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(self.fd) };
        let _ = tcsetattr(borrowed, SetArg::TCSANOW, &self.original);
    }
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
