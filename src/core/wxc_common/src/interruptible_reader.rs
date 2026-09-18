// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A Unix pipe reader whose `read` can be cancelled out-of-band.
//!
//! The in-tree Unix backends (Seatbelt, Bubblewrap) hand the caller the child's
//! raw stdout/stderr pipe, where a blocking `read` only ends at EOF — when every
//! write end closes. A backgrounded descendant that inherited the pipe can hold
//! its write end open past the foreground command's exit, leaving such a read
//! parked indefinitely. [`InterruptibleReader`] wraps the pipe so a separate
//! [`ReadCanceller`] (a [`StreamCloser`]) can make that read return EOF
//! (`Ok(0)`) promptly, without killing the child.
//!
//! It uses a self-pipe + `poll(2)`: the read fd is set non-blocking and the
//! reader blocks in `poll` on both the data pipe and the read end of a
//! self-pipe; cancellation writes a byte to the self-pipe (waking the `poll`)
//! and sets a flag so later reads drain bytes already available, then report
//! EOF without waiting for more.

use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::sandbox_process::StreamCloser;

/// Cancellation state shared between an [`InterruptibleReader`] and the
/// [`ReadCanceller`]s minted from it: the write end of the self-pipe used to
/// wake the reader's `poll`, plus a flag so a read after cancellation returns
/// EOF without touching the data pipe.
struct CancelState {
    cancelled: AtomicBool,
    /// Write end of the self-pipe; one byte here wakes the reader's `poll`.
    wake_w: OwnedFd,
}

impl CancelState {
    /// Mark cancelled (once) and nudge the reader's `poll` awake.
    fn cancel(&self) {
        // Flag first so a read that wakes observes EOF, then wake the poll. If
        // we were already cancelled, do nothing — `close` is idempotent.
        if self.cancelled.swap(true, Ordering::Release) {
            return;
        }
        // A single byte makes `poll` return. The self-pipe write end is
        // non-blocking, so this never blocks; ignore the result — `EAGAIN`
        // (a wake byte is already pending) and `EPIPE` (the reader's end has
        // been dropped) are both fine.
        let byte = [0u8; 1];
        // SAFETY: `wake_w` is a valid, owned, non-blocking pipe write fd; the
        // buffer is a valid 1-byte local.
        unsafe {
            libc::write(self.wake_w.as_raw_fd(), byte.as_ptr().cast(), 1);
        }
    }
}

/// A [`StreamCloser`] for an [`InterruptibleReader`]. Cloneable and `Send +
/// Sync` so several may be held (and fired from any thread); all share one
/// cancellation state, and `close` is idempotent.
#[derive(Clone)]
pub struct ReadCanceller(Arc<CancelState>);

impl StreamCloser for ReadCanceller {
    fn close(&self) {
        self.0.cancel();
    }
}

/// A readable Unix fd whose `read` can be cancelled via a [`ReadCanceller`].
///
/// Implements [`Read`]: it blocks in `poll(2)` on the data pipe and a self-pipe
/// and returns the next chunk, real EOF (`Ok(0)`), or — once a paired
/// [`ReadCanceller::close`] fires — bytes already buffered followed by a prompt
/// cancellation EOF (`Ok(0)`).
pub struct InterruptibleReader {
    /// The child's stdout/stderr fd. Normally non-blocking; pty callers may
    /// preserve blocking mode because duplicated primary fds share flags.
    fd: OwnedFd,
    /// Read end of the self-pipe; readable once cancellation writes its byte.
    wake_r: OwnedFd,
    state: Arc<CancelState>,
}

impl InterruptibleReader {
    /// Wrap an owned readable pipe `fd` so its reads can be cancelled
    /// out-of-band. Sets `fd` non-blocking and creates the self-pipe used for
    /// wakeups.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`io::Error`] if the self-pipe cannot be created
    /// or either fd cannot be switched to non-blocking mode.
    pub fn new(fd: OwnedFd) -> io::Result<Self> {
        Self::new_inner(fd, true)
    }

    /// Wrap a readable fd without changing its shared file-status flags.
    ///
    /// This is intended for a pseudo-terminal primary whose duplicated fd is
    /// also used for stdin. `O_NONBLOCK` belongs to the shared open-file
    /// description, so setting it on the reader would unexpectedly make the
    /// writer non-blocking too.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`io::Error`] if the cancellation self-pipe
    /// cannot be created or configured.
    pub fn new_blocking(fd: OwnedFd) -> io::Result<Self> {
        Self::new_inner(fd, false)
    }

    fn new_inner(fd: OwnedFd, make_nonblocking: bool) -> io::Result<Self> {
        if make_nonblocking {
            set_nonblocking(fd.as_raw_fd())?;
        }

        // Self-pipe for wakeups: the write end is non-blocking so `cancel`
        // never stalls; the read end stays blocking but is only ever polled.
        let mut fds = [0 as RawFd; 2];
        // SAFETY: `fds` is a valid 2-element array for `pipe` to fill.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `pipe` succeeded, so both fds are freshly owned by us.
        let wake_r = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let wake_w = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        // `pipe(2)` doesn't set close-on-exec, so mark both ends `FD_CLOEXEC` —
        // otherwise they leak into any process this thread later forks+execs
        // (e.g. another sandbox child). The data pipe is already CLOEXEC: Rust
        // sets it on `Child` stdio.
        set_cloexec(wake_r.as_raw_fd())?;
        set_cloexec(wake_w.as_raw_fd())?;
        set_nonblocking(wake_w.as_raw_fd())?;

        Ok(Self {
            fd,
            wake_r,
            state: Arc::new(CancelState {
                cancelled: AtomicBool::new(false),
                wake_w,
            }),
        })
    }

    /// Mint a closer that EOFs this reader's `read` on demand. Several closers
    /// may be minted; they share one cancellation state.
    pub fn canceller(&self) -> ReadCanceller {
        ReadCanceller(Arc::clone(&self.state))
    }
}

/// Wrap an optional child pipe end into an [`InterruptibleReader`] plus a
/// [`ReadCanceller`] for its [`StreamCloser`]. `None` (inherited stdio) stays
/// `None` for both. Convenience for the Unix backends, which hold `ChildStdout`
/// / `ChildStderr` (both `Into<OwnedFd>`).
///
/// # Errors
///
/// Propagates any [`io::Error`] from [`InterruptibleReader::new`].
pub fn wrap_pipe<T: Into<OwnedFd>>(
    pipe: Option<T>,
) -> io::Result<(Option<InterruptibleReader>, Option<ReadCanceller>)> {
    let Some(pipe) = pipe else {
        return Ok((None, None));
    };
    let reader = InterruptibleReader::new(pipe.into())?;
    let canceller = reader.canceller();
    Ok((Some(reader), Some(canceller)))
}

impl Read for InterruptibleReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // A zero-length read must return `Ok(0)` immediately (the `Read`
        // contract), never block in `poll`.
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            let cancelled = self.state.cancelled.load(Ordering::Acquire);
            let mut poll_fds = [
                libc::pollfd {
                    fd: self.fd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: self.wake_r.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // SAFETY: `poll_fds` is a valid 2-element array of pollfds; both
            // fds are owned and live for the duration of the call.
            // After cancellation, poll without waiting so bytes already in the
            // kernel buffer are preserved but later descendant output is not.
            let timeout = if cancelled { 0 } else { -1 };
            let rc = unsafe { libc::poll(poll_fds.as_mut_ptr(), 2, timeout) };
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            if rc == 0 {
                return Ok(0);
            }

            // Data wins over cancellation for this read so foreground bytes
            // already queued when close fired are not lost.
            if poll_fds[0].revents != 0 {
                // SAFETY: `fd` is owned and `buf` is a valid writable slice.
                let n =
                    unsafe { libc::read(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
                if n >= 0 {
                    return Ok(n as usize);
                }
                let err = io::Error::last_os_error();
                match err.raw_os_error() {
                    // Spurious readiness (e.g. POLLHUP with no buffered bytes):
                    // loop and re-poll, or finish if cancellation has fired.
                    Some(libc::EAGAIN) if self.state.cancelled.load(Ordering::Acquire) => {
                        return Ok(0);
                    }
                    Some(libc::EAGAIN) => continue,
                    _ if err.kind() == io::ErrorKind::Interrupted => continue,
                    _ => return Err(err),
                }
            }

            if self.state.cancelled.load(Ordering::Acquire) || poll_fds[1].revents != 0 {
                return Ok(0);
            }
        }
    }
}

/// Add `O_NONBLOCK` to `fd`'s file-status flags.
fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` is a valid open fd; `fcntl` with these commands only reads
    // and writes its flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Add `FD_CLOEXEC` to `fd`'s descriptor flags so it doesn't leak across `exec`.
fn set_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` is a valid open fd; `fcntl` with these commands only reads
    // and writes its descriptor flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::{Duration, Instant};

    /// Build an `InterruptibleReader` over a fresh pipe, returning it plus the
    /// write end so a test can feed it bytes.
    fn reader_with_writer() -> (InterruptibleReader, OwnedFd) {
        let mut fds = [0 as RawFd; 2];
        assert!(unsafe { libc::pipe(fds.as_mut_ptr()) } == 0, "pipe");
        let read_end = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let write_end = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        let reader = InterruptibleReader::new(read_end).expect("wrap reader");
        (reader, write_end)
    }

    #[test]
    fn reads_data_then_eof_on_writer_close() {
        let (mut reader, write_end) = reader_with_writer();
        let mut writer = std::fs::File::from(write_end);
        writer.write_all(b"hello").expect("write");
        drop(writer); // close write end -> EOF after the data

        let mut buf = [0u8; 16];
        let n = reader.read(&mut buf).expect("read data");
        assert_eq!(&buf[..n], b"hello");
        assert_eq!(reader.read(&mut buf).expect("read eof"), 0);
    }

    #[test]
    fn zero_length_read_returns_ok_zero_without_blocking() {
        // The write end stays open, so a normal read would block; a zero-length
        // read must still return Ok(0) immediately per the `Read` contract.
        let (mut reader, _write_end) = reader_with_writer();
        let mut empty: [u8; 0] = [];
        assert_eq!(reader.read(&mut empty).expect("zero-length read"), 0);
    }

    #[test]
    fn close_unblocks_a_parked_read_without_writer_close() {
        // The write end stays open for the whole test, so a plain read would
        // block forever; the canceller must EOF it promptly.
        let (reader, _write_end) = reader_with_writer();
        let canceller = reader.canceller();
        let mut reader = reader;

        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 16];
            let start = Instant::now();
            let n = reader.read(&mut buf).expect("read returns");
            (n, start.elapsed())
        });

        std::thread::sleep(Duration::from_millis(50));
        canceller.close();

        let (n, elapsed) = handle.join().expect("reader thread");
        assert_eq!(n, 0, "cancelled read reports EOF");
        assert!(
            elapsed < Duration::from_secs(5),
            "read should return promptly after close, took {elapsed:?}"
        );
    }

    #[test]
    fn close_preserves_bytes_already_buffered() {
        let (mut reader, write_end) = reader_with_writer();
        let mut writer = std::fs::File::from(write_end);
        writer.write_all(b"foreground").expect("write");
        let canceller = reader.canceller();

        canceller.close();

        let mut buf = [0u8; 32];
        let n = reader.read(&mut buf).expect("read buffered data");
        assert_eq!(&buf[..n], b"foreground");
        assert_eq!(reader.read(&mut buf).expect("cancelled eof"), 0);
    }

    #[test]
    fn close_is_idempotent_and_reads_stay_eof() {
        let (mut reader, _write_end) = reader_with_writer();
        let canceller = reader.canceller();
        canceller.close();
        canceller.close(); // second call is a no-op

        let mut buf = [0u8; 16];
        assert_eq!(reader.read(&mut buf).expect("eof"), 0);
        assert_eq!(reader.read(&mut buf).expect("still eof"), 0);
    }

    #[test]
    fn blocking_constructor_preserves_shared_file_status_flags() {
        let mut fds = [0 as RawFd; 2];
        assert!(unsafe { libc::pipe(fds.as_mut_ptr()) } == 0, "pipe");
        let read_end = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let write_end = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        let reader = InterruptibleReader::new_blocking(read_end).expect("wrap reader");

        // SAFETY: the reader owns this valid fd and F_GETFL only reads flags.
        let flags = unsafe { libc::fcntl(reader.fd.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0, "F_GETFL");
        assert_eq!(flags & libc::O_NONBLOCK, 0);

        drop(write_end);
    }

    #[test]
    fn blocking_constructor_still_allows_concurrent_cancellation() {
        let mut fds = [0 as RawFd; 2];
        assert!(unsafe { libc::pipe(fds.as_mut_ptr()) } == 0, "pipe");
        let read_end = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let _write_end = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        let mut reader = InterruptibleReader::new_blocking(read_end).expect("wrap reader");
        let canceller = reader.canceller();

        let blocked = std::thread::spawn(move || {
            let mut byte = [0_u8; 1];
            reader.read(&mut byte)
        });
        std::thread::sleep(Duration::from_millis(50));
        canceller.close();

        assert_eq!(blocked.join().expect("reader thread").expect("read"), 0);
    }
}
