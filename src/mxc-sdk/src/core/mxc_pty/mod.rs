// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `mxc_pty` — shared pty bridge for the unix-side MXC backends.
//!
//! Both the Linux LXC backend (`crate::lxc_common::lxc_bindings::attach_run`) and
//! the macOS Seatbelt backend (`crate::seatbelt_common::seatbelt_runner`) need to
//! run a child process attached to a freshly-allocated pty so the inner
//! shell sees a real TTY (`isatty(0/1/2) -> true`) and the host can stream
//! output as it arrives. The two implementations were ~95% the same code;
//! this crate is the deduplicated home for that pty plumbing.

use std::process::Command;
use std::time::Duration;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::io::{Read, Write};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::fd::AsRawFd;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::sync::{Arc, Mutex};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::mxc_common::interruptible_reader::{InterruptibleReader, ReadCanceller};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::mxc_common::sandbox_process::StreamCloser;
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

/// Dimensions of a pseudo-terminal.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PtySize {
    /// Terminal rows.
    pub rows: u16,
    /// Terminal columns.
    pub cols: u16,
    /// Optional pixel width.
    pub pixel_width: u16,
    /// Optional pixel height.
    pub pixel_height: u16,
}

/// Caller-owned primary side of a Unix pseudo-terminal.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub struct LivePty {
    primary: std::fs::File,
    #[cfg(target_os = "macos")]
    secondary_path: std::path::PathBuf,
    access: Mutex<PtyAccess>,
    size: Mutex<PtySize>,
    eof: PtyEof,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct PtyAccess {
    writer: Option<std::fs::File>,
    reader_claimed: bool,
    native_bridge: Option<NativeBridge>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct NativeBridge {
    input_canceller: ReadCanceller,
    output_canceller: ReadCanceller,
    input_shutdown: BridgeShutdown,
    output_shutdown: BridgeShutdown,
    input_thread: std::thread::JoinHandle<()>,
    output_thread: std::thread::JoinHandle<()>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl NativeBridge {
    fn shutdown(self) {
        self.input_shutdown.cancel();
        self.output_shutdown.cancel();
        self.input_canceller.close();
        self.output_canceller.close();
        let _ = self.input_thread.join();
        let _ = self.output_thread.join();
    }

    fn finish(self) {
        const OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
        const OUTPUT_DRAIN_POLL: Duration = Duration::from_millis(10);

        self.input_shutdown.cancel();
        self.input_canceller.close();
        let _ = self.input_thread.join();

        let deadline = std::time::Instant::now() + OUTPUT_DRAIN_TIMEOUT;
        while !self.output_thread.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(OUTPUT_DRAIN_POLL);
        }
        if !self.output_thread.is_finished() {
            self.output_canceller.close();
            self.output_shutdown.cancel();
        }
        let _ = self.output_thread.join();
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Clone)]
struct BridgeShutdown {
    state: Arc<BridgeShutdownState>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct BridgeShutdownState {
    cancelled: AtomicBool,
    wake_read: std::os::fd::OwnedFd,
    wake_write: std::os::fd::OwnedFd,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl BridgeShutdown {
    fn new() -> std::io::Result<Self> {
        let (wake_read, wake_write) = create_pipe()?;
        set_nonblocking(wake_write.as_raw_fd())?;
        Ok(Self {
            state: Arc::new(BridgeShutdownState {
                cancelled: AtomicBool::new(false),
                wake_read,
                wake_write,
            }),
        })
    }

    fn cancel(&self) {
        if !self.state.cancelled.swap(true, Ordering::AcqRel) {
            let byte = [1_u8];
            // SAFETY: the write descriptor is owned by `state`, and `byte` is valid.
            let _ = unsafe {
                libc::write(
                    self.state.wake_write.as_raw_fd(),
                    byte.as_ptr().cast(),
                    byte.len(),
                )
            };
        }
    }

    fn is_cancelled(&self) -> bool {
        self.state.cancelled.load(Ordering::Acquire)
    }

    fn wait_writable(&self, fd: std::os::fd::RawFd) -> std::io::Result<bool> {
        if self.state.cancelled.load(Ordering::Acquire) {
            return Ok(false);
        }
        loop {
            let mut poll_fds = [
                libc::pollfd {
                    fd,
                    events: libc::POLLOUT,
                    revents: 0,
                },
                libc::pollfd {
                    fd: self.state.wake_read.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // SAFETY: `poll_fds` contains two live descriptors for this call.
            let result = unsafe { libc::poll(poll_fds.as_mut_ptr(), 2, -1) };
            if result >= 0 {
                return Ok(
                    !self.state.cancelled.load(Ordering::Acquire) && poll_fds[1].revents == 0
                );
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Clone, Copy)]
enum PtyEof {
    CurrentCanonical,
    Forwarded(PtyDiscipline),
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Clone, Copy)]
struct PtyDiscipline {
    canonical: bool,
    extended: bool,
    ignore_cr: bool,
    cr_to_nl: bool,
    nl_to_cr: bool,
    strip_high_bit: bool,
    eof: u8,
    eol: u8,
    eol2: u8,
    erase: u8,
    kill: u8,
    word_erase: u8,
    literal_next: u8,
}

/// Owned native pipes bridged to a pseudo-terminal.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug)]
pub struct NativePtyStdio {
    /// Writable terminal input pipe.
    pub stdin: std::os::fd::OwnedFd,
    /// Readable merged terminal output pipe.
    pub stdout: std::os::fd::OwnedFd,
}

/// Cancels a blocking pseudo-terminal output read.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Clone)]
pub struct PtyReadCanceller(ReadCanceller);

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl std::fmt::Debug for PtyReadCanceller {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("PtyReadCanceller").finish()
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl StreamCloser for PtyReadCanceller {
    fn close(&self) {
        self.0.close();
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl std::fmt::Debug for LivePty {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LivePty")
            .field("size", &self.size())
            .field(
                "reader_claimed",
                &self
                    .access
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .reader_claimed,
            )
            .finish_non_exhaustive()
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl LivePty {
    /// Attach `command` to a newly allocated pseudo-terminal.
    ///
    /// The caller must spawn the command after this returns and retain the
    /// returned primary while the child is running.
    pub fn attach(
        command: &mut Command,
        size: PtySize,
        unblock_signals: &'static [Signal],
    ) -> std::io::Result<Self> {
        Self::attach_with_eof(command, size, unblock_signals, false)
    }

    /// Attach a terminal-forwarding process to a newly allocated PTY.
    ///
    /// Input close forwards the PTY's initial `VEOF` byte through the
    /// forwarding process even after that process switches the outer terminal
    /// to raw mode.
    pub fn attach_forwarded(
        command: &mut Command,
        size: PtySize,
        unblock_signals: &'static [Signal],
    ) -> std::io::Result<Self> {
        Self::attach_with_eof(command, size, unblock_signals, true)
    }

    fn attach_with_eof(
        command: &mut Command,
        size: PtySize,
        unblock_signals: &'static [Signal],
        forward_eof: bool,
    ) -> std::io::Result<Self> {
        use std::os::fd::AsRawFd;
        use std::process::Stdio;

        use nix::pty::Winsize;

        let winsize = (size.rows != 0 && size.cols != 0).then_some(Winsize {
            ws_row: size.rows,
            ws_col: size.cols,
            ws_xpixel: size.pixel_width,
            ws_ypixel: size.pixel_height,
        });
        let (master, slave) = open_pty(winsize.as_ref())?;
        #[cfg(target_os = "macos")]
        let secondary_path = nix::unistd::ttyname(&slave).map_err(std::io::Error::from)?;
        let eof = if forward_eof {
            PtyEof::Forwarded(terminal_discipline(&slave)?)
        } else {
            PtyEof::CurrentCanonical
        };

        set_nonblocking(master.as_raw_fd())?;

        let secondary_in: Stdio = slave.try_clone()?.into();
        let secondary_out: Stdio = slave.try_clone()?.into();
        let secondary_err: Stdio = slave.into();
        command
            .stdin(secondary_in)
            .stdout(secondary_out)
            .stderr(secondary_err);

        // SAFETY: this runs after fork and uses only async-signal-safe calls.
        unsafe {
            use std::os::unix::process::CommandExt;
            command.pre_exec(move || {
                nix::unistd::setsid().map_err(std::io::Error::from)?;
                let _ = libc::ioctl(0, libc::TIOCSCTTY as _, 0);

                let mut mask = nix::sys::signal::SigSet::empty();
                mask.add(nix::sys::signal::Signal::SIGWINCH);
                for signal in unblock_signals {
                    mask.add(*signal);
                }
                mask.thread_unblock().map_err(std::io::Error::from)
            });
        }

        let primary: std::fs::File = master.into();
        let writer = primary.try_clone()?;
        Ok(Self {
            primary,
            #[cfg(target_os = "macos")]
            secondary_path,
            access: Mutex::new(PtyAccess {
                writer: Some(writer),
                reader_claimed: false,
                native_bridge: None,
            }),
            size: Mutex::new(size),
            eof,
        })
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn secondary_path(&self) -> &std::path::Path {
        &self.secondary_path
    }

    /// Clone the merged terminal output reader.
    pub fn try_clone_reader(&self) -> std::io::Result<Box<dyn Read + Send>> {
        self.try_clone_reader_with_canceller()
            .map(|(reader, _)| reader)
    }

    /// Clone the merged terminal output reader with an out-of-band canceller.
    pub fn try_clone_reader_with_canceller(
        &self,
    ) -> std::io::Result<(Box<dyn Read + Send>, PtyReadCanceller)> {
        let (reader, canceller) = self.new_reader()?;
        let mut access = self
            .access
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if access.native_bridge.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "PTY native streams have already been transferred",
            ));
        }
        access.reader_claimed = true;
        Ok((Box::new(reader), canceller))
    }

    /// Take the terminal input writer. This succeeds only once.
    pub fn take_writer(&self) -> std::io::Result<Box<dyn Write + Send>> {
        self.access
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .writer
            .take()
            .map(|writer| Box::new(PtyWriter::new(writer, self.eof)) as Box<dyn Write + Send>)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "PTY input writer has already been taken",
                )
            })
    }

    /// Drop the writer when it has not been transferred to the caller.
    pub fn close_writer(&self) {
        let writer = self
            .access
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .writer
            .take();
        if let Some(writer) = writer {
            drop(PtyWriter::new(writer, self.eof));
        }
    }

    /// Transfer native pipe endpoints bridged to terminal input and output.
    pub fn take_native_stdio(&self) -> std::io::Result<NativePtyStdio> {
        use std::fs::File;

        let input_primary = self.primary.try_clone()?;
        let (input_read_fd, input_write_fd) = create_pipe()?;
        let input_reader = InterruptibleReader::new(input_read_fd)?;
        let input_canceller = input_reader.canceller();
        let input_shutdown = BridgeShutdown::new()?;

        let output_primary = self.primary.try_clone()?;
        let (output_reader, output_canceller) = Self::reader_from_file(output_primary)?;
        let (output_read_fd, output_write_fd) = create_pipe()?;
        set_nonblocking(output_write_fd.as_raw_fd())?;
        let output_shutdown = BridgeShutdown::new()?;

        let mut access = self
            .access
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if access.native_bridge.is_some() || access.writer.is_none() || access.reader_claimed {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "PTY streams have already been accessed",
            ));
        }

        let (output_setup_sender, output_setup_receiver) = std::sync::mpsc::sync_channel(1);
        let output_thread = std::thread::Builder::new()
            .name("mxc-pty-output-bridge".to_string())
            .spawn({
                let output_shutdown = output_shutdown.clone();
                move || {
                    match block_sigpipe() {
                        Ok(()) => {
                            let _ = output_setup_sender.send(Ok(()));
                        }
                        Err(error) => {
                            let _ = output_setup_sender.send(Err(error));
                            return;
                        }
                    }
                    let mut reader = output_reader;
                    let mut writer = Some(File::from(output_write_fd));
                    let mut buffer = [0_u8; 8192];
                    loop {
                        let count = match reader.read(&mut buffer) {
                            Ok(0) | Err(_) => return,
                            Ok(count) => count,
                        };
                        let Some(sink) = writer.as_mut() else {
                            continue;
                        };
                        if write_all_until_shutdown(sink, &buffer[..count], &output_shutdown)
                            .is_err()
                        {
                            if output_shutdown.is_cancelled() {
                                return;
                            }
                            // The consumer closed its end. Keep draining the
                            // terminal anyway: on Darwin the child cannot exit
                            // while its output sits in the primary's queue.
                            writer = None;
                        }
                    }
                }
            })?;
        match output_setup_receiver.recv() {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                output_canceller.close();
                output_shutdown.cancel();
                let _ = output_thread.join();
                return Err(error);
            }
            Err(_) => {
                output_canceller.close();
                output_shutdown.cancel();
                let _ = output_thread.join();
                return Err(std::io::Error::other(
                    "PTY output bridge exited before configuring SIGPIPE",
                ));
            }
        }
        let input_thread = match std::thread::Builder::new()
            .name("mxc-pty-input-bridge".to_string())
            .spawn({
                let input_shutdown = input_shutdown.clone();
                let eof = self.eof;
                move || {
                    let mut reader = input_reader;
                    let mut writer = PtyWriter::new(input_primary, eof);
                    let mut buffer = [0_u8; 8192];
                    loop {
                        let count = match reader.read(&mut buffer) {
                            Ok(0) => {
                                if input_shutdown.is_cancelled() {
                                    writer.abandon_eof();
                                } else {
                                    let _ = writer.send_eof_until_shutdown(&input_shutdown);
                                }
                                return;
                            }
                            Err(_) => {
                                writer.abandon_eof();
                                return;
                            }
                            Ok(count) => count,
                        };
                        if writer
                            .write_all_until_shutdown(&buffer[..count], &input_shutdown)
                            .is_err()
                        {
                            writer.abandon_eof();
                            return;
                        }
                    }
                }
            }) {
            Ok(thread) => thread,
            Err(error) => {
                output_canceller.close();
                output_shutdown.cancel();
                let _ = output_thread.join();
                return Err(error);
            }
        };

        access.writer.take();
        access.reader_claimed = true;
        access.native_bridge = Some(NativeBridge {
            input_canceller,
            output_canceller: output_canceller.0.clone(),
            input_shutdown,
            output_shutdown,
            input_thread,
            output_thread,
        });
        Ok(NativePtyStdio {
            stdin: input_write_fd,
            stdout: output_read_fd,
        })
    }

    /// Stop and join any native PTY bridge threads.
    pub fn finish_native_bridge(&self) {
        let bridge = self
            .access
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .native_bridge
            .take();
        if let Some(bridge) = bridge {
            bridge.finish();
        }
    }

    /// Resize the pseudo-terminal and notify its foreground process group.
    pub fn resize(&self, size: PtySize) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;

        if size.rows == 0 || size.cols == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "PTY rows and columns must be non-zero",
            ));
        }
        let winsize = libc::winsize {
            ws_row: size.rows,
            ws_col: size.cols,
            ws_xpixel: size.pixel_width,
            ws_ypixel: size.pixel_height,
        };
        if unsafe { libc::ioctl(self.primary.as_raw_fd(), libc::TIOCSWINSZ, &winsize) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        *self
            .size
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = size;
        Ok(())
    }

    /// Return the last successfully applied terminal dimensions.
    pub fn size(&self) -> PtySize {
        *self
            .size
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Return whether the terminal secondary is in canonical input mode.
    pub fn is_canonical_mode(&self) -> std::io::Result<bool> {
        use nix::sys::termios::{self, LocalFlags};

        termios::tcgetattr(&self.primary)
            .map(|settings| settings.local_flags.contains(LocalFlags::ICANON))
            .map_err(std::io::Error::from)
    }

    /// Claim a reader for internal draining only when no caller has cloned one.
    pub fn take_unclaimed_reader(
        &self,
    ) -> std::io::Result<Option<(Box<dyn Read + Send>, PtyReadCanceller)>> {
        let mut access = self
            .access
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if access.reader_claimed {
            return Ok(None);
        }
        let (reader, canceller) = self.new_reader()?;
        access.reader_claimed = true;
        Ok(Some((Box::new(reader), canceller)))
    }

    fn new_reader(&self) -> std::io::Result<(PtyReader, PtyReadCanceller)> {
        Self::reader_from_file(self.primary.try_clone()?)
    }

    fn reader_from_file(reader: std::fs::File) -> std::io::Result<(PtyReader, PtyReadCanceller)> {
        let reader = InterruptibleReader::new(reader.into())?;
        let canceller = PtyReadCanceller(reader.canceller());
        Ok((PtyReader(reader), canceller))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for LivePty {
    fn drop(&mut self) {
        let bridge = self
            .access
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .native_bridge
            .take();
        if let Some(bridge) = bridge {
            bridge.shutdown();
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct PtyReader(InterruptibleReader);

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Read for PtyReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self.0.read(buffer) {
            Err(error) if error.raw_os_error() == Some(libc::EIO) => Ok(0),
            result => result,
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct PtyWriter {
    writer: Option<std::fs::File>,
    eof: PtyEof,
    eof_sent: bool,
    canonical_line: Vec<u8>,
    canonical_limit: usize,
    literal_next: bool,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl PtyWriter {
    fn new(writer: std::fs::File, eof: PtyEof) -> Self {
        let canonical_limit = canonical_line_limit(&writer);
        Self {
            writer: Some(writer),
            eof,
            eof_sent: false,
            canonical_line: Vec::new(),
            canonical_limit,
            literal_next: false,
        }
    }

    fn write_all_until_shutdown(
        &mut self,
        buffer: &[u8],
        shutdown: &BridgeShutdown,
    ) -> std::io::Result<()> {
        let writer = self
            .writer
            .as_mut()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
        write_all_until_shutdown(writer, buffer, shutdown)?;
        self.track_canonical_input(buffer);
        Ok(())
    }

    fn send_eof_until_shutdown(&mut self, shutdown: &BridgeShutdown) -> std::io::Result<()> {
        let Some((eof, count)) = self.take_eof() else {
            return Ok(());
        };
        let writer = self
            .writer
            .as_mut()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
        write_all_until_shutdown(writer, &[eof, eof, eof][..count], shutdown)?;
        writer.flush()
    }

    fn send_eof(&mut self) -> std::io::Result<()> {
        // Drop must not prevent the owning process timeout from running when a
        // terminal input queue has no active reader.
        const EOF_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

        let Some((eof, count)) = self.take_eof() else {
            return Ok(());
        };
        let writer = self
            .writer
            .as_mut()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
        write_all_until_deadline(writer, &[eof, eof, eof][..count], EOF_WRITE_TIMEOUT)?;
        writer.flush()
    }

    fn take_eof(&mut self) -> Option<(u8, usize)> {
        if self.eof_sent {
            return None;
        }
        self.eof_sent = true;
        let eof = match self.eof {
            PtyEof::CurrentCanonical => self.writer.as_ref().and_then(terminal_eof_byte),
            PtyEof::Forwarded(discipline) => {
                control_enabled(discipline.eof).then_some(discipline.eof)
            }
        }?;
        let count = if self.literal_next {
            3
        } else if self.canonical_line.is_empty() {
            1
        } else {
            2
        };
        Some((eof, count))
    }

    fn abandon_eof(&mut self) {
        self.eof_sent = true;
    }

    fn track_canonical_input(&mut self, buffer: &[u8]) {
        let discipline = match self.eof {
            PtyEof::CurrentCanonical => self
                .writer
                .as_ref()
                .and_then(|writer| terminal_discipline(writer).ok()),
            PtyEof::Forwarded(discipline) => Some(discipline),
        };
        let Some(discipline) = discipline.filter(|discipline| discipline.canonical) else {
            return;
        };

        for raw_byte in buffer {
            let mut byte = *raw_byte;
            if discipline.strip_high_bit {
                byte &= 0x7f;
            }
            if byte == b'\r' {
                if discipline.ignore_cr {
                    continue;
                }
                if discipline.cr_to_nl {
                    byte = b'\n';
                }
            } else if byte == b'\n' && discipline.nl_to_cr {
                byte = b'\r';
            }

            if self.literal_next {
                self.literal_next = false;
                if self.canonical_line.len() < self.canonical_limit {
                    self.canonical_line.push(byte);
                }
                continue;
            }
            if discipline.extended && control_matches(byte, discipline.literal_next) {
                self.literal_next = true;
                continue;
            }
            if control_matches(byte, discipline.kill) {
                self.canonical_line.clear();
                continue;
            }
            if control_matches(byte, discipline.erase) {
                self.canonical_line.pop();
                continue;
            }
            if discipline.extended && control_matches(byte, discipline.word_erase) {
                while self
                    .canonical_line
                    .last()
                    .is_some_and(|byte| byte.is_ascii_whitespace())
                {
                    self.canonical_line.pop();
                }
                while self
                    .canonical_line
                    .last()
                    .is_some_and(|byte| !byte.is_ascii_whitespace())
                {
                    self.canonical_line.pop();
                }
                continue;
            }
            if byte == b'\n'
                || control_matches(byte, discipline.eol)
                || control_matches(byte, discipline.eol2)
            {
                self.canonical_line.clear();
                continue;
            }
            if !control_matches(byte, discipline.eof)
                && self.canonical_line.len() < self.canonical_limit
            {
                self.canonical_line.push(byte);
            }
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn canonical_line_limit(writer: &std::fs::File) -> usize {
    #[cfg(target_os = "linux")]
    {
        let _ = writer;
        4095
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: `writer` owns a live terminal descriptor and `fpathconf` only
        // queries its canonical input limit.
        let limit = unsafe { libc::fpathconf(writer.as_raw_fd(), libc::_PC_MAX_CANON) };
        usize::try_from(limit)
            .ok()
            .filter(|limit| *limit > 0)
            .unwrap_or(4096)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Write for PtyWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let writer = self
            .writer
            .as_mut()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
        loop {
            match writer.write(buffer) {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    let mut poll_fd = libc::pollfd {
                        fd: writer.as_raw_fd(),
                        events: libc::POLLOUT,
                        revents: 0,
                    };
                    // SAFETY: `poll_fd` references the live writer descriptor for this call.
                    let result = unsafe { libc::poll(&mut poll_fd, 1, -1) };
                    if result < 0 {
                        let error = std::io::Error::last_os_error();
                        if error.kind() != std::io::ErrorKind::Interrupted {
                            return Err(error);
                        }
                    }
                }
                Ok(count) => {
                    self.track_canonical_input(&buffer[..count]);
                    return Ok(count);
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer
            .as_mut()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?
            .flush()
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for PtyWriter {
    fn drop(&mut self) {
        let _ = self.send_eof();
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn write_all_until_shutdown(
    writer: &mut std::fs::File,
    mut buffer: &[u8],
    shutdown: &BridgeShutdown,
) -> std::io::Result<()> {
    while !buffer.is_empty() {
        if shutdown.is_cancelled() {
            return Err(std::io::ErrorKind::Interrupted.into());
        }
        match writer.write(buffer) {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(count) => buffer = &buffer[count..],
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if !shutdown.wait_writable(writer.as_raw_fd())? {
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn write_all_until_deadline(
    writer: &mut std::fs::File,
    mut buffer: &[u8],
    timeout: std::time::Duration,
) -> std::io::Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    while !buffer.is_empty() {
        match writer.write(buffer) {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(count) => buffer = &buffer[count..],
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                let now = std::time::Instant::now();
                if now >= deadline {
                    return Err(std::io::ErrorKind::TimedOut.into());
                }
                let timeout_ms = (deadline - now)
                    .as_millis()
                    .clamp(1, libc::c_int::MAX as u128)
                    as libc::c_int;
                let mut poll_fd = libc::pollfd {
                    fd: writer.as_raw_fd(),
                    events: libc::POLLOUT,
                    revents: 0,
                };
                // SAFETY: `poll_fd` references the live writer descriptor for this call.
                let result = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };
                if result == 0 {
                    return Err(std::io::ErrorKind::TimedOut.into());
                }
                if result < 0 {
                    let error = std::io::Error::last_os_error();
                    if error.kind() != std::io::ErrorKind::Interrupted {
                        return Err(error);
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn terminal_eof_byte(file: &std::fs::File) -> Option<u8> {
    terminal_discipline(file)
        .ok()
        .filter(|discipline| discipline.canonical)
        .map(|discipline| discipline.eof)
        .filter(|eof| control_enabled(*eof))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn terminal_discipline(fd: &impl std::os::fd::AsFd) -> std::io::Result<PtyDiscipline> {
    use nix::sys::termios::{self, InputFlags, LocalFlags, SpecialCharacterIndices};

    let settings = termios::tcgetattr(fd).map_err(std::io::Error::from)?;
    let control = |index| settings.control_chars[index as usize];
    Ok(PtyDiscipline {
        canonical: settings.local_flags.contains(LocalFlags::ICANON),
        extended: settings.local_flags.contains(LocalFlags::IEXTEN),
        ignore_cr: settings.input_flags.contains(InputFlags::IGNCR),
        cr_to_nl: settings.input_flags.contains(InputFlags::ICRNL),
        nl_to_cr: settings.input_flags.contains(InputFlags::INLCR),
        strip_high_bit: settings.input_flags.contains(InputFlags::ISTRIP),
        eof: control(SpecialCharacterIndices::VEOF),
        eol: control(SpecialCharacterIndices::VEOL),
        eol2: control(SpecialCharacterIndices::VEOL2),
        erase: control(SpecialCharacterIndices::VERASE),
        kill: control(SpecialCharacterIndices::VKILL),
        word_erase: control(SpecialCharacterIndices::VWERASE),
        literal_next: control(SpecialCharacterIndices::VLNEXT),
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn control_matches(byte: u8, control: u8) -> bool {
    control_enabled(control) && byte == control
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn control_enabled(control: u8) -> bool {
    control != libc::_POSIX_VDISABLE
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn open_pty(
    winsize: Option<&nix::pty::Winsize>,
) -> std::io::Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
    use std::os::fd::{FromRawFd, IntoRawFd};
    use std::path::Path;

    use nix::fcntl::{open, OFlag};
    use nix::pty::{grantpt, posix_openpt, unlockpt};
    use nix::sys::stat::Mode;

    let flags = OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_CLOEXEC;
    let master = posix_openpt(flags).map_err(std::io::Error::from)?;
    grantpt(&master).map_err(std::io::Error::from)?;
    unlockpt(&master).map_err(std::io::Error::from)?;

    #[cfg(target_os = "linux")]
    let slave_name = nix::pty::ptsname_r(&master).map_err(std::io::Error::from)?;
    #[cfg(target_os = "macos")]
    let slave_name = {
        static PTSNAME_LOCK: Mutex<()> = Mutex::new(());
        let _guard = PTSNAME_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: `ptsname`'s process-global storage is serialized by
        // `PTSNAME_LOCK`, and `master` remains open for the call.
        unsafe { nix::pty::ptsname(&master) }.map_err(std::io::Error::from)?
    };

    let slave_fd =
        open(Path::new(&slave_name), flags, Mode::empty()).map_err(std::io::Error::from)?;
    // SAFETY: `open` returned a new owned descriptor.
    let slave = unsafe { std::os::fd::OwnedFd::from_raw_fd(slave_fd) };
    if let Some(winsize) = winsize {
        // SAFETY: `slave` is a live PTY secondary and `winsize` points to a
        // valid `winsize` value for the duration of the ioctl.
        if unsafe { libc::ioctl(slave.as_raw_fd(), libc::TIOCSWINSZ as _, winsize) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    // SAFETY: converting transfers the descriptor out of `PtyMaster` exactly once.
    let master = unsafe { std::os::fd::OwnedFd::from_raw_fd(master.into_raw_fd()) };
    Ok((master, slave))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn create_pipe() -> std::io::Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
    #[cfg(target_os = "linux")]
    {
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).map_err(std::io::Error::from)
    }
    #[cfg(target_os = "macos")]
    {
        // macOS has no `pipe2`, and `O_CLOEXEC` applies only to `open`, so
        // close-on-exec must be set in a second call. A `fork`+`exec` racing
        // on another thread can inherit the ends in between and hold them
        // open, delaying EOF.
        //
        // Accepted rather than fixed: Rust's own `Stdio::piped()` has the same
        // window on macOS, so the descriptors carrying a workload's streams
        // already have it, and spawns owned by the embedding application are
        // outside this crate's control either way.
        let (read, write) = nix::unistd::pipe().map_err(std::io::Error::from)?;
        set_cloexec(read.as_raw_fd())?;
        set_cloexec(write.as_raw_fd())?;
        Ok((read, write))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn block_sigpipe() -> std::io::Result<()> {
    let mut signals = nix::sys::signal::SigSet::empty();
    signals.add(nix::sys::signal::Signal::SIGPIPE);
    signals.thread_block().map_err(std::io::Error::from)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn set_nonblocking(fd: std::os::fd::RawFd) -> std::io::Result<()> {
    // SAFETY: `fd` is a valid open descriptor; these commands only update its flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` remains open and `flags | O_NONBLOCK` is valid for F_SETFL.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn set_cloexec(fd: std::os::fd::RawFd) -> std::io::Result<()> {
    // SAFETY: `fd` is a valid open descriptor; these commands only update its flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` remains open and `flags | FD_CLOEXEC` is valid for F_SETFD.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
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
    use std::os::unix::io::AsRawFd;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Instant;

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
    let size = outer_winsize.map_or_else(PtySize::default, |winsize| PtySize {
        rows: winsize.ws_row,
        cols: winsize.ws_col,
        pixel_width: winsize.ws_xpixel,
        pixel_height: winsize.ws_ypixel,
    });
    let terminal = LivePty::attach(&mut command, size, options.unblock_signals)
        .map_err(|error| format!("failed to allocate PTY: {error}"))?;

    let mut child = command
        .spawn()
        .map_err(|e| format!("failed to spawn child: {}", e))?;

    drop(command);

    let mut primary_writer = terminal
        .take_writer()
        .map_err(|error| format!("take PTY writer: {error}"))?;
    let mut primary_reader = terminal
        .take_unclaimed_reader()
        .map_err(|error| format!("clone PTY reader: {error}"))?
        .map(|(reader, _)| reader)
        .ok_or_else(|| "PTY reader was already claimed".to_string())?;

    // Resize forwarder: when the host's terminal resizes, the kernel
    // delivers SIGWINCH to us (because our fd 0 is the outer pty
    // secondary). Read the new size off fd 0 and push it to the inner pty
    // primary via TIOCSWINSZ — that delivers SIGWINCH to the inner
    // child, so TUIs reflow correctly. Hand the forwarder its own
    // dup of the primary so the resize fd isn't tied to the lifetime
    // of `primary_writer` (which the input-forwarder thread can drop
    // mid-session); the forwarder leaks its dup for the rest of the
    // process, the same lifetime as the signal handler that targets it.
    let winch_primary = terminal
        .primary
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
    Err("crate::mxc_pty::run_with_pty is only supported on Linux and macOS".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Serialize tests that spawn children and inspect process-wide descriptor
    // state so concurrent cases cannot make those assertions nondeterministic.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    static RUN_WITH_PTY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Reads a PTY-backed stream on a worker thread so the child is never
    /// blocked by a full terminal output queue.
    ///
    /// Darwin blocks the final close of the secondary until the primary's
    /// output queue drains, and `SIGKILL` does not release it. So a drain must
    /// already be running before anything waits for the child.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    struct PtyDrain {
        collected: Arc<Mutex<Vec<u8>>>,
        worker: Option<std::thread::JoinHandle<()>>,
        finished: std::sync::mpsc::Receiver<()>,
        canceller: Option<PtyReadCanceller>,
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    impl PtyDrain {
        const TIMEOUT: Duration = Duration::from_secs(20);
        /// How long [`Drop`] waits for an uncancellable worker before leaving
        /// it running. Only reached while unwinding.
        const DROP_GRACE: Duration = Duration::from_secs(2);

        /// Only for native-pipe readers, which have no canceller. Drains of a
        /// PTY reader must use [`Self::start_cancellable`] so [`Drop`] can
        /// unblock the worker.
        fn start(source: Box<dyn Read + Send>) -> Self {
            Self::start_inner(source, None)
        }

        /// The canceller lets [`Drop`] unblock the worker, so a failing test
        /// cannot leave it parked holding the primary.
        fn start_cancellable(source: (Box<dyn Read + Send>, PtyReadCanceller)) -> Self {
            Self::start_inner(source.0, Some(source.1))
        }

        fn start_inner(
            mut source: Box<dyn Read + Send>,
            canceller: Option<PtyReadCanceller>,
        ) -> Self {
            let collected = Arc::new(Mutex::new(Vec::new()));
            let sink = Arc::clone(&collected);
            let (done, finished) = std::sync::mpsc::sync_channel(1);
            let worker = std::thread::spawn(move || {
                let mut buffer = [0u8; 8192];
                while let Ok(count) = source.read(&mut buffer) {
                    if count == 0 {
                        break;
                    }
                    sink.lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .extend_from_slice(&buffer[..count]);
                }
                let _ = done.send(());
            });
            Self {
                collected,
                worker: Some(worker),
                finished,
                canceller,
            }
        }

        /// Everything drained so far, as lossy UTF-8.
        fn snapshot(&self) -> String {
            let bytes = self.collected.lock().unwrap_or_else(|e| e.into_inner());
            String::from_utf8_lossy(&bytes).into_owned()
        }

        /// Blocks until `marker` appears in the drained output.
        fn wait_for(&self, marker: &str) -> String {
            let deadline = std::time::Instant::now() + Self::TIMEOUT;
            loop {
                let seen = self.snapshot();
                if seen.contains(marker) {
                    return seen;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "terminal output never contained {marker:?}; got: {seen:?}"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        /// Cancels the read so a parked worker reaches end of input.
        fn cancel(&self) {
            if let Some(canceller) = &self.canceller {
                canceller.close();
            }
        }

        /// Waits for end of input and returns the full output.
        fn finish(mut self) -> String {
            self.finished
                .recv_timeout(Self::TIMEOUT)
                .unwrap_or_else(|_| panic!("terminal drain did not reach end of input"));
            if let Some(worker) = self.worker.take() {
                worker.join().expect("terminal drain thread");
            }
            self.snapshot()
        }
    }

    /// Releases the worker rather than detaching it. A detached PTY worker
    /// still owns the reader, so dropping `LivePty` would not close the final
    /// primary and a failing test would hang instead of failing.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    impl Drop for PtyDrain {
        fn drop(&mut self) {
            let Some(worker) = self.worker.take() else {
                return;
            };
            if let Some(canceller) = &self.canceller {
                // Cancelling unblocks the read, so the join cannot outlast it.
                canceller.close();
                let _ = worker.join();
                return;
            }
            // A native-pipe drain has nothing to cancel: only the bridge closes
            // the write end, and while unwinding it outlives this drop. Joining
            // would hang, so wait briefly and otherwise leave the worker to
            // finish on its own. It holds a pipe read end, not the primary, so
            // dropping `LivePty` still closes the terminal.
            if self.finished.recv_timeout(Self::DROP_GRACE).is_ok() {
                let _ = worker.join();
            }
        }
    }

    /// Waits for `child` with a deadline instead of hanging the whole suite.
    ///
    /// Deliberately does not fall back to `kill`: a child stuck in the Darwin
    /// terminal drain ignores `SIGKILL`. Unwinding drops `LivePty`, which
    /// closes the primary and releases it.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn wait_for_exit(child: &mut std::process::Child) -> std::process::ExitStatus {
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = child.try_wait().expect("poll child") {
                return status;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "child did not exit within the test deadline"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

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
    fn live_pty_supports_input_output_and_resize() {
        let _guard = RUN_WITH_PTY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("stty size; read value; printf 'reply:%s\\n' \"$value\"");
        let terminal = LivePty::attach(
            &mut command,
            PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            },
            &[],
        )
        .expect("attach PTY");
        terminal
            .resize(PtySize {
                rows: 40,
                cols: 120,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("resize PTY");

        let mut child = command.spawn().expect("spawn child");
        drop(command);
        let drain = PtyDrain::start_cancellable(
            terminal
                .try_clone_reader_with_canceller()
                .expect("clone reader"),
        );
        let mut writer = terminal.take_writer().expect("take writer");
        writer.write_all(b"hello\r").expect("write input");
        drop(writer);

        assert!(wait_for_exit(&mut child).success());
        drop(terminal);
        let output = drain.finish();
        assert!(output.contains("40 120"), "got: {output:?}");
        assert!(output.contains("reply:hello"), "got: {output:?}");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn dropping_writer_sends_canonical_terminal_eof() {
        let _guard = RUN_WITH_PTY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("cat >/dev/null; printf 'terminal-eof-observed\\n'");
        let terminal = LivePty::attach(&mut command, PtySize::default(), &[]).expect("attach PTY");
        let mut child = command.spawn().expect("spawn child");
        drop(command);
        let drain = PtyDrain::start_cancellable(
            terminal
                .try_clone_reader_with_canceller()
                .expect("clone reader"),
        );

        let mut writer = terminal.take_writer().expect("take writer");
        writer
            .write_all(b"partial-line")
            .expect("write partial line");
        drop(writer);

        assert!(wait_for_exit(&mut child).success());
        drop(terminal);
        let output = drain.finish();
        assert!(output.contains("terminal-eof-observed"), "got: {output:?}");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn close_writer_sends_canonical_terminal_eof() {
        let _guard = RUN_WITH_PTY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("cat >/dev/null; printf 'closed-writer-eof\\n'");
        let terminal = LivePty::attach(&mut command, PtySize::default(), &[]).expect("attach PTY");
        let mut child = command.spawn().expect("spawn child");
        drop(command);
        let drain = PtyDrain::start_cancellable(
            terminal
                .try_clone_reader_with_canceller()
                .expect("clone reader"),
        );

        terminal.close_writer();
        // Closing again is a no-op, and the writer can no longer be taken.
        terminal.close_writer();
        assert_eq!(
            terminal
                .take_writer()
                .err()
                .expect("writer was already closed")
                .kind(),
            std::io::ErrorKind::BrokenPipe
        );

        assert!(wait_for_exit(&mut child).success());
        drop(terminal);
        let output = drain.finish();
        assert!(output.contains("closed-writer-eof"), "got: {output:?}");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn close_writer_after_take_writer_leaves_the_taken_writer_usable() {
        let _guard = RUN_WITH_PTY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("read value; printf 'reply:%s\\n' \"$value\"");
        let terminal = LivePty::attach(&mut command, PtySize::default(), &[]).expect("attach PTY");
        let mut child = command.spawn().expect("spawn child");
        drop(command);
        let drain = PtyDrain::start_cancellable(
            terminal
                .try_clone_reader_with_canceller()
                .expect("clone reader"),
        );

        let mut writer = terminal.take_writer().expect("take writer");
        terminal.close_writer();
        writer.write_all(b"still-writable\r").expect("write input");
        drop(writer);

        assert!(wait_for_exit(&mut child).success());
        drop(terminal);
        let output = drain.finish();
        assert!(output.contains("reply:still-writable"), "got: {output:?}");
    }

    /// The drain-before-wait pattern every backend uses: nothing claimed a
    /// reader, so the runner claims one and discards output while it waits.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn take_unclaimed_reader_drains_output_so_waiting_cannot_deadlock() {
        let _guard = RUN_WITH_PTY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("head -c 200000 /dev/zero; printf 'drained-to-exit\\n'");
        let terminal = LivePty::attach(&mut command, PtySize::default(), &[]).expect("attach PTY");
        let mut child = command.spawn().expect("spawn child");
        drop(command);

        terminal.close_writer();
        let drain = PtyDrain::start_cancellable(
            terminal
                .take_unclaimed_reader()
                .expect("take unclaimed reader")
                .expect("reader was unclaimed"),
        );
        assert!(
            terminal
                .take_unclaimed_reader()
                .expect("second take")
                .is_none(),
            "the reader is claimed after the first take"
        );

        assert!(wait_for_exit(&mut child).success());
        let seen = drain.wait_for("drained-to-exit");
        assert!(seen.contains("drained-to-exit"), "got: {seen:?}");
        drain.cancel();
        drop(terminal);
        let _ = drain.finish();
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn take_unclaimed_reader_yields_nothing_once_a_reader_is_claimed() {
        let _guard = RUN_WITH_PTY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg("printf claimed");
        let terminal = LivePty::attach(&mut command, PtySize::default(), &[]).expect("attach PTY");
        let mut child = command.spawn().expect("spawn child");
        drop(command);
        let drain = PtyDrain::start_cancellable(
            terminal
                .try_clone_reader_with_canceller()
                .expect("clone reader"),
        );

        assert!(
            terminal
                .take_unclaimed_reader()
                .expect("take unclaimed reader")
                .is_none(),
            "a cloned reader belongs to the caller"
        );

        assert!(wait_for_exit(&mut child).success());
        drop(terminal);
        let output = drain.finish();
        assert!(output.contains("claimed"), "got: {output:?}");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn take_unclaimed_reader_yields_nothing_after_native_stdio() {
        let _guard = RUN_WITH_PTY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg("printf bridged");
        let terminal = LivePty::attach(&mut command, PtySize::default(), &[]).expect("attach PTY");
        let mut child = command.spawn().expect("spawn child");
        drop(command);
        let stdio = terminal.take_native_stdio().expect("take native stdio");

        assert!(
            terminal
                .take_unclaimed_reader()
                .expect("take unclaimed reader")
                .is_none(),
            "the native bridge owns terminal output"
        );

        assert!(wait_for_exit(&mut child).success());
        terminal.finish_native_bridge();
        drop(stdio);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn dropping_untouched_writer_does_not_wait_for_an_input_reader() {
        let _guard = RUN_WITH_PTY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg("sleep 30");
        let terminal = LivePty::attach(&mut command, PtySize::default(), &[]).expect("attach PTY");
        let mut child = command.spawn().expect("spawn child");
        drop(command);
        let drain = PtyDrain::start_cancellable(
            terminal
                .try_clone_reader_with_canceller()
                .expect("clone reader"),
        );

        let started = std::time::Instant::now();
        drop(terminal.take_writer().expect("take writer"));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "closing untouched canonical input blocked without a reader"
        );

        let _ = child.kill();
        let _ = child.wait();
        drop(terminal);
        let _ = drain.finish();
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn dropping_writer_does_not_wait_for_a_full_input_queue() {
        let _guard = RUN_WITH_PTY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg("sleep 30");
        let terminal = LivePty::attach(&mut command, PtySize::default(), &[]).expect("attach PTY");
        let mut child = command.spawn().expect("spawn child");
        drop(command);
        let drain = PtyDrain::start_cancellable(
            terminal
                .try_clone_reader_with_canceller()
                .expect("clone reader"),
        );

        let mut fill = terminal
            .access
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .writer
            .as_ref()
            .expect("PTY writer")
            .try_clone()
            .expect("clone writer");
        let buffer = [b'x'; 4096];
        let mut queue_full = false;
        // A PTY input queue is far smaller than 16 MiB. Cap the attempts so a
        // platform that unexpectedly discards input fails instead of looping.
        for _ in 0..4096 {
            match fill.write(&buffer) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    queue_full = true;
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => panic!("fill PTY input queue: {error}"),
            }
        }
        // Linux reports `EWOULDBLOCK` once the terminal input queue is full;
        // Darwin's `ttyinput` silently discards the excess instead. Either way
        // the queue is saturated, which is what the drop path must survive.
        #[cfg(target_os = "linux")]
        assert!(queue_full, "PTY input queue did not reach backpressure");
        #[cfg(target_os = "macos")]
        let _ = queue_full;
        drop(fill);

        let started = std::time::Instant::now();
        drop(terminal.take_writer().expect("take writer"));
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "closing canonical input blocked on a full input queue"
        );

        let _ = child.kill();
        let _ = child.wait();
        drop(terminal);
        let _ = drain.finish();
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn assert_canonical_eof_after_input(setup: &str, input: &[u8], native: bool) {
        let _guard = RUN_WITH_PTY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg(format!(
            "{setup}; printf ready; cat >/dev/null; printf terminal-eof-observed"
        ));
        let terminal = LivePty::attach(&mut command, PtySize::default(), &[]).expect("attach PTY");
        let mut child = command.spawn().expect("spawn child");
        drop(command);

        let (mut writer, drain): (Box<dyn Write + Send>, PtyDrain) = if native {
            let stdio = terminal.take_native_stdio().expect("take native stdio");
            (
                Box::new(std::fs::File::from(stdio.stdin)),
                PtyDrain::start(Box::new(std::fs::File::from(stdio.stdout))),
            )
        } else {
            (
                Box::new(terminal.take_writer().expect("take writer")),
                PtyDrain::start_cancellable(
                    terminal
                        .try_clone_reader_with_canceller()
                        .expect("clone reader"),
                ),
            )
        };

        drain.wait_for("ready");
        writer.write_all(input).expect("write terminal input");
        drop(writer);

        assert!(wait_for_exit(&mut child).success());
        terminal.finish_native_bridge();
        drop(terminal);

        let text = drain.finish();
        assert!(text.contains("terminal-eof-observed"), "got: {text:?}");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn boxed_writer_tracks_cr_without_icrnl_as_partial_input() {
        assert_canonical_eof_after_input("stty -echo -icrnl", b"hello\r", false);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_writer_tracks_cr_without_icrnl_as_partial_input() {
        assert_canonical_eof_after_input("stty -echo -icrnl", b"hello\r", true);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn boxed_writer_tracks_kill_character_as_empty_input() {
        assert_canonical_eof_after_input("stty -echo", b"abc\x15", false);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_writer_tracks_kill_character_as_empty_input() {
        assert_canonical_eof_after_input("stty -echo", b"abc\x15", true);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn boxed_writer_closes_after_pending_literal_next() {
        assert_canonical_eof_after_input("stty -echo", b"abc\x16", false);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_writer_closes_after_pending_literal_next() {
        assert_canonical_eof_after_input("stty -echo", b"abc\x16", true);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn boxed_writer_tracks_input_beyond_posix_max_canon() {
        let mut input = vec![b'x'; 300];
        input.extend(std::iter::repeat_n(127, 255));
        assert_canonical_eof_after_input("stty -echo erase '^?'", &input, false);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_writer_tracks_input_beyond_posix_max_canon() {
        let mut input = vec![b'x'; 300];
        input.extend(std::iter::repeat_n(127, 255));
        assert_canonical_eof_after_input("stty -echo erase '^?'", &input, true);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn assert_disabled_eof_does_not_inject_input(native: bool) {
        let _guard = RUN_WITH_PTY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg(
            "stty -echo eof undef; printf ready; dd bs=1 count=1 2>/dev/null; printf injected",
        );
        let terminal = LivePty::attach(&mut command, PtySize::default(), &[]).expect("attach PTY");
        let mut child = command.spawn().expect("spawn child");
        drop(command);

        let (writer, drain): (Option<Box<dyn Write + Send>>, PtyDrain) = if native {
            let stdio = terminal.take_native_stdio().expect("take native stdio");
            (
                Some(Box::new(std::fs::File::from(stdio.stdin))),
                PtyDrain::start(Box::new(std::fs::File::from(stdio.stdout))),
            )
        } else {
            (
                None,
                PtyDrain::start_cancellable(
                    terminal
                        .try_clone_reader_with_canceller()
                        .expect("clone reader"),
                ),
            )
        };

        drain.wait_for("ready");
        match writer {
            Some(writer) => drop(writer),
            None => drop(terminal.take_writer().expect("take writer")),
        }

        std::thread::sleep(Duration::from_millis(200));
        assert!(child.try_wait().expect("poll child").is_none());
        let _ = child.kill();
        let _ = child.wait();
        terminal.finish_native_bridge();
        drop(terminal);
        let text = drain.finish();
        assert!(!text.contains("injected"), "got: {text:?}");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn boxed_writer_skips_disabled_eof() {
        assert_disabled_eof_does_not_inject_input(false);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_writer_skips_disabled_eof() {
        assert_disabled_eof_does_not_inject_input(true);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn canonical_tracking_is_bounded() {
        let (master, _slave) = open_pty(None).expect("open PTY");
        let file: std::fs::File = master.into();
        let discipline = PtyDiscipline {
            canonical: true,
            extended: true,
            strip_high_bit: false,
            ignore_cr: false,
            cr_to_nl: true,
            nl_to_cr: false,
            eof: 4,
            eol: 0,
            eol2: 0,
            erase: 127,
            kill: 21,
            word_erase: 23,
            literal_next: 22,
        };
        let mut writer = PtyWriter::new(file, PtyEof::Forwarded(discipline));
        writer.track_canonical_input(&vec![b'x'; writer.canonical_limit + 1024]);
        assert_eq!(writer.canonical_line.len(), writer.canonical_limit);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn writer_blocks_until_nonblocking_primary_accepts_large_input() {
        let _guard = RUN_WITH_PTY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg("cat >/dev/null");
        let terminal = LivePty::attach(&mut command, PtySize::default(), &[]).expect("attach PTY");
        let mut child = command.spawn().expect("spawn child");
        drop(command);

        let drain = PtyDrain::start_cancellable(
            terminal
                .try_clone_reader_with_canceller()
                .expect("clone reader"),
        );
        let mut writer = terminal.take_writer().expect("take writer");
        let mut input = b"x\n".repeat(128 * 1024);
        input.extend_from_slice(b"partial-line");
        writer.write_all(&input).expect("write large partial input");
        drop(writer);

        assert!(wait_for_exit(&mut child).success());
        drop(terminal);
        let _ = drain.finish();
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn reader_cancellation_unblocks_descendant_held_terminal() {
        let _guard = RUN_WITH_PTY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("(sleep 30) & printf 'foreground-exited\\n'");
        let terminal = LivePty::attach(&mut command, PtySize::default(), &[]).expect("attach PTY");
        let mut child = command.spawn().expect("spawn child");
        drop(command);

        // The drain must already be running: on Darwin the foreground shell
        // cannot exit while its output sits in the terminal queue.
        let drain = PtyDrain::start_cancellable(
            terminal
                .try_clone_reader_with_canceller()
                .expect("clone reader"),
        );
        assert!(wait_for_exit(&mut child).success());
        drain.wait_for("foreground-exited");

        // The backgrounded `sleep` still holds the secondary open, so the read
        // parks until it is cancelled.
        drain.cancel();
        let output = drain.finish();
        assert!(output.contains("foreground-exited"), "got: {output:?}");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_stdio_bridges_terminal_io_once() {
        use std::fs::File;

        let _guard = RUN_WITH_PTY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("read value; printf 'native-reply:%s\\n' \"$value\"");
        let terminal = LivePty::attach(&mut command, PtySize::default(), &[]).expect("attach PTY");
        let mut child = command.spawn().expect("spawn child");
        drop(command);

        let stdio = terminal.take_native_stdio().expect("take native stdio");
        assert!(terminal.take_writer().is_err());
        assert!(terminal.try_clone_reader().is_err());
        let mut input = File::from(stdio.stdin);
        let mut output = File::from(stdio.stdout);
        input.write_all(b"hello").expect("write partial input");
        drop(input);

        assert!(wait_for_exit(&mut child).success());
        terminal.finish_native_bridge();
        let mut text = String::new();
        output.read_to_string(&mut text).expect("read output");
        assert!(text.contains("native-reply:hello"), "got: {text:?}");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_bridge_delivers_eof_after_large_partial_input() {
        let _guard = RUN_WITH_PTY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("stty -echo; sleep 0.1; cat >/dev/null; printf 'native-eof-observed\\n'");
        let terminal = LivePty::attach(&mut command, PtySize::default(), &[]).expect("attach PTY");
        let mut child = command.spawn().expect("spawn child");
        drop(command);

        let stdio = terminal.take_native_stdio().expect("take native stdio");
        let input_thread = std::thread::spawn(move || {
            let mut input = std::fs::File::from(stdio.stdin);
            let mut bytes = b"x\n".repeat(128 * 1024);
            bytes.extend_from_slice(b"partial-line");
            input.write_all(&bytes).expect("write large partial input");
            drop(input);
            stdio.stdout
        });

        assert!(wait_for_exit(&mut child).success());
        terminal.finish_native_bridge();
        let stdout = input_thread.join().expect("input thread");
        let mut output = std::fs::File::from(stdout);
        let mut text = String::new();
        output.read_to_string(&mut text).expect("read output");
        assert!(text.contains("native-eof-observed"), "got: {text:?}");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_bridge_finishes_when_descendant_holds_terminal() {
        let _guard = RUN_WITH_PTY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg("(sleep 30) & printf 'done\\n'");
        let terminal = LivePty::attach(&mut command, PtySize::default(), &[]).expect("attach PTY");
        let mut child = command.spawn().expect("spawn child");
        let session = child.id() as libc::pid_t;
        drop(command);
        let stdio = terminal.take_native_stdio().expect("take native stdio");
        drop(stdio.stdin);

        assert!(wait_for_exit(&mut child).success());
        let start = std::time::Instant::now();
        terminal.finish_native_bridge();
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "native bridge did not cancel promptly"
        );
        // SAFETY: the child created its own session with its PID as the process-group ID.
        unsafe {
            libc::kill(-session, libc::SIGKILL);
        }

        let mut output = std::fs::File::from(stdio.stdout);
        let mut text = String::new();
        output.read_to_string(&mut text).expect("read output");
        assert!(text.contains("done"), "got: {text:?}");
    }

    /// Reads whatever is already buffered on `fd` without blocking.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn drain_available(fd: std::os::fd::RawFd) -> String {
        // SAFETY: `fd` is owned by the caller and stays open across the call.
        let previous = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if previous < 0 {
            return String::new();
        }
        // SAFETY: as above.
        unsafe { libc::fcntl(fd, libc::F_SETFL, previous | libc::O_NONBLOCK) };
        let mut collected = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            // SAFETY: `buffer` is a valid writable slice for the length passed.
            let count = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
            if count <= 0 {
                break;
            }
            collected.extend_from_slice(&buffer[..count as usize]);
        }
        // SAFETY: restores the descriptor flags sampled above.
        unsafe { libc::fcntl(fd, libc::F_SETFL, previous) };
        String::from_utf8_lossy(&collected).into_owned()
    }

    /// Collects output until `marker` arrives.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn wait_for_marker(fd: std::os::fd::RawFd, marker: &str) -> String {
        const MARKER_TIMEOUT: Duration = Duration::from_secs(10);
        const MARKER_POLL: Duration = Duration::from_millis(10);

        let deadline = std::time::Instant::now() + MARKER_TIMEOUT;
        let mut collected = String::new();
        while std::time::Instant::now() < deadline {
            collected.push_str(&drain_available(fd));
            if collected.contains(marker) {
                return collected;
            }
            std::thread::sleep(MARKER_POLL);
        }
        panic!("timed out waiting for {marker:?}; got: {collected:?}");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_bridge_cancellation_does_not_inject_eof() {
        let _guard = RUN_WITH_PTY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut command = Command::new("/bin/sh");
        // The reader has to stay in the foreground process group. A
        // backgrounded reader is orphaned once the parent shell exits, and
        // reading a controlling terminal from an orphaned group fails with
        // EIO, which looks exactly like the injected end-of-input this test
        // is meant to catch.
        command
            .arg("-c")
            .arg("printf 'done\\n'; read value; printf 'eof-injected'");
        let terminal = LivePty::attach(&mut command, PtySize::default(), &[]).expect("attach PTY");
        let mut child = command.spawn().expect("spawn child");
        let session = child.id() as libc::pid_t;
        drop(command);
        let stdio = terminal.take_native_stdio().expect("take native stdio");
        let input = stdio.stdin;

        // The shell is now blocked in `read`, so any end-of-input it observes
        // has to come from the bridge.
        let mut text = wait_for_marker(stdio.stdout.as_raw_fd(), "done");

        terminal.finish_native_bridge();
        drop(input);

        // The bridge has stopped copying, so watch the primary directly and
        // keep draining it. An undrained terminal would wedge the shell mid
        // exit, which looks exactly like it never left its `read`.
        let watch = std::time::Instant::now() + Duration::from_millis(500);
        while std::time::Instant::now() < watch {
            text.push_str(&drain_available(stdio.stdout.as_raw_fd()));
            text.push_str(&drain_available(terminal.primary.as_raw_fd()));
            assert!(!text.contains("eof-injected"), "got: {text:?}");
            assert!(
                child.try_wait().expect("poll child").is_none(),
                "cancellation ended the shell's `read`; got: {text:?}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        // SAFETY: the child created its own session with its PID as the process-group ID.
        unsafe {
            libc::kill(-session, libc::SIGKILL);
        }

        // Reap on a deadline, still draining: a Darwin child stuck writing to a
        // full terminal does not die until the queue drains.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            text.push_str(&drain_available(stdio.stdout.as_raw_fd()));
            text.push_str(&drain_available(terminal.primary.as_raw_fd()));
            if child.try_wait().expect("poll child").is_some() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the shell did not exit after SIGKILL; got: {text:?}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        assert!(text.contains("done"), "got: {text:?}");
        assert!(!text.contains("eof-injected"), "got: {text:?}");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_bridge_preserves_fast_multichunk_output() {
        let _guard = RUN_WITH_PTY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("head -c 262144 /dev/zero; printf 'complete-output\\n'");
        let terminal = LivePty::attach(&mut command, PtySize::default(), &[]).expect("attach PTY");
        let mut child = command.spawn().expect("spawn child");
        drop(command);
        let stdio = terminal.take_native_stdio().expect("take native stdio");
        drop(stdio.stdin);

        let output_thread = std::thread::spawn(move || {
            let mut output = std::fs::File::from(stdio.stdout);
            let mut bytes = Vec::new();
            output.read_to_end(&mut bytes).expect("read output");
            bytes
        });
        assert!(wait_for_exit(&mut child).success());
        terminal.finish_native_bridge();

        let output = output_thread.join().expect("output thread");
        assert!(output.len() >= 262_144, "output was truncated");
        assert!(
            output.ends_with(b"complete-output\r\n"),
            "final output marker was truncated"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_bridge_cancels_blocked_input_write() {
        let _guard = RUN_WITH_PTY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg("(trap '' HUP; sleep 30) & exit 0");
        let terminal = LivePty::attach(&mut command, PtySize::default(), &[]).expect("attach PTY");
        let mut child = command.spawn().expect("spawn child");
        drop(command);
        let stdio = terminal.take_native_stdio().expect("take native stdio");
        drop(stdio.stdout);

        let input_thread = std::thread::spawn(move || {
            let mut input = std::fs::File::from(stdio.stdin);
            let buffer = vec![b'x'; 1024 * 1024];
            let _ = input.write_all(&buffer);
        });
        assert!(wait_for_exit(&mut child).success());

        let start = std::time::Instant::now();
        terminal.finish_native_bridge();
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "blocked input bridge did not cancel promptly"
        );
        input_thread.join().expect("input thread");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_bridge_survives_closed_output_consumer() {
        let _guard = RUN_WITH_PTY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg("printf output-after-close");
        let terminal = LivePty::attach(&mut command, PtySize::default(), &[]).expect("attach PTY");
        let mut child = command.spawn().expect("spawn child");
        drop(command);
        let stdio = terminal.take_native_stdio().expect("take native stdio");
        drop(stdio.stdin);
        drop(stdio.stdout);

        assert!(wait_for_exit(&mut child).success());
        terminal.finish_native_bridge();
    }

    /// The closed-consumer case above drains the child's whole output in one
    /// read, so it only catches a bridge that stops draining because Darwin
    /// blocks the secondary's close. Gate a bulk write behind the close so the
    /// child also blocks on a full terminal queue, which catches it anywhere.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_bridge_keeps_draining_after_the_output_consumer_closes() {
        let _guard = RUN_WITH_PTY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg("read go; head -c 1000000 /dev/zero");
        let terminal = LivePty::attach(&mut command, PtySize::default(), &[]).expect("attach PTY");
        let mut child = command.spawn().expect("spawn child");
        drop(command);
        let stdio = terminal.take_native_stdio().expect("take native stdio");

        // Close the consumer first so the echoed input already triggers EPIPE.
        drop(stdio.stdout);
        let mut input = std::fs::File::from(stdio.stdin);
        input.write_all(b"go\n").expect("write input");
        drop(input);

        assert!(wait_for_exit(&mut child).success());
        terminal.finish_native_bridge();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn native_bridge_cancels_full_output_pipe() {
        let _guard = RUN_WITH_PTY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg("read ready; head -c 8192 /dev/zero");
        let terminal = LivePty::attach(&mut command, PtySize::default(), &[]).expect("attach PTY");
        let mut child = command.spawn().expect("spawn child");
        drop(command);
        let stdio = terminal.take_native_stdio().expect("take native stdio");

        // SAFETY: this lowers the capacity of the live output pipe so the
        // bridge predictably parks in its cancellable write path.
        assert!(
            unsafe { libc::fcntl(stdio.stdout.as_raw_fd(), libc::F_SETPIPE_SZ, 4096) } >= 0,
            "set output pipe capacity: {}",
            std::io::Error::last_os_error()
        );
        let mut input = std::fs::File::from(stdio.stdin);
        input.write_all(b"go\n").expect("write input");
        drop(input);

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().expect("poll child") {
                assert!(status.success());
                break;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("child blocked before filling the native output pipe");
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        let start = std::time::Instant::now();
        terminal.finish_native_bridge();
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "full output bridge did not cancel promptly"
        );
        drop(stdio.stdout);
    }

    /// macOS has no `F_SETPIPE_SZ`, so fill the output pipe by volume instead.
    #[cfg(target_os = "macos")]
    #[test]
    fn native_bridge_cancels_when_the_output_pipe_fills() {
        let _guard = RUN_WITH_PTY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg("head -c 1000000 /dev/zero");
        let terminal = LivePty::attach(&mut command, PtySize::default(), &[]).expect("attach PTY");
        let mut child = command.spawn().expect("spawn child");
        drop(command);
        let stdio = terminal.take_native_stdio().expect("take native stdio");
        drop(stdio.stdin);

        // Never read stdout: the pipe fills, the bridge parks in its
        // cancellable write, and the child blocks on the terminal behind it.
        std::thread::sleep(Duration::from_millis(250));
        assert!(
            child.try_wait().expect("poll child").is_none(),
            "child should still be blocked behind the full output pipe"
        );

        // Run the join off-thread so a bridge that ignores cancellation fails
        // the test instead of hanging it.
        let (done, finished) = std::sync::mpsc::sync_channel(1);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                terminal.finish_native_bridge();
                let _ = done.send(());
            });
            let cancelled = finished.recv_timeout(Duration::from_secs(5)).is_ok();
            if !cancelled {
                // Drain so the parked bridge can finish and the scope can join.
                let mut sink = std::fs::File::from(stdio.stdout.try_clone().expect("clone stdout"));
                let mut scratch = [0u8; 8192];
                while sink.read(&mut scratch).unwrap_or(0) > 0 {}
            }
            assert!(cancelled, "full output bridge did not cancel promptly");
        });

        drop(stdio.stdout);
        drop(terminal);
        let _ = wait_for_exit(&mut child);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn size_reports_the_last_applied_dimensions() {
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg("true");
        let initial = PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        };
        let terminal = LivePty::attach(&mut command, initial, &[]).expect("attach PTY");
        assert_eq!(terminal.size(), initial);

        let resized = PtySize {
            rows: 40,
            cols: 120,
            pixel_width: 0,
            pixel_height: 0,
        };
        terminal.resize(resized).expect("resize PTY");
        assert_eq!(terminal.size(), resized);

        // A rejected resize must not disturb the recorded size.
        assert_eq!(
            terminal
                .resize(PtySize {
                    rows: 0,
                    cols: 0,
                    pixel_width: 0,
                    pixel_height: 0,
                })
                .expect_err("zero dimensions are rejected")
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert_eq!(terminal.size(), resized);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn is_canonical_mode_follows_the_terminal_discipline() {
        let _guard = RUN_WITH_PTY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("printf 'ready\\n'; read go; stty -icanon; printf 'canonical-off\\n'; read done");
        let terminal = LivePty::attach(&mut command, PtySize::default(), &[]).expect("attach PTY");
        let mut child = command.spawn().expect("spawn child");
        drop(command);
        let drain = PtyDrain::start_cancellable(
            terminal
                .try_clone_reader_with_canceller()
                .expect("clone reader"),
        );
        let mut writer = terminal.take_writer().expect("take writer");

        drain.wait_for("ready");
        assert!(terminal.is_canonical_mode().expect("read discipline"));

        writer.write_all(b"go\r").expect("write input");
        drain.wait_for("canonical-off");
        assert!(!terminal.is_canonical_mode().expect("read discipline"));

        drop(writer);
        let _ = child.kill();
        let _ = wait_for_exit(&mut child);
        drop(terminal);
        let _ = drain.finish();
    }

    /// `resize` must notify the foreground process group, not just set the
    /// kernel's window size.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn resize_signals_the_foreground_process_group() {
        let _guard = RUN_WITH_PTY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg(
            "trap 'stty size; exit 0' WINCH; printf 'ready\\n'; \
             i=0; while [ $i -lt 200 ]; do sleep 0.1; i=$((i+1)); done",
        );
        let terminal = LivePty::attach(
            &mut command,
            PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            },
            &[],
        )
        .expect("attach PTY");
        let mut child = command.spawn().expect("spawn child");
        drop(command);
        let drain = PtyDrain::start_cancellable(
            terminal
                .try_clone_reader_with_canceller()
                .expect("clone reader"),
        );

        drain.wait_for("ready");
        terminal
            .resize(PtySize {
                rows: 40,
                cols: 120,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("resize PTY");

        let seen = drain.wait_for("40 120");
        assert!(seen.contains("40 120"), "got: {seen:?}");
        assert!(wait_for_exit(&mut child).success());
        drop(terminal);
        let _ = drain.finish();
    }

    /// A forwarding process switches the terminal to raw mode, so the live
    /// discipline no longer reports an EOF character. `attach_forwarded`
    /// captures it up front and still delivers it.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn forwarded_eof_is_delivered_through_a_raw_mode_terminal() {
        let _guard = RUN_WITH_PTY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg(
            "stty raw -echo; printf 'ready\\r\\n'; \
             head -c 1 | od -An -tx1 | tr -d ' \\n'; printf '\\r\\n'",
        );
        let terminal = LivePty::attach_forwarded(&mut command, PtySize::default(), &[])
            .expect("attach forwarded PTY");
        let mut child = command.spawn().expect("spawn child");
        drop(command);
        let drain = PtyDrain::start_cancellable(
            terminal
                .try_clone_reader_with_canceller()
                .expect("clone reader"),
        );

        drain.wait_for("ready");
        drop(terminal.take_writer().expect("take writer"));

        assert!(wait_for_exit(&mut child).success());
        drop(terminal);
        let output = drain.finish();
        assert!(output.contains("04"), "expected ^D byte; got: {output:?}");
    }

    /// The contrast to the test above: the default discipline reads the live
    /// termios, which reports no EOF character once the terminal is raw.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn current_canonical_eof_is_skipped_for_a_raw_mode_terminal() {
        let _guard = RUN_WITH_PTY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("stty raw -echo; printf 'ready\\r\\n'; head -c 1 >/dev/null");
        let terminal = LivePty::attach(&mut command, PtySize::default(), &[]).expect("attach PTY");
        let mut child = command.spawn().expect("spawn child");
        drop(command);
        let drain = PtyDrain::start_cancellable(
            terminal
                .try_clone_reader_with_canceller()
                .expect("clone reader"),
        );

        drain.wait_for("ready");
        drop(terminal.take_writer().expect("take writer"));

        std::thread::sleep(Duration::from_secs(1));
        assert!(
            child.try_wait().expect("poll child").is_none(),
            "no EOF byte should reach a raw-mode terminal"
        );

        let _ = child.kill();
        let _ = wait_for_exit(&mut child);
        drop(terminal);
        let _ = drain.finish();
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn raw_secondary_guard_sets_raw_mode_and_restores_on_drop() {
        use nix::sys::termios::{self, LocalFlags};

        let (primary, secondary) = open_pty(None).expect("open PTY pair");
        let before = termios::tcgetattr(&secondary).expect("read termios");
        assert!(before.local_flags.contains(LocalFlags::ICANON));

        {
            let _raw = RawSecondaryGuard::install(secondary.as_raw_fd()).expect("install raw mode");
            let during = termios::tcgetattr(&secondary).expect("read termios");
            assert!(!during.local_flags.contains(LocalFlags::ICANON));
            assert!(!during.local_flags.contains(LocalFlags::ECHO));
        }

        let after = termios::tcgetattr(&secondary).expect("read termios");
        // PENDIN is kernel-managed status, not settable state.
        let settable = |flags: LocalFlags| flags - LocalFlags::PENDIN;
        assert_eq!(settable(after.local_flags), settable(before.local_flags));
        assert_eq!(after.input_flags, before.input_flags);
        assert_eq!(after.output_flags, before.output_flags);
        drop(primary);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn raw_secondary_guard_declines_a_non_tty() {
        let (read, write) = create_pipe().expect("create pipe");
        assert!(RawSecondaryGuard::install(read.as_raw_fd()).is_none());
        drop((read, write));
    }

    /// A failed `exec` must still surface as a spawn error after `attach`
    /// has rewired stdio onto the terminal.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn attach_still_reports_a_failed_exec() {
        let _guard = RUN_WITH_PTY_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let mut command = Command::new("/nonexistent/mxc-pty-missing-binary");
        let terminal = LivePty::attach(&mut command, PtySize::default(), &[]).expect("attach PTY");
        let error = command
            .spawn()
            .expect_err("missing binary must fail to spawn");
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        drop(terminal);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn echo_runs_under_pty() {
        let _guard = RUN_WITH_PTY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
        let _guard = RUN_WITH_PTY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg("sleep 30");
        let opts = PtyOptions {
            timeout: Some(Duration::from_millis(750)),
            ..PtyOptions::default()
        };
        let outcome = run_with_pty(cmd, opts).expect("bridge spawns");
        assert!(matches!(outcome, PtyOutcome::TimedOut));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn allocated_pty_descriptors_are_cloexec() {
        use nix::fcntl::{fcntl, FcntlArg, FdFlag};

        let (master, slave) = open_pty(None).expect("open PTY");
        for (label, fd) in [
            ("primary", master.as_raw_fd()),
            ("secondary", slave.as_raw_fd()),
        ] {
            let bits = fcntl(fd, FcntlArg::F_GETFD).expect("F_GETFD");
            let flags = FdFlag::from_bits_truncate(bits);
            assert!(flags.contains(FdFlag::FD_CLOEXEC), "{label} lacked CLOEXEC");
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_bridge_descriptors_are_cloexec() {
        use nix::fcntl::{fcntl, FcntlArg, FdFlag};

        let (read, write) = create_pipe().expect("create pipe");
        for (label, fd) in [("read", read.as_raw_fd()), ("write", write.as_raw_fd())] {
            let bits = fcntl(fd, FcntlArg::F_GETFD).expect("F_GETFD");
            let flags = FdFlag::from_bits_truncate(bits);
            assert!(flags.contains(FdFlag::FD_CLOEXEC), "{label} lacked CLOEXEC");
        }
    }

    /// Regression: PTY descriptors must be created with `FD_CLOEXEC`; otherwise, a child
    /// inherits the primary fd across `exec` — the secondary never hangs up
    /// when the parent dies and the sandboxed shell becomes immortal,
    /// leaking a pty pair per spawn until the host hits
    /// `kern.tty.ptmx_max` (default 511 on macOS). The original secondary fd
    /// (consumed into `secondary_err: Stdio`) also leaks: Rust's spawn
    /// `dup2`s it onto fd 2 without closing the source, so the original
    /// fd number stays open as a second secondary reference unless CLOEXEC trims it at
    /// `execve` time.
    ///
    /// The parent inspects the blocked child's descriptor table so the probe
    /// cannot create transient shell descriptors and mistake them for leaks.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn pty_fds_do_not_leak_into_child_across_exec() {
        let _guard = RUN_WITH_PTY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let inherited = process_pty_fds(std::process::id())
            .expect("inspect parent descriptors")
            .into_iter()
            .map(|(fd, _)| fd)
            .collect::<std::collections::HashSet<_>>();

        let mut cmd = Command::new("/bin/sleep");
        cmd.arg("30");
        let terminal = LivePty::attach(&mut cmd, PtySize::default(), &[]).expect("attach PTY");
        let mut child = cmd.spawn().expect("spawn child");
        drop(cmd);

        std::thread::sleep(Duration::from_millis(50));
        let leaks = process_pty_fds(child.id())
            .expect("inspect child descriptors")
            .into_iter()
            .filter(|(fd, _)| !inherited.contains(fd))
            .map(|(fd, target)| format!("LEAK fd={fd} target={target}"))
            .collect::<Vec<_>>();
        let _ = child.kill();
        let _ = child.wait();
        drop(terminal);

        assert!(
            leaks.is_empty(),
            "child inherited pty fd(s) across exec:\n{}",
            leaks.join("\n"),
        );
    }

    #[cfg(target_os = "linux")]
    fn process_pty_fds(pid: u32) -> std::io::Result<Vec<(String, String)>> {
        let mut pty_fds = Vec::new();
        for entry in std::fs::read_dir(format!("/proc/{pid}/fd"))? {
            let entry = entry?;
            let fd = entry.file_name().to_string_lossy().into_owned();
            if matches!(fd.as_str(), "0" | "1" | "2") {
                continue;
            }
            let Ok(target) = std::fs::read_link(entry.path()) else {
                continue;
            };
            let target = target.to_string_lossy();
            if target == "/dev/ptmx" || target.starts_with("/dev/pts/") {
                pty_fds.push((fd, target.into_owned()));
            }
        }
        Ok(pty_fds)
    }

    #[cfg(target_os = "macos")]
    fn process_pty_fds(pid: u32) -> std::io::Result<Vec<(String, String)>> {
        let output = Command::new("/usr/sbin/lsof")
            .args(["-p", &pid.to_string()])
            .output()?;
        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .skip(1)
            .filter_map(|line| {
                let columns = line.split_whitespace().collect::<Vec<_>>();
                let fd = columns.get(3)?;
                let target = columns.last()?;
                let fd_number =
                    fd.trim_end_matches(|character: char| character.is_ascii_alphabetic());
                (fd_number.parse::<u32>().ok()? > 2
                    && (target.starts_with("/dev/ttys")
                        || target.starts_with("/dev/pts/")
                        || *target == "/dev/ptmx"))
                    .then(|| (fd_number.to_string(), (*target).to_string()))
            })
            .collect())
    }
}
