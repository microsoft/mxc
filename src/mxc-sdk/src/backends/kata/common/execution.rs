// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! One process running in a started sandbox.
//!
//! The shim connects a process's standard streams to named pipes (FIFOs) whose
//! paths are named in the `Exec` request. MXC creates the FIFOs and holds one
//! end of each, so a stream carries data from the first byte and its end of
//! file is the shim closing its side.

use std::fs::{File, OpenOptions};
use std::io::{self, PipeReader, PipeWriter, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, TryRecvError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use nix::sys::stat::Mode;
use nix::unistd::mkfifo;
use serde_json::Value;

use crate::kata_common::error::KataError;
use crate::kata_common::task_api::{self, ExecRequest, StdioPaths, TaskClient};

/// How long a killed process may take to report its exit.
const KILL_REPORT_TIMEOUT: Duration = Duration::from_secs(10);

/// Sends the shim a close-stdin request once, so the process sees end of file.
/// The shim does not do this when the stdin FIFO is closed.
struct StdinClose {
    task: TaskClient,
    task_id: String,
    exec_id: String,
    sent: AtomicBool,
}

impl StdinClose {
    fn send(&self) {
        if !self.sent.swap(true, Ordering::AcqRel) {
            let _ = self.task.close_stdin(&self.task_id, &self.exec_id);
        }
    }
}

/// Writes to a process's standard input. Dropping it, or the process being
/// waited on, delivers end of file.
pub(crate) struct StdinWriter {
    file: Option<File>,
    close: Arc<StdinClose>,
}

impl std::fmt::Debug for StdinWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StdinWriter")
            .field("open", &self.file.is_some())
            .finish()
    }
}

impl AsRawFd for StdinWriter {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_ref().map_or(-1, AsRawFd::as_raw_fd)
    }
}

impl Write for StdinWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.file.as_mut() {
            Some(file) => file.write(buf),
            None => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "standard input is closed",
            )),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.file.as_mut() {
            Some(file) => file.flush(),
            None => Ok(()),
        }
    }
}

impl Drop for StdinWriter {
    fn drop(&mut self) {
        // Close the FIFO first so everything written is already delivered when
        // the shim is told to end the stream.
        self.file.take();
        self.close.send();
    }
}

/// Waits until `fd` is ready for `events` or `wake` has data. Returns each
/// descriptor's `revents`.
fn poll_or_wake(fd: RawFd, events: i16, wake: RawFd) -> io::Result<(i16, i16)> {
    let mut polled = [
        libc::pollfd {
            fd,
            events,
            revents: 0,
        },
        libc::pollfd {
            fd: wake,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        // SAFETY: `polled` is a valid array of two pollfd.
        if unsafe { libc::poll(polled.as_mut_ptr(), 2, -1) } >= 0 {
            return Ok((polled[0].revents, polled[1].revents));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// Writes all of `data`, giving up when `wake` has data or the write fails.
///
/// Waits for room before each write and writes at most `PIPE_BUF` bytes, which
/// then cannot block. So `sink` can be left blocking, as a stream shared with
/// this process's parent must be, and a full pipe nobody reads cannot trap the
/// thread.
fn write_until_woken(sink: &mut (impl Write + AsRawFd), wake: RawFd, mut data: &[u8]) -> bool {
    while !data.is_empty() {
        match poll_or_wake(sink.as_raw_fd(), libc::POLLOUT, wake) {
            Ok((_, 0)) => {}
            _ => return false,
        }
        match sink.write(&data[..data.len().min(libc::PIPE_BUF)]) {
            Ok(0) => return false,
            Ok(written) => data = &data[written..],
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) => {}
            Err(_) => return false,
        }
    }
    true
}

/// Moves bytes from `source` to `sink` until `source` ends, a write fails, or
/// `wake` has data.
fn forward(source: RawFd, wake: RawFd, sink: &mut (impl Write + AsRawFd)) {
    let mut buffer = [0u8; 8192];
    // Poll rather than read directly so the thread can be woken when the
    // process ends; this process's stdin is shared with its parent and must not
    // be made non-blocking.
    while let Ok((ready, woken)) = poll_or_wake(source, libc::POLLIN, wake) {
        if woken != 0 || ready & libc::POLLNVAL != 0 {
            return;
        }
        // SAFETY: the buffer is valid for its length.
        let read = unsafe { libc::read(source, buffer.as_mut_ptr().cast(), buffer.len()) };
        if read < 0 {
            match io::Error::last_os_error().kind() {
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock => continue,
                _ => return,
            }
        }
        if read == 0 || !write_until_woken(sink, wake, &buffer[..read as usize]) {
            return;
        }
    }
}

/// Copies `source` to `sink` until `source` ends, a write fails, or the pump is
/// stopped, then drops `sink`. Dropping a [`StdinWriter`] ends the process's
/// input.
pub(crate) struct Pump {
    wake: PipeWriter,
    // Kept so the wake write cannot hit a closed pipe after the thread ends.
    _wake_read: PipeReader,
    handle: Option<JoinHandle<()>>,
}

impl Pump {
    pub(crate) fn start<W: Write + AsRawFd + Send + 'static>(
        source: impl AsFd + Send + 'static,
        mut sink: W,
    ) -> io::Result<Self> {
        let (wake_read, wake) = io::pipe()?;
        let thread_wake = wake_read.try_clone()?;
        let handle = std::thread::Builder::new()
            .name("mxc-kata-pump".to_string())
            .spawn(move || {
                forward(
                    source.as_fd().as_raw_fd(),
                    thread_wake.as_raw_fd(),
                    &mut sink,
                );
                drop(sink);
            })?;
        Ok(Self {
            wake,
            _wake_read: wake_read,
            handle: Some(handle),
        })
    }

    /// Feeds `writer` from a new pipe and returns the pipe's write end. The
    /// process's input ends when the caller closes it.
    pub(crate) fn pipe(writer: StdinWriter) -> io::Result<(PipeWriter, Self)> {
        let (reader, write_end) = io::pipe()?;
        Ok((write_end, Self::start(reader, writer)?))
    }

    /// Ends the pump and waits for it. Never waits on the process.
    pub(crate) fn stop(mut self) {
        self.shut_down();
    }

    /// Gives the pump up to `grace` to end by itself, then stops it.
    pub(crate) fn finish(self, grace: Duration) {
        let deadline = Instant::now() + grace;
        while self.handle.as_ref().is_some_and(|h| !h.is_finished()) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        self.stop();
    }

    fn shut_down(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = (&self.wake).write(&[0]);
            let _ = handle.join();
        }
    }
}

impl Drop for Pump {
    fn drop(&mut self) {
        self.shut_down();
    }
}

/// How far a kill reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KillScope {
    /// Only the process. Other processes in the sandbox keep running, so the
    /// sandbox stays usable. A descendant that holds the process's output open
    /// keeps the shim from reporting its exit until the descendant ends.
    Process,
    /// Every process in the sandbox. For a sandbox that exists only for this
    /// process, so nothing can keep its output open.
    Sandbox,
}

/// What it takes to kill a process, separate from the [`Execution`] that owns
/// its streams, so a terminator can run while another thread waits.
#[derive(Debug, Clone)]
pub(crate) struct Killer {
    task: TaskClient,
    task_id: String,
    exec_id: String,
    scope: KillScope,
}

impl Killer {
    /// Kills the process with SIGKILL, and with [`KillScope::Sandbox`] every
    /// other process in the sandbox too. A process that already exited is not
    /// an error.
    pub(crate) fn kill(&self) -> Result<(), KataError> {
        let killed = match self
            .task
            .kill(&self.task_id, &self.exec_id, task_api::SIGKILL, false)
        {
            Ok(()) => Ok(()),
            Err(e) if e.is_not_found() => Ok(()),
            Err(e) => Err(KataError::failed(format!("killing the process: {e}"))),
        };
        if self.scope == KillScope::Sandbox {
            // Empty exec id: the sandbox's init process, with `all` set to
            // signal every process in the container.
            let _ = self.task.kill(&self.task_id, "", task_api::SIGKILL, true);
        }
        killed
    }
}

/// How a wait ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExitOutcome {
    /// The process exited with this code. A process killed by signal N reports
    /// 128 + N.
    Exited(i32),
    /// The deadline passed and the process was killed.
    TimedOut,
}

#[derive(Debug)]
pub(crate) struct Execution {
    task: TaskClient,
    task_id: String,
    exec_id: String,
    scope: KillScope,
    fifos: Vec<PathBuf>,
    stdout: Option<OwnedFd>,
    stderr: Option<OwnedFd>,
    stdin: Option<StdinWriter>,
    exit: Receiver<Result<i32, String>>,
    /// The exit once seen, so repeated waits agree.
    result: Option<Result<i32, String>>,
    /// The process is known to be gone: it exited, or a timeout killed it.
    gone: bool,
    released: bool,
}

fn make_fifo(dir: &Path, name: &str) -> Result<PathBuf, KataError> {
    let path = dir.join(name);
    mkfifo(&path, Mode::from_bits_truncate(0o600))
        .map_err(|e| KataError::failed(format!("cannot create {}: {e}", path.display())))?;
    Ok(path)
}

fn open_read(path: &Path) -> io::Result<OwnedFd> {
    // Non-blocking so the open does not wait for the shim to open its end. The
    // kernel reports end of file only after a writer has connected and left, so
    // a reader that starts early waits rather than seeing a false end.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    Ok(file.into())
}

impl Execution {
    /// Starts `process` (an OCI process) in the sandbox task `task_id`.
    ///
    /// `io_dir` must exist. `exec_id` must be unique within the task.
    pub(crate) fn start(
        task: &TaskClient,
        task_id: &str,
        exec_id: &str,
        process: &Value,
        io_dir: &Path,
        scope: KillScope,
    ) -> Result<Self, KataError> {
        let mut fifos = Vec::new();
        let result = Self::start_inner(task, task_id, exec_id, process, io_dir, scope, &mut fifos);
        if result.is_err() {
            for fifo in &fifos {
                let _ = std::fs::remove_file(fifo);
            }
        }
        result
    }

    fn start_inner(
        task: &TaskClient,
        task_id: &str,
        exec_id: &str,
        process: &Value,
        io_dir: &Path,
        scope: KillScope,
        fifos: &mut Vec<PathBuf>,
    ) -> Result<Self, KataError> {
        let stdin_path = make_fifo(io_dir, &format!("{exec_id}.in"))?;
        fifos.push(stdin_path.clone());
        let stdout_path = make_fifo(io_dir, &format!("{exec_id}.out"))?;
        fifos.push(stdout_path.clone());
        let stderr_path = make_fifo(io_dir, &format!("{exec_id}.err"))?;
        fifos.push(stderr_path.clone());

        let io_error = |what: &str, e: io::Error| KataError::failed(format!("{what}: {e}"));
        let stdout = open_read(&stdout_path).map_err(|e| io_error("opening stdout", e))?;
        let stderr = open_read(&stderr_path).map_err(|e| io_error("opening stderr", e))?;
        // Read-write so the open does not wait for the shim, and the write end
        // stays valid until MXC closes it.
        let stdin_file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(&stdin_path)
            .map_err(|e| io_error("opening stdin", e))?;

        let spec = serde_json::to_vec(process)
            .map_err(|e| KataError::failed(format!("encoding the process: {e}")))?;
        task.exec(&ExecRequest {
            id: task_id.to_string(),
            exec_id: exec_id.to_string(),
            stdio: StdioPaths {
                stdin: stdin_path.display().to_string(),
                stdout: stdout_path.display().to_string(),
                stderr: stderr_path.display().to_string(),
            },
            spec: task_api::oci_process(spec),
        })
        .map_err(|e| KataError::failed(format!("the shim refused the process: {e}")))?;

        if let Err(e) = task.start(task_id, exec_id) {
            // Registered but not running: remove it so the shim keeps no entry.
            let _ = task.delete(task_id, exec_id);
            return Err(KataError::failed(format!("the process did not start: {e}")));
        }

        let (sender, exit) = mpsc::channel();
        // Built before the wait thread so a failed spawn drops it, which kills
        // the process and releases its shim entry and FIFOs.
        let execution = Self {
            task: task.clone(),
            task_id: task_id.to_string(),
            exec_id: exec_id.to_string(),
            scope,
            fifos: std::mem::take(fifos),
            stdout: Some(stdout),
            stderr: Some(stderr),
            stdin: Some(StdinWriter {
                file: Some(stdin_file),
                close: Arc::new(StdinClose {
                    task: task.clone(),
                    task_id: task_id.to_string(),
                    exec_id: exec_id.to_string(),
                    sent: AtomicBool::new(false),
                }),
            }),
            exit,
            result: None,
            gone: false,
            released: false,
        };

        let waiter = task.clone();
        let (wait_task_id, wait_exec_id) = (task_id.to_string(), exec_id.to_string());
        std::thread::Builder::new()
            .name("mxc-kata-wait".to_string())
            .spawn(move || {
                let status = waiter
                    .wait(&wait_task_id, &wait_exec_id)
                    .map(|code| code as i32)
                    .map_err(|e| e.to_string());
                let _ = sender.send(status);
            })
            .map_err(|e| KataError::failed(format!("cannot start the wait thread: {e}")))?;

        Ok(execution)
    }

    pub(crate) fn take_stdin(&mut self) -> Option<StdinWriter> {
        self.stdin.take()
    }

    pub(crate) fn take_stdout(&mut self) -> Option<OwnedFd> {
        self.stdout.take()
    }

    pub(crate) fn take_stderr(&mut self) -> Option<OwnedFd> {
        self.stderr.take()
    }

    /// A cloneable handle that can kill this process while another thread
    /// waits on it.
    pub(crate) fn killer(&self) -> Killer {
        Killer {
            task: self.task.clone(),
            task_id: self.task_id.clone(),
            exec_id: self.exec_id.clone(),
            scope: self.scope,
        }
    }

    pub(crate) fn kill(&self) -> Result<(), KataError> {
        self.killer().kill()
    }

    /// The exit if it has been reported, without waiting.
    pub(crate) fn try_wait(&mut self) -> Result<Option<i32>, KataError> {
        if self.result.is_none() {
            match self.exit.try_recv() {
                Ok(result) => self.result = Some(result),
                Err(TryRecvError::Empty) => return Ok(None),
                Err(TryRecvError::Disconnected) => {
                    self.result = Some(Err("the wait thread ended without a result".to_string()))
                }
            }
        }
        self.gone = true;
        self.exit_code().map(Some)
    }

    fn exit_code(&self) -> Result<i32, KataError> {
        match self.result.as_ref().expect("result recorded") {
            Ok(code) => Ok(*code),
            Err(message) => Err(KataError::failed(format!(
                "could not learn how the process ended: {message}"
            ))),
        }
    }

    /// Waits for the exit, killing the process if `deadline` passes first.
    pub(crate) fn wait(&mut self, deadline: Option<Instant>) -> Result<ExitOutcome, KataError> {
        if self.result.is_none() {
            let received = match deadline {
                None => self.exit.recv().map_err(|_| RecvTimeoutError::Disconnected),
                Some(deadline) => self
                    .exit
                    .recv_timeout(deadline.saturating_duration_since(Instant::now())),
            };
            match received {
                Ok(result) => self.result = Some(result),
                Err(RecvTimeoutError::Disconnected) => {
                    self.result = Some(Err("the wait thread ended without a result".to_string()))
                }
                Err(RecvTimeoutError::Timeout) => {
                    self.kill()?;
                    match self.exit.recv_timeout(KILL_REPORT_TIMEOUT) {
                        Ok(Ok(_)) => self.gone = true,
                        Ok(Err(message)) => {
                            return Err(KataError::failed(format!(
                                "could not confirm the process exited after SIGKILL: {message}"
                            )))
                        }
                        Err(_) => {
                            return Err(KataError::failed(format!(
                                "the process did not exit within {}s of SIGKILL",
                                KILL_REPORT_TIMEOUT.as_secs()
                            )))
                        }
                    }
                    return Ok(ExitOutcome::TimedOut);
                }
            }
        }
        self.gone = true;
        self.exit_code().map(ExitOutcome::Exited)
    }

    /// Removes the shim's record of the process and the FIFOs. Safe to repeat.
    /// Call once the process has exited and its output has been read.
    pub(crate) fn release(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        // Dropping stdin first sends the close-stdin request while the process
        // is still registered.
        self.stdin.take();
        let _ = self.task.delete(&self.task_id, &self.exec_id);
        for fifo in &self.fifos {
            let _ = std::fs::remove_file(fifo);
        }
    }
}

impl Drop for Execution {
    fn drop(&mut self) {
        if !self.gone {
            let _ = self.kill();
        }
        self.release();
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! A process's stdin FIFO and a fake shim, for tests of the input path.

    use std::io::Read;
    use std::os::unix::net::UnixListener;

    use super::*;
    use crate::kata_common::ttrpc::{serve_methods, Client};

    pub(crate) struct StdinFixture {
        writer: Option<StdinWriter>,
        /// The name of each call the shim has received, such as `CloseIO`.
        pub(crate) calls: Receiver<String>,
        guest: File,
        _dir: tempfile::TempDir,
    }

    pub(crate) fn stdin_fixture() -> StdinFixture {
        let dir = tempfile::tempdir().unwrap();
        let fifo = make_fifo(dir.path(), "exec.in").unwrap();
        // Opened as `start_inner` does: MXC's own end reads and writes.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(&fifo)
            .unwrap();
        let guest = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo)
            .unwrap();
        let socket = dir.path().join("shim.sock");
        let calls = serve_methods(UnixListener::bind(&socket).unwrap());
        let task = TaskClient::new(Client::new(socket.to_str().unwrap()));
        StdinFixture {
            writer: Some(StdinWriter {
                file: Some(file),
                close: Arc::new(StdinClose {
                    task,
                    task_id: "task".to_string(),
                    exec_id: "exec".to_string(),
                    sent: AtomicBool::new(false),
                }),
            }),
            calls,
            guest,
            _dir: dir,
        }
    }

    impl StdinFixture {
        pub(crate) fn take_writer(&mut self) -> StdinWriter {
            self.writer.take().expect("the writer was already taken")
        }

        /// What the guest has read so far, once the FIFO holds `len` bytes.
        pub(crate) fn read_exactly(&mut self, len: usize) -> Vec<u8> {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut data = vec![0u8; len];
            let mut filled = 0;
            while filled < len && Instant::now() < deadline {
                match self.guest.read(&mut data[filled..]) {
                    Ok(0) => break,
                    Ok(read) => filled += read,
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
            data.truncate(filled);
            data
        }

        /// Bytes waiting in the FIFO.
        pub(crate) fn queued(&self) -> usize {
            queued(&self.guest)
        }
    }

    /// Bytes waiting to be read from a pipe.
    pub(crate) fn queued(pipe: &impl AsRawFd) -> usize {
        let mut queued: libc::c_int = 0;
        // SAFETY: FIONREAD writes one int through the pointer.
        unsafe { libc::ioctl(pipe.as_raw_fd(), libc::FIONREAD, &mut queued) };
        queued as usize
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{queued, stdin_fixture};
    use super::*;

    #[test]
    fn a_pump_forwards_input_and_ends_it_when_its_source_closes() {
        let mut fixture = stdin_fixture();
        let (source, mut feed) = io::pipe().unwrap();
        let pump = Pump::start(source, fixture.take_writer()).unwrap();

        feed.write_all(b"hello").unwrap();
        assert_eq!(fixture.read_exactly(5), b"hello");
        assert!(
            fixture
                .calls
                .recv_timeout(Duration::from_millis(300))
                .is_err(),
            "input ended while the source was still open"
        );

        drop(feed);
        assert_eq!(
            fixture.calls.recv_timeout(Duration::from_secs(10)).unwrap(),
            "CloseIO"
        );
        pump.stop();
    }

    /// Feeds a pump whose sink is full and unread, and checks that stopping it
    /// does not wait on the sink and that the feeder's writes then fail.
    fn assert_stops_with_a_full_sink(
        pump: Pump,
        mut feed: PipeWriter,
        sink_queued: impl Fn() -> usize,
    ) {
        let feeder = std::thread::spawn(move || feed.write_all(&vec![0u8; 4 << 20]));

        // Wait for the sink to fill, then give the pump time to try one more write.
        let deadline = Instant::now() + Duration::from_secs(10);
        while sink_queued() < 64 * 1024 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(sink_queued() >= 64 * 1024, "the sink never filled");
        std::thread::sleep(Duration::from_millis(300));

        let (stopped, done) = mpsc::channel();
        std::thread::spawn(move || {
            pump.stop();
            let _ = stopped.send(());
        });
        assert!(
            done.recv_timeout(Duration::from_secs(10)).is_ok(),
            "stop waited on a write that cannot finish"
        );
        // The feeder's writes end rather than wait for a pump that is gone.
        assert!(feeder.join().unwrap().is_err());
    }

    /// The guest never reads, and MXC holds the FIFO's read end too, so a write
    /// that waits for room is never released by the process exiting.
    #[test]
    fn a_pump_stuck_on_a_full_fifo_stops_when_asked() {
        let mut fixture = stdin_fixture();
        let (source, feed) = io::pipe().unwrap();
        let pump = Pump::start(source, fixture.take_writer()).unwrap();
        assert_stops_with_a_full_sink(pump, feed, || fixture.queued());
    }

    /// The consumer of this process's own output stops reading. The stream is
    /// shared with the caller, so it must stay blocking.
    #[test]
    fn a_pump_stuck_on_a_full_output_pipe_stops_when_asked_and_leaves_it_blocking() {
        let (source, feed) = io::pipe().unwrap();
        let (consumer, sink) = io::pipe().unwrap();
        let pump = Pump::start(source, sink.try_clone().unwrap()).unwrap();
        assert_stops_with_a_full_sink(pump, feed, || queued(&consumer));
        // SAFETY: `sink` is open; F_GETFL only reads its flags.
        let flags = unsafe { libc::fcntl(sink.as_raw_fd(), libc::F_GETFL) };
        assert_eq!(flags & libc::O_NONBLOCK, 0, "the shared stream was changed");
    }
}
