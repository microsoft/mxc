// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Piped execution: the frame consumer never waits for a caller's output pipe.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::mxc_common::mxc_error::MxcError;
use crate::mxc_common::sandbox_process::StreamCloser;
use crate::mxc_common::state_aware_backend::{ExecHandle, ExecOutcome, PipeHandle};
use crate::mxc_common::stream_buffer::{
    bounded_stream_pair, StreamCanceller, StreamOverflow, StreamWriter,
};

use super::frame::{encode_frame, FrameAccumulator, FrameType, MAX_FRAME_PAYLOAD};
use super::payload::{parse_error, parse_exit, parse_started, ExecStartPayload};
use super::transport::{connect_exec, ExecConnection, UpgradeTarget};

/// Pending bytes per output, excluding one pump chunk and the native pipe.
pub(crate) const MAX_PENDING_BYTES: usize = 8 * 1024 * 1024;
const POLL: Duration = Duration::from_millis(5);

#[cfg(windows)]
trait CancelPipe: Send + Sync {
    fn cancel(&self);
}

#[cfg(windows)]
struct PipeRef<T>(Arc<T>);

#[cfg(windows)]
impl<T: std::os::windows::io::AsRawHandle + Send + Sync> CancelPipe for PipeRef<T> {
    fn cancel(&self) {
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::IO::CancelIoEx;
        // SAFETY: this Arc owns the exact handle used for the pending I/O.
        unsafe {
            let _ = CancelIoEx(HANDLE(self.0.as_raw_handle()), None);
        }
    }
}

fn failure(code: &str, message: impl Into<String>) -> MxcError {
    MxcError::backend_error(format!("w365_agents {code}: {}", message.into())).with_details(
        serde_json::json!({
            "code": code,
            "possiblySucceeded": true,
            "outcomeUnknown": true
        }),
    )
}

struct WorkerStop {
    cancelled: AtomicBool,
    finished: AtomicBool,
    #[cfg(windows)]
    pipe: Mutex<Option<Box<dyn CancelPipe>>>,
}

impl WorkerStop {
    #[cfg(windows)]
    fn for_pipe<T: std::os::windows::io::AsRawHandle + Send + Sync + 'static>(
        pipe: &Arc<T>,
    ) -> Arc<Self> {
        Arc::new(Self {
            cancelled: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            pipe: Mutex::new(Some(Box::new(PipeRef(Arc::clone(pipe))))),
        })
    }

    #[cfg(unix)]
    fn for_pipe<T>(_pipe: &Arc<T>) -> Arc<Self> {
        Arc::new(Self {
            cancelled: AtomicBool::new(false),
            finished: AtomicBool::new(false),
        })
    }

    fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        #[cfg(windows)]
        {
            // Retry across the flag-check -> kernel-I/O window, as for the
            // common cancellable reader. The Arc keeps the exact handle alive.
            while !self.finished.load(Ordering::Acquire) {
                if let Some(pipe) = self.pipe.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
                    pipe.cancel();
                }
                thread::sleep(POLL);
            }
        }
    }
}

struct Worker {
    join: JoinHandle<()>,
    stop: Arc<WorkerStop>,
}

impl Worker {
    fn spawn(
        name: &str,
        stop: Arc<WorkerStop>,
        work: impl FnOnce(Arc<WorkerStop>) + Send + 'static,
    ) -> io::Result<Self> {
        let worker_stop = Arc::clone(&stop);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let join = thread::Builder::new().name(name.into()).spawn(move || {
            struct Finished(Arc<WorkerStop>);
            impl Drop for Finished {
                fn drop(&mut self) {
                    #[cfg(windows)]
                    self.0.pipe.lock().unwrap_or_else(|e| e.into_inner()).take();
                    self.0.finished.store(true, Ordering::Release);
                }
            }
            let _finished = Finished(Arc::clone(&worker_stop));
            #[cfg(unix)]
            {
                // A library host need not ignore SIGPIPE. Only this worker's
                // mask changes, so closing a caller's pipe cannot kill it.
                let mut signals = nix::sys::signal::SigSet::empty();
                signals.add(nix::sys::signal::Signal::SIGPIPE);
                if let Err(error) = signals.thread_block() {
                    let _ = ready_tx.send(Err(io::Error::from(error)));
                    return;
                }
            }
            let _ = ready_tx.send(Ok(()));
            work(worker_stop);
        })?;
        if let Err(error) = ready_rx
            .recv()
            .unwrap_or_else(|_| Err(io::Error::other("W365 pipe worker did not initialize")))
        {
            let _ = join.join();
            return Err(error);
        }
        Ok(Self { join, stop })
    }
}

struct Control {
    socket: TcpStream,
    cancelled: Arc<AtomicBool>,
    terminal: AtomicBool,
    outputs: [StreamCanceller; 2],
    workers: Vec<Arc<WorkerStop>>,
    relay: Mutex<Option<JoinHandle<()>>>,
}

impl Control {
    fn stop(&self) {
        self.cancelled.store(true, Ordering::Release);
        let _ = self.socket.shutdown(Shutdown::Both);
        for output in &self.outputs {
            output.close();
        }
        for worker in &self.workers {
            worker.cancel();
        }
        if let Some(relay) = self.relay.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = relay.join();
        }
    }
}

impl Drop for Control {
    fn drop(&mut self) {
        if !self.terminal.load(Ordering::Acquire) {
            self.stop();
        }
        // Capture releases its process before joining readers. After completion
        // the supervisor owns the pumps until caller-owned pipes drain or close.
    }
}

#[cfg(windows)]
fn raw(pipe: &impl std::os::windows::io::AsRawHandle) -> PipeHandle {
    windows::Win32::Foundation::HANDLE(pipe.as_raw_handle())
}

#[cfg(unix)]
fn raw(pipe: &impl std::os::fd::AsRawFd) -> PipeHandle {
    pipe.as_raw_fd()
}

#[cfg(windows)]
fn prepare_pipe_io(_pipe: &impl std::os::windows::io::AsRawHandle) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn prepare_pipe_io(pipe: &impl std::os::fd::AsRawFd) -> io::Result<()> {
    let fd = pipe.as_raw_fd();
    // SAFETY: the borrowed descriptor remains owned by the worker.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn output_worker(
    pipe: io::PipeWriter,
    mut source: crate::mxc_common::stream_buffer::StreamReader,
    fault: Arc<Mutex<Option<io::Error>>>,
) -> io::Result<Worker> {
    prepare_pipe_io(&pipe)?;
    let pipe = Arc::new(pipe);
    let stop = WorkerStop::for_pipe(&pipe);
    Worker::spawn("w365-output", stop, move |stop| {
        let mut pipe = &*pipe;
        let mut bytes = [0; MAX_FRAME_PAYLOAD];
        let result = (|| {
            while !stop.cancelled() {
                let count = source.read(&mut bytes)?;
                if count == 0 {
                    break;
                }
                let mut pending = &bytes[..count];
                while !pending.is_empty() && !stop.cancelled() {
                    match pipe.write(pending) {
                        Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                        Ok(count) => pending = &pending[count..],
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(POLL)
                        }
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(error) => return Err(error),
                    }
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            // Closing a caller-owned reader intentionally abandons its output.
            if !stop.cancelled() && error.kind() != io::ErrorKind::BrokenPipe {
                *fault.lock().unwrap_or_else(|e| e.into_inner()) = Some(error);
            }
        }
    })
}

enum Input {
    Bytes(Vec<u8>),
    Eof,
    Error(io::Error),
}

fn input_worker(pipe: io::PipeReader, tx: mpsc::SyncSender<Input>) -> io::Result<Worker> {
    prepare_pipe_io(&pipe)?;
    let pipe = Arc::new(pipe);
    let stop = WorkerStop::for_pipe(&pipe);
    Worker::spawn("w365-input", stop, move |stop| {
        let mut pipe = &*pipe;
        let mut bytes = [0; MAX_FRAME_PAYLOAD];
        while !stop.cancelled() {
            let message = match pipe.read(&mut bytes) {
                Ok(0) => Input::Eof,
                Ok(count) => Input::Bytes(bytes[..count].to_vec()),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(POLL);
                    continue;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => Input::Error(error),
            };
            let terminal = !matches!(message, Input::Bytes(_));
            let mut pending = message;
            loop {
                if stop.cancelled() {
                    return;
                }
                match tx.try_send(pending) {
                    Ok(()) => break,
                    Err(mpsc::TrySendError::Disconnected(_)) => return,
                    Err(mpsc::TrySendError::Full(message)) => {
                        pending = message;
                        thread::sleep(POLL);
                    }
                }
            }
            if terminal {
                return;
            }
        }
    })
}

pub(crate) fn run(target: UpgradeTarget, start: ExecStartPayload) -> Result<ExecHandle, MxcError> {
    let start_frame = start.encode()?;
    let (stdout_reader, stdout_pipe) = io::pipe().map_err(setup_error)?;
    let (stderr_reader, stderr_pipe) = io::pipe().map_err(setup_error)?;
    let (stdin_pipe, stdin_writer) = io::pipe().map_err(setup_error)?;
    let (out, out_source, out_overflow) = bounded_stream_pair(MAX_PENDING_BYTES);
    let (err, err_source, err_overflow) = bounded_stream_pair(MAX_PENDING_BYTES);
    let outputs = [out_source.canceller(), err_source.canceller()];
    let output_fault = Arc::new(Mutex::new(None));
    let (tx, rx) = mpsc::sync_channel(1);
    let mut workers = Vec::new();
    let setup = (|| {
        workers.push(output_worker(
            stdout_pipe,
            out_source,
            Arc::clone(&output_fault),
        )?);
        workers.push(output_worker(
            stderr_pipe,
            err_source,
            Arc::clone(&output_fault),
        )?);
        workers.push(input_worker(stdin_pipe, tx)?);
        Ok::<(), io::Error>(())
    })();
    if let Err(error) = setup {
        for output in &outputs {
            output.close();
        }
        for worker in workers {
            worker.stop.cancel();
            let _ = worker.join.join();
        }
        return Err(setup_error(error));
    }

    // No remote process has been admitted before pipes and workers are ready.
    let connected = connect_exec(&target);
    let mut stream = match connected {
        Ok(stream) => stream,
        Err(error) => {
            for output in &outputs {
                output.close();
            }
            for worker in workers {
                worker.stop.cancel();
                let _ = worker.join.join();
            }
            return Err(error);
        }
    };
    let socket = match stream.socket().try_clone() {
        Ok(socket) => socket,
        Err(error) => {
            for output in &outputs {
                output.close();
            }
            for worker in workers {
                worker.stop.cancel();
                let _ = worker.join.join();
            }
            return Err(setup_error(error));
        }
    };
    let control = Arc::new(Control {
        socket,
        cancelled: Arc::new(AtomicBool::new(false)),
        terminal: AtomicBool::new(false),
        outputs,
        workers: workers
            .iter()
            .map(|worker| Arc::clone(&worker.stop))
            .collect(),
        relay: Mutex::new(None),
    });
    // A failed post-upgrade send is an unknown execution outcome, never an exit.
    if let Err(error) = stream.write_all(&start_frame).and_then(|()| stream.flush()) {
        control.stop();
        for worker in workers {
            let _ = worker.join.join();
        }
        return Err(failure(
            "exec_transport",
            format!("send EXEC_START: {error}"),
        ));
    }
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let supervisor_control = Arc::downgrade(&control);
    let cancellation = Arc::clone(&control.cancelled);
    let worker_slot = Arc::new(Mutex::new(Some(workers)));
    let relay_workers = Arc::clone(&worker_slot);
    let spawned = thread::Builder::new()
        .name("w365-relay".into())
        .spawn(move || {
            let Some(workers) = relay_workers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
            else {
                let _ = done_tx.send(Err(failure(
                    "exec_worker",
                    "W365 workers were already consumed",
                )));
                return;
            };
            let result = consume(
                &mut stream,
                rx,
                &out,
                &err,
                &cancellation,
                &output_fault,
                start.client_budget,
            )
            .and_then(|code| truncated(code, &out_overflow, &err_overflow));
            let _ = stream.socket().shutdown(Shutdown::Both);
            drop(stream);
            out.close();
            err.close();
            if let Some(input) = workers.last() {
                input.stop.cancel();
            }
            if let Some(control) = supervisor_control.upgrade() {
                control.terminal.store(true, Ordering::Release);
            }
            let _ = done_tx.send(result);
            // Completion is independent of output backpressure, but these workers
            // remain owned until each caller-owned pipe drains or closes.
            for worker in workers {
                let _ = worker.join.join();
            }
        });
    let relay = match spawned {
        Ok(relay) => relay,
        Err(error) => {
            control.stop();
            if let Some(workers) = worker_slot.lock().unwrap_or_else(|e| e.into_inner()).take() {
                for worker in workers {
                    let _ = worker.join.join();
                }
            }
            return Err(failure(
                "exec_worker",
                format!("start W365 relay worker: {error}"),
            ));
        }
    };
    *control.relay.lock().unwrap_or_else(|e| e.into_inner()) = Some(relay);

    let stdout = raw(&stdout_reader);
    let stderr = raw(&stderr_reader);
    let stdin = raw(&stdin_writer);
    let input = Arc::new(Mutex::new(Some(stdin_writer)));
    let closer = Arc::clone(&input);
    let wait_control = Arc::clone(&control);
    Ok(ExecHandle {
        stdout,
        stderr,
        stdin,
        stdin_closer: Some(Box::new(move || {
            closer.lock().unwrap_or_else(|e| e.into_inner()).take();
        })),
        waiter: Box::new(move || {
            let _originals = (stdout_reader, stderr_reader, input, wait_control);
            done_rx
                .recv()
                .map_err(|_| failure("exec_worker", "W365 relay ended without an outcome"))?
        }),
        terminator: Box::new(move || {
            control.stop();
            Err(failure(
                "remote_termination_unsupported",
                "W365 relay closed locally; remote process termination is not confirmed. Release the reservation explicitly.",
            ))
        }),
    })
}

fn setup_error(error: io::Error) -> MxcError {
    MxcError::backend_error(format!("set up W365 execution pipes: {error}"))
}

fn truncated(
    code: i32,
    stdout: &StreamOverflow,
    stderr: &StreamOverflow,
) -> Result<ExecOutcome, MxcError> {
    if stdout.has_overflowed() || stderr.has_overflowed() {
        return Err(failure(
            "output_truncated",
            "W365 execution output exceeded the pending-byte limit; output was truncated",
        )
        .with_details(serde_json::json!({
            "code": "output_truncated", "exitCode": code,
            "stdoutTruncated": stdout.has_overflowed(),
            "stderrTruncated": stderr.has_overflowed(),
            "pendingByteLimit": MAX_PENDING_BYTES
        })));
    }
    Ok(ExecOutcome::Exited(code))
}

fn consume(
    stream: &mut ExecConnection,
    input: mpsc::Receiver<Input>,
    out: &StreamWriter,
    err: &StreamWriter,
    cancelled: &AtomicBool,
    output_fault: &Mutex<Option<io::Error>>,
    budget: Duration,
) -> Result<i32, MxcError> {
    let mut accumulator = FrameAccumulator::new();
    let mut bytes = [0; 16 * 1024];
    let mut stdin_open = true;
    let mut started = false;
    let deadline = Instant::now() + budget;
    loop {
        if Instant::now() >= deadline {
            return Err(failure(
                "exec_client_timeout",
                "local execution budget expired without Exit; remote outcome is unknown",
            ));
        }
        if let Some(error) = output_fault
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            return Err(failure(
                "output_io",
                format!("write W365 output pipe: {error}"),
            ));
        }
        if cancelled.load(Ordering::Acquire) {
            return Err(failure(
                "exec_disposed",
                "W365 execution relay was closed locally; remote outcome is unknown",
            ));
        }
        match stream.read(&mut bytes) {
            Ok(0) => {
                return Err(failure(
                    "exec_transport",
                    "W365 transport closed before EXIT; execution outcome is unknown",
                ))
            }
            Ok(count) => accumulator.extend(&bytes[..count]),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                thread::sleep(POLL);
            }
            Err(error) => {
                return Err(failure(
                    "exec_transport",
                    format!("read W365 execution: {error}"),
                ))
            }
        }
        while let Some(frame) = accumulator
            .next_frame()
            .map_err(|error| failure("exec_protocol", error.message))?
        {
            match frame.kind {
                Some(FrameType::Started) if !started => {
                    parse_started(&frame.payload)
                        .map_err(|error| failure("exec_protocol", error.message))?;
                    started = true;
                }
                Some(FrameType::Stdout) if started => out.write(&frame.payload),
                Some(FrameType::Stderr) if started => err.write(&frame.payload),
                Some(FrameType::Exit) if started => {
                    return parse_exit(&frame.payload)
                        .map(|exit| exit.exit_code)
                        .map_err(|error| failure("exec_protocol", error.message))
                }
                Some(FrameType::Error) => {
                    let error = parse_error(&frame.payload)
                        .map_err(|error| failure("exec_protocol", error.message))?;
                    return Err(failure(
                        "remote_exec_error",
                        format!("W365 remote execution failed: {}", error.message),
                    )
                    .with_details(serde_json::json!({
                        "code":"remote_exec_error", "remoteCode":error.code,
                        "possiblySucceeded":true, "outcomeUnknown":true
                    })));
                }
                _ => {
                    return Err(failure(
                        "exec_protocol",
                        format!("unexpected W365 frame type {}", frame.raw_kind),
                    ))
                }
            }
        }
        // Read terminal frames before sending more input: a process may exit
        // without consuming stdin. One input chunk per read keeps EXIT fair.
        if stdin_open && started {
            let frame = match input.try_recv() {
                Ok(Input::Bytes(bytes)) => Some(encode_frame(FrameType::Stdin, &bytes)),
                Ok(Input::Eof) | Err(mpsc::TryRecvError::Disconnected) => {
                    stdin_open = false;
                    Some(encode_frame(FrameType::StdinClose, b""))
                }
                Ok(Input::Error(error)) => {
                    return Err(failure(
                        "stdin_io",
                        format!("read W365 stdin pipe: {error}"),
                    ))
                }
                Err(mpsc::TryRecvError::Empty) => None,
            };
            if let Some(frame) = frame {
                stream
                    .write_all(&frame)
                    .and_then(|()| stream.flush())
                    .map_err(|error| {
                        failure("exec_transport", format!("send W365 stdin: {error}"))
                    })?;
            }
        }
    }
}
