// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Writes an exec's stdin on a thread of its own, because a write to a process
//! that is not reading blocks until it reads or exits.

use std::fs::File;
use std::io::{ErrorKind, Write};
use std::os::windows::io::AsRawHandle;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use mxc_sdk::wslc_common::container_steps::StdinControl;
use tokio::sync::mpsc;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::IO::CancelIoEx;

#[derive(Debug)]
pub enum StdinEnd {
    /// Every chunk was written.
    Closed,

    /// [`StdinStop::stop`] ended the writer before its input was finished.
    Stopped,

    /// The process stopped reading before its input was finished.
    ReaderGone,
    Failed(std::io::Error),
}

struct Shared {
    stdin: File,
    gate: Mutex<Gate>,
    write_done: Condvar,
    interrupted: Box<dyn Fn() -> bool + Send + Sync>,
}

/// Lets [`StdinStop::stop`] tell whether a write is in progress, since
/// cancelling I/O affects only a write that has already started.
#[derive(Default)]
struct Gate {
    stopped: bool,
    writing: bool,
    frozen: bool,
}

impl Shared {
    fn gate(&self) -> MutexGuard<'_, Gate> {
        self.gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

pub struct StdinWriter(Arc<Shared>);

/// Closes an exec's stdin early, whatever its writer is doing.
pub struct StdinStop {
    shared: Weak<Shared>,
    wake: mpsc::WeakSender<Vec<u8>>,
}

/// Pair a writer for `stdin` with the handle that stops it, where `wake`
/// belongs to the channel the writer will drain and `interrupted` reports
/// whether the exec was cancelled.
pub fn stdin_writer(
    stdin: File,
    wake: mpsc::WeakSender<Vec<u8>>,
    interrupted: impl Fn() -> bool + Send + Sync + 'static,
) -> (StdinWriter, StdinStop) {
    let shared = Arc::new(Shared {
        stdin,
        gate: Mutex::new(Gate::default()),
        write_done: Condvar::new(),
        interrupted: Box::new(interrupted),
    });
    let stop = StdinStop {
        shared: Arc::downgrade(&shared),
        wake,
    };
    (StdinWriter(shared), stop)
}

/// Write each chunk to `stdin` on a new thread, closing it once an empty chunk
/// marks end-of-file or the returned handle stops it, and passing a write that
/// fails for any reason but the process no longer reading to `on_failure`.
pub fn spawn(
    stdin: File,
    chunks: mpsc::Receiver<Vec<u8>>,
    wake: mpsc::WeakSender<Vec<u8>>,
    interrupted: impl Fn() -> bool + Send + Sync + 'static,
    on_failure: impl FnOnce(std::io::Error) + Send + 'static,
) -> std::io::Result<StdinStop> {
    let (writer, stop) = stdin_writer(stdin, wake, interrupted);
    std::thread::Builder::new()
        .name("wslc-exec-stdin".to_string())
        .spawn(move || {
            let mut chunks = chunks;
            if let StdinEnd::Failed(error) = writer.write_all(&mut chunks) {
                eprintln!("[wslc-daemon] writing exec stdin failed: {error}");
                on_failure(error);

                // Closing stdin now would let the process take what was
                // written as its whole input before the exec is cancelled.
                writer.wait_until_stopped();
            }
        })?;
    Ok(stop)
}

impl StdinWriter {
    /// Write each chunk until an empty chunk marks end-of-file or the writer is
    /// stopped, then close stdin.
    #[cfg(test)]
    fn run(self, mut chunks: mpsc::Receiver<Vec<u8>>) -> StdinEnd {
        self.write_all(&mut chunks)
    }

    fn write_all(&self, chunks: &mut mpsc::Receiver<Vec<u8>>) -> StdinEnd {
        let shared = &self.0;
        loop {
            // Input that ends without end-of-file is cut short, so stdin stays
            // open until the exec decides the process no longer needs it.
            let Some(chunk) = chunks.blocking_recv() else {
                self.wait_until_stopped();
                return StdinEnd::Stopped;
            };
            {
                let mut gate = shared.gate();
                if gate.stopped {
                    return StdinEnd::Stopped;
                }

                // Input reaching an exec that has timed out or been cancelled
                // is cut short, so the process gets none of it, not even
                // end-of-file.
                if gate.frozen || (shared.interrupted)() {
                    drop(gate);
                    self.wait_until_stopped();
                    return StdinEnd::Stopped;
                }
                if chunk.is_empty() {
                    return StdinEnd::Closed;
                }
                gate.writing = true;
            }
            let written = (&shared.stdin).write_all(&chunk);
            let stopped = {
                let mut gate = shared.gate();
                gate.writing = false;
                shared.write_done.notify_all();
                gate.stopped
            };
            if stopped {
                return StdinEnd::Stopped;
            }
            if let Err(error) = written {
                return if is_reader_gone(&error) {
                    StdinEnd::ReaderGone
                } else {
                    StdinEnd::Failed(error)
                };
            }
        }
    }

    fn wait_until_stopped(&self) {
        let mut gate = self.0.gate();
        while !gate.stopped {
            gate = self
                .0
                .write_done
                .wait(gate)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }
}

impl StdinStop {
    /// Make the writer pass on nothing more, not even end-of-file, while
    /// leaving stdin open.
    pub fn freeze(&self) {
        if let Some(shared) = self.shared.upgrade() {
            shared.gate().frozen = true;
        }
    }

    /// Make the writer close stdin now, dropping input it has not written.
    pub fn stop(self) {
        let Some(shared) = self.shared.upgrade() else {
            return;
        };
        shared.gate().stopped = true;
        shared.write_done.notify_all();

        // An idle writer wakes on this empty chunk and sees `stopped` before it
        // could take the chunk for end-of-file.
        if let Some(wake) = self.wake.upgrade() {
            let _ = wake.try_send(Vec::new());
        }

        let handle = HANDLE(shared.stdin.as_raw_handle());
        let deadline = Instant::now() + STOP_WRITE_WAIT;
        let mut gate = shared.gate();
        while gate.writing {
            let now = Instant::now();
            if now >= deadline {
                eprintln!(
                    "[wslc-daemon] an exec's stdin write ignored cancellation for \
                     {STOP_WRITE_WAIT:?}; its writer thread is left to finish on its own"
                );
                return;
            }

            // SAFETY: `shared` keeps the handle open for this call; cancelling
            // another thread's synchronous write on it is supported.
            unsafe {
                let _ = CancelIoEx(handle, None);
            }

            // A cancellation issued before the write reaches the kernel finds
            // nothing to cancel, so it is repeated until the write returns.
            gate = shared
                .write_done
                .wait_timeout(gate, CANCEL_RETRY_INTERVAL.min(deadline - now))
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .0;
        }
    }
}

/// How long [`StdinStop::stop`] keeps cancelling a write that has not
/// returned, so a handle that ignores cancellation cannot hold up the exec.
const STOP_WRITE_WAIT: Duration = Duration::from_secs(5);

impl StdinControl for StdinStop {
    fn freeze(&self) {
        StdinStop::freeze(self);
    }

    fn close(self: Box<Self>) {
        self.stop();
    }
}

const CANCEL_RETRY_INTERVAL: Duration = Duration::from_millis(10);

fn is_reader_gone(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::BrokenPipe | ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::windows::io::FromRawHandle;

    use windows::Win32::System::Pipes::CreatePipe;

    /// An anonymous pipe as `(reader, writer)`, with a small buffer so a reader
    /// that stops draining stalls the writer quickly.
    fn pipe() -> (File, File) {
        let mut read = HANDLE::default();
        let mut write = HANDLE::default();

        // SAFETY: both out pointers are valid locals.
        unsafe { CreatePipe(&mut read, &mut write, None, 4096) }.expect("CreatePipe");

        // SAFETY: CreatePipe returned two fresh handles that nothing else owns.
        unsafe {
            (
                File::from_raw_handle(read.0),
                File::from_raw_handle(write.0),
            )
        }
    }

    /// Read `reader` to end-of-file on another thread, failing if that takes
    /// longer than a writer that is working correctly could.
    fn read_to_end_within(mut reader: File, limit: Duration) -> Vec<u8> {
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut received = Vec::new();
            let _ = reader.read_to_end(&mut received);
            let _ = done_tx.send(received);
        });
        done_rx
            .recv_timeout(limit)
            .expect("the reader never saw end-of-file")
    }

    #[test]
    fn every_chunk_arrives_and_the_reader_then_sees_end_of_file() {
        let (mut reader, writer) = pipe();
        let (tx, rx) = mpsc::channel(4);
        let (writer, _stop) = stdin_writer(writer, tx.downgrade(), never_interrupted);
        let expected: Vec<u8> = (0..=255u8).cycle().take(200_000).collect();
        let chunks: Vec<Vec<u8>> = expected.chunks(7_000).map(<[u8]>::to_vec).collect();

        let writing = std::thread::spawn(move || writer.run(rx));
        let sending = std::thread::spawn(move || {
            for chunk in chunks {
                tx.blocking_send(chunk).expect("writer is receiving");
            }
            tx.blocking_send(Vec::new()).expect("writer is receiving");
        });
        let mut received = Vec::new();
        reader.read_to_end(&mut received).expect("read to EOF");

        sending.join().unwrap();
        assert!(matches!(writing.join().unwrap(), StdinEnd::Closed));
        assert_eq!(received, expected);
    }

    #[test]
    fn a_reader_that_stops_draining_stalls_only_its_own_writer() {
        let (_stalled_reader, stalled_writer) = pipe();
        let (stalled_tx, stalled_rx) = mpsc::channel(1);
        let _stalled = spawn(
            stalled_writer,
            stalled_rx,
            stalled_tx.downgrade(),
            never_interrupted,
            |_| {},
        )
        .expect("spawn the stalled writer");
        stalled_tx
            .try_send(vec![0; 1024 * 1024])
            .expect("the first chunk is queued without waiting");

        let (reader, writer) = pipe();
        let (tx, rx) = mpsc::channel(2);
        let _stop = spawn(writer, rx, tx.downgrade(), never_interrupted, |_| {})
            .expect("spawn the second writer");
        tx.try_send(b"still flowing".to_vec()).unwrap();
        tx.try_send(Vec::new()).unwrap();

        assert_eq!(
            read_to_end_within(reader, Duration::from_secs(10)),
            b"still flowing",
            "a second exec's stdin must not wait on a stalled one"
        );
    }

    #[test]
    fn input_that_ends_without_end_of_file_leaves_stdin_open_until_stopped() {
        let (reader, writer) = pipe();
        let (tx, rx) = mpsc::channel(1);
        let stop =
            spawn(writer, rx, tx.downgrade(), never_interrupted, |_| {}).expect("spawn the writer");
        let held = stop.shared.clone();
        tx.try_send(b"partial".to_vec()).unwrap();
        drop(tx);

        // Give a writer that wrongly takes a closed channel for end-of-file
        // time to close stdin.
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            held.upgrade().is_some(),
            "input cut short must not reach the process as end-of-file"
        );

        stop.stop();
        assert_eq!(
            read_to_end_within(reader, Duration::from_secs(10)),
            b"partial"
        );
    }

    fn never_interrupted() -> bool {
        false
    }

    /// Send `partial`, interrupt the exec with `interrupt`, then send more input
    /// and end-of-file, and check that stdin stays open and the process got
    /// only `partial`.
    fn assert_interruption_freezes_stdin(
        interrupted: Arc<std::sync::atomic::AtomicBool>,
        interrupt: impl FnOnce(&StdinStop),
    ) {
        let (reader, writer) = pipe();
        let (tx, rx) = mpsc::channel(4);
        let stop = spawn(
            writer,
            rx,
            tx.downgrade(),
            move || interrupted.load(std::sync::atomic::Ordering::Acquire),
            |_| {},
        )
        .expect("spawn the writer");
        let held = stop.shared.clone();
        let reading =
            std::thread::spawn(move || read_to_end_within(reader, Duration::from_secs(20)));

        tx.blocking_send(b"partial".to_vec()).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        interrupt(&stop);
        tx.blocking_send(b" and the rest".to_vec()).unwrap();
        tx.blocking_send(Vec::new()).unwrap();

        // Give a writer that wrongly passes on input after the interruption
        // time to write it and close stdin.
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            held.upgrade().is_some(),
            "an interrupted exec's process must not get end-of-file"
        );

        stop.stop();
        assert_eq!(reading.join().unwrap(), b"partial");
    }

    #[test]
    fn a_cancelled_exec_passes_on_no_more_input_or_end_of_file() {
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = Arc::clone(&cancelled);
        assert_interruption_freezes_stdin(cancelled, move |_| {
            flag.store(true, std::sync::atomic::Ordering::Release);
        });
    }

    #[test]
    fn a_frozen_writer_passes_on_no_more_input_or_end_of_file() {
        let never = Arc::new(std::sync::atomic::AtomicBool::new(false));
        assert_interruption_freezes_stdin(never, StdinStop::freeze);
    }

    #[test]
    fn a_reader_that_exits_early_is_not_a_failure() {
        let (reader, writer) = pipe();
        drop(reader);
        let (tx, rx) = mpsc::channel(1);
        let (writer, _stop) = stdin_writer(writer, tx.downgrade(), never_interrupted);
        tx.try_send(b"nobody reads this".to_vec()).unwrap();
        drop(tx);

        assert!(matches!(writer.run(rx), StdinEnd::ReaderGone));
    }

    #[test]
    fn a_failed_write_is_reported_and_stdin_held_open_until_the_writer_is_stopped() {
        let path = std::env::temp_dir().join(format!(
            "mxc-stdin-writer-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, b"").unwrap();
        let read_only = File::open(&path).unwrap();
        let (tx, rx) = mpsc::channel(1);
        let (failed_tx, failed_rx) = std::sync::mpsc::channel();
        let stop = spawn(
            read_only,
            rx,
            tx.downgrade(),
            never_interrupted,
            move |error| {
                let _ = failed_tx.send(error.kind());
            },
        )
        .expect("spawn the writer");
        let held = stop.shared.clone();
        tx.try_send(b"lost".to_vec()).unwrap();

        let kind = failed_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("a failed write must be reported");
        assert!(!is_reader_gone(&std::io::Error::from(kind)));

        // Give a writer that wrongly lets go of stdin time to do so.
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            held.upgrade().is_some(),
            "stdin must stay open until the writer is stopped"
        );

        stop.stop();
        let deadline = Instant::now() + Duration::from_secs(10);
        while held.upgrade().is_some() {
            assert!(
                Instant::now() < deadline,
                "stopping the writer must close stdin"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(tx);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn stopping_an_idle_writer_closes_stdin_while_its_sender_lives() {
        let (reader, writer) = pipe();
        let (tx, rx) = mpsc::channel(1);
        let stop =
            spawn(writer, rx, tx.downgrade(), never_interrupted, |_| {}).expect("spawn the writer");

        stop.stop();

        assert!(read_to_end_within(reader, Duration::from_secs(10)).is_empty());
        drop(tx);
    }

    #[test]
    fn stopping_a_writer_blocked_on_a_full_pipe_closes_stdin() {
        let (mut reader, writer) = pipe();
        let (tx, rx) = mpsc::channel(1);
        let (writer, stop) = stdin_writer(writer, tx.downgrade(), never_interrupted);
        let (ended_tx, ended_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = ended_tx.send(writer.run(rx));
        });
        tx.try_send(vec![0; 1024 * 1024]).unwrap();
        let mut first = [0u8; 1];
        reader
            .read_exact(&mut first)
            .expect("the write has started");

        stop.stop();

        let Ok(end) = ended_rx.recv_timeout(Duration::from_secs(10)) else {
            // Drain the pipe so the blocked write can return and the test
            // fails rather than hangs.
            let _ = read_to_end_within(reader, Duration::from_secs(10));
            panic!("stopping the writer did not abandon its blocked write");
        };
        assert!(matches!(end, StdinEnd::Stopped));
        let rest = read_to_end_within(reader, Duration::from_secs(10));
        assert!(rest.len() < 1024 * 1024, "the blocked write was abandoned");
        drop(tx);
    }
}
