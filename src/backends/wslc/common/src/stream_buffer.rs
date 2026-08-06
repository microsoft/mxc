// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! An in-memory byte stream connecting the WSLC SDK's output callbacks to a
//! caller reading them live.
//!
//! The SDK hands us output as callback invocations on its own threads, not as a
//! pipe end, so the streaming path needs somewhere to put those bytes until the
//! caller reads them.
//!
//! The queue is **unbounded on purpose**. Applying backpressure would mean
//! blocking an SDK callback thread, and that thread is the one that also
//! delivers the process-exit callback the teardown path waits for — a full
//! buffer would deadlock shutdown. Unread output is therefore bounded only by
//! what the container writes, the same exposure the run-to-completion path
//! already has (it buffers every byte until exit).

use std::collections::VecDeque;
use std::io::Read;
use std::sync::{Arc, Condvar, Mutex};

use wxc_common::sandbox_process::StreamCloser;

#[derive(Default)]
struct State {
    buffer: VecDeque<u8>,
    /// No more bytes will arrive (the process exited, or teardown ran).
    closed: bool,
    /// A [`StreamCanceller`] fired: reads report EOF without draining.
    cancelled: bool,
}

struct Shared {
    state: Mutex<State>,
    /// Signalled when bytes arrive or the stream is closed/cancelled.
    ready: Condvar,
}

impl Shared {
    /// Lock the state, tolerating poisoning: it is a byte queue and two flags,
    /// with no invariant a panicking holder could break.
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Create a connected writer / reader pair.
pub(crate) fn stream_pair() -> (StreamWriter, StreamReader) {
    let shared = Arc::new(Shared {
        state: Mutex::new(State::default()),
        ready: Condvar::new(),
    });
    (StreamWriter(Arc::clone(&shared)), StreamReader(shared))
}

/// The producing end, written from the SDK's callback threads. Never blocks.
pub(crate) struct StreamWriter(Arc<Shared>);

impl StreamWriter {
    /// Append one callback chunk and wake a parked reader.
    ///
    /// Bytes are dropped once the stream is closed or cancelled: after either,
    /// no read can observe them, so queueing them would grow the buffer with
    /// nothing to drain it.
    pub(crate) fn write(&self, bytes: &[u8]) {
        let mut state = self.0.lock();
        if state.closed || state.cancelled {
            return;
        }
        state.buffer.extend(bytes);
        self.0.ready.notify_all();
    }

    /// Signal end of stream, so a reader sees EOF once it has drained what is
    /// already buffered. Idempotent.
    pub(crate) fn close(&self) {
        let mut state = self.0.lock();
        state.closed = true;
        self.0.ready.notify_all();
    }
}

/// The consuming end, handed to the caller as the sandbox's stdout/stderr.
pub(crate) struct StreamReader(Arc<Shared>);

impl StreamReader {
    /// Mint a closer that EOFs this reader's `read` on demand — the
    /// [`StreamCloser`] behind
    /// [`SandboxProcess::stdout_closer`](wxc_common::sandbox_process::SandboxProcess::stdout_closer).
    pub(crate) fn canceller(&self) -> StreamCanceller {
        StreamCanceller(Arc::clone(&self.0))
    }
}

impl Read for StreamReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // The `Read` contract: a zero-length read returns immediately rather
        // than parking until bytes arrive.
        if buf.is_empty() {
            return Ok(0);
        }
        let mut state = self.0.lock();
        while state.buffer.is_empty() && !state.closed && !state.cancelled {
            state = self.0.ready.wait(state).unwrap_or_else(|e| e.into_inner());
        }
        // Cancellation wins over buffered bytes so an abandoned stream ends
        // promptly, matching the Unix `InterruptibleReader`.
        if state.cancelled {
            return Ok(0);
        }
        // `VecDeque<u8>` is itself a `Read`, and consumes what it hands over.
        state.buffer.read(buf)
    }
}

/// A [`StreamCloser`] for a [`StreamReader`]. `Send + Sync` and cloneable, so a
/// watchdog thread can hold and fire one while another thread is parked in
/// `read`; `close` is idempotent.
#[derive(Clone)]
pub(crate) struct StreamCanceller(Arc<Shared>);

impl StreamCloser for StreamCanceller {
    fn close(&self) {
        abandon(&self.0);
    }
}

/// Mark a stream abandoned: no read can observe it again, so stop queueing and
/// release whatever is buffered. Shared by [`StreamCanceller::close`] and
/// [`StreamReader`]'s `Drop`, which mean the same thing to the writer side.
fn abandon(shared: &Arc<Shared>) {
    let mut state = shared.lock();
    state.cancelled = true;
    // The caller has abandoned this stream, so anything still queued is
    // unreachable — release it rather than hold it for the container's life.
    state.buffer = VecDeque::new();
    shared.ready.notify_all();
}

impl Drop for StreamReader {
    /// Dropping the reader abandons the stream. Without this, a caller that
    /// takes stdout/stderr and then drops it leaves the queue with no consumer
    /// — and `WslcSandboxProcess::wait` no longer drains a *taken* stream — so
    /// the callback side would append to this unbounded buffer for the life of
    /// the container.
    fn drop(&mut self) {
        abandon(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn reads_buffered_bytes_then_eof_on_close() {
        let (writer, mut reader) = stream_pair();
        writer.write(b"hello");
        writer.close();

        let mut buf = [0u8; 16];
        let n = reader.read(&mut buf).expect("read data");
        assert_eq!(&buf[..n], b"hello");
        assert_eq!(reader.read(&mut buf).expect("read eof"), 0);
    }

    #[test]
    fn read_returns_what_fits_and_keeps_the_rest() {
        let (writer, mut reader) = stream_pair();
        writer.write(b"abcdef");
        writer.close();

        let mut buf = [0u8; 4];
        assert_eq!(reader.read(&mut buf).expect("first read"), 4);
        assert_eq!(&buf, b"abcd");
        let n = reader.read(&mut buf).expect("second read");
        assert_eq!(&buf[..n], b"ef");
    }

    #[test]
    fn read_parks_until_bytes_arrive() {
        let (writer, mut reader) = stream_pair();
        let producer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            writer.write(b"late");
            writer.close();
        });

        let mut buf = [0u8; 16];
        let n = reader.read(&mut buf).expect("read data");
        assert_eq!(&buf[..n], b"late");
        producer.join().expect("producer");
    }

    #[test]
    fn cancel_releases_buffered_bytes_and_drops_later_writes() {
        // Once abandoned, no read can observe the stream again, so nothing may
        // stay queued (or be queued) for the container's remaining life.
        let (writer, reader) = stream_pair();
        writer.write(b"buffered");
        reader.canceller().close();
        assert!(reader.0.lock().buffer.is_empty(), "queued bytes released");

        writer.write(b"later");
        assert!(reader.0.lock().buffer.is_empty(), "later writes dropped");
    }

    #[test]
    fn write_never_blocks_on_an_unread_stream() {
        // The core invariant: an SDK callback thread must never be stalled by a
        // caller that isn't reading, since that same thread delivers the exit
        // callback teardown waits on. Nothing drains this stream at all.
        let (writer, _reader) = stream_pair();
        let start = Instant::now();
        for _ in 0..16 {
            writer.write(&[0u8; 256 * 1024]);
        }
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "writes must not block on an unread stream, took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn dropping_the_reader_stops_the_writer_queueing() {
        // A caller that takes stdout/stderr and drops it leaves no consumer,
        // and `wait` does not drain a taken stream — so the writer must stop
        // queueing rather than grow the unbounded buffer for the container's
        // remaining life.
        let (writer, reader) = stream_pair();
        let probe = reader.canceller(); // shares the state so we can inspect it
        writer.write(b"queued");
        drop(reader);

        assert!(probe.0.lock().buffer.is_empty(), "queued bytes released");
        writer.write(&[0u8; 64 * 1024]);
        assert!(
            probe.0.lock().buffer.is_empty(),
            "writes after the reader is dropped must not queue"
        );
    }

    #[test]
    fn cancel_unblocks_a_parked_read() {
        // The writer stays open and never writes, so a plain read would park
        // forever; the canceller must EOF it promptly. Deliberately no write
        // here — a write would legitimately wake the reader with data, which
        // says nothing about cancellation.
        let (_writer, mut reader) = stream_pair();
        let canceller = reader.canceller();

        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 16];
            let start = Instant::now();
            let n = reader.read(&mut buf).expect("read returns");
            (n, start.elapsed())
        });

        std::thread::sleep(Duration::from_millis(50));
        canceller.close();
        canceller.close(); // idempotent

        let (n, elapsed) = handle.join().expect("reader thread");
        assert_eq!(n, 0, "cancelled read reports EOF");
        assert!(
            elapsed < Duration::from_secs(5),
            "read should return promptly after close, took {elapsed:?}"
        );
    }
}
