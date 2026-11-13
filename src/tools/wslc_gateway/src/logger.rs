// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Best-effort logging to stdout from a separate thread. A stalled or closed
//! stdout drops lines instead of blocking or stopping the gateway.

use std::io::Write;
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const CAPACITY: usize = 1024;
const FLUSH_TIMEOUT: Duration = Duration::from_secs(1);

static LOGGER: OnceLock<Logger> = OnceLock::new();

/// Logs a line. Format workload-supplied text with `{:?}` so it can't
/// forge lines such as `READY`.
macro_rules! log {
    ($($arg:tt)*) => {
        $crate::logger::line(format!($($arg)*))
    };
}

pub fn init() {
    LOGGER.get_or_init(|| Logger::start(std::io::stdout(), CAPACITY));
}

/// Without [`init`], as in unit tests, lines are discarded.
pub fn line(line: String) {
    if let Some(logger) = LOGGER.get() {
        logger.line(line);
    }
}

/// Waits briefly for queued lines to be written, before the process exits.
pub fn flush() {
    if let Some(logger) = LOGGER.get() {
        logger.flush(FLUSH_TIMEOUT);
    }
}

enum Entry {
    Line(String),
    Flush(SyncSender<()>),
}

struct Logger(SyncSender<Entry>);

impl Logger {
    fn start(mut sink: impl Write + Send + 'static, capacity: usize) -> Self {
        let (sender, receiver) = sync_channel(capacity);
        std::thread::spawn(move || {
            for entry in receiver {
                match entry {
                    Entry::Line(line) => {
                        let _ = writeln!(sink, "{line}");
                        let _ = sink.flush();
                    }
                    Entry::Flush(done) => {
                        let _ = done.send(());
                    }
                }
            }
        });
        Self(sender)
    }

    /// Drops the line when the queue is full.
    fn line(&self, line: String) {
        let _ = self.0.try_send(Entry::Line(line));
    }

    fn flush(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let (done, written) = sync_channel(1);
        let mut entry = Entry::Flush(done);
        loop {
            match self.0.try_send(entry) {
                Ok(()) => {
                    return written
                        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                        .is_ok()
                }
                Err(TrySendError::Full(e)) if Instant::now() < deadline => {
                    entry = e;
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::{Arc, Mutex};

    struct Stalled;

    impl Write for Stalled {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            loop {
                std::thread::park();
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct Closed;

    impl Write for Closed {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
    }

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Write for Captured {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_stalled_sink_drops_lines_instead_of_blocking() {
        let logger = Logger::start(Stalled, 4);
        let started = Instant::now();
        for i in 0..10_000 {
            logger.line(format!("line {i}"));
        }
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(!logger.flush(Duration::from_millis(100)));
    }

    #[test]
    fn a_closed_sink_keeps_the_logger_running() {
        let logger = Logger::start(Closed, 4);
        logger.line("lost".to_string());
        assert!(logger.flush(Duration::from_secs(5)));
    }

    #[test]
    fn lines_are_written_in_order() {
        let sink = Captured::default();
        let logger = Logger::start(sink.clone(), 4);
        logger.line("one".to_string());
        logger.line("two".to_string());
        assert!(logger.flush(Duration::from_secs(5)));
        assert_eq!(&*sink.0.lock().unwrap(), b"one\ntwo\n");
    }
}
