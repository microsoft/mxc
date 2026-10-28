// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Collects the run's tagged Seatbelt reports from the macOS unified log.
//!
//! `log stream` only shows events logged after it attaches, so the collector
//! triggers a tagged marker deny and waits to see it before the workload
//! starts, and again after the workload exits to drain late events.

use std::ffi::CString;
use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::seatbelt_common::capture_analysis::{
    parse_stream_line, CaptureMarker, SandboxLogEvent, StreamLine,
};
use crate::seatbelt_common::seatbelt_runner::apply_profile_before_exec;

const LOG_TOOL: &str = "/usr/bin/log";
const MARKER_PROBE: &str = "/bin/ls";
// Must exist: Seatbelt does not report lookups of missing paths.
const MARKER_TARGET: &str = "/private/var/empty";
const READY_TIMEOUT: Duration = Duration::from_secs(10);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const MARKER_RETRY: Duration = Duration::from_millis(250);
const MAX_LINE_BYTES: usize = 64 * 1024;
const MAX_STDERR_BYTES: u64 = 4 * 1024;
/// Upper bound on retained raw events; later events only set the truncation flag.
pub(crate) const MAX_CAPTURED_EVENTS: usize = 100_000;

/// Raw events collected for one run.
#[derive(Debug, Default)]
pub(crate) struct CollectedEvents {
    pub(crate) events: Vec<SandboxLogEvent>,
    pub(crate) events_truncated: bool,
    /// False when the closing marker was not seen, so late events may be missing.
    pub(crate) drained: bool,
}

#[derive(Default)]
struct State {
    events: Vec<SandboxLogEvent>,
    events_truncated: bool,
    ready: bool,
    done: bool,
    ended: bool,
}

impl State {
    fn seen(&self, marker: CaptureMarker) -> bool {
        match marker {
            CaptureMarker::Ready => self.ready,
            CaptureMarker::Done => self.done,
        }
    }
}

#[derive(Default)]
struct Shared {
    state: Mutex<State>,
    changed: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// A running `log stream` filtered to one run's capture tag.
pub(crate) struct DenialCollector {
    tag: String,
    child: Option<Child>,
    stdout_reader: Option<JoinHandle<()>>,
    stderr_reader: Option<JoinHandle<String>>,
    shared: Arc<Shared>,
}

impl DenialCollector {
    /// Starts `log stream` and returns once it is confirmed to be receiving
    /// this run's tagged Seatbelt reports.
    pub(crate) fn start(tag: &str) -> Result<Self, String> {
        let mut child = Command::new(LOG_TOOL)
            .args(["stream", "--style", "ndjson", "--predicate"])
            .arg(stream_predicate(tag))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("captureDenials could not start '{LOG_TOOL} stream': {e}"))?;

        let shared = Arc::new(Shared::default());
        let stdout = child.stdout.take().expect("stdout is piped");
        let stderr = child.stderr.take().expect("stderr is piped");
        let stdout_reader = {
            let shared = Arc::clone(&shared);
            let tag = tag.to_string();
            std::thread::spawn(move || read_stream(BufReader::new(stdout), &tag, &shared))
        };
        let stderr_reader = std::thread::spawn(move || {
            let mut text = String::new();
            let mut limited = stderr.take(MAX_STDERR_BYTES);
            let _ = limited.read_to_string(&mut text);
            // Keep draining so `log` never blocks on a full stderr pipe.
            let _ = std::io::copy(&mut limited.into_inner(), &mut std::io::sink());
            text
        });

        let mut collector = Self {
            tag: tag.to_string(),
            child: Some(child),
            stdout_reader: Some(stdout_reader),
            stderr_reader: Some(stderr_reader),
            shared,
        };
        match collector.wait_for_marker(CaptureMarker::Ready, READY_TIMEOUT) {
            Ok(true) => Ok(collector),
            Ok(false) => {
                let stderr = collector.stop();
                Err(with_log_stderr(
                    format!(
                        "captureDenials could not confirm within {}s that '{LOG_TOOL} stream' \
                         receives Seatbelt reports",
                        READY_TIMEOUT.as_secs()
                    ),
                    &stderr,
                ))
            }
            Err(error) => {
                let stderr = collector.stop();
                Err(with_log_stderr(error, &stderr))
            }
        }
    }

    /// Waits for late events, stops `log stream`, and returns what it captured.
    pub(crate) fn finish(mut self) -> Result<CollectedEvents, String> {
        let drained = self.wait_for_marker(CaptureMarker::Done, DRAIN_TIMEOUT);
        let stderr = self.stop();
        let drained = drained.map_err(|error| with_log_stderr(error, &stderr))?;
        let mut state = self.shared.lock();
        Ok(CollectedEvents {
            events: std::mem::take(&mut state.events),
            events_truncated: state.events_truncated,
            drained,
        })
    }

    /// Repeats the marker until the stream reports it. `Ok(false)` means the
    /// timeout passed; `Err` means `log stream` exited.
    fn wait_for_marker(&self, marker: CaptureMarker, timeout: Duration) -> Result<bool, String> {
        let deadline = Instant::now() + timeout;
        loop {
            emit_marker(&self.tag, marker)?;
            let wait = deadline
                .saturating_duration_since(Instant::now())
                .min(MARKER_RETRY);
            let (state, _) = self
                .shared
                .changed
                .wait_timeout_while(self.shared.lock(), wait, |state| {
                    !state.seen(marker) && !state.ended
                })
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.seen(marker) {
                return Ok(true);
            }
            if state.ended {
                return Err(format!("'{LOG_TOOL} stream' exited unexpectedly"));
            }
            drop(state);
            if Instant::now() >= deadline {
                return Ok(false);
            }
        }
    }

    /// Kills and reaps `log stream`, returning its captured stderr.
    fn stop(&mut self) -> String {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(reader) = self.stdout_reader.take() {
            let _ = reader.join();
        }
        self.stderr_reader
            .take()
            .and_then(|reader| reader.join().ok())
            .unwrap_or_default()
    }
}

impl Drop for DenialCollector {
    fn drop(&mut self) {
        self.stop();
    }
}

fn stream_predicate(tag: &str) -> String {
    format!(r#"sender == "Sandbox" AND eventMessage CONTAINS "{tag}""#)
}

fn read_stream(mut reader: impl BufRead, tag: &str, shared: &Shared) {
    let mut line = Vec::new();
    loop {
        line.clear();
        let limit = MAX_LINE_BYTES as u64 + 1;
        match (&mut reader).take(limit).read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        if line.len() > MAX_LINE_BYTES {
            if !line.ends_with(b"\n") && skip_line(&mut reader).is_err() {
                break;
            }
            shared.lock().events_truncated = true;
            continue;
        }
        let parsed = parse_stream_line(&String::from_utf8_lossy(&line), tag);
        let mut state = shared.lock();
        match parsed {
            StreamLine::Marker(CaptureMarker::Ready) => state.ready = true,
            StreamLine::Marker(CaptureMarker::Done) => state.done = true,
            StreamLine::Event(event) if state.events.len() < MAX_CAPTURED_EVENTS => {
                state.events.push(event);
            }
            StreamLine::Event(_) => state.events_truncated = true,
            StreamLine::Ignored => continue,
        }
        shared.changed.notify_all();
    }
    shared.lock().ended = true;
    shared.changed.notify_all();
}

fn skip_line(reader: &mut impl BufRead) -> std::io::Result<()> {
    loop {
        let buf = reader.fill_buf()?;
        if buf.is_empty() {
            return Ok(());
        }
        if let Some(end) = buf.iter().position(|&b| b == b'\n') {
            reader.consume(end + 1);
            return Ok(());
        }
        let len = buf.len();
        reader.consume(len);
    }
}

/// Runs a short sandboxed probe whose only effect is one tagged deny report.
fn emit_marker(tag: &str, marker: CaptureMarker) -> Result<(), String> {
    let profile = format!(
        r#"(version 1)(allow default)(deny file-read-metadata (with message "{tag}:{}") (literal "{MARKER_TARGET}"))"#,
        marker.as_str()
    );
    let profile = CString::new(profile)
        .map_err(|_| "captureDenials marker profile contains a NUL byte".to_string())?;
    let mut command = Command::new(MARKER_PROBE);
    command
        .args(["-d", MARKER_TARGET])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    apply_profile_before_exec(&mut command, profile);
    command
        .status()
        .map(|_| ())
        .map_err(|e| format!("captureDenials could not run its log marker probe: {e}"))
}

fn with_log_stderr(message: String, stderr: &str) -> String {
    let stderr = stderr.trim();
    if stderr.is_empty() {
        message
    } else {
        format!("{message}: {stderr}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_line_is_skipped_and_flagged() {
        let tag = "mxc-capture-linetest";
        let event = serde_json::json!({
            "eventMessage": format!("Sandbox: cat(7) deny(1) file-read-data /x\n{tag}"),
        });
        let input = format!("{}\n{event}\n", "a".repeat(MAX_LINE_BYTES * 2));
        let shared = Shared::default();
        read_stream(std::io::Cursor::new(input), tag, &shared);
        let state = shared.lock();
        assert!(state.events_truncated);
        assert_eq!(state.events.len(), 1);
        assert!(state.ended);
    }

    #[test]
    fn collector_sees_tagged_deny_and_drains() {
        let tag = "mxc-capture-collectortest";
        let collector = match DenialCollector::start(tag) {
            Ok(collector) => collector,
            Err(error) => panic!("log stream unavailable on this host: {error}"),
        };
        let profile = format!(
            r#"(version 1)(allow default)(deny file-read-data (with message "{tag}") (literal "/private/etc/hosts"))"#
        );
        let mut command = Command::new("/bin/cat");
        command
            .arg("/private/etc/hosts")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        apply_profile_before_exec(&mut command, CString::new(profile).unwrap());
        assert!(!command.status().unwrap().success());

        let collected = collector.finish().unwrap();
        assert!(collected.drained);
        assert!(
            collected.events.iter().any(|event| event
                .message
                .contains("deny(1) file-read-data /private/etc/hosts")
                || event.message.contains("deny(1) file-read-data /etc/hosts")),
            "events: {:?}",
            collected.events
        );
    }
}
