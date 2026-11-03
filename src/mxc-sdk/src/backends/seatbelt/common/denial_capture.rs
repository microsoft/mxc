// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Collects the run's tagged Seatbelt reports from the macOS unified log.
//!
//! `log stream` only shows events logged after it attaches, so the collector
//! triggers a tagged marker deny and waits to see it before the workload
//! starts, and again after the workload exits to drain late events.

use std::ffi::CString;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::learning_mode_core::capture_diagnostics::CaptureAnalysis;
use crate::seatbelt_common::capture_analysis::{
    parse_stream_line, CaptureAnalyzer, CaptureMarker, StreamLine,
};
use crate::seatbelt_common::seatbelt_runner::apply_profile_before_exec;

const LOG_TOOL: &str = "/usr/bin/log";
// `log stream` only notices a closed stdout when it next writes, so it would
// outlive a killed MXC. The shell kills it once MXC's end of stdin closes.
const WATCHDOG_SHELL: &str = "/bin/sh";
const WATCHDOG_SCRIPT: &str =
    r#""$@" & pid=$!; exec >/dev/null 2>&1; read _; kill -KILL "$pid"; wait "$pid""#;
const MARKER_PROBE: &str = "/bin/ls";
// Must exist: Seatbelt does not report lookups of missing paths.
const MARKER_TARGET: &str = "/private/var/empty";
const READY_TIMEOUT: Duration = Duration::from_secs(10);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const MARKER_RETRY: Duration = Duration::from_millis(250);
const MAX_LINE_BYTES: usize = 64 * 1024;
const MAX_STDERR_BYTES: u64 = 4 * 1024;
pub(crate) const MAX_TRACE_BYTES: u64 = 1024 * 1024 * 1024;

/// What one run's `log stream` produced.
pub(crate) struct CollectedEvents {
    analyzer: CaptureAnalyzer,
    /// An oversized line was skipped.
    lines_skipped: bool,
    /// False when the closing marker was not seen, so late events may be missing.
    pub(crate) drained: bool,
    /// Why the trace file stopped being written, if it did.
    pub(crate) trace_error: Option<String>,
    /// The trace reached `MAX_TRACE_BYTES` and later lines were not written.
    pub(crate) trace_truncated: bool,
}

impl CollectedEvents {
    pub(crate) fn into_analysis(self) -> CaptureAnalysis {
        self.analyzer.finish(self.lines_skipped || !self.drained)
    }
}

#[derive(Default)]
struct State {
    analyzer: CaptureAnalyzer,
    lines_skipped: bool,
    trace_error: Option<String>,
    trace_truncated: bool,
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

/// Whether `/usr/bin/log` is an executable file. Account or MDM policy can
/// still block `log stream`; each run's readiness check catches that.
pub(crate) fn log_tool_available() -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(LOG_TOOL)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

impl DenialCollector {
    /// Starts `log stream` and returns once it is confirmed to be receiving
    /// this run's tagged Seatbelt reports. Raw lines are copied to `trace`.
    pub(crate) fn start(tag: &str, trace: Option<File>) -> Result<Self, String> {
        let mut child = Command::new(WATCHDOG_SHELL)
            .args(["-c", WATCHDOG_SCRIPT, "sh", LOG_TOOL])
            .args(["stream", "--style", "ndjson", "--predicate"])
            .arg(stream_predicate(tag))
            .stdin(Stdio::piped())
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
            std::thread::spawn(move || {
                read_stream(
                    BufReader::new(stdout),
                    &tag,
                    &shared,
                    trace.map(BufWriter::new),
                    MAX_TRACE_BYTES,
                )
            })
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
            analyzer: std::mem::take(&mut state.analyzer),
            lines_skipped: state.lines_skipped,
            drained,
            trace_error: state.trace_error.take(),
            trace_truncated: state.trace_truncated,
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
            // Killing the shell instead would orphan `log stream`.
            drop(child.stdin.take());
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

fn read_stream(
    mut reader: impl BufRead,
    tag: &str,
    shared: &Shared,
    mut trace: Option<impl Write>,
    trace_limit: u64,
) {
    let mut line = Vec::new();
    let mut trace_bytes = 0u64;
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
            shared.lock().lines_skipped = true;
            continue;
        }
        if let Some(writer) = trace.as_mut() {
            let line_bytes = line.len() as u64 + u64::from(!line.ends_with(b"\n"));
            if trace_bytes + line_bytes > trace_limit {
                let mut state = shared.lock();
                state.trace_truncated = true;
                if let Err(error) = writer.flush() {
                    state.trace_error = Some(error.to_string());
                }
                trace = None;
            } else if let Err(error) = write_trace_line(writer, &line) {
                shared.lock().trace_error = Some(error.to_string());
                trace = None;
            } else {
                trace_bytes += line_bytes;
            }
        }
        let parsed = parse_stream_line(&String::from_utf8_lossy(&line), tag);
        let mut state = shared.lock();
        match parsed {
            StreamLine::Marker(CaptureMarker::Ready) => state.ready = true,
            StreamLine::Marker(CaptureMarker::Done) => state.done = true,
            StreamLine::Event(event) => state.analyzer.add(&event),
            StreamLine::Ignored => continue,
        }
        shared.changed.notify_all();
    }
    if let Some(Err(error)) = trace.as_mut().map(Write::flush) {
        shared.lock().trace_error = Some(error.to_string());
    }
    shared.lock().ended = true;
    shared.changed.notify_all();
}

fn write_trace_line(writer: &mut impl Write, line: &[u8]) -> std::io::Result<()> {
    writer.write_all(line)?;
    if !line.ends_with(b"\n") {
        writer.write_all(b"\n")?;
    }
    Ok(())
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
        read_stream(
            std::io::Cursor::new(input),
            tag,
            &shared,
            None::<Vec<u8>>,
            MAX_TRACE_BYTES,
        );
        let mut state = shared.lock();
        assert!(state.lines_skipped);
        assert!(state.ended);
        assert_eq!(
            std::mem::take(&mut state.analyzer)
                .finish(false)
                .denials
                .len(),
            1
        );
    }

    #[test]
    fn repeats_are_counted_without_truncating() {
        const REPEATS: u64 = 150_000;
        let tag = "mxc-capture-repeattest";
        let report = |path: &str| {
            serde_json::json!({
                "eventMessage": format!("Sandbox: cat(7) deny(1) file-read-data {path}\n{tag}"),
            })
            .to_string()
        };
        let done = serde_json::json!({
            "eventMessage": format!("Sandbox: ls(8) deny(1) file-read-metadata /private/var/empty\n{tag}:done"),
        });
        let input = format!(
            "{}{}\n{done}\n",
            format!("{}\n", report("/flood")).repeat(REPEATS as usize),
            report("/late"),
        );
        let shared = Shared::default();
        read_stream(
            std::io::Cursor::new(input),
            tag,
            &shared,
            None::<Vec<u8>>,
            MAX_TRACE_BYTES,
        );
        let mut state = shared.lock();
        assert!(state.done);
        let analysis = std::mem::take(&mut state.analyzer).finish(false);
        let resources: Vec<_> = analysis
            .denials
            .iter()
            .map(|d| d.resource.as_str())
            .collect();
        assert_eq!(resources, ["/flood", "/late"]);
        assert!(!analysis.denied_resources_truncated);
        assert_eq!(
            analysis.network_verbose_logging.total_occurrences,
            REPEATS + 1
        );
    }

    #[test]
    fn trace_receives_raw_lines() {
        let tag = "mxc-capture-tracetest";
        let input = format!("Filtering the log data\n{{\"eventMessage\":\"x\\n{tag}\"}}");
        let shared = Shared::default();
        let mut trace = Vec::new();
        read_stream(
            std::io::Cursor::new(input.clone()),
            tag,
            &shared,
            Some(&mut trace),
            MAX_TRACE_BYTES,
        );
        assert_eq!(String::from_utf8(trace).unwrap(), format!("{input}\n"));
        assert!(shared.lock().trace_error.is_none());
        assert!(!shared.lock().trace_truncated);
    }

    #[test]
    fn trace_stops_at_limit_but_analysis_continues() {
        let tag = "mxc-capture-tracelimit";
        let report = |path: &str| {
            serde_json::json!({
                "eventMessage": format!("Sandbox: cat(7) deny(1) file-read-data {path}\n{tag}"),
            })
            .to_string()
        };
        let first = report("/first");
        let input = format!("{first}\n{}\n", report("/second"));
        let shared = Shared::default();
        let mut trace = Vec::new();
        read_stream(
            std::io::Cursor::new(input),
            tag,
            &shared,
            Some(&mut trace),
            first.len() as u64 + 1,
        );
        assert_eq!(String::from_utf8(trace).unwrap(), format!("{first}\n"));
        let mut state = shared.lock();
        assert!(state.trace_truncated);
        assert!(state.trace_error.is_none());
        let analysis = std::mem::take(&mut state.analyzer).finish(false);
        let resources: Vec<_> = analysis
            .denials
            .iter()
            .map(|d| d.resource.as_str())
            .collect();
        assert_eq!(resources, ["/first", "/second"]);
    }

    #[test]
    fn collector_sees_tagged_deny_and_drains() {
        let tag = "mxc-capture-collectortest";
        let collector = match DenialCollector::start(tag, None) {
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
        let denials = collected.into_analysis().denials;
        assert!(
            denials
                .iter()
                .any(|d| d.resource == "/private/etc/hosts" || d.resource == "/etc/hosts"),
            "denials: {denials:?}"
        );
    }
}
