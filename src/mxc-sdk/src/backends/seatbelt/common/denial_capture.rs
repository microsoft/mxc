// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Collects the run's tagged Seatbelt reports from the macOS unified log.
//!
//! Before the workload starts, a short `log stream` confirms that a tagged
//! marker deny reaches the log. After the workload exits, a second marker is
//! logged and `log show` reads the run's reports from the log store. The
//! result is complete only when both markers are found.

use std::ffi::CString;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Read, Seek, Write};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::learning_mode_core::capture_diagnostics::CaptureAnalysis;
use crate::seatbelt_common::capture_analysis::{
    parse_stream_line, CaptureAnalyzer, CaptureMarker, StreamLine,
};
use crate::seatbelt_common::seatbelt_runner::apply_profile_before_exec;

const LOG_TOOL: &str = "/usr/bin/log";
const MARKER_PROBE: &str = "/bin/ls";
// Must exist: Seatbelt does not report lookups of missing paths.
const MARKER_TARGET: &str = "/private/var/empty";
const READY_TIMEOUT: Duration = Duration::from_secs(10);
const MARKER_TIMEOUT: Duration = Duration::from_secs(5);
const SHOW_TIMEOUT: Duration = Duration::from_secs(20);
// How long to keep retrying `log show` while a marker is missing.
const MARKER_RETRY_TIMEOUT: Duration = Duration::from_secs(5);
// Lets an orphaned `log stream` exit if MXC is killed during startup.
const STREAM_TIMEOUT_SECS: u64 = READY_TIMEOUT.as_secs() + 5;
// Widens the `log show` window so it still covers the ready marker.
const WINDOW_MARGIN_SECS: u64 = 2;
const RETRY: Duration = Duration::from_millis(250);
const POLL: Duration = Duration::from_millis(5);
const MAX_LINE_BYTES: usize = 64 * 1024;
const MAX_STDERR_BYTES: u64 = 4 * 1024;
pub(crate) const MAX_TRACE_BYTES: u64 = 1024 * 1024 * 1024;

/// The run's reports as read from the log.
#[derive(Default)]
pub(crate) struct CollectedEvents {
    analyzer: CaptureAnalyzer,
    /// An oversized line was skipped.
    lines_skipped: bool,
    ready: bool,
    done: bool,
    /// `log show` was killed at its deadline and may have missed reports.
    timed_out: bool,
    /// Why the trace file stopped being written, if it did.
    pub(crate) trace_error: Option<String>,
    /// The trace reached `MAX_TRACE_BYTES` and later lines were not written.
    pub(crate) trace_truncated: bool,
}

impl CollectedEvents {
    /// False when a marker was missing or `log show` timed out, so some
    /// reports may be too.
    pub(crate) fn drained(&self) -> bool {
        self.ready && self.done && !self.timed_out
    }

    pub(crate) fn into_analysis(self) -> CaptureAnalysis {
        let missing = self.lines_skipped || !self.drained();
        self.analyzer.finish(missing)
    }
}

/// One run's capture, from the readiness check until its reports are read.
pub(crate) struct DenialCollector {
    tag: String,
    started: Instant,
    trace: Option<File>,
}

/// Whether `/usr/bin/log` is an executable file. Account or MDM policy can
/// still block it; each run's readiness check catches that.
pub(crate) fn log_tool_available() -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(LOG_TOOL)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

impl DenialCollector {
    /// Returns once this run's tagged Seatbelt reports are confirmed to reach
    /// the log. Raw `log show` lines are later copied to `trace`.
    pub(crate) fn start(tag: &str, trace: Option<File>) -> Result<Self, String> {
        let started = Instant::now();
        confirm_logging(tag)?;
        Ok(Self {
            tag: tag.to_string(),
            started,
            trace,
        })
    }

    /// Logs the closing marker and reads the run's reports with `log show`,
    /// retrying while a marker is missing from the log store.
    pub(crate) fn finish(self) -> Result<CollectedEvents, String> {
        emit_marker(
            &self.tag,
            CaptureMarker::Done,
            Instant::now() + timeout(MARKER_TIMEOUT),
        )?;
        let retry_deadline = Instant::now() + timeout(MARKER_RETRY_TIMEOUT);
        loop {
            let trace = self.trace.as_ref().map(reset_trace).transpose();
            let trace = trace.map_err(|e| format!("could not reset trace file: {e}"))?;
            let window = self.started.elapsed().as_secs() + WINDOW_MARGIN_SECS;
            let mut log = LogProcess::spawn(
                "show",
                show_command(&self.tag, window),
                &self.tag,
                trace,
                None,
            )?;
            let status = wait_until(&mut log.child, Instant::now() + timeout(SHOW_TIMEOUT));
            let (mut collected, stderr) = log.stop();
            match status {
                Ok(Some(status)) if !status.success() => {
                    return Err(with_log_stderr(
                        format!("'{LOG_TOOL} show' failed with {status}"),
                        &stderr,
                    ));
                }
                Ok(Some(_)) => {}
                // A retry would likely be just as slow.
                Ok(None) => {
                    collected.timed_out = true;
                    return Ok(collected);
                }
                Err(error) => return Err(format!("could not wait for '{LOG_TOOL} show': {error}")),
            }
            if collected.drained() || Instant::now() + RETRY >= retry_deadline {
                return Ok(collected);
            }
            std::thread::sleep(RETRY);
        }
    }
}

/// Repeats the ready marker until `log stream` reports it.
fn confirm_logging(tag: &str) -> Result<(), String> {
    let (sender, markers) = mpsc::channel();
    let log = LogProcess::spawn("stream", stream_command(tag), tag, None, Some(sender))?;
    let ready_timeout = timeout(READY_TIMEOUT);
    let deadline = Instant::now() + ready_timeout;
    let result = loop {
        if let Err(error) = emit_marker(tag, CaptureMarker::Ready, deadline) {
            break Err(error);
        }
        let wait = deadline
            .saturating_duration_since(Instant::now())
            .min(RETRY);
        match markers.recv_timeout(wait) {
            Ok(CaptureMarker::Ready) => break Ok(()),
            Err(RecvTimeoutError::Disconnected) => {
                break Err(format!("'{LOG_TOOL} stream' exited unexpectedly"));
            }
            _ if Instant::now() < deadline => {}
            _ => {
                break Err(format!(
                    "captureDenials could not confirm within {}s that '{LOG_TOOL} stream' \
                     receives Seatbelt reports",
                    ready_timeout.as_secs()
                ));
            }
        }
    };
    let (_, stderr) = log.stop();
    result.map_err(|error| with_log_stderr(error, &stderr))
}

/// A running `log` command whose output is parsed on a background thread.
struct LogProcess {
    child: Child,
    output: JoinHandle<CollectedEvents>,
    stderr: JoinHandle<String>,
}

impl LogProcess {
    fn spawn(
        name: &str,
        command: Vec<String>,
        tag: &str,
        trace: Option<File>,
        markers: Option<Sender<CaptureMarker>>,
    ) -> Result<Self, String> {
        let mut child = Command::new(&command[0])
            .args(&command[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("captureDenials could not start '{LOG_TOOL} {name}': {e}"))?;
        let stdout = child.stdout.take().expect("stdout is piped");
        let stderr = child.stderr.take().expect("stderr is piped");
        let tag = tag.to_string();
        let output = std::thread::spawn(move || {
            read_log(
                BufReader::new(stdout),
                &tag,
                trace.map(BufWriter::new),
                MAX_TRACE_BYTES,
                markers,
            )
        });
        let stderr = std::thread::spawn(move || {
            let mut text = String::new();
            let mut limited = stderr.take(MAX_STDERR_BYTES);
            let _ = limited.read_to_string(&mut text);
            // Keep draining so `log` never blocks on a full stderr pipe.
            let _ = std::io::copy(&mut limited.into_inner(), &mut std::io::sink());
            text
        });
        Ok(Self {
            child,
            output,
            stderr,
        })
    }

    /// Kills and reaps `log`, returning what it printed.
    fn stop(mut self) -> (CollectedEvents, String) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let collected = self.output.join().unwrap_or_default();
        (collected, self.stderr.join().unwrap_or_default())
    }
}

/// Waits for `child` to exit. A child still running at `deadline` is killed
/// and `None` is returned.
fn wait_until(child: &mut Child, deadline: Instant) -> std::io::Result<Option<ExitStatus>> {
    loop {
        match child.try_wait()? {
            Some(status) => return Ok(Some(status)),
            None if Instant::now() < deadline => std::thread::sleep(POLL),
            None => {
                let _ = child.kill();
                child.wait()?;
                return Ok(None);
            }
        }
    }
}

fn reset_trace(trace: &File) -> std::io::Result<File> {
    trace.set_len(0)?;
    (&*trace).rewind()?;
    trace.try_clone()
}

fn read_log(
    mut reader: impl BufRead,
    tag: &str,
    mut trace: Option<impl Write>,
    trace_limit: u64,
    markers: Option<Sender<CaptureMarker>>,
) -> CollectedEvents {
    let mut collected = CollectedEvents::default();
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
            collected.lines_skipped = true;
            continue;
        }
        if let Some(writer) = trace.as_mut() {
            let line_bytes = line.len() as u64 + u64::from(!line.ends_with(b"\n"));
            let written = if trace_bytes + line_bytes > trace_limit {
                collected.trace_truncated = true;
                writer.flush()
            } else {
                trace_bytes += line_bytes;
                write_trace_line(writer, &line)
            };
            if let Err(error) = written {
                collected.trace_error = Some(error.to_string());
            }
            if collected.trace_truncated || collected.trace_error.is_some() {
                trace = None;
            }
        }
        match parse_stream_line(&String::from_utf8_lossy(&line), tag) {
            StreamLine::Marker(marker) => {
                match marker {
                    CaptureMarker::Ready => collected.ready = true,
                    CaptureMarker::Done => collected.done = true,
                }
                if let Some(markers) = &markers {
                    let _ = markers.send(marker);
                }
            }
            StreamLine::Event(event) => collected.analyzer.add(&event),
            StreamLine::Ignored => {}
        }
    }
    if let Some(Err(error)) = trace.as_mut().map(Write::flush) {
        collected.trace_error = Some(error.to_string());
    }
    collected
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
/// A probe still running at `deadline` is killed.
fn emit_marker(tag: &str, marker: CaptureMarker, deadline: Instant) -> Result<(), String> {
    let profile = format!(
        r#"(version 1)(allow default)(deny file-read-metadata (with message "{tag}:{}") (literal "{MARKER_TARGET}"))"#,
        marker.as_str()
    );
    let profile = CString::new(profile)
        .map_err(|_| "captureDenials marker profile contains a NUL byte".to_string())?;
    let mut command = marker_command();
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    apply_profile_before_exec(&mut command, profile);
    let mut probe = command
        .spawn()
        .map_err(|e| format!("captureDenials could not run its log marker probe: {e}"))?;
    wait_until(&mut probe, deadline)
        .map(|_| ())
        .map_err(|e| format!("captureDenials could not wait for its log marker probe: {e}"))
}

fn predicate(tag: &str) -> String {
    format!(r#"sender == "Sandbox" AND eventMessage CONTAINS "{tag}""#)
}

fn stream_command(tag: &str) -> Vec<String> {
    #[cfg(test)]
    if let Some(command) = test_tools::get().stream {
        return command;
    }
    let timeout = format!("{STREAM_TIMEOUT_SECS}s");
    [
        LOG_TOOL,
        "stream",
        "--style",
        "ndjson",
        "--timeout",
        &timeout,
        "--predicate",
    ]
    .into_iter()
    .map(str::to_string)
    .chain([predicate(tag)])
    .collect()
}

fn show_command(tag: &str, window_secs: u64) -> Vec<String> {
    #[cfg(test)]
    if let Some(command) = test_tools::get().show {
        return command;
    }
    let window = format!("{window_secs}s");
    [
        LOG_TOOL,
        "show",
        "--style",
        "ndjson",
        "--last",
        &window,
        "--predicate",
    ]
    .into_iter()
    .map(str::to_string)
    .chain([predicate(tag)])
    .collect()
}

fn marker_command() -> Command {
    #[cfg(test)]
    if let Some(command) = test_tools::get().marker {
        let mut probe = Command::new(&command[0]);
        probe.args(&command[1..]);
        return probe;
    }
    let mut probe = Command::new(MARKER_PROBE);
    probe.args(["-d", MARKER_TARGET]);
    probe
}

fn timeout(default: Duration) -> Duration {
    #[cfg(test)]
    if let Some(timeout) = test_tools::get().timeout {
        return timeout;
    }
    default
}

fn with_log_stderr(message: String, stderr: &str) -> String {
    let stderr = stderr.trim();
    if stderr.is_empty() {
        message
    } else {
        format!("{message}: {stderr}")
    }
}

/// Lets tests replace the collector's commands and timeouts on their thread.
#[cfg(test)]
pub(crate) mod test_tools {
    use std::cell::RefCell;
    use std::time::Duration;

    #[derive(Clone, Default)]
    pub(crate) struct TestTools {
        /// Replaces `log stream` and its arguments.
        pub(crate) stream: Option<Vec<String>>,
        /// Replaces `log show` and its arguments.
        pub(crate) show: Option<Vec<String>>,
        /// Replaces the marker probe and its arguments.
        pub(crate) marker: Option<Vec<String>>,
        /// Replaces every timeout.
        pub(crate) timeout: Option<Duration>,
    }

    thread_local! {
        static TOOLS: RefCell<TestTools> = RefCell::default();
    }

    pub(crate) fn set(tools: TestTools) {
        TOOLS.with(|current| *current.borrow_mut() = tools);
    }

    pub(super) fn get() -> TestTools {
        TOOLS.with(|current| current.borrow().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(tag: &str, path: &str) -> String {
        serde_json::json!({
            "eventMessage": format!("Sandbox: cat(7) deny(1) file-read-data {path}\n{tag}"),
        })
        .to_string()
    }

    fn marker(tag: &str, marker: CaptureMarker) -> String {
        serde_json::json!({
            "eventMessage": format!(
                "Sandbox: ls(8) deny(1) file-read-metadata {MARKER_TARGET}\n{tag}:{}",
                marker.as_str()
            ),
        })
        .to_string()
    }

    fn read(input: String, tag: &str, trace: Option<&mut Vec<u8>>, limit: u64) -> CollectedEvents {
        read_log(std::io::Cursor::new(input), tag, trace, limit, None)
    }

    fn resources(collected: CollectedEvents) -> Vec<String> {
        let analysis = collected.into_analysis();
        analysis.denials.into_iter().map(|d| d.resource).collect()
    }

    #[test]
    fn oversized_line_is_skipped_and_flagged() {
        let tag = "mxc-capture-linetest";
        let input = format!(
            "{}\n{}\n",
            "a".repeat(MAX_LINE_BYTES * 2),
            report(tag, "/x")
        );
        let collected = read(input, tag, None, MAX_TRACE_BYTES);
        assert!(collected.lines_skipped);
        assert_eq!(resources(collected), ["/x"]);
    }

    #[test]
    fn repeats_are_counted_without_truncating() {
        const REPEATS: u64 = 150_000;
        let tag = "mxc-capture-repeattest";
        let input = format!(
            "{}\n{}{}\n{}\n",
            marker(tag, CaptureMarker::Ready),
            format!("{}\n", report(tag, "/flood")).repeat(REPEATS as usize),
            report(tag, "/late"),
            marker(tag, CaptureMarker::Done),
        );
        let collected = read(input, tag, None, MAX_TRACE_BYTES);
        assert!(collected.drained());
        let analysis = collected.into_analysis();
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
        let mut trace = Vec::new();
        let collected = read(input.clone(), tag, Some(&mut trace), MAX_TRACE_BYTES);
        assert_eq!(String::from_utf8(trace).unwrap(), format!("{input}\n"));
        assert!(collected.trace_error.is_none());
        assert!(!collected.trace_truncated);
    }

    #[test]
    fn trace_stops_at_limit_but_analysis_continues() {
        let tag = "mxc-capture-tracelimit";
        let first = report(tag, "/first");
        let input = format!("{first}\n{}\n", report(tag, "/second"));
        let mut trace = Vec::new();
        let collected = read(input, tag, Some(&mut trace), first.len() as u64 + 1);
        assert_eq!(String::from_utf8(trace).unwrap(), format!("{first}\n"));
        assert!(collected.trace_truncated);
        assert!(collected.trace_error.is_none());
        assert_eq!(resources(collected), ["/first", "/second"]);
    }

    #[test]
    fn a_stalled_marker_probe_cannot_hold_startup_past_its_deadline() {
        test_tools::set(test_tools::TestTools {
            marker: Some(vec!["/bin/sleep".to_string(), "60".to_string()]),
            timeout: Some(Duration::from_secs(1)),
            ..Default::default()
        });
        let started = Instant::now();

        let error = DenialCollector::start("mxc-capture-stalledstart", None)
            .err()
            .expect("readiness fails");

        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(error.contains("could not confirm within 1s"), "{error}");
    }

    /// Finishes a capture whose `log show` is replaced by `script`, run from
    /// a directory holding `ready.ndjson`, `done.ndjson` and `report.ndjson`.
    fn finish_with_show(tag: &str, script: &str) -> Result<CollectedEvents, String> {
        let directory = tempfile::tempdir().unwrap();
        for (name, line) in [
            ("ready", marker(tag, CaptureMarker::Ready)),
            ("done", marker(tag, CaptureMarker::Done)),
            ("report", report(tag, "/secret")),
        ] {
            std::fs::write(directory.path().join(format!("{name}.ndjson")), line + "\n").unwrap();
        }
        let script = format!("cd '{}' && {script}", directory.path().display());
        test_tools::set(test_tools::TestTools {
            show: Some(vec!["/bin/sh".to_string(), "-c".to_string(), script]),
            marker: Some(vec!["/usr/bin/true".to_string()]),
            timeout: Some(Duration::from_secs(1)),
            ..Default::default()
        });
        let collector = DenialCollector {
            tag: tag.to_string(),
            started: Instant::now(),
            trace: None,
        };
        collector.finish()
    }

    #[test]
    fn stored_reports_are_complete_only_with_both_markers() {
        let tag = "mxc-capture-showmarkers";
        let complete = finish_with_show(tag, "cat ready.ndjson report.ndjson done.ndjson").unwrap();
        assert!(complete.drained());
        assert_eq!(resources(complete), ["/secret"]);

        let no_ready = finish_with_show(tag, "cat report.ndjson done.ndjson").unwrap();
        assert!(!no_ready.drained());
    }

    #[test]
    fn a_show_without_the_done_marker_is_retried() {
        let tag = "mxc-capture-showretry";
        let collected = finish_with_show(
            tag,
            "if [ -e tried ]; then cat ready.ndjson report.ndjson done.ndjson; \
             else touch tried; cat ready.ndjson; fi",
        )
        .unwrap();
        assert!(collected.drained());
        assert_eq!(resources(collected), ["/secret"]);
    }

    #[test]
    fn a_failed_or_stalled_log_show_is_not_trusted() {
        let tag = "mxc-capture-showfail";
        let error = finish_with_show(tag, "echo 'log: not permitted' >&2; exit 1")
            .err()
            .expect("log show fails");
        assert!(error.contains("log: not permitted"), "{error}");

        let started = Instant::now();
        let stalled = finish_with_show(
            tag,
            "cat ready.ndjson report.ndjson done.ndjson; exec /bin/sleep 60",
        )
        .unwrap();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(!stalled.drained());
    }

    #[test]
    fn collector_sees_tagged_deny() {
        let tag = "mxc-capture-collectortest";
        let trace = tempfile::tempfile().unwrap();
        let collector = DenialCollector::start(tag, Some(trace.try_clone().unwrap()))
            .unwrap_or_else(|error| panic!("log stream unavailable on this host: {error}"));
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
        assert!(collected.drained());
        let denials = resources(collected);
        assert!(
            denials
                .iter()
                .any(|d| d == "/private/etc/hosts" || d == "/etc/hosts"),
            "denials: {denials:?}"
        );
        let mut traced = String::new();
        (&trace).rewind().unwrap();
        (&trace).read_to_string(&mut traced).unwrap();
        assert!(traced.contains(&format!("{tag}:done")), "{traced}");
    }
}
