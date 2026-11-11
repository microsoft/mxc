// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A container held for the life of one executor process.
//!
//! Each container lifecycle operation of the executor normally runs in its own
//! process. A MicroVM serves one host session at a time, so an `exec` started
//! by one executor process waits until the process running an earlier `exec`
//! exits. [`hold_container`] instead provisions and starts a container, runs
//! the exec requests it reads side by side in this process, and stops and
//! deprovisions the container when the requests end. The container ID never
//! leaves the process.
//!
//! Requests and events are JSON objects, one per line:
//!
//! - `{"type":"exec","id":"1","request":{...}}` runs the exec request, which
//!   has the shape of an `--operation exec` request. `id` names it in later
//!   requests and events and must not name a running exec.
//! - `{"type":"cancel","id":"1"}` cancels that exec, if it still runs.
//! - `{"type":"ready"}` reports that the container started.
//! - `{"type":"stdout","id":"1","data":"<base64>"}` and `stderr` carry output.
//! - `{"type":"exit","id":"1","exitCode":0}`, `{"type":"timeout","id":"1"}`, or
//!   `{"type":"error","id":"1","error":{...}}` end each exec, after its output.
//! - `{"type":"error","error":{...}}` reports a failure that ends the
//!   container, such as a failed provision or a malformed request.
//!
//! The end of the requests cancels the execs that still run, then stops and
//! deprovisions the container.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::mxc_common::config_parser::{
    load_state_aware_request_from_json_with_options, CliTargetId,
};
use crate::mxc_common::logger::Logger;
use crate::mxc_common::mxc_error::{ErrorEnvelope, MxcError, MxcErrorCode};
use crate::mxc_common::sandbox_process::{SandboxProcess, StreamCloser};
use crate::mxc_common::script_runner::{warning_envelope_lines, RunCancellation};
use crate::mxc_common::state_aware_request::{ParsedStateAwareRequest, Phase};

const POLL: Duration = Duration::from_millis(50);
/// How long output may still arrive after an exec ends, as for a relayed exec.
const DRAIN_GRACE: Duration = Duration::from_secs(2);
/// How long the end of the requests waits for cancelled execs before the
/// container stops, which ends them.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);
const CHUNK_BYTES: usize = 64 * 1024;

/// Provisions and starts the container that `provision` describes, runs the
/// exec requests read from `requests` side by side, and stops and
/// deprovisions the container once the requests end or `cancellation` is
/// requested. Writes the events to `events`.
///
/// `provision` is an `--operation provision` request: it has no `phase`. The
/// returned error, also written as the last event, is the first failure that
/// ended the container; the end of the requests is not one.
pub fn hold_container(
    provision: &str,
    experimental: bool,
    logger: &Logger,
    requests: impl Read + Send + 'static,
    events: impl Write + Send + 'static,
    cancellation: &RunCancellation,
) -> Result<(), MxcError> {
    let events = Events::new(Box::new(events));
    let result =
        LifecycleContainer::provision(provision, experimental, logger).and_then(|container| {
            events.send(&Event::Ready);
            let served = serve(&container, requests, &events, cancellation);
            let released = container.release();
            match (served, released) {
                (Ok(()), released) => released,
                (Err(error), released) => Err(with_cleanup_failure(error, released.err())),
            }
        });
    if let Err(error) = &result {
        events.send(&Event::Error {
            id: None,
            error: error.to_envelope(),
        });
    }
    result
}

/// What serving needs from a container. The engine drives a real one through
/// lifecycle requests; tests substitute their own.
trait Container {
    fn exec(&self, request: &str) -> Result<Box<dyn SandboxProcess>, MxcError>;
}

/// A container driven through the engine's lifecycle operations.
struct LifecycleContainer<'a> {
    sandbox_id: String,
    version: String,
    experimental: bool,
    logger: &'a Logger,
}

impl<'a> LifecycleContainer<'a> {
    fn provision(
        provision: &str,
        experimental: bool,
        logger: &'a Logger,
    ) -> Result<Self, MxcError> {
        let envelope = operation(logger, |logger| {
            let parsed = parse(provision, Phase::Provision, None, experimental, logger)?;
            super::state_aware::run_state_aware_envelope(parsed, false, logger)
                .map_err(super::Error::into_mxc_error)
        })?;
        let sandbox_id = envelope
            .pointer("/result/sandboxId")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| MxcError::backend_error("provision returned no container ID"))?;
        // The provision request parsed, so it declares a version.
        let version = serde_json::from_str::<serde_json::Value>(provision)
            .ok()
            .and_then(|request| request["version"].as_str().map(str::to_owned))
            .ok_or_else(|| MxcError::malformed_request("the provision request has no version"))?;
        let container = Self {
            sandbox_id: sandbox_id.to_owned(),
            version,
            experimental,
            logger,
        };
        if let Err(error) = container.phase(Phase::Start) {
            return Err(with_cleanup_failure(error, container.release().err()));
        }
        Ok(container)
    }

    fn phase(&self, phase: Phase) -> Result<(), MxcError> {
        let request = serde_json::json!({ "version": self.version }).to_string();
        operation(self.logger, |logger| {
            let parsed = parse(
                &request,
                phase,
                Some(&self.sandbox_id),
                self.experimental,
                logger,
            )?;
            super::state_aware::run_state_aware_envelope(parsed, false, logger)
                .map(|_| ())
                .map_err(super::Error::into_mxc_error)
        })
    }

    /// Stops and deprovisions the container. A container that never started,
    /// or already stopped, is only deprovisioned.
    fn release(&self) -> Result<(), MxcError> {
        let stopped = match self.phase(Phase::Stop) {
            Err(error)
                if matches!(
                    error.code,
                    MxcErrorCode::NotStarted | MxcErrorCode::AlreadyStopped
                ) =>
            {
                Ok(())
            }
            other => other,
        };
        let deprovisioned = self.phase(Phase::Deprovision);
        match (stopped, deprovisioned) {
            (Ok(()), deprovisioned) => deprovisioned,
            (Err(error), deprovisioned) => Err(with_cleanup_failure(error, deprovisioned.err())),
        }
    }
}

impl Container for LifecycleContainer<'_> {
    fn exec(&self, request: &str) -> Result<Box<dyn SandboxProcess>, MxcError> {
        operation(self.logger, |logger| {
            let parsed = parse(
                request,
                Phase::Exec,
                Some(&self.sandbox_id),
                self.experimental,
                logger,
            )?;
            super::state_aware::exec_state_aware_parsed(parsed, logger, false)
                .map_err(super::Error::into_mxc_error)
        })
    }
}

/// Runs one lifecycle operation with a logger that shares the caller's
/// diagnostic sinks, then writes what it buffered to stderr, which carries
/// diagnostics while stdout carries events.
fn operation<T>(
    sinks: &Logger,
    run: impl FnOnce(&mut Logger) -> Result<T, MxcError>,
) -> Result<T, MxcError> {
    let mut logger = sinks.clone_diagnostic_sink();
    let result = run(&mut logger);
    let warnings = warning_envelope_lines(&logger.take_warnings());
    if !warnings.is_empty() {
        write_diagnostics(&format!("\n{}\n", warnings.join("\n")));
    }
    write_diagnostics(logger.get_buffer());
    result
}

/// Writes diagnostics to stderr. A caller that died leaves a broken pipe, and
/// the container must still be torn down, so a failed write is ignored rather
/// than panicking as `eprint!` would.
fn write_diagnostics(text: &str) {
    if !text.is_empty() {
        let _ = std::io::stderr().write_all(text.as_bytes());
    }
}

/// Parses a request of the executor's lifecycle transport, which carries the
/// phase and container ID outside the JSON.
fn parse(
    json: &str,
    phase: Phase,
    sandbox_id: Option<&str>,
    experimental: bool,
    logger: &mut Logger,
) -> Result<ParsedStateAwareRequest, MxcError> {
    let target = sandbox_id.map(|value| CliTargetId {
        flag: "--container-id",
        value,
    });
    let mut parsed =
        load_state_aware_request_from_json_with_options(json, logger, phase, target, &[])
            .map_err(super::state_aware::parse_error_to_mxc)?;
    parsed.set_experimental_enabled(experimental);
    Ok(parsed)
}

fn with_cleanup_failure(mut error: MxcError, cleanup: Option<MxcError>) -> MxcError {
    if let Some(cleanup) = cleanup {
        error
            .message
            .push_str(&format!("; cleanup failure: {cleanup}"));
    }
    error
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum RequestKind {
    Exec,
    Cancel,
}

// A struct rather than an internally tagged enum, which cannot hold a raw value.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    #[serde(rename = "type")]
    kind: RequestKind,
    id: String,
    // Kept as written, so the exact parser sees duplicate fields and the like.
    #[serde(default)]
    request: Option<Box<RawValue>>,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
enum Event<'a> {
    Ready,
    Stdout {
        id: &'a str,
        data: String,
    },
    Stderr {
        id: &'a str,
        data: String,
    },
    Exit {
        id: &'a str,
        #[serde(rename = "exitCode")]
        exit_code: i32,
    },
    Timeout {
        id: &'a str,
    },
    Error {
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<&'a str>,
        error: ErrorEnvelope,
    },
}

/// Writes one event per line. Concurrent execs interleave whole lines.
#[derive(Clone)]
struct Events(Arc<EventsInner>);

struct EventsInner {
    writer: Mutex<Box<dyn Write + Send>>,
    broken: AtomicBool,
}

impl Events {
    fn new(writer: Box<dyn Write + Send>) -> Self {
        Self(Arc::new(EventsInner {
            writer: Mutex::new(writer),
            broken: AtomicBool::new(false),
        }))
    }

    fn send(&self, event: &Event<'_>) {
        if self.broken() {
            return;
        }
        let Ok(mut line) = serde_json::to_vec(event) else {
            return;
        };
        line.push(b'\n');
        let mut writer = self.0.writer.lock().unwrap_or_else(PoisonError::into_inner);
        if writer
            .write_all(&line)
            .and_then(|()| writer.flush())
            .is_err()
        {
            self.0.broken.store(true, Ordering::Release);
        }
    }

    /// Whether a write failed, which means the caller stopped reading.
    fn broken(&self) -> bool {
        self.0.broken.load(Ordering::Acquire)
    }
}

struct Running {
    cancel: mpsc::Sender<()>,
    supervisor: JoinHandle<()>,
}

/// Serves requests until they end, `cancellation` is requested, or a request
/// is malformed, then cancels the execs that still run.
fn serve(
    container: &dyn Container,
    requests: impl Read + Send + 'static,
    events: &Events,
    cancellation: &RunCancellation,
) -> Result<(), MxcError> {
    let lines = read_lines(requests)
        .map_err(|error| MxcError::backend_error(format!("cannot read requests: {error}")))?;
    let (finished, finishing) = mpsc::channel::<String>();
    let mut running = HashMap::<String, Running>::new();
    let reap = |running: &mut HashMap<String, Running>, id: String| {
        if let Some(exec) = running.remove(&id) {
            let _ = exec.supervisor.join();
        }
    };
    let result = loop {
        for id in finishing.try_iter() {
            reap(&mut running, id);
        }
        if cancellation.check().is_err() || events.broken() {
            break Ok(());
        }
        let line = match lines.recv_timeout(POLL) {
            Ok(Ok(line)) => line,
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::InvalidData => {
                break Err(MxcError::malformed_request(format!(
                    "held-container requests must be UTF-8: {error}"
                )))
            }
            Ok(Err(error)) => {
                break Err(MxcError::backend_error(format!(
                    "cannot read requests: {error}"
                )))
            }
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break Ok(()),
        };
        if line.trim().is_empty() {
            continue;
        }
        let request = match serde_json::from_str::<Request>(&line) {
            Ok(request) => request,
            Err(error) => {
                break Err(MxcError::malformed_request(format!(
                    "malformed held-container request: {error}"
                )))
            }
        };
        match (request.kind, request.request) {
            (RequestKind::Cancel, None) => {
                if let Some(exec) = running.get(&request.id) {
                    let _ = exec.cancel.send(());
                }
            }
            (RequestKind::Exec, Some(exec)) => {
                if running.contains_key(&request.id) {
                    break Err(MxcError::malformed_request(format!(
                        "exec {:?} is already running",
                        request.id
                    )));
                }
                let started = container.exec(exec.get()).and_then(|process| {
                    start(request.id.clone(), process, events, finished.clone()).map_err(|error| {
                        MxcError::backend_error(format!("cannot supervise the exec: {error}"))
                    })
                });
                match started {
                    Ok(exec) => {
                        running.insert(request.id, exec);
                    }
                    Err(error) => events.send(&Event::Error {
                        id: Some(&request.id),
                        error: error.to_envelope(),
                    }),
                }
            }
            (RequestKind::Exec, None) => {
                break Err(MxcError::malformed_request(
                    "an exec request requires a request",
                ))
            }
            (RequestKind::Cancel, Some(_)) => {
                break Err(MxcError::malformed_request(
                    "a cancel request takes no request",
                ))
            }
        }
    };
    for exec in running.values() {
        let _ = exec.cancel.send(());
    }
    let deadline = Instant::now() + SHUTDOWN_GRACE;
    while !running.is_empty() && Instant::now() < deadline {
        if let Ok(id) = finishing.recv_timeout(POLL) {
            reap(&mut running, id);
        }
    }
    result
}

/// Reads request lines on a thread, so serving can also watch for cancellation
/// and finished execs. A closed channel means the requests ended.
fn read_lines(
    requests: impl Read + Send + 'static,
) -> std::io::Result<mpsc::Receiver<std::io::Result<String>>> {
    let (sender, receiver) = mpsc::channel();
    std::thread::Builder::new()
        .name("mxc-held-requests".to_owned())
        .spawn(move || {
            for line in BufReader::new(requests).lines() {
                let failed = line.is_err();
                if sender.send(line).is_err() || failed {
                    return;
                }
            }
        })?;
    Ok(receiver)
}

/// Relays a running exec's output and its end on a thread of its own.
fn start(
    id: String,
    process: Box<dyn SandboxProcess>,
    events: &Events,
    finished: mpsc::Sender<String>,
) -> std::io::Result<Running> {
    let (cancel, cancelled) = mpsc::channel();
    let events = events.clone();
    let supervisor = std::thread::Builder::new()
        .name("mxc-held-exec".to_owned())
        .spawn(move || {
            let mut process = process;
            let end = supervise(&id, process.as_mut(), &cancelled, &events);
            events.send(&match &end {
                Ok(exit_code) => Event::Exit {
                    id: &id,
                    exit_code: *exit_code,
                },
                Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                    Event::Timeout { id: &id }
                }
                Err(error) => Event::Error {
                    id: Some(&id),
                    error: MxcError::backend_error(error.to_string()).to_envelope(),
                },
            });
            drop(process);
            let _ = finished.send(id);
        })?;
    Ok(Running { cancel, supervisor })
}

/// Relays `process`'s output until it ends, cancelling it once asked to or
/// once the requests end, and returns its exit code.
fn supervise(
    id: &str,
    process: &mut dyn SandboxProcess,
    cancelled: &mpsc::Receiver<()>,
    events: &Events,
) -> std::io::Result<i32> {
    let closers: Vec<Box<dyn StreamCloser>> = [process.stdout_closer(), process.stderr_closer()]
        .into_iter()
        .flatten()
        .collect();
    let mut pumps = Vec::new();
    let streams = [
        (process.take_stdout(), Stream::Stdout),
        (process.take_stderr(), Stream::Stderr),
    ];
    for (reader, stream) in streams {
        let Some(reader) = reader else { continue };
        match pump(id, reader, stream, events) {
            Ok(pump) => pumps.push(pump),
            Err(error) => {
                // A stream that nobody reads could block the exec, so end it.
                let _ = process.kill();
                drain(pumps, closers);
                return Err(error);
            }
        }
    }
    let mut cancelling = false;
    let end = loop {
        match process.try_wait() {
            Ok(Some(code)) => break Ok(code),
            Ok(None) => {}
            Err(error) => break Err(error),
        }
        if cancelling {
            std::thread::sleep(POLL);
            continue;
        }
        match cancelled.recv_timeout(POLL) {
            Err(RecvTimeoutError::Timeout) => {}
            Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                cancelling = true;
                if let Err(error) = process.kill() {
                    break Err(error);
                }
            }
        }
    };
    drain(pumps, closers);
    end
}

#[derive(Clone, Copy)]
enum Stream {
    Stdout,
    Stderr,
}

fn pump(
    id: &str,
    mut reader: Box<dyn Read + Send>,
    stream: Stream,
    events: &Events,
) -> std::io::Result<JoinHandle<()>> {
    let id = id.to_owned();
    let events = events.clone();
    std::thread::Builder::new()
        .name("mxc-held-output".to_owned())
        .spawn(move || {
            let mut buffer = vec![0; CHUNK_BYTES];
            loop {
                let length = match reader.read(&mut buffer) {
                    Ok(0) => return,
                    Ok(length) => length,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => return,
                };
                let data = base64::engine::general_purpose::STANDARD.encode(&buffer[..length]);
                events.send(&match stream {
                    Stream::Stdout => Event::Stdout { id: &id, data },
                    Stream::Stderr => Event::Stderr { id: &id, data },
                });
            }
        })
}

/// Waits for the output of an ended exec. A process the exec left behind can
/// keep a stream open, so after the grace period the streams are closed.
fn drain(pumps: Vec<JoinHandle<()>>, closers: Vec<Box<dyn StreamCloser>>) {
    let deadline = Instant::now() + DRAIN_GRACE;
    while pumps.iter().any(|pump| !pump.is_finished()) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    for closer in closers {
        closer.close();
    }
    for pump in pumps {
        let _ = pump.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{PipeReader, PipeWriter};
    use std::sync::atomic::AtomicUsize;

    /// An exec whose output and end the test controls.
    struct FakeProcess {
        stdout: Option<PipeReader>,
        stderr: Option<PipeReader>,
        writers: Arc<Mutex<Option<(PipeWriter, PipeWriter)>>>,
        end: Arc<Mutex<Option<std::io::Result<i32>>>>,
        kills: Arc<AtomicUsize>,
    }

    impl SandboxProcess for FakeProcess {
        fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>> {
            None
        }
        fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
            self.stdout.take().map(|reader| Box::new(reader) as _)
        }
        fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>> {
            self.stderr.take().map(|reader| Box::new(reader) as _)
        }
        fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
            match self.end.lock().unwrap().as_ref() {
                None => Ok(None),
                Some(Ok(code)) => Ok(Some(*code)),
                Some(Err(error)) => Err(std::io::Error::new(error.kind(), error.to_string())),
            }
        }
        fn id(&self) -> u32 {
            0
        }
        fn kill(&mut self) -> std::io::Result<()> {
            self.kills.fetch_add(1, Ordering::SeqCst);
            // Like an NVX exec, a cancelled exec ends with 137 and closes its streams.
            self.writers.lock().unwrap().take();
            self.end.lock().unwrap().get_or_insert(Ok(137));
            Ok(())
        }
        fn wait(&mut self) -> std::io::Result<i32> {
            unreachable!("held containers poll their execs")
        }
    }

    /// Controls one exec started by the fake container.
    #[derive(Clone)]
    struct Handle {
        writers: Arc<Mutex<Option<(PipeWriter, PipeWriter)>>>,
        end: Arc<Mutex<Option<std::io::Result<i32>>>>,
        kills: Arc<AtomicUsize>,
    }

    impl Handle {
        fn write(&self, stdout: &[u8], stderr: &[u8]) {
            let mut writers = self.writers.lock().unwrap();
            let (out, err) = writers.as_mut().expect("exec still running");
            out.write_all(stdout).unwrap();
            err.write_all(stderr).unwrap();
        }
        fn exit(&self, end: std::io::Result<i32>) {
            self.writers.lock().unwrap().take();
            *self.end.lock().unwrap() = Some(end);
        }
    }

    /// Records exec requests, and fails the ones whose request is `"fail"`.
    #[derive(Default)]
    struct FakeContainer {
        execs: Mutex<Vec<(String, Handle)>>,
    }

    impl Container for FakeContainer {
        fn exec(&self, request: &str) -> Result<Box<dyn SandboxProcess>, MxcError> {
            if request == r#""fail""# {
                return Err(MxcError::policy_validation("rejected exec"));
            }
            let (stdout, out) = std::io::pipe().unwrap();
            let (stderr, err) = std::io::pipe().unwrap();
            let handle = Handle {
                writers: Arc::new(Mutex::new(Some((out, err)))),
                end: Arc::new(Mutex::new(None)),
                kills: Arc::new(AtomicUsize::new(0)),
            };
            self.execs
                .lock()
                .unwrap()
                .push((request.to_owned(), handle.clone()));
            Ok(Box::new(FakeProcess {
                stdout: Some(stdout),
                stderr: Some(stderr),
                writers: handle.writers,
                end: handle.end,
                kills: handle.kills,
            }))
        }
    }

    impl FakeContainer {
        fn wait_for(&self, count: usize) -> Vec<(String, Handle)> {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let execs = self.execs.lock().unwrap().clone();
                if execs.len() >= count {
                    return execs;
                }
                assert!(
                    Instant::now() < deadline,
                    "only {} execs started",
                    execs.len()
                );
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }

    /// Collects events, and lets a test wait for one.
    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);

    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Sink {
        fn events(&self) -> Vec<serde_json::Value> {
            String::from_utf8(self.0.lock().unwrap().clone())
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        }
        fn wait_for(&self, found: impl Fn(&[serde_json::Value]) -> bool) -> Vec<serde_json::Value> {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let events = self.events();
                if found(&events) {
                    return events;
                }
                assert!(Instant::now() < deadline, "event never arrived: {events:?}");
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }

    fn output(events: &[serde_json::Value], id: &str, kind: &str) -> Vec<u8> {
        events
            .iter()
            .filter(|event| event["type"] == kind && event["id"] == id)
            .flat_map(|event| {
                base64::engine::general_purpose::STANDARD
                    .decode(event["data"].as_str().unwrap())
                    .unwrap()
            })
            .collect()
    }

    fn ended(events: &[serde_json::Value], id: &str) -> Option<serde_json::Value> {
        events
            .iter()
            .find(|event| {
                event["id"] == id
                    && matches!(event["type"].as_str(), Some("exit" | "timeout" | "error"))
            })
            .cloned()
    }

    struct Served {
        requests: Option<PipeWriter>,
        container: Arc<FakeContainer>,
        sink: Sink,
        cancellation: RunCancellation,
        server: JoinHandle<Result<(), MxcError>>,
    }

    impl Served {
        fn new() -> Self {
            let (reader, requests) = std::io::pipe().unwrap();
            let container = Arc::new(FakeContainer::default());
            let sink = Sink::default();
            let cancellation = RunCancellation::default();
            let server = {
                let container = container.clone();
                let events = Events::new(Box::new(sink.clone()));
                let cancellation = cancellation.clone();
                std::thread::spawn(move || {
                    serve(container.as_ref(), reader, &events, &cancellation)
                })
            };
            Self {
                requests: Some(requests),
                container,
                sink,
                cancellation,
                server,
            }
        }

        fn send(&mut self, line: &str) {
            let requests = self.requests.as_mut().unwrap();
            requests.write_all(line.as_bytes()).unwrap();
            requests.write_all(b"\n").unwrap();
        }

        fn end(mut self) -> (Result<(), MxcError>, Vec<serde_json::Value>) {
            drop(self.requests.take());
            let result = self.server.join().unwrap();
            (result, self.sink.events())
        }
    }

    #[test]
    fn execs_run_side_by_side_and_end_after_their_output() {
        let mut served = Served::new();
        served.send(r#"{"type":"exec","id":"long","request":{"version":"1"}}"#);
        served.send(r#"{"type":"exec","id":"short","request":{"version":"2"}}"#);
        let execs = served.container.wait_for(2);
        assert_eq!(execs[0].0, r#"{"version":"1"}"#);
        // The second exec ends while the first still runs.
        execs[1].1.write(b"out", b"err");
        execs[1].1.exit(Ok(3));
        let events = served
            .sink
            .wait_for(|events| ended(events, "short").is_some());
        assert!(ended(&events, "long").is_none());
        assert_eq!(output(&events, "short", "stdout"), b"out");
        assert_eq!(output(&events, "short", "stderr"), b"err");
        assert_eq!(ended(&events, "short").unwrap()["exitCode"], 3);
        let last = events
            .iter()
            .rposition(|event| event["id"] == "short")
            .unwrap();
        assert_eq!(
            events[last]["type"], "exit",
            "output follows the exit: {events:?}"
        );

        execs[0].1.exit(Ok(0));
        served
            .sink
            .wait_for(|events| ended(events, "long").is_some());
        let (result, events) = served.end();
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(ended(&events, "long").unwrap()["exitCode"], 0);
        assert_eq!(execs[0].1.kills.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn cancel_ends_only_its_exec() {
        let mut served = Served::new();
        served.send(r#"{"type":"exec","id":"a","request":{}}"#);
        served.send(r#"{"type":"exec","id":"b","request":{}}"#);
        let execs = served.container.wait_for(2);
        served.send(r#"{"type":"cancel","id":"a"}"#);
        // Cancelling an unknown exec, or one that already ended, is not an error.
        served.send(r#"{"type":"cancel","id":"unknown"}"#);
        let events = served.sink.wait_for(|events| ended(events, "a").is_some());
        assert_eq!(ended(&events, "a").unwrap()["exitCode"], 137);
        assert_eq!(execs[0].1.kills.load(Ordering::SeqCst), 1);
        assert!(ended(&events, "b").is_none());
        execs[1].1.exit(Ok(0));
        served.sink.wait_for(|events| ended(events, "b").is_some());
        served.send(r#"{"type":"cancel","id":"b"}"#);
        let (result, events) = served.end();
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(ended(&events, "b").unwrap()["exitCode"], 0);
        assert_eq!(execs[1].1.kills.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn the_end_of_the_requests_cancels_running_execs() {
        let mut served = Served::new();
        served.send(r#"{"type":"exec","id":"a","request":{}}"#);
        let execs = served.container.wait_for(1);
        let (result, events) = served.end();
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(execs[0].1.kills.load(Ordering::SeqCst), 1);
        assert_eq!(ended(&events, "a").unwrap()["exitCode"], 137);
    }

    #[test]
    fn cancellation_stops_serving_and_cancels_running_execs() {
        let mut served = Served::new();
        served.send(r#"{"type":"exec","id":"a","request":{}}"#);
        let execs = served.container.wait_for(1);
        assert!(served.cancellation.request());
        let result = served.server.join().unwrap();
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(execs[0].1.kills.load(Ordering::SeqCst), 1);
        assert_eq!(ended(&served.sink.events(), "a").unwrap()["exitCode"], 137);
    }

    #[test]
    fn exec_outcomes_map_to_terminal_events() {
        let mut served = Served::new();
        served.send(r#"{"type":"exec","id":"rejected","request":"fail"}"#);
        served.send(r#"{"type":"exec","id":"slow","request":{}}"#);
        served.send(r#"{"type":"exec","id":"lost","request":{}}"#);
        let execs = served.container.wait_for(2);
        execs[0].1.exit(Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "the exec timed out",
        )));
        execs[1]
            .1
            .exit(Err(std::io::Error::other("outcome unknown")));
        let events = served
            .sink
            .wait_for(|events| ended(events, "lost").is_some());
        let rejected = ended(&events, "rejected").unwrap();
        assert_eq!(rejected["type"], "error");
        assert_eq!(rejected["error"]["code"], "policy_validation");
        assert_eq!(ended(&events, "slow").unwrap()["type"], "timeout");
        let lost = ended(&events, "lost").unwrap();
        assert_eq!(lost["type"], "error");
        assert_eq!(lost["error"]["code"], "backend_error");
        assert!(lost["error"]["message"]
            .as_str()
            .unwrap()
            .contains("outcome unknown"));
        // A failed exec does not end the container.
        served.send(r#"{"type":"exec","id":"after","request":{}}"#);
        served.container.wait_for(3)[2].1.exit(Ok(0));
        let (result, events) = served.end();
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(ended(&events, "after").unwrap()["exitCode"], 0);
    }

    #[test]
    fn malformed_requests_end_serving_and_cancel_running_execs() {
        for line in [
            "not json",
            r#"{"type":"exec","id":"x"}"#,
            r#"{"type":"cancel","id":"x","request":{}}"#,
            r#"{"type":"run","id":"x"}"#,
            r#"{"type":"cancel","id":"x","extra":true}"#,
            r#"{"type":"exec","id":"a","request":{}}"#,
        ] {
            let mut served = Served::new();
            served.send(r#"{"type":"exec","id":"a","request":{}}"#);
            let execs = served.container.wait_for(1);
            served.send(line);
            let error = served.server.join().unwrap().unwrap_err();
            assert_eq!(
                error.code,
                MxcErrorCode::MalformedRequest,
                "{line}: {error}"
            );
            assert_eq!(execs[0].1.kills.load(Ordering::SeqCst), 1, "{line}");
        }
    }

    #[test]
    fn a_caller_that_stops_reading_ends_serving() {
        struct Closed;
        impl Write for Closed {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let (reader, mut requests) = std::io::pipe().unwrap();
        let container = FakeContainer::default();
        let events = Events::new(Box::new(Closed));
        writeln!(requests, r#"{{"type":"exec","id":"a","request":{{}}}}"#).unwrap();
        let cancellation = RunCancellation::default();
        std::thread::scope(|scope| {
            let server = scope.spawn(|| serve(&container, reader, &events, &cancellation));
            let execs = container.wait_for(1);
            execs[0].1.exit(Ok(0));
            assert!(server.join().unwrap().is_ok());
        });
        drop(requests);
    }
}
