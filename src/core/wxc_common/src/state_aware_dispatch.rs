// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! State-aware dispatcher: routes a parsed state-aware request to the right
//! backend's `StatefulSandboxBackend` impl, runs the per-phase typed flow, and
//! produces either a JSON response envelope (non-exec phases or dispatch
//! failure) or an exit code (exec phase, which streams its output live).
//!
//! `run_state_aware` is the entry point invoked from `wxc-exec`'s main flow.
//! It resolves the backend (by `containment` for provision, by `sandbox_id`
//! prefix for non-provision phases) and either dispatches to the registered
//! state-aware backend or surfaces `unsupported_phase` for backends without a
//! state-aware impl.
//!
//! `dispatch_state_aware<B>` is the per-backend phase router, generic over the
//! `StatefulSandboxBackend` impl. It validates, calls the right phase method,
//! and wraps the typed result into a wire-format response envelope.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::Value;

use crate::exec_stream::wrap_read_checked;
use crate::id::parse_sandbox_id_prefix;
use crate::models::ContainmentBackend;
use crate::mxc_error::{MxcError, ResponseEnvelope};
use crate::state_aware_backend::{
    DeprovisionResult, ExecHandle, ExecOutcome, ExecStdio, ProvisionResult, StartResult,
    StatefulSandboxBackend, StopResult,
};
use crate::state_aware_request::{ParsedStateAwareRequest, Phase};
use crate::validator::validate_exec_common;

/// Outcome of dispatching one state-aware request. Distinguishes the two
/// success modes: non-exec phases produce a JSON envelope; exec phases stream
/// their output live and exit with the script's exit code.
#[derive(Debug)]
pub enum DispatchOutcome {
    /// JSON envelope to write to stdout (non-exec phases or dispatch failure).
    Envelope(Value),
    /// Exec phase completed; the executor process should exit with this code.
    /// Stdout already carried the script's output; no JSON envelope is emitted.
    ExecCompleted { exit_code: i32 },
}

/// Fallback dispatch for backends whose state-aware impl isn't reachable
/// from `wxc_common` (e.g. it lives in a backend crate that depends on
/// `wxc_common`, so a direct call here would create a cycle). Callers in
/// `wxc-exec` resolve known backends and invoke `dispatch_state_aware`
/// directly; anything they don't handle falls through to this function,
/// which surfaces `unsupported_phase` for the resolved backend.
pub fn run_state_aware(
    parsed: ParsedStateAwareRequest,
    dry_run: bool,
) -> Result<DispatchOutcome, MxcError> {
    let _ = dry_run;

    let backend = resolve_backend(&parsed)?;
    Err(MxcError::unsupported_phase(format!(
        "backend {:?} does not implement state-aware lifecycle",
        backend
    )))
}

/// Streaming counterpart of the exec phase of [`dispatch_state_aware`]: run the
/// exec phase up to (and including) [`StatefulSandboxBackend::exec`] and return
/// the resulting [`ExecHandle`] to the caller **without** relaying it to
/// this process's stdio.
///
/// This is what lets the library / FFI streaming path drive an exec live —
/// wrapping the returned handle in a [`SandboxProcess`](crate::sandbox_process::SandboxProcess)
/// via [`ExecSandboxProcess`](crate::exec_stream::ExecSandboxProcess) — instead
/// of the run-to-completion relay that [`dispatch_state_aware`] performs for
/// `wxc-exec`. Requires the `exec` phase; any other phase is a
/// `malformed_request`. `dry_run` has no meaning for a streaming exec (there is
/// nothing to stream) and is intentionally not accepted.
pub fn dispatch_state_aware_exec<B: StatefulSandboxBackend>(
    backend: &mut B,
    parsed: ParsedStateAwareRequest,
) -> Result<ExecHandle, MxcError> {
    if !matches!(parsed.phase, Phase::Exec) {
        return Err(MxcError::malformed_request(format!(
            "streaming exec requires the exec phase, got {}",
            parsed.phase
        )));
    }
    let request = parsed.request.clone();
    let sandbox_id = parsed.sandbox_id_required()?.to_string();
    let config = parsed.deserialize_config::<B::ExecConfig>(B::BACKEND_KEY, "exec")?;
    validate_exec_common(&request)?;
    backend.validate_exec(&sandbox_id, &request, config.as_ref())?;
    // The caller drives the returned streams itself, so the backend must
    // surface real pipes and leave this process's console alone.
    backend.exec(&sandbox_id, &request, config, ExecStdio::Piped)
}

/// Per-backend phase router. The `run_state_aware` arm for a participating
/// backend constructs `B` and delegates here.
pub fn dispatch_state_aware<B: StatefulSandboxBackend>(
    backend: &mut B,
    parsed: ParsedStateAwareRequest,
    dry_run: bool,
) -> Result<DispatchOutcome, MxcError> {
    let request = parsed.request.clone();
    let phase = parsed.phase;
    match phase {
        Phase::Provision => {
            let config =
                parsed.deserialize_config::<B::ProvisionConfig>(B::BACKEND_KEY, "provision")?;
            backend.validate_provision(&request, config.as_ref())?;
            if dry_run {
                return Ok(DispatchOutcome::Envelope(empty_result_envelope()));
            }
            let result = backend.provision(&request, config)?;
            Ok(DispatchOutcome::Envelope(provision_envelope(result)?))
        }
        Phase::Start => {
            let sandbox_id = parsed.sandbox_id_required()?.to_string();
            let config = parsed.deserialize_config::<B::StartConfig>(B::BACKEND_KEY, "start")?;
            backend.validate_start(&sandbox_id, &request, config.as_ref())?;
            if dry_run {
                return Ok(DispatchOutcome::Envelope(empty_result_envelope()));
            }
            let result = backend.start(&sandbox_id, &request, config)?;
            Ok(DispatchOutcome::Envelope(metadata_envelope(result)?))
        }
        Phase::Exec => {
            let sandbox_id = parsed.sandbox_id_required()?.to_string();
            let config = parsed.deserialize_config::<B::ExecConfig>(B::BACKEND_KEY, "exec")?;
            // Everything needed for exec is now owned (`request` clone, owned
            // `sandbox_id`, owned `config`); drop the parsed request so its
            // retained decoded source text and raw `experimental` tree are not
            // held for the (potentially long) blocking child run + stdio relay.
            drop(parsed);
            validate_exec_common(&request)?;
            backend.validate_exec(&sandbox_id, &request, config.as_ref())?;
            if dry_run {
                return Ok(DispatchOutcome::Envelope(empty_result_envelope()));
            }
            let handle = backend.exec(&sandbox_id, &request, config, ExecStdio::Relayed)?;
            let exit_code = relay_exec_to_stdio(handle)?;
            Ok(DispatchOutcome::ExecCompleted { exit_code })
        }
        Phase::Stop => {
            let sandbox_id = parsed.sandbox_id_required()?.to_string();
            let config = parsed.deserialize_config::<B::StopConfig>(B::BACKEND_KEY, "stop")?;
            backend.validate_stop(&sandbox_id, &request, config.as_ref())?;
            if dry_run {
                return Ok(DispatchOutcome::Envelope(empty_result_envelope()));
            }
            let result = backend.stop(&sandbox_id, &request, config)?;
            Ok(DispatchOutcome::Envelope(metadata_envelope(result)?))
        }
        Phase::Deprovision => {
            let sandbox_id = parsed.sandbox_id_required()?.to_string();
            let config =
                parsed.deserialize_config::<B::DeprovisionConfig>(B::BACKEND_KEY, "deprovision")?;
            backend.validate_deprovision(&sandbox_id, &request, config.as_ref())?;
            if dry_run {
                return Ok(DispatchOutcome::Envelope(empty_result_envelope()));
            }
            let result = backend.deprovision(&sandbox_id, &request, config)?;
            Ok(DispatchOutcome::Envelope(metadata_envelope(result)?))
        }
    }
}

/// Resolves the target backend: from `containment` for provision, from the
/// `sandbox_id` prefix for non-provision phases.
pub fn resolve_backend(parsed: &ParsedStateAwareRequest) -> Result<ContainmentBackend, MxcError> {
    if parsed.phase == Phase::Provision {
        return parsed.containment.clone().ok_or_else(|| {
            MxcError::malformed_request("provision phase requires a containment field")
        });
    }
    let sandbox_id = parsed.sandbox_id_required()?;
    let prefix = parse_sandbox_id_prefix(sandbox_id)?;
    backend_from_prefix(prefix)
}

/// Maps a state-aware sandbox-id prefix to its `ContainmentBackend`.
/// Subsequent state-aware backends register their prefix here.
fn backend_from_prefix(prefix: &str) -> Result<ContainmentBackend, MxcError> {
    match prefix {
        "iso" => Ok(ContainmentBackend::IsolationSession),
        "lxc" => Ok(ContainmentBackend::Lxc),
        "wsb" => Ok(ContainmentBackend::WindowsSandbox),
        "wslc" => Ok(ContainmentBackend::Wslc),
        // Future state-aware backends extend this list.
        other => Err(MxcError::unsupported_containment(format!(
            "no state-aware backend registered for prefix {:?}",
            other
        ))),
    }
}

/// Streams the running process's pipes to this process's stdio and waits for exit.
///
/// Relay threads start **before** the waiter runs: a child that fills its
/// stdout pipe buffer would otherwise block forever, since nothing would be
/// draining it while we wait.
///
/// - **stdout / stderr** are pumped to this process's own streams and drained
///   after the waiter returns, so output already in flight is not lost to the
///   executor exiting first. That drain is time-bounded: see [`drain_pumps`]
///   for what is given up when a writer outlives the workload.
/// - **stdin is not forwarded.** `ExecHandle::stdin` is left untouched here.
///   Forwarding it correctly needs an ownership model this type does not yet
///   have -- a pipe reaches EOF only once *every* write handle is closed, and
///   the relay can only borrow-and-duplicate the backend's handle, so neither
///   side is able to close the child's stdin. It also needs a stop signal, as a
///   read on the executor's stdin never returns when that stdin is a console or
///   node-pty handle held open by a parent. IsolationSession's own relay
///   documents both hazards and solves them with
///   `create_relay_thread_with_stop`; the generic path will need an equivalent.
///
///   Until that exists, a backend under [`ExecStdio::Relayed`] **must not
///   give the child a stdin pipe whose write end it keeps**. Nothing here writes
///   to that pipe and nothing can close it, so a workload that reads stdin
///   blocks forever -- and it does so while this function is inside `waiter()`,
///   which the drain bound does not cover, hanging the executor with the sandbox
///   still alive. Wire the child's stdin to something already at EOF instead.
///
/// Each stream is written through and flushed as it arrives rather than via
/// `io::copy`, because Rust's stdout is line-buffered: a progress indicator
/// that emits partial lines (or bare `\r`) must still appear progressively.
///
/// **Backend contract:** the backend must not retain its own copy of the
/// child's *write* ends. The pumps finish on EOF, which the OS reports only
/// once every writer handle is closed; a retained duplicate keeps a pump alive
/// until the drain gives up on it, costing that delay and the output still
/// buffered behind it.
///
/// A backend that relays internally hands back null pipe handles plus a waiter
/// that yields the already-captured exit code. No wrapping succeeds, no thread
/// is spawned, and this reduces to calling the waiter — the original
/// call-through behaviour, unchanged.
///
/// Deliberately not built on IsolationSession's `pipe_relay`, which solves the
/// same problem for that backend: it lives in a `backends/*` crate that
/// `wxc_common` must not depend on, it is Windows-only (raw `HANDLE`s and
/// `CreateThread`), and it is `unsafe`. This dispatcher is cross-platform and
/// stays in safe `std::io`. Its per-write flush is the same conclusion that
/// relay reached independently.
fn relay_exec_to_stdio(handle: ExecHandle) -> Result<i32, MxcError> {
    let ExecHandle {
        stdout,
        stderr,
        stdin: _,
        waiter,
        terminator,
        // This relay forwards no input, so the backend's stdin end is left to
        // the backend's own teardown.
        stdin_closer: _,
    } = handle;

    // Classify every stream before committing to anything. A null handle is an
    // absent stream and is fine; a handle the backend named but that cannot be
    // duplicated is a setup failure -- see `wrap_read_checked`.
    let streams = wrap_read_checked(stdout, "stdout").and_then(|out| {
        let err = wrap_read_checked(stderr, "stderr")?;
        Ok(RelayStreams {
            stdout: out,
            stderr: err,
        })
    });

    relay_prepared_streams(streams, waiter, terminator)
}

/// The streams a relay will pump, once classified.
struct RelayStreams {
    stdout: Option<Box<dyn std::io::Read + Send>>,
    stderr: Option<Box<dyn std::io::Read + Send>>,
}

/// Run the relay over already-classified streams.
///
/// Split from [`relay_exec_to_stdio`] so the failure paths are reachable in a
/// test without fabricating an invalid OS handle: a caller can hand this an
/// `Err` directly and observe the exec being terminated and then reaped.
fn relay_prepared_streams(
    streams: Result<RelayStreams, MxcError>,
    waiter: Box<dyn FnOnce() -> Result<ExecOutcome, MxcError> + Send>,
    terminator: Box<dyn FnOnce() -> Result<(), MxcError> + Send>,
) -> Result<i32, MxcError> {
    let streams = match streams {
        Ok(streams) => streams,
        Err(error) => return abort_relay(waiter, terminator, Vec::new(), error),
    };

    // Pumps are started fallibly and *before* the waiter runs: a child that
    // fills its stdout pipe buffer would otherwise block forever, since nothing
    // would be draining it while we wait. `thread::spawn` would panic if the OS
    // refused, which here would unwind past the terminator and leave the
    // workload running.
    let mut pumps: Vec<Pump> = Vec::new();

    if let Some(src) = streams.stdout {
        match spawn_pump("mxc-relay-stdout", src, std::io::stdout()) {
            Ok(pump) => pumps.push(pump),
            Err(error) => return abort_relay(waiter, terminator, pumps, error),
        }
    }
    if let Some(src) = streams.stderr {
        match spawn_pump("mxc-relay-stderr", src, std::io::stderr()) {
            Ok(pump) => pumps.push(pump),
            Err(error) => return abort_relay(waiter, terminator, pumps, error),
        }
    }

    // `terminator` stays alive until the end of this scope: the closure may own
    // resources tied to the running process, and the waiter-error path below
    // still needs to invoke it.
    let outcome = waiter();

    // A waiter error means "I could not determine the exit", not "the child is
    // dead" -- so the workload may still be running and still holding the write
    // ends. Terminate before draining, exactly as `abort_relay` does. The drain
    // is bounded, so the cost of getting this order wrong is not a hang: it is a
    // stall for the whole grace period, followed by the loss of whatever output
    // was still buffered behind those write ends.
    if outcome.is_err() {
        let _ = terminator();
    }

    // Drain what the child wrote before it exited. Bounded -- see `drain_pumps`.
    drain_pumps(pumps);

    // A backend serving `ExecStdio::Relayed` reports `Exited`, so a timeout
    // here is a contract violation.
    match outcome {
        Ok(ExecOutcome::Exited(code)) => Ok(code),
        Ok(ExecOutcome::TimedOut) => Err(MxcError::backend_error(
            "backend reported a timeout to the relay, which has no way \
             to represent one; a backend serving ExecStdio::Relayed must \
             report ExecOutcome::Exited",
        )),
        Err(error) => Err(error),
    }
}

/// Join `pumps`, giving them at most [`POST_EXIT_DRAIN_GRACE`] between them.
///
/// A pump only ends at EOF, which needs *every* writer closed -- and a
/// backgrounded descendant that inherited the pipe can hold its write end open
/// long after the foreground command exits (the same hazard `sandbox_process`
/// documents, and solves there with a cancel-and-discard). Once the exit code
/// is in hand, truncating late output is the lesser loss against never
/// returning it at all.
///
/// A pump that misses the deadline is **muted** rather than merely abandoned.
/// Its thread outlives this call still holding a live read handle, and an
/// unmuted one would go on writing to the process's stdout -- where it can
/// interleave with whatever the caller emits next. The error envelope is the
/// case that matters: it is JSON, and a machine parses it, so a stray chunk of
/// child output appended to it turns a diagnosable backend error into a parse
/// failure.
///
/// Muting is not instantaneous: a pump blocked mid-write can still land the
/// chunk it already committed to. It takes effect from the next read onward,
/// which closes the window that lasts as long as the process does.
fn drain_pumps(pumps: Vec<Pump>) {
    drain_pumps_within(pumps, POST_EXIT_DRAIN_GRACE);
}

/// [`drain_pumps`] with the grace period injected — the seam that lets a test
/// drive the expiry path without waiting out the real one.
fn drain_pumps_within(pumps: Vec<Pump>, grace: Duration) {
    let deadline = Instant::now() + grace;
    for pump in pumps {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if pump.finished.recv_timeout(remaining).is_ok() {
            let _ = pump.thread.join();
        } else {
            pump.mute();
        }
    }
}

/// How long the relay waits for its pumps to drain after the exec has exited.
/// Long enough to flush what a finished child left in the pipe, short enough
/// that a descendant holding the write end open cannot wedge the executor.
const POST_EXIT_DRAIN_GRACE: Duration = Duration::from_secs(5);

/// A running pump: the thread, plus a signal it sends when its copy loop ends.
/// The signal is what makes the post-exit drain boundable -- `JoinHandle` has
/// no timed join.
struct Pump {
    thread: std::thread::JoinHandle<()>,
    finished: std::sync::mpsc::Receiver<()>,
    muted: Arc<AtomicBool>,
}

impl Pump {
    /// Stop this pump writing to its destination, without waiting for it.
    ///
    /// The thread keeps reading and discarding rather than stopping outright:
    /// its source is still connected to the workload, and abandoning a full
    /// pipe is what wedges a child that is still writing.
    fn mute(&self) {
        self.muted.store(true, Ordering::Relaxed);
    }
}

/// Tear down a relay that could not be set up: terminate the exec that was
/// already started, drain any pump that did start, then **run the waiter** so
/// the exec is reaped rather than merely signalled.
///
/// Terminating is a request, not a reaping. Dropping the waiter instead of
/// running it skips whatever completion work the backend put behind it and, for
/// a local child on Unix, leaves a zombie until the executor exits. The
/// streaming adapter's `Drop` already terminates-then-joins for this reason;
/// this is the same contract on the failure path.
///
/// Running it is as much as this can promise. `waiter` is `FnOnce`, so if it
/// fails -- which by its own contract means the exit could not be determined,
/// not that the child is gone -- it has been consumed and no reaping operation
/// is left to retry. Closing that gap needs a separate, infallible reaper on
/// [`ExecHandle`]; until then a failed wait during teardown can leave the exec
/// terminated but unreaped.
///
/// The drain is bounded for the same reason the post-exit one is: terminating
/// the foreground child does *not* guarantee its write ends are closed, because
/// a backgrounded descendant may still hold them. An unbounded join here would
/// hang before reaching the waiter and so defeat the one thing this function
/// exists to guarantee.
///
/// The waiter's own outcome is discarded: the setup error is what the caller
/// needs to see, and masking it with a teardown result would hide the cause.
fn abort_relay(
    waiter: Box<dyn FnOnce() -> Result<ExecOutcome, MxcError> + Send>,
    terminator: Box<dyn FnOnce() -> Result<(), MxcError> + Send>,
    pumps: Vec<Pump>,
    error: MxcError,
) -> Result<i32, MxcError> {
    let _ = terminator();
    drain_pumps(pumps);
    let _ = waiter();
    Err(error)
}

/// Start one named pump thread, reporting an OS refusal instead of panicking.
///
/// The returned [`Pump`] carries a completion signal alongside the join handle
/// so callers can bound how long they wait for it; see [`drain_pumps`].
fn spawn_pump<R, W>(name: &str, src: R, dst: W) -> Result<Pump, MxcError>
where
    R: std::io::Read + Send + 'static,
    W: std::io::Write + Send + 'static,
{
    let muted = Arc::new(AtomicBool::new(false));
    let thread_muted = Arc::clone(&muted);
    let (finished_tx, finished) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            pump_stream(src, dst, &thread_muted);
            let _ = finished_tx.send(());
        })
        .map(|thread| Pump {
            thread,
            finished,
            muted,
        })
        .map_err(|error| MxcError::backend_error(format!("failed to start {name}: {error}")))
}

/// Copy `src` to `dst` until EOF, flushing after every chunk so output reaches
/// the terminal as it is produced.
///
/// **Draining does not stop when the destination breaks.** If the executor's
/// own stdout goes away, this keeps reading and discards instead of returning:
/// the backend still holds the read handle's peer, so the child may never see
/// a broken pipe -- it would simply fill the buffer and block forever while the
/// waiter waits for an exit that cannot come. Losing output is recoverable;
/// wedging the workload is not.
///
/// `muted` is the same policy imposed from outside: set once the relay has
/// stopped waiting for this pump, so it stops writing to a destination it no
/// longer has exclusive use of, while still draining its source. See
/// [`drain_pumps`].
///
/// Read errors do end the pump: there is nothing left to drain.
fn pump_stream<R: std::io::Read, W: std::io::Write>(mut src: R, mut dst: W, muted: &AtomicBool) {
    let mut buf = [0u8; 8192];
    let mut discarding = false;
    loop {
        match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if !discarding && !muted.load(Ordering::Relaxed) {
                    // A failed flush is as fatal to the destination as a failed
                    // write: either way nothing more will reach it.
                    let wrote = dst.write_all(&buf[..n]).and_then(|()| dst.flush());
                    if wrote.is_err() {
                        discarding = true;
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}

// ---------- Wire-format envelope construction ----------

/// `{ "result": { "sandboxId": "...", "metadata": {...}? } }`
#[derive(Serialize)]
struct ProvisionWireBody<M: Serialize> {
    #[serde(rename = "sandboxId")]
    sandbox_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<M>,
}

/// `{ "metadata": {...}? }` — used by start / stop / deprovision phases.
#[derive(Serialize)]
struct MetadataWireBody<M: Serialize> {
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<M>,
}

fn provision_envelope<M: Serialize>(r: ProvisionResult<M>) -> Result<Value, MxcError> {
    let body = ProvisionWireBody {
        sandbox_id: r.sandbox_id,
        metadata: r.metadata,
    };
    let envelope = ResponseEnvelope::Result(body);
    serde_json::to_value(&envelope).map_err(|e| {
        MxcError::backend_error(format!("provision envelope serialisation failed: {}", e))
    })
}

fn metadata_envelope<R: HasMetadata>(r: R) -> Result<Value, MxcError> {
    let body = MetadataWireBody {
        metadata: r.into_metadata(),
    };
    let envelope = ResponseEnvelope::Result(body);
    serde_json::to_value(&envelope).map_err(|e| {
        MxcError::backend_error(format!("metadata envelope serialisation failed: {}", e))
    })
}

fn empty_result_envelope() -> Value {
    serde_json::json!({"result": {}})
}

// Lets `metadata_envelope` accept any of the per-phase result types without a
// long manual match.
trait HasMetadata {
    type Metadata: Serialize;
    fn into_metadata(self) -> Option<Self::Metadata>;
}

impl<M: Serialize> HasMetadata for StartResult<M> {
    type Metadata = M;
    fn into_metadata(self) -> Option<M> {
        self.metadata
    }
}
impl<M: Serialize> HasMetadata for StopResult<M> {
    type Metadata = M;
    fn into_metadata(self) -> Option<M> {
        self.metadata
    }
}
impl<M: Serialize> HasMetadata for DeprovisionResult<M> {
    type Metadata = M;
    fn into_metadata(self) -> Option<M> {
        self.metadata
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ExecutionRequest;
    use crate::mxc_error::MxcErrorCode;
    use serde::{Deserialize, Serialize};
    use serde_json::json;
    use std::cell::Cell;
    use std::time::Duration;

    /// Fully-configurable backend stub for dispatcher tests.
    /// Each phase is wired to either succeed (the default — empty result with
    /// no metadata) or fail with a typed `MxcError` (set via the `*_error`
    /// fields). Calls to each phase method are counted on `*_calls` so tests
    /// can assert the routing landed on the right method.
    struct StubBackend {
        provision_calls: Cell<u32>,
        start_calls: Cell<u32>,
        exec_calls: Cell<u32>,
        stop_calls: Cell<u32>,
        deprovision_calls: Cell<u32>,
        validate_provision_calls: Cell<u32>,
        validate_start_calls: Cell<u32>,
        validate_exec_calls: Cell<u32>,
        validate_stop_calls: Cell<u32>,
        validate_deprovision_calls: Cell<u32>,
        /// The [`ExecStdio`] the dispatcher passed to the most recent
        /// `exec`. Swapping the two variants would compile and silently
        /// change behaviour on both paths.
        last_exec_stdio: Cell<Option<ExecStdio>>,
        provision_error: Option<MxcError>,
        validate_provision_error: Option<MxcError>,
    }

    impl StubBackend {
        fn new() -> Self {
            Self {
                provision_calls: Cell::new(0),
                start_calls: Cell::new(0),
                exec_calls: Cell::new(0),
                stop_calls: Cell::new(0),
                deprovision_calls: Cell::new(0),
                validate_provision_calls: Cell::new(0),
                validate_start_calls: Cell::new(0),
                validate_exec_calls: Cell::new(0),
                validate_stop_calls: Cell::new(0),
                validate_deprovision_calls: Cell::new(0),
                last_exec_stdio: Cell::new(None),
                provision_error: None,
                validate_provision_error: None,
            }
        }
    }

    impl StatefulSandboxBackend for StubBackend {
        const ID_PREFIX: &'static str = "stubd";
        const BACKEND_KEY: &'static str = "stub_dispatch";
        type ProvisionConfig = ();
        type StartConfig = ();
        type ExecConfig = ();
        type StopConfig = ();
        type DeprovisionConfig = ();
        type ProvisionMetadata = ();
        type StartMetadata = ();
        type StopMetadata = ();
        type DeprovisionMetadata = ();

        fn provision(
            &mut self,
            _request: &ExecutionRequest,
            _config: Option<()>,
        ) -> Result<ProvisionResult<()>, MxcError> {
            self.provision_calls.set(self.provision_calls.get() + 1);
            if let Some(e) = self.provision_error.clone() {
                return Err(e);
            }
            Ok(ProvisionResult {
                sandbox_id: format!("{}:fixed-token", Self::ID_PREFIX),
                metadata: None,
            })
        }
        fn start(
            &mut self,
            _sandbox_id: &str,
            _request: &ExecutionRequest,
            _config: Option<()>,
        ) -> Result<StartResult<()>, MxcError> {
            self.start_calls.set(self.start_calls.get() + 1);
            Ok(StartResult { metadata: None })
        }
        fn exec(
            &mut self,
            _sandbox_id: &str,
            _request: &ExecutionRequest,
            _config: Option<()>,
            stdio: ExecStdio,
        ) -> Result<ExecHandle, MxcError> {
            self.exec_calls.set(self.exec_calls.get() + 1);
            self.last_exec_stdio.set(Some(stdio));
            Err(MxcError::backend_error("stub exec not wired"))
        }
        fn stop(
            &mut self,
            _sandbox_id: &str,
            _request: &ExecutionRequest,
            _config: Option<()>,
        ) -> Result<StopResult<()>, MxcError> {
            self.stop_calls.set(self.stop_calls.get() + 1);
            Ok(StopResult { metadata: None })
        }
        fn deprovision(
            &mut self,
            _sandbox_id: &str,
            _request: &ExecutionRequest,
            _config: Option<()>,
        ) -> Result<DeprovisionResult<()>, MxcError> {
            self.deprovision_calls.set(self.deprovision_calls.get() + 1);
            Ok(DeprovisionResult { metadata: None })
        }

        fn validate_provision(
            &self,
            _request: &ExecutionRequest,
            _config: Option<&()>,
        ) -> Result<(), MxcError> {
            self.validate_provision_calls
                .set(self.validate_provision_calls.get() + 1);
            if let Some(e) = self.validate_provision_error.clone() {
                return Err(e);
            }
            Ok(())
        }
        fn validate_start(
            &self,
            _sandbox_id: &str,
            _request: &ExecutionRequest,
            _config: Option<&()>,
        ) -> Result<(), MxcError> {
            self.validate_start_calls
                .set(self.validate_start_calls.get() + 1);
            Ok(())
        }
        fn validate_exec(
            &self,
            _sandbox_id: &str,
            _request: &ExecutionRequest,
            _config: Option<&()>,
        ) -> Result<(), MxcError> {
            self.validate_exec_calls
                .set(self.validate_exec_calls.get() + 1);
            Ok(())
        }
        fn validate_stop(
            &self,
            _sandbox_id: &str,
            _request: &ExecutionRequest,
            _config: Option<&()>,
        ) -> Result<(), MxcError> {
            self.validate_stop_calls
                .set(self.validate_stop_calls.get() + 1);
            Ok(())
        }
        fn validate_deprovision(
            &self,
            _sandbox_id: &str,
            _request: &ExecutionRequest,
            _config: Option<&()>,
        ) -> Result<(), MxcError> {
            self.validate_deprovision_calls
                .set(self.validate_deprovision_calls.get() + 1);
            Ok(())
        }
    }

    /// Backend that exercises typed-config deserialisation via
    /// `ParsedStateAwareRequest::deserialize_config`. The dispatcher's start
    /// phase must extract `experimental.<BACKEND_KEY>.start` into this type
    /// and pass it through to `start()`.
    #[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Default)]
    struct TypedStartConfig {
        configuration_id: String,
    }

    struct TypedConfigStubBackend {
        captured_start_config: Cell<Option<TypedStartConfig>>,
    }

    impl TypedConfigStubBackend {
        fn new() -> Self {
            Self {
                captured_start_config: Cell::new(None),
            }
        }
    }

    impl StatefulSandboxBackend for TypedConfigStubBackend {
        const ID_PREFIX: &'static str = "typed";
        const BACKEND_KEY: &'static str = "typed_stub";
        type ProvisionConfig = ();
        type StartConfig = TypedStartConfig;
        type ExecConfig = ();
        type StopConfig = ();
        type DeprovisionConfig = ();
        type ProvisionMetadata = ();
        type StartMetadata = ();
        type StopMetadata = ();
        type DeprovisionMetadata = ();

        fn exec(
            &mut self,
            _sandbox_id: &str,
            _request: &ExecutionRequest,
            _config: Option<()>,
            _stdio: ExecStdio,
        ) -> Result<ExecHandle, MxcError> {
            Err(MxcError::backend_error("typed stub exec not wired"))
        }

        fn start(
            &mut self,
            _sandbox_id: &str,
            _request: &ExecutionRequest,
            config: Option<TypedStartConfig>,
        ) -> Result<StartResult<()>, MxcError> {
            self.captured_start_config.set(config);
            Ok(StartResult { metadata: None })
        }
    }

    fn parsed(
        phase: Phase,
        sandbox_id: Option<&str>,
        exp: Option<Value>,
    ) -> ParsedStateAwareRequest {
        ParsedStateAwareRequest {
            request: ExecutionRequest::default(),
            phase,
            containment: Some(ContainmentBackend::IsolationSession),
            sandbox_id: sandbox_id.map(String::from),
            correlation_vector: None,
            experimental_raw: exp,
            source_text: None,
        }
    }

    /// Like [`parsed`], but with a command line set so the request survives
    /// `validate_exec_common` and dispatch actually reaches `exec`. The default
    /// request has an empty `script_code`, which is rejected before the backend
    /// is called.
    fn parsed_runnable_exec(sandbox_id: &str) -> ParsedStateAwareRequest {
        let mut p = parsed(Phase::Exec, Some(sandbox_id), None);
        p.request.script_code = "echo hi".to_string();
        p
    }

    fn assert_envelope(outcome: DispatchOutcome) -> Value {
        match outcome {
            DispatchOutcome::Envelope(v) => v,
            DispatchOutcome::ExecCompleted { exit_code } => {
                panic!(
                    "expected envelope, got ExecCompleted {{ exit_code: {} }}",
                    exit_code
                )
            }
        }
    }

    #[test]
    fn dispatch_provision_calls_validate_then_provision() {
        let mut b = StubBackend::new();
        let env = assert_envelope(
            dispatch_state_aware(&mut b, parsed(Phase::Provision, None, None), false).unwrap(),
        );
        assert_eq!(b.validate_provision_calls.get(), 1);
        assert_eq!(b.provision_calls.get(), 1);
        assert_eq!(env, json!({"result": {"sandboxId": "stubd:fixed-token"}}));
    }

    #[test]
    fn dispatch_provision_dry_run_skips_provision_call_but_runs_validate() {
        let mut b = StubBackend::new();
        let env = assert_envelope(
            dispatch_state_aware(&mut b, parsed(Phase::Provision, None, None), true).unwrap(),
        );
        assert_eq!(b.validate_provision_calls.get(), 1);
        assert_eq!(b.provision_calls.get(), 0);
        assert_eq!(env, json!({"result": {}}));
    }

    #[test]
    fn dispatch_provision_returns_validate_error_without_calling_provision() {
        let mut b = StubBackend::new();
        b.validate_provision_error = Some(MxcError::policy_validation("nope"));
        let err =
            dispatch_state_aware(&mut b, parsed(Phase::Provision, None, None), false).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
        assert_eq!(b.validate_provision_calls.get(), 1);
        assert_eq!(b.provision_calls.get(), 0);
    }

    #[test]
    fn dispatch_provision_propagates_provision_error() {
        let mut b = StubBackend::new();
        b.provision_error = Some(MxcError::backend_error("boom"));
        let err =
            dispatch_state_aware(&mut b, parsed(Phase::Provision, None, None), false).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::BackendError);
        assert_eq!(b.provision_calls.get(), 1);
    }

    #[test]
    fn dispatch_start_requires_sandbox_id() {
        let mut b = StubBackend::new();
        let err =
            dispatch_state_aware(&mut b, parsed(Phase::Start, None, None), false).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedRequest);
        assert_eq!(b.start_calls.get(), 0);
    }

    #[test]
    fn dispatch_start_calls_validate_then_start() {
        let mut b = StubBackend::new();
        let env = assert_envelope(
            dispatch_state_aware(&mut b, parsed(Phase::Start, Some("stubd:abc"), None), false)
                .unwrap(),
        );
        assert_eq!(b.validate_start_calls.get(), 1);
        assert_eq!(b.start_calls.get(), 1);
        assert_eq!(env, json!({"result": {}}));
    }

    #[test]
    fn dispatch_exec_validate_common_rejects_empty_command_line() {
        let mut b = StubBackend::new();
        let err = dispatch_state_aware(&mut b, parsed(Phase::Exec, Some("stubd:abc"), None), false)
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedRequest);
        assert_eq!(b.validate_exec_calls.get(), 0);
        assert_eq!(b.exec_calls.get(), 0);
    }

    #[test]
    fn dispatch_exec_dry_run_skips_exec_call() {
        let mut b = StubBackend::new();
        let mut p = parsed(Phase::Exec, Some("stubd:abc"), None);
        p.request.script_code = "echo".into();
        let env = assert_envelope(dispatch_state_aware(&mut b, p, true).unwrap());
        assert_eq!(b.validate_exec_calls.get(), 1);
        assert_eq!(b.exec_calls.get(), 0);
        assert_eq!(env, json!({"result": {}}));
    }

    // The remaining three phases complete the dry-run contract: `--dry-run`
    // must run the validation hook and then NOT execute the phase body.
    //
    // These exist because the E2E harness cannot pin this. For `start`, `stop`
    // and `deprovision` the real backends return `metadata: None`, which the
    // dispatcher renders as `{"result":{}}` — byte-identical to the dry-run
    // short-circuit's own envelope. So no observable at the process boundary
    // distinguishes "the phase ran" from "the phase was skipped"; only a
    // call-counting backend can. A per-arm regression that stopped honouring
    // `dry_run` in one of these phases would otherwise be invisible.

    #[test]
    fn dispatch_start_dry_run_skips_start_call_but_runs_validate() {
        let mut b = StubBackend::new();
        let env = assert_envelope(
            dispatch_state_aware(&mut b, parsed(Phase::Start, Some("stubd:abc"), None), true)
                .unwrap(),
        );
        assert_eq!(b.validate_start_calls.get(), 1);
        assert_eq!(b.start_calls.get(), 0, "dry-run must not start the sandbox");
        assert_eq!(env, json!({"result": {}}));
    }

    #[test]
    fn dispatch_stop_dry_run_skips_stop_call_but_runs_validate() {
        let mut b = StubBackend::new();
        let env = assert_envelope(
            dispatch_state_aware(&mut b, parsed(Phase::Stop, Some("stubd:abc"), None), true)
                .unwrap(),
        );
        assert_eq!(b.validate_stop_calls.get(), 1);
        assert_eq!(b.stop_calls.get(), 0, "dry-run must not stop the sandbox");
        assert_eq!(env, json!({"result": {}}));
    }

    #[test]
    fn dispatch_deprovision_dry_run_skips_deprovision_call_but_runs_validate() {
        let mut b = StubBackend::new();
        let env = assert_envelope(
            dispatch_state_aware(
                &mut b,
                parsed(Phase::Deprovision, Some("stubd:abc"), None),
                true,
            )
            .unwrap(),
        );
        assert_eq!(b.validate_deprovision_calls.get(), 1);
        assert_eq!(
            b.deprovision_calls.get(),
            0,
            "dry-run must not deprovision the sandbox"
        );
        assert_eq!(env, json!({"result": {}}));
    }

    #[test]
    fn dispatch_stop_routes_correctly() {
        let mut b = StubBackend::new();
        assert_envelope(
            dispatch_state_aware(&mut b, parsed(Phase::Stop, Some("stubd:abc"), None), false)
                .unwrap(),
        );
        assert_eq!(b.validate_stop_calls.get(), 1);
        assert_eq!(b.stop_calls.get(), 1);
    }

    #[test]
    fn dispatch_deprovision_routes_correctly() {
        let mut b = StubBackend::new();
        assert_envelope(
            dispatch_state_aware(
                &mut b,
                parsed(Phase::Deprovision, Some("stubd:abc"), None),
                false,
            )
            .unwrap(),
        );
        assert_eq!(b.validate_deprovision_calls.get(), 1);
        assert_eq!(b.deprovision_calls.get(), 1);
    }

    #[test]
    fn typed_config_stub_receives_typed_start_config() {
        let mut b = TypedConfigStubBackend::new();
        let exp = json!({
            "typed_stub": { "start": {"configuration_id": "small"} }
        });
        let p = parsed(Phase::Start, Some("typed:abc"), Some(exp));
        assert_envelope(dispatch_state_aware(&mut b, p, false).unwrap());
        let captured = b.captured_start_config.into_inner();
        assert_eq!(
            captured,
            Some(TypedStartConfig {
                configuration_id: "small".into()
            })
        );
    }

    #[test]
    fn typed_config_stub_receives_none_when_experimental_block_absent() {
        let mut b = TypedConfigStubBackend::new();
        let p = parsed(Phase::Start, Some("typed:abc"), None);
        assert_envelope(dispatch_state_aware(&mut b, p, false).unwrap());
        assert_eq!(b.captured_start_config.into_inner(), None);
    }

    #[test]
    fn typed_config_stub_surfaces_shape_mismatch_as_malformed_request() {
        let mut b = TypedConfigStubBackend::new();
        // Wrong shape — missing required `configuration_id`.
        let exp = json!({
            "typed_stub": { "start": {"wrong_field": 1} }
        });
        let p = parsed(Phase::Start, Some("typed:abc"), Some(exp));
        let err = dispatch_state_aware(&mut b, p, false).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedRequest);
        assert!(
            err.message.contains("experimental.typed_stub.start"),
            "expected envelope-ready error path, got: {}",
            err.message
        );
        assert_eq!(b.captured_start_config.into_inner(), None);
    }

    // ---------- run_state_aware / resolve_backend ----------

    #[test]
    fn run_state_aware_provision_for_recognized_backend_returns_unsupported_phase() {
        // No state-aware impls registered yet — every recognized backend is
        // unsupported. Smoke-test scenario #2 from decision 6.
        let p = ParsedStateAwareRequest {
            request: ExecutionRequest::default(),
            phase: Phase::Provision,
            containment: Some(ContainmentBackend::Wslc),
            sandbox_id: None,
            correlation_vector: None,
            experimental_raw: None,
            source_text: None,
        };
        let err = run_state_aware(p, false).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::UnsupportedPhase);
    }

    #[test]
    fn run_state_aware_provision_without_containment_is_malformed() {
        let p = ParsedStateAwareRequest {
            request: ExecutionRequest::default(),
            phase: Phase::Provision,
            containment: None,
            sandbox_id: None,
            correlation_vector: None,
            experimental_raw: None,
            source_text: None,
        };
        let err = run_state_aware(p, false).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedRequest);
    }

    #[test]
    fn resolve_backend_for_iso_prefix_returns_isolation_session() {
        let p = ParsedStateAwareRequest {
            request: ExecutionRequest::default(),
            phase: Phase::Start,
            containment: None,
            sandbox_id: Some("iso:wxc-abcd1234".into()),
            correlation_vector: None,
            experimental_raw: None,
            source_text: None,
        };
        assert_eq!(
            resolve_backend(&p).unwrap(),
            ContainmentBackend::IsolationSession
        );
    }

    #[test]
    fn resolve_backend_for_lxc_prefix_returns_lxc() {
        let p = ParsedStateAwareRequest {
            request: ExecutionRequest::default(),
            phase: Phase::Start,
            containment: None,
            sandbox_id: Some("lxc:mxc-abcd1234".into()),
            correlation_vector: None,
            experimental_raw: None,
            source_text: None,
        };
        assert_eq!(resolve_backend(&p).unwrap(), ContainmentBackend::Lxc);
    }

    #[test]
    fn resolve_backend_for_wsb_prefix_returns_windows_sandbox() {
        let p = ParsedStateAwareRequest {
            request: ExecutionRequest::default(),
            phase: Phase::Start,
            containment: None,
            sandbox_id: Some("wsb:deadbeef".into()),
            correlation_vector: None,
            experimental_raw: None,
            source_text: None,
        };
        assert_eq!(
            resolve_backend(&p).unwrap(),
            ContainmentBackend::WindowsSandbox
        );
    }

    #[test]
    fn resolve_backend_for_wslc_prefix_returns_wslc() {
        let p = ParsedStateAwareRequest {
            request: ExecutionRequest::default(),
            phase: Phase::Start,
            containment: None,
            sandbox_id: Some("wslc:deadbeef".into()),
            correlation_vector: None,
            experimental_raw: None,
            source_text: None,
        };
        assert_eq!(resolve_backend(&p).unwrap(), ContainmentBackend::Wslc);
    }

    #[test]
    fn resolve_backend_for_unknown_prefix_returns_unsupported_containment() {
        let p = ParsedStateAwareRequest {
            request: ExecutionRequest::default(),
            phase: Phase::Start,
            containment: None,
            sandbox_id: Some("unknownxyz:abc".into()),
            correlation_vector: None,
            experimental_raw: None,
            source_text: None,
        };
        let err = resolve_backend(&p).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::UnsupportedContainment);
    }

    #[test]
    fn resolve_backend_for_malformed_id_surfaces_malformed_id() {
        let p = ParsedStateAwareRequest {
            request: ExecutionRequest::default(),
            phase: Phase::Start,
            containment: None,
            sandbox_id: Some("no-colon".into()),
            correlation_vector: None,
            experimental_raw: None,
            source_text: None,
        };
        let err = resolve_backend(&p).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
    }

    // ===== stdio topology per entry point ===================================
    //
    // Which topology each entry point sends is the whole point of the parameter,
    // and getting it backwards would compile: a relayed exec would lose its
    // console, and a piped caller would have its own console written to by a
    // sandbox. Both directions are pinned.

    /// The relayed path relays the handle to this process's stdio, so the backend
    /// may probe this process's terminal state to decide whether to allocate a
    /// pseudo-console.
    #[test]
    fn dispatch_state_aware_asks_for_relayed_stdio() {
        let mut b = StubBackend::new();
        let _ = dispatch_state_aware(&mut b, parsed_runnable_exec("stubd:abc"), false);
        assert_eq!(b.exec_calls.get(), 1, "exec should have been reached");
        assert_eq!(
            b.last_exec_stdio.get(),
            Some(ExecStdio::Relayed),
            "the relayed path must not ask a backend for caller-owned pipes"
        );
    }

    /// The streaming path hands the caller the streams, so the backend must be
    /// told to surface separate raw pipes and leave the host console alone.
    #[test]
    fn dispatch_state_aware_exec_asks_for_piped_stdio() {
        let mut b = StubBackend::new();
        let _ = dispatch_state_aware_exec(&mut b, parsed_runnable_exec("stubd:abc"));
        assert_eq!(b.exec_calls.get(), 1, "exec should have been reached");
        assert_eq!(
            b.last_exec_stdio.get(),
            Some(ExecStdio::Piped),
            "the streaming path must never let a backend touch the caller's console"
        );
    }

    // ===== relay_exec_to_stdio =============================================

    use crate::state_aware_backend::null_pipe_handle;
    use std::io::{Read, Write};

    // Build a PipeHandle from a live pipe end. The relay duplicates it, so the
    // original stays owned by the test.
    #[cfg(target_os = "windows")]
    fn reader_handle(r: &std::io::PipeReader) -> crate::state_aware_backend::PipeHandle {
        use std::os::windows::io::AsRawHandle;
        windows::Win32::Foundation::HANDLE(r.as_raw_handle() as _)
    }
    #[cfg(not(target_os = "windows"))]
    fn reader_handle(r: &std::io::PipeReader) -> crate::state_aware_backend::PipeHandle {
        use std::os::fd::AsRawFd;
        r.as_raw_fd()
    }

    /// The all-null handle shape (what every in-tree state-aware backend
    /// returns today) must stay a pure call-through: no threads, no wrapping,
    /// just the waiter's exit code. This is the regression guard for the
    /// pre-relay behaviour.
    #[test]
    fn relay_with_null_handles_returns_waiter_exit_code() {
        let handle = ExecHandle {
            stdin_closer: None,
            stdout: null_pipe_handle(),
            stderr: null_pipe_handle(),
            stdin: null_pipe_handle(),
            waiter: Box::new(|| Ok(ExecOutcome::Exited(42))),
            terminator: Box::new(|| Ok(())),
        };
        assert_eq!(relay_exec_to_stdio(handle).unwrap(), 42);
    }

    /// A backend that reports a timeout to the relay has broken the
    /// contract, and the relay says so rather than inventing an exit code.
    ///
    /// The regression this pins is the tempting alternative: mapping it
    /// to some sentinel code, which the CLI would then report as the workload's
    /// own exit status.
    #[test]
    fn relay_refuses_a_timeout_rather_than_inventing_an_exit_code() {
        let handle = ExecHandle {
            stdin_closer: None,
            stdout: null_pipe_handle(),
            stderr: null_pipe_handle(),
            stdin: null_pipe_handle(),
            waiter: Box::new(|| Ok(ExecOutcome::TimedOut)),
            terminator: Box::new(|| Ok(())),
        };
        let err = relay_exec_to_stdio(handle).expect_err("the relay cannot represent a timeout");
        assert!(
            err.message.contains("ExecStdio::Relayed"),
            "the refusal should name the contract it is enforcing: {}",
            err.message
        );
    }

    /// A waiter error still surfaces unchanged through the relay.
    #[test]
    fn relay_with_null_handles_propagates_waiter_error() {
        let handle = ExecHandle {
            stdin_closer: None,
            stdout: null_pipe_handle(),
            stderr: null_pipe_handle(),
            stdin: null_pipe_handle(),
            waiter: Box::new(|| Err(MxcError::backend_error("waiter blew up"))),
            terminator: Box::new(|| Ok(())),
        };
        let err = relay_exec_to_stdio(handle).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::BackendError);
    }

    /// The top-level relay really wraps the handle and pumps it.
    ///
    /// Asserted by consumption rather than by observing output: a pipe delivers
    /// its bytes once, to whoever reads first, so if the relay's pump drained
    /// them the test's own reader sees EOF afterwards. Reverting
    /// `relay_exec_to_stdio` to its original waiter-only body leaves the bytes
    /// sitting in the pipe and fails this.
    ///
    /// That matters because every other relay test calls `relay_prepared_streams`
    /// or `pump_stream` directly, so without this one the entry point the change
    /// is named for could be gutted with the suite still green.
    ///
    /// `reader` deliberately stays alive across the call: the relay duplicates
    /// the handle *inside* it, so dropping it earlier would hand the relay a
    /// closed handle and silently produce no stream. EOF still arrives, because
    /// that depends on the *write* end, which is already closed.
    ///
    /// This does print one line to the real console, because relaying to
    /// `std::io::stdout()` is the behaviour under test and a pump thread's
    /// writes bypass the harness's capture. The payload is kept to a single
    /// short line for that reason; the assertion is `leftover`, not the console.
    #[test]
    fn relay_drains_a_real_stdout_pipe_and_returns_exit_code() {
        let (mut reader, mut writer) = std::io::pipe().expect("pipe");
        writer.write_all(b"relayed-stdout\n").unwrap();
        drop(writer); // EOF, so the pump can finish

        let handle = ExecHandle {
            stdin_closer: None,
            stdout: reader_handle(&reader),
            stderr: null_pipe_handle(),
            stdin: null_pipe_handle(),
            waiter: Box::new(|| Ok(ExecOutcome::Exited(3))),
            terminator: Box::new(|| Ok(())),
        };

        assert_eq!(relay_exec_to_stdio(handle).unwrap(), 3);

        let mut leftover = Vec::new();
        reader.read_to_end(&mut leftover).unwrap();
        assert!(
            leftover.is_empty(),
            "the relay must have consumed the pipe; found {:?}",
            String::from_utf8_lossy(&leftover)
        );
    }

    /// A non-null handle the backend named but that cannot be duplicated is a
    /// setup failure, not an absent stream. The relay must surface it, and must
    /// both terminate *and* reap the exec it already started -- terminating
    /// alone would skip the backend's completion work and, for a local child,
    /// leave a zombie.
    ///
    /// Driven through `relay_prepared_streams` with an `Err` rather than a
    /// fabricated invalid handle: `BorrowedHandle`/`BorrowedFd::borrow_raw`
    /// require a live handle, so passing a bogus raw value to force the failure
    /// would break their safety contract to test it.
    #[test]
    fn relay_with_failed_stream_setup_terminates_and_reaps() {
        let (tx, rx) = std::sync::mpsc::channel();
        let waiter_tx = tx.clone();
        let result = relay_prepared_streams(
            Err(MxcError::backend_error(
                "failed to duplicate the exec stdout pipe handle",
            )),
            Box::new(move || {
                let _ = waiter_tx.send("waiter");
                Ok(ExecOutcome::Exited(0))
            }),
            Box::new(move || {
                let _ = tx.send("terminator");
                Ok(())
            }),
        );

        let err = result.unwrap_err();
        assert_eq!(err.code, MxcErrorCode::BackendError);
        assert!(
            err.message.contains("stdout"),
            "the setup error must survive teardown: {}",
            err.message
        );

        // Terminate first, then reap: killing is a request, waiting is what
        // actually collects the process.
        let order: Vec<&str> = rx.try_iter().collect();
        assert_eq!(
            order,
            vec!["terminator", "waiter"],
            "the exec must be terminated and then waited for"
        );
    }

    /// The terminator must NOT be invoked on a normal completion — it is the
    /// cancellation path, not the teardown path.
    #[test]
    fn relay_does_not_invoke_terminator_on_normal_completion() {
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = ExecHandle {
            stdin_closer: None,
            stdout: null_pipe_handle(),
            stderr: null_pipe_handle(),
            stdin: null_pipe_handle(),
            waiter: Box::new(|| Ok(ExecOutcome::Exited(0))),
            terminator: Box::new(move || {
                let _ = tx.send(());
                Ok(())
            }),
        };
        assert_eq!(relay_exec_to_stdio(handle).unwrap(), 0);
        assert!(
            rx.try_recv().is_err(),
            "terminator must not fire when the process exited on its own"
        );
    }

    /// Every byte crosses the pump, including across multiple reads.
    #[test]
    fn pump_stream_copies_all_bytes() {
        let (src_r, mut src_w) = std::io::pipe().expect("pipe");
        let (mut dst_r, dst_w) = std::io::pipe().expect("pipe");

        let payload: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();
        let writer = std::thread::spawn(move || {
            src_w.write_all(&payload).unwrap();
            drop(src_w);
        });
        let unmuted = Arc::new(AtomicBool::new(false));
        let pump = std::thread::spawn(move || pump_stream(src_r, dst_w, &unmuted));

        let mut got = Vec::new();
        dst_r.read_to_end(&mut got).unwrap();
        writer.join().unwrap();
        pump.join().unwrap();

        assert_eq!(got.len(), expected.len(), "byte count must match");
        assert_eq!(got, expected, "payload must survive the pump intact");
    }

    /// A destination that breaks mid-stream must not stop the pump draining.
    ///
    /// The backend still holds the peer of the read handle, so a child whose
    /// output is no longer being consumed does not necessarily see a broken
    /// pipe -- it fills the buffer and blocks, and the waiter then waits for an
    /// exit that cannot happen. Discarding is the lesser loss.
    #[test]
    fn pump_stream_keeps_draining_after_the_destination_fails() {
        /// Accepts the first write, then fails every write and flush.
        struct FailsAfterFirstWrite {
            writes: usize,
        }
        impl std::io::Write for FailsAfterFirstWrite {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.writes += 1;
                if self.writes > 1 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "destination gone",
                    ));
                }
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                if self.writes > 1 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "destination gone",
                    ));
                }
                Ok(())
            }
        }

        let (src_r, mut src_w) = std::io::pipe().expect("pipe");
        let unmuted = Arc::new(AtomicBool::new(false));
        let pump = std::thread::spawn(move || {
            pump_stream(src_r, FailsAfterFirstWrite { writes: 0 }, &unmuted);
        });

        // Far more than one buffer, so the writer would block if the pump
        // stopped reading after the destination broke.
        let chunk = vec![b'x'; 8192];
        for _ in 0..16 {
            src_w
                .write_all(&chunk)
                .expect("the pump must keep draining");
        }
        drop(src_w);

        // The join is the assertion: a pump that stopped reading would leave
        // the writes above blocked and never reach EOF.
        pump.join().expect("pump thread should finish");
    }

    /// The pumps must start *before* the waiter runs.
    ///
    /// Nothing else covers this: the other relay test prewrites a few bytes and
    /// uses an instantly-returning waiter, and the payload test calls
    /// `pump_stream` directly, so both would still pass if the wait happened
    /// first.
    ///
    /// The source signals as soon as it is first read and then reports EOF, and
    /// the waiter blocks until **both** signals arrive; a relay that waited
    /// before draining would never produce them. Both streams are supplied
    /// deliberately: with stdout alone, moving only the stderr pump below the
    /// waiter would go unnoticed, and an stderr-heavy child would then fill its
    /// pipe and deadlock exactly as this rule exists to prevent.
    ///
    /// Signalling rather than filling a pipe keeps this independent of the
    /// platform's pipe-buffer size and, more importantly, writes nothing: the
    /// pumps run on spawned threads whose direct `std::io::stdout()` writes
    /// bypass the test harness's capture, so a volume-based version of this
    /// test dumps its payload into the console output of every run, passing or
    /// not.
    ///
    /// The waiter times out rather than blocking forever, so the regression
    /// surfaces as a failed assertion instead of a hung suite.
    #[test]
    fn relay_starts_pumps_before_waiting() {
        struct SignalsOnFirstRead(Option<std::sync::mpsc::Sender<()>>);
        impl std::io::Read for SignalsOnFirstRead {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                if let Some(tx) = self.0.take() {
                    let _ = tx.send(());
                }
                Ok(0) // EOF: the pump has done its job by reading at all.
            }
        }

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let streams = RelayStreams {
            stdout: Some(Box::new(SignalsOnFirstRead(Some(started_tx.clone())))),
            stderr: Some(Box::new(SignalsOnFirstRead(Some(started_tx)))),
        };

        let waiter = Box::new(move || {
            let mut started = 0;
            while started < 2 {
                if started_rx.recv_timeout(Duration::from_secs(10)).is_err() {
                    return Err(MxcError::backend_error(format!(
                        "only {started} of the 2 pumps had started when the waiter began waiting"
                    )));
                }
                started += 1;
            }
            Ok(ExecOutcome::Exited(0))
        });

        let result = relay_prepared_streams(Ok(streams), waiter, Box::new(|| Ok(())));
        assert_eq!(
            result.expect("the pumps must be draining while the waiter waits"),
            0
        );
    }

    /// A waiter that *errors* means the exit could not be determined, not that
    /// the child is dead. The relay must terminate **before** draining: the
    /// workload may still hold the write ends, and a bounded drain that runs
    /// first burns its entire grace and then discards what was still buffered.
    ///
    /// Both halves are pinned, and they need different instruments. The
    /// terminator is observed directly, because the returned error comes from
    /// the waiter and would arrive whether or not anything was terminated. The
    /// *ordering* is pinned by the clock: the only thing that can deliver EOF to
    /// this pump is the terminator dropping the write end, so terminating first
    /// ends the drain at once, whereas draining first waits out the full
    /// `POST_EXIT_DRAIN_GRACE` before giving up.
    #[test]
    fn relay_terminates_before_draining_when_the_waiter_errors() {
        let (src_r, src_w) = std::io::pipe().expect("pipe");
        // Held by the terminator alone: dropping it is what lets the pump EOF.
        let writer = Arc::new(std::sync::Mutex::new(Some(src_w)));
        let closer = Arc::clone(&writer);
        let terminated = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&terminated);

        let started = Instant::now();
        let result = relay_prepared_streams(
            Ok(RelayStreams {
                stdout: Some(Box::new(src_r)),
                stderr: None,
            }),
            Box::new(|| Err(MxcError::backend_error("could not determine the exit"))),
            Box::new(move || {
                flag.store(true, Ordering::Relaxed);
                closer.lock().expect("writer lock").take();
                Ok(())
            }),
        );
        let elapsed = started.elapsed();

        assert!(
            terminated.load(Ordering::Relaxed),
            "a waiter error leaves the child possibly alive, so it must be terminated"
        );
        assert!(
            elapsed < POST_EXIT_DRAIN_GRACE / 2,
            "the terminator must run before the drain, not after it; took {elapsed:?}"
        );
        let err = result.unwrap_err();
        assert_eq!(err.code, MxcErrorCode::BackendError);
        assert!(
            err.message.contains("could not determine the exit"),
            "the waiter's error must survive teardown: {}",
            err.message
        );
    }

    /// Output must appear as it is produced, not be held until EOF.
    ///
    /// The destination is wrapped in a `BufWriter` large enough to swallow the
    /// whole payload, which is what makes this discriminating: the real sink is
    /// `std::io::stdout()`, and that is line-buffered, so a pump that wrote
    /// without flushing would strand a partial line exactly like this. Against
    /// a bare `PipeWriter` the bytes would become readable whether or not the
    /// pump flushed, and the test would prove nothing.
    ///
    /// The payload carries no newline and the source stays open, so the only
    /// thing that can deliver it is the pump's explicit flush; without it,
    /// `read_exact` blocks until the harness times the test out.
    #[test]
    fn pump_stream_flushes_before_eof() {
        let (src_r, mut src_w) = std::io::pipe().expect("pipe");
        let (mut dst_r, dst_w) = std::io::pipe().expect("pipe");
        let dst = std::io::BufWriter::with_capacity(64 * 1024, dst_w);

        let unmuted = Arc::new(AtomicBool::new(false));
        let pump = std::thread::spawn(move || pump_stream(src_r, dst, &unmuted));

        src_w.write_all(b"no-newline-yet").unwrap();
        src_w.flush().unwrap();

        let mut got = [0u8; 14];
        dst_r
            .read_exact(&mut got)
            .expect("partial line must arrive before EOF");
        assert_eq!(&got, b"no-newline-yet");

        drop(src_w);
        pump.join().unwrap();
    }

    /// A muted pump stops writing but keeps reading.
    ///
    /// Both halves matter and the test pins both. Muting exists so a pump the
    /// relay has stopped waiting for cannot append stray bytes to whatever the
    /// caller emits next; draining on regardless is what stops the workload
    /// wedging on a pipe nobody empties.
    #[test]
    fn a_muted_pump_stops_writing_but_keeps_draining() {
        let (src_r, mut src_w) = std::io::pipe().expect("pipe");
        let (mut dst_r, dst_w) = std::io::pipe().expect("pipe");

        let muted = Arc::new(AtomicBool::new(false));
        let thread_muted = Arc::clone(&muted);
        let pump = std::thread::spawn(move || pump_stream(src_r, dst_w, &thread_muted));

        src_w.write_all(b"before").unwrap();
        src_w.flush().unwrap();
        let mut got = [0u8; 6];
        dst_r.read_exact(&mut got).expect("pre-mute output");
        assert_eq!(&got, b"before");

        muted.store(true, Ordering::Relaxed);

        // Far more than one pipe buffer. If muting stopped the pump reading,
        // these writes would block and the test would never finish.
        let chunk = vec![b'x'; 8192];
        for _ in 0..16 {
            src_w
                .write_all(&chunk)
                .expect("a muted pump must still drain its source");
        }
        drop(src_w);
        pump.join().unwrap();

        // Nothing written after the mute: the destination saw only "before",
        // so reading it to the end now yields EOF immediately.
        let mut leftover = Vec::new();
        dst_r.read_to_end(&mut leftover).unwrap();
        assert!(
            leftover.is_empty(),
            "a muted pump wrote {} bytes it should have discarded",
            leftover.len()
        );
    }

    /// `abort_relay` must terminate *before* draining, not merely before
    /// reaping.
    ///
    /// Called directly, because the only route to it through
    /// `relay_prepared_streams` is a classification failure, which by
    /// construction has no pumps yet -- so that path can never distinguish the
    /// two orders. The reachable non-empty case is a `spawn_pump` refusal,
    /// which cannot be injected from a test.
    ///
    /// The clock is the instrument: the terminator is the only thing that can
    /// deliver EOF here, so terminating first ends the drain at once, while
    /// draining first waits out the whole grace and then mutes the pump.
    #[test]
    fn abort_relay_terminates_before_draining() {
        let (src_r, src_w) = std::io::pipe().expect("pipe");
        let (dst_r, dst_w) = std::io::pipe().expect("pipe");
        // Held by the terminator alone: dropping it is what lets the pump EOF.
        let writer = Arc::new(std::sync::Mutex::new(Some(src_w)));
        let closer = Arc::clone(&writer);
        let pump = spawn_pump("test-abort-pump", src_r, dst_w).expect("spawn");

        let started = Instant::now();
        let result = abort_relay(
            Box::new(|| Ok(ExecOutcome::Exited(0))),
            Box::new(move || {
                closer.lock().expect("writer lock").take();
                Ok(())
            }),
            vec![pump],
            MxcError::backend_error("stream setup failed"),
        );
        let elapsed = started.elapsed();

        assert!(
            elapsed < POST_EXIT_DRAIN_GRACE / 2,
            "the terminator must run before the drain, not after it; took {elapsed:?}"
        );
        let err = result.expect_err("abort_relay must surface the setup error");
        assert!(
            err.message.contains("stream setup failed"),
            "the setup error must survive teardown: {}",
            err.message
        );

        drop(dst_r);
    }

    /// The drain is bounded, and what it abandons it mutes.
    ///
    /// This is the guarantee both drain sites depend on. `abort_relay` needs it
    /// most: an unbounded join there would hang before reaching the waiter and
    /// so defeat the very reaping that function exists to perform.
    #[test]
    fn drain_pumps_bounds_the_wait_and_mutes_what_it_abandons() {
        // A source that never ends. Holding `src_w` open is what makes this the
        // hazard case: the pump cannot reach EOF, so an unbounded join hangs.
        let (src_r, src_w) = std::io::pipe().expect("pipe");
        let (dst_r, dst_w) = std::io::pipe().expect("pipe");
        let pump = spawn_pump("test-endless-pump", src_r, dst_w).expect("spawn");
        let muted = Arc::clone(&pump.muted);

        let started = Instant::now();
        drain_pumps_within(vec![pump], Duration::from_millis(50));
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_secs(2),
            "the drain must give up on an endless pump, took {elapsed:?}"
        );
        assert!(
            muted.load(Ordering::Relaxed),
            "an abandoned pump must be muted so it cannot write after the relay returns"
        );

        // Release the thread rather than leaving it parked for the run.
        drop(src_w);
        drop(dst_r);
    }
}
