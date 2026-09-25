// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Owns the WSLc SDK session and containers on a single dedicated worker
//! thread.
//!
//! The WSLc SDK's `WslcSession` / `WslcContainer` / `WslcProcess` handles are
//! thread-affine and must all be created and used from one apartment. This
//! module confines every SDK call to a single long-lived worker thread that
//! joins the MTA for its whole lifetime; async pipe handlers dispatch typed
//! [`WorkerCommand`]s to it over a channel and await the reply.
//!
//! State-aware topology (decided): **one** shared `WslcSession` (the WSL2
//! utility VM, booted lazily on first provision and amortised across all
//! sandboxes) and a refcounted `sandbox_id -> container` map. The session is
//! released when the last container is deprovisioned and the idle timeout
//! elapses.
//!
//! Each phase drives the real WSLc SDK via the reusable steps in
//! [`wslc_common::container_steps`]: `provision` ensures the session + resolves
//! the image + creates a container with a keepalive init process; `start` boots
//! it; `exec` runs a fresh `WslcCreateContainerProcess` to completion, streaming
//! its stdout/stderr live to the pipe handler via an [`OutputSink`]; `stop` /
//! `deprovision` stop + delete. The completion reply carries the exit code;
//! output flows over the sink. (Client `Stdin` forwarding is a later fill-in.)

use std::collections::{hash_map::Entry, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

use anyhow::Result;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot};

use wslc_common::container_steps::{self, OutStream, OutputSink, ProcessSettings};
use wslc_common::daemon_protocol::{
    DeprovisionConfig, ErrKind, ExecConfig, ExecTerminal, NetworkMode, ProvisionConfig,
    StartConfig, StopConfig,
};
use wslc_common::policy_mapping;
use wslc_common::wslc_bindings::{
    WslcContainer, WslcContainerGuard, WslcContainerNetworkingMode, WslcSdk, WslcSessionGuard,
};
use wxc_common::logger::{Logger, Mode};
use wxc_common::models::{FailurePhase, ScriptResponse};

/// Fixed name of the single WSL2 utility-VM session the daemon owns.
const SESSION_NAME: &str = "mxc-wslc-daemon";

/// Default on-disk WSLc image/session store. Matches the one-shot runner's
/// default so images pre-pulled via `setup-wslc.ps1` are found by the daemon.
fn default_storage_path() -> String {
    std::env::temp_dir()
        .join("mxc-wslc-sessions")
        .to_string_lossy()
        .to_string()
}

/// Convert a step helper's `failure_phase` into a typed failure, since the wire
/// carries only a message and an [`ErrKind`].
fn sr_err(resp: ScriptResponse) -> WorkerError {
    let err = anyhow::anyhow!(resp.error_message);
    match resp.failure_phase {
        FailurePhase::BackendUnavailable => WorkerError::Unavailable(err),
        FailurePhase::Rejected => WorkerError::Rejected(err),
        _ => WorkerError::Backend(err),
    }
}

/// A typed worker failure. The control server maps [`WorkerError::kind`] onto
/// the protocol's [`ErrKind`] so clients can react (e.g. distinguish an unknown
/// sandbox from a backend fault) without string-matching the message.
#[derive(Debug)]
pub enum WorkerError {
    /// The referenced sandbox id is unknown to the daemon.
    NotProvisioned(String),

    /// The sandbox exists but has not been started.
    NotStarted(String),

    /// The host cannot run WSLc at all.
    Unavailable(anyhow::Error),

    /// The request cannot be honored as written.
    Rejected(anyhow::Error),

    /// A backend/SDK-level failure, or an internal worker/channel fault.
    Backend(anyhow::Error),
}

impl WorkerError {
    /// The protocol classification the control server returns for this error.
    pub fn kind(&self) -> ErrKind {
        match self {
            WorkerError::NotProvisioned(_) => ErrKind::NotProvisioned,
            WorkerError::NotStarted(_) => ErrKind::NotStarted,
            WorkerError::Unavailable(_) => ErrKind::Unavailable,
            WorkerError::Rejected(_) => ErrKind::Rejected,
            WorkerError::Backend(_) => ErrKind::Backend,
        }
    }
}

impl std::fmt::Display for WorkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerError::NotProvisioned(id) => write!(f, "unknown sandbox {id}"),
            WorkerError::NotStarted(id) => write!(f, "sandbox {id} is not started"),
            WorkerError::Unavailable(e) | WorkerError::Rejected(e) | WorkerError::Backend(e) => {
                write!(f, "{e:#}")
            }
        }
    }
}

impl std::error::Error for WorkerError {}

impl From<anyhow::Error> for WorkerError {
    fn from(e: anyhow::Error) -> Self {
        WorkerError::Backend(e)
    }
}

/// A unit of work dispatched from an async pipe handler to the WSLc worker
/// thread. Each variant carries a `oneshot` reply channel the worker fulfils.
pub enum WorkerCommand {
    Provision {
        config: ProvisionConfig,
        reply: oneshot::Sender<Result<String, WorkerError>>,
    },
    Start {
        config: StartConfig,
        reply: oneshot::Sender<Result<(), WorkerError>>,
    },
    /// Validate the sandbox (exists + started) and, if admitted, run the
    /// command to completion. The two replies make admission **atomic** with the
    /// run: because the worker services this whole command on its single thread
    /// without yielding, no `Stop`/`Deprovision` can interleave between the
    /// validation and the run. `admit` carries the pre-run decision (so an
    /// unknown/not-started sandbox is a pre-admission typed error, never a
    /// post-admission stream `Error`); `done` carries the run's exit code.
    Exec {
        config: ExecConfig,
        /// Live-output sink the worker hands to `exec_in_container`; the SDK's
        /// stdout/stderr callbacks push chunks through it to the pipe handler as
        /// bytes arrive, alongside the capped capture buffers.
        sink: OutputSink,
        cancellation: Arc<AtomicBool>,
        registration: Arc<ExecRegistration>,
        admit: oneshot::Sender<Result<(), WorkerError>>,
        done: oneshot::Sender<Result<ExecTerminal, WorkerError>>,
    },
    Stop {
        config: StopConfig,
        reply: oneshot::Sender<Result<(), WorkerError>>,
    },
    Deprovision {
        config: DeprovisionConfig,
        reply: oneshot::Sender<Result<(), WorkerError>>,
    },
    /// Report the current live-container count (drives the idle watchdog).
    ContainerCount { reply: oneshot::Sender<usize> },
    /// Release all containers + the session and stop the worker thread.
    Shutdown { reply: oneshot::Sender<()> },
}

/// A chunk of live process output streamed from the worker to the pipe handler:
/// which stream it came from and the bytes (owned, so it can cross the channel).
pub type OutputChunk = (OutStream, Vec<u8>);

/// Bound on the number of unconsumed live-output chunks buffered between the
/// SDK's I/O callback threads and the pipe handler. The channel is bounded (not
/// unbounded) so a container emitting output faster than a slow client drains it
/// cannot grow the queue without limit and OOM the persistent daemon, taking
/// down every sandbox it owns — the same hazard the capture-buffer cap guards
/// against. When the queue is full the sink does **not** block (see
/// [`enqueue_output`]): it latches a truncation flag and drops further bytes so
/// the SDK callback thread — which also delivers the process-exit callback — is
/// never parked. Stalling that thread could otherwise block exit delivery and
/// wedge teardown for every sandbox sharing the daemon.
const LIVE_OUTPUT_CHANNEL_CAPACITY: usize = 256;

/// Max bytes per enqueued live-output chunk. A single SDK callback can deliver
/// an arbitrarily large buffer; splitting it here bounds each queue entry's
/// allocation and keeps the resulting `Stdout`/`Stderr` frame well under the
/// protocol's `MAX_FRAME_SIZE` (a `Vec<u8>` serializes as a JSON number array,
/// ~4x expansion), so a large callback can never overflow a frame and abort the
/// stream before its terminal frame.
const LIVE_OUTPUT_MAX_CHUNK_BYTES: usize = 64 * 1024;

/// Enqueue an SDK output callback, splitting it into `LIVE_OUTPUT_MAX_CHUNK_BYTES`
/// pieces so each queue entry and its resulting frame stay bounded regardless of
/// the callback's buffer size.
///
/// This runs **synchronously on the SDK's I/O callback thread**, which also
/// delivers the process-exit callback. It must therefore never block: a
/// [`try_send`](mpsc::Sender::try_send) that finds the bounded queue full does
/// **not** apply backpressure (that would park this thread and could deadlock
/// exit delivery and teardown for every sandbox on the daemon). Instead it
/// latches `overflowed` and stops enqueuing; the pipe handler turns a latched
/// overflow into a terminal `Error` frame so the client sees an explicit
/// truncation rather than a silently short stream. Once latched, subsequent
/// callbacks return immediately so the client receives a clean truncated prefix
/// rather than a gapped stream. A closed receiver (client left / leak-path
/// `close()`) likewise stops enqueuing.
fn enqueue_output(
    tx: &mpsc::Sender<OutputChunk>,
    overflowed: &AtomicBool,
    kind: OutStream,
    bytes: &[u8],
) {
    if overflowed.load(Ordering::Relaxed) {
        return;
    }
    for chunk in bytes.chunks(LIVE_OUTPUT_MAX_CHUNK_BYTES) {
        match tx.try_send((kind, chunk.to_vec())) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                overflowed.store(true, Ordering::Relaxed);
                return;
            }
            Err(TrySendError::Closed(_)) => return,
        }
    }
}

/// An admitted exec: the completion receiver (the run's exit code), the
/// live-output receiver the pipe handler drains into `Stdout`/`Stderr` frames,
/// and the `overflowed` latch the sink sets when it had to drop output because a
/// slow client let the bounded queue fill. The registration keeps the exec id
/// reserved until the pipe handler finishes terminal delivery. The pipe handler
/// reports a set overflow latch as a terminal `Error` frame.
#[derive(Debug)]
pub struct ExecStream {
    pub done: oneshot::Receiver<Result<ExecTerminal, WorkerError>>,
    pub output: mpsc::Receiver<OutputChunk>,
    pub overflowed: Arc<AtomicBool>,
    pub(crate) registration: Arc<ExecRegistration>,
}

pub(crate) type ActiveExecs = Arc<Mutex<HashMap<String, ActiveExec>>>;

#[derive(Debug)]
pub(crate) struct ActiveExec {
    run_token: String,
    cancellation: Weak<AtomicBool>,
}

#[derive(Debug)]
pub(crate) struct ExecRegistration {
    exec_id: String,
    run_token: String,
    active_execs: ActiveExecs,
    cancellation: Arc<AtomicBool>,
}

impl Drop for ExecRegistration {
    fn drop(&mut self) {
        let mut active_execs = self
            .active_execs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if active_execs.get(&self.exec_id).is_some_and(|current| {
            current.run_token == self.run_token
                && current
                    .cancellation
                    .ptr_eq(&Arc::downgrade(&self.cancellation))
        }) {
            active_execs.remove(&self.exec_id);
        }
    }
}

pub(crate) fn register_exec(
    active_execs: &ActiveExecs,
    exec_id: &str,
    run_token: &str,
    cancellation: &Arc<AtomicBool>,
) -> Result<ExecRegistration, WorkerError> {
    let active_exec = ActiveExec {
        run_token: run_token.to_string(),
        cancellation: Arc::downgrade(cancellation),
    };
    let mut active_execs_guard = active_execs
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match active_execs_guard.entry(exec_id.to_string()) {
        Entry::Occupied(mut entry) if entry.get().cancellation.upgrade().is_none() => {
            entry.insert(active_exec);
        }
        Entry::Occupied(_) => {
            return Err(WorkerError::Rejected(anyhow::anyhow!(
                "exec id {exec_id:?} is already active"
            )));
        }
        Entry::Vacant(entry) => {
            entry.insert(active_exec);
        }
    }
    drop(active_execs_guard);

    Ok(ExecRegistration {
        exec_id: exec_id.to_string(),
        run_token: run_token.to_string(),
        active_execs: Arc::clone(active_execs),
        cancellation: Arc::clone(cancellation),
    })
}

/// A cheap, clonable handle async tasks use to drive the worker thread.
#[derive(Clone)]
pub struct SessionHandle {
    tx: mpsc::UnboundedSender<WorkerCommand>,
    active_execs: ActiveExecs,
}

impl SessionHandle {
    /// Provision a container, returning its minted `sandbox_id`.
    pub async fn provision(&self, config: ProvisionConfig) -> Result<String, WorkerError> {
        let (reply, rx) = oneshot::channel();
        self.send(WorkerCommand::Provision { config, reply })?;
        rx.await.map_err(worker_gone)?
    }

    /// Start a provisioned container.
    pub async fn start(&self, config: StartConfig) -> Result<(), WorkerError> {
        let (reply, rx) = oneshot::channel();
        self.send(WorkerCommand::Start { config, reply })?;
        rx.await.map_err(worker_gone)?
    }

    /// Admit and run a command in a started container. Awaits the worker's
    /// **admission** decision first: on rejection (unknown/not-started sandbox)
    /// this returns the typed error *before* the caller writes any admission to
    /// the client. On admission it returns an [`ExecStream`] — the completion
    /// receiver (the run's exit code) plus the live-output receiver, which the
    /// caller drains into `Stdout`/`Stderr` frames as bytes arrive. Admission and
    /// the start of the run are atomic on the worker thread, so no lifecycle
    /// command can invalidate the checked state between the two.
    pub async fn exec(&self, config: ExecConfig) -> Result<ExecStream, WorkerError> {
        let (admit, admit_rx) = oneshot::channel();
        let (done, done_rx) = oneshot::channel();
        let (stream_tx, output) = mpsc::channel::<OutputChunk>(LIVE_OUTPUT_CHANNEL_CAPACITY);
        // The sink is invoked from the SDK's I/O callback threads (native OS
        // threads, never the async runtime). Those same threads deliver the
        // process-exit callback, so the sink must never block: [`enqueue_output`]
        // uses a non-blocking `try_send` and, on a full queue, latches
        // `overflowed` and drops further bytes instead of parking the thread.
        // Memory stays bounded by the channel capacity; a slow/non-reading
        // client can no longer wedge exit delivery or teardown for every sandbox
        // on the daemon. The pipe handler reports a set latch as a terminal
        // `Error` frame so truncation is explicit rather than silent.
        let overflowed = Arc::new(AtomicBool::new(false));
        let sink_overflowed = Arc::clone(&overflowed);
        let sink: OutputSink = Box::new(move |kind, bytes| {
            enqueue_output(&stream_tx, &sink_overflowed, kind, bytes);
        });
        let cancellation = Arc::new(AtomicBool::new(false));
        let registration = Arc::new(register_exec(
            &self.active_execs,
            &config.exec_id,
            &config.run_token,
            &cancellation,
        )?);
        self.send(WorkerCommand::Exec {
            config,
            sink,
            cancellation,
            registration: Arc::clone(&registration),
            admit,
            done,
        })?;
        admit_rx.await.map_err(worker_gone)??;
        Ok(ExecStream {
            done: done_rx,
            output,
            overflowed,
            registration,
        })
    }

    /// Signal an admitted exec without waiting for the apartment-affine worker,
    /// which is blocked in that exec until the process exits.
    pub fn cancel_exec(&self, exec_id: &str, run_token: &str) {
        if let Some(cancellation) = self
            .active_execs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(exec_id)
            .filter(|current| current.run_token == run_token)
            .and_then(|current| current.cancellation.upgrade())
        {
            cancellation.store(true, Ordering::Release);
        }
    }

    /// Stop a running container.
    pub async fn stop(&self, config: StopConfig) -> Result<(), WorkerError> {
        let (reply, rx) = oneshot::channel();
        self.send(WorkerCommand::Stop { config, reply })?;
        rx.await.map_err(worker_gone)?
    }

    /// Deprovision (delete) a container.
    pub async fn deprovision(&self, config: DeprovisionConfig) -> Result<(), WorkerError> {
        let (reply, rx) = oneshot::channel();
        self.send(WorkerCommand::Deprovision { config, reply })?;
        rx.await.map_err(worker_gone)?
    }

    /// Current number of live containers (0 means the daemon is idle).
    pub async fn container_count(&self) -> Result<usize, WorkerError> {
        let (reply, rx) = oneshot::channel();
        self.send(WorkerCommand::ContainerCount { reply })?;
        rx.await.map_err(worker_gone)
    }

    /// Ask the worker to release everything and stop. Awaits confirmation.
    pub async fn shutdown(&self) -> Result<(), WorkerError> {
        let (reply, rx) = oneshot::channel();
        self.send(WorkerCommand::Shutdown { reply })?;
        rx.await.map_err(worker_gone)
    }

    fn send(&self, cmd: WorkerCommand) -> Result<(), WorkerError> {
        self.tx
            .send(cmd)
            .map_err(|_| WorkerError::Backend(anyhow::anyhow!("WSLc worker thread is gone")))
    }
}

fn worker_gone(_e: oneshot::error::RecvError) -> WorkerError {
    WorkerError::Backend(anyhow::anyhow!("WSLc worker dropped the reply channel"))
}

/// Per-container bookkeeping held by the worker: whether the container is
/// currently started and the live `WslcContainer` handle (kept alive across
/// phases so repeated `exec`s hit a warm container). The sandbox id is the
/// map key.
struct ContainerEntry {
    started: bool,
    quarantined: bool,
    container: WslcContainerGuard,
}

/// The single-threaded WSLc session owner. Constructed and run entirely on the
/// worker thread. Holds the lazily-loaded SDK and the one shared session (the
/// WSL2 utility VM), plus the `sandbox_id -> container` map. The SDK/session/
/// guard handles are `!Send` raw pointers, but they never leave this thread —
/// only [`WorkerCommand`]s cross the channel.
struct Worker {
    logger: Logger,
    // Field order is load-bearing on implicit drop: `containers` and `session`
    // hold handles whose Drop calls into the SDK, so they must drop before `sdk`
    // unloads `wslcsdk.dll`.
    containers: HashMap<String, ContainerEntry>,
    session: Option<WslcSessionGuard>,
    sdk: Option<WslcSdk>,
}

impl Worker {
    fn new() -> Self {
        Self {
            logger: Logger::new(Mode::Console),
            sdk: None,
            session: None,
            containers: HashMap::new(),
        }
    }

    /// Lazily load the SDK and boot the shared session on first use. Idempotent.
    fn ensure_session(&mut self) -> Result<(), WorkerError> {
        if self.sdk.is_none() {
            // SAFETY: the worker thread is already in the MTA (see `ComApartment`).
            let sdk =
                unsafe { container_steps::load_sdk_checked(&mut self.logger) }.map_err(sr_err)?;
            self.sdk = Some(sdk);
        }
        if self.session.is_none() {
            let storage = default_storage_path();
            let sdk = self.sdk.as_ref().expect("sdk loaded above");
            // SAFETY: `sdk` holds valid pointers and COM is initialised.
            let session = unsafe {
                container_steps::create_daemon_session(
                    sdk,
                    SESSION_NAME,
                    &storage,
                    &mut self.logger,
                )
            }
            .map_err(sr_err)?;
            self.session = Some(session);
        }
        Ok(())
    }

    fn provision(&mut self, config: ProvisionConfig) -> Result<String, WorkerError> {
        self.ensure_session()?;

        let sdk = self.sdk.as_ref().expect("session ensured");
        let session = self.session.as_ref().expect("session ensured").as_raw();

        let mounts: Vec<policy_mapping::VolumeMount> = config
            .volumes
            .iter()
            .map(|v| policy_mapping::VolumeMount {
                windows_path: v.host.clone(),
                container_path: v.container.clone(),
                read_only: v.read_only,
            })
            .collect();
        let net_mode = match config.network {
            NetworkMode::None => WslcContainerNetworkingMode::WSLC_CONTAINER_NETWORKING_MODE_NONE,
            NetworkMode::Bridged => {
                WslcContainerNetworkingMode::WSLC_CONTAINER_NETWORKING_MODE_BRIDGED
            }
        };

        // SAFETY: `sdk`/`session` are valid; every buffer the SDK stores pointers
        // into is owned by a stationary local (`keepalive`) until create returns.
        let container = unsafe {
            container_steps::resolve_image(
                sdk,
                session,
                &config.image,
                config.image_tar_path.as_deref(),
                None,
                &mut self.logger,
            )
            .map_err(sr_err)?;

            let mut keepalive =
                ProcessSettings::build_detached(sdk, container_steps::KEEPALIVE_SCRIPT, &[], "")
                    .map_err(sr_err)?;

            container_steps::create_daemon_container(
                sdk,
                session,
                &config.image,
                &mounts,
                net_mode,
                &mut keepalive,
                &mut self.logger,
            )
            .map_err(sr_err)?
        };

        let sandbox_id = format!("wslc:{}", uuid::Uuid::new_v4().simple());
        self.containers.insert(
            sandbox_id.clone(),
            ContainerEntry {
                started: false,
                quarantined: false,
                container,
            },
        );
        Ok(sandbox_id)
    }

    fn start(&mut self, config: StartConfig) -> Result<(), WorkerError> {
        // Existence check first, so an unknown sandbox errors without needing the
        // SDK (keeps the no-WSL unit tests self-contained).
        if !self.containers.contains_key(&config.sandbox_id) {
            return Err(WorkerError::NotProvisioned(config.sandbox_id));
        }
        let sdk = self
            .sdk
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no active WSLc session"))?;
        let entry = self
            .containers
            .get_mut(&config.sandbox_id)
            .expect("checked above");
        if entry.quarantined {
            return Err(WorkerError::Backend(anyhow::anyhow!(
                "sandbox {} is quarantined after an exec whose termination could not be \
                 confirmed; deprovision it before reuse",
                config.sandbox_id
            )));
        }
        // SAFETY: `sdk` is valid and `entry.container` is a live handle.
        unsafe {
            container_steps::start_daemon_container(sdk, entry.container.as_raw(), &mut self.logger)
        }
        .map_err(sr_err)?;
        entry.started = true;
        Ok(())
    }

    /// Validate that a sandbox exists and is started, returning the live handle
    /// needed to run. Sole owner of the exists+started invariant: [`exec`] trusts
    /// the handle it is given and never re-checks, because the worker services
    /// admission and the run on one thread without yielding between them.
    fn validate_exec(&self, sandbox_id: &str) -> Result<WslcContainer, WorkerError> {
        match self.containers.get(sandbox_id) {
            None => Err(WorkerError::NotProvisioned(sandbox_id.to_string())),
            Some(entry) if entry.quarantined => Err(WorkerError::Backend(anyhow::anyhow!(
                "sandbox {sandbox_id} is quarantined after an exec whose termination could not \
                 be confirmed; deprovision it before reuse"
            ))),
            Some(entry) if !entry.started => Err(WorkerError::NotStarted(sandbox_id.to_string())),
            Some(entry) => Ok(entry.container.as_raw()),
        }
    }

    /// Run a command in a sandbox whose existence/started state was already
    /// confirmed by [`validate_exec`]; `container` is that validated handle.
    /// `sink` streams the run's stdout/stderr live to the pipe handler.
    fn exec(
        &mut self,
        config: ExecConfig,
        container: WslcContainer,
        sink: OutputSink,
        cancellation: &AtomicBool,
    ) -> Result<ExecTerminal, WorkerError> {
        let sdk = self
            .sdk
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no active WSLc session"))?;

        // ProcessSettings::build expects `NAME=VALUE` env entries.
        let env: Vec<String> = config
            .env
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();

        // SAFETY: `sdk` is valid and `container` is a live, started handle.
        let outcome = unsafe {
            container_steps::exec_in_container(
                sdk,
                container,
                &config.script_code,
                &env,
                &config.working_directory,
                config.timeout_ms,
                cancellation,
                Some(sink),
                &mut self.logger,
            )
        }
        .map_err(sr_err)?;

        match outcome.completion {
            container_steps::ProcessCompletion::TerminationUnconfirmed => {
                let detail = outcome
                    .post_launch_error
                    .map(|error| error.error_message)
                    .unwrap_or_else(|| "process termination could not be confirmed".to_string());
                Err(self.quarantine(&config.sandbox_id, container, &detail))
            }
            container_steps::ProcessCompletion::Confirmed(terminal) => Ok(terminal),
        }
    }

    fn quarantine(
        &mut self,
        sandbox_id: &str,
        container: WslcContainer,
        detail: &str,
    ) -> WorkerError {
        let delete_result = self.sdk.as_ref().map(|sdk| {
            // SAFETY: `sdk` is valid and `container` is the live handle stored
            // for `sandbox_id`.
            unsafe { container_steps::delete_daemon_container(sdk, container, &mut self.logger) }
        });

        match delete_result {
            Some(Ok(())) => {
                self.containers.remove(sandbox_id);
                WorkerError::Backend(anyhow::anyhow!(
                    "exec on sandbox {sandbox_id} could not be confirmed terminated ({detail}); \
                     the container was quarantined and deleted"
                ))
            }
            Some(Err(delete_error)) => {
                if let Some(entry) = self.containers.get_mut(sandbox_id) {
                    entry.quarantined = true;
                }
                WorkerError::Backend(anyhow::anyhow!(
                    "exec on sandbox {sandbox_id} could not be confirmed terminated ({detail}); \
                     quarantine deletion failed and the sandbox remains blocked until \
                     deprovision succeeds: {}",
                    delete_error.error_message
                ))
            }
            None => {
                if let Some(entry) = self.containers.get_mut(sandbox_id) {
                    entry.quarantined = true;
                }
                WorkerError::Backend(anyhow::anyhow!(
                    "exec on sandbox {sandbox_id} could not be confirmed terminated ({detail}); \
                     the sandbox remains quarantined because no active WSLc SDK is available"
                ))
            }
        }
    }

    fn stop(&mut self, config: StopConfig) -> Result<(), WorkerError> {
        if !self.containers.contains_key(&config.sandbox_id) {
            return Err(WorkerError::NotProvisioned(config.sandbox_id));
        }
        let sdk = self
            .sdk
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no active WSLc session"))?;
        let entry = self
            .containers
            .get_mut(&config.sandbox_id)
            .expect("checked above");
        // SAFETY: `sdk` is valid and `entry.container` is a live handle.
        unsafe {
            container_steps::stop_daemon_container(sdk, entry.container.as_raw(), &mut self.logger)
        }
        .map_err(sr_err)?;
        entry.started = false;
        Ok(())
    }

    fn deprovision(&mut self, config: DeprovisionConfig) -> Result<(), WorkerError> {
        let container_raw = match self.containers.get(&config.sandbox_id) {
            Some(e) => e.container.as_raw(),
            None => return Err(WorkerError::NotProvisioned(config.sandbox_id)),
        };

        if let Some(sdk) = self.sdk.as_ref() {
            // SAFETY: `sdk` is valid and `container_raw` is a live handle.
            unsafe {
                container_steps::delete_daemon_container(sdk, container_raw, &mut self.logger)
            }
            .map_err(sr_err)?;
        }

        // Delete succeeded (or no SDK loaded): drop the handle now. Keeping the
        // entry on failure above leaves it retryable.
        self.containers.remove(&config.sandbox_id);

        // The shared session (and SDK) stay loaded so a subsequent provision
        // reuses the already-booted WSL2 VM. The idle watchdog releases them via
        // `shutdown` once the container count has stayed at zero for the idle
        // timeout.
        Ok(())
    }

    fn shutdown(&mut self) {
        if let Some(sdk) = self.sdk.as_ref() {
            for (_, entry) in self.containers.drain() {
                // SAFETY: `sdk` is valid and `entry.container` is a live handle.
                unsafe {
                    if entry.started {
                        let _ = container_steps::stop_daemon_container(
                            sdk,
                            entry.container.as_raw(),
                            &mut self.logger,
                        );
                    }
                    let _ = container_steps::delete_daemon_container(
                        sdk,
                        entry.container.as_raw(),
                        &mut self.logger,
                    );
                }
                // entry (WslcContainerGuard) drops here, releasing the handle.
            }
        } else {
            self.containers.clear();
        }
        // Session guard drops before the SDK unloads the DLL.
        self.session = None;
        self.sdk = None;
    }
}

/// Spawn the WSLc worker thread and return a handle to it.
///
/// The thread joins the MTA for its entire lifetime (WSLc SDK apartment
/// affinity) and processes [`WorkerCommand`]s until a [`WorkerCommand::Shutdown`]
/// is received or the command channel closes.
pub fn spawn() -> Result<SessionHandle> {
    let (tx, mut rx) = mpsc::unbounded_channel::<WorkerCommand>();
    let active_execs = Arc::new(Mutex::new(HashMap::new()));

    std::thread::Builder::new()
        .name("wslc-session-worker".to_string())
        .spawn(move || {
            #[cfg(windows)]
            let _com = match ComApartment::enter() {
                Ok(com) => com,
                Err(e) => {
                    eprintln!("[wslc-daemon] worker COM initialisation failed: {e:#}");
                    return;
                }
            };

            let mut worker = Worker::new();
            while let Some(cmd) = rx.blocking_recv() {
                match cmd {
                    WorkerCommand::Provision { config, reply } => {
                        let _ = reply.send(worker.provision(config));
                    }
                    WorkerCommand::Start { config, reply } => {
                        let _ = reply.send(worker.start(config));
                    }
                    WorkerCommand::Exec {
                        config,
                        sink,
                        cancellation,
                        registration: _registration,
                        admit,
                        done,
                    } => {
                        // Validate and run in one handler so admission is atomic
                        // with the start of the run: the worker never yields
                        // between the two, so no Stop/Deprovision can interleave.
                        match worker.validate_exec(&config.sandbox_id) {
                            Err(e) => {
                                let _ = admit.send(Err(e));
                            }
                            Ok(_) if cancellation.load(Ordering::Acquire) => {
                                if admit.send(Ok(())).is_ok() {
                                    let _ = done.send(Ok(ExecTerminal::Cancelled));
                                }
                            }
                            // Only run if the admission receiver is still there:
                            // if the client handler was dropped before it read
                            // admission, the blocking exec would otherwise starve
                            // every other lifecycle command for its full timeout.
                            Ok(container) if admit.send(Ok(())).is_ok() => {
                                let sandbox_id = config.sandbox_id.clone();
                                let outcome = worker.exec(config, container, sink, &cancellation);
                                if let Err(orphaned) = done.send(outcome) {
                                    // The client handler is gone (e.g. its
                                    // post-admission Ok write failed) but the run
                                    // already happened. Record the result so a
                                    // completed exec is never silently lost.
                                    worker.logger.log_line(&format!(
                                        "exec on {sandbox_id} completed after the client \
                                         disconnected; orphaned result: {orphaned:?}"
                                    ));
                                }
                            }
                            Ok(_) => {}
                        }
                    }
                    WorkerCommand::Stop { config, reply } => {
                        let _ = reply.send(worker.stop(config));
                    }
                    WorkerCommand::Deprovision { config, reply } => {
                        let _ = reply.send(worker.deprovision(config));
                    }
                    WorkerCommand::ContainerCount { reply } => {
                        let _ = reply.send(worker.containers.len());
                    }
                    WorkerCommand::Shutdown { reply } => {
                        worker.shutdown();
                        let _ = reply.send(());
                        break;
                    }
                }
            }
        })
        .map_err(|e| anyhow::anyhow!("spawn WSLc worker thread: {e}"))?;

    Ok(SessionHandle { tx, active_execs })
}

/// RAII guard that keeps the calling thread in the COM MTA for the WSLc SDK.
#[cfg(windows)]
struct ComApartment;

#[cfg(windows)]
impl ComApartment {
    fn enter() -> Result<Self> {
        use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};
        // SAFETY: called once at worker-thread startup. On success the matching
        // `CoUninitialize` runs in `Drop`; on failure no guard is produced, so
        // `CoUninitialize` is never called for an apartment we did not enter.
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if hr.is_err() {
            anyhow::bail!("CoInitializeEx(MTA) failed: {hr:?}");
        }
        Ok(Self)
    }
}

#[cfg(windows)]
impl Drop for ComApartment {
    fn drop(&mut self) {
        use windows::Win32::System::Com::CoUninitialize;
        // SAFETY: balances the CoInitializeEx in `enter`, on the same thread.
        unsafe {
            CoUninitialize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn count(handle: &SessionHandle) -> usize {
        handle.container_count().await.unwrap()
    }

    // ---- No-WSL unit tests (run everywhere, never touch the SDK) ----

    #[test]
    fn sr_err_carries_the_step_failure_phase() {
        for (phase, expected) in [
            (FailurePhase::BackendUnavailable, ErrKind::Unavailable),
            (FailurePhase::Rejected, ErrKind::Rejected),
            (FailurePhase::LaunchFailed, ErrKind::Backend),
            (FailurePhase::PostLaunchFailed, ErrKind::Backend),
            (FailurePhase::None, ErrKind::Backend),
        ] {
            let resp = ScriptResponse {
                exit_code: -1,
                error_message: "boom".to_string(),
                failure_phase: phase.clone(),
                ..Default::default()
            };
            assert_eq!(sr_err(resp).kind(), expected, "phase {phase:?}");
        }
    }

    #[test]
    fn sr_err_preserves_the_step_message() {
        let resp = ScriptResponse {
            exit_code: -1,
            error_message: "WSLc components are missing".to_string(),
            failure_phase: FailurePhase::BackendUnavailable,
            ..Default::default()
        };
        assert_eq!(sr_err(resp).to_string(), "WSLc components are missing");
    }

    #[tokio::test]
    async fn start_unknown_sandbox_errors() {
        let handle = spawn().unwrap();
        let err = handle
            .start(StartConfig {
                sandbox_id: "wslc:does-not-exist".to_string(),
            })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("unknown sandbox"));
        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn exec_unknown_sandbox_errors() {
        let handle = spawn().unwrap();
        let err = handle
            .exec(ExecConfig {
                exec_id: "unknown-1".to_string(),
                run_token: "run-unknown-1".to_string(),
                sandbox_id: "wslc:does-not-exist".to_string(),
                script_code: "echo hi".to_string(),
                working_directory: String::new(),
                env: Vec::new(),
                timeout_ms: 0,
            })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("unknown sandbox"));
        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn stop_unknown_sandbox_errors() {
        let handle = spawn().unwrap();
        let err = handle
            .stop(StopConfig {
                sandbox_id: "wslc:does-not-exist".to_string(),
            })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("unknown sandbox"));
        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn deprovision_unknown_sandbox_errors() {
        let handle = spawn().unwrap();
        let err = handle
            .deprovision(DeprovisionConfig {
                sandbox_id: "wslc:does-not-exist".to_string(),
            })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("unknown sandbox"));
        assert_eq!(count(&handle).await, 0);
        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn unknown_sandbox_maps_to_not_provisioned_kind() {
        let handle = spawn().unwrap();
        let err = handle
            .start(StartConfig {
                sandbox_id: "wslc:does-not-exist".to_string(),
            })
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrKind::NotProvisioned);
        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn exec_unknown_sandbox_admission_is_not_provisioned() {
        let handle = spawn().unwrap();
        let err = handle
            .exec(ExecConfig {
                exec_id: "unknown-2".to_string(),
                run_token: "run-unknown-2".to_string(),
                sandbox_id: "wslc:does-not-exist".to_string(),
                script_code: "echo hi".to_string(),
                working_directory: String::new(),
                env: Vec::new(),
                timeout_ms: 0,
            })
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrKind::NotProvisioned);
        handle.shutdown().await.unwrap();
    }

    #[test]
    fn cancel_exec_marks_the_registered_run() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let cancellation = Arc::new(AtomicBool::new(false));
        let active_execs = Arc::new(Mutex::new(HashMap::from([(
            "exec-1".to_string(),
            ActiveExec {
                run_token: "run-1".to_string(),
                cancellation: Arc::downgrade(&cancellation),
            },
        )])));
        let handle = SessionHandle { tx, active_execs };

        handle.cancel_exec("exec-1", "run-1");

        assert!(cancellation.load(Ordering::Acquire));
    }

    #[test]
    fn delayed_cancellation_does_not_target_reused_exec_id() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let cancellation = Arc::new(AtomicBool::new(false));
        let active_execs = Arc::new(Mutex::new(HashMap::new()));
        let registration =
            register_exec(&active_execs, "exec-1", "replacement-run", &cancellation).unwrap();
        let handle = SessionHandle { tx, active_execs };

        handle.cancel_exec("exec-1", "completed-run");
        assert!(!cancellation.load(Ordering::Acquire));

        handle.cancel_exec("exec-1", "replacement-run");
        assert!(cancellation.load(Ordering::Acquire));
        drop(registration);
    }

    #[test]
    fn duplicate_live_exec_id_is_rejected_without_replacing_registration() {
        let active_execs = Arc::new(Mutex::new(HashMap::new()));
        let first = Arc::new(AtomicBool::new(false));
        let second = Arc::new(AtomicBool::new(false));
        let registration = register_exec(&active_execs, "exec-1", "run-1", &first).unwrap();

        let error = register_exec(&active_execs, "exec-1", "run-2", &second).unwrap_err();

        assert_eq!(error.kind(), ErrKind::Rejected);
        let registered = active_execs
            .lock()
            .unwrap()
            .get("exec-1")
            .and_then(|entry| entry.cancellation.upgrade())
            .unwrap();
        assert!(Arc::ptr_eq(&registered, &first));
        drop(registration);
    }

    #[test]
    fn stale_exec_id_can_be_registered_again() {
        let stale = Arc::new(AtomicBool::new(false));
        let active_execs = Arc::new(Mutex::new(HashMap::from([(
            "exec-1".to_string(),
            ActiveExec {
                run_token: "stale-run".to_string(),
                cancellation: Arc::downgrade(&stale),
            },
        )])));
        drop(stale);
        let cancellation = Arc::new(AtomicBool::new(false));

        let registration =
            register_exec(&active_execs, "exec-1", "replacement-run", &cancellation).unwrap();

        let registered = active_execs
            .lock()
            .unwrap()
            .get("exec-1")
            .and_then(|entry| entry.cancellation.upgrade())
            .unwrap();
        assert!(Arc::ptr_eq(&registered, &cancellation));
        drop(registration);
        assert!(!active_execs.lock().unwrap().contains_key("exec-1"));
    }

    #[test]
    fn older_registration_does_not_remove_replacement() {
        let active_execs = Arc::new(Mutex::new(HashMap::new()));
        let first = Arc::new(AtomicBool::new(false));
        let first_registration = register_exec(&active_execs, "exec-1", "run-1", &first).unwrap();
        let second = Arc::new(AtomicBool::new(false));
        active_execs.lock().unwrap().insert(
            "exec-1".to_string(),
            ActiveExec {
                run_token: "run-2".to_string(),
                cancellation: Arc::downgrade(&second),
            },
        );

        drop(first_registration);

        let registered = active_execs
            .lock()
            .unwrap()
            .get("exec-1")
            .and_then(|entry| entry.cancellation.upgrade())
            .unwrap();
        assert!(Arc::ptr_eq(&registered, &second));
    }

    #[test]
    fn cancelling_unknown_or_stale_exec_id_is_a_no_op() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let stale = Arc::new(AtomicBool::new(false));
        let active_execs = Arc::new(Mutex::new(HashMap::from([(
            "stale".to_string(),
            ActiveExec {
                run_token: "stale-run".to_string(),
                cancellation: Arc::downgrade(&stale),
            },
        )])));
        drop(stale);
        let handle = SessionHandle { tx, active_execs };

        handle.cancel_exec("unknown", "unknown-run");
        handle.cancel_exec("stale", "stale-run");
    }

    #[tokio::test]
    async fn large_callback_split_into_frame_safe_chunks() {
        use wslc_common::daemon_protocol::{encode_frame, StreamFrame, MAX_FRAME_SIZE};

        let (tx, mut rx) = mpsc::channel::<OutputChunk>(LIVE_OUTPUT_CHANNEL_CAPACITY);
        // A single callback far larger than one chunk (and, unsplit, larger than
        // one frame once number-array-encoded): must arrive as many bounded chunks.
        let payload = vec![b'x'; LIVE_OUTPUT_MAX_CHUNK_BYTES * 3 + 7];
        let producer = tokio::task::spawn_blocking({
            let payload = payload.clone();
            move || {
                let overflowed = AtomicBool::new(false);
                enqueue_output(&tx, &overflowed, OutStream::Stdout, &payload)
            }
        });

        let mut reassembled = Vec::new();
        let mut chunks = 0usize;
        while let Some((kind, data)) = rx.recv().await {
            assert_eq!(kind, OutStream::Stdout);
            assert!(data.len() <= LIVE_OUTPUT_MAX_CHUNK_BYTES);
            let encoded = encode_frame(&StreamFrame::Stdout { data: data.clone() }).unwrap();
            assert!(encoded.len() <= MAX_FRAME_SIZE);
            reassembled.extend_from_slice(&data);
            chunks += 1;
        }
        producer.await.unwrap();
        assert_eq!(reassembled, payload);
        assert!(
            chunks >= 4,
            "expected the callback to be split, got {chunks}"
        );
    }
    //
    // Exercises the real SDK path end to end: provision (boot VM + create
    // container) → start → exec → stop → deprovision → refcount back to 0. It
    // needs a WSL2 host with `alpine:latest` pre-pulled into the daemon session
    // cache (`%TEMP%\mxc-wslc-sessions`, e.g. via `scripts\setup-wslc.ps1
    // -Image alpine:latest`), so it is `#[ignore]`d and run explicitly with
    // `cargo test -p wxc_wslc_daemon -- --ignored`.
    #[tokio::test]
    #[ignore = "requires a WSL2 host with alpine:latest pre-pulled into the daemon session cache"]
    async fn full_lifecycle_on_wsl_host() {
        let handle = spawn().unwrap();
        assert_eq!(count(&handle).await, 0);

        let id = handle
            .provision(ProvisionConfig {
                image: "alpine:latest".to_string(),
                image_tar_path: None,
                volumes: Vec::new(),
                network: Default::default(),
            })
            .await
            .unwrap();
        assert_eq!(count(&handle).await, 1);

        handle
            .start(StartConfig {
                sandbox_id: id.clone(),
            })
            .await
            .unwrap();

        let mut exec = handle
            .exec(ExecConfig {
                exec_id: "full-lifecycle".to_string(),
                run_token: "full-lifecycle-run".to_string(),
                sandbox_id: id.clone(),
                script_code: "echo hi".to_string(),
                working_directory: String::new(),
                env: Vec::new(),
                timeout_ms: 30_000,
            })
            .await
            .unwrap();
        // Drain the live output stream, then await the exit code.
        let mut stdout = Vec::new();
        while let Some((kind, data)) = exec.output.recv().await {
            if kind == OutStream::Stdout {
                stdout.extend_from_slice(&data);
            }
        }
        let code = exec.done.await.unwrap().unwrap();
        assert_eq!(code, ExecTerminal::Exited(0));
        assert_eq!(String::from_utf8_lossy(&stdout).trim(), "hi");

        handle
            .stop(StopConfig {
                sandbox_id: id.clone(),
            })
            .await
            .unwrap();

        handle
            .deprovision(DeprovisionConfig { sandbox_id: id })
            .await
            .unwrap();
        assert_eq!(count(&handle).await, 0);

        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires a WSL2 host with alpine:latest pre-pulled into the daemon session cache"]
    async fn cancelled_queued_exec_never_starts_process() {
        let handle = spawn().unwrap();
        let id = handle
            .provision(ProvisionConfig {
                image: "alpine:latest".to_string(),
                image_tar_path: None,
                volumes: Vec::new(),
                network: Default::default(),
            })
            .await
            .unwrap();
        handle
            .start(StartConfig {
                sandbox_id: id.clone(),
            })
            .await
            .unwrap();

        let blocker = handle
            .exec(ExecConfig {
                exec_id: "queue-blocker".to_string(),
                run_token: "queue-blocker-run".to_string(),
                sandbox_id: id.clone(),
                script_code: "sleep 2".to_string(),
                working_directory: String::new(),
                env: Vec::new(),
                timeout_ms: 30_000,
            })
            .await
            .unwrap();

        let queued_handle = handle.clone();
        let queued_id = id.clone();
        let queued = tokio::spawn(async move {
            queued_handle
                .exec(ExecConfig {
                    exec_id: "cancelled-queued".to_string(),
                    run_token: "cancelled-queued-run".to_string(),
                    sandbox_id: queued_id,
                    script_code: "touch /tmp/mxc-cancelled-queued-marker".to_string(),
                    working_directory: String::new(),
                    env: Vec::new(),
                    timeout_ms: 30_000,
                })
                .await
        });

        for _ in 0..100 {
            if handle
                .active_execs
                .lock()
                .unwrap()
                .contains_key("cancelled-queued")
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            handle
                .active_execs
                .lock()
                .unwrap()
                .contains_key("cancelled-queued"),
            "queued exec was not registered"
        );
        handle.cancel_exec("cancelled-queued", "cancelled-queued-run");
        assert_eq!(
            blocker.done.await.unwrap().unwrap(),
            ExecTerminal::Exited(0)
        );

        let queued = queued.await.unwrap().unwrap();
        assert_eq!(queued.done.await.unwrap().unwrap(), ExecTerminal::Cancelled);

        let marker_check = handle
            .exec(ExecConfig {
                exec_id: "marker-check".to_string(),
                run_token: "marker-check-run".to_string(),
                sandbox_id: id.clone(),
                script_code: "test ! -e /tmp/mxc-cancelled-queued-marker".to_string(),
                working_directory: String::new(),
                env: Vec::new(),
                timeout_ms: 30_000,
            })
            .await
            .unwrap();
        assert_eq!(
            marker_check.done.await.unwrap().unwrap(),
            ExecTerminal::Exited(0)
        );

        handle
            .stop(StopConfig {
                sandbox_id: id.clone(),
            })
            .await
            .unwrap();
        handle
            .deprovision(DeprovisionConfig { sandbox_id: id })
            .await
            .unwrap();
        handle.shutdown().await.unwrap();
    }
}
