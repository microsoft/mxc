// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use crate::mxc_common::logger::Logger;
use crate::mxc_common::mxc_error::{MxcError, MxcErrorCode};
use crate::mxc_common::script_runner::RunCancellation;
use aci_edge_sandboxes::agent::{
    AgentBackend, AgentConfig, BundledAgent, CpuProfile, ImageDigest, PlatformSnapshots,
    SandboxDiagnostics, SetupConfig,
};
use aci_edge_sandboxes::{
    AciEdgeSandbox, Backend, Capabilities, Error, ErrorCode, ExecIo, ExecOutcome, ExecRequest,
    ImageSource, OutputCloser, OutputSink, ProvisionRequest, SandboxSpec, StartResult,
};

const BUNDLE_FINGERPRINTS: &[super::signature_verification::BundleFingerprint<'static>] = {
    use super::signature_verification::BundleFingerprint;
    include!(concat!(env!("OUT_DIR"), "\\nvx_bundle_fingerprints.rs"))
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SandboxId(aci_edge_sandboxes::SandboxId);

impl SandboxId {
    pub fn from_token(token: &str) -> aci_edge_sandboxes::Result<Self> {
        aci_edge_sandboxes::SandboxId::from_token(token).map(Self)
    }

    pub fn from_mxc(value: &str) -> Result<Self, MxcError> {
        let token = value.strip_prefix("microvm:").ok_or_else(|| {
            MxcError::malformed_id("MicroVM sandbox ID must start with 'microvm:'")
        })?;
        Self::from_token(token).map_err(|_| {
            MxcError::malformed_id(
                "MicroVM sandbox ID must contain 32 lowercase hexadecimal digits",
            )
        })
    }

    pub fn to_mxc_string(&self) -> String {
        format!("microvm:{}", self.0.token())
    }
}

impl std::fmt::Display for SandboxId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, formatter)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProvisionOutput {
    pub sandbox_id: SandboxId,
    pub metadata: Option<serde_json::Map<String, serde_json::Value>>,
}

pub(super) const CAPTURE_LIMIT_BYTES: usize = 64 * 1024 * 1024;
const STARTUP_LOG_LIMIT: usize = 8 * 1024;
const HOST_TIMEOUT_SLACK_MS: u64 = 30_000;
const POLL: Duration = Duration::from_millis(100);
const CANCEL_GRACE: Duration = Duration::from_secs(2);
pub(super) const UNKNOWN_OUTCOME: &str =
    "NVX execution outcome is unknown after the 2-second cancellation grace period; \
     the workload may still be running";
pub(super) const CANCEL_UNFINISHED: &str =
    "NVX cancellation did not finish within the 2-second grace period; \
     a background native call may still be running";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PreparedProvision {
    pub request: ProvisionRequest,
    pub spec: SandboxSpec,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExecOutput {
    pub outcome: ExecOutcome,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub(super) trait SandboxClient {
    fn capabilities(&self) -> Result<Capabilities, MxcError>;
    fn validate_provision(&self, input: &PreparedProvision) -> Result<(), MxcError>;
    fn validate_exec(&self, request: &ExecRequest) -> Result<(), MxcError>;
    /// Opens the process-owned execution host, returning a cold-boot fallback reason if template
    /// initialization is unavailable. Invalid setup and handle-close failures remain errors.
    fn open_execution_host(&mut self) -> Result<Option<MxcError>, MxcError>;
    fn probe(&self) -> Result<(), MxcError>;
    fn provision(&self, input: &PreparedProvision) -> Result<ProvisionOutput, MxcError>;
    fn start(&self, sandbox_id: &SandboxId) -> Result<StartResult, MxcError>;
    fn diagnostics(&self, sandbox_id: &SandboxId) -> Result<SandboxDiagnostics, MxcError>;
    fn exec_and_wait(
        &self,
        sandbox_id: &SandboxId,
        request: &ExecRequest,
        cancellation: Option<&RunCancellation>,
        logger: &mut Logger,
    ) -> Result<ExecOutput, MxcError>;
    fn stop(&self, sandbox_id: &SandboxId) -> Result<(), MxcError>;
    fn deprovision(&self, sandbox_id: &SandboxId) -> Result<(), MxcError>;
    fn close(&mut self) -> Result<(), MxcError>;
}

pub(super) fn startup_diagnostics(diagnostics: &SandboxDiagnostics) -> String {
    let mut excerpt = String::new();
    for (name, path) in [
        ("vmm_log", &diagnostics.vmm_log),
        ("console_log", &diagnostics.console_log),
        ("outcome_report", &diagnostics.outcome_report),
    ] {
        excerpt.push_str(&format!("; {name}: "));
        match read_startup_log(path) {
            Ok((bytes, truncated)) => {
                if truncated {
                    excerpt.push_str("[truncated] ");
                }
                if bytes.is_empty() {
                    excerpt.push_str("[empty]");
                } else {
                    excerpt.push_str(&String::from_utf8_lossy(&bytes));
                }
            }
            Err(error) => excerpt.push_str(&format!("unavailable ({}): {error}", path.display())),
        }
    }
    excerpt
}

fn read_startup_log(path: &Path) -> io::Result<(Vec<u8>, bool)> {
    let mut file = std::fs::File::open(path)?;
    let length = file.metadata()?.len();
    let start = length.saturating_sub(STARTUP_LOG_LIMIT as u64);
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::new();
    file.take(STARTUP_LOG_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)?;
    let truncated = start != 0 || bytes.len() > STARTUP_LOG_LIMIT;
    bytes.truncate(STARTUP_LOG_LIMIT);
    Ok((bytes, truncated))
}

pub(super) fn map_error(error: Error) -> MxcError {
    let code = match error.code() {
        ErrorCode::MalformedRequest => MxcErrorCode::MalformedRequest,
        ErrorCode::MalformedId => MxcErrorCode::MalformedId,
        ErrorCode::StaleId => MxcErrorCode::StaleId,
        ErrorCode::NotStarted => MxcErrorCode::NotStarted,
        ErrorCode::AlreadyStarted => MxcErrorCode::AlreadyStarted,
        ErrorCode::AlreadyStopped => MxcErrorCode::AlreadyStopped,
        ErrorCode::PolicyValidation => MxcErrorCode::PolicyValidation,
        ErrorCode::BackendUnavailable => MxcErrorCode::BackendUnavailable,
        ErrorCode::Unsupported | ErrorCode::BackendError => MxcErrorCode::BackendError,
        _ => MxcErrorCode::BackendError,
    };
    let mut message = format!("NVX signed bundled agent: {error}");
    let mut source = std::error::Error::source(&error);
    while let Some(cause) = source {
        message.push_str(&format!(": {cause}"));
        source = cause.source();
    }
    MxcError::new(code, message)
}

pub(super) fn sandbox_spec(image: &str) -> Result<SandboxSpec, MxcError> {
    crate::mxc_contract::dev::ImageReference::validate(image)
        .map_err(MxcError::malformed_request)?;
    Ok(SandboxSpec::new().with_image(ImageSource::Reference(image.to_owned())))
}

struct ClientInner {
    backend: Arc<AgentBackend>,
    client: AciEdgeSandbox,
    _bundle_guard: super::signature_verification::BundleGuard,
    _state_root_guard: Option<crate::mxc_common::filesystem_security::LockedDirectoryPath>,
}

pub(super) struct NvxClient(Option<ClientInner>);

// Sandboxes have the agent's default resources, one virtual processor and 256 MiB of memory,
// unless a request sets their memory, so the smallest templates fit them.
const PLATFORM_SNAPSHOT_MAX_VCPUS: u32 = 1;
const PLATFORM_SNAPSHOT_MAX_MEMORY_MIB: u32 = 256;

fn agent_setup(bundle: &BundledAgent, state_root: &Path) -> SetupConfig {
    bundle.setup(state_root).with_cpu_profile(CpuProfile::Host)
}

fn platform_snapshots() -> PlatformSnapshots {
    PlatformSnapshots::new(
        PLATFORM_SNAPSHOT_MAX_VCPUS,
        PLATFORM_SNAPSHOT_MAX_MEMORY_MIB,
    )
}

/// Opens the agent without platform snapshots, so opening it never boots a VM.
pub(super) fn create_persistent_client(
    guard: crate::mxc_common::filesystem_security::LockedDirectoryPath,
) -> Result<NvxClient, MxcError> {
    let path = guard.path().to_path_buf();
    create_client_with_guard(&path, Some(guard))
}

fn create_client_with_guard(
    state_root: &Path,
    guard: Option<crate::mxc_common::filesystem_security::LockedDirectoryPath>,
) -> Result<NvxClient, MxcError> {
    let bundle = BundledAgent::discover().map_err(map_error)?;
    let directory = bundle.directory().canonicalize().map_err(|error| {
        MxcError::backend_unavailable(format!("cannot resolve NVX bundle: {error}"))
    })?;
    let bundle = BundledAgent::from_dir(directory).map_err(map_error)?;
    let bundle_guard =
        super::signature_verification::verify_bundle(bundle.directory(), Some(BUNDLE_FINGERPRINTS))
            .map_err(|error| MxcError::backend_unavailable(error.to_string()))?;
    // The crate's output pump can outlive an unknown execution outcome and client teardown.
    crate::mxc_common::module_lifetime::pin_current_module()
        .map_err(MxcError::backend_unavailable)?;
    let config = bundle.config(agent_setup(&bundle, state_root));
    let backend = Arc::new(AgentBackend::new(config).map_err(map_error)?);
    let client = AciEdgeSandbox::from_shared(backend.clone());
    Ok(NvxClient(Some(ClientInner {
        backend,
        client,
        _bundle_guard: bundle_guard,
        _state_root_guard: guard,
    })))
}

impl NvxClient {
    fn inner(&self) -> Result<&ClientInner, MxcError> {
        self.0
            .as_ref()
            .ok_or_else(|| MxcError::backend_error("NVX client is closed"))
    }
}

pub(super) fn agent_bundle_available() -> bool {
    BundledAgent::discover().is_ok_and(|bundle| bundle.library().is_file())
}

pub(super) fn require_agent_bundle_present() -> Result<(), MxcError> {
    let bundle = BundledAgent::discover().map_err(map_error)?;
    if bundle.library().is_file() {
        Ok(())
    } else {
        Err(MxcError::backend_unavailable(format!(
            "NVX bundle is missing {}",
            bundle.library().display()
        )))
    }
}

pub(super) fn state_root(
) -> Result<crate::mxc_common::filesystem_security::LockedDirectoryPath, MxcError> {
    let local_app_data = std::env::var_os("LOCALAPPDATA")
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("USERPROFILE")
                .filter(|value| !value.is_empty())
                .map(|profile| std::path::PathBuf::from(profile).join("AppData").join("Local"))
        })
        .ok_or_else(|| {
            MxcError::backend_unavailable(
                "NVX signed bundled agent: cannot resolve LOCALAPPDATA for the agent state directory",
            )
        })?;
    let bundle = BundledAgent::discover().map_err(map_error)?;
    state_root_in(&local_app_data, bundle.manifest_sha256())
}

fn state_root_in(
    local_app_data: &Path,
    manifest_sha256: [u8; 32],
) -> Result<crate::mxc_common::filesystem_security::LockedDirectoryPath, MxcError> {
    let local_app_data = std::path::absolute(local_app_data).map_err(|error| {
        MxcError::backend_unavailable(format!(
            "NVX signed bundled agent: cannot resolve the agent state directory: {error}"
        ))
    })?;
    let parent = lock_lifecycle_state_root_in(&local_app_data)?;
    let bundle_key: String = manifest_sha256[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let root = crate::mxc_common::filesystem_security::lock_owner_only_directory_path(
        parent.path(),
        &[std::ffi::OsStr::new(&bundle_key)],
        0,
    )
    .map_err(|error| {
        MxcError::backend_unavailable(format!(
            "NVX signed bundled agent: cannot create the bundle state directory below '{}': {error}",
            parent.path().display()
        ))
    })?;
    crate::mxc_common::filesystem_security::set_current_user_owner(root.path()).map_err(
        |error| {
            MxcError::backend_unavailable(format!(
                "NVX signed bundled agent: cannot secure the bundle state directory {}: {error}",
                root.path().display()
            ))
        },
    )?;
    Ok(root)
}

pub(super) fn lifecycle_state_root(
) -> Result<crate::mxc_common::filesystem_security::LockedDirectoryPath, MxcError> {
    let local_app_data = std::env::var_os("LOCALAPPDATA").ok_or_else(|| {
        MxcError::backend_unavailable(
            "cannot resolve LOCALAPPDATA for the persistent NVX lifecycle state",
        )
    })?;
    let local_app_data = std::path::PathBuf::from(local_app_data);
    lock_lifecycle_state_root_in(&local_app_data)
}

fn lock_lifecycle_state_root_in(
    local_app_data: &Path,
) -> Result<crate::mxc_common::filesystem_security::LockedDirectoryPath, MxcError> {
    let root = crate::mxc_common::filesystem_security::lock_owner_only_directory_path(
        local_app_data,
        [
            std::ffi::OsStr::new("Microsoft"),
            std::ffi::OsStr::new("MXC"),
            std::ffi::OsStr::new("nvx"),
        ]
        .as_slice(),
        2,
    )
    .map_err(|error| {
        MxcError::backend_unavailable(format!(
            "cannot admit persistent NVX state below '{}': {error}",
            local_app_data.display()
        ))
    })?;
    crate::mxc_common::filesystem_security::set_current_user_owner(root.path()).map_err(
        |error| {
            MxcError::backend_unavailable(format!(
                "cannot make the current user the owner of persistent NVX state '{}': {error}",
                root.path().display()
            ))
        },
    )?;
    Ok(root)
}

pub(super) enum Event {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit(Result<ExecOutcome, MxcError>),
}

struct EventSink {
    sender: mpsc::SyncSender<Event>,
    closed: Arc<AtomicBool>,
    stderr: bool,
}

impl OutputSink for EventSink {
    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        // Bound buffering even when the caller holds its output without reading.
        for bytes in data.chunks(64 * 1024) {
            let mut event = if self.stderr {
                Event::Stderr(bytes.to_vec())
            } else {
                Event::Stdout(bytes.to_vec())
            };
            loop {
                if self.closed.load(Ordering::Acquire) {
                    return Err(io::ErrorKind::BrokenPipe.into());
                }
                match self.sender.try_send(event) {
                    Ok(()) => break,
                    Err(mpsc::TrySendError::Full(pending)) => {
                        event = pending;
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(mpsc::TrySendError::Disconnected(_)) => {
                        return Err(io::ErrorKind::BrokenPipe.into())
                    }
                }
            }
        }
        Ok(())
    }

    fn close_handle(&self) -> Option<OutputCloser> {
        let closed = self.closed.clone();
        Some(OutputCloser::new(move || {
            closed.store(true, Ordering::Release)
        }))
    }
}

#[derive(Clone)]
pub(super) struct StreamingExecution(Arc<StreamingExecutionInner>);

struct StreamingExecutionInner {
    control: Arc<dyn aci_edge_sandboxes::ExecControl>,
    receiver: Mutex<Option<mpsc::Receiver<Event>>>,
    closed: Arc<AtomicBool>,
    cancellation: Mutex<Option<Instant>>,
}

impl NvxClient {
    pub(super) fn start_execution(
        &self,
        sandbox_id: &SandboxId,
        request: &ExecRequest,
    ) -> Result<StreamingExecution, MxcError> {
        let inner = self.inner()?;
        let (sender, receiver) = mpsc::sync_channel(1);
        let closed = Arc::new(AtomicBool::new(false));
        let io = ExecIo {
            stdout: Box::new(EventSink {
                sender: sender.clone(),
                closed: closed.clone(),
                stderr: false,
            }),
            stderr: Box::new(EventSink {
                sender: sender.clone(),
                closed: closed.clone(),
                stderr: true,
            }),
            stdin: None,
        };
        let control: Arc<dyn aci_edge_sandboxes::ExecControl> = Arc::from(
            inner
                .backend
                .exec(&sandbox_id.0, request, io)
                .map_err(map_error)?,
        );
        StreamingExecution::observe(control, sender, receiver, closed)
    }
}

impl StreamingExecution {
    fn observe(
        control: Arc<dyn aci_edge_sandboxes::ExecControl>,
        sender: mpsc::SyncSender<Event>,
        receiver: mpsc::Receiver<Event>,
        closed: Arc<AtomicBool>,
    ) -> Result<Self, MxcError> {
        let waiting = control.clone();
        if let Err(error) = std::thread::Builder::new()
            .name("mxc-nvx-stream".to_owned())
            .spawn(move || {
                let _ = sender.send(Event::Exit(waiting.wait().map_err(map_error)));
            })
        {
            closed.store(true, Ordering::Release);
            return Err(MxcError::backend_error(format!(
                "cannot start NVX stream observer: {error}; execution outcome is unknown"
            )));
        }
        Ok(Self(Arc::new(StreamingExecutionInner {
            control,
            receiver: Mutex::new(Some(receiver)),
            closed,
            cancellation: Mutex::new(None),
        })))
    }
    pub(super) fn next<T>(
        &self,
        timeout_ms: Option<u64>,
        deliver: impl FnOnce(Event) -> T,
    ) -> Result<Option<T>, MxcError> {
        let deadline = timeout_ms
            .and_then(|timeout| Instant::now().checked_add(Duration::from_millis(timeout)));
        let receiver = self
            .0
            .receiver
            .lock()
            .map_err(|_| MxcError::backend_error("NVX stream receiver lock poisoned"))?;
        let receiver = receiver
            .as_ref()
            .ok_or_else(|| MxcError::backend_error("NVX execution was released"))?;
        loop {
            let cancelled = *self
                .0
                .cancellation
                .lock()
                .map_err(|_| MxcError::backend_error("NVX cancellation lock poisoned"))?;
            if cancelled.is_some_and(|start| start.elapsed() >= CANCEL_GRACE) {
                return Err(MxcError::backend_error(UNKNOWN_OUTCOME));
            }
            let pause = deadline.map_or(POLL, |end| {
                POLL.min(end.saturating_duration_since(Instant::now()))
            });
            match receiver.recv_timeout(pause) {
                Ok(event) => return Ok(Some(deliver(event))),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(MxcError::backend_error(
                        "NVX stream ended without an outcome",
                    ))
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if deadline.is_some_and(|end| Instant::now() >= end) {
                        return Ok(None);
                    }
                }
            }
        }
    }

    pub(super) fn cancel(&self) -> Result<(), MxcError> {
        {
            let mut cancelled = self
                .0
                .cancellation
                .lock()
                .map_err(|_| MxcError::backend_error("NVX cancellation lock poisoned"))?;
            if cancelled.is_some() {
                return Ok(());
            }
            *cancelled = Some(Instant::now());
        }
        self.0.closed.store(true, Ordering::Release);
        let control = self.0.control.clone();
        let (sender, receiver) = mpsc::channel();
        std::thread::Builder::new()
            .name("mxc-nvx-stream-cancel".to_owned())
            .spawn(move || {
                let _ = sender.send(control.cancel().map_err(map_error));
            })
            .map_err(|error| {
                MxcError::backend_error(format!("cannot start NVX cancellation worker: {error}"))
            })?;
        receiver
            .recv_timeout(CANCEL_GRACE)
            .map_err(|_| MxcError::backend_error(CANCEL_UNFINISHED))?
    }

    pub(super) fn release(&self) -> Result<(), MxcError> {
        self.0.closed.store(true, Ordering::Release);
        self.0
            .receiver
            .lock()
            .map_err(|_| MxcError::backend_error("NVX stream receiver lock poisoned"))?
            .take();
        Ok(())
    }
}

impl Drop for StreamingExecutionInner {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
    }
}

#[derive(Default)]
struct Captured {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    overflow: bool,
}

struct CaptureSink {
    shared: Arc<Mutex<Captured>>,
    stderr: bool,
    limit: usize,
}

impl OutputSink for CaptureSink {
    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        let mut captured = self
            .shared
            .lock()
            .map_err(|_| io::Error::other("NVX capture lock poisoned"))?;
        if data.len()
            > self
                .limit
                .saturating_sub(captured.stdout.len() + captured.stderr.len())
        {
            captured.overflow = true;
            return Err(io::Error::other("NVX capture limit exceeded"));
        }
        if self.stderr {
            captured.stderr.extend_from_slice(data);
        } else {
            captured.stdout.extend_from_slice(data);
        }
        Ok(())
    }
}

pub(super) fn capture_limit_error(limit: usize) -> MxcError {
    MxcError::backend_error(format!(
        "NVX signed bundled agent: combined stdout/stderr capture limit of {limit} bytes exceeded"
    ))
}

fn execution_failure(primary: Option<MxcError>, cleanup: MxcError) -> MxcError {
    match primary {
        Some(mut primary) => {
            primary
                .message
                .push_str(&format!("; cleanup failure: {cleanup}"));
            primary
        }
        None => cleanup,
    }
}

fn collect_execution(
    control: Arc<dyn aci_edge_sandboxes::ExecControl>,
    captured: Arc<Mutex<Captured>>,
    deadline: Option<Instant>,
    cancellation: Option<&RunCancellation>,
    limit: usize,
) -> Result<ExecOutput, MxcError> {
    let (sender, receiver) = mpsc::channel();
    let waiting = control.clone();
    // Workers retain their controls; the caller must not join an unresponsive native call.
    let _waiter = std::thread::Builder::new()
        .name("mxc-nvx-wait".to_owned())
        .spawn(move || {
            let _ = sender.send(waiting.wait());
        })
        .map_err(|error| {
            MxcError::backend_error(format!(
                "cannot start NVX wait thread: {error}; execution outcome is unknown"
            ))
        })?;
    let mut failure = None;
    let mut host_timeout = false;
    let mut observed = None;
    let mut cancel_deadline: Option<Instant> = None;
    let mut cancel_result: Option<mpsc::Receiver<Result<(), MxcError>>> = None;
    let outcome = loop {
        match cancel_result.as_ref().map(mpsc::Receiver::try_recv) {
            Some(Ok(result)) => {
                cancel_result = None;
                if let Err(error) = result {
                    failure = Some(execution_failure(failure, error));
                }
            }
            Some(Err(mpsc::TryRecvError::Disconnected)) => {
                cancel_result = None;
                failure = Some(execution_failure(
                    failure,
                    MxcError::backend_error("NVX cancellation worker terminated without a result"),
                ));
            }
            Some(Err(mpsc::TryRecvError::Empty)) | None => {}
        }
        if cancel_result.is_none() {
            if let Some(outcome) = observed.take() {
                break outcome;
            }
        }
        if cancel_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            let message = if observed.is_some() {
                CANCEL_UNFINISHED
            } else {
                UNKNOWN_OUTCOME
            };
            // Do not wait for capture locks or worker destruction after this deadline.
            let mut error = MxcError::backend_error(message);
            if let Some(primary) = failure {
                error = execution_failure(Some(error), primary);
            }
            if let Some(Err(native)) = observed {
                error = execution_failure(Some(error), native);
            }
            return Err(error);
        }
        let pause = cancel_deadline.map_or(POLL, |deadline| {
            POLL.min(deadline.saturating_duration_since(Instant::now()))
        });
        if observed.is_none() {
            match receiver.recv_timeout(pause) {
                Ok(result) => observed = Some(result.map_err(map_error)),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    observed = Some(Err(MxcError::backend_error(
                        "NVX wait thread terminated without an outcome",
                    )));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        } else {
            std::thread::sleep(pause);
        }
        if observed.is_some() {
            continue;
        }
        if cancel_deadline.is_none() {
            match captured.lock() {
                Ok(capture) if capture.overflow => failure = Some(capture_limit_error(limit)),
                Err(_) => failure = Some(MxcError::backend_error("NVX capture lock poisoned")),
                _ => {}
            }
            if failure.is_none() {
                if let Some(cancellation) = cancellation {
                    failure = cancellation.check().err();
                }
            }
            if failure.is_none() && deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                host_timeout = true;
            }
            if failure.is_some() || host_timeout {
                cancel_deadline = Some(Instant::now() + CANCEL_GRACE);
                let cancelling = control.clone();
                let (sender, receiver) = mpsc::channel();
                match std::thread::Builder::new()
                    .name("mxc-nvx-cancel".to_owned())
                    .spawn(move || {
                        let _ = sender.send(cancelling.cancel().map_err(map_error));
                    }) {
                    Ok(_worker) => cancel_result = Some(receiver),
                    Err(error) => {
                        failure = Some(execution_failure(
                            failure,
                            MxcError::backend_error(format!(
                                "cannot start NVX cancellation worker: {error}"
                            )),
                        ));
                    }
                }
            }
        }
    };
    let mut captured = captured
        .lock()
        .map_err(|_| MxcError::backend_error("NVX capture lock poisoned"))?;
    if captured.overflow && failure.is_none() {
        failure = Some(capture_limit_error(limit));
    }
    if let Some(mut error) = failure {
        if let Err(cleanup) = outcome {
            error
                .message
                .push_str(&format!("; cleanup failure: {cleanup}"));
        }
        return Err(error);
    }
    let outcome = outcome?;
    Ok(ExecOutput {
        outcome: if host_timeout
            && matches!(outcome, ExecOutcome::Cancelled | ExecOutcome::TimedOut)
        {
            ExecOutcome::TimedOut
        } else {
            outcome
        },
        stdout: std::mem::take(&mut captured.stdout),
        stderr: std::mem::take(&mut captured.stderr),
    })
}

impl SandboxClient for NvxClient {
    fn capabilities(&self) -> Result<Capabilities, MxcError> {
        Ok(self.inner()?.client.capabilities())
    }
    fn validate_provision(&self, input: &PreparedProvision) -> Result<(), MxcError> {
        self.inner()?
            .client
            .validate_provision_with(&input.request, &input.spec)
            .map_err(map_error)
    }
    fn validate_exec(&self, request: &ExecRequest) -> Result<(), MxcError> {
        self.inner()?
            .client
            .validate_exec(request)
            .map_err(map_error)
    }
    fn open_execution_host(&mut self) -> Result<Option<MxcError>, MxcError> {
        let inner = self
            .0
            .as_mut()
            .ok_or_else(|| MxcError::backend_error("NVX client is closed"))?;
        let cold = inner.backend.config();
        let setup = cold
            .setup
            .clone()
            .with_platform_snapshots(platform_snapshots());
        setup.validate().map_err(map_error)?;
        let config = AgentConfig::new(setup, cold.library.clone(), cold.library_sha256);
        // The native library retains hosts by setup for the process lifetime, including after this
        // operation's handle closes. Keep this setup stable rather than adding another cache.
        let backend = match AgentBackend::new(config) {
            Ok(backend) => Arc::new(backend),
            Err(error)
                if matches!(
                    error.code(),
                    ErrorCode::BackendUnavailable
                        | ErrorCode::BackendError
                        | ErrorCode::Unsupported
                ) =>
            {
                return Ok(Some(map_error(error)));
            }
            Err(error) => return Err(map_error(error)),
        };
        inner.client = AciEdgeSandbox::from_shared(backend.clone());
        let cold = std::mem::replace(&mut inner.backend, backend);
        Arc::try_unwrap(cold)
            .map_err(|_| {
                MxcError::backend_error(
                    "cannot close the NVX agent opened without platform snapshots: backend \
                     still has other owners",
                )
            })?
            .close()
            .map_err(map_error)?;
        Ok(None)
    }
    fn probe(&self) -> Result<(), MxcError> {
        self.inner()?.client.probe().map_err(map_error)
    }
    fn provision(&self, input: &PreparedProvision) -> Result<ProvisionOutput, MxcError> {
        let inner = self.inner()?;
        if let Some(ImageSource::Reference(reference)) = &input.spec.image {
            inner
                .backend
                .register_reference(reference, ImageDigest::Compute)
                .map_err(map_error)?;
        }
        inner
            .client
            .provision_with(&input.request, &input.spec)
            .map(|result| ProvisionOutput {
                sandbox_id: SandboxId(result.sandbox_id),
                metadata: result.metadata,
            })
            .map_err(map_error)
    }
    fn start(&self, sandbox_id: &SandboxId) -> Result<StartResult, MxcError> {
        self.inner()?.client.start(&sandbox_id.0).map_err(map_error)
    }
    fn diagnostics(&self, sandbox_id: &SandboxId) -> Result<SandboxDiagnostics, MxcError> {
        self.inner()?
            .backend
            .diagnostics(&sandbox_id.0)
            .map_err(map_error)
    }
    fn exec_and_wait(
        &self,
        sandbox_id: &SandboxId,
        request: &ExecRequest,
        cancellation: Option<&RunCancellation>,
        logger: &mut Logger,
    ) -> Result<ExecOutput, MxcError> {
        if let Some(cancellation) = cancellation {
            cancellation.check()?;
        }
        let inner = self.inner()?;
        inner.client.validate_exec(request).map_err(map_error)?;
        let captured = Arc::new(Mutex::new(Captured::default()));
        let io = ExecIo {
            stdout: Box::new(CaptureSink {
                shared: captured.clone(),
                stderr: false,
                limit: CAPTURE_LIMIT_BYTES,
            }),
            stderr: Box::new(CaptureSink {
                shared: captured.clone(),
                stderr: true,
                limit: CAPTURE_LIMIT_BYTES,
            }),
            stdin: None,
        };
        let control: Arc<dyn aci_edge_sandboxes::ExecControl> = Arc::from(
            inner
                .backend
                .exec(&sandbox_id.0, request, io)
                .map_err(map_error)?,
        );
        logger.log_diagnostic_line("NVX execution started");
        let deadline = request
            .process
            .timeout
            .filter(|v| !v.is_zero())
            .and_then(|v| {
                Instant::now()
                    .checked_add(v.saturating_add(Duration::from_millis(HOST_TIMEOUT_SLACK_MS)))
            });
        collect_execution(
            control,
            captured,
            deadline,
            cancellation,
            CAPTURE_LIMIT_BYTES,
        )
    }

    fn stop(&self, sandbox_id: &SandboxId) -> Result<(), MxcError> {
        self.inner()?
            .client
            .stop(&sandbox_id.0)
            .map(|_| ())
            .map_err(map_error)
    }
    fn deprovision(&self, sandbox_id: &SandboxId) -> Result<(), MxcError> {
        self.inner()?
            .client
            .deprovision(&sandbox_id.0)
            .map(|_| ())
            .map_err(map_error)
    }
    fn close(&mut self) -> Result<(), MxcError> {
        let Some(ClientInner {
            backend,
            client,
            _bundle_guard,
            _state_root_guard,
        }) = self.0.take()
        else {
            return Ok(());
        };
        drop(client);
        let backend = Arc::try_unwrap(backend).map_err(|_| {
            MxcError::backend_error("cannot close NVX agent: backend still has other owners")
        })?;
        backend.close().map_err(map_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aci_edge_sandboxes::ExecControl;
    use std::sync::Condvar;

    #[test]
    fn lifecycle_ids_preserve_native_tokens_and_reject_malformed_ids() {
        let token = "0123456789abcdef0123456789abcdef";
        let native = SandboxId::from_token(token).unwrap();
        let text = format!("microvm:{token}");
        assert_eq!(native.to_mxc_string(), text);
        assert_eq!(SandboxId::from_mxc(&text).unwrap(), native);
        for invalid in [
            "microvm:",
            "microvm:bad",
            "microvm:ABCDEF0123456789abcdef0123456789",
            "other:0123456789abcdef0123456789abcdef",
        ] {
            assert_eq!(
                SandboxId::from_mxc(invalid).unwrap_err().code,
                MxcErrorCode::MalformedId
            );
        }
    }

    #[test]
    fn streaming_queue_bounds_output_and_closing_releases_backpressure() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let closed = Arc::new(AtomicBool::new(false));
        let mut sink = EventSink {
            sender,
            closed,
            stderr: true,
        };
        let closer = sink.close_handle().unwrap();
        let bytes = vec![0xff; 192 * 1024];
        let (done_sender, done_receiver) = mpsc::channel();
        let writer = std::thread::spawn(move || {
            let result = sink.write(&bytes);
            done_sender
                .send(result.map_err(|error| error.kind()))
                .unwrap();
        });
        match receiver.recv_timeout(Duration::from_secs(2)).unwrap() {
            Event::Stderr(data) => assert_eq!(data, vec![0xff; 64 * 1024]),
            _ => panic!("stderr must retain its stream and bytes"),
        }
        // Fill the single buffered slot, then ensure another write is interrupted.
        std::thread::sleep(Duration::from_millis(30));
        assert!(matches!(
            done_receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        closer.close();
        assert_eq!(
            done_receiver.recv_timeout(Duration::from_secs(2)).unwrap(),
            Err(io::ErrorKind::BrokenPipe)
        );
        writer.join().unwrap();
        // Closing does not discard already accepted output.
        match receiver.recv_timeout(Duration::from_secs(2)).unwrap() {
            Event::Stderr(data) => assert_eq!(data, vec![0xff; 64 * 1024]),
            _ => panic!("buffered bytes must remain readable"),
        }
    }

    #[test]
    fn streaming_cancel_returns_unknown_when_no_terminal_event_arrives() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let execution = StreamingExecution(Arc::new(StreamingExecutionInner {
            control: Arc::new(FakeControl::new(false, ExecOutcome::Cancelled)),
            receiver: Mutex::new(Some(receiver)),
            closed: Arc::new(AtomicBool::new(false)),
            cancellation: Mutex::new(None),
        }));
        execution.cancel().unwrap();
        let error = execution.next(None, |_| ()).unwrap_err();
        assert_eq!(error.message, UNKNOWN_OUTCOME);
        execution.release().unwrap();
        drop(sender);
    }

    #[test]
    fn streaming_observer_delivers_binary_streams_before_the_exit_result() {
        let control = Arc::new(FakeControl::new(false, ExecOutcome::Exited(42)));
        let (sender, receiver) = mpsc::sync_channel(1);
        let closed = Arc::new(AtomicBool::new(false));
        let mut stdout = EventSink {
            sender: sender.clone(),
            closed: closed.clone(),
            stderr: false,
        };
        let mut stderr = EventSink {
            sender: sender.clone(),
            closed: closed.clone(),
            stderr: true,
        };
        let execution =
            StreamingExecution::observe(control.clone(), sender, receiver, closed).unwrap();
        let writer = std::thread::spawn(move || {
            let result = stdout
                .write(&vec![0xff; 128 * 1024])
                .and_then(|()| stderr.write(&vec![0x80; 128 * 1024]));
            *control.state.lock().unwrap() = true;
            control.wake.notify_all();
            result
        });
        let mut output = Vec::new();
        let mut error = Vec::new();
        loop {
            match execution
                .next(Some(5000), |event| event)
                .unwrap()
                .expect("stream progress")
            {
                Event::Stdout(bytes) => output.extend(bytes),
                Event::Stderr(bytes) => error.extend(bytes),
                Event::Exit(result) => {
                    assert_eq!(result.unwrap(), ExecOutcome::Exited(42));
                    break;
                }
            }
        }
        writer.join().unwrap().unwrap();
        assert_eq!(output, vec![0xff; 128 * 1024]);
        assert_eq!(error, vec![0x80; 128 * 1024]);
        execution.release().unwrap();
    }

    #[test]
    fn agent_setup_selects_host_cpu_profile_and_platform_snapshots_fit_its_defaults() {
        let bundle = BundledAgent::from_dir(r"C:\bundle").unwrap();
        let setup = agent_setup(&bundle, Path::new(r"C:\state"));
        assert_eq!(setup.cpu_profile, CpuProfile::Host);
        let json = serde_json::to_value(&setup).unwrap();
        assert_eq!(json["cpuProfile"], "host");
        assert!(json.get("platformSnapshots").is_none(), "{json}");

        let setup = setup.with_platform_snapshots(platform_snapshots());
        assert_eq!(
            serde_json::to_value(&setup).unwrap()["platformSnapshots"],
            serde_json::json!({"enabled": true, "maxVcpus": 1, "maxMemoryMib": 256})
        );
        // The templates must fit the sandboxes that keep the agent's default resources.
        setup.validate().unwrap();
        let defaults = setup.defaults.resources;
        assert_eq!(defaults.vcpus, Some(PLATFORM_SNAPSHOT_MAX_VCPUS));
        assert_eq!(defaults.memory_mib, Some(PLATFORM_SNAPSHOT_MAX_MEMORY_MIB));
    }

    #[test]
    fn state_root_is_keyed_by_bundle_owned_by_the_user_and_reused() {
        let local_app_data = tempfile::tempdir().unwrap();
        let root = state_root_in(local_app_data.path(), [0xab; 32]).unwrap();
        assert_eq!(
            root.path(),
            local_app_data
                .path()
                .join(r"Microsoft\MXC\nvx\abababababababab")
        );
        assert!(
            crate::mxc_common::filesystem_security::owner_is_current_user(root.path()).unwrap()
        );
        std::fs::write(root.path().join("registered-image"), b"cached").unwrap();
        let reused = state_root_in(local_app_data.path(), [0xab; 32]).unwrap();
        assert_eq!(reused.path(), root.path());
        assert_eq!(
            std::fs::read(reused.path().join("registered-image")).unwrap(),
            b"cached"
        );
        let other_bundle = state_root_in(local_app_data.path(), [0xcd; 32]).unwrap();
        assert_ne!(other_bundle.path(), root.path());
        assert!(!other_bundle.path().join("registered-image").exists());
    }

    struct FakeControl {
        state: Mutex<bool>,
        wake: Condvar,
        outcome: ExecOutcome,
    }

    impl FakeControl {
        fn new(complete: bool, outcome: ExecOutcome) -> Self {
            Self {
                state: Mutex::new(complete),
                wake: Condvar::new(),
                outcome,
            }
        }
    }

    impl ExecControl for FakeControl {
        fn wait(&self) -> aci_edge_sandboxes::Result<ExecOutcome> {
            let mut ready = self.state.lock().unwrap();
            while !*ready {
                ready = self.wake.wait(ready).unwrap();
            }
            Ok(self.outcome)
        }
        fn cancel(&self) -> aci_edge_sandboxes::Result<()> {
            *self.state.lock().unwrap() = true;
            self.wake.notify_all();
            Ok(())
        }
    }

    #[test]
    fn capture_enforces_one_combined_binary_limit() {
        for (stderr, overflow) in [(b"xy".as_slice(), false), (b"xyz".as_slice(), true)] {
            let capture = Arc::new(Mutex::new(Captured::default()));
            let mut stdout = CaptureSink {
                shared: capture.clone(),
                stderr: false,
                limit: 5,
            };
            let mut error = CaptureSink {
                shared: capture.clone(),
                stderr: true,
                limit: 5,
            };
            stdout.write(&[0xff, 0, 0x80]).unwrap();
            assert_eq!(error.write(stderr).is_err(), overflow);
            let control = Arc::new(FakeControl::new(!overflow, ExecOutcome::Exited(7)));
            let result = collect_execution(control, capture, None, None, 5);
            if overflow {
                assert!(result.unwrap_err().message.contains("capture limit of 5"));
            } else {
                let output = result.unwrap();
                assert_eq!(output.outcome, ExecOutcome::Exited(7));
                assert_eq!(output.stdout, [0xff, 0, 0x80]);
                assert_eq!(output.stderr, stderr);
            }
        }
    }

    #[test]
    fn unbounded_output_without_a_deadline_hits_the_capture_limit() {
        let captured = Arc::new(Mutex::new(Captured::default()));
        let mut sink = CaptureSink {
            shared: captured.clone(),
            stderr: false,
            limit: 16,
        };
        let writer = std::thread::spawn(move || while sink.write(&[0xff]).is_ok() {});
        let control = Arc::new(FakeControl::new(false, ExecOutcome::Cancelled));
        let error = collect_execution(control.clone(), captured, None, None, 16).unwrap_err();
        writer.join().unwrap();
        assert!(error.message.contains("capture limit of 16"));
        assert!(*control.state.lock().unwrap());
    }

    #[test]
    fn cancellation_and_host_deadline_wait_for_terminal_outcome() {
        let cancelled = RunCancellation::default();
        cancelled.request();
        let control = Arc::new(FakeControl::new(false, ExecOutcome::Cancelled));
        let error = collect_execution(
            control.clone(),
            Arc::new(Mutex::new(Captured::default())),
            None,
            Some(&cancelled),
            5,
        )
        .unwrap_err();
        assert_eq!(error.message, "execution cancelled");
        assert!(*control.state.lock().unwrap());

        let captured = Arc::new(Mutex::new(Captured {
            stdout: b"partial".to_vec(),
            ..Default::default()
        }));
        let control = Arc::new(FakeControl::new(false, ExecOutcome::Cancelled));
        let output =
            collect_execution(control.clone(), captured, Some(Instant::now()), None, 32).unwrap();
        assert_eq!(output.outcome, ExecOutcome::TimedOut);
        assert_eq!(output.stdout, b"partial");
        assert!(*control.state.lock().unwrap());
    }

    #[test]
    fn failed_cancel_waits_for_independent_observer_error() {
        struct FailedCancel {
            done: Mutex<bool>,
            wake: Condvar,
            cancelled: mpsc::Sender<()>,
        }
        impl ExecControl for FailedCancel {
            fn wait(&self) -> aci_edge_sandboxes::Result<ExecOutcome> {
                let mut done = self.done.lock().unwrap();
                while !*done {
                    done = self.wake.wait(done).unwrap();
                }
                Err(Error::new(
                    ErrorCode::BackendError,
                    "workload may still be running; stop or deprovision the sandbox",
                )
                .with_source("native cancellation failed"))
            }
            fn cancel(&self) -> aci_edge_sandboxes::Result<()> {
                self.cancelled.send(()).unwrap();
                Err(Error::new(ErrorCode::BackendError, "cancel failed"))
            }
        }
        let (sender, receiver) = mpsc::channel();
        let control = Arc::new(FailedCancel {
            done: Mutex::new(false),
            wake: Condvar::new(),
            cancelled: sender,
        });
        let observer_control = control.clone();
        let observer = std::thread::spawn(move || {
            let cancelled = receiver.recv_timeout(Duration::from_secs(5)).is_ok();
            std::thread::sleep(Duration::from_millis(100));
            *observer_control.done.lock().unwrap() = true;
            observer_control.wake.notify_all();
            cancelled
        });
        let cancelled = RunCancellation::default();
        cancelled.request();
        let error = collect_execution(
            control,
            Arc::new(Mutex::new(Captured::default())),
            None,
            Some(&cancelled),
            5,
        )
        .unwrap_err();
        assert!(observer.join().unwrap(), "cancellation was never requested");
        assert!(error.message.contains("execution cancelled"), "{error}");
        assert!(error.message.contains("cancel failed"), "{error}");
        assert!(
            error.message.contains("workload may still be running"),
            "{error}"
        );
        assert!(
            error.message.contains("native cancellation failed"),
            "{error}"
        );
    }

    #[test]
    fn cancellation_is_bounded_even_without_an_outcome_or_cancel_return() {
        use std::sync::atomic::{AtomicBool, Ordering};

        #[derive(Clone, Copy)]
        enum Cancel {
            Accept,
            Fail,
            Block,
            BlockWithOutcome,
        }
        struct StalledControl {
            release: Mutex<bool>,
            wake: Condvar,
            attempted: AtomicBool,
            cancel: Cancel,
        }
        impl StalledControl {
            fn wait_for_release(&self) {
                let mut release = self.release.lock().unwrap();
                while !*release {
                    release = self.wake.wait(release).unwrap();
                }
            }
        }
        impl ExecControl for StalledControl {
            fn wait(&self) -> aci_edge_sandboxes::Result<ExecOutcome> {
                if matches!(self.cancel, Cancel::BlockWithOutcome) {
                    let mut release = self.release.lock().unwrap();
                    while !self.attempted.load(Ordering::Acquire) {
                        release = self.wake.wait(release).unwrap();
                    }
                    return Ok(ExecOutcome::Exited(7));
                }
                self.wait_for_release();
                Ok(ExecOutcome::Cancelled)
            }
            fn cancel(&self) -> aci_edge_sandboxes::Result<()> {
                {
                    let _release = self.release.lock().unwrap();
                    self.attempted.store(true, Ordering::Release);
                    self.wake.notify_all();
                }
                match self.cancel {
                    Cancel::Accept => Ok(()),
                    Cancel::Fail => Err(Error::new(ErrorCode::BackendError, "cancel failed")),
                    Cancel::Block | Cancel::BlockWithOutcome => {
                        self.wait_for_release();
                        Ok(())
                    }
                }
            }
        }

        for cancel in [
            Cancel::Accept,
            Cancel::Fail,
            Cancel::Block,
            Cancel::BlockWithOutcome,
        ] {
            let control = Arc::new(StalledControl {
                release: Mutex::new(false),
                wake: Condvar::new(),
                attempted: AtomicBool::new(false),
                cancel,
            });
            let worker_control = control.clone();
            let (sender, receiver) = mpsc::channel();
            let caller = std::thread::spawn(move || {
                let cancellation = RunCancellation::default();
                if matches!(cancel, Cancel::Accept | Cancel::BlockWithOutcome) {
                    cancellation.request();
                }
                let captured = Captured {
                    overflow: matches!(cancel, Cancel::Block),
                    ..Default::default()
                };
                let result = collect_execution(
                    worker_control,
                    Arc::new(Mutex::new(captured)),
                    matches!(cancel, Cancel::Fail).then(Instant::now),
                    Some(&cancellation),
                    5,
                );
                let _ = sender.send(result);
            });
            let result = receiver.recv_timeout(Duration::from_secs(4));
            let attempted = control.attempted.load(Ordering::Acquire);
            // Release fake native calls even when the bounded-return assertion fails.
            *control.release.lock().unwrap() = true;
            control.wake.notify_all();
            caller.join().unwrap();
            assert!(attempted, "the cancellation path was not reached");
            let error = result
                .expect("cancellation must return before the independent watchdog")
                .unwrap_err();
            assert_eq!(error.code, MxcErrorCode::BackendError);
            if matches!(cancel, Cancel::BlockWithOutcome) {
                assert!(error.message.starts_with(CANCEL_UNFINISHED), "{error}");
                assert!(!error.message.contains("outcome is unknown"), "{error}");
            } else {
                assert!(error.message.starts_with(UNKNOWN_OUTCOME), "{error}");
            }
            let primary = match cancel {
                Cancel::Accept | Cancel::BlockWithOutcome => "execution cancelled",
                Cancel::Fail => "cancel failed",
                Cancel::Block => "capture limit of 5",
            };
            assert!(error.message.contains(primary), "{error}");
        }
    }

    #[test]
    fn release_failure_keeps_outcome_and_native_cause() {
        struct ReleaseFailure;
        impl ExecControl for ReleaseFailure {
            fn wait(&self) -> aci_edge_sandboxes::Result<ExecOutcome> {
                Err(Error::new(
                    ErrorCode::BackendError,
                    "execution exited but release failed",
                )
                .with_source("native release failure"))
            }
            fn cancel(&self) -> aci_edge_sandboxes::Result<()> {
                panic!("completed execution must not be cancelled")
            }
        }
        let error = collect_execution(
            Arc::new(ReleaseFailure),
            Arc::new(Mutex::new(Captured::default())),
            None,
            None,
            5,
        )
        .unwrap_err();
        assert_eq!(error.code, MxcErrorCode::BackendError);
        assert!(error
            .message
            .contains("execution exited but release failed"));
        assert!(error.message.contains("native release failure"));
    }

    #[test]
    fn cancellation_and_wait_errors_are_reported() {
        struct FailingControl {
            state: Mutex<bool>,
            wake: Condvar,
        }
        impl ExecControl for FailingControl {
            fn wait(&self) -> aci_edge_sandboxes::Result<ExecOutcome> {
                let mut ready = self.state.lock().unwrap();
                while !*ready {
                    ready = self.wake.wait(ready).unwrap();
                }
                Err(Error::new(ErrorCode::BackendError, "wait failed"))
            }
            fn cancel(&self) -> aci_edge_sandboxes::Result<()> {
                *self.state.lock().unwrap() = true;
                self.wake.notify_all();
                Err(Error::new(ErrorCode::BackendError, "cancel failed"))
            }
        }
        let cancelled = RunCancellation::default();
        cancelled.request();
        let control = Arc::new(FailingControl {
            state: Mutex::new(false),
            wake: Condvar::new(),
        });
        let error = collect_execution(
            control,
            Arc::new(Mutex::new(Captured::default())),
            None,
            Some(&cancelled),
            5,
        )
        .unwrap_err();
        assert_eq!(error.code, MxcErrorCode::BackendError);
        assert!(error.message.contains("execution cancelled"));
        assert!(error.message.contains("cancel failed"));
        assert!(error.message.contains("wait failed"));
    }

    #[test]
    fn maps_crate_errors_without_success_fallbacks() {
        for (native, expected) in [
            (ErrorCode::MalformedRequest, MxcErrorCode::MalformedRequest),
            (ErrorCode::PolicyValidation, MxcErrorCode::PolicyValidation),
            (
                ErrorCode::BackendUnavailable,
                MxcErrorCode::BackendUnavailable,
            ),
            (ErrorCode::Unsupported, MxcErrorCode::BackendError),
        ] {
            assert_eq!(map_error(Error::new(native, "detail")).code, expected);
        }
    }
}
