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
//! it; `exec` runs a fresh `WslcCreateContainerProcess` to completion; `stop` /
//! `deprovision` stop + delete. Live bidirectional stdio streaming over the
//! control pipe is still a later fill-in — `exec` currently returns the exit
//! code only.

use std::collections::HashMap;

use anyhow::Result;
use tokio::sync::{mpsc, oneshot};

use wslc_common::container_steps::{self, ProcessSettings};
use wslc_common::daemon_protocol::{
    DeprovisionConfig, ExecConfig, NetworkMode, ProvisionConfig, StartConfig, StopConfig,
};
use wslc_common::policy_mapping;
use wslc_common::wslc_bindings::{
    WslcContainerGuard, WslcContainerNetworkingMode, WslcSdk, WslcSessionGuard,
};
use wxc_common::logger::{Logger, Mode};
use wxc_common::models::ScriptResponse;

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

/// Map a step helper's `ScriptResponse` error into the daemon's `anyhow` error.
fn sr_err(resp: ScriptResponse) -> anyhow::Error {
    anyhow::anyhow!(resp.error_message)
}

/// A unit of work dispatched from an async pipe handler to the WSLc worker
/// thread. Each variant carries a `oneshot` reply channel the worker fulfils.
pub enum WorkerCommand {
    Provision {
        config: ProvisionConfig,
        reply: oneshot::Sender<Result<String>>,
    },
    Start {
        config: StartConfig,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Run a command to completion, returning its exit code. Live stdio
    /// streaming is layered on in the fill-in phase; for now this is
    /// request/response only.
    Exec {
        config: ExecConfig,
        reply: oneshot::Sender<Result<i32>>,
    },
    Stop {
        config: StopConfig,
        reply: oneshot::Sender<Result<()>>,
    },
    Deprovision {
        config: DeprovisionConfig,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Report the current live-container count (drives the idle watchdog).
    ContainerCount { reply: oneshot::Sender<usize> },
    /// Release all containers + the session and stop the worker thread.
    Shutdown { reply: oneshot::Sender<()> },
}

/// A cheap, clonable handle async tasks use to drive the worker thread.
#[derive(Clone)]
pub struct SessionHandle {
    tx: mpsc::UnboundedSender<WorkerCommand>,
}

impl SessionHandle {
    /// Provision a container, returning its minted `sandbox_id`.
    pub async fn provision(&self, config: ProvisionConfig) -> Result<String> {
        let (reply, rx) = oneshot::channel();
        self.send(WorkerCommand::Provision { config, reply })?;
        rx.await.map_err(worker_gone)?
    }

    /// Start a provisioned container.
    pub async fn start(&self, config: StartConfig) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        self.send(WorkerCommand::Start { config, reply })?;
        rx.await.map_err(worker_gone)?
    }

    /// Run a command in a started container to completion.
    pub async fn exec(&self, config: ExecConfig) -> Result<i32> {
        let (reply, rx) = oneshot::channel();
        self.send(WorkerCommand::Exec { config, reply })?;
        rx.await.map_err(worker_gone)?
    }

    /// Stop a running container.
    pub async fn stop(&self, config: StopConfig) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        self.send(WorkerCommand::Stop { config, reply })?;
        rx.await.map_err(worker_gone)?
    }

    /// Deprovision (delete) a container.
    pub async fn deprovision(&self, config: DeprovisionConfig) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        self.send(WorkerCommand::Deprovision { config, reply })?;
        rx.await.map_err(worker_gone)?
    }

    /// Current number of live containers (0 means the daemon is idle).
    pub async fn container_count(&self) -> Result<usize> {
        let (reply, rx) = oneshot::channel();
        self.send(WorkerCommand::ContainerCount { reply })?;
        rx.await.map_err(worker_gone)
    }

    /// Ask the worker to release everything and stop. Awaits confirmation.
    pub async fn shutdown(&self) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        self.send(WorkerCommand::Shutdown { reply })?;
        rx.await.map_err(worker_gone)
    }

    fn send(&self, cmd: WorkerCommand) -> Result<()> {
        self.tx
            .send(cmd)
            .map_err(|_| anyhow::anyhow!("WSLc worker thread is gone"))
    }
}

fn worker_gone(_e: oneshot::error::RecvError) -> anyhow::Error {
    anyhow::anyhow!("WSLc worker dropped the reply channel")
}

/// Per-container bookkeeping held by the worker: whether the container is
/// currently started and the live `WslcContainer` handle (kept alive across
/// phases so repeated `exec`s hit a warm container). The sandbox id is the
/// map key.
struct ContainerEntry {
    started: bool,
    container: WslcContainerGuard,
}

/// The single-threaded WSLc session owner. Constructed and run entirely on the
/// worker thread. Holds the lazily-loaded SDK and the one shared session (the
/// WSL2 utility VM), plus the `sandbox_id -> container` map. The SDK/session/
/// guard handles are `!Send` raw pointers, but they never leave this thread —
/// only [`WorkerCommand`]s cross the channel.
struct Worker {
    logger: Logger,
    sdk: Option<WslcSdk>,
    session: Option<WslcSessionGuard>,
    containers: HashMap<String, ContainerEntry>,
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
    fn ensure_session(&mut self) -> Result<()> {
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

    fn provision(&mut self, config: ProvisionConfig) -> Result<String> {
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
                container,
            },
        );
        Ok(sandbox_id)
    }

    fn start(&mut self, config: StartConfig) -> Result<()> {
        // Existence check first, so an unknown sandbox errors without needing the
        // SDK (keeps the no-WSL unit tests self-contained).
        if !self.containers.contains_key(&config.sandbox_id) {
            anyhow::bail!("unknown sandbox {}", config.sandbox_id);
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
            container_steps::start_daemon_container(sdk, entry.container.as_raw(), &mut self.logger)
        }
        .map_err(sr_err)?;
        entry.started = true;
        Ok(())
    }

    fn exec(&mut self, config: ExecConfig) -> Result<i32> {
        let (container, started) = match self.containers.get(&config.sandbox_id) {
            Some(e) => (e.container.as_raw(), e.started),
            None => anyhow::bail!("unknown sandbox {}", config.sandbox_id),
        };
        if !started {
            anyhow::bail!("sandbox {} is not started", config.sandbox_id);
        }
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
                &mut self.logger,
            )
        }
        .map_err(sr_err)?;

        if outcome.timed_out {
            anyhow::bail!("exec timed out after {}ms", config.timeout_ms);
        }
        // NOTE: outcome.stdout/stderr are captured but not yet forwarded — live
        // stdio streaming over the control pipe is a later fill-in; the PR1
        // contract returns the exit code only.
        Ok(outcome.exit_code)
    }

    fn stop(&mut self, config: StopConfig) -> Result<()> {
        if !self.containers.contains_key(&config.sandbox_id) {
            anyhow::bail!("unknown sandbox {}", config.sandbox_id);
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

    fn deprovision(&mut self, config: DeprovisionConfig) -> Result<()> {
        let entry = self
            .containers
            .remove(&config.sandbox_id)
            .ok_or_else(|| anyhow::anyhow!("unknown sandbox {}", config.sandbox_id))?;

        let result = if let Some(sdk) = self.sdk.as_ref() {
            // SAFETY: `sdk` is valid and `entry.container` is a live handle.
            unsafe {
                container_steps::delete_daemon_container(
                    sdk,
                    entry.container.as_raw(),
                    &mut self.logger,
                )
            }
            .map_err(sr_err)
        } else {
            Ok(())
        };

        // Release the container handle regardless of delete success. Must happen
        // before the SDK/session are torn down below (their DLL must stay loaded).
        drop(entry);

        // Release the shared session (and unload the SDK) once idle. Ordering is
        // load-bearing: the session guard's Drop uses SDK fn pointers, so it must
        // drop before the SDK unloads the DLL.
        if self.containers.is_empty() {
            self.session = None;
            self.sdk = None;
        }
        result
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

    std::thread::Builder::new()
        .name("wslc-session-worker".to_string())
        .spawn(move || {
            #[cfg(windows)]
            let _com = ComApartment::enter();

            let mut worker = Worker::new();
            while let Some(cmd) = rx.blocking_recv() {
                match cmd {
                    WorkerCommand::Provision { config, reply } => {
                        let _ = reply.send(worker.provision(config));
                    }
                    WorkerCommand::Start { config, reply } => {
                        let _ = reply.send(worker.start(config));
                    }
                    WorkerCommand::Exec { config, reply } => {
                        let _ = reply.send(worker.exec(config));
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

    Ok(SessionHandle { tx })
}

/// RAII guard that keeps the calling thread in the COM MTA for the WSLc SDK.
#[cfg(windows)]
struct ComApartment;

#[cfg(windows)]
impl ComApartment {
    fn enter() -> Self {
        use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};
        // SAFETY: called once at worker-thread startup; balanced by CoUninitialize
        // in Drop. A non-success HRESULT (e.g. already-initialised) is benign here.
        unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        }
        Self
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

    // ---- Full lifecycle integration test (WSL2 host only) ----
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

        let code = handle
            .exec(ExecConfig {
                sandbox_id: id.clone(),
                script_code: "echo hi".to_string(),
                working_directory: String::new(),
                env: Vec::new(),
                timeout_ms: 30_000,
            })
            .await
            .unwrap();
        assert_eq!(code, 0);

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
}
