// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `mxc-sdk`: an importable library for running MXC containers in-process.
//!
//! See the [consumer glossary](https://github.com/microsoft/mxc/blob/main/docs/glossary.md)
//! for terminology.
//!
//! Create a [`v1::ContainerRequest`] with its command and restrictions, then either:
//!
//! - hand it to [`v1::run`] to run the contained process **to completion** and get
//!   its captured stdout/stderr and exit outcome in one call, or
//! - hand it to [`v1::spawn`] for a live [`v1::MxcProcess`] handle you can
//!   stream stdio through, feed stdin, and kill while it runs.
//! - hand it to [`v1::spawn_with_pty`] for an [`v1::MxcPtyProcess`] with
//!   merged terminal output and resize support.
//!
//! Either way the right containment backend is selected for the host and the
//! ordinary `run` and `spawn` paths allocate no PTY.
//!
//! ```no_run
//! use mxc_sdk::v1::{self, WaitResult};
//!
//! let request = v1::ContainerRequest::new("echo hi");
//! let output = v1::run(request, Default::default())?;
//! match output.outcome {
//!     WaitResult::Exited(code) => println!("exit={code}"),
//!     WaitResult::TimedOut => println!("timed out"),
//! }
//! println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Backend support
//!
//! The selected backend is driven by the request's [`v1::Containment`].
//! Requests default to the host's native process backend.
//!
//! | Backend | Host | Selected by |
//! |---------|------|-------------|
//! | Bubblewrap | Linux | [`v1::Containment::Process`] or [`v1::Containment::Bubblewrap`] |
//! | LXC | Linux | [`v1::Containment::Lxc`] |
//! | Seatbelt | macOS | [`v1::Containment::Process`] or [`v1::Containment::Seatbelt`] |
//! | ProcessContainer (PSEC) | Windows | [`v1::Containment::Process`] |
//! | Explicit ProcessContainer configuration | Windows | [`v1::Containment::ProcessContainer`] |
//! | WSLC (WSL Container) | Windows | [`v1::Containment::Wslc`] |
//! | IsolationSession | Windows | [`v1::Containment::IsolationSession`] |
//!
//! LXC is reachable only by naming it: [`v1::Containment::Process`] resolves to
//! Bubblewrap on Linux. It needs root. Ordinary streaming uses pipes, while
//! [`v1::spawn_with_pty`] allocates a caller-controlled terminal.
//!
//! WSLC requires the crate's `wslc` build feature, and IsolationSession
//! requires the `isolation_session` build feature. A WSLC process reads
//! end-of-file on stdin, and [`MxcProcess::take_stdin`] returns `None` for it,
//! unless it was started by [`v1::spawn_with_stdin`] or
//! [`v1::container::spawn_in_container_with_stdin`].
//! IsolationSession is also available through the typed lifecycle API.
//!
//! The `wslc` feature stages `wslcsdk.dll` into the cargo profile directory,
//! and WSLC loads it from beside the module holding this code, so an executable
//! copied or installed out of that directory needs the DLL brought along. The
//! crate README covers that and the separate `wxc-wslc-daemon.exe` that the
//! container lifecycle needs.
//!
//! A concrete backend selected on another host returns an [`Error`] with
//! [`ErrorCode::UnsupportedContainment`].
//!
//! # Diagnosing a failure
//!
//! [`Error`] carries an [`ErrorCode`] and a message. When an underlying platform
//! API fails, it also identifies the call and its status:
//!
//! ```no_run
//! # fn demo(error: mxc_sdk::v1::Error) {
//! if let Some(operation) = &error.operation {
//!     eprintln!("{operation} failed with {:?}", error.native_code);
//! }
//! if let Some(hint) = &error.remediation {
//!     eprintln!("  try: {hint}");
//! }
//! # }
//! ```
//!
//! [`Error::operation`] and [`Error::native_code`] are absent for a failure
//! raised before any API call was reached (a malformed policy, say) and a
//! native code only ever appears alongside the operation it belongs to.
//! `Display` renders both, so logging the error alone does not lose them.
//!
//! ```no_run
//! use mxc_sdk::v1;
//!
//! // Run a command inside a WSL container (Windows, --features wslc).
//! let wslc = v1::configs::WslcConfig { image: "python:3.12".to_string(), ..Default::default() };
//! let request = v1::ContainerRequest {
//!     containment: v1::Containment::Wslc(wslc),
//!     ..v1::ContainerRequest::new("python3 -c 'print(42)'")
//! };
//! let output = v1::run(request, Default::default())?;
//! # Ok::<(), mxc_sdk::v1::Error>(())
//! ```
//!
//! ## Choosing an entry point
//!
//! |             | container request | existing container | Stdio |
//! |-------------|-------------------|--------------------|-------|
//! | **capture** | [`v1::run`] | [`v1::container::run_in_container`] | captured stdout and stderr |
//! | **handle**  | [`v1::spawn`] | [`v1::container::spawn_in_container`] | separate live pipes |
//! | **PTY**     | [`v1::spawn_with_pty`] | [`v1::container::spawn_in_container_with_pty`] | merged output, resize |
//!
//! [`v1::container::provision_container`], [`v1::container::start_container`],
//! [`v1::container::stop_container`], and
//! [`v1::container::deprovision_container`] drive the lifecycle with typed Rust
//! requests. All SDK execution APIs take typed requests.
//!
//! ## Standard streams
//!
//! The V1 `run` and `spawn` APIs use ordinary pipes; PTY allocation is explicit
//! through [`v1::spawn_with_pty`] and
//! [`v1::container::spawn_in_container_with_pty`]. [`v1::run`] captures both output streams. With
//! [`v1::spawn`] or [`v1::container::spawn_in_container`], callers
//! can take the streams from [`MxcProcess`] or let `wait` drain and discard any
//! stream they did not take. WSLC exposes stdin only for
//! [`v1::spawn_with_stdin`] and [`v1::container::spawn_in_container_with_stdin`].
//!
//! [`v1::spawn_with_pty`] allocates a caller-controlled PTY for create-and-run
//! execution on supported backends, including IsolationSession, Bubblewrap, LXC,
//! and Seatbelt direct execution.
//! [`v1::container::spawn_in_container_with_pty`] does the same for a process in
//! an existing IsolationSession container. Unsupported backends reject the
//! request before creating a sandbox.
//!
//! Policy and operational warnings are available through [`MxcProcess::warnings`]
//! and [`ExecutionResult::warnings`]. These include security warnings, network rules
//! that cannot carry traffic, and operational warnings such as unavailable
//! telemetry routing.
//!
//! ## Internal module boundaries
//!
//! This crate root is the curated public facade. Backend dispatch, host
//! probing, execution, and backend implementations are doc-hidden compatibility
//! exports for workspace consumers rather than supported SDK entry points.

#[path = "backends/mod.rs"]
mod backend_modules;
#[path = "core/mod.rs"]
mod core_modules;

#[doc(hidden)]
pub use backend_modules::bubblewrap::common as bwrap_common;
#[doc(hidden)]
#[cfg(all(feature = "hyperlight", target_arch = "x86_64"))]
pub use backend_modules::hyperlight::common as hyperlight_common;
#[doc(hidden)]
#[cfg(all(target_os = "windows", feature = "isolation_session"))]
pub use backend_modules::isolation_session::bindings as isolation_session_bindings;
#[doc(hidden)]
#[cfg(all(target_os = "windows", feature = "isolation_session"))]
pub use backend_modules::isolation_session::common as isolation_session_common;
#[doc(hidden)]
pub use backend_modules::lxc::common as lxc_common;
#[doc(hidden)]
#[cfg(all(target_os = "windows", target_arch = "x86_64", feature = "microvm"))]
pub use backend_modules::nvx::runner as nvx_runner;
#[doc(hidden)]
#[cfg(target_os = "windows")]
pub use backend_modules::process_container::common as process_container_common;
#[doc(hidden)]
pub use backend_modules::seatbelt::common as seatbelt_common;
#[doc(hidden)]
#[cfg(target_os = "windows")]
pub use backend_modules::windows_sandbox::common as windows_sandbox_common;
#[doc(hidden)]
#[cfg(target_os = "windows")]
pub use backend_modules::windows_sandbox::lifecycle as windows_sandbox_lifecycle;
#[doc(hidden)]
#[cfg(all(target_os = "windows", feature = "wslc"))]
pub use backend_modules::wslc::common as wslc_common;
#[doc(hidden)]
pub use core_modules::learning_mode_core;
#[doc(hidden)]
pub use core_modules::learning_mode_windows;
#[doc(hidden)]
pub use core_modules::mxc_common;
#[doc(hidden)]
pub use core_modules::mxc_contract;
#[doc(hidden)]
pub use core_modules::mxc_engine;
#[doc(hidden)]
pub use core_modules::mxc_pty;
#[doc(hidden)]
pub use core_modules::mxc_schema_support;
#[doc(hidden)]
pub use core_modules::mxc_telemetry;
#[doc(hidden)]
pub use core_modules::process_security_environment_spec;

mod configs;
mod dev;
mod options;
mod policy;
mod sandbox;
mod state_aware_sdk;

mod telemetry;

#[cfg(doctest)]
mod api_tests;

#[cfg(target_os = "windows")]
use crate::mxc_engine::ProbeOutput;
use crate::mxc_engine::{Error, ErrorCode};

use sandbox::{ExecutionResult, MxcProcess};

/// V1 contract-mapped request and typed lifecycle APIs.
///
/// These types and entry points target the latest published V1 contract
/// owned by this SDK. Callers supply typed requests rather than JSON or a
/// schema version.
///
pub mod v1 {
    /// Caller-authored exact-JSON execution and lifecycle operations.
    pub mod dev {
        pub use crate::dev::*;
    }

    pub use crate::mxc_engine::{
        available_backends, platform_support, AvailableBackend, BackendCapability,
        BubblewrapNetworkSupport, Error, ErrorCode, PlatformSupport, ProxyEnforcement,
    };
    #[cfg(target_os = "windows")]
    pub use crate::mxc_engine::{ProbeFacts, ProbeOutput, UiCapabilitySupport};
    pub use crate::options::{
        DeprovisionOptions, ProvisionOptions, RunInContainerOptions, RunOptions,
        SpawnInContainerOptions, SpawnInContainerWithPtyOptions, SpawnOptions, SpawnWithPtyOptions,
        StartOptions, StopOptions, TelemetryConfig,
    };

    /// V1 telemetry consent administration.
    pub mod telemetry {
        pub use crate::telemetry::*;
    }

    /// Backend-specific V1 configuration sections.
    pub mod configs {
        pub use crate::configs::{
            CaptureDenials, CaptureDenialsMode, LxcConfig, ProcessContainerConfig,
            ProcessContainerFilesystem, ProcessContainerNetwork, ProcessContainerSystemSettings,
            ProcessContainerUi, ProcessContainerUiIsolation, SeatbeltConfig, WslcConfig,
        };
    }

    /// V1 policy authoring types.
    pub mod policy {
        /// Host filesystem-policy discovery helpers and their options.
        pub mod filesystem {
            pub use crate::policy::{
                available_tools_policy, temporary_files_policy, user_profile_policy,
                FilesystemPolicyResult, ToolsPolicyContainerType, ToolsPolicyOptions,
            };
        }

        pub use crate::policy::{
            ClipboardPolicy, Containment, FilesystemPolicy, NetworkAction, NetworkEgressPolicy,
            NetworkIngressPolicy, NetworkPeerPolicy, NetworkPolicy, NetworkPortPolicy,
            NetworkProtocol, NetworkRulePolicy, NetworkRuntimeConfig, UiPolicy,
        };
    }

    /// V1 typed lifecycle entry points.
    pub mod container {
        use super::{
            ContainerId, Error, ExecutionRequest, ExecutionResult, RunInContainerOptions,
            SpawnInContainerOptions,
        };

        pub use crate::sandbox::{
            deprovision as deprovision_container, provision as provision_container,
            spawn_in_container, spawn_in_container_with_pty, spawn_in_container_with_stdin,
            start as start_container, stop as stop_container, validate_deprovision,
            validate_process, validate_provision, validate_start, validate_stop,
        };

        /// Run a workload in an existing container to completion and capture output.
        pub fn run_in_container(
            container_id: &ContainerId,
            request: ExecutionRequest,
            options: RunInContainerOptions,
        ) -> Result<ExecutionResult, Error> {
            crate::wait_with_output(spawn_in_container(
                container_id,
                request,
                SpawnInContainerOptions {
                    telemetry: options.telemetry,
                },
            )?)
        }
    }

    pub use crate::policy::{
        ClipboardPolicy, ContainerRequest, Containment, FilesystemPolicy, NetworkAction,
        NetworkEgressPolicy, NetworkIngressPolicy, NetworkPeerPolicy, NetworkPolicy,
        NetworkPortPolicy, NetworkProtocol, NetworkRulePolicy, NetworkRuntimeConfig, UiPolicy,
    };
    pub use crate::sandbox::{
        CaptureDenialsError, CaptureDenialsResult, ExecutionMetadata, ExecutionResult, MxcProcess,
        MxcPtyProcess, MxcPtySize, StreamCloser, WaitResult,
    };
    pub use crate::state_aware_sdk::{
        ContainerId, ExecutionRequest, IsolationSessionProvisionMetadata, LifecycleResult,
        ProcessNetworkPolicy, ProvisionMetadata, ProvisionRequest, ProvisionResult,
        ValidationResult,
    };

    /// Probe an optional ProcessContainer request without creating a container.
    ///
    /// Other containments use backend availability discovery and their normal
    /// launch-time validation because this result describes ProcessContainer tiers.
    #[cfg(target_os = "windows")]
    pub fn probe(request: Option<&ContainerRequest>) -> Result<crate::ProbeOutput, Error> {
        let prepared = request.map(crate::policy::prepare_request).transpose()?;
        crate::mxc_engine::probe_execution_request(prepared.as_ref().map(|request| &request.inner))
    }

    /// Spawn a [`ContainerRequest`] and return its live process.
    ///
    /// Returns a [`MxcProcess`] handle for live bidirectional stdio and termination;
    /// no pty is allocated. Any stdout/stderr stream the caller does not
    /// `take_*` is drained and discarded by [`wait`](MxcProcess::wait).
    ///
    /// A WSLC process started this way reads end-of-file on stdin; use
    /// [`spawn_with_stdin`] to give it input.
    pub fn spawn(request: ContainerRequest, options: SpawnOptions) -> Result<MxcProcess, Error> {
        let prepared = crate::policy::prepare_creation_request(&request, options.telemetry)?;
        crate::mxc_engine::spawn_execution_request(&prepared.inner, false).map(MxcProcess::new)
    }

    /// Spawn a [`ContainerRequest`] with a writable stdin, which
    /// [`MxcProcess::take_stdin`] returns.
    pub fn spawn_with_stdin(
        request: ContainerRequest,
        options: SpawnOptions,
    ) -> Result<MxcProcess, Error> {
        let prepared = crate::policy::prepare_creation_request(&request, options.telemetry)?;
        crate::mxc_engine::spawn_execution_request(&prepared.inner, true).map(MxcProcess::new)
    }

    /// Spawn a [`ContainerRequest`] attached to a caller-controlled PTY.
    pub fn spawn_with_pty(
        request: ContainerRequest,
        options: SpawnWithPtyOptions,
    ) -> Result<MxcPtyProcess, Error> {
        options.size.validate()?;
        let prepared = crate::policy::prepare_creation_request(&request, options.telemetry)?;
        crate::mxc_engine::spawn_with_pty(&prepared.inner, options.size.into())
            .and_then(MxcPtyProcess::new)
    }

    /// Run a [`ContainerRequest`] to completion and capture its output.
    ///
    /// Both streams are drained concurrently, so an output-heavy child cannot
    /// deadlock. No pty is allocated.
    ///
    /// Use [`spawn`] instead when you need to stream stdio, feed stdin, or kill
    /// the process while it runs.
    ///
    /// `Err` is returned when the backend can't be selected/spawned (an
    /// [`Error`]), or when waiting on the child fails at the OS level.
    pub fn run(request: ContainerRequest, options: RunOptions) -> Result<ExecutionResult, Error> {
        crate::wait_with_output(spawn(
            request,
            SpawnOptions {
                telemetry: options.telemetry,
            },
        )?)
    }

    #[cfg(all(test, target_os = "windows"))]
    mod tests {
        use super::*;

        #[test]
        fn public_creation_uses_required_telemetry_without_opt_in() {
            use crate::mxc_common::telemetry::{self, events::test_sink};

            let store = tempfile::tempdir().unwrap();
            let env = telemetry::test_support::TelemetryTestEnv::new(store.path());
            env.set_policy_value(0);
            telemetry::consent::set_consent(false, "test").unwrap();
            let _lock = test_sink::TEST_LOCK
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            test_sink::install();

            for enabled in [None, Some(false)] {
                let request = ContainerRequest {
                    containment: Containment::Bubblewrap,
                    ..ContainerRequest::new("true")
                };
                let error = run(
                    request,
                    RunOptions {
                        telemetry: enabled.map(|enabled| TelemetryConfig {
                            enabled: Some(enabled),
                        }),
                    },
                )
                .unwrap_err();
                assert_eq!(error.code, ErrorCode::UnsupportedContainment);

                let expected = usize::from(crate::mxc_telemetry::REQUIRED_COLLECTION_ELIGIBLE);
                let starts = test_sink::take_starts();
                let ends = test_sink::take_executions();
                let errors = test_sink::take_errors();
                assert_eq!(starts.len(), expected, "enabled={enabled:?}");
                assert_eq!(ends.len(), expected, "enabled={enabled:?}");
                assert_eq!(errors.len(), expected, "enabled={enabled:?}");
                if let Some(start) = starts.first() {
                    assert_eq!(start.session_id, ends[0].session_id);
                    assert_eq!(start.session_id, errors[0].session_id);
                    assert_eq!(start.backend, "bubblewrap");
                    assert_eq!(ends[0].outcome, "failure");
                }
                assert!(test_sink::take_requirements().is_empty());
                assert!(test_sink::take_verbose().is_empty());
            }
            test_sink::clear();
        }

        #[test]
        fn json_and_public_creation_preserve_process_attribution_without_telemetry() {
            use crate::mxc_common::telemetry::{self, events::test_sink};

            let store = tempfile::tempdir().unwrap();
            let env = telemetry::test_support::TelemetryTestEnv::new(store.path());
            env.set_policy_value(0);
            telemetry::consent::set_consent(false, "test").unwrap();
            let _lock = test_sink::TEST_LOCK
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            test_sink::install();

            for typed in [false, true] {
                for enabled in [None, Some(false)] {
                    let succeeded = if typed {
                        run(
                            ContainerRequest {
                                containment: Containment::Process,
                                ..ContainerRequest::new("cmd /c exit 0")
                            },
                            RunOptions {
                                telemetry: enabled.map(|enabled| TelemetryConfig {
                                    enabled: Some(enabled),
                                }),
                            },
                        )
                        .is_ok()
                    } else {
                        let mut request = serde_json::json!({
                            "version": "1.0.0",
                            "containment": "process",
                            "process": { "commandLine": "cmd /c exit 0" }
                        });
                        if let Some(enabled) = enabled {
                            request["telemetry"] = serde_json::json!({ "enabled": enabled });
                        }
                        crate::__ffi::run_json(&request.to_string(), false).is_ok()
                    };
                    let expected = usize::from(crate::mxc_telemetry::REQUIRED_COLLECTION_ELIGIBLE);
                    let starts = test_sink::take_starts();
                    let ends = test_sink::take_executions();
                    assert_eq!(starts.len(), expected, "typed={typed}, enabled={enabled:?}");
                    assert_eq!(ends.len(), expected, "typed={typed}, enabled={enabled:?}");
                    if let Some(start) = starts.first() {
                        assert_eq!(start.sandbox_kind, "process");
                        assert_eq!(ends[0].sandbox_kind, "process");
                        assert_eq!(start.backend, "processcontainer");
                        assert_eq!(
                            ends[0].outcome,
                            if succeeded { "success" } else { "failure" }
                        );
                    }
                    test_sink::take_errors();
                    test_sink::take_requirements();
                }
            }
            test_sink::clear();
        }

        #[test]
        fn public_request_probe_uses_sdk_request_model() {
            let request = ContainerRequest::new("cmd /c exit 0");
            let output = probe(Some(&request)).expect("default request probes");
            assert!(output.error.is_some() || output.tier.is_some());
        }
    }
}

mod lifecycle_thread_context {
    /// Context carried onto the C ABI lifecycle worker.
    #[doc(hidden)]
    pub struct LifecycleThreadContext {
        #[cfg(target_os = "windows")]
        token: Option<crate::mxc_common::process_util::SendOwnedHandle>,
        telemetry: crate::mxc_common::telemetry::session::SessionContext,
        sink: Option<crate::mxc_common::logger::Logger>,
    }

    impl LifecycleThreadContext {
        /// Capture the caller's security and diagnostic context before spawning.
        pub fn capture() -> Result<Self, String> {
            #[cfg(target_os = "windows")]
            let token =
                crate::mxc_common::process_util::duplicate_thread_token().map_err(|error| {
                    format!("could not preserve the calling thread's impersonation: {error}")
                })?;
            let sink = crate::mxc_common::logger::Logger::inherit_thread_diagnostic_sink();
            Ok(Self {
                #[cfg(target_os = "windows")]
                token,
                telemetry: crate::mxc_common::telemetry::session::capture(),
                sink: sink.has_diagnostic_sink().then_some(sink),
            })
        }

        /// Run under the captured context, refusing to execute if impersonation fails.
        pub fn run<T>(self, f: impl FnOnce() -> T) -> Result<T, String> {
            #[cfg(target_os = "windows")]
            if let Some(token) = &self.token {
                // SAFETY: token is a live impersonation token and None selects this thread.
                unsafe {
                    windows::Win32::System::Threading::SetThreadToken(None, Some(token.get()))
                }
                .map_err(|error| {
                    format!("could not impersonate on the lifecycle worker: {error}")
                })?;
            }
            let _session = crate::mxc_common::telemetry::session::resume(self.telemetry);
            let _sink = self
                .sink
                .as_ref()
                .map(crate::mxc_common::logger::Logger::install_thread_diagnostic_sink);
            Ok(f())
        }
    }
}

/// Internal adapters for the C ABI and native contract tests, not SDK authoring APIs.
#[doc(hidden)]
pub mod __ffi {
    use super::*;
    use crate::sandbox::WaitResult;

    /// Whether this build contains the Windows x64 MicroVM runtime adapter.
    #[doc(hidden)]
    pub const MICROVM_RUNTIME_COMPILED: bool = cfg!(all(
        target_os = "windows",
        target_arch = "x86_64",
        feature = "microvm"
    ));

    /// Register the runtime directory used by the MicroVM backend in this process.
    pub fn register_runtime_directory(backend: &str, directory: &str) -> Result<(), Error> {
        if backend != "microvm" {
            return Err(Error::new(
                ErrorCode::UnsupportedContainment,
                "unknown runtime backend",
            ));
        }
        #[cfg(all(target_os = "windows", target_arch = "x86_64", feature = "microvm"))]
        {
            crate::backend_modules::nvx::register_runtime_directory(directory).map_err(Error::from)
        }
        #[cfg(not(all(target_os = "windows", target_arch = "x86_64", feature = "microvm")))]
        {
            let _ = directory;
            Err(Error::new(
                ErrorCode::BackendUnavailable,
                "MicroVM runtime is unavailable on this platform",
            ))
        }
    }

    /// Spawn a raw exact-version JSON container request as a live process.
    ///
    /// The JSON must declare an exact registered `version` and contain a
    /// container request. Lifecycle requests are rejected; use lifecycle APIs.
    /// `experimental` permits selecting an experimental backend (MicroVM,
    /// Hyperlight, or Windows Sandbox), which is otherwise refused with
    /// [`ErrorCode::BackendUnavailable`]. It is ignored for production backends and
    /// is never read from the JSON.
    pub fn spawn_container_json(
        request_json: &str,
        experimental: bool,
    ) -> Result<MxcProcess, Error> {
        crate::mxc_engine::spawn_one_shot_json(request_json, experimental, false)
            .map(MxcProcess::new)
    }

    /// [`spawn_container_json`] with a writable stdin, which
    /// [`MxcProcess::take_stdin`] returns.
    pub fn spawn_container_with_stdin_json(
        request_json: &str,
        experimental: bool,
    ) -> Result<MxcProcess, Error> {
        crate::mxc_engine::spawn_one_shot_json(request_json, experimental, true)
            .map(MxcProcess::new)
    }

    /// Spawn an exact-version JSON request attached to a caller-controlled PTY.
    #[doc(hidden)]
    pub fn spawn_with_pty_json(
        request_json: &str,
        experimental: bool,
        size: v1::MxcPtySize,
    ) -> Result<v1::MxcPtyProcess, Error> {
        size.validate()?;
        crate::mxc_engine::spawn_one_shot_pty_json(request_json, experimental, size.into())
            .and_then(v1::MxcPtyProcess::new)
    }

    /// Run a raw exact-version JSON container request to completion and capture
    /// its output. The JSON and `experimental` rules match [`spawn_container_json`].
    pub fn run_json(request_json: &str, experimental: bool) -> Result<ExecutionResult, Error> {
        match crate::mxc_engine::execute_one_shot_json(request_json, experimental)? {
            #[cfg(all(target_os = "windows", target_arch = "x86_64", feature = "microvm"))]
            crate::mxc_engine::OneShotExecution::Captured(result) => {
                Ok(captured_execution_result(result))
            }
            crate::mxc_engine::OneShotExecution::Streaming(process) => {
                wait_with_output(MxcProcess::new(process))
            }
        }
    }

    #[doc(hidden)]
    pub use crate::lifecycle_thread_context::LifecycleThreadContext;

    /// Run an [MXC lifecycle JSON request](https://github.com/microsoft/mxc/blob/main/docs/development/architecture/container-lifecycle.md#raw-json-entry-points) and return its JSON response envelope.
    pub fn run_lifecycle_json(
        request_json: &str,
        dry_run: bool,
        experimental: bool,
    ) -> Result<String, Error> {
        crate::mxc_engine::run_state_aware_json(request_json, dry_run, experimental)
    }

    /// Execute a lifecycle request (as a JSON string) as a **live streaming**
    /// process, returning a [`MxcProcess`] handle for output streaming, waiting,
    /// and termination, exactly like [`v1::spawn`]. Backends that expose process
    /// input also make [`MxcProcess::take_stdin`] available.
    ///
    /// The request JSON must specify the `exec` lifecycle phase (with a
    /// `sandboxId` identifying a started container). No pty is allocated.
    ///
    /// IsolationSession and WSLC serve this with the crate's corresponding
    /// `isolation_session` or `wslc` feature. WSLC returns stdout and stderr
    /// pipes, and its process reads end-of-file on stdin; use
    /// [`execute_lifecycle_with_stdin_json`] to give it input. Windows Sandbox
    /// cannot hand back pipes and refuses.
    /// `experimental` opts in to experimental backends, as for
    /// [`run_lifecycle_json`].
    ///
    /// [`MxcProcess::kill`] reaches only the foreground process here; a descendant the
    /// workload backgrounded is reclaimed when the container is stopped and
    /// deprovisioned.
    pub fn execute_lifecycle_json(
        request_json: &str,
        experimental: bool,
    ) -> Result<MxcProcess, Error> {
        crate::mxc_engine::exec_state_aware_json(request_json, experimental, false)
            .map(MxcProcess::new)
    }

    /// Execute with the backend's captured-output limits.
    pub fn execute_lifecycle_capture_json(
        request_json: &str,
        experimental: bool,
    ) -> Result<MxcProcess, Error> {
        crate::mxc_engine::exec_state_aware_capture_json(request_json, experimental)
            .map(MxcProcess::new)
    }

    /// [`execute_lifecycle_json`] with a writable stdin, which
    /// [`MxcProcess::take_stdin`] returns.
    pub fn execute_lifecycle_with_stdin_json(
        request_json: &str,
        experimental: bool,
    ) -> Result<MxcProcess, Error> {
        crate::mxc_engine::exec_state_aware_json(request_json, experimental, true)
            .map(MxcProcess::new)
    }

    /// Spawn a lifecycle execution request with a caller-controlled PTY.
    #[doc(hidden)]
    pub fn spawn_in_container_with_pty_json(
        request_json: &str,
        size: v1::MxcPtySize,
        experimental: bool,
    ) -> Result<v1::MxcPtyProcess, Error> {
        size.validate()?;
        crate::mxc_engine::exec_state_aware_pty_json(request_json, experimental, size.into())
            .and_then(v1::MxcPtyProcess::new)
    }

    /// Execute a lifecycle request attached to this process's stdio.
    #[expect(
        dead_code,
        reason = "Attached exec is reserved but not exposed by the SDK yet"
    )]
    fn exec_attached(request_json: &str, experimental: bool) -> Result<WaitResult, Error> {
        exec_attached_json(request_json, experimental)
    }

    /// Run an exact-JSON lifecycle execution request attached to this process's stdio.
    fn exec_attached_json(request_json: &str, experimental: bool) -> Result<WaitResult, Error> {
        use crate::mxc_common::state_aware_backend::ExecOutcome;
        crate::mxc_engine::exec_state_aware_attached(request_json, experimental).map(|outcome| {
            match outcome {
                ExecOutcome::Exited(code) => WaitResult::Exited(code),
                ExecOutcome::TimedOut => WaitResult::TimedOut,
            }
        })
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64", feature = "microvm"))]
fn captured_execution_result(
    result: crate::mxc_engine::CapturedExecutionResult,
) -> ExecutionResult {
    ExecutionResult {
        outcome: match result.outcome {
            crate::mxc_engine::CapturedOutcome::Exited(code) => sandbox::WaitResult::Exited(code),
            crate::mxc_engine::CapturedOutcome::TimedOut => sandbox::WaitResult::TimedOut,
        },
        warnings: result.warnings,
        stdout: result.stdout,
        stderr: result.stderr,
        output_metadata: None,
    }
}

fn wait_with_output(sandbox: MxcProcess) -> Result<ExecutionResult, Error> {
    sandbox.wait_with_output().map_err(|e| {
        Error::new(
            ErrorCode::BackendError,
            format!("waiting for the sandbox to complete failed: {e}"),
        )
    })
}
