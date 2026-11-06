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
//! | ProcessContainer (AppContainer / BaseContainer) | Windows | [`v1::Containment::Process`] |
//! | Explicit ProcessContainer configuration | Windows | [`v1::Containment::ProcessContainer`] |
//! | WSLC (WSL Container) | Windows | [`v1::Containment::Wslc`] |
//! | IsolationSession | Windows | [`v1::Containment::IsolationSession`] |
//!
//! LXC is reachable only by naming it: [`v1::Containment::Process`] resolves to
//! Bubblewrap on Linux. It needs root. Ordinary streaming uses pipes, while
//! [`v1::spawn_with_pty`] allocates a caller-controlled terminal.
//!
//! WSLC requires the crate's `wslc` build feature, and IsolationSession
//! requires the `isolation_session` build feature. WSLC's container has no
//! stdin (the WSLC SDK exposes no process-input API), so
//! [`v1::MxcProcess::take_stdin`] returns `None` for it.
//! IsolationSession is also available through the typed lifecycle API.
//!
//! The `wslc` feature stages `wslcsdk.dll` into the cargo profile directory,
//! and WSLC loads it from beside the module holding this code, so an executable
//! copied or installed out of that directory needs the DLL brought along. The
//! crate README covers that and the separate `wxc-wslc-daemon.exe` that the
//! container lifecycle needs.
//!
//! A concrete backend selected on another host returns an [`v1::Error`] with
//! [`v1::ErrorCode::UnsupportedContainment`].
//!
//! # Diagnosing a failure
//!
//! [`v1::Error`] carries an [`v1::ErrorCode`] and a message. When an underlying platform
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
//! [`v1::Error::operation`] and [`v1::Error::native_code`] are absent for a failure
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
//! can take the streams from [`v1::MxcProcess`] or let `wait` drain and discard any
//! stream they did not take. WSLC does not expose stdin.
//!
//! [`v1::spawn_with_pty`] allocates a caller-controlled PTY for create-and-run
//! execution on supported backends, including IsolationSession, Bubblewrap, LXC,
//! and Seatbelt direct execution.
//! [`v1::container::spawn_in_container_with_pty`] does the same for a process in
//! an existing IsolationSession container. Unsupported backends reject the
//! request before creating a sandbox.
//!
//! Policy and operational warnings are available through [`v1::MxcProcess::warnings`]
//! and [`v1::ExecutionResult::warnings`]. These include security warnings, network rules
//! that cannot carry traffic, and operational warnings such as unavailable
//! telemetry routing.
//!
//! ## Module boundaries
//!
//! [`v1`] is the only public SDK namespace. Backend implementations, exact-contract
//! adapters, and native binding helpers are private to this crate.

#[path = "lib.rs"]
#[doc(hidden)]
#[allow(
    dead_code,
    unused_imports,
    reason = "Shared implementation also supplies workspace-only tools and native bindings"
)]
mod implementation;

pub(crate) use implementation::*;

#[doc(inline)]
pub use implementation::v1;

#[cfg(doctest)]
mod api_tests;
