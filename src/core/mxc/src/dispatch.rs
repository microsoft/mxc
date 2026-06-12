// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Backend runner selection for the `mxc` library.
//!
//! This is the in-process equivalent of the `match request.containment`
//! block that each executor binary (`wxc-exec`, `lxc-exec`, `mxc-exec-mac`)
//! performs before running. It lives here — rather than in `wxc_common` —
//! because constructing a backend runner requires depending on the
//! `backends/*` crates, and `wxc_common` must not (it is the cross-platform
//! foundation those backends build on).
//!
//! The binaries delegate their shared backend arms to [`select_runner`] so
//! the selection logic has a single home instead of three drifting copies.
//!
//! Only the backends the `mxc` library officially supports are handled here:
//! ProcessContainer (Windows AppContainer / BaseContainer fallback),
//! Bubblewrap (Linux), and Seatbelt (macOS). Every other backend — including
//! the experimental ones (Windows Sandbox, IsolationSession, MicroVM,
//! Hyperlight, WSLC, LXC) — returns [`MxcError::unsupported_containment`];
//! callers that need those must drive the standalone executor binaries.

use wxc_common::logger::Logger;
use wxc_common::models::{ContainmentBackend, ExecutionRequest};
use wxc_common::mxc_error::MxcError;
use wxc_common::sandbox_process::SandboxProcess;
use wxc_common::script_runner::ScriptRunner;

/// `Err` when the host OS has no MXC sandbox backend. Checked before backend
/// selection so an unsupported platform reports a clear message rather than a
/// backend-specific one (the default/abstract intent resolves to
/// ProcessContainer on non-Linux/macOS hosts).
fn ensure_host_supported() -> Result<(), MxcError> {
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    {
        Ok(())
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        Err(MxcError::unsupported_containment(
            "the mxc library has no sandbox backend for this host OS \
             (supported: Windows, Linux, macOS)",
        ))
    }
}

/// The result of selecting a backend runner for a request.
///
/// Carries the boxed runner plus any resources whose lifetime must outlive
/// the run. On Windows the BaseContainer fallback may apply host ACEs that
/// are restored when the [`DaclManager`](wxc_common::filesystem_dacl::DaclManager)
/// guard is dropped, so callers must keep [`Selection`] alive until after
/// `runner.run(..)` returns and then drop it.
pub struct Selection {
    /// The chosen containment backend runner.
    pub runner: Box<dyn ScriptRunner>,

    /// Host-ACE restore guard for the Windows BaseContainer fallback path.
    /// `None` on the AppContainer fast path and on every non-Windows host.
    /// Drop it (after the run) to restore any ACEs the dispatcher applied.
    #[cfg(target_os = "windows")]
    pub dacl_guard: Option<wxc_common::filesystem_dacl::DaclManager>,

    /// Non-fatal diagnostics produced during selection (e.g. the selected
    /// isolation tier, or fallback warnings). Callers may log these.
    pub warnings: Vec<String>,
}

impl Selection {
    fn new(runner: Box<dyn ScriptRunner>) -> Self {
        Self {
            runner,
            #[cfg(target_os = "windows")]
            dacl_guard: None,
            warnings: Vec::new(),
        }
    }
}

/// Select the containment backend runner for `request` on the current host.
///
/// Mirrors the dispatch logic in the executor binaries but is restricted to
/// the backends the `mxc` library supports. Returns
/// [`MxcError::unsupported_containment`] for unsupported backends and
/// [`MxcError::backend_error`] when backend construction itself fails (only
/// the Windows fallback dispatcher can fail this way).
#[allow(unused_variables)]
pub fn select_runner(
    request: &ExecutionRequest,
    logger: &mut Logger,
) -> Result<Selection, MxcError> {
    ensure_host_supported()?;
    match &request.containment {
        ContainmentBackend::Seatbelt => select_seatbelt(request),
        ContainmentBackend::Bubblewrap => select_bubblewrap(request),
        ContainmentBackend::ProcessContainer => select_process_container(request, logger),
        other => Err(MxcError::unsupported_containment(format!(
            "the mxc library does not support the '{}' backend; use the wxc-exec / \
             lxc-exec / mxc-exec-mac executor binary instead",
            other.wire_name()
        ))),
    }
}

// ---------------------------------------------------------------------------
// macOS — Seatbelt
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn select_seatbelt(_request: &ExecutionRequest) -> Result<Selection, MxcError> {
    use seatbelt_common::seatbelt_runner::SeatbeltScriptRunner;
    Ok(Selection::new(Box::new(SeatbeltScriptRunner::new())))
}

#[cfg(not(target_os = "macos"))]
fn select_seatbelt(_request: &ExecutionRequest) -> Result<Selection, MxcError> {
    Err(MxcError::unsupported_containment(
        "Seatbelt is only available on macOS",
    ))
}

// ---------------------------------------------------------------------------
// Linux — Bubblewrap
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn select_bubblewrap(_request: &ExecutionRequest) -> Result<Selection, MxcError> {
    use bwrap_common::bwrap_runner::BubblewrapScriptRunner;
    Ok(Selection::new(Box::new(BubblewrapScriptRunner::new())))
}

#[cfg(not(target_os = "linux"))]
fn select_bubblewrap(_request: &ExecutionRequest) -> Result<Selection, MxcError> {
    Err(MxcError::unsupported_containment(
        "Bubblewrap is only available on Linux",
    ))
}

// ---------------------------------------------------------------------------
// Windows — ProcessContainer (AppContainer + BaseContainer fallback)
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn select_process_container(
    request: &ExecutionRequest,
    logger: &mut Logger,
) -> Result<Selection, MxcError> {
    use appcontainer_common::appcontainer_runner::AppContainerScriptRunner;
    use appcontainer_common::dispatcher::dispatch_with_fallback;
    use wxc_common::config_parser::is_base_container_version;

    // BaseContainer (OS sandbox API) is used when experimental is enabled or
    // when the schema version implies it — matching wxc-exec's behaviour.
    let version_implies_base_container = is_base_container_version(&request.schema_version);
    let use_base_container = request.experimental_enabled || version_implies_base_container;

    if !use_base_container {
        return Ok(Selection::new(Box::new(AppContainerScriptRunner::new())));
    }

    match dispatch_with_fallback(request) {
        Ok(dispatched) => {
            let mut warnings = dispatched.warnings.clone();
            warnings.push(format!(
                "selected isolation tier: {}",
                dispatched.tier.as_str()
            ));
            let (runner, dacl_guard) = dispatched.into_runner_and_guard();
            Ok(Selection {
                runner,
                dacl_guard,
                warnings,
            })
        }
        Err(e) => {
            let _ = logger;
            // Preserve the per-entry DACL retained-entry warnings the
            // dispatcher drains on a failed apply (parity with wxc-exec's
            // diagnostic output).
            let mut message = format!("BaseContainer dispatch failed: {e}");
            if let appcontainer_common::dispatcher::DispatchError::Dacl { warnings, .. } = &e {
                for w in warnings {
                    message.push_str(&format!("\n  dacl warning: {w}"));
                }
            }
            Err(MxcError::backend_error(message))
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn select_process_container(
    _request: &ExecutionRequest,
    _logger: &mut Logger,
) -> Result<Selection, MxcError> {
    Err(MxcError::unsupported_containment(
        "ProcessContainer (AppContainer / BaseContainer) is only available on Windows",
    ))
}

// ---------------------------------------------------------------------------
// Streaming (handle-based) spawn
// ---------------------------------------------------------------------------

/// Spawn a [`SandboxProcess`] handle for `request` on the current host.
///
/// The streaming analogue of [`select_runner`]: instead of returning a runner
/// to drive to completion, it spawns the sandboxed process with piped stdio
/// and returns a handle the caller can write to, read from, wait on, and
/// kill. Backends without a streaming implementation yet return
/// [`MxcError::unsupported_containment`].
#[allow(unused_variables)]
pub fn spawn_runner(
    request: &ExecutionRequest,
    logger: &mut Logger,
) -> Result<Box<dyn SandboxProcess>, MxcError> {
    ensure_host_supported()?;
    match &request.containment {
        ContainmentBackend::Seatbelt => spawn_seatbelt(request, logger),
        ContainmentBackend::Bubblewrap => spawn_bubblewrap(request, logger),
        ContainmentBackend::ProcessContainer => spawn_process_container(request, logger),
        other => Err(MxcError::unsupported_containment(format!(
            "the mxc library does not yet support streaming for the '{}' backend",
            other.wire_name()
        ))),
    }
}

#[cfg(target_os = "linux")]
fn spawn_bubblewrap(
    request: &ExecutionRequest,
    logger: &mut Logger,
) -> Result<Box<dyn SandboxProcess>, MxcError> {
    use wxc_common::sandbox_process::StreamingRunner;
    let mut runner = bwrap_common::bwrap_runner::BubblewrapScriptRunner::new();
    runner
        .spawn_streaming(request, logger)
        .map_err(|resp| MxcError::backend_error(resp.error_message))
}

#[cfg(not(target_os = "linux"))]
fn spawn_bubblewrap(
    _request: &ExecutionRequest,
    _logger: &mut Logger,
) -> Result<Box<dyn SandboxProcess>, MxcError> {
    Err(MxcError::unsupported_containment(
        "Bubblewrap is only available on Linux",
    ))
}

#[cfg(target_os = "macos")]
fn spawn_seatbelt(
    request: &ExecutionRequest,
    logger: &mut Logger,
) -> Result<Box<dyn SandboxProcess>, MxcError> {
    use wxc_common::sandbox_process::StreamingRunner;
    let mut runner = seatbelt_common::seatbelt_runner::SeatbeltScriptRunner::new();
    runner
        .spawn_streaming(request, logger)
        .map_err(|resp| MxcError::backend_error(resp.error_message))
}

#[cfg(not(target_os = "macos"))]
fn spawn_seatbelt(
    _request: &ExecutionRequest,
    _logger: &mut Logger,
) -> Result<Box<dyn SandboxProcess>, MxcError> {
    Err(MxcError::unsupported_containment(
        "Seatbelt is only available on macOS",
    ))
}

#[cfg(target_os = "windows")]
fn spawn_process_container(
    request: &ExecutionRequest,
    logger: &mut Logger,
) -> Result<Box<dyn SandboxProcess>, MxcError> {
    use appcontainer_common::appcontainer_runner::AppContainerScriptRunner;
    use wxc_common::config_parser::is_base_container_version;
    use wxc_common::sandbox_process::StreamingRunner;

    // Backend choice matches the run-to-completion path's first split — the
    // AppContainer fast path vs the native BaseContainer (OS sandbox API) —
    // but, unlike `select_runner` (run-to-completion), it does NOT route
    // through `dispatch_with_fallback`: there is no AppContainer-BFS /
    // AppContainer-DACL fallback for streaming.
    //
    // Why: `dispatch_with_fallback` yields a run-to-completion
    // `Box<dyn ScriptRunner>` plus a `DaclManager` guard, neither of which
    // fits the streaming handle (the DACL tier would require the returned
    // `SandboxProcess` to own the guard so ACE restore outlives the child).
    //
    // Consequence (intentional, fail-closed): an experimental / newer-schema
    // config on a host that lacks the native BaseContainer API fails here with
    // a clear "BaseContainer API unavailable" error from
    // `BaseContainerRunner`'s validation, whereas `spawn_sandbox_from_config`
    // (run-to-completion) would fall back to an AppContainer tier. Streaming
    // therefore requires the native BaseContainer API for those configs.
    let version_implies_base_container = is_base_container_version(&request.schema_version);
    if request.experimental_enabled || version_implies_base_container {
        let mut runner = appcontainer_common::base_container_runner::BaseContainerRunner::new();
        return runner
            .spawn_streaming(request, logger)
            .map_err(|resp| MxcError::backend_error(resp.error_message));
    }

    let mut runner = AppContainerScriptRunner::new();
    runner
        .spawn_streaming(request, logger)
        .map_err(|resp| MxcError::backend_error(resp.error_message))
}

#[cfg(not(target_os = "windows"))]
fn spawn_process_container(
    _request: &ExecutionRequest,
    _logger: &mut Logger,
) -> Result<Box<dyn SandboxProcess>, MxcError> {
    Err(MxcError::unsupported_containment(
        "ProcessContainer (AppContainer / BaseContainer) is only available on Windows",
    ))
}
