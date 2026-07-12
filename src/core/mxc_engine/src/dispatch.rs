// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Streaming backend dispatch for the `mxc-sdk` library.
//!
//! Spawns the right [`SandboxProcess`] for the request's containment backend.
//! It lives here — rather than in `wxc_common` — because constructing a
//! backend runner requires depending on the `backends/*` crates, and
//! `wxc_common` must not (it is the cross-platform foundation those backends
//! build on).
//!
//! Only the backends with a streaming path are handled here: ProcessContainer
//! (Windows AppContainer / BaseContainer fallback), Bubblewrap (Linux), and
//! Seatbelt (macOS). Every other backend — including the experimental ones
//! (Windows Sandbox, IsolationSession, MicroVM, Hyperlight, WSLC) and LXC (no
//! streaming path suitable for the library) — returns
//! [`MxcError::unsupported_containment`]; callers that need those must drive the
//! standalone executor binaries (whose run-to-completion path will, in a later
//! increment, also route through this engine).

use wxc_common::logger::Logger;
use wxc_common::models::{ContainmentBackend, ExecutionRequest, ScriptResponse};
use wxc_common::mxc_error::MxcError;
use wxc_common::sandbox_process::SandboxProcess;

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
            "the mxc engine has no sandbox backend for this host OS \
             (supported: Windows, Linux, macOS)",
        ))
    }
}

// ---------------------------------------------------------------------------
// Streaming (handle-based) spawn
// ---------------------------------------------------------------------------

/// Spawn a [`SandboxProcess`] handle for `request` on the current host.
///
/// Spawns the sandboxed process with piped stdio and returns a handle the
/// caller can write to, read from, wait on, and kill. Backends without a
/// streaming implementation return [`MxcError::unsupported_containment`].
pub fn spawn_runner(
    request: &ExecutionRequest,
    logger: &mut Logger,
) -> Result<Box<dyn SandboxProcess>, MxcError> {
    ensure_host_supported()?;
    // `dry_run` means "validate, don't execute" — there is no process to
    // stream, so reject it rather than silently ignoring it.
    if request.dry_run {
        return Err(MxcError::malformed_request(
            "dry_run is not supported for streaming spawns",
        ));
    }
    match &request.containment {
        ContainmentBackend::Seatbelt => spawn_seatbelt(request, logger),
        ContainmentBackend::Bubblewrap => spawn_bubblewrap(request, logger),
        ContainmentBackend::ProcessContainer => spawn_process_container(request, logger),
        other => Err(MxcError::unsupported_containment(format!(
            "the mxc engine does not yet support streaming for the '{}' backend",
            other.wire_name()
        ))),
    }
}

/// Map a backend's `spawn` failure `ScriptResponse` to an
/// [`MxcError`], preserving the `BackendUnavailable` phase (so callers can fall
/// back to a lower tier) and folding any `extended_error` detail into the
/// message — rather than flattening everything to a generic `BackendError`.
fn map_spawn_error(resp: ScriptResponse) -> MxcError {
    use wxc_common::models::FailurePhase;

    let mut message = resp.error_message;
    if !resp.extended_error.is_empty() {
        if message.is_empty() {
            message = resp.extended_error;
        } else {
            message = format!("{message} ({})", resp.extended_error);
        }
    }
    match resp.failure_phase {
        FailurePhase::BackendUnavailable => MxcError::backend_unavailable(message),
        _ => MxcError::backend_error(message),
    }
}

#[cfg(target_os = "linux")]
fn spawn_bubblewrap(
    request: &ExecutionRequest,
    logger: &mut Logger,
) -> Result<Box<dyn SandboxProcess>, MxcError> {
    use wxc_common::sandbox_process::{SandboxBackend, StdioMode};
    let mut runner = bwrap_common::bwrap_runner::BubblewrapScriptRunner::new();
    runner
        .spawn(request, logger, StdioMode::Pipes)
        .map_err(map_spawn_error)
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
    use wxc_common::sandbox_process::{SandboxBackend, StdioMode};
    let mut runner = seatbelt_common::seatbelt_runner::SeatbeltScriptRunner::new();
    runner
        .spawn(request, logger, StdioMode::Pipes)
        .map_err(map_spawn_error)
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
    use appcontainer_common::appcontainer_runner::{AppContainerScriptRunner, FilesystemMode};
    use appcontainer_common::fallback_detector::is_base_container_usable;
    use wxc_common::sandbox_process::{SandboxBackend, StdioMode};

    // ProcessContainer resolves to a concrete backend purely by host
    // capability: prefer the native BaseContainer (OS sandbox API) when usable,
    // otherwise AppContainer. The schema version does not influence this choice.
    //
    // Unlike the executor binaries' run-to-completion path, streaming does NOT
    // route through `dispatch_with_fallback` — that yields a run-to-completion
    // `Box<dyn ScriptRunner>` plus a `DaclManager` guard, neither of which fits
    // the streaming handle (the DACL tier would require the returned
    // `SandboxProcess` to own the guard so ACE restore outlives the child). So
    // streaming offers only two of the dispatcher's tiers: BaseContainer when
    // the API is usable, otherwise AppContainer in BFS mode (equivalent to the
    // dispatcher's Tier 2 AppContainer-BFS path, which still requires
    // `bfscfg.exe`). The Tier 3 AppContainer-DACL fallback is not available on
    // the streaming path. The BaseContainer-vs-AppContainer choice uses the same
    // `is_base_container_usable()` probe as the dispatcher's Tier 1 selection, so
    // the two paths agree on that decision.
    if is_base_container_usable() {
        let mut runner = appcontainer_common::base_container_runner::BaseContainerRunner::new();
        return runner
            .spawn(request, logger, StdioMode::Pipes)
            .map_err(map_spawn_error);
    }

    // Select BFS mode explicitly so this does not silently change if
    // `AppContainerScriptRunner::new()`'s default filesystem mode is ever
    // altered.
    let mut runner = AppContainerScriptRunner::with_filesystem_mode(FilesystemMode::Bfs);
    runner
        .spawn(request, logger, StdioMode::Pipes)
        .map_err(map_spawn_error)
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

#[cfg(test)]
mod tests {
    use super::{ensure_host_supported, spawn_runner};
    use crate::policy::{build_request, SandboxPolicy};
    use wxc_common::logger::{Logger, Mode};
    use wxc_common::models::ContainmentBackend;
    use wxc_common::mxc_error::MxcErrorCode;

    fn minimal_policy() -> SandboxPolicy {
        SandboxPolicy {
            version: "0.7.0-alpha".to_string(),
            filesystem: None,
            network: None,
            ui: None,
            timeout_ms: None,
        }
    }

    #[test]
    fn streaming_rejects_dry_run() {
        // `dry_run` ("validate, don't execute") has no process to stream, so the
        // streaming spawn rejects it. The public `SandboxRequest` can't set it,
        // so drive the dispatch directly with the internal model.
        let mut request = build_request(&minimal_policy(), None).expect("build_request");
        request.inner.dry_run = true;
        let mut logger = Logger::new(Mode::Buffer);
        let err = match spawn_runner(&request.inner, &mut logger) {
            Ok(_) => panic!("dry_run must be rejected"),
            Err(e) => e,
        };
        assert_eq!(err.code, MxcErrorCode::MalformedRequest);
    }

    #[test]
    fn streaming_rejects_unsupported_containment() {
        // LXC has no streaming path in the library; selecting it must surface a
        // clear `UnsupportedContainment` rather than spawning. The public
        // `SandboxRequest` can't choose a backend, so drive dispatch with the
        // internal model.
        let mut request = build_request(&minimal_policy(), None).expect("build_request");
        request.inner.containment = ContainmentBackend::Lxc;
        let mut logger = Logger::new(Mode::Buffer);
        let err = match spawn_runner(&request.inner, &mut logger) {
            Ok(_) => panic!("LXC must be rejected"),
            Err(e) => e,
        };
        assert_eq!(err.code, MxcErrorCode::UnsupportedContainment);
        assert!(err.message.contains("lxc"), "got: {}", err.message);
    }

    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    #[test]
    fn host_support_ok_on_supported_platforms() {
        // The three platforms the library supports must all pass the host gate
        // `spawn_runner` checks before backend selection; this guards against a
        // regression in the `cfg` list dropping one of them.
        assert!(ensure_host_supported().is_ok());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn streaming_rejects_gui_access() {
        // A windowed (guiAccess) app needs inherited stdio, so it can't stream
        // over pipes — the backend must reject it rather than drop the GUI cap.
        let policy = SandboxPolicy {
            version: "0.7.0-alpha".to_string(),
            filesystem: Some(crate::policy::FilesystemSection {
                readwrite_paths: vec!["/tmp".to_string()],
                readonly_paths: vec![],
                denied_paths: vec![],
                clear_policy_on_exit: None,
            }),
            network: None,
            ui: None,
            timeout_ms: None,
        };
        let mut request = build_request(&policy, None).expect("build_request");
        request.set_script("echo hi");
        request
            .inner
            .seatbelt
            .as_mut()
            .expect("seatbelt config on macOS")
            .gui_access = true;
        let mut logger = Logger::new(Mode::Buffer);
        let err = match spawn_runner(&request.inner, &mut logger) {
            Ok(_) => panic!("guiAccess must be rejected"),
            Err(e) => e,
        };
        assert!(err.message.contains("guiAccess"), "got: {}", err.message);
    }
}
