// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Run-to-completion backend selection and execution.
//!
//! This is the single home for "given an [`ExecutionRequest`], build the right
//! [`ScriptRunner`] and run it to completion." It centralizes the backend
//! `match` that previously lived inline in each executor binary (`wxc-exec`,
//! `lxc-exec`, `mxc-exec-mac`) so the binaries can shrink to thin CLI shells.
//!
//! Two entry points:
//!
//! - [`resolve_runner`] performs backend selection only, returning a
//!   [`ResolvedRunner`] (the boxed runner plus, on Windows, an optional
//!   [`DaclManager`](wxc_common::filesystem_dacl::DaclManager) guard for the
//!   ProcessContainer fallback tiers, whose `Drop` restores host ACEs).
//!   Callers that must manage the guard's lifetime across signal / audit
//!   machinery (`wxc-exec`) use this and own the guard themselves.
//! - [`run`] is the convenience wrapper: resolve, run to completion, and drop
//!   the runner (then, on Windows, the guard) in the correct order. Callers
//!   without such machinery (`lxc-exec`, `mxc-exec-mac`, and the FFI layer) use
//!   this.
//!
//! Backend selection is per-host: the Windows body drives the ProcessContainer
//! fallback tiers plus the Windows experimental backends; the Linux body
//! mirrors `lxc-exec` (Bubblewrap / LXC / experimental); the macOS body always
//! resolves to Seatbelt.

use wxc_common::logger::Logger;
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
use wxc_common::models::ContainmentBackend;
use wxc_common::models::{ExecutionRequest, ScriptResponse};
use wxc_common::mxc_error::MxcError;
use wxc_common::script_runner::ScriptRunner;

use crate::error::Error;

/// A backend runner resolved for an [`ExecutionRequest`], ready to run.
///
/// On Windows, `dacl_manager` — when present — is the guard for the
/// ProcessContainer DACL-fallback tier: its `Drop` restores the host ACEs the
/// tier applied. It must outlive the run — drop the `runner` first, then the
/// manager (struct fields drop in declaration order, so `runner` is declared
/// first). Callers that hand the manager off to external cleanup machinery
/// (`wxc-exec` parks it for its Ctrl-C handler) take it out of the struct.
pub struct ResolvedRunner {
    /// The boxed run-to-completion runner for the selected backend.
    pub runner: Box<dyn ScriptRunner>,
    /// Guard restoring host ACEs applied by the ProcessContainer DACL-fallback
    /// tier; `None` for every other tier and backend. Windows only.
    #[cfg(target_os = "windows")]
    pub dacl_manager: Option<wxc_common::filesystem_dacl::DaclManager>,
}

impl ResolvedRunner {
    /// Wrap a runner that needs no DACL guard.
    #[cfg(target_os = "windows")]
    fn without_guard(runner: Box<dyn ScriptRunner>) -> Self {
        Self {
            runner,
            dacl_manager: None,
        }
    }

    /// Wrap a runner (non-Windows hosts have no DACL guard).
    #[cfg(not(target_os = "windows"))]
    fn without_guard(runner: Box<dyn ScriptRunner>) -> Self {
        Self { runner }
    }
}

/// Select the containment backend for `request` and construct its
/// run-to-completion [`ScriptRunner`].
///
/// On Windows the ProcessContainer backend drives
/// [`dispatch_with_fallback`](appcontainer_common::dispatcher::dispatch_with_fallback),
/// logging the selected isolation tier and any tier-selection warnings to
/// `logger`, and surfacing the DACL guard in the returned [`ResolvedRunner`].
///
/// Experimental backends require `request.experimental_enabled`; when it is
/// unset they return a [`malformed_request`](MxcError::malformed_request)
/// error. Backends that are not available on this host / not compiled in return
/// an [`unsupported_containment`](MxcError::unsupported_containment) error.
pub fn resolve_runner(
    request: &ExecutionRequest,
    logger: &mut Logger,
) -> Result<ResolvedRunner, Error> {
    resolve_runner_inner(request, logger).map_err(Error::from)
}

/// Resolve `request`'s backend and run it to completion.
///
/// Convenience over [`resolve_runner`] for callers without external guard /
/// signal machinery: it runs the resolved runner and drops it — then, on
/// Windows, the DACL guard — in the correct order before returning the
/// [`ScriptResponse`].
pub fn run(request: &ExecutionRequest, logger: &mut Logger) -> Result<ScriptResponse, Error> {
    let mut resolved = resolve_runner(request, logger)?;
    let response = resolved.runner.run(request, logger);
    // `resolved` drops here: `runner` first (releasing child handles), then —
    // on Windows — `dacl_manager` (restoring host ACEs).
    Ok(response)
}

// ---------------------------------------------------------------------------
// Windows: ProcessContainer fallback tiers + Windows experimental backends.
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn resolve_runner_inner(
    request: &ExecutionRequest,
    logger: &mut Logger,
) -> Result<ResolvedRunner, MxcError> {
    use std::fmt::Write;

    match request.containment {
        ContainmentBackend::ProcessContainer => {
            // ProcessContainer resolves to a concrete Windows backend purely by
            // host capability: `dispatch_with_fallback` prefers the native
            // BaseContainer (OS sandbox API) when usable and otherwise falls
            // back to AppContainer tiers (BFS / DACL). The schema version does
            // not influence this choice.
            match appcontainer_common::dispatcher::dispatch_with_fallback(request) {
                Ok(dispatched) => {
                    for w in &dispatched.warnings {
                        let _ = writeln!(logger, "warning: {w}");
                    }
                    let _ = writeln!(
                        logger,
                        "selected isolation tier: {}",
                        dispatched.tier.as_str()
                    );
                    let (runner, dacl_manager) = dispatched.into_runner_and_guard();
                    Ok(ResolvedRunner {
                        runner,
                        dacl_manager,
                    })
                }
                Err(e) => {
                    // Surface any retained-entry DACL warnings through the
                    // logger so the caller's buffer flush still reports them.
                    if let appcontainer_common::dispatcher::DispatchError::Dacl {
                        warnings, ..
                    } = &e
                    {
                        for w in warnings {
                            let _ = writeln!(logger, "dacl warning: {w}");
                        }
                    }
                    Err(MxcError::backend_unavailable(format!("{e}")))
                }
            }
        }
        ContainmentBackend::Wslc => {
            #[cfg(feature = "wslc")]
            {
                if !request.experimental_enabled {
                    return Err(MxcError::malformed_request(
                        "WSLC is an experimental feature. Use --experimental flag.",
                    ));
                }
                let _ = writeln!(logger, "Using WSLContainer runner (--experimental)");
                let wslc_config = request
                    .experimental
                    .wslc
                    .as_ref()
                    .cloned()
                    .unwrap_or_default();
                Ok(ResolvedRunner::without_guard(Box::new(
                    wslc_common::wsl_container_runner::WSLContainerRunner::new(&wslc_config),
                )))
            }
            #[cfg(not(feature = "wslc"))]
            {
                let _ = logger;
                Err(MxcError::unsupported_containment(
                    "WSLC backend not compiled. Rebuild with --features wslc.",
                ))
            }
        }
        ContainmentBackend::Lxc => Err(MxcError::unsupported_containment(
            "LXC backend not available on Windows",
        )),
        ContainmentBackend::Bubblewrap => Err(MxcError::unsupported_containment(
            "Bubblewrap backend not available on Windows",
        )),
        ContainmentBackend::Seatbelt => Err(MxcError::unsupported_containment(
            "Seatbelt backend is only available on macOS (use mxc-exec-mac)",
        )),
        ContainmentBackend::Vm => Err(MxcError::unsupported_containment(
            "VM backend not yet implemented",
        )),
        ContainmentBackend::MicroVm => {
            if !request.experimental_enabled {
                return Err(MxcError::malformed_request(
                    "MicroVM is an experimental feature. Use --experimental flag.",
                ));
            }
            #[cfg(feature = "microvm")]
            {
                Ok(ResolvedRunner::without_guard(Box::new(
                    nanvix_runner::NanVixScriptRunner::new(),
                )))
            }
            #[cfg(not(feature = "microvm"))]
            {
                Err(MxcError::unsupported_containment(
                    "MicroVM backend not compiled in (build with --features microvm)",
                ))
            }
        }
        ContainmentBackend::Hyperlight => resolve_hyperlight(request),
        ContainmentBackend::WindowsSandbox => {
            if !request.experimental_enabled {
                return Err(MxcError::malformed_request(
                    "Windows Sandbox is an experimental feature. Use --experimental flag.",
                ));
            }
            let sandbox_config = request
                .experimental
                .windows_sandbox
                .as_ref()
                .cloned()
                .unwrap_or_default();
            Ok(ResolvedRunner::without_guard(Box::new(
                windows_sandbox_common::windows_sandbox_runner::WindowsSandboxScriptRunner::new(
                    &sandbox_config,
                ),
            )))
        }
        ContainmentBackend::IsolationSession => {
            #[cfg(feature = "isolation_session")]
            {
                if !request.experimental_enabled {
                    return Err(MxcError::malformed_request(
                        "Isolation Session is an experimental feature. Use --experimental flag.",
                    ));
                }
                Ok(ResolvedRunner::without_guard(Box::new(
                    isolation_session_common::IsolationSessionRunner::new(),
                )))
            }
            #[cfg(not(feature = "isolation_session"))]
            {
                Err(MxcError::unsupported_containment(
                    "IsolationSession backend not compiled. Rebuild with --features isolation_session.",
                ))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Linux: mirrors `lxc-exec` — Bubblewrap (default), LXC, and the experimental
// Hyperlight / MicroVM backends. Any other containment falls back to LXC.
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn resolve_runner_inner(
    request: &ExecutionRequest,
    logger: &mut Logger,
) -> Result<ResolvedRunner, MxcError> {
    use wxc_common::sandbox_process::Runner;

    match request.containment {
        ContainmentBackend::Hyperlight => resolve_hyperlight(request),
        ContainmentBackend::MicroVm => {
            if !request.experimental_enabled {
                return Err(MxcError::malformed_request(
                    "MicroVM is an experimental feature. Use --experimental flag.",
                ));
            }
            #[cfg(feature = "microvm")]
            {
                Ok(ResolvedRunner::without_guard(Box::new(
                    nanvix_runner::NanVixScriptRunner::new(),
                )))
            }
            #[cfg(not(feature = "microvm"))]
            {
                Err(MxcError::unsupported_containment(
                    "MicroVM backend not compiled in (build with --features microvm)",
                ))
            }
        }
        ContainmentBackend::Bubblewrap => Ok(ResolvedRunner::without_guard(Box::new(Runner::new(
            bwrap_common::bwrap_runner::BubblewrapScriptRunner::new(),
        )))),
        ContainmentBackend::Lxc => Ok(ResolvedRunner::without_guard(Box::new(
            lxc_common::lxc_runner::LxcScriptRunner::new(
                &request.lxc_config,
                &request.container_id,
                &request.lifecycle,
            ),
        ))),
        ref other => {
            logger.log_line(&format!(
                "Note: containment {other:?} unsupported on lxc-exec; falling back to LXC."
            ));
            Ok(ResolvedRunner::without_guard(Box::new(
                lxc_common::lxc_runner::LxcScriptRunner::new(
                    &request.lxc_config,
                    &request.container_id,
                    &request.lifecycle,
                ),
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// macOS: always Seatbelt (the SDK selects it on darwin; be lenient and log a
// note if the request asked for something else).
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn resolve_runner_inner(
    request: &ExecutionRequest,
    logger: &mut Logger,
) -> Result<ResolvedRunner, MxcError> {
    use wxc_common::sandbox_process::Runner;

    if request.containment != ContainmentBackend::Seatbelt {
        logger.log_line("Note: Overriding containment backend to Seatbelt on macOS.");
    }
    Ok(ResolvedRunner::without_guard(Box::new(Runner::new(
        seatbelt_common::seatbelt_runner::SeatbeltScriptRunner::new(),
    ))))
}

// ---------------------------------------------------------------------------
// Any other host: no backend.
// ---------------------------------------------------------------------------

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn resolve_runner_inner(
    _request: &ExecutionRequest,
    _logger: &mut Logger,
) -> Result<ResolvedRunner, MxcError> {
    Err(MxcError::unsupported_containment(
        "the mxc engine has no run-to-completion backend for this host OS \
         (supported: Windows, Linux, macOS)",
    ))
}

/// Construct the Hyperlight runner, shared by the Windows and Linux bodies.
/// Requires x86_64 (Hyperlight needs KVM or WHP) and the `hyperlight` feature.
#[cfg(any(target_os = "windows", target_os = "linux"))]
fn resolve_hyperlight(request: &ExecutionRequest) -> Result<ResolvedRunner, MxcError> {
    #[cfg(all(feature = "hyperlight", target_arch = "x86_64"))]
    {
        if !request.experimental_enabled {
            return Err(MxcError::malformed_request(
                "Hyperlight (Hyperlight+Unikraft) is an experimental feature. \
                 Use --experimental flag.",
            ));
        }
        Ok(ResolvedRunner::without_guard(Box::new(
            hyperlight_common::HyperlightScriptRunner::new(),
        )))
    }
    #[cfg(not(all(feature = "hyperlight", target_arch = "x86_64")))]
    {
        let _ = request;
        Err(MxcError::unsupported_containment(
            "Hyperlight backend requires x86_64 (Hyperlight needs KVM or WHP)",
        ))
    }
}
