// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Run-to-completion backend selection and execution.
//!
//! This is the single home for "given an [`ExecutionRequest`], build the right
//! [`ScriptRunner`] and run it to completion." It centralizes the backend
//! `match` that previously lived inline in each executor binary so the binaries
//! can shrink to thin CLI shells.
//!
//! Two entry points:
//!
//! - [`resolve_runner`] performs backend selection only, returning a
//!   [`ResolvedRunner`] (the boxed runner plus, for the Windows
//!   ProcessContainer fallback tiers, an optional [`DaclManager`] guard whose
//!   `Drop` restores host ACEs). Callers that need to manage the guard's
//!   lifetime across signal / audit machinery (i.e. `wxc-exec`) use this and
//!   own the guard themselves.
//! - [`run`] is the convenience wrapper: resolve, run to completion, and drop
//!   the runner (then the guard) in the correct order. Callers without signal
//!   machinery (the FFI layer, and — in a later increment — `lxc-exec` /
//!   `mxc-exec-mac`) use this.
//!
//! **Windows only for now.** This mirrors `wxc-exec`'s one-shot dispatch. The
//! Linux (`lxc-exec`) and macOS (`mxc-exec-mac`) run-to-completion paths route
//! through this module in a later increment.

use wxc_common::filesystem_dacl::DaclManager;
use wxc_common::logger::Logger;
use wxc_common::models::{ContainmentBackend, ExecutionRequest, ScriptResponse};
use wxc_common::mxc_error::MxcError;
use wxc_common::script_runner::ScriptRunner;

use crate::error::Error;

/// A backend runner resolved for an [`ExecutionRequest`], ready to run.
///
/// The `dacl_manager`, when present, is the guard for the Windows
/// ProcessContainer DACL-fallback tier: its `Drop` restores the host ACEs the
/// tier applied. It must outlive the run — drop the `runner` first, then the
/// manager (struct fields drop in declaration order, so `runner` is declared
/// first). Callers that hand the manager off to external cleanup machinery
/// (`wxc-exec` parks it for its Ctrl-C handler) take it out of the struct.
pub struct ResolvedRunner {
    /// The boxed run-to-completion runner for the selected backend.
    pub runner: Box<dyn ScriptRunner>,
    /// Guard restoring host ACEs applied by the ProcessContainer DACL-fallback
    /// tier; `None` for every other tier and backend.
    pub dacl_manager: Option<DaclManager>,
}

impl ResolvedRunner {
    fn without_guard(runner: Box<dyn ScriptRunner>) -> Self {
        Self {
            runner,
            dacl_manager: None,
        }
    }
}

/// Select the containment backend for `request` and construct its
/// run-to-completion [`ScriptRunner`].
///
/// For the Windows ProcessContainer backend this drives
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
/// signal machinery: it runs the resolved runner and drops it — then the DACL
/// guard — in the correct order before returning the [`ScriptResponse`].
pub fn run(request: &ExecutionRequest, logger: &mut Logger) -> Result<ScriptResponse, Error> {
    let mut resolved = resolve_runner(request, logger)?;
    let response = resolved.runner.run(request, logger);
    // `resolved` drops here: `runner` first (releasing child handles), then
    // `dacl_manager` (restoring host ACEs).
    Ok(response)
}

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
        ContainmentBackend::Hyperlight => {
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
                Err(MxcError::unsupported_containment(
                    "Hyperlight backend requires x86_64 (Hyperlight needs KVM or WHP)",
                ))
            }
        }
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
