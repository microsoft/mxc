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

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
const ERR_NVX_EXPERIMENTAL_OPT_IN_REQUIRED: &str =
    "NVX is an experimental feature. Use --experimental flag.";
#[cfg(all(
    not(feature = "nvx"),
    any(target_os = "windows", target_os = "linux", target_os = "macos")
))]
const ERR_NVX_FEATURE_REQUIRED: &str = "NVX backend not compiled in (build with --features nvx)";
#[cfg(all(
    feature = "nvx",
    any(target_os = "windows", target_os = "linux", target_os = "macos")
))]
const ERR_NVX_RUNTIME_IMPLEMENTATION_MISSING: &str =
    "NVX runtime implementation is not present in this build";

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
    log_policy_hash(request, logger);
    #[cfg(target_os = "windows")]
    {
        resolve_runner_inner_windows(request, logger).map_err(Error::from)
    }
    #[cfg(not(target_os = "windows"))]
    resolve_runner_inner(request, logger).map_err(Error::from)
}

/// Record `mxc.PolicyHash`: the canonical identity of the effective policy this
/// run is about to be launched under, plus the config schema version.
pub fn log_policy_hash(request: &ExecutionRequest, logger: &mut Logger) {
    use wxc_common::audit::{AuditEvent, AuditEventName};

    if !logger.has_diagnostic_sink() && !wxc_common::telemetry::is_active() {
        return;
    }

    let policy_hash = wxc_common::policy_identity::policy_hash(request);
    if wxc_common::telemetry::is_active() {
        let identity = policy_hash_identity(&request.container_id);
        wxc_common::telemetry::log_policy_hash(&identity, &policy_hash, &request.schema_version);
    }
    let record = AuditEvent::new(AuditEventName::PolicyHash)
        .str("backend", request.containment.wire_name())
        .str("policy_hash", &policy_hash)
        .str("config_schema_version", &request.schema_version);
    logger.log_audit_event(&record);
}

fn policy_hash_identity(container_id: &str) -> String {
    let identity = if container_id.is_empty() {
        "CLI"
    } else {
        container_id
    };
    wxc_common::policy_identity::redact_identity(identity)
}

/// Resolve a runner for the `wxc-exec --audit` compatibility workflow.
#[cfg(target_os = "windows")]
pub fn resolve_runner_for_audit(
    request: &ExecutionRequest,
    logger: &mut Logger,
) -> Result<ResolvedRunner, Error> {
    resolve_runner_inner_windows(request, logger).map_err(Error::from)
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
fn resolve_runner_inner_windows(
    request: &ExecutionRequest,
    logger: &mut Logger,
) -> Result<ResolvedRunner, MxcError> {
    use std::fmt::Write;

    match request.containment {
        ContainmentBackend::ProcessContainer => {
            // ProcessContainer resolves to a concrete Windows backend purely by
            // host capability: `dispatch_with_fallback_and_capture` prefers
            // the native BaseContainer (OS sandbox API) when usable and
            // otherwise falls back to AppContainer tiers (BFS / DACL). The
            // schema version does not influence this choice. When the request
            // sets `captureDenials`, `factory_for_request` hands the guarded
            // WPR fallback factory to the dispatcher so an AppContainer
            // fallback tier can still honor it instead of failing closed.
            let capture_factory = crate::guarded_capture::factory_for_request(request);
            match appcontainer_common::dispatcher::dispatch_with_fallback_and_capture(
                request,
                capture_factory,
            ) {
                Ok(dispatched) => {
                    for w in &dispatched.warnings {
                        let _ = writeln!(logger, "warning: {w}");
                    }
                    let _ = writeln!(
                        logger,
                        "selected isolation tier: {}",
                        dispatched.tier.as_str()
                    );
                    dispatched.log_enforcement_degraded(logger);
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
        ContainmentBackend::Nvx => resolve_nvx_backend(request),
        ContainmentBackend::Hyperlight => resolve_hyperlight(request),
        ContainmentBackend::WindowsSandbox => {
            if !request.experimental_enabled {
                return Err(MxcError::malformed_request(
                    "Windows Sandbox is an experimental feature. Use --experimental flag.",
                ));
            }
            if let Some(ws) = &request.experimental.windows_sandbox {
                let default = wxc_common::models::WindowsSandboxConfig::default();
                if ws.idle_timeout_ms != default.idle_timeout_ms
                    || ws.daemon_pipe_name != default.daemon_pipe_name
                {
                    let _ = writeln!(
                        logger,
                        "warning: experimental.windows_sandbox.idleTimeoutMs and daemonPipeName \
                         are ignored by the one-shot backend; each invocation launches and tears \
                         down a fresh VM"
                    );
                }
            }
            Ok(ResolvedRunner::without_guard(Box::new(
                windows_sandbox_lifecycle::WindowsSandboxRunner::new(),
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
// Hyperlight backend. Any other containment falls back to LXC.
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn resolve_runner_inner(
    request: &ExecutionRequest,
    logger: &mut Logger,
) -> Result<ResolvedRunner, MxcError> {
    use wxc_common::sandbox_process::Runner;

    match request.containment {
        ContainmentBackend::Hyperlight => resolve_hyperlight(request),
        ContainmentBackend::Nvx => resolve_nvx_backend(request),
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

    if request.containment == ContainmentBackend::Nvx {
        return resolve_nvx_backend(request);
    }

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

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
fn resolve_nvx_backend(request: &ExecutionRequest) -> Result<ResolvedRunner, MxcError> {
    if !request.experimental_enabled {
        return Err(MxcError::malformed_request(
            ERR_NVX_EXPERIMENTAL_OPT_IN_REQUIRED,
        ));
    }

    #[cfg(feature = "nvx")]
    {
        resolve_nvx_backend_with_preflight(nvx_runner::preflight)
    }

    #[cfg(not(feature = "nvx"))]
    {
        Err(MxcError::unsupported_containment(ERR_NVX_FEATURE_REQUIRED))
    }
}

#[cfg(all(
    feature = "nvx",
    any(target_os = "windows", target_os = "linux", target_os = "macos")
))]
fn resolve_nvx_backend_with_preflight<F>(preflight: F) -> Result<ResolvedRunner, MxcError>
where
    F: FnOnce() -> Result<(), MxcError>,
{
    preflight()?;
    Err(MxcError::backend_unavailable(
        ERR_NVX_RUNTIME_IMPLEMENTATION_MISSING,
    ))
}

/// Construct the Hyperlight runner, shared by the Windows and Linux bodies.
/// Requires x86_64 (Hyperlight needs KVM or WHP) and the `hyperlight` feature.
/// On Windows, pre-checks that `winhvplatform.dll` is loadable so a missing
/// WHP becomes a typed error rather than a delay-load SEH exception.
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
        // WHP is delay-loaded; check before pyhl::install warms a VM.
        #[cfg(target_os = "windows")]
        if !hyperlight_common::is_whp_available() {
            return Err(MxcError::backend_unavailable(
                "Hyperlight requires Windows Hypervisor Platform (WHP). \
                 Enable the HypervisorPlatform Windows optional feature and reboot.",
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

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;
    use wxc_common::logger::Mode;
    use wxc_common::models::{ExperimentalConfig, WindowsSandboxConfig};
    use wxc_common::mxc_error::MxcErrorCode;

    fn windows_sandbox_request(config: Option<WindowsSandboxConfig>) -> ExecutionRequest {
        ExecutionRequest {
            containment: ContainmentBackend::WindowsSandbox,
            experimental_enabled: true,
            experimental: ExperimentalConfig {
                windows_sandbox: config,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn nvx_request(experimental_enabled: bool) -> ExecutionRequest {
        ExecutionRequest {
            containment: ContainmentBackend::Nvx,
            experimental_enabled,
            ..Default::default()
        }
    }

    #[test]
    fn policy_hash_identity_matches_runner_identity_rules() {
        assert_eq!(policy_hash_identity(""), "CLI");
        assert_eq!(
            policy_hash_identity("sandbox-0123456789abcdef"),
            "sandbox-0123456789abcdef"
        );
        assert_eq!(policy_hash_identity("alice@example.com"), "entra-upn");
        assert_eq!(policy_hash_identity("arbitrary identity"), "redacted");
    }

    #[test]
    fn windows_sandbox_default_settings_do_not_warn() {
        for config in [None, Some(WindowsSandboxConfig::default())] {
            let request = windows_sandbox_request(config);
            let mut logger = Logger::new(Mode::Buffer);
            resolve_runner_inner_windows(&request, &mut logger).unwrap();
            assert!(logger.get_buffer().is_empty());
        }
    }

    #[test]
    fn windows_sandbox_non_default_legacy_settings_warn() {
        let config = WindowsSandboxConfig {
            idle_timeout_ms: 1,
            ..Default::default()
        };
        let request = windows_sandbox_request(Some(config));
        let mut logger = Logger::new(Mode::Buffer);

        resolve_runner_inner_windows(&request, &mut logger).unwrap();

        let warning = logger.get_buffer();
        assert!(warning.contains("idleTimeoutMs"));
        assert!(warning.contains("daemonPipeName"));
        assert!(warning.contains("fresh VM"));
    }

    #[test]
    fn nvx_without_experimental_opt_in_is_rejected_as_malformed_request() {
        let request = nvx_request(false);
        let mut logger = Logger::new(Mode::Buffer);

        let err = match resolve_runner_inner_windows(&request, &mut logger) {
            Ok(_) => panic!("expected malformed_request"),
            Err(err) => err,
        };

        assert_eq!(err.code, MxcErrorCode::MalformedRequest);
        assert_eq!(err.message, ERR_NVX_EXPERIMENTAL_OPT_IN_REQUIRED);
    }

    #[cfg(not(feature = "nvx"))]
    #[test]
    fn nvx_without_feature_returns_typed_unsupported_containment() {
        let request = nvx_request(true);
        let mut logger = Logger::new(Mode::Buffer);

        let err = match resolve_runner_inner_windows(&request, &mut logger) {
            Ok(_) => panic!("expected unsupported_containment"),
            Err(err) => err,
        };

        assert_eq!(err.code, MxcErrorCode::UnsupportedContainment);
        assert_eq!(err.message, ERR_NVX_FEATURE_REQUIRED);
    }

    #[cfg(feature = "nvx")]
    #[test]
    fn nvx_with_feature_propagates_preflight_backend_unavailable() {
        let request = nvx_request(true);
        let mut logger = Logger::new(Mode::Buffer);

        let err = match resolve_runner_inner_windows(&request, &mut logger) {
            Ok(_) => panic!("expected backend_unavailable"),
            Err(err) => err,
        };

        assert_eq!(err.code, MxcErrorCode::BackendUnavailable);
        assert_eq!(
            err.message,
            nvx_runner::ERR_WORKLOAD_IMAGE_ASSET_UNAVAILABLE
        );
    }

    #[cfg(feature = "nvx")]
    #[test]
    fn nvx_without_runtime_returns_backend_unavailable_even_if_preflight_succeeds() {
        let err = match resolve_nvx_backend_with_preflight(|| Ok(())) {
            Ok(_) => panic!("runtime stub must not resolve a runner"),
            Err(err) => err,
        };

        assert_eq!(err.code, MxcErrorCode::BackendUnavailable);
        assert_eq!(err.message, ERR_NVX_RUNTIME_IMPLEMENTATION_MISSING);
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    use wxc_common::logger::Mode;
    use wxc_common::mxc_error::MxcErrorCode;

    fn nvx_request(experimental_enabled: bool) -> ExecutionRequest {
        ExecutionRequest {
            containment: ContainmentBackend::Nvx,
            experimental_enabled,
            ..Default::default()
        }
    }

    #[test]
    fn nvx_without_experimental_opt_in_is_rejected_as_malformed_request() {
        let request = nvx_request(false);
        let mut logger = Logger::new(Mode::Buffer);

        let err = match resolve_runner_inner(&request, &mut logger) {
            Ok(_) => panic!("expected malformed_request"),
            Err(err) => err,
        };

        assert_eq!(err.code, MxcErrorCode::MalformedRequest);
        assert_eq!(err.message, ERR_NVX_EXPERIMENTAL_OPT_IN_REQUIRED);
    }

    #[cfg(not(feature = "nvx"))]
    #[test]
    fn nvx_without_feature_returns_typed_unsupported_containment() {
        let request = nvx_request(true);
        let mut logger = Logger::new(Mode::Buffer);

        let err = match resolve_runner_inner(&request, &mut logger) {
            Ok(_) => panic!("expected unsupported_containment"),
            Err(err) => err,
        };

        assert_eq!(err.code, MxcErrorCode::UnsupportedContainment);
        assert_eq!(err.message, ERR_NVX_FEATURE_REQUIRED);
    }

    #[cfg(feature = "nvx")]
    #[test]
    fn nvx_with_feature_propagates_preflight_backend_unavailable() {
        let request = nvx_request(true);
        let mut logger = Logger::new(Mode::Buffer);

        let err = match resolve_runner_inner(&request, &mut logger) {
            Ok(_) => panic!("expected backend_unavailable"),
            Err(err) => err,
        };

        assert_eq!(err.code, MxcErrorCode::BackendUnavailable);
        assert_eq!(
            err.message,
            nvx_runner::ERR_WORKLOAD_IMAGE_ASSET_UNAVAILABLE
        );
    }

    #[cfg(feature = "nvx")]
    #[test]
    fn nvx_without_runtime_returns_backend_unavailable_even_if_preflight_succeeds() {
        let err = match resolve_nvx_backend_with_preflight(|| Ok(())) {
            Ok(_) => panic!("runtime stub must not resolve a runner"),
            Err(err) => err,
        };

        assert_eq!(err.code, MxcErrorCode::BackendUnavailable);
        assert_eq!(err.message, ERR_NVX_RUNTIME_IMPLEMENTATION_MISSING);
    }
}
