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
/// Development backends that still require runtime authorization check
/// `request.experimental_enabled`; when it is unset they return a
/// [`malformed_request`](MxcError::malformed_request) error. Backends that are
/// not available on this host / not compiled in return an
/// [`unsupported_containment`](MxcError::unsupported_containment) error.
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
    let config_schema_version = config_schema_version(request);
    if wxc_common::telemetry::is_active() {
        let identity = policy_hash_identity(&request.container_id);
        wxc_common::telemetry::log_policy_hash(&identity, &policy_hash, config_schema_version);
    }
    let record = AuditEvent::new(AuditEventName::PolicyHash)
        .str("backend", request.containment.wire_name())
        .str("policy_hash", &policy_hash)
        .str("config_schema_version", config_schema_version);
    logger.log_audit_event(&record);
}

fn config_schema_version(request: &ExecutionRequest) -> &'static str {
    request.source_contract_version()
}

fn policy_hash_identity(container_id: &str) -> String {
    let identity = if container_id.is_empty() {
        "CLI"
    } else {
        container_id
    };
    wxc_common::policy_identity::redact_identity(identity)
}

#[cfg(test)]
mod attribution_tests {
    use super::config_schema_version;
    use crate::policy::{build_request, SandboxPolicy};
    use wxc_common::logger::{Logger, Mode};
    use wxc_common::models::NetworkEnforcementCompatibility;
    use wxc_common::state_aware_request::MxcRequest;

    #[test]
    fn telemetry_attributes_exact_json_but_not_typed_sdk_requests() {
        let mut logger = Logger::new(Mode::Buffer);
        let parsed = wxc_common::config_parser::load_mxc_request_from_json(
            r#"{
                "version": "0.7.0-alpha",
                "process": {"commandLine": "echo exact"}
            }"#,
            &mut logger,
        )
        .unwrap();
        let MxcRequest::OneShot(exact) = parsed else {
            panic!("expected one-shot request");
        };
        assert_eq!(config_schema_version(&exact), "0.7.0-alpha");
        assert_eq!(
            exact.network_enforcement_compatibility,
            NetworkEnforcementCompatibility::LegacyCompatible
        );

        let direct = build_request(
            &SandboxPolicy {
                version: "0.7.0-alpha".to_string(),
                filesystem: None,
                network: None,
                ui: None,
                timeout_ms: None,
            },
            "echo direct",
            None,
        )
        .unwrap();
        assert_eq!(config_schema_version(&direct.inner), "");
        assert_eq!(direct.inner.source_contract, None);
        assert_eq!(
            direct.inner.network_enforcement_compatibility,
            NetworkEnforcementCompatibility::LegacyCompatible
        );
    }
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
                let _ = writeln!(logger, "Using WSLContainer runner");
                let wslc_config = request.wslc.as_ref().cloned().unwrap_or_default();
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
            if let Some(ws) = &request.windows_sandbox {
                let default = wxc_common::models::WindowsSandboxConfig::default();
                if ws.idle_timeout_ms != default.idle_timeout_ms
                    || ws.daemon_pipe_name != default.daemon_pipe_name
                {
                    let _ = writeln!(
                        logger,
                        "warning: windowsSandbox.idleTimeoutMs and daemonPipeName \
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
// Linux: Bubblewrap, LXC, and the experimental Hyperlight / MicroVM backends.
// A concrete backend selected for another host must fail closed.
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn resolve_runner_inner(
    request: &ExecutionRequest,
    _logger: &mut Logger,
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
        ref other => Err(MxcError::unsupported_containment(format!(
            "the '{}' backend is not available on Linux",
            other.wire_name()
        ))),
    }
}

// ---------------------------------------------------------------------------
// macOS: Seatbelt only. A concrete backend selected for another host must fail
// closed rather than silently weakening or changing the requested containment.
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn resolve_runner_inner(
    request: &ExecutionRequest,
    _logger: &mut Logger,
) -> Result<ResolvedRunner, MxcError> {
    use wxc_common::sandbox_process::Runner;

    if request.containment != ContainmentBackend::Seatbelt {
        return Err(MxcError::unsupported_containment(format!(
            "the '{}' backend is not available on macOS",
            request.containment.wire_name()
        )));
    }
    Ok(ResolvedRunner::without_guard(Box::new(Runner::new(
        seatbelt_common::seatbelt_runner::SeatbeltScriptRunner::new(),
    ))))
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::*;
    use wxc_common::logger::Mode;

    #[test]
    fn cross_platform_backend_is_rejected_instead_of_falling_back_to_lxc() {
        let request = ExecutionRequest {
            containment: ContainmentBackend::Seatbelt,
            ..Default::default()
        };
        let mut logger = Logger::new(Mode::Buffer);

        let error = match resolve_runner_inner(&request, &mut logger) {
            Ok(_) => panic!("Seatbelt must not fall back to LXC on Linux"),
            Err(error) => error,
        };

        assert_eq!(
            error.code,
            wxc_common::mxc_error::MxcErrorCode::UnsupportedContainment
        );
        assert!(error.message.contains("seatbelt"));
    }
}

#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::*;
    use wxc_common::logger::Mode;

    #[test]
    fn cross_platform_backend_is_rejected_instead_of_falling_back_to_seatbelt() {
        let request = ExecutionRequest {
            containment: ContainmentBackend::Lxc,
            ..Default::default()
        };
        let mut logger = Logger::new(Mode::Buffer);

        let error = match resolve_runner_inner(&request, &mut logger) {
            Ok(_) => panic!("LXC must not fall back to Seatbelt on macOS"),
            Err(error) => error,
        };

        assert_eq!(
            error.code,
            wxc_common::mxc_error::MxcErrorCode::UnsupportedContainment
        );
        assert!(error.message.contains("lxc"));
    }
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
    use wxc_common::models::WindowsSandboxConfig;

    fn windows_sandbox_request(config: Option<WindowsSandboxConfig>) -> ExecutionRequest {
        ExecutionRequest {
            containment: ContainmentBackend::WindowsSandbox,
            experimental_enabled: true,
            windows_sandbox: config,
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

    #[cfg(feature = "wslc")]
    #[test]
    fn wslc_resolves_without_experimental_optin() {
        let request = ExecutionRequest {
            containment: ContainmentBackend::Wslc,
            ..Default::default()
        };
        let mut logger = Logger::new(Mode::Buffer);

        resolve_runner_inner_windows(&request, &mut logger)
            .expect("WSLC selection must not require runtime experimental authorization");

        assert!(!logger.get_buffer().contains("experimental"));
    }
}
