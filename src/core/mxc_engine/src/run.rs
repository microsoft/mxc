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
//!   [`ResolvedRunner`] containing the boxed runner.
//! - [`run`] is the convenience wrapper: resolve, run to completion, and drop
//!   the runner (then, on Windows, the guard) in the correct order. Callers
//!   without such machinery (`lxc-exec`, `mxc-exec-mac`, and the FFI layer) use
//!   this.
//!
//! Backend selection is per-host: the Windows body drives native
//! ProcessContainer plus the Windows experimental backends; the Linux body
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
pub struct ResolvedRunner {
    /// The boxed run-to-completion runner for the selected backend.
    pub runner: Box<dyn ScriptRunner>,
}

impl ResolvedRunner {
    /// Wrap a resolved runner.
    fn without_guard(runner: Box<dyn ScriptRunner>) -> Self {
        Self { runner }
    }
}

/// Select the containment backend for `request` and construct its
/// run-to-completion [`ScriptRunner`].
///
/// On Windows the ProcessContainer backend uses only the native PSEC or SBOX
/// BaseContainer contracts.
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
/// Convenience over [`resolve_runner`] that runs the resolved backend to
/// completion.
pub fn run(request: &ExecutionRequest, logger: &mut Logger) -> Result<ScriptResponse, Error> {
    let mut resolved = resolve_runner(request, logger)?;
    let response = resolved.runner.run(request, logger);
    Ok(response)
}

// ---------------------------------------------------------------------------
// Windows: native ProcessContainer + Windows experimental backends.
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn resolve_runner_inner_windows(
    request: &ExecutionRequest,
    logger: &mut Logger,
) -> Result<ResolvedRunner, MxcError> {
    use std::fmt::Write;

    match request.containment {
        ContainmentBackend::ProcessContainer => {
            // ProcessContainer uses native PSEC when compatible and otherwise
            // transitional SBOX. Guarded WPR supplies denial capture when
            // native PSEC capture is unavailable.
            let capture_factory = crate::guarded_capture::factory_for_request(request);
            appcontainer_common::dispatcher::dispatch(request, capture_factory)
                .map(|runner| ResolvedRunner { runner })
                .map_err(|error| MxcError::backend_unavailable(error.to_string()))
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
}
