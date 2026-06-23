// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TraceLogging ETW telemetry for MXC.
//!
//! Provides structured event emission for execution observability
//! and adoption metrics. Events are emitted to the local ETW subsystem
//! via the `mxc_telemetry` crate (pure Rust, using the `tracelogging`
//! crate). Every event includes common fields (Version, Channel,
//! IsDebugging, UTCReplace_AppSessionGuid) as Part C custom event data.
//!
//! On non-Windows platforms, all telemetry functions are no-ops.

pub mod events;

use std::time::Duration;

use crate::models::{ContainmentBackend, FailurePhase, ScriptResponse, TelemetryConfig};

pub use events::{log_error, log_execution, ExecutionEvent, FailureReason};

/// MXC version string, set at compile time.
const MXC_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Build channel — `"dev"` for debug builds, `"release"` for release builds.
#[cfg(debug_assertions)]
const MXC_CHANNEL: &str = "dev";
#[cfg(not(debug_assertions))]
const MXC_CHANNEL: &str = "release";

/// Returns the MXC version string.
pub fn version() -> &'static str {
    MXC_VERSION
}

/// Resolve whether telemetry is enabled for this invocation.
///
/// Resolution:
/// - `experimental.telemetry.enabled` in JSON config — explicit override.
/// - Default: off (telemetry requires explicit opt-in).
///
/// Note: Consent is the SDK consumer's responsibility. MXC does not implement
/// consent prompts or persistent consent storage.
pub fn is_enabled(config: &TelemetryConfig) -> bool {
    config.enabled.unwrap_or(false)
}

/// Initialize the TraceLogging ETW provider.
///
/// If telemetry is enabled, registers the `Microsoft.MXC` provider with ETW.
/// Returns `true` if telemetry was activated, `false` if disabled or on
/// non-Windows platforms.
///
/// Errors during registration are silently swallowed (telemetry must not
/// affect execution).
pub fn init(config: &TelemetryConfig) -> bool {
    if !is_enabled(config) {
        return false;
    }

    mxc_telemetry::init(MXC_VERSION, MXC_CHANNEL)
}

/// Unregister the TraceLogging ETW provider.
///
/// Should be called before process exit if `init()` returned `true`.
/// On early-exit paths where `shutdown()` cannot be called, the OS
/// will clean up the provider registration at process termination.
pub fn shutdown() {
    mxc_telemetry::shutdown();
}

/// Stable telemetry name for a containment backend.
fn backend_name(backend: &ContainmentBackend) -> &'static str {
    match backend {
        ContainmentBackend::ProcessContainer => "processcontainer",
        ContainmentBackend::WindowsSandbox => "windows_sandbox",
        ContainmentBackend::Lxc => "lxc",
        ContainmentBackend::MicroVm => "microvm",
        ContainmentBackend::Wslc => "wslc",
        ContainmentBackend::IsolationSession => "isolation_session",
        ContainmentBackend::Seatbelt => "seatbelt",
        ContainmentBackend::Bubblewrap => "bubblewrap",
        ContainmentBackend::Hyperlight => "hyperlight",
        ContainmentBackend::Vm => "vm",
    }
}

/// Classify a failed execution into a bounded [`FailureReason`].
fn classify_failure(phase: &FailurePhase) -> FailureReason {
    match phase {
        FailurePhase::LaunchFailed | FailurePhase::BackendUnavailable => FailureReason::InitError,
        FailurePhase::Timeout => FailureReason::Timeout,
        FailurePhase::ProcessExited | FailurePhase::None => FailureReason::ProcessError,
    }
}

/// Emit completion telemetry for a finished execution and shut the provider
/// down. No-op when `active` is `false`.
///
/// This is the single shared emit path for the `wxc` and `lxc` executors:
/// it records an `MXC.Execution` event and, for failures that carry an error
/// message, an `MXC.Error` event (category + exit code only — never the
/// message text), then calls [`shutdown`].
pub fn emit_completion(
    active: bool,
    containment: &ContainmentBackend,
    response: &ScriptResponse,
    elapsed: Duration,
) {
    if !active {
        return;
    }

    let backend = backend_name(containment);
    let failed = response.exit_code != 0;
    let outcome = if failed { "failure" } else { "success" };
    let failure_reason = failed.then(|| classify_failure(&response.failure_phase));

    log_execution(&ExecutionEvent {
        backend,
        exit_code: response.exit_code,
        outcome,
        duration_ms: elapsed.as_millis() as u64,
        failure_reason,
    });

    // The presence of an error message signals an infrastructure error (as
    // opposed to a script that merely exited non-zero). We use it only as a
    // boolean signal — the message text itself is never emitted.
    if failed && !response.error_message.is_empty() {
        log_error(
            backend,
            classify_failure(&response.failure_phase),
            response.exit_code,
        );
    }

    shutdown();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_enabled_explicit_true() {
        let config = TelemetryConfig {
            enabled: Some(true),
        };
        assert!(is_enabled(&config));
    }

    #[test]
    fn is_enabled_explicit_false() {
        let config = TelemetryConfig {
            enabled: Some(false),
        };
        assert!(!is_enabled(&config));
    }

    #[test]
    fn is_enabled_default_off() {
        let config = TelemetryConfig::default();
        assert!(!is_enabled(&config));
    }

    #[test]
    fn version_is_not_empty() {
        assert!(!version().is_empty());
    }
}
