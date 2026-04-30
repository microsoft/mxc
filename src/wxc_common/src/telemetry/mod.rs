// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TraceLogging ETW telemetry for MXC.
//!
//! Provides structured event emission for execution observability
//! and adoption metrics. Events are emitted to the local ETW subsystem
//! via the `tracelogging` crate and can be captured by any ETW consumer
//! (tracelog, logman, WPR, or an external agent).

pub mod events;

use tracelogging as tlg;

use crate::models::TelemetryConfig;

pub use events::{log_error, log_execution, ExecutionEvent, FailureReason};

// Define the TraceLogging ETW provider at the module level so it is
// accessible to both this module and the events submodule.
//
// The group_id is the well-known Microsoft Telemetry provider group GUID.
// This is the Rust equivalent of C/C++ TraceLoggingOptionGroup(...) with this
// GUID (sometimes wrapped as TraceLoggingOptionMicrosoftTelemetry()).
// Joining this group tells the Windows Connected User Experiences and Telemetry
// component (CUET / DiagTrack) that this is a Microsoft first-party telemetry
// provider. The CUET component must also be configured via OneSettings to
// collect from this specific provider before events flow to the backend.
tlg::define_provider!(
    MXC_PROVIDER,
    "Microsoft.MXC",
    group_id("4f50731a-89cf-4782-b3e0-dce8c90476ba")
);

/// MXC version string, set at compile time.
const MXC_VERSION: &str = env!("CARGO_PKG_VERSION");

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
/// Returns `true` if telemetry was activated, `false` if disabled.
/// Errors during registration are silently swallowed (telemetry must not
/// affect execution).
pub fn init(config: &TelemetryConfig) -> bool {
    if !is_enabled(config) {
        return false;
    }

    // SAFETY: We guarantee that `shutdown()` is called before the process exits,
    // which calls `MXC_PROVIDER.unregister()`.
    unsafe {
        MXC_PROVIDER.register();
    }

    true
}

/// Unregister the TraceLogging ETW provider.
///
/// Must be called before process exit if `init()` returned `true`.
pub fn shutdown() {
    MXC_PROVIDER.unregister();
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
