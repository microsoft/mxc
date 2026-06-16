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

use crate::models::TelemetryConfig;

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
