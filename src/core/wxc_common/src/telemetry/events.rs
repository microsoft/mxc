// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TraceLogging ETW event emission for MXC telemetry.
//!
//! Event-specific data types and emission functions. The actual ETW
//! write is delegated to the `mxc_telemetry` crate, which adds
//! common fields automatically.

/// Bounded set of failure categories for error classification.
/// Prevents free-form strings that could contain PII.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureReason {
    ConfigError,
    PolicyError,
    ProcessError,
    Timeout,
    InitError,
    Unknown,
}

impl FailureReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ConfigError => "config_error",
            Self::PolicyError => "policy_error",
            Self::ProcessError => "process_error",
            Self::Timeout => "timeout",
            Self::InitError => "init_error",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for FailureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Data for an MXC.Execution ETW event.
pub struct ExecutionEvent<'a> {
    pub backend: &'a str,
    pub exit_code: i32,
    pub outcome: &'a str,
    pub duration_ms: u64,
    pub failure_reason: Option<FailureReason>,
}

/// Log an MXC.Execution ETW event.
///
/// Delegates to the `mxc_telemetry` provider which adds common fields
/// (Version, Channel, IsDebugging, UTCReplace_AppSessionGuid).
pub fn log_execution(event: &ExecutionEvent<'_>) {
    let failure_str = event.failure_reason.map(|r| r.as_str()).unwrap_or("");

    mxc_telemetry::log_execution(
        event.backend,
        event.exit_code,
        event.outcome,
        event.duration_ms,
        failure_str,
    );
}

/// Log an MXC.Error ETW event.
///
/// To avoid leaking PII (paths, usernames, credentials embedded in error
/// strings), MXC deliberately does **not** emit the free-form error message.
/// The event carries only the bounded `error_type` category and the process
/// `exit_code`.
pub fn log_error(backend: &str, error_type: FailureReason, exit_code: i32) {
    mxc_telemetry::log_error(backend, error_type.as_str(), exit_code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_reason_as_str() {
        assert_eq!(FailureReason::ConfigError.as_str(), "config_error");
        assert_eq!(FailureReason::PolicyError.as_str(), "policy_error");
        assert_eq!(FailureReason::ProcessError.as_str(), "process_error");
        assert_eq!(FailureReason::Timeout.as_str(), "timeout");
        assert_eq!(FailureReason::InitError.as_str(), "init_error");
        assert_eq!(FailureReason::Unknown.as_str(), "unknown");
    }
}
