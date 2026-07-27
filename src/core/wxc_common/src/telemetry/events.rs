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
    /// An MXC-internal defect (e.g. a panic caught by the global panic hook),
    /// as opposed to an expected operational failure of a sandboxed run.
    InternalError,
    /// Execution was interrupted by the operator (Ctrl-C, console close, or a
    /// system shutdown/logoff) via the console control handler.
    Cancelled,
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
            Self::InternalError => "internal_error",
            Self::Cancelled => "cancelled",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for FailureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Attribution shared by every telemetry event emitted for one dispatch: the
/// containment `backend`, the state-aware lifecycle `phase` (empty for one-shot),
/// and the `correlation_vector` MS-CV span (empty for one-shot). Grouped into one
/// struct so the three `&str`s can't be swapped positionally as they thread
/// through the emit helpers.
#[derive(Debug, Clone, Copy)]
pub struct TelemetryContext<'a> {
    pub backend: &'a str,
    /// State-aware lifecycle phase — one of `provision|start|exec|stop|
    /// deprovision`, or `""` for one-shot (non-state-aware) executions.
    pub phase: &'a str,
    /// Microsoft Correlation Vector (MS-CV) span for this event, emitted under
    /// `__TlgCV__` (see [`crate::telemetry::correlation_vector`]), or `""` for
    /// one-shot executions.
    pub correlation_vector: &'a str,
}

/// Data for an MXC.Execution ETW event.
pub struct ExecutionEvent<'a> {
    pub backend: &'a str,
    pub exit_code: i32,
    pub outcome: &'a str,
    pub duration_ms: u64,
    pub failure_reason: Option<FailureReason>,
    /// State-aware lifecycle phase that produced this event — one of
    /// `provision|start|exec|stop|deprovision`. Empty (`""`) for one-shot
    /// (non-state-aware) executions, which have no lifecycle phase.
    pub phase: &'a str,
    /// Microsoft Correlation Vector (MS-CV) span for this event — seeded at
    /// `provision` and spun per phase so events from the separate per-phase
    /// `wxc-exec` processes share a base prefix and can be joined (see
    /// [`crate::telemetry::correlation_vector`]). Carries no `sandbox_id` / UPN.
    /// Empty (`""`) for one-shot executions.
    pub correlation_vector: &'a str,
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
        event.phase,
        event.correlation_vector,
    );

    #[cfg(test)]
    test_sink::record_execution(event);
}

/// Log an MXC.Error ETW event.
///
/// To avoid leaking PII (paths, usernames, credentials embedded in error
/// strings), MXC deliberately does **not** emit the free-form error message.
/// The event carries only the bounded `error_type` category, the process
/// `exit_code`, and the [`TelemetryContext`] attribution (backend, lifecycle
/// phase, and correlation vector — the latter two empty for one-shot).
pub fn log_error(ctx: TelemetryContext<'_>, error_type: FailureReason, exit_code: i32) {
    mxc_telemetry::log_error(
        ctx.backend,
        error_type.as_str(),
        exit_code,
        ctx.phase,
        ctx.correlation_vector,
    );

    #[cfg(test)]
    test_sink::record_error(ctx, error_type, exit_code);
}

/// In-memory capture sink for the two ETW emit calls, so tests can assert the
/// records that the real emit glue (`emit_panic` / `emit_cancellation` /
/// `emit_state_aware`) produces without an ETW consumer. Inert unless a test
/// explicitly installs it; the production path above always makes the direct
/// `mxc_telemetry` call regardless.
#[cfg(test)]
pub(super) mod test_sink {
    use super::{ExecutionEvent, FailureReason, TelemetryContext};
    use std::cell::Cell;
    use std::sync::Mutex;

    /// Owned copy of an `MXC.Execution` record as captured for a test.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct CapturedExecution {
        pub backend: String,
        pub exit_code: i32,
        pub outcome: String,
        pub duration_ms: u64,
        pub failure_reason: Option<FailureReason>,
        pub phase: String,
        pub correlation_vector: String,
    }

    /// Owned copy of an `MXC.Error` record as captured for a test.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct CapturedError {
        pub backend: String,
        pub error_type: FailureReason,
        pub exit_code: i32,
        pub phase: String,
        pub correlation_vector: String,
    }

    thread_local! {
        /// Per-thread capture flag. Thread-local (not a global `AtomicBool`) so a
        /// stray emit on another thread — e.g. a concurrent `#[should_panic]`
        /// test tripping the global panic hook — can never leak a record into a
        /// telemetry test's capture buffer. Only emits on the installing thread
        /// are recorded, and telemetry tests drive the emit glue synchronously.
        static INSTALLED: Cell<bool> = const { Cell::new(false) };
    }

    static EXECUTIONS: Mutex<Vec<CapturedExecution>> = Mutex::new(Vec::new());
    static ERRORS: Mutex<Vec<CapturedError>> = Mutex::new(Vec::new());

    /// Start capturing emitted records into the sink (and clear any leftovers).
    /// The caller must hold the telemetry `TEST_LOCK` for the capture window.
    pub fn install() {
        clear();
        INSTALLED.with(|f| f.set(true));
    }

    /// Stop capturing and drop any buffered records.
    pub fn clear() {
        INSTALLED.with(|f| f.set(false));
        EXECUTIONS.lock().unwrap_or_else(|e| e.into_inner()).clear();
        ERRORS.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    /// Drain and return the captured `MXC.Execution` records.
    pub fn take_executions() -> Vec<CapturedExecution> {
        std::mem::take(&mut *EXECUTIONS.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Drain and return the captured `MXC.Error` records.
    pub fn take_errors() -> Vec<CapturedError> {
        std::mem::take(&mut *ERRORS.lock().unwrap_or_else(|e| e.into_inner()))
    }

    pub(super) fn record_execution(event: &ExecutionEvent<'_>) {
        if !INSTALLED.with(|f| f.get()) {
            return;
        }
        EXECUTIONS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(CapturedExecution {
                backend: event.backend.to_owned(),
                exit_code: event.exit_code,
                outcome: event.outcome.to_owned(),
                duration_ms: event.duration_ms,
                failure_reason: event.failure_reason,
                phase: event.phase.to_owned(),
                correlation_vector: event.correlation_vector.to_owned(),
            });
    }

    pub(super) fn record_error(
        ctx: TelemetryContext<'_>,
        error_type: FailureReason,
        exit_code: i32,
    ) {
        if !INSTALLED.with(|f| f.get()) {
            return;
        }
        ERRORS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(CapturedError {
                backend: ctx.backend.to_owned(),
                error_type,
                exit_code,
                phase: ctx.phase.to_owned(),
                correlation_vector: ctx.correlation_vector.to_owned(),
            });
    }
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
        assert_eq!(FailureReason::InternalError.as_str(), "internal_error");
        assert_eq!(FailureReason::Cancelled.as_str(), "cancelled");
        assert_eq!(FailureReason::Unknown.as_str(), "unknown");
    }
}
