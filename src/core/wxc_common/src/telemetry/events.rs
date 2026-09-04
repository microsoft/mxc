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
    pub sandbox_kind: &'a str,
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
    pub sandbox_kind: &'a str,
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
        event.sandbox_kind,
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
        ctx.sandbox_kind,
        error_type.as_str(),
        exit_code,
        ctx.phase,
        ctx.correlation_vector,
    );

    #[cfg(test)]
    test_sink::record_error(ctx, error_type, exit_code);
}

/// Emit a process lifecycle event required by the Windows diagnostics
/// contract. The event kind and payload are coupled in a single enum
/// to make mismatches unrepresentable at compile time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessEvent<'a> {
    Exited(i32),
    TimedOut(u64),
    /// Kill method attempted, plus the numeric OS error code returned by the
    /// failed termination call (e.g. `error.code().0` on Windows), so ETW
    /// consumers can see *why* the kill failed, not just what was attempted.
    KillFailed(&'a str, i32),
}

fn requirement_emission_allowed() -> bool {
    super::emit_active() && super::emission_is_authorized()
}

pub fn log_process_event(identity: &str, process_id: u32, event: ProcessEvent<'_>) {
    if !requirement_emission_allowed() {
        return;
    }

    match event {
        ProcessEvent::Exited(exit_code) => {
            mxc_telemetry::log_process_exited(identity, process_id, exit_code);
        }
        ProcessEvent::TimedOut(timeout_ms) => {
            mxc_telemetry::log_process_timed_out(identity, process_id, timeout_ms);
        }
        ProcessEvent::KillFailed(error_type, error_code) => {
            mxc_telemetry::log_process_kill_failed(identity, process_id, error_type, error_code);
        }
    }

    #[cfg(test)]
    test_sink::record_process(identity, process_id, event);
}

pub fn log_enforcement_degraded(
    identity: &str,
    tier: &str,
    needs_dacl_augmentation: bool,
    degradation_reasons: &str,
    effective_enforcement_level: &str,
) {
    if !requirement_emission_allowed() {
        return;
    }

    mxc_telemetry::log_enforcement_degraded(
        identity,
        tier,
        needs_dacl_augmentation,
        degradation_reasons,
        effective_enforcement_level,
    );
    #[cfg(test)]
    test_sink::record_requirement(
        "MXC.EnforcementDegraded",
        vec![
            ("identity".to_owned(), identity.to_owned()),
            ("tier".to_owned(), tier.to_owned()),
            (
                "needs_dacl_augmentation".to_owned(),
                needs_dacl_augmentation.to_string(),
            ),
            (
                "degradation_reasons".to_owned(),
                degradation_reasons.to_owned(),
            ),
            (
                "effective_enforcement_level".to_owned(),
                effective_enforcement_level.to_owned(),
            ),
        ],
    );
}

pub fn log_policy_hash(identity: &str, policy_hash: &str, config_schema_version: &str) {
    if !requirement_emission_allowed() {
        return;
    }

    mxc_telemetry::log_policy_hash(identity, policy_hash, config_schema_version);
    #[cfg(test)]
    test_sink::record_requirement(
        "MXC.PolicyHash",
        vec![
            ("identity".to_owned(), identity.to_owned()),
            ("policy_hash".to_owned(), policy_hash.to_owned()),
            (
                "config_schema_version".to_owned(),
                config_schema_version.to_owned(),
            ),
        ],
    );
}

pub fn log_network_policy_applied(
    identity: &str,
    enforcement_mode: &str,
    default_policy: &str,
    proxy_port: u64,
) {
    if !requirement_emission_allowed() {
        return;
    }

    mxc_telemetry::log_network_policy_applied(
        identity,
        enforcement_mode,
        default_policy,
        proxy_port,
    );
    #[cfg(test)]
    test_sink::record_requirement(
        "MXC.SandboxNetworkPolicyApplied",
        vec![
            ("identity".to_owned(), identity.to_owned()),
            ("enforcement_mode".to_owned(), enforcement_mode.to_owned()),
            ("default_policy".to_owned(), default_policy.to_owned()),
            ("proxy_port".to_owned(), proxy_port.to_string()),
        ],
    );
}

pub fn log_sandbox_torn_down(identity: &str, status: &str, released_resources: &str) {
    if !requirement_emission_allowed() {
        return;
    }

    mxc_telemetry::log_sandbox_torn_down(identity, status, released_resources);
    #[cfg(test)]
    test_sink::record_requirement(
        "MXC.SandboxTornDown",
        vec![
            ("identity".to_owned(), identity.to_owned()),
            ("status".to_owned(), status.to_owned()),
            (
                "released_resources".to_owned(),
                released_resources.to_owned(),
            ),
        ],
    );
}

pub fn log_config_rejected(
    correlation_id: &str,
    backend: &str,
    reason: &str,
    offending_field: &str,
    phase: &str,
) {
    if !requirement_emission_allowed() {
        return;
    }

    mxc_telemetry::log_config_rejected(correlation_id, backend, reason, offending_field, phase);
    #[cfg(test)]
    test_sink::record_requirement(
        "MXC.ConfigRejected",
        vec![
            ("correlation_id".to_owned(), correlation_id.to_owned()),
            ("backend".to_owned(), backend.to_owned()),
            ("reason".to_owned(), reason.to_owned()),
            ("offending_field".to_owned(), offending_field.to_owned()),
            ("phase".to_owned(), phase.to_owned()),
        ],
    );
}

/// In-memory capture sink for the two ETW emit calls, so tests can assert the
/// records that the real emit glue (`emit_panic` / `emit_cancellation` /
/// `emit_state_aware`) produces without an ETW consumer. Inert unless a test
/// explicitly installs it; the production path above always makes the direct
/// `mxc_telemetry` call regardless.
#[cfg(test)]
pub(super) mod test_sink {
    use super::{ExecutionEvent, FailureReason, ProcessEvent, TelemetryContext};
    use std::cell::Cell;
    use std::sync::Mutex;

    /// Serializes any test that installs/clears this capture sink or drives
    /// the emit glue in `telemetry::tests`, since `EXECUTIONS`/`ERRORS`/
    /// `REQUIREMENTS` below (and the process-global emit-slot state in the
    /// parent module) are shared regardless of which thread `cargo test`
    /// happens to run a given test on. Every test that touches this module,
    /// directly or via the parent module's emit helpers, must hold this lock
    /// for its capture window.
    pub(crate) static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Owned copy of an `MXC.Execution` record as captured for a test.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct CapturedExecution {
        pub backend: String,
        pub sandbox_kind: String,
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
        pub sandbox_kind: String,
        pub error_type: FailureReason,
        pub exit_code: i32,
        pub phase: String,
        pub correlation_vector: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct CapturedRequirement {
        pub name: String,
        pub fields: Vec<(String, String)>,
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
    static REQUIREMENTS: Mutex<Vec<CapturedRequirement>> = Mutex::new(Vec::new());

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
        REQUIREMENTS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    /// Drain and return the captured `MXC.Execution` records.
    pub fn take_executions() -> Vec<CapturedExecution> {
        std::mem::take(&mut *EXECUTIONS.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Drain and return the captured `MXC.Error` records.
    pub fn take_errors() -> Vec<CapturedError> {
        std::mem::take(&mut *ERRORS.lock().unwrap_or_else(|e| e.into_inner()))
    }

    pub fn take_requirements() -> Vec<CapturedRequirement> {
        std::mem::take(&mut *REQUIREMENTS.lock().unwrap_or_else(|e| e.into_inner()))
    }

    pub(super) fn record_requirement(name: &str, fields: Vec<(String, String)>) {
        if INSTALLED.with(|f| f.get()) {
            REQUIREMENTS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(CapturedRequirement {
                    name: name.to_owned(),
                    fields,
                });
        }
    }

    pub(super) fn record_process(identity: &str, process_id: u32, event: ProcessEvent<'_>) {
        let (name, fields) = match event {
            ProcessEvent::Exited(exit_code) => (
                "MXC.ProcessExited",
                vec![
                    ("identity".to_owned(), identity.to_owned()),
                    ("process_id".to_owned(), process_id.to_string()),
                    ("ExitCode".to_owned(), exit_code.to_string()),
                ],
            ),
            ProcessEvent::TimedOut(timeout_ms) => (
                "MXC.ProcessTimedOut",
                vec![
                    ("identity".to_owned(), identity.to_owned()),
                    ("process_id".to_owned(), process_id.to_string()),
                    ("TimeoutMs".to_owned(), timeout_ms.to_string()),
                ],
            ),
            ProcessEvent::KillFailed(error_type, error_code) => (
                "MXC.ProcessKillFailed",
                vec![
                    ("identity".to_owned(), identity.to_owned()),
                    ("process_id".to_owned(), process_id.to_string()),
                    ("mxc.error_type".to_owned(), error_type.to_owned()),
                    ("mxc.error_code".to_owned(), error_code.to_string()),
                ],
            ),
        };

        if INSTALLED.with(|f| f.get()) {
            REQUIREMENTS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(CapturedRequirement {
                    name: name.to_owned(),
                    fields,
                });
        }
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
                sandbox_kind: event.sandbox_kind.to_owned(),
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
                sandbox_kind: ctx.sandbox_kind.to_owned(),
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

    #[test]
    fn requirement_events_use_bounded_event_names() {
        let _lock = test_sink::TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        super::super::reset_for_test();
        super::super::TEST_FORCE_ACTIVE.with(|value| value.set(true));
        super::super::TEST_FORCE_AUTHORIZED.with(|value| value.set(Some(true)));
        test_sink::install();
        log_process_event("opaque", 42, ProcessEvent::Exited(0));
        log_process_event("opaque", 42, ProcessEvent::TimedOut(1000));
        log_process_event("opaque", 42, ProcessEvent::KillFailed("terminate", 5));
        log_enforcement_degraded("opaque", "base_container", true, "reason", "dacl_augmented");
        log_policy_hash("opaque", "sha256:abc", "0.8.0-alpha");
        log_network_policy_applied("opaque", "proxy", "deny", 8080);
        log_sandbox_torn_down("opaque", "success", "released");
        log_config_rejected(
            "corr",
            "process_container",
            "invalid",
            "process.commandLine",
            "validate",
        );
        let events = test_sink::take_requirements();
        super::super::reset_for_test();

        // Validate ProcessExited payload
        let process_exited = events
            .iter()
            .find(|e| {
                e.name == "MXC.ProcessExited"
                    && e.fields
                        .iter()
                        .any(|(n, v)| n == "identity" && v == "opaque")
            })
            .expect("MXC.ProcessExited with opaque identity");
        assert!(process_exited
            .fields
            .iter()
            .any(|(n, v)| n == "process_id" && v == "42"));
        assert!(
            process_exited
                .fields
                .iter()
                .any(|(n, v)| n == "ExitCode" && v == "0"),
            "ProcessExited must include ExitCode field with value 0"
        );

        // Validate ProcessTimedOut payload
        let process_timedout = events
            .iter()
            .find(|e| e.name == "MXC.ProcessTimedOut")
            .expect("MXC.ProcessTimedOut");
        assert!(process_timedout
            .fields
            .iter()
            .any(|(n, v)| n == "identity" && v == "opaque"));
        assert!(process_timedout
            .fields
            .iter()
            .any(|(n, v)| n == "process_id" && v == "42"));
        assert!(
            process_timedout
                .fields
                .iter()
                .any(|(n, v)| n == "TimeoutMs" && v == "1000"),
            "ProcessTimedOut must include TimeoutMs field with value 1000"
        );

        // Validate ProcessKillFailed payload
        let process_killfailed = events
            .iter()
            .find(|e| e.name == "MXC.ProcessKillFailed")
            .expect("MXC.ProcessKillFailed");
        assert!(process_killfailed
            .fields
            .iter()
            .any(|(n, v)| n == "identity" && v == "opaque"));
        assert!(process_killfailed
            .fields
            .iter()
            .any(|(n, v)| n == "process_id" && v == "42"));
        assert!(
            process_killfailed
                .fields
                .iter()
                .any(|(n, v)| n == "mxc.error_type" && v == "terminate"),
            "ProcessKillFailed must include mxc.error_type field"
        );
        assert!(
            process_killfailed
                .fields
                .iter()
                .any(|(n, v)| n == "mxc.error_code" && v == "5"),
            "ProcessKillFailed must include mxc.error_code field"
        );

        // Validate EnforcementDegraded payload
        let enforcement = events
            .iter()
            .find(|e| e.name == "MXC.EnforcementDegraded")
            .expect("enforcement event");
        assert!(enforcement
            .fields
            .iter()
            .any(|(n, v)| n == "identity" && v == "opaque"));
        assert!(
            enforcement
                .fields
                .iter()
                .any(|(n, v)| n == "tier" && v == "base_container"),
            "EnforcementDegraded must include tier field with correct value"
        );
        assert!(enforcement
            .fields
            .contains(&("needs_dacl_augmentation".to_owned(), "true".to_owned())));
        assert!(
            enforcement
                .fields
                .iter()
                .any(|(n, v)| !n.starts_with("degradation_reasons") || !v.is_empty()),
            "EnforcementDegraded must include non-empty degradation_reasons"
        );
        assert!(
            enforcement
                .fields
                .iter()
                .any(|(n, v)| !n.starts_with("effective_enforcement_level") || !v.is_empty()),
            "EnforcementDegraded must include non-empty effective_enforcement_level"
        );

        // Validate PolicyHash payload
        let policy_hash = events
            .iter()
            .find(|e| e.name == "MXC.PolicyHash")
            .expect("policy hash event");
        assert!(policy_hash
            .fields
            .contains(&("identity".to_owned(), "opaque".to_owned())));
        assert!(policy_hash
            .fields
            .contains(&("policy_hash".to_owned(), "sha256:abc".to_owned())));
        assert!(policy_hash
            .fields
            .contains(&("config_schema_version".to_owned(), "0.8.0-alpha".to_owned())));

        // Validate SandboxNetworkPolicyApplied payload
        let network = events
            .iter()
            .find(|e| e.name == "MXC.SandboxNetworkPolicyApplied")
            .expect("network event");
        assert!(network
            .fields
            .iter()
            .any(|(n, v)| n == "identity" && v == "opaque"));
        assert!(network
            .fields
            .iter()
            .any(|(n, v)| n == "enforcement_mode" && v == "proxy"));
        assert!(network
            .fields
            .iter()
            .any(|(n, v)| n == "default_policy" && v == "deny"));
        assert!(network
            .fields
            .contains(&("proxy_port".to_owned(), "8080".to_owned())));

        // Validate SandboxTornDown payload
        let teardown = events
            .iter()
            .find(|e| e.name == "MXC.SandboxTornDown")
            .expect("teardown event");
        assert!(teardown
            .fields
            .iter()
            .any(|(n, v)| n == "identity" && v == "opaque"));
        assert!(teardown
            .fields
            .iter()
            .any(|(n, v)| n == "status" && v == "success"));
        assert!(teardown
            .fields
            .contains(&("released_resources".to_owned(), "released".to_owned())));

        // Validate ConfigRejected payload
        let rejected = events
            .iter()
            .find(|e| e.name == "MXC.ConfigRejected")
            .expect("config rejection event");
        assert!(rejected
            .fields
            .iter()
            .any(|(n, v)| n == "correlation_id" && v == "corr"));
        assert!(rejected
            .fields
            .iter()
            .any(|(n, v)| n == "backend" && v == "process_container"));
        assert!(rejected
            .fields
            .iter()
            .any(|(n, v)| n == "reason" && v == "invalid"));
        assert!(rejected.fields.contains(&(
            "offending_field".to_owned(),
            "process.commandLine".to_owned()
        )));
        assert!(rejected
            .fields
            .contains(&("phase".to_owned(), "validate".to_owned())));
    }

    #[test]
    fn requirement_events_respect_live_authorization() {
        let _lock = test_sink::TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        super::super::reset_for_test();
        super::super::TEST_FORCE_ACTIVE.with(|value| value.set(true));
        super::super::TEST_FORCE_AUTHORIZED.with(|value| value.set(Some(false)));
        test_sink::install();

        log_process_event("opaque", 42, ProcessEvent::Exited(0));
        log_enforcement_degraded("opaque", "base_container", true, "reason", "dacl_augmented");
        log_policy_hash("opaque", "sha256:abc", "0.8.0-alpha");
        log_network_policy_applied("opaque", "proxy", "deny", 8080);
        log_sandbox_torn_down("opaque", "success", "released");
        log_config_rejected(
            "corr",
            "process_container",
            "invalid",
            "process.commandLine",
            "validate",
        );

        assert!(test_sink::take_requirements().is_empty());
        super::super::reset_for_test();
    }
}
