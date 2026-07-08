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

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use crate::logger::Logger;
use crate::models::{ContainmentBackend, FailurePhase, ScriptResponse, TelemetryConfig};
use crate::mxc_error::{MxcError, MxcErrorCode};
use crate::state_aware_dispatch::DispatchOutcome;

pub use events::{log_error, log_execution, ExecutionEvent, FailureReason};

/// Conventional process exit code for a Rust panic/abort. Used as the reported
/// `exit_code` on crash telemetry, since the panicking process has not (and
/// will not) produce a real [`ScriptResponse`].
const PANIC_EXIT_CODE: i32 = 101;

/// Reported `exit_code` for a cancelled run. The OS terminates the process with
/// its own status (e.g. `STATUS_CONTROL_C_EXIT`) after the control handler
/// returns, so this is a bounded sentinel for attribution only: 130 is the
/// conventional "terminated by Ctrl-C" (128 + SIGINT) code.
const CANCELLED_EXIT_CODE: i32 = 130;

/// Containment backend for this process, stashed at telemetry init so that
/// out-of-band emit paths with no [`ScriptResponse`] in scope — the global
/// panic hook and the console control (Ctrl-C / close) handler — can still
/// attribute their events to the correct backend.
static PROCESS_BACKEND: OnceLock<&'static str> = OnceLock::new();

/// State-aware lifecycle phase for this process, stashed at dispatch so the
/// out-of-band emit paths (panic hook, console control handler) can attribute
/// their events to the phase that was executing. A `wxc-exec` invocation runs
/// exactly one state-aware phase, so a set-once value is sufficient. One-shot
/// executions never set it, leaving the phase `""` (no lifecycle phase).
static PROCESS_PHASE: OnceLock<&'static str> = OnceLock::new();

/// Set once the first terminal telemetry event has been emitted for this
/// process. The best-effort out-of-band paths (panic hook, cancellation
/// handler) can race the main thread's normal completion emit; this guard makes
/// emission exactly-once so a single dispatch never yields duplicate
/// `MXC.Execution` records.
static HAS_EMITTED: AtomicBool = AtomicBool::new(false);

/// Claim the single terminal-emit slot for this process. Returns `true` if a
/// terminal event has *already* been emitted (so the caller should skip),
/// `false` for the first caller (which then owns emission).
fn already_emitted() -> bool {
    HAS_EMITTED.swap(true, Ordering::SeqCst)
}

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
/// Returns `true` if telemetry was activated, `false` if disabled or if
/// registration failed.
///
/// Registration failures never affect execution: they are logged as a
/// diagnostic via the supplied [`Logger`] (so the failure is visible on the
/// console when running with diagnostics) and otherwise swallowed — the caller
/// simply proceeds with telemetry inactive. ETW is Windows-only; on other
/// platforms `mxc_telemetry::init` is a no-op stub that always returns `false`,
/// which is expected rather than a failure, so no diagnostic is emitted there.
pub fn init(config: &TelemetryConfig, logger: &mut Logger) -> bool {
    if !is_enabled(config) {
        return false;
    }

    let activated = mxc_telemetry::init(MXC_VERSION, MXC_CHANNEL);
    if !activated && cfg!(target_os = "windows") {
        logger
            .log_line("telemetry: ETW provider registration failed; continuing without telemetry");
    }
    activated
}

/// Unregister the TraceLogging ETW provider.
///
/// Should be called before process exit if `init()` returned `true`.
/// On early-exit paths where `shutdown()` cannot be called, the OS
/// will clean up the provider registration at process termination.
pub fn shutdown() {
    mxc_telemetry::shutdown();
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
    if already_emitted() {
        return;
    }

    let backend = containment.wire_name();
    let failed = response.exit_code != 0;
    let outcome = if failed { "failure" } else { "success" };
    let failure_reason = failed.then(|| classify_failure(&response.failure_phase));

    log_execution(&ExecutionEvent {
        backend,
        exit_code: response.exit_code,
        outcome,
        duration_ms: elapsed.as_millis() as u64,
        failure_reason,
        // One-shot execution — no state-aware lifecycle phase.
        phase: "",
    });

    // The presence of an error message signals an infrastructure error (as
    // opposed to a script that merely exited non-zero). We use it only as a
    // boolean signal — the message text itself is never emitted.
    if failed && !response.error_message.is_empty() {
        log_error(
            backend,
            classify_failure(&response.failure_phase),
            response.exit_code,
            "",
        );
    }

    shutdown();
}

/// Emit failure telemetry for an early-exit path that terminates **before** a
/// runner produces a [`ScriptResponse`], then shut the provider down. No-op
/// when `active` is `false`.
///
/// One-shot executors validate configuration and select a backend before
/// running; failures there call `process::exit` directly and would otherwise
/// bypass [`emit_completion`] entirely. This records an `MXC.Execution` event
/// (exit code 1, `failure` outcome) plus an `MXC.Error` event carrying the
/// bounded `reason` category and exit code, so config/policy/init failures are
/// observable. `duration_ms` is reported as `0` because no execution occurred.
pub fn emit_early_exit(active: bool, containment: &ContainmentBackend, reason: FailureReason) {
    if !active {
        return;
    }
    if already_emitted() {
        return;
    }

    let backend = containment.wire_name();

    log_execution(&ExecutionEvent {
        backend,
        exit_code: 1,
        outcome: "failure",
        duration_ms: 0,
        failure_reason: Some(reason),
        // One-shot early-exit — no state-aware lifecycle phase.
        phase: "",
    });

    log_error(backend, reason, 1, "");

    shutdown();
}

/// Record the containment backend for this process so best-effort emit paths
/// that have no [`ScriptResponse`] in scope (the panic hook and the console
/// control handler) can attribute their events.
///
/// Call once, immediately after a successful [`init`]. Later calls are ignored
/// (the value is set-once).
pub fn set_process_context(containment: &ContainmentBackend) {
    let _ = PROCESS_BACKEND.set(containment.wire_name());
}

/// Sentinel backend name used when no process backend was recorded (e.g. a
/// panic before [`set_process_context`] ran).
const UNKNOWN_BACKEND: &str = "unknown";

/// The stashed process backend wire-name, or [`UNKNOWN_BACKEND`] if none was
/// recorded.
fn process_backend() -> &'static str {
    resolve_backend_name(PROCESS_BACKEND.get().copied())
}

/// Pure defaulting for the process backend: the stashed value, or
/// [`UNKNOWN_BACKEND`] when unset. Split out (global-free) so the fallback
/// behaviour is unit-testable without writing the set-once [`PROCESS_BACKEND`].
fn resolve_backend_name(stored: Option<&'static str>) -> &'static str {
    stored.unwrap_or(UNKNOWN_BACKEND)
}

/// Record the state-aware lifecycle phase for this process so best-effort emit
/// paths that have no outcome in scope (the panic hook and the console control
/// handler) can attribute their events to the phase that was executing.
///
/// Call once, from the state-aware entry point after resolving the phase.
/// One-shot executions never call this, so their out-of-band events keep the
/// empty (`""`) phase. Later calls are ignored (the value is set-once).
pub fn set_process_phase(phase: &'static str) {
    let _ = PROCESS_PHASE.set(phase);
}

/// The stashed state-aware phase, or `""` (one-shot / not yet set).
fn process_phase() -> &'static str {
    resolve_phase_name(PROCESS_PHASE.get().copied())
}

/// Pure defaulting for the process phase: the stashed value, or `""` (one-shot /
/// not yet set). Split out (global-free) so the fallback behaviour is
/// unit-testable without writing the set-once [`PROCESS_PHASE`].
fn resolve_phase_name(stored: Option<&'static str>) -> &'static str {
    stored.unwrap_or("")
}

/// Install a crash-telemetry panic hook that emits [`emit_panic`] and then
/// chains the previously-installed hook, so the default stderr backtrace still
/// prints and the "always emit a diagnostic" contract holds for the panic case.
///
/// Shared by the `wxc` (one-shot and state-aware) and `lxc` entry points. Call
/// once, after telemetry is active and [`set_process_context`] (and, for
/// state-aware, [`set_process_phase`]) have run. The hook body is panic-free
/// and emits no message text.
pub fn install_panic_hook() {
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        emit_panic();
        previous_hook(info);
    }));
}

/// Build the `MXC.Execution` event for an out-of-band crash/cancellation. Pure
/// (no ETW I/O) so the exit-code/reason/phase attribution can be unit-tested.
fn crash_event<'a>(
    backend: &'a str,
    phase: &'a str,
    exit_code: i32,
    reason: FailureReason,
) -> ExecutionEvent<'a> {
    ExecutionEvent {
        backend,
        exit_code,
        outcome: "failure",
        duration_ms: 0,
        failure_reason: Some(reason),
        phase,
    }
}

/// The pair of events an out-of-band crash/cancellation emits: one failure
/// `MXC.Execution` and one `MXC.Error`, both attributed to the same backend,
/// phase, exit code, and reason.
struct CrashTelemetry<'a> {
    execution: ExecutionEvent<'a>,
    error: FailureReason,
    exit_code: i32,
}

/// Pure outcome→events mapping shared by [`emit_panic`]/[`emit_cancellation`]
/// and their tests. Takes the backend/phase attribution as parameters (rather
/// than reading the process-global [`PROCESS_BACKEND`]/[`PROCESS_PHASE`]) so the
/// mapping can be asserted deterministically for any backend/phase combination
/// without writing the set-once globals.
fn plan_crash<'a>(
    backend: &'a str,
    phase: &'a str,
    exit_code: i32,
    reason: FailureReason,
) -> CrashTelemetry<'a> {
    CrashTelemetry {
        execution: crash_event(backend, phase, exit_code, reason),
        error: reason,
        exit_code,
    }
}

/// Emit the planned crash/cancellation events. The thin I/O tail shared by
/// [`emit_panic`] and [`emit_cancellation`]: it performs the two ETW writes and
/// deliberately does **not** call [`shutdown`] (see the callers' docs). Takes
/// resolved attribution so the pure [`plan_crash`] mapping stays testable.
fn emit_crash(backend: &str, phase: &str, exit_code: i32, reason: FailureReason) {
    let plan = plan_crash(backend, phase, exit_code, reason);
    log_execution(&plan.execution);
    log_error(backend, plan.error, plan.exit_code, phase);
}

/// Emit crash telemetry from a global panic hook.
///
/// Guarded by [`mxc_telemetry::is_active`], so it is a cheap no-op when
/// telemetry is disabled or the provider is already shut down. It records a
/// failure `MXC.Execution` and an `MXC.Error` categorised as
/// [`FailureReason::InternalError`], attributed to the process backend stashed
/// by [`set_process_context`] and the phase stashed by [`set_process_phase`].
///
/// Unlike [`emit_completion`]/[`emit_early_exit`], this deliberately does **not**
/// call [`shutdown`]: it runs while the thread is unwinding (or about to abort),
/// where the OS reclaims the ETW registration at process exit. It also carries
/// **no** panic message text, which can contain paths or other PII.
pub fn emit_panic() {
    if !mxc_telemetry::is_active() || already_emitted() {
        return;
    }
    emit_crash(
        process_backend(),
        process_phase(),
        PANIC_EXIT_CODE,
        FailureReason::InternalError,
    );
}

/// Emit cancellation telemetry from a console control (Ctrl-C / close / shutdown)
/// handler.
///
/// Guarded by [`mxc_telemetry::is_active`], so it is a cheap no-op when
/// telemetry is disabled or already shut down. It records a failure
/// `MXC.Execution` and an `MXC.Error` categorised as [`FailureReason::Cancelled`],
/// attributed to the process backend stashed by [`set_process_context`] and the
/// phase stashed by [`set_process_phase`].
///
/// Like [`emit_panic`], it deliberately does **not** call [`shutdown`]: the
/// handler runs on a short OS-imposed budget just before the default handler
/// tears the process down via `ExitProcess`, and the main thread may still be
/// live. It is allocation-light and emits no free-form text.
pub fn emit_cancellation() {
    if !mxc_telemetry::is_active() || already_emitted() {
        return;
    }
    emit_crash(
        process_backend(),
        process_phase(),
        CANCELLED_EXIT_CODE,
        FailureReason::Cancelled,
    );
}

/// Map an [`MxcError`] surfaced by state-aware dispatch to a bounded
/// [`FailureReason`]. Exhaustive over [`MxcErrorCode`] so a newly-added code
/// forces a compile error here rather than silently classifying as `Unknown`.
fn classify_mxc_error(err: &MxcError) -> FailureReason {
    match err.code {
        MxcErrorCode::MalformedRequest | MxcErrorCode::MalformedId => FailureReason::ConfigError,
        MxcErrorCode::PolicyValidation => FailureReason::PolicyError,
        MxcErrorCode::UnsupportedContainment
        | MxcErrorCode::UnsupportedPhase
        | MxcErrorCode::BackendUnavailable => FailureReason::InitError,
        MxcErrorCode::StaleId
        | MxcErrorCode::NotProvisioned
        | MxcErrorCode::NotStarted
        | MxcErrorCode::AlreadyStarted
        | MxcErrorCode::AlreadyStopped
        | MxcErrorCode::BackendError => FailureReason::ProcessError,
    }
}

/// The telemetry a completed state-aware dispatch should emit: one
/// `MXC.Execution`, plus an optional `MXC.Error` category when the dispatch was
/// an MXC infrastructure failure. Pure (no ETW I/O) so the outcome→event mapping
/// can be unit-tested deterministically without an active provider.
struct StateAwareEvents<'a> {
    execution: ExecutionEvent<'a>,
    error: Option<FailureReason>,
}

/// Pure outcome→events mapping shared by [`emit_state_aware`] and its tests.
/// See [`emit_state_aware`] for the mapping rationale.
fn plan_state_aware<'a>(
    backend: &'a str,
    phase: &'a str,
    outcome: &Result<DispatchOutcome, MxcError>,
    duration_ms: u64,
) -> StateAwareEvents<'a> {
    match outcome {
        Ok(DispatchOutcome::Envelope(_)) => StateAwareEvents {
            execution: ExecutionEvent {
                backend,
                exit_code: 0,
                outcome: "success",
                duration_ms,
                failure_reason: None,
                phase,
            },
            error: None,
        },
        Ok(DispatchOutcome::ExecCompleted { exit_code }) => {
            let failed = *exit_code != 0;
            StateAwareEvents {
                execution: ExecutionEvent {
                    backend,
                    exit_code: *exit_code,
                    outcome: if failed { "failure" } else { "success" },
                    duration_ms,
                    // A non-zero guest exit is a faithfully propagated sandbox
                    // exit code, not an MXC infrastructure error — leave the
                    // reason unset and emit no MXC.Error (mirrors one-shot
                    // emit_completion).
                    failure_reason: None,
                    phase,
                },
                error: None,
            }
        }
        Err(err) => {
            let reason = classify_mxc_error(err);
            StateAwareEvents {
                execution: ExecutionEvent {
                    backend,
                    exit_code: 1,
                    outcome: "failure",
                    duration_ms,
                    failure_reason: Some(reason),
                    phase,
                },
                error: Some(reason),
            }
        }
    }
}

/// Emit telemetry for one completed state-aware lifecycle dispatch, tagged with
/// the lifecycle `phase`, then shut the provider down. No-op when `active` is
/// `false`.
///
/// This is the state-aware counterpart to [`emit_completion`]. Outcome mapping:
/// - [`DispatchOutcome::Envelope`] (non-exec phases and exec dry-run) — success,
///   exit code 0.
/// - [`DispatchOutcome::ExecCompleted`] — mirrors one-shot: an `MXC.Execution`
///   with the sandbox exit code. A clean non-zero *sandbox* exit is not an MXC
///   failure, so no `MXC.Error` is emitted.
/// - `Err(MxcError)` — an `MXC.Execution` failure plus an `MXC.Error` carrying
///   the [`classify_mxc_error`] category.
///
/// Terminal path (`run_state_aware_main` exits immediately after), so it calls
/// [`shutdown`].
pub fn emit_state_aware(
    active: bool,
    backend: &str,
    phase: &str,
    outcome: &Result<DispatchOutcome, MxcError>,
    elapsed: Duration,
) {
    if !active {
        return;
    }
    if already_emitted() {
        return;
    }

    let duration_ms = elapsed.as_millis() as u64;
    let plan = plan_state_aware(backend, phase, outcome, duration_ms);

    log_execution(&plan.execution);
    if let Some(reason) = plan.error {
        log_error(backend, reason, plan.execution.exit_code, phase);
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

    #[test]
    fn emit_panic_noop_without_active_provider() {
        // With telemetry never initialised, the panic hook path must be a
        // silent, panic-free no-op.
        emit_panic();
    }

    #[test]
    fn emit_cancellation_noop_without_active_provider() {
        // With telemetry never initialised, the cancellation path must be a
        // silent, panic-free no-op.
        emit_cancellation();
    }

    #[test]
    fn emit_state_aware_noop_when_inactive() {
        // Inactive provider — must be a panic-free no-op for every outcome.
        let ok = Ok(DispatchOutcome::ExecCompleted { exit_code: 0 });
        emit_state_aware(false, "isolation_session", "exec", &ok, Duration::ZERO);
    }

    #[test]
    fn classify_mxc_error_maps_codes() {
        // Exhaustive over all MxcErrorCode variants so the mapping stays total.
        assert_eq!(
            classify_mxc_error(&MxcError::malformed_request("x")),
            FailureReason::ConfigError
        );
        assert_eq!(
            classify_mxc_error(&MxcError::malformed_id("x")),
            FailureReason::ConfigError
        );
        assert_eq!(
            classify_mxc_error(&MxcError::policy_validation("x")),
            FailureReason::PolicyError
        );
        assert_eq!(
            classify_mxc_error(&MxcError::unsupported_containment("x")),
            FailureReason::InitError
        );
        assert_eq!(
            classify_mxc_error(&MxcError::unsupported_phase("x")),
            FailureReason::InitError
        );
        assert_eq!(
            classify_mxc_error(&MxcError::backend_unavailable("x")),
            FailureReason::InitError
        );
        assert_eq!(
            classify_mxc_error(&MxcError::stale_id("x")),
            FailureReason::ProcessError
        );
        assert_eq!(
            classify_mxc_error(&MxcError::not_provisioned("x")),
            FailureReason::ProcessError
        );
        assert_eq!(
            classify_mxc_error(&MxcError::not_started("x")),
            FailureReason::ProcessError
        );
        assert_eq!(
            classify_mxc_error(&MxcError::already_started("x")),
            FailureReason::ProcessError
        );
        assert_eq!(
            classify_mxc_error(&MxcError::already_stopped("x")),
            FailureReason::ProcessError
        );
        assert_eq!(
            classify_mxc_error(&MxcError::backend_error("x")),
            FailureReason::ProcessError
        );
    }

    #[test]
    fn crash_event_carries_reason_phase_and_exit_code() {
        let event = crash_event("lxc", "exec", PANIC_EXIT_CODE, FailureReason::InternalError);
        assert_eq!(event.backend, "lxc");
        assert_eq!(event.phase, "exec");
        assert_eq!(event.exit_code, PANIC_EXIT_CODE);
        assert_eq!(event.outcome, "failure");
        assert_eq!(event.failure_reason, Some(FailureReason::InternalError));

        let cancel = crash_event(
            "appcontainer",
            "",
            CANCELLED_EXIT_CODE,
            FailureReason::Cancelled,
        );
        assert_eq!(cancel.phase, "");
        assert_eq!(cancel.exit_code, CANCELLED_EXIT_CODE);
        assert_eq!(cancel.failure_reason, Some(FailureReason::Cancelled));
    }

    #[test]
    fn plan_crash_maps_panic_and_cancellation_for_any_context() {
        // The pure mapper takes backend/phase as parameters, so both the panic
        // and cancellation shapes are asserted deterministically across
        // backend/phase combinations without writing the set-once globals.
        let panic = plan_crash("lxc", "exec", PANIC_EXIT_CODE, FailureReason::InternalError);
        assert_eq!(panic.execution.backend, "lxc");
        assert_eq!(panic.execution.phase, "exec");
        assert_eq!(panic.execution.outcome, "failure");
        assert_eq!(panic.execution.exit_code, PANIC_EXIT_CODE);
        assert_eq!(
            panic.execution.failure_reason,
            Some(FailureReason::InternalError)
        );
        // The MXC.Error carries the same reason/exit code as the execution event.
        assert_eq!(panic.error, FailureReason::InternalError);
        assert_eq!(panic.exit_code, PANIC_EXIT_CODE);

        let cancel = plan_crash(
            "isolation_session",
            "",
            CANCELLED_EXIT_CODE,
            FailureReason::Cancelled,
        );
        assert_eq!(cancel.execution.backend, "isolation_session");
        assert_eq!(cancel.execution.phase, "");
        assert_eq!(cancel.execution.exit_code, CANCELLED_EXIT_CODE);
        assert_eq!(cancel.error, FailureReason::Cancelled);
        assert_eq!(cancel.exit_code, CANCELLED_EXIT_CODE);
    }

    #[test]
    fn resolve_context_names_apply_defaults() {
        // Global-free defaulting: unset falls back, set passes through. Lets the
        // fallback behaviour be tested without the set-once OnceLock globals.
        assert_eq!(resolve_backend_name(None), UNKNOWN_BACKEND);
        assert_eq!(resolve_backend_name(Some("lxc")), "lxc");
        assert_eq!(resolve_phase_name(None), "");
        assert_eq!(resolve_phase_name(Some("provision")), "provision");
    }

    #[test]
    fn plan_state_aware_envelope_is_success() {
        let outcome = Ok(DispatchOutcome::Envelope(serde_json::json!({})));
        let plan = plan_state_aware("isolation_session", "provision", &outcome, 7);
        assert_eq!(plan.execution.outcome, "success");
        assert_eq!(plan.execution.exit_code, 0);
        assert_eq!(plan.execution.phase, "provision");
        assert_eq!(plan.execution.duration_ms, 7);
        assert!(plan.execution.failure_reason.is_none());
        assert!(plan.error.is_none());
    }

    #[test]
    fn plan_state_aware_exec_nonzero_is_failure_without_error() {
        // A non-zero *sandbox* exit is a faithfully propagated exit code, not an
        // MXC failure — failure execution event, but no MXC.Error.
        let outcome = Ok(DispatchOutcome::ExecCompleted { exit_code: 3 });
        let plan = plan_state_aware("isolation_session", "exec", &outcome, 0);
        assert_eq!(plan.execution.outcome, "failure");
        assert_eq!(plan.execution.exit_code, 3);
        assert!(plan.execution.failure_reason.is_none());
        assert!(plan.error.is_none());

        // Zero exit is a clean success.
        let ok = Ok(DispatchOutcome::ExecCompleted { exit_code: 0 });
        let ok_plan = plan_state_aware("isolation_session", "exec", &ok, 0);
        assert_eq!(ok_plan.execution.outcome, "success");
        assert!(ok_plan.error.is_none());
    }

    #[test]
    fn plan_state_aware_error_emits_classified_error() {
        let outcome = Err(MxcError::backend_unavailable("no host"));
        let plan = plan_state_aware("isolation_session", "start", &outcome, 5);
        assert_eq!(plan.execution.outcome, "failure");
        assert_eq!(plan.execution.exit_code, 1);
        assert_eq!(
            plan.execution.failure_reason,
            Some(FailureReason::InitError)
        );
        assert_eq!(plan.error, Some(FailureReason::InitError));
    }

    #[test]
    fn set_process_context_records_backend() {
        // This is the only setter of the set-once PROCESS_BACKEND across the
        // crate's tests, so the recorded value is deterministic here.
        set_process_context(&ContainmentBackend::Lxc);
        assert_eq!(process_backend(), "lxc");
    }

    #[test]
    fn classify_failure_maps_all_phases() {
        // Backend/launch failures classify as init errors.
        assert_eq!(
            classify_failure(&FailurePhase::LaunchFailed),
            FailureReason::InitError
        );
        assert_eq!(
            classify_failure(&FailurePhase::BackendUnavailable),
            FailureReason::InitError
        );
        // A process that ran and exited (or an unclassified failure) is a
        // process error.
        assert_eq!(
            classify_failure(&FailurePhase::ProcessExited),
            FailureReason::ProcessError
        );
        assert_eq!(
            classify_failure(&FailurePhase::None),
            FailureReason::ProcessError
        );
    }
}
