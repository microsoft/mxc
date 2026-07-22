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

pub mod correlation_vector;
pub mod events;

use std::time::Duration;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use crate::logger::Logger;
use crate::models::{ContainmentBackend, FailurePhase, ScriptResponse, TelemetryConfig};
use crate::mxc_error::{MxcError, MxcErrorCode};
use crate::state_aware_dispatch::DispatchOutcome;

pub use events::{log_error, log_execution, ExecutionEvent, FailureReason, TelemetryContext};

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
///
/// A `Mutex<Option<_>>` (rather than a `OnceLock`) so `#[cfg(test)]`
/// [`reset_for_test`] can clear it between tests; the setter still enforces
/// set-once semantics (only writes when currently unset).
static PROCESS_BACKEND: Mutex<Option<&'static str>> = Mutex::new(None);

/// State-aware lifecycle phase for this process, stashed at dispatch so the
/// out-of-band emit paths (panic hook, console control handler) can attribute
/// their events to the phase that was executing. A `wxc-exec` invocation runs
/// exactly one state-aware phase, so a set-once value is sufficient. One-shot
/// executions never set it, leaving the phase `""` (no lifecycle phase).
///
/// Set-once (only written when unset); resettable in tests via
/// [`reset_for_test`].
static PROCESS_PHASE: Mutex<Option<&'static str>> = Mutex::new(None);

/// The Microsoft Correlation Vector (MS-CV) span for this process — the value
/// emitted under `__TlgCV__`. It is a random-seeded MS-CV for the state-aware
/// lifecycle this `wxc-exec` invocation is a phase of (seeded at `provision`,
/// spun per phase — see [`correlation_vector`]). Stashed at dispatch so the
/// out-of-band emit paths (panic hook, console control handler) can tag their
/// events with it, letting a crash / cancellation during any phase be correlated
/// back to the full lifecycle (join on the shared base prefix). Carries no
/// `sandbox_id` / UPN — privacy-safe by construction. One-shot executions never
/// set it, leaving it `""` (no lifecycle to join).
///
/// Set-once (only written when unset); resettable in tests via
/// [`reset_for_test`].
static PROCESS_CORRELATION_VECTOR: Mutex<Option<String>> = Mutex::new(None);

/// Set once the first terminal telemetry event has been emitted for this
/// process. The best-effort out-of-band paths (panic hook, cancellation
/// handler) can race the main thread's normal completion emit; this guard makes
/// emission exactly-once so a single dispatch never yields duplicate
/// `MXC.Execution` records.
static HAS_EMITTED: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
thread_local! {
    /// Test-only override that forces [`emit_active`] to report the provider as
    /// active, so the emit glue in [`emit_panic`]/[`emit_cancellation`] can be
    /// exercised deterministically on every platform (ETW registration only
    /// succeeds on Windows). Thread-local (not a global `AtomicBool`) so a
    /// concurrent `#[should_panic]` test on another thread can't observe a
    /// telemetry test's forced-active state and trip the global panic hook into
    /// the sink. Never set outside tests.
    static TEST_FORCE_ACTIVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether the emit glue should proceed. In production this is exactly
/// [`mxc_telemetry::is_active`]; in tests a forced override (thread-local, set
/// under `TEST_LOCK`) can make it report active without a real ETW provider.
fn emit_active() -> bool {
    #[cfg(test)]
    if TEST_FORCE_ACTIVE.with(|f| f.get()) {
        return true;
    }
    mxc_telemetry::is_active()
}

/// Claim the single terminal-emit slot for this process. Returns `true` if a
/// terminal event has *already* been emitted (so the caller should skip),
/// `false` for the first caller (which then owns emission).
fn already_emitted() -> bool {
    HAS_EMITTED.swap(true, Ordering::SeqCst)
}

/// Reset all per-process telemetry state (the exactly-once emit slot and the
/// stashed backend / phase / correlation-id context) so tests can drive the emit
/// paths from a known-clean baseline. Tests that touch this state must hold
/// [`TEST_LOCK`] for the duration, since the state is process-global.
#[cfg(test)]
fn reset_for_test() {
    HAS_EMITTED.store(false, Ordering::SeqCst);
    *PROCESS_BACKEND.lock().unwrap_or_else(|e| e.into_inner()) = None;
    *PROCESS_PHASE.lock().unwrap_or_else(|e| e.into_inner()) = None;
    *PROCESS_CORRELATION_VECTOR
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = None;
    TEST_FORCE_ACTIVE.with(|f| f.set(false));
    events::test_sink::clear();
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
        FailurePhase::LaunchFailed
        | FailurePhase::BackendUnavailable
        | FailurePhase::PostLaunchFailed => FailureReason::InitError,
        FailurePhase::Rejected => FailureReason::PolicyError,
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
        // One-shot execution — already correlated by AppSessionGuid, no
        // cross-phase lifecycle to join.
        correlation_vector: "",
    });

    // The presence of an error message signals an infrastructure error (as
    // opposed to a script that merely exited non-zero). We use it only as a
    // boolean signal — the message text itself is never emitted.
    if failed && !response.error_message.is_empty() {
        log_error(
            TelemetryContext {
                backend,
                phase: "",
                correlation_vector: "",
            },
            classify_failure(&response.failure_phase),
            response.exit_code,
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
        // One-shot early-exit — no cross-phase lifecycle to correlate.
        correlation_vector: "",
    });

    log_error(
        TelemetryContext {
            backend,
            phase: "",
            correlation_vector: "",
        },
        reason,
        1,
    );

    shutdown();
}

/// Record the containment backend for this process so best-effort emit paths
/// that have no [`ScriptResponse`] in scope (the panic hook and the console
/// control handler) can attribute their events.
///
/// Call once, immediately after a successful [`init`]. Later calls are ignored
/// (the value is set-once).
pub fn set_process_context(containment: &ContainmentBackend) {
    let mut slot = PROCESS_BACKEND.lock().unwrap_or_else(|e| e.into_inner());
    if slot.is_none() {
        *slot = Some(containment.wire_name());
    }
}

/// Sentinel backend name used when no process backend was recorded (e.g. a
/// panic before [`set_process_context`] ran).
const UNKNOWN_BACKEND: &str = "unknown";

/// The stashed process backend wire-name, or [`UNKNOWN_BACKEND`] if none was
/// recorded.
///
/// Uses `try_lock`: this runs from the panic hook / console control handler,
/// which can fire *while the main thread holds* [`PROCESS_BACKEND`] (e.g. a
/// panic inside a setter). A blocking `lock()` would then deadlock the very path
/// meant to record the crash, so on contention (or poison) we fall back to the
/// sentinel rather than block.
fn process_backend() -> &'static str {
    let stored = PROCESS_BACKEND.try_lock().ok().and_then(|slot| *slot);
    resolve_backend_name(stored)
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
    let mut slot = PROCESS_PHASE.lock().unwrap_or_else(|e| e.into_inner());
    if slot.is_none() {
        *slot = Some(phase);
    }
}

/// The stashed state-aware phase, or `""` (one-shot / not yet set).
///
/// Uses `try_lock` for the same reentrancy-deadlock reason as
/// [`process_backend`]: it runs from the out-of-band crash paths.
fn process_phase() -> &'static str {
    let stored = PROCESS_PHASE.try_lock().ok().and_then(|slot| *slot);
    resolve_phase_name(stored)
}

/// Record the lifecycle correlation vector (MS-CV span) for this process so the
/// out-of-band emit paths (panic hook, console control handler) can tag their
/// events with it. Call once, from the state-aware entry point, passing the
/// seeded/spun MS-CV for this phase (see [`correlation_vector`]). One-shot
/// executions never call this. Later calls are ignored (the value is set-once).
pub fn set_process_correlation_vector(correlation_vector: &str) {
    // Allocate the owned copy *before* taking the lock so the critical section
    // does no allocation — a panic mid-allocation while holding the lock would
    // otherwise deadlock the panic hook's `process_correlation_vector` reader.
    let owned = correlation_vector.to_owned();
    let mut slot = PROCESS_CORRELATION_VECTOR
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if slot.is_none() {
        *slot = Some(owned);
    }
}

/// The stashed lifecycle correlation vector, or `""` (one-shot / not set / lock
/// contended). Returns an owned `String` because the value lives behind a
/// `Mutex` (no `'static` borrow to hand out, unlike the `&'static str` context
/// fields). Uses `try_lock` for the same reentrancy-deadlock reason as
/// [`process_backend`].
fn process_correlation_vector() -> String {
    PROCESS_CORRELATION_VECTOR
        .try_lock()
        .ok()
        .and_then(|slot| slot.clone())
        .unwrap_or_default()
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
/// (no ETW I/O) so the exit-code/reason/attribution mapping can be unit-tested.
fn crash_event<'a>(
    ctx: TelemetryContext<'a>,
    exit_code: i32,
    reason: FailureReason,
) -> ExecutionEvent<'a> {
    ExecutionEvent {
        backend: ctx.backend,
        exit_code,
        outcome: "failure",
        duration_ms: 0,
        failure_reason: Some(reason),
        phase: ctx.phase,
        correlation_vector: ctx.correlation_vector,
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
/// and their tests. Takes the [`TelemetryContext`] attribution as a parameter
/// (rather than reading the process globals) so the mapping can be asserted
/// deterministically for any attribution without writing the globals.
fn plan_crash<'a>(
    ctx: TelemetryContext<'a>,
    exit_code: i32,
    reason: FailureReason,
) -> CrashTelemetry<'a> {
    CrashTelemetry {
        execution: crash_event(ctx, exit_code, reason),
        error: reason,
        exit_code,
    }
}

/// Emit the planned crash/cancellation events. The thin I/O tail shared by
/// [`emit_panic`] and [`emit_cancellation`]: it performs the two ETW writes and
/// deliberately does **not** call [`shutdown`] (see the callers' docs). Takes
/// resolved attribution so the pure [`plan_crash`] mapping stays testable.
fn emit_crash(ctx: TelemetryContext<'_>, exit_code: i32, reason: FailureReason) {
    let plan = plan_crash(ctx, exit_code, reason);
    log_execution(&plan.execution);
    log_error(ctx, plan.error, plan.exit_code);
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
    if !emit_active() || already_emitted() {
        return;
    }
    let correlation_vector = process_correlation_vector();
    emit_crash(
        TelemetryContext {
            backend: process_backend(),
            phase: process_phase(),
            correlation_vector: &correlation_vector,
        },
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
    if !emit_active() || already_emitted() {
        return;
    }
    let correlation_vector = process_correlation_vector();
    emit_crash(
        TelemetryContext {
            backend: process_backend(),
            phase: process_phase(),
            correlation_vector: &correlation_vector,
        },
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
    ctx: TelemetryContext<'a>,
    outcome: &Result<DispatchOutcome, MxcError>,
    duration_ms: u64,
) -> StateAwareEvents<'a> {
    match outcome {
        Ok(DispatchOutcome::Envelope(_)) => StateAwareEvents {
            execution: ExecutionEvent {
                backend: ctx.backend,
                exit_code: 0,
                outcome: "success",
                duration_ms,
                failure_reason: None,
                phase: ctx.phase,
                correlation_vector: ctx.correlation_vector,
            },
            error: None,
        },
        Ok(DispatchOutcome::ExecCompleted { exit_code }) => {
            let failed = *exit_code != 0;
            StateAwareEvents {
                execution: ExecutionEvent {
                    backend: ctx.backend,
                    exit_code: *exit_code,
                    outcome: if failed { "failure" } else { "success" },
                    duration_ms,
                    // A non-zero guest exit is a faithfully propagated sandbox
                    // exit code, not an MXC infrastructure error — leave the
                    // reason unset and emit no MXC.Error (mirrors one-shot
                    // emit_completion).
                    failure_reason: None,
                    phase: ctx.phase,
                    correlation_vector: ctx.correlation_vector,
                },
                error: None,
            }
        }
        Err(err) => {
            let reason = classify_mxc_error(err);
            StateAwareEvents {
                execution: ExecutionEvent {
                    backend: ctx.backend,
                    exit_code: 1,
                    outcome: "failure",
                    duration_ms,
                    failure_reason: Some(reason),
                    phase: ctx.phase,
                    correlation_vector: ctx.correlation_vector,
                },
                error: Some(reason),
            }
        }
    }
}

/// Emit telemetry for one completed state-aware lifecycle dispatch, tagged with
/// the lifecycle `phase` and the `correlation_vector` (both carried in `ctx`), then
/// shut the provider down. No-op when `active` is `false`.
///
/// `ctx.correlation_vector` is the MS-CV span for this phase — every phase of one
/// lifecycle shares a base prefix (seeded at `provision`, spun per phase) so
/// `provision`→…→`deprovision` events (each emitted by a separate `wxc-exec`
/// process) can be joined. Empty for phases with no vector.
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
    ctx: TelemetryContext<'_>,
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
    let plan = plan_state_aware(ctx, outcome, duration_ms);

    log_execution(&plan.execution);
    if let Some(reason) = plan.error {
        log_error(ctx, reason, plan.execution.exit_code);
    }

    shutdown();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes tests that touch the process-global emit slot / context
    /// (`HAS_EMITTED`, `PROCESS_BACKEND`, `PROCESS_PHASE`, `PROCESS_CORRELATION_VECTOR`)
    /// or drive the emit paths, so their global state can't leak across tests.
    /// Mirrors the `TEST_LOCK` pattern in `mxc_telemetry`.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

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
        // silent, panic-free no-op. Serialized: shares the emit-slot / force-
        // active globals with the capture tests below.
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        emit_panic();
        assert!(
            events::test_sink::take_executions().is_empty(),
            "inactive provider must not emit"
        );
    }

    #[test]
    fn emit_cancellation_noop_without_active_provider() {
        // With telemetry never initialised, the cancellation path must be a
        // silent, panic-free no-op.
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        emit_cancellation();
        assert!(
            events::test_sink::take_executions().is_empty(),
            "inactive provider must not emit"
        );
    }

    #[test]
    fn emit_panic_active_captures_execution_and_error() {
        // Drive the real emit glue (globals read → active guard → paired write)
        // with the provider forced active and the capture sink installed, then
        // assert the exact MXC.Execution + MXC.Error records a panic produces.
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        events::test_sink::install();
        TEST_FORCE_ACTIVE.with(|f| f.set(true));
        set_process_context(&ContainmentBackend::IsolationSession);
        set_process_phase("exec");
        set_process_correlation_vector("iso:wxc-abcd");

        emit_panic();

        let execs = events::test_sink::take_executions();
        assert_eq!(execs.len(), 1, "panic emits exactly one MXC.Execution");
        let exec = &execs[0];
        assert_eq!(exec.backend, "isolation_session");
        assert_eq!(exec.exit_code, PANIC_EXIT_CODE);
        assert_eq!(exec.outcome, "failure");
        assert_eq!(exec.failure_reason, Some(FailureReason::InternalError));
        assert_eq!(exec.phase, "exec");
        assert_eq!(exec.correlation_vector, "iso:wxc-abcd");

        let errors = events::test_sink::take_errors();
        assert_eq!(errors.len(), 1, "panic emits exactly one MXC.Error");
        let error = &errors[0];
        assert_eq!(error.backend, "isolation_session");
        assert_eq!(error.error_type, FailureReason::InternalError);
        assert_eq!(error.exit_code, PANIC_EXIT_CODE);
        assert_eq!(error.phase, "exec");
        assert_eq!(error.correlation_vector, "iso:wxc-abcd");

        reset_for_test();
    }

    #[test]
    fn emit_cancellation_active_captures_execution_and_error() {
        // Same shape as the panic case, but the cancellation exit code (130)
        // and the `cancelled` category.
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        events::test_sink::install();
        TEST_FORCE_ACTIVE.with(|f| f.set(true));
        set_process_context(&ContainmentBackend::IsolationSession);
        set_process_phase("start");
        set_process_correlation_vector("iso:wxc-abcd");

        emit_cancellation();

        let execs = events::test_sink::take_executions();
        assert_eq!(execs.len(), 1);
        let exec = &execs[0];
        assert_eq!(exec.exit_code, CANCELLED_EXIT_CODE);
        assert_eq!(exec.outcome, "failure");
        assert_eq!(exec.failure_reason, Some(FailureReason::Cancelled));
        assert_eq!(exec.phase, "start");
        assert_eq!(exec.correlation_vector, "iso:wxc-abcd");

        let errors = events::test_sink::take_errors();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].error_type, FailureReason::Cancelled);
        assert_eq!(errors[0].exit_code, CANCELLED_EXIT_CODE);

        reset_for_test();
    }

    #[test]
    fn second_terminal_emit_is_suppressed_end_to_end() {
        // With the provider active, the first out-of-band emit claims the slot
        // and produces its record pair; a second (racing) emit must be fully
        // suppressed by the exactly-once guard — zero additional records.
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        events::test_sink::install();
        TEST_FORCE_ACTIVE.with(|f| f.set(true));
        set_process_context(&ContainmentBackend::IsolationSession);
        set_process_phase("exec");

        emit_panic();
        emit_cancellation();

        assert_eq!(
            events::test_sink::take_executions().len(),
            1,
            "second emit must not add an MXC.Execution"
        );
        assert_eq!(
            events::test_sink::take_errors().len(),
            1,
            "second emit must not add an MXC.Error"
        );

        reset_for_test();
    }

    #[test]
    fn terminal_emit_slot_is_exactly_once_and_resettable() {
        // The exactly-once slot (`HAS_EMITTED`) is concurrency-critical: the
        // out-of-band panic/cancellation paths race the main completion emit,
        // and the guard is what keeps a single dispatch from producing
        // duplicate MXC.Execution records. Lock the global state, reset to a
        // known baseline, and assert claim-once semantics end-to-end.
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();

        // First claim owns emission; the second (and any later) claim is told
        // a terminal event already fired, so the caller must skip.
        assert!(!already_emitted(), "first claim should own the slot");
        assert!(already_emitted(), "second claim must be suppressed");
        assert!(already_emitted(), "slot stays claimed until reset");

        // Reset clears the slot so a fresh process (test) starts clean again.
        reset_for_test();
        assert!(!already_emitted(), "reset must release the slot");

        // Leave the slot released for the next test holding the lock.
        reset_for_test();
    }

    #[test]
    fn reset_clears_stashed_process_context() {
        // reset_for_test must also clear the stashed backend/phase/correlation-id
        // so one test's context can't bleed into another's out-of-band
        // attribution.
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();

        set_process_context(&ContainmentBackend::IsolationSession);
        set_process_phase("provision");
        set_process_correlation_vector("iso:wxc-abcd");
        assert_eq!(process_backend(), "isolation_session");
        assert_eq!(process_phase(), "provision");
        assert_eq!(process_correlation_vector(), "iso:wxc-abcd");

        // Set-once: a second set is ignored while the slot is populated.
        set_process_phase("deprovision");
        assert_eq!(process_phase(), "provision", "phase is set-once");

        reset_for_test();
        assert_eq!(process_backend(), UNKNOWN_BACKEND);
        assert_eq!(process_phase(), "");
        assert_eq!(process_correlation_vector(), "");
    }

    #[test]
    fn emit_state_aware_noop_when_inactive() {
        // Inactive provider — must be a panic-free no-op for every outcome.
        let ok = Ok(DispatchOutcome::ExecCompleted { exit_code: 0 });
        emit_state_aware(
            false,
            TelemetryContext {
                backend: "isolation_session",
                phase: "exec",
                correlation_vector: "iso:wxc-abcd",
            },
            &ok,
            Duration::ZERO,
        );
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
        let event = crash_event(
            TelemetryContext {
                backend: "lxc",
                phase: "exec",
                correlation_vector: "iso:wxc-abcd",
            },
            PANIC_EXIT_CODE,
            FailureReason::InternalError,
        );
        assert_eq!(event.backend, "lxc");
        assert_eq!(event.phase, "exec");
        assert_eq!(event.correlation_vector, "iso:wxc-abcd");
        assert_eq!(event.exit_code, PANIC_EXIT_CODE);
        assert_eq!(event.outcome, "failure");
        assert_eq!(event.failure_reason, Some(FailureReason::InternalError));

        let cancel = crash_event(
            TelemetryContext {
                backend: "appcontainer",
                phase: "",
                correlation_vector: "",
            },
            CANCELLED_EXIT_CODE,
            FailureReason::Cancelled,
        );
        assert_eq!(cancel.phase, "");
        assert_eq!(cancel.correlation_vector, "");
        assert_eq!(cancel.exit_code, CANCELLED_EXIT_CODE);
        assert_eq!(cancel.failure_reason, Some(FailureReason::Cancelled));
    }

    #[test]
    fn plan_crash_maps_panic_and_cancellation_for_any_context() {
        // The pure mapper takes the attribution context as a parameter, so both
        // the panic and cancellation shapes are asserted deterministically across
        // backend/phase combinations without writing the set-once globals.
        let panic = plan_crash(
            TelemetryContext {
                backend: "lxc",
                phase: "exec",
                correlation_vector: "iso:wxc-abcd",
            },
            PANIC_EXIT_CODE,
            FailureReason::InternalError,
        );
        assert_eq!(panic.execution.backend, "lxc");
        assert_eq!(panic.execution.phase, "exec");
        assert_eq!(panic.execution.correlation_vector, "iso:wxc-abcd");
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
            TelemetryContext {
                backend: "isolation_session",
                phase: "",
                correlation_vector: "",
            },
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
    fn plan_state_aware_matrix_over_phases_and_outcomes() {
        // Full {provision, start, exec, stop, deprovision} × {envelope success,
        // zero guest exit, non-zero guest exit, MxcError} matrix. A non-zero
        // guest exit realistically only occurs on `exec`, but plan_state_aware
        // is phase-agnostic, so exercising every phase validates the mxc.phase
        // (and the __TlgCV__ correlation vector) threading as well as the outcome mapping.
        const PHASES: [&str; 5] = ["provision", "start", "exec", "stop", "deprovision"];
        let correlation = "corr-abcd1234";

        for phase in PHASES {
            let ctx = TelemetryContext {
                backend: "isolation_session",
                phase,
                correlation_vector: correlation,
            };

            // Envelope success → success / exit 0 / no error.
            let envelope = Ok(DispatchOutcome::Envelope(serde_json::json!({})));
            let plan = plan_state_aware(ctx, &envelope, 7);
            assert_eq!(plan.execution.phase, phase);
            assert_eq!(plan.execution.correlation_vector, correlation);
            assert_eq!(plan.execution.outcome, "success");
            assert_eq!(plan.execution.exit_code, 0);
            assert_eq!(plan.execution.duration_ms, 7);
            assert!(plan.execution.failure_reason.is_none());
            assert!(plan.error.is_none());

            // Zero guest exit is also a clean success.
            let zero = Ok(DispatchOutcome::ExecCompleted { exit_code: 0 });
            let zero_plan = plan_state_aware(ctx, &zero, 0);
            assert_eq!(zero_plan.execution.phase, phase);
            assert_eq!(zero_plan.execution.correlation_vector, correlation);
            assert_eq!(zero_plan.execution.outcome, "success");
            assert_eq!(zero_plan.execution.exit_code, 0);
            assert!(zero_plan.error.is_none());

            // Non-zero guest exit → failure with the propagated exit code, but
            // NO MXC.Error (a faithfully-propagated script exit, not an MXC
            // failure).
            let nonzero = Ok(DispatchOutcome::ExecCompleted { exit_code: 42 });
            let nonzero_plan = plan_state_aware(ctx, &nonzero, 3);
            assert_eq!(nonzero_plan.execution.phase, phase);
            assert_eq!(nonzero_plan.execution.correlation_vector, correlation);
            assert_eq!(nonzero_plan.execution.outcome, "failure");
            assert_eq!(nonzero_plan.execution.exit_code, 42);
            assert!(nonzero_plan.execution.failure_reason.is_none());
            assert!(nonzero_plan.error.is_none());

            // MxcError → failure / exit 1 / classified MXC.Error.
            let err = Err(MxcError::backend_unavailable("no host"));
            let err_plan = plan_state_aware(ctx, &err, 5);
            assert_eq!(err_plan.execution.phase, phase);
            assert_eq!(err_plan.execution.correlation_vector, correlation);
            assert_eq!(err_plan.execution.outcome, "failure");
            assert_eq!(err_plan.execution.exit_code, 1);
            assert_eq!(
                err_plan.execution.failure_reason,
                Some(FailureReason::InitError)
            );
            assert_eq!(err_plan.error, Some(FailureReason::InitError));
        }
    }

    #[test]
    fn set_process_context_records_backend() {
        // Touches the process-global set-once PROCESS_BACKEND, so serialize on
        // TEST_LOCK and reset to a clean baseline first.
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        set_process_context(&ContainmentBackend::Lxc);
        assert_eq!(process_backend(), "lxc");
        reset_for_test();
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
        // A rejected request is a policy error; a post-launch infra failure
        // is an init error.
        assert_eq!(
            classify_failure(&FailurePhase::Rejected),
            FailureReason::PolicyError
        );
        assert_eq!(
            classify_failure(&FailurePhase::PostLaunchFailed),
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

    #[test]
    fn emit_state_aware_production_path_captures_records() {
        // Exercises the real `emit_state_aware` glue (not just the pure
        // `plan_state_aware` mapper): active guard → exactly-once slot → paired
        // ETW writes → shutdown. Asserts the captured records carry the threaded
        // phase + correlation vector for both a success envelope and an MxcError.
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        events::test_sink::install();

        // Provision-style success envelope → one MXC.Execution, no MXC.Error.
        let envelope = Ok(DispatchOutcome::Envelope(serde_json::json!({})));
        emit_state_aware(
            true,
            TelemetryContext {
                backend: "isolation_session",
                phase: "provision",
                correlation_vector: "corr-provision",
            },
            &envelope,
            Duration::from_millis(4),
        );
        let execs = events::test_sink::take_executions();
        assert_eq!(execs.len(), 1);
        assert_eq!(execs[0].phase, "provision");
        assert_eq!(execs[0].correlation_vector, "corr-provision");
        assert_eq!(execs[0].outcome, "success");
        assert!(events::test_sink::take_errors().is_empty());

        // Fresh slot for the error case (the emit above claimed it once).
        reset_for_test();
        events::test_sink::install();
        let err = Err(MxcError::policy_validation("bad policy"));
        emit_state_aware(
            true,
            TelemetryContext {
                backend: "isolation_session",
                phase: "start",
                correlation_vector: "corr-start",
            },
            &err,
            Duration::from_millis(2),
        );
        let execs = events::test_sink::take_executions();
        assert_eq!(execs.len(), 1);
        assert_eq!(execs[0].phase, "start");
        assert_eq!(execs[0].correlation_vector, "corr-start");
        assert_eq!(execs[0].outcome, "failure");
        let errors = events::test_sink::take_errors();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].error_type, FailureReason::PolicyError);
        assert_eq!(errors[0].phase, "start");
        assert_eq!(errors[0].correlation_vector, "corr-start");

        reset_for_test();
    }

    // Validates that the emit guard honors the *real* `mxc_telemetry` provider —
    // not just the `TEST_FORCE_ACTIVE` override — by registering the provider for
    // real (only possible on Windows) and asserting `emit_panic` captures without
    // any forced-active flag set.
    #[cfg(windows)]
    #[test]
    fn emit_honors_real_provider_activation() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        events::test_sink::install();

        // Register the real ETW provider; on Windows this makes is_active() true.
        assert!(
            mxc_telemetry::init(version(), MXC_CHANNEL),
            "provider registration should succeed on Windows"
        );
        assert!(mxc_telemetry::is_active());
        // Deliberately do NOT set TEST_FORCE_ACTIVE — the emit must proceed off
        // the real provider state alone.
        set_process_context(&ContainmentBackend::IsolationSession);
        set_process_phase("exec");

        emit_panic();

        assert_eq!(
            events::test_sink::take_executions().len(),
            1,
            "emit must fire off the real active provider without TEST_FORCE_ACTIVE"
        );

        mxc_telemetry::shutdown();
        reset_for_test();
    }
}
