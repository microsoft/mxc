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

pub mod consent;
pub mod consent_cli;
pub mod consent_prompt;
pub mod correlation_state;
pub mod correlation_vector;
pub mod events;
pub mod policy;

use std::time::Duration;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use crate::logger::Logger;
use crate::models::{ContainmentBackend, FailurePhase, ScriptResponse, TelemetryConfig};
use crate::mxc_error::{MxcError, MxcErrorCode};
use crate::state_aware_dispatch::DispatchOutcome;

pub use consent::ConsentState;
pub use events::{log_error, log_execution, ExecutionEvent, FailureReason, TelemetryContext};
pub use policy::PolicyState;

#[cfg(target_os = "windows")]
#[derive(Default)]
struct FailureReporter {
    reported: Mutex<std::collections::HashSet<String>>,
}

#[cfg(target_os = "windows")]
impl FailureReporter {
    fn report(&self, signature: String, emit: impl FnOnce(&str)) {
        let is_new = self
            .reported
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(signature.clone());
        if is_new {
            emit(&signature);
        }
    }
}

#[cfg(any(test, all(feature = "test-support", debug_assertions)))]
pub mod test_support {
    use super::consent::test_support::LocalAppDataGuard;
    use super::policy::test_support::PolicyKeyGuard;

    /// Lock-order-safe redirect guard for tests that need both the consent
    /// store and the policy key redirected away from real user/machine state.
    pub struct TelemetryTestEnv {
        _consent: LocalAppDataGuard,
        policy: PolicyKeyGuard,
    }

    impl TelemetryTestEnv {
        /// Redirect both telemetry globals for the lifetime of the guard.
        pub fn new(store: &std::path::Path) -> Self {
            let policy = PolicyKeyGuard::new();
            let _consent = LocalAppDataGuard::set(store);
            Self { _consent, policy }
        }

        #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
        pub fn set_policy_value(&self, value: u32) {
            self.policy.set_value(value);
        }
    }
}

/// Conventional process exit code for a Rust panic/abort. Used as the reported
/// `exit_code` on crash telemetry, since the panicking process has not (and
/// will not) produce a real [`ScriptResponse`].
const PANIC_EXIT_CODE: i32 = 101;

/// Reported exit code for a cancelled run.
const CANCELLED_EXIT_CODE: i32 = 130;

/// Backend attribution for out-of-band events.
static PROCESS_BACKEND: Mutex<Option<&'static str>> = Mutex::new(None);

/// Caller-requested containment attribution for out-of-band events.
static PROCESS_SANDBOX_KIND: Mutex<Option<&'static str>> = Mutex::new(None);

/// State-aware phase attribution for out-of-band events.
static PROCESS_PHASE: Mutex<Option<&'static str>> = Mutex::new(None);

/// Correlation-vector attribution for out-of-band events.
static PROCESS_CORRELATION_VECTOR: Mutex<Option<String>> = Mutex::new(None);

/// Prevents duplicate terminal events for one executor process.
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
    /// Optional authorization result used to prove the live gate independently
    /// of platform consent storage.
    static TEST_AUTHORIZATION_OVERRIDE: std::cell::Cell<Option<bool>> = const {
        std::cell::Cell::new(None)
    };
}

/// Whether the provider is active, including the test override.
fn emit_active() -> bool {
    #[cfg(test)]
    if TEST_FORCE_ACTIVE.with(|f| f.get()) {
        return true;
    }
    mxc_telemetry::is_active()
}

/// Evaluate consent and policy for one complete logical emission.
fn authorization_allows_emission() -> bool {
    #[cfg(test)]
    if let Some(allowed) = TEST_AUTHORIZATION_OVERRIDE.with(|value| value.get()) {
        return allowed;
    }

    consent::get_consent().allows_collection() && policy::get_policy().allows_collection()
}

fn invocation_can_emit(active: bool) -> bool {
    active && authorization_allows_emission()
}

fn process_can_emit() -> bool {
    emit_active() && authorization_allows_emission()
}

/// Proof that one complete logical telemetry emission is authorized.
///
/// Pair-writing helpers require this token so their `Execution` and `Error`
/// events share one consent and policy decision without repeating blocking
/// storage reads between the two writes.
///
/// The type is zero-sized, not `Copy`/`Clone`, and has a private constructor,
/// so it cannot be forged, split across unrelated emissions, or reused after
/// authorization has already been consumed by a previous emission.
#[must_use = "an emission authorization does nothing unless events are written under it"]
struct EmissionAuthorization {
    _private: (),
}

impl EmissionAuthorization {
    /// Evaluate the authorization decision for a request-scoped emission
    /// (the one-shot completion / early-exit / state-aware paths). Returns
    /// `Some` only when the caller's cached `active` flag *and* the current
    /// authorization state (consent && policy) both permit emission.
    fn for_invocation(active: bool) -> Option<Self> {
        invocation_can_emit(active).then_some(Self { _private: () })
    }

    /// Evaluate the authorization decision for a process-scoped, out-of-band
    /// emission — used by the panic hook and the console-control (Ctrl-C)
    /// handler, where no request context is in scope. Consults the live
    /// provider state via [`emit_active`] rather than a cached `active` flag.
    fn for_process() -> Option<Self> {
        process_can_emit().then_some(Self { _private: () })
    }
}
/// Claim the terminal-event slot for this process.
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
    *PROCESS_SANDBOX_KIND
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = None;
    *PROCESS_PHASE.lock().unwrap_or_else(|e| e.into_inner()) = None;
    *PROCESS_CORRELATION_VECTOR
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = None;
    TEST_FORCE_ACTIVE.with(|f| f.set(false));
    TEST_AUTHORIZATION_OVERRIDE.with(|value| value.set(None));
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

/// Returns whether this invocation may emit telemetry.
pub fn is_enabled(config: &TelemetryConfig) -> bool {
    // Only an explicit opt-in enables telemetry for this invocation.
    if config.enabled != Some(true) {
        return false;
    }
    policy::get_policy().allows_collection() && consent::get_consent().allows_collection()
}

/// Initialize the telemetry provider when the gates allow it.
pub fn init(config: &TelemetryConfig, logger: &mut Logger) -> bool {
    if !is_enabled(config) {
        log_suppression_reason(config, logger);
        return false;
    }

    let activated = mxc_telemetry::init(MXC_VERSION, MXC_CHANNEL);
    if !activated && cfg!(target_os = "windows") {
        logger
            .log_line("telemetry: ETW provider registration failed; continuing without telemetry");
    }
    if activated && !mxc_telemetry::IS_UTC_ROUTED {
        logger.log_line(
            "telemetry: events are emitted to local ETW only; this build has no provider group \
             GUID, so nothing is routed to the Microsoft pipeline (set \
             MXC_TELEMETRY_PROVIDER_GROUP_GUID at build time for an internal build)",
        );
    }
    activated
}

/// Explain, on the diagnostic log, exactly which gate turned telemetry off.
///
/// Without this an operator who set `telemetry.enabled: true` sees no events
/// and no reason — every gate fails closed and silently. Each conjunct of
/// [`is_enabled`] is reported independently so the log distinguishes "the run
/// never asked" from "the user has not consented" from "an administrator
/// blocked it".
fn log_suppression_reason(config: &TelemetryConfig, logger: &mut Logger) {
    if config.enabled != Some(true) {
        logger.log_line("telemetry: not requested for this run (telemetry.enabled is not true)");
        return;
    }

    let policy = policy::get_policy();
    let consent = consent::get_consent();
    logger.log_line(&format!(
        "telemetry: requested but suppressed (consent={}, policy={}); \
         MXC consent is independent of the Windows diagnostic-data setting",
        consent.as_str(),
        policy.as_str()
    ));
}

/// Unregister the telemetry provider.
pub fn shutdown() {
    mxc_telemetry::shutdown();
}

fn sandbox_kind_for<'a>(backend: &'a str, requested: Option<&'a str>) -> &'a str {
    requested.unwrap_or(backend)
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

/// Emit completion telemetry for an executor invocation.
pub fn emit_completion(
    active: bool,
    containment: &ContainmentBackend,
    response: &ScriptResponse,
    elapsed: Duration,
) {
    emit_completion_with_kind(active, containment, None, response, elapsed);
}

/// Emit completion telemetry with the caller-requested containment kind.
pub fn emit_completion_with_kind(
    active: bool,
    containment: &ContainmentBackend,
    requested_sandbox_kind: Option<&'static str>,
    response: &ScriptResponse,
    elapsed: Duration,
) {
    let Some(auth) = EmissionAuthorization::for_invocation(active) else {
        return;
    };
    if already_emitted() {
        return;
    }
    emit_completion_event(
        &auth,
        containment,
        response,
        elapsed,
        requested_sandbox_kind,
    );
    shutdown();
}

fn emit_completion_event(
    _auth: &EmissionAuthorization,
    containment: &ContainmentBackend,
    response: &ScriptResponse,
    elapsed: Duration,
    requested_sandbox_kind: Option<&str>,
) {
    // The `_auth` parameter is the single authorization token for this
    // emission (see `EmissionAuthorization`). Both writes below execute under
    // it — there is no per-write reread of consent/policy state.
    let backend = containment.wire_name();
    let sandbox_kind = sandbox_kind_for(backend, requested_sandbox_kind);
    let failed = response.exit_code != 0;
    let outcome = if failed { "failure" } else { "success" };
    let failure_reason = failed.then(|| classify_failure(&response.failure_phase));

    log_execution(&ExecutionEvent {
        backend,
        sandbox_kind,
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
            sandbox_kind,
            classify_failure(&response.failure_phase),
            response.exit_code,
        );
    }
}

/// Emit completion telemetry for an in-process SDK invocation.
///
/// Unlike [`emit_completion`], this does not use the executable-wide
/// exactly-once slot: SDK processes may run multiple or concurrent sandboxes,
/// and their handle wrappers enforce exactly-once emission per invocation.
pub fn emit_sdk_completion(
    active: bool,
    containment: &ContainmentBackend,
    response: &ScriptResponse,
    elapsed: Duration,
) {
    emit_sdk_completion_with_kind(active, containment, None, response, elapsed);
}

/// Emit SDK completion telemetry with the request-scoped sandbox kind.
pub fn emit_sdk_completion_with_kind(
    active: bool,
    containment: &ContainmentBackend,
    requested_sandbox_kind: Option<&'static str>,
    response: &ScriptResponse,
    elapsed: Duration,
) {
    emit_sdk_with_release(active, |auth| {
        emit_completion_event(auth, containment, response, elapsed, requested_sandbox_kind)
    });
}

/// Emit failure telemetry for an early-exit path that terminates **before** a
/// runner produces a [`ScriptResponse`], then shut the provider down. No-op
/// when `active` is `false`.
///
/// One-shot executors validate configuration and select a backend before
/// running; failures there call `process::exit` directly and would otherwise
/// bypass [`emit_completion`] entirely. This records an `Execution` event
/// (exit code 1, `failure` outcome) plus an `Error` event carrying the
/// bounded `reason` category and exit code, so config/policy/init failures are
/// observable. `duration_ms` is reported as `0` because no execution occurred.
pub fn emit_early_exit(active: bool, containment: &ContainmentBackend, reason: FailureReason) {
    emit_early_exit_with_kind(active, containment, None, reason);
}

/// Emit early-exit telemetry with the caller-requested containment kind.
pub fn emit_early_exit_with_kind(
    active: bool,
    containment: &ContainmentBackend,
    requested_sandbox_kind: Option<&'static str>,
    reason: FailureReason,
) {
    let Some(auth) = EmissionAuthorization::for_invocation(active) else {
        return;
    };
    if already_emitted() {
        return;
    }
    emit_early_exit_event(&auth, containment, reason, requested_sandbox_kind);
    shutdown();
}

fn emit_early_exit_event(
    _auth: &EmissionAuthorization,
    containment: &ContainmentBackend,
    reason: FailureReason,
    requested_sandbox_kind: Option<&str>,
) {
    // The `_auth` parameter is the single authorization token for this
    // emission (see `EmissionAuthorization`). Both writes below execute under
    // it — there is no per-write reread of consent/policy state.
    let backend = containment.wire_name();
    let sandbox_kind = sandbox_kind_for(backend, requested_sandbox_kind);

    log_execution(&ExecutionEvent {
        backend,
        sandbox_kind,
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
        sandbox_kind,
        reason,
        1,
    );
}

/// Emit an SDK spawn failure without claiming the executable-wide terminal slot.
pub fn emit_sdk_early_exit(active: bool, containment: &ContainmentBackend, reason: FailureReason) {
    emit_sdk_early_exit_with_kind(active, containment, None, reason);
}

/// Emit SDK early-exit telemetry with the request-scoped sandbox kind.
pub fn emit_sdk_early_exit_with_kind(
    active: bool,
    containment: &ContainmentBackend,
    requested_sandbox_kind: Option<&'static str>,
    reason: FailureReason,
) {
    emit_sdk_with_release(active, |auth| {
        emit_early_exit_event(auth, containment, reason, requested_sandbox_kind)
    });
}

fn emit_sdk_with_release(active: bool, emit: impl FnOnce(&EmissionAuthorization)) {
    if !active {
        return;
    }
    if let Some(auth) = EmissionAuthorization::for_invocation(active) {
        emit(&auth);
    }
    shutdown();
}

/// Record the containment backend for this process so best-effort emit paths
/// that have no [`ScriptResponse`] in scope (the panic hook and the console
/// control handler) can attribute their events.
///
/// Call once, immediately after a successful [`init`]. Later calls are ignored
/// (the value is set-once).
pub fn set_process_context(containment: &ContainmentBackend) {
    set_process_context_with_kind(containment, None);
}

/// Record both the resolved backend and the caller-requested containment kind
/// for out-of-band events.
pub fn set_process_context_with_kind(
    containment: &ContainmentBackend,
    requested_sandbox_kind: Option<&'static str>,
) {
    let backend = containment.wire_name();
    let mut slot = PROCESS_BACKEND.lock().unwrap_or_else(|e| e.into_inner());
    if slot.is_none() {
        *slot = Some(backend);
    }
    drop(slot);

    let mut slot = PROCESS_SANDBOX_KIND
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if slot.is_none() {
        *slot = Some(sandbox_kind_for(backend, requested_sandbox_kind));
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

/// The caller-requested containment kind, defaulting to the resolved backend
/// when no request-scoped value was recorded.
fn process_sandbox_kind() -> &'static str {
    PROCESS_SANDBOX_KIND
        .try_lock()
        .ok()
        .and_then(|slot| *slot)
        .unwrap_or_else(process_backend)
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

/// Build the `Execution` event for an out-of-band crash/cancellation. Pure
/// (no ETW I/O) so the exit-code/reason/attribution mapping can be unit-tested.
#[cfg(test)]
fn crash_event<'a>(
    ctx: TelemetryContext<'a>,
    exit_code: i32,
    reason: FailureReason,
) -> ExecutionEvent<'a> {
    crash_event_with_kind(ctx, ctx.backend, exit_code, reason)
}

fn crash_event_with_kind<'a>(
    ctx: TelemetryContext<'a>,
    sandbox_kind: &'a str,
    exit_code: i32,
    reason: FailureReason,
) -> ExecutionEvent<'a> {
    ExecutionEvent {
        backend: ctx.backend,
        sandbox_kind,
        exit_code,
        outcome: "failure",
        duration_ms: 0,
        failure_reason: Some(reason),
        phase: ctx.phase,
        correlation_vector: ctx.correlation_vector,
    }
}

/// The pair of events an out-of-band crash/cancellation emits: one failure
/// `Execution` and one `Error`, both attributed to the same backend,
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
#[cfg(test)]
fn plan_crash<'a>(
    ctx: TelemetryContext<'a>,
    exit_code: i32,
    reason: FailureReason,
) -> CrashTelemetry<'a> {
    plan_crash_with_kind(ctx, ctx.backend, exit_code, reason)
}

fn plan_crash_with_kind<'a>(
    ctx: TelemetryContext<'a>,
    sandbox_kind: &'a str,
    exit_code: i32,
    reason: FailureReason,
) -> CrashTelemetry<'a> {
    CrashTelemetry {
        execution: crash_event_with_kind(ctx, sandbox_kind, exit_code, reason),
        error: reason,
        exit_code,
    }
}

/// Emit the planned crash/cancellation events. The thin I/O tail shared by
/// [`emit_panic`] and [`emit_cancellation`]: it performs the two ETW writes and
/// deliberately does **not** call [`shutdown`] (see the callers' docs). Takes
/// resolved attribution so the pure [`plan_crash`] mapping stays testable.
///
/// The `_auth` parameter is the single authorization token for this emission
/// (see [`EmissionAuthorization`]). Both writes below execute under it — no
/// per-write reread of consent/policy state.
fn emit_crash(
    _auth: &EmissionAuthorization,
    ctx: TelemetryContext<'_>,
    sandbox_kind: &str,
    exit_code: i32,
    reason: FailureReason,
) {
    let plan = plan_crash_with_kind(ctx, sandbox_kind, exit_code, reason);
    log_execution(&plan.execution);
    log_error(ctx, sandbox_kind, plan.error, plan.exit_code);
}

/// Emit crash telemetry from a global panic hook.
///
/// Guarded by [`mxc_telemetry::is_active`], so it is a cheap no-op when
/// telemetry is disabled or the provider is already shut down. It records a
/// failure `Execution` and an `Error` categorised as
/// [`FailureReason::InternalError`], attributed to the process backend stashed
/// by [`set_process_context`] and the phase stashed by [`set_process_phase`].
///
/// Unlike [`emit_completion`]/[`emit_early_exit`], this deliberately does **not**
/// call [`shutdown`]: it runs while the thread is unwinding (or about to abort),
/// where the OS reclaims the ETW registration at process exit. It also carries
/// **no** panic message text, which can contain paths or other PII.
pub fn emit_panic() {
    let Some(auth) = EmissionAuthorization::for_process() else {
        return;
    };
    if already_emitted() {
        return;
    }
    let correlation_vector = process_correlation_vector();
    emit_crash(
        &auth,
        TelemetryContext {
            backend: process_backend(),
            phase: process_phase(),
            correlation_vector: &correlation_vector,
        },
        process_sandbox_kind(),
        PANIC_EXIT_CODE,
        FailureReason::InternalError,
    );
}

/// Emit cancellation telemetry from a console control (Ctrl-C / close / shutdown)
/// handler.
///
/// Guarded by [`mxc_telemetry::is_active`], so it is a cheap no-op when
/// telemetry is disabled or already shut down. It records a failure
/// `Execution` and an `Error` categorised as [`FailureReason::Cancelled`],
/// attributed to the process backend stashed by [`set_process_context`] and the
/// phase stashed by [`set_process_phase`].
///
/// Like [`emit_panic`], it deliberately does **not** call [`shutdown`]: the
/// handler runs on a short OS-imposed budget just before the default handler
/// tears the process down via `ExitProcess`, and the main thread may still be
/// live. It is allocation-light and emits no free-form text.
pub fn emit_cancellation() {
    let Some(auth) = EmissionAuthorization::for_process() else {
        return;
    };
    if already_emitted() {
        return;
    }
    let correlation_vector = process_correlation_vector();
    emit_crash(
        &auth,
        TelemetryContext {
            backend: process_backend(),
            phase: process_phase(),
            correlation_vector: &correlation_vector,
        },
        process_sandbox_kind(),
        CANCELLED_EXIT_CODE,
        FailureReason::Cancelled,
    );
}

/// Map an [`MxcError`] surfaced by state-aware dispatch to a bounded
/// [`FailureReason`]. Exhaustive over [`MxcErrorCode`] so a newly-added code
/// forces a compile error here rather than silently classifying as `Unknown`.
///
/// Public so the streaming SDK path (`mxc_engine::spawn`) can preserve the
/// actual error category on early-exit telemetry rather than reporting every
/// dispatch failure as `InitError`.
pub fn classify_mxc_error(err: &MxcError) -> FailureReason {
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
/// `Execution`, plus an optional `Error` category when the dispatch was
/// an MXC infrastructure failure. Pure (no ETW I/O) so the outcome→event mapping
/// can be unit-tested deterministically without an active provider.
struct StateAwareEvents<'a> {
    execution: ExecutionEvent<'a>,
    error: Option<FailureReason>,
}

/// Pure outcome→events mapping shared by [`emit_state_aware`] and its tests.
/// See [`emit_state_aware`] for the mapping rationale.
#[cfg(test)]
fn plan_state_aware<'a>(
    ctx: TelemetryContext<'a>,
    outcome: &Result<DispatchOutcome, MxcError>,
    duration_ms: u64,
) -> StateAwareEvents<'a> {
    plan_state_aware_with_kind(ctx, outcome, duration_ms, ctx.backend)
}

fn plan_state_aware_with_kind<'a>(
    ctx: TelemetryContext<'a>,
    outcome: &Result<DispatchOutcome, MxcError>,
    duration_ms: u64,
    sandbox_kind: &'a str,
) -> StateAwareEvents<'a> {
    match outcome {
        Ok(DispatchOutcome::Envelope(_)) => StateAwareEvents {
            execution: ExecutionEvent {
                backend: ctx.backend,
                sandbox_kind,
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
                    sandbox_kind,
                    exit_code: *exit_code,
                    outcome: if failed { "failure" } else { "success" },
                    duration_ms,
                    // A non-zero guest exit is a faithfully propagated sandbox
                    // exit code, not an MXC infrastructure error — leave the
                    // reason unset and emit no Error (mirrors one-shot
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
                    sandbox_kind,
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
/// - [`DispatchOutcome::ExecCompleted`] — mirrors one-shot: an `Execution`
///   with the sandbox exit code. A clean non-zero *sandbox* exit is not an MXC
///   failure, so no `Error` is emitted.
/// - `Err(MxcError)` — an `Execution` failure plus an `Error` carrying
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
    emit_state_aware_with_kind(active, None, ctx, outcome, elapsed);
}

/// Emit state-aware telemetry with the caller-requested containment kind.
pub fn emit_state_aware_with_kind(
    active: bool,
    requested_sandbox_kind: Option<&'static str>,
    ctx: TelemetryContext<'_>,
    outcome: &Result<DispatchOutcome, MxcError>,
    elapsed: Duration,
) {
    let Some(auth) = EmissionAuthorization::for_invocation(active) else {
        return;
    };
    if already_emitted() {
        return;
    }
    emit_state_aware_event(&auth, ctx, outcome, elapsed, requested_sandbox_kind);
    shutdown();
}

fn emit_state_aware_event(
    _auth: &EmissionAuthorization,
    ctx: TelemetryContext<'_>,
    outcome: &Result<DispatchOutcome, MxcError>,
    elapsed: Duration,
    requested_sandbox_kind: Option<&str>,
) {
    // The `_auth` parameter is the single authorization token for this
    // emission (see `EmissionAuthorization`). Both writes below execute under
    // it — there is no per-write reread of consent/policy state.
    let duration_ms = elapsed.as_millis() as u64;
    let sandbox_kind = sandbox_kind_for(ctx.backend, requested_sandbox_kind);
    let plan = plan_state_aware_with_kind(ctx, outcome, duration_ms, sandbox_kind);

    log_execution(&plan.execution);
    if let Some(reason) = plan.error {
        log_error(ctx, sandbox_kind, reason, plan.execution.exit_code);
    }
}

/// Emit telemetry for an in-process SDK state-aware invocation.
///
/// The SDK wrapper owns exactly-once emission for its request/handle, so this
/// bypasses the executable-wide terminal slot used by `wxc-exec`.
pub fn emit_sdk_state_aware(
    active: bool,
    ctx: TelemetryContext<'_>,
    outcome: &Result<DispatchOutcome, MxcError>,
    elapsed: Duration,
) {
    emit_sdk_state_aware_with_kind(active, None, ctx, outcome, elapsed);
}

/// Emit SDK state-aware telemetry with request-scoped attribution.
pub fn emit_sdk_state_aware_with_kind(
    active: bool,
    requested_sandbox_kind: Option<&'static str>,
    ctx: TelemetryContext<'_>,
    outcome: &Result<DispatchOutcome, MxcError>,
    elapsed: Duration,
) {
    emit_sdk_with_release(active, |auth| {
        emit_state_aware_event(auth, ctx, outcome, elapsed, requested_sandbox_kind)
    });
}

/// Emit a confirmed SDK streaming-handle cancellation and release the
/// invocation's provider reference.
///
/// This is separate from generic completion mapping because an explicit,
/// successful [`SandboxProcess::kill`](crate::sandbox_process::SandboxProcess::kill)
/// is a cancellation, not an initialization or process failure.
pub fn emit_sdk_cancellation_with_kind(
    active: bool,
    requested_sandbox_kind: Option<&'static str>,
    ctx: TelemetryContext<'_>,
    elapsed: Duration,
) {
    emit_sdk_with_release(active, |auth| {
        let _auth = auth;
        let sandbox_kind = sandbox_kind_for(ctx.backend, requested_sandbox_kind);
        log_execution(&ExecutionEvent {
            backend: ctx.backend,
            sandbox_kind,
            exit_code: CANCELLED_EXIT_CODE,
            outcome: "failure",
            duration_ms: elapsed.as_millis() as u64,
            failure_reason: Some(FailureReason::Cancelled),
            phase: ctx.phase,
            correlation_vector: ctx.correlation_vector,
        });
        log_error(
            ctx,
            sandbox_kind,
            FailureReason::Cancelled,
            CANCELLED_EXIT_CODE,
        );
    });
}

#[cfg(test)]
mod tests {
    use super::test_support::TelemetryTestEnv;
    use super::*;

    /// Serializes tests that touch the process-global emit slot / context
    /// (`HAS_EMITTED`, `PROCESS_BACKEND`, `PROCESS_PHASE`, `PROCESS_CORRELATION_VECTOR`)
    /// or drive the emit paths, so their global state can't leak across tests.
    /// Mirrors the `TEST_LOCK` pattern in `mxc_telemetry`.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn is_enabled_explicit_true_alone_does_not_bypass_consent() {
        // Consent isolated to a fresh, empty store (Undetermined) — an
        // explicit `enabled: true` in the config must not be able to turn
        // telemetry on for someone who has not granted consent.
        let tmp = tempfile::tempdir().unwrap();
        let _env = TelemetryTestEnv::new(tmp.path());
        let config = TelemetryConfig {
            enabled: Some(true),
            ..Default::default()
        };
        assert!(!is_enabled(&config));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn is_enabled_true_when_consent_granted() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = TelemetryTestEnv::new(tmp.path());
        consent::set_consent(true, "cli").unwrap();
        // An explicit opt-in is required in addition to consent.
        assert!(is_enabled(&TelemetryConfig {
            enabled: Some(true),
            ..Default::default()
        }));
    }

    /// An administrative denial overrides an explicit user grant. This is the
    /// MDM/Intune ceiling: policy can only ever subtract.
    #[cfg(target_os = "windows")]
    #[test]
    fn is_enabled_false_when_policy_blocks_despite_consent() {
        let tmp = tempfile::tempdir().unwrap();
        let env = TelemetryTestEnv::new(tmp.path());
        consent::set_consent(true, "cli").unwrap();
        env.set_policy_value(0);

        assert!(!is_enabled(&TelemetryConfig {
            enabled: Some(true),
            ..Default::default()
        }));
    }

    /// The converse, and the load-bearing privacy invariant: a permissive
    /// administrative policy is *not* consent. An admin who allows telemetry
    /// has not decided on the user's behalf.
    #[cfg(target_os = "windows")]
    #[test]
    fn is_enabled_false_when_policy_allows_but_consent_is_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let env = TelemetryTestEnv::new(tmp.path());
        env.set_policy_value(3);

        assert_eq!(policy::get_policy(), policy::PolicyState::Allowed);
        assert!(!is_enabled(&TelemetryConfig {
            enabled: Some(true),
            ..Default::default()
        }));
    }

    /// Explicit user denial must beat every policy state — including a
    /// permissive one. Completes the consent × policy matrix.
    #[cfg(target_os = "windows")]
    #[test]
    fn is_enabled_false_when_consent_denied_under_every_policy() {
        for policy_value in [None, Some(0u32), Some(1), Some(3)] {
            let tmp = tempfile::tempdir().unwrap();
            let env = TelemetryTestEnv::new(tmp.path());
            consent::set_consent(false, "cli").unwrap();
            if let Some(value) = policy_value {
                env.set_policy_value(value);
            }

            assert!(
                !is_enabled(&TelemetryConfig {
                    enabled: Some(true),
                    ..Default::default()
                }),
                "denied consent must win over explicit enable under policy {policy_value:?}"
            );
        }
    }

    /// The policy is a ceiling, never a grant: no policy value may enable
    /// telemetry for a user who has never recorded a decision. `Denied` is
    /// covered above; this covers the fresh-machine `Undetermined` case, which
    /// is the one a permissive policy could plausibly be mistaken for a grant.
    #[cfg(target_os = "windows")]
    #[test]
    fn is_enabled_false_when_consent_undetermined_under_every_policy() {
        for policy_value in [None, Some(0u32), Some(1), Some(3)] {
            let tmp = tempfile::tempdir().unwrap();
            let env = TelemetryTestEnv::new(tmp.path());
            if let Some(value) = policy_value {
                env.set_policy_value(value);
            }

            assert_eq!(consent::get_consent(), consent::ConsentState::Undetermined);
            assert!(
                !is_enabled(&TelemetryConfig {
                    enabled: Some(true),
                    ..Default::default()
                }),
                "undetermined consent must block an explicit enable under policy {policy_value:?}"
            );
        }
    }

    #[test]
    fn is_enabled_explicit_false() {
        // The kill switch wins even when consent has been granted.
        let tmp = tempfile::tempdir().unwrap();
        let _env = TelemetryTestEnv::new(tmp.path());
        #[cfg(target_os = "windows")]
        consent::set_consent(true, "cli").unwrap();
        let config = TelemetryConfig {
            enabled: Some(false),
            ..Default::default()
        };
        assert!(!is_enabled(&config));
    }

    #[test]
    fn is_enabled_default_off() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = TelemetryTestEnv::new(tmp.path());
        let config = TelemetryConfig::default();
        assert!(!is_enabled(&config));
    }

    /// The load-bearing half of "omitted = off". Without granting consent
    /// first this test would pass for the wrong reason — a fresh store is
    /// `Undetermined`, which disables telemetry on its own — and would keep
    /// passing if omission silently started meaning "defer to consent".
    #[cfg(target_os = "windows")]
    #[test]
    fn is_enabled_false_when_enabled_omitted_despite_consent_and_permissive_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let env = TelemetryTestEnv::new(tmp.path());
        consent::set_consent(true, "cli").unwrap();
        env.set_policy_value(3);

        assert_eq!(consent::get_consent(), consent::ConsentState::Granted);
        assert_eq!(policy::get_policy(), policy::PolicyState::Allowed);
        // Every other gate is open; only the omitted opt-in keeps it off.
        assert!(!is_enabled(&TelemetryConfig {
            enabled: None,
            ..Default::default()
        }));
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
    fn live_authorization_gate_suppresses_and_then_allows_emission() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        events::test_sink::install();
        TEST_FORCE_ACTIVE.with(|active| active.set(true));
        TEST_AUTHORIZATION_OVERRIDE.with(|allowed| allowed.set(Some(false)));
        set_process_context(&ContainmentBackend::IsolationSession);

        emit_panic();
        assert!(events::test_sink::take_executions().is_empty());
        assert!(events::test_sink::take_errors().is_empty());

        TEST_AUTHORIZATION_OVERRIDE.with(|allowed| allowed.set(Some(true)));
        emit_panic();
        assert_eq!(events::test_sink::take_executions().len(), 1);
        assert_eq!(events::test_sink::take_errors().len(), 1);

        reset_for_test();
    }

    #[test]
    fn emit_panic_active_captures_execution_and_error() {
        // Drive the real emit glue (globals read → active guard → paired write)
        // with the provider forced active and the capture sink installed, then
        // assert the exact Execution + Error records a panic produces.
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        events::test_sink::install();
        TEST_AUTHORIZATION_OVERRIDE.with(|allowed| allowed.set(Some(true)));
        TEST_FORCE_ACTIVE.with(|f| f.set(true));
        set_process_context_with_kind(&ContainmentBackend::IsolationSession, Some("vm"));
        set_process_phase("exec");
        set_process_correlation_vector("iso:wxc-abcd");

        emit_panic();

        let execs = events::test_sink::take_executions();
        assert_eq!(execs.len(), 1, "panic emits exactly one Execution");
        let exec = &execs[0];
        assert_eq!(exec.backend, "isolation_session");
        assert_eq!(exec.sandbox_kind, "vm");
        assert_eq!(exec.exit_code, PANIC_EXIT_CODE);
        assert_eq!(exec.outcome, "failure");
        assert_eq!(exec.failure_reason, Some(FailureReason::InternalError));
        assert_eq!(exec.phase, "exec");
        assert_eq!(exec.correlation_vector, "iso:wxc-abcd");

        let errors = events::test_sink::take_errors();
        assert_eq!(errors.len(), 1, "panic emits exactly one Error");
        let error = &errors[0];
        assert_eq!(error.backend, "isolation_session");
        assert_eq!(error.sandbox_kind, "vm");
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
        TEST_AUTHORIZATION_OVERRIDE.with(|allowed| allowed.set(Some(true)));
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
    fn emit_completion_captures_success_and_failure_records() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        events::test_sink::install();
        TEST_AUTHORIZATION_OVERRIDE.with(|allowed| allowed.set(Some(true)));

        emit_completion(
            true,
            &ContainmentBackend::IsolationSession,
            &ScriptResponse {
                exit_code: 0,
                ..Default::default()
            },
            Duration::from_millis(12),
        );
        let executions = events::test_sink::take_executions();
        assert_eq!(executions.len(), 1);
        assert_eq!(executions[0].outcome, "success");
        assert_eq!(executions[0].exit_code, 0);
        assert_eq!(executions[0].failure_reason, None);
        assert!(events::test_sink::take_errors().is_empty());

        reset_for_test();
        events::test_sink::install();
        TEST_AUTHORIZATION_OVERRIDE.with(|allowed| allowed.set(Some(true)));
        emit_completion_with_kind(
            true,
            &ContainmentBackend::IsolationSession,
            Some("process"),
            &ScriptResponse {
                exit_code: 1,
                error_message: "launch failed".to_string(),
                failure_phase: FailurePhase::LaunchFailed,
                ..Default::default()
            },
            Duration::from_millis(3),
        );
        let executions = events::test_sink::take_executions();
        assert_eq!(executions.len(), 1);
        assert_eq!(executions[0].outcome, "failure");
        assert_eq!(executions[0].exit_code, 1);
        assert_eq!(executions[0].sandbox_kind, "process");
        assert_eq!(executions[0].failure_reason, Some(FailureReason::InitError));
        let errors = events::test_sink::take_errors();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].sandbox_kind, "process");
        assert_eq!(errors[0].error_type, FailureReason::InitError);

        reset_for_test();
    }

    #[test]
    fn emit_early_exit_captures_execution_and_error() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        events::test_sink::install();
        TEST_AUTHORIZATION_OVERRIDE.with(|allowed| allowed.set(Some(true)));

        emit_early_exit_with_kind(
            true,
            &ContainmentBackend::IsolationSession,
            Some("vm"),
            FailureReason::PolicyError,
        );

        let executions = events::test_sink::take_executions();
        assert_eq!(executions.len(), 1);
        assert_eq!(executions[0].outcome, "failure");
        assert_eq!(executions[0].exit_code, 1);
        assert_eq!(executions[0].sandbox_kind, "vm");
        assert_eq!(
            executions[0].failure_reason,
            Some(FailureReason::PolicyError)
        );
        let errors = events::test_sink::take_errors();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].sandbox_kind, "vm");
        assert_eq!(errors[0].error_type, FailureReason::PolicyError);

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
        TEST_AUTHORIZATION_OVERRIDE.with(|value| value.set(Some(true)));
        set_process_context(&ContainmentBackend::IsolationSession);
        set_process_phase("exec");

        emit_panic();
        emit_cancellation();

        assert_eq!(
            events::test_sink::take_executions().len(),
            1,
            "second emit must not add an Execution"
        );
        assert_eq!(
            events::test_sink::take_errors().len(),
            1,
            "second emit must not add an Error"
        );

        reset_for_test();
    }

    #[test]
    fn terminal_emit_slot_is_exactly_once_and_resettable() {
        // The exactly-once slot (`HAS_EMITTED`) is concurrency-critical: the
        // out-of-band panic/cancellation paths race the main completion emit,
        // and the guard is what keeps a single dispatch from producing
        // duplicate Execution records. Lock the global state, reset to a
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
        // reset_for_test must clear the stashed backend/phase/correlation-id
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
        // The Error carries the same reason/exit code as the execution event.
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
            // NO Error (a faithfully-propagated script exit, not an MXC
            // failure).
            let nonzero = Ok(DispatchOutcome::ExecCompleted { exit_code: 42 });
            let nonzero_plan = plan_state_aware(ctx, &nonzero, 3);
            assert_eq!(nonzero_plan.execution.phase, phase);
            assert_eq!(nonzero_plan.execution.correlation_vector, correlation);
            assert_eq!(nonzero_plan.execution.outcome, "failure");
            assert_eq!(nonzero_plan.execution.exit_code, 42);
            assert!(nonzero_plan.execution.failure_reason.is_none());
            assert!(nonzero_plan.error.is_none());

            // MxcError → failure / exit 1 / classified Error.
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
        TEST_AUTHORIZATION_OVERRIDE.with(|allowed| allowed.set(Some(true)));

        // Provision-style success envelope → one Execution, no Error.
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
        TEST_AUTHORIZATION_OVERRIDE.with(|allowed| allowed.set(Some(true)));
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

    #[test]
    fn sdk_state_aware_events_keep_request_scoped_sandbox_kind() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        events::test_sink::install();
        TEST_AUTHORIZATION_OVERRIDE.with(|allowed| allowed.set(Some(true)));

        let outcome = Ok(DispatchOutcome::Envelope(serde_json::json!({})));
        let error = Err(MxcError::policy_validation("simulated"));
        emit_sdk_state_aware_with_kind(
            true,
            Some("process"),
            TelemetryContext {
                backend: "windows_sandbox",
                phase: "exec",
                correlation_vector: "corr-process",
            },
            &outcome,
            Duration::ZERO,
        );
        emit_sdk_state_aware_with_kind(
            true,
            Some("vm"),
            TelemetryContext {
                backend: "windows_sandbox",
                phase: "exec",
                correlation_vector: "corr-vm",
            },
            &error,
            Duration::ZERO,
        );

        let executions = events::test_sink::take_executions();
        assert_eq!(executions.len(), 2);
        assert_eq!(executions[0].sandbox_kind, "process");
        assert_eq!(executions[1].sandbox_kind, "vm");
        assert_eq!(executions[0].correlation_vector, "corr-process");
        assert_eq!(executions[1].correlation_vector, "corr-vm");
        let errors = events::test_sink::take_errors();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].sandbox_kind, "vm");
        assert_eq!(errors[0].backend, "windows_sandbox");

        reset_for_test();
    }

    #[test]
    fn sdk_cancellation_uses_cancelled_reason_and_request_context() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        events::test_sink::install();
        TEST_AUTHORIZATION_OVERRIDE.with(|allowed| allowed.set(Some(true)));

        emit_sdk_cancellation_with_kind(
            true,
            Some("process"),
            TelemetryContext {
                backend: "appcontainer",
                phase: "",
                correlation_vector: "",
            },
            Duration::from_millis(9),
        );
        emit_sdk_cancellation_with_kind(
            true,
            Some("vm"),
            TelemetryContext {
                backend: "windows_sandbox",
                phase: "exec",
                correlation_vector: "corr-cancelled",
            },
            Duration::from_millis(17),
        );

        let executions = events::test_sink::take_executions();
        assert_eq!(executions.len(), 2);
        assert_eq!(executions[0].backend, "appcontainer");
        assert_eq!(executions[0].sandbox_kind, "process");
        assert_eq!(executions[0].duration_ms, 9);
        assert_eq!(executions[0].phase, "");
        assert_eq!(executions[0].correlation_vector, "");
        assert_eq!(executions[1].backend, "windows_sandbox");
        assert_eq!(executions[1].sandbox_kind, "vm");
        assert_eq!(executions[1].exit_code, CANCELLED_EXIT_CODE);
        assert_eq!(executions[1].outcome, "failure");
        assert_eq!(executions[1].duration_ms, 17);
        assert_eq!(executions[1].failure_reason, Some(FailureReason::Cancelled));
        assert_eq!(executions[1].phase, "exec");
        assert_eq!(executions[1].correlation_vector, "corr-cancelled");

        let errors = events::test_sink::take_errors();
        assert_eq!(errors.len(), 2);
        assert_eq!(errors[0].sandbox_kind, "process");
        assert_eq!(errors[0].error_type, FailureReason::Cancelled);
        assert_eq!(errors[0].exit_code, CANCELLED_EXIT_CODE);
        assert_eq!(errors[0].phase, "");
        assert_eq!(errors[0].correlation_vector, "");
        assert_eq!(errors[1].sandbox_kind, "vm");
        assert_eq!(errors[1].error_type, FailureReason::Cancelled);
        assert_eq!(errors[1].exit_code, CANCELLED_EXIT_CODE);
        assert_eq!(errors[1].phase, "exec");
        assert_eq!(errors[1].correlation_vector, "corr-cancelled");

        reset_for_test();
    }

    #[cfg(windows)]
    #[test]
    fn sdk_emit_releases_provider_when_live_authorization_closes() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        TEST_AUTHORIZATION_OVERRIDE.with(|allowed| allowed.set(Some(false)));

        assert!(mxc_telemetry::init(version(), MXC_CHANNEL));
        assert!(mxc_telemetry::is_active());

        emit_sdk_with_release(true, |_auth| {
            panic!("authorization must suppress the event")
        });

        assert!(!mxc_telemetry::is_active());
        reset_for_test();
    }

    /// Regression: the paired-write authorization decision must be captured
    /// *once* per logical emission and shared by both writes. If authorization
    /// flips from allowed → denied *after* the token is minted but *before*
    /// the second write in a pair, the second write must still fire (they
    /// share the one decision proven by the `EmissionAuthorization` token).
    /// This structurally forbids a revocation-race window between the paired
    /// `log_execution` and `log_error` calls, without re-introducing blocking
    /// consent/policy I/O on the hot path.
    #[test]
    fn paired_write_shares_single_authorization_decision() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        events::test_sink::install();
        TEST_FORCE_ACTIVE.with(|f| f.set(true));
        TEST_AUTHORIZATION_OVERRIDE.with(|allowed| allowed.set(Some(true)));

        // Precondition: authorization initially allows — the token can be
        // minted.
        assert!(EmissionAuthorization::for_invocation(true).is_some());

        // Drive the paired-write path (Execution + Error) on the state-aware
        // emit, which is representative of the completion / early-exit /
        // crash pairs (all share the same token-threading structure).
        let err = Err(MxcError::policy_validation("simulated"));
        emit_state_aware(
            true,
            TelemetryContext {
                backend: "isolation_session",
                phase: "exec",
                correlation_vector: "corr-race",
            },
            &err,
            Duration::from_millis(1),
        );

        // Revoke authorization after the emission. Prior to the token
        // refactor this override could have been read a second time between
        // the paired writes; under the token, both writes were already
        // committed under the up-front decision.
        TEST_AUTHORIZATION_OVERRIDE.with(|allowed| allowed.set(Some(false)));
        assert!(EmissionAuthorization::for_invocation(true).is_none());

        let execs = events::test_sink::take_executions();
        let errors = events::test_sink::take_errors();
        assert_eq!(execs.len(), 1, "Execution must be emitted under the token");
        assert_eq!(
            errors.len(),
            1,
            "Error must be emitted under the same token as its paired Execution"
        );
        assert_eq!(execs[0].outcome, "failure");
        assert_eq!(errors[0].error_type, FailureReason::PolicyError);

        reset_for_test();
    }

    /// Regression: a denied initial authorization must skip the pair entirely
    /// — neither `log_execution` nor `log_error` may fire when the token
    /// cannot be minted.
    #[test]
    fn paired_write_denies_pair_when_token_cannot_be_minted() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        events::test_sink::install();
        TEST_FORCE_ACTIVE.with(|f| f.set(true));
        TEST_AUTHORIZATION_OVERRIDE.with(|allowed| allowed.set(Some(false)));

        assert!(EmissionAuthorization::for_invocation(true).is_none());

        let err = Err(MxcError::policy_validation("simulated"));
        emit_state_aware(
            true,
            TelemetryContext {
                backend: "isolation_session",
                phase: "exec",
                correlation_vector: "corr-denied",
            },
            &err,
            Duration::from_millis(1),
        );

        assert!(events::test_sink::take_executions().is_empty());
        assert!(events::test_sink::take_errors().is_empty());

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
        TEST_AUTHORIZATION_OVERRIDE.with(|allowed| allowed.set(Some(true)));

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

    #[cfg(windows)]
    #[test]
    fn live_withdrawal_and_policy_block_suppress_the_next_emission() {
        let store = tempfile::tempdir().expect("temp dir");
        let env = test_support::TelemetryTestEnv::new(store.path());
        env.set_policy_value(3);
        consent::set_consent(true, "test").expect("set consent");

        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        events::test_sink::install();
        TEST_FORCE_ACTIVE.with(|f| f.set(true));
        set_process_context(&ContainmentBackend::IsolationSession);

        consent::withdraw_consent().expect("withdraw consent");
        emit_panic();
        assert!(
            events::test_sink::take_executions().is_empty(),
            "withdrawal must suppress the next logical emission"
        );

        reset_for_test();
        events::test_sink::install();
        TEST_FORCE_ACTIVE.with(|f| f.set(true));
        consent::set_consent(true, "test").expect("restore consent");
        env.set_policy_value(0);

        emit_cancellation();
        assert!(
            events::test_sink::take_executions().is_empty(),
            "a newly blocking policy must suppress the next logical emission"
        );

        reset_for_test();
    }
}
