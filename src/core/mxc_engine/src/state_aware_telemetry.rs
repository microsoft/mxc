// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Telemetry and correlation-vector orchestration for the state-aware
//! lifecycle.
//!
//! This wraps [`crate::run_state_aware`] with everything a lifecycle dispatch
//! needs around it: telemetry init/shutdown, process attribution (backend +
//! phase), the Microsoft Correlation Vector (MS-CV) seed/spin plan, the crash
//! panic hook, and the terminal `emit_state_aware` event.
//!
//! It lives here — rather than in an executor binary — because every executor
//! that dispatches the state-aware lifecycle needs identical behavior. When
//! this logic lived in `wxc`'s `main.rs`, the `lxc` executor called
//! [`crate::run_state_aware`] directly and so silently produced no lifecycle
//! telemetry and no correlation vector: a Linux lifecycle was invisible to the
//! same dashboards that observed a Windows one, and a client relaying a
//! provision-seeded cV had nothing to relay. Sharing the orchestration is what
//! keeps the two executors from drifting apart again.

use std::time::Instant;

use wxc_common::logger::Logger;
use wxc_common::mxc_error::MxcError;
use wxc_common::state_aware_dispatch::{resolve_backend, DispatchOutcome};
use wxc_common::state_aware_request::ParsedStateAwareRequest;
use wxc_common::telemetry;

/// The correlation-vector action a state-aware phase should take, decided purely
/// from the phase and the relayed value. Returned by [`plan_correlation_vector`]
/// so the seed-vs-spin decision is unit-testable without touching the RNG/clock;
/// the caller executes the plan against the (nondeterministic) operators.
#[derive(Debug, PartialEq, Eq)]
enum CvPlan<'a> {
    /// Mint a fresh vector. Used for `provision`, and for any non-provision phase
    /// whose relayed value is missing, empty, or not relayable (malformed /
    /// hostile) — so garbage never even reaches the `spin` operator.
    Seed,
    /// Spin the relayed value to derive this phase's child vector. Only planned
    /// for a value [`is_relayable`](telemetry::correlation_vector::is_relayable)
    /// vouches for, so `spin` here always builds on a real parent rather than
    /// silently reseeding.
    Spin(&'a str),
}

/// Plans the Microsoft Correlation Vector (MS-CV) action for a state-aware phase.
///
/// Provision always seeds a fresh random base. Every later phase spins the
/// relayed `incoming_cv` so sibling phases get distinct vectors that still share
/// the lifecycle prefix — but only when the relayed value is actually relayable
/// (a valid mutable or frozen vector). A missing, empty, or malformed relayed
/// value is planned as [`CvPlan::Seed`] so the `Spin` arm never stands in for a
/// reseed; the decision stays a pure function of `(is_provision, incoming_cv)`
/// with no RNG, so it is deterministically testable.
fn plan_correlation_vector(is_provision: bool, incoming_cv: Option<&str>) -> CvPlan<'_> {
    match incoming_cv {
        Some(cv) if !is_provision && telemetry::correlation_vector::is_relayable(cv) => {
            CvPlan::Spin(cv)
        }
        _ => CvPlan::Seed,
    }
}

/// Executes the pure [`plan_correlation_vector`] plan against the (nondeterministic)
/// MS-CV operators, returning this phase's correlation vector. Empty when
/// telemetry is inactive so an inactive provider does no RNG/clock work and
/// provision output is unchanged.
fn compute_phase_correlation(
    telemetry_active: bool,
    is_provision: bool,
    incoming_cv: Option<&str>,
) -> String {
    if !telemetry_active {
        return String::new();
    }
    match plan_correlation_vector(is_provision, incoming_cv) {
        CvPlan::Seed => telemetry::correlation_vector::seed(),
        CvPlan::Spin(cv) => telemetry::correlation_vector::spin(cv),
    }
}

/// Injects the freshly-seeded correlation vector into a provision result
/// envelope (`{ "result": { ..., "correlationVector": "<cV>" } }`) so the client
/// can relay it into every later phase of the lifecycle. No-op when the outcome
/// is not a result envelope (exec-completed / error paths carry no cV).
fn inject_correlation_vector(outcome: &mut Result<DispatchOutcome, MxcError>, cv: &str) {
    if let Ok(DispatchOutcome::Envelope(value)) = outcome {
        if let Some(result) = value.get_mut("result").and_then(|r| r.as_object_mut()) {
            result.insert(
                "correlationVector".to_string(),
                serde_json::Value::String(cv.to_string()),
            );
        }
    }
}

/// Run a state-aware phase with full telemetry and correlation-vector
/// orchestration, returning the dispatch outcome for the caller to render.
///
/// The caller still owns the terminal behavior (flushing `logger`'s buffer,
/// writing the envelope to stdout, choosing an exit code) — only the
/// observability wrapper is shared. Telemetry is gated on `experimental`
/// exactly like the one-shot path and reads the same typed
/// `experimental.telemetry` field; a malformed telemetry block is already
/// rejected at parse time, so there is no client-error handling here.
pub fn run_state_aware_with_telemetry(
    parsed: ParsedStateAwareRequest,
    dry_run: bool,
    experimental: bool,
    logger: &mut Logger,
) -> Result<DispatchOutcome, MxcError> {
    // Resolve attribution (phase + backend) BEFORE dispatch consumes `parsed`.
    let phase = parsed.phase.as_str();
    // Whether this invocation is the provision phase. Provision seeds a fresh
    // random correlation-vector base and returns it in the result envelope;
    // every later phase relays that base back and spins it. We deliberately
    // ignore any client-supplied `correlationVector` on provision so a lifecycle
    // can never be seeded with a stale or foreign vector.
    let is_provision = phase == "provision";
    // The relayed correlation vector for non-provision phases (the base seeded at
    // provision). Captured before `dispatch` consumes `parsed`. `None` for
    // provision (which seeds its own below).
    let incoming_cv = if is_provision {
        None
    } else {
        parsed.correlation_vector.clone()
    };
    let resolved_backend = resolve_backend(&parsed).ok();
    let backend = resolved_backend
        .as_ref()
        .map(|b| b.wire_name())
        .unwrap_or("unknown");
    let telemetry_active = if experimental {
        parsed
            .request
            .experimental
            .telemetry
            .as_ref()
            .map(|c| telemetry::init(c, logger))
            .unwrap_or(false)
    } else {
        false
    };

    // Compute this phase's MS-CV, executing the pure seed-vs-spin plan against
    // the operators. Only computed when telemetry is active so an inactive
    // provider does no work and provision output is unchanged.
    let correlation =
        compute_phase_correlation(telemetry_active, is_provision, incoming_cv.as_deref());

    // Attribute out-of-band emit paths (the console-control handler installed in
    // `main`, and the panic hook installed just below) to the resolved backend
    // and the lifecycle phase, and install a crash-telemetry panic hook for this
    // dispatch — mirroring the one-shot path, which the `-> !` entry points
    // bypass. The shared hook chains the previous hook (default stderr backtrace
    // still prints) and is panic-free.
    if telemetry_active {
        if let Some(containment) = resolved_backend.as_ref() {
            telemetry::set_process_context(containment);
        }
        telemetry::set_process_phase(phase);
        // Stash this phase's correlation vector so out-of-band events
        // (panic / cancellation) carry the same cV as the terminal emit below.
        telemetry::set_process_correlation_vector(&correlation);
        telemetry::install_panic_hook();
    }

    let started = Instant::now();
    let mut outcome = crate::run_state_aware(parsed, dry_run);
    let elapsed = started.elapsed();

    // For provision, return the freshly-seeded correlation vector to the client
    // by injecting it into the result envelope so it can be relayed into later
    // phases. Gated on telemetry so provision output is unchanged when telemetry
    // is off.
    if is_provision && telemetry_active {
        inject_correlation_vector(&mut outcome, &correlation);
    }

    // Emit lifecycle telemetry (and shut the provider down) before the caller
    // flushes the diagnostic buffer / envelope. Terminal path — safe to shut
    // down here.
    telemetry::emit_state_aware(
        telemetry_active,
        telemetry::TelemetryContext {
            backend,
            phase,
            correlation_vector: &correlation,
        },
        &outcome,
        elapsed,
    );

    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_correlation_vector_provision_seeds_fresh_vector() {
        // Provision ignores any relayed value and always plans a fresh seed.
        assert_eq!(
            plan_correlation_vector(true, Some("BBBBBBBBBBBBBBBBBBBBBB.5")),
            CvPlan::Seed
        );
        assert_eq!(plan_correlation_vector(true, None), CvPlan::Seed);
    }

    #[test]
    fn plan_correlation_vector_phase_spins_relayed_base() {
        // A relayable relayed value is spun to derive this phase's child vector.
        let base = "AAAAAAAAAAAAAAAAAAAAAA.0";
        assert_eq!(
            plan_correlation_vector(false, Some(base)),
            CvPlan::Spin(base)
        );
        // A valid frozen relayed value is also relayable (spin passes it through).
        let frozen = "AAAAAAAAAAAAAAAAAAAAAA.0!";
        assert_eq!(
            plan_correlation_vector(false, Some(frozen)),
            CvPlan::Spin(frozen)
        );
    }

    #[test]
    fn plan_correlation_vector_phase_reseeds_for_missing_empty_or_malformed() {
        // Missing / empty / non-relayable relayed values plan a fresh `Seed`, so
        // the `Spin` arm never stands in for a reseed (garbage never reaches the
        // `spin` operator).
        for incoming in [None, Some(""), Some("garbage"), Some("short.0")] {
            assert_eq!(
                plan_correlation_vector(false, incoming),
                CvPlan::Seed,
                "non-relayable relay {incoming:?} must plan Seed"
            );
        }
    }

    #[test]
    fn compute_phase_correlation_is_empty_when_telemetry_inactive() {
        // Inactive telemetry does no RNG/clock work regardless of phase/relay.
        assert!(compute_phase_correlation(false, true, None).is_empty());
        assert!(
            compute_phase_correlation(false, false, Some("AAAAAAAAAAAAAAAAAAAAAA.0")).is_empty()
        );
    }

    #[test]
    fn compute_phase_correlation_spins_relayable_and_reseeds_garbage() {
        // Active provision seeds a fresh valid vector.
        let provisioned = compute_phase_correlation(true, true, None);
        assert!(telemetry::correlation_vector::is_relayable(&provisioned));
        // Active non-provision spins a relayable relay onto the shared prefix.
        let base = "AAAAAAAAAAAAAAAAAAAAAA.0";
        let spun = compute_phase_correlation(true, false, Some(base));
        assert!(spun.starts_with(&format!("{base}.")), "{spun:?}");
        // Active non-provision with garbage reseeds to a fresh, unrelated vector.
        let reseeded = compute_phase_correlation(true, false, Some("garbage"));
        assert!(telemetry::correlation_vector::is_relayable(&reseeded));
        assert!(!reseeded.starts_with("garbage"));
    }

    #[test]
    fn inject_correlation_vector_sets_field_on_envelope() {
        let mut outcome: Result<DispatchOutcome, MxcError> = Ok(DispatchOutcome::Envelope(
            serde_json::json!({ "result": { "sandboxId": "iso:wxc-abc" } }),
        ));
        inject_correlation_vector(&mut outcome, "AAAAAAAAAAAAAAAAAAAAAA.0");
        match outcome {
            Ok(DispatchOutcome::Envelope(v)) => assert_eq!(
                v["result"]["correlationVector"],
                serde_json::json!("AAAAAAAAAAAAAAAAAAAAAA.0")
            ),
            _ => panic!("expected envelope"),
        }
    }

    #[test]
    fn inject_correlation_vector_noop_on_non_envelope() {
        // Exec-completed / error outcomes carry no result envelope: injection is
        // a no-op and must not panic.
        let mut exit: Result<DispatchOutcome, MxcError> =
            Ok(DispatchOutcome::ExecCompleted { exit_code: 0 });
        inject_correlation_vector(&mut exit, "AAAAAAAAAAAAAAAAAAAAAA.0");
        assert!(matches!(
            exit,
            Ok(DispatchOutcome::ExecCompleted { exit_code: 0 })
        ));
    }
}
