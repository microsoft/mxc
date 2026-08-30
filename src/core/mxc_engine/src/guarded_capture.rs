// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Adapts `plm::elevated`'s guarded WPR capture protocol to
//! `appcontainer_common::guarded_capture`'s DI traits.
//!
//! `appcontainer_common` cannot depend on `plm` directly (see
//! `appcontainer_common::guarded_capture`'s module docs for the crate-layering
//! rationale). `mxc_engine` sits above both — it already has the Windows
//! backend crates as dependencies — so it owns the concrete adapter and hands
//! it to the dispatcher only for requests that actually need the fallback
//! (`request.policy.capture_denials.is_some()` on a non-native tier).

use appcontainer_common::guarded_capture::{
    AnalyzedTrace, GuardedCaptureFactory, GuardedCaptureSession,
};
use learning_mode_core::AnalysisResult;
const GUARDIAN_CONFIRM_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(100);
const MAX_GUARDIAN_CONFIRM_ATTEMPTS: usize = 3;
/// Bounded per-attempt deadline for confirming that the guardian released the
/// sandbox after a discard failure. The guardian terminates promptly once a
/// discard/abandon has been requested, so this is intentionally short: without
/// it, each confirmation would inherit `plm`'s multi-minute stop timeout and a
/// three-attempt retry loop could block for tens of minutes.
const GUARDIAN_CONFIRM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Timing/attempt policy for [`confirm_guardian_release_after_discard_failure`].
/// Extracted into a struct so the confirmation timeout and retry delay are
/// injectable in tests without touching the production defaults ([`Self::default`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GuardianConfirmPolicy {
    max_attempts: usize,
    /// Per-attempt deadline handed to each guardian-release confirmation.
    confirm_timeout: std::time::Duration,
    /// Delay applied between confirmation attempts.
    retry_delay: std::time::Duration,
}

impl Default for GuardianConfirmPolicy {
    fn default() -> Self {
        Self {
            max_attempts: MAX_GUARDIAN_CONFIRM_ATTEMPTS,
            confirm_timeout: GUARDIAN_CONFIRM_TIMEOUT,
            retry_delay: GUARDIAN_CONFIRM_RETRY_DELAY,
        }
    }
}

/// Retries guardian-release confirmation under `policy`. Each attempt calls
/// `confirm_release` with the policy's `confirm_timeout`; between failed
/// attempts it invokes `on_retry` (diagnostics) and then `sleep` with the
/// policy's `retry_delay`. Both the clock (via `confirm_timeout`) and the sleep
/// are injected so the timing is unit-testable without real waits.
fn confirm_guardian_release_after_discard_failure(
    policy: GuardianConfirmPolicy,
    mut confirm_release: impl FnMut(std::time::Duration) -> Result<(), String>,
    mut on_retry: impl FnMut(usize, &str),
    mut sleep: impl FnMut(std::time::Duration),
) -> Result<(), String> {
    for attempt in 1..=policy.max_attempts {
        match confirm_release(policy.confirm_timeout) {
            Ok(()) => return Ok(()),
            Err(error) if attempt < policy.max_attempts => {
                on_retry(attempt, &error);
                sleep(policy.retry_delay);
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("guardian confirmation attempt range is non-empty")
}

/// Resolve `plm.exe` next to the module containing `mxc_engine`.
///
/// This is the executor directory for `wxc-exec.exe` and the native runtime
/// asset directory for `mxc_ffi.dll`. `current_exe()` is not sufficient for
/// library consumers because a framework-dependent .NET app reports
/// `dotnet.exe`, not the loaded MXC native module.
///
/// Packaging and code-signing of `plm.exe` (so it ships alongside
/// `wxc-exec.exe` / `mxc_ffi.dll` in released artifacts) is delivered by #834;
/// this resolver only locates the co-located binary at runtime.
fn plm_exe_path() -> Result<std::path::PathBuf, String> {
    let module = wxc_common::process_util::module_path_for_address(plm_exe_path as *const ())?;
    let dir = module
        .parent()
        .ok_or_else(|| "the MXC native module has no parent directory".to_string())?;
    Ok(dir.join("plm.exe"))
}

/// [`GuardedCaptureSession`] backed by a live `plm::elevated::GuardedSession`.
struct PlmGuardedCaptureSession {
    session: plm::elevated::GuardedSession,
}

impl GuardedCaptureSession for PlmGuardedCaptureSession {
    fn attach_process_tree(
        &mut self,
        job_handle: usize,
        root_process_handle: usize,
    ) -> Result<(), String> {
        self.session
            .attach_process_tree(job_handle, root_process_handle)
            .map_err(|e| format!("guarded WPR process-tree attach failed: {e:#}"))
    }

    fn discard(&mut self) -> Result<(), String> {
        let discard_error = match self.session.discard() {
            Ok(()) => return Ok(()),
            Err(error) => error,
        };

        match confirm_guardian_release_after_discard_failure(
            GuardianConfirmPolicy::default(),
            |timeout| {
                self.session
                    .cancel_within(timeout)
                    .map_err(|error| format!("{error:#}"))
            },
            |attempt, error| {
                eprintln!(
                    "[mxc] guarded WPR guardian termination remains unconfirmed after \
                     discard failure (attempt {attempt}/{MAX_GUARDIAN_CONFIRM_ATTEMPTS}); \
                     sandbox enforcement is still active: {error}"
                );
            },
            std::thread::sleep,
        ) {
            Ok(()) => Err(format!(
                "guarded WPR discard failed: {discard_error:#}; guardian termination was \
                 confirmed by the cleanup fallback"
            )),
            Err(error) => {
                eprintln!(
                    "[mxc] guarded WPR guardian termination could not be confirmed after \
                     {MAX_GUARDIAN_CONFIRM_ATTEMPTS} attempts; aborting to preserve sandbox \
                     enforcement: {error}"
                );
                std::process::abort();
            }
        }
    }

    fn stop_analyzed(&mut self) -> Result<AnalysisResult, String> {
        self.session
            .stop_analyzed()
            .map_err(|e| format!("guarded WPR stop/analyze failed: {e:#}"))
    }

    fn stop_analyzed_with_trace(
        &mut self,
        trace_destination: &std::path::Path,
    ) -> Result<AnalyzedTrace, String> {
        // `Err` is an analysis failure. A trace-transfer failure after a
        // successful analysis is carried inside `AnalyzedTraceTransfer` and
        // mapped to `AnalyzedTrace::trace_retention` — never allowed to discard
        // the decoded analysis.
        let plm::elevated::AnalyzedTraceTransfer {
            analysis,
            trace_transfer,
        } = self
            .session
            .stop_analyzed_with_trace(trace_destination)
            .map_err(|e| format!("guarded WPR stop/analyze failed: {e:#}"))?;
        Ok(AnalyzedTrace {
            analysis,
            trace_retention: trace_transfer
                .map_err(|e| format!("guarded WPR trace transfer failed: {e:#}")),
        })
    }
}

/// [`GuardedCaptureFactory`] that starts a guarded WPR capture session via the
/// elevated `plm.exe` guardian, using [`plm::elevated::start_guarded_session_with_executable`].
pub struct PlmGuardedCaptureFactory;

impl GuardedCaptureFactory for PlmGuardedCaptureFactory {
    fn allows_trace_transfer(&self) -> bool {
        true
    }

    fn start(&self, owner_pid: u32) -> Result<Box<dyn GuardedCaptureSession>, String> {
        let plm_path = plm_exe_path()?;
        start_with_plm_path(&plm_path, owner_pid)
    }
}

/// Start a guarded session against an explicit `plm.exe` path. Split out from
/// [`PlmGuardedCaptureFactory::start`] so unit tests can exercise the
/// missing-guardian rejection deterministically, against a synthetic path,
/// rather than depending on whether `plm.exe` happens to already exist next to
/// the current test binary in a given build/CI environment.
///
/// Trust: co-location (via [`plm_exe_path`]) is only a *discovery* mechanism.
/// The authoritative pre-launch trust gate lives in `plm::trust` and runs
/// inside the PLM launch path immediately before `ShellExecuteExW("runas")`:
/// it verifies `plm.exe`'s Authenticode chain and Microsoft signer identity,
/// rejects a containing directory any unprivileged principal could modify, and
/// pins the file open (deny write/delete) across the launch to close the
/// check-then-launch window. An unsigned, non-Microsoft, or user-replaceable
/// `plm.exe` is refused before any elevation occurs. The existence check here
/// is just a fast, friendly pre-check. Distribution of a signed, packaged
/// `plm.exe` alongside `wxc-exec.exe` / `mxc_ffi.dll` is owned by #834; on
/// unsigned local/dev builds the trust gate deliberately refuses to elevate.
fn start_with_plm_path(
    plm_path: &std::path::Path,
    owner_pid: u32,
) -> Result<Box<dyn GuardedCaptureSession>, String> {
    if !plm_path.exists() {
        return Err(format!(
            "plm.exe not found at {} (required for the guarded WPR captureDenials fallback)",
            plm_path.display()
        ));
    }
    let session = plm::elevated::start_guarded_session_with_executable(plm_path, owner_pid)
        .map_err(|e| format!("guarded WPR session start failed: {e:#}"))?;
    Ok(Box::new(PlmGuardedCaptureSession { session }))
}

/// Build the guarded-capture factory to hand to the dispatcher for `request`,
/// or `None` when `captureDenials` isn't requested. Centralizing this (rather
/// than constructing a `PlmGuardedCaptureFactory` unconditionally at every call
/// site) keeps `run.rs` / `dispatch.rs` from wiring a factory the request never
/// needed.
pub(crate) fn factory_for_request(
    request: &wxc_common::models::ExecutionRequest,
) -> Option<std::sync::Arc<dyn GuardedCaptureFactory>> {
    if request.policy.capture_denials.is_some() {
        Some(std::sync::Arc::new(PlmGuardedCaptureFactory))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_rejects_a_nonexistent_plm_path() {
        // Deterministic regardless of build/CI environment: point at a path
        // that is guaranteed not to exist rather than relying on whether
        // `plm.exe` happens to already sit next to the test binary.
        let missing = std::env::temp_dir().join("mxc-guarded-capture-test-nonexistent-plm.exe");
        assert!(!missing.exists(), "test setup: path must not exist");

        let error = match start_with_plm_path(&missing, std::process::id()) {
            Ok(_) => panic!("a nonexistent plm.exe path must be rejected"),
            Err(error) => error,
        };
        assert!(error.contains("plm.exe"), "got: {error}");
    }

    #[test]
    fn factory_for_request_is_none_without_capture_denials() {
        let request = wxc_common::models::ExecutionRequest::default();
        assert!(factory_for_request(&request).is_none());
    }

    #[test]
    fn factory_for_request_is_some_with_capture_denials() {
        let mut request = wxc_common::models::ExecutionRequest::default();
        request.policy.capture_denials = Some(Default::default());
        assert!(factory_for_request(&request).is_some());
    }

    #[test]
    fn plm_factory_supports_requested_trace_transfer() {
        let mut request = wxc_common::models::ExecutionRequest::default();
        request.policy.capture_denials = Some(Default::default());

        assert!(factory_for_request(&request)
            .unwrap()
            .allows_trace_transfer());
    }

    #[test]
    fn resolver_locates_the_current_native_module() {
        let module = wxc_common::process_util::module_path_for_address(
            resolver_locates_the_current_native_module as *const (),
        )
        .expect("test module path should resolve");
        assert!(module.is_absolute());
        assert!(module.is_file());
    }

    #[test]
    fn discard_failure_retries_with_backoff_until_release_is_confirmed() {
        let mut attempts = 0;
        let mut retries = Vec::new();
        let mut sleeps = Vec::new();

        confirm_guardian_release_after_discard_failure(
            GuardianConfirmPolicy::default(),
            |_timeout| {
                attempts += 1;
                if attempts < 3 {
                    Err(format!("confirmation attempt {attempts} failed"))
                } else {
                    Ok(())
                }
            },
            |attempt, error| retries.push((attempt, error.to_string())),
            |delay| sleeps.push(delay),
        )
        .unwrap();

        assert_eq!(attempts, 3);
        assert_eq!(
            retries,
            [
                (1, "confirmation attempt 1 failed".to_string()),
                (2, "confirmation attempt 2 failed".to_string())
            ]
        );
        // A retry sleep happens once per failed-but-retried attempt, using the
        // policy's retry delay (never a real sleep in tests).
        assert_eq!(
            sleeps,
            [GUARDIAN_CONFIRM_RETRY_DELAY, GUARDIAN_CONFIRM_RETRY_DELAY]
        );
    }

    #[test]
    fn discard_failure_stops_after_bounded_confirmation_attempts() {
        let mut attempts = 0;
        let mut retries = Vec::new();
        let mut sleeps = Vec::new();

        let error = confirm_guardian_release_after_discard_failure(
            GuardianConfirmPolicy::default(),
            |_timeout| {
                attempts += 1;
                Err(format!("confirmation attempt {attempts} failed"))
            },
            |attempt, error| retries.push((attempt, error.to_string())),
            |delay| sleeps.push(delay),
        )
        .unwrap_err();

        assert_eq!(attempts, MAX_GUARDIAN_CONFIRM_ATTEMPTS);
        assert_eq!(retries.len(), MAX_GUARDIAN_CONFIRM_ATTEMPTS - 1);
        assert_eq!(sleeps.len(), MAX_GUARDIAN_CONFIRM_ATTEMPTS - 1);
        assert_eq!(
            error,
            format!("confirmation attempt {MAX_GUARDIAN_CONFIRM_ATTEMPTS} failed")
        );
    }

    #[test]
    fn each_guardian_confirmation_receives_the_short_bounded_timeout() {
        // Every confirmation attempt must be handed the short 10s bound (not
        // plm's multi-minute stop timeout), so a retry loop cannot block for
        // tens of minutes.
        let mut timeouts = Vec::new();

        let _ = confirm_guardian_release_after_discard_failure(
            GuardianConfirmPolicy::default(),
            |timeout| {
                timeouts.push(timeout);
                Err("still failing".to_string())
            },
            |_attempt, _error| {},
            |_delay| {},
        );

        assert_eq!(timeouts.len(), MAX_GUARDIAN_CONFIRM_ATTEMPTS);
        assert!(
            timeouts
                .iter()
                .all(|&timeout| timeout == GUARDIAN_CONFIRM_TIMEOUT),
            "every confirmation must receive the 10s bound, got: {timeouts:?}"
        );
        assert_eq!(GUARDIAN_CONFIRM_TIMEOUT, std::time::Duration::from_secs(10));
    }

    #[test]
    fn confirmation_returns_ok_once_abandonment_is_confirmed() {
        // A single successful confirmation short-circuits with Ok — modelling
        // `cancel_within` returning Ok after the guardian is confirmed gone. No
        // retries, no sleeps.
        let mut attempts = 0;
        let mut retries = 0;
        let mut sleeps = 0;

        let result = confirm_guardian_release_after_discard_failure(
            GuardianConfirmPolicy::default(),
            |_timeout| {
                attempts += 1;
                Ok(())
            },
            |_attempt, _error| retries += 1,
            |_delay| sleeps += 1,
        );

        assert!(result.is_ok());
        assert_eq!(attempts, 1);
        assert_eq!(retries, 0);
        assert_eq!(sleeps, 0);
    }
}
