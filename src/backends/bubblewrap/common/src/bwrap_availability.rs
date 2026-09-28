// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Combined Bubblewrap version and launchability discovery.

use std::collections::HashSet;
use std::fmt;
use std::io;
use std::process::Command;
use std::sync::{mpsc, Arc, Condvar, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use wxc_common::models::{ContainmentBackend, ExecutionRequest, NetworkPolicy};

use crate::bwrap_command::{self, ResolvedNetworkMode};
use crate::bwrap_runner::BubblewrapScriptRunner;
use crate::bwrap_version::{self, BwrapUnavailable, BwrapVersion};
use crate::probe_exec::{self, CapturedProcess, ProbeFailure};

/// Maximum time spent proving a version-compatible Bubblewrap can launch.
pub const BWRAP_VIABILITY_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum time spent on the combined version and launchability predicate.
pub const BWRAP_AVAILABILITY_TIMEOUT: Duration = Duration::from_secs(
    bwrap_version::BWRAP_VERSION_TIMEOUT.as_secs() + BWRAP_VIABILITY_TIMEOUT.as_secs(),
);

/// Why Bubblewrap cannot currently be launched on this host.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BwrapAvailabilityError {
    /// The existing version probe rejected the installed executable.
    Version(BwrapUnavailable),
    /// The executable passed version validation but the minimal sandbox launch failed.
    LaunchFailed {
        /// Exit status when Bubblewrap ran to completion.
        status: Option<i32>,
        /// Actionable launch, supervision, or cleanup detail.
        detail: String,
    },
}

impl From<BwrapUnavailable> for BwrapAvailabilityError {
    fn from(error: BwrapUnavailable) -> Self {
        Self::Version(error)
    }
}

impl fmt::Display for BwrapAvailabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Version(error) => error.fmt(formatter),
            Self::LaunchFailed { status, detail } => {
                write!(
                    formatter,
                    "The Bubblewrap (bwrap) sandbox launchability probe"
                )?;
                match status {
                    Some(code) => write!(formatter, " exited with status {code}")?,
                    None => write!(formatter, " failed without an exit status")?,
                }
                if !detail.is_empty() {
                    write!(formatter, ": {detail}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for BwrapAvailabilityError {}

#[derive(Debug, Default)]
struct AvailabilityState {
    success: OnceLock<BwrapVersion>,
    gate: Arc<AvailabilityGate>,
}

#[derive(Debug, Default)]
struct AvailabilityGate {
    in_flight: Mutex<bool>,
    available: Condvar,
}

#[derive(Debug)]
struct AvailabilityPermit {
    gate: Arc<AvailabilityGate>,
}

impl Drop for AvailabilityPermit {
    fn drop(&mut self) {
        self.gate.release();
    }
}

impl AvailabilityGate {
    fn acquire_permit_until(self: &Arc<Self>, deadline: Instant) -> Option<AvailabilityPermit> {
        let mut in_flight = self
            .in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            if !*in_flight {
                *in_flight = true;
                return Some(AvailabilityPermit {
                    gate: Arc::clone(self),
                });
            }
            let (next, wait_result) = self
                .available
                .wait_timeout(in_flight, remaining)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            in_flight = next;
            if wait_result.timed_out() {
                return None;
            }
        }
    }

    fn release(&self) {
        let mut in_flight = self
            .in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *in_flight = false;
        self.available.notify_all();
    }
}

static BWRAP_AVAILABILITY_STATE: OnceLock<Arc<AvailabilityState>> = OnceLock::new();

/// Probe for a version-compatible Bubblewrap that can launch a minimal sandbox.
///
/// Complete successes are cached. Failures remain retryable so environment or
/// policy changes can make a later discovery call succeed.
pub fn probe_bwrap_available() -> Result<BwrapVersion, BwrapAvailabilityError> {
    probe_bwrap_available_cached(
        Arc::clone(BWRAP_AVAILABILITY_STATE.get_or_init(|| Arc::new(AvailabilityState::default()))),
        BWRAP_AVAILABILITY_TIMEOUT,
        bwrap_version::probe_bwrap_uncached,
        run_viability_until,
    )
}

fn probe_bwrap_available_cached<P, L>(
    state: Arc<AvailabilityState>,
    timeout: Duration,
    probe_version: P,
    launch: L,
) -> Result<BwrapVersion, BwrapAvailabilityError>
where
    P: FnOnce() -> Result<BwrapVersion, BwrapUnavailable>,
    L: FnOnce(BwrapVersion, Instant) -> Result<(), BwrapAvailabilityError> + Send + 'static,
{
    if let Some(version) = state.success.get() {
        return Ok(*version);
    }

    let deadline = Instant::now() + timeout;
    let version = probe_version().map_err(BwrapAvailabilityError::Version)?;
    let permit = match state.gate.acquire_permit_until(deadline) {
        Some(permit) => permit,
        None => {
            return state
                .success
                .get()
                .copied()
                .ok_or_else(|| availability_timeout(timeout));
        }
    };
    if let Some(version) = state.success.get() {
        return Ok(*version);
    }

    let (sender, receiver) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("bwrap-availability-probe".to_string())
        .spawn({
            let state = Arc::clone(&state);
            move || {
                let _permit = permit;
                let result = launch(version, deadline);
                if result.is_ok() {
                    let _ = state.success.set(version);
                }
                let _ = sender.send(result.map(|()| version));
            }
        })
        .map_err(|error| BwrapAvailabilityError::LaunchFailed {
            status: None,
            detail: format!("failed to start launchability worker: {error}"),
        })?;

    match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => state
            .success
            .get()
            .copied()
            .ok_or_else(|| availability_timeout(timeout)),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(BwrapAvailabilityError::LaunchFailed {
            status: None,
            detail: "launchability worker exited without returning a result".to_string(),
        }),
    }
}

fn availability_timeout(timeout: Duration) -> BwrapAvailabilityError {
    BwrapAvailabilityError::LaunchFailed {
        status: None,
        detail: format!("timed out after {}ms", timeout.as_millis()),
    }
}

fn viability_request() -> ExecutionRequest {
    let mut request = ExecutionRequest {
        containment: ContainmentBackend::Bubblewrap,
        ..Default::default()
    };
    request.script_code = "exit 0".to_string();
    request.working_directory = "/".to_string();
    request.env = Some(vec!["PATH=/usr/bin:/bin".to_string()]);
    request.policy.default_network_policy = NetworkPolicy::Allow;
    request.policy.allow_local_network = true;
    request
}

fn run_viability_until(
    version: BwrapVersion,
    deadline: Instant,
) -> Result<(), BwrapAvailabilityError> {
    let request = viability_request();
    let mode = ResolvedNetworkMode::from_request(&request, false);
    if mode != ResolvedNetworkMode::Shared {
        return Err(BwrapAvailabilityError::LaunchFailed {
            status: None,
            detail: format!("internal viability request resolved to {mode:?}, expected Shared"),
        });
    }

    BubblewrapScriptRunner
        .validate_prepared_with_probe(&request, || Ok(version))
        .map_err(|response| BwrapAvailabilityError::LaunchFailed {
            status: None,
            detail: response.error_message,
        })?;

    let args =
        bwrap_command::build_args_classified_with_mode(&request, None, &HashSet::new(), mode);
    let launch_deadline = deadline.min(Instant::now() + BWRAP_VIABILITY_TIMEOUT);
    let mut command = Command::new("bwrap");
    command.args(args);
    probe_exec::run_bounded(&mut command, launch_deadline)
        .map_err(map_probe_failure)
        .and_then(finish_viability)
}

fn finish_viability(captured: CapturedProcess) -> Result<(), BwrapAvailabilityError> {
    if captured.stdout.truncated || captured.stderr.truncated {
        return Err(BwrapAvailabilityError::LaunchFailed {
            status: captured.status.code(),
            detail: format!(
                "probe output exceeded the {} byte limit",
                probe_exec::MAX_PROBE_OUTPUT_BYTES
            ),
        });
    }

    let cleanup = captured.cleanup_error;
    if captured.status.success() {
        if let Some(error) = cleanup {
            if error.kind() != io::ErrorKind::PermissionDenied {
                return Err(BwrapAvailabilityError::LaunchFailed {
                    status: captured.status.code(),
                    detail: format!("failed to clean up the probe process group: {error}"),
                });
            }
        }
        return Ok(());
    }

    let mut detail = String::from_utf8_lossy(&captured.stderr.bytes)
        .trim()
        .to_string();
    if detail.is_empty() {
        detail = "the minimal sandbox exited unsuccessfully".to_string();
    }
    if let Some(error) = cleanup {
        detail.push_str(&format!(
            "; failed to clean up the probe process group: {error}"
        ));
    }
    Err(BwrapAvailabilityError::LaunchFailed {
        status: captured.status.code(),
        detail,
    })
}

fn map_probe_failure(failure: ProbeFailure) -> BwrapAvailabilityError {
    let detail = match failure {
        ProbeFailure::Spawn(error) => format!("failed to start bwrap: {error}"),
        ProbeFailure::TimedOut { cleanup_error } => {
            let suffix = cleanup_error
                .map(|error| format!("; failed to terminate it: {error}"))
                .unwrap_or_default();
            format!(
                "timed out after {}ms{suffix}",
                BWRAP_VIABILITY_TIMEOUT.as_millis()
            )
        }
        ProbeFailure::Wait { stage, error } => {
            format!(
                "failed while {} the launchability probe: {error}",
                stage.as_str()
            )
        }
        ProbeFailure::Internal(detail) => detail,
    };
    BwrapAvailabilityError::LaunchFailed {
        status: None,
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn viability_request_uses_shared_network_and_production_arguments() {
        let request = viability_request();
        let mode = ResolvedNetworkMode::from_request(&request, false);
        let args =
            bwrap_command::build_args_classified_with_mode(&request, None, &HashSet::new(), mode);

        assert_eq!(mode, ResolvedNetworkMode::Shared);
        assert!(!args.iter().any(|argument| argument == "--unshare-net"));
        assert!(args
            .windows(3)
            .any(|arguments| arguments == ["--setenv", "PATH", "/usr/bin:/bin"]));
        assert!(args
            .windows(3)
            .any(|arguments| arguments == ["--", "sh", "-c"]));
        assert_eq!(args.last().map(String::as_str), Some("exit 0"));
    }

    #[test]
    fn successful_combined_probe_is_cached() {
        let state = Arc::new(AvailabilityState::default());
        let launches = Arc::new(AtomicUsize::new(0));
        let observed_launches = Arc::clone(&launches);
        let version = BwrapVersion::new(0, 11, 0);

        let first = probe_bwrap_available_cached(
            Arc::clone(&state),
            Duration::from_secs(1),
            || Ok(version),
            move |_, _| {
                observed_launches.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );
        let second = probe_bwrap_available_cached(
            state,
            Duration::ZERO,
            || panic!("cached success must skip version probing"),
            |_, _| panic!("cached success must skip viability launch"),
        );

        assert_eq!(first, Ok(version));
        assert_eq!(second, first);
        assert_eq!(launches.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn failed_combined_probe_is_not_cached() {
        let state = Arc::new(AvailabilityState::default());
        let version = BwrapVersion::new(0, 11, 0);
        let version_probes = Arc::new(AtomicUsize::new(0));
        let failure = BwrapAvailabilityError::LaunchFailed {
            status: Some(1),
            detail: "denied".to_string(),
        };

        assert_eq!(
            probe_bwrap_available_cached(
                Arc::clone(&state),
                Duration::from_secs(1),
                {
                    let version_probes = Arc::clone(&version_probes);
                    move || {
                        version_probes.fetch_add(1, Ordering::SeqCst);
                        Ok(version)
                    }
                },
                {
                    let failure = failure.clone();
                    move |_, _| Err(failure)
                },
            ),
            Err(failure)
        );
        assert_eq!(
            probe_bwrap_available_cached(
                state,
                Duration::from_secs(1),
                {
                    let version_probes = Arc::clone(&version_probes);
                    move || {
                        version_probes.fetch_add(1, Ordering::SeqCst);
                        Ok(version)
                    }
                },
                |_, _| Ok(()),
            ),
            Ok(version)
        );
        assert_eq!(version_probes.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn version_failure_skips_viability_launch() {
        let state = Arc::new(AvailabilityState::default());
        let failure = BwrapUnavailable::NotFound;
        assert_eq!(
            probe_bwrap_available_cached(
                state,
                Duration::from_secs(1),
                {
                    let failure = failure.clone();
                    move || Err(failure)
                },
                |_, _| panic!("version failure must skip viability"),
            ),
            Err(BwrapAvailabilityError::Version(failure))
        );
    }

    #[test]
    fn combined_budget_equals_version_plus_viability() {
        assert_eq!(BWRAP_AVAILABILITY_TIMEOUT, Duration::from_secs(10));
        assert_eq!(
            BWRAP_AVAILABILITY_TIMEOUT,
            bwrap_version::BWRAP_VERSION_TIMEOUT + BWRAP_VIABILITY_TIMEOUT
        );
    }

    #[test]
    fn concurrent_callers_share_one_viability_launch() {
        let state = Arc::new(AvailabilityState::default());
        let version = BwrapVersion::new(0, 11, 0);
        let launches = Arc::new(AtomicUsize::new(0));
        let (started_sender, started_receiver) = mpsc::sync_channel(1);
        let (release_sender, release_receiver) = mpsc::sync_channel(1);

        let first_state = Arc::clone(&state);
        let first_launches = Arc::clone(&launches);
        let first = thread::spawn(move || {
            probe_bwrap_available_cached(
                first_state,
                Duration::from_secs(1),
                move || Ok(version),
                move |_, _| {
                    first_launches.fetch_add(1, Ordering::SeqCst);
                    started_sender.send(()).unwrap();
                    release_receiver.recv().unwrap();
                    Ok(())
                },
            )
        });
        started_receiver.recv().unwrap();

        let second_state = Arc::clone(&state);
        let second_launches = Arc::clone(&launches);
        let second = thread::spawn(move || {
            probe_bwrap_available_cached(
                second_state,
                Duration::from_secs(1),
                move || Ok(version),
                move |_, _| {
                    second_launches.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
            )
        });

        release_sender.send(()).unwrap();
        assert_eq!(first.join().unwrap(), Ok(version));
        assert_eq!(second.join().unwrap(), Ok(version));
        assert_eq!(launches.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn timed_out_waiter_does_not_start_a_duplicate_launch() {
        let state = Arc::new(AvailabilityState::default());
        let version = BwrapVersion::new(0, 11, 0);
        let launches = Arc::new(AtomicUsize::new(0));
        let (started_sender, started_receiver) = mpsc::sync_channel(1);
        let (release_sender, release_receiver) = mpsc::sync_channel(1);

        let first_state = Arc::clone(&state);
        let first_launches = Arc::clone(&launches);
        let first = thread::spawn(move || {
            probe_bwrap_available_cached(
                first_state,
                Duration::from_secs(1),
                move || Ok(version),
                move |_, _| {
                    first_launches.fetch_add(1, Ordering::SeqCst);
                    started_sender.send(()).unwrap();
                    release_receiver.recv().unwrap();
                    Ok(())
                },
            )
        });
        started_receiver.recv().unwrap();

        let second_launches = Arc::clone(&launches);
        let timeout = probe_bwrap_available_cached(
            Arc::clone(&state),
            Duration::from_millis(10),
            move || Ok(version),
            move |_, _| {
                second_launches.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(
            timeout,
            BwrapAvailabilityError::LaunchFailed {
                status: None,
                detail: "timed out after 10ms".to_string(),
            }
        );
        assert_eq!(launches.load(Ordering::SeqCst), 1);

        release_sender.send(()).unwrap();
        assert_eq!(first.join().unwrap(), Ok(version));
        assert_eq!(
            probe_bwrap_available_cached(
                state,
                Duration::ZERO,
                || panic!("published success must skip version probing"),
                |_, _| panic!("published success must skip viability launch"),
            ),
            Ok(version)
        );
    }

    #[test]
    fn success_published_after_result_timeout_is_visible_to_next_caller() {
        let state = Arc::new(AvailabilityState::default());
        let version = BwrapVersion::new(0, 11, 0);
        let launches = Arc::new(AtomicUsize::new(0));
        let observed_launches = Arc::clone(&launches);
        let (release_sender, release_receiver) = mpsc::sync_channel(1);

        let result = probe_bwrap_available_cached(
            Arc::clone(&state),
            Duration::from_millis(10),
            || Ok(version),
            move |_, _| {
                observed_launches.fetch_add(1, Ordering::SeqCst);
                release_receiver.recv().unwrap();
                Ok(())
            },
        );
        assert_eq!(
            result.unwrap_err(),
            BwrapAvailabilityError::LaunchFailed {
                status: None,
                detail: "timed out after 10ms".to_string(),
            }
        );

        release_sender.send(()).unwrap();
        let published_deadline = Instant::now() + Duration::from_secs(1);
        while state.success.get().is_none() && Instant::now() < published_deadline {
            thread::yield_now();
        }
        assert_eq!(state.success.get(), Some(&version));
        assert_eq!(
            probe_bwrap_available_cached(
                state,
                Duration::ZERO,
                || panic!("published success must skip version probing"),
                |_, _| panic!("published success must skip viability launch"),
            ),
            Ok(version)
        );
        assert_eq!(launches.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn disconnected_worker_is_not_reported_as_a_timeout() {
        let error = probe_bwrap_available_cached(
            Arc::new(AvailabilityState::default()),
            Duration::from_secs(1),
            || Ok(BwrapVersion::new(0, 11, 0)),
            |_, _| panic!("simulated worker failure"),
        )
        .unwrap_err();

        assert_eq!(
            error,
            BwrapAvailabilityError::LaunchFailed {
                status: None,
                detail: "launchability worker exited without returning a result".to_string(),
            }
        );
    }

    #[test]
    fn version_probe_runs_before_waiting_for_the_viability_gate() {
        let state = Arc::new(AvailabilityState::default());
        let permit = state
            .gate
            .acquire_permit_until(Instant::now() + Duration::from_secs(1))
            .expect("test owns the gate");
        let versions = Arc::new(AtomicUsize::new(0));
        let observed_versions = Arc::clone(&versions);

        let error = probe_bwrap_available_cached(
            state,
            Duration::from_millis(10),
            move || {
                observed_versions.fetch_add(1, Ordering::SeqCst);
                Ok(BwrapVersion::new(0, 11, 0))
            },
            |_, _| panic!("a timed-out gate waiter must not launch"),
        )
        .unwrap_err();

        drop(permit);
        assert_eq!(versions.load(Ordering::SeqCst), 1);
        assert_eq!(
            error,
            BwrapAvailabilityError::LaunchFailed {
                status: None,
                detail: "timed out after 10ms".to_string(),
            }
        );
    }

    fn captured(
        raw_status: i32,
        stderr: &[u8],
        cleanup_error: Option<io::Error>,
    ) -> CapturedProcess {
        CapturedProcess {
            status: std::process::ExitStatus::from_raw(raw_status),
            stdout: probe_exec::CapturedOutput {
                bytes: Vec::new(),
                truncated: false,
            },
            stderr: probe_exec::CapturedOutput {
                bytes: stderr.to_vec(),
                truncated: false,
            },
            cleanup_error,
        }
    }

    #[test]
    fn reaped_zero_exit_ignores_setuid_permission_denied_cleanup_diagnostic() {
        assert_eq!(
            finish_viability(captured(
                0,
                &[],
                Some(io::Error::from(io::ErrorKind::PermissionDenied)),
            )),
            Ok(())
        );
    }

    #[test]
    fn reaped_zero_exit_rejects_unexpected_cleanup_diagnostic() {
        let error = finish_viability(captured(
            0,
            &[],
            Some(io::Error::new(
                io::ErrorKind::TimedOut,
                "cleanup deadline expired",
            )),
        ))
        .unwrap_err();
        assert_eq!(
            error,
            BwrapAvailabilityError::LaunchFailed {
                status: Some(0),
                detail: "failed to clean up the probe process group: cleanup deadline expired"
                    .to_string(),
            }
        );
    }

    #[test]
    fn nonzero_exit_includes_cleanup_diagnostic_as_context() {
        let error = finish_viability(captured(
            1 << 8,
            b"user namespaces disabled",
            Some(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "cleanup denied",
            )),
        ))
        .unwrap_err();
        assert_eq!(
            error,
            BwrapAvailabilityError::LaunchFailed {
                status: Some(1),
                detail: "user namespaces disabled; failed to clean up the probe process group: cleanup denied"
                    .to_string(),
            }
        );
    }

    #[test]
    fn truncated_output_is_a_launch_failure() {
        let mut process = captured(0, &[], None);
        process.stdout.truncated = true;
        let error = finish_viability(process).unwrap_err();
        assert_eq!(
            error,
            BwrapAvailabilityError::LaunchFailed {
                status: Some(0),
                detail: format!(
                    "probe output exceeded the {} byte limit",
                    probe_exec::MAX_PROBE_OUTPUT_BYTES
                ),
            }
        );
    }

    #[test]
    fn probe_failures_preserve_actionable_causes() {
        let cases = [
            (
                ProbeFailure::Spawn(io::Error::new(io::ErrorKind::NotFound, "missing")),
                "failed to start bwrap: missing",
            ),
            (
                ProbeFailure::TimedOut {
                    cleanup_error: None,
                },
                "timed out after 5000ms",
            ),
            (
                ProbeFailure::TimedOut {
                    cleanup_error: Some(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "kill denied",
                    )),
                },
                "timed out after 5000ms; failed to terminate it: kill denied",
            ),
            (
                ProbeFailure::Wait {
                    stage: probe_exec::WaitStage::Waiting,
                    error: io::Error::new(io::ErrorKind::Other, "wait failed"),
                },
                "failed while waiting for the launchability probe: wait failed",
            ),
            (
                ProbeFailure::Wait {
                    stage: probe_exec::WaitStage::Reaping,
                    error: io::Error::new(io::ErrorKind::Other, "reap failed"),
                },
                "failed while reaping the launchability probe: reap failed",
            ),
            (
                ProbeFailure::Internal("reader failed".to_string()),
                "reader failed",
            ),
        ];

        for (failure, expected) in cases {
            assert_eq!(
                map_probe_failure(failure),
                BwrapAvailabilityError::LaunchFailed {
                    status: None,
                    detail: expected.to_string(),
                }
            );
        }
    }

    #[test]
    fn availability_errors_have_distinct_messages() {
        let version_error = BwrapAvailabilityError::Version(BwrapUnavailable::NotFound);
        let launch_error = BwrapAvailabilityError::LaunchFailed {
            status: Some(1),
            detail: "denied".to_string(),
        };

        assert_eq!(
            version_error.to_string(),
            "Bubblewrap (bwrap) is not installed or not on PATH. Install it via your package manager (e.g., apt install bubblewrap). Version 0.5.0 or newer is required."
        );
        assert_eq!(
            launch_error.to_string(),
            "The Bubblewrap (bwrap) sandbox launchability probe exited with status 1: denied"
        );
    }
}
