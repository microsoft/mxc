// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Dependency-injection boundary for the guarded WPR capture fallback.
//!
//! `appcontainer_common` implements the legacy containment tiers (BaseContainer
//! SBOX, AppContainer + BFS, AppContainer + DACL) that a host without the
//! native V2 PSEC + Learning Mode APIs still needs `captureDenials` on.
//! Elevated WPR capture lives in `plm` (the host's guarded PLM tool), and
//! `appcontainer_common` MUST NOT depend on `plm` directly: `plm` links the
//! Windows ETL decoder (`learning_mode_windows`) and elevation/pipe machinery
//! that is unrelated to this crate's job, and the crate-layering rule
//! (backend-support crates don't cross-depend on one another) forbids it.
//!
//! Instead, this module defines the minimal traits a legacy-tier runner needs
//! to start and stop a guarded WPR capture scoped to its own sandboxed process
//! tree. `mxc_engine` (which already depends on `plm` for the executor
//! binaries' guarded-PLM lifecycle) implements them by adapting
//! `plm::elevated::{start_guarded_session_with_executable, GuardedSession}`,
//! and hands the concrete factory to the dispatcher only when it explicitly
//! opts a request into the fallback (see
//! `dispatcher::dispatch_with_fallback_and_capture` /
//! `dispatcher::spawn_with_fallback_and_capture`) — a runner never picks up
//! guarded capture silently.

use std::path::Path;

use learning_mode_core::AnalysisResult;
use wxc_common::models::{
    CaptureDenialsErrorOutput, FailurePhase, SandboxOutputMetadata, ScriptResponse,
};

/// Error returned when an injected guarded-capture implementation cannot
/// transfer retained ETL requested by the caller.
pub const RETAIN_ETL_UNSUPPORTED_MSG: &str =
    "processContainer.captureDenials.retainEtl is not supported by the configured \
     guarded-WPR capture provider";

/// Outcome of [`GuardedCaptureSession::stop_analyzed_with_trace`].
///
/// The process-scoped [`AnalysisResult`] is always present: an analysis failure
/// is reported as the method's `Err`, never as a value here. `trace_retention`
/// independently reports whether the sealed ETL was transferred to the
/// requested destination — a retention failure that occurs *after* a successful
/// analysis is carried as data so the canonical denials JSON can still be
/// published while the retention failure is surfaced separately.
#[derive(Debug)]
pub struct AnalyzedTrace {
    /// The bounded, process-scoped analysis of the guarded WPR trace.
    pub analysis: AnalysisResult,
    /// Whether the sealed ETL reached the requested destination. `Ok(())` means
    /// the ETL is persisted there; `Err` carries the retention failure while the
    /// `analysis` above remains valid.
    pub trace_retention: Result<(), String>,
}

/// A live guarded WPR capture session scoped to one sandboxed process tree.
///
/// Implementations own the elevated PLM child connection. [`stop_analyzed`]
/// asks the guardian to stop the host-wide WPR trace and decode it, returning
/// the bounded, process-scoped [`AnalysisResult`]. When the caller explicitly
/// requests `retainEtl`, implementations that support trace transfer may also
/// return the sealed ETL through [`stop_analyzed_with_trace`].
///
/// [`stop_analyzed`]: GuardedCaptureSession::stop_analyzed
pub trait GuardedCaptureSession: Send {
    /// Duplicates and attaches the caller's sandbox job and still-owned
    /// suspended root process in the elevated guardian. Both values must be
    /// HANDLEs owned by the authenticated unelevated process.
    fn attach_process_tree(
        &mut self,
        job_handle: usize,
        root_process_handle: usize,
    ) -> Result<(), String>;

    /// Stops the owned WPR trace and securely discards its raw ETL without
    /// analysis. Used when job attachment, sandbox launch, or sandbox
    /// termination fails.
    ///
    /// This method must not return, on either success or error, until the
    /// elevated guardian has terminated and released every duplicated sandbox
    /// handle. Runners rely on that guarantee before allowing firewall,
    /// filesystem, and DACL enforcement guards to drop.
    fn discard(&mut self) -> Result<(), String>;

    /// Stops the guarded capture and analyzes it against exact process
    /// generations: the guardian-attested root handle lifetime plus descendants
    /// reconciled from retained handles and job membership accounting.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message if the guardian connection is gone,
    /// the stop/analyze round trip fails, or the guardian reports a decode
    /// error.
    fn stop_analyzed(&mut self) -> Result<AnalysisResult, String>;

    /// Stops and analyzes the guarded capture, and transfers the sealed ETL to
    /// `trace_destination` when the caller explicitly requests ETL retention.
    ///
    /// # Errors
    ///
    /// `Err` represents an *analysis* failure. A trace-transfer failure that
    /// occurs after a successful analysis is NOT an error here: it is carried in
    /// [`AnalyzedTrace::trace_retention`] so the decoded denials are never
    /// discarded.
    fn stop_analyzed_with_trace(
        &mut self,
        trace_destination: &std::path::Path,
    ) -> Result<AnalyzedTrace, String>;
}

/// Starts a [`GuardedCaptureSession`] for the calling (unelevated) process.
///
/// Implementations are constructed by a higher layer (`mxc_engine`) that can
/// depend on `plm`; `appcontainer_common` only ever sees the trait object.
pub trait GuardedCaptureFactory: Send + Sync {
    /// Whether this factory can transfer the sealed ETL when `retainEtl` is
    /// requested. Implementations that only support analysis keep the default.
    fn allows_trace_transfer(&self) -> bool {
        false
    }

    /// Starts a new guarded WPR capture session.
    ///
    /// `owner_pid` is the calling (unelevated) process's own OS process id —
    /// used by the elevated guardian to authenticate the connection — **not**
    /// the sandboxed child's pid. The child identity and lifetime are attested
    /// later from its duplicated process handle; no caller-supplied child PID
    /// or timestamp is trusted.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message on failure (elevation refused,
    /// guardian unreachable, a WPR session is already active, etc.). The
    /// caller must terminate the still-suspended sandboxed child on failure
    /// rather than resume it, so no active trace is ever left behind.
    fn start(&self, owner_pid: u32) -> Result<Box<dyn GuardedCaptureSession>, String>;
}

pub(crate) fn release_after_termination_failure(
    mut session: Box<dyn GuardedCaptureSession>,
) -> Result<(), String> {
    session.discard()
}

/// Fails closed when `retainEtl` is requested but cannot be honored.
///
/// ETL retention is satisfied either by a native capture path that seals its
/// own ETL (`native_capture_retains_etl` — BaseContainer's PSEC/V2 path) or by a
/// guarded-WPR provider that can transfer the sealed ETL
/// (`provider_allows_trace_transfer`). When retention is requested and neither
/// holds, the request is rejected with [`RETAIN_ETL_UNSUPPORTED_MSG`].
///
/// Centralized so both the AppContainer fallback tiers (which have no native
/// capture path and always pass `native_capture_retains_etl = false`) and the
/// BaseContainer runner (which passes `true` when its native PSEC/V2 capture is
/// selected, making the guarded-provider capability irrelevant) share one gate.
pub fn validate_retain_etl_supported(
    retain_etl: bool,
    provider_allows_trace_transfer: bool,
    native_capture_retains_etl: bool,
) -> Result<(), ScriptResponse> {
    if retain_etl && !native_capture_retains_etl && !provider_allows_trace_transfer {
        return Err(ScriptResponse {
            failure_phase: FailurePhase::BackendUnavailable,
            ..ScriptResponse::error(RETAIN_ETL_UNSUPPORTED_MSG)
        });
    }
    Ok(())
}

/// Structured output metadata plus the teardown status produced by finalizing a
/// guarded WPR capture. Both legacy-tier runners (`appcontainer_runner`,
/// `base_container_runner`) consume this so the analysis-success/trace-failure
/// and trace-success/JSON-failure transitions live in exactly one place and
/// cannot drift between the two runners.
#[derive(Debug)]
pub struct GuardedCaptureFinalization {
    /// Structured output metadata to store on the sandbox process, if any.
    pub metadata: Option<SandboxOutputMetadata>,
    /// Teardown status to thread through the runner's `wait()`. `Ok(())` iff the
    /// canonical denials JSON was written and no retention was requested (or
    /// retention succeeded); a retention-only failure after a successful
    /// analysis returns `Err` while still publishing the JSON via `metadata`
    /// (mirroring the native capture path).
    pub result: Result<(), String>,
}

/// How the caller asked the guarded capture to be stopped, plus — for the
/// retention case — the transfer destination. Selects `stop_analyzed` vs
/// `stop_analyzed_with_trace` inside [`finalize_guarded_capture`].
pub enum GuardedStop<'a> {
    /// `retainEtl` not requested: stop and analyze only.
    AnalyzeOnly,
    /// `retainEtl` requested: stop, analyze, and transfer the sealed ETL to
    /// `destination`.
    AnalyzeAndRetain { destination: &'a Path },
}

/// Stops a guarded WPR capture and turns its outcome into the canonical denials
/// JSON plus structured metadata, in one shared place for both legacy-tier
/// runners.
///
/// - Analysis failure ⇒ no JSON, `metadata: None`, `result: Err`.
/// - Analysis success, no retention ⇒ JSON written, success metadata,
///   `result: Ok`.
/// - Analysis success, retention success ⇒ JSON written with `etlPath` set,
///   `result: Ok`.
/// - Analysis success, retention failure ⇒ JSON written (canonical success,
///   `etlPath = None`) AND `capture_denials_error` describing the retention
///   failure with an empty ETL path (nothing was persisted); `result: Err`.
/// - Analysis + retention success but the JSON write fails ⇒ `etlPath` is
///   preserved in `capture_denials_error` so the caller can find/delete the
///   retained ETL; `result: Err`.
pub fn finalize_guarded_capture(
    session: &mut dyn GuardedCaptureSession,
    output_path: Option<&Path>,
    stop: GuardedStop<'_>,
    exit_code: i32,
) -> GuardedCaptureFinalization {
    match stop {
        GuardedStop::AnalyzeOnly => {
            finalize_analysis(session.stop_analyzed(), output_path, exit_code, None)
        }
        GuardedStop::AnalyzeAndRetain { destination } => {
            match session.stop_analyzed_with_trace(destination) {
                Ok(AnalyzedTrace {
                    analysis,
                    trace_retention,
                }) => finalize_analysis(
                    Ok(analysis),
                    output_path,
                    exit_code,
                    Some((destination, trace_retention)),
                ),
                // Analysis failure: nothing decoded, nothing persisted.
                Err(error) => finalize_analysis(Err(error), output_path, exit_code, None),
            }
        }
    }
}

/// Core of [`finalize_guarded_capture`]: publishes the denials JSON and
/// computes the metadata / teardown status from the analysis result and the
/// optional retention outcome (`(destination, transfer status)`).
fn finalize_analysis(
    analysis: Result<AnalysisResult, String>,
    output_path: Option<&Path>,
    exit_code: i32,
    retention: Option<(&Path, Result<(), String>)>,
) -> GuardedCaptureFinalization {
    let analysis = match analysis {
        Ok(analysis) => analysis,
        Err(error) => {
            return GuardedCaptureFinalization {
                metadata: None,
                result: Err(format!(
                    "captureDenials failed to stop and analyze the guarded WPR session: {error}"
                )),
            };
        }
    };
    let Some(output_path) = output_path else {
        return GuardedCaptureFinalization {
            metadata: None,
            result: Err("captureDenials internal output path was not initialized".to_string()),
        };
    };
    match crate::capture_output::write_denials_document(analysis, exit_code, output_path) {
        Ok(mut success) => match retention {
            // No retention requested, or retention succeeded: publish success.
            None | Some((_, Ok(()))) => {
                if let Some((destination, Ok(()))) = retention {
                    success.etl_path = Some(destination.to_string_lossy().into_owned());
                }
                GuardedCaptureFinalization {
                    metadata: Some(SandboxOutputMetadata {
                        capture_denials: Some(success),
                        capture_denials_error: None,
                    }),
                    result: Ok(()),
                }
            }
            // Retention requested but the transfer failed: publish the canonical
            // JSON success (etlPath stays None — nothing persisted) and surface
            // the retention failure with an empty ETL path.
            Some((_, Err(retention_error))) => {
                let message =
                    format!("captureDenials could not retain the sealed ETL: {retention_error}");
                GuardedCaptureFinalization {
                    metadata: Some(SandboxOutputMetadata {
                        capture_denials: Some(success),
                        capture_denials_error: Some(CaptureDenialsErrorOutput {
                            message: message.clone(),
                            etl_path: String::new(),
                        }),
                    }),
                    result: Err(message),
                }
            }
        },
        Err(write_error) => {
            // The JSON write failed. When the ETL was successfully retained,
            // preserve its path so the caller can still find/delete it.
            let retained_etl = match retention {
                Some((destination, Ok(()))) => Some(destination.to_string_lossy().into_owned()),
                _ => None,
            };
            let message = write_error.to_string();
            let metadata = retained_etl.map(|etl_path| SandboxOutputMetadata {
                capture_denials: None,
                capture_denials_error: Some(CaptureDenialsErrorOutput {
                    message: message.clone(),
                    etl_path,
                }),
            });
            GuardedCaptureFinalization {
                metadata,
                result: Err(message),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use learning_mode_core::{AccessType, DeniedResource, ResourceType};

    /// A fake session/factory pair proving both traits are object-safe and
    /// usable behind `dyn` references — the shape the dispatcher stores them
    /// in ([`crate::guarded_capture`] traits are only ever consumed as trait
    /// objects across the `appcontainer_common` / `mxc_engine` boundary).
    struct FakeSession {
        analysis: AnalysisResult,
    }

    impl GuardedCaptureSession for FakeSession {
        fn attach_process_tree(
            &mut self,
            job_handle: usize,
            root_process_handle: usize,
        ) -> Result<(), String> {
            if job_handle == 0 || root_process_handle == 0 {
                return Err("handles must be non-zero".to_string());
            }
            Ok(())
        }

        fn discard(&mut self) -> Result<(), String> {
            Ok(())
        }

        fn stop_analyzed(&mut self) -> Result<AnalysisResult, String> {
            Ok(self.analysis.clone())
        }

        fn stop_analyzed_with_trace(
            &mut self,
            trace_destination: &std::path::Path,
        ) -> Result<AnalyzedTrace, String> {
            std::fs::write(trace_destination, b"fake etl").map_err(|error| error.to_string())?;
            Ok(AnalyzedTrace {
                analysis: self.analysis.clone(),
                trace_retention: Ok(()),
            })
        }
    }

    struct FakeFactory;

    impl GuardedCaptureFactory for FakeFactory {
        fn allows_trace_transfer(&self) -> bool {
            true
        }

        fn start(&self, owner_pid: u32) -> Result<Box<dyn GuardedCaptureSession>, String> {
            if owner_pid == 0 {
                return Err("owner pid must be non-zero".to_string());
            }
            Ok(Box::new(FakeSession {
                analysis: AnalysisResult::complete(vec![DeniedResource {
                    resource: r"C:\blocked.txt".to_string(),
                    resource_type: ResourceType::File,
                    access_type: AccessType::Read,
                    pid: owner_pid,
                    filetime: 1,
                }]),
            }))
        }
    }

    #[test]
    fn factory_and_session_are_object_safe() {
        let factory: Box<dyn GuardedCaptureFactory> = Box::new(FakeFactory);
        let mut session = factory.start(1234).expect("start should succeed");
        session
            .attach_process_tree(42, 43)
            .expect("attach_process_tree should succeed");
        let analysis = session
            .stop_analyzed()
            .expect("stop_analyzed should succeed");
        assert_eq!(analysis.denials.len(), 1);
    }

    #[test]
    fn factory_rejects_zero_owner_pid() {
        let factory: Box<dyn GuardedCaptureFactory> = Box::new(FakeFactory);
        let error = match factory.start(0) {
            Ok(_) => panic!("owner pid 0 must be rejected"),
            Err(error) => error,
        };
        assert!(error.contains("owner pid"));
    }

    #[test]
    fn release_waits_for_discard_contract_completion() {
        struct BlockingSession {
            entered: std::sync::mpsc::Sender<()>,
            release: std::sync::mpsc::Receiver<()>,
        }

        impl GuardedCaptureSession for BlockingSession {
            fn attach_process_tree(
                &mut self,
                _job_handle: usize,
                _root_process_handle: usize,
            ) -> Result<(), String> {
                Ok(())
            }

            fn discard(&mut self) -> Result<(), String> {
                self.entered.send(()).unwrap();
                self.release.recv().unwrap();
                Err("discard failed after guardian release".to_string())
            }

            fn stop_analyzed(&mut self) -> Result<AnalysisResult, String> {
                unreachable!()
            }

            fn stop_analyzed_with_trace(
                &mut self,
                _trace_destination: &std::path::Path,
            ) -> Result<AnalyzedTrace, String> {
                unreachable!()
            }
        }

        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let result = release_after_termination_failure(Box::new(BlockingSession {
                entered: entered_tx,
                release: release_rx,
            }));
            done_tx.send(result).unwrap();
        });

        entered_rx.recv().unwrap();
        assert!(done_rx
            .recv_timeout(std::time::Duration::from_millis(50))
            .is_err());
        release_tx.send(()).unwrap();
        assert_eq!(
            done_rx.recv().unwrap().unwrap_err(),
            "discard failed after guardian release"
        );
        thread.join().unwrap();
    }

    struct ScriptedSession {
        analysis: Result<AnalysisResult, String>,
        trace_retention: Result<(), String>,
    }

    impl GuardedCaptureSession for ScriptedSession {
        fn attach_process_tree(&mut self, _job: usize, _root: usize) -> Result<(), String> {
            Ok(())
        }

        fn discard(&mut self) -> Result<(), String> {
            Ok(())
        }

        fn stop_analyzed(&mut self) -> Result<AnalysisResult, String> {
            self.analysis.clone()
        }

        fn stop_analyzed_with_trace(
            &mut self,
            trace_destination: &std::path::Path,
        ) -> Result<AnalyzedTrace, String> {
            // Analysis failure short-circuits before any ETL is persisted.
            let analysis = self.analysis.clone()?;
            // Model the guardian atomically persisting the ETL only on transfer
            // success, so a retention failure leaves nothing at the destination.
            if self.trace_retention.is_ok() {
                std::fs::write(trace_destination, b"etl").map_err(|error| error.to_string())?;
            }
            Ok(AnalyzedTrace {
                analysis,
                trace_retention: self.trace_retention.clone(),
            })
        }
    }

    fn analysis_with_one_denial() -> AnalysisResult {
        AnalysisResult::complete(vec![DeniedResource {
            resource: r"C:\blocked.txt".to_string(),
            resource_type: ResourceType::File,
            access_type: AccessType::Read,
            pid: 4321,
            filetime: 7,
        }])
    }

    #[test]
    fn finalize_analyze_only_writes_json_success() {
        let directory = tempfile::tempdir().unwrap();
        let output_path = directory.path().join("denials.json");
        let mut session = ScriptedSession {
            analysis: Ok(analysis_with_one_denial()),
            trace_retention: Ok(()),
        };

        let finalization = finalize_guarded_capture(
            &mut session,
            Some(&output_path),
            GuardedStop::AnalyzeOnly,
            3,
        );

        assert!(finalization.result.is_ok());
        let capture = finalization
            .metadata
            .as_ref()
            .unwrap()
            .capture_denials
            .as_ref()
            .unwrap();
        assert_eq!(capture.total_denials, 1);
        assert_eq!(capture.etl_path, None);
        assert!(finalization
            .metadata
            .unwrap()
            .capture_denials_error
            .is_none());
        assert!(output_path.is_file());
    }

    #[test]
    fn finalize_retention_success_advertises_etl_path() {
        let directory = tempfile::tempdir().unwrap();
        let output_path = directory.path().join("denials.json");
        let etl_destination = directory.path().join("trace.etl");
        let mut session = ScriptedSession {
            analysis: Ok(analysis_with_one_denial()),
            trace_retention: Ok(()),
        };

        let finalization = finalize_guarded_capture(
            &mut session,
            Some(&output_path),
            GuardedStop::AnalyzeAndRetain {
                destination: &etl_destination,
            },
            0,
        );

        assert!(finalization.result.is_ok());
        let capture = finalization.metadata.unwrap().capture_denials.unwrap();
        assert_eq!(
            capture.etl_path.as_deref().map(std::path::Path::new),
            Some(etl_destination.as_path())
        );
        assert!(etl_destination.is_file());
    }

    #[test]
    fn finalize_trace_failure_after_analysis_publishes_json_and_surfaces_retention() {
        // The core analysis-success/trace-failure contract: the canonical
        // denials JSON is published (etlPath = None, nothing persisted) AND the
        // retention failure is surfaced through capture_denials_error with an
        // empty ETL path.
        let directory = tempfile::tempdir().unwrap();
        let output_path = directory.path().join("denials.json");
        let etl_destination = directory.path().join("trace.etl");
        let mut session = ScriptedSession {
            analysis: Ok(analysis_with_one_denial()),
            trace_retention: Err("the sealed ETL was too large to transfer".to_string()),
        };

        let finalization = finalize_guarded_capture(
            &mut session,
            Some(&output_path),
            GuardedStop::AnalyzeAndRetain {
                destination: &etl_destination,
            },
            0,
        );

        // Retention failure is reported through the teardown status...
        let error = finalization.result.unwrap_err();
        assert!(error.contains("too large to transfer"), "got: {error}");
        // ...while the canonical denials JSON is still published.
        assert!(output_path.is_file());
        let metadata = finalization.metadata.unwrap();
        let capture = metadata.capture_denials.unwrap();
        assert_eq!(capture.total_denials, 1);
        assert_eq!(capture.etl_path, None, "no ETL was retained");
        let failure = metadata.capture_denials_error.unwrap();
        assert!(failure.message.contains("too large to transfer"));
        assert_eq!(
            failure.etl_path, "",
            "nothing was persisted at the destination"
        );
        assert!(
            !etl_destination.exists(),
            "no ETL file should have been produced"
        );
    }

    #[test]
    fn finalize_json_failure_after_retention_preserves_etl_path() {
        // ETL retained, but the denials JSON write fails (destination collides
        // with an existing file): the retained ETL path must be preserved so the
        // caller can find/delete it.
        let directory = tempfile::tempdir().unwrap();
        let output_path = directory.path().join("denials.json");
        std::fs::write(&output_path, b"pre-existing").unwrap();
        let etl_destination = directory.path().join("trace.etl");
        let mut session = ScriptedSession {
            analysis: Ok(analysis_with_one_denial()),
            trace_retention: Ok(()),
        };

        let finalization = finalize_guarded_capture(
            &mut session,
            Some(&output_path),
            GuardedStop::AnalyzeAndRetain {
                destination: &etl_destination,
            },
            0,
        );

        assert!(finalization.result.is_err());
        let metadata = finalization.metadata.unwrap();
        assert!(metadata.capture_denials.is_none());
        let failure = metadata.capture_denials_error.unwrap();
        assert_eq!(
            std::path::Path::new(&failure.etl_path),
            etl_destination,
            "the retained ETL path must be preserved for cleanup"
        );
        assert!(etl_destination.is_file());
    }

    #[test]
    fn finalize_analysis_failure_publishes_nothing() {
        let directory = tempfile::tempdir().unwrap();
        let output_path = directory.path().join("denials.json");
        let mut session = ScriptedSession {
            analysis: Err("guardian connection lost".to_string()),
            trace_retention: Ok(()),
        };

        let finalization = finalize_guarded_capture(
            &mut session,
            Some(&output_path),
            GuardedStop::AnalyzeOnly,
            0,
        );

        assert!(finalization.metadata.is_none());
        assert!(finalization
            .result
            .unwrap_err()
            .contains("guardian connection lost"));
        assert!(
            !output_path.exists(),
            "no JSON should be written on analysis failure"
        );
    }

    #[test]
    fn retain_etl_validation_rejects_when_no_transfer_and_no_native() {
        let error = validate_retain_etl_supported(true, false, false).unwrap_err();
        assert_eq!(error.failure_phase, FailurePhase::BackendUnavailable);
        assert_eq!(error.error_message, RETAIN_ETL_UNSUPPORTED_MSG);
    }

    #[test]
    fn retain_etl_validation_allows_when_provider_supports_transfer() {
        assert!(validate_retain_etl_supported(true, true, false).is_ok());
    }

    #[test]
    fn retain_etl_validation_allows_native_capture_without_transfer() {
        // BaseContainer's native PSEC/V2 capture retains its own ETL, so the
        // guarded-provider transfer capability is irrelevant.
        assert!(validate_retain_etl_supported(true, false, true).is_ok());
    }

    #[test]
    fn retain_etl_validation_allows_when_retention_not_requested() {
        assert!(validate_retain_etl_supported(false, false, false).is_ok());
    }
}
