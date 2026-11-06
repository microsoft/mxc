// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Results of create-and-run backends that return captured output instead of
//! live streams (the NVX MicroVM and ACI backends).

use std::io::Write;

use crate::mxc_common::logger::Logger;
use crate::mxc_common::models::{FailurePhase, ScriptResponse};
use crate::mxc_common::mxc_error::{MxcError, MxcErrorCode};

/// How a captured create-and-run workload finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapturedOutcome {
    /// The workload exited with this code.
    Exited(i32),
    /// The workload did not finish before `process.timeout`.
    TimedOut,
}

/// Outcome and output of a create-and-run backend that captures output rather
/// than streaming it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedRun {
    pub outcome: CapturedOutcome,
    pub warnings: Vec<String>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Short backend name used in timeout and relay messages, such as `NVX`.
    pub backend_label: &'static str,
}

impl CapturedRun {
    /// The run-to-completion response for this outcome.
    pub fn response(&self) -> ScriptResponse {
        match self.outcome {
            CapturedOutcome::Exited(exit_code) => ScriptResponse {
                exit_code,
                ..Default::default()
            },
            CapturedOutcome::TimedOut => ScriptResponse {
                exit_code: -1,
                error_message: format!("{} workload timed out", self.backend_label),
                failure_phase: FailurePhase::Timeout,
                ..Default::default()
            },
        }
    }

    /// Writes the captured streams unchanged to `stdout` and `stderr`, then
    /// returns the run-to-completion response.
    pub fn relay(
        self,
        stdout: &mut impl Write,
        stderr: &mut impl Write,
    ) -> Result<ScriptResponse, MxcError> {
        let label = self.backend_label;
        stdout
            .write_all(&self.stdout)
            .and_then(|()| stdout.flush())
            .map_err(|error| {
                MxcError::backend_error(format!("cannot relay {label} stdout: {error}"))
            })?;
        stderr
            .write_all(&self.stderr)
            .and_then(|()| stderr.flush())
            .map_err(|error| {
                MxcError::backend_error(format!("cannot relay {label} stderr: {error}"))
            })?;
        Ok(self.response())
    }
}

/// Maps a captured-backend error to the run-to-completion response the
/// executor reports.
pub fn error_response(error: MxcError) -> ScriptResponse {
    match error.code {
        MxcErrorCode::PolicyValidation | MxcErrorCode::MalformedRequest => {
            ScriptResponse::rejected(&error.message)
        }
        MxcErrorCode::BackendUnavailable => ScriptResponse::unavailable(&error.message),
        _ => ScriptResponse::failed(FailurePhase::PostLaunchFailed, &error.to_string()),
    }
}

/// Combines a run's primary result with the cleanup failures that followed it.
///
/// A cleanup failure turns a successful run into an error, because the caller
/// must learn that backend resources may remain. A failed run keeps its
/// original error code and gains the cleanup failures in its message.
pub fn finish_with_cleanup<T>(
    backend_label: &str,
    primary: Result<T, MxcError>,
    cleanup_errors: Vec<MxcError>,
    logger: &mut Logger,
) -> Result<T, MxcError> {
    match primary {
        Ok(output) if cleanup_errors.is_empty() => Ok(output),
        Ok(_) => Err(MxcError::backend_error(format!(
            "{backend_label} cleanup failed after workload completion: {}",
            cleanup_errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        ))),
        Err(mut error) => {
            for cleanup in cleanup_errors {
                logger.warning_line(&format!("{backend_label} cleanup failed: {cleanup}"));
                error.message.push_str("; cleanup failure: ");
                error.message.push_str(&cleanup.to_string());
            }
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(outcome: CapturedOutcome, stdout: &[u8], stderr: &[u8]) -> CapturedRun {
        CapturedRun {
            outcome,
            warnings: Vec::new(),
            stdout: stdout.to_vec(),
            stderr: stderr.to_vec(),
            backend_label: "TEST",
        }
    }

    #[test]
    fn relay_preserves_exit_code_and_bytes() {
        for (expected_stdout, expected_stderr) in [
            (b"out".as_slice(), b"err".as_slice()),
            (b"\xff\0\xfe".as_slice(), b"\x80\0\x81".as_slice()),
            (b"".as_slice(), b"".as_slice()),
        ] {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let response = run(
                CapturedOutcome::Exited(42),
                expected_stdout,
                expected_stderr,
            )
            .relay(&mut stdout, &mut stderr)
            .unwrap();
            assert_eq!(response.exit_code, 42);
            assert_eq!(stdout, expected_stdout);
            assert_eq!(stderr, expected_stderr);
            assert!(response.standard_out.is_empty());
            assert!(response.standard_err.is_empty());
            assert!(response.error_message.is_empty());
        }
    }

    #[test]
    fn timeout_names_the_backend_and_keeps_partial_output() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let response = run(CapturedOutcome::TimedOut, b"partial-out", b"partial-err")
            .relay(&mut stdout, &mut stderr)
            .unwrap();
        assert_eq!(response.exit_code, -1);
        assert_eq!(response.failure_phase, FailurePhase::Timeout);
        assert_eq!(response.error_message, "TEST workload timed out");
        assert_eq!(stdout, b"partial-out");
        assert_eq!(stderr, b"partial-err");
    }

    #[test]
    fn relay_failures_name_the_backend_and_stream() {
        struct FailingWriter {
            on_flush: bool,
        }

        impl Write for FailingWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.on_flush {
                    Ok(bytes.len())
                } else {
                    Err(std::io::Error::other("test write failure"))
                }
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::other("test flush failure"))
            }
        }

        for on_flush in [false, true] {
            for stream in ["stdout", "stderr"] {
                let result = run(CapturedOutcome::Exited(0), b"out", b"err");
                let mut failing = FailingWriter { on_flush };
                let mut sink = std::io::sink();
                let error = if stream == "stdout" {
                    result.relay(&mut failing, &mut sink)
                } else {
                    result.relay(&mut sink, &mut failing)
                }
                .unwrap_err();
                assert_eq!(error.code, MxcErrorCode::BackendError);
                let operation = if on_flush { "flush" } else { "write" };
                assert_eq!(
                    error.message,
                    format!("cannot relay TEST {stream}: test {operation} failure")
                );
            }
        }
    }

    #[test]
    fn error_response_preserves_rejection_and_availability_categories() {
        let rejected = error_response(MxcError::policy_validation("refused"));
        assert_eq!(
            rejected.failure_phase.error_code().as_str(),
            "policy_validation"
        );
        let malformed = error_response(MxcError::malformed_request("bad"));
        assert_eq!(
            malformed.failure_phase.error_code().as_str(),
            "policy_validation"
        );
        let unavailable = error_response(MxcError::backend_unavailable("missing"));
        assert_eq!(
            unavailable.failure_phase.error_code().as_str(),
            "backend_unavailable"
        );
        let failed = error_response(MxcError::backend_error("broke"));
        assert_eq!(failed.failure_phase, FailurePhase::PostLaunchFailed);
        assert!(failed.error_message.contains("broke"));
    }

    #[test]
    fn cleanup_failure_is_not_success_and_preserves_primary_error() {
        let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
        let cleanup = || vec![MxcError::backend_error("delete failed")];
        let success = finish_with_cleanup("TEST", Ok(42), cleanup(), &mut logger).unwrap_err();
        assert_eq!(success.code, MxcErrorCode::BackendError);
        assert!(success
            .message
            .starts_with("TEST cleanup failed after workload completion"));

        let failure = finish_with_cleanup::<()>(
            "TEST",
            Err(MxcError::backend_unavailable("start failed")),
            cleanup(),
            &mut logger,
        )
        .unwrap_err();
        assert_eq!(failure.code, MxcErrorCode::BackendUnavailable);
        assert!(failure.message.contains("start failed"));
        assert!(failure.message.contains("cleanup failure"));
        assert!(failure.message.contains("delete failed"));
        assert_eq!(
            finish_with_cleanup("TEST", Ok(7), Vec::new(), &mut logger),
            Ok(7)
        );
    }
}
