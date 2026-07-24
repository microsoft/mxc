// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! RAII lifecycle for a Learning Mode capture: create a process security environment,
//! start a trace against it, hand the environment to the runner to launch the child,
//! then — after the child exits — seal the ETL and tear the environment down.
//!
//! The ordering the OS requires is:
//!
//! 1. `CreateProcessSecurityEnvironment(spec)` → env handle
//! 2. `StartLearningModeTrace(env)` → trace handle (**before** the child launches, so no
//!    early denials are missed)
//! 3. `CreateProcessAsUserInsideSecurityEnvironment(env, …)` → child (**runner's job**;
//!    the session exposes the env handle for it via [`CaptureSession::environment`])
//! 4. wait for the child to exit
//! 5. `StopLearningModeTrace(trace, outputPath)` → sealed ETL (NULL path discards)
//! 6. `CloseProcessSecurityEnvironment(env)` → teardown
//!
//! [`CaptureSession::begin`] performs steps 1–2; the runner performs steps 3–4 with the
//! handle from [`CaptureSession::environment`]; [`CaptureSession::finish`] performs steps
//! 5–6 in order. If the session is dropped without `finish` (e.g. the launch failed or a
//! `?` unwound the stack), [`Drop`] runs a best-effort teardown — discard the trace, then
//! close the environment — so no broker-side trace or environment is leaked.

use std::path::Path;

use windows::Win32::Foundation::HANDLE;

use crate::ffi::{LearningModeApi, LearningModeTraceHandle};
use crate::secenv::{ProcessSecurityEnvironment, SecurityEnvironmentApi};
use crate::LearningModeError;

/// An in-flight Learning Mode capture: a live security environment with a trace already
/// started against it.
///
/// Construct with [`CaptureSession::begin`]; drive the child launch with the handle from
/// [`CaptureSession::environment`]; seal and tear down with [`CaptureSession::finish`].
/// Dropping without `finish` discards the trace and closes the environment on a
/// best-effort basis.
#[derive(Debug)]
pub struct CaptureSession {
    secenv_api: SecurityEnvironmentApi,
    learning_mode_api: LearningModeApi,
    /// `Some` until `finish`/`Drop` closes it.
    environment: Option<ProcessSecurityEnvironment>,
    /// `Some` until `finish`/`Drop` seals or discards it.
    trace: Option<LearningModeTraceHandle>,
}

impl CaptureSession {
    /// Create a security environment from `sandbox_specification` and start a Learning
    /// Mode trace against it. Call **before** launching the child.
    ///
    /// `flags` is normally [`crate::PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE`].
    ///
    /// # Errors
    /// - [`LearningModeError::ApiCall`] if `CreateProcessSecurityEnvironment` fails.
    /// - [`LearningModeError::ApiCall`] if `StartLearningModeTrace` fails — in which case
    ///   the just-created environment is closed before returning so it is not leaked.
    /// - [`LearningModeError::CleanupFailed`] if starting the trace fails and closing
    ///   the just-created environment also fails.
    pub fn begin(
        secenv_api: SecurityEnvironmentApi,
        learning_mode_api: LearningModeApi,
        sandbox_specification: &[u8],
        flags: u32,
    ) -> Result<Self, LearningModeError> {
        let mut environment = secenv_api.create(sandbox_specification, flags)?;

        // SAFETY: `environment` was just created by `secenv_api.create` and is live for
        // the duration of this call; `start_trace` only reads it.
        let trace = match unsafe { learning_mode_api.start_trace(environment.raw()) } {
            Ok(trace) => trace,
            Err(start_err) => {
                return match secenv_api.close(&mut environment) {
                    Ok(()) => Err(start_err),
                    Err(cleanup) => Err(LearningModeError::CleanupFailed {
                        primary: Box::new(start_err),
                        cleanup: Box::new(cleanup),
                    }),
                };
            }
        };

        Ok(Self {
            secenv_api,
            learning_mode_api,
            environment: Some(environment),
            trace: Some(trace),
        })
    }

    /// The `HPROCESS_SECURITY_ENVIRONMENT` handle to pass to
    /// `CreateProcessAsUserInsideSecurityEnvironment`.
    ///
    /// # Panics
    /// Panics only on an internal invariant violation — the environment is present for
    /// the entire session lifetime (set by [`begin`](Self::begin), taken only by
    /// [`finish`](Self::finish), which consumes `self`, or by [`Drop`]), so a live
    /// `&self` here always holds one. Failing fast surfaces a misuse at the call site
    /// rather than silently handing a NULL handle to a Win32 API.
    #[must_use]
    pub fn environment(&self) -> HANDLE {
        match self.environment.as_ref() {
            Some(env) => env.raw(),
            None => {
                panic!("CaptureSession::environment called after the environment was torn down")
            }
        }
    }

    /// Seal the trace to `output_path` (or discard it when `None`), then close the
    /// security environment. Call **after** the child has exited.
    ///
    /// Both teardown steps are attempted even if the first fails. If both fail,
    /// [`LearningModeError::CleanupFailed`] preserves both errors.
    ///
    /// # Errors
    /// - [`LearningModeError::ApiCall`] from `StopLearningModeTrace` or
    ///   `CloseProcessSecurityEnvironment`.
    /// - [`LearningModeError::CleanupFailed`] if both teardown calls fail.
    pub fn finish(mut self, output_path: Option<&Path>) -> Result<(), LearningModeError> {
        let stop_result = match self.trace.take() {
            Some(trace) => self.learning_mode_api.stop_trace(trace, output_path),
            None => Ok(()),
        };
        let close_result = match self.environment.as_mut() {
            Some(environment) => self.secenv_api.close(environment),
            None => Ok(()),
        };
        if close_result.is_ok() {
            self.environment.take();
        }
        combine_teardown_results(stop_result, close_result)
    }
}

fn combine_teardown_results(
    stop_result: Result<(), LearningModeError>,
    close_result: Result<(), LearningModeError>,
) -> Result<(), LearningModeError> {
    match (stop_result, close_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(primary), Err(cleanup)) => Err(LearningModeError::CleanupFailed {
            primary: Box::new(primary),
            cleanup: Box::new(cleanup),
        }),
    }
}

impl Drop for CaptureSession {
    fn drop(&mut self) {
        // Best-effort teardown for the early-exit / unwind path: discard the trace
        // (NULL output path) before closing the environment. Errors are unrecoverable
        // here and are intentionally ignored — `finish` is the fallible path.
        if let Some(trace) = self.trace.take() {
            let _ = self.learning_mode_api.stop_trace(trace, None);
        }
        if let Some(environment) = self.environment.take() {
            drop(environment);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn api_error(function: &'static str, code: u32) -> LearningModeError {
        LearningModeError::ApiCall { function, code }
    }

    #[test]
    fn teardown_preserves_both_failures() {
        let result = combine_teardown_results(
            Err(api_error("StopLearningModeTrace", 5)),
            Err(api_error("CloseProcessSecurityEnvironment", 6)),
        );

        let LearningModeError::CleanupFailed { primary, cleanup } =
            result.expect_err("both teardown failures must be returned")
        else {
            panic!("expected CleanupFailed");
        };
        assert!(primary.to_string().contains("StopLearningModeTrace"));
        assert!(cleanup
            .to_string()
            .contains("CloseProcessSecurityEnvironment"));
    }

    #[test]
    fn teardown_returns_single_failure_unchanged() {
        let result =
            combine_teardown_results(Ok(()), Err(api_error("CloseProcessSecurityEnvironment", 6)));

        assert!(matches!(
            result,
            Err(LearningModeError::ApiCall {
                function: "CloseProcessSecurityEnvironment",
                code: 6
            })
        ));
    }
}
