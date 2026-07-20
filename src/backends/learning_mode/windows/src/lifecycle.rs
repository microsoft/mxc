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
    pub fn begin(
        secenv_api: SecurityEnvironmentApi,
        learning_mode_api: LearningModeApi,
        sandbox_specification: &[u8],
        flags: u32,
    ) -> Result<Self, LearningModeError> {
        let environment = secenv_api.create(sandbox_specification, flags)?;

        // SAFETY: `environment` was just created by `secenv_api.create` and is live for
        // the duration of this call; `start_trace` only reads it.
        let trace = match unsafe { learning_mode_api.start_trace(environment.raw()) } {
            Ok(trace) => trace,
            Err(start_err) => {
                // Don't leak the environment if the trace could not be started.
                let _ = secenv_api.close(environment);
                return Err(start_err);
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
    /// Never after a successful [`begin`](Self::begin) and before
    /// [`finish`](Self::finish); the environment is present for the whole session
    /// lifetime.
    #[must_use]
    pub fn environment(&self) -> HANDLE {
        self.environment.as_ref().map_or(
            HANDLE(std::ptr::null_mut()),
            ProcessSecurityEnvironment::raw,
        )
    }

    /// Seal the trace to `output_path` (or discard it when `None`), then close the
    /// security environment. Call **after** the child has exited.
    ///
    /// Both teardown steps are attempted even if the first fails; the first error
    /// encountered is returned so a failure is never silently swallowed.
    ///
    /// # Errors
    /// [`LearningModeError::ApiCall`] from `StopLearningModeTrace` or
    /// `CloseProcessSecurityEnvironment`.
    pub fn finish(mut self, output_path: Option<&Path>) -> Result<(), LearningModeError> {
        let stop_result = match self.trace.take() {
            Some(trace) => self.learning_mode_api.stop_trace(trace, output_path),
            None => Ok(()),
        };
        let close_result = match self.environment.take() {
            Some(environment) => self.secenv_api.close(environment),
            None => Ok(()),
        };
        stop_result.and(close_result)
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
            let _ = self.secenv_api.close(environment);
        }
    }
}
