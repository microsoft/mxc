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
//! 3. attach `env` as `PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT`, then call
//!    `CreateProcessW` (**runner's job**; the session exposes the handle via
//!    [`CaptureSession::environment`])
//! 4. wait for the child to exit
//! 5. `StopLearningModeTrace(trace, outputPath)` → sealed ETL (bounded retries
//!    for transient delivery failures)
//! 6. `CloseLearningModeTrace(trace)` → release broker state and staged ETL
//! 7. `CloseProcessSecurityEnvironment(env)` → teardown
//!
//! [`CaptureSession::begin`] performs steps 1–2; the runner performs steps 3–4 with the
//! handle from [`CaptureSession::environment`]; [`CaptureSession::finish`] performs steps
//! 5–7 in order. If the session is dropped without `finish` (e.g. the launch failed or a
//! `?` unwound the stack), [`Drop`] closes the trace without stopping it — the OS-supported
//! discard path — then closes the environment.

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
/// Dropping without `finish` closes and discards the trace, then closes the environment.
#[derive(Debug)]
pub struct CaptureSession {
    learning_mode_api: LearningModeApi,
    /// `Some` until `finish`/`Drop` closes it.
    environment: Option<ProcessSecurityEnvironment>,
    /// `Some` until `finish`/`Drop` closes it.
    trace: Option<LearningModeTraceHandle>,
}

impl CaptureSession {
    /// Create a security environment from `sandbox_specification` and start a Learning
    /// Mode trace against it. Call **before** launching the child.
    ///
    /// `flags` is normally [`crate::PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE`].
    ///
    /// # Errors
    /// - [`LearningModeError::HResultCall`] if `CreateProcessSecurityEnvironment` fails.
    /// - [`LearningModeError::HResultCall`] if `StartLearningModeTrace` fails — in which
    ///   case the just-created environment is closed before returning so it is not leaked.
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
                environment.close();
                return Err(start_err);
            }
        };

        Ok(Self {
            learning_mode_api,
            environment: Some(environment),
            trace: Some(trace),
        })
    }

    /// The `HPROCESS_SECURITY_ENVIRONMENT` handle to pass to
    /// [`crate::SecurityEnvironmentStartupInfo`].
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

    /// Stop the trace and deliver it to `output_path` (or skip delivery when
    /// `None`), retry transient delivery failures, close the trace, then close
    /// the security environment. Call **after** the child has exited.
    ///
    /// # Errors
    /// - [`LearningModeError::HResultCall`] from `StopLearningModeTrace`.
    pub fn finish(mut self, output_path: Option<&Path>) -> Result<(), LearningModeError> {
        let stop_result = match self.trace.as_ref() {
            Some(trace) => self
                .learning_mode_api
                .stop_trace_with_retry(trace, output_path),
            None => Ok(()),
        };
        if let Some(trace) = self.trace.take() {
            trace.close();
        }
        if let Some(environment) = self.environment.take() {
            environment.close();
        }
        stop_result
    }
}

impl Drop for CaptureSession {
    fn drop(&mut self) {
        // Close without Stop is the OS-supported early-exit discard path.
        drop(self.trace.take());
        if let Some(environment) = self.environment.take() {
            drop(environment);
        }
    }
}
