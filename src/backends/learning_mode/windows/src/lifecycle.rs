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

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
    use std::sync::{Mutex, MutexGuard};
    use windows::Win32::Foundation::{ERROR_SHARING_VIOLATION, E_FAIL, S_OK};
    use windows_core::HRESULT;

    /// Serializes access to the shared fake-call event log and result knobs.
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    /// Ordered log of the fake export calls, as they happen across both APIs.
    static EVENTS: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());

    static CREATE_RESULT: AtomicI32 = AtomicI32::new(S_OK.0);
    static START_RESULT: AtomicI32 = AtomicI32::new(S_OK.0);
    static STOP_RESULT: AtomicI32 = AtomicI32::new(S_OK.0);
    static STOP_FAILURE_RESULT: AtomicI32 = AtomicI32::new(E_FAIL.0);
    static STOP_FAILURES_REMAINING: AtomicUsize = AtomicUsize::new(0);

    fn record(event: &'static str) {
        EVENTS.lock().unwrap().push(event);
    }

    fn take_events() -> Vec<&'static str> {
        std::mem::take(&mut *EVENTS.lock().unwrap())
    }

    fn dangling_handle() -> HANDLE {
        HANDLE(std::ptr::dangling_mut::<c_void>())
    }

    unsafe extern "system" fn fake_create(
        _: *const c_void,
        _: u32,
        _: u32,
        out: *mut HANDLE,
    ) -> HRESULT {
        record("create");
        let result = HRESULT(CREATE_RESULT.load(Ordering::SeqCst));
        if result.is_ok() {
            unsafe { *out = dangling_handle() };
        }
        result
    }

    unsafe extern "system" fn fake_query(_: *mut u64) -> HRESULT {
        S_OK
    }

    unsafe extern "system" fn fake_env_close(_: HANDLE) {
        record("env_close");
    }

    unsafe extern "system" fn fake_start(_: HANDLE, out: *mut HANDLE) -> HRESULT {
        record("start");
        let result = HRESULT(START_RESULT.load(Ordering::SeqCst));
        if result.is_ok() {
            unsafe { *out = dangling_handle() };
        }
        result
    }

    unsafe extern "system" fn fake_stop(_: HANDLE, _: *const u16) -> HRESULT {
        record("stop");
        if STOP_FAILURES_REMAINING
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return HRESULT(STOP_FAILURE_RESULT.load(Ordering::SeqCst));
        }
        HRESULT(STOP_RESULT.load(Ordering::SeqCst))
    }

    unsafe extern "system" fn fake_trace_close(_: HANDLE) {
        record("trace_close");
    }

    fn reset() -> MutexGuard<'static, ()> {
        let guard = TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        take_events();
        CREATE_RESULT.store(S_OK.0, Ordering::SeqCst);
        START_RESULT.store(S_OK.0, Ordering::SeqCst);
        STOP_RESULT.store(S_OK.0, Ordering::SeqCst);
        STOP_FAILURE_RESULT.store(E_FAIL.0, Ordering::SeqCst);
        STOP_FAILURES_REMAINING.store(0, Ordering::SeqCst);
        guard
    }

    fn fake_secenv_api() -> SecurityEnvironmentApi {
        SecurityEnvironmentApi::from_raw_parts(fake_create, fake_query, fake_env_close)
    }

    fn fake_learning_mode_api() -> LearningModeApi {
        LearningModeApi::from_raw_parts(fake_start, fake_stop, fake_trace_close)
    }

    fn begin_session() -> Result<CaptureSession, LearningModeError> {
        CaptureSession::begin(
            fake_secenv_api(),
            fake_learning_mode_api(),
            b"PSEC-fake-spec",
            crate::PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE,
        )
    }

    #[test]
    fn begin_creates_environment_before_starting_trace() {
        let _guard = reset();
        let session = begin_session().expect("begin should succeed with passing fakes");

        // The environment must be created first so the trace keys on a live handle.
        assert_eq!(take_events(), vec!["create", "start"]);
        assert_eq!(session.environment(), dangling_handle());

        // Tidy up deterministically so Drop bookkeeping does not leak into siblings.
        drop(session);
    }

    #[test]
    fn begin_start_failure_closes_environment_and_leaves_no_trace() {
        let _guard = reset();
        START_RESULT.store(E_FAIL.0, Ordering::SeqCst);

        let error = begin_session().expect_err("start failure must propagate");
        assert!(matches!(
            error,
            LearningModeError::HResultCall {
                function: "StartLearningModeTrace",
                code
            } if code == E_FAIL.0
        ));

        // The just-created environment is torn down; the trace was never created so
        // it is never closed, and Stop is never attempted.
        assert_eq!(take_events(), vec!["create", "start", "env_close"]);
    }

    #[test]
    fn finish_retries_stop_then_closes_trace_then_environment() {
        let _guard = reset();
        STOP_FAILURE_RESULT.store(
            HRESULT::from_win32(ERROR_SHARING_VIOLATION.0).0,
            Ordering::SeqCst,
        );
        STOP_FAILURES_REMAINING.store(2, Ordering::SeqCst);

        let session = begin_session().expect("begin should succeed");
        assert_eq!(take_events(), vec!["create", "start"]);

        session
            .finish(None)
            .expect("finish should succeed after retries");

        // Stop is retried until it succeeds, THEN the trace closes, THEN the
        // environment closes — the exact teardown ordering the OS requires.
        assert_eq!(
            take_events(),
            vec!["stop", "stop", "stop", "trace_close", "env_close"]
        );
    }

    #[test]
    fn finish_propagates_permanent_stop_failure_but_still_tears_down() {
        let _guard = reset();
        STOP_RESULT.store(E_FAIL.0, Ordering::SeqCst);

        let session = begin_session().expect("begin should succeed");
        take_events();

        let error = session
            .finish(None)
            .expect_err("a permanent stop failure must surface");
        assert!(matches!(
            error,
            LearningModeError::HResultCall {
                function: "StopLearningModeTrace",
                ..
            }
        ));

        // Even when Stop fails permanently, the trace and environment are still
        // closed, in order, so nothing leaks.
        assert_eq!(take_events(), vec!["stop", "trace_close", "env_close"]);
    }

    #[test]
    fn drop_without_finish_discards_trace_then_closes_environment() {
        let _guard = reset();
        let session = begin_session().expect("begin should succeed");
        take_events();

        drop(session);

        // Dropping without `finish` closes (discards) the trace WITHOUT calling
        // Stop, then closes the environment.
        assert_eq!(take_events(), vec!["trace_close", "env_close"]);
    }
}
