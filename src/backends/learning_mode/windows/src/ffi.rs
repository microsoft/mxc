// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows runtime FFI for the `processmodel.dll` Learning Mode trace exports.
//!
//! The three exports are resolved once via `LoadLibraryExW(LOAD_LIBRARY_SEARCH_SYSTEM32)`
//! and `GetProcAddress`. As with the sibling `Experimental_CreateProcessInSandbox`
//! adapter, `processmodel.dll` is intentionally never freed: it is a system DLL that
//! stays resident for the process lifetime, so the module handle is used only to
//! resolve exports and then dropped without `FreeLibrary`.

use std::path::Path;
use std::ptr;

use windows::Win32::Foundation::{GetLastError, HANDLE, HMODULE};
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows_core::{HRESULT, PCSTR, PCWSTR};
use wxc_common::string_util;

use crate::LearningModeError;

/// System DLL that hosts the flat Learning Mode trace exports.
const PROCESSMODEL_DLL: &str = "processmodel.dll";

/// `HRESULT StartLearningModeTrace(HANDLE securityEnvironment, HLEARNINGMODE_TRACE* trace)`.
///
/// `HLEARNINGMODE_TRACE` is a `typedef HANDLE`; the export surfaces it through the
/// out-parameter.
type PfnStartLearningModeTrace = unsafe extern "system" fn(
    process_security_environment: HANDLE,
    trace_out: *mut HANDLE,
) -> HRESULT;

/// `HRESULT StopLearningModeTrace(HLEARNINGMODE_TRACE trace, LPCWSTR outputEtlPath)`.
///
/// A non-null `output_path` names a file the export opens under the caller's own
/// identity; the broker seals and copies the ETL into it. A null `output_path`
/// stops without delivery. The handle remains valid so the caller may retry
/// delivery until it closes the trace.
type PfnStopLearningModeTrace =
    unsafe extern "system" fn(trace: HANDLE, output_path: *const u16) -> HRESULT;

/// `void CloseLearningModeTrace(HLEARNINGMODE_TRACE trace)`.
type PfnCloseLearningModeTrace = unsafe extern "system" fn(trace: HANDLE);

/// Opaque handle to an in-progress Learning Mode trace (`HLEARNINGMODE_TRACE`).
///
/// Obtained from [`LearningModeApi::start_trace`]. [`LearningModeApi::stop_trace`]
/// borrows it so delivery can be retried. Dropping or explicitly closing the
/// handle releases all broker state; closing without stopping discards the trace.
pub struct LearningModeTraceHandle {
    raw: HANDLE,
    close: PfnCloseLearningModeTrace,
}

impl LearningModeTraceHandle {
    fn new(raw: HANDLE, close: PfnCloseLearningModeTrace) -> Self {
        Self { raw, close }
    }

    /// Close the trace and release all service-managed state.
    pub fn close(mut self) {
        self.close_inner();
    }

    fn close_inner(&mut self) {
        if !self.raw.0.is_null() {
            // SAFETY: `raw` was returned by `StartLearningModeTrace`, and
            // `close` was resolved from the same processmodel.dll contract.
            unsafe { (self.close)(self.raw) };
            self.raw = HANDLE(ptr::null_mut());
        }
    }
}

impl std::fmt::Debug for LearningModeTraceHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("LearningModeTraceHandle")
            .field(&self.raw)
            .finish()
    }
}

impl Drop for LearningModeTraceHandle {
    fn drop(&mut self) {
        self.close_inner();
    }
}

/// Resolved Learning Mode trace exports from `processmodel.dll`.
///
/// Construct with [`LearningModeApi::load`]. Cloning is cheap (the struct holds three
/// function pointers into the resident system DLL).
#[derive(Clone, Copy)]
pub struct LearningModeApi {
    start: PfnStartLearningModeTrace,
    stop: PfnStopLearningModeTrace,
    close: PfnCloseLearningModeTrace,
}

impl std::fmt::Debug for LearningModeApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LearningModeApi")
            .field("start", &(self.start as *const ()))
            .field("stop", &(self.stop as *const ()))
            .field("close", &(self.close as *const ()))
            .finish()
    }
}

impl LearningModeApi {
    /// Load `processmodel.dll` and resolve the Learning Mode trace exports.
    ///
    /// # Errors
    /// - [`LearningModeError::DllLoad`] if `processmodel.dll` cannot be loaded.
    /// - [`LearningModeError::ExportMissing`] if any export is absent. Requiring
    ///   `CloseLearningModeTrace` rejects builds that expose the incompatible
    ///   earlier two-export ABI.
    pub fn load() -> Result<Self, LearningModeError> {
        let dll = string_util::to_wide(PROCESSMODEL_DLL);

        // SAFETY: `dll` is a valid null-terminated wide string that outlives the call.
        // `LOAD_LIBRARY_SEARCH_SYSTEM32` restricts the search to System32, preventing
        // DLL-planting. The module handle is used only for `GetProcAddress` below and
        // is never freed (the DLL stays resident for the process lifetime). Each
        // resolved pointer is transmuted to a signature that matches the C
        // declaration of the corresponding export exactly.
        unsafe {
            let hmodule = LoadLibraryExW(PCWSTR(dll.as_ptr()), None, LOAD_LIBRARY_SEARCH_SYSTEM32)
                .map_err(|e| LearningModeError::DllLoad(e.to_string()))?;

            let start_proc = resolve_export(hmodule, c"StartLearningModeTrace")?;
            let stop_proc = resolve_export(hmodule, c"StopLearningModeTrace")?;
            let close_proc = resolve_export(hmodule, c"CloseLearningModeTrace")?;

            let start: PfnStartLearningModeTrace = std::mem::transmute(start_proc);
            let stop: PfnStopLearningModeTrace = std::mem::transmute(stop_proc);
            let close: PfnCloseLearningModeTrace = std::mem::transmute(close_proc);

            Ok(Self { start, stop, close })
        }
    }

    /// Start a Learning Mode trace for the sandbox identified by
    /// `security_environment`.
    ///
    /// # Safety
    /// `security_environment` must be a live `HPROCESS_SECURITY_ENVIRONMENT` handle
    /// obtained from the sandbox launch path; the broker resolves it to the target
    /// AppContainer SID server-side.
    ///
    /// # Errors
    /// [`LearningModeError::HResultCall`] if the export returns a failing HRESULT.
    pub unsafe fn start_trace(
        &self,
        security_environment: HANDLE,
    ) -> Result<LearningModeTraceHandle, LearningModeError> {
        let mut trace = HANDLE(ptr::null_mut());
        // SAFETY: `self.start` was resolved from `processmodel.dll` and matches the
        // declared C signature; `trace` is a valid out-pointer. The caller upholds
        // the validity of `security_environment` per this method's safety contract.
        let result = (self.start)(security_environment, &mut trace);
        if result.is_err() {
            return Err(LearningModeError::HResultCall {
                function: "StartLearningModeTrace",
                code: result.0,
            });
        }
        Ok(LearningModeTraceHandle::new(trace, self.close))
    }

    /// Stop `trace`, sealing and copying the ETL into `output_path`. Passing `None`
    /// stops without delivery.
    ///
    /// The handle remains live after success or failure, so callers may retry with
    /// the same or a different output path before closing it.
    ///
    /// # Errors
    /// - [`LearningModeError::InvalidInput`] if `output_path` contains an embedded NUL.
    /// - [`LearningModeError::HResultCall`] if the export returns a failing HRESULT.
    pub fn stop_trace(
        &self,
        trace: &LearningModeTraceHandle,
        output_path: Option<&Path>,
    ) -> Result<(), LearningModeError> {
        let wide_path = encode_output_path(output_path)?;
        self.stop_trace_encoded(trace, wide_path.as_deref())
    }

    fn stop_trace_encoded(
        &self,
        trace: &LearningModeTraceHandle,
        wide_path: Option<&[u16]>,
    ) -> Result<(), LearningModeError> {
        let path_ptr = wide_path.map_or(ptr::null(), |path| path.as_ptr());

        // SAFETY: `self.stop` was resolved from `processmodel.dll` and matches the
        // declared C signature. `trace.raw` came from a prior `start_trace`, and
        // `path_ptr` is either null or points at the null-terminated `wide_path`
        // buffer, which outlives the call.
        let result = unsafe { (self.stop)(trace.raw, path_ptr) };
        if result.is_err() {
            return Err(LearningModeError::HResultCall {
                function: "StopLearningModeTrace",
                code: result.0,
            });
        }
        Ok(())
    }
}

fn encode_output_path(output_path: Option<&Path>) -> Result<Option<Vec<u16>>, LearningModeError> {
    output_path
        .map(|path| {
            string_util::os_str_to_wide(path.as_os_str()).map_err(|_| {
                LearningModeError::InvalidInput {
                    parameter: "output_path",
                    detail: "path contains an embedded NUL".to_string(),
                }
            })
        })
        .transpose()
}

/// Resolve a single export from an already-loaded module, mapping a missing symbol
/// to [`LearningModeError::ExportMissing`].
///
/// # Safety
/// `hmodule` must be a valid module handle.
unsafe fn resolve_export(
    hmodule: HMODULE,
    name: &'static std::ffi::CStr,
) -> Result<unsafe extern "system" fn() -> isize, LearningModeError> {
    // SAFETY: `name` is a valid null-terminated C string; `hmodule` is valid per the
    // caller's contract.
    match GetProcAddress(hmodule, PCSTR(name.as_ptr().cast())) {
        Some(proc) => Ok(proc),
        None => Err(LearningModeError::ExportMissing {
            api: "Learning Mode trace",
            export: name.to_str().unwrap_or("<non-utf8 export>"),
            detail: format!(
                "GetProcAddress returned NULL (GetLastError = {})",
                last_error()
            ),
        }),
    }
}

/// Capture `GetLastError` as a plain `u32`.
fn last_error() -> u32 {
    // SAFETY: `GetLastError` has no preconditions and no side effects beyond reading
    // the calling thread's last-error slot.
    unsafe { GetLastError().0 }
}

/// Capability probe: `true` only when `processmodel.dll` exposes all three Learning Mode
/// trace exports on this machine.
#[must_use]
pub fn is_learning_mode_api_available() -> bool {
    LearningModeApi::load().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
    use std::sync::Mutex;
    use windows::Win32::Foundation::{E_FAIL, S_FALSE, S_OK};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static START_RESULT: AtomicI32 = AtomicI32::new(S_OK.0);
    static STOP_RESULT: AtomicI32 = AtomicI32::new(S_OK.0);
    static STOP_CALLS: AtomicUsize = AtomicUsize::new(0);
    static CLOSE_CALLS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "system" fn fake_start(_: HANDLE, trace_out: *mut HANDLE) -> HRESULT {
        let result = HRESULT(START_RESULT.load(Ordering::SeqCst));
        if result.is_ok() {
            unsafe {
                *trace_out = HANDLE(std::ptr::dangling_mut::<std::ffi::c_void>());
            }
        }
        result
    }

    unsafe extern "system" fn fake_stop(_: HANDLE, _: *const u16) -> HRESULT {
        STOP_CALLS.fetch_add(1, Ordering::SeqCst);
        HRESULT(STOP_RESULT.load(Ordering::SeqCst))
    }

    unsafe extern "system" fn fake_close(_: HANDLE) {
        CLOSE_CALLS.fetch_add(1, Ordering::SeqCst);
    }

    fn fake_api() -> LearningModeApi {
        LearningModeApi {
            start: fake_start,
            stop: fake_stop,
            close: fake_close,
        }
    }

    fn fake_environment() -> HANDLE {
        HANDLE(std::ptr::dangling_mut::<std::ffi::c_void>())
    }

    fn reset_fakes() {
        START_RESULT.store(S_OK.0, Ordering::SeqCst);
        STOP_RESULT.store(S_OK.0, Ordering::SeqCst);
        STOP_CALLS.store(0, Ordering::SeqCst);
        CLOSE_CALLS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn probe_does_not_panic_and_matches_load() {
        // On a non-feature OS build the exports are absent and both return
        // false/Err; on a feature build both are true/Ok. Either way the probe must
        // agree with `load()` and never panic.
        let available = is_learning_mode_api_available();
        assert_eq!(available, LearningModeApi::load().is_ok());
    }

    #[test]
    fn load_failure_is_graceful_when_api_absent() {
        // Where the API is unavailable, `load()` must return a typed error rather
        // than panicking. Where it is available this is vacuously satisfied.
        match LearningModeApi::load() {
            Ok(api) => {
                // Smoke: the resolved struct is Debug-formattable.
                let _ = format!("{api:?}");
            }
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    matches!(
                        e,
                        LearningModeError::DllLoad(_) | LearningModeError::ExportMissing { .. }
                    ),
                    "unexpected error variant: {msg}"
                );
            }
        }
    }

    #[test]
    fn output_path_rejects_embedded_nul() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_fakes();
        let path = PathBuf::from(OsString::from_wide(&['a' as u16, 0, 'b' as u16]));
        let api = fake_api();
        let trace = unsafe { api.start_trace(fake_environment()).unwrap() };

        let error = api
            .stop_trace(&trace, Some(&path))
            .expect_err("embedded NUL must be rejected");

        assert!(matches!(
            error,
            LearningModeError::InvalidInput {
                parameter: "output_path",
                ..
            }
        ));
        assert_eq!(STOP_CALLS.load(Ordering::SeqCst), 0);
        drop(trace);
        assert_eq!(CLOSE_CALLS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn successful_hresult_starts_retryable_trace() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_fakes();
        START_RESULT.store(S_FALSE.0, Ordering::SeqCst);
        let api = fake_api();
        let trace = unsafe {
            api.start_trace(fake_environment())
                .expect("non-failing HRESULT should succeed")
        };

        api.stop_trace(&trace, None).unwrap();
        api.stop_trace(&trace, None).unwrap();
        assert_eq!(STOP_CALLS.load(Ordering::SeqCst), 2);

        trace.close();
        assert_eq!(CLOSE_CALLS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn failed_hresult_keeps_trace_live_until_close() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_fakes();
        let api = fake_api();
        let trace = unsafe { api.start_trace(fake_environment()).unwrap() };
        STOP_RESULT.store(E_FAIL.0, Ordering::SeqCst);

        let error = api.stop_trace(&trace, None).unwrap_err();
        assert!(matches!(
            error,
            LearningModeError::HResultCall {
                function: "StopLearningModeTrace",
                code
            } if code == E_FAIL.0
        ));

        drop(trace);
        assert_eq!(CLOSE_CALLS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn failed_start_preserves_hresult_and_does_not_close() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_fakes();
        START_RESULT.store(E_FAIL.0, Ordering::SeqCst);
        let api = fake_api();

        let error = unsafe { api.start_trace(fake_environment()).unwrap_err() };

        assert!(matches!(
            error,
            LearningModeError::HResultCall {
                function: "StartLearningModeTrace",
                code
            } if code == E_FAIL.0
        ));
        assert_eq!(CLOSE_CALLS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn explicit_close_is_exactly_once() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_fakes();
        let api = fake_api();
        let trace = unsafe { api.start_trace(fake_environment()).unwrap() };

        trace.close();

        assert_eq!(CLOSE_CALLS.load(Ordering::SeqCst), 1);
    }
}
