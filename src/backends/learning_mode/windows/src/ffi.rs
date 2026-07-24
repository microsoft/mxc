// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows runtime FFI for the `processmodel.dll` Learning Mode trace exports.
//!
//! The two exports are resolved once via `LoadLibraryExW(LOAD_LIBRARY_SEARCH_SYSTEM32)`
//! and `GetProcAddress`. As with the sibling `Experimental_CreateProcessInSandbox`
//! adapter, `processmodel.dll` is intentionally never freed: it is a system DLL that
//! stays resident for the process lifetime, so the module handle is used only to
//! resolve exports and then dropped without `FreeLibrary`.

use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use windows::Win32::Foundation::{GetLastError, HANDLE, HMODULE};
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows_core::{PCSTR, PCWSTR};
use wxc_common::string_util;

use crate::LearningModeError;

/// System DLL that hosts the flat Learning Mode trace exports.
const PROCESSMODEL_DLL: &str = "processmodel.dll";

/// `BOOL StartLearningModeTrace(HANDLE hProcessSecurityEnvironment, HLEARNINGMODE_TRACE* pphTrace)`.
///
/// `HLEARNINGMODE_TRACE` is a `typedef HANDLE`; the export surfaces it through the
/// out-parameter. A zero (`FALSE`) return signals failure (`GetLastError`).
type PfnStartLearningModeTrace =
    unsafe extern "system" fn(process_security_environment: HANDLE, trace_out: *mut HANDLE) -> i32;

/// `BOOL StopLearningModeTrace(HLEARNINGMODE_TRACE* pphTrace, LPCWSTR lpOutputPath)`.
///
/// A non-null `output_path` names a file the export opens under the caller's own
/// identity; the broker seals the ETL into it. A null `output_path` discards the
/// trace. `*trace` is set to null on return regardless.
type PfnStopLearningModeTrace =
    unsafe extern "system" fn(trace: *mut HANDLE, output_path: *const u16) -> i32;

/// Opaque handle to an in-progress Learning Mode trace (`HLEARNINGMODE_TRACE`).
///
/// Obtained from [`LearningModeApi::start_trace`] and consumed by
/// [`LearningModeApi::stop_trace`]. The handle is owned by the AppInfo broker and
/// bound to this process; if the process exits without stopping, the broker discards
/// the trace automatically.
#[derive(Debug)]
pub struct LearningModeTraceHandle(HANDLE);

/// Resolved Learning Mode trace exports from `processmodel.dll`.
///
/// Construct with [`LearningModeApi::load`]. Cloning is cheap (the struct holds two
/// function pointers into the resident system DLL).
#[derive(Clone, Copy)]
pub struct LearningModeApi {
    start: PfnStartLearningModeTrace,
    stop: PfnStopLearningModeTrace,
}

impl std::fmt::Debug for LearningModeApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LearningModeApi")
            .field("start", &(self.start as *const ()))
            .field("stop", &(self.stop as *const ()))
            .finish()
    }
}

impl LearningModeApi {
    /// Load `processmodel.dll` and resolve the Learning Mode trace exports.
    ///
    /// # Errors
    /// - [`LearningModeError::DllLoad`] if `processmodel.dll` cannot be loaded.
    /// - [`LearningModeError::ExportMissing`] if either export is absent (the OS
    ///   build predates the API or has it gated off).
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

            let start: PfnStartLearningModeTrace = std::mem::transmute(start_proc);
            let stop: PfnStopLearningModeTrace = std::mem::transmute(stop_proc);

            Ok(Self { start, stop })
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
    /// [`LearningModeError::ApiCall`] carrying `GetLastError` if the export returns
    /// `FALSE`.
    pub unsafe fn start_trace(
        &self,
        security_environment: HANDLE,
    ) -> Result<LearningModeTraceHandle, LearningModeError> {
        let mut trace = HANDLE(ptr::null_mut());
        // SAFETY: `self.start` was resolved from `processmodel.dll` and matches the
        // declared C signature; `trace` is a valid out-pointer. The caller upholds
        // the validity of `security_environment` per this method's safety contract.
        let ok = (self.start)(security_environment, &mut trace);
        if ok == 0 {
            return Err(LearningModeError::ApiCall {
                function: "StartLearningModeTrace",
                code: last_error(),
            });
        }
        Ok(LearningModeTraceHandle(trace))
    }

    /// Stop `trace`, sealing the ETL into `output_path`. Passing `None` discards the
    /// trace (used for early-exit teardown).
    ///
    /// The handle is consumed; the export nulls it internally on return.
    ///
    /// # Errors
    /// - [`LearningModeError::InvalidInput`] if `output_path` contains an embedded NUL.
    /// - [`LearningModeError::ApiCall`] carrying `GetLastError` if the export returns
    ///   `FALSE`.
    /// - [`LearningModeError::CleanupFailed`] if rejecting an invalid path also fails
    ///   to discard the live trace.
    pub fn stop_trace(
        &self,
        trace: LearningModeTraceHandle,
        output_path: Option<&Path>,
    ) -> Result<(), LearningModeError> {
        let wide_path = match encode_output_path(output_path) {
            Ok(path) => path,
            Err(primary) => {
                let cleanup = self.stop_trace_encoded(trace, None);
                return match cleanup {
                    Ok(()) => Err(primary),
                    Err(cleanup) => Err(LearningModeError::CleanupFailed {
                        primary: Box::new(primary),
                        cleanup: Box::new(cleanup),
                    }),
                };
            }
        };
        self.stop_trace_encoded(trace, wide_path.as_deref())
    }

    fn stop_trace_encoded(
        &self,
        trace: LearningModeTraceHandle,
        wide_path: Option<&[u16]>,
    ) -> Result<(), LearningModeError> {
        let path_ptr = wide_path.map_or(ptr::null(), |path| path.as_ptr());
        let mut handle = trace.0;

        // SAFETY: `self.stop` was resolved from `processmodel.dll` and matches the
        // declared C signature. `handle` came from a prior `start_trace`, and
        // `path_ptr` is either null or points at the null-terminated `wide_path`
        // buffer, which outlives the call.
        let ok = unsafe { (self.stop)(&mut handle, path_ptr) };
        if ok == 0 {
            return Err(LearningModeError::ApiCall {
                function: "StopLearningModeTrace",
                code: last_error(),
            });
        }
        Ok(())
    }
}

fn encode_output_path(output_path: Option<&Path>) -> Result<Option<Vec<u16>>, LearningModeError> {
    output_path
        .map(|path| {
            // `encode_wide` preserves non-Unicode path data that `to_string_lossy`
            // would replace, so the ETL lands at exactly the requested path.
            let mut wide = path.as_os_str().encode_wide().collect::<Vec<u16>>();
            if wide.contains(&0) {
                return Err(LearningModeError::InvalidInput {
                    parameter: "output_path",
                    detail: "path contains an embedded NUL".to_string(),
                });
            }
            wide.push(0);
            Ok(wide)
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

/// Capability probe: `true` only when `processmodel.dll` exposes both Learning Mode
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
        let path = PathBuf::from(OsString::from_wide(&['a' as u16, 0, 'b' as u16]));

        let error = encode_output_path(Some(&path)).expect_err("embedded NUL must be rejected");

        assert!(matches!(
            error,
            LearningModeError::InvalidInput {
                parameter: "output_path",
                ..
            }
        ));
    }
}
