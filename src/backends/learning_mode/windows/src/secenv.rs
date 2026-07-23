// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows runtime FFI for the `processmodel.dll` **process security-environment**
//! exports — the 2-phase sandbox launch model that produces the
//! `HPROCESS_SECURITY_ENVIRONMENT` handle that [`crate::LearningModeApi::start_trace`]
//! keys the Learning Mode trace on.
//!
//! `StartLearningModeTrace` is keyed on a security-environment handle (the broker
//! resolves it to the target AppContainer SID server-side). Neither of MXC's existing
//! launch paths yields that handle — classic AppContainer uses `CreateProcess` +
//! `SECURITY_CAPABILITIES`, and BaseContainer uses the one-shot RPC-brokered
//! `Experimental_CreateProcessInSandbox`. To capture denials, MXC adopts the flat
//! 2-phase model exported by the same `processmodel.dll`:
//!
//! ```c
//! BOOL CreateProcessSecurityEnvironment(
//!     LPCVOID sandboxSpecification, DWORD sandboxSpecificationSize,
//!     PROCESS_SECURITY_ENVIRONMENT_FLAGS flags,
//!     HPROCESS_SECURITY_ENVIRONMENT* processSecurityEnvironment);
//! BOOL CreateProcessAsUserInsideSecurityEnvironment(
//!     HANDLE userToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
//!     DWORD dwCreationFlags, LPCVOID lpEnvironment, LPCWSTR lpCurrentDirectory,
//!     LPSTARTUPINFOW lpStartupInfo, HANDLE processSecurityEnvironment,
//!     LPPROCESS_INFORMATION lpProcessInformation);
//! BOOL CloseProcessSecurityEnvironment(HPROCESS_SECURITY_ENVIRONMENT* processSecurityEnvironment);
//! ```
//!
//! `sandboxSpecification`/`...Size` is a compiled FlatBuffer sandbox-spec blob (the
//! same `"SBOX"` format the BaseContainer runner already builds via `sandbox_spec`);
//! the spec must encode the learning-mode capability. Unlike the RPC one-shot, the
//! launch export returns a real `PROCESS_INFORMATION`, so wxc-exec owns the child
//! handle directly (stdio via `STARTUPINFOW`, wait, and job-object handling behave like
//! the classic path). `Close` tears the environment down; `Detach` (declared by the DLL
//! but not needed here) leaves the child running independently.
//!
//! As with the trace exports, each function is resolved at runtime and tolerates the
//! `Experimental_`-prefixed name as a fallback for OS builds that predate the
//! graduation out of the `Experimental_` prefix.

use std::ffi::c_void;
use std::ptr;

use windows::Win32::Foundation::{GetLastError, HANDLE, HMODULE};
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows::Win32::System::Threading::{PROCESS_INFORMATION, STARTUPINFOW};
use windows_core::{PCSTR, PCWSTR};
use wxc_common::string_util;

use crate::LearningModeError;

/// System DLL that hosts the flat process security-environment exports.
const PROCESSMODEL_DLL: &str = "processmodel.dll";

/// No special behaviour when creating the security environment
/// (`PROCESS_SECURITY_ENVIRONMENT_FLAGS` value `0`).
///
/// A `KILL_ON_CLOSE` bit exists (tears the child down when the environment closes) but
/// its numeric value is intentionally not declared here yet: explicit
/// [`SecurityEnvironmentApi::close`] after the child has exited already provides
/// deterministic teardown, so shipping code does not need to guess the flag value.
pub const PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE: u32 = 0;

/// `BOOL CreateProcessSecurityEnvironment(LPCVOID sandboxSpecification,
/// DWORD sandboxSpecificationSize, PROCESS_SECURITY_ENVIRONMENT_FLAGS flags,
/// HPROCESS_SECURITY_ENVIRONMENT* processSecurityEnvironment)`.
///
/// `PROCESS_SECURITY_ENVIRONMENT_FLAGS` is a C enum (`int`-sized), passed as `u32`.
type PfnCreateProcessSecurityEnvironment = unsafe extern "system" fn(
    sandbox_specification: *const c_void,
    sandbox_specification_size: u32,
    flags: u32,
    process_security_environment: *mut HANDLE,
) -> i32;

/// `BOOL CreateProcessAsUserInsideSecurityEnvironment(HANDLE userToken,
/// LPCWSTR lpApplicationName, LPWSTR lpCommandLine, DWORD dwCreationFlags,
/// LPCVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo,
/// HANDLE processSecurityEnvironment, LPPROCESS_INFORMATION lpProcessInformation)`.
///
/// `userToken`/`lpApplicationName`/`lpCommandLine`/`lpEnvironment`/`lpCurrentDirectory`
/// are optional; `lpStartupInfo`/`processSecurityEnvironment`/`lpProcessInformation` are
/// required. When `lpEnvironment` is non-null, `dwCreationFlags` must include
/// `CREATE_UNICODE_ENVIRONMENT`.
pub type PfnCreateProcessAsUserInsideSecurityEnvironment = unsafe extern "system" fn(
    user_token: HANDLE,
    application_name: *const u16,
    command_line: *mut u16,
    creation_flags: u32,
    environment: *const c_void,
    current_directory: *const u16,
    startup_info: *const STARTUPINFOW,
    process_security_environment: HANDLE,
    process_information: *mut PROCESS_INFORMATION,
) -> i32;

/// `BOOL CloseProcessSecurityEnvironment(HPROCESS_SECURITY_ENVIRONMENT* processSecurityEnvironment)`.
///
/// The export nulls `*processSecurityEnvironment` on success.
type PfnCloseProcessSecurityEnvironment =
    unsafe extern "system" fn(process_security_environment: *mut HANDLE) -> i32;

/// Opaque handle to a process security environment (`HPROCESS_SECURITY_ENVIRONMENT`, a
/// `HANDLE`).
///
/// Produced by [`SecurityEnvironmentApi::create`], threaded into the trace start and
/// the in-environment launch, and torn down by [`SecurityEnvironmentApi::close`]. The
/// wrapped [`HANDLE`] is passed by value to the launch/trace exports and by pointer to
/// the close export (which nulls it on return).
#[derive(Debug)]
pub struct ProcessSecurityEnvironment(HANDLE);

impl ProcessSecurityEnvironment {
    /// The raw `HPROCESS_SECURITY_ENVIRONMENT` handle, for passing to the trace-start
    /// and in-environment launch exports.
    #[must_use]
    pub fn raw(&self) -> HANDLE {
        self.0
    }
}

/// Which candidate export name resolved for each function on this machine — a
/// diagnostic used by the capability probe to report the exact live surface (plain vs
/// `Experimental_`).
#[derive(Debug, Clone, Copy, Default)]
pub struct SecurityEnvironmentExportReport {
    /// Resolved name of the create export, if present.
    pub create: Option<&'static str>,
    /// Resolved name of the in-environment launch export, if present.
    pub launch: Option<&'static str>,
    /// Resolved name of the close export, if present.
    pub close: Option<&'static str>,
}

impl SecurityEnvironmentExportReport {
    /// `true` only when every export required for the 2-phase launch resolved.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.create.is_some() && self.launch.is_some() && self.close.is_some()
    }
}

/// Candidate names for each export: the graduated (plain) name is preferred, with the
/// `Experimental_`-prefixed name kept as a fallback for older feature builds.
const CREATE_NAMES: &[&core::ffi::CStr] = &[
    c"CreateProcessSecurityEnvironment",
    c"Experimental_CreateProcessSecurityEnvironment",
];
const LAUNCH_NAMES: &[&core::ffi::CStr] = &[
    c"CreateProcessAsUserInsideSecurityEnvironment",
    c"Experimental_CreateProcessAsUserInsideSecurityEnvironment",
];
const CLOSE_NAMES: &[&core::ffi::CStr] = &[
    c"CloseProcessSecurityEnvironment",
    c"Experimental_CloseProcessSecurityEnvironment",
];

/// Resolved process security-environment exports from `processmodel.dll`.
#[derive(Clone, Copy)]
pub struct SecurityEnvironmentApi {
    create: PfnCreateProcessSecurityEnvironment,
    launch: PfnCreateProcessAsUserInsideSecurityEnvironment,
    close: PfnCloseProcessSecurityEnvironment,
}

impl std::fmt::Debug for SecurityEnvironmentApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityEnvironmentApi")
            .field("create", &(self.create as *const ()))
            .field("launch", &(self.launch as *const ()))
            .field("close", &(self.close as *const ()))
            .finish()
    }
}

impl SecurityEnvironmentApi {
    /// Load `processmodel.dll` and resolve the 2-phase security-environment exports.
    ///
    /// # Errors
    /// - [`LearningModeError::DllLoad`] if `processmodel.dll` cannot be loaded.
    /// - [`LearningModeError::ExportMissing`] if any required export is absent under
    ///   either its plain or `Experimental_`-prefixed name.
    pub fn load() -> Result<Self, LearningModeError> {
        let dll = string_util::to_wide(PROCESSMODEL_DLL);

        // SAFETY: `dll` is a valid null-terminated wide string that outlives the call.
        // `LOAD_LIBRARY_SEARCH_SYSTEM32` restricts the search to System32. The module
        // handle is used only for `GetProcAddress` and is never freed (the DLL stays
        // resident). Each resolved pointer is transmuted to a signature matching the C
        // declaration of the corresponding export exactly.
        unsafe {
            let hmodule = LoadLibraryExW(PCWSTR(dll.as_ptr()), None, LOAD_LIBRARY_SEARCH_SYSTEM32)
                .map_err(|e| LearningModeError::DllLoad(e.to_string()))?;

            let create_proc = resolve_any(hmodule, CREATE_NAMES)?;
            let launch_proc = resolve_any(hmodule, LAUNCH_NAMES)?;
            let close_proc = resolve_any(hmodule, CLOSE_NAMES)?;

            Ok(Self {
                create: std::mem::transmute::<
                    unsafe extern "system" fn() -> isize,
                    PfnCreateProcessSecurityEnvironment,
                >(create_proc),
                launch: std::mem::transmute::<
                    unsafe extern "system" fn() -> isize,
                    PfnCreateProcessAsUserInsideSecurityEnvironment,
                >(launch_proc),
                close: std::mem::transmute::<
                    unsafe extern "system" fn() -> isize,
                    PfnCloseProcessSecurityEnvironment,
                >(close_proc),
            })
        }
    }

    /// Create a process security environment from a compiled FlatBuffer sandbox-spec
    /// blob. `flags` is currently always [`PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE`].
    ///
    /// # Errors
    /// [`LearningModeError::ApiCall`] carrying `GetLastError` if the export returns
    /// `FALSE` (including a spec larger than `u32::MAX`, reported as
    /// `ERROR_INVALID_PARAMETER`).
    pub fn create(
        &self,
        sandbox_specification: &[u8],
        flags: u32,
    ) -> Result<ProcessSecurityEnvironment, LearningModeError> {
        let mut env = HANDLE(ptr::null_mut());
        let spec_len =
            u32::try_from(sandbox_specification.len()).map_err(|_| LearningModeError::ApiCall {
                function: "CreateProcessSecurityEnvironment",
                code: windows::Win32::Foundation::ERROR_INVALID_PARAMETER.0,
            })?;

        // SAFETY: `self.create` was resolved from `processmodel.dll` and matches the
        // declared C signature. `sandbox_specification`/`spec_len` describe a valid,
        // contiguous byte buffer that outlives the call, and `env` is a valid
        // out-pointer.
        let ok = unsafe {
            (self.create)(
                sandbox_specification.as_ptr().cast(),
                spec_len,
                flags,
                &mut env,
            )
        };
        if ok == 0 {
            return Err(LearningModeError::ApiCall {
                function: "CreateProcessSecurityEnvironment",
                code: last_error(),
            });
        }
        Ok(ProcessSecurityEnvironment(env))
    }

    /// Close a process security environment, tearing down its server-side state and
    /// (per the create flags) the child. The export nulls the handle on return.
    ///
    /// # Errors
    /// [`LearningModeError::ApiCall`] carrying `GetLastError` if the export returns
    /// `FALSE`.
    pub fn close(&self, env: ProcessSecurityEnvironment) -> Result<(), LearningModeError> {
        let mut handle = env.0;
        // SAFETY: `self.close` was resolved from `processmodel.dll` and matches the
        // declared C signature; `handle` came from a prior `create` and `&mut handle`
        // is a valid in/out-pointer.
        let ok = unsafe { (self.close)(&mut handle) };
        if ok == 0 {
            return Err(LearningModeError::ApiCall {
                function: "CloseProcessSecurityEnvironment",
                code: last_error(),
            });
        }
        Ok(())
    }

    /// The resolved in-environment launch export.
    ///
    /// The stdio/wait/job-object orchestration around
    /// `CreateProcessAsUserInsideSecurityEnvironment` belongs to the runner, so the raw
    /// function pointer is exposed rather than a fully-wrapped launch here. The runner
    /// supplies the `STARTUPINFOW`, receives the real `PROCESS_INFORMATION`, and owns
    /// the returned handles. Callers must pass the environment handle from
    /// [`ProcessSecurityEnvironment::raw`], and — when supplying an environment block —
    /// include `CREATE_UNICODE_ENVIRONMENT` in the creation flags.
    #[must_use]
    pub fn launch_fn(&self) -> PfnCreateProcessAsUserInsideSecurityEnvironment {
        self.launch
    }
}

/// Resolve the first name in `names` that is present in `hmodule`.
///
/// # Safety
/// `hmodule` must be a valid module handle.
unsafe fn resolve_any(
    hmodule: HMODULE,
    names: &[&'static core::ffi::CStr],
) -> Result<unsafe extern "system" fn() -> isize, LearningModeError> {
    let mut last_detail = String::new();
    for name in names {
        // SAFETY: `name` is a valid null-terminated C string; `hmodule` is valid per
        // the caller's contract.
        if let Some(proc) = unsafe { GetProcAddress(hmodule, PCSTR(name.as_ptr().cast())) } {
            return Ok(proc);
        }
        last_detail = format!(
            "GetProcAddress returned NULL (GetLastError = {})",
            last_error()
        );
    }
    Err(LearningModeError::ExportMissing {
        api: "process security-environment",
        export: names
            .first()
            .and_then(|n| n.to_str().ok())
            .unwrap_or("<security-environment export>"),
        detail: last_detail,
    })
}

/// Capture `GetLastError` as a plain `u32`.
fn last_error() -> u32 {
    // SAFETY: `GetLastError` has no preconditions and no side effects beyond reading
    // the calling thread's last-error slot.
    unsafe { GetLastError().0 }
}

/// Diagnostic probe reporting which security-environment export name resolved for each
/// function (plain vs `Experimental_`). Returns an all-`None` report if the DLL itself
/// cannot be loaded.
#[must_use]
pub fn probe_security_environment_exports() -> SecurityEnvironmentExportReport {
    let dll = string_util::to_wide(PROCESSMODEL_DLL);
    // SAFETY: `dll` is a valid null-terminated wide string that outlives the call;
    // `LOAD_LIBRARY_SEARCH_SYSTEM32` restricts the search to System32.
    let hmodule =
        match unsafe { LoadLibraryExW(PCWSTR(dll.as_ptr()), None, LOAD_LIBRARY_SEARCH_SYSTEM32) } {
            Ok(h) => h,
            Err(_) => return SecurityEnvironmentExportReport::default(),
        };

    // SAFETY: `hmodule` is valid; `first_present` only reads exports.
    unsafe {
        SecurityEnvironmentExportReport {
            create: first_present(hmodule, CREATE_NAMES),
            launch: first_present(hmodule, LAUNCH_NAMES),
            close: first_present(hmodule, CLOSE_NAMES),
        }
    }
}

/// Return the first candidate name that resolves in `hmodule`, or `None`.
///
/// # Safety
/// `hmodule` must be a valid module handle.
unsafe fn first_present(
    hmodule: HMODULE,
    names: &[&'static core::ffi::CStr],
) -> Option<&'static str> {
    for name in names {
        // SAFETY: `name` is a valid null-terminated C string; `hmodule` is valid.
        if unsafe { GetProcAddress(hmodule, PCSTR(name.as_ptr().cast())) }.is_some() {
            return name.to_str().ok();
        }
    }
    None
}

/// Capability probe: `true` only when `processmodel.dll` exposes every export required
/// for the 2-phase security-environment launch on this machine.
#[must_use]
pub fn is_security_environment_api_available() -> bool {
    probe_security_environment_exports().is_complete()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_does_not_panic_and_agrees_with_load() {
        let report = probe_security_environment_exports();
        assert_eq!(report.is_complete(), SecurityEnvironmentApi::load().is_ok());
        assert_eq!(
            report.is_complete(),
            is_security_environment_api_available()
        );
    }

    #[test]
    fn load_failure_is_graceful_when_api_absent() {
        match SecurityEnvironmentApi::load() {
            Ok(api) => {
                let _ = format!("{api:?}");
            }
            Err(e) => assert!(
                matches!(
                    e,
                    LearningModeError::DllLoad(_) | LearningModeError::ExportMissing { .. }
                ),
                "unexpected error variant: {e}"
            ),
        }
    }

    #[test]
    fn flag_none_is_zero() {
        assert_eq!(PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE, 0);
    }
}
