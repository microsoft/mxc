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
//! HRESULT CreateProcessSecurityEnvironment(
//!     LPCVOID sandboxSpecification, DWORD sandboxSpecificationSize,
//!     PROCESS_SECURITY_ENVIRONMENT_FLAGS flags,
//!     HPROCESS_SECURITY_ENVIRONMENT* processSecurityEnvironment);
//! void CloseProcessSecurityEnvironment(HPROCESS_SECURITY_ENVIRONMENT processSecurityEnvironment);
//! ```
//!
//! `sandboxSpecification`/`...Size` is a `"PSEC"` process-security-environment
//! FlatBuffer;
//! the spec must encode the learning-mode capability. The environment handle is
//! attached to a normal `CreateProcessW` launch through
//! `PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT`; KernelBase routes that launch
//! through the security environment internally. `Close` tears the environment down.
//!
//! As with the trace exports, each function is resolved at runtime. The
//! ABI-changing create/close exports require their official plain names.

use std::ffi::c_void;
use std::ptr;

use windows::Win32::Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER, HANDLE, HMODULE};
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows::Win32::System::Threading::{
    DeleteProcThreadAttributeList, InitializeProcThreadAttributeList, UpdateProcThreadAttribute,
    LPPROC_THREAD_ATTRIBUTE_LIST, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTUPINFOEXW, STARTUPINFOW,
};
use windows_core::{HRESULT, PCSTR, PCWSTR};
use wxc_common::string_util;

use crate::LearningModeError;

/// System DLL that hosts the flat process security-environment exports.
const PROCESSMODEL_DLL: &str = "processmodel.dll";

/// No special behaviour when creating the security environment
/// (`PROCESS_SECURITY_ENVIRONMENT_FLAGS` value `0`).
///
/// A terminate-on-close bit exists, but its numeric value is intentionally not
/// declared here: explicit [`ProcessSecurityEnvironment::close`] after the child
/// has exited already provides deterministic teardown.
pub const PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE: u32 = 0;

/// `HRESULT CreateProcessSecurityEnvironment(LPCVOID sandboxSpecification,
/// DWORD sandboxSpecificationSize, PROCESS_SECURITY_ENVIRONMENT_FLAGS flags,
/// HPROCESS_SECURITY_ENVIRONMENT* processSecurityEnvironment)`.
///
/// `PROCESS_SECURITY_ENVIRONMENT_FLAGS` is a C enum (`int`-sized), passed as `u32`.
type PfnCreateProcessSecurityEnvironment = unsafe extern "system" fn(
    sandbox_specification: *const c_void,
    sandbox_specification_size: u32,
    flags: u32,
    process_security_environment: *mut HANDLE,
) -> HRESULT;

/// `HRESULT QueryProcessSecurityEnvironmentSupport(UINT64* supportFlags)`.
type PfnQueryProcessSecurityEnvironmentSupport =
    unsafe extern "system" fn(support_flags: *mut u64) -> HRESULT;

/// `void CloseProcessSecurityEnvironment(HPROCESS_SECURITY_ENVIRONMENT processSecurityEnvironment)`.
type PfnCloseProcessSecurityEnvironment =
    unsafe extern "system" fn(process_security_environment: HANDLE);

/// Opaque handle to a process security environment (`HPROCESS_SECURITY_ENVIRONMENT`, a
/// `HANDLE`).
///
/// Produced by [`SecurityEnvironmentApi::create`], threaded into the trace start and
/// the in-environment launch, and torn down by [`ProcessSecurityEnvironment::close`]. The
/// wrapped [`HANDLE`] is passed by value to the launch, trace, and close exports.
/// Drop guarantees the infallible close is called exactly once.
pub struct ProcessSecurityEnvironment {
    handle: HANDLE,
    close: PfnCloseProcessSecurityEnvironment,
}

impl std::fmt::Debug for ProcessSecurityEnvironment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessSecurityEnvironment")
            .field("handle", &self.handle)
            .finish()
    }
}

impl ProcessSecurityEnvironment {
    /// The raw `HPROCESS_SECURITY_ENVIRONMENT` handle, for passing to the trace-start
    /// and in-environment launch exports.
    #[must_use]
    pub fn raw(&self) -> HANDLE {
        self.handle
    }

    /// Close the environment and release its server-side state.
    pub fn close(mut self) {
        self.close_inner();
    }

    fn close_inner(&mut self) {
        if self.handle.0.is_null() {
            return;
        }

        // SAFETY: `close` was resolved from `processmodel.dll`; `self.handle`
        // came from a successful create call and remains owned by this wrapper.
        unsafe { (self.close)(self.handle) };
        self.handle = HANDLE(ptr::null_mut());
    }
}

impl Drop for ProcessSecurityEnvironment {
    fn drop(&mut self) {
        self.close_inner();
    }
}

/// `ProcThreadAttributeSecurityEnvironment` (enum value 35), encoded with the
/// standard `PROC_THREAD_ATTRIBUTE_INPUT` flag.
const PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT: usize = 35 | 0x0002_0000;

/// Owns the extended startup information required to insert a process into an
/// existing process security environment through `CreateProcessW`.
pub struct SecurityEnvironmentStartupInfo {
    storage: Vec<usize>,
    attribute_list: LPPROC_THREAD_ATTRIBUTE_LIST,
    environment_value: Box<HANDLE>,
    inherited_handles: Vec<HANDLE>,
    startup_info: STARTUPINFOEXW,
}

impl SecurityEnvironmentStartupInfo {
    /// Add `environment` to an extended copy of `startup_info`.
    pub fn new(
        mut startup_info: STARTUPINFOW,
        environment: HANDLE,
        inherited_handles: &[HANDLE],
    ) -> Result<Self, LearningModeError> {
        let attribute_count = 1 + u32::from(!inherited_handles.is_empty());
        let mut byte_count = 0usize;
        // SAFETY: the documented sizing call uses a null list and writes only
        // the required byte count.
        let sizing_result = unsafe {
            InitializeProcThreadAttributeList(None, attribute_count, None, &mut byte_count)
        };
        let sizing_error = last_error();
        if sizing_result.is_ok() || sizing_error != ERROR_INSUFFICIENT_BUFFER.0 || byte_count == 0 {
            return Err(LearningModeError::ApiCall {
                function: "InitializeProcThreadAttributeList(size)",
                code: sizing_error,
            });
        }

        let word_count = byte_count.div_ceil(std::mem::size_of::<usize>());
        let mut storage = vec![0usize; word_count];
        let attribute_list = LPPROC_THREAD_ATTRIBUTE_LIST(storage.as_mut_ptr().cast());

        // SAFETY: `storage` is aligned for pointers, has at least
        // `byte_count` writable bytes, and remains owned by the returned value.
        unsafe {
            InitializeProcThreadAttributeList(
                Some(attribute_list),
                attribute_count,
                None,
                &mut byte_count,
            )
        }
        .map_err(|_| LearningModeError::ApiCall {
            function: "InitializeProcThreadAttributeList",
            code: last_error(),
        })?;

        let environment_value = Box::new(environment);
        // SAFETY: the attribute list is initialized, and the boxed HANDLE has
        // a stable address that outlives every use of the list.
        if unsafe {
            UpdateProcThreadAttribute(
                attribute_list,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT,
                Some((&raw const *environment_value).cast()),
                std::mem::size_of::<HANDLE>(),
                None,
                None,
            )
        }
        .is_err()
        {
            let code = last_error();
            // SAFETY: balances the successful initialization above.
            unsafe { DeleteProcThreadAttributeList(attribute_list) };
            return Err(LearningModeError::ApiCall {
                function: "UpdateProcThreadAttribute(SecurityEnvironment)",
                code,
            });
        }

        let inherited_handles = inherited_handles.to_vec();
        if !inherited_handles.is_empty()
            && unsafe {
                UpdateProcThreadAttribute(
                    attribute_list,
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    Some(inherited_handles.as_ptr().cast()),
                    std::mem::size_of_val(inherited_handles.as_slice()),
                    None,
                    None,
                )
            }
            .is_err()
        {
            let code = last_error();
            // SAFETY: balances the successful initialization above.
            unsafe { DeleteProcThreadAttributeList(attribute_list) };
            return Err(LearningModeError::ApiCall {
                function: "UpdateProcThreadAttribute(HANDLE_LIST)",
                code,
            });
        }

        startup_info.cb = u32::try_from(std::mem::size_of::<STARTUPINFOEXW>()).map_err(|_| {
            LearningModeError::ApiCall {
                function: "STARTUPINFOEXW size",
                code: windows::Win32::Foundation::ERROR_INVALID_PARAMETER.0,
            }
        })?;
        let startup_info = STARTUPINFOEXW {
            StartupInfo: startup_info,
            lpAttributeList: attribute_list,
        };

        Ok(Self {
            storage,
            attribute_list,
            environment_value,
            inherited_handles,
            startup_info,
        })
    }

    /// Extended startup information to pass to `CreateProcessW`.
    #[must_use]
    pub fn startup_info(&self) -> &STARTUPINFOEXW {
        &self.startup_info
    }
}

impl std::fmt::Debug for SecurityEnvironmentStartupInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityEnvironmentStartupInfo")
            .field(
                "attribute_bytes",
                &(self.storage.len() * std::mem::size_of::<usize>()),
            )
            .field("environment", &self.environment_value)
            .field("inherited_handles", &self.inherited_handles)
            .finish()
    }
}

impl Drop for SecurityEnvironmentStartupInfo {
    fn drop(&mut self) {
        if !self.attribute_list.is_invalid() {
            // SAFETY: the list was successfully initialized and has not been
            // deleted yet.
            unsafe { DeleteProcThreadAttributeList(self.attribute_list) };
            self.attribute_list = LPPROC_THREAD_ATTRIBUTE_LIST::default();
        }
    }
}

/// Which candidate export name resolved for each function on this machine — a
/// diagnostic used by the capability probe to report the exact live surface (plain vs
/// `Experimental_`).
#[derive(Debug, Clone, Copy, Default)]
pub struct SecurityEnvironmentExportReport {
    /// Resolved name of the create export, if present.
    pub create: Option<&'static str>,
    /// Resolved name of the support-query export, if present.
    pub query_support: Option<&'static str>,
    /// Resolved name of the close export, if present.
    pub close: Option<&'static str>,
}

impl SecurityEnvironmentExportReport {
    /// `true` only when every export required for the 2-phase launch resolved.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.create.is_some() && self.query_support.is_some() && self.close.is_some()
    }
}

const CREATE_NAMES: &[&core::ffi::CStr] = &[c"CreateProcessSecurityEnvironment"];
const QUERY_SUPPORT_NAMES: &[&core::ffi::CStr] = &[c"QueryProcessSecurityEnvironmentSupport"];
const CLOSE_NAMES: &[&core::ffi::CStr] = &[c"CloseProcessSecurityEnvironment"];

/// Resolved process security-environment exports from `processmodel.dll`.
#[derive(Clone, Copy)]
pub struct SecurityEnvironmentApi {
    create: PfnCreateProcessSecurityEnvironment,
    query_support: PfnQueryProcessSecurityEnvironmentSupport,
    close: PfnCloseProcessSecurityEnvironment,
}

impl std::fmt::Debug for SecurityEnvironmentApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityEnvironmentApi")
            .field("create", &(self.create as *const ()))
            .field("query_support", &(self.query_support as *const ()))
            .field("close", &(self.close as *const ()))
            .finish()
    }
}

impl SecurityEnvironmentApi {
    /// Load `processmodel.dll` and resolve the 2-phase security-environment exports.
    ///
    /// # Errors
    /// - [`LearningModeError::DllLoad`] if `processmodel.dll` cannot be loaded.
    /// - [`LearningModeError::ExportMissing`] if any required export is absent.
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
            let query_support_proc = resolve_any(hmodule, QUERY_SUPPORT_NAMES)?;
            let close_proc = resolve_any(hmodule, CLOSE_NAMES)?;

            Ok(Self {
                create: std::mem::transmute::<
                    unsafe extern "system" fn() -> isize,
                    PfnCreateProcessSecurityEnvironment,
                >(create_proc),
                query_support: std::mem::transmute::<
                    unsafe extern "system" fn() -> isize,
                    PfnQueryProcessSecurityEnvironmentSupport,
                >(query_support_proc),
                close: std::mem::transmute::<
                    unsafe extern "system" fn() -> isize,
                    PfnCloseProcessSecurityEnvironment,
                >(close_proc),
            })
        }
    }

    /// Whether the official V2 API supports native deny paths.
    pub fn supports_deny_paths(&self) -> Result<bool, LearningModeError> {
        const PSE_SUPPORT_FS_DENY: u64 = 0x0000_0000_0000_0001;
        let mut support_flags = 0u64;
        // SAFETY: `query_support` matches the official V2 declaration and
        // `support_flags` is a valid out-pointer.
        let result = unsafe { (self.query_support)(&mut support_flags) };
        if result.is_err() {
            return Err(LearningModeError::HResultCall {
                function: "QueryProcessSecurityEnvironmentSupport",
                code: result.0,
            });
        }
        Ok(support_flags & PSE_SUPPORT_FS_DENY != 0)
    }

    /// Create a process security environment from a PSEC FlatBuffer
    /// blob. `flags` is currently always [`PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE`].
    ///
    /// # Errors
    /// [`LearningModeError::HResultCall`] if the export returns a failing HRESULT.
    pub fn create(
        &self,
        sandbox_specification: &[u8],
        flags: u32,
    ) -> Result<ProcessSecurityEnvironment, LearningModeError> {
        let mut env = HANDLE(ptr::null_mut());
        let spec_len = u32::try_from(sandbox_specification.len()).map_err(|_| {
            LearningModeError::HResultCall {
                function: "CreateProcessSecurityEnvironment",
                code: windows::Win32::Foundation::E_INVALIDARG.0,
            }
        })?;

        // SAFETY: `self.create` was resolved from `processmodel.dll` and matches the
        // declared C signature. `sandbox_specification`/`spec_len` describe a valid,
        // contiguous byte buffer that outlives the call, and `env` is a valid
        // out-pointer.
        let result = unsafe {
            (self.create)(
                sandbox_specification.as_ptr().cast(),
                spec_len,
                flags,
                &mut env,
            )
        };
        if result.is_err() {
            return Err(LearningModeError::HResultCall {
                function: "CreateProcessSecurityEnvironment",
                code: result.0,
            });
        }
        if env.0.is_null() {
            return Err(LearningModeError::HResultCall {
                function: "CreateProcessSecurityEnvironment",
                code: windows::Win32::Foundation::E_UNEXPECTED.0,
            });
        }
        Ok(ProcessSecurityEnvironment {
            handle: env,
            close: self.close,
        })
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
            query_support: first_present(hmodule, QUERY_SUPPORT_NAMES),
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CLOSE_CALLS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "system" fn fake_close(_: HANDLE) {
        CLOSE_CALLS.fetch_add(1, Ordering::SeqCst);
    }

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

    #[test]
    fn startup_info_attaches_security_environment_attribute() {
        let startup_info = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let environment = HANDLE(std::ptr::dangling_mut::<c_void>());

        match SecurityEnvironmentStartupInfo::new(startup_info, environment, &[]) {
            Ok(extended) => {
                assert_eq!(
                    extended.startup_info().StartupInfo.cb as usize,
                    std::mem::size_of::<STARTUPINFOEXW>()
                );
                assert!(!extended.startup_info().lpAttributeList.is_invalid());
            }
            Err(LearningModeError::ApiCall { code, .. })
                if code == windows::Win32::Foundation::ERROR_NOT_SUPPORTED.0
                    || code == windows::Win32::Foundation::ERROR_CALL_NOT_IMPLEMENTED.0 =>
            {
                // Off-feature Windows builds reject the private attribute at
                // UpdateProcThreadAttribute time.
            }
            Err(error) => panic!("unexpected attribute-list error: {error}"),
        }
    }

    #[test]
    fn explicit_close_is_exactly_once() {
        CLOSE_CALLS.store(0, Ordering::SeqCst);
        let environment = ProcessSecurityEnvironment {
            handle: HANDLE(std::ptr::dangling_mut::<c_void>()),
            close: fake_close,
        };

        environment.close();
        assert_eq!(CLOSE_CALLS.load(Ordering::SeqCst), 1);
    }
}
