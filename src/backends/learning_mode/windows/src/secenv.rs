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
//! `Experimental_CreateProcessInSandbox`. To capture denials, MXC uses the
//! official process security-environment model exported by `processmodel.dll`:
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
use std::sync::OnceLock;

use windows::Win32::Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER, HANDLE, HMODULE};
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows::Win32::System::Threading::{
    DeleteProcThreadAttributeList, InitializeProcThreadAttributeList, UpdateProcThreadAttribute,
    LPPROC_THREAD_ATTRIBUTE_LIST, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTUPINFOEXW, STARTUPINFOW,
};
use windows::Win32::System::WindowsProgramming::IsApiSetImplemented;
use windows_core::{HRESULT, PCSTR, PCWSTR};
use mxc_alpha_wxc_common::string_util;

use crate::LearningModeError;

/// System DLL that hosts the flat process security-environment exports.
const PROCESSMODEL_DLL: &str = "processmodel.dll";
const SECURITY_ENVIRONMENT_API_SET_NAME: &str = "api-win-appmodel-processmodel~securityenvironment";
const SECURITY_ENVIRONMENT_API_SET: &core::ffi::CStr =
    c"api-win-appmodel-processmodel~securityenvironment";

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

/// Which official export resolved for each function on this machine.
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
///
/// `cacheable` records whether this surface was produced by the memoizing
/// [`SecurityEnvironmentApi::load`] (the real, process-wide singleton) as opposed
/// to a test fake. Only cacheable surfaces are allowed to populate the process-wide
/// [`supports_deny_paths`](Self::supports_deny_paths) cache, so injected fakes can
/// never poison it for the real API or for each other.
#[derive(Clone, Copy)]
pub struct SecurityEnvironmentApi {
    create: PfnCreateProcessSecurityEnvironment,
    query_support: PfnQueryProcessSecurityEnvironmentSupport,
    close: PfnCloseProcessSecurityEnvironment,
    cacheable: bool,
}

impl std::fmt::Debug for SecurityEnvironmentApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityEnvironmentApi")
            .field("create", &(self.create as *const ()))
            .field("query_support", &(self.query_support as *const ()))
            .field("close", &(self.close as *const ()))
            .field("cacheable", &self.cacheable)
            .finish()
    }
}

fn is_security_environment_api_set_implemented() -> bool {
    // SAFETY: the contract is a valid static null-terminated string.
    unsafe { IsApiSetImplemented(PCSTR(SECURITY_ENVIRONMENT_API_SET.as_ptr().cast())).as_bool() }
}

impl SecurityEnvironmentApi {
    /// Load `processmodel.dll` and resolve the 2-phase security-environment exports.
    ///
    /// The result — success or failure — is memoized for the lifetime of the
    /// process: `processmodel.dll` is a resident system DLL whose export set does
    /// not change while the process runs, so repeated probes would only repeat the
    /// same work and return the same answer. The cached error is cloned (see
    /// [`LearningModeError`]), preserving the original diagnostic on every call. The
    /// cached surface is marked cacheable so its
    /// [`supports_deny_paths`](Self::supports_deny_paths) result is memoized too.
    ///
    /// # Errors
    /// - [`LearningModeError::ApiSetUnavailable`] if the security-environment
    ///   API-set named group is not implemented.
    /// - [`LearningModeError::DllLoad`] if `processmodel.dll` cannot be loaded.
    /// - [`LearningModeError::ExportMissing`] if any required export is absent.
    pub fn load() -> Result<Self, LearningModeError> {
        static CACHE: OnceLock<Result<SecurityEnvironmentApi, LearningModeError>> = OnceLock::new();
        CACHE.get_or_init(Self::load_uncached).clone()
    }

    /// Perform the actual DLL load and export resolution, bypassing the cache.
    fn load_uncached() -> Result<Self, LearningModeError> {
        if !is_security_environment_api_set_implemented() {
            return Err(LearningModeError::ApiSetUnavailable {
                api: "process security-environment",
                api_set: SECURITY_ENVIRONMENT_API_SET_NAME,
            });
        }

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
                cacheable: true,
            })
        }
    }

    /// Construct an API surface directly from raw export pointers, bypassing the
    /// DLL load. Test-only: lets sibling modules inject fakes. The surface is marked
    /// non-cacheable so its [`supports_deny_paths`](Self::supports_deny_paths) result
    /// never populates the process-wide cache.
    #[cfg(test)]
    pub(crate) fn from_raw_parts(
        create: PfnCreateProcessSecurityEnvironment,
        query_support: PfnQueryProcessSecurityEnvironmentSupport,
        close: PfnCloseProcessSecurityEnvironment,
    ) -> Self {
        Self {
            create,
            query_support,
            close,
            cacheable: false,
        }
    }

    /// Like [`from_raw_parts`](Self::from_raw_parts) but marked cacheable, so the
    /// memoization of [`supports_deny_paths`](Self::supports_deny_paths) can be
    /// exercised host-independently. Test-only.
    #[cfg(test)]
    pub(crate) fn from_raw_parts_cacheable(
        create: PfnCreateProcessSecurityEnvironment,
        query_support: PfnQueryProcessSecurityEnvironmentSupport,
        close: PfnCloseProcessSecurityEnvironment,
    ) -> Self {
        Self {
            create,
            query_support,
            close,
            cacheable: true,
        }
    }

    /// Whether the official V2 API supports native deny paths.
    ///
    /// The answer is a fixed host capability, so for the real (cacheable) API the
    /// result — including a typed error — is memoized once per process. Non-cacheable
    /// test fakes always query directly and never touch the process-wide cache.
    pub fn supports_deny_paths(&self) -> Result<bool, LearningModeError> {
        if self.cacheable {
            static CACHE: OnceLock<Result<bool, LearningModeError>> = OnceLock::new();
            CACHE
                .get_or_init(|| self.query_deny_paths_support())
                .clone()
        } else {
            self.query_deny_paths_support()
        }
    }

    /// Query `QueryProcessSecurityEnvironmentSupport` for the native-deny-path bit,
    /// without consulting or populating the process-wide cache.
    fn query_deny_paths_support(&self) -> Result<bool, LearningModeError> {
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

/// Diagnostic probe reporting which official security-environment exports
/// resolved. Returns an all-`None` report if the DLL itself cannot be loaded.
#[must_use]
pub fn probe_security_environment_exports() -> SecurityEnvironmentExportReport {
    if !is_security_environment_api_set_implemented() {
        return SecurityEnvironmentExportReport::default();
    }

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
    use std::sync::atomic::{AtomicI32, AtomicU64, AtomicUsize, Ordering};
    use std::sync::Mutex;
    use windows::Win32::Foundation::{E_FAIL, S_OK};

    static CLOSE_CALLS: AtomicUsize = AtomicUsize::new(0);

    /// Serializes the tests that share the query fakes' global counters.
    static QUERY_LOCK: Mutex<()> = Mutex::new(());
    static QUERY_CALLS: AtomicUsize = AtomicUsize::new(0);
    static QUERY_RESULT: AtomicI32 = AtomicI32::new(S_OK.0);
    static QUERY_FLAGS: AtomicU64 = AtomicU64::new(0);

    /// Native-deny-path support bit reported by `QueryProcessSecurityEnvironmentSupport`.
    const PSE_SUPPORT_FS_DENY: u64 = 0x0000_0000_0000_0001;

    unsafe extern "system" fn fake_close(_: HANDLE) {
        CLOSE_CALLS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "system" fn fake_create(
        _: *const c_void,
        _: u32,
        _: u32,
        _: *mut HANDLE,
    ) -> HRESULT {
        S_OK
    }

    unsafe extern "system" fn fake_query(support_flags: *mut u64) -> HRESULT {
        QUERY_CALLS.fetch_add(1, Ordering::SeqCst);
        let result = HRESULT(QUERY_RESULT.load(Ordering::SeqCst));
        if result.is_ok() {
            unsafe { *support_flags = QUERY_FLAGS.load(Ordering::SeqCst) };
        }
        result
    }

    fn reset_query_fakes() {
        QUERY_CALLS.store(0, Ordering::SeqCst);
        QUERY_RESULT.store(S_OK.0, Ordering::SeqCst);
        QUERY_FLAGS.store(0, Ordering::SeqCst);
    }

    fn fake_uncached_api() -> SecurityEnvironmentApi {
        SecurityEnvironmentApi::from_raw_parts(fake_create, fake_query, fake_close)
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
                    LearningModeError::ApiSetUnavailable { .. }
                        | LearningModeError::DllLoad(_)
                        | LearningModeError::ExportMissing { .. }
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

    #[test]
    fn export_report_all_present_is_complete() {
        let report = SecurityEnvironmentExportReport {
            create: Some("CreateProcessSecurityEnvironment"),
            query_support: Some("QueryProcessSecurityEnvironmentSupport"),
            close: Some("CloseProcessSecurityEnvironment"),
        };
        assert!(report.is_complete());
    }

    #[test]
    fn export_report_each_missing_export_is_incomplete() {
        let complete = SecurityEnvironmentExportReport {
            create: Some("CreateProcessSecurityEnvironment"),
            query_support: Some("QueryProcessSecurityEnvironmentSupport"),
            close: Some("CloseProcessSecurityEnvironment"),
        };

        assert!(!SecurityEnvironmentExportReport {
            create: None,
            ..complete
        }
        .is_complete());
        assert!(!SecurityEnvironmentExportReport {
            query_support: None,
            ..complete
        }
        .is_complete());
        assert!(!SecurityEnvironmentExportReport {
            close: None,
            ..complete
        }
        .is_complete());
        assert!(!SecurityEnvironmentExportReport::default().is_complete());
    }

    #[test]
    fn supports_deny_paths_reports_flag_state() {
        let _guard = QUERY_LOCK.lock().unwrap();
        let api = fake_uncached_api();

        reset_query_fakes();
        QUERY_FLAGS.store(PSE_SUPPORT_FS_DENY, Ordering::SeqCst);
        assert!(api.supports_deny_paths().unwrap());
        assert_eq!(QUERY_CALLS.load(Ordering::SeqCst), 1);

        reset_query_fakes();
        QUERY_FLAGS.store(0, Ordering::SeqCst);
        assert!(!api.supports_deny_paths().unwrap());

        reset_query_fakes();
        // Unrelated support bits must not be mistaken for deny-path support.
        QUERY_FLAGS.store(0xFFFF_FFFF_FFFF_FFFE, Ordering::SeqCst);
        assert!(!api.supports_deny_paths().unwrap());
    }

    #[test]
    fn supports_deny_paths_maps_failing_hresult() {
        let _guard = QUERY_LOCK.lock().unwrap();
        reset_query_fakes();
        QUERY_RESULT.store(E_FAIL.0, Ordering::SeqCst);
        let api = fake_uncached_api();

        let error = api.supports_deny_paths().unwrap_err();
        assert!(matches!(
            error,
            LearningModeError::HResultCall {
                function: "QueryProcessSecurityEnvironmentSupport",
                code
            } if code == E_FAIL.0
        ));
    }

    #[test]
    fn non_cacheable_api_queries_every_call() {
        let _guard = QUERY_LOCK.lock().unwrap();
        reset_query_fakes();
        QUERY_FLAGS.store(PSE_SUPPORT_FS_DENY, Ordering::SeqCst);
        let api = fake_uncached_api();

        assert!(api.supports_deny_paths().unwrap());
        assert!(api.supports_deny_paths().unwrap());
        // A test fake must never be memoized: both calls hit the underlying query.
        assert_eq!(QUERY_CALLS.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn cacheable_api_memoizes_support_query() {
        // The only test that drives the cacheable (process-wide) support cache, so
        // the `OnceLock` initializer runs deterministically here.
        let _guard = QUERY_LOCK.lock().unwrap();
        reset_query_fakes();
        QUERY_FLAGS.store(PSE_SUPPORT_FS_DENY, Ordering::SeqCst);
        let api =
            SecurityEnvironmentApi::from_raw_parts_cacheable(fake_create, fake_query, fake_close);

        let first = api.supports_deny_paths().unwrap();
        let second = api.supports_deny_paths().unwrap();
        assert_eq!(first, second);
        // The result is memoized for the process: the query runs at most once.
        assert_eq!(QUERY_CALLS.load(Ordering::SeqCst), 1);
    }
}
