// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows runtime FFI for the `processmodel.dll` **process security-environment**
//! exports — the 2-phase sandbox launch model that produces the
//! `HPROCESS_SECURITY_ENVIRONMENT` handle that
//! [`learning_mode_windows::LearningModeApi::start_trace`]
//! keys the Learning Mode trace on.
//!
//! `StartLearningModeTrace` is keyed on a security-environment handle (the broker
//! resolves it to the target AppContainer SID server-side). BaseContainer uses
//! the official process security-environment model exported by `processmodel.dll`:
//!
//! ```c
//! HRESULT CreateProcessSecurityEnvironment(
//!     LPCVOID sandboxSpecification, DWORD sandboxSpecificationSize,
//!     PROCESS_SECURITY_ENVIRONMENT_FLAGS flags,
//!     HPROCESS_SECURITY_ENVIRONMENT* processSecurityEnvironment);
//! HRESULT IsProcessSecurityEnvironmentVersionSupported(
//!     DWORD major, BOOLEAN* available, DWORD* minor);
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
use windows_core::{HRESULT, PCSTR, PCWSTR};
use wxc_common::api_set::is_api_set_implemented;
use wxc_common::string_util;

use crate::secenv_policy::{RawPolicyDetail, RawPolicyResult, MAX_DETAILS, MAX_RESOURCE_CHARS};
use learning_mode_windows::LearningModeError;
use wxc_common::policy_enforcement::NativePolicyResult;

/// System DLL that hosts the flat process security-environment exports.
const PROCESSMODEL_DLL: &str = "processmodel.dll";
pub(crate) const SECURITY_ENVIRONMENT_API_SET: &core::ffi::CStr =
    c"api-win-appmodel-processmodel~securityenvironment";

/// Capability advertised by `QueryProcessSecurityEnvironmentSupport`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum SecurityEnvironmentSupport {
    /// Native filesystem deny paths.
    FileSystemDeny = 0x0000_0001,
    /// Enumeration-only filesystem paths.
    FileSystemEnumerate = 0x0000_0004,
    /// The ingress policy table.
    NetworkIngress = 0x0000_0008,
    /// Creation-policy results through CreateProcessSecurityEnvironment2.
    PolicyResult = 0x0000_0010,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct SecurityEnvironmentVersion {
    pub(crate) major: u16,
    pub(crate) minor: u16,
}

impl SecurityEnvironmentVersion {
    pub(crate) const V1_0: Self = Self { major: 1, minor: 0 };
    pub(crate) const V1_1: Self = Self { major: 1, minor: 1 };
}

impl SecurityEnvironmentSupport {
    pub(crate) const fn required_version(self) -> SecurityEnvironmentVersion {
        match self {
            Self::FileSystemDeny | Self::PolicyResult => SecurityEnvironmentVersion::V1_0,
            Self::FileSystemEnumerate | Self::NetworkIngress => SecurityEnvironmentVersion::V1_1,
        }
    }
}

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

type PfnCreateProcessSecurityEnvironment2 = unsafe extern "system" fn(
    sandbox_specification: *const c_void,
    sandbox_specification_size: u32,
    flags: u32,
    policy_result: *mut RawPolicyResult,
    process_security_environment: *mut HANDLE,
) -> HRESULT;

/// The policy decision is independent of provisioning success.
#[derive(Debug)]
pub(crate) struct PolicyCreateOutcome {
    pub hresult: HRESULT,
    pub policy: NativePolicyResult,
    pub environment: Option<ProcessSecurityEnvironment>,
    pub invalid_result: Option<&'static str>,
}

/// `HRESULT QueryProcessSecurityEnvironmentSupport(
/// PROCESS_SECURITY_ENVIRONMENT_SUPPORT_FLAGS* supportFlags)`.
/// The native flags enum is 32-bit.
type PfnQueryProcessSecurityEnvironmentSupport =
    unsafe extern "system" fn(support_flags: *mut u32) -> HRESULT;

/// `HRESULT IsProcessSecurityEnvironmentVersionSupported(
/// DWORD major, BOOLEAN* available, DWORD* minor)`.
type PfnIsProcessSecurityEnvironmentVersionSupported =
    unsafe extern "system" fn(major: u32, available: *mut u8, minor: *mut u32) -> HRESULT;

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
    #[cfg(test)]
    pub(crate) fn from_test_handle(
        handle: HANDLE,
        close: unsafe extern "system" fn(HANDLE),
    ) -> Self {
        Self { handle, close }
    }

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

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct PolicyResultExportReport {
    pub exports: SecurityEnvironmentExportReport,
    pub create2: Option<&'static str>,
    pub support_flags: Option<u32>,
    pub support_query_hresult: Option<i32>,
}

impl PolicyResultExportReport {
    pub fn policy_results_available(&self) -> bool {
        self.exports.is_complete()
            && self.create2.is_some()
            && self
                .support_flags
                .is_some_and(|flags| flags & SecurityEnvironmentSupport::PolicyResult as u32 != 0)
    }
}

const CREATE_NAMES: &[&core::ffi::CStr] = &[c"CreateProcessSecurityEnvironment"];
const CREATE2_NAMES: &[&core::ffi::CStr] = &[c"CreateProcessSecurityEnvironment2"];
const QUERY_SUPPORT_NAMES: &[&core::ffi::CStr] = &[c"QueryProcessSecurityEnvironmentSupport"];
const VERSION_SUPPORT_NAMES: &[&core::ffi::CStr] =
    &[c"IsProcessSecurityEnvironmentVersionSupported"];
const CLOSE_NAMES: &[&core::ffi::CStr] = &[c"CloseProcessSecurityEnvironment"];

/// Resolved process security-environment exports from `processmodel.dll`.
///
/// `cacheable` records whether this surface was produced by the memoizing
/// [`SecurityEnvironmentApi::load`] (the real, process-wide singleton) as opposed
/// to a test fake. Only cacheable surfaces are allowed to populate the process-wide
/// support-flags cache, so injected fakes can never poison it for the real API or
/// for each other.
#[derive(Clone, Copy)]
pub struct SecurityEnvironmentApi {
    create: PfnCreateProcessSecurityEnvironment,
    create2: Option<PfnCreateProcessSecurityEnvironment2>,
    query_support: PfnQueryProcessSecurityEnvironmentSupport,
    version_support: Option<PfnIsProcessSecurityEnvironmentVersionSupported>,
    close: PfnCloseProcessSecurityEnvironment,
    cacheable: bool,
}

impl std::fmt::Debug for SecurityEnvironmentApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityEnvironmentApi")
            .field("create", &(self.create as *const ()))
            .field("query_support", &(self.query_support as *const ()))
            .field(
                "version_support",
                &self.version_support.map(|function| function as *const ()),
            )
            .field("close", &(self.close as *const ()))
            .field("cacheable", &self.cacheable)
            .finish()
    }
}

impl SecurityEnvironmentApi {
    /// Load `processmodel.dll` and resolve the 2-phase security-environment exports.
    ///
    /// The result — success or failure — is memoized for the lifetime of the
    /// process: `processmodel.dll` is a resident system DLL whose export set does
    /// not change while the process runs, so repeated probes would only repeat the
    /// same work and return the same answer. The cached error is cloned (see
    /// [`LearningModeError`]), preserving the original diagnostic on every call. The
    /// cached surface is marked cacheable so its support flags are memoized too.
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
        if !is_api_set_implemented(SECURITY_ENVIRONMENT_API_SET) {
            return Err(LearningModeError::ApiSetUnavailable {
                api: "process security-environment",
                api_set: SECURITY_ENVIRONMENT_API_SET
                    .to_str()
                    .expect("API-set contract names must be UTF-8"),
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
            let create2 =
                GetProcAddress(hmodule, PCSTR(CREATE2_NAMES[0].as_ptr().cast())).map(|function| {
                    std::mem::transmute::<
                        unsafe extern "system" fn() -> isize,
                        PfnCreateProcessSecurityEnvironment2,
                    >(function)
                });
            let query_support_proc = resolve_any(hmodule, QUERY_SUPPORT_NAMES)?;
            let version_support =
                GetProcAddress(hmodule, PCSTR(VERSION_SUPPORT_NAMES[0].as_ptr().cast())).map(
                    |function| {
                        std::mem::transmute::<
                            unsafe extern "system" fn() -> isize,
                            PfnIsProcessSecurityEnvironmentVersionSupported,
                        >(function)
                    },
                );
            let close_proc = resolve_any(hmodule, CLOSE_NAMES)?;

            Ok(Self {
                create2,
                create: std::mem::transmute::<
                    unsafe extern "system" fn() -> isize,
                    PfnCreateProcessSecurityEnvironment,
                >(create_proc),
                query_support: std::mem::transmute::<
                    unsafe extern "system" fn() -> isize,
                    PfnQueryProcessSecurityEnvironmentSupport,
                >(query_support_proc),
                version_support,
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
    /// non-cacheable so its support flags never populate the process-wide cache.
    #[cfg(test)]
    pub(crate) fn from_raw_parts(
        create: PfnCreateProcessSecurityEnvironment,
        query_support: PfnQueryProcessSecurityEnvironmentSupport,
        close: PfnCloseProcessSecurityEnvironment,
    ) -> Self {
        Self {
            create,
            create2: None,
            query_support,
            version_support: None,
            close,
            cacheable: false,
        }
    }

    /// Like [`from_raw_parts`](Self::from_raw_parts) but marked cacheable, so support
    /// flag memoization can be exercised host-independently. Test-only.
    #[cfg(test)]
    pub(crate) fn from_raw_parts_cacheable(
        create: PfnCreateProcessSecurityEnvironment,
        query_support: PfnQueryProcessSecurityEnvironmentSupport,
        close: PfnCloseProcessSecurityEnvironment,
    ) -> Self {
        Self {
            create,
            create2: None,
            query_support,
            version_support: None,
            close,
            cacheable: true,
        }
    }

    pub(crate) fn policy_results_available(&self) -> Result<bool, LearningModeError> {
        if self.create2.is_none() {
            return Ok(false);
        }
        self.query_support(SecurityEnvironmentSupport::PolicyResult)
    }

    pub(crate) fn create_with_policy_result(
        &self,
        specification: &[u8],
        flags: u32,
    ) -> Result<PolicyCreateOutcome, LearningModeError> {
        let create = self.create2.ok_or(LearningModeError::HResultCall {
            function: "CreateProcessSecurityEnvironment2",
            code: windows::Win32::Foundation::E_NOTIMPL.0,
        })?;
        let size =
            u32::try_from(specification.len()).map_err(|_| LearningModeError::HResultCall {
                function: "CreateProcessSecurityEnvironment2",
                code: windows::Win32::Foundation::E_INVALIDARG.0,
            })?;
        let mut storage = vec![0u16; MAX_RESOURCE_CHARS];
        let mut details = vec![RawPolicyDetail::default(); MAX_DETAILS];
        let mut result = RawPolicyResult::new(&mut details, &mut storage);
        let mut handle = HANDLE(ptr::null_mut());
        // SAFETY: the function has the exact CPSE2 ABI; all input/output storage
        // stays live through this call and resource counts are checked afterward.
        let hresult = unsafe {
            create(
                specification.as_ptr().cast(),
                size,
                flags,
                &mut result,
                &mut handle,
            )
        };
        let environment = (!handle.0.is_null()).then_some(ProcessSecurityEnvironment {
            handle,
            close: self.close,
        });
        let (policy, invalid_result) = result.to_owned(&details, &storage);
        Ok(PolicyCreateOutcome {
            hresult,
            policy,
            environment,
            invalid_result,
        })
    }

    /// Whether the requested PSEC contract version is supported.
    pub fn supports_version(&self, major: u32, minor: u32) -> Result<bool, LearningModeError> {
        let Some(version_support) = self.version_support else {
            return Ok(major == 1 && minor == 0);
        };
        query_supported_minor_version_with(major, version_support)
            .map(|supported| supported.is_some_and(|supported| supported >= minor))
    }

    /// Whether the official PSEC API advertises `capability`.
    pub fn query_support(
        &self,
        capability: SecurityEnvironmentSupport,
    ) -> Result<bool, LearningModeError> {
        self.support_flags()
            .map(|support_flags| support_flags & capability as u32 != 0)
    }

    #[cfg(test)]
    fn query_support_cached(
        &self,
        capability: SecurityEnvironmentSupport,
        cache: &OnceLock<Result<u32, LearningModeError>>,
    ) -> Result<bool, LearningModeError> {
        self.support_flags_cached(cache)
            .map(|support_flags| support_flags & capability as u32 != 0)
    }

    /// Return the immutable support flags advertised by the official PSEC API.
    ///
    /// The real API is process-wide and immutable, so both successful flags and
    /// typed failures are memoized. Injected test surfaces remain uncached.
    fn support_flags(&self) -> Result<u32, LearningModeError> {
        if self.cacheable {
            static CACHE: OnceLock<Result<u32, LearningModeError>> = OnceLock::new();
            self.support_flags_cached(&CACHE)
        } else {
            self.query_support_flags()
        }
    }

    fn support_flags_cached(
        &self,
        cache: &OnceLock<Result<u32, LearningModeError>>,
    ) -> Result<u32, LearningModeError> {
        cache.get_or_init(|| self.query_support_flags()).clone()
    }

    fn query_support_flags(&self) -> Result<u32, LearningModeError> {
        let (result, support_flags) = query_support_flags_raw(self.query_support);
        if result.is_err() {
            return Err(LearningModeError::HResultCall {
                function: "QueryProcessSecurityEnvironmentSupport",
                code: result.0,
            });
        }
        Ok(support_flags)
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
        let environment = (!env.0.is_null()).then_some(ProcessSecurityEnvironment {
            handle: env,
            close: self.close,
        });
        if result.is_err() {
            return Err(LearningModeError::HResultCall {
                function: "CreateProcessSecurityEnvironment",
                code: result.0,
            });
        }
        let Some(environment) = environment else {
            return Err(LearningModeError::HResultCall {
                function: "CreateProcessSecurityEnvironment",
                code: windows::Win32::Foundation::E_UNEXPECTED.0,
            });
        };
        Ok(environment)
    }
}

/// Whether the process security-environment API supports `capability`.
///
/// API loading, contract-version validation, and query failures all fail closed.
#[must_use]
pub(crate) fn query_support(capability: SecurityEnvironmentSupport) -> bool {
    try_query_support(capability).unwrap_or(false)
}

pub(crate) fn try_query_support(
    capability: SecurityEnvironmentSupport,
) -> Result<bool, LearningModeError> {
    SecurityEnvironmentApi::load().and_then(|api| {
        let version = capability.required_version();
        if !api.supports_version(u32::from(version.major), u32::from(version.minor))? {
            return Ok(false);
        }
        api.query_support(capability)
    })
}

pub(crate) fn supports_version(
    version: SecurityEnvironmentVersion,
) -> Result<bool, LearningModeError> {
    SecurityEnvironmentApi::load()?
        .supports_version(u32::from(version.major), u32::from(version.minor))
}

pub(crate) fn create(
    sandbox_specification: &[u8],
    flags: u32,
) -> Result<ProcessSecurityEnvironment, LearningModeError> {
    SecurityEnvironmentApi::load()?.create(sandbox_specification, flags)
}

fn query_support_flags_raw(query: PfnQueryProcessSecurityEnvironmentSupport) -> (HRESULT, u32) {
    let mut flags = 0u32;
    // SAFETY: the function has the native enum-pointer ABI; flags is writable
    // for the complete synchronous query. This does not create an environment.
    let status = unsafe { query(&mut flags) };
    (status, flags)
}

fn query_supported_minor_version_with(
    major: u32,
    version_support: PfnIsProcessSecurityEnvironmentVersionSupported,
) -> Result<Option<u32>, LearningModeError> {
    let mut available = 0u8;
    let mut minor = 0u32;
    // SAFETY: `version_support` has the documented OS ABI and both output
    // pointers remain valid for the duration of the call.
    let result = unsafe { version_support(major, &mut available, &mut minor) };
    if result.is_err() {
        return Err(LearningModeError::HResultCall {
            function: "IsProcessSecurityEnvironmentVersionSupported",
            code: result.0,
        });
    }
    Ok((available != 0).then_some(minor))
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

/// Resolve the legacy creation exports without invoking any native support query.
#[must_use]
pub fn probe_security_environment_exports() -> SecurityEnvironmentExportReport {
    probe_exports(false).exports
}

/// Resolve exports and query capabilities for explicitly requested policy reporting.
pub(crate) fn probe_policy_result_exports() -> PolicyResultExportReport {
    probe_exports(true)
}

fn probe_exports(report_policy: bool) -> PolicyResultExportReport {
    if !is_api_set_implemented(SECURITY_ENVIRONMENT_API_SET) {
        return PolicyResultExportReport::default();
    }

    let dll = string_util::to_wide(PROCESSMODEL_DLL);
    // SAFETY: `dll` is a valid null-terminated wide string that outlives the call;
    // `LOAD_LIBRARY_SEARCH_SYSTEM32` restricts the search to System32.
    let hmodule =
        match unsafe { LoadLibraryExW(PCWSTR(dll.as_ptr()), None, LOAD_LIBRARY_SEARCH_SYSTEM32) } {
            Ok(h) => h,
            Err(_) => return PolicyResultExportReport::default(),
        };

    // SAFETY: the module is valid and the support-query signature matches the
    // OS declaration. The called query owns no environment or resource lifetime.
    unsafe {
        probe_exports_with(
            |names| first_present(hmodule, names),
            || {
                GetProcAddress(hmodule, PCSTR(QUERY_SUPPORT_NAMES[0].as_ptr().cast())).map(
                    |function| {
                        query_support_flags_raw(std::mem::transmute::<
                            unsafe extern "system" fn() -> isize,
                            PfnQueryProcessSecurityEnvironmentSupport,
                        >(function))
                    },
                )
            },
            report_policy,
        )
    }
}

fn probe_exports_with(
    mut resolve: impl FnMut(&[&'static core::ffi::CStr]) -> Option<&'static str>,
    query: impl FnOnce() -> Option<(HRESULT, u32)>,
    report_policy: bool,
) -> PolicyResultExportReport {
    let exports = SecurityEnvironmentExportReport {
        create: resolve(CREATE_NAMES),
        query_support: resolve(QUERY_SUPPORT_NAMES),
        close: resolve(CLOSE_NAMES),
    };
    if !report_policy {
        return PolicyResultExportReport {
            exports,
            ..Default::default()
        };
    }
    let create2 = resolve(CREATE2_NAMES);
    let query_result = query();
    PolicyResultExportReport {
        exports,
        create2,
        support_flags: query_result.and_then(|(status, flags)| status.is_ok().then_some(flags)),
        support_query_hresult: query_result.map(|(status, _)| status.0),
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
    use std::sync::atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering};
    use std::sync::Mutex;
    use windows::Win32::Foundation::{E_FAIL, E_NOTIMPL, S_OK};

    static CLOSE_CALLS: AtomicUsize = AtomicUsize::new(0);

    /// Serializes the tests that share the query fakes' global counters.
    static QUERY_LOCK: Mutex<()> = Mutex::new(());
    static QUERY_CALLS: AtomicUsize = AtomicUsize::new(0);
    static QUERY_RESULT: AtomicI32 = AtomicI32::new(S_OK.0);
    static QUERY_FLAGS: AtomicU32 = AtomicU32::new(0);
    static VERSION_RESULT: AtomicI32 = AtomicI32::new(S_OK.0);
    static VERSION_MINOR: AtomicUsize = AtomicUsize::new(1);

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

    unsafe extern "system" fn fake_query(support_flags: *mut u32) -> HRESULT {
        QUERY_CALLS.fetch_add(1, Ordering::SeqCst);
        let result = HRESULT(QUERY_RESULT.load(Ordering::SeqCst));
        if result.is_ok() {
            unsafe { *support_flags = QUERY_FLAGS.load(Ordering::SeqCst) };
        }
        result
    }

    unsafe extern "system" fn fake_version(_: u32, available: *mut u8, minor: *mut u32) -> HRESULT {
        let result = HRESULT(VERSION_RESULT.load(Ordering::SeqCst));
        if result.is_ok() {
            unsafe {
                *available = 1;
                *minor = VERSION_MINOR.load(Ordering::SeqCst) as u32;
            }
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
    fn legacy_api_debug_keeps_its_export_fields() {
        let api = fake_uncached_api();
        let expected = format!(
            "SecurityEnvironmentApi {{ create: {:?}, query_support: {:?}, version_support: None, close: {:?}, cacheable: false }}",
            api.create as *const (),
            api.query_support as *const (),
            api.close as *const (),
        );
        assert_eq!(format!("{api:?}"), expected);
        assert!(!format!("{api:#?}").contains("create2"));
    }

    unsafe extern "system" fn fake_create2(
        _: *const c_void,
        _: u32,
        _: u32,
        _: *mut RawPolicyResult,
        _: *mut HANDLE,
    ) -> HRESULT {
        E_FAIL
    }

    #[test]
    fn policy_enforcement_requires_the_cpse2_export() {
        for reporting_export_present in [false, true] {
            let resolve = |names: &[&'static core::ffi::CStr]| {
                let name = names[0].to_str().unwrap();
                (matches!(
                    name,
                    "CreateProcessSecurityEnvironment"
                        | "QueryProcessSecurityEnvironmentSupport"
                        | "CloseProcessSecurityEnvironment"
                ) || (reporting_export_present && name == "CreateProcessSecurityEnvironment2"))
                    .then_some(name)
            };
            let report = probe_exports_with(resolve, || Some((S_OK, 0x10)), true);
            assert!(report.exports.is_complete());
            assert_eq!(report.policy_results_available(), reporting_export_present);
        }
        let error = fake_uncached_api()
            .create_with_policy_result(&[], 0)
            .unwrap_err();
        assert!(matches!(
            error,
            LearningModeError::HResultCall {
                function: "CreateProcessSecurityEnvironment2",
                code,
            } if code == E_NOTIMPL.0
        ));
    }

    #[test]
    fn policy_enforcement_availability_requires_the_support_bit_and_export() {
        let _guard = QUERY_LOCK.lock().unwrap();
        reset_query_fakes();
        let mut api = fake_uncached_api();
        QUERY_FLAGS.store(0x1f, Ordering::SeqCst);
        assert!(!api.policy_results_available().unwrap());
        assert_eq!(QUERY_CALLS.load(Ordering::SeqCst), 0);

        api.create2 = Some(fake_create2);
        QUERY_FLAGS.store(0x0f, Ordering::SeqCst);
        assert!(!api.policy_results_available().unwrap());
        QUERY_FLAGS.store(0x10, Ordering::SeqCst);
        assert!(api.policy_results_available().unwrap());
        assert_eq!(std::mem::size_of::<SecurityEnvironmentSupport>(), 4);
    }

    #[test]
    fn policy_enforcement_availability_preserves_query_failures() {
        let _guard = QUERY_LOCK.lock().unwrap();
        reset_query_fakes();
        let mut api = fake_uncached_api();
        api.create2 = Some(fake_create2);
        QUERY_RESULT.store(E_FAIL.0, Ordering::SeqCst);
        assert!(matches!(
            api.policy_results_available(),
            Err(LearningModeError::HResultCall {
                function: "QueryProcessSecurityEnvironmentSupport",
                code,
            }) if code == E_FAIL.0
        ));
    }

    #[test]
    fn policy_enforcement_export_report_distinguishes_missing_bits_and_symbols() {
        let supported = PolicyResultExportReport {
            exports: SecurityEnvironmentExportReport {
                create: Some("CreateProcessSecurityEnvironment"),
                query_support: Some("QueryProcessSecurityEnvironmentSupport"),
                close: Some("CloseProcessSecurityEnvironment"),
            },
            create2: Some("CreateProcessSecurityEnvironment2"),
            support_flags: Some(0x10),
            support_query_hresult: Some(S_OK.0),
        };
        assert!(supported.policy_results_available());
        assert!(!PolicyResultExportReport {
            support_flags: Some(0x0f),
            ..supported
        }
        .policy_results_available());
        assert!(!PolicyResultExportReport {
            create2: None,
            ..supported
        }
        .policy_results_available());
        assert!(!PolicyResultExportReport {
            support_flags: None,
            support_query_hresult: Some(E_FAIL.0),
            ..supported
        }
        .policy_results_available());
        assert!(!PolicyResultExportReport {
            exports: SecurityEnvironmentExportReport {
                close: None,
                ..supported.exports
            },
            ..supported
        }
        .policy_results_available());
    }

    #[test]
    fn legacy_export_probe_never_invokes_capability_query() {
        let _guard = QUERY_LOCK.lock().unwrap();
        for create2_present in [false, true] {
            for status in [S_OK, E_FAIL] {
                reset_query_fakes();
                QUERY_RESULT.store(status.0, Ordering::SeqCst);
                QUERY_FLAGS.store(0x10, Ordering::SeqCst);
                let resolve = |names: &[&'static core::ffi::CStr]| {
                    if names == CREATE2_NAMES && !create2_present {
                        None
                    } else {
                        names[0].to_str().ok()
                    }
                };
                let query = || Some(query_support_flags_raw(fake_query));
                let legacy = probe_exports_with(resolve, query, false).exports;
                assert!(legacy.is_complete());
                assert_eq!(QUERY_CALLS.load(Ordering::SeqCst), 0);
                let SecurityEnvironmentExportReport {
                    create,
                    query_support,
                    close,
                } = legacy;
                assert!(create.is_some() && query_support.is_some() && close.is_some());
                let reported = probe_exports_with(resolve, query, true);
                assert_eq!(QUERY_CALLS.load(Ordering::SeqCst), 1);
                assert_eq!(reported.support_query_hresult, Some(status.0));
                assert_eq!(
                    reported.policy_results_available(),
                    create2_present && status.is_ok()
                );
            }
        }
    }

    #[test]
    fn policy_enforcement_create_preserves_failed_hresult_and_output() {
        unsafe extern "system" fn reported(
            _: *const c_void,
            _: u32,
            _: u32,
            output: *mut RawPolicyResult,
            environment: *mut HANDLE,
        ) -> HRESULT {
            // SAFETY: the tested adapter supplies the initialized header,
            // MAX_RESOURCE_CHARS writable code units, and a writable handle.
            unsafe {
                *environment = HANDLE(ptr::null_mut());
                let result = &mut *output;
                assert_eq!(result.version, 1);
                assert_eq!(result.details_capacity as usize, MAX_DETAILS);
                assert_eq!(result.resource_capacity_chars as usize, MAX_RESOURCE_CHARS);
                let text: Vec<_> = "internetclient".encode_utf16().chain(Some(0)).collect();
                ptr::copy_nonoverlapping(text.as_ptr(), result.resource_buffer, text.len());
                result.outcome = 3;
                result.details_count = 1;
                let detail = &mut *result.details;
                detail.failure_class = 1;
                detail.failure_reason = 1;
                detail.required_action = 1;
                detail.resource_kind = 2;
                detail.flags = 3;
                detail.resource_chars_written = text.len() as u32;
                detail.resource_chars_required = text.len() as u32;
                result.resource_chars_written = text.len() as u32;
                result.resource_chars_required = text.len() as u32;
            }
            HRESULT::from_win32(1260)
        }
        let mut api = fake_uncached_api();
        api.create2 = Some(reported);
        let output = api.create_with_policy_result(&[1], 0).unwrap();
        assert_eq!(output.hresult, HRESULT::from_win32(1260));
        assert_eq!(output.policy.outcome.code, 3);
        assert_eq!(output.policy.outcome.name.as_deref(), Some("blocked"));
        assert_eq!(
            output.policy.details[0].resource.as_deref(),
            Some("internetclient")
        );
        assert_eq!(output.invalid_result, None);
        assert!(output.environment.is_none());
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
    fn support_flags_are_reported_independently() {
        let _guard = QUERY_LOCK.lock().unwrap();
        let api = fake_uncached_api();

        reset_query_fakes();
        QUERY_FLAGS.store(
            SecurityEnvironmentSupport::FileSystemDeny as u32,
            Ordering::SeqCst,
        );
        assert!(api
            .query_support(SecurityEnvironmentSupport::FileSystemDeny)
            .unwrap());
        assert!(!api
            .query_support(SecurityEnvironmentSupport::FileSystemEnumerate)
            .unwrap());
        assert!(!api
            .query_support(SecurityEnvironmentSupport::NetworkIngress)
            .unwrap());

        reset_query_fakes();
        QUERY_FLAGS.store(
            SecurityEnvironmentSupport::FileSystemEnumerate as u32,
            Ordering::SeqCst,
        );
        assert!(!api
            .query_support(SecurityEnvironmentSupport::FileSystemDeny)
            .unwrap());
        assert!(api
            .query_support(SecurityEnvironmentSupport::FileSystemEnumerate)
            .unwrap());
        assert!(!api
            .query_support(SecurityEnvironmentSupport::NetworkIngress)
            .unwrap());

        reset_query_fakes();
        QUERY_FLAGS.store(
            SecurityEnvironmentSupport::NetworkIngress as u32,
            Ordering::SeqCst,
        );
        assert!(!api
            .query_support(SecurityEnvironmentSupport::FileSystemDeny)
            .unwrap());
        assert!(!api
            .query_support(SecurityEnvironmentSupport::FileSystemEnumerate)
            .unwrap());
        assert!(api
            .query_support(SecurityEnvironmentSupport::NetworkIngress)
            .unwrap());
    }

    #[test]
    fn supported_minor_version_preserves_api_outcomes() {
        VERSION_RESULT.store(S_OK.0, Ordering::SeqCst);
        VERSION_MINOR.store(3, Ordering::SeqCst);
        assert_eq!(
            query_supported_minor_version_with(1, fake_version).unwrap(),
            Some(3)
        );

        VERSION_RESULT.store(E_FAIL.0, Ordering::SeqCst);
        let error = query_supported_minor_version_with(1, fake_version).unwrap_err();
        assert!(matches!(
            error,
            LearningModeError::HResultCall {
                function: "IsProcessSecurityEnvironmentVersionSupported",
                code
            } if code == E_FAIL.0
        ));
    }

    #[test]
    fn missing_version_export_supports_only_the_baseline_contract() {
        let api = fake_uncached_api();

        assert!(api.supports_version(1, 0).unwrap());
        assert!(!api.supports_version(1, 1).unwrap());
        assert!(!api.supports_version(2, 0).unwrap());
    }

    #[test]
    fn query_support_maps_failing_hresult() {
        let _guard = QUERY_LOCK.lock().unwrap();
        reset_query_fakes();
        QUERY_RESULT.store(E_FAIL.0, Ordering::SeqCst);
        let api = fake_uncached_api();

        let error = api
            .query_support(SecurityEnvironmentSupport::FileSystemDeny)
            .unwrap_err();
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
        QUERY_FLAGS.store(
            SecurityEnvironmentSupport::FileSystemDeny as u32,
            Ordering::SeqCst,
        );
        let api = fake_uncached_api();

        assert!(api
            .query_support(SecurityEnvironmentSupport::FileSystemDeny)
            .unwrap());
        assert!(api
            .query_support(SecurityEnvironmentSupport::FileSystemDeny)
            .unwrap());
        // A test fake must never be memoized: both calls hit the underlying query.
        assert_eq!(QUERY_CALLS.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn cacheable_api_memoizes_support_flags_across_capabilities() {
        let _guard = QUERY_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        reset_query_fakes();
        QUERY_FLAGS.store(
            SecurityEnvironmentSupport::FileSystemDeny as u32,
            Ordering::SeqCst,
        );
        let api =
            SecurityEnvironmentApi::from_raw_parts_cacheable(fake_create, fake_query, fake_close);
        let cache = OnceLock::new();

        assert!(api
            .query_support_cached(SecurityEnvironmentSupport::FileSystemDeny, &cache)
            .unwrap());
        assert!(!api
            .query_support_cached(SecurityEnvironmentSupport::FileSystemEnumerate, &cache)
            .unwrap());
        assert!(!api
            .query_support_cached(SecurityEnvironmentSupport::NetworkIngress, &cache)
            .unwrap());
        assert_eq!(QUERY_CALLS.load(Ordering::SeqCst), 1);
    }
}
