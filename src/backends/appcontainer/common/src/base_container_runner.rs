// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `BaseContainerRunner` — executes scripts through the Windows BaseContainer APIs.
//!
//! The runner prefers the PSEC 1.0 / `CreateProcessSecurityEnvironment`
//! two-phase contract whenever its runtime probe succeeds and attaches the
//! resulting environment to `CreateProcessW`. It temporarily falls back to the
//! legacy `SandboxSpec` / one-shot `Experimental_CreateProcessInSandbox`
//! contract when PSEC is unavailable or cannot represent the requested policy.

use std::ffi::c_void;
use std::fmt::Write;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Arc;

use learning_mode_core::DenialAnalyzer;
use learning_mode_windows::{
    CaptureSession, EtlDenialAnalyzer, LearningModeApi, ProcessSecurityEnvironment,
    SecurityEnvironmentApi, SecurityEnvironmentStartupInfo, PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE,
};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, SetHandleInformation, ERROR_CALL_NOT_IMPLEMENTED,
    ERROR_NOT_SUPPORTED, E_NOTIMPL, HANDLE, HANDLE_FLAG_INHERIT, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows::Win32::System::Threading::{
    CreateProcessW, GetExitCodeProcess, TerminateProcess, WaitForSingleObject,
    EXTENDED_STARTUPINFO_PRESENT, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION,
    STARTF_USESTDHANDLES, STARTUPINFOW,
};
use windows_core::{PCWSTR, PWSTR};

use crate::capture_output::{
    combine_capture_and_cleanup_results, combine_process_and_teardown_results,
    remove_internal_capture_file, unique_denials_output_paths, write_denials_document,
    write_stderr_line_best_effort,
};
use crate::guarded_capture::{
    finalize_guarded_capture, validate_retain_etl_supported, GuardedCaptureFactory,
    GuardedCaptureSession, GuardedStop,
};
use crate::job_object::UiJobObject;
use crate::launch_diagnostics::{
    diagnose_create_process_failure, diagnose_environment_not_supported, diagnose_process_exit,
    is_environment_not_supported,
};
use crate::proxy_coordinator::ProxyCoordinator;
use crate::sandbox_tracking::{self, TrackingEntry};
use process_security_environment_spec::process_security_environment_layout::{
    finish_process_security_environment_buffer, EndpointPolicyT as PsecEndpointPolicy,
    FilterAction as PsecFilterAction, NetworkPolicyT as PsecNetworkPolicy,
    ProcessSecurityEnvironmentT as PsecProcessSecurityEnvironment, ProxyInfoT as PsecProxyInfo,
    SchemaVersionT,
};
use sandbox_spec::base_container_layout::{
    endpoint_policyT, finish_sandbox_spec_buffer, proxy_infoT, FilterAction as SboxFilterAction,
    IntegrityLevel, NetworkPolicyT as SboxNetworkPolicy, SandboxSpecT,
};
use wxc_common::log_symbols::{
    EMOJI_ALLOWED, EMOJI_BLOCKED, EMOJI_NEUTRAL, EMOJI_SECTION, EMOJI_WARNING,
};
use wxc_common::logger::Logger;
use wxc_common::models::{
    CaptureDenialsErrorOutput, CaptureDenialsOutput, ContainerPolicy, ExecutionRequest,
    FailurePhase, NetworkEnforcementMode, NetworkPolicy, ProxyAddress, SandboxOutputMetadata,
    ScriptResponse,
};
use wxc_common::process_util::{
    create_std_pipes, InterruptiblePipeReader, OwnedHandle, PipeReadCanceller, PipeWriter,
    SendOwnedHandle,
};
use wxc_common::sandbox_process::{
    boxed_closer, cancel_and_join_discard, spawn_discard, take_boxed_read, take_boxed_write,
    SandboxBackend, SandboxProcess, StdioMode, StreamCloser,
};
use wxc_common::script_runner::get_timeout_milliseconds;
use wxc_common::string_util;
use wxc_common::validator::validate_network_policy_support;

use windows::Win32::System::Threading::{
    ResumeThread, CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
};

/// Serialize `KEY=VALUE` pairs into a double-null-terminated UTF-16 environment block.
///
/// Entries are sorted case-insensitively by key as required by `CreateProcessW`.
fn encode_env_block(env_vars: &[String]) -> Vec<u16> {
    let mut entries: Vec<(&str, &str)> =
        env_vars.iter().filter_map(|e| e.split_once('=')).collect();

    entries.sort_by(|(a, _), (b, _)| a.to_ascii_uppercase().cmp(&b.to_ascii_uppercase()));

    let mut block = Vec::new();
    for (key, value) in &entries {
        for ch in format!("{}={}", key, value).encode_utf16() {
            block.push(ch);
        }

        block.push(0);
    }
    block.push(0);
    block
}

/// Function pointer type matching `Experimental_CreateProcessInSandbox` from processmodel.dll.
type PfnCreateProcessInSandbox = unsafe extern "system" fn(
    application_name: *const u16,
    command_line: *mut u16,
    process_attributes: *const c_void,
    thread_attributes: *const c_void,
    inherit_handles: i32,
    creation_flags: u32,
    environment: *const c_void,
    current_directory: *const u16,
    startup_info: *const STARTUPINFOW,
    identity: *const u16,
    sandbox_specification: *const u8,
    sandbox_specification_size: u32,
    process_information: *mut PROCESS_INFORMATION,
) -> i32;

/// Function pointer type matching `Experimental_QuerySandboxSupport`. Writes the
/// `SANDBOX_CAP_*` bitmask to `*capabilities` and returns a non-zero BOOL on
/// success. This export is newer than the create API, so its absence is
/// ambiguous and must not be read as "sandbox unsupported".
type PfnQuerySandboxSupport = unsafe extern "system" fn(capabilities: *mut u64) -> i32;

struct SandboxLaunchArgs<'a> {
    api: PfnCreateProcessInSandbox,
    command_line: &'a mut [u16],
    current_directory: *const u16,
    startup_info: &'a STARTUPINFOW,
    identity: &'a [u16],
    sandbox_specification: &'a [u8],
    no_window_flag: u32,
}

impl SandboxLaunchArgs<'_> {
    /// Launches through the one-shot API, retrying once without the
    /// environment block on downlevel systems that reject that parameter.
    fn launch_with_environment_fallback(
        &mut self,
        creation_flags: u32,
        environment: *const c_void,
        process_information: &mut PROCESS_INFORMATION,
        logger: &mut Logger,
    ) -> (i32, Option<windows::Win32::Foundation::WIN32_ERROR>) {
        let mut current_creation_flags = creation_flags;
        let mut current_environment = environment;
        let mut retries_remaining = 1;

        loop {
            *process_information = unsafe { std::mem::zeroed() };
            let result = unsafe {
                (self.api)(
                    ptr::null(),
                    self.command_line.as_mut_ptr(),
                    ptr::null(),
                    ptr::null(),
                    i32::from(false),
                    current_creation_flags,
                    current_environment,
                    self.current_directory,
                    self.startup_info,
                    self.identity.as_ptr(),
                    self.sandbox_specification.as_ptr(),
                    self.sandbox_specification.len() as u32,
                    process_information,
                )
            };
            if result != 0 {
                return (result, None);
            }

            let error = unsafe { GetLastError() };
            if retries_remaining == 0
                || !is_environment_not_supported(error.0, !current_environment.is_null())
            {
                return (result, Some(error));
            }
            retries_remaining -= 1;

            unsafe {
                if !process_information.hProcess.is_invalid() {
                    let _ = CloseHandle(process_information.hProcess);
                }
                if !process_information.hThread.is_invalid() {
                    let _ = CloseHandle(process_information.hThread);
                }
            }

            let diagnostic = diagnose_environment_not_supported();
            let _ = writeln!(
                logger,
                "{EMOJI_WARNING} Launch diagnostic [{}]: {}",
                diagnostic.kind, diagnostic.message
            );

            current_environment = ptr::null();
            current_creation_flags = CREATE_SUSPENDED.0 | self.no_window_flag;
        }
    }
}

/// `SANDBOX_CAP_CREATE_PROCESS_IN_SANDBOX`: when clear, Tier 1 is unusable.
const SANDBOX_CAP_CREATE_PROCESS_IN_SANDBOX: u64 = 0x0000_0000_0000_0001;

/// `SANDBOX_CAP_FS_DENY`: when set, the BaseContainer (Tier 1) backend can
/// enforce `filesystem.deniedPaths`. Bit 0 reports whether the create API is
/// callable; deny support is expected to light up on a separate bit (currently
/// assumed bit 1). When clear, `deniedPaths` is rejected at launch and callers
/// must rely on default-deny plus explicit `readwrite`/`readonly` grants.
const SANDBOX_CAP_FS_DENY: u64 = 0x0000_0000_0000_0002;
/// `SANDBOX_CAP_NETWORK_PROXY`: when set, SBOX uses the model-2 proxy
/// contract, which requires an AppContainer proxy peer identity that MXC does
/// not yet provide.
const SANDBOX_CAP_NETWORK_PROXY: u64 = 0x0000_0000_0000_0004;
const CAPTURE_API_AVAILABLE_LOG: &str =
    "captureDenials: learning-mode trace API available (processmodel.dll)";
const PSEC_DENIED_PATHS_UNSUPPORTED_MSG: &str =
    "filesystem.deniedPaths on the process-security-environment path requires \
     QueryProcessSecurityEnvironmentSupport to advertise PSE_SUPPORT_FS_DENY; this OS \
     build does not support that policy, and the process-security-environment path \
     cannot fall back to AppContainer or host-DACL enforcement";
const CREATE_PROCESS_IN_SANDBOX_API: &str = "Experimental_CreateProcessInSandbox";
const CREATE_PROCESS_IN_SECURITY_ENVIRONMENT_API: &str =
    "CreateProcessW(PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT)";

#[derive(Debug)]
struct CaptureCleanupError {
    output: CaptureDenialsOutput,
    cleanup_message: String,
}

impl std::fmt::Display for CaptureCleanupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.cleanup_message)
    }
}

impl std::error::Error for CaptureCleanupError {}

/// True when a Win32 error code signals the BaseContainer feature is not
/// enabled on this build (symbol present, capability gated off).
fn is_api_not_implemented(err: u32) -> bool {
    err == ERROR_CALL_NOT_IMPLEMENTED.0 || err == E_NOTIMPL.0 as u32
}

/// Proxy compatibility deliberately selects transitional SBOX because PSEC
/// cannot yet supply the proxy peer identity. If that older contract reports
/// `ERROR_NOT_SUPPORTED`, expose it as backend availability without changing
/// error classification for unrelated SBOX policies.
fn is_proxy_fallback_unavailable(
    err: u32,
    request: &ExecutionRequest,
    use_process_security_environment: bool,
) -> bool {
    err == ERROR_NOT_SUPPORTED.0
        && !use_process_security_environment
        && request.policy.network_proxy.is_enabled()
}

fn learning_mode_api_not_implemented(error: &learning_mode_windows::LearningModeError) -> bool {
    match error {
        learning_mode_windows::LearningModeError::ApiSetUnavailable { .. }
        | learning_mode_windows::LearningModeError::DllLoad(_)
        | learning_mode_windows::LearningModeError::ExportMissing { .. } => true,
        learning_mode_windows::LearningModeError::HResultCall { code, .. } => *code == E_NOTIMPL.0,
        learning_mode_windows::LearningModeError::ApiCall { code, .. } => {
            is_api_not_implemented(*code)
        }
        _ => false,
    }
}

trait CaptureSessionOps {
    fn environment(&self) -> HANDLE;
    fn finish(
        self: Box<Self>,
        output_path: Option<&std::path::Path>,
    ) -> Result<(), learning_mode_windows::LearningModeError>;
}

impl CaptureSessionOps for CaptureSession {
    fn environment(&self) -> HANDLE {
        self.environment()
    }

    fn finish(
        self: Box<Self>,
        output_path: Option<&std::path::Path>,
    ) -> Result<(), learning_mode_windows::LearningModeError> {
        (*self).finish(output_path)
    }
}

trait CaptureSessionFactory: Send + Sync {
    fn begin(
        &self,
        sandbox_specification: &[u8],
        flags: u32,
    ) -> Result<Box<dyn CaptureSessionOps>, learning_mode_windows::LearningModeError>;
}

trait CapturePlatformSupport: Send + Sync {
    fn check_apis(&self, require_learning_mode: bool) -> Result<(), String>;
    fn supports_deny_paths(&self) -> Result<bool, String>;
}

struct RealCaptureSessionFactory;

impl CaptureSessionFactory for RealCaptureSessionFactory {
    fn begin(
        &self,
        sandbox_specification: &[u8],
        flags: u32,
    ) -> Result<Box<dyn CaptureSessionOps>, learning_mode_windows::LearningModeError> {
        let security_environment_api = SecurityEnvironmentApi::load()?;
        let learning_mode_api = LearningModeApi::load()?;
        CaptureSession::begin(
            security_environment_api,
            learning_mode_api,
            sandbox_specification,
            flags,
        )
        .map(|session| Box::new(session) as Box<dyn CaptureSessionOps>)
    }
}

struct RealCapturePlatformSupport;

impl CapturePlatformSupport for RealCapturePlatformSupport {
    fn check_apis(&self, require_learning_mode: bool) -> Result<(), String> {
        SecurityEnvironmentApi::load()
            .map_err(|error| format!("security-environment API: {error}"))?;
        if require_learning_mode {
            LearningModeApi::load().map_err(|error| format!("learning-mode trace API: {error}"))?;
        }
        Ok(())
    }

    fn supports_deny_paths(&self) -> Result<bool, String> {
        SecurityEnvironmentApi::load()
            .map_err(|error| format!("process security-environment API unavailable: {error}"))?
            .supports_deny_paths()
            .map_err(|error| {
                format!("could not query process security-environment support: {error}")
            })
    }
}

enum ResolvedNetworkPolicy<'a> {
    Proxy(Option<&'a ProxyAddress>),
    Egress(&'a NetworkPolicy),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SboxProxyContract {
    LegacyOrUnknown,
    Unavailable,
    Model2PeerIdentity,
}

/// Script runner that uses `Experimental_CreateProcessInSandbox` API
/// to launch a sandboxed process.
pub struct BaseContainerRunner {
    proxy_coordinator: ProxyCoordinator,
    capture_factory: Arc<dyn CaptureSessionFactory>,
    capture_support: Arc<dyn CapturePlatformSupport>,
    guarded_capture_factory: Option<Arc<dyn GuardedCaptureFactory>>,
    #[cfg(test)]
    psec_usable_override: Option<bool>,
}

impl Default for BaseContainerRunner {
    fn default() -> Self {
        Self {
            proxy_coordinator: ProxyCoordinator::default(),
            capture_factory: Arc::new(RealCaptureSessionFactory),
            capture_support: Arc::new(RealCapturePlatformSupport),
            guarded_capture_factory: None,
            #[cfg(test)]
            psec_usable_override: None,
        }
    }
}

/// SandboxSpec FlatBuffer schema version embedded in every spec payload.
const SANDBOX_SPEC_VERSION: &str = "0.1.0";

/// Sandbox cleanup stub. The actual cleanup (DeleteAppContainerProfile, BFS
/// policy removal, registry tracking deletion) is currently disabled because
/// wxc-exec only tracks the main AppContainer process handle -- child processes
/// may still be running when we reach this point. The tracking entry and
/// ephemeral identity features remain active for diagnostics and future use.
fn run_sandbox_cleanup(
    _identity: &str,
    _sid_string: &str,
    _proxy_enabled: bool,
    logger: &mut Logger,
) {
    let _ = writeln!(
        logger,
        "{EMOJI_SECTION} SECTION: Lifecycle cleanup (skipping -- child process tracking not yet implemented)"
    );
}

fn guarded_capture_started_too_late(
    previous_suspend_count: u32,
    guarded_capture_active: bool,
) -> bool {
    guarded_capture_active && previous_suspend_count == 0
}

impl BaseContainerRunner {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    fn with_capture_factory(capture_factory: Arc<dyn CaptureSessionFactory>) -> Self {
        Self {
            proxy_coordinator: ProxyCoordinator::default(),
            capture_factory,
            capture_support: Arc::new(RealCapturePlatformSupport),
            guarded_capture_factory: None,
            psec_usable_override: Some(true),
        }
    }

    #[cfg(test)]
    fn with_capture_components(
        capture_factory: Arc<dyn CaptureSessionFactory>,
        capture_support: Arc<dyn CapturePlatformSupport>,
    ) -> Self {
        Self {
            proxy_coordinator: ProxyCoordinator::default(),
            capture_factory,
            capture_support,
            guarded_capture_factory: None,
            psec_usable_override: Some(true),
        }
    }

    pub fn with_guarded_capture_factory(mut self, factory: Arc<dyn GuardedCaptureFactory>) -> Self {
        self.guarded_capture_factory = Some(factory);
        self
    }

    fn cleanup_capture_begin_failure(&mut self, logger: &mut Logger) {
        // CaptureSession owns and closes the PSEC environment. No legacy
        // identity/tracking state is created for this path.
        self.proxy_coordinator.stop(logger);
    }

    /// Security-sensitive teardown shared by every guarded-capture failure path
    /// that must abandon a sandbox before it is handed to the caller (attach
    /// failure, guardian-start failure, and post-resume failure).
    ///
    /// Ordering is load-bearing: the job is terminated **first** (killing the
    /// child and every descendant), and per-run sandbox enforcement plus the
    /// proxy are torn down **only** once termination succeeded — never while a
    /// process could still be running unobserved. A guarded WPR `session`, if
    /// one was already started, is discarded through the authenticated
    /// protocol. Returns `base_message` with any termination/discard failures
    /// appended; `terminate_context` names what was being terminated (e.g. "the
    /// suspended sandbox" vs "the sandbox process tree").
    #[allow(clippy::too_many_arguments)]
    fn abandon_capture_launch(
        &mut self,
        job: &UiJobObject,
        process: HANDLE,
        thread: HANDLE,
        session: Option<Box<dyn GuardedCaptureSession>>,
        identity: &str,
        sid_string: &str,
        legacy_destroy_on_exit: bool,
        proxy_enabled: bool,
        terminate_context: &str,
        mut base_message: String,
        logger: &mut Logger,
    ) -> String {
        // Guarded capture needs strict drain certainty here: nothing may be
        // left running before the trace is stopped/discarded.
        let termination_error = job.terminate_and_wait(u32::MAX).err();
        let discard_error = session.and_then(|mut session| session.discard().err());
        // SAFETY: `process`/`thread` are the just-created, still-owned child
        // handles; nothing else references them on this failure path.
        unsafe {
            let _ = CloseHandle(process);
            let _ = CloseHandle(thread);
        }
        if termination_error.is_none() {
            if legacy_destroy_on_exit {
                run_sandbox_cleanup(identity, sid_string, proxy_enabled, logger);
                sandbox_tracking::unregister_ctrl_c_cleanup();
            }
            self.proxy_coordinator.stop(logger);
        }
        if let Some(terminate_error) = termination_error {
            let _ = write!(
                base_message,
                "; additionally failed to terminate {terminate_context}: {terminate_error}"
            );
        }
        if let Some(discard_error) = discard_error {
            let _ = write!(
                base_message,
                "; additionally failed to stop and discard guarded WPR: {discard_error}"
            );
        }
        base_message
    }

    /// Pre-flight probe: check whether the current OS build exports the
    /// `Experimental_CreateProcessInSandbox` symbol from `processmodel.dll`.
    ///
    /// Returns `Ok(())` if the export is resolvable, or `Err` with a
    /// human-readable description when the DLL or export is missing.
    ///
    /// Note: a successful probe only means the symbol exists. The OS may
    /// still reject calls at runtime with `ERROR_CALL_NOT_IMPLEMENTED` if
    /// the feature is disabled (e.g., via internal feature-enablement mechanisms).
    pub fn is_base_container_api_present() -> Result<(), String> {
        Self::load_api().map(|_| ())
    }

    /// Is the BaseContainer (Tier 1) backend actually **usable** here, not just
    /// symbol-present? Resolves enablement up front so tier selection
    /// never picks a Tier 1 that cannot launch:
    ///
    /// 1. Probe the PSEC create/close contract.
    /// 2. Otherwise query transitional SBOX support when available.
    /// 3. Otherwise probe the SBOX create API itself.
    pub fn is_base_container_usable() -> bool {
        #[cfg(test)]
        if let Ok(forced) = std::env::var("MXC_FORCE_BC_USABLE") {
            return forced == "1";
        }
        if Self::is_process_security_environment_usable() {
            return true;
        }
        Self::is_legacy_base_container_usable()
    }

    /// Whether PSEC can create and close a minimal security environment on
    /// this host. Export presence and the support query alone are insufficient
    /// on transitional builds where the API surface exists before the feature
    /// is enabled.
    pub fn is_process_security_environment_usable() -> bool {
        static USABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *USABLE.get_or_init(|| {
            let request = ExecutionRequest {
                schema_version: "0.8.0-alpha".to_string(),
                ..Default::default()
            };
            let specification = Self::build_process_security_environment_spec(&request);
            SecurityEnvironmentApi::load()
                .and_then(|api| api.create(&specification, PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE))
                .and_then(|environment| {
                    let startup_info = SecurityEnvironmentStartupInfo::new(
                        STARTUPINFOW::default(),
                        environment.raw(),
                        &[],
                    );
                    environment.close();
                    startup_info.map(drop)
                })
                .is_ok()
        })
    }

    /// Whether this host can create a PSEC environment and start a Learning Mode trace.
    ///
    /// The successful probe session is dropped immediately, which closes and discards the trace.
    pub fn is_capture_denials_usable() -> bool {
        // Do not cache: StartLearningModeTrace can fail transiently, so later probes must retry.
        if !Self::is_process_security_environment_usable() {
            return false;
        }

        let request = ExecutionRequest {
            schema_version: "0.8.0-alpha".to_string(),
            ..Default::default()
        };
        let specification = Self::build_process_security_environment_spec(&request);
        SecurityEnvironmentApi::load()
            .and_then(|security_environment_api| {
                CaptureSession::begin(
                    security_environment_api,
                    LearningModeApi::load()?,
                    &specification,
                    PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE,
                )
            })
            .is_ok()
    }

    /// Whether the transitional SBOX BaseContainer contract is usable.
    fn is_legacy_base_container_usable() -> bool {
        #[cfg(test)]
        if let Ok(forced) = std::env::var("MXC_FORCE_BC_USABLE") {
            return forced == "1";
        }
        match Self::query_sandbox_create_capability() {
            Some(enabled) => enabled,
            None => Self::probe_create_process_feature_enabled(),
        }
    }

    /// Whether the BaseContainer (Tier 1) backend can enforce
    /// `filesystem.deniedPaths` on this host.
    ///
    /// Reads the `SANDBOX_CAP_FS_DENY` bit from
    /// `Experimental_QuerySandboxSupport`. Returns `false` when the query
    /// export is absent or the bit is clear — the behavior on builds where
    /// BaseContainer deny support has not yet shipped, where `deniedPaths` is
    /// rejected at launch. Tier 3 (AppContainer + DACL) enforces `deniedPaths`
    /// via DENY ACEs independently of this bit.
    pub fn base_container_supports_deny_paths() -> bool {
        Self::query_sandbox_capabilities()
            .is_some_and(|capabilities| Self::decode_deny_capability(1, capabilities))
    }

    /// Decode a `QuerySandboxSupport` result for the deny-paths capability.
    /// `succeeded` is the export's Win32 `BOOL` return (TRUE = nonzero = the
    /// query call succeeded), NOT an HRESULT. The capability is present only
    /// when the call succeeded and the bit is set.
    fn decode_deny_capability(succeeded: i32, capabilities: u64) -> bool {
        succeeded != 0 && (capabilities & SANDBOX_CAP_FS_DENY) != 0
    }

    /// Query `Experimental_QuerySandboxSupport` for the create-process bit.
    /// `None` means the answer is unknown (export absent, or the query call
    /// itself failed), so the caller must probe another way rather than assume
    /// "unusable".
    fn query_sandbox_create_capability() -> Option<bool> {
        Self::query_sandbox_capabilities()
            .map(|capabilities| Self::decode_create_capability(1, capabilities))
    }

    /// Query the capability-aware SBOX contract. `None` means the export is
    /// absent or the query failed, so callers must use the legacy probe path.
    fn query_sandbox_capabilities() -> Option<u64> {
        let query = Self::load_query_sandbox_support()?;
        let mut capabilities: u64 = 0;
        // SAFETY: `query` is the resolved export; `capabilities` is a valid
        // out-param.
        let ok = unsafe { query(&mut capabilities) };
        // A FALSE return means the query call failed, so the capability is
        // unknown; return None to fall through to the create-API probe rather
        // than treating it as "disabled".
        if ok == 0 {
            return None;
        }
        Some(capabilities)
    }

    /// Decode a `QuerySandboxSupport` result: the create-process capability is
    /// present only when the call succeeded (`ok != 0`) and the bit is set.
    fn decode_create_capability(ok: i32, capabilities: u64) -> bool {
        ok != 0 && (capabilities & SANDBOX_CAP_CREATE_PROCESS_IN_SANDBOX) != 0
    }

    /// Whether the request can use the legacy SBOX contract selected by MXC.
    ///
    /// A successful support query identifies the capability-aware OS contract:
    /// with `SANDBOX_CAP_NETWORK_PROXY` clear, proxy is unavailable; with it
    /// set, proxy requires `allowed_appcontainer_peer` and an AppContainer-hosted
    /// proxy. MXC supports neither shape yet, so proxy requests use the
    /// AppContainer fallback. Query-less builds retain the older SBOX proxy
    /// behavior.
    fn legacy_sbox_compatible_with_request(
        request: &ExecutionRequest,
        queried_capabilities: Option<u64>,
    ) -> bool {
        if !request.policy.network_proxy.is_enabled() {
            return true;
        }

        matches!(
            Self::decode_sbox_proxy_contract(queried_capabilities),
            SboxProxyContract::LegacyOrUnknown
        )
    }

    fn decode_sbox_proxy_contract(queried_capabilities: Option<u64>) -> SboxProxyContract {
        match queried_capabilities {
            None => SboxProxyContract::LegacyOrUnknown,
            Some(capabilities) if (capabilities & SANDBOX_CAP_NETWORK_PROXY) != 0 => {
                SboxProxyContract::Model2PeerIdentity
            }
            Some(_) => SboxProxyContract::Unavailable,
        }
    }

    /// Resolve `Experimental_QuerySandboxSupport`; `None` if not present.
    fn load_query_sandbox_support() -> Option<PfnQuerySandboxSupport> {
        let dll_name = string_util::to_wide("processmodel.dll");
        // SAFETY: same rationale as `load_api`.
        unsafe {
            let hmodule = LoadLibraryExW(
                PCWSTR(dll_name.as_ptr()),
                None,
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
            .ok()?;
            let proc = GetProcAddress(
                hmodule,
                windows::core::PCSTR(c"Experimental_QuerySandboxSupport".as_ptr().cast()),
            )?;
            #[allow(clippy::missing_transmute_annotations)]
            Some(std::mem::transmute(proc))
        }
    }

    /// Fallback enablement probe for builds without
    /// `Experimental_QuerySandboxSupport`: call the create API with invalid
    /// arguments so nothing launches. `ERROR_CALL_NOT_IMPLEMENTED` means
    /// disabled; any other result means enabled.
    fn probe_create_process_feature_enabled() -> bool {
        let api = match Self::load_api() {
            Ok(f) => f,
            Err(_) => return false,
        };

        let mut pi = PROCESS_INFORMATION::default();
        // SAFETY: `api` is the resolved export; all inputs are null and `pi` is
        // a valid out-param. The call returns an error without launching.
        let result = unsafe {
            api(
                ptr::null(),     // application_name
                ptr::null_mut(), // command_line
                ptr::null(),     // process_attributes
                ptr::null(),     // thread_attributes
                0,               // inherit_handles
                0,               // creation_flags
                ptr::null(),     // environment
                ptr::null(),     // current_directory
                ptr::null(),     // startup_info
                ptr::null(),     // identity
                ptr::null(),     // sandbox_specification
                0,               // sandbox_specification_size
                &mut pi,         // process_information
            )
        };
        // Capture the error immediately, before any branching can clobber it.
        let err = unsafe { GetLastError() };

        if result != 0 {
            // Unexpected success; close any handles and treat as enabled.
            // SAFETY: handles are validated before being closed.
            unsafe {
                if !pi.hProcess.is_invalid() {
                    let _ = CloseHandle(pi.hProcess);
                }
                if !pi.hThread.is_invalid() {
                    let _ = CloseHandle(pi.hThread);
                }
            }
            return true;
        }

        !is_api_not_implemented(err.0)
    }

    fn resolved_network_policy(policy: &ContainerPolicy) -> ResolvedNetworkPolicy<'_> {
        if policy.network_proxy.is_enabled() {
            ResolvedNetworkPolicy::Proxy(policy.network_proxy.address.as_ref())
        } else {
            ResolvedNetworkPolicy::Egress(&policy.default_network_policy)
        }
    }

    // A BaseContainer network policy contains either proxy settings or an egress policy.
    fn build_network_policy(policy: &ContainerPolicy) -> SboxNetworkPolicy {
        let mut network = SboxNetworkPolicy::default();
        match Self::resolved_network_policy(policy) {
            ResolvedNetworkPolicy::Proxy(address) => {
                network.proxy = address.map(|address| {
                    let mut proxy = proxy_infoT::default();
                    proxy.url = Some(address.to_url());
                    Box::new(proxy)
                });
            }
            ResolvedNetworkPolicy::Egress(default_policy) => {
                let mut egress = endpoint_policyT::default();
                egress.default_action = match default_policy {
                    NetworkPolicy::Allow => SboxFilterAction::allow,
                    NetworkPolicy::Block => SboxFilterAction::deny,
                };
                network.egress = Some(Box::new(egress));
            }
        }
        network
    }

    fn build_process_security_environment_network_policy(
        policy: &ContainerPolicy,
    ) -> PsecNetworkPolicy {
        let mut network = PsecNetworkPolicy::default();
        match Self::resolved_network_policy(policy) {
            ResolvedNetworkPolicy::Proxy(address) => {
                network.proxy = address.map(|address| {
                    let mut proxy = PsecProxyInfo::default();
                    proxy.url = Some(address.to_url());
                    Box::new(proxy)
                });
            }
            ResolvedNetworkPolicy::Egress(default_policy) => {
                let mut egress = PsecEndpointPolicy::default();
                egress.default_action = match default_policy {
                    NetworkPolicy::Allow => PsecFilterAction::allow,
                    NetworkPolicy::Block => PsecFilterAction::deny,
                };
                network.egress = Some(Box::new(egress));
            }
        }
        network
    }

    fn should_use_process_security_environment(
        request: &ExecutionRequest,
        psec_usable: bool,
        psec_supports_deny_paths: bool,
    ) -> bool {
        if !psec_usable {
            return false;
        }
        Self::psec_policy_compatible(request, psec_supports_deny_paths)
    }

    fn psec_policy_compatible(request: &ExecutionRequest, psec_supports_deny_paths: bool) -> bool {
        !request.policy.least_privilege_mode
            && !request.policy.network_proxy.is_enabled()
            && (request.policy.denied_paths.is_empty() || psec_supports_deny_paths)
    }

    fn process_security_environment_usable(&self) -> bool {
        #[cfg(test)]
        if let Some(usable) = self.psec_usable_override {
            return usable;
        }
        Self::is_process_security_environment_usable()
    }

    /// Whether a `captureDenials` request is eligible for the native
    /// (PSEC + Learning Mode) capture path, given the effective PSEC usability
    /// and a [`CapturePlatformSupport`] probe. Shared by the instance
    /// ([`Self::uses_process_security_environment`], probing `self.capture_support`)
    /// and static ([`Self::uses_native_capture_for_request`], probing
    /// [`RealCapturePlatformSupport`]) eligibility checks so the two cannot drift.
    fn native_capture_eligible(
        request: &ExecutionRequest,
        psec_usable: bool,
        support: &dyn CapturePlatformSupport,
    ) -> bool {
        #[cfg(test)]
        let native_capture_usable = std::env::var("MXC_FORCE_NATIVE_CAPTURE_USABLE").map_or_else(
            |_| psec_usable && support.check_apis(true).is_ok(),
            |forced| forced == "1",
        );
        #[cfg(not(test))]
        let native_capture_usable = psec_usable && support.check_apis(true).is_ok();

        request.policy.capture_denials.is_some()
            && native_capture_usable
            && Self::psec_policy_compatible(
                request,
                request.policy.denied_paths.is_empty()
                    || support.supports_deny_paths().unwrap_or(false),
            )
    }

    fn uses_process_security_environment(&self, request: &ExecutionRequest) -> bool {
        if request.policy.capture_denials.is_some() {
            return Self::native_capture_eligible(
                request,
                self.process_security_environment_usable(),
                self.capture_support.as_ref(),
            );
        }
        let supports_deny_paths = request.policy.denied_paths.is_empty()
            || self.capture_support.supports_deny_paths().unwrap_or(false);
        Self::should_use_process_security_environment(
            request,
            self.process_security_environment_usable(),
            supports_deny_paths,
        )
    }

    pub(crate) fn is_usable_for_request(request: &ExecutionRequest) -> bool {
        #[cfg(test)]
        if let Ok(forced) = std::env::var("MXC_FORCE_BC_USABLE") {
            return forced == "1";
        }
        let psec_usable = Self::is_process_security_environment_usable();
        if request.policy.capture_denials.is_some() {
            if Self::uses_native_capture_for_request(request) {
                return true;
            }
            if !Self::legacy_sbox_compatible_with_request(
                request,
                Self::query_sandbox_capabilities(),
            ) {
                return false;
            }
            return Self::is_legacy_base_container_usable();
        }
        let psec_supports_deny_paths = request.policy.denied_paths.is_empty()
            || SecurityEnvironmentApi::load()
                .and_then(|api| api.supports_deny_paths())
                .unwrap_or(false);
        if Self::should_use_process_security_environment(
            request,
            psec_usable,
            psec_supports_deny_paths,
        ) {
            return true;
        }
        if !Self::legacy_sbox_compatible_with_request(request, Self::query_sandbox_capabilities()) {
            return false;
        }
        Self::is_legacy_base_container_usable()
    }

    pub(crate) fn supports_deny_paths_for_request(request: &ExecutionRequest) -> bool {
        let psec_supports_deny_paths = SecurityEnvironmentApi::load()
            .and_then(|api| api.supports_deny_paths())
            .unwrap_or(false);
        let uses_native_capture = Self::uses_native_capture_for_request(request);
        if uses_native_capture {
            return true;
        }
        if request.policy.capture_denials.is_none()
            && Self::should_use_process_security_environment(
                request,
                Self::is_process_security_environment_usable(),
                psec_supports_deny_paths,
            )
        {
            return true;
        }
        crate::fallback_detector::base_container_supports_deny_paths()
    }

    pub(crate) fn uses_native_capture_for_request(request: &ExecutionRequest) -> bool {
        Self::native_capture_eligible(
            request,
            Self::is_process_security_environment_usable(),
            &RealCapturePlatformSupport,
        )
    }

    fn build_process_security_environment_spec(request: &ExecutionRequest) -> Vec<u8> {
        let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);

        let capabilities = Self::effective_capabilities(request);
        let ui_restrictions = crate::job_object::to_job_object_uilimit_mask(
            &wxc_common::ui_policy::resolve_ui_restrictions(
                &request.policy.ui,
                &request.policy.base_process_ui,
            ),
        ) as u64;

        let mut spec = PsecProcessSecurityEnvironment::default();
        spec.version = SchemaVersionT { major: 1, minor: 0 };
        spec.capabilities = (!capabilities.is_empty()).then(|| capabilities.join(","));
        spec.disallow_win32k_system_calls = request.policy.ui.disable;
        spec.ui_restrictions = ui_restrictions;
        spec.fs_read_write = Self::non_empty_paths(&request.policy.readwrite_paths);
        spec.fs_read_only = Self::non_empty_paths(&request.policy.readonly_paths);
        spec.fs_deny = Self::non_empty_paths(&request.policy.denied_paths);
        spec.network_policy = Some(Box::new(
            Self::build_process_security_environment_network_policy(&request.policy),
        ));
        let spec = spec.pack(&mut builder);
        finish_process_security_environment_buffer(&mut builder, spec);
        builder.finished_data().to_vec()
    }

    /// Build a FlatBuffer `SandboxSpec` from the container policy in the request.
    ///
    /// Maps `ContainerPolicy` and `UiPolicy` fields to the BaseContainer schema:
    /// - `app_container` is always `true` (AppContainer is the base sandbox primitive)
    /// - `least_privilege` from `policy.least_privilege_mode`
    /// - `capabilities` from `policy.capabilities` (comma-joined)
    /// - `fs_read_write` from `policy.readwrite_paths`
    /// - `fs_read_only` from `policy.readonly_paths`
    /// - `fs_deny` from `policy.denied_paths`
    /// - `disallow_win32k_system_calls` from `ui.disable`
    /// - `ui_restrictions` bitmask from `ui.to_ui_restrictions_bitmask()`
    /// - `network_policy.egress.default_action` from `policy.default_network_policy` without proxy
    /// - `network_policy.proxy.url` instead of `egress` when proxy config is enabled
    fn build_sandbox_spec(request: &ExecutionRequest) -> Vec<u8> {
        let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);

        let caps = Self::effective_capabilities(request);
        let ui_restrictions = crate::job_object::to_job_object_uilimit_mask(
            &wxc_common::ui_policy::resolve_ui_restrictions(
                &request.policy.ui,
                &request.policy.base_process_ui,
            ),
        ) as u64;

        let mut spec = SandboxSpecT::default();
        spec.version = SANDBOX_SPEC_VERSION.to_string();
        spec.app_container = true;
        spec.disallow_win32k_system_calls = request.policy.ui.disable;
        spec.ui_restrictions = ui_restrictions;
        spec.least_privilege = request.policy.least_privilege_mode;
        spec.capabilities = (!caps.is_empty()).then(|| caps.join(","));
        spec.fs_read_write = Self::non_empty_paths(&request.policy.readwrite_paths);
        spec.fs_read_only = Self::non_empty_paths(&request.policy.readonly_paths);
        spec.network_policy = Some(Box::new(Self::build_network_policy(&request.policy)));
        spec.integrity = IntegrityLevel::system_default;
        spec.fs_deny = Self::non_empty_paths(&request.policy.denied_paths);
        let spec = spec.pack(&mut builder);
        finish_sandbox_spec_buffer(&mut builder, spec);
        builder.finished_data().to_vec()
    }

    fn non_empty_paths(paths: &[String]) -> Option<Vec<String>> {
        (!paths.is_empty()).then(|| paths.to_vec())
    }

    fn needs_internet_client(request: &ExecutionRequest) -> bool {
        let use_caps_for_network = matches!(
            request.policy.network_enforcement_mode,
            NetworkEnforcementMode::Capabilities | NetworkEnforcementMode::Both
        );
        use_caps_for_network
            && request.policy.default_network_policy == NetworkPolicy::Allow
            && !request
                .policy
                .capabilities
                .iter()
                .any(|capability| capability == "internetClient")
    }

    fn effective_capabilities(request: &ExecutionRequest) -> Vec<String> {
        // Match legacy AppContainer behaviour: when network enforcement uses
        // capabilities and the default policy is Allow, ensure internetClient
        // is present so the sandboxed process has network access.
        let mut caps: Vec<_> = request
            .policy
            .capabilities
            .iter()
            .filter(|capability| !capability.is_empty())
            .cloned()
            .collect();
        if Self::needs_internet_client(request) {
            caps.push("internetClient".to_string());
        }
        caps
    }

    /// Log the contents of a built sandbox spec FlatBuffer for debug verification.
    ///
    /// Reads back token, network, and UI restriction fields from the serialised
    /// spec and writes a structured summary to the logger.
    fn log_sandbox_spec(spec_bytes: &[u8], logger: &mut Logger) {
        let spec = match sandbox_spec::base_container_layout::root_as_sandbox_spec(spec_bytes) {
            Ok(s) => s,
            Err(_) => return,
        };

        let _ = writeln!(
            logger,
            "sandbox spec built (version={}, {} bytes)",
            spec.version(),
            spec_bytes.len()
        );

        // Token
        let _ = writeln!(logger, "[token]");
        let integrity_emoji = if spec.integrity() == IntegrityLevel::system_default {
            EMOJI_NEUTRAL
        } else {
            EMOJI_WARNING
        };
        let _ = writeln!(
            logger,
            "  integrity:       {} {:?}",
            integrity_emoji,
            spec.integrity()
        );
        let app_container_emoji = if spec.app_container() {
            EMOJI_NEUTRAL
        } else {
            EMOJI_WARNING
        };
        let _ = writeln!(
            logger,
            "  app_container:   {} {} (least_privilege: {})",
            app_container_emoji,
            if spec.app_container() { "on" } else { "off" },
            if spec.least_privilege() { "on" } else { "off" }
        );
        if let Some(caps) = spec.capabilities() {
            let _ = writeln!(logger, "  capabilities:    {}", caps);
        }

        // Network
        let _ = writeln!(logger, "[network]");
        if let Some(default_action) = spec
            .network_policy()
            .and_then(|np| np.egress())
            .map(|egress| egress.default_action())
        {
            let _ = writeln!(
                logger,
                "  network_policy.egress.default_action: {:?}",
                default_action
            );
        }
        let proxy_url = spec
            .network_policy()
            .and_then(|np| np.proxy())
            .and_then(|proxy| proxy.url());
        if let Some(url) = proxy_url {
            let _ = writeln!(logger, "  network_policy.proxy.url: {}", url);
        } else {
            let _ = writeln!(logger, "  <unspecified>");
        }

        // UI restrictions
        let _ = writeln!(logger, "[ui subsystem]");
        let _ = writeln!(
            logger,
            "  win32k_system_calls: {} {}",
            if spec.disallow_win32k_system_calls() {
                EMOJI_BLOCKED
            } else {
                EMOJI_ALLOWED
            },
            if spec.disallow_win32k_system_calls() {
                "blocked"
            } else {
                "allowed"
            }
        );
        let r = spec.ui_restrictions();
        let flags: &[(&str, u64)] = &[
            ("handles", 0x0001),
            ("read_clip", 0x0002),
            ("write_clip", 0x0004),
            ("sys_params", 0x0008),
            ("display", 0x0010),
            ("atoms", 0x0020),
            ("desktop", 0x0040),
            ("exit_windows", 0x0080),
            ("ime", 0x0100),
            ("injection", 0x0200),
        ];
        let allowed: Vec<&str> = flags
            .iter()
            .filter(|(_, bit)| r & bit == 0)
            .map(|(name, _)| *name)
            .collect();
        let blocked: Vec<&str> = flags
            .iter()
            .filter(|(_, bit)| r & bit != 0)
            .map(|(name, _)| *name)
            .collect();
        let allowed_str = if allowed.is_empty() {
            "<none>".to_string()
        } else {
            allowed.join(", ")
        };
        let blocked_str = if blocked.is_empty() {
            "<none>".to_string()
        } else {
            blocked.join(", ")
        };
        let _ = writeln!(
            logger,
            "  uilimits allowed {EMOJI_ALLOWED}: {}",
            allowed_str
        );
        let _ = writeln!(
            logger,
            "  uilimits blocked {EMOJI_BLOCKED}: {} (0x{:04X})",
            blocked_str,
            spec.ui_restrictions()
        );
    }

    /// Load `processmodel.dll` and resolve the `Experimental_CreateProcessInSandbox` export.
    fn load_api() -> Result<PfnCreateProcessInSandbox, String> {
        let dll_name = string_util::to_wide("processmodel.dll");

        // SAFETY: `dll_name` is a valid null-terminated wide string that outlives the
        // call. `LOAD_LIBRARY_SEARCH_SYSTEM32` restricts the search to System32, avoiding
        // DLL-planting attacks. The returned `hmodule` is used only with `GetProcAddress`
        // below and is never freed (the DLL stays loaded for the process lifetime).
        // `GetProcAddress` returns a valid function pointer for a known export; we
        // transmute it to `PfnCreateProcessInSandbox` whose signature matches the
        // C declaration of `Experimental_CreateProcessInSandbox` in processmodel.dll.
        unsafe {
            let hmodule = LoadLibraryExW(
                PCWSTR(dll_name.as_ptr()),
                None,
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
            .map_err(|e| format!("LoadLibraryExW(processmodel.dll) failed: {e}"))?;

            let proc = GetProcAddress(
                hmodule,
                windows::core::PCSTR(c"Experimental_CreateProcessInSandbox".as_ptr().cast()),
            )
            .ok_or_else(|| {
                "GetProcAddress(Experimental_CreateProcessInSandbox) failed — \
                 API not present on this OS build"
                    .to_string()
            })?;

            #[allow(clippy::missing_transmute_annotations)]
            Ok(std::mem::transmute(proc))
        }
    }
}

impl BaseContainerRunner {
    /// Set up and launch the BaseContainer child, returning a [`BaseChild`] the
    /// caller runs to completion (blocking) or wraps in a streaming handle. When
    /// `capture` is set the child's stdio is wired to pipes the caller drives
    /// (the streaming path); otherwise the child inherits the parent's std
    /// handles / console (the run-to-completion path).
    fn spawn_base(
        &mut self,
        request: &ExecutionRequest,
        logger: &mut Logger,
        capture: bool,
    ) -> Result<BaseChild, ScriptResponse> {
        let _ = writeln!(
            logger,
            "{EMOJI_SECTION} SECTION: Backend runner 'BaseContainer'"
        );

        // --- Learning-mode capabilities (parity with AppContainerScriptRunner) ---
        // Emit per-capability diagnostics (informational for `learningModeLogging`,
        // a security warning for `permissiveLearningMode`).
        crate::appcontainer_runner::log_learning_mode_capability_diagnostics(
            &request.policy.capabilities,
            logger,
        );

        // Launch builtin test proxy if requested (before building spec so we have the port).
        let mut request = request.clone();
        if request.policy.network_proxy.builtin_test_server {
            match self.proxy_coordinator.launch_test_proxy(logger) {
                Ok(port) => {
                    let addr = ProxyAddress::new("127.0.0.1".to_string(), port);
                    request.policy.network_proxy.address = Some(addr);
                }
                Err(e) => {
                    return Err(ScriptResponse::error(&format!(
                        "Failed to start builtin test proxy: {e}"
                    )));
                }
            }
        }

        // Log the effective proxy config after resolution.
        if request.policy.network_proxy.is_enabled() {
            let addr = request
                .policy
                .network_proxy
                .address
                .as_ref()
                .map(|a| a.to_url())
                .unwrap_or_else(|| "<pending>".to_string());
            let _ = writeln!(
                logger,
                "effective proxy: {} (builtin_test_server={})",
                addr, request.policy.network_proxy.builtin_test_server
            );
            let _ = writeln!(
                logger,
                "warning: proxy support on Windows is best-effort -- only scripts that use \
                 the WinHTTP stack will be proxied; other HTTP stacks may bypass it.",
            );
        }

        let _ = writeln!(logger, "{EMOJI_SECTION} SECTION: Build sandbox spec");

        let capture_denials = request.policy.capture_denials.clone();
        let use_process_security_environment = self.uses_process_security_environment(&request);
        let use_guarded_capture = capture_denials.is_some() && !use_process_security_environment;
        let spec_bytes = if !use_process_security_environment {
            let bytes = Self::build_sandbox_spec(&request);
            Self::log_sandbox_spec(&bytes, logger);
            Some(bytes)
        } else {
            None
        };
        if capture_denials.is_some() {
            let _ = writeln!(logger, "{EMOJI_SECTION} SECTION: captureDenials");
        }

        let process_security_environment_spec = use_process_security_environment
            .then(|| Self::build_process_security_environment_spec(&request));
        if let Some(psec_spec) = process_security_environment_spec.as_ref() {
            let _ = writeln!(
                logger,
                "process security environment spec built (PSEC 1.0, {} bytes)",
                psec_spec.len()
            );
        }

        // Resolve two paths for the capture:
        //   * `capture_etl_path` — a runner-managed `.etl` in a protected
        //     per-run directory for native V2 capture. Guarded WPR analyzes
        //     its ETL while elevated and returns only a bounded process-scoped
        //     result.
        //   * `capture_output_path` — the JSON denials deliverable that consuming
        //     apps read: caller-specified via `captureDenials.outputPath` when
        //     provided, else a managed per-run temp `.json` file.
        let mut managed_capture = if use_process_security_environment {
            capture_denials
                .as_ref()
                .map(|config| managed_capture_output_path(config.retain_etl))
                .transpose()?
        } else {
            None
        };
        let capture_output_paths = capture_denials
            .as_ref()
            .map(|config| {
                let retain_guarded_etl = use_guarded_capture
                    && config.retain_etl
                    && self
                        .guarded_capture_factory
                        .as_ref()
                        .is_some_and(|factory| factory.allows_trace_transfer());
                unique_denials_output_paths(config.output_path.as_deref(), retain_guarded_etl)
            })
            .transpose()
            .map_err(|error| ScriptResponse::error(&error))?;
        let (capture_output_path, guarded_capture_etl_path) = match capture_output_paths {
            Some(paths) => (Some(paths.denials), paths.etl),
            None => (None, None),
        };

        let _ = writeln!(logger, "{EMOJI_SECTION} SECTION: Load API");

        // Prefer the process-security-environment APIs whenever they are usable
        // and compatible with the requested policy. Guarded capture deliberately
        // retains SBOX when the complete native PSEC/V2 capture capability set
        // is unavailable or policy-incompatible.
        let create_process_in_sandbox = if !use_process_security_environment {
            let api = match Self::load_api() {
                Ok(f) => f,
                Err(e) => return Err(ScriptResponse::error(&e)),
            };
            let _ = writeln!(
                logger,
                "loaded Experimental_CreateProcessInSandbox from processmodel.dll"
            );
            Some(api)
        } else {
            None
        };

        let _ = writeln!(logger, "{EMOJI_SECTION} SECTION: Launch process");

        // 3. Build the command line (passed directly, same as AppContainerScriptRunner).
        let mut cmd_wide = string_util::to_wide(&request.script_code);

        // Resolved via the shared helper so both Windows launch paths agree and
        // neither can pass a NULL cwd (see `working_directory`).
        let working_directory = crate::working_directory::launch_working_directory(&request);
        let _ = writeln!(
            logger,
            "working directory: {}",
            working_directory.describe()
        );
        let cwd_wide = string_util::to_wide(&working_directory.path);
        let cwd_ptr = cwd_wide.as_ptr();

        let legacy_destroy_on_exit =
            !use_process_security_environment && request.lifecycle.destroy_on_exit;

        // Identity applies only to the SBOX one-shot API. PSEC creates and owns
        // its own AppContainer identity and profile.
        // Otherwise we honour whatever the caller passed in (or the default).
        let (identity, sid_string) = if use_process_security_environment {
            ("<process-security-environment>".to_string(), String::new())
        } else if legacy_destroy_on_exit {
            let ephemeral = sandbox_tracking::generate_sandbox_identity();
            let _ = writeln!(
                logger,
                "{EMOJI_WARNING} destroy_on_exit=true: overriding caller identity '{}' -> '{}' for ephemeral cleanup",
                request.container_id, ephemeral
            );

            // Derive the AppContainer SID for registry tracking.
            // This is deterministic and does not require the profile to exist yet.
            let sid = match sandbox_tracking::derive_sid_string(&ephemeral) {
                Ok(s) => {
                    let _ = writeln!(logger, "derived SID: {}", s);
                    s
                }
                Err(e) => {
                    let _ = writeln!(logger, "warning: could not derive SID: {}", e);
                    String::new()
                }
            };

            // Write registry tracking entry before launch so it survives crashes.
            if !sid.is_empty() {
                let entry = TrackingEntry {
                    identity: ephemeral.clone(),
                    sid_string: sid.clone(),
                    destroy_on_exit: true,
                    requested_identity: request.container_id.clone(),
                };
                if let Err(e) = sandbox_tracking::write_tracking_entry(&entry, logger) {
                    let _ = writeln!(logger, "warning: tracking entry write failed: {}", e);
                }
            }

            (ephemeral, sid)
        } else {
            let id = if request.container_id.is_empty() {
                sandbox_tracking::generate_sandbox_identity()
            } else {
                request.container_id.clone()
            };
            let _ = writeln!(
                logger,
                "destroy_on_exit=false; using identity '{}', no tracking",
                id
            );
            (id, String::new())
        };
        let identity_wide = string_util::to_wide(&identity);

        // Register Ctrl+C handler early so cleanup runs if wxc-exec is interrupted
        // during or after the create call.
        if legacy_destroy_on_exit {
            sandbox_tracking::register_ctrl_c_cleanup(
                &identity,
                &sid_string,
                request.policy.network_proxy.is_enabled(),
            );
        }

        // --- Determine STDIO mode ---
        // If wxc-exec's stdout or stderr is not a terminal (i.e., piped by the SDK),
        // we forward our own std handles to the child via STARTF_USESTDHANDLES so the
        // child's output streams directly to the SDK in real time.
        //
        // In capture mode (`StdioMode::Pipes`) we always take the pipe
        // path and wire the child to capture pipes that the streaming handle
        // reads from.
        let pipe_mode =
            capture || !std::io::stdout().is_terminal() || !std::io::stderr().is_terminal();

        if pipe_mode {
            if capture {
                let _ = writeln!(
                    logger,
                    "STDIO mode: capture (piping child output to the streaming handle)"
                );
            } else {
                let _ = writeln!(
                    logger,
                    "STDIO mode: passthrough (forwarding parent handles to child)"
                );
            }
        }

        // --- Retrieve / create std handles (pipe mode only) ---
        let mut h_stdin = HANDLE::default();
        let mut h_stdout = HANDLE::default();
        let mut h_stderr = HANDLE::default();

        // Capture pipe read-ends (parent side) kept alive until after the wait;
        // child-side ends kept alive until after process creation.
        let mut capture_reads: Option<(OwnedHandle, OwnedHandle)> = None;
        let mut capture_child_ends: Vec<OwnedHandle> = Vec::new();
        // Parent's stdin write-end; in capture mode it is handed to the caller
        // so they can write to the child.
        let mut captured_stdin_write: Option<OwnedHandle> = None;

        if pipe_mode {
            if capture {
                let (stdin_read, stdin_write) = match create_std_pipes(false) {
                    Ok(p) => p,
                    Err(e) => return Err(ScriptResponse::error(&format!("stdin pipe: {e}"))),
                };
                let (stdout_read, stdout_write) = match create_std_pipes(true) {
                    Ok(p) => p,
                    Err(e) => return Err(ScriptResponse::error(&format!("stdout pipe: {e}"))),
                };
                let (stderr_read, stderr_write) = match create_std_pipes(true) {
                    Ok(p) => p,
                    Err(e) => return Err(ScriptResponse::error(&format!("stderr pipe: {e}"))),
                };

                h_stdin = stdin_read.get();
                h_stdout = stdout_write.get();
                h_stderr = stderr_write.get();

                capture_child_ends.push(stdin_read);
                capture_child_ends.push(stdout_write);
                capture_child_ends.push(stderr_write);
                captured_stdin_write = Some(stdin_write);
                capture_reads = Some((stdout_read, stderr_read));
            } else {
                h_stdin = match unsafe { GetStdHandle(STD_INPUT_HANDLE) } {
                    Ok(h) => h,
                    Err(e) => {
                        return Err(ScriptResponse::error(&format!("GetStdHandle(STDIN): {e}")))
                    }
                };
                h_stdout = match unsafe { GetStdHandle(STD_OUTPUT_HANDLE) } {
                    Ok(h) => h,
                    Err(e) => {
                        return Err(ScriptResponse::error(&format!("GetStdHandle(STDOUT): {e}")))
                    }
                };
                h_stderr = match unsafe { GetStdHandle(STD_ERROR_HANDLE) } {
                    Ok(h) => h,
                    Err(e) => {
                        return Err(ScriptResponse::error(&format!("GetStdHandle(STDERR): {e}")))
                    }
                };

                if h_stdin.is_invalid() || h_stdin == HANDLE::default() {
                    return Err(ScriptResponse::error(
                        "GetStdHandle(STDIN) returned null/invalid handle",
                    ));
                }
                if h_stdout.is_invalid() || h_stdout == HANDLE::default() {
                    return Err(ScriptResponse::error(
                        "GetStdHandle(STDOUT) returned null/invalid handle",
                    ));
                }
                if h_stderr.is_invalid() || h_stderr == HANDLE::default() {
                    return Err(ScriptResponse::error(
                        "GetStdHandle(STDERR) returned null/invalid handle",
                    ));
                }

                // Ensure the handles are inheritable.
                unsafe {
                    if let Err(e) =
                        SetHandleInformation(h_stdin, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT)
                    {
                        return Err(ScriptResponse::error(&format!(
                            "SetHandleInformation(STDIN): {e}"
                        )));
                    }
                    if let Err(e) =
                        SetHandleInformation(h_stdout, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT)
                    {
                        return Err(ScriptResponse::error(&format!(
                            "SetHandleInformation(STDOUT): {e}"
                        )));
                    }
                    if let Err(e) =
                        SetHandleInformation(h_stderr, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT)
                    {
                        return Err(ScriptResponse::error(&format!(
                            "SetHandleInformation(STDERR): {e}"
                        )));
                    }
                }
            }
        }

        // STARTUPINFOW -- in pipe mode, pass parent handles via STARTF_USESTDHANDLES
        // so child output streams directly to the SDK caller.
        let si = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            dwFlags: if pipe_mode {
                STARTF_USESTDHANDLES
            } else {
                Default::default()
            },
            hStdInput: h_stdin,
            hStdOutput: h_stdout,
            hStdError: h_stderr,
            ..unsafe { std::mem::zeroed() }
        };
        #[allow(unused_assignments)]
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        // Environment block for the sandboxed child.
        // Explicit variables are always isolated from the parent environment.
        // The one-shot API supplies its own default when this is NULL, but the
        // attribute-based CreateProcessW capture path must receive an explicit
        // clean block or it would inherit all wxc-exec process variables.
        let env_block: Option<Vec<u16>> = if request.env.is_empty() {
            if use_process_security_environment {
                let entries =
                    crate::appcontainer_runner::create_default_env_entries().map_err(|error| {
                        ScriptResponse::error(&format!(
                            "captureDenials failed to create a clean child environment: {error}"
                        ))
                    })?;
                Some(crate::appcontainer_runner::encode_env_block(&entries))
            } else {
                None
            }
        } else {
            Some(encode_env_block(&request.env))
        };

        let env_ptr = env_block
            .as_ref()
            .map(|b| b.as_ptr() as *const c_void)
            .unwrap_or(ptr::null());
        // Suppress the empty console window for console-subsystem children when
        // stdio is piped (no console is shared). In console-sharing mode (ConPTY)
        // the child inherits the parent's live console for interactive I/O, so
        // CREATE_NO_WINDOW must not be set there.
        let no_window_flag = if pipe_mode { CREATE_NO_WINDOW.0 } else { 0 };
        // Create the child suspended so its main thread cannot spawn any
        // descendant before we've assigned it to the job object below; it is
        // resumed right after the assignment. Guarded capture verifies below
        // that the API honored CREATE_SUSPENDED; an already-running child would
        // have executed before capture attachment and must fail closed.
        let creation_flags = CREATE_SUSPENDED.0
            | no_window_flag
            | if env_block.is_some() {
                CREATE_UNICODE_ENVIRONMENT.0
            } else {
                0
            };

        let _ = writeln!(logger, "launching: {}", request.script_code);
        let _ = writeln!(logger, "identity: {identity}");

        // Log the derived AppContainerSID for diagnostic correlation.
        let ac_sid_str = derive_sid_string_from_name(&identity);
        let _ = writeln!(logger, "AppContainerSID: {ac_sid_str}");

        // 4. Call Experimental_CreateProcessInSandbox.
        //    If the OS returns ERROR_NOT_SUPPORTED (0x32) and we passed a non-null
        //    environment block, this is a downlevel build that doesn't support the
        //    `environment` parameter. Retry once without it.
        let current_env_ptr = env_ptr;
        let current_creation_flags = creation_flags;

        // Prefer a process security environment when its runtime probe succeeds.
        // During the SBOX-to-PSEC transition, ordinary requests fall back to the
        // legacy contract when PSEC is unavailable or policy-incompatible.
        // captureDenials still requires PSEC because SBOX cannot provide the
        // environment handle needed to key the trace.
        let mut capture_session: Option<Box<dyn CaptureSessionOps>> = None;
        let mut security_environment: Option<ProcessSecurityEnvironment> = None;
        if use_process_security_environment {
            let psec_spec = process_security_environment_spec
                .as_deref()
                .expect("PSEC spec is initialized when the PSEC path is selected");
            if capture_denials.is_some() {
                match self
                    .capture_factory
                    .begin(psec_spec, PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE)
                {
                    Ok(session) => {
                        let _ = writeln!(
                            logger,
                            "{CAPTURE_API_AVAILABLE_LOG}; security environment and trace started"
                        );
                        capture_session = Some(session);
                    }
                    Err(e) => {
                        let msg =
                            format!("captureDenials: failed to start learning-mode capture: {e}");
                        let _ = writeln!(logger, "Error: {msg}");
                        let failure_phase = if learning_mode_api_not_implemented(&e) {
                            FailurePhase::BackendUnavailable
                        } else {
                            FailurePhase::LaunchFailed
                        };
                        self.cleanup_capture_begin_failure(logger);
                        return Err(ScriptResponse {
                            exit_code: -1,
                            error_message: msg.clone(),
                            standard_err: msg,
                            failure_phase,
                            ..Default::default()
                        });
                    }
                }
            } else {
                let result = SecurityEnvironmentApi::load()
                    .and_then(|api| api.create(psec_spec, PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE));
                match result {
                    Ok(environment) => {
                        let _ = writeln!(
                            logger,
                            "process security environment created (processmodel.dll)"
                        );
                        security_environment = Some(environment);
                    }
                    Err(error) => {
                        let msg =
                            format!("failed to create the process security environment: {error}");
                        let _ = writeln!(logger, "Error: {msg}");
                        let failure_phase = if learning_mode_api_not_implemented(&error) {
                            FailurePhase::BackendUnavailable
                        } else {
                            FailurePhase::LaunchFailed
                        };
                        return Err(ScriptResponse {
                            exit_code: -1,
                            error_message: msg.clone(),
                            standard_err: msg,
                            failure_phase,
                            ..Default::default()
                        });
                    }
                }
            }
        }

        // The launch yields (api_return_code, last_win32_error_on_failure).
        let (success, last_error, launch_api_name) = if use_process_security_environment {
            // Single-attempt in-environment launch. The process security
            // environment is attached as a process-thread attribute; the
            // CreateProcessInSandbox environment fallback does not apply here.
            pi = unsafe { std::mem::zeroed() };
            let inherited_handles = if pipe_mode {
                vec![h_stdin, h_stdout, h_stderr]
            } else {
                Vec::new()
            };
            let environment_handle = capture_session
                .as_ref()
                .map(|session| session.environment())
                .or_else(|| {
                    security_environment
                        .as_ref()
                        .map(ProcessSecurityEnvironment::raw)
                })
                .expect("PSEC environment owner is initialized before launch");
            let extended_startup = match SecurityEnvironmentStartupInfo::new(
                si,
                environment_handle,
                &inherited_handles,
            ) {
                Ok(startup) => startup,
                Err(primary) => {
                    let cleanup_error = capture_session
                        .take()
                        .map(|session| session.finish(None))
                        .unwrap_or(Ok(()))
                        .err();
                    let mut msg =
                        format!("failed to attach the process security environment: {primary}");
                    if let Some(cleanup_error) = &cleanup_error {
                        let _ = write!(
                            msg,
                            "; additionally failed to discard the learning-mode trace: {cleanup_error}"
                        );
                    }
                    let _ = writeln!(logger, "Error: {msg}");
                    let failure_phase = if learning_mode_api_not_implemented(&primary)
                        || cleanup_error
                            .as_ref()
                            .is_some_and(learning_mode_api_not_implemented)
                    {
                        FailurePhase::BackendUnavailable
                    } else {
                        FailurePhase::LaunchFailed
                    };
                    if capture_denials.is_some() {
                        self.cleanup_capture_begin_failure(logger);
                    }
                    return Err(ScriptResponse {
                        exit_code: -1,
                        error_message: msg.clone(),
                        standard_err: msg,
                        failure_phase,
                        ..Default::default()
                    });
                }
            };
            let environment = (!current_env_ptr.is_null()).then_some(current_env_ptr);
            let result = unsafe {
                CreateProcessW(
                    PCWSTR::null(),
                    Some(PWSTR(cmd_wide.as_mut_ptr())),
                    None,
                    None,
                    !inherited_handles.is_empty(),
                    PROCESS_CREATION_FLAGS(current_creation_flags | EXTENDED_STARTUPINFO_PRESENT.0),
                    environment,
                    PCWSTR(cwd_ptr),
                    &extended_startup.startup_info().StartupInfo,
                    &mut pi,
                )
            };
            if result.is_ok() {
                (1, None, CREATE_PROCESS_IN_SECURITY_ENVIRONMENT_API)
            } else {
                (
                    0,
                    Some(unsafe { GetLastError() }),
                    CREATE_PROCESS_IN_SECURITY_ENVIRONMENT_API,
                )
            }
        } else {
            let create_process_in_sandbox = match create_process_in_sandbox {
                Some(api) => api,
                None => {
                    return Err(ScriptResponse::error(
                        "internal error: SBOX launch API was not initialized",
                    ))
                }
            };
            let spec_bytes = match spec_bytes.as_deref() {
                Some(bytes) => bytes,
                None => {
                    return Err(ScriptResponse::error(
                        "internal error: SBOX specification was not initialized",
                    ))
                }
            };
            let (success, error) = SandboxLaunchArgs {
                api: create_process_in_sandbox,
                command_line: &mut cmd_wide,
                current_directory: cwd_ptr,
                startup_info: &si,
                identity: &identity_wide,
                sandbox_specification: spec_bytes,
                no_window_flag,
            }
            .launch_with_environment_fallback(
                current_creation_flags,
                current_env_ptr,
                &mut pi,
                logger,
            );
            (success, error, CREATE_PROCESS_IN_SANDBOX_API)
        };

        if success == 0 {
            let err = last_error.unwrap_or_else(|| unsafe { GetLastError() });
            // Clean up any partially-populated handles from the failed API call.
            unsafe {
                if !pi.hProcess.is_invalid() {
                    let _ = CloseHandle(pi.hProcess);
                }
                if !pi.hThread.is_invalid() {
                    let _ = CloseHandle(pi.hThread);
                }
            }
            let capture_cleanup_error = capture_session
                .take()
                .and_then(|session| session.finish(None).err());
            if capture_denials.is_some() && use_process_security_environment {
                self.cleanup_capture_begin_failure(logger);
            } else if legacy_destroy_on_exit {
                // The OS may have created the AppContainer profile before
                // failing, so run the same cleanup logic used on normal exit.
                run_sandbox_cleanup(
                    &identity,
                    &sid_string,
                    request.policy.network_proxy.is_enabled(),
                    logger,
                );
            }

            //
            // Diagnose the launch failure (FailurePhase::LaunchFailed).
            //
            let diag = diagnose_create_process_failure(
                err.0,
                &request.script_code,
                &request.policy.readonly_paths,
            );

            let mut extended_error = format!(
                "{launch_api_name} failed: {err:?} (working directory: {})",
                working_directory.describe()
            );
            if let Some(cleanup_error) = capture_cleanup_error {
                let _ = write!(
                    extended_error,
                    "; capture teardown also failed: {cleanup_error}"
                );
            }
            let _ = writeln!(logger, "Error: {extended_error}");

            let _ = writeln!(
                logger,
                "Error: Launch diagnostic [{}]: {}",
                diag.kind, diag.message
            );

            // Classify a disabled-feature error as BackendUnavailable; any
            // other launch error stays LaunchFailed.
            let failure_phase = if is_api_not_implemented(err.0)
                || is_proxy_fallback_unavailable(err.0, &request, use_process_security_environment)
            {
                FailurePhase::BackendUnavailable
            } else {
                FailurePhase::LaunchFailed
            };

            return Err(ScriptResponse {
                exit_code: -1,
                error_message: diag.message.clone(),
                standard_err: diag.message,
                extended_error,
                failure_phase,
                ..Default::default()
            });
        }

        let _ = writeln!(logger, "process created (PID: {})", pi.dwProcessId);

        // Child has inherited the pipe handles; close the parent's child-side
        // ends so the read-ends observe EOF when the child exits.
        capture_child_ends.clear();

        let (stdout_read, stderr_read) = match capture_reads {
            Some((out, err)) => (Some(out), Some(err)),
            None => (None, None),
        };

        // Assign the child to a job object so the streaming handle's `kill()`
        // (and the timeout / `Drop` paths) can tree-kill it — the child plus
        // every descendant it spawns after assignment. This backend *is* a
        // security boundary, so fail **closed**: if the job cannot be created
        // or the process cannot be assigned, terminate the just-launched child
        // and reject the spawn rather than run a sandbox that cannot be
        // reliably torn down. (Previously this was best-effort: a failed
        // assignment left `job = None`, after which `kill()`/timeout/`Drop`
        // could only `TerminateProcess` the root and no descendant was
        // tree-killed at all.)
        //
        // The child was created suspended (CREATE_SUSPENDED) and is resumed only
        // after this assignment, so no descendant it spawns can escape the job.
        // If the create API ignores CREATE_SUSPENDED on a given build, guarded
        // capture rejects the launch below because its trace would be incomplete.
        // Non-capture launches retain the historical harmless-no-op behavior.
        let job = match UiJobObject::new().and_then(|job| {
            // Pass the raw handle — `assign_process` borrows it and does not
            // take ownership. Wrapping it in a temporary `OwnedHandle` here
            // would close `pi.hProcess` when the temporary dropped, leaving the
            // owned handle on the `BaseChild` below pointing at a closed (and
            // possibly reused) handle. Sole ownership stays with that field.
            job.assign_process(pi.hProcess)?;
            Ok(job)
        }) {
            Ok(job) => job,
            Err(e) => {
                let _ = writeln!(
                    logger,
                    "Error: BaseContainer job-object setup failed ({e}); terminating \
                     the child and failing closed — a sandbox that cannot be \
                     tree-killed must not run."
                );
                // The child is already running and there is no job to tree-kill
                // through, so terminate the root directly and reap it before
                // tearing down sandbox / proxy state, upholding the same
                // "enforcement never outlives a live child" invariant as the
                // normal teardown paths.
                unsafe {
                    let _ = TerminateProcess(pi.hProcess, u32::MAX);
                    let _ = WaitForSingleObject(pi.hProcess, u32::MAX);
                    let _ = CloseHandle(pi.hProcess);
                    let _ = CloseHandle(pi.hThread);
                }
                let capture_cleanup_error = capture_session
                    .take()
                    .and_then(|session| session.finish(None).err());
                if capture_denials.is_some() && use_process_security_environment {
                    self.cleanup_capture_begin_failure(logger);
                } else if legacy_destroy_on_exit {
                    run_sandbox_cleanup(
                        &identity,
                        &sid_string,
                        request.policy.network_proxy.is_enabled(),
                        logger,
                    );
                    sandbox_tracking::unregister_ctrl_c_cleanup();
                }
                if !use_process_security_environment {
                    self.proxy_coordinator.stop(logger);
                }

                const JOB_SETUP_FAILED_MSG: &str =
                    "BaseContainer sandbox could not be placed in a job object, so it \
                     could not be reliably terminated; the launch was rejected to \
                     avoid running an uncontainable sandbox.";
                let mut extended_error = format!("BaseContainer job-object setup failed: {e}");
                if let Some(cleanup_error) = capture_cleanup_error {
                    let _ = write!(
                        extended_error,
                        "; capture teardown also failed: {cleanup_error}"
                    );
                }
                return Err(ScriptResponse {
                    exit_code: -1,
                    error_message: JOB_SETUP_FAILED_MSG.to_string(),
                    standard_err: JOB_SETUP_FAILED_MSG.to_string(),
                    extended_error,
                    failure_phase: FailurePhase::LaunchFailed,
                    ..Default::default()
                });
            }
        };

        let mut guarded_capture_session = if use_guarded_capture {
            let factory = self
                .guarded_capture_factory
                .as_ref()
                .ok_or_else(|| ScriptResponse {
                    failure_phase: FailurePhase::BackendUnavailable,
                    ..ScriptResponse::error(
                        "guarded WPR capture was selected without a capture factory",
                    )
                })?;
            match factory.start(std::process::id()) {
                Ok(mut session) => {
                    if let Err(attach_error) =
                        session.attach_process_tree(job.handle_value(), pi.hProcess.0 as usize)
                    {
                        let message = self.abandon_capture_launch(
                            &job,
                            pi.hProcess,
                            pi.hThread,
                            Some(session),
                            &identity,
                            &sid_string,
                            legacy_destroy_on_exit,
                            request.policy.network_proxy.is_enabled(),
                            "the suspended sandbox",
                            format!(
                                "captureDenials failed to attach the sandbox process tree to \
                                 guarded WPR before resuming the sandbox: {attach_error}"
                            ),
                            logger,
                        );
                        return Err(ScriptResponse {
                            failure_phase: FailurePhase::LaunchFailed,
                            ..ScriptResponse::error(&message)
                        });
                    }
                    Some(session)
                }
                Err(error) => {
                    let message = self.abandon_capture_launch(
                        &job,
                        pi.hProcess,
                        pi.hThread,
                        None,
                        &identity,
                        &sid_string,
                        legacy_destroy_on_exit,
                        request.policy.network_proxy.is_enabled(),
                        "the suspended sandbox",
                        format!(
                            "captureDenials failed to start guarded WPR before resuming the \
                             sandbox: {error}"
                        ),
                        logger,
                    );
                    return Err(ScriptResponse {
                        failure_phase: FailurePhase::LaunchFailed,
                        ..ScriptResponse::error(&message)
                    });
                }
            }
        } else {
            None
        };
        // The child was created suspended; now that it is in the job object (so
        // every descendant it spawns is captured), resume its main thread.
        // SAFETY: `pi.hThread` is the just-created, still-owned main-thread
        // handle; `ResumeThread` only adjusts its suspend count.
        let previous_suspend_count = unsafe { ResumeThread(pi.hThread) };
        let resume_error = if previous_suspend_count == u32::MAX {
            Some(format!(
                "ResumeThread failed for the BaseContainer child: {:?}",
                unsafe { GetLastError() }
            ))
        } else if guarded_capture_started_too_late(
            previous_suspend_count,
            guarded_capture_session.is_some(),
        ) {
            Some(
                "the legacy BaseContainer API ignored CREATE_SUSPENDED, so guarded WPR could not \
                 observe the complete sandbox execution"
                    .to_string(),
            )
        } else {
            None
        };
        if let Some(message) = resume_error {
            let message = self.abandon_capture_launch(
                &job,
                pi.hProcess,
                pi.hThread,
                guarded_capture_session.take(),
                &identity,
                &sid_string,
                legacy_destroy_on_exit,
                request.policy.network_proxy.is_enabled(),
                "the sandbox process tree",
                message,
                logger,
            );
            return Err(ScriptResponse {
                failure_phase: FailurePhase::LaunchFailed,
                ..ScriptResponse::error(&message)
            });
        }

        // Hand ownership to the caller via `BaseChild`, which performs
        // sandbox/proxy teardown after the child exits. `job` is always present
        // here (we failed closed above); the `Option` and the root-only fallback
        // in `kill()` remain purely as defense-in-depth.
        Ok(BaseChild {
            process: OwnedHandle::new(pi.hProcess),
            thread: OwnedHandle::new(pi.hThread),
            pid: pi.dwProcessId,
            job: Some(job),
            stdin_write: captured_stdin_write,
            stdout_read,
            stderr_read,
            timeout_ms: get_timeout_milliseconds(request.script_timeout),
            destroy_on_exit: legacy_destroy_on_exit,
            proxy_enabled: request.policy.network_proxy.is_enabled(),
            identity,
            sid_string,
            proxy_coordinator: std::mem::take(&mut self.proxy_coordinator),
            capture_session,
            guarded_capture_session,
            guarded_capture_etl_path,
            security_environment,
            managed_capture: managed_capture.take(),
            capture_output_path,
            retain_capture_etl: capture_denials
                .as_ref()
                .is_some_and(|config| config.retain_etl),
        })
    }
}

/// A BaseContainer child launched by [`BaseContainerRunner::spawn_base`].
/// `spawn_base` resumes it only after job assignment and any guarded-capture
/// attachment. This owns the process handle, parent-side pipe ends, and the
/// per-run proxy/sandbox state it tears down once the child exits.
struct BaseChild {
    process: OwnedHandle,
    thread: OwnedHandle,
    pid: u32,
    /// Job object the child is assigned to, used to tree-kill it. Always
    /// `Some` on a successfully spawned child (`spawn_base` fails closed when
    /// the job cannot be set up); the `Option` is retained so `kill()` can keep
    /// a root-only fallback as defense-in-depth.
    job: Option<UiJobObject>,
    stdin_write: Option<OwnedHandle>,
    stdout_read: Option<OwnedHandle>,
    stderr_read: Option<OwnedHandle>,
    timeout_ms: u32,
    destroy_on_exit: bool,
    proxy_enabled: bool,
    identity: String,
    sid_string: String,
    proxy_coordinator: ProxyCoordinator,
    /// Live learning-mode capture session (`Some` only when `captureDenials`
    /// is configured and the OS API is available). Sealed in `run_teardown`
    /// after the child exits.
    capture_session: Option<Box<dyn CaptureSessionOps>>,
    /// Live guarded WPR session used when the legacy SBOX tier supplies
    /// containment and native PSEC/V2 capture is unavailable.
    guarded_capture_session: Option<Box<dyn GuardedCaptureSession>>,
    /// Caller-visible guarded ETL destination when retention is requested.
    guarded_capture_etl_path: Option<PathBuf>,
    /// Non-capture PSEC environment retained until the child exits so policy
    /// enforcement outlives the process tree.
    security_environment: Option<ProcessSecurityEnvironment>,
    /// Protected per-run ETL path and its cleanup guard.
    managed_capture: Option<ManagedCapturePath>,
    /// Resolved JSON denials deliverable path (caller-specified or a managed
    /// per-run temp file). `Some` iff `capture_session` is `Some`.
    capture_output_path: Option<PathBuf>,
    /// Whether the sealed ETL is retained after analysis.
    retain_capture_etl: bool,
}

impl SandboxBackend for BaseContainerRunner {
    fn validate(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        validate_network_policy_support(request, self.network_policy_support())?;
        if request.policy.allowed_proxy_peer.is_some() {
            return Err(ScriptResponse::error(
                "processContainer.network.allowedProxyPeer is not implemented",
            ));
        }

        let capture_denials = request.policy.capture_denials.is_some();
        if !request.policy.allowed_hosts.is_empty() || !request.policy.blocked_hosts.is_empty() {
            return Err(ScriptResponse::error(
                wxc_common::error::HOST_LISTS_NOT_SUPPORTED_MSG,
            ));
        }
        // Dry-run validates the schema and policy shape without selecting or
        // probing a host capture provider.
        if request.dry_run {
            return Ok(());
        }
        let use_process_security_environment = self.uses_process_security_environment(request);
        // BaseContainer's native PSEC/V2 capture seals its own ETL, so when it
        // is selected retainEtl is honored natively regardless of the guarded
        // provider's transfer capability (the native-capture exception).
        validate_retain_etl_supported(
            request
                .policy
                .capture_denials
                .as_ref()
                .is_some_and(|config| config.retain_etl),
            self.guarded_capture_factory
                .as_ref()
                .is_some_and(|factory| factory.allows_trace_transfer()),
            use_process_security_environment,
        )?;
        if capture_denials
            && !use_process_security_environment
            && self.guarded_capture_factory.is_none()
        {
            return Err(ScriptResponse {
                failure_phase: FailurePhase::BackendUnavailable,
                ..ScriptResponse::error(
                    "processContainer.captureDenials requires either the complete native \
                     PSEC/V2 Learning Mode API set or an explicitly configured guarded-WPR \
                     fallback",
                )
            });
        }
        if use_process_security_environment && request.policy.least_privilege_mode {
            return Err(ScriptResponse::error(
                "the process-security-environment path cannot be combined with \
                 processContainer.leastPrivilege because it does not support LPAC tokens",
            ));
        }
        if use_process_security_environment && request.policy.network_proxy.is_enabled() {
            return Err(ScriptResponse::error(
                "the process-security-environment path cannot be combined with network.proxy \
                 until it can supply the required proxy AppContainer peer identity",
            ));
        }
        if use_process_security_environment && !capture_denials {
            self.capture_support
                .check_apis(false)
                .map_err(|detail| ScriptResponse {
                    failure_phase: FailurePhase::BackendUnavailable,
                    ..ScriptResponse::error(&format!(
                        "the selected process-security-environment path requires the official \
                         process security-environment APIs ({detail})"
                    ))
                })?;
        }
        // deniedPaths reaches BaseContainer through whichever contract the
        // runtime probe selected. Each path has a distinct support query; fail
        // closed rather than silently dropping the deny policy.
        if !request.policy.denied_paths.is_empty() {
            let deny_supported = if use_process_security_environment {
                self.capture_support
                    .supports_deny_paths()
                    .map_err(|message| ScriptResponse {
                        failure_phase: FailurePhase::BackendUnavailable,
                        ..ScriptResponse::error(&message)
                    })?
            } else {
                crate::fallback_detector::base_container_supports_deny_paths()
            };
            if !deny_supported {
                return Err(if use_process_security_environment {
                    ScriptResponse {
                        failure_phase: FailurePhase::BackendUnavailable,
                        ..ScriptResponse::error(PSEC_DENIED_PATHS_UNSUPPORTED_MSG)
                    }
                } else {
                    ScriptResponse::error(wxc_common::error::DENIED_PATHS_FEATURE_DISABLED_MSG)
                });
            }
        }
        if use_process_security_environment {
            return Ok(());
        }

        Self::is_base_container_api_present().map_err(|e| {
            let hint = format!(
                "BaseContainer API unavailable: {e}\n\
                 Hint: this OS build does not support the BaseContainer backend. \
                 MXC selects BaseContainer automatically when the host supports it \
                 and otherwise uses AppContainer; use an OS build with BaseContainer \
                 support if you require it."
            );
            ScriptResponse {
                // Symbol absent: report BackendUnavailable, not a hard error.
                failure_phase: FailurePhase::BackendUnavailable,
                ..ScriptResponse::error(&hint)
            }
        })
    }

    fn spawn(
        &mut self,
        request: &ExecutionRequest,
        logger: &mut Logger,
        stdio: StdioMode,
    ) -> Result<Box<dyn SandboxProcess>, ScriptResponse> {
        use wxc_common::validator::validate_common;

        validate_common(request)?;
        self.validate(request)?;

        // Pipes → capture pipes the caller drives; Inherit → the child inherits
        // the binary's own std handles / console (a TTY when the binary has one).
        let capture = stdio == StdioMode::Pipes;
        let child = self.spawn_base(request, logger, capture)?;
        Ok(Box::new(BaseContainerSandboxProcess::from_child(child)))
    }

    fn diagnose_exit(&self, request: &ExecutionRequest, exit_code: i32) -> Option<String> {
        diagnose_process_exit(
            &request.script_code,
            &request.policy.readonly_paths,
            &request.policy.readwrite_paths,
            exit_code as u32,
        )
        .map(|diag| diag.message)
    }
}

/// A running BaseContainer-sandboxed process exposed as a [`SandboxProcess`].
/// Owns the process handle, the parent-side pipes, and the per-run proxy /
/// sandbox state, which it tears down once the child exits.
struct BaseContainerSandboxProcess {
    process: SendOwnedHandle,
    _thread: SendOwnedHandle,
    job: Option<UiJobObject>,
    pid: u32,
    stdin: Option<PipeWriter>,
    stdout: Option<InterruptiblePipeReader>,
    stderr: Option<InterruptiblePipeReader>,
    /// Cancellers for the stdout/stderr reads, kept so the `SandboxProcess`
    /// closers can mint a [`StreamCloser`] even after the stream is taken.
    stdout_canceller: Option<PipeReadCanceller>,
    stderr_canceller: Option<PipeReadCanceller>,
    timeout_ms: u32,
    destroy_on_exit: bool,
    proxy_enabled: bool,
    identity: String,
    sid_string: String,
    proxy_coordinator: ProxyCoordinator,
    /// Cached teardown outcome so repeated terminal waits cannot hide a
    /// capture failure after the session has been consumed.
    teardown_result: Option<Result<(), String>>,
    /// Live learning-mode capture session, moved from the `BaseChild`. Sealed
    /// in `run_teardown` once the child has exited and been reaped.
    capture_session: Option<Box<dyn CaptureSessionOps>>,
    guarded_capture_session: Option<Box<dyn GuardedCaptureSession>>,
    /// Caller-visible guarded ETL destination when retention is requested.
    guarded_capture_etl_path: Option<PathBuf>,
    /// Non-capture PSEC environment, closed after the child exits and is reaped.
    security_environment: Option<ProcessSecurityEnvironment>,
    /// Protected per-run ETL path and its cleanup guard.
    managed_capture: Option<ManagedCapturePath>,
    /// Resolved JSON denials deliverable path.
    capture_output_path: Option<PathBuf>,
    /// Whether the sealed ETL is retained after analysis.
    retain_capture_etl: bool,
    /// Exit code of the child, recorded by `wait` before teardown so the
    /// denials summary can carry it. `None` on the `Drop`/early-exit path.
    last_exit_code: Option<i32>,
    /// Structured output published after capture teardown succeeds.
    output_metadata: Option<SandboxOutputMetadata>,
}

// SAFETY: the fields are Windows HANDLEs / handle-owning managers and owned
// strings. HANDLEs are process-global and safe to use from any single thread;
// this handle is owned exclusively by the caller, so moving it across threads
// is sound.
unsafe impl Send for BaseContainerSandboxProcess {}

impl BaseContainerSandboxProcess {
    fn from_child(mut child: BaseChild) -> Self {
        let process = SendOwnedHandle::take(&mut child.process);
        let thread = SendOwnedHandle::take(&mut child.thread);
        let stdin = child.stdin_write.take().map(PipeWriter::new);
        let stdout = child.stdout_read.take().map(InterruptiblePipeReader::new);
        let stderr = child.stderr_read.take().map(InterruptiblePipeReader::new);
        let stdout_canceller = stdout.as_ref().map(InterruptiblePipeReader::canceller);
        let stderr_canceller = stderr.as_ref().map(InterruptiblePipeReader::canceller);
        Self {
            process,
            _thread: thread,
            job: child.job.take(),
            pid: child.pid,
            stdin,
            stdout,
            stderr,
            stdout_canceller,
            stderr_canceller,
            timeout_ms: child.timeout_ms,
            destroy_on_exit: child.destroy_on_exit,
            proxy_enabled: child.proxy_enabled,
            identity: std::mem::take(&mut child.identity),
            sid_string: std::mem::take(&mut child.sid_string),
            proxy_coordinator: std::mem::take(&mut child.proxy_coordinator),
            teardown_result: None,
            capture_session: child.capture_session.take(),
            guarded_capture_session: child.guarded_capture_session.take(),
            guarded_capture_etl_path: child.guarded_capture_etl_path.take(),
            security_environment: child.security_environment.take(),
            managed_capture: child.managed_capture.take(),
            capture_output_path: child.capture_output_path.take(),
            retain_capture_etl: child.retain_capture_etl,
            last_exit_code: None,
            output_metadata: None,
        }
    }

    fn run_teardown(&mut self, allow_retention: bool) -> std::io::Result<()> {
        if let Some(result) = &self.teardown_result {
            return result.clone().map_err(std::io::Error::other);
        }
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);

        // Seal the learning-mode ETL trace now that the child has exited and
        // been reaped (both `wait` and `Drop` kill + reap before calling this).
        // Seal the ETL, decode it into the JSON denials deliverable, and either
        // delete it or report its retained path according to the request. Any
        // seal/decode/write failure is returned through `wait()`.
        let capture_result = if let Some(session) = self.capture_session.take() {
            let managed_capture = self.managed_capture.take();
            if !allow_retention {
                let result = discard_abandoned_capture(session, managed_capture);
                self.capture_output_path.take();
                result.map(|_| None)
            } else {
                let etl_path = managed_capture
                    .as_ref()
                    .map(|capture| capture.etl_path.as_path());
                let output_path = self.capture_output_path.take();
                let exit_code = self.last_exit_code.unwrap_or(-1);
                let retain_etl = allow_retention && self.retain_capture_etl;
                let finish_result = session.finish(etl_path);
                let (mut etl_path, mut etl_directory) = managed_capture
                    .map(ManagedCapturePath::disarm)
                    .map(|(path, directory)| (Some(path), Some(directory)))
                    .unwrap_or((None, None));
                let promotion_error = if finish_result.is_ok() && retain_etl {
                    match (&etl_path, &etl_directory) {
                        (Some(etl), Some(directory)) => {
                            match promote_capture_for_retention(etl, directory) {
                                Ok((retained_etl, retained_directory)) => {
                                    etl_path = Some(retained_etl);
                                    etl_directory = Some(retained_directory);
                                    None
                                }
                                Err(error) => Some(error),
                            }
                        }
                        _ => None,
                    }
                } else {
                    None
                };
                let (capture_result, etl_was_sealed) = match finish_result {
                    Ok(()) => (
                        match (&etl_path, &output_path) {
                            (Some(etl), Some(output)) => Self::decode_write_and_finalize(
                                &EtlDenialAnalyzer,
                                etl,
                                etl_directory.as_deref(),
                                output,
                                exit_code,
                                retain_etl,
                            )
                            .map(Some),
                            _ => finalize_capture_result(
                                Err(std::io::Error::other(
                                    "captureDenials internal output paths were not initialized",
                                )),
                                etl_path.as_deref(),
                                etl_directory.as_deref(),
                                retain_etl,
                            )
                            .map(Some),
                        },
                        true,
                    ),
                    Err(error) => (
                        finalize_capture_seal_failure(
                            std::io::Error::other(format!(
                                "captureDenials failed to finalize the denial capture: {error}"
                            )),
                            etl_path.as_deref(),
                            etl_directory.as_deref(),
                        )
                        .map(Some),
                        false,
                    ),
                };
                let result = match (capture_result, promotion_error) {
                    (Ok(Some(metadata)), Some(error)) => {
                        self.output_metadata = Some(SandboxOutputMetadata {
                            capture_denials: Some(metadata),
                            capture_denials_error: Some(CaptureDenialsErrorOutput {
                                message: error.to_string(),
                                etl_path: etl_path
                                    .as_deref()
                                    .map(|path| path.to_string_lossy().into_owned())
                                    .unwrap_or_default(),
                            }),
                        });
                        Err(error)
                    }
                    (Err(capture_error), Some(promotion_error)) => {
                        let error = std::io::Error::other(format!(
                            "{capture_error}; additionally {promotion_error}"
                        ));
                        if let Some(etl_path) = etl_path.as_deref() {
                            self.output_metadata = Some(SandboxOutputMetadata {
                                capture_denials: None,
                                capture_denials_error: Some(CaptureDenialsErrorOutput {
                                    message: error.to_string(),
                                    etl_path: etl_path.to_string_lossy().into_owned(),
                                }),
                            });
                        }
                        Err(error)
                    }
                    (Ok(Some(metadata)), None) => {
                        self.output_metadata = Some(SandboxOutputMetadata {
                            capture_denials: Some(metadata.clone()),
                            capture_denials_error: None,
                        });
                        Ok(Some(metadata))
                    }
                    (Err(error), None) => {
                        if let Some(metadata) = capture_output_from_cleanup_error(&error) {
                            self.output_metadata = Some(SandboxOutputMetadata {
                                capture_denials: Some(metadata.clone()),
                                capture_denials_error: None,
                            });
                        } else if retain_etl && etl_was_sealed {
                            if let Some(etl_path) = etl_path.as_deref() {
                                self.output_metadata = Some(SandboxOutputMetadata {
                                    capture_denials: None,
                                    capture_denials_error: Some(CaptureDenialsErrorOutput {
                                        message: error.to_string(),
                                        etl_path: etl_path.to_string_lossy().into_owned(),
                                    }),
                                });
                            }
                        }
                        Err(error)
                    }
                    (Ok(None), promotion_error) => promotion_error.map_or(Ok(None), Err),
                };
                result
            }
        } else {
            self.managed_capture.take();
            Ok(None)
        };
        let guarded_capture_result: std::io::Result<Option<CaptureDenialsOutput>> =
            if let Some(mut session) = self.guarded_capture_session.take() {
                let output_path = self.capture_output_path.take();
                let etl_path = self
                    .guarded_capture_etl_path
                    .take()
                    .filter(|_| allow_retention);
                let exit_code = self.last_exit_code.unwrap_or(-1);
                let stop = match etl_path.as_deref() {
                    Some(destination) => GuardedStop::AnalyzeAndRetain { destination },
                    None => GuardedStop::AnalyzeOnly,
                };
                // The shared finalizer owns every analysis-vs-retention state
                // transition so this native-tier guarded fallback and the
                // AppContainer guarded tier stay byte-for-byte identical.
                let finalization = finalize_guarded_capture(
                    session.as_mut(),
                    output_path.as_deref(),
                    stop,
                    exit_code,
                );
                self.output_metadata = finalization.metadata;
                finalization
                    .result
                    .map(|()| None)
                    .map_err(std::io::Error::other)
            } else {
                Ok(None)
            };
        self.security_environment.take();

        if self.destroy_on_exit {
            run_sandbox_cleanup(
                &self.identity,
                &self.sid_string,
                self.proxy_enabled,
                &mut logger,
            );
            sandbox_tracking::unregister_ctrl_c_cleanup();
        }
        self.proxy_coordinator.stop(&mut logger);
        let result = capture_result
            .and(guarded_capture_result)
            .map(|_| ())
            .map_err(|error| error.to_string());
        self.teardown_result = Some(result.clone());
        result.map_err(std::io::Error::other)
    }

    fn release_guarded_capture_after_termination_failure(&mut self) {
        let Some(session) = self.guarded_capture_session.take() else {
            return;
        };
        // The trait contract keeps this call blocked until the elevated
        // guardian has released its duplicate job handle, even when discard
        // itself fails. Only then may Drop return and release enforcement.
        if let Err(error) = crate::guarded_capture::release_after_termination_failure(session) {
            write_stderr_line_best_effort(format_args!(
                "failed to discard guarded WPR capture after sandbox termination failure: {error}"
            ));
        }
    }

    fn kill_process_tree(&mut self) -> std::io::Result<()> {
        if let Some(job) = &self.job {
            if self.guarded_capture_session.is_some() {
                // Guarded-WPR capture needs strict drain certainty: the ETL is
                // only safely scoped if the job is proven to have fully drained
                // before the trace is stopped/discarded.
                job.terminate_and_wait(u32::MAX)
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
            } else {
                // Ordinary run: terminate the tree, but a slow drain is a
                // warning, not a hard failure that would discard an otherwise
                // valid result.
                match job.terminate_best_effort(u32::MAX) {
                    Ok(Some(drain_warning)) => write_stderr_line_best_effort(format_args!(
                        "sandbox job did not fully drain within the teardown window \
                         (continuing): {drain_warning}"
                    )),
                    Ok(None) => {}
                    Err(error) => return Err(std::io::Error::other(error.to_string())),
                }
            }
        } else {
            unsafe { TerminateProcess(self.process.get(), u32::MAX) }
                .map_err(|error| std::io::Error::other(format!("TerminateProcess: {error}")))?;
        }
        Ok(())
    }

    fn terminate_and_reap(&mut self) -> std::io::Result<()> {
        self.kill_process_tree()?;
        unsafe {
            match WaitForSingleObject(self.process.get(), u32::MAX) {
                WAIT_OBJECT_0 => Ok(()),
                status => Err(std::io::Error::other(format!(
                    "WaitForSingleObject(process) returned {status:?}"
                ))),
            }
        }
    }

    /// Decodes a sealed capture into the JSON denials document at `output_path`.
    fn decode_and_write_denials(
        analyzer: &dyn DenialAnalyzer,
        etl_path: &std::path::Path,
        output_path: &std::path::Path,
        exit_code: i32,
    ) -> std::io::Result<CaptureDenialsOutput> {
        let analysis = analyzer.analyze(etl_path).map_err(|error| {
            std::io::Error::other(format!(
                "captureDenials failed to decode denials ETL: {error}"
            ))
        })?;
        write_denials_document(analysis, exit_code, output_path)
    }

    fn decode_write_and_finalize(
        analyzer: &dyn DenialAnalyzer,
        etl_path: &Path,
        etl_directory: Option<&Path>,
        output_path: &Path,
        exit_code: i32,
        retain_etl: bool,
    ) -> std::io::Result<CaptureDenialsOutput> {
        finalize_capture_result(
            Self::decode_and_write_denials(analyzer, etl_path, output_path, exit_code),
            Some(etl_path),
            etl_directory,
            retain_etl,
        )
    }
}

fn finalize_capture_result(
    capture_result: std::io::Result<CaptureDenialsOutput>,
    etl_path: Option<&Path>,
    etl_directory: Option<&Path>,
    retain_etl: bool,
) -> std::io::Result<CaptureDenialsOutput> {
    if retain_etl {
        let Some(etl_path) = etl_path else {
            return capture_result;
        };
        let retained_path = etl_path.to_string_lossy().into_owned();
        return capture_result
            .map(|mut output| {
                output.etl_path = Some(retained_path);
                output
            })
            .map_err(|error| {
                std::io::Error::other(format!(
                    "{error}; retained ETL file at {}",
                    etl_path.display()
                ))
            });
    }

    combine_capture_output_and_cleanup_results(
        capture_result,
        etl_path
            .map(|path| remove_managed_capture_path(path, etl_directory))
            .unwrap_or(Ok(())),
    )
}

fn combine_capture_output_and_cleanup_results(
    capture_result: std::io::Result<CaptureDenialsOutput>,
    cleanup_result: std::io::Result<()>,
) -> std::io::Result<CaptureDenialsOutput> {
    match (capture_result, cleanup_result) {
        (Ok(output), Ok(())) => Ok(output),
        (Ok(output), Err(cleanup_error)) => Err(std::io::Error::other(CaptureCleanupError {
            output,
            cleanup_message: cleanup_error.to_string(),
        })),
        (Err(capture_error), Ok(())) => Err(capture_error),
        (Err(capture_error), Err(cleanup_error)) => Err(std::io::Error::other(format!(
            "{capture_error}; additionally failed to clean up the internal ETL: {cleanup_error}"
        ))),
    }
}

fn capture_output_from_cleanup_error(error: &std::io::Error) -> Option<&CaptureDenialsOutput> {
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<CaptureCleanupError>())
        .map(|error| &error.output)
}

fn finalize_capture_seal_failure<T>(
    capture_error: std::io::Error,
    etl_path: Option<&Path>,
    etl_directory: Option<&Path>,
) -> std::io::Result<T> {
    combine_capture_and_cleanup_results(
        Err(capture_error),
        etl_path
            .map(|path| remove_managed_capture_path(path, etl_directory))
            .unwrap_or(Ok(())),
    )
}

fn discard_abandoned_capture(
    session: Box<dyn CaptureSessionOps>,
    managed_capture: Option<ManagedCapturePath>,
) -> std::io::Result<()> {
    let result = session.finish(None).map_err(|error| {
        std::io::Error::other(format!(
            "captureDenials failed to discard the abandoned denial capture: {error}"
        ))
    });
    drop(managed_capture);
    result
}

fn remove_managed_capture_path(path: &Path, directory: Option<&Path>) -> std::io::Result<()> {
    let file_result = remove_internal_capture_file(path);
    let directory_result = match directory {
        Some(directory) => match std::fs::remove_dir(directory) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(std::io::Error::other(format!(
                "captureDenials failed to remove internal ETL directory {}: {error}",
                directory.display()
            ))),
        },
        None => Ok(()),
    };
    match (file_result, directory_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(file_error), Err(directory_error)) => Err(std::io::Error::other(format!(
            "{file_error}; additionally {directory_error}"
        ))),
    }
}
impl SandboxProcess for BaseContainerSandboxProcess {
    fn output_metadata(&self) -> Option<&SandboxOutputMetadata> {
        self.output_metadata.as_ref()
    }

    fn take_stdin(&mut self) -> Option<Box<dyn std::io::Write + Send>> {
        take_boxed_write(&mut self.stdin)
    }

    fn take_stdout(&mut self) -> Option<Box<dyn std::io::Read + Send>> {
        take_boxed_read(&mut self.stdout)
    }

    fn take_stderr(&mut self) -> Option<Box<dyn std::io::Read + Send>> {
        take_boxed_read(&mut self.stderr)
    }

    fn stdout_closer(&self) -> Option<Box<dyn StreamCloser>> {
        boxed_closer(&self.stdout_canceller)
    }

    fn stderr_closer(&self) -> Option<Box<dyn StreamCloser>> {
        boxed_closer(&self.stderr_canceller)
    }

    fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
        match unsafe { WaitForSingleObject(self.process.get(), 0) } {
            WAIT_OBJECT_0 => {
                let mut code: u32 = 0;
                if unsafe { GetExitCodeProcess(self.process.get(), &mut code) }.is_err() {
                    return Err(std::io::Error::other("GetExitCodeProcess failed"));
                }
                // Keep polling non-blocking and independent of captureDenials.
                // `wait()` or `Drop` owns descendant termination and capture
                // finalization after the root exit becomes observable.
                Ok(Some(code as i32))
            }
            WAIT_TIMEOUT => Ok(None),
            _ => Err(std::io::Error::other("WaitForSingleObject failed")),
        }
    }

    fn id(&self) -> u32 {
        self.pid
    }

    fn kill(&mut self) -> std::io::Result<()> {
        // Tree-kill via the job object when the child was successfully assigned
        // to one; otherwise fall back to terminating the root process.
        self.kill_process_tree()
    }

    fn wait(&mut self) -> std::io::Result<i32> {
        // Close our copy of any not-taken stdin so the child sees EOF and can
        // exit reliably (an interactive command would otherwise block waiting
        // for input).
        self.stdin.take();

        // Drain (and discard) any not-taken streams concurrently to avoid the
        // child blocking on a full pipe buffer.
        let stdout_thread = spawn_discard(self.stdout.take());
        let stderr_thread = spawn_discard(self.stderr.take());

        let result = match unsafe { WaitForSingleObject(self.process.get(), self.timeout_ms) } {
            WAIT_OBJECT_0 => {
                let mut code: u32 = 0;
                if unsafe { GetExitCodeProcess(self.process.get(), &mut code) }.is_err() {
                    Err(std::io::Error::other("GetExitCodeProcess failed"))
                } else {
                    Ok(code as i32)
                }
            }
            WAIT_TIMEOUT => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("script timed out after {}ms", self.timeout_ms),
            )),
            _ => Err(std::io::Error::other("WaitForSingleObject failed")),
        };

        // Tree-kill (the job when assigned, else the root) so any backgrounded
        // descendant dies *before* `run_teardown()` stops the proxy / sandbox
        // enforcement — upholding the same invariant as `Drop`. The foreground
        // child has already exited on the success path; on a timeout or wait
        // failure this also terminates it. Then reap the root before releasing
        // the pipe drains — and killing the tree closes the descendant's pipe
        // write-ends, so the drains can finish.
        let termination_result = self.terminate_and_reap();
        cancel_and_join_discard(stdout_thread, &self.stdout_canceller);
        cancel_and_join_discard(stderr_thread, &self.stderr_canceller);
        termination_result?;
        // Record the child's exit code so `run_teardown` can stamp it into the
        // denials summary. On a timeout / wait failure there is no exit code.
        self.last_exit_code = result.as_ref().ok().copied();
        let teardown_result = self.run_teardown(true);
        combine_process_and_teardown_results(result, teardown_result)
    }
}

impl Drop for BaseContainerSandboxProcess {
    fn drop(&mut self) {
        // Kill and reap before tearing down proxy / sandbox state, so an
        // abandoned-but-running sandbox cannot outlive its enforcement (or
        // leak as an orphan).
        if let Err(error) = self.terminate_and_reap() {
            write_stderr_line_best_effort(format_args!(
                "failed to terminate sandbox process tree during drop: {error}"
            ));
            self.release_guarded_capture_after_termination_failure();
            return;
        }
        // A dropped handle has no observer for output metadata, so retaining
        // its ETL would leave a sensitive artifact with no discoverable owner.
        // If wait already attempted teardown, it already reported any failure.
        if self.teardown_result.is_none() {
            if let Err(error) = self.run_teardown(false) {
                write_stderr_line_best_effort(format_args!(
                    "captureDenials teardown failed during drop: {error}"
                ));
            }
        }
    }
}

struct ManagedCapturePath {
    directory: PathBuf,
    etl_path: PathBuf,
    armed: bool,
}

impl ManagedCapturePath {
    fn disarm(mut self) -> (PathBuf, PathBuf) {
        self.armed = false;
        (
            std::mem::take(&mut self.etl_path),
            std::mem::take(&mut self.directory),
        )
    }
}

impl Drop for ManagedCapturePath {
    fn drop(&mut self) {
        if self.armed {
            let _ = remove_managed_capture_path(&self.etl_path, Some(&self.directory));
        }
    }
}

fn managed_capture_output_path(retain_etl: bool) -> Result<ManagedCapturePath, ScriptResponse> {
    if !retain_etl {
        return managed_capture_output_path_in(
            &std::env::temp_dir(),
            "mxc_capture_denials_",
            false,
        );
    }

    let local_app_data = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("USERPROFILE")
                .map(PathBuf::from)
                .map(|profile| profile.join("AppData").join("Local"))
        })
        .ok_or_else(|| {
            ScriptResponse::error(
                "captureDenials could not resolve LOCALAPPDATA for protected ETL storage",
            )
        })?;
    let root = local_app_data
        .join("Microsoft")
        .join("MXC")
        .join("capture-denials")
        .join("working");
    managed_capture_output_path_in(&root, "", true)
}

fn promote_capture_for_retention(
    etl_path: &Path,
    directory: &Path,
) -> std::io::Result<(PathBuf, PathBuf)> {
    let working_root = directory
        .parent()
        .ok_or_else(|| std::io::Error::other("captureDenials working directory has no parent"))?;
    let capture_root = working_root
        .parent()
        .ok_or_else(|| std::io::Error::other("captureDenials working root has no parent"))?;
    let retained_root = capture_root.join(crate::capture_output::RETAINED_CAPTURE_DIR_NAME);
    std::fs::create_dir_all(&retained_root)?;
    wxc_common::filesystem_dacl::set_owner_only_dacl(&retained_root, true)
        .map_err(std::io::Error::other)?;
    let directory_name = directory.file_name().ok_or_else(|| {
        std::io::Error::other("captureDenials working directory has no file name")
    })?;
    let retained_directory = retained_root.join(directory_name);
    std::fs::rename(directory, &retained_directory).map_err(|error| {
        std::io::Error::other(format!(
            "captureDenials failed to move sealed ETL into retained storage: {error}; retained ETL file remains at {}",
            etl_path.display()
        ))
    })?;
    Ok((
        retained_directory.join(
            etl_path
                .file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new("capture.etl")),
        ),
        retained_directory,
    ))
}

fn managed_capture_output_path_in(
    root: &Path,
    directory_prefix: &str,
    secure_root: bool,
) -> Result<ManagedCapturePath, ScriptResponse> {
    if secure_root {
        std::fs::create_dir_all(root).map_err(|error| {
            ScriptResponse::error(&format!(
                "captureDenials failed to create ETL root {}: {error}",
                root.display()
            ))
        })?;
        wxc_common::filesystem_dacl::set_owner_only_dacl(root, true).map_err(|error| {
            ScriptResponse::error(&format!(
                "captureDenials failed to secure ETL root {}: {error}",
                root.display()
            ))
        })?;
    }

    for _ in 0..8 {
        let suffix = crate::capture_output::random_capture_suffix()
            .map_err(|error| ScriptResponse::error(&error))?;
        let directory = root.join(format!("{directory_prefix}{}_{suffix}", std::process::id()));
        match std::fs::create_dir(&directory) {
            Ok(()) => {
                if let Err(error) =
                    wxc_common::filesystem_dacl::set_owner_only_dacl(&directory, true)
                {
                    let _ = std::fs::remove_dir(&directory);
                    return Err(ScriptResponse::error(&format!(
                        "captureDenials failed to secure ETL directory {}: {error}",
                        directory.display()
                    )));
                }
                return Ok(ManagedCapturePath {
                    etl_path: directory.join("capture.etl"),
                    directory,
                    armed: true,
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(ScriptResponse::error(&format!(
                    "captureDenials failed to create ETL directory {}: {error}",
                    directory.display()
                )));
            }
        }
    }

    Err(ScriptResponse::error(
        "captureDenials failed to allocate a unique protected ETL directory",
    ))
}

/// Derive the AppContainer SID string from a container identity name.
/// Best-effort: returns a placeholder if derivation fails.
fn derive_sid_string_from_name(name: &str) -> String {
    use windows::Win32::Security::FreeSid;
    use windows::Win32::Security::Isolation::DeriveAppContainerSidFromAppContainerName;

    let wide_name = string_util::to_wide(name);
    let pcwstr_name = PCWSTR(wide_name.as_ptr());

    match unsafe { DeriveAppContainerSidFromAppContainerName(pcwstr_name) } {
        Ok(sid) => {
            let s = unsafe { string_util::sid_to_string(sid.0) }
                .unwrap_or_else(|| "unknown-sid".to_string());
            // SAFETY: SID returned by DeriveAppContainerSidFromAppContainerName
            // must be freed with FreeSid.
            unsafe {
                FreeSid(sid);
            }
            s
        }
        Err(_) => "unknown-sid".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job_object::to_job_object_uilimit_mask;
    use learning_mode_core::{
        AccessType, AnalysisResult, AnalyzeError, DenialsDocument, DeniedResource, ResourceType,
    };
    use process_security_environment_spec::process_security_environment_layout as psec_layout;
    use sandbox_spec::base_container_layout;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wxc_common::models::{ClipboardPolicy, ProxyConfig, UiPolicy};
    use wxc_common::ui_policy::EffectiveUiRestrictions;

    #[test]
    fn guarded_capture_rejects_a_child_that_was_never_suspended() {
        assert!(guarded_capture_started_too_late(0, true));
        assert!(!guarded_capture_started_too_late(1, true));
        assert!(!guarded_capture_started_too_late(0, false));
    }

    struct FakeCaptureSession {
        finish_error: Option<(&'static str, i32)>,
        finish_calls: Arc<AtomicUsize>,
    }

    impl CaptureSessionOps for FakeCaptureSession {
        fn environment(&self) -> HANDLE {
            HANDLE(std::ptr::dangling_mut())
        }

        fn finish(
            self: Box<Self>,
            _output_path: Option<&std::path::Path>,
        ) -> Result<(), learning_mode_windows::LearningModeError> {
            self.finish_calls.fetch_add(1, Ordering::SeqCst);
            match self.finish_error {
                Some((function, code)) => {
                    Err(learning_mode_windows::LearningModeError::HResultCall { function, code })
                }
                None => Ok(()),
            }
        }
    }

    struct FakeCaptureFactory {
        begin_error: Option<(&'static str, i32)>,
        finish_error: Option<(&'static str, i32)>,
        begin_calls: AtomicUsize,
        finish_calls: Arc<AtomicUsize>,
    }

    impl CaptureSessionFactory for FakeCaptureFactory {
        fn begin(
            &self,
            _sandbox_specification: &[u8],
            _flags: u32,
        ) -> Result<Box<dyn CaptureSessionOps>, learning_mode_windows::LearningModeError> {
            self.begin_calls.fetch_add(1, Ordering::SeqCst);
            if let Some((function, code)) = self.begin_error {
                return Err(learning_mode_windows::LearningModeError::HResultCall {
                    function,
                    code,
                });
            }
            Ok(Box::new(FakeCaptureSession {
                finish_error: self.finish_error,
                finish_calls: Arc::clone(&self.finish_calls),
            }))
        }
    }

    struct FakeCaptureSupport {
        api_error: Option<&'static str>,
        deny_error: Option<&'static str>,
        deny_supported: bool,
        api_calls: AtomicUsize,
        learning_mode_api_calls: AtomicUsize,
        deny_calls: AtomicUsize,
    }

    impl CapturePlatformSupport for FakeCaptureSupport {
        fn check_apis(&self, require_learning_mode: bool) -> Result<(), String> {
            self.api_calls.fetch_add(1, Ordering::SeqCst);
            if require_learning_mode {
                self.learning_mode_api_calls.fetch_add(1, Ordering::SeqCst);
            }
            self.api_error
                .map_or(Ok(()), |error| Err(error.to_string()))
        }

        fn supports_deny_paths(&self) -> Result<bool, String> {
            self.deny_calls.fetch_add(1, Ordering::SeqCst);
            self.deny_error
                .map_or(Ok(self.deny_supported), |error| Err(error.to_string()))
        }
    }

    fn fake_capture_factory() -> Arc<FakeCaptureFactory> {
        Arc::new(FakeCaptureFactory {
            begin_error: None,
            finish_error: None,
            begin_calls: AtomicUsize::new(0),
            finish_calls: Arc::new(AtomicUsize::new(0)),
        })
    }

    fn capture_request_with_denied_path() -> ExecutionRequest {
        let mut request = ExecutionRequest {
            schema_version: "0.8.0-alpha".to_string(),
            ..Default::default()
        };
        request.policy.capture_denials = Some(Default::default());
        request.policy.denied_paths = vec![r"C:\secret".to_string()];
        request
    }

    struct FakeAnalyzer {
        result: Result<AnalysisResult, &'static str>,
    }

    impl DenialAnalyzer for FakeAnalyzer {
        fn analyze(&self, _source_path: &Path) -> Result<AnalysisResult, AnalyzeError> {
            match &self.result {
                Ok(result) => Ok(result.clone()),
                Err(message) => Err(AnalyzeError::Decode((*message).to_string())),
            }
        }
    }

    fn expected_mask(r: EffectiveUiRestrictions) -> u64 {
        to_job_object_uilimit_mask(&r) as u64
    }

    #[test]
    fn managed_capture_paths_are_unique_per_run() {
        let parent = tempfile::tempdir().expect("temp parent");
        let root = parent.path().join("capture-denials");
        let first = managed_capture_output_path_in(&root, "", true).expect("first path");
        let second = managed_capture_output_path_in(&root, "", true).expect("second path");
        let first_directory = first.directory.clone();
        let second_directory = second.directory.clone();

        assert_ne!(first.directory, second.directory);
        assert_eq!(first.etl_path.parent(), Some(first.directory.as_path()));
        assert_eq!(second.etl_path.parent(), Some(second.directory.as_path()));
        assert_eq!(
            first.etl_path.extension().and_then(|ext| ext.to_str()),
            Some("etl")
        );
        assert!(wxc_common::filesystem_dacl::owner_is_self(&first.directory)
            .expect("read managed directory owner"));
        drop(first);
        drop(second);
        assert!(!first_directory.exists());
        assert!(!second_directory.exists());
    }

    #[test]
    fn retained_capture_moves_out_of_working_storage() {
        let parent = tempfile::tempdir().expect("temp parent");
        let working = parent.path().join("capture-denials").join("working");
        let directory = working.join("1234_abcd");
        std::fs::create_dir_all(&directory).expect("working directory");
        let etl_path = directory.join("capture.etl");
        std::fs::write(&etl_path, b"fake etl").expect("seed ETL");

        let (retained_etl, retained_directory) =
            promote_capture_for_retention(&etl_path, &directory).expect("promote capture");
        let retained_root = parent.path().join("capture-denials").join("retained");

        assert!(!directory.exists());
        assert_eq!(retained_directory.parent(), Some(retained_root.as_path()));
        assert_eq!(
            std::fs::read(retained_etl).expect("read retained ETL"),
            b"fake etl"
        );
    }

    #[test]
    fn cleanup_failure_preserves_successful_capture_output() {
        let output = CaptureDenialsOutput {
            kind: CaptureDenialsOutput::KIND.to_string(),
            output_path: "denials.json".to_string(),
            exit_code: 0,
            total_denials: 1,
            denied_resources_truncated: false,
            etl_path: None,
        };

        let error = combine_capture_output_and_cleanup_results(
            Ok(output.clone()),
            Err(std::io::Error::other("delete failed")),
        )
        .expect_err("cleanup failure should propagate");

        assert_eq!(capture_output_from_cleanup_error(&error), Some(&output));
        assert!(error.to_string().contains("delete failed"));
    }

    #[test]
    fn injected_analyzer_writes_document_and_returns_metadata() {
        let directory = tempfile::tempdir().expect("temp directory");
        let output_path = directory.path().join("denials.json");
        let analyzer = FakeAnalyzer {
            result: Ok(AnalysisResult::complete(vec![DeniedResource {
                resource: r"C:\blocked.txt".to_string(),
                resource_type: ResourceType::File,
                access_type: AccessType::Read,
                pid: 42,
                filetime: 99,
            }])),
        };

        let metadata = BaseContainerSandboxProcess::decode_and_write_denials(
            &analyzer,
            Path::new("ignored.etl"),
            &output_path,
            7,
        )
        .expect("decode succeeds");

        assert_eq!(metadata.kind, CaptureDenialsOutput::KIND);
        assert_eq!(metadata.exit_code, 7);
        assert_eq!(metadata.total_denials, 1);
        let document: DenialsDocument =
            serde_json::from_slice(&std::fs::read(output_path).unwrap()).unwrap();
        assert_eq!(document.denials.len(), 1);
    }

    #[test]
    fn injected_analyzer_writes_empty_document() {
        let directory = tempfile::tempdir().expect("temp directory");
        let output_path = directory.path().join("denials.json");
        let analyzer = FakeAnalyzer {
            result: Ok(AnalysisResult::complete(Vec::new())),
        };

        let metadata = BaseContainerSandboxProcess::decode_and_write_denials(
            &analyzer,
            Path::new("ignored.etl"),
            &output_path,
            0,
        )
        .expect("decode succeeds");

        assert_eq!(metadata.total_denials, 0);
        assert!(output_path.exists());
    }

    #[test]
    fn injected_analyzer_failure_leaves_no_output_file() {
        let directory = tempfile::tempdir().expect("temp directory");
        let etl_path = directory.path().join("capture.etl");
        let output_path = directory.path().join("denials.json");
        std::fs::write(&etl_path, b"fake etl").expect("seed ETL");
        let analyzer = FakeAnalyzer {
            result: Err("simulated decode failure"),
        };

        let error = BaseContainerSandboxProcess::decode_write_and_finalize(
            &analyzer,
            &etl_path,
            None,
            &output_path,
            0,
            false,
        )
        .expect_err("decode should fail");

        assert!(error.to_string().contains("simulated decode failure"));
        assert!(!etl_path.exists());
        assert!(!output_path.exists());
    }

    #[test]
    fn default_etl_cleanup_removes_file_after_success() {
        let directory = tempfile::tempdir().expect("temp directory");
        let etl_path = directory.path().join("capture.etl");
        let output_path = directory.path().join("denials.json");
        std::fs::write(&etl_path, b"fake etl").expect("seed ETL");
        let analyzer = FakeAnalyzer {
            result: Ok(AnalysisResult::complete(Vec::new())),
        };

        let metadata = BaseContainerSandboxProcess::decode_write_and_finalize(
            &analyzer,
            &etl_path,
            None,
            &output_path,
            0,
            false,
        )
        .expect("decode should succeed");

        assert!(metadata.etl_path.is_none());
        assert!(!etl_path.exists());
        assert!(output_path.exists());
    }

    #[test]
    fn default_etl_cleanup_removes_managed_directory() {
        let parent = tempfile::tempdir().expect("temp parent");
        let directory = parent.path().join("managed");
        std::fs::create_dir(&directory).expect("managed directory");
        let etl_path = directory.join("capture.etl");
        let output_path = parent.path().join("denials.json");
        std::fs::write(&etl_path, b"fake etl").expect("seed ETL");
        let analyzer = FakeAnalyzer {
            result: Ok(AnalysisResult::complete(Vec::new())),
        };

        BaseContainerSandboxProcess::decode_write_and_finalize(
            &analyzer,
            &etl_path,
            Some(&directory),
            &output_path,
            0,
            false,
        )
        .expect("decode should succeed");

        assert!(!directory.exists());
        assert!(output_path.exists());
    }

    #[test]
    fn requested_etl_retention_reports_path_and_preserves_file() {
        let directory = tempfile::tempdir().expect("temp directory");
        let etl_path = directory.path().join("capture.etl");
        let output_path = directory.path().join("denials.json");
        std::fs::write(&etl_path, b"fake etl").expect("seed ETL");
        let analyzer = FakeAnalyzer {
            result: Ok(AnalysisResult::complete(Vec::new())),
        };

        let metadata = BaseContainerSandboxProcess::decode_write_and_finalize(
            &analyzer,
            &etl_path,
            None,
            &output_path,
            0,
            true,
        )
        .expect("decode should succeed");

        assert_eq!(
            metadata.etl_path.as_deref(),
            Some(etl_path.to_string_lossy().as_ref())
        );
        assert!(etl_path.exists());
        assert!(output_path.exists());
    }

    #[test]
    fn requested_etl_retention_preserves_file_when_analysis_fails() {
        let directory = tempfile::tempdir().expect("temp directory");
        let etl_path = directory.path().join("capture.etl");
        let output_path = directory.path().join("denials.json");
        std::fs::write(&etl_path, b"fake etl").expect("seed ETL");
        let analyzer = FakeAnalyzer {
            result: Err("simulated decode failure"),
        };

        let error = BaseContainerSandboxProcess::decode_write_and_finalize(
            &analyzer,
            &etl_path,
            None,
            &output_path,
            0,
            true,
        )
        .expect_err("decode should fail");

        let message = error.to_string();
        assert!(message.contains("simulated decode failure"));
        assert!(message.contains("retained ETL file at"));
        assert!(message.contains(&etl_path.to_string_lossy().into_owned()));
        assert!(etl_path.exists());
        assert!(!output_path.exists());
    }

    #[test]
    fn requested_etl_retention_cleans_directory_when_seal_fails() {
        let parent = tempfile::tempdir().expect("temp parent");
        let directory = parent.path().join("managed");
        std::fs::create_dir(&directory).expect("managed directory");
        let etl_path = directory.join("capture.etl");

        let error = finalize_capture_seal_failure::<CaptureDenialsOutput>(
            std::io::Error::other("simulated seal failure"),
            Some(&etl_path),
            Some(&directory),
        )
        .expect_err("seal failure should propagate");

        assert!(error.to_string().contains("simulated seal failure"));
        assert!(!error.to_string().contains("retained ETL file at"));
        assert!(!directory.exists());
    }

    #[test]
    fn abandoned_capture_discards_without_sealing_output() {
        struct DiscardRecordingSession {
            discarded: Arc<std::sync::atomic::AtomicBool>,
        }

        impl CaptureSessionOps for DiscardRecordingSession {
            fn environment(&self) -> HANDLE {
                HANDLE(std::ptr::dangling_mut())
            }

            fn finish(
                self: Box<Self>,
                output_path: Option<&Path>,
            ) -> Result<(), learning_mode_windows::LearningModeError> {
                self.discarded
                    .store(output_path.is_none(), Ordering::SeqCst);
                Ok(())
            }
        }

        let parent = tempfile::tempdir().expect("temp parent");
        let directory = parent.path().join("managed");
        std::fs::create_dir(&directory).expect("managed directory");
        let managed_capture = ManagedCapturePath {
            etl_path: directory.join("capture.etl"),
            directory: directory.clone(),
            armed: true,
        };
        let discarded = Arc::new(std::sync::atomic::AtomicBool::new(false));

        discard_abandoned_capture(
            Box::new(DiscardRecordingSession {
                discarded: Arc::clone(&discarded),
            }),
            Some(managed_capture),
        )
        .expect("discard capture");

        assert!(discarded.load(Ordering::SeqCst));
        assert!(!directory.exists());
    }

    #[test]
    fn successful_process_reports_capture_teardown_failure() {
        let error =
            combine_process_and_teardown_results(Ok(0), Err(std::io::Error::other("seal failed")))
                .expect_err("capture failure must override successful process exit");

        assert!(error.to_string().contains("seal failed"));
    }

    #[test]
    fn wait_and_capture_failures_preserve_retained_etl_path() {
        let error = combine_process_and_teardown_results(
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "script timed out after 1000ms",
            )),
            Err(std::io::Error::other(
                r"decode failed; retained ETL file at C:\Temp\capture.etl",
            )),
        )
        .expect_err("both failures should be reported");

        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        let message = error.to_string();
        assert!(message.contains("script timed out after 1000ms"));
        assert!(message.contains("decode failed"));
        assert!(message.contains(r"C:\Temp\capture.etl"));
    }

    #[test]
    fn is_api_not_implemented_classifies_disabled_feature() {
        assert!(is_api_not_implemented(ERROR_CALL_NOT_IMPLEMENTED.0));
        assert!(is_api_not_implemented(E_NOTIMPL.0 as u32));
        // ERROR_NOT_SUPPORTED, ERROR_INVALID_PARAMETER, and success are not
        // globally classified as disabled-feature failures.
        assert!(!is_api_not_implemented(ERROR_NOT_SUPPORTED.0));
        assert!(!is_api_not_implemented(87));
        assert!(!is_api_not_implemented(0));
    }

    #[test]
    fn error_not_supported_is_backend_unavailable_only_for_proxy_fallback() {
        let mut proxy_request = ExecutionRequest {
            schema_version: "0.6.0-alpha".to_string(),
            ..Default::default()
        };
        proxy_request.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("127.0.0.1".to_string(), 8080)),
            builtin_test_server: false,
        };

        assert!(is_proxy_fallback_unavailable(
            ERROR_NOT_SUPPORTED.0,
            &proxy_request,
            false
        ));
        assert!(!is_proxy_fallback_unavailable(
            ERROR_NOT_SUPPORTED.0,
            &proxy_request,
            true
        ));

        proxy_request.schema_version = "0.7.0-alpha".to_string();
        assert!(is_proxy_fallback_unavailable(
            ERROR_NOT_SUPPORTED.0,
            &proxy_request,
            false
        ));

        let ordinary_request = ExecutionRequest::default();
        assert!(!is_proxy_fallback_unavailable(
            ERROR_NOT_SUPPORTED.0,
            &ordinary_request,
            false
        ));
    }

    #[test]
    fn learning_mode_api_not_implemented_checks_primary_failure() {
        use learning_mode_windows::LearningModeError;

        let disabled = LearningModeError::HResultCall {
            function: "StartLearningModeTrace",
            code: E_NOTIMPL.0,
        };
        assert!(learning_mode_api_not_implemented(&disabled));

        let ordinary = LearningModeError::HResultCall {
            function: "StartLearningModeTrace",
            code: windows::Win32::Foundation::E_INVALIDARG.0,
        };
        assert!(!learning_mode_api_not_implemented(&ordinary));

        assert!(learning_mode_api_not_implemented(
            &LearningModeError::ExportMissing {
                api: "Learning Mode trace",
                export: "StartLearningModeTrace",
                detail: "not found".to_string(),
            }
        ));
        assert!(learning_mode_api_not_implemented(
            &LearningModeError::DllLoad("missing processmodel.dll".to_string())
        ));
    }

    #[test]
    fn capture_factory_injects_begin_failure() {
        let factory = Arc::new(FakeCaptureFactory {
            begin_error: Some((
                "StartLearningModeTrace",
                windows::Win32::Foundation::E_FAIL.0,
            )),
            finish_error: None,
            begin_calls: AtomicUsize::new(0),
            finish_calls: Arc::new(AtomicUsize::new(0)),
        });
        let runner = BaseContainerRunner::with_capture_factory(factory.clone());

        let error = match runner
            .capture_factory
            .begin(&[], PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE)
        {
            Ok(_) => panic!("fake begin must fail"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("StartLearningModeTrace"));
        assert_eq!(factory.begin_calls.load(Ordering::SeqCst), 1);
        assert_eq!(factory.finish_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn capture_factory_injects_finish_failure_once() {
        let factory = Arc::new(FakeCaptureFactory {
            begin_error: None,
            finish_error: Some((
                "StopLearningModeTrace",
                windows::Win32::Foundation::E_FAIL.0,
            )),
            begin_calls: AtomicUsize::new(0),
            finish_calls: Arc::new(AtomicUsize::new(0)),
        });
        let runner = BaseContainerRunner::with_capture_factory(factory.clone());
        let session = runner
            .capture_factory
            .begin(&[], PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE)
            .expect("fake begin");

        let error = session.finish(None).expect_err("fake finish must fail");

        assert!(matches!(
            error,
            learning_mode_windows::LearningModeError::HResultCall {
                function: "StopLearningModeTrace",
                ..
            }
        ));
        assert_eq!(factory.begin_calls.load(Ordering::SeqCst), 1);
        assert_eq!(factory.finish_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn decode_create_capability_table() {
        let cap = SANDBOX_CAP_CREATE_PROCESS_IN_SANDBOX;
        assert!(!BaseContainerRunner::decode_create_capability(0, cap)); // FALSE return
        assert!(!BaseContainerRunner::decode_create_capability(1, 0)); // bit clear
        assert!(BaseContainerRunner::decode_create_capability(1, cap)); // enabled
        assert!(BaseContainerRunner::decode_create_capability(1, cap | 0x4)); // extra bits ok
    }

    #[test]
    fn decode_deny_capability_table() {
        // create bit alone does not imply deny support, and vice versa.
        let cap = SANDBOX_CAP_FS_DENY;
        assert!(!BaseContainerRunner::decode_deny_capability(0, cap)); // FALSE return
        assert!(!BaseContainerRunner::decode_deny_capability(1, 0)); // bit clear
        assert!(BaseContainerRunner::decode_deny_capability(1, cap)); // enabled
        assert!(!BaseContainerRunner::decode_deny_capability(
            1,
            SANDBOX_CAP_CREATE_PROCESS_IN_SANDBOX
        ));
        assert!(BaseContainerRunner::decode_deny_capability(
            1,
            cap | SANDBOX_CAP_CREATE_PROCESS_IN_SANDBOX
        ));
    }

    #[test]
    fn legacy_sbox_proxy_compatibility_uses_appcontainer_on_query_aware_hosts() {
        let mut request = ExecutionRequest::default();
        request.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("127.0.0.1".to_string(), 8080)),
            builtin_test_server: false,
        };

        assert!(BaseContainerRunner::legacy_sbox_compatible_with_request(
            &request, None
        ));
        assert!(!BaseContainerRunner::legacy_sbox_compatible_with_request(
            &request,
            Some(SANDBOX_CAP_CREATE_PROCESS_IN_SANDBOX)
        ));
        assert!(!BaseContainerRunner::legacy_sbox_compatible_with_request(
            &request,
            Some(SANDBOX_CAP_CREATE_PROCESS_IN_SANDBOX | SANDBOX_CAP_NETWORK_PROXY)
        ));
        assert_eq!(
            BaseContainerRunner::decode_sbox_proxy_contract(None),
            SboxProxyContract::LegacyOrUnknown
        );
        assert_eq!(
            BaseContainerRunner::decode_sbox_proxy_contract(Some(
                SANDBOX_CAP_CREATE_PROCESS_IN_SANDBOX
            )),
            SboxProxyContract::Unavailable
        );
        assert_eq!(
            BaseContainerRunner::decode_sbox_proxy_contract(Some(
                SANDBOX_CAP_CREATE_PROCESS_IN_SANDBOX | SANDBOX_CAP_NETWORK_PROXY
            )),
            SboxProxyContract::Model2PeerIdentity
        );
    }

    #[test]
    fn legacy_sbox_non_proxy_requests_ignore_proxy_contract_capability() {
        let request = ExecutionRequest::default();

        assert!(BaseContainerRunner::legacy_sbox_compatible_with_request(
            &request,
            Some(SANDBOX_CAP_CREATE_PROCESS_IN_SANDBOX | SANDBOX_CAP_NETWORK_PROXY)
        ));
    }

    #[test]
    fn build_sandbox_spec_produces_valid_flatbuffer() {
        let mut request = ExecutionRequest::default();
        request.policy.least_privilege_mode = true;
        request.policy.capabilities = vec!["internetClient".into(), "registryRead".into()];
        request.policy.readwrite_paths = vec!["C:\\temp".into()];
        request.policy.readonly_paths = vec!["C:\\Windows".into()];
        request.policy.denied_paths = vec!["C:\\secret".into()];

        let bytes = BaseContainerRunner::build_sandbox_spec(&request);

        // Verify the buffer has the SBOX identifier.
        assert!(base_container_layout::sandbox_spec_buffer_has_identifier(
            &bytes
        ));

        // Parse and verify field values.
        let spec = base_container_layout::root_as_sandbox_spec(&bytes)
            .expect("should be a valid SandboxSpec");
        assert_eq!(spec.version(), "0.1.0");
        assert!(spec.app_container());
        assert!(spec.least_privilege());
        assert_eq!(spec.capabilities(), Some("internetClient,registryRead"));
        assert!(spec.disallow_win32k_system_calls());
        // disable=true sets all non-IME restrictions; ime=false (default) adds IME
        assert_eq!(
            spec.ui_restrictions(),
            expected_mask(EffectiveUiRestrictions {
                block_clipboard_read: true,
                block_clipboard_write: true,
                block_input_injection: true,
                block_input_method_changes: true,
                block_external_ui_objects: true,
                block_global_ui_namespace: true,
                block_desktop_switching: true,
                block_logoff_or_shutdown: true,
                block_system_parameter_changes: true,
                block_display_settings_changes: true,
            })
        );

        let rw = spec.fs_read_write().unwrap();
        assert_eq!(rw.len(), 1);
        assert_eq!(rw.get(0), "C:\\temp");

        let ro = spec.fs_read_only().unwrap();
        assert_eq!(ro.len(), 1);
        assert_eq!(ro.get(0), "C:\\Windows");

        let deny = spec.fs_deny().unwrap();
        assert_eq!(deny.len(), 1);
        assert_eq!(deny.get(0), "C:\\secret");

        let network = spec.network_policy().expect("network_policy should be set");
        let egress = network.egress().expect("egress should be set");
        assert_eq!(
            egress.default_action(),
            base_container_layout::FilterAction::deny
        );
    }

    #[test]
    fn build_process_security_environment_spec_produces_valid_psec() {
        let mut request = ExecutionRequest::default();
        request.policy.capabilities = vec!["internetClient".into(), "registryRead".into()];
        request.policy.readwrite_paths = vec!["C:\\temp".into()];
        request.policy.readonly_paths = vec!["C:\\Windows".into()];
        request.policy.denied_paths = vec!["C:\\secret".into()];

        let bytes = BaseContainerRunner::build_process_security_environment_spec(&request);

        assert!(psec_layout::process_security_environment_buffer_has_identifier(&bytes));
        let spec = psec_layout::root_as_process_security_environment(&bytes).unwrap();
        let version = spec.version();
        assert_eq!(version.major(), 1);
        assert_eq!(version.minor(), 0);
        assert_eq!(spec.capabilities(), Some("internetClient,registryRead"));
        assert!(spec.disallow_win32k_system_calls());
        assert_eq!(
            spec.ui_restrictions(),
            expected_mask(EffectiveUiRestrictions {
                block_clipboard_read: true,
                block_clipboard_write: true,
                block_input_injection: true,
                block_input_method_changes: true,
                block_external_ui_objects: true,
                block_global_ui_namespace: true,
                block_desktop_switching: true,
                block_logoff_or_shutdown: true,
                block_system_parameter_changes: true,
                block_display_settings_changes: true,
            })
        );
        assert_eq!(
            spec.fs_read_write().unwrap().iter().collect::<Vec<_>>(),
            vec!["C:\\temp"]
        );
        assert_eq!(
            spec.fs_read_only().unwrap().iter().collect::<Vec<_>>(),
            vec!["C:\\Windows"]
        );
        assert_eq!(
            spec.fs_deny().unwrap().iter().collect::<Vec<_>>(),
            vec!["C:\\secret"]
        );
        let egress = spec
            .network_policy()
            .and_then(|policy| policy.egress())
            .expect("PSEC must carry an explicit egress default");
        assert_eq!(egress.default_action(), psec_layout::FilterAction::deny);
        assert!(egress.allow().is_none());
        assert!(egress.deny().is_none());
    }

    #[test]
    fn build_process_security_environment_spec_ignores_empty_capability() {
        let mut request = ExecutionRequest::default();
        request.policy.capabilities = vec![String::new()];
        request.policy.default_network_policy = NetworkPolicy::Allow;

        let bytes = BaseContainerRunner::build_process_security_environment_spec(&request);
        let spec = psec_layout::root_as_process_security_environment(&bytes).unwrap();

        assert_eq!(spec.capabilities(), Some("internetClient"));
    }

    #[test]
    fn build_process_security_environment_spec_preserves_allow_egress() {
        let mut request = ExecutionRequest::default();
        request.policy.default_network_policy = NetworkPolicy::Allow;

        let bytes = BaseContainerRunner::build_process_security_environment_spec(&request);
        let spec = psec_layout::root_as_process_security_environment(&bytes).unwrap();
        let egress = spec
            .network_policy()
            .and_then(|policy| policy.egress())
            .expect("PSEC must carry an explicit egress default");

        assert_eq!(egress.default_action(), psec_layout::FilterAction::allow);
        assert_eq!(spec.capabilities(), Some("internetClient"));
    }

    #[test]
    fn build_process_security_environment_spec_preserves_proxy_url() {
        let mut request = ExecutionRequest::default();
        request.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("127.0.0.1".to_string(), 8080)),
            builtin_test_server: false,
        };

        let bytes = BaseContainerRunner::build_process_security_environment_spec(&request);
        let spec = psec_layout::root_as_process_security_environment(&bytes).unwrap();
        let network = spec.network_policy().expect("network policy");
        assert_eq!(
            network.proxy().and_then(|proxy| proxy.url()),
            Some("http://127.0.0.1:8080")
        );
        assert!(network.egress().is_none());
    }

    #[test]
    fn process_security_environment_preference_is_schema_independent() {
        for version in ["", "0.6.0-alpha", "0.7.99", "0.8.0-alpha", "1.0.0"] {
            let request = ExecutionRequest {
                schema_version: version.to_string(),
                ..Default::default()
            };
            assert!(
                BaseContainerRunner::should_use_process_security_environment(&request, true, true),
                "PSEC should be preferred for schema version {version}"
            );
        }
    }

    #[test]
    fn psec_is_used_only_when_runtime_probe_succeeds() {
        let request = ExecutionRequest {
            schema_version: "0.6.0-alpha".to_string(),
            ..Default::default()
        };

        assert!(BaseContainerRunner::should_use_process_security_environment(&request, true, true));
        assert!(
            !BaseContainerRunner::should_use_process_security_environment(&request, false, true)
        );
    }

    #[test]
    fn proxy_uses_legacy_contract() {
        let mut request = ExecutionRequest::default();
        request.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("127.0.0.1".to_string(), 8080)),
            builtin_test_server: false,
        };

        let runner = BaseContainerRunner::with_capture_factory(fake_capture_factory());
        assert!(
            !BaseContainerRunner::should_use_process_security_environment(&request, true, true)
        );
        assert!(
            !runner.uses_process_security_environment(&request),
            "proxy requests must build the legacy SBOX contract"
        );
    }

    #[test]
    fn capture_proxy_uses_guarded_contract() {
        let _guard = crate::test_env::CaptureCapabilityGuard::set(true, true);
        let mut request = ExecutionRequest::default();
        request.policy.capture_denials = Some(Default::default());
        request.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("127.0.0.1".to_string(), 8080)),
            builtin_test_server: false,
        };
        let support = Arc::new(FakeCaptureSupport {
            api_error: None,
            deny_error: None,
            deny_supported: true,
            api_calls: AtomicUsize::new(0),
            learning_mode_api_calls: AtomicUsize::new(0),
            deny_calls: AtomicUsize::new(0),
        });
        let runner = BaseContainerRunner::with_capture_components(fake_capture_factory(), support);

        assert!(
            !runner.uses_process_security_environment(&request),
            "capture must not select PSEC when another requested policy is incompatible"
        );
        assert!(
            !BaseContainerRunner::uses_native_capture_for_request(&request),
            "dispatcher capability selection must reject policy-incompatible PSEC capture"
        );
    }

    #[test]
    fn least_privilege_uses_legacy_contract() {
        let mut request = ExecutionRequest::default();
        request.policy.least_privilege_mode = true;

        assert!(
            !BaseContainerRunner::should_use_process_security_environment(&request, true, true)
        );
    }

    #[test]
    fn denied_paths_use_legacy_contract_when_psec_lacks_support() {
        let mut request = ExecutionRequest::default();
        request.policy.denied_paths = vec![r"C:\secret".to_string()];

        assert!(
            !BaseContainerRunner::should_use_process_security_environment(&request, true, false)
        );
    }

    #[test]
    fn build_sandbox_spec_empty_policy() {
        // Default network policy is Block — no internetClient auto-add.
        let request = ExecutionRequest::default();
        let bytes = BaseContainerRunner::build_sandbox_spec(&request);

        assert!(base_container_layout::sandbox_spec_buffer_has_identifier(
            &bytes
        ));

        let spec = base_container_layout::root_as_sandbox_spec(&bytes).unwrap();
        assert_eq!(spec.version(), "0.1.0");
        assert!(spec.app_container());
        assert!(!spec.least_privilege());
        assert!(spec.capabilities().is_none());
        assert!(spec.fs_read_write().is_none());
        assert!(spec.fs_read_only().is_none());
        assert!(spec.fs_deny().is_none());
        assert!(spec.disallow_win32k_system_calls());
        let network = spec.network_policy().expect("network_policy should be set");
        let egress = network.egress().expect("egress should be set");
        assert_eq!(
            egress.default_action(),
            base_container_layout::FilterAction::deny
        );
    }

    #[test]
    fn build_sandbox_spec_network_block_no_internet_client() {
        let mut request = ExecutionRequest::default();
        request.policy.default_network_policy = NetworkPolicy::Block;

        let bytes = BaseContainerRunner::build_sandbox_spec(&request);
        let spec = base_container_layout::root_as_sandbox_spec(&bytes).unwrap();
        assert!(spec.capabilities().is_none());
        let network = spec.network_policy().expect("network_policy should be set");
        let egress = network.egress().expect("egress should be set");
        assert_eq!(
            egress.default_action(),
            base_container_layout::FilterAction::deny
        );
    }

    #[test]
    fn build_sandbox_spec_network_allow_sets_egress_default_action() {
        let mut request = ExecutionRequest::default();
        request.policy.default_network_policy = NetworkPolicy::Allow;

        let bytes = BaseContainerRunner::build_sandbox_spec(&request);
        let spec = base_container_layout::root_as_sandbox_spec(&bytes).unwrap();
        assert_eq!(spec.capabilities(), Some("internetClient"));
        let network = spec.network_policy().expect("network_policy should be set");
        let egress = network.egress().expect("egress should be set");
        assert_eq!(
            egress.default_action(),
            base_container_layout::FilterAction::allow
        );
    }

    #[test]
    fn build_sandbox_spec_ui_disabled() {
        let mut request = ExecutionRequest::default();
        request.policy.ui = UiPolicy {
            disable: true,
            ..Default::default()
        };

        let bytes = BaseContainerRunner::build_sandbox_spec(&request);
        let spec = base_container_layout::root_as_sandbox_spec(&bytes).unwrap();

        assert!(spec.disallow_win32k_system_calls());
        // disable=true sets all non-IME restrictions; ime=false (default) adds IME
        assert_eq!(
            spec.ui_restrictions(),
            expected_mask(EffectiveUiRestrictions {
                block_clipboard_read: true,
                block_clipboard_write: true,
                block_input_injection: true,
                block_input_method_changes: true,
                block_external_ui_objects: true,
                block_global_ui_namespace: true,
                block_desktop_switching: true,
                block_logoff_or_shutdown: true,
                block_system_parameter_changes: true,
                block_display_settings_changes: true,
            })
        );
    }

    #[test]
    fn build_sandbox_spec_ui_clipboard_read_only() {
        let mut request = ExecutionRequest::default();
        request.policy.ui = UiPolicy {
            disable: false,
            clipboard: ClipboardPolicy::Read,
            injection: true,
        };

        let bytes = BaseContainerRunner::build_sandbox_spec(&request);
        let spec = base_container_layout::root_as_sandbox_spec(&bytes).unwrap();

        assert!(!spec.disallow_win32k_system_calls());
        // WRITECLIPBOARD + backend defaults (isolation=container: HANDLES+GLOBALATOMS,
        // desktopSystemControl=false: DESKTOP+EXITWINDOWS, systemSettings=none: SYSTEMPARAMETERS+DISPLAYSETTINGS, ime=false: IME)
        assert_eq!(
            spec.ui_restrictions(),
            expected_mask(EffectiveUiRestrictions {
                block_clipboard_write: true,
                block_external_ui_objects: true,
                block_global_ui_namespace: true,
                block_desktop_switching: true,
                block_logoff_or_shutdown: true,
                block_system_parameter_changes: true,
                block_display_settings_changes: true,
                block_input_method_changes: true,
                ..Default::default()
            })
        );
    }

    #[test]
    fn build_sandbox_spec_ui_clipboard_readwrite_no_injection() {
        let mut request = ExecutionRequest::default();
        request.policy.ui = UiPolicy {
            disable: false,
            clipboard: ClipboardPolicy::All,
            injection: false,
        };

        let bytes = BaseContainerRunner::build_sandbox_spec(&request);
        let spec = base_container_layout::root_as_sandbox_spec(&bytes).unwrap();

        assert!(!spec.disallow_win32k_system_calls());
        // INJECTION + backend defaults
        assert_eq!(
            spec.ui_restrictions(),
            expected_mask(EffectiveUiRestrictions {
                block_input_injection: true,
                block_external_ui_objects: true,
                block_global_ui_namespace: true,
                block_desktop_switching: true,
                block_logoff_or_shutdown: true,
                block_system_parameter_changes: true,
                block_display_settings_changes: true,
                block_input_method_changes: true,
                ..Default::default()
            })
        );
    }

    #[test]
    fn build_sandbox_spec_proxy_url() {
        use wxc_common::models::ProxyAddress;

        let mut request = ExecutionRequest::default();
        request.policy.default_network_policy = NetworkPolicy::Allow;
        request.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("127.0.0.1".to_string(), 8080)),
            builtin_test_server: false,
        };

        let bytes = BaseContainerRunner::build_sandbox_spec(&request);
        let spec = base_container_layout::root_as_sandbox_spec(&bytes).unwrap();

        let net = spec.network_policy().expect("network_policy should be set");
        let proxy = net.proxy().expect("proxy should be set");
        assert_eq!(proxy.url(), Some("http://127.0.0.1:8080"));
        assert!(net.egress().is_none());
    }

    #[test]
    fn build_sandbox_spec_no_proxy() {
        let request = ExecutionRequest::default();
        let bytes = BaseContainerRunner::build_sandbox_spec(&request);
        let spec = base_container_layout::root_as_sandbox_spec(&bytes).unwrap();
        let network = spec.network_policy().expect("network_policy should be set");
        assert!(network.proxy().is_none());
        let egress = network.egress().expect("egress should be set");
        assert_eq!(
            egress.default_action(),
            base_container_layout::FilterAction::deny
        );
    }

    // ---- validate_runner: unsupported policy fields surface as errors. ----

    use wxc_common::sandbox_process::SandboxBackend;

    #[test]
    fn validate_runner_accepts_denied_paths_when_supported() {
        let _guard = crate::test_env::DenyPathsGuard::supported(true);
        let runner = BaseContainerRunner::new();
        let mut request = ExecutionRequest::default();
        request.policy.denied_paths = vec!["C:\\secret".into()];

        // May still fail if the BaseContainer API is unavailable, but not for deny.
        if let Err(err) = runner.validate(&request) {
            assert!(
                !err.error_message.contains("deniedPaths")
                    && !err.error_message.contains("SANDBOX_CAP_FS_DENY"),
                "deniedPaths should not be rejected when supported, got: {}",
                err.error_message
            );
        }
    }

    #[test]
    fn validate_runner_rejects_denied_paths_when_unsupported() {
        let _guard = crate::test_env::DenyPathsGuard::supported(false);
        let support = Arc::new(FakeCaptureSupport {
            api_error: None,
            deny_error: None,
            deny_supported: false,
            api_calls: AtomicUsize::new(0),
            learning_mode_api_calls: AtomicUsize::new(0),
            deny_calls: AtomicUsize::new(0),
        });
        let runner = BaseContainerRunner::with_capture_components(fake_capture_factory(), support);
        let mut request = ExecutionRequest::default();
        request.policy.denied_paths = vec!["C:\\secret".into()];

        let err = runner
            .validate(&request)
            .expect_err("deniedPaths must be rejected when the capability is unavailable");
        assert!(
            err.error_message.contains("SANDBOX_CAP_FS_DENY"),
            "expected the capability-gate message, got: {}",
            err.error_message
        );
    }

    #[test]
    fn validate_runner_rejects_allowed_hosts() {
        let runner = BaseContainerRunner::new();
        let mut request = ExecutionRequest {
            dry_run: true,
            ..Default::default()
        };
        request.policy.allowed_hosts = vec!["example.com".into()];

        let err = runner
            .validate(&request)
            .expect_err("allowedHosts is not yet supported");
        assert!(err.error_message.contains("allowedHosts"));
    }

    #[test]
    fn validate_runner_rejects_blocked_hosts() {
        let runner = BaseContainerRunner::new();
        let mut request = ExecutionRequest {
            dry_run: true,
            ..Default::default()
        };
        request.policy.blocked_hosts = vec!["bad.example.com".into()];

        let err = runner
            .validate(&request)
            .expect_err("blockedHosts is not yet supported");
        assert!(err.error_message.contains("blockedHosts"));
    }

    #[test]
    fn validate_runner_accepts_empty_policy() {
        let runner = BaseContainerRunner::new();
        let request = ExecutionRequest::default();
        // validate_runner may still surface the host-API-unavailable error on
        // dev machines where BaseContainer isn't present; we only assert that
        // the policy-field checks above don't fire. Skip when the host doesn't
        // expose the API.
        if BaseContainerRunner::is_base_container_api_present().is_ok() {
            assert!(runner.validate(&request).is_ok());
        }
    }

    #[test]
    fn capture_denied_paths_error_names_v2_capability() {
        assert!(
            PSEC_DENIED_PATHS_UNSUPPORTED_MSG.contains("QueryProcessSecurityEnvironmentSupport")
        );
        assert!(PSEC_DENIED_PATHS_UNSUPPORTED_MSG.contains("PSE_SUPPORT_FS_DENY"));
        assert!(!PSEC_DENIED_PATHS_UNSUPPORTED_MSG.contains("Experimental_QuerySandboxSupport"));
        assert!(PSEC_DENIED_PATHS_UNSUPPORTED_MSG.contains("cannot fall back to AppContainer"));
    }

    #[test]
    fn capture_validation_requires_guarded_fallback_when_v2_api_is_unavailable() {
        let _guard = crate::test_env::lock();
        let factory = fake_capture_factory();
        let support = Arc::new(FakeCaptureSupport {
            api_error: Some("missing CloseLearningModeTrace"),
            deny_error: None,
            deny_supported: true,
            api_calls: AtomicUsize::new(0),
            learning_mode_api_calls: AtomicUsize::new(0),
            deny_calls: AtomicUsize::new(0),
        });
        let runner = BaseContainerRunner::with_capture_components(factory.clone(), support.clone());

        let error = runner
            .validate(&capture_request_with_denied_path())
            .expect_err("missing V2 API must fail closed");

        assert_eq!(error.failure_phase, FailurePhase::BackendUnavailable);
        assert!(error.error_message.contains("guarded-WPR fallback"));
        assert_eq!(support.api_calls.load(Ordering::SeqCst), 1);
        assert_eq!(support.learning_mode_api_calls.load(Ordering::SeqCst), 1);
        assert_eq!(support.deny_calls.load(Ordering::SeqCst), 0);
        assert_eq!(factory.begin_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn capture_validation_requires_guarded_fallback_when_native_deny_query_fails() {
        let _guard = crate::test_env::lock();
        let factory = fake_capture_factory();
        let support = Arc::new(FakeCaptureSupport {
            api_error: None,
            deny_error: Some("query failed"),
            deny_supported: false,
            api_calls: AtomicUsize::new(0),
            learning_mode_api_calls: AtomicUsize::new(0),
            deny_calls: AtomicUsize::new(0),
        });
        let runner = BaseContainerRunner::with_capture_components(factory.clone(), support.clone());

        let error = runner
            .validate(&capture_request_with_denied_path())
            .expect_err("deny query failure must fail closed");

        assert_eq!(error.failure_phase, FailurePhase::BackendUnavailable);
        assert!(error.error_message.contains("guarded-WPR fallback"));
        assert_eq!(support.api_calls.load(Ordering::SeqCst), 1);
        assert_eq!(support.deny_calls.load(Ordering::SeqCst), 1);
        assert_eq!(factory.begin_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn capture_validation_requires_guarded_fallback_when_native_deny_bit_is_clear() {
        let _guard = crate::test_env::lock();
        let factory = fake_capture_factory();
        let support = Arc::new(FakeCaptureSupport {
            api_error: None,
            deny_error: None,
            deny_supported: false,
            api_calls: AtomicUsize::new(0),
            learning_mode_api_calls: AtomicUsize::new(0),
            deny_calls: AtomicUsize::new(0),
        });
        let runner = BaseContainerRunner::with_capture_components(factory.clone(), support.clone());

        let error = runner
            .validate(&capture_request_with_denied_path())
            .expect_err("missing deny support bit must fail closed");

        assert_eq!(error.failure_phase, FailurePhase::BackendUnavailable);
        assert!(error.error_message.contains("guarded-WPR fallback"));
        assert_eq!(support.api_calls.load(Ordering::SeqCst), 1);
        assert_eq!(support.deny_calls.load(Ordering::SeqCst), 1);
        assert_eq!(factory.begin_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn psec_without_capture_requires_only_security_environment_api() {
        let factory = fake_capture_factory();
        let support = Arc::new(FakeCaptureSupport {
            api_error: None,
            deny_error: None,
            deny_supported: true,
            api_calls: AtomicUsize::new(0),
            learning_mode_api_calls: AtomicUsize::new(0),
            deny_calls: AtomicUsize::new(0),
        });
        let runner = BaseContainerRunner::with_capture_components(factory.clone(), support.clone());
        let request = ExecutionRequest {
            schema_version: "0.6.0-alpha".to_string(),
            ..Default::default()
        };

        runner
            .validate(&request)
            .expect("PSEC requires the security-environment API but not Learning Mode");

        assert_eq!(support.api_calls.load(Ordering::SeqCst), 1);
        assert_eq!(support.learning_mode_api_calls.load(Ordering::SeqCst), 0);
        assert_eq!(support.deny_calls.load(Ordering::SeqCst), 0);
        assert_eq!(factory.begin_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn psec_dry_run_skips_host_api_probes() {
        let factory = fake_capture_factory();
        let support = Arc::new(FakeCaptureSupport {
            api_error: Some("V2 exports unavailable"),
            deny_error: Some("deny support query unavailable"),
            deny_supported: false,
            api_calls: AtomicUsize::new(0),
            learning_mode_api_calls: AtomicUsize::new(0),
            deny_calls: AtomicUsize::new(0),
        });
        let runner = BaseContainerRunner::with_capture_components(factory.clone(), support.clone());
        let mut request = ExecutionRequest {
            schema_version: "0.6.0-alpha".to_string(),
            dry_run: true,
            ..Default::default()
        };
        request.policy.capture_denials = Some(Default::default());
        request.policy.denied_paths = vec![r"C:\secret".to_string()];

        runner
            .validate(&request)
            .expect("dry-run should validate policy without probing host APIs");

        assert_eq!(support.api_calls.load(Ordering::SeqCst), 0);
        assert_eq!(support.learning_mode_api_calls.load(Ordering::SeqCst), 0);
        assert_eq!(support.deny_calls.load(Ordering::SeqCst), 0);
        assert_eq!(factory.begin_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn validate_runner_allows_least_privilege_via_legacy_contract() {
        let runner = BaseContainerRunner::with_capture_factory(fake_capture_factory());
        let mut request = ExecutionRequest {
            dry_run: true,
            ..Default::default()
        };
        request.policy.least_privilege_mode = true;

        runner
            .validate(&request)
            .expect("leastPrivilege should route through the legacy SBOX contract");
    }

    #[test]
    fn validate_runner_allows_proxy_via_legacy_contract() {
        let runner = BaseContainerRunner::with_capture_factory(fake_capture_factory());
        let mut request = ExecutionRequest {
            dry_run: true,
            ..Default::default()
        };
        request.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("127.0.0.1".to_string(), 8080)),
            builtin_test_server: false,
        };

        runner
            .validate(&request)
            .expect("network.proxy should route through the legacy SBOX contract");
    }

    #[test]
    fn validate_runner_allows_capture_denials_on_older_schema() {
        let factory = fake_capture_factory();
        let support = Arc::new(FakeCaptureSupport {
            api_error: None,
            deny_error: None,
            deny_supported: true,
            api_calls: AtomicUsize::new(0),
            learning_mode_api_calls: AtomicUsize::new(0),
            deny_calls: AtomicUsize::new(0),
        });
        let runner = BaseContainerRunner::with_capture_components(factory.clone(), support.clone());
        let mut request = ExecutionRequest {
            schema_version: "0.7.0-alpha".to_string(),
            dry_run: true,
            ..Default::default()
        };
        request.policy.capture_denials = Some(Default::default());

        runner
            .validate(&request)
            .expect("captureDenials should use PSEC regardless of schema version");
        assert_eq!(support.api_calls.load(Ordering::SeqCst), 0);
        assert_eq!(support.learning_mode_api_calls.load(Ordering::SeqCst), 0);
        assert_eq!(factory.begin_calls.load(Ordering::SeqCst), 0);
    }

    // ETL-retention capability validation (the retainEtl gate, including the
    // BaseContainer native-PSEC exception) is exercised as a consolidated
    // matrix in `crate::guarded_capture`'s tests, so it is not duplicated here.
}
