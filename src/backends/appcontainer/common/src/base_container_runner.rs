// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `BaseContainerRunner` — executes scripts via `Experimental_CreateProcessInSandbox` API.
//!
//! When `wxc-exec` receives a config with `schema_version` >= 0.5, this runner:
//! 1. Builds a FlatBuffer `SandboxSpec` from the container policy
//! 2. Loads `processmodel.dll` dynamically
//! 3. Calls `Experimental_CreateProcessInSandbox` to launch the child process
//! 4. Waits for the process to exit and returns the result

use std::ffi::c_void;
use std::fmt::Write;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Arc;

use learning_mode_core::{
    write_document, DenialAnalyzer, DenialSummary, DenialsDocument, DenialsOutputPointer,
};
use learning_mode_windows::{
    CaptureSession, EtlDenialAnalyzer, LearningModeApi, SecurityEnvironmentApi,
    SecurityEnvironmentStartupInfo, PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE,
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

use crate::job_object::UiJobObject;
use crate::launch_diagnostics::{
    diagnose_create_process_failure, diagnose_environment_not_supported, diagnose_process_exit,
    is_environment_not_supported,
};
use crate::proxy_coordinator::ProxyCoordinator;
use crate::sandbox_tracking::{self, TrackingEntry};
use process_security_environment_spec::process_security_environment_layout::{
    finish_process_security_environment_buffer, NetworkPolicy as PsecNetworkPolicy,
    NetworkPolicyArgs as PsecNetworkPolicyArgs, ProcessSecurityEnvironment,
    ProcessSecurityEnvironmentArgs, ProxyInfo as PsecProxyInfo, ProxyInfoArgs as PsecProxyInfoArgs,
    SchemaVersion,
};
use sandbox_spec::base_container_layout::{
    finish_sandbox_spec_buffer, proxy_info, proxy_infoArgs, IntegrityLevel,
    NetworkPolicy as FbsNetworkPolicy, NetworkPolicyArgs, SandboxSpec, SandboxSpecArgs,
};
use wxc_common::log_symbols::{
    EMOJI_ALLOWED, EMOJI_BLOCKED, EMOJI_NEUTRAL, EMOJI_SECTION, EMOJI_WARNING,
};
use wxc_common::logger::Logger;
use wxc_common::models::{
    CaptureDenialsOutput, ExecutionRequest, FailurePhase, NetworkEnforcementMode, NetworkPolicy,
    ProxyAddress, SandboxOutputMetadata, ScriptResponse,
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

fn create_string_vector<'a>(
    builder: &mut flatbuffers::FlatBufferBuilder<'a>,
    values: &'a [String],
) -> Option<flatbuffers::WIPOffset<flatbuffers::Vector<'a, flatbuffers::ForwardsUOffset<&'a str>>>>
{
    if values.is_empty() {
        return None;
    }
    let offsets: Vec<_> = values
        .iter()
        .map(|value| builder.create_string(value))
        .collect();
    Some(builder.create_vector(&offsets))
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
const CAPTURE_API_AVAILABLE_LOG: &str =
    "captureDenials: learning-mode trace API available (processmodel.dll)";
const CREATE_PROCESS_IN_SANDBOX_API: &str = "Experimental_CreateProcessInSandbox";
const CREATE_PROCESS_IN_SECURITY_ENVIRONMENT_API: &str =
    "CreateProcessW(PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT)";

/// True when a Win32 error code signals the BaseContainer feature is not
/// enabled on this build (symbol present, capability gated off).
fn is_api_not_implemented(err: u32) -> bool {
    err == ERROR_CALL_NOT_IMPLEMENTED.0 || err == E_NOTIMPL.0 as u32
}

fn learning_mode_api_not_implemented(error: &learning_mode_windows::LearningModeError) -> bool {
    match error {
        learning_mode_windows::LearningModeError::DllLoad(_)
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

/// Script runner that uses `Experimental_CreateProcessInSandbox` API
/// to launch a sandboxed process.
pub struct BaseContainerRunner {
    proxy_coordinator: ProxyCoordinator,
    capture_factory: Arc<dyn CaptureSessionFactory>,
}

impl Default for BaseContainerRunner {
    fn default() -> Self {
        Self {
            proxy_coordinator: ProxyCoordinator::default(),
            capture_factory: Arc::new(RealCaptureSessionFactory),
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

impl BaseContainerRunner {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    fn with_capture_factory(capture_factory: Arc<dyn CaptureSessionFactory>) -> Self {
        Self {
            proxy_coordinator: ProxyCoordinator::default(),
            capture_factory,
        }
    }

    fn cleanup_capture_prelaunch_failure(
        &mut self,
        request: &ExecutionRequest,
        sid_string: &str,
        logger: &mut Logger,
    ) {
        // This cannot be deferred to BaseContainerRunner::drop: the runner may
        // outlive a failed spawn.
        if request.lifecycle.destroy_on_exit {
            // CaptureSession::begin receives the sandbox specification, not
            // the later process identity. Its infallible environment close
            // leaves only the pre-launch tracking entry to remove.
            sandbox_tracking::remove_tracking_entry(sid_string, logger);
            sandbox_tracking::unregister_ctrl_c_cleanup();
        }
        self.proxy_coordinator.stop(logger);
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
    /// 1. `Experimental_QuerySandboxSupport`, when present, is authoritative.
    /// 2. Otherwise, probe the create API itself (older builds lack the query).
    /// 3. If even the create symbol is absent, the OS is down-level.
    pub fn is_base_container_usable() -> bool {
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
        let Some(query) = Self::load_query_sandbox_support() else {
            return false;
        };
        let mut capabilities: u64 = 0;
        // SAFETY: `query` is the resolved export; `capabilities` is a valid
        // out-param.
        let succeeded = unsafe { query(&mut capabilities) };
        Self::decode_deny_capability(succeeded, capabilities)
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
        Some(Self::decode_create_capability(ok, capabilities))
    }

    /// Decode a `QuerySandboxSupport` result: the create-process capability is
    /// present only when the call succeeded (`ok != 0`) and the bit is set.
    fn decode_create_capability(ok: i32, capabilities: u64) -> bool {
        ok != 0 && (capabilities & SANDBOX_CAP_CREATE_PROCESS_IN_SANDBOX) != 0
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
    /// - `network_policy.proxy.url` from proxy config
    fn build_sandbox_spec(request: &ExecutionRequest) -> Vec<u8> {
        let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);

        let version = builder.create_string(SANDBOX_SPEC_VERSION);

        let caps = Self::effective_capabilities(request);
        let capabilities = if caps.is_empty() {
            None
        } else {
            Some(builder.create_string(&caps.join(",")))
        };

        let fs_read_write = if request.policy.readwrite_paths.is_empty() {
            None
        } else {
            let offsets: Vec<_> = request
                .policy
                .readwrite_paths
                .iter()
                .map(|s| builder.create_string(s))
                .collect();
            Some(builder.create_vector(&offsets))
        };

        let fs_read_only = if request.policy.readonly_paths.is_empty() {
            None
        } else {
            let offsets: Vec<_> = request
                .policy
                .readonly_paths
                .iter()
                .map(|s| builder.create_string(s))
                .collect();
            Some(builder.create_vector(&offsets))
        };

        let fs_deny = if request.policy.denied_paths.is_empty() {
            None
        } else {
            let offsets: Vec<_> = request
                .policy
                .denied_paths
                .iter()
                .map(|s| builder.create_string(s))
                .collect();
            Some(builder.create_vector(&offsets))
        };

        // Build NetworkPolicy with proxy URL if configured
        let network_policy = if request.policy.network_proxy.is_enabled() {
            let proxy_url = request
                .policy
                .network_proxy
                .address
                .as_ref()
                .map(|addr| addr.to_url());

            let proxy = if let Some(url) = &proxy_url {
                let url_offset = builder.create_string(url);
                Some(proxy_info::create(
                    &mut builder,
                    &proxy_infoArgs {
                        url: Some(url_offset),
                    },
                ))
            } else {
                None
            };

            Some(FbsNetworkPolicy::create(
                &mut builder,
                &NetworkPolicyArgs { proxy },
            ))
        } else {
            None
        };

        // UI restrictions
        let ui_restrictions = crate::job_object::to_job_object_uilimit_mask(
            &wxc_common::ui_policy::resolve_ui_restrictions(
                &request.policy.ui,
                &request.policy.base_process_ui,
            ),
        ) as u64;

        let spec = SandboxSpec::create(
            &mut builder,
            &SandboxSpecArgs {
                version: Some(version),
                app_container: true,
                disallow_win32k_system_calls: request.policy.ui.disable,
                ui_restrictions,
                least_privilege: request.policy.least_privilege_mode,
                capabilities,
                fs_read_write,
                fs_read_only,
                fs_deny,
                network_policy,
                ..Default::default()
            },
        );

        finish_sandbox_spec_buffer(&mut builder, spec);
        builder.finished_data().to_vec()
    }

    fn effective_capabilities(request: &ExecutionRequest) -> Vec<String> {
        // Match legacy AppContainer behaviour: when network enforcement uses
        // capabilities and the default policy is Allow, ensure internetClient
        // is present so the sandboxed process has network access.
        let mut caps = request.policy.capabilities.clone();
        let use_caps_for_network = matches!(
            request.policy.network_enforcement_mode,
            NetworkEnforcementMode::Capabilities | NetworkEnforcementMode::Both
        );
        if use_caps_for_network
            && request.policy.default_network_policy == NetworkPolicy::Allow
            && !caps.iter().any(|c| c == "internetClient")
        {
            caps.push("internetClient".to_string());
        }
        caps
    }

    /// Build the PSEC 1.0 FlatBuffer consumed by
    /// `CreateProcessSecurityEnvironment`.
    fn build_process_security_environment_spec(request: &ExecutionRequest) -> Vec<u8> {
        let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);
        let version = SchemaVersion::new(1, 0);

        let caps = Self::effective_capabilities(request);
        let capabilities = if caps.is_empty() {
            None
        } else {
            Some(builder.create_string(&caps.join(",")))
        };

        let fs_read_write = create_string_vector(&mut builder, &request.policy.readwrite_paths);
        let fs_read_only = create_string_vector(&mut builder, &request.policy.readonly_paths);
        let fs_deny = create_string_vector(&mut builder, &request.policy.denied_paths);

        let network_policy = if request.policy.network_proxy.is_enabled() {
            let proxy = request
                .policy
                .network_proxy
                .address
                .as_ref()
                .map(|address| {
                    let url = builder.create_string(&address.to_url());
                    PsecProxyInfo::create(&mut builder, &PsecProxyInfoArgs { url: Some(url) })
                });
            Some(PsecNetworkPolicy::create(
                &mut builder,
                &PsecNetworkPolicyArgs {
                    proxy,
                    ..Default::default()
                },
            ))
        } else {
            None
        };

        let ui_restrictions = crate::job_object::to_job_object_uilimit_mask(
            &wxc_common::ui_policy::resolve_ui_restrictions(
                &request.policy.ui,
                &request.policy.base_process_ui,
            ),
        ) as u64;

        let spec = ProcessSecurityEnvironment::create(
            &mut builder,
            &ProcessSecurityEnvironmentArgs {
                version: Some(&version),
                capabilities,
                disallow_win32k_system_calls: request.policy.ui.disable,
                ui_restrictions,
                fs_read_write,
                fs_read_only,
                fs_deny,
                network_policy,
            },
        );
        finish_process_security_environment_buffer(&mut builder, spec);
        builder.finished_data().to_vec()
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

        // 1. Build the FlatBuffer sandbox spec from the request policy.
        let spec_bytes = Self::build_sandbox_spec(&request);

        Self::log_sandbox_spec(&spec_bytes, logger);

        let capture_denials = request.policy.capture_denials.clone();
        if capture_denials.is_some() {
            let _ = writeln!(logger, "{EMOJI_SECTION} SECTION: captureDenials");
        }

        let capture_spec_bytes = capture_denials
            .as_ref()
            .map(|_| Self::build_process_security_environment_spec(&request));
        if let Some(capture_spec) = capture_spec_bytes.as_ref() {
            let _ = writeln!(
                logger,
                "process security environment spec built (PSEC 1.0, {} bytes)",
                capture_spec.len()
            );
        }

        // Resolve two paths for the capture:
        //   * `capture_etl_path` — an always-internal, runner-managed temp `.etl`
        //     that the OS broker seals into. It is decoded then deleted in
        //     `run_teardown`; callers never see it.
        //   * `capture_output_path` — the JSON denials deliverable that consuming
        //     apps read: caller-specified via `captureDenials.outputPath` when
        //     provided, else a managed per-run temp `.json` file.
        let (capture_etl_path, capture_output_path) =
            if let Some(capture_config) = capture_denials.as_ref() {
                (
                    Some(managed_capture_output_path()?),
                    Some(unique_denials_output_path(
                        capture_config.output_path.as_deref(),
                    )?),
                )
            } else {
                (None, None)
            };

        let _ = writeln!(logger, "{EMOJI_SECTION} SECTION: Load API");

        // 2. Dynamically load the API from processmodel.dll.
        let create_process_in_sandbox = match Self::load_api() {
            Ok(f) => f,
            Err(e) => return Err(ScriptResponse::error(&e)),
        };
        let _ = writeln!(
            logger,
            "loaded Experimental_CreateProcessInSandbox from processmodel.dll"
        );

        let _ = writeln!(logger, "{EMOJI_SECTION} SECTION: Launch process");

        // 3. Build the command line (passed directly, same as AppContainerScriptRunner).
        let mut cmd_wide = string_util::to_wide(&request.script_code);

        // Working directory (NULL falls back to the current directory).
        let cwd_wide;
        let cwd_ptr = if request.working_directory.is_empty() {
            ptr::null()
        } else {
            cwd_wide = string_util::to_wide(&request.working_directory);
            cwd_wide.as_ptr()
        };

        // Identity: when destroy_on_exit is true we generate a random ephemeral
        // identity so each sandbox gets a unique, cleanable AppContainer profile.
        // Otherwise we honour whatever the caller passed in (or the default).
        let (identity, sid_string) = if request.lifecycle.destroy_on_exit {
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
        if request.lifecycle.destroy_on_exit {
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
            if capture_denials.is_some() {
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
        // resumed right after the assignment. If the sandbox create API ignores
        // CREATE_SUSPENDED on a given build, the child starts running anyway and
        // the later resume is a harmless no-op.
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

        // Pre-launch check: abort if policy paths are on ReFS (Dev Drive) volumes
        // where BFS cannot enforce filesystem policy.
        if let Some(diag) = crate::launch_diagnostics::check_refs_volumes(
            &request.policy.readonly_paths,
            &request.policy.readwrite_paths,
        ) {
            let _ = writeln!(
                logger,
                "Error: Pre-launch diagnostic [{}]: {}",
                diag.kind, diag.message
            );
            return Err(ScriptResponse {
                exit_code: -1,
                error_message: diag.message.clone(),
                standard_err: diag.message,
                failure_phase: FailurePhase::LaunchFailed,
                ..Default::default()
            });
        }

        // 4. Call Experimental_CreateProcessInSandbox.
        //    If the OS returns ERROR_NOT_SUPPORTED (0x32) and we passed a non-null
        //    environment block, this is a downlevel build that doesn't support the
        //    `environment` parameter. Retry once without it.
        let current_env_ptr = env_ptr;
        let current_creation_flags = creation_flags;

        // When captureDenials is active, launch inside a process security
        // environment that already has a learning-mode trace started against it,
        // instead of the one-shot CreateProcessInSandbox. `begin` creates the
        // environment and starts the trace *before* the child launches (so no
        // early denials are missed); the environment handle is attached to a
        // normal CreateProcessW call via PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT.
        // On any early return below, `capture_session` drops and its Drop
        // discards the trace and closes the environment (no broker leak).
        let mut capture_session: Option<Box<dyn CaptureSessionOps>> = None;
        if capture_denials.is_some() {
            let capture_spec = capture_spec_bytes
                .as_deref()
                .expect("capture spec is initialized with captureDenials");
            match self
                .capture_factory
                .begin(capture_spec, PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE)
            {
                Ok(session) => {
                    let _ = writeln!(
                        logger,
                        "{CAPTURE_API_AVAILABLE_LOG}; security environment and trace started"
                    );
                    capture_session = Some(session);
                }
                Err(e) => {
                    let msg = format!("captureDenials: failed to start learning-mode capture: {e}");
                    let _ = writeln!(logger, "Error: {msg}");
                    let failure_phase = if learning_mode_api_not_implemented(&e) {
                        FailurePhase::BackendUnavailable
                    } else {
                        FailurePhase::LaunchFailed
                    };
                    self.cleanup_capture_prelaunch_failure(&request, &sid_string, logger);
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

        // The launch yields (api_return_code, last_win32_error_on_failure).
        let (success, last_error, launch_api_name) = if let Some(session) = capture_session.as_ref()
        {
            // Single-attempt in-environment launch. The learning-mode security
            // environment is attached as a process-thread attribute; the
            // CreateProcessInSandbox environment fallback does not apply here.
            pi = unsafe { std::mem::zeroed() };
            let inherited_handles = if pipe_mode {
                vec![h_stdin, h_stdout, h_stderr]
            } else {
                Vec::new()
            };
            let extended_startup = match SecurityEnvironmentStartupInfo::new(
                si,
                session.environment(),
                &inherited_handles,
            ) {
                Ok(startup) => startup,
                Err(primary) => {
                    let cleanup_error = capture_session
                        .take()
                        .map(|session| session.finish(None))
                        .unwrap_or(Ok(()))
                        .err();
                    let mut msg = format!(
                        "captureDenials: failed to attach the process security environment: {primary}"
                    );
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
                    self.cleanup_capture_prelaunch_failure(&request, &sid_string, logger);
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
            let (success, error) = SandboxLaunchArgs {
                api: create_process_in_sandbox,
                command_line: &mut cmd_wide,
                current_directory: cwd_ptr,
                startup_info: &si,
                identity: &identity_wide,
                sandbox_specification: &spec_bytes,
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
            if capture_denials.is_some() {
                self.cleanup_capture_prelaunch_failure(&request, &sid_string, logger);
            } else if request.lifecycle.destroy_on_exit {
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

            let mut extended_error = format!("{launch_api_name} failed: {err:?}");
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
            let failure_phase = if is_api_not_implemented(err.0) {
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
        // If the create API ignores CREATE_SUSPENDED on a given build the child
        // is already running; it is a shell that has not yet run the user
        // command, so the pre-assignment window is empty in practice and the
        // later resume is a harmless no-op.
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
                if capture_denials.is_some() {
                    self.cleanup_capture_prelaunch_failure(&request, &sid_string, logger);
                } else if request.lifecycle.destroy_on_exit {
                    run_sandbox_cleanup(
                        &identity,
                        &sid_string,
                        request.policy.network_proxy.is_enabled(),
                        logger,
                    );
                    sandbox_tracking::unregister_ctrl_c_cleanup();
                }
                if capture_denials.is_none() {
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

        // The child was created suspended; now that it is in the job object (so
        // every descendant it spawns is captured), resume its main thread. If the
        // create API ignored CREATE_SUSPENDED the thread is already running and
        // this is a harmless no-op.
        // SAFETY: `pi.hThread` is the just-created, still-owned main-thread
        // handle; `ResumeThread` only adjusts its suspend count.
        unsafe {
            ResumeThread(pi.hThread);
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
            destroy_on_exit: request.lifecycle.destroy_on_exit,
            proxy_enabled: request.policy.network_proxy.is_enabled(),
            identity,
            sid_string,
            proxy_coordinator: std::mem::take(&mut self.proxy_coordinator),
            capture_session,
            capture_etl_path,
            capture_output_path,
        })
    }
}

/// A BaseContainer child launched by [`BaseContainerRunner::spawn_base`]. The
/// child runs immediately (no suspend); this owns the process handle, the
/// parent-side pipe ends, and the per-run proxy/sandbox state it tears down
/// once the child exits.
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
    /// Internal runner-managed temp `.etl` the broker seals into. Decoded
    /// then deleted in `run_teardown`. `Some` iff `capture_session` is `Some`.
    capture_etl_path: Option<PathBuf>,
    /// Resolved JSON denials deliverable path (caller-specified or a managed
    /// per-run temp file). `Some` iff `capture_session` is `Some`.
    capture_output_path: Option<PathBuf>,
}

impl SandboxBackend for BaseContainerRunner {
    fn validate(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        if request.policy.capture_denials.is_some() && request.policy.least_privilege_mode {
            return Err(ScriptResponse::error(
                "processContainer.captureDenials cannot be combined with \
                 processContainer.leastPrivilege because the Windows process \
                 security-environment contract does not support LPAC tokens",
            ));
        }
        // deniedPaths reaches the OS via the SandboxSpec `fs_deny` field, honored
        // only when the OS advertises SANDBOX_CAP_FS_DENY. The dispatcher only
        // routes deny here when supported; fail closed for direct callers.
        if !request.policy.denied_paths.is_empty()
            && !crate::fallback_detector::base_container_supports_deny_paths()
        {
            return Err(ScriptResponse::error(
                wxc_common::error::DENIED_PATHS_FEATURE_DISABLED_MSG,
            ));
        }
        if !request.policy.allowed_hosts.is_empty() || !request.policy.blocked_hosts.is_empty() {
            return Err(ScriptResponse::error(
                wxc_common::error::HOST_LISTS_NOT_SUPPORTED_MSG,
            ));
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
    /// Internal runner-managed temp `.etl` the broker seals into.
    capture_etl_path: Option<PathBuf>,
    /// Resolved JSON denials deliverable path.
    capture_output_path: Option<PathBuf>,
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
            capture_etl_path: child.capture_etl_path.take(),
            capture_output_path: child.capture_output_path.take(),
            last_exit_code: None,
            output_metadata: None,
        }
    }

    fn run_teardown(&mut self) -> std::io::Result<()> {
        if let Some(result) = &self.teardown_result {
            return result.clone().map_err(std::io::Error::other);
        }
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);

        // Seal the learning-mode ETL trace now that the child has exited and
        // been reaped (both `wait` and `Drop` kill + reap before calling this).
        // The ETL is an internal temp: seal it, decode it into the JSON denials
        // deliverable that consuming apps read, delete the temp, and retain
        // structured metadata for the caller. Any seal/decode/write failure is
        // returned through `wait()`.
        let capture_result = if let Some(session) = self.capture_session.take() {
            let etl_path = self.capture_etl_path.take();
            let output_path = self.capture_output_path.take();
            let exit_code = self.last_exit_code.unwrap_or(-1);
            let result = match session.finish(etl_path.as_deref()) {
                Ok(()) => match (&etl_path, &output_path) {
                    (Some(etl), Some(output)) => {
                        Self::decode_write_and_cleanup(&EtlDenialAnalyzer, etl, output, exit_code)
                            .map(Some)
                    }
                    _ => combine_capture_and_cleanup_results(
                        Err(std::io::Error::other(
                            "captureDenials internal output paths were not initialized",
                        )),
                        etl_path
                            .as_deref()
                            .map(remove_internal_capture_file)
                            .unwrap_or(Ok(())),
                    ),
                },
                Err(error) => combine_capture_and_cleanup_results(
                    Err(std::io::Error::other(format!(
                        "captureDenials failed to finalize the denial capture: {error}"
                    ))),
                    etl_path
                        .as_deref()
                        .map(remove_internal_capture_file)
                        .unwrap_or(Ok(())),
                ),
            };
            if let Ok(Some(metadata)) = &result {
                self.output_metadata = Some(SandboxOutputMetadata {
                    capture_denials: Some(metadata.clone()),
                });
            }
            result
        } else {
            Ok(None)
        };

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
            .map(|_| ())
            .map_err(|error| error.to_string());
        self.teardown_result = Some(result.clone());
        result.map_err(std::io::Error::other)
    }

    fn kill_process_tree(&mut self) -> std::io::Result<()> {
        if let Some(job) = &self.job {
            job.terminate(u32::MAX);
        } else {
            unsafe {
                let _ = TerminateProcess(self.process.get(), u32::MAX);
            }
        }
        Ok(())
    }

    fn terminate_and_reap(&mut self) {
        let _ = self.kill_process_tree();
        unsafe {
            let _ = WaitForSingleObject(self.process.get(), u32::MAX);
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

        let summary = DenialSummary::new(
            exit_code,
            analysis.denials.len(),
            analysis.denied_resources_truncated,
        );
        let document = DenialsDocument::new(analysis.denials, summary);

        write_denials_output_file(output_path, |writer| write_document(writer, &document))?;

        let pointer = DenialsOutputPointer::new(output_path.to_string_lossy(), &document.summary);
        Ok(CaptureDenialsOutput {
            kind: pointer.kind,
            output_path: pointer.output_path,
            exit_code: pointer.exit_code,
            total_denials: pointer.total_denials,
            denied_resources_truncated: pointer.denied_resources_truncated,
        })
    }

    fn decode_write_and_cleanup(
        analyzer: &dyn DenialAnalyzer,
        etl_path: &Path,
        output_path: &Path,
        exit_code: i32,
    ) -> std::io::Result<CaptureDenialsOutput> {
        combine_capture_and_cleanup_results(
            Self::decode_and_write_denials(analyzer, etl_path, output_path, exit_code),
            remove_internal_capture_file(etl_path),
        )
    }
}

fn remove_internal_capture_file(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(std::io::Error::other(format!(
            "captureDenials failed to remove internal ETL file {}: {error}",
            path.display()
        ))),
    }
}

fn combine_capture_and_cleanup_results<T>(
    capture_result: std::io::Result<T>,
    cleanup_result: std::io::Result<()>,
) -> std::io::Result<T> {
    match (capture_result, cleanup_result) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(capture_error), Ok(())) => Err(capture_error),
        (Ok(_), Err(cleanup_error)) => Err(cleanup_error),
        (Err(capture_error), Err(cleanup_error)) => Err(std::io::Error::other(format!(
            "{capture_error}; additionally failed to clean up the internal ETL: {cleanup_error}"
        ))),
    }
}

fn write_stderr_line_best_effort(message: std::fmt::Arguments<'_>) {
    let stderr = std::io::stderr();
    let mut stderr = stderr.lock();
    let _ = std::io::Write::write_fmt(&mut stderr, format_args!("{message}\n"));
    let _ = std::io::Write::flush(&mut stderr);
}

fn write_denials_output_file(
    output_path: &Path,
    write: impl FnOnce(&mut std::io::BufWriter<std::fs::File>) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)
        .map_err(|error| {
            std::io::Error::other(format!(
                "captureDenials failed to create denials output file {}: {error}",
                output_path.display()
            ))
        })?;

    let write_result = {
        let mut writer = std::io::BufWriter::new(file);
        write(&mut writer)
    };
    if let Err(error) = write_result {
        let write_error = std::io::Error::other(format!(
            "captureDenials failed to write denials output file {}: {error}",
            output_path.display()
        ));
        return match std::fs::remove_file(output_path) {
            Ok(()) => Err(write_error),
            Err(cleanup_error) if cleanup_error.kind() == std::io::ErrorKind::NotFound => {
                Err(write_error)
            }
            Err(cleanup_error) => Err(std::io::Error::other(format!(
                "{write_error}; additionally failed to remove incomplete output file {}: {cleanup_error}",
                output_path.display()
            ))),
        };
    }

    Ok(())
}

/// Inserts a per-run identifier into a denials output path's file stem so
/// concurrent and sequential captures using the same configured `outputPath`
/// produce distinct files instead of clobbering one another.
///
/// `C:\app\denials.json` → `C:\app\denials.<run_id>.json`. A path with no
/// extension gets `<name>.<run_id>`; a bare filename (no parent) keeps its
/// directory-less form.
fn insert_run_id_into_stem(path: &Path, run_id: &str) -> PathBuf {
    let Some(file_name) = path.file_name().and_then(|s| s.to_str()) else {
        return path.to_path_buf();
    };
    let new_name = match path.extension().and_then(|s| s.to_str()) {
        Some(ext) => {
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or(file_name);
            format!("{stem}.{run_id}.{ext}")
        }
        None => format!("{file_name}.{run_id}"),
    };
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(new_name),
        _ => PathBuf::from(new_name),
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
        self.terminate_and_reap();
        cancel_and_join_discard(stdout_thread, &self.stdout_canceller);
        cancel_and_join_discard(stderr_thread, &self.stderr_canceller);
        // Record the child's exit code so `run_teardown` can stamp it into the
        // denials summary. On a timeout / wait failure there is no exit code.
        self.last_exit_code = result.as_ref().ok().copied();
        let teardown_result = self.run_teardown();
        combine_process_and_teardown_results(result, teardown_result)
    }
}

impl Drop for BaseContainerSandboxProcess {
    fn drop(&mut self) {
        // Kill and reap before tearing down proxy / sandbox state, so an
        // abandoned-but-running sandbox cannot outlive its enforcement (or
        // leak as an orphan).
        self.terminate_and_reap();
        if let Err(error) = self.run_teardown() {
            write_stderr_line_best_effort(format_args!(
                "captureDenials teardown failed during drop: {error}"
            ));
        }
    }
}

fn managed_capture_output_path() -> Result<PathBuf, ScriptResponse> {
    let suffix = random_capture_suffix()?;
    Ok(std::env::temp_dir().join(format!(
        "mxc_capture_denials_{}_{suffix}.etl",
        std::process::id()
    )))
}

fn unique_denials_output_path(configured_path: Option<&str>) -> Result<PathBuf, ScriptResponse> {
    let suffix = random_capture_suffix()?;
    let run_id = format!("{}_{suffix}", std::process::id());
    Ok(match configured_path {
        Some(path) => insert_run_id_into_stem(Path::new(path), &run_id),
        None => std::env::temp_dir().join(format!("mxc_denials_{run_id}.json")),
    })
}

fn random_capture_suffix() -> Result<String, ScriptResponse> {
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce).map_err(|error| {
        ScriptResponse::error(&format!(
            "captureDenials could not generate a unique output path: {error}"
        ))
    })?;
    Ok(nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>())
}

fn combine_process_and_teardown_results(
    process_result: std::io::Result<i32>,
    teardown_result: std::io::Result<()>,
) -> std::io::Result<i32> {
    match (process_result, teardown_result) {
        (Ok(exit_code), Ok(())) => Ok(exit_code),
        (Ok(_), Err(teardown_error)) => Err(teardown_error),
        (Err(wait_error), Ok(())) => Err(wait_error),
        (Err(wait_error), Err(teardown_error)) => {
            write_stderr_line_best_effort(format_args!(
                "captureDenials teardown also failed after process wait failure: {teardown_error}"
            ));
            Err(wait_error)
        }
    }
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
        AccessType, AnalysisResult, AnalyzeError, DeniedResource, ResourceType,
    };
    use process_security_environment_spec::process_security_environment_layout as psec_layout;
    use sandbox_spec::base_container_layout;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wxc_common::models::{ClipboardPolicy, ProxyConfig, UiPolicy};
    use wxc_common::ui_policy::EffectiveUiRestrictions;

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
        let first = managed_capture_output_path().expect("first path");
        let second = managed_capture_output_path().expect("second path");

        assert_ne!(first, second);
        assert_eq!(first.parent(), Some(std::env::temp_dir().as_path()));
        assert_eq!(second.parent(), Some(std::env::temp_dir().as_path()));
        assert_eq!(first.extension().and_then(|ext| ext.to_str()), Some("etl"));
    }

    #[test]
    fn managed_denials_paths_are_unique_per_run() {
        let first = unique_denials_output_path(None).expect("first path");
        let second = unique_denials_output_path(None).expect("second path");

        assert_ne!(first, second);
        assert_eq!(first.parent(), Some(std::env::temp_dir().as_path()));
        assert_eq!(second.parent(), Some(std::env::temp_dir().as_path()));
        assert_eq!(first.extension().and_then(|ext| ext.to_str()), Some("json"));
    }

    #[test]
    fn failed_denials_write_removes_incomplete_output() {
        let directory = tempfile::tempdir().expect("temp directory");
        let output_path = directory.path().join("denials.json");

        let error = write_denials_output_file(&output_path, |writer| {
            std::io::Write::write_all(writer, b"{\"partial\":")?;
            Err(std::io::Error::other("simulated write failure"))
        })
        .expect_err("write should fail");

        assert!(error.to_string().contains("simulated write failure"));
        assert!(!output_path.exists());
    }

    #[test]
    fn denials_output_does_not_overwrite_an_existing_file() {
        let directory = tempfile::tempdir().expect("temp directory");
        let output_path = directory.path().join("denials.json");
        std::fs::write(&output_path, b"existing").expect("seed output");

        write_denials_output_file(&output_path, |_| Ok(())).expect_err("collision should fail");

        assert_eq!(
            std::fs::read(&output_path).expect("read existing output"),
            b"existing"
        );
    }

    #[test]
    fn missing_internal_etl_is_already_clean() {
        let directory = tempfile::tempdir().expect("temp directory");
        let missing = directory.path().join("missing.etl");
        remove_internal_capture_file(&missing).expect("missing file should be clean");
    }

    #[test]
    fn capture_and_etl_cleanup_failures_are_both_preserved() {
        let error = combine_capture_and_cleanup_results::<()>(
            Err(std::io::Error::other("decode failed")),
            Err(std::io::Error::other("delete failed")),
        )
        .expect_err("combined operation should fail");

        let message = error.to_string();
        assert!(message.contains("decode failed"));
        assert!(message.contains("delete failed"));
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

        let error = BaseContainerSandboxProcess::decode_write_and_cleanup(
            &analyzer,
            &etl_path,
            &output_path,
            0,
        )
        .expect_err("decode should fail");

        assert!(error.to_string().contains("simulated decode failure"));
        assert!(!etl_path.exists());
        assert!(!output_path.exists());
    }

    #[test]
    fn successful_process_reports_capture_teardown_failure() {
        let error =
            combine_process_and_teardown_results(Ok(0), Err(std::io::Error::other("seal failed")))
                .expect_err("capture failure must override successful process exit");

        assert!(error.to_string().contains("seal failed"));
    }

    #[test]
    fn insert_run_id_into_stem_injects_id_before_extension() {
        let got = insert_run_id_into_stem(Path::new(r"C:\app\denials.json"), "1234_abcd");
        assert_eq!(got, PathBuf::from(r"C:\app\denials.1234_abcd.json"));
    }

    #[test]
    fn insert_run_id_into_stem_handles_no_extension() {
        let got = insert_run_id_into_stem(Path::new(r"C:\app\denials"), "77_abcd");
        assert_eq!(got, PathBuf::from(r"C:\app\denials.77_abcd"));
    }

    #[test]
    fn insert_run_id_into_stem_handles_bare_filename() {
        let got = insert_run_id_into_stem(Path::new("denials.json"), "9_abcd");
        assert_eq!(got, PathBuf::from("denials.9_abcd.json"));
    }

    #[test]
    fn insert_run_id_into_stem_preserves_multi_dot_stem() {
        let got = insert_run_id_into_stem(Path::new(r"C:\app\out.denials.json"), "5_abcd");
        assert_eq!(got, PathBuf::from(r"C:\app\out.denials.5_abcd.json"));
    }

    #[test]
    fn is_api_not_implemented_classifies_disabled_feature() {
        assert!(is_api_not_implemented(ERROR_CALL_NOT_IMPLEMENTED.0));
        assert!(is_api_not_implemented(E_NOTIMPL.0 as u32));
        // ERROR_INVALID_PARAMETER (87) and success are ordinary, not "disabled".
        assert!(!is_api_not_implemented(87));
        assert!(!is_api_not_implemented(0));
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
            begin_error: Some(("StartLearningModeTrace", windows::Win32::Foundation::E_FAIL.0)),
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
            finish_error: Some(("StopLearningModeTrace", windows::Win32::Foundation::E_FAIL.0)),
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

        assert!(spec.network_policy().is_none());
    }

    #[test]
    fn build_process_security_environment_spec_produces_valid_psec() {
        let mut request = ExecutionRequest::default();
        request.policy.capabilities = vec!["internetClient".into(), "registryRead".into()];
        request.policy.readwrite_paths = vec!["C:\\temp".into()];
        request.policy.readonly_paths = vec!["C:\\Windows".into()];
        request.policy.denied_paths = vec!["C:\\secret".into()];
        request.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("127.0.0.1".to_string(), 8080)),
            builtin_test_server: false,
        };

        let bytes = BaseContainerRunner::build_process_security_environment_spec(&request);

        assert!(psec_layout::process_security_environment_buffer_has_identifier(&bytes));
        let spec = psec_layout::root_as_process_security_environment(&bytes).unwrap();
        let version = spec.version();
        assert_eq!(version.major(), 1);
        assert_eq!(version.minor(), 0);
        assert_eq!(spec.capabilities(), Some("internetClient,registryRead"));
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
        assert_eq!(
            spec.network_policy()
                .and_then(|policy| policy.proxy())
                .and_then(|proxy| proxy.url()),
            Some("http://127.0.0.1:8080")
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
        assert!(spec.network_policy().is_none());
    }

    #[test]
    fn build_sandbox_spec_network_block_no_internet_client() {
        let mut request = ExecutionRequest::default();
        request.policy.default_network_policy = NetworkPolicy::Block;

        let bytes = BaseContainerRunner::build_sandbox_spec(&request);
        let spec = base_container_layout::root_as_sandbox_spec(&bytes).unwrap();
        assert!(spec.capabilities().is_none());
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
        request.policy.default_network_policy = NetworkPolicy::Block;
        request.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("127.0.0.1".to_string(), 8080)),
            builtin_test_server: false,
        };

        let bytes = BaseContainerRunner::build_sandbox_spec(&request);
        let spec = base_container_layout::root_as_sandbox_spec(&bytes).unwrap();

        let net = spec.network_policy().expect("network_policy should be set");
        let proxy = net.proxy().expect("proxy should be set");
        assert_eq!(proxy.url(), Some("http://127.0.0.1:8080"));
    }

    #[test]
    fn build_sandbox_spec_no_proxy() {
        let request = ExecutionRequest::default();
        let bytes = BaseContainerRunner::build_sandbox_spec(&request);
        let spec = base_container_layout::root_as_sandbox_spec(&bytes).unwrap();
        assert!(spec.network_policy().is_none());
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
        let runner = BaseContainerRunner::new();
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
        let mut request = ExecutionRequest::default();
        request.policy.allowed_hosts = vec!["example.com".into()];

        let err = runner
            .validate(&request)
            .expect_err("allowedHosts is not yet supported");
        assert!(err.error_message.contains("allowedHosts"));
    }

    #[test]
    fn validate_runner_rejects_blocked_hosts() {
        let runner = BaseContainerRunner::new();
        let mut request = ExecutionRequest::default();
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
    fn validate_runner_rejects_capture_denials_with_least_privilege() {
        let runner = BaseContainerRunner::new();
        let mut request = ExecutionRequest::default();
        request.policy.capture_denials = Some(Default::default());
        request.policy.least_privilege_mode = true;

        let error = runner
            .validate(&request)
            .expect_err("PSEC cannot represent leastPrivilege");

        assert!(error.error_message.contains("leastPrivilege"));
    }
}
