// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `BaseContainerRunner` — executes scripts through the Windows BaseContainer APIs.
//!
//! The runner uses the PSEC / `CreateProcessSecurityEnvironment` two-phase
//! contract and attaches the resulting environment to `CreateProcessW`.

use std::ffi::c_void;
use std::fmt::Write;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Arc;

use learning_mode_core::DenialAnalyzer;
use learning_mode_windows::{EtlDenialAnalyzer, LearningModeApi};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, SetHandleInformation, ERROR_CALL_NOT_IMPLEMENTED, E_NOTIMPL, HANDLE,
    HANDLE_FLAG_INHERIT, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows::Win32::System::Threading::{
    CreateProcessW, GetExitCodeProcess, TerminateProcess, WaitForSingleObject,
    EXTENDED_STARTUPINFO_PRESENT, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION,
    STARTF_USESTDHANDLES, STARTUPINFOW,
};
use windows_core::{PCWSTR, PWSTR};

use crate::base_container_helpers::{
    build_psec_spec, has_conflicting_proxy_identity, unrestricted_host_loopback_allowed,
    PsecContract, ResolvedPsecContract,
};
use crate::capture_output::{
    combine_capture_and_cleanup_results, combine_process_and_teardown_results,
    remove_internal_capture_file, unique_denials_output_paths, write_denials_document,
    write_stderr_line_best_effort,
};
use crate::job_object::UiJobObject;
use crate::launch_diagnostics::{
    diagnose_create_process_failure, diagnose_missing_required_env, diagnose_process_exit,
    validate_required_child_env,
};
use crate::native_capture::CaptureSession;
use crate::proxy_coordinator::ProxyCoordinator;
use crate::secenv::{
    ProcessSecurityEnvironment, SecurityEnvironmentApi, SecurityEnvironmentStartupInfo,
    PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE,
};
use wxc_common::audit::{
    sanitize_identity, AuditEvent, AuditEventName, KillMethod, TeardownSkipReason, TeardownStatus,
};
use wxc_common::error::WxcError;
use wxc_common::log_symbols::EMOJI_SECTION;
use wxc_common::logger::Logger;
use wxc_common::models::{
    CaptureDenialsErrorOutput, CaptureDenialsOutput, ContainmentBackend, ExecutionRequest,
    FailurePhase, ProxyAddress, SandboxOutputMetadata, ScriptResponse,
};
use wxc_common::process_util::{
    create_std_pipes, InterruptiblePipeReader, OwnedHandle, PipeReadCanceller, PipeWriter,
    SendOwnedHandle,
};
use wxc_common::sandbox_process::{
    boxed_closer, cancel_and_join_discard, duplicate_and_take_native_stdio, spawn_discard,
    take_boxed_read, take_boxed_write, NativeStdio, SandboxBackend, SandboxProcess, StdioMode,
    StreamCloser,
};
use wxc_common::script_runner::get_timeout_milliseconds;
use wxc_common::string_util;
use wxc_common::validator::{validate_network_policy_support, NetworkPolicySupport};

use windows::Win32::System::Threading::{
    ResumeThread, CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
};

/// Build the environment block handed to the contained child.
///
/// Honors the three states of [`ExecutionRequest::env`]:
///
/// * `None` — no environment supplied. The child gets a clean default user
///   profile block (never the `wxc-exec` process's own variables).
/// * `Some(entries)` — the caller's environment, used **verbatim**. MXC adds
///   nothing to it, including when `entries` is empty: an explicitly empty
///   environment produces an empty block, not the default one. Proxy variables
///   are still injected, because the proxy is enforced policy rather than
///   inherited environment.
///
/// When `inherit_default_env` is set, `entries` is layered on top of the
/// default block instead of replacing it, which is the supported way to ask for
/// "the user's profile block plus these".
fn build_child_env_block(request: &ExecutionRequest) -> Result<Option<Vec<u16>>, WxcError> {
    let proxy_address = if request.policy.runtime_network_proxy_specified {
        request.policy.network_proxy.address.as_ref()
    } else {
        None
    };

    let entries = match request.env.as_deref() {
        None => {
            let mut entries = crate::appcontainer_runner::create_default_env_entries()?;
            if let Some(address) = proxy_address {
                crate::appcontainer_runner::inject_proxy_vars(&mut entries, address);
            }
            entries
        }
        Some(supplied) if request.inherit_default_env => {
            crate::appcontainer_runner::build_inherited_entries(supplied, proxy_address)?
        }
        Some(supplied) => {
            crate::appcontainer_runner::build_explicit_entries(supplied, proxy_address)
        }
    };
    Ok(Some(crate::appcontainer_runner::encode_env_block(&entries)))
}

const CAPTURE_API_AVAILABLE_LOG: &str =
    "captureDenials: learning-mode trace API available (processmodel.dll)";
const PSEC_DENIED_PATHS_UNSUPPORTED_MSG: &str =
    "filesystem.deniedPaths on the process-security-environment path requires \
     QueryProcessSecurityEnvironmentSupport to advertise PSE_SUPPORT_FS_DENY; this OS \
     build does not support that policy, and the process-security-environment path \
     cannot fall back to AppContainer or host-DACL enforcement";
const PSEC_ENUMERATE_PATHS_UNSUPPORTED_MSG: &str =
    "processContainer.filesystem.enumeratePaths requires Process Security Environment contract version 1.1 \
     and QueryProcessSecurityEnvironmentSupport to advertise PSE_SUPPORT_FS_ENUMERATE; this OS \
     build does not support that policy, and enumeration-only access cannot fall back to \
     AppContainer enforcement";
const PSEC_INGRESS_UNSUPPORTED_MSG: &str =
    "network.ingress.hostLoopback='allow' requires Process Security Environment contract version \
     1.1 with ingress support";
const CREATE_PROCESS_IN_SECURITY_ENVIRONMENT_API: &str =
    "CreateProcessW(PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT)";

trait PsecCapabilityProbe {
    fn supports_version_1_1(&self) -> Result<bool, String>;
    fn supports_enumerate_paths(&self) -> Result<bool, String>;
    fn supports_network_ingress(&self) -> Result<bool, String>;
}

impl PsecCapabilityProbe for SecurityEnvironmentApi {
    fn supports_version_1_1(&self) -> Result<bool, String> {
        self.supports_version(1, 1)
            .map_err(|error| error.to_string())
    }

    fn supports_enumerate_paths(&self) -> Result<bool, String> {
        self.supports_enumerate_paths()
            .map_err(|error| error.to_string())
    }

    fn supports_network_ingress(&self) -> Result<bool, String> {
        self.supports_network_ingress()
            .map_err(|error| error.to_string())
    }
}

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
    fn supports_enumerate_paths(&self) -> Result<bool, String> {
        Ok(false)
    }
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

    fn supports_enumerate_paths(&self) -> Result<bool, String> {
        let api = SecurityEnvironmentApi::load()
            .map_err(|error| format!("process security-environment API unavailable: {error}"))?;
        if !api.supports_version(1, 1).map_err(|error| {
            format!("could not query process security-environment version: {error}")
        })? {
            return Ok(false);
        }
        api.supports_enumerate_paths().map_err(|error| {
            format!("could not query process security-environment support: {error}")
        })
    }
}

/// Script runner that launches through a process security environment.
pub struct BaseContainerRunner {
    proxy_coordinator: ProxyCoordinator,
    capture_factory: Arc<dyn CaptureSessionFactory>,
    capture_support: Arc<dyn CapturePlatformSupport>,
    #[cfg(test)]
    psec_usable_override: Option<bool>,
}

impl Default for BaseContainerRunner {
    fn default() -> Self {
        Self {
            proxy_coordinator: ProxyCoordinator::default(),
            capture_factory: Arc::new(RealCaptureSessionFactory),
            capture_support: Arc::new(RealCapturePlatformSupport),
            #[cfg(test)]
            psec_usable_override: None,
        }
    }
}

impl BaseContainerRunner {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    fn build_process_security_environment_spec(request: &ExecutionRequest) -> Vec<u8> {
        build_psec_spec(
            request,
            ResolvedPsecContract::with_all_contract_capabilities(request),
        )
    }

    #[cfg(test)]
    fn with_capture_factory(capture_factory: Arc<dyn CaptureSessionFactory>) -> Self {
        Self {
            proxy_coordinator: ProxyCoordinator::default(),
            capture_factory,
            capture_support: Arc::new(RealCapturePlatformSupport),
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
            psec_usable_override: Some(true),
        }
    }

    fn cleanup_capture_begin_failure(&mut self, logger: &mut Logger) {
        // CaptureSession owns and closes the PSEC environment. No legacy
        // identity/tracking state is created for this path.
        self.proxy_coordinator.stop(logger);
    }

    /// Whether the BaseContainer (Tier 1) PSEC backend is usable.
    pub fn is_base_container_usable() -> bool {
        #[cfg(test)]
        if let Ok(forced) = std::env::var("MXC_FORCE_BC_USABLE") {
            return forced == "1";
        }
        Self::is_process_security_environment_usable()
    }

    /// Whether the process security environment API set is present.
    pub fn is_base_container_api_present() -> Result<(), String> {
        SecurityEnvironmentApi::load()
            .map(drop)
            .map_err(|error| error.to_string())
    }

    /// Whether PSEC can create and close a minimal security environment on
    /// this host. Export presence and the support query alone are insufficient
    /// on transitional builds where the API surface exists before the feature
    /// is enabled.
    pub fn is_process_security_environment_usable() -> bool {
        static USABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *USABLE.get_or_init(|| {
            let request = ExecutionRequest {
                ..Default::default()
            };
            let specification = build_psec_spec(&request, ResolvedPsecContract::baseline());
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

    /// Whether the native PSEC plus Learning Mode API set is available.
    ///
    /// This does not start a Learning Mode trace. It also does not evaluate
    /// whether a particular request is compatible with PSEC.
    pub fn is_native_capture_available() -> bool {
        #[cfg(test)]
        if let Ok(forced) = std::env::var("MXC_FORCE_NATIVE_CAPTURE_USABLE") {
            return forced == "1";
        }

        Self::is_process_security_environment_usable()
            && RealCapturePlatformSupport.check_apis(true).is_ok()
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
            ..Default::default()
        };
        let specification = build_psec_spec(&request, ResolvedPsecContract::baseline());
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

    /// Whether PSEC can enforce `filesystem.deniedPaths`.
    pub fn supports_native_denied_paths() -> bool {
        Self::is_process_security_environment_usable()
            && SecurityEnvironmentApi::load()
                .and_then(|api| api.supports_deny_paths())
                .unwrap_or(false)
    }

    /// Whether PSEC can enforce `processContainer.filesystem.enumeratePaths` on this host.
    pub fn supports_enumerate_paths() -> bool {
        Self::is_process_security_environment_usable()
            && Self::query_psec_enumerate_support().unwrap_or(false)
    }

    /// Whether BaseContainer can enforce
    /// `network.ingress.hostLoopback = "allow"`.
    pub fn supports_ingress_host_loopback_allow() -> bool {
        Self::is_process_security_environment_usable()
            && Self::query_psec_ingress_support().unwrap_or(false)
    }

    fn resolve_psec_contract(
        request: &ExecutionRequest,
    ) -> Result<ResolvedPsecContract, ScriptResponse> {
        let contract = PsecContract::for_request(request);
        if contract == PsecContract::V1_0 {
            return Ok(ResolvedPsecContract::baseline());
        }

        let api = SecurityEnvironmentApi::load().map_err(|error| ScriptResponse {
            failure_phase: FailurePhase::BackendUnavailable,
            ..ScriptResponse::error(&format!(
                "failed to load Process Security Environment support APIs: {error}"
            ))
        })?;
        Self::resolve_psec_contract_with_probe(request, &api)
    }

    fn resolve_psec_contract_with_probe(
        request: &ExecutionRequest,
        probe: &dyn PsecCapabilityProbe,
    ) -> Result<ResolvedPsecContract, ScriptResponse> {
        let contract = PsecContract::for_request(request);
        if contract == PsecContract::V1_0 {
            return Ok(ResolvedPsecContract::baseline());
        }

        let requires_enumerate_paths = !request.policy.enumerate_paths.is_empty();
        let requires_unrestricted_host_loopback =
            unrestricted_host_loopback_allowed(&request.policy);
        let version_supported = probe
            .supports_version_1_1()
            .map_err(|error| ScriptResponse {
                failure_phase: FailurePhase::BackendUnavailable,
                ..ScriptResponse::error(&format!(
                    "failed to query Process Security Environment contract support: {error}"
                ))
            })?;
        if !version_supported {
            return Err(ScriptResponse {
                failure_phase: FailurePhase::Rejected,
                ..ScriptResponse::error(if requires_enumerate_paths {
                    PSEC_ENUMERATE_PATHS_UNSUPPORTED_MSG
                } else {
                    PSEC_INGRESS_UNSUPPORTED_MSG
                })
            });
        }

        let enumerate_paths_supported = if requires_enumerate_paths {
            probe
                .supports_enumerate_paths()
                .map_err(|error| ScriptResponse {
                    failure_phase: FailurePhase::BackendUnavailable,
                    ..ScriptResponse::error(&format!(
                        "failed to query Process Security Environment filesystem enumeration support: {error}"
                    ))
                })?
        } else {
            true
        };
        if requires_enumerate_paths && !enumerate_paths_supported {
            return Err(ScriptResponse {
                failure_phase: FailurePhase::Rejected,
                ..ScriptResponse::error(PSEC_ENUMERATE_PATHS_UNSUPPORTED_MSG)
            });
        }

        let network_ingress_supported =
            probe
                .supports_network_ingress()
                .map_err(|error| ScriptResponse {
                    failure_phase: FailurePhase::BackendUnavailable,
                    ..ScriptResponse::error(&format!(
                        "failed to query Process Security Environment ingress support: {error}"
                    ))
                })?;
        if requires_unrestricted_host_loopback && !network_ingress_supported {
            return Err(ScriptResponse {
                failure_phase: FailurePhase::Rejected,
                ..ScriptResponse::error(PSEC_INGRESS_UNSUPPORTED_MSG)
            });
        }
        Ok(ResolvedPsecContract {
            contract,
            supports_network_ingress: network_ingress_supported,
        })
    }

    fn query_psec_ingress_support() -> Result<bool, learning_mode_windows::LearningModeError> {
        let api = SecurityEnvironmentApi::load()?;
        if !api.supports_version(1, 1)? {
            return Ok(false);
        }
        api.supports_network_ingress()
    }

    fn query_psec_enumerate_support() -> Result<bool, learning_mode_windows::LearningModeError> {
        let api = SecurityEnvironmentApi::load()?;
        if !api.supports_version(1, 1)? {
            return Ok(false);
        }
        api.supports_enumerate_paths()
    }
    fn should_use_process_security_environment(
        request: &ExecutionRequest,
        psec_usable: bool,
        psec_supports_deny_paths: bool,
        psec_supports_enumerate_paths: bool,
    ) -> bool {
        if !psec_usable {
            return false;
        }
        Self::psec_policy_compatible(
            request,
            psec_supports_deny_paths,
            psec_supports_enumerate_paths,
        )
    }

    fn psec_policy_compatible(
        request: &ExecutionRequest,
        psec_supports_deny_paths: bool,
        psec_supports_enumerate_paths: bool,
    ) -> bool {
        !request.policy.least_privilege_mode
            && (!request.policy.network_proxy.is_enabled()
                || request.policy.runtime_network_proxy_specified)
            && (request.policy.denied_paths.is_empty() || psec_supports_deny_paths)
            && (request.policy.enumerate_paths.is_empty() || psec_supports_enumerate_paths)
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
                request.policy.enumerate_paths.is_empty()
                    || support.supports_enumerate_paths().unwrap_or(false),
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
        let supports_enumerate_paths = request.policy.enumerate_paths.is_empty()
            || self
                .capture_support
                .supports_enumerate_paths()
                .unwrap_or(false);
        Self::should_use_process_security_environment(
            request,
            self.process_security_environment_usable(),
            supports_deny_paths,
            supports_enumerate_paths,
        )
    }

    pub(crate) fn is_usable_for_request(request: &ExecutionRequest) -> bool {
        #[cfg(test)]
        if let Ok(forced) = std::env::var("MXC_FORCE_BC_USABLE") {
            return forced == "1";
        }
        let psec_usable = Self::is_process_security_environment_usable();
        if request.policy.capture_denials.is_some() {
            return Self::uses_native_capture_for_request(request);
        }
        let psec_supports_deny_paths = request.policy.denied_paths.is_empty()
            || SecurityEnvironmentApi::load()
                .and_then(|api| api.supports_deny_paths())
                .unwrap_or(false);
        let psec_supports_enumerate_paths = request.policy.enumerate_paths.is_empty()
            || Self::query_psec_enumerate_support().unwrap_or(false);
        Self::should_use_process_security_environment(
            request,
            psec_usable,
            psec_supports_deny_paths,
            psec_supports_enumerate_paths,
        )
    }

    pub(crate) fn supports_deny_paths_for_request(request: &ExecutionRequest) -> bool {
        let psec_supports_deny_paths = SecurityEnvironmentApi::load()
            .and_then(|api| api.supports_deny_paths())
            .unwrap_or(false);
        let uses_native_capture = Self::uses_native_capture_for_request(request);
        if uses_native_capture {
            return true;
        }
        Self::should_use_process_security_environment(
            request,
            Self::is_process_security_environment_usable(),
            psec_supports_deny_paths,
            request.policy.enumerate_paths.is_empty()
                || Self::query_psec_enumerate_support().unwrap_or(false),
        )
    }

    pub(crate) fn capabilities_for_request(
        request: &ExecutionRequest,
    ) -> crate::fallback_detector::BaseContainerRequestCapabilities {
        crate::fallback_detector::BaseContainerRequestCapabilities {
            usable: Self::is_usable_for_request(request),
            supports_deny_paths: Self::supports_deny_paths_for_request(request),
            supports_enumerate_paths: Self::is_process_security_environment_usable()
                && Self::query_psec_enumerate_support().unwrap_or(false),
        }
    }

    pub(crate) fn uses_native_capture_for_request(request: &ExecutionRequest) -> bool {
        Self::native_capture_eligible(
            request,
            Self::is_process_security_environment_usable(),
            &RealCapturePlatformSupport,
        )
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

        let psec_contract = Self::resolve_psec_contract(request)?;

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
        if capture_denials.is_some() {
            let _ = writeln!(logger, "{EMOJI_SECTION} SECTION: captureDenials");
        }

        let process_security_environment_spec = build_psec_spec(&request, psec_contract);
        let contract_version = psec_contract.contract.version();
        let _ = writeln!(
            logger,
            "process security environment spec built (PSEC {}.{}, {} bytes)",
            contract_version.major,
            contract_version.minor,
            process_security_environment_spec.len()
        );

        // Resolve two paths for the capture:
        //   * `capture_etl_path` — a runner-managed `.etl` in a protected
        //     per-run directory for native V2 capture. Guarded WPR analyzes
        //     its ETL while elevated and returns only a bounded process-scoped
        //     result.
        //   * `capture_output_path` — the JSON denials deliverable that consuming
        //     apps read: caller-specified via `captureDenials.outputPath` when
        //     provided, else a managed per-run temp `.json` file.
        let mut managed_capture = capture_denials
            .as_ref()
            .map(|config| managed_capture_output_path(config.retain_etl))
            .transpose()?;
        let capture_output_paths = capture_denials
            .as_ref()
            .map(|config| unique_denials_output_paths(config.output_path.as_deref(), false))
            .transpose()
            .map_err(|error| ScriptResponse::error(&error))?;
        let capture_output_path = match capture_output_paths {
            Some(paths) => Some(paths.denials),
            None => None,
        };

        let _ = writeln!(logger, "{EMOJI_SECTION} SECTION: Load API");

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

        let identity = "<process-security-environment>".to_string();

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
        // CreateProcessW must receive an explicit clean block or it would
        // inherit all wxc-exec process variables.
        let env_block = build_child_env_block(&request).map_err(|error| {
            ScriptResponse::error(&format!(
                "failed to create a clean child environment: {error}"
            ))
        })?;

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
        // descendant before we've assigned it to the job object below.
        let creation_flags = CREATE_SUSPENDED.0
            | no_window_flag
            | if env_block.is_some() {
                CREATE_UNICODE_ENVIRONMENT.0
            } else {
                0
            };

        let _ = writeln!(logger, "launching: {}", request.script_code);
        let _ = writeln!(logger, "identity: {identity}");

        let current_env_ptr = env_ptr;
        let current_creation_flags = creation_flags;

        let mut capture_session: Option<Box<dyn CaptureSessionOps>> = None;
        let mut security_environment: Option<ProcessSecurityEnvironment> = None;
        {
            let psec_spec = process_security_environment_spec.as_slice();
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
        let extended_startup =
            match SecurityEnvironmentStartupInfo::new(si, environment_handle, &inherited_handles) {
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
        let (success, last_error) = if result.is_ok() {
            (1, None)
        } else {
            (0, Some(unsafe { GetLastError() }))
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
                self.cleanup_capture_begin_failure(logger);
            }

            //
            // Diagnose the launch failure (FailurePhase::LaunchFailed).
            //
            let diagnostic_env = if request.inherit_default_env {
                None
            } else {
                request.env.as_deref()
            };
            let diag = diagnose_missing_required_env(err.0, diagnostic_env).unwrap_or_else(|| {
                diagnose_create_process_failure(
                    err.0,
                    &request.script_code,
                    &request.policy.readonly_paths,
                )
            });

            let mut extended_error = format!(
                "{CREATE_PROCESS_IN_SECURITY_ENVIRONMENT_API} failed: {err:?} (working directory: {})",
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
                    self.cleanup_capture_begin_failure(logger);
                }
                self.proxy_coordinator.stop(logger);

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
        // every descendant it spawns is captured), resume its main thread.
        // SAFETY: `pi.hThread` is the just-created, still-owned main-thread
        // handle; `ResumeThread` only adjusts its suspend count.
        let previous_suspend_count = unsafe { ResumeThread(pi.hThread) };
        if previous_suspend_count == u32::MAX {
            let mut message = format!(
                "ResumeThread failed for the BaseContainer child: {:?}",
                unsafe { GetLastError() }
            );
            if let Err(error) = job.terminate_and_wait(u32::MAX) {
                let _ = write!(
                    message,
                    "; additionally failed to terminate the sandbox process tree: {error}"
                );
            }
            unsafe {
                let _ = CloseHandle(pi.hProcess);
                let _ = CloseHandle(pi.hThread);
            }
            if let Some(error) = capture_session
                .take()
                .and_then(|session| session.finish(None).err())
            {
                let _ = write!(
                    message,
                    "; additionally failed to discard the learning-mode trace: {error}"
                );
            }
            self.proxy_coordinator.stop(logger);
            return Err(ScriptResponse {
                failure_phase: FailurePhase::LaunchFailed,
                ..ScriptResponse::error(&message)
            });
        }

        wxc_common::telemetry::log_network_policy_applied(
            sanitize_identity(&identity),
            request.policy.network_enforcement_mode.as_str(),
            request.policy.default_network_policy.as_str(),
            request
                .policy
                .network_proxy
                .address
                .as_ref()
                .map(|address| address.port as u64)
                .unwrap_or(0),
        );
        if logger.has_diagnostic_sink() {
            let record = AuditEvent::new(AuditEventName::NetworkPolicyApplied)
                .str("backend", ContainmentBackend::ProcessContainer.wire_name())
                .str("identity", sanitize_identity(&identity))
                .str(
                    "tier",
                    crate::fallback_detector::IsolationTier::BaseContainer.as_str(),
                )
                .str(
                    "enforcement_mode",
                    request.policy.network_enforcement_mode.as_str(),
                )
                .str(
                    "default_policy",
                    request.policy.default_network_policy.as_str(),
                )
                .u64(
                    "proxy_port",
                    request
                        .policy
                        .network_proxy
                        .address
                        .as_ref()
                        .map(|address| address.port as u64)
                        .unwrap_or(0),
                )
                .u64("firewall_rules_created", 0)
                .bool("firewall_applied", false)
                .str(
                    "status",
                    wxc_common::audit::OperationStatus::Success.as_str(),
                );
            logger.log_audit_event(&record);
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
            preserve_policy: request.lifecycle.preserve_policy,
            identity,
            proxy_coordinator: std::mem::take(&mut self.proxy_coordinator),
            capture_session,
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
/// `spawn_base` resumes it only after job assignment. This owns the process
/// handle, parent-side pipe ends, and per-run state it tears down once the
/// child exits.
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
    preserve_policy: bool,
    identity: String,
    proxy_coordinator: ProxyCoordinator,
    /// Live learning-mode capture session (`Some` only when `captureDenials`
    /// is configured and the OS API is available). Sealed in `run_teardown`
    /// after the child exits.
    capture_session: Option<Box<dyn CaptureSessionOps>>,
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
    fn network_policy_support(&self) -> NetworkPolicySupport {
        NetworkPolicySupport::ALL
    }

    fn validate(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        validate_required_child_env(request)?;
        validate_network_policy_support(request, self.network_policy_support())?;
        let capture_denials = request.policy.capture_denials.is_some();
        if !request.policy.allowed_hosts.is_empty() || !request.policy.blocked_hosts.is_empty() {
            return Err(ScriptResponse::error(
                wxc_common::error::HOST_LISTS_NOT_SUPPORTED_MSG,
            ));
        }
        if has_conflicting_proxy_identity(&request.policy) {
            return Err(ScriptResponse::error(
                "processContainer.network.allowedProxyPeer grants loopback access only to the \
                 specified peer and cannot be combined with \
                 network.ingress.hostLoopback='allow', which grants unrestricted host-loopback \
                 access",
            ));
        }
        // Dry-run validates the schema and policy shape without selecting or
        // probing a host capture provider.
        if request.dry_run {
            return Ok(());
        }
        if !self.uses_process_security_environment(request) {
            return Err(ScriptResponse {
                failure_phase: FailurePhase::BackendUnavailable,
                ..ScriptResponse::error(
                    "the request cannot be represented by the process security environment \
                     available on this host",
                )
            });
        }
        if request.policy.least_privilege_mode {
            return Err(ScriptResponse::error(
                "the process-security-environment path cannot be combined with \
                 processContainer.leastPrivilege because it does not support LPAC tokens",
            ));
        }
        if !capture_denials {
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
        if !request.policy.denied_paths.is_empty() {
            let deny_supported = self
                .capture_support
                .supports_deny_paths()
                .map_err(|message| ScriptResponse {
                    failure_phase: FailurePhase::BackendUnavailable,
                    ..ScriptResponse::error(&message)
                })?;
            if !deny_supported {
                return Err(ScriptResponse {
                    failure_phase: FailurePhase::BackendUnavailable,
                    ..ScriptResponse::error(PSEC_DENIED_PATHS_UNSUPPORTED_MSG)
                });
            }
        }
        Ok(())
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
        Ok(Box::new(BaseContainerSandboxProcess::from_child(
            child, logger,
        )))
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
    // Retained here, in addition to the optional engine telemetry wrapper, so
    // callers still receive timeout classification when telemetry is disabled.
    timeout_requested: bool,
    preserve_policy: bool,
    identity: String,
    proxy_coordinator: ProxyCoordinator,
    /// Cached teardown outcome so repeated terminal waits cannot hide a
    /// capture failure after the session has been consumed.
    teardown_result: Option<Result<(), String>>,
    /// Live learning-mode capture session, moved from the `BaseChild`. Sealed
    /// in `run_teardown` once the child has exited and been reaped.
    capture_session: Option<Box<dyn CaptureSessionOps>>,
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
    audit_logger: Logger,
}

// SAFETY: the fields are Windows HANDLEs / handle-owning managers and owned
// strings. HANDLEs are process-global and safe to use from any single thread;
// this handle is owned exclusively by the caller, so moving it across threads
// is sound.
unsafe impl Send for BaseContainerSandboxProcess {}

impl BaseContainerSandboxProcess {
    fn from_child(mut child: BaseChild, logger: &Logger) -> Self {
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
            timeout_requested: false,
            preserve_policy: child.preserve_policy,
            identity: sanitize_identity(&std::mem::take(&mut child.identity)).to_string(),
            proxy_coordinator: std::mem::take(&mut child.proxy_coordinator),
            teardown_result: None,
            capture_session: child.capture_session.take(),
            security_environment: child.security_environment.take(),
            managed_capture: child.managed_capture.take(),
            capture_output_path: child.capture_output_path.take(),
            retain_capture_etl: child.retain_capture_etl,
            last_exit_code: None,
            output_metadata: None,
            audit_logger: logger.clone_diagnostic_sink(),
        }
    }

    fn audit(&self, name: AuditEventName) -> AuditEvent {
        AuditEvent::new(name)
            .str("backend", ContainmentBackend::ProcessContainer.wire_name())
            .str("identity", &self.identity)
            .str(
                "tier",
                crate::fallback_detector::IsolationTier::BaseContainer.as_str(),
            )
            .u64("pid", self.pid as u64)
    }

    fn audit_enabled(&self) -> bool {
        self.audit_logger.has_diagnostic_sink()
    }

    fn run_teardown(&mut self, allow_retention: bool) -> std::io::Result<()> {
        if let Some(result) = &self.teardown_result {
            return result.clone().map_err(std::io::Error::other);
        }
        let mut logger = self.audit_logger.clone_diagnostic_sink();

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
        self.security_environment.take();
        let proxy_stopped = self.proxy_coordinator.stop(&mut logger);
        let result = capture_result
            .map(|_| ())
            .map_err(|error| error.to_string());
        self.log_teardown(&result, proxy_stopped);
        self.teardown_result = Some(result.clone());
        result.map_err(std::io::Error::other)
    }

    fn log_teardown(&mut self, capture_result: &Result<(), String>, proxy_stopped: bool) {
        if !self.audit_enabled() && !wxc_common::telemetry::is_active() {
            return;
        }
        let (status, skip_reason) =
            base_container_teardown_status(capture_result.is_err(), false, self.preserve_policy);
        wxc_common::telemetry::log_sandbox_torn_down(
            &self.identity,
            status.as_str(),
            &format!(
                "firewall_rules_removed=0,bfs_removed=false,proxy_stopped={proxy_stopped},\
                 container_released=false"
            ),
        );
        if self.audit_enabled() {
            let mut record = self
                .audit(AuditEventName::SandboxTornDown)
                .str("status", status.as_str())
                .u64("firewall_rules_removed", 0)
                .bool("firewall_removal_ok", true)
                .bool("bfs_removed", false)
                .bool("proxy_stopped", proxy_stopped)
                .bool("preserve_policy", self.preserve_policy)
                .bool("container_released", false);
            if let Some(reason) = skip_reason {
                record = record.str("skip_reason", reason.as_str());
            }
            self.audit_logger.log_audit_event(&record);
        }
    }

    fn kill_process_tree(&mut self) -> std::io::Result<()> {
        if let Some(job) = &self.job {
            if let Err(error) = job.terminate_raw(u32::MAX) {
                self.record_kill_failure(KillMethod::TerminateJobObject, &error);
                return Err(std::io::Error::other(format!(
                    "TerminateJobObject: {error}"
                )));
            }
            if let Err(drain_warning) = job.wait_for_empty() {
                write_stderr_line_best_effort(format_args!(
                    "sandbox job did not fully drain within the teardown window \
                     (continuing): {drain_warning}"
                ));
            }
        } else if let Err(error) = unsafe { TerminateProcess(self.process.get(), u32::MAX) } {
            self.record_kill_failure(KillMethod::TerminateProcess, &error);
            return Err(std::io::Error::other(format!("TerminateProcess: {error}")));
        }
        Ok(())
    }

    fn record_kill_failure(&mut self, method: KillMethod, error: &windows::core::Error) {
        wxc_common::telemetry::log_process_event(
            &self.identity,
            self.pid,
            wxc_common::telemetry::ProcessEvent::KillFailed(method.as_str(), error.code().0),
        );
        if self.audit_enabled() {
            let record = self
                .audit(AuditEventName::ProcessKillFailed)
                .str("kill_method", method.as_str())
                .i64("error_code", error.code().0 as i64);
            self.audit_logger.log_audit_event(&record);
        }
    }

    fn timeout_result(&mut self) -> std::io::Result<i32> {
        wxc_common::telemetry::log_process_event(
            &self.identity,
            self.pid,
            wxc_common::telemetry::ProcessEvent::TimedOut(self.timeout_ms as u64),
        );
        if self.audit_enabled() {
            let record = self
                .audit(AuditEventName::ProcessTimedOut)
                .u64("timeout_ms", self.timeout_ms as u64);
            self.audit_logger.log_audit_event(&record);
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("script timed out after {}ms", self.timeout_ms),
        ))
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

fn base_container_teardown_status(
    capture_failed: bool,
    destroy_on_exit: bool,
    preserve_policy: bool,
) -> (TeardownStatus, Option<TeardownSkipReason>) {
    if capture_failed {
        (TeardownStatus::Failure, None)
    } else if preserve_policy {
        (
            TeardownStatus::Skipped,
            Some(TeardownSkipReason::PreservePolicy),
        )
    } else if destroy_on_exit {
        (
            TeardownStatus::Skipped,
            Some(TeardownSkipReason::CleanupNotImplemented),
        )
    } else {
        (TeardownStatus::Success, None)
    }
}

impl SandboxProcess for BaseContainerSandboxProcess {
    fn output_metadata(&self) -> Option<&SandboxOutputMetadata> {
        self.output_metadata.as_ref()
    }

    fn take_native_stdio(&mut self) -> std::io::Result<Option<NativeStdio>> {
        let stdio = duplicate_and_take_native_stdio(
            &mut self.stdin,
            &mut self.stdout,
            &mut self.stderr,
            |stream| stream.try_clone_owned_handle(),
            |stream| stream.try_clone_owned_handle(),
            |stream| stream.try_clone_owned_handle(),
        )?;
        if stdio.is_some() {
            self.stdout_canceller.take();
            self.stderr_canceller.take();
        }
        Ok(stdio)
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
                if self.timeout_requested {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "sandbox execution timed out",
                    ))
                } else {
                    Ok(Some(code as i32))
                }
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

    fn kill_for_timeout(&mut self) -> std::io::Result<()> {
        self.timeout_requested = true;
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
                } else if self.timeout_requested {
                    self.timeout_result()
                } else {
                    let exit_code = code as i32;
                    wxc_common::telemetry::log_process_event(
                        &self.identity,
                        self.pid,
                        wxc_common::telemetry::ProcessEvent::Exited(exit_code),
                    );
                    if self.audit_enabled() {
                        let record = self
                            .audit(AuditEventName::ProcessExited)
                            .i64("exit_code", exit_code as i64);
                        self.audit_logger.log_audit_event(&record);
                    }
                    Ok(exit_code)
                }
            }
            WAIT_TIMEOUT => self.timeout_result(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job_object::to_job_object_uilimit_mask;
    use learning_mode_core::{
        AccessType, AnalysisResult, AnalyzeError, DenialsDocument, DeniedResource, ResourceType,
    };
    use process_security_environment_spec::process_security_environment_layout as psec_layout;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wxc_common::models::{
        ContainerPolicy, NetworkAction, NetworkCidr, NetworkEnforcementCompatibility, NetworkPeer,
        NetworkPolicy, NetworkPort, NetworkProtocol, NetworkRule, ProxyConfig,
    };
    use wxc_common::ui_policy::EffectiveUiRestrictions;

    struct FakePsecCapabilityProbe {
        version_1_1: Result<bool, &'static str>,
        enumerate_paths: Result<bool, &'static str>,
        network_ingress: Result<bool, &'static str>,
    }

    impl PsecCapabilityProbe for FakePsecCapabilityProbe {
        fn supports_version_1_1(&self) -> Result<bool, String> {
            self.version_1_1.map_err(str::to_string)
        }

        fn supports_enumerate_paths(&self) -> Result<bool, String> {
            self.enumerate_paths.map_err(str::to_string)
        }

        fn supports_network_ingress(&self) -> Result<bool, String> {
            self.network_ingress.map_err(str::to_string)
        }
    }

    fn enumerate_request() -> ExecutionRequest {
        let mut request = ExecutionRequest::default();
        request.policy.enumerate_paths = vec!["C:\\tools".to_string()];
        request.policy.network_ingress = Some(wxc_common::models::NetworkIngressPolicy {
            default: NetworkAction::Deny,
            host_loopback: NetworkAction::Deny,
        });
        request
    }

    fn host_loopback_request() -> ExecutionRequest {
        let mut request = ExecutionRequest::default();
        request.policy.network_ingress = Some(wxc_common::models::NetworkIngressPolicy {
            default: NetworkAction::Allow,
            host_loopback: NetworkAction::Allow,
        });
        request
    }

    fn response_error(response: ScriptResponse) -> String {
        response.error_message
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
            network_enforcement_compatibility: NetworkEnforcementCompatibility::Strict,
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
        // ERROR_INVALID_PARAMETER and success are not disabled-feature failures.
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
    fn validate_runner_rejects_a_sparse_verbatim_environment_before_host_probes() {
        let runner = BaseContainerRunner::new();
        let request = ExecutionRequest {
            env: Some(vec!["SystemRoot=C:\\Windows".to_string()]),
            ..Default::default()
        };

        let error = runner
            .validate(&request)
            .expect_err("BaseContainer must reject the environment before launch");
        assert_eq!(error.failure_phase, FailurePhase::Rejected);
        assert!(error.error_message.contains("LOCALAPPDATA"));
    }

    #[test]
    fn runtime_proxy_builds_psec_environment() {
        let mut request = ExecutionRequest::default();
        request.policy.runtime_network_proxy_specified = true;
        request.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("127.0.0.1".to_string(), 8080)),
            builtin_test_server: false,
        };
        request.env = Some(vec!["PATH=C:\\Windows".to_string()]);

        let environment = build_child_env_block(&request)
            .expect("environment")
            .expect("runtime proxy environment");
        let rendered = String::from_utf16_lossy(&environment);
        assert!(rendered.contains("PATH=C:\\Windows"));
        assert!(rendered.contains("HTTP_PROXY=http://127.0.0.1:8080"));
        assert!(rendered.contains("HTTPS_PROXY=http://127.0.0.1:8080"));
    }

    #[test]
    fn absent_env_yields_the_default_user_environment() {
        // No caller environment: the child must get a populated default block,
        // not an empty one.
        let request = ExecutionRequest::default();
        assert!(request.env.is_none());

        let environment = build_child_env_block(&request)
            .expect("environment")
            .expect("PSEC always needs an explicit block");
        let rendered = String::from_utf16_lossy(&environment);
        assert!(
            rendered.len() > 2,
            "default block should carry the user profile variables"
        );
    }

    #[test]
    fn explicitly_empty_env_yields_an_empty_block_not_the_default() {
        // `"env": []` is a request for an empty environment. It must not be
        // silently upgraded to the default profile block.
        let request = ExecutionRequest {
            env: Some(Vec::new()),
            ..Default::default()
        };

        let environment = build_child_env_block(&request)
            .expect("environment")
            .expect("an explicitly empty env must still produce a block");
        assert_eq!(
            environment.len(),
            2,
            "an empty block still requires two terminators"
        );
        assert_eq!(environment, vec![0u16, 0u16]);
    }

    #[test]
    fn supplied_env_is_used_verbatim() {
        // MXC adds nothing to a caller-supplied environment -- notably not the
        // variables Windows requires to be present. A caller that replaces the
        // block owns its contents; a missing requirement surfaces as an
        // actionable launch error instead.
        let request = ExecutionRequest {
            env: Some(vec!["MYVAR=hello".to_string()]),
            ..Default::default()
        };

        let environment = build_child_env_block(&request)
            .expect("environment")
            .expect("explicit block");
        let rendered = String::from_utf16_lossy(&environment);

        assert!(rendered.contains("MYVAR=hello"));
        assert!(!rendered.to_ascii_uppercase().contains("SYSTEMROOT"));
        assert!(!rendered.to_ascii_uppercase().contains("LOCALAPPDATA"));
    }

    #[test]
    fn inherit_default_env_layers_the_caller_entries_on_the_default_block() {
        // `inheritDefaultEnv` is how a caller asks for "the profile block plus
        // these": the defaults must survive, and a caller entry must replace
        // the same-named default rather than being appended alongside it.
        let request = ExecutionRequest {
            env: Some(vec![
                "MYVAR=hello".to_string(),
                "systemroot=C:\\Override".to_string(),
            ]),
            inherit_default_env: true,
            ..Default::default()
        };

        let environment = build_child_env_block(&request)
            .expect("environment")
            .expect("explicit block");
        let rendered = String::from_utf16_lossy(&environment);

        assert!(rendered.contains("MYVAR=hello"));
        assert!(rendered.to_ascii_uppercase().contains("LOCALAPPDATA"));
        assert!(rendered.contains("systemroot=C:\\Override"));
        assert_eq!(
            rendered.to_ascii_uppercase().matches("SYSTEMROOT=").count(),
            1,
            "a caller entry must replace the default, not duplicate it"
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
    fn build_process_security_environment_spec_serializes_enumerate_paths_as_v1_1() {
        let mut request = ExecutionRequest::default();
        request.policy.enumerate_paths = vec!["C:\\tools".into()];

        let bytes = BaseContainerRunner::build_process_security_environment_spec(&request);
        let spec = psec_layout::root_as_process_security_environment(&bytes).unwrap();

        assert_eq!(spec.version().major(), 1);
        assert_eq!(spec.version().minor(), 1);
        assert_eq!(
            spec.fs_enumerate().unwrap().iter().collect::<Vec<_>>(),
            vec!["C:\\tools"]
        );
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
    fn build_process_security_environment_spec_preserves_directional_allow_egress() {
        let mut request = ExecutionRequest::default();
        request.policy.network_egress = Some(wxc_common::models::NetworkEgressPolicy {
            default: NetworkAction::Allow,
            ..Default::default()
        });

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
    fn psec_1_1_encodes_host_loopback_ingress() {
        let mut request = ExecutionRequest::default();
        request.policy.network_ingress = Some(wxc_common::models::NetworkIngressPolicy {
            default: NetworkAction::Deny,
            host_loopback: NetworkAction::Allow,
        });

        let bytes = BaseContainerRunner::build_process_security_environment_spec(&request);
        let spec = psec_layout::root_as_process_security_environment(&bytes).unwrap();
        let ingress = spec
            .network_policy()
            .and_then(|network| network.ingress())
            .expect("PSEC 1.1 must carry host-loopback policy");

        assert_eq!(spec.version().minor(), 1);
        assert!(spec.capabilities().is_none());
        assert_eq!(ingress.default_action(), psec_layout::FilterAction::deny);
        assert_eq!(ingress.host_loopback(), psec_layout::FilterAction::allow);
        assert_eq!(
            spec.network_policy()
                .and_then(|network| network.allowed_appcontainer_peer()),
            Some(crate::base_container_helpers::LOOPBACK_NETWORK_PEER)
        );
    }

    #[test]
    fn psec_resolver_rejects_unsupported_version_with_enumeration_diagnostic() {
        let error = BaseContainerRunner::resolve_psec_contract_with_probe(
            &enumerate_request(),
            &FakePsecCapabilityProbe {
                version_1_1: Ok(false),
                enumerate_paths: Ok(true),
                network_ingress: Ok(true),
            },
        )
        .unwrap_err();

        assert_eq!(response_error(error), PSEC_ENUMERATE_PATHS_UNSUPPORTED_MSG);
    }

    #[test]
    fn psec_resolver_rejects_unsupported_enumeration_capability() {
        let error = BaseContainerRunner::resolve_psec_contract_with_probe(
            &enumerate_request(),
            &FakePsecCapabilityProbe {
                version_1_1: Ok(true),
                enumerate_paths: Ok(false),
                network_ingress: Ok(true),
            },
        )
        .unwrap_err();

        assert_eq!(response_error(error), PSEC_ENUMERATE_PATHS_UNSUPPORTED_MSG);
    }

    #[test]
    fn psec_enumeration_without_ingress_support_omits_ingress_table() {
        let request = enumerate_request();
        let resolution = BaseContainerRunner::resolve_psec_contract_with_probe(
            &request,
            &FakePsecCapabilityProbe {
                version_1_1: Ok(true),
                enumerate_paths: Ok(true),
                network_ingress: Ok(false),
            },
        )
        .unwrap();

        let bytes = build_psec_spec(&request, resolution);
        let spec = psec_layout::root_as_process_security_environment(&bytes).unwrap();

        assert_eq!(spec.version().minor(), 1);
        assert!(spec.network_policy().unwrap().ingress().is_none());
    }

    #[test]
    fn psec_resolver_preserves_host_loopback_diagnostic_when_version_is_unsupported() {
        let error = BaseContainerRunner::resolve_psec_contract_with_probe(
            &host_loopback_request(),
            &FakePsecCapabilityProbe {
                version_1_1: Ok(false),
                enumerate_paths: Ok(true),
                network_ingress: Ok(true),
            },
        )
        .unwrap_err();

        assert_eq!(response_error(error), PSEC_INGRESS_UNSUPPORTED_MSG);
    }

    #[test]
    fn psec_resolver_rejects_host_loopback_without_ingress_capability() {
        let error = BaseContainerRunner::resolve_psec_contract_with_probe(
            &host_loopback_request(),
            &FakePsecCapabilityProbe {
                version_1_1: Ok(true),
                enumerate_paths: Ok(true),
                network_ingress: Ok(false),
            },
        )
        .unwrap_err();

        assert_eq!(response_error(error), PSEC_INGRESS_UNSUPPORTED_MSG);
    }

    #[test]
    fn psec_resolver_surfaces_capability_query_errors() {
        let version_error = BaseContainerRunner::resolve_psec_contract_with_probe(
            &enumerate_request(),
            &FakePsecCapabilityProbe {
                version_1_1: Err("version query failed"),
                enumerate_paths: Ok(true),
                network_ingress: Ok(true),
            },
        )
        .unwrap_err();
        assert!(response_error(version_error).contains("version query failed"));

        let enumeration_error = BaseContainerRunner::resolve_psec_contract_with_probe(
            &enumerate_request(),
            &FakePsecCapabilityProbe {
                version_1_1: Ok(true),
                enumerate_paths: Err("enumeration query failed"),
                network_ingress: Ok(true),
            },
        )
        .unwrap_err();
        assert!(response_error(enumeration_error).contains("enumeration query failed"));

        let ingress_error = BaseContainerRunner::resolve_psec_contract_with_probe(
            &enumerate_request(),
            &FakePsecCapabilityProbe {
                version_1_1: Ok(true),
                enumerate_paths: Ok(true),
                network_ingress: Err("ingress query failed"),
            },
        )
        .unwrap_err();
        assert!(response_error(ingress_error).contains("ingress query failed"));
    }

    #[test]
    fn psec_resolver_returns_full_capability_success() {
        let resolution = BaseContainerRunner::resolve_psec_contract_with_probe(
            &host_loopback_request(),
            &FakePsecCapabilityProbe {
                version_1_1: Ok(true),
                enumerate_paths: Ok(true),
                network_ingress: Ok(true),
            },
        )
        .unwrap();

        assert_eq!(resolution.contract, PsecContract::V1_1);
        assert!(resolution.supports_network_ingress);
    }

    #[test]
    fn psec_1_0_uses_capability_for_ingress_default_allow() {
        let mut request = ExecutionRequest::default();
        request.policy.network_ingress = Some(wxc_common::models::NetworkIngressPolicy {
            default: NetworkAction::Allow,
            host_loopback: NetworkAction::Deny,
        });
        request.policy.allowed_proxy_peer = Some("S-1-15-2-1".into());

        let bytes = build_psec_spec(&request, ResolvedPsecContract::baseline());
        let spec = psec_layout::root_as_process_security_environment(&bytes).unwrap();
        let network = spec.network_policy().expect("network policy");

        assert_eq!(spec.version().minor(), 0);
        assert_eq!(
            spec.capabilities(),
            Some(crate::network_policy_helpers::PRIVATE_NETWORK_CAPABILITY)
        );
        assert_eq!(network.allowed_appcontainer_peer(), Some("S-1-15-2-1"));
        assert!(network.ingress().is_none());
    }

    #[test]
    fn psec_proxy_and_direct_egress_forms_are_mutually_exclusive() {
        for runtime_proxy_specified in [false, true] {
            let mut request = ExecutionRequest::default();
            request.policy.runtime_network_proxy_specified = runtime_proxy_specified;
            request.policy.network_proxy = ProxyConfig {
                address: Some(ProxyAddress::new("127.0.0.1".to_string(), 8080)),
                builtin_test_server: false,
            };
            request.policy.allowed_proxy_peer = Some("Contoso.Proxy_12345".to_string());

            let bytes = BaseContainerRunner::build_process_security_environment_spec(&request);
            let spec = psec_layout::root_as_process_security_environment(&bytes).unwrap();
            let network = spec.network_policy().expect("network policy");
            assert_eq!(
                network.proxy().and_then(|proxy| proxy.url()),
                Some("http://127.0.0.1:8080")
            );
            assert_eq!(
                network.allowed_appcontainer_peer(),
                Some("Contoso.Proxy_12345")
            );
            assert!(network.egress().is_none());
        }

        let request = ExecutionRequest::default();
        let bytes = BaseContainerRunner::build_process_security_environment_spec(&request);
        let spec = psec_layout::root_as_process_security_environment(&bytes).unwrap();
        let network = spec.network_policy().expect("network policy");
        assert!(network.proxy().is_none());
        assert!(network.egress().is_some());
    }

    fn request_with_rich_network_rules() -> ExecutionRequest {
        let mut request = ExecutionRequest::default();
        request.policy.network_egress = Some(wxc_common::models::NetworkEgressPolicy {
            default: NetworkAction::Deny,
            allow: vec![NetworkRule {
                to: vec![
                    NetworkPeer {
                        cidr: NetworkCidr {
                            address: "10.0.0.0".parse().unwrap(),
                            prefix_length: 8,
                        },
                        except: vec![NetworkCidr {
                            address: "10.1.0.0".parse().unwrap(),
                            prefix_length: 16,
                        }],
                    },
                    NetworkPeer {
                        cidr: NetworkCidr {
                            address: "2001:db8::".parse().unwrap(),
                            prefix_length: 32,
                        },
                        except: Vec::new(),
                    },
                ],
                ports: vec![NetworkPort {
                    protocol: NetworkProtocol::Icmp,
                    port: None,
                    end_port: None,
                }],
            }],
            deny: vec![NetworkRule {
                to: Vec::new(),
                ports: vec![NetworkPort {
                    protocol: NetworkProtocol::Tcp,
                    port: Some(8000),
                    end_port: Some(8080),
                }],
            }],
        });
        request
    }

    #[test]
    fn build_process_security_environment_spec_preserves_rich_network_rules() {
        let request = request_with_rich_network_rules();
        let bytes = BaseContainerRunner::build_process_security_environment_spec(&request);
        let spec = psec_layout::root_as_process_security_environment(&bytes).unwrap();
        let egress = spec
            .network_policy()
            .and_then(|policy| policy.egress())
            .expect("egress policy");

        assert_eq!(spec.capabilities(), Some("internetClient"));
        let allow = egress.allow().expect("allow rules");
        assert_eq!(allow.len(), 2, "ICMP must expand by address family");
        assert_eq!(
            allow.get(0).ports().unwrap().get(0).protocol(),
            psec_layout::IpProtocol::icmpv4
        );
        let ipv4_destination = allow.get(0).destinations().unwrap().get(0);
        assert_eq!(
            ipv4_destination.subnet().unwrap().address(),
            Some("10.0.0.0")
        );
        assert_eq!(
            ipv4_destination.except().unwrap().get(0).address(),
            Some("10.1.0.0")
        );
        assert_eq!(
            allow.get(1).ports().unwrap().get(0).protocol(),
            psec_layout::IpProtocol::icmpv6
        );
        assert_eq!(
            allow
                .get(1)
                .destinations()
                .unwrap()
                .get(0)
                .subnet()
                .unwrap()
                .address(),
            Some("2001:db8::")
        );

        let denied_port = egress.deny().unwrap().get(0).ports().unwrap().get(0);
        assert_eq!(denied_port.protocol(), psec_layout::IpProtocol::tcp);
        assert_eq!(denied_port.port(), 8000);
        assert_eq!(denied_port.end_port(), 8080);
    }

    #[test]
    fn build_process_security_environment_spec_splits_mixed_icmp_rules() {
        let mut request = ExecutionRequest::default();
        request.policy.network_egress = Some(wxc_common::models::NetworkEgressPolicy {
            default: NetworkAction::Deny,
            allow: vec![NetworkRule {
                to: Vec::new(),
                ports: vec![
                    NetworkPort {
                        protocol: NetworkProtocol::Tcp,
                        port: Some(443),
                        end_port: None,
                    },
                    NetworkPort {
                        protocol: NetworkProtocol::Icmp,
                        port: None,
                        end_port: None,
                    },
                ],
            }],
            deny: Vec::new(),
        });

        let bytes = BaseContainerRunner::build_process_security_environment_spec(&request);
        let spec = psec_layout::root_as_process_security_environment(&bytes).unwrap();
        let allow = spec
            .network_policy()
            .and_then(|policy| policy.egress())
            .and_then(|egress| egress.allow())
            .expect("allow rules");

        assert_eq!(allow.len(), 3);
        assert_eq!(
            allow.get(0).ports().unwrap().get(0).protocol(),
            psec_layout::IpProtocol::tcp
        );
        assert_eq!(
            allow.get(1).ports().unwrap().get(0).protocol(),
            psec_layout::IpProtocol::icmpv4
        );
        assert_eq!(
            allow.get(2).ports().unwrap().get(0).protocol(),
            psec_layout::IpProtocol::icmpv6
        );
    }

    #[test]
    fn build_process_security_environment_spec_limits_icmp_to_destination_family() {
        for (cidr, expected_protocol) in [
            ("10.0.0.0/8", psec_layout::IpProtocol::icmpv4),
            ("2001:db8::/32", psec_layout::IpProtocol::icmpv6),
        ] {
            let (address, prefix_length) = cidr.split_once('/').unwrap();
            let mut request = ExecutionRequest::default();
            request.policy.network_egress = Some(wxc_common::models::NetworkEgressPolicy {
                default: NetworkAction::Deny,
                allow: vec![NetworkRule {
                    to: vec![NetworkPeer {
                        cidr: NetworkCidr {
                            address: address.parse().unwrap(),
                            prefix_length: prefix_length.parse().unwrap(),
                        },
                        except: Vec::new(),
                    }],
                    ports: vec![NetworkPort {
                        protocol: NetworkProtocol::Icmp,
                        port: None,
                        end_port: None,
                    }],
                }],
                deny: Vec::new(),
            });

            let bytes = BaseContainerRunner::build_process_security_environment_spec(&request);
            let spec = psec_layout::root_as_process_security_environment(&bytes).unwrap();
            let allow = spec
                .network_policy()
                .and_then(|policy| policy.egress())
                .and_then(|egress| egress.allow())
                .expect("allow rules");

            assert_eq!(allow.len(), 1, "{cidr} must emit one ICMP family");
            assert_eq!(
                allow.get(0).ports().unwrap().get(0).protocol(),
                expected_protocol
            );
        }
    }

    #[test]
    fn build_process_security_environment_spec_preserves_all_port_destinations() {
        let peer = NetworkPeer {
            cidr: NetworkCidr {
                address: "10.0.0.0".parse().unwrap(),
                prefix_length: 8,
            },
            except: Vec::new(),
        };
        let mut request = ExecutionRequest::default();
        request.policy.network_egress = Some(wxc_common::models::NetworkEgressPolicy {
            default: NetworkAction::Deny,
            allow: vec![NetworkRule {
                to: vec![peer.clone()],
                ports: Vec::new(),
            }],
            deny: vec![NetworkRule {
                to: vec![peer],
                ports: Vec::new(),
            }],
        });

        let bytes = BaseContainerRunner::build_process_security_environment_spec(&request);
        let spec = psec_layout::root_as_process_security_environment(&bytes).unwrap();
        let egress = spec
            .network_policy()
            .and_then(|policy| policy.egress())
            .expect("egress policy");

        for rule in [
            egress.allow().unwrap().get(0),
            egress.deny().unwrap().get(0),
        ] {
            assert!(rule.ports().is_none(), "empty ports means all ports");
            assert_eq!(
                rule.destinations()
                    .unwrap()
                    .get(0)
                    .subnet()
                    .unwrap()
                    .address(),
                Some("10.0.0.0")
            );
        }
    }

    #[test]
    fn process_security_environment_preference_is_network_compatibility_independent() {
        for compatibility in [
            NetworkEnforcementCompatibility::LegacyCompatible,
            NetworkEnforcementCompatibility::Strict,
        ] {
            let request = ExecutionRequest {
                network_enforcement_compatibility: compatibility,
                ..Default::default()
            };
            assert!(
                BaseContainerRunner::should_use_process_security_environment(
                    &request, true, true, true,
                ),
                "PSEC should be preferred for {compatibility:?}"
            );
        }
    }

    #[test]
    fn psec_is_used_only_when_runtime_probe_succeeds() {
        let request = ExecutionRequest {
            network_enforcement_compatibility: NetworkEnforcementCompatibility::LegacyCompatible,
            ..Default::default()
        };

        assert!(
            BaseContainerRunner::should_use_process_security_environment(
                &request, true, true, true
            )
        );
        assert!(
            !BaseContainerRunner::should_use_process_security_environment(
                &request, false, true, true
            )
        );
    }

    #[test]
    fn runtime_proxy_requires_psec() {
        let mut request = ExecutionRequest::default();
        request.policy.runtime_network_proxy_specified = true;
        request.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("127.0.0.1".to_string(), 8080)),
            builtin_test_server: false,
        };
        request.policy.network_egress = Some(wxc_common::models::NetworkEgressPolicy::default());
        request.policy.network_ingress = Some(wxc_common::models::NetworkIngressPolicy {
            default: NetworkAction::Allow,
            host_loopback: NetworkAction::Allow,
        });

        assert!(
            BaseContainerRunner::should_use_process_security_environment(
                &request, true, true, true
            )
        );
        assert!(
            !BaseContainerRunner::should_use_process_security_environment(
                &request, false, true, true
            )
        );
    }

    #[test]
    fn conflicting_proxy_identity_table() {
        for allowed_proxy_peer in [false, true] {
            for host_loopback in [NetworkAction::Deny, NetworkAction::Allow] {
                let mut policy = ContainerPolicy {
                    network_ingress: Some(wxc_common::models::NetworkIngressPolicy {
                        default: NetworkAction::Allow,
                        host_loopback,
                    }),
                    ..Default::default()
                };
                if allowed_proxy_peer {
                    policy.allowed_proxy_peer = Some("Contoso.Proxy_123".to_string());
                }

                assert_eq!(
                    has_conflicting_proxy_identity(&policy),
                    allowed_proxy_peer && host_loopback == NetworkAction::Allow
                );
            }
        }
    }

    #[test]
    fn validate_rejects_conflicting_proxy_identity_paths() {
        let runner = BaseContainerRunner::with_capture_factory(fake_capture_factory());
        let mut request = ExecutionRequest {
            dry_run: true,
            ..Default::default()
        };
        request.policy.allowed_proxy_peer = Some("Contoso.Proxy_123".to_string());
        request.policy.network_ingress = Some(wxc_common::models::NetworkIngressPolicy {
            default: NetworkAction::Allow,
            host_loopback: NetworkAction::Allow,
        });

        let error = runner
            .validate(&request)
            .expect_err("proxy peer identity and host loopback are mutually exclusive");
        assert_eq!(
            error.error_message,
            "processContainer.network.allowedProxyPeer grants loopback access only to the \
             specified peer and cannot be combined with \
             network.ingress.hostLoopback='allow', which grants unrestricted host-loopback access"
        );
    }

    #[test]
    fn legacy_proxy_is_not_psec_compatible() {
        let mut request = ExecutionRequest::default();
        request.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("127.0.0.1".to_string(), 8080)),
            builtin_test_server: false,
        };

        let runner = BaseContainerRunner::with_capture_factory(fake_capture_factory());
        assert!(
            !BaseContainerRunner::should_use_process_security_environment(
                &request, true, true, true
            )
        );
        assert!(
            !runner.uses_process_security_environment(&request),
            "legacy proxy requests must fall through to an AppContainer tier"
        );
    }

    #[test]
    fn capture_runtime_proxy_uses_native_contract() {
        let _guard = crate::test_env::CaptureCapabilityGuard::set(true, true);
        let mut request = ExecutionRequest::default();
        request.policy.capture_denials = Some(Default::default());
        request.policy.runtime_network_proxy_specified = true;
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

        assert!(runner.uses_process_security_environment(&request));
        assert!(BaseContainerRunner::uses_native_capture_for_request(
            &request
        ));
    }

    #[test]
    fn least_privilege_is_not_psec_compatible() {
        let mut request = ExecutionRequest::default();
        request.policy.least_privilege_mode = true;

        assert!(
            !BaseContainerRunner::should_use_process_security_environment(
                &request, true, true, true
            )
        );
    }

    #[test]
    fn denied_paths_are_not_psec_compatible_when_support_is_absent() {
        let mut request = ExecutionRequest::default();
        request.policy.denied_paths = vec![r"C:\secret".to_string()];

        assert!(
            !BaseContainerRunner::should_use_process_security_environment(
                &request, true, false, true
            )
        );
    }

    #[test]
    fn enumerate_paths_require_supported_psec() {
        let mut request = ExecutionRequest::default();
        request.policy.enumerate_paths = vec![r"C:\tools".to_string()];

        assert!(
            BaseContainerRunner::should_use_process_security_environment(
                &request, true, true, true
            )
        );
        assert!(
            !BaseContainerRunner::should_use_process_security_environment(
                &request, true, true, false
            )
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
                    && !err.error_message.contains("PSE_SUPPORT_FS_DENY"),
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
            err.error_message
                .contains("cannot be represented by the process security environment"),
            "expected the PSEC compatibility message, got: {}",
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
        assert!(PSEC_DENIED_PATHS_UNSUPPORTED_MSG.contains("cannot fall back to AppContainer"));
    }

    #[test]
    fn capture_validation_rejects_when_v2_api_is_unavailable() {
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
        assert!(error
            .error_message
            .contains("cannot be represented by the process security environment"));
        assert_eq!(support.api_calls.load(Ordering::SeqCst), 1);
        assert_eq!(support.learning_mode_api_calls.load(Ordering::SeqCst), 1);
        assert_eq!(support.deny_calls.load(Ordering::SeqCst), 0);
        assert_eq!(factory.begin_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn capture_validation_rejects_when_native_deny_query_fails() {
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
        assert!(error
            .error_message
            .contains("cannot be represented by the process security environment"));
        assert_eq!(support.api_calls.load(Ordering::SeqCst), 1);
        assert_eq!(support.deny_calls.load(Ordering::SeqCst), 1);
        assert_eq!(factory.begin_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn capture_validation_rejects_when_native_deny_bit_is_clear() {
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
        assert!(error
            .error_message
            .contains("cannot be represented by the process security environment"));
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
            network_enforcement_compatibility: NetworkEnforcementCompatibility::LegacyCompatible,
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
            network_enforcement_compatibility: NetworkEnforcementCompatibility::LegacyCompatible,
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
            network_enforcement_compatibility: NetworkEnforcementCompatibility::LegacyCompatible,
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
