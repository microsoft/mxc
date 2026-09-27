// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Typed state-aware lifecycle C ABI.

use std::ffi::c_char;
use std::ptr;

use mxc_sdk::sandbox;
use mxc_sdk::{
    Error, ErrorCode, ExecRequest, OperationOptions, ProvisionMetadata, ProvisionRequest,
    SandboxId, StateAwareExecBackendOptions,
};

use crate::state_aware::{exec_outcome_to_abi, MxcExecOutcome};
use crate::streaming::{finish_spawn, MxcSandbox};
use crate::typed::{
    borrowed_slice, flag, optional_bool, optional_u32, optional_utf8, policy, presence, utf8,
    MxcEnvironment, MxcOptionalBool, MxcOptionalU32, MxcTypedFilesystemPolicy,
    MxcTypedNetworkPolicy, MxcTypedSandboxPolicy, MxcUtf8Slice, MXC_TYPED_ABI_VERSION_1,
};
use crate::{
    alloc_cstring, free_cstr, report_panic, status_from_error_code, MxcErrorDetail,
    MXC_STATUS_NULL_ARGUMENT, MXC_STATUS_PANIC, MXC_STATUS_SUCCESS,
};

/// Provision a new sandbox.
pub const MXC_STATE_AWARE_PROVISION: i32 = 0;
/// Start an existing sandbox.
pub const MXC_STATE_AWARE_START: i32 = 1;
/// Execute in an existing sandbox.
pub const MXC_STATE_AWARE_EXEC: i32 = 2;
/// Stop an existing sandbox.
pub const MXC_STATE_AWARE_STOP: i32 = 3;
/// Deprovision an existing sandbox.
pub const MXC_STATE_AWARE_DEPROVISION: i32 = 4;

/// Provision an IsolationSession sandbox.
pub const MXC_STATE_AWARE_ISOLATION_SESSION: i32 = 0;
/// Provision a WSL Container sandbox.
pub const MXC_STATE_AWARE_WSLC: i32 = 1;

/// No backend-specific provision metadata.
pub const MXC_PROVISION_METADATA_NONE: i32 = 0;
/// IsolationSession provision metadata.
pub const MXC_PROVISION_METADATA_ISOLATION_SESSION: i32 = 1;

/// Typed provision input.
#[repr(C)]
pub struct MxcTypedProvisionRequest {
    pub backend: i32,
    pub app_id: *const MxcUtf8Slice,
    pub image: *const MxcUtf8Slice,
    pub image_tar_path: *const MxcUtf8Slice,
    pub filesystem: *const MxcTypedFilesystemPolicy,
    pub network: *const MxcTypedNetworkPolicy,
}

/// Typed lifecycle exec input.
#[repr(C)]
pub struct MxcTypedExecRequest {
    pub command: MxcUtf8Slice,
    pub working_directory: *const MxcUtf8Slice,
    pub environment: MxcEnvironment,
    pub inherit_default_env: MxcOptionalBool,
    pub timeout_ms: MxcOptionalU32,
    pub network_proxy: *const MxcUtf8Slice,
}

/// Versioned typed state-aware operation request.
#[repr(C)]
pub struct MxcTypedStateAwareRequest {
    pub abi_version: u32,
    pub struct_size: usize,
    pub operation: i32,
    pub sandbox_id: *const MxcUtf8Slice,
    pub provision: *const MxcTypedProvisionRequest,
    pub exec: *const MxcTypedExecRequest,
    pub telemetry_enabled: MxcOptionalBool,
    pub experimental: i32,
}

/// Typed result for provision, lifecycle, and validation operations.
#[repr(C)]
pub struct MxcTypedStateAwareResult {
    pub status: i32,
    pub sandbox_id_utf8: *mut c_char,
    pub warnings_json_utf8: *mut c_char,
    pub metadata_kind: i32,
    pub agent_user_name_utf8: *mut c_char,
    pub agent_user_sid_utf8: *mut c_char,
    pub ephemeral_workspace_path_utf8: *mut c_char,
    pub error: MxcErrorDetail,
}

impl MxcTypedStateAwareResult {
    fn empty() -> Self {
        Self {
            status: MXC_STATUS_SUCCESS,
            sandbox_id_utf8: ptr::null_mut(),
            warnings_json_utf8: ptr::null_mut(),
            metadata_kind: MXC_PROVISION_METADATA_NONE,
            agent_user_name_utf8: ptr::null_mut(),
            agent_user_sid_utf8: ptr::null_mut(),
            ephemeral_workspace_path_utf8: ptr::null_mut(),
            error: MxcErrorDetail::none(),
        }
    }

    fn error(error: &Error) -> Self {
        Self {
            status: status_from_error_code(error.code),
            error: MxcErrorDetail::from_error(error),
            ..Self::empty()
        }
    }

    fn warnings(mut self, warnings: &[String]) -> Result<Self, Error> {
        if !warnings.is_empty() {
            let json = serde_json::to_vec(warnings).map_err(|error| {
                Error::new(
                    ErrorCode::BackendError,
                    format!("failed to serialize lifecycle warnings: {error}"),
                )
            })?;
            self.warnings_json_utf8 = alloc_cstring(&json);
        }
        Ok(self)
    }

    fn free_strings(&mut self) {
        free_cstr(&mut self.sandbox_id_utf8);
        free_cstr(&mut self.warnings_json_utf8);
        free_cstr(&mut self.agent_user_name_utf8);
        free_cstr(&mut self.agent_user_sid_utf8);
        free_cstr(&mut self.ephemeral_workspace_path_utf8);
        self.error.free_strings();
    }
}

fn malformed(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::MalformedRequest, message)
}

unsafe fn parse_request<'a>(
    request: *const MxcTypedStateAwareRequest,
) -> Result<&'a MxcTypedStateAwareRequest, Error> {
    if request.is_null() {
        return Err(malformed("typed state-aware request pointer is null"));
    }
    // SAFETY: non-null pointer is caller-guaranteed readable.
    let request = unsafe { &*request };
    if request.abi_version != MXC_TYPED_ABI_VERSION_1 {
        return Err(malformed(format!(
            "unsupported typed state-aware ABI version {}",
            request.abi_version
        )));
    }
    if request.struct_size < std::mem::size_of::<MxcTypedStateAwareRequest>() {
        return Err(malformed(format!(
            "typed state-aware struct_size {} is smaller than required {}",
            request.struct_size,
            std::mem::size_of::<MxcTypedStateAwareRequest>()
        )));
    }
    Ok(request)
}

fn options(request: &MxcTypedStateAwareRequest) -> Result<OperationOptions, Error> {
    let mut options = OperationOptions::new(flag(request.experimental, "experimental")?);
    if let Some(enabled) = optional_bool(request.telemetry_enabled, "telemetry_enabled")? {
        options = options.with_telemetry_opt_in(enabled);
    }
    Ok(options)
}

unsafe fn mapped_policy(
    filesystem: *const MxcTypedFilesystemPolicy,
    network: *const MxcTypedNetworkPolicy,
) -> Result<mxc_sdk::SandboxPolicy, Error> {
    let bridge = MxcTypedSandboxPolicy {
        filesystem,
        network,
        ui: ptr::null(),
        timeout_ms: MxcOptionalU32 {
            is_set: 0,
            value: 0,
        },
        telemetry_enabled: MxcOptionalBool {
            is_set: 0,
            value: 0,
        },
    };
    // SAFETY: nested pointers retain the caller's borrowed lifetime.
    unsafe { policy(&bridge) }.map(|(policy, _)| policy)
}

unsafe fn provision_request(
    request: &MxcTypedStateAwareRequest,
) -> Result<ProvisionRequest, Error> {
    if request.provision.is_null() {
        return Err(malformed("provision operation requires provision input"));
    }
    // SAFETY: selected operation requires caller-readable provision input.
    let value = unsafe { &*request.provision };
    // SAFETY: provision strings follow the borrowed request contract.
    let app_id = unsafe { optional_utf8(value.app_id, "provision.app_id")? };
    // SAFETY: provision strings follow the borrowed request contract.
    let image = unsafe { optional_utf8(value.image, "provision.image")? };
    // SAFETY: provision strings follow the borrowed request contract.
    let image_tar_path =
        unsafe { optional_utf8(value.image_tar_path, "provision.image_tar_path")? };
    let mut mapped = match value.backend {
        MXC_STATE_AWARE_ISOLATION_SESSION => {
            if image.is_some() || image_tar_path.is_some() {
                return Err(malformed(
                    "IsolationSession provision does not accept image fields",
                ));
            }
            ProvisionRequest::isolation_session(app_id)
        }
        MXC_STATE_AWARE_WSLC => {
            if app_id.is_some() {
                return Err(malformed("WSLC provision does not accept app_id"));
            }
            ProvisionRequest::wslc(image, image_tar_path)
        }
        _ => return Err(malformed("provision.backend has an unknown value")),
    };
    // SAFETY: policy pointers follow the borrowed request contract.
    let policy = unsafe { mapped_policy(value.filesystem, value.network)? };
    if let Some(filesystem) = policy.filesystem {
        mapped.set_filesystem(filesystem);
    }
    if let Some(network) = policy.network {
        mapped.set_network(network);
    }
    Ok(mapped)
}

unsafe fn sandbox_id(request: &MxcTypedStateAwareRequest) -> Result<SandboxId, Error> {
    if request.sandbox_id.is_null() {
        return Err(malformed("operation requires sandbox_id"));
    }
    // SAFETY: selected operation requires a caller-readable ID.
    let value = unsafe { utf8(*request.sandbox_id, "sandbox_id")? };
    SandboxId::parse(value)
}

unsafe fn exec_request(request: &MxcTypedStateAwareRequest) -> Result<ExecRequest, Error> {
    if request.exec.is_null() {
        return Err(malformed("exec operation requires exec input"));
    }
    // SAFETY: selected operation requires caller-readable exec input.
    let value = unsafe { &*request.exec };
    // SAFETY: command bytes follow the borrowed request contract.
    let mut mapped = ExecRequest::new(unsafe { utf8(value.command, "exec.command")? });
    if let Some(working_directory) =
        // SAFETY: optional string follows the borrowed request contract.
        unsafe { optional_utf8(value.working_directory, "exec.working_directory")? }
    {
        mapped.set_working_directory(working_directory);
    }
    if presence(value.environment.is_set, "exec.environment.is_set")? {
        // SAFETY: environment entries follow the borrowed request contract.
        let entries = unsafe {
            borrowed_slice(
                value.environment.entries,
                value.environment.len,
                "exec.environment.entries",
            )?
        };
        let mut environment = Vec::with_capacity(entries.len());
        for (index, entry) in entries.iter().enumerate() {
            // SAFETY: key/value bytes follow the borrowed request contract.
            let key = unsafe { utf8(entry.key, &format!("exec.environment[{index}].key"))? };
            if key.is_empty() || key.contains('=') {
                return Err(malformed(format!(
                    "exec.environment[{index}].key must be non-empty and contain no '='"
                )));
            }
            // SAFETY: key/value bytes follow the borrowed request contract.
            let value = unsafe { utf8(entry.value, &format!("exec.environment[{index}].value"))? };
            environment.push((key, value));
        }
        mapped.set_environment(environment);
    }
    if let Some(inherit) = optional_bool(value.inherit_default_env, "exec.inherit_default_env")? {
        mapped.inherit_default_env(inherit);
    }
    if let Some(timeout_ms) = optional_u32(value.timeout_ms, "exec.timeout_ms")? {
        mapped.set_timeout(timeout_ms);
    }
    if let Some(network_proxy) =
        // SAFETY: optional string follows the borrowed request contract.
        unsafe { optional_utf8(value.network_proxy, "exec.network_proxy")? }
    {
        mapped.set_backend_options(StateAwareExecBackendOptions::Wslc { network_proxy });
    }
    Ok(mapped)
}

fn provision_result(result: Result<mxc_sdk::ProvisionResult, Error>) -> MxcTypedStateAwareResult {
    match result {
        Ok(result) => {
            let mut mapped = MxcTypedStateAwareResult::empty();
            mapped.sandbox_id_utf8 = alloc_cstring(result.sandbox_id.as_str().as_bytes());
            match result.metadata {
                Some(ProvisionMetadata::IsolationSessionProvision(metadata)) => {
                    mapped.metadata_kind = MXC_PROVISION_METADATA_ISOLATION_SESSION;
                    mapped.agent_user_name_utf8 =
                        alloc_cstring(metadata.agent_user_name.as_bytes());
                    mapped.agent_user_sid_utf8 = alloc_cstring(metadata.agent_user_sid.as_bytes());
                    mapped.ephemeral_workspace_path_utf8 =
                        alloc_cstring(metadata.ephemeral_workspace_path.as_bytes());
                }
                None => {}
                Some(_) => {
                    return MxcTypedStateAwareResult::error(&Error::new(
                        ErrorCode::BackendError,
                        "typed provision returned unsupported metadata",
                    ))
                }
            }
            mapped
                .warnings(&result.warnings)
                .unwrap_or_else(|error| MxcTypedStateAwareResult::error(&error))
        }
        Err(error) => MxcTypedStateAwareResult::error(&error),
    }
}

fn lifecycle_result(result: Result<mxc_sdk::LifecycleResult, Error>) -> MxcTypedStateAwareResult {
    match result {
        Ok(result) => MxcTypedStateAwareResult::empty()
            .warnings(&result.warnings)
            .unwrap_or_else(|error| MxcTypedStateAwareResult::error(&error)),
        Err(error) => MxcTypedStateAwareResult::error(&error),
    }
}

fn validation_result(result: Result<mxc_sdk::ValidationResult, Error>) -> MxcTypedStateAwareResult {
    match result {
        Ok(result) => MxcTypedStateAwareResult::empty()
            .warnings(&result.warnings)
            .unwrap_or_else(|error| MxcTypedStateAwareResult::error(&error)),
        Err(error) => MxcTypedStateAwareResult::error(&error),
    }
}

unsafe fn run(
    request: *const MxcTypedStateAwareRequest,
    dry_run: bool,
) -> MxcTypedStateAwareResult {
    // SAFETY: caller contract is forwarded to request conversion.
    let request = match unsafe { parse_request(request) } {
        Ok(request) => request,
        Err(error) => return MxcTypedStateAwareResult::error(&error),
    };
    let options = match options(request) {
        Ok(options) => options,
        Err(error) => return MxcTypedStateAwareResult::error(&error),
    };
    match request.operation {
        MXC_STATE_AWARE_PROVISION => {
            // SAFETY: selected operation controls which request payload is read.
            let provision = match unsafe { provision_request(request) } {
                Ok(provision) => provision,
                Err(error) => return MxcTypedStateAwareResult::error(&error),
            };
            if dry_run {
                validation_result(sandbox::validate_provision(provision, options))
            } else {
                provision_result(sandbox::provision(provision, options))
            }
        }
        MXC_STATE_AWARE_START | MXC_STATE_AWARE_STOP | MXC_STATE_AWARE_DEPROVISION => {
            // SAFETY: selected operation requires caller-readable sandbox ID.
            let sandbox_id = match unsafe { sandbox_id(request) } {
                Ok(sandbox_id) => sandbox_id,
                Err(error) => return MxcTypedStateAwareResult::error(&error),
            };
            match (request.operation, dry_run) {
                (MXC_STATE_AWARE_START, true) => {
                    validation_result(sandbox::validate_start(&sandbox_id, options))
                }
                (MXC_STATE_AWARE_START, false) => {
                    lifecycle_result(sandbox::start(&sandbox_id, options))
                }
                (MXC_STATE_AWARE_STOP, true) => {
                    validation_result(sandbox::validate_stop(&sandbox_id, options))
                }
                (MXC_STATE_AWARE_STOP, false) => {
                    lifecycle_result(sandbox::stop(&sandbox_id, options))
                }
                (MXC_STATE_AWARE_DEPROVISION, true) => {
                    validation_result(sandbox::validate_deprovision(&sandbox_id, options))
                }
                (MXC_STATE_AWARE_DEPROVISION, false) => {
                    lifecycle_result(sandbox::deprovision(&sandbox_id, options))
                }
                _ => unreachable!(),
            }
        }
        MXC_STATE_AWARE_EXEC if dry_run => {
            // SAFETY: selected operation requires caller-readable ID and exec input.
            let sandbox_id = match unsafe { sandbox_id(request) } {
                Ok(sandbox_id) => sandbox_id,
                Err(error) => return MxcTypedStateAwareResult::error(&error),
            };
            // SAFETY: selected operation requires caller-readable ID and exec input.
            let exec = match unsafe { exec_request(request) } {
                Ok(exec) => exec,
                Err(error) => return MxcTypedStateAwareResult::error(&error),
            };
            validation_result(sandbox::validate_exec(&sandbox_id, exec, options))
        }
        MXC_STATE_AWARE_EXEC => MxcTypedStateAwareResult::error(&malformed(
            "non-dry-run exec must use the typed streaming or attached entry point",
        )),
        _ => MxcTypedStateAwareResult::error(&malformed("operation has an unknown value")),
    }
}

/// Run a typed state-aware envelope operation or validation.
///
/// # Safety
/// `request` and every reachable pointer must remain readable for the call;
/// `out` must point to writable result storage.
#[no_mangle]
pub unsafe extern "C" fn mxc_state_aware_typed(
    request: *const MxcTypedStateAwareRequest,
    dry_run: i32,
    out: *mut MxcTypedStateAwareResult,
) -> i32 {
    if out.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }
    let dry_run = match flag(dry_run, "dry_run") {
        Ok(value) => value,
        Err(error) => {
            let result = MxcTypedStateAwareResult::error(&error);
            let status = result.status;
            // SAFETY: `out` is non-null and caller-guaranteed writable.
            unsafe { ptr::write(out, result) };
            return status;
        }
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: caller contract is forwarded to the conversion helper.
        unsafe { run(request, dry_run) }
    }))
    .unwrap_or_else(|panic| {
        report_panic("mxc_state_aware_typed", &*panic);
        let mut result = MxcTypedStateAwareResult::empty();
        result.status = MXC_STATUS_PANIC;
        result.error = MxcErrorDetail::from_message("the mxc engine panicked");
        result
    });
    let status = result.status;
    // SAFETY: `out` is non-null and caller-guaranteed writable.
    unsafe { ptr::write(out, result) };
    status
}

/// Free strings owned by a typed state-aware result.
///
/// # Safety
/// `result` must be null or a result filled by [`mxc_state_aware_typed`].
#[no_mangle]
pub unsafe extern "C" fn mxc_state_aware_typed_result_free(result: *mut MxcTypedStateAwareResult) {
    if result.is_null() {
        return;
    }
    if let Err(panic) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: caller guarantees a valid result that has not been freed.
        unsafe { (*result).free_strings() };
    })) {
        report_panic("mxc_state_aware_typed_result_free", &*panic);
    }
}

unsafe fn exec_parts(
    request: *const MxcTypedStateAwareRequest,
) -> Result<(SandboxId, ExecRequest, OperationOptions), Error> {
    // SAFETY: caller contract is forwarded to request conversion.
    let request = unsafe { parse_request(request)? };
    if request.operation != MXC_STATE_AWARE_EXEC {
        return Err(malformed("typed exec entry point requires exec operation"));
    }
    // SAFETY: exec operation requires caller-readable ID and exec input.
    let sandbox_id = unsafe { sandbox_id(request)? };
    // SAFETY: exec operation requires caller-readable ID and exec input.
    let exec = unsafe { exec_request(request)? };
    Ok((sandbox_id, exec, options(request)?))
}

/// Run typed state-aware exec as a live streaming sandbox.
///
/// # Safety
/// Request pointers must remain readable for the call. `out_handle` must point
/// to empty writable handle storage; `out_error` must be null or fresh writable
/// detail storage.
#[no_mangle]
pub unsafe extern "C" fn mxc_state_aware_exec_typed(
    request: *const MxcTypedStateAwareRequest,
    out_handle: *mut *mut MxcSandbox,
    out_error: *mut MxcErrorDetail,
) -> i32 {
    if !out_handle.is_null() {
        // SAFETY: caller-guaranteed writable pointer storage.
        unsafe { *out_handle = ptr::null_mut() };
    }
    if !out_error.is_null() {
        // SAFETY: caller-guaranteed writable detail storage.
        unsafe { ptr::write(out_error, MxcErrorDetail::none()) };
    }
    if out_handle.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: caller contract is forwarded to request conversion.
        let (sandbox_id, exec, options) = unsafe { exec_parts(request) }.map_err(|error| {
            (
                status_from_error_code(error.code),
                MxcErrorDetail::from_error(&error),
            )
        })?;
        sandbox::exec(&sandbox_id, exec, options).map_err(|error| {
            (
                status_from_error_code(error.code),
                MxcErrorDetail::from_error(&error),
            )
        })
    }))
    .unwrap_or_else(|panic| {
        report_panic("mxc_state_aware_exec_typed", &*panic);
        Err((
            MXC_STATUS_PANIC,
            MxcErrorDetail::from_message("the mxc engine panicked"),
        ))
    });
    // SAFETY: out-parameter contracts were checked above.
    unsafe { finish_spawn(outcome, out_handle, out_error) }
}

/// Run typed state-aware exec attached to this process's stdio.
///
/// # Safety
/// Request pointers must remain readable for the call. `out_outcome` must
/// point to writable storage; `out_error` must be null or fresh writable
/// detail storage.
#[no_mangle]
pub unsafe extern "C" fn mxc_state_aware_exec_attached_typed(
    request: *const MxcTypedStateAwareRequest,
    out_outcome: *mut MxcExecOutcome,
    out_error: *mut MxcErrorDetail,
) -> i32 {
    if !out_error.is_null() {
        // SAFETY: caller-guaranteed writable detail storage.
        unsafe { ptr::write(out_error, MxcErrorDetail::none()) };
    }
    if out_outcome.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: caller contract is forwarded to request conversion.
        let (sandbox_id, exec, options) = unsafe { exec_parts(request) }.map_err(|error| {
            (
                status_from_error_code(error.code),
                MxcErrorDetail::from_error(&error),
            )
        })?;
        sandbox::exec_attached(&sandbox_id, exec, options).map_err(|error| {
            (
                status_from_error_code(error.code),
                MxcErrorDetail::from_error(&error),
            )
        })
    }))
    .unwrap_or_else(|panic| {
        report_panic("mxc_state_aware_exec_attached_typed", &*panic);
        Err((
            MXC_STATUS_PANIC,
            MxcErrorDetail::from_message("the mxc engine panicked"),
        ))
    });
    match outcome {
        Ok(outcome) => {
            // SAFETY: `out_outcome` is non-null and caller-guaranteed writable.
            unsafe { ptr::write(out_outcome, exec_outcome_to_abi(outcome)) };
            MXC_STATUS_SUCCESS
        }
        Err((status, mut error)) => {
            if out_error.is_null() {
                error.free_strings();
            } else {
                // SAFETY: `out_error` is caller-guaranteed writable.
                unsafe { ptr::write(out_error, error) };
            }
            status
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(value: &str) -> MxcUtf8Slice {
        MxcUtf8Slice {
            data: value.as_ptr(),
            len: value.len(),
        }
    }

    fn start(id: &MxcUtf8Slice) -> MxcTypedStateAwareRequest {
        MxcTypedStateAwareRequest {
            abi_version: MXC_TYPED_ABI_VERSION_1,
            struct_size: std::mem::size_of::<MxcTypedStateAwareRequest>(),
            operation: MXC_STATE_AWARE_START,
            sandbox_id: id,
            provision: ptr::null(),
            exec: ptr::null(),
            telemetry_enabled: MxcOptionalBool {
                is_set: 0,
                value: 0,
            },
            experimental: 0,
        }
    }

    #[test]
    fn typed_lifecycle_rejects_unknown_abi_revision() {
        let id = text("iso:example");
        let mut request = start(&id);
        request.abi_version = 99;
        // SAFETY: every pointer remains valid for the call.
        // SAFETY: every pointer remains valid for the call.
        let error = match unsafe { parse_request(&request) } {
            Ok(_) => panic!("unknown ABI revision must be rejected"),
            Err(error) => error,
        };
        assert!(error.message.contains("ABI version"));
    }

    #[test]
    fn typed_lifecycle_rejects_windows_sandbox_id() {
        let id = text("wsb:example");
        let request = start(&id);
        // SAFETY: every pointer remains valid for the call.
        let result = unsafe { run(&request, true) };
        assert_eq!(
            result.status,
            crate::MXC_STATUS_MALFORMED_REQUEST,
            "typed v1 must keep Windows Sandbox on raw JSON"
        );
    }
}
