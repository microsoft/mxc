// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use serde_json::Value;

use crate::mxc_common::models::{ExecutionRequest, MicroVmProvisionConfig};
use crate::mxc_common::mxc_error::MxcError;
use crate::mxc_common::state_aware_backend::{
    DeprovisionResult, ExecHandle, ExecStdio, ProvisionResult, StartResult, StatefulSandboxBackend,
    StopResult,
};

use super::abi::ProvisionInput;
use super::runtime::{NvxClient, SandboxClient, SandboxId};

pub(crate) struct NvxStateAwareRunner {
    client: std::cell::RefCell<Option<NvxClient>>,
    capture_limit: Option<usize>,
    provisioned_id: std::cell::RefCell<Option<SandboxId>>,
    sensitive_proxy: std::cell::Cell<bool>,
}

impl NvxStateAwareRunner {
    pub(crate) fn new() -> Self {
        Self {
            client: std::cell::RefCell::new(None),
            capture_limit: None,
            provisioned_id: std::cell::RefCell::new(None),
            sensitive_proxy: std::cell::Cell::new(true),
        }
    }

    pub(crate) fn with_capture_limit(limit: usize) -> Self {
        let mut runner = Self::new();
        runner.capture_limit = Some(limit);
        runner
    }

    fn client(&self) -> Result<std::cell::Ref<'_, NvxClient>, MxcError> {
        if self.client.borrow().is_none() {
            *self.client.borrow_mut() = Some(open_client()?);
        }
        Ok(std::cell::Ref::map(self.client.borrow(), |client| {
            client
                .as_ref()
                .expect("NVX lifecycle client was initialized")
        }))
    }

    fn take_client(&mut self) -> Result<NvxClient, MxcError> {
        if self.client.get_mut().is_none() {
            let _ = self.client()?;
        }
        self.client
            .get_mut()
            .take()
            .ok_or_else(|| MxcError::backend_error("NVX lifecycle client was already consumed"))
    }

    pub(crate) fn finish<T>(&mut self, primary: Result<T, MxcError>) -> Result<T, MxcError> {
        let cleanup = self
            .client
            .get_mut()
            .take()
            .and_then(|mut client| client.close().err())
            .map(|error| {
                super::runner::protect_native_error(error, "close", self.sensitive_proxy.get())
            })
            .into_iter()
            .collect();
        let mut result = super::runner::finish_run(
            primary,
            cleanup,
            &mut crate::mxc_common::logger::Logger::new(crate::mxc_common::logger::Mode::Buffer),
        );
        if let (Err(error), Some(id)) = (&mut result, self.provisioned_id.get_mut().take()) {
            // Closing a native host can consume its handle even on failure.
            // Keep the provisioned container and return its identity, rather
            // than attempting rollback through that ambiguous handle.
            let mut details = serde_json::Map::new();
            if let Some(previous) = error.details.take() {
                details.insert("primaryDetails".to_owned(), previous);
            }
            details.insert(
                "nvxRecovery".to_owned(),
                serde_json::json!({
                    "sandboxId": id.to_mxc_string(),
                    "state": "provisioned"
                }),
            );
            error.details = Some(Value::Object(details));
            let recovery =
                "Provision succeeded but cleanup failed. The container is retained. Use \
                 details.nvxRecovery.sandboxId with Rust v1::dev JSON lifecycle operations \
                 to continue or deprovision it; do not retry provision.";
            error.remediation = Some(match error.remediation.take() {
                Some(previous) => format!("{previous} {recovery}"),
                None => recovery.to_owned(),
            });
        }
        result
    }
}

fn open_client() -> Result<NvxClient, MxcError> {
    #[cfg(test)]
    if let Some(client) = tests::take_injected_client() {
        return Ok(client);
    }
    super::runtime::require_agent_bundle_present()?;
    let state_root = super::runtime::lifecycle_state_root()?;
    super::runtime::create_persistent_client(state_root)
}

impl StatefulSandboxBackend for NvxStateAwareRunner {
    const ID_PREFIX: &'static str = "microvm";
    const BACKEND_KEY: &'static str = "microvm";

    type ProvisionConfig = MicroVmProvisionConfig;
    type StartConfig = ();
    type ExecConfig = ();
    type StopConfig = ();
    type DeprovisionConfig = ();
    type ProvisionMetadata = Value;
    type StartMetadata = ();
    type StopMetadata = ();
    type DeprovisionMetadata = ();

    fn provision(
        &mut self,
        request: &ExecutionRequest,
        config: Option<Self::ProvisionConfig>,
    ) -> Result<ProvisionResult<Self::ProvisionMetadata>, MxcError> {
        let sensitive_proxy = super::runner::request_has_sensitive_proxy(request);
        self.sensitive_proxy.set(sensitive_proxy);
        let protect = |operation, error| {
            super::runner::protect_native_error(error, operation, sensitive_proxy)
        };
        let client = self.client()?;
        let capabilities = client
            .capabilities()
            .map_err(|error| protect("capabilities", error))?;
        let (request, spec) =
            super::policy::provision_request_with_config(request, config.as_ref(), &capabilities)?;
        let input = ProvisionInput { request, spec };
        client
            .validate_provision(&input)
            .map_err(|error| protect("validate_provision", error))?;
        client.probe().map_err(|error| protect("probe", error))?;
        let (sandbox_id, metadata) = client
            .provision_with_metadata(&input)
            .map_err(|error| protect("provision", error))?;
        *self.provisioned_id.borrow_mut() = Some(sandbox_id.clone());
        Ok(ProvisionResult {
            sandbox_id: sandbox_id.to_mxc_string(),
            metadata: metadata.map(Value::Object),
        })
    }

    fn start(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<Self::StartConfig>,
    ) -> Result<StartResult<Self::StartMetadata>, MxcError> {
        let sandbox_id = SandboxId::from_mxc(sandbox_id)?;
        self.client()?
            .start(&sandbox_id)
            .map_err(|error| super::runner::protect_native_error(error, "start", true))?;
        Ok(StartResult { metadata: None })
    }

    fn exec(
        &mut self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<Self::ExecConfig>,
        stdio: ExecStdio,
    ) -> Result<ExecHandle, MxcError> {
        let sandbox_id = SandboxId::from_mxc(sandbox_id)?;
        let client = self.client()?;
        let capabilities = client
            .capabilities()
            .map_err(|error| super::runner::protect_native_error(error, "capabilities", true))?;
        let request = super::policy::exec_request_for_existing(request, &capabilities)?;
        client
            .validate_exec(&request)
            .map_err(|error| super::runner::protect_native_error(error, "validate_exec", true))?;
        drop(client);
        super::runner::exec_existing(
            self.take_client()?,
            sandbox_id,
            &request,
            stdio,
            self.capture_limit,
            true,
        )
    }

    fn stop(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<Self::StopConfig>,
    ) -> Result<StopResult<Self::StopMetadata>, MxcError> {
        let sandbox_id = SandboxId::from_mxc(sandbox_id)?;
        self.client()?
            .stop(&sandbox_id)
            .map_err(|error| super::runner::protect_native_error(error, "stop", true))?;
        Ok(StopResult { metadata: None })
    }

    fn deprovision(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<Self::DeprovisionConfig>,
    ) -> Result<DeprovisionResult<Self::DeprovisionMetadata>, MxcError> {
        let sandbox_id = SandboxId::from_mxc(sandbox_id)?;
        self.client()?
            .deprovision(&sandbox_id)
            .map_err(|error| super::runner::protect_native_error(error, "deprovision", true))?;
        Ok(DeprovisionResult { metadata: None })
    }

    fn validate_provision(
        &self,
        request: &ExecutionRequest,
        config: Option<&Self::ProvisionConfig>,
    ) -> Result<(), MxcError> {
        super::policy::validate_provision_request(request, config)?;
        let sensitive_proxy = super::runner::request_has_sensitive_proxy(request);
        self.sensitive_proxy.set(sensitive_proxy);
        let protect = |operation, error| {
            super::runner::protect_native_error(error, operation, sensitive_proxy)
        };
        let client = self.client()?;
        let capabilities = client
            .capabilities()
            .map_err(|error| protect("capabilities", error))?;
        let (request, spec) =
            super::policy::provision_request_with_config(request, config, &capabilities)?;
        client
            .validate_provision(&ProvisionInput { request, spec })
            .map_err(|error| protect("validate_provision", error))
    }

    fn validate_start(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&Self::StartConfig>,
    ) -> Result<(), MxcError> {
        SandboxId::from_mxc(sandbox_id)?;
        super::policy::validate_post_provision_request(request)?;
        let _ = self.client()?;
        Ok(())
    }

    fn validate_exec(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&Self::ExecConfig>,
    ) -> Result<(), MxcError> {
        SandboxId::from_mxc(sandbox_id)?;
        super::policy::validate_post_provision_request(request)?;
        super::policy::validate_process_request(request)?;
        let capabilities = self
            .client()?
            .capabilities()
            .map_err(|error| super::runner::protect_native_error(error, "capabilities", true))?;
        let request = super::policy::exec_request_for_existing(request, &capabilities)?;
        self.client()?
            .validate_exec(&request)
            .map_err(|error| super::runner::protect_native_error(error, "validate_exec", true))
    }

    fn validate_stop(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&Self::StopConfig>,
    ) -> Result<(), MxcError> {
        SandboxId::from_mxc(sandbox_id)?;
        super::policy::validate_post_provision_request(request)?;
        let _ = self.client()?;
        Ok(())
    }

    fn validate_deprovision(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&Self::DeprovisionConfig>,
    ) -> Result<(), MxcError> {
        SandboxId::from_mxc(sandbox_id)?;
        super::policy::validate_post_provision_request(request)?;
        let _ = self.client()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::abi::{
        AgentLibrary, ExecEvent, Exports, STATUS_ERROR, STATUS_INVALID_HANDLE, STATUS_OK,
    };
    use super::*;
    use crate::v1::{dev, ErrorCode};
    use std::cell::{Cell, RefCell};

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";
    const ID: &str = "microvm:0123456789abcdef0123456789abcdef";
    const SECRET: &str = "native rejection http://user:very-secret@127.0.0.1:3128";

    #[derive(Default)]
    struct NativeState {
        host: u64,
        closed_hosts: Vec<u64>,
        calls: Vec<&'static str>,
        fail: Option<&'static str>,
        close_fails: bool,
        provisioned: bool,
        buffers: usize,
    }

    thread_local! {
        static INJECTED: RefCell<Option<NvxClient>> = const { RefCell::new(None) };
        static NATIVE: RefCell<NativeState> = RefCell::new(NativeState::default());
        static NEXT_HOST: Cell<u64> = const { Cell::new(1) };
    }

    pub(super) fn take_injected_client() -> Option<NvxClient> {
        INJECTED.with(|slot| slot.borrow_mut().take())
    }

    fn reply(operation: &'static str, body: &[u8], out: *mut *mut u8, len: *mut usize) -> i32 {
        NATIVE.with(|state| {
            let mut state = state.borrow_mut();
            state.calls.push(operation);
            let failed = state.fail == Some(operation);
            let body = if failed {
                br#"{"code":"policy_validation","message":"native rejection http://user:very-secret@127.0.0.1:3128"}"#.as_slice()
            } else {
                if operation == "provision" { state.provisioned = true; }
                if operation == "deprovision" { state.provisioned = false; }
                body
            };
            if body.is_empty() {
                unsafe { *len = 0; *out = std::ptr::null_mut(); }
            } else {
                let mut bytes = body.to_vec().into_boxed_slice();
                unsafe {
                    *len = bytes.len();
                    *out = bytes.as_mut_ptr();
                }
                std::mem::forget(bytes);
                state.buffers += 1;
            }
            if failed { STATUS_ERROR } else { STATUS_OK }
        })
    }

    unsafe extern "C" fn free_buffer(bytes: *mut u8, len: usize) {
        if bytes.is_null() {
            return;
        }
        unsafe {
            drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                bytes, len,
            )))
        };
        NATIVE.with(|state| state.borrow_mut().buffers -= 1);
    }

    unsafe extern "C" fn close(host: u64) -> i32 {
        NATIVE.with(|state| {
            let mut state = state.borrow_mut();
            state.calls.push("close");
            state.closed_hosts.push(host);
            if host != state.host {
                return STATUS_INVALID_HANDLE;
            }
            if state.close_fails {
                STATUS_ERROR
            } else {
                STATUS_OK
            }
        })
    }

    unsafe extern "C" fn capabilities(_host: u64, out: *mut *mut u8, len: *mut usize) -> i32 {
        reply(
            "capabilities",
            br#"{
          "spec":{"imageReference":true,"memory":true},
          "exec":{"commandLine":true,"cwd":true,"env":true},
          "filesystem":{"readonlyPaths":true,"readwritePaths":true,"deniedPaths":true},
          "network":{"egressAllow":true,"egressDeny":true,"ingressAllow":true,
          "ingressDeny":true,"hostLoopbackAllow":true,"hostLoopbackDeny":true,
          "egressRules":true,"networkProxy":true}}"#,
            out,
            len,
        )
    }

    unsafe extern "C" fn query(_host: u64, out: *mut *mut u8, len: *mut usize) -> i32 {
        reply("probe", b"", out, len)
    }

    macro_rules! native_call {
        ($name:ident, $body:expr) => {
            unsafe extern "C" fn $name(
                _host: u64,
                _input: *const u8,
                _input_len: usize,
                out: *mut *mut u8,
                len: *mut usize,
            ) -> i32 {
                reply(stringify!($name), $body, out, len)
            }
        };
    }
    native_call!(validate_provision, b"");
    native_call!(validate_exec, b"");
    native_call!(
        provision,
        br#"{"token":"0123456789abcdef0123456789abcdef"}"#
    );
    native_call!(start, b"{}");
    native_call!(stop, b"{}");
    native_call!(deprovision, b"{}");

    unsafe extern "C" fn host_open(
        _input: *const u8,
        _length: usize,
        _host: *mut u64,
        _out: *mut *mut u8,
        _out_len: *mut usize,
    ) -> i32 {
        STATUS_INVALID_HANDLE
    }
    unsafe extern "C" fn exec(
        _host: u64,
        _token: *const u8,
        _token_len: usize,
        _input: *const u8,
        _input_len: usize,
        _exec: *mut u64,
        out: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32 {
        if NATIVE.with(|state| state.borrow().fail == Some("exec")) {
            reply("exec", b"", out, out_len)
        } else {
            STATUS_INVALID_HANDLE
        }
    }
    unsafe extern "C" fn next(_exec: u64, _timeout: i64, _event: *mut ExecEvent) -> i32 {
        STATUS_INVALID_HANDLE
    }
    unsafe extern "C" fn write(
        _exec: u64,
        _input: *const u8,
        _len: usize,
        _timeout: i64,
        _written: *mut usize,
        _out: *mut *mut u8,
        _out_len: *mut usize,
    ) -> i32 {
        STATUS_INVALID_HANDLE
    }

    fn install(fail: Option<&'static str>, close_fails: bool) -> u64 {
        static LIBRARY: std::sync::OnceLock<AgentLibrary> = std::sync::OnceLock::new();
        let library = LIBRARY.get_or_init(|| {
            AgentLibrary::from_exports_for_test(Exports {
                host_open,
                host_close: close,
                host_info: query,
                capabilities,
                probe: query,
                validate_provision,
                validate_exec,
                provision,
                start,
                stop,
                deprovision,
                diagnostics: start,
                guest_logs: start,
                exec,
                exec_next: next,
                exec_write: write,
                exec_close_input: query,
                exec_cancel: query,
                exec_release: close,
                image_register: start,
                image_list: query,
                image_verify: start,
                image_unregister: start,
                buffer_free: free_buffer,
            })
        });
        let host = NEXT_HOST.with(|next| {
            let host = next.get();
            next.set(host + 1);
            host
        });
        NATIVE.with(|state| {
            let provisioned = state.borrow().provisioned;
            *state.borrow_mut() = NativeState {
                host,
                fail,
                close_fails,
                provisioned,
                ..Default::default()
            };
        });
        INJECTED.with(|slot| {
            assert!(slot.borrow().is_none());
            *slot.borrow_mut() = Some(NvxClient::from_library(library, host));
        });
        host
    }

    fn invoke(phase: &str, dry_run: bool, proxy: bool) -> Result<String, crate::v1::Error> {
        let mut request = serde_json::json!({"version":"1.1.0-alpha", "phase":phase});
        if phase == "provision" {
            request["containment"] = "microvm".into();
            request["microvm"] = serde_json::json!({
                "image":"mcr.microsoft.com/azurelinux/base/core:3.0"
            });
            if proxy {
                request["runtimeConfig"] = serde_json::json!({
                    "networkProxy":"http://user:very-secret@127.0.0.1:3128"
                });
            }
        } else {
            request["sandboxId"] = ID.into();
            if phase == "exec" {
                request["process"] = serde_json::json!({"commandLine":"true"});
            }
        }
        let json = request.to_string();
        let options = dev::JsonOptions { experimental: true };
        match (phase, dry_run) {
            ("provision", false) => dev::provision_container_json(&json, options),
            ("provision", true) => dev::validate_provision_json(&json, options),
            ("start", false) => dev::start_container_json(&json, options),
            ("start", true) => dev::validate_start_json(&json, options),
            ("stop", false) => dev::stop_container_json(&json, options),
            ("stop", true) => dev::validate_stop_json(&json, options),
            ("deprovision", false) => dev::deprovision_container_json(&json, options),
            ("deprovision", true) => dev::validate_deprovision_json(&json, options),
            ("exec", true) => dev::validate_process_json(&json, options),
            _ => panic!("unsupported test operation"),
        }
    }

    fn assert_closed_once() {
        assert!(INJECTED.with(|slot| slot.borrow().is_none()));
        NATIVE.with(|state| {
            let state = state.borrow();
            assert_eq!(
                state.calls.iter().filter(|call| **call == "close").count(),
                1
            );
            assert_eq!(state.calls.last(), Some(&"close"));
            assert_eq!(state.closed_hosts, [state.host]);
            assert_eq!(state.buffers, 0);
        });
    }

    #[test]
    fn public_envelopes_close_explicitly_on_success_and_dry_run() {
        for phase in ["provision", "start", "stop", "deprovision", "exec"] {
            for dry_run in [false, true] {
                if phase == "exec" && !dry_run {
                    continue;
                }
                install(None, false);
                let result = invoke(phase, dry_run, false).unwrap();
                let result: Value = serde_json::from_str(&result).unwrap();
                if phase == "provision" && !dry_run {
                    assert_eq!(result["result"]["sandboxId"], ID);
                } else {
                    assert_eq!(result, serde_json::json!({"result":{}}));
                }
                assert_closed_once();
            }
        }
    }

    #[test]
    fn close_failures_are_errors_and_provision_identity_is_recoverable() {
        for phase in ["provision", "start", "stop", "deprovision", "exec"] {
            for dry_run in [false, true] {
                if phase == "exec" && !dry_run {
                    continue;
                }
                let failed_host = install(None, true);
                let error = invoke(phase, dry_run, false).unwrap_err();
                assert_eq!(error.code, ErrorCode::BackendError);
                assert!(error.message.contains("cleanup failed"));
                assert_closed_once();
                if phase == "provision" && !dry_run {
                    assert_eq!(
                        error.details.as_ref().unwrap()["nvxRecovery"]["sandboxId"],
                        ID
                    );
                    assert!(NATIVE.with(|state| state.borrow().provisioned));
                    assert!(!error.to_string().contains(TOKEN));
                    let recovery_host = install(None, false);
                    assert_ne!(recovery_host, failed_host);
                    let recovered_id = error.details.unwrap()["nvxRecovery"]["sandboxId"]
                        .as_str()
                        .unwrap()
                        .to_owned();
                    let request = serde_json::json!({
                        "version":"1.1.0-alpha", "phase":"deprovision", "sandboxId":recovered_id
                    });
                    dev::deprovision_container_json(
                        &request.to_string(),
                        dev::JsonOptions { experimental: true },
                    )
                    .unwrap();
                    assert_closed_once();
                    assert!(!NATIVE.with(|state| state.borrow().provisioned));
                } else {
                    assert_eq!(error.details, None);
                }
            }
        }
    }

    #[test]
    fn primary_native_errors_survive_close_failures_and_proxy_details_are_redacted() {
        for (phase, operation) in [
            ("provision", "validate_provision"),
            ("provision", "provision"),
            ("start", "start"),
            ("stop", "stop"),
            ("deprovision", "deprovision"),
            ("exec", "validate_exec"),
        ] {
            for close_fails in [false, true] {
                install(Some(operation), close_fails);
                let error = invoke(phase, phase == "exec", false).unwrap_err();
                assert_eq!(error.code, ErrorCode::PolicyValidation);
                let primary = if phase == "provision" {
                    format!("NVX signed bundled agent: {SECRET}")
                } else {
                    format!("NVX {operation} failed; native error detail withheld to protect potentially sensitive proxy configuration")
                };
                if close_fails {
                    assert!(error
                        .message
                        .starts_with(&format!("{primary}; cleanup failure: ")));
                } else {
                    assert_eq!(error.message, primary);
                }
                if phase != "provision" {
                    assert_eq!(error.details, None);
                    assert_eq!(error.operation, None);
                    assert_eq!(error.native_code, None);
                    assert_eq!(error.remediation, None);
                    assert!(!format!("{error:?}").contains(SECRET));
                }
                assert_closed_once();
            }
        }
        for fail in [None, Some("validate_provision")] {
            install(fail, true);
            let error = invoke("provision", false, true).unwrap_err();
            assert!(!format!("{error:?}").contains("very-secret"));
            assert!(error.message.contains("native error detail withheld"));
            assert_closed_once();
        }
    }

    #[test]
    fn early_validation_preserves_exact_error_without_opening_a_client() {
        NATIVE.with(|state| *state.borrow_mut() = NativeState::default());
        let error = dev::validate_start_json(
            r#"{"version":"1.1.0-alpha","phase":"start","sandboxId":"microvm:invalid"}"#,
            dev::JsonOptions { experimental: true },
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedId);
        assert_eq!(
            error.message,
            "MicroVM sandbox ID must contain 32 lowercase hexadecimal digits"
        );
        assert!(NATIVE.with(|state| state.borrow().calls.is_empty()));
    }

    #[test]
    fn primary_structured_error_is_preserved_and_drop_remains_fallback_only() {
        install(None, true);
        let mut runner = NvxStateAwareRunner::new();
        drop(runner.client().unwrap());
        let primary = MxcError::stale_id("primary failure")
            .with_details(serde_json::json!({"existing":[1,2]}))
            .with_api_failure(crate::mxc_common::mxc_error::ApiFailure::new(
                "primary.operation",
            ))
            .with_remediation("original remedy");
        let error = runner.finish::<()>(Err(primary.clone())).unwrap_err();
        assert_eq!(error.code, primary.code);
        assert_eq!(error.details, primary.details);
        assert_eq!(error.api_failure, primary.api_failure);
        assert_eq!(error.remediation, primary.remediation);
        assert!(error
            .message
            .starts_with("primary failure; cleanup failure: "));
        assert_closed_once();

        install(None, true);
        let mut runner = NvxStateAwareRunner::new();
        drop(runner.client().unwrap());
        *runner.provisioned_id.get_mut() = Some(SandboxId::from_token(TOKEN).unwrap());
        let recovered = runner.finish::<()>(Err(primary.clone())).unwrap_err();
        assert_eq!(
            recovered.details.as_ref().unwrap()["primaryDetails"],
            primary.details.clone().unwrap()
        );
        assert_eq!(
            recovered.details.as_ref().unwrap()["nvxRecovery"]["sandboxId"],
            ID
        );
        assert_eq!(recovered.api_failure, primary.api_failure);
        assert!(recovered
            .remediation
            .unwrap()
            .starts_with("original remedy "));
        assert_closed_once();

        install(None, false);
        let runner = NvxStateAwareRunner::new();
        drop(runner.client().unwrap());
        drop(runner);
        assert_closed_once();
    }

    #[test]
    fn public_exec_validation_failure_closes_before_transferring_ownership() {
        install(Some("validate_exec"), true);
        let error = dev::run_in_container_json(
            &serde_json::json!({
                "version":"1.1.0-alpha", "phase":"exec", "sandboxId":ID,
                "process":{"commandLine":"true"}
            })
            .to_string(),
            dev::JsonOptions { experimental: true },
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::PolicyValidation);
        assert!(error.message.starts_with("NVX validate_exec failed;"));
        assert!(error.message.contains("; cleanup failure: "));
        assert_closed_once();

        install(Some("validate_provision"), true);
        let error = invoke("provision", true, false).unwrap_err();
        assert_eq!(error.code, ErrorCode::PolicyValidation);
        assert!(error.message.starts_with(&format!(
            "NVX signed bundled agent: {SECRET}; cleanup failure: "
        )));
        assert_closed_once();
    }

    #[test]
    fn public_exec_start_failure_closes_transferred_client_and_retains_container() {
        for close_fails in [false, true] {
            install(Some("exec"), close_fails);
            NATIVE.with(|state| state.borrow_mut().provisioned = true);
            let error = dev::run_in_container_json(
                &serde_json::json!({
                    "version":"1.1.0-alpha", "phase":"exec", "sandboxId":ID,
                    "process":{"commandLine":"true"}
                })
                .to_string(),
                dev::JsonOptions { experimental: true },
            )
            .unwrap_err();
            assert_eq!(error.code, ErrorCode::PolicyValidation);
            let primary = "NVX exec failed; native error detail withheld to protect potentially sensitive proxy configuration";
            if close_fails {
                assert!(error
                    .message
                    .starts_with(&format!("{primary}; cleanup failure: ")));
                assert!(error.message.contains("NVX close failed;"));
                assert_eq!(error.message.matches("; cleanup failure: ").count(), 1);
            } else {
                assert_eq!(error.message, primary);
            }
            assert_eq!(error.details, None);
            let diagnostic = format!("{error:?}");
            assert!(!diagnostic.contains(SECRET));
            assert!(!diagnostic.contains("127.0.0.1:3128"));
            assert!(!diagnostic.contains(TOKEN));
            assert_closed_once();
            NATIVE.with(|state| {
                let state = state.borrow();
                assert!(state.calls.contains(&"validate_exec"));
                assert!(state.calls.ends_with(&["exec", "close"]));
                assert_eq!(
                    state.calls.iter().filter(|call| **call == "exec").count(),
                    1
                );
                for forbidden in ["provision", "start", "stop", "deprovision"] {
                    assert!(!state.calls.contains(&forbidden));
                }
                assert!(state.provisioned);
            });
        }
    }

    #[test]
    fn lifecycle_ids_use_the_public_microvm_prefix() {
        let native = SandboxId::from_token("0123456789abcdef0123456789abcdef").unwrap();
        let public = native.to_mxc_string();
        assert_eq!(public, "microvm:0123456789abcdef0123456789abcdef");
        assert_eq!(SandboxId::from_mxc(&public).unwrap(), native);
    }

    #[test]
    fn lifecycle_ids_reject_native_or_malformed_values() {
        for value in [
            "aci-edge-sandboxes:0123456789abcdef0123456789abcdef",
            "microvm:bad",
            "microvm:0123456789ABCDEF0123456789ABCDEF",
        ] {
            assert!(SandboxId::from_mxc(value).is_err(), "{value}");
        }
    }
}
