// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use serde_json::Value;

use crate::mxc_common::models::{ExecutionRequest, MicroVmProvisionConfig};
use crate::mxc_common::mxc_error::MxcError;
use crate::mxc_common::state_aware_backend::{
    DeprovisionResult, ExecHandle, ExecStdio, ProvisionResult, StartResult, StatefulSandboxBackend,
    StopResult,
};

use super::runtime::PreparedProvision;
use super::runtime::{NvxClient, SandboxClient, SandboxId};

pub(crate) fn dispatch(
    bound: crate::mxc_common::state_aware_binding::BoundStateAwareRequest<NvxStateAwareRunner>,
    dry_run: bool,
) -> Result<crate::mxc_common::state_aware_dispatch::DispatchOutcome, MxcError> {
    use crate::mxc_common::state_aware_binding::BoundStateAwareOperation;
    use crate::mxc_common::state_aware_dispatch::dispatch_state_aware;

    // The shared dispatcher repeats these checks, but they must precede
    // impersonation capture and native work on a small-stack thread.
    let request = bound.request();
    match bound.operation() {
        BoundStateAwareOperation::Provision(config) => {
            super::policy::validate_provision_request(request, config.as_ref())?;
        }
        BoundStateAwareOperation::Start { sandbox_id, .. }
        | BoundStateAwareOperation::Stop { sandbox_id, .. }
        | BoundStateAwareOperation::Deprovision { sandbox_id, .. } => {
            SandboxId::from_mxc(sandbox_id)?;
            super::policy::validate_post_provision_request(request)?;
        }
        BoundStateAwareOperation::Exec { sandbox_id, .. } => {
            validate_exec_before_worker(request, sandbox_id)?;
        }
        BoundStateAwareOperation::ProvisionSession(_)
        | BoundStateAwareOperation::DeprovisionSession { .. } => {
            return dispatch_state_aware(&mut NvxStateAwareRunner::new(), bound, dry_run);
        }
    }

    super::run_with_sufficient_stack(move || {
        let mut runner = NvxStateAwareRunner::new();
        let outcome = dispatch_state_aware(&mut runner, bound, dry_run);
        runner.finish(outcome)
    })
}

fn validate_exec_before_worker(
    request: &ExecutionRequest,
    sandbox_id: &str,
) -> Result<(), MxcError> {
    crate::mxc_common::validator::validate_exec_common(request)?;
    SandboxId::from_mxc(sandbox_id)?;
    super::policy::validate_post_provision_request(request)?;
    super::policy::validate_process_request(request)
}

pub(crate) fn dispatch_exec(
    bound: crate::mxc_common::state_aware_binding::BoundStateAwareRequest<NvxStateAwareRunner>,
    capture_output: bool,
) -> Result<Box<dyn crate::mxc_common::sandbox_process::SandboxProcess>, MxcError> {
    use crate::mxc_common::state_aware_binding::BoundStateAwareOperation;
    let BoundStateAwareOperation::Exec { sandbox_id, .. } = bound.operation() else {
        return Err(MxcError::malformed_request(format!(
            "streaming exec requires the exec phase, got {}",
            bound.phase()
        )));
    };
    validate_exec_before_worker(bound.request(), sandbox_id)?;

    super::run_with_sufficient_stack(move || {
        let mut runner = if capture_output {
            NvxStateAwareRunner::for_capture()
        } else {
            NvxStateAwareRunner::new()
        };
        let handle =
            crate::mxc_common::state_aware_dispatch::dispatch_state_aware_exec(&mut runner, bound);
        let handle = runner.finish(handle)?;
        Ok(
            Box::new(crate::mxc_common::exec_stream::ExecSandboxProcess::from_exec_handle(handle)?)
                as Box<dyn crate::mxc_common::sandbox_process::SandboxProcess>,
        )
    })
}

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

    pub(crate) fn for_capture() -> Self {
        let mut runner = Self::new();
        runner.capture_limit = Some(super::runtime::CAPTURE_LIMIT_BYTES);
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
        let input = PreparedProvision { request, spec };
        client
            .validate_provision(&input)
            .map_err(|error| protect("validate_provision", error))?;
        client.probe().map_err(|error| protect("probe", error))?;
        let provisioned = client
            .provision(&input)
            .map_err(|error| protect("provision", error))?;
        *self.provisioned_id.borrow_mut() = Some(provisioned.sandbox_id.clone());
        Ok(ProvisionResult {
            sandbox_id: provisioned.sandbox_id.to_mxc_string(),
            metadata: provisioned.metadata.map(Value::Object),
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
            .validate_provision(&PreparedProvision { request, spec })
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
    use super::super::{run_with_sufficient_stack, stack_has_sufficient_space};
    use super::*;
    use crate::mxc_common::mxc_error::MxcErrorCode;
    use crate::mxc_common::state_aware_binding::{
        BoundStateAwareOperation, BoundStateAwareRequest,
    };
    use windows::Win32::Security::{ImpersonateSelf, RevertToSelf, SecurityIdentification};

    #[test]
    fn stack_guard_requires_current_pointer_inside_bounds() {
        let low = 0x1000;
        let high = low + 2 * 1024 * 1024;
        assert!(stack_has_sufficient_space(low, high, low + 1024 * 1024));
        assert!(!stack_has_sufficient_space(
            low,
            high,
            low + 1024 * 1024 - 1
        ));
        assert!(!stack_has_sufficient_space(low, high, low - 1));
        assert!(!stack_has_sufficient_space(low, high, high));
        assert!(!stack_has_sufficient_space(high, low, high));
    }

    #[test]
    fn consumed_stack_dispatches_to_worker() {
        const CHILD: &str = "MXC_TEST_CONSUMED_NVX_STACK";
        if std::env::var_os(CHILD).is_some() {
            #[inline(never)]
            fn consume(depth: usize, caller: std::thread::ThreadId) {
                let mut frame = [0u8; 32 * 1024];
                std::hint::black_box(&mut frame);
                let (mut low, mut high) = (0usize, 0usize);
                // SAFETY: both output pointers refer to writable stack locals.
                unsafe {
                    windows::Win32::System::Threading::GetCurrentThreadStackLimits(
                        &mut low, &mut high,
                    )
                };
                let current = std::hint::black_box(&frame) as *const _ as usize;
                assert!(current >= low && current < high);
                if current - low < 800 * 1024 {
                    let worker =
                        run_with_sufficient_stack(|| Ok(std::thread::current().id())).unwrap();
                    assert_ne!(caller, worker, "insufficient remaining stack ran inline");
                } else {
                    assert!(depth < 48, "failed to consume the bounded test stack");
                    consume(depth + 1, caller);
                }
                std::hint::black_box(&frame);
            }
            std::thread::Builder::new()
                .stack_size(2 * 1024 * 1024)
                .spawn(|| consume(0, std::thread::current().id()))
                .unwrap()
                .join()
                .unwrap();
            return;
        }

        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "backend_modules::nvx::state_aware::tests::consumed_stack_dispatches_to_worker",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while child.try_wait().unwrap().is_none() {
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "consumed-stack test timed out: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn provision_policy_is_validated_before_low_stack_worker() {
        std::thread::Builder::new()
            .stack_size(512 * 1024)
            .spawn(|| {
                // SAFETY: reverted on this thread before it exits.
                unsafe { ImpersonateSelf(SecurityIdentification) }.unwrap();
                struct Revert;
                impl Drop for Revert {
                    fn drop(&mut self) {
                        // SAFETY: balances the successful ImpersonateSelf call.
                        unsafe { RevertToSelf() }.unwrap();
                    }
                }
                let _revert = Revert;
                let mut request = ExecutionRequest::default();
                request.policy.ui_specified = true;
                let bound = BoundStateAwareRequest::for_test(
                    request,
                    BoundStateAwareOperation::Provision(Some(MicroVmProvisionConfig {
                        image: "mcr.microsoft.com/azurelinux/base/core:3.0".into(),
                        memory_mib: None,
                    })),
                );
                let error = dispatch(bound, true).unwrap_err();
                assert_eq!(error.code, MxcErrorCode::PolicyValidation);
            })
            .unwrap()
            .join()
            .unwrap();
    }
}
