// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use serde_json::Value;

use crate::mxc_common::logger::Logger;
use crate::mxc_common::models::{ExecutionRequest, MicroVmProvisionConfig};
use crate::mxc_common::mxc_error::MxcError;
use crate::mxc_common::state_aware_backend::{
    DeprovisionResult, ExecHandle, ExecStdio, ProvisionResult, StartResult, StatefulSandboxBackend,
    StopResult,
};

use super::runtime::PreparedProvision;
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
            &mut Logger::inherit_thread_diagnostic_sink(),
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
        let _ = self.client()?;
        let client =
            self.client.get_mut().as_mut().ok_or_else(|| {
                MxcError::backend_error("NVX lifecycle client was already consumed")
            })?;
        let mut logger = Logger::inherit_thread_diagnostic_sink();
        super::runner::prepare_execution(client, true, None, &mut logger)?;
        super::runner::start_sandbox(client, &sandbox_id, true, &mut logger)?;
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
