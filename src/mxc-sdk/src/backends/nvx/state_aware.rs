// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use aci_edge_sandboxes::{AciEdgeSandbox, SandboxId};
use serde_json::Value;

use crate::mxc_common::models::{ExecutionRequest, MicroVmProvisionConfig};
use crate::mxc_common::mxc_error::MxcError;
use crate::mxc_common::state_aware_backend::{
    DeprovisionResult, ExecHandle, ExecStdio, ProvisionResult, StartResult, StatefulSandboxBackend,
    StopResult,
};

pub struct NvxStateAwareRunner {
    client: AciEdgeSandbox,
}

impl NvxStateAwareRunner {
    pub fn new() -> Result<Self, MxcError> {
        let state_root = super::runtime::lifecycle_state_root()?;
        Ok(Self {
            client: super::runtime::create_client(&state_root)?,
        })
    }
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
        let (provision, spec) = super::policy::provision_request(
            request,
            config.as_ref(),
            &self.client.capabilities(),
        )?;
        let result = self
            .client
            .provision_with(&provision, &spec)
            .map_err(super::runtime::map_nvx_error)?;
        Ok(ProvisionResult {
            sandbox_id: mxc_id(&result.sandbox_id),
            metadata: result.metadata.map(Value::Object),
        })
    }

    fn start(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<Self::StartConfig>,
    ) -> Result<StartResult<Self::StartMetadata>, MxcError> {
        self.client
            .start(&native_id(sandbox_id)?)
            .map_err(super::runtime::map_nvx_error)?;
        Ok(StartResult { metadata: None })
    }

    fn exec(
        &mut self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<Self::ExecConfig>,
        stdio: ExecStdio,
    ) -> Result<ExecHandle, MxcError> {
        let piped = stdio == ExecStdio::Piped;
        let request = super::policy::exec_request(request, piped, &self.client.capabilities())?;
        let execution = self
            .client
            .exec(&native_id(sandbox_id)?, &request)
            .map_err(super::runtime::map_nvx_error)?;
        super::process::into_exec_handle(execution, stdio)
    }

    fn stop(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<Self::StopConfig>,
    ) -> Result<StopResult<Self::StopMetadata>, MxcError> {
        self.client
            .stop(&native_id(sandbox_id)?)
            .map_err(super::runtime::map_nvx_error)?;
        Ok(StopResult { metadata: None })
    }

    fn deprovision(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<Self::DeprovisionConfig>,
    ) -> Result<DeprovisionResult<Self::DeprovisionMetadata>, MxcError> {
        self.client
            .deprovision(&native_id(sandbox_id)?)
            .map_err(super::runtime::map_nvx_error)?;
        Ok(DeprovisionResult { metadata: None })
    }

    fn validate_provision(
        &self,
        request: &ExecutionRequest,
        config: Option<&Self::ProvisionConfig>,
    ) -> Result<(), MxcError> {
        let (provision, spec) =
            super::policy::provision_request(request, config, &self.client.capabilities())?;
        self.client
            .validate_provision_with(&provision, &spec)
            .map_err(super::runtime::map_nvx_error)
    }

    fn validate_start(
        &self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<&Self::StartConfig>,
    ) -> Result<(), MxcError> {
        native_id(sandbox_id).map(|_| ())
    }

    fn validate_exec(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&Self::ExecConfig>,
    ) -> Result<(), MxcError> {
        native_id(sandbox_id)?;
        let request = super::policy::exec_request(request, false, &self.client.capabilities())?;
        self.client
            .validate_exec(&request)
            .map_err(super::runtime::map_nvx_error)
    }

    fn validate_stop(
        &self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<&Self::StopConfig>,
    ) -> Result<(), MxcError> {
        native_id(sandbox_id).map(|_| ())
    }

    fn validate_deprovision(
        &self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<&Self::DeprovisionConfig>,
    ) -> Result<(), MxcError> {
        native_id(sandbox_id).map(|_| ())
    }
}

fn native_id(value: &str) -> Result<SandboxId, MxcError> {
    let token = value
        .strip_prefix("microvm:")
        .ok_or_else(|| MxcError::malformed_id("MicroVM sandbox ID must start with 'microvm:'"))?;
    SandboxId::from_token(token).map_err(super::runtime::map_nvx_error)
}

fn mxc_id(value: &SandboxId) -> String {
    format!("microvm:{}", value.token())
}

#[cfg(test)]
mod tests {
    use super::super::test_support::Fixture;
    use super::*;
    use crate::mxc_common::state_aware_backend::ExecOutcome;
    use crate::mxc_common::state_aware_binding::{
        BoundStateAwareOperation, BoundStateAwareRequest,
    };
    use crate::mxc_common::state_aware_dispatch::{
        dispatch_state_aware_exec, dispatch_state_aware_typed, TypedDispatchOutcome,
    };

    fn bound_exec() -> BoundStateAwareRequest<NvxStateAwareRunner> {
        BoundStateAwareRequest::for_test(
            ExecutionRequest {
                script_code: "printf test".to_owned(),
                script_timeout: 1_000,
                inherit_default_env: true,
                ..Default::default()
            },
            BoundStateAwareOperation::Exec {
                sandbox_id: mxc_id(&Fixture::id()),
                config: None,
            },
        )
    }

    #[test]
    fn relayed_dispatch_reports_nvx_timeout_not_a_protocol_violation() {
        for outcome in [
            aci_edge_sandboxes::ExecOutcome::Exited(7),
            aci_edge_sandboxes::ExecOutcome::TimedOut,
        ] {
            let fixture = Fixture {
                outcome: Some(outcome),
                ..Default::default()
            };
            let mut backend = NvxStateAwareRunner {
                client: AciEdgeSandbox::new(fixture.clone()),
            };
            let result = dispatch_state_aware_typed(&mut backend, bound_exec(), false);
            if outcome == aci_edge_sandboxes::ExecOutcome::TimedOut {
                let error = result.unwrap_err();
                assert_eq!(
                    error.code,
                    crate::mxc_common::mxc_error::MxcErrorCode::BackendError
                );
                assert_eq!(
                    error.message,
                    "NVX relayed exec timed out; workload deadline elapsed"
                );
            } else {
                assert!(matches!(
                    result.unwrap(),
                    TypedDispatchOutcome::ExecCompleted { exit_code: 7 }
                ));
            }
            assert_eq!(*fixture.stdin_piped.lock().unwrap(), Some(false));
            let mut events = vec!["validate_exec", "validate_exec", "exec", "wait"];
            if outcome == aci_edge_sandboxes::ExecOutcome::TimedOut {
                events.push("cancel");
            }
            assert_eq!(*fixture.events.lock().unwrap(), events);
        }
    }

    #[test]
    fn piped_dispatch_retains_exit_timeout_and_real_stream_contracts() {
        for outcome in [
            aci_edge_sandboxes::ExecOutcome::Exited(7),
            aci_edge_sandboxes::ExecOutcome::TimedOut,
        ] {
            let fixture = Fixture {
                outcome: Some(outcome),
                ..Default::default()
            };
            let mut backend = NvxStateAwareRunner {
                client: AciEdgeSandbox::new(fixture.clone()),
            };
            let handle = dispatch_state_aware_exec(&mut backend, bound_exec()).unwrap();
            assert!(!handle.stdin.0.is_null());
            assert!(!handle.stdout.0.is_null());
            assert!(!handle.stderr.0.is_null());
            assert!(handle.stdin_closer.is_some());
            // The real adapter, not the outcome helper, owns these pipes and waiter.
            let actual = (handle.waiter)().unwrap();
            assert_eq!(
                actual,
                if outcome == aci_edge_sandboxes::ExecOutcome::TimedOut {
                    ExecOutcome::TimedOut
                } else {
                    ExecOutcome::Exited(7)
                }
            );
            assert_eq!(*fixture.stdin_piped.lock().unwrap(), Some(true));
            assert_eq!(
                *fixture.events.lock().unwrap(),
                ["validate_exec", "validate_exec", "exec", "wait"]
            );
        }
    }

    #[test]
    fn ids_translate_without_exposing_native_prefix() {
        let native = SandboxId::from_token("0123456789abcdef0123456789abcdef").unwrap();
        let mxc = mxc_id(&native);
        assert_eq!(mxc, "microvm:0123456789abcdef0123456789abcdef");
        assert_eq!(native_id(&mxc).unwrap(), native);
    }

    #[test]
    fn malformed_mxc_ids_are_rejected() {
        assert!(native_id("aci-edge-sandboxes:0123456789abcdef0123456789abcdef").is_err());
        assert!(native_id("microvm:bad").is_err());
    }
}
