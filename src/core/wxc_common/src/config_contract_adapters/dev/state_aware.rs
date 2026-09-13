// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::config_contract_adapters::dev::common::{
    convert_filesystem, convert_network, convert_process, convert_telemetry, convert_version,
};
use crate::error::WxcError;
use crate::models::{IsolationSessionProvisionConfig, WslcProvisionConfig};
use crate::state_aware_operation::{StateAwareOperation, StateAwareProvision};
use crate::state_aware_wire::StateAwareInput;
use crate::wire;
use mxc_config_contract::dev as contract;

fn convert_state_aware_isolation_session(
    value: contract::StateAwareIsolationSession,
) -> Option<IsolationSessionProvisionConfig> {
    let contract::StateAwareIsolationSession { provision } = value;
    provision
        .into_option()
        .map(convert_isolation_session_provision)
}

fn convert_isolation_session_provision(
    value: contract::IsolationSessionProvision,
) -> IsolationSessionProvisionConfig {
    let contract::IsolationSessionProvision { app_id } = value;
    IsolationSessionProvisionConfig {
        app_id: app_id.into_option(),
    }
}

fn convert_isolation_session_provision_experimental(
    value: contract::IsolationSessionProvisionExperimental,
) -> Option<IsolationSessionProvisionConfig> {
    let contract::IsolationSessionProvisionExperimental { isolation_session } = value;
    isolation_session
        .into_option()
        .and_then(convert_state_aware_isolation_session)
}

fn convert_isolation_session_network(value: contract::IsolationSessionNetwork) -> wire::Network {
    let contract::IsolationSessionNetwork {
        allow_local_network: contract::True,
        default_policy: contract::IsolationSessionNetworkDefaultPolicy,
    } = value;
    wire::Network {
        allow_local_network: Some(true),
        default_policy: Some(wire::NetworkPolicy::Allow),
        allowed_hosts: None,
        enforcement_mode: None,
        blocked_hosts: None,
        proxy: None,
        egress: None,
        ingress: None,
    }
}

fn consume_windows_sandbox_experimental(value: contract::WindowsSandboxExperimental) {
    let contract::WindowsSandboxExperimental {} = value;
}

fn convert_wslc_provision(value: contract::WslcProvision) -> WslcProvisionConfig {
    let contract::WslcProvision {
        image,
        image_tar_path,
    } = value;
    WslcProvisionConfig {
        image: image.into_option(),
        image_tar_path: image_tar_path.into_option(),
    }
}

fn convert_state_aware_wslc(value: contract::StateAwareWslc) -> Option<WslcProvisionConfig> {
    let contract::StateAwareWslc { provision } = value;
    provision.into_option().map(convert_wslc_provision)
}

fn convert_wslc_provision_experimental(
    value: contract::WslcProvisionExperimental,
) -> Option<WslcProvisionConfig> {
    let contract::WslcProvisionExperimental { wslc } = value;
    wslc.into_option().and_then(convert_state_aware_wslc)
}

fn consume_start_experimental(value: contract::StartExperimental) {
    let contract::StartExperimental {} = value;
}

fn consume_exec_experimental(value: contract::ExecExperimental) {
    let contract::ExecExperimental {} = value;
}

fn consume_stop_experimental(value: contract::StopExperimental) {
    let contract::StopExperimental {} = value;
}

fn consume_deprovision_experimental(value: contract::DeprovisionExperimental) {
    let contract::DeprovisionExperimental {} = value;
}

fn state_aware_common(
    schema: contract::OptionalField<String>,
    comment: contract::OptionalField<serde_json::Value>,
    version: contract::Version,
    telemetry: contract::OptionalField<contract::Telemetry>,
) -> wire::MxcConfig {
    wire::MxcConfig {
        schema: schema.into_option(),
        comment: comment.into_option(),
        version: Some(convert_version(version).to_owned()),
        phase: None,
        experimental: None,
        containment: None,
        container_id: None,
        sandbox_id: None,
        process: None,
        filesystem: None,
        fallback: None,
        network: None,
        runtime_config: None,
        telemetry: telemetry.into_option().map(convert_telemetry),
        lifecycle: None,
        lxc: None,
        process_container: None,
        seatbelt: None,
        ui: None,
    }
}

pub(super) fn provision_into_input(
    request: contract::ProvisionRequest,
) -> Result<StateAwareInput, WxcError> {
    match request {
        contract::ProvisionRequest::IsolationSession(request) => {
            isolation_session_provision_into_input(request)
        }
        contract::ProvisionRequest::WindowsSandbox(request) => {
            windows_sandbox_provision_into_input(request)
        }
        contract::ProvisionRequest::Wslc(request) => wslc_provision_into_input(request),
    }
}

fn isolation_session_provision_into_input(
    request: contract::IsolationSessionProvisionRequest,
) -> Result<StateAwareInput, WxcError> {
    let contract::IsolationSessionProvisionRequest {
        schema,
        comment,
        version,
        phase: contract::ProvisionPhase,
        containment: contract::IsolationSessionContainment,
        network,
        telemetry,
        experimental,
    } = request;
    let provision = experimental
        .into_option()
        .and_then(convert_isolation_session_provision_experimental);
    let mut common = state_aware_common(schema, comment, version, telemetry);
    common.network = Some(convert_isolation_session_network(network));
    StateAwareInput::new(
        common,
        StateAwareOperation::Provision(StateAwareProvision::IsolationSession(provision)),
    )
}

fn windows_sandbox_provision_into_input(
    request: contract::WindowsSandboxProvisionRequest,
) -> Result<StateAwareInput, WxcError> {
    let contract::WindowsSandboxProvisionRequest {
        schema,
        comment,
        version,
        phase: contract::ProvisionPhase,
        containment: contract::WindowsSandboxContainment,
        filesystem,
        telemetry,
        experimental,
    } = request;
    if let Some(experimental) = experimental.into_option() {
        consume_windows_sandbox_experimental(experimental);
    }
    let mut common = state_aware_common(schema, comment, version, telemetry);
    common.filesystem = filesystem.into_option().map(convert_filesystem);
    StateAwareInput::new(
        common,
        StateAwareOperation::Provision(StateAwareProvision::WindowsSandbox),
    )
}

fn wslc_provision_into_input(
    request: contract::WslcProvisionRequest,
) -> Result<StateAwareInput, WxcError> {
    let contract::WslcProvisionRequest {
        schema,
        comment,
        version,
        phase: contract::ProvisionPhase,
        containment: contract::WslcContainment,
        filesystem,
        network,
        telemetry,
        experimental,
    } = request;
    let provision = experimental
        .into_option()
        .and_then(convert_wslc_provision_experimental);
    let mut common = state_aware_common(schema, comment, version, telemetry);
    common.filesystem = filesystem.into_option().map(convert_filesystem);
    common.network = network.into_option().map(convert_network);
    StateAwareInput::new(
        common,
        StateAwareOperation::Provision(StateAwareProvision::Wslc(provision)),
    )
}

pub(super) fn start_into_input(
    request: contract::StartRequest,
) -> Result<StateAwareInput, WxcError> {
    let contract::StartRequest {
        schema,
        comment,
        version,
        phase: contract::StartPhase,
        sandbox_id,
        telemetry,
        experimental,
    } = request;
    if let Some(experimental) = experimental.into_option() {
        consume_start_experimental(experimental);
    }
    let common = state_aware_common(schema, comment, version, telemetry);
    StateAwareInput::new(common, StateAwareOperation::Start { sandbox_id })
}

pub(super) fn exec_into_input(request: contract::ExecRequest) -> Result<StateAwareInput, WxcError> {
    let contract::ExecRequest {
        schema,
        comment,
        version,
        phase: contract::ExecPhase,
        sandbox_id,
        process,
        network,
        telemetry,
        experimental,
    } = request;
    if let Some(experimental) = experimental.into_option() {
        consume_exec_experimental(experimental);
    }
    let mut common = state_aware_common(schema, comment, version, telemetry);
    common.process = Some(convert_process(process));
    common.network = network.into_option().map(convert_network);
    StateAwareInput::new(common, StateAwareOperation::Exec { sandbox_id })
}

pub(super) fn stop_into_input(request: contract::StopRequest) -> Result<StateAwareInput, WxcError> {
    let contract::StopRequest {
        schema,
        comment,
        version,
        phase: contract::StopPhase,
        sandbox_id,
        telemetry,
        experimental,
    } = request;
    if let Some(experimental) = experimental.into_option() {
        consume_stop_experimental(experimental);
    }
    let common = state_aware_common(schema, comment, version, telemetry);
    StateAwareInput::new(common, StateAwareOperation::Stop { sandbox_id })
}

pub(super) fn deprovision_into_input(
    request: contract::DeprovisionRequest,
) -> Result<StateAwareInput, WxcError> {
    let contract::DeprovisionRequest {
        schema,
        comment,
        version,
        phase: contract::DeprovisionPhase,
        sandbox_id,
        telemetry,
        experimental,
    } = request;
    if let Some(experimental) = experimental.into_option() {
        consume_deprovision_experimental(experimental);
    }
    let common = state_aware_common(schema, comment, version, telemetry);
    StateAwareInput::new(common, StateAwareOperation::Deprovision { sandbox_id })
}

#[cfg(test)]
#[path = "state_aware_tests/mod.rs"]
mod tests;
