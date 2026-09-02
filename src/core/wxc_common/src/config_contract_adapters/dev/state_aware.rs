// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::config_contract_adapters::dev::common::{
    convert_filesystem, convert_network, convert_process, convert_telemetry, convert_version,
};
use crate::state_aware_wire::StateAwareWireInput;
use crate::wire;
use mxc_config_contract::dev as contract;

#[derive(serde::Deserialize)]
struct ExperimentalProbe {
    #[serde(default)]
    experimental: Option<serde_json::Value>,
}

fn extract_experimental_value(
    source_text: &str,
) -> Result<Option<serde_json::Value>, serde_json::Error> {
    serde_json::from_str::<ExperimentalProbe>(source_text).map(|probe| probe.experimental)
}

fn convert_state_aware_isolation_session(
    value: contract::StateAwareIsolationSession,
) -> wire::IsolationSession {
    let contract::StateAwareIsolationSession { provision } = value;
    wire::IsolationSession {
        provision: provision
            .into_option()
            .map(convert_isolation_session_provision),
    }
}

fn convert_isolation_session_provision(
    value: contract::IsolationSessionProvision,
) -> wire::IsolationSessionProvisionPhase {
    let contract::IsolationSessionProvision { app_id } = value;
    wire::IsolationSessionProvisionPhase {
        app_id: app_id.into_option(),
    }
}

fn convert_isolation_session_provision_experimental(
    value: contract::IsolationSessionProvisionExperimental,
) -> wire::Experimental {
    let contract::IsolationSessionProvisionExperimental { isolation_session } = value;
    wire::Experimental {
        test: None,
        windows_sandbox: None,
        wslc: None,
        isolation_session: isolation_session
            .into_option()
            .map(convert_state_aware_isolation_session),
        seatbelt: None,
    }
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

fn convert_windows_sandbox_provision_experimental(
    value: contract::WindowsSandboxExperimental,
) -> wire::Experimental {
    let contract::WindowsSandboxExperimental {} = value;
    wire::Experimental {
        test: None,
        windows_sandbox: None,
        wslc: None,
        isolation_session: None,
        seatbelt: None,
    }
}

fn convert_wslc_provision(value: contract::WslcProvision) -> wire::WslcProvisionPhase {
    let contract::WslcProvision {
        image,
        image_tar_path,
    } = value;
    wire::WslcProvisionPhase {
        image: image.into_option(),
        image_tar_path: image_tar_path.into_option(),
    }
}

fn convert_state_aware_wslc(value: contract::StateAwareWslc) -> wire::Wslc {
    let contract::StateAwareWslc { provision } = value;
    wire::Wslc {
        cpu_count: None,
        gpu: None,
        image: None,
        image_tar_path: None,
        memory_mb: None,
        port_mappings: None,
        storage_path: None,
        target_os: None,
        provision: provision.into_option().map(convert_wslc_provision),
    }
}

fn convert_wslc_provision_experimental(
    value: contract::WslcProvisionExperimental,
) -> wire::Experimental {
    let contract::WslcProvisionExperimental { wslc } = value;
    wire::Experimental {
        test: None,
        windows_sandbox: None,
        wslc: wslc.into_option().map(convert_state_aware_wslc),
        isolation_session: None,
        seatbelt: None,
    }
}

fn convert_start_experimental(value: contract::StartExperimental) -> wire::Experimental {
    let contract::StartExperimental {} = value;
    wire::Experimental {
        test: None,
        windows_sandbox: None,
        wslc: None,
        isolation_session: None,
        seatbelt: None,
    }
}

fn convert_exec_experimental(value: contract::ExecExperimental) -> wire::Experimental {
    let contract::ExecExperimental {} = value;
    wire::Experimental {
        test: None,
        windows_sandbox: None,
        wslc: None,
        isolation_session: None,
        seatbelt: None,
    }
}

fn convert_stop_experimental(value: contract::StopExperimental) -> wire::Experimental {
    let contract::StopExperimental {} = value;
    wire::Experimental {
        test: None,
        windows_sandbox: None,
        wslc: None,
        isolation_session: None,
        seatbelt: None,
    }
}

fn convert_deprovision_experimental(
    value: contract::DeprovisionExperimental,
) -> wire::Experimental {
    let contract::DeprovisionExperimental {} = value;
    wire::Experimental {
        test: None,
        windows_sandbox: None,
        wslc: None,
        isolation_session: None,
        seatbelt: None,
    }
}

pub(super) fn provision_into_wire(request: contract::ProvisionRequest) -> wire::MxcConfig {
    match request {
        contract::ProvisionRequest::IsolationSession(request) => {
            isolation_session_provision_into_wire(request)
        }
        contract::ProvisionRequest::WindowsSandbox(request) => {
            windows_sandbox_provision_into_wire(request)
        }
        contract::ProvisionRequest::Wslc(request) => wslc_provision_into_wire(request),
    }
}

fn isolation_session_provision_into_wire(
    request: contract::IsolationSessionProvisionRequest,
) -> wire::MxcConfig {
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
    wire::MxcConfig {
        schema: schema.into_option(),
        comment: comment.into_option(),
        version: Some(convert_version(version).to_owned()),
        phase: Some(wire::Phase::Provision),
        experimental: experimental
            .into_option()
            .map(convert_isolation_session_provision_experimental),
        containment: Some(wire::Containment::IsolationSession),
        container_id: None,
        sandbox_id: None,
        process: None,
        filesystem: None,
        fallback: None,
        network: Some(convert_isolation_session_network(network)),
        runtime_config: None,
        telemetry: telemetry.into_option().map(convert_telemetry),
        lifecycle: None,
        lxc: None,
        process_container: None,
        seatbelt: None,
        ui: None,
    }
}

fn windows_sandbox_provision_into_wire(
    request: contract::WindowsSandboxProvisionRequest,
) -> wire::MxcConfig {
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
    wire::MxcConfig {
        schema: schema.into_option(),
        comment: comment.into_option(),
        version: Some(convert_version(version).to_owned()),
        phase: Some(wire::Phase::Provision),
        experimental: experimental
            .into_option()
            .map(convert_windows_sandbox_provision_experimental),
        containment: Some(wire::Containment::WindowsSandbox),
        container_id: None,
        sandbox_id: None,
        process: None,
        filesystem: filesystem.into_option().map(convert_filesystem),
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

fn wslc_provision_into_wire(request: contract::WslcProvisionRequest) -> wire::MxcConfig {
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
    wire::MxcConfig {
        schema: schema.into_option(),
        comment: comment.into_option(),
        version: Some(convert_version(version).to_owned()),
        phase: Some(wire::Phase::Provision),
        experimental: experimental
            .into_option()
            .map(convert_wslc_provision_experimental),
        containment: Some(wire::Containment::Wslc),
        container_id: None,
        sandbox_id: None,
        process: None,
        filesystem: filesystem.into_option().map(convert_filesystem),
        fallback: None,
        network: network.into_option().map(convert_network),
        runtime_config: None,
        telemetry: telemetry.into_option().map(convert_telemetry),
        lifecycle: None,
        lxc: None,
        process_container: None,
        seatbelt: None,
        ui: None,
    }
}

pub(super) fn start_into_wire(request: contract::StartRequest) -> wire::MxcConfig {
    let contract::StartRequest {
        schema,
        comment,
        version,
        phase: contract::StartPhase,
        sandbox_id,
        telemetry,
        experimental,
    } = request;
    wire::MxcConfig {
        schema: schema.into_option(),
        comment: comment.into_option(),
        version: Some(convert_version(version).to_owned()),
        phase: Some(wire::Phase::Start),
        sandbox_id: Some(sandbox_id),
        experimental: experimental.into_option().map(convert_start_experimental),
        containment: None,
        container_id: None,
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

pub(super) fn exec_into_wire(request: contract::ExecRequest) -> wire::MxcConfig {
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
    wire::MxcConfig {
        schema: schema.into_option(),
        comment: comment.into_option(),
        version: Some(convert_version(version).to_owned()),
        phase: Some(wire::Phase::Exec),
        sandbox_id: Some(sandbox_id),
        experimental: experimental.into_option().map(convert_exec_experimental),
        containment: None,
        container_id: None,
        process: Some(convert_process(process)),
        filesystem: None,
        fallback: None,
        network: network.into_option().map(convert_network),
        runtime_config: None,
        telemetry: telemetry.into_option().map(convert_telemetry),
        lifecycle: None,
        lxc: None,
        process_container: None,
        seatbelt: None,
        ui: None,
    }
}

pub(super) fn stop_into_wire(request: contract::StopRequest) -> wire::MxcConfig {
    let contract::StopRequest {
        schema,
        comment,
        version,
        phase: contract::StopPhase,
        sandbox_id,
        telemetry,
        experimental,
    } = request;
    wire::MxcConfig {
        schema: schema.into_option(),
        comment: comment.into_option(),
        version: Some(convert_version(version).to_owned()),
        phase: Some(wire::Phase::Stop),
        sandbox_id: Some(sandbox_id),
        experimental: experimental.into_option().map(convert_stop_experimental),
        containment: None,
        container_id: None,
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

pub(super) fn deprovision_into_wire(request: contract::DeprovisionRequest) -> wire::MxcConfig {
    let contract::DeprovisionRequest {
        schema,
        comment,
        version,
        phase: contract::DeprovisionPhase,
        sandbox_id,
        telemetry,
        experimental,
    } = request;
    wire::MxcConfig {
        schema: schema.into_option(),
        comment: comment.into_option(),
        version: Some(convert_version(version).to_owned()),
        phase: Some(wire::Phase::Deprovision),
        sandbox_id: Some(sandbox_id),
        experimental: experimental
            .into_option()
            .map(convert_deprovision_experimental),
        containment: None,
        container_id: None,
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

pub(super) fn into_state_aware_wire_input(
    config: wire::MxcConfig,
    source_text: &str,
) -> Result<StateAwareWireInput, serde_json::Error> {
    Ok(StateAwareWireInput {
        config,
        experimental_raw: extract_experimental_value(source_text)?,
        source_text: source_text.into(),
    })
}

#[cfg(test)]
#[path = "state_aware_tests/mod.rs"]
mod tests;
