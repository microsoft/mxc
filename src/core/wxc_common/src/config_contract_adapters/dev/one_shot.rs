// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::config_contract_adapters::dev::common::{
    convert_filesystem, convert_network, convert_process, convert_telemetry, convert_version,
};
use crate::wire;
use mxc_config_contract::dev as contract;

fn convert_containment(value: contract::OneShotContainment) -> wire::Containment {
    match value {
        contract::OneShotContainment::Process => wire::Containment::Process,
        contract::OneShotContainment::ProcessContainer => wire::Containment::ProcessContainer,
        contract::OneShotContainment::Lxc => wire::Containment::Lxc,
        contract::OneShotContainment::Bubblewrap => wire::Containment::Bubblewrap,
        contract::OneShotContainment::Seatbelt => wire::Containment::Seatbelt,
        contract::OneShotContainment::Vm => wire::Containment::Vm,
        contract::OneShotContainment::WindowsSandbox => wire::Containment::WindowsSandbox,
        contract::OneShotContainment::Microvm => wire::Containment::Microvm,
        contract::OneShotContainment::Hyperlight => wire::Containment::Hyperlight,
        contract::OneShotContainment::Wslc => wire::Containment::Wslc,
        contract::OneShotContainment::IsolationSession => wire::Containment::IsolationSession,
    }
}

fn convert_lifecycle(value: contract::Lifecycle) -> wire::Lifecycle {
    let contract::Lifecycle {
        destroy_on_exit,
        preserve_policy,
    } = value;
    wire::Lifecycle {
        destroy_on_exit: destroy_on_exit.into_option(),
        preserve_policy: preserve_policy.into_option(),
    }
}

fn convert_fallback(value: contract::Fallback) -> wire::Fallback {
    let contract::Fallback {
        allow_dacl_mutation,
    } = value;
    wire::Fallback {
        allow_dacl_mutation: allow_dacl_mutation.into_option(),
    }
}

fn convert_clipboard(value: contract::UiClipboard) -> wire::ClipboardPolicy {
    match value {
        contract::UiClipboard::None => wire::ClipboardPolicy::None,
        contract::UiClipboard::Read => wire::ClipboardPolicy::Read,
        contract::UiClipboard::Write => wire::ClipboardPolicy::Write,
        contract::UiClipboard::All => wire::ClipboardPolicy::All,
    }
}

fn convert_ui(value: contract::Ui) -> wire::Ui {
    let contract::Ui {
        disable,
        clipboard,
        injection,
    } = value;
    wire::Ui {
        disable: disable.into_option(),
        clipboard: clipboard.into_option().map(convert_clipboard),
        injection: injection.into_option(),
    }
}

fn convert_capture_denials_mode(value: contract::CaptureDenialsMode) -> wire::CaptureDenialsMode {
    match value {
        contract::CaptureDenialsMode::Block => wire::CaptureDenialsMode::Block,
        contract::CaptureDenialsMode::Allow => wire::CaptureDenialsMode::Allow,
    }
}

fn convert_capture_denials(value: contract::CaptureDenials) -> wire::CaptureDenials {
    let contract::CaptureDenials {
        mode,
        output_path,
        retain_etl,
    } = value;
    wire::CaptureDenials {
        mode: mode.into_option().map(convert_capture_denials_mode),
        output_path: output_path.into_option(),
        retain_etl: retain_etl.into_option(),
    }
}

fn convert_process_container(value: contract::ProcessContainer) -> wire::ProcessContainer {
    let contract::ProcessContainer {
        least_privilege,
        learning_mode,
        capabilities,
        capture_denials,
        ui,
        network,
    } = value;
    wire::ProcessContainer {
        least_privilege: least_privilege.into_option(),
        learning_mode: learning_mode.into_option(),
        capabilities: capabilities.into_option().map(|capabilities| {
            capabilities
                .into_iter()
                .map(contract::ProcessContainerCapability::into_inner)
                .collect()
        }),
        capture_denials: capture_denials.into_option().map(convert_capture_denials),
        ui: ui.into_option().map(convert_process_container_ui),
        network: network.into_option().map(convert_process_container_network),
    }
}

fn convert_process_container_network(
    value: contract::ProcessContainerNetwork,
) -> wire::ProcessContainerNetwork {
    let contract::ProcessContainerNetwork { allowed_proxy_peer } = value;
    wire::ProcessContainerNetwork {
        allowed_proxy_peer: allowed_proxy_peer.into_option(),
    }
}

fn convert_runtime_config(value: contract::RuntimeConfig) -> wire::RuntimeConfig {
    let contract::RuntimeConfig { network_proxy } = value;
    wire::RuntimeConfig {
        network_proxy: network_proxy.into_option(),
    }
}

fn convert_process_container_ui_isolation(
    value: contract::ProcessContainerUiIsolation,
) -> wire::UiIsolation {
    match value {
        contract::ProcessContainerUiIsolation::Container => wire::UiIsolation::Container,
        contract::ProcessContainerUiIsolation::Desktop => wire::UiIsolation::Desktop,
        contract::ProcessContainerUiIsolation::Handles => wire::UiIsolation::Handles,
        contract::ProcessContainerUiIsolation::Atoms => wire::UiIsolation::Atoms,
    }
}

fn convert_process_container_ui(value: contract::ProcessContainerUi) -> wire::BaseProcessUi {
    let contract::ProcessContainerUi {
        isolation,
        desktop_system_control,
        system_settings,
        ime,
    } = value;
    wire::BaseProcessUi {
        isolation: isolation
            .into_option()
            .map(convert_process_container_ui_isolation),
        desktop_system_control: desktop_system_control.into_option(),
        system_settings: system_settings.into_option(),
        ime: ime.into_option(),
    }
}

fn convert_lxc(value: contract::Lxc) -> wire::Lxc {
    let contract::Lxc {
        distribution,
        release,
    } = value;
    wire::Lxc {
        distribution: Some(distribution),
        release: Some(release),
    }
}

fn convert_launch_method(value: contract::LaunchMethod) -> wire::LaunchMethod {
    match value {
        contract::LaunchMethod::Exec => wire::LaunchMethod::Exec,
        contract::LaunchMethod::Open => wire::LaunchMethod::Open,
    }
}

fn convert_seatbelt(value: contract::Seatbelt) -> wire::Seatbelt {
    let contract::Seatbelt {
        profile_override,
        gui_access,
        launch_method,
        nested_pty,
        keychain_access,
        system_power_access,
        extra_mach_lookups,
    } = value;
    wire::Seatbelt {
        profile_override: profile_override.into_option(),
        gui_access: gui_access.into_option(),
        launch_method: launch_method.into_option().map(convert_launch_method),
        nested_pty: nested_pty.into_option(),
        keychain_access: keychain_access.into_option(),
        system_power_access: system_power_access.into_option(),
        extra_mach_lookups: extra_mach_lookups.into_option(),
    }
}

fn convert_test(value: contract::TestFeature) -> wire::TestFeature {
    let contract::TestFeature { message } = value;
    wire::TestFeature {
        message: message.into_option(),
    }
}

fn convert_windows_sandbox(value: contract::OneShotWindowsSandbox) -> wire::WindowsSandbox {
    let contract::OneShotWindowsSandbox {
        idle_timeout,
        idle_timeout_ms,
        daemon_pipe_name,
    } = value;
    wire::WindowsSandbox {
        idle_timeout: idle_timeout.into_option(),
        idle_timeout_ms: idle_timeout_ms.into_option(),
        daemon_pipe_name: daemon_pipe_name.into_option(),
    }
}

fn convert_protocol(value: contract::TransportProtocol) -> wire::TransportProtocol {
    match value {
        contract::TransportProtocol::Tcp => wire::TransportProtocol::Tcp,
    }
}

fn convert_wslc_port_mapping(value: contract::PortMapping) -> wire::PortMapping {
    let contract::PortMapping {
        windows_port,
        container_port,
        protocol,
    } = value;
    wire::PortMapping {
        windows_port: windows_port.get(),
        container_port: container_port.get(),
        protocol: protocol.into_option().map(convert_protocol),
    }
}

fn convert_wslc(value: contract::OneShotWslc) -> wire::Wslc {
    let contract::OneShotWslc {
        target_os,
        image,
        image_tar_path,
        cpu_count,
        memory_mb,
        gpu,
        storage_path,
        port_mappings,
    } = value;
    wire::Wslc {
        provision: None,
        target_os: target_os.into_option(),
        image: image.into_option(),
        image_tar_path: image_tar_path.into_option(),
        cpu_count: cpu_count.into_option(),
        memory_mb: memory_mb.into_option(),
        gpu: gpu.into_option(),
        storage_path: storage_path.into_option(),
        port_mappings: port_mappings.into_option().map(|mappings| {
            mappings
                .into_iter()
                .map(convert_wslc_port_mapping)
                .collect()
        }),
    }
}

fn convert_experimental(value: contract::OneShotExperimental) -> wire::Experimental {
    let contract::OneShotExperimental {
        test,
        windows_sandbox,
        wslc,
        telemetry,
    } = value;
    wire::Experimental {
        test: test.into_option().map(convert_test),
        windows_sandbox: windows_sandbox.into_option().map(convert_windows_sandbox),
        wslc: wslc.into_option().map(convert_wslc),
        isolation_session: None,
        seatbelt: None,
        telemetry: telemetry.into_option().map(convert_telemetry),
    }
}

pub(super) fn into_wire(request: contract::OneShotRequest) -> wire::MxcConfig {
    let contract::OneShotRequest {
        schema,
        comment,
        version,
        container_id,
        containment,
        lifecycle,
        process,
        filesystem,
        fallback,
        network,
        lxc,
        process_container,
        ui,
        seatbelt,
        runtime_config,
        experimental,
    } = request;
    wire::MxcConfig {
        schema: schema.into_option(),
        comment: comment.into_option(),
        version: Some(convert_version(version).to_owned()),
        phase: None,
        sandbox_id: None,
        correlation_vector: None,
        container_id: container_id.into_option(),
        containment: containment.into_option().map(convert_containment),
        process: Some(convert_process(process)),
        lifecycle: lifecycle.into_option().map(convert_lifecycle),
        process_container: process_container
            .into_option()
            .map(convert_process_container),
        lxc: lxc.into_option().map(convert_lxc),
        filesystem: filesystem.into_option().map(convert_filesystem),
        fallback: fallback.into_option().map(convert_fallback),
        network: network.into_option().map(convert_network),
        runtime_config: runtime_config.into_option().map(convert_runtime_config),
        ui: ui.into_option().map(convert_ui),
        seatbelt: seatbelt.into_option().map(convert_seatbelt),
        experimental: experimental.into_option().map(convert_experimental),
    }
}

#[cfg(test)]
#[path = "one_shot_tests/mod.rs"]
mod tests;
