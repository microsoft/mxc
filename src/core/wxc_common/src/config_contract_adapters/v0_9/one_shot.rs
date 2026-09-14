// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::common::{
    convert_filesystem, convert_network, convert_process, convert_runtime_config,
    convert_telemetry, convert_version,
};
use crate::wire;
use mxc_config_contract::published::v0_9_0_alpha as contract;

fn convert_containment(value: contract::Containment) -> wire::Containment {
    match value {
        contract::Containment::Process => wire::Containment::Process,
        contract::Containment::ProcessContainer => wire::Containment::ProcessContainer,
        contract::Containment::Lxc => wire::Containment::Lxc,
        contract::Containment::Bubblewrap => wire::Containment::Bubblewrap,
        contract::Containment::Seatbelt => wire::Containment::Seatbelt,
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
        extra_mach_lookups,
    } = value;
    wire::Seatbelt {
        profile_override: profile_override.into_option(),
        gui_access: gui_access.into_option(),
        launch_method: launch_method.into_option().map(convert_launch_method),
        nested_pty: nested_pty.into_option(),
        keychain_access: keychain_access.into_option(),
        extra_mach_lookups: extra_mach_lookups.into_option(),
    }
}

pub(crate) fn into_wire(request: contract::Request) -> wire::MxcConfig {
    let contract::Request {
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
        telemetry,
    } = request;
    wire::MxcConfig {
        schema: schema.into_option(),
        comment: comment.into_option(),
        version: Some(convert_version(version).to_owned()),
        phase: None,
        sandbox_id: None,
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
        telemetry: telemetry.into_option().map(convert_telemetry),
        ui: ui.into_option().map(convert_ui),
        seatbelt: seatbelt.into_option().map(convert_seatbelt),
        experimental: None,
    }
}
