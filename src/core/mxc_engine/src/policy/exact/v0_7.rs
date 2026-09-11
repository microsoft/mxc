// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_config_contract::published::v0_7_0_alpha as contract;
use wxc_common::mxc_error::MxcError;

use crate::configs::{
    ProcessContainerSystemSettings, ProcessContainerUi, ProcessContainerUiIsolation,
};

use super::super::{ClipboardPolicy, Containment, ProxySpec, UiSection};
use super::{
    error, legacy_enforcement, non_empty_port, normalized_capabilities, selected_process_container,
    LegacyEnforcement, PreparedInput,
};

fn map_proxy(proxy: &ProxySpec) -> Result<contract::NetworkProxy, MxcError> {
    match proxy {
        ProxySpec::BuiltinTestServer => Err(error(
            "network.proxy.builtinTestServer is not supported by the in-process Rust SDK; use localhost or url",
        )),
        ProxySpec::Localhost(port) => Ok(contract::NetworkProxy::Localhost(non_empty_port(
            *port,
            "network.proxy.localhost",
        )?)),
        ProxySpec::Url(url) => Ok(contract::NetworkProxy::Url(url.clone())),
    }
}

fn map_ui(ui: &UiSection) -> contract::Ui {
    contract::Ui {
        disable: contract::OptionalField::present(!ui.allow_windows),
        clipboard: contract::OptionalField::present(match ui.clipboard {
            ClipboardPolicy::None => contract::UiClipboard::None,
            ClipboardPolicy::Read => contract::UiClipboard::Read,
            ClipboardPolicy::Write => contract::UiClipboard::Write,
            ClipboardPolicy::All => contract::UiClipboard::All,
        }),
        injection: contract::OptionalField::present(ui.allow_input_injection),
    }
}

fn map_process_container_ui(ui: &ProcessContainerUi) -> contract::ProcessContainerUi {
    contract::ProcessContainerUi {
        isolation: contract::OptionalField::present(match ui.isolation {
            ProcessContainerUiIsolation::Container => {
                contract::ProcessContainerUiIsolation::Container
            }
            ProcessContainerUiIsolation::Desktop => contract::ProcessContainerUiIsolation::Desktop,
            ProcessContainerUiIsolation::Handles => contract::ProcessContainerUiIsolation::Handles,
            ProcessContainerUiIsolation::Atoms => contract::ProcessContainerUiIsolation::Atoms,
        }),
        desktop_system_control: contract::OptionalField::present(ui.desktop_system_control),
        system_settings: contract::OptionalField::present(
            match ui.system_settings {
                ProcessContainerSystemSettings::All => "all",
                ProcessContainerSystemSettings::Parameters => "parameters",
                ProcessContainerSystemSettings::Display => "display",
                ProcessContainerSystemSettings::None => "none",
            }
            .to_string(),
        ),
        ime: contract::OptionalField::present(ui.ime),
    }
}

fn map_legacy_enforcement(value: LegacyEnforcement) -> contract::NetworkEnforcementMode {
    match value {
        LegacyEnforcement::Capabilities => contract::NetworkEnforcementMode::Capabilities,
        LegacyEnforcement::Firewall => contract::NetworkEnforcementMode::Firewall,
        LegacyEnforcement::Both => contract::NetworkEnforcementMode::Both,
    }
}

pub(super) fn build(input: &PreparedInput<'_>) -> Result<contract::Request, MxcError> {
    let policy = input.policy;
    let containment = input.containment;
    let network_format = input.network_format;
    if network_format == super::NetworkFormat::Directional {
        return Err(error(
            "network egress/ingress/runtimeConfig and processContainer.network require schema version 0.8 or later",
        ));
    }
    if matches!(
        containment,
        Containment::Wslc(_) | Containment::IsolationSession
    ) {
        return Err(error(
            "selected containment requires schema version 0.9.0-alpha",
        ));
    }
    let process_container = selected_process_container(containment);
    if let Some(process_container) = process_container.as_ref() {
        if process_container.learning_mode {
            return Err(error(
                "processContainer.learningMode requires schema version 0.8 or later",
            ));
        }
        if process_container.capture_denials.is_some() {
            return Err(error(
                "processContainer.captureDenials requires schema version 0.8 or later",
            ));
        }
        if process_container
            .network
            .as_ref()
            .and_then(|network| network.allowed_proxy_peer.as_ref())
            .is_some()
        {
            return Err(error(
                "processContainer.network requires schema version 0.8 or later",
            ));
        }
    }
    let enforcement = legacy_enforcement(policy, containment, process_container.is_some());
    let seatbelt = if cfg!(target_os = "macos") && matches!(containment, Containment::Process) {
        contract::OptionalField::present(contract::Seatbelt {
            profile_override: Default::default(),
            gui_access: Default::default(),
            launch_method: Default::default(),
            nested_pty: Default::default(),
            keychain_access: Default::default(),
            extra_mach_lookups: Default::default(),
        })
    } else {
        Default::default()
    };
    Ok(contract::Request {
        schema: Default::default(),
        comment: Default::default(),
        version: contract::Version::V0_7_0Alpha,
        container_id: contract::OptionalField::present(input.container_id.clone()),
        containment: contract::OptionalField::present(
            if cfg!(target_os = "macos") && matches!(containment, Containment::Process) {
                contract::Containment::Seatbelt
            } else {
                match containment {
                    Containment::Process => contract::Containment::Process,
                    Containment::ProcessContainer(_) => contract::Containment::ProcessContainer,
                    _ => unreachable!("unsupported containment checked above"),
                }
            },
        ),
        lifecycle: contract::OptionalField::present(contract::Lifecycle {
            destroy_on_exit: contract::OptionalField::present(true),
            preserve_policy: contract::OptionalField::present(
                !policy
                    .filesystem
                    .as_ref()
                    .and_then(|filesystem| filesystem.clear_policy_on_exit)
                    .unwrap_or(true),
            ),
        }),
        process: contract::Process {
            command_line: contract::NonEmptyString::new(input.script.to_string()).map_err(error)?,
            cwd: Default::default(),
            env: Default::default(),
            timeout: contract::OptionalField::present(policy.timeout_ms.unwrap_or(0)),
        },
        filesystem: contract::OptionalField::present(contract::Filesystem {
            readwrite_paths: contract::OptionalField::present(
                policy
                    .filesystem
                    .as_ref()
                    .map(|filesystem| filesystem.readwrite_paths.clone())
                    .unwrap_or_default(),
            ),
            readonly_paths: contract::OptionalField::present(
                policy
                    .filesystem
                    .as_ref()
                    .map(|filesystem| filesystem.readonly_paths.clone())
                    .unwrap_or_default(),
            ),
            denied_paths: contract::OptionalField::present(
                policy
                    .filesystem
                    .as_ref()
                    .map(|filesystem| filesystem.denied_paths.clone())
                    .unwrap_or_default(),
            ),
        }),
        fallback: Default::default(),
        network: contract::OptionalField::present(contract::Network {
            default_policy: contract::OptionalField::present(
                if policy
                    .network
                    .as_ref()
                    .is_some_and(|network| network.allow_outbound)
                {
                    contract::DefaultNetworkPolicy::Allow
                } else {
                    contract::DefaultNetworkPolicy::Block
                },
            ),
            enforcement_mode: optional!(contract, enforcement.map(map_legacy_enforcement)),
            allowed_hosts: match policy.network.as_ref() {
                Some(network) => contract::OptionalField::present(network.allowed_hosts.clone()),
                None => Default::default(),
            },
            blocked_hosts: match policy.network.as_ref() {
                Some(network) => contract::OptionalField::present(network.blocked_hosts.clone()),
                None => Default::default(),
            },
            allow_local_network: match policy.network.as_ref() {
                Some(network) => contract::OptionalField::present(network.allow_local_network),
                None => Default::default(),
            },
            proxy: optional!(
                contract,
                policy
                    .network
                    .as_ref()
                    .and_then(|network| network.proxy.as_ref())
                    .map(map_proxy)
                    .transpose()?
            ),
        }),
        ui: optional!(contract, policy.ui.as_ref().map(map_ui)),
        process_container: optional!(
            contract,
            process_container.as_ref().map(|process_container| {
                contract::ProcessContainer {
                    least_privilege: contract::OptionalField::present(
                        process_container.least_privilege,
                    ),
                    capabilities: contract::OptionalField::present(normalized_capabilities(
                        policy,
                        process_container,
                        network_format,
                    )),
                    ui: optional!(
                        contract,
                        process_container.ui.as_ref().map(map_process_container_ui)
                    ),
                }
            })
        ),
        lxc: Default::default(),
        seatbelt,
    })
}
