// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::error::WxcError;
use crate::models::{ContainmentBackend, IsolationSessionProvisionConfig, WslcProvisionConfig};
use crate::state_aware_operation::{StateAwareOperation, StateAwareProvision};
use crate::state_aware_request::Phase;
use crate::state_aware_wire::StateAwareInput;
use crate::wire;
use mxc_config_contract::dev as contract;

fn malformed(message: impl Into<String>) -> WxcError {
    WxcError::ConfigParse(message.into())
}

fn require_sandbox_id(phase: Phase, sandbox_id: Option<&str>) -> Result<String, WxcError> {
    sandbox_id.map(str::to_owned).ok_or_else(|| {
        malformed(format!(
            "the {phase} operation requires a sandbox ID supplied by the API or --sandbox-id"
        ))
    })
}

fn reject_non_exec_process(common: &wire::MxcConfig, phase: Phase) -> Result<(), WxcError> {
    if common.process.is_some() {
        return Err(malformed(format!(
            "process is accepted only by one-shot execution and the exec operation, not {phase}"
        )));
    }
    Ok(())
}

fn reject_non_exec_policy(common: &wire::MxcConfig, phase: Phase) -> Result<(), WxcError> {
    for (present, field) in [
        (common.filesystem.is_some(), "filesystem"),
        (common.network.is_some(), "network"),
        (common.runtime_config.is_some(), "runtimeConfig"),
        (common.ui.is_some(), "ui"),
    ] {
        if present {
            return Err(malformed(format!(
                "{field} is not accepted by the {phase} operation"
            )));
        }
    }
    Ok(())
}

fn take_experimental(common: &mut wire::MxcConfig) -> wire::Experimental {
    common.experimental.take().unwrap_or(wire::Experimental {
        test: None,
        windows_sandbox: None,
        wslc: None,
        isolation_session: None,
        seatbelt: None,
    })
}

fn reject_foreign_experimental(
    experimental: &wire::Experimental,
    expected: &str,
) -> Result<(), WxcError> {
    let foreign = [
        ("test", experimental.test.is_some()),
        (
            "windows_sandbox",
            expected != "windows_sandbox" && experimental.windows_sandbox.is_some(),
        ),
        ("wslc", expected != "wslc" && experimental.wslc.is_some()),
        (
            "isolation_session",
            expected != "isolation_session" && experimental.isolation_session.is_some(),
        ),
        ("seatbelt", experimental.seatbelt.is_some()),
    ]
    .into_iter()
    .find_map(|(name, present)| present.then_some(name));

    if let Some(name) = foreign {
        return Err(malformed(format!(
            "experimental.{name} is not accepted when provisioning {expected}"
        )));
    }
    Ok(())
}

fn isolation_session_provision(
    experimental: wire::Experimental,
) -> Result<StateAwareProvision, WxcError> {
    reject_foreign_experimental(&experimental, "isolation_session")?;
    let config = experimental
        .isolation_session
        .map(|value| IsolationSessionProvisionConfig {
            app_id: value
                .app_id
                .or_else(|| value.provision.and_then(|value| value.app_id)),
        });
    Ok(StateAwareProvision::IsolationSession(config))
}

fn windows_sandbox_provision(
    experimental: wire::Experimental,
) -> Result<StateAwareProvision, WxcError> {
    reject_foreign_experimental(&experimental, "windows_sandbox")?;
    if let Some(value) = experimental.windows_sandbox {
        if value.idle_timeout.is_some()
            || value.idle_timeout_ms.is_some()
            || value.daemon_pipe_name.is_some()
        {
            return Err(malformed(
                "experimental.windows_sandbox settings are not accepted by lifecycle provision",
            ));
        }
    }
    Ok(StateAwareProvision::WindowsSandbox)
}

fn wslc_provision(experimental: wire::Experimental) -> Result<StateAwareProvision, WxcError> {
    reject_foreign_experimental(&experimental, "wslc")?;
    let config = experimental
        .wslc
        .map(|value| {
            if value.target_os.is_some()
                || value.cpu_count.is_some()
                || value.memory_mb.is_some()
                || value.gpu.is_some()
                || value.storage_path.is_some()
                || value.port_mappings.is_some()
            {
                return Err(malformed(
                    "lifecycle provision accepts only experimental.wslc.image and imageTarPath",
                ));
            }
            let nested = value.provision;
            if nested.is_some() {
                return Err(malformed(
                    "experimental.wslc.provision is no longer supported; place image and \
                     imageTarPath directly under experimental.wslc",
                ));
            }
            Ok(WslcProvisionConfig {
                image: value.image,
                image_tar_path: value.image_tar_path,
            })
        })
        .transpose()?;
    Ok(StateAwareProvision::Wslc(config))
}

fn provision_operation(common: &mut wire::MxcConfig) -> Result<StateAwareOperation, WxcError> {
    reject_non_exec_process(common, Phase::Provision)?;
    if common.runtime_config.is_some() || common.ui.is_some() {
        return Err(malformed(
            "runtimeConfig and ui are not accepted by the provision operation",
        ));
    }

    let containment = common
        .containment
        .take()
        .map(ContainmentBackend::from)
        .ok_or_else(|| malformed("the provision operation requires containment"))?;
    let experimental = take_experimental(common);
    let provision = match containment {
        ContainmentBackend::IsolationSession => isolation_session_provision(experimental)?,
        ContainmentBackend::WindowsSandbox => windows_sandbox_provision(experimental)?,
        ContainmentBackend::Wslc => wslc_provision(experimental)?,
        backend => {
            return Err(malformed(format!(
                "backend '{}' does not support lifecycle provision",
                backend.wire_name()
            )))
        }
    };
    Ok(StateAwareOperation::Provision(provision))
}

pub(super) fn operation_into_input(
    request: contract::OneShotRequest,
    phase: Phase,
    sandbox_id: Option<&str>,
) -> Result<StateAwareInput, WxcError> {
    let mut common = super::one_shot::into_wire(request);
    let operation = match phase {
        Phase::Provision => {
            if sandbox_id.is_some() {
                return Err(malformed(
                    "a sandbox ID is not accepted by the provision operation",
                ));
            }
            provision_operation(&mut common)?
        }
        Phase::Exec => {
            if common.filesystem.is_some() || common.ui.is_some() {
                return Err(malformed(
                    "filesystem and ui are not accepted by the exec operation",
                ));
            }
            StateAwareOperation::Exec {
                sandbox_id: require_sandbox_id(phase, sandbox_id)?,
            }
        }
        Phase::Start => {
            reject_non_exec_process(&common, phase)?;
            reject_non_exec_policy(&common, phase)?;
            StateAwareOperation::Start {
                sandbox_id: require_sandbox_id(phase, sandbox_id)?,
            }
        }
        Phase::Stop => {
            reject_non_exec_process(&common, phase)?;
            reject_non_exec_policy(&common, phase)?;
            StateAwareOperation::Stop {
                sandbox_id: require_sandbox_id(phase, sandbox_id)?,
            }
        }
        Phase::Deprovision => {
            reject_non_exec_process(&common, phase)?;
            reject_non_exec_policy(&common, phase)?;
            StateAwareOperation::Deprovision {
                sandbox_id: require_sandbox_id(phase, sandbox_id)?,
            }
        }
    };
    StateAwareInput::new(common, operation)
}
