// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_config_contract::ContractVersion;
use serde::Serialize;
use serde_json::Value;
use wxc_common::mxc_error::MxcError;

/// Windows ProcessContainer settings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessContainer {
    /// Enforce least-privilege mode.
    pub least_privilege: bool,
    /// Additional AppContainer capabilities, such as `registryRead`.
    pub capabilities: Vec<String>,
}

pub(crate) struct CaptureDenialsInput<'a> {
    pub mode: &'static str,
    pub output_path: Option<&'a str>,
    pub retain_etl: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProcessContainerUi {
    isolation: &'static str,
    desktop_system_control: bool,
    system_settings: &'static str,
    ime: bool,
}

impl Default for ProcessContainerUi {
    fn default() -> Self {
        Self {
            isolation: "container",
            desktop_system_control: false,
            system_settings: "none",
            ime: false,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProcessContainerV0_6 {
    least_privilege: bool,
    capabilities: Vec<String>,
    ui: ProcessContainerUi,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CaptureDenialsV0_8<'a> {
    mode: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_path: Option<&'a str>,
    retain_etl: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProcessContainerV0_8<'a> {
    #[serde(flatten)]
    common: ProcessContainerV0_6,
    #[serde(skip_serializing_if = "Option::is_none")]
    capture_denials: Option<CaptureDenialsV0_8<'a>>,
}

#[derive(Debug)]
pub(crate) enum VersionedProcessContainerConfig<'a> {
    V0_6(ProcessContainerV0_6),
    V0_7(ProcessContainerV0_6),
    V0_8(ProcessContainerV0_8<'a>),
}

impl VersionedProcessContainerConfig<'_> {
    pub(crate) fn into_value(self) -> Result<Value, MxcError> {
        match self {
            Self::V0_6(config) | Self::V0_7(config) => serialize_config(&config),
            Self::V0_8(config) => serialize_config(&config),
        }
    }
}

/// Creates the ProcessContainer wire object for an exact schema version.
pub(crate) fn create_process_container_config<'a>(
    version: &str,
    config: &ProcessContainer,
    allow_outbound: bool,
    allow_local_network: bool,
    capture_denials: Option<CaptureDenialsInput<'a>>,
) -> Result<VersionedProcessContainerConfig<'a>, MxcError> {
    let version = ContractVersion::parse_exact(version).ok_or_else(|| {
        MxcError::malformed_request(format!(
            "Unsupported policy version '{version}'; expected 0.6.0-alpha, \
             0.7.0-alpha, or 0.8.0-alpha"
        ))
    })?;

    let mut capabilities = Vec::new();
    if allow_outbound {
        capabilities.push("internetClient".to_string());
    }
    if allow_local_network {
        capabilities.push("privateNetworkClientServer".to_string());
    }
    for capability in &config.capabilities {
        if !capabilities
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(capability))
        {
            capabilities.push(capability.clone());
        }
    }

    let common = ProcessContainerV0_6 {
        least_privilege: config.least_privilege,
        capabilities,
        ui: ProcessContainerUi::default(),
    };

    match version {
        ContractVersion::V0_6_0Alpha => {
            if capture_denials.is_some() {
                return Err(MxcError::malformed_request(format!(
                    "processContainer.captureDenials is not available in schema version '{}'",
                    version.as_str()
                )));
            }
            Ok(VersionedProcessContainerConfig::V0_6(common))
        }
        ContractVersion::V0_7_0Alpha => {
            if capture_denials.is_some() {
                return Err(MxcError::malformed_request(format!(
                    "processContainer.captureDenials is not available in schema version '{}'",
                    version.as_str()
                )));
            }
            Ok(VersionedProcessContainerConfig::V0_7(common))
        }
        ContractVersion::V0_8_0Alpha => Ok(VersionedProcessContainerConfig::V0_8(
            ProcessContainerV0_8 {
                common,
                capture_denials: capture_denials.map(|capture| CaptureDenialsV0_8 {
                    mode: capture.mode,
                    output_path: capture.output_path,
                    retain_etl: capture.retain_etl,
                }),
            },
        )),
    }
}

fn serialize_config(config: &impl Serialize) -> Result<Value, MxcError> {
    serde_json::to_value(config).map_err(|error| {
        MxcError::backend_error(format!(
            "failed to serialize ProcessContainer configuration: {error}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_versions_emit_only_published_fields() {
        for version in ["0.6.0-alpha", "0.7.0-alpha"] {
            let value = create_process_container_config(
                version,
                &ProcessContainer {
                    least_privilege: true,
                    capabilities: vec!["registryRead".to_string()],
                },
                true,
                false,
                None,
            )
            .expect("published ProcessContainer config")
            .into_value()
            .expect("serialize ProcessContainer config");

            assert_eq!(value["leastPrivilege"], true);
            assert_eq!(
                value["capabilities"],
                serde_json::json!(["internetClient", "registryRead"])
            );
            assert!(value.get("captureDenials").is_none());
        }
    }

    #[test]
    fn capture_denials_requires_v0_8() {
        let capture = || CaptureDenialsInput {
            mode: "block",
            output_path: None,
            retain_etl: false,
        };

        let error = create_process_container_config(
            "0.7.0-alpha",
            &ProcessContainer::default(),
            false,
            false,
            Some(capture()),
        )
        .expect_err("0.7 must reject captureDenials");
        assert!(error.message.contains("not available"));

        let value = create_process_container_config(
            "0.8.0-alpha",
            &ProcessContainer::default(),
            false,
            false,
            Some(capture()),
        )
        .expect("0.8 captureDenials config")
        .into_value()
        .expect("serialize ProcessContainer config");
        assert_eq!(value["captureDenials"]["mode"], "block");
        assert!(value["captureDenials"].get("outputPath").is_none());
    }

    #[test]
    fn capability_merge_is_case_insensitive() {
        let value = create_process_container_config(
            "0.7.0-alpha",
            &ProcessContainer {
                capabilities: vec!["INTERNETCLIENT".to_string()],
                ..Default::default()
            },
            true,
            false,
            None,
        )
        .expect("ProcessContainer config")
        .into_value()
        .expect("serialize ProcessContainer config");

        assert_eq!(value["capabilities"], serde_json::json!(["internetClient"]));
    }
}
