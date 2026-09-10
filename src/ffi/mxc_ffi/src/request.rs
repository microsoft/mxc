// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Co-versioned JSON request contract used by language bindings.

use std::collections::BTreeMap;

use mxc_sdk::configs::{
    CaptureDenials, ProcessContainer, ProcessContainerNetwork, ProcessContainerSystemSettings,
    ProcessContainerUi, ProcessContainerUiIsolation,
};
use mxc_sdk::policy::{FilesystemSection, NetworkSection, UiSection};
use mxc_sdk::{
    build_request_with_containment, Containment, Error, ErrorCode, SandboxPolicy, SandboxRequest,
    WslcSection,
};
use serde::de::{Error as _, IgnoredAny};
use serde::{Deserialize, Deserializer};

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RequestSpec {
    policy: RequestPolicy,
    command: String,
    #[serde(default)]
    containment: RequestContainment,
    #[serde(default)]
    container_name: Option<String>,
    #[serde(default)]
    working_directory: Option<String>,
    #[serde(default)]
    environment: BTreeMap<String, String>,
    #[serde(default)]
    experimental: bool,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RequestPolicy {
    version: String,
    #[serde(default)]
    filesystem: Option<FilesystemSection>,
    #[serde(default)]
    network: Option<NetworkSection>,
    #[serde(default)]
    ui: Option<UiSection>,
    #[serde(default)]
    timeout_ms: Option<u32>,
    #[serde(
        default,
        rename = "captureDenials",
        deserialize_with = "reject_legacy_capture_denials"
    )]
    _capture_denials: (),
    #[serde(default)]
    telemetry: TelemetryField,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TelemetrySpec {
    #[serde(default)]
    enabled: Option<bool>,
}

#[derive(Default)]
enum TelemetryField {
    #[default]
    Absent,
    Present(Option<TelemetrySpec>),
}

impl<'de> Deserialize<'de> for TelemetryField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<TelemetrySpec>::deserialize(deserializer).map(Self::Present)
    }
}

fn reject_legacy_capture_denials<'de, D>(deserializer: D) -> Result<(), D::Error>
where
    D: Deserializer<'de>,
{
    IgnoredAny::deserialize(deserializer)?;
    Err(D::Error::custom(
        "policy.captureDenials is not supported; set containment.type to \
         processContainer and use containment.captureDenials",
    ))
}

impl RequestPolicy {
    fn into_sdk(self) -> Result<(SandboxPolicy, Option<TelemetrySpec>), Error> {
        let telemetry = match self.telemetry {
            TelemetryField::Absent => None,
            TelemetryField::Present(telemetry) => {
                if let Ok(version) = semver::Version::parse(&self.version) {
                    if version.major == 0 && version.minor < 9 {
                        return Err(Error::new(
                            ErrorCode::MalformedRequest,
                            "policy.telemetry requires config schema version 0.9.0-alpha or later",
                        ));
                    }
                }
                telemetry
            }
        };
        Ok((
            SandboxPolicy {
                version: self.version,
                filesystem: self.filesystem,
                network: self.network,
                ui: self.ui,
                timeout_ms: self.timeout_ms,
            },
            telemetry,
        ))
    }
}

#[derive(Default, serde::Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
enum RequestContainment {
    #[default]
    Process,
    ProcessContainer {
        #[serde(default, rename = "leastPrivilege")]
        least_privilege: bool,
        #[serde(default, rename = "learningMode")]
        learning_mode: bool,
        #[serde(default)]
        capabilities: Vec<String>,
        #[serde(default, rename = "captureDenials")]
        capture_denials: Option<CaptureDenials>,
        #[serde(default = "default_process_container_ui")]
        ui: Option<ProcessContainerUiSpec>,
        #[serde(default)]
        network: Option<ProcessContainerNetworkSpec>,
    },
    Wslc {
        #[serde(default = "default_wslc_image")]
        image: String,
        #[serde(default, rename = "imageTarPath")]
        image_tar_path: Option<String>,
        #[serde(default, rename = "cpuCount")]
        cpu_count: Option<u32>,
        #[serde(default, rename = "memoryMb")]
        memory_mb: Option<u64>,
        #[serde(default)]
        gpu: bool,
        #[serde(default, rename = "storagePath")]
        storage_path: Option<String>,
        #[serde(default, rename = "portMappings")]
        port_mappings: Vec<WslcPortMappingSpec>,
    },
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProcessContainerUiSpec {
    #[serde(default)]
    isolation: ProcessContainerUiIsolationSpec,
    #[serde(default)]
    desktop_system_control: bool,
    #[serde(default)]
    system_settings: ProcessContainerSystemSettingsSpec,
    #[serde(default)]
    ime: bool,
}

impl Default for ProcessContainerUiSpec {
    fn default() -> Self {
        Self {
            isolation: ProcessContainerUiIsolationSpec::Container,
            desktop_system_control: false,
            system_settings: ProcessContainerSystemSettingsSpec::None,
            ime: false,
        }
    }
}

#[derive(Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
enum ProcessContainerUiIsolationSpec {
    Desktop,
    Handles,
    Atoms,
    #[default]
    Container,
}

#[derive(Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
enum ProcessContainerSystemSettingsSpec {
    All,
    Parameters,
    Display,
    #[default]
    None,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProcessContainerNetworkSpec {
    #[serde(default)]
    allowed_proxy_peer: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WslcPortMappingSpec {
    windows_port: u16,
    container_port: u16,
}

fn default_process_container_ui() -> Option<ProcessContainerUiSpec> {
    Some(ProcessContainerUiSpec::default())
}

fn default_wslc_image() -> String {
    "alpine:latest".to_string()
}

impl RequestContainment {
    // These public SDK configuration types are `#[non_exhaustive]`, so a
    // downstream binding crate must start from `Default` and assign fields
    // rather than using struct update syntax.
    #[allow(clippy::field_reassign_with_default)]
    fn into_sdk(self) -> Containment {
        match self {
            Self::Process => Containment::Process,
            Self::ProcessContainer {
                least_privilege,
                learning_mode,
                capabilities,
                capture_denials,
                ui,
                network,
            } => {
                let mut process_container = ProcessContainer::default();
                process_container.least_privilege = least_privilege;
                process_container.learning_mode = learning_mode;
                process_container.capabilities = capabilities;
                process_container.capture_denials = capture_denials;
                process_container.ui = ui.map(ProcessContainerUiSpec::into_sdk);
                process_container.network = network.map(ProcessContainerNetworkSpec::into_sdk);
                Containment::ProcessContainer(process_container)
            }
            Self::Wslc {
                image,
                image_tar_path,
                cpu_count,
                memory_mb,
                gpu,
                storage_path,
                port_mappings,
            } => {
                let mut wslc = WslcSection::default();
                wslc.image = image;
                wslc.image_tar_path = image_tar_path;
                wslc.cpu_count = cpu_count;
                wslc.memory_mb = memory_mb;
                wslc.gpu = gpu;
                wslc.storage_path = storage_path;
                wslc.port_mappings = port_mappings
                    .into_iter()
                    .map(|mapping| (mapping.windows_port, mapping.container_port))
                    .collect();
                Containment::Wslc(wslc)
            }
        }
    }
}

impl ProcessContainerUiSpec {
    fn into_sdk(self) -> ProcessContainerUi {
        let mut ui = ProcessContainerUi::default();
        ui.isolation = match self.isolation {
            ProcessContainerUiIsolationSpec::Desktop => ProcessContainerUiIsolation::Desktop,
            ProcessContainerUiIsolationSpec::Handles => ProcessContainerUiIsolation::Handles,
            ProcessContainerUiIsolationSpec::Atoms => ProcessContainerUiIsolation::Atoms,
            ProcessContainerUiIsolationSpec::Container => ProcessContainerUiIsolation::Container,
        };
        ui.desktop_system_control = self.desktop_system_control;
        ui.system_settings = match self.system_settings {
            ProcessContainerSystemSettingsSpec::All => ProcessContainerSystemSettings::All,
            ProcessContainerSystemSettingsSpec::Parameters => {
                ProcessContainerSystemSettings::Parameters
            }
            ProcessContainerSystemSettingsSpec::Display => ProcessContainerSystemSettings::Display,
            ProcessContainerSystemSettingsSpec::None => ProcessContainerSystemSettings::None,
        };
        ui.ime = self.ime;
        ui
    }
}

impl ProcessContainerNetworkSpec {
    fn into_sdk(self) -> ProcessContainerNetwork {
        let mut network = ProcessContainerNetwork::default();
        network.allowed_proxy_peer = self.allowed_proxy_peer;
        network
    }
}

/// Parse a binding request and build the public Rust SDK request it describes.
pub(crate) fn build_request_from_json(request_json: &str) -> Result<SandboxRequest, Error> {
    let mut deserializer = serde_json::Deserializer::from_str(request_json);
    let mut ignored_paths = Vec::new();
    let spec: RequestSpec = serde_ignored::deserialize(&mut deserializer, |path| {
        ignored_paths.push(path.to_string().replace(".?.", "."));
    })
    .map_err(malformed_request)?;
    deserializer.end().map_err(malformed_request)?;
    if let Some(path) = ignored_paths.first() {
        return Err(Error::new(
            ErrorCode::MalformedRequest,
            format!("unknown request field `{path}`"),
        ));
    }
    if let Some(name) = spec
        .environment
        .keys()
        .find(|name| name.is_empty() || name.contains('='))
    {
        return Err(Error::new(
            ErrorCode::MalformedRequest,
            format!("invalid environment variable name `{name}`"),
        ));
    }
    let (policy, telemetry) = spec.policy.into_sdk()?;
    let containment = spec.containment.into_sdk();

    let mut request = build_request_with_containment(
        &policy,
        &containment,
        &spec.command,
        spec.container_name.as_deref(),
    )?;
    if let Some(working_directory) = spec.working_directory {
        request.set_working_directory(working_directory);
    }
    request.set_env(spec.environment);
    request.set_experimental(spec.experimental);
    if let Some(enabled) = telemetry.and_then(|telemetry| telemetry.enabled) {
        request.set_telemetry_opt_in(enabled);
    }
    Ok(request)
}

fn malformed_request(error: serde_json::Error) -> Error {
    Error::new(
        ErrorCode::MalformedRequest,
        format!("failed to parse request JSON: {error}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_full_request_goldens_are_accepted_by_native_contract() {
        let process_container =
            include_str!("../../../../tests/policy/request-process-container.json");
        let process_spec: RequestSpec =
            serde_json::from_str(process_container).expect("process-container golden parses");
        assert_eq!(process_spec.command, "echo parity");
        assert_eq!(
            process_spec.environment.get("PARITY").map(String::as_str),
            Some("true")
        );
        assert_eq!(process_spec.policy.timeout_ms, Some(30_000));
        let filesystem = process_spec
            .policy
            .filesystem
            .as_ref()
            .expect("filesystem policy is preserved");
        assert_eq!(filesystem.readwrite_paths, ["C:\\work"]);
        assert_eq!(filesystem.readonly_paths, ["C:\\input"]);
        assert_eq!(filesystem.denied_paths, ["C:\\secret"]);
        assert_eq!(filesystem.clear_policy_on_exit, Some(true));
        let ui = process_spec
            .policy
            .ui
            .as_ref()
            .expect("UI policy is preserved");
        assert!(!ui.allow_windows);
        assert_eq!(ui.clipboard, mxc_sdk::policy::ClipboardPolicy::Read);
        assert!(!ui.allow_input_injection);
        let authored_network = process_spec
            .policy
            .network
            .as_ref()
            .expect("network policy is preserved");
        assert_eq!(
            authored_network
                .runtime_config
                .as_ref()
                .and_then(|runtime| runtime.network_proxy.as_deref()),
            Some("http://127.0.0.1:8080")
        );
        match process_spec.containment {
            RequestContainment::ProcessContainer {
                least_privilege,
                capabilities,
                capture_denials,
                network,
                ..
            } => {
                assert!(least_privilege);
                assert_eq!(capabilities, ["internetClient"]);
                let capture = capture_denials.expect("captureDenials is preserved");
                assert_eq!(
                    capture.output_path.as_deref(),
                    Some("C:\\logs\\denials.json")
                );
                assert!(capture.retain_etl);
                assert_eq!(
                    network.and_then(|value| value.allowed_proxy_peer),
                    Some("Contoso.App_123".to_string())
                );
            }
            _ => panic!("process-container golden selected the wrong containment"),
        }
        let mut buildable_process_container: serde_json::Value =
            serde_json::from_str(process_container).expect("process-container golden parses");
        buildable_process_container["containment"]["captureDenials"]["outputPath"] =
            serde_json::Value::String(
                std::env::temp_dir()
                    .join("denials.json")
                    .to_string_lossy()
                    .into_owned(),
            );
        build_request_from_json(&buildable_process_container.to_string())
            .expect("process-container golden builds a public SDK request");

        let directional_network =
            include_str!("../../../../tests/policy/request-directional-network.json");
        let network_spec: RequestSpec =
            serde_json::from_str(directional_network).expect("directional-network golden parses");
        assert_eq!(network_spec.command, "echo network");
        assert!(matches!(
            network_spec.containment,
            RequestContainment::Process
        ));
        let network = network_spec
            .policy
            .network
            .as_ref()
            .expect("directional network policy is preserved");
        let allow = network
            .egress
            .as_ref()
            .and_then(|egress| egress.allow.as_ref())
            .expect("egress allow rule is preserved");
        let peers = allow[0].to.as_ref().expect("destination peer is preserved");
        assert_eq!(peers[0].cidr, "10.20.0.0/16");
        assert_eq!(
            peers[0].except.as_deref(),
            Some(["10.20.30.0/24".to_string()].as_slice())
        );
        let ports = allow[0].ports.as_ref().expect("port rule is preserved");
        assert_eq!(ports[0].protocol, Some(mxc_sdk::NetworkProtocol::Tcp));
        assert_eq!(ports[0].port, Some(443));
        assert_eq!(ports[0].end_port, Some(444));
        build_request_from_json(directional_network)
            .expect("directional-network golden builds a public SDK request");

        let wslc = include_str!("../../../../tests/policy/request-wslc.json");
        let wslc_spec: RequestSpec = serde_json::from_str(wslc).expect("WSLC golden parses");
        assert_eq!(wslc_spec.command, "printf parity");
        assert!(wslc_spec.experimental);
        match wslc_spec.containment {
            RequestContainment::Wslc {
                image,
                cpu_count,
                memory_mb,
                port_mappings,
                ..
            } => {
                assert_eq!(image, "alpine:3.20");
                assert_eq!(cpu_count, Some(2));
                assert_eq!(memory_mb, Some(1024));
                assert_eq!(port_mappings.len(), 1);
                assert_eq!(port_mappings[0].windows_port, 8080);
                assert_eq!(port_mappings[0].container_port, 80);
            }
            _ => panic!("WSLC golden selected the wrong containment"),
        }
        build_request_from_json(wslc).expect("WSLC golden builds a public SDK request");
    }

    #[test]
    fn telemetry_is_parsed_from_the_binding_policy() {
        for (telemetry, expected) in [
            ("", None),
            (r#","telemetry":{"enabled":true}"#, Some(true)),
            (r#","telemetry":{"enabled":false}"#, Some(false)),
            (r#","telemetry":null"#, None),
            (r#","telemetry":{}"#, None),
            (r#","telemetry":{"enabled":null}"#, None),
        ] {
            let request_json = format!(
                r#"{{
                    "policy": {{
                        "version": "0.9.0-alpha"
                        {telemetry}
                    }},
                    "command": "echo hi"
                }}"#
            );
            let request = build_request_from_json(&request_json)
                .unwrap_or_else(|error| panic!("request failed: {error}"));
            assert_eq!(request.telemetry_enabled(), expected);
        }
    }

    #[test]
    fn telemetry_rejects_unknown_fields() {
        let error = build_request_from_json(
            r#"{
                "policy": {
                    "version": "0.9.0-alpha",
                    "telemetry": {
                        "enabled": true,
                        "unexpected": true
                    }
                },
                "command": "echo hi"
            }"#,
        )
        .expect_err("unknown telemetry fields must fail");

        assert!(
            error.message.contains("unknown field `unexpected`"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn telemetry_rejects_pre_0_9_policies() {
        let error = build_request_from_json(
            r#"{
                "policy": {
                    "version": "0.8.0-alpha",
                    "telemetry": null
                },
                "command": "echo hi"
            }"#,
        )
        .expect_err("telemetry must require policy version 0.9 or later");

        assert!(
            error
                .message
                .contains("telemetry requires config schema version 0.9.0-alpha"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn telemetry_rejects_malformed_enabled_values() {
        let error = build_request_from_json(
            r#"{
                "policy": {
                    "version": "0.9.0-alpha",
                    "telemetry": {
                        "enabled": "yes"
                    }
                },
                "command": "echo hi"
            }"#,
        )
        .expect_err("non-boolean telemetry must fail");

        assert!(
            error.message.contains("invalid type"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn duplicate_request_and_telemetry_fields_are_rejected() {
        for request_json in [
            r#"{
                "policy": { "version": "0.9.0-alpha" },
                "command": "echo first",
                "command": "echo second"
            }"#,
            r#"{
                "policy": {
                    "version": "0.9.0-alpha",
                    "telemetry": { "enabled": true },
                    "telemetry": null
                },
                "command": "echo hi"
            }"#,
        ] {
            let error =
                build_request_from_json(request_json).expect_err("duplicate fields must fail");
            assert!(
                error.message.contains("duplicate field"),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn unknown_policy_fields_are_rejected() {
        let error = build_request_from_json(
            r#"{
                "policy": {
                    "version": "0.9.0-alpha",
                    "timeoutMS": 1
                },
                "command": "echo hi"
            }"#,
        )
        .expect_err("unknown policy fields must fail");

        assert!(
            error.message.contains("unknown field `timeoutMS`"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn unknown_nested_policy_fields_are_rejected() {
        for (request_json, expected_path) in [
            (
                r#"{
                    "policy": {
                        "version": "0.9.0-alpha",
                        "filesystem": {
                            "readwritePaths": [],
                            "unexpected": true
                        }
                    },
                    "command": "echo hi"
                }"#,
                "policy.filesystem.unexpected",
            ),
            (
                r#"{
                    "policy": {
                        "version": "0.9.0-alpha",
                        "network": {
                            "allowOutboud": true
                        }
                    },
                    "command": "echo hi"
                }"#,
                "policy.network.allowOutboud",
            ),
            (
                r#"{
                    "policy": {
                        "version": "0.9.0-alpha",
                        "ui": {
                            "unexpected": true
                        }
                    },
                    "command": "echo hi"
                }"#,
                "policy.ui.unexpected",
            ),
        ] {
            let error =
                build_request_from_json(request_json).expect_err("unknown nested fields must fail");
            assert!(
                error.message.contains(expected_path),
                "unexpected error for {expected_path}: {error}"
            );
        }
    }

    #[test]
    fn invalid_environment_variable_names_are_rejected() {
        for name in ["", "A=B"] {
            let request_json = serde_json::json!({
                "policy": { "version": "0.9.0-alpha" },
                "command": "echo hi",
                "environment": { name: "value" }
            })
            .to_string();
            let error =
                build_request_from_json(&request_json).expect_err("invalid names must fail");
            assert!(
                error.message.contains("invalid environment variable name"),
                "unexpected error for {name:?}: {error}"
            );
        }
    }

    #[test]
    fn capture_denials_is_mapped_to_process_container_configuration() {
        let error = build_request_from_json(
            r#"{
                "policy": { "version": "0.7.0-alpha" },
                "command": "echo hi",
                "containment": {
                    "type": "processContainer",
                    "captureDenials": {}
                }
            }"#,
        )
        .expect_err("captureDenials must reach version validation");

        assert!(
            error
                .message
                .contains("processContainer.captureDenials requires schema version 0.8"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn root_policy_capture_denials_is_rejected_instead_of_ignored() {
        let error = build_request_from_json(
            r#"{
                "policy": {
                    "version": "0.8.0-alpha",
                    "captureDenials": {}
                },
                "command": "echo hi"
            }"#,
        )
        .expect_err("a misplaced backend setting must fail closed");

        assert!(error
            .message
            .contains("policy.captureDenials is not supported"));
    }

    #[test]
    fn process_container_options_map_to_the_sdk_type() {
        let containment: RequestContainment = serde_json::from_str(
            r#"{
                "type": "processContainer",
                "leastPrivilege": true,
                "learningMode": true,
                "capabilities": ["internetClient"],
                "captureDenials": { "mode": "allow", "retainEtl": true },
                "ui": {
                    "isolation": "atoms",
                    "desktopSystemControl": true,
                    "systemSettings": "parameters",
                    "ime": true
                },
                "network": {
                    "allowedProxyPeer": "Contoso.Proxy_123"
                }
            }"#,
        )
        .expect("request containment parses");

        let Containment::ProcessContainer(config) = containment.into_sdk() else {
            panic!("expected ProcessContainer");
        };
        assert!(config.least_privilege);
        assert!(config.learning_mode);
        assert_eq!(config.capabilities, ["internetClient"]);
        assert!(config.capture_denials.expect("capture").retain_etl);
        let ui = config.ui.expect("ui");
        assert_eq!(ui.isolation, ProcessContainerUiIsolation::Atoms);
        assert!(ui.desktop_system_control);
        assert_eq!(
            ui.system_settings,
            ProcessContainerSystemSettings::Parameters
        );
        assert!(ui.ime);
        assert_eq!(
            config
                .network
                .expect("network")
                .allowed_proxy_peer
                .as_deref(),
            Some("Contoso.Proxy_123")
        );
    }

    #[test]
    fn wslc_options_map_to_the_sdk_type() {
        let containment: RequestContainment = serde_json::from_str(
            r#"{
                "type": "wslc",
                "image": "python:3.12",
                "imageTarPath": "C:\\images\\python.tar",
                "cpuCount": 4,
                "memoryMb": 4096,
                "gpu": true,
                "storagePath": "C:\\wslc",
                "portMappings": [
                    { "windowsPort": 8080, "containerPort": 80 }
                ]
            }"#,
        )
        .expect("request containment parses");

        let Containment::Wslc(config) = containment.into_sdk() else {
            panic!("expected WSLC");
        };
        assert_eq!(config.image, "python:3.12");
        assert_eq!(
            config.image_tar_path.as_deref(),
            Some(r"C:\images\python.tar")
        );
        assert_eq!(config.cpu_count, Some(4));
        assert_eq!(config.memory_mb, Some(4096));
        assert!(config.gpu);
        assert_eq!(config.storage_path.as_deref(), Some(r"C:\wslc"));
        assert_eq!(config.port_mappings, [(8080, 80)]);
    }

    #[test]
    fn directional_networking_reaches_schema_version_validation() {
        let error = build_request_from_json(
            r#"{
                "policy": {
                    "version": "0.7.0-alpha",
                    "network": {
                        "egress": { "default": "deny" }
                    }
                },
                "command": "echo hi"
            }"#,
        )
        .expect_err("directional networking must reach version validation");

        assert!(
            error
                .message
                .contains("network egress/ingress/runtimeConfig"),
            "unexpected error: {error}"
        );
    }
}
