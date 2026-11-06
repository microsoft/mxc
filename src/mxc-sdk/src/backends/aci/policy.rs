// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Maps create-and-run requests onto ACI sandbox and command requests, and
//! rejects policy that an ACI sandbox cannot enforce.

use std::time::Duration;

use crate::mxc_common::guest_process::validate_process;
use crate::mxc_common::models::{AciConfig, ExecutionRequest};
use crate::mxc_common::mxc_error::MxcError;

use super::proto::ExecSandboxRequest;
use super::service::SandboxGroup;

const BACKEND: &str = "ACI";
const SHELL: &str = "/bin/sh";

/// The sandbox to create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SandboxSpec {
    pub group: SandboxGroup,
    pub image: String,
    pub cpu: Option<u32>,
    pub memory_gb: Option<u32>,
}

impl SandboxSpec {
    /// The data-plane body that creates a Linux sandbox in `location`.
    pub fn body(&self, location: &str) -> serde_json::Value {
        let mut properties = serde_json::json!({
            "guestOs": "linux",
            "architecture": "amd64",
            "image": self.image,
        });
        let mut resources = serde_json::Map::new();
        if let Some(cpu) = self.cpu {
            resources.insert("cpu".into(), cpu.into());
        }
        if let Some(memory_gb) = self.memory_gb {
            resources.insert("memory".into(), memory_gb.into());
        }
        if !resources.is_empty() {
            properties["resources"] = serde_json::Value::Object(resources);
        }
        serde_json::json!({
            "location": location,
            "tags": {"createdBy": "mxc"},
            "properties": properties,
        })
    }
}

/// The command to run and how long to wait for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExecSpec {
    pub request: ExecSandboxRequest,
    /// `None` waits until the command exits.
    pub timeout: Option<Duration>,
}

/// Rejects settings an ACI sandbox cannot honor, before any Azure call.
pub(super) fn validate_request(request: &ExecutionRequest) -> Result<&AciConfig, MxcError> {
    let config = request
        .aci
        .as_ref()
        .ok_or_else(|| MxcError::malformed_request("the aci section is required"))?;
    if !request.lifecycle.destroy_on_exit {
        return Err(MxcError::policy_validation(
            "ACI requires lifecycle.destroyOnExit=true",
        ));
    }
    if request.lifecycle.preserve_policy {
        return Err(MxcError::policy_validation(
            "ACI requires lifecycle.preservePolicy=false",
        ));
    }
    SandboxGroup::parse(&config.sandbox_group)?;
    crate::mxc_contract::dev::ImageReference::validate(&config.image, "aci.image")
        .map_err(MxcError::malformed_request)?;
    for (field, value) in [
        ("aci.provision.cpu", config.cpu),
        ("aci.provision.memoryGb", config.memory_gb),
    ] {
        if value == Some(0) {
            return Err(MxcError::malformed_request(format!(
                "{field} must be greater than zero"
            )));
        }
    }
    for (field, paths) in [
        ("filesystem.readonlyPaths", &request.policy.readonly_paths),
        ("filesystem.readwritePaths", &request.policy.readwrite_paths),
        ("filesystem.deniedPaths", &request.policy.denied_paths),
    ] {
        if !paths.is_empty() {
            return Err(MxcError::policy_validation(format!(
                "ACI does not support {field}: host paths cannot be shared with a sandbox that runs in Azure"
            )));
        }
    }
    if !request.policy.enumerate_paths.is_empty() {
        return Err(MxcError::policy_validation(
            "ACI does not support filesystem.enumeratePaths",
        ));
    }
    if request.policy.network_specified {
        return Err(MxcError::policy_validation(
            "ACI does not support network policy; the sandbox group's network configuration applies",
        ));
    }
    if request.policy.runtime_network_proxy_specified || request.policy.network_proxy.is_enabled() {
        return Err(MxcError::policy_validation(
            "ACI does not support runtimeConfig.networkProxy",
        ));
    }
    if request.policy.ui_specified {
        return Err(MxcError::policy_validation(
            "ACI does not support UI policy",
        ));
    }
    if request.policy.capture_denials.is_some() {
        return Err(MxcError::policy_validation(
            "ACI does not support processContainer.captureDenials",
        ));
    }
    validate_process(request, BACKEND)?;
    Ok(config)
}

/// The sandbox a validated request creates.
pub(super) fn sandbox_spec(request: &ExecutionRequest) -> Result<SandboxSpec, MxcError> {
    let config = validate_request(request)?;
    Ok(SandboxSpec {
        group: SandboxGroup::parse(&config.sandbox_group)?,
        image: config.image.clone(),
        cpu: config.cpu,
        memory_gb: config.memory_gb,
    })
}

/// The command a validated request runs: `process.commandLine` in the guest's
/// POSIX shell, with environment entries added to the sandbox's environment.
pub(super) fn exec_spec(request: &ExecutionRequest) -> ExecSpec {
    let timeout = (request.script_timeout != 0)
        .then(|| Duration::from_millis(u64::from(request.script_timeout)));
    ExecSpec {
        request: ExecSandboxRequest {
            command: SHELL.to_owned(),
            args: vec!["-c".to_owned(), request.script_code.clone()],
            working_directory: (!request.working_directory.is_empty())
                .then(|| request.working_directory.clone()),
            environment: request.env.as_deref().map(environment).unwrap_or_default(),
            // The gateway counts whole seconds; round up so it never stops early.
            timeout_seconds: timeout.map(|timeout| {
                i32::try_from(timeout.as_millis().div_ceil(1000)).unwrap_or(i32::MAX)
            }),
        },
        timeout,
    }
}

/// Splits validated `KEY=VALUE` entries. A repeated name keeps its last value.
fn environment(entries: &[String]) -> Vec<(String, String)> {
    let mut variables: Vec<(String, String)> = Vec::new();
    for entry in entries {
        let (key, value) = entry.split_once('=').unwrap_or((entry.as_str(), ""));
        match variables.iter_mut().find(|(existing, _)| existing == key) {
            Some((_, existing)) => value.clone_into(existing),
            None => variables.push((key.to_owned(), value.to_owned())),
        }
    }
    variables
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_common::models::{
        CaptureDenialsConfig, ContainmentBackend, NetworkEgressPolicy, ProxyAddress,
    };
    use crate::mxc_common::mxc_error::MxcErrorCode;

    pub(crate) const GROUP: &str = "/subscriptions/51aca303-03da-4510-849d-d4f32d3f39ac/resourceGroups/tryme-01/providers/Microsoft.ContainerInstance/sandboxGroups/sbg-001";
    const IMAGE: &str = "mcr.microsoft.com/azurelinux/base/core:3.0";

    fn request() -> ExecutionRequest {
        ExecutionRequest {
            script_code: "echo ok".to_owned(),
            containment: ContainmentBackend::Aci,
            aci: Some(AciConfig {
                sandbox_group: GROUP.to_owned(),
                image: IMAGE.to_owned(),
                cpu: None,
                memory_gb: None,
            }),
            ..ExecutionRequest::default()
        }
    }

    fn json_request(json: &serde_json::Value) -> ExecutionRequest {
        let mut logger =
            crate::mxc_common::logger::Logger::new(crate::mxc_common::logger::Mode::Buffer);
        match crate::mxc_common::config_parser::load_mxc_request_from_json(
            &json.to_string(),
            &mut logger,
        )
        .unwrap()
        {
            crate::mxc_common::state_aware_request::MxcRequest::OneShot(request) => request,
            _ => panic!("expected create-and-run request"),
        }
    }

    fn assert_rejected(request: &ExecutionRequest, code: MxcErrorCode, text: &str) {
        let error = validate_request(request).unwrap_err();
        assert_eq!(error.code, code, "{error}");
        assert!(error.message.contains(text), "{error}");
    }

    #[test]
    fn json_requests_reach_the_sandbox_and_command_specs() {
        let request = json_request(&serde_json::json!({
            "version": "1.1.0-alpha",
            "containment": "aci",
            "aci": {"sandboxGroup": GROUP, "image": IMAGE, "provision": {"cpu": 2, "memoryGb": 4}},
            "process": {
                "commandLine": "printf '%s' \"$GREETING\"",
                "cwd": "/tmp",
                "timeout": 1500,
                "env": ["GREETING=first", "OTHER=x", "GREETING=second"],
                "inheritDefaultEnv": true
            }
        }));
        assert_eq!(request.containment, ContainmentBackend::Aci);
        assert!(!request.experimental_enabled);
        let sandbox = sandbox_spec(&request).unwrap();
        assert_eq!(
            sandbox.group.subscription,
            "51aca303-03da-4510-849d-d4f32d3f39ac"
        );
        assert_eq!(
            sandbox.body("centraluseuap"),
            serde_json::json!({
                "location": "centraluseuap",
                "tags": {"createdBy": "mxc"},
                "properties": {
                    "guestOs": "linux",
                    "architecture": "amd64",
                    "image": IMAGE,
                    "resources": {"cpu": 2, "memory": 4}
                }
            })
        );
        let exec = exec_spec(&request);
        assert_eq!(exec.timeout, Some(Duration::from_millis(1500)));
        assert_eq!(
            exec.request,
            ExecSandboxRequest {
                command: "/bin/sh".to_owned(),
                args: vec!["-c".to_owned(), "printf '%s' \"$GREETING\"".to_owned()],
                working_directory: Some("/tmp".to_owned()),
                environment: vec![
                    ("GREETING".to_owned(), "second".to_owned()),
                    ("OTHER".to_owned(), "x".to_owned()),
                ],
                timeout_seconds: Some(2),
            }
        );
    }

    #[test]
    fn omitted_settings_keep_service_and_guest_defaults() {
        let request = request();
        let body = sandbox_spec(&request).unwrap().body("westus");
        assert!(body["properties"].get("resources").is_none());
        let exec = exec_spec(&request);
        assert_eq!(exec.timeout, None);
        assert_eq!(exec.request.timeout_seconds, None);
        assert_eq!(exec.request.working_directory, None);
        assert!(exec.request.environment.is_empty());

        let mut cpu_only = request.clone();
        cpu_only.aci.as_mut().unwrap().cpu = Some(1);
        assert_eq!(
            sandbox_spec(&cpu_only).unwrap().body("westus")["properties"]["resources"],
            serde_json::json!({"cpu": 1})
        );
    }

    #[test]
    fn unenforceable_policy_fails_closed() {
        type Change = fn(&mut ExecutionRequest);
        let cases: [(&str, Change); 9] = [
            ("filesystem.readonlyPaths", |r| {
                r.policy.readonly_paths = vec![r"C:\ro".into()]
            }),
            ("filesystem.readwritePaths", |r| {
                r.policy.readwrite_paths = vec![r"C:\rw".into()]
            }),
            ("filesystem.deniedPaths", |r| {
                r.policy.denied_paths = vec![r"C:\no".into()]
            }),
            ("filesystem.enumeratePaths", |r| {
                r.policy.enumerate_paths = vec![r"C:\e".into()]
            }),
            ("network policy", |r| {
                r.policy.network_specified = true;
                r.policy.network_egress = Some(NetworkEgressPolicy::default());
            }),
            ("runtimeConfig.networkProxy", |r| {
                r.policy.runtime_network_proxy_specified = true;
                r.policy.network_proxy.address =
                    Some(ProxyAddress::new("127.0.0.1".to_owned(), 3128));
            }),
            ("UI policy", |r| r.policy.ui_specified = true),
            ("captureDenials", |r| {
                r.policy.capture_denials = Some(CaptureDenialsConfig::default())
            }),
            ("destroyOnExit=true", |r| {
                r.lifecycle.destroy_on_exit = false
            }),
        ];
        for (text, change) in cases {
            let mut rejected = request();
            change(&mut rejected);
            assert_rejected(&rejected, MxcErrorCode::PolicyValidation, text);
        }
        let mut preserve = request();
        preserve.lifecycle.preserve_policy = true;
        assert_rejected(
            &preserve,
            MxcErrorCode::PolicyValidation,
            "preservePolicy=false",
        );
    }

    #[test]
    fn json_network_and_proxy_sections_are_rejected_even_when_empty() {
        for extra in [
            serde_json::json!({"network": {}}),
            serde_json::json!({"network": {"egress": {"default": "allow"}}}),
            serde_json::json!({"runtimeConfig": {"networkProxy": "http://127.0.0.1:3128"}}),
            serde_json::json!({"ui": {"disable": true}}),
            serde_json::json!({"filesystem": {"readonlyPaths": [r"C:\data"]}}),
        ] {
            let mut json = serde_json::json!({
                "version": "1.1.0-alpha",
                "containment": "aci",
                "aci": {"sandboxGroup": GROUP, "image": IMAGE},
                "process": {"commandLine": "true"}
            });
            json.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            let error = validate_request(&json_request(&json)).unwrap_err();
            assert_eq!(
                error.code,
                MxcErrorCode::PolicyValidation,
                "{extra}: {error}"
            );
        }
    }

    #[test]
    fn invalid_sandbox_settings_are_malformed() {
        let mut missing = request();
        missing.aci = None;
        assert_rejected(&missing, MxcErrorCode::MalformedRequest, "aci section");

        let mut group = request();
        group.aci.as_mut().unwrap().sandbox_group = "/subscriptions/x".to_owned();
        assert_rejected(&group, MxcErrorCode::MalformedRequest, "aci.sandboxGroup");

        for image in ["", "python:3.12", "library/python"] {
            let mut bad = request();
            bad.aci.as_mut().unwrap().image = image.to_owned();
            assert_rejected(&bad, MxcErrorCode::MalformedRequest, "aci.image");
        }

        let mut cpu = request();
        cpu.aci.as_mut().unwrap().cpu = Some(0);
        assert_rejected(&cpu, MxcErrorCode::MalformedRequest, "aci.provision.cpu");
        let mut memory = request();
        memory.aci.as_mut().unwrap().memory_gb = Some(0);
        assert_rejected(
            &memory,
            MxcErrorCode::MalformedRequest,
            "aci.provision.memoryGb",
        );
    }

    #[test]
    fn guest_process_limits_match_the_microvm_backend() {
        let mut env = request();
        env.env = Some(vec!["KEY=value".to_owned()]);
        assert_rejected(
            &env,
            MxcErrorCode::PolicyValidation,
            "ACI process.env requires inheritDefaultEnv=true",
        );
        env.inherit_default_env = true;
        assert!(validate_request(&env).is_ok());
        env.env = Some(vec!["https_proxy=http://proxy".to_owned()]);
        assert_rejected(&env, MxcErrorCode::PolicyValidation, "proxy environment");

        let mut cwd = request();
        cwd.working_directory = "relative".to_owned();
        assert_rejected(
            &cwd,
            MxcErrorCode::PolicyValidation,
            "absolute POSIX guest path",
        );

        let mut timeout = request();
        timeout.script_timeout = 3_600_001;
        assert_rejected(&timeout, MxcErrorCode::PolicyValidation, "one hour");
        timeout.script_timeout = 3_600_000;
        assert_eq!(exec_spec(&timeout).request.timeout_seconds, Some(3_600));
    }
}
