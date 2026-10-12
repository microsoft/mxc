// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Minimal MXC adapter for one-shot execution through the signed NVX agent.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use aci_edge_sandboxes::agent::{
    AgentBackend, AgentConfig, BundleSource, CpuProfile, ImageSettings, ReferenceSettings,
    RuntimeSource, SandboxDefaults, SetupConfig,
};
use aci_edge_sandboxes::{AciEdgeSandbox, ExecOutcome, ExecRequest, ImageSource, ProvisionRequest};

use crate::mxc_common::logger::Logger;
use crate::mxc_common::models::{ExecutionRequest, FailurePhase, ScriptResponse};
use crate::mxc_common::mxc_error::{MxcError, MxcErrorCode};
use crate::mxc_common::script_runner::ScriptRunner;

const BUNDLE_DIR_ENV: &str = "MXC_NVX_BUNDLE_DIR";
const STATE_ROOT_ENV: &str = "MXC_NVX_STATE_ROOT";
const LOCAL_APP_DATA_ENV: &str = "LOCALAPPDATA";
const TEST_IMAGE_REFERENCE: &str = "mcr.microsoft.com/azurelinux/base/python:3.12";
const RUNTIME_MANIFEST_SHA256: [u8; 32] = [
    0xf0, 0xb0, 0xa1, 0x9e, 0x31, 0x6d, 0x8b, 0x42, 0xa2, 0x62, 0xc0, 0xf8, 0x82, 0x18, 0xad, 0xb6,
    0xfb, 0xe1, 0xab, 0x45, 0x19, 0xf4, 0xff, 0x19, 0x05, 0x88, 0xcf, 0x3b, 0x1e, 0x4b, 0x36, 0x4b,
];
const AGENT_LIBRARY_SHA256: [u8; 32] = [
    0xba, 0x38, 0x37, 0xe2, 0x62, 0xb6, 0x84, 0x06, 0x89, 0x25, 0x6a, 0x67, 0x64, 0xa6, 0x4d, 0x50,
    0xc7, 0xdf, 0x84, 0x89, 0x36, 0x46, 0xbd, 0xb9, 0x24, 0xb3, 0x24, 0x1a, 0xa8, 0x35, 0x9b, 0x98,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapturedOutcome {
    Exited(i32),
    TimedOut,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedRun {
    pub outcome: CapturedOutcome,
    pub warnings: Vec<String>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct NvxRunner;

impl NvxRunner {
    pub fn new() -> Self {
        Self
    }

    pub fn run_captured(
        &mut self,
        request: &ExecutionRequest,
        logger: &mut Logger,
    ) -> Result<CapturedRun, MxcError> {
        reject_deferred_policy(request)?;

        let client = create_client(&ProcessEnvironment)?;
        client.probe().map_err(map_nvx_error)?;

        let provisioned = client
            .provision(&ProvisionRequest::new())
            .map_err(map_nvx_error)?;
        let sandbox_id = provisioned.sandbox_id;
        let primary = (|| {
            client.start(&sandbox_id).map_err(map_nvx_error)?;
            let execution = client
                .exec(&sandbox_id, &exec_request(request))
                .map_err(map_nvx_error)?;
            execution.wait_with_output().map_err(map_nvx_error)
        })();

        let stop_error = client.stop(&sandbox_id).err().map(map_nvx_error);
        let stop_error = match stop_error {
            Some(error) if primary.is_err() && error.code == MxcErrorCode::AlreadyStopped => None,
            other => other,
        };
        let cleanup_errors: Vec<MxcError> = [
            stop_error,
            client.deprovision(&sandbox_id).err().map(map_nvx_error),
        ]
        .into_iter()
        .flatten()
        .collect();

        let output = match primary {
            Ok(output) if cleanup_errors.is_empty() => output,
            Ok(_) => {
                return Err(MxcError::backend_error(format!(
                    "NVX cleanup failed after workload completion: {}",
                    cleanup_errors
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("; ")
                )));
            }
            Err(mut error) => {
                for cleanup in cleanup_errors {
                    let warning = format!("NVX cleanup failed: {cleanup}");
                    logger.warning_line(&warning);
                    error.message.push_str("; cleanup failure: ");
                    error.message.push_str(&cleanup.to_string());
                }
                return Err(error);
            }
        };

        let outcome = match output.outcome {
            ExecOutcome::Exited(code) => CapturedOutcome::Exited(code),
            ExecOutcome::TimedOut => CapturedOutcome::TimedOut,
            ExecOutcome::Signaled(signal) => {
                CapturedOutcome::Exited(128_i32.saturating_add(signal))
            }
            other => {
                return Err(MxcError::backend_error(format!(
                    "NVX workload did not complete normally: {other}"
                )));
            }
        };

        Ok(CapturedRun {
            outcome,
            warnings: Vec::new(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

impl ScriptRunner for NvxRunner {
    fn validate_runner(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        reject_deferred_policy(request).map_err(|error| ScriptResponse::rejected(&error.message))
    }

    fn execute(&mut self, request: &ExecutionRequest, logger: &mut Logger) -> ScriptResponse {
        match self.run_captured(request, logger) {
            Ok(result) => captured_to_script_response(result),
            Err(error) if error.code == MxcErrorCode::PolicyValidation => {
                ScriptResponse::rejected(&error.message)
            }
            Err(error) => ScriptResponse {
                exit_code: -1,
                error_message: error.to_string(),
                failure_phase: if error.code == MxcErrorCode::BackendUnavailable {
                    FailurePhase::BackendUnavailable
                } else {
                    FailurePhase::PostLaunchFailed
                },
                ..Default::default()
            },
        }
    }
}

trait Environment {
    fn value(&self, name: &str) -> Option<OsString>;
}

struct ProcessEnvironment;

impl Environment for ProcessEnvironment {
    fn value(&self, name: &str) -> Option<OsString> {
        std::env::var_os(name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeConfig {
    bundle_dir: PathBuf,
    state_root: PathBuf,
}

fn runtime_config(environment: &impl Environment) -> Result<RuntimeConfig, MxcError> {
    let bundle_dir = required_directory(environment, BUNDLE_DIR_ENV)?;
    for relative in [PathBuf::from("SOURCE-MANIFEST.json"), agent_library_path()] {
        let path = bundle_dir.join(&relative);
        if !path.is_file() {
            return Err(MxcError::backend_unavailable(format!(
                "{BUNDLE_DIR_ENV} is missing required file {}",
                relative.display()
            )));
        }
    }

    let state_root = match non_empty_value(environment, STATE_ROOT_ENV) {
        Some(path) => absolute_path(PathBuf::from(path), STATE_ROOT_ENV)?,
        None => {
            let local_app_data =
                non_empty_value(environment, LOCAL_APP_DATA_ENV).ok_or_else(|| {
                    MxcError::backend_unavailable(format!(
                        "{STATE_ROOT_ENV} is unset and {LOCAL_APP_DATA_ENV} is unavailable"
                    ))
                })?;
            absolute_path(
                PathBuf::from(local_app_data)
                    .join("Microsoft")
                    .join("MXC")
                    .join("NVX"),
                LOCAL_APP_DATA_ENV,
            )?
        }
    };
    std::fs::create_dir_all(&state_root).map_err(|error| {
        MxcError::backend_unavailable(format!(
            "could not create NVX state root {}: {error}",
            state_root.display()
        ))
    })?;

    Ok(RuntimeConfig {
        bundle_dir,
        state_root,
    })
}

fn required_directory(environment: &impl Environment, name: &str) -> Result<PathBuf, MxcError> {
    let value = non_empty_value(environment, name).ok_or_else(|| {
        MxcError::backend_unavailable(format!(
            "{name} must name the manually extracted signed NVX bundle"
        ))
    })?;
    let path = absolute_path(PathBuf::from(value), name)?;
    if !path.is_dir() {
        return Err(MxcError::backend_unavailable(format!(
            "{name} does not name a directory: {}",
            path.display()
        )));
    }
    Ok(path)
}

fn non_empty_value(environment: &impl Environment, name: &str) -> Option<OsString> {
    environment.value(name).filter(|value| !value.is_empty())
}

fn absolute_path(path: PathBuf, name: &str) -> Result<PathBuf, MxcError> {
    std::path::absolute(path).map_err(|error| {
        MxcError::backend_unavailable(format!("could not resolve {name}: {error}"))
    })
}

fn agent_library_path() -> PathBuf {
    PathBuf::from("bin").join("aci_edge_agent.dll")
}

fn create_client(environment: &impl Environment) -> Result<AciEdgeSandbox, MxcError> {
    let runtime = runtime_config(environment)?;
    let source = RuntimeSource::Bundle(BundleSource {
        path: runtime.bundle_dir.clone(),
        manifest_sha256: RUNTIME_MANIFEST_SHA256,
    });
    let setup = SetupConfig::new(runtime.state_root, source)
        .with_cpu_profile(CpuProfile::Auto)
        .with_defaults(
            SandboxDefaults::default()
                .with_image(ImageSource::Reference(TEST_IMAGE_REFERENCE.to_owned())),
        )
        .with_images(ImageSettings::default().with_references(ReferenceSettings::default()));
    let library = runtime.bundle_dir.join(agent_library_path());
    let backend = Arc::new(
        AgentBackend::new(AgentConfig::new(setup, library, AGENT_LIBRARY_SHA256))
            .map_err(map_nvx_error)?,
    );
    Ok(AciEdgeSandbox::from_shared(backend))
}

fn captured_to_script_response(result: CapturedRun) -> ScriptResponse {
    let standard_out = String::from_utf8_lossy(&result.stdout).into_owned();
    let standard_err = String::from_utf8_lossy(&result.stderr).into_owned();
    match result.outcome {
        CapturedOutcome::Exited(exit_code) => ScriptResponse {
            exit_code,
            standard_out,
            standard_err,
            ..Default::default()
        },
        CapturedOutcome::TimedOut => ScriptResponse {
            exit_code: -1,
            standard_out,
            standard_err,
            error_message: "NVX workload timed out".to_string(),
            failure_phase: FailurePhase::Timeout,
            ..Default::default()
        },
    }
}

fn reject_deferred_policy(request: &ExecutionRequest) -> Result<(), MxcError> {
    if !request.lifecycle.destroy_on_exit {
        return Err(MxcError::policy_validation(
            "the initial NVX integration requires lifecycle.destroyOnExit=true",
        ));
    }
    if request.lifecycle.preserve_policy {
        return Err(MxcError::policy_validation(
            "the initial NVX integration requires lifecycle.preservePolicy=false",
        ));
    }

    let policy = &request.policy;
    let filesystem_supplied = !policy.readonly_paths.is_empty()
        || !policy.readwrite_paths.is_empty()
        || !policy.enumerate_paths.is_empty()
        || !policy.denied_paths.is_empty();
    let network_supplied = policy.network_specified
        || policy.runtime_network_proxy_specified
        || policy.network_proxy.is_enabled();

    if filesystem_supplied
        || network_supplied
        || policy.ui_specified
        || policy.capture_denials.is_some()
    {
        return Err(MxcError::policy_validation(
            "the initial NVX integration supports process settings only; filesystem, network, UI, and capture-denials policies are not yet supported",
        ));
    }
    Ok(())
}

fn exec_request(request: &ExecutionRequest) -> ExecRequest {
    let mut exec = ExecRequest::command_line(request.script_code.clone());
    if request.script_timeout != 0 {
        exec = exec.with_timeout(Duration::from_millis(u64::from(request.script_timeout)));
    }
    if !request.working_directory.is_empty() {
        exec = exec.with_cwd(request.working_directory.clone());
    }
    if let Some(environment) = &request.env {
        exec = exec.with_envs(environment.clone());
    }
    exec = exec.with_inherit_default_env(request.inherit_default_env);
    exec
}

fn map_nvx_error(error: aci_edge_sandboxes::Error) -> MxcError {
    let code = match error.code() {
        aci_edge_sandboxes::ErrorCode::MalformedRequest => MxcErrorCode::MalformedRequest,
        aci_edge_sandboxes::ErrorCode::MalformedId => MxcErrorCode::MalformedId,
        aci_edge_sandboxes::ErrorCode::StaleId => MxcErrorCode::StaleId,
        aci_edge_sandboxes::ErrorCode::NotStarted => MxcErrorCode::NotStarted,
        aci_edge_sandboxes::ErrorCode::AlreadyStarted => MxcErrorCode::AlreadyStarted,
        aci_edge_sandboxes::ErrorCode::AlreadyStopped => MxcErrorCode::AlreadyStopped,
        aci_edge_sandboxes::ErrorCode::PolicyValidation => MxcErrorCode::PolicyValidation,
        aci_edge_sandboxes::ErrorCode::BackendUnavailable => MxcErrorCode::BackendUnavailable,
        aci_edge_sandboxes::ErrorCode::Unsupported
        | aci_edge_sandboxes::ErrorCode::BackendError => MxcErrorCode::BackendError,
        _ => MxcErrorCode::BackendError,
    };
    MxcError::new(code, error.message())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use tempfile::TempDir;

    use super::*;

    #[derive(Default)]
    struct TestEnvironment {
        values: HashMap<&'static str, OsString>,
    }

    impl TestEnvironment {
        fn with(mut self, name: &'static str, value: impl Into<OsString>) -> Self {
            self.values.insert(name, value.into());
            self
        }
    }

    impl Environment for TestEnvironment {
        fn value(&self, name: &str) -> Option<OsString> {
            self.values.get(name).cloned()
        }
    }

    fn request() -> ExecutionRequest {
        ExecutionRequest {
            script_code: "printf 'ok\\n'".to_string(),
            ..Default::default()
        }
    }

    fn assert_process_only_rejection(request: &ExecutionRequest) {
        let error = reject_deferred_policy(request).unwrap_err();
        assert_eq!(error.code, MxcErrorCode::PolicyValidation);
        assert_eq!(
            error.message,
            "the initial NVX integration supports process settings only; filesystem, network, UI, and capture-denials policies are not yet supported"
        );
    }

    fn bundle() -> TempDir {
        let directory = TempDir::new().unwrap();
        std::fs::write(directory.path().join("SOURCE-MANIFEST.json"), b"{}").unwrap();
        std::fs::create_dir(directory.path().join("bin")).unwrap();
        std::fs::write(directory.path().join(agent_library_path()), b"dll").unwrap();
        directory
    }

    #[test]
    fn runtime_config_requires_bundle_environment() {
        let error = runtime_config(&TestEnvironment::default()).unwrap_err();
        assert_eq!(error.code, MxcErrorCode::BackendUnavailable);
        assert!(error.message.contains(BUNDLE_DIR_ENV));
    }

    #[test]
    fn runtime_config_rejects_bundle_file() {
        let directory = TempDir::new().unwrap();
        let file = directory.path().join("bundle.zip");
        std::fs::write(&file, b"zip").unwrap();
        let error = runtime_config(
            &TestEnvironment::default()
                .with(BUNDLE_DIR_ENV, file.as_os_str())
                .with(LOCAL_APP_DATA_ENV, directory.path().as_os_str()),
        )
        .unwrap_err();
        assert_eq!(error.code, MxcErrorCode::BackendUnavailable);
        assert!(error.message.contains("directory"));
    }

    #[test]
    fn runtime_config_uses_default_state_root() {
        let bundle = bundle();
        let local = TempDir::new().unwrap();
        let config = runtime_config(
            &TestEnvironment::default()
                .with(BUNDLE_DIR_ENV, bundle.path().as_os_str())
                .with(LOCAL_APP_DATA_ENV, local.path().as_os_str()),
        )
        .unwrap();
        assert_eq!(
            config.state_root,
            local.path().join("Microsoft").join("MXC").join("NVX")
        );
        assert!(config.state_root.is_dir());
    }

    #[test]
    fn rejects_destroy_on_exit_false() {
        let mut request = request();
        request.lifecycle.destroy_on_exit = false;
        let error = reject_deferred_policy(&request).unwrap_err();
        assert_eq!(error.code, MxcErrorCode::PolicyValidation);
        assert!(error.message.contains("destroyOnExit=true"));
    }

    #[test]
    fn rejects_preserve_policy_true() {
        let mut request = request();
        request.lifecycle.preserve_policy = true;
        let error = reject_deferred_policy(&request).unwrap_err();
        assert_eq!(error.code, MxcErrorCode::PolicyValidation);
        assert!(error.message.contains("preservePolicy=false"));
    }

    #[test]
    fn rejects_filesystem_network_and_ui_policy() {
        let mut filesystem = request();
        filesystem
            .policy
            .readonly_paths
            .push(r"C:\input".to_string());
        assert_process_only_rejection(&filesystem);

        let mut network = request();
        network.policy.network_specified = true;
        assert_process_only_rejection(&network);

        let mut ui = request();
        ui.policy.ui_specified = true;
        assert_process_only_rejection(&ui);

        let mut capture_denials = request();
        capture_denials.policy.capture_denials =
            Some(crate::mxc_common::models::CaptureDenialsConfig::default());
        assert_process_only_rejection(&capture_denials);
    }

    #[test]
    fn accepts_process_only_defaults() {
        assert!(reject_deferred_policy(&request()).is_ok());
    }

    #[test]
    fn executor_adapter_preserves_exit_and_output() {
        let response = captured_to_script_response(CapturedRun {
            outcome: CapturedOutcome::Exited(42),
            warnings: Vec::new(),
            stdout: b"out".to_vec(),
            stderr: b"err".to_vec(),
        });
        assert_eq!(response.exit_code, 42);
        assert_eq!(response.standard_out, "out");
        assert_eq!(response.standard_err, "err");
        assert!(response.error_message.is_empty());
    }

    #[test]
    fn executor_adapter_marks_timeout() {
        let response = captured_to_script_response(CapturedRun {
            outcome: CapturedOutcome::TimedOut,
            warnings: Vec::new(),
            stdout: Vec::new(),
            stderr: Vec::new(),
        });
        assert_eq!(response.exit_code, -1);
        assert_eq!(response.failure_phase, FailurePhase::Timeout);
    }
}
