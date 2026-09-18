// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::config_parser::load_state_aware_request_from_json_with_options;
use crate::logger::{Logger, Mode};
use crate::mxc_error::MxcErrorCode;
use crate::state_aware_backend::{
    null_pipe_handle, DeprovisionResult, ExecHandle, ExecOutcome, ExecStdio, ProvisionResult,
    StartResult, StopResult,
};
use crate::state_aware_dispatch::{
    dispatch_state_aware, dispatch_state_aware_exec, DispatchOutcome,
};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::marker::PhantomData;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Config {
    Absent,
    Unit,
    Isolation(Option<String>),
    Wslc(Option<String>, Option<String>),
}

trait Case: Sized {
    type ProvisionConfig;
    const BACKEND: &'static str;
    const PREFIX: &'static str;
    fn observe(config: Option<&Self::ProvisionConfig>) -> Config;
    fn bind(
        parsed: ParsedStateAwareRequest,
    ) -> Result<BoundStateAwareRequest<Recording<Self>>, MxcError>;
}

struct Isolation;
struct WindowsSandbox;
struct Wslc;

impl Case for Isolation {
    type ProvisionConfig = IsolationSessionProvisionConfig;
    const BACKEND: &'static str = "isolation_session";
    const PREFIX: &'static str = "iso";
    fn observe(config: Option<&Self::ProvisionConfig>) -> Config {
        config.map_or(Config::Absent, |config| {
            Config::Isolation(config.app_id.clone())
        })
    }
    fn bind(
        parsed: ParsedStateAwareRequest,
    ) -> Result<BoundStateAwareRequest<Recording<Self>>, MxcError> {
        bind_isolation_session(parsed)
    }
}

impl Case for WindowsSandbox {
    type ProvisionConfig = ();
    const BACKEND: &'static str = "windows_sandbox";
    const PREFIX: &'static str = "wsb";
    fn observe(config: Option<&Self::ProvisionConfig>) -> Config {
        config.map_or(Config::Absent, |_| Config::Unit)
    }
    fn bind(
        parsed: ParsedStateAwareRequest,
    ) -> Result<BoundStateAwareRequest<Recording<Self>>, MxcError> {
        bind_windows_sandbox(parsed)
    }
}

impl Case for Wslc {
    type ProvisionConfig = WslcProvisionConfig;
    const BACKEND: &'static str = "wslc";
    const PREFIX: &'static str = "wslc";
    fn observe(config: Option<&Self::ProvisionConfig>) -> Config {
        config.map_or(Config::Absent, |config| {
            Config::Wslc(config.image.clone(), config.image_tar_path.clone())
        })
    }
    fn bind(
        parsed: ParsedStateAwareRequest,
    ) -> Result<BoundStateAwareRequest<Recording<Self>>, MxcError> {
        bind_wslc(parsed)
    }
}

#[derive(Debug, PartialEq)]
struct Event {
    validation: bool,
    phase: Phase,
    id: Option<String>,
    common: Value,
    config: Config,
    stdio: Option<ExecStdio>,
}

fn common_snapshot(request: &ExecutionRequest) -> Value {
    let proxy = request.policy.network_proxy.address.as_ref();
    json!({
        "serialized": request,
        "networkSpecified": request.policy.network_specified,
        "networkModeSpecified": request.policy.network_mode_specified,
        "runtimeProxySpecified": request.policy.runtime_network_proxy_specified,
        "uiSpecified": request.policy.ui_specified,
        "proxyAddress": proxy.map(|address| &address.address),
        "proxyPort": proxy.map(|address| address.port),
        "proxyUrl": proxy.and_then(|address| address.original_url.as_ref()),
        "builtinProxy": request.policy.network_proxy.builtin_test_server,
        "telemetryKind": request.telemetry.as_ref().and_then(|value| value.requested_sandbox_kind),
    })
}

struct Recording<C> {
    events: RefCell<Vec<Event>>,
    reject_validation: bool,
    case: PhantomData<C>,
}

impl<C> Recording<C> {
    fn new(reject_validation: bool) -> Self {
        Self {
            events: RefCell::new(Vec::new()),
            reject_validation,
            case: PhantomData,
        }
    }

    fn observe(
        &self,
        validation: bool,
        phase: Phase,
        id: Option<&str>,
        request: &ExecutionRequest,
        config: Config,
        stdio: Option<ExecStdio>,
    ) -> Result<(), MxcError> {
        self.events.borrow_mut().push(Event {
            validation,
            phase,
            id: id.map(str::to_owned),
            common: common_snapshot(request),
            config,
            stdio,
        });
        if validation && self.reject_validation {
            return Err(MxcError::policy_validation("recorded validation refusal"));
        }
        Ok(())
    }
}

impl<C: Case> StatefulSandboxBackend for Recording<C> {
    const ID_PREFIX: &'static str = C::PREFIX;
    const BACKEND_KEY: &'static str = C::BACKEND;
    type ProvisionConfig = C::ProvisionConfig;
    type StartConfig = ();
    type ExecConfig = ();
    type StopConfig = ();
    type DeprovisionConfig = ();
    type ProvisionMetadata = ();
    type StartMetadata = ();
    type StopMetadata = ();
    type DeprovisionMetadata = ();

    fn validate_provision(
        &self,
        request: &ExecutionRequest,
        config: Option<&Self::ProvisionConfig>,
    ) -> Result<(), MxcError> {
        self.observe(
            true,
            Phase::Provision,
            None,
            request,
            C::observe(config),
            None,
        )
    }
    fn validate_start(
        &self,
        id: &str,
        request: &ExecutionRequest,
        config: Option<&()>,
    ) -> Result<(), MxcError> {
        self.observe(true, Phase::Start, Some(id), request, unit(config), None)
    }
    fn validate_exec(
        &self,
        id: &str,
        request: &ExecutionRequest,
        config: Option<&()>,
    ) -> Result<(), MxcError> {
        self.observe(true, Phase::Exec, Some(id), request, unit(config), None)
    }
    fn validate_stop(
        &self,
        id: &str,
        request: &ExecutionRequest,
        config: Option<&()>,
    ) -> Result<(), MxcError> {
        self.observe(true, Phase::Stop, Some(id), request, unit(config), None)
    }
    fn validate_deprovision(
        &self,
        id: &str,
        request: &ExecutionRequest,
        config: Option<&()>,
    ) -> Result<(), MxcError> {
        self.observe(
            true,
            Phase::Deprovision,
            Some(id),
            request,
            unit(config),
            None,
        )
    }
    fn provision(
        &mut self,
        request: &ExecutionRequest,
        config: Option<Self::ProvisionConfig>,
    ) -> Result<ProvisionResult<()>, MxcError> {
        self.observe(
            false,
            Phase::Provision,
            None,
            request,
            C::observe(config.as_ref()),
            None,
        )?;
        Ok(ProvisionResult {
            sandbox_id: format!("{}:created", C::PREFIX),
            metadata: None,
        })
    }
    fn start(
        &mut self,
        id: &str,
        request: &ExecutionRequest,
        config: Option<()>,
    ) -> Result<StartResult<()>, MxcError> {
        self.observe(
            false,
            Phase::Start,
            Some(id),
            request,
            unit(config.as_ref()),
            None,
        )?;
        Ok(StartResult { metadata: None })
    }
    fn exec(
        &mut self,
        id: &str,
        request: &ExecutionRequest,
        config: Option<()>,
        stdio: ExecStdio,
    ) -> Result<ExecHandle, MxcError> {
        self.observe(
            false,
            Phase::Exec,
            Some(id),
            request,
            unit(config.as_ref()),
            Some(stdio),
        )?;
        Ok(ExecHandle {
            stdin: null_pipe_handle(),
            stdout: null_pipe_handle(),
            stderr: null_pipe_handle(),
            waiter: Box::new(|| Ok(ExecOutcome::Exited(7))),
            terminator: Box::new(|| Ok(())),
            stdin_closer: None,
        })
    }
    fn stop(
        &mut self,
        id: &str,
        request: &ExecutionRequest,
        config: Option<()>,
    ) -> Result<StopResult<()>, MxcError> {
        self.observe(
            false,
            Phase::Stop,
            Some(id),
            request,
            unit(config.as_ref()),
            None,
        )?;
        Ok(StopResult { metadata: None })
    }
    fn deprovision(
        &mut self,
        id: &str,
        request: &ExecutionRequest,
        config: Option<()>,
    ) -> Result<DeprovisionResult<()>, MxcError> {
        self.observe(
            false,
            Phase::Deprovision,
            Some(id),
            request,
            unit(config.as_ref()),
            None,
        )?;
        Ok(DeprovisionResult { metadata: None })
    }
}

fn unit(config: Option<&()>) -> Config {
    config.map_or(Config::Absent, |_| Config::Unit)
}

fn input<C: Case>(phase: Phase) -> Value {
    let mut value = json!({
        "version": "0.9.0-alpha",
        "telemetry": {"enabled": false},
    });
    if phase == Phase::Provision {
        value["containment"] = json!(C::BACKEND);
        if C::BACKEND == "isolation_session" {
            value["network"] = json!({
                "egress": {"default": "allow"},
                "ingress": {"default": "allow", "hostLoopback": "allow"}
            });
        }
    } else if phase == Phase::Exec {
        value["process"] = json!({
            "commandLine": "echo typed",
            "env": ["TYPED_BINDING=preserved"],
            "timeout": 7,
        });
    }
    value
}

fn parse_for_phase(input: &Value, phase: Phase) -> ParsedStateAwareRequest {
    let sandbox_id = (phase != Phase::Provision).then(|| {
        let prefix = match input
            .get("_testBackend")
            .and_then(Value::as_str)
            .unwrap_or_default()
        {
            "isolation_session" => "iso",
            "windows_sandbox" => "wsb",
            "wslc" => "wslc",
            _ => panic!("missing test backend"),
        };
        format!("{prefix}:test-id")
    });
    let mut document = input.clone();
    document.as_object_mut().unwrap().remove("_testBackend");
    load_state_aware_request_from_json_with_options(
        &document.to_string(),
        &mut Logger::new(Mode::Buffer),
        phase,
        sandbox_id.as_deref(),
        &[],
    )
    .unwrap()
}

fn assert_dispatch<C: Case>(input: &Value, phase: Phase, expected_config: Config) {
    for (dry_run, reject_validation) in [(false, false), (true, false), (false, true)] {
        let parsed = parse_for_phase(input, phase);
        let phase = parsed.phase();
        let id = parsed.sandbox_id().map(str::to_owned);
        let common = common_snapshot(parsed.request());
        let bound = C::bind(parsed).unwrap();
        assert_eq!(bound.phase(), phase);
        assert_eq!(bound.sandbox_id(), id.as_deref());
        assert_eq!(common_snapshot(bound.request()), common);
        let mut backend = Recording::<C>::new(reject_validation);
        let outcome = dispatch_state_aware(&mut backend, bound, dry_run);
        if reject_validation {
            let error = outcome.unwrap_err();
            assert_eq!(error.code, MxcErrorCode::PolicyValidation);
            assert_eq!(error.message, "recorded validation refusal");
        } else if phase == Phase::Exec && !dry_run {
            assert!(matches!(
                outcome.unwrap(),
                DispatchOutcome::ExecCompleted { exit_code: 7 }
            ));
        } else {
            assert!(matches!(outcome.unwrap(), DispatchOutcome::Envelope(_)));
        }
        let events = backend.events.into_inner();
        assert_eq!(
            events.len(),
            if dry_run || reject_validation { 1 } else { 2 }
        );
        for (index, event) in events.iter().enumerate() {
            assert_eq!(event.validation, index == 0);
            assert_eq!(event.phase, phase);
            assert_eq!(event.id, id);
            assert_eq!(event.common, common);
            assert_eq!(event.config, expected_config);
            assert_eq!(
                event.stdio,
                (index == 1 && phase == Phase::Exec).then_some(ExecStdio::Relayed)
            );
        }
    }
}

fn lifecycle_matrix<C: Case>() {
    for phase in [
        Phase::Provision,
        Phase::Start,
        Phase::Exec,
        Phase::Stop,
        Phase::Deprovision,
    ] {
        let mut value = input::<C>(phase);
        value["_testBackend"] = json!(C::BACKEND);
        assert_dispatch::<C>(&value, phase, Config::Absent);
        value["experimental"] = json!({});
        assert_dispatch::<C>(&value, phase, Config::Absent);
    }
}

#[test]
fn every_backend_and_phase_preserves_validation_execution_and_dry_run_order() {
    lifecycle_matrix::<Isolation>();
    lifecycle_matrix::<WindowsSandbox>();
    lifecycle_matrix::<Wslc>();
}

#[test]
fn non_provision_operations_reject_backend_experimental_config() {
    for phase in [Phase::Start, Phase::Exec, Phase::Stop, Phase::Deprovision] {
        let mut value = input::<Isolation>(phase);
        value["experimental"] = json!({"isolation_session": {}});
        let error = load_state_aware_request_from_json_with_options(
            &value.to_string(),
            &mut Logger::new(Mode::Buffer),
            phase,
            Some("iso:test-id"),
            &[],
        )
        .unwrap_err();
        let message = format!("{error:?}");
        assert!(
            message.contains("experimental.isolation_session is not accepted"),
            "{message}"
        );
    }
}

#[test]
fn isolation_provision_preserves_each_backend_observable_configuration() {
    let mut value = input::<Isolation>(Phase::Provision);
    value["experimental"] = json!({"isolation_session": {}});
    assert_dispatch::<Isolation>(&value, Phase::Provision, Config::Isolation(None));
    for (config, expected) in [
        (json!({}), Config::Isolation(None)),
        (json!({"appId": ""}), Config::Isolation(Some(String::new()))),
        (
            json!({"appId": "PFN:example"}),
            Config::Isolation(Some("PFN:example".into())),
        ),
    ] {
        value["experimental"] = json!({"isolation_session": config});
        assert_dispatch::<Isolation>(&value, Phase::Provision, expected);
    }
}

#[test]
fn wslc_provision_preserves_each_backend_observable_configuration() {
    let mut value = input::<Wslc>(Phase::Provision);
    value["experimental"] = json!({"wslc": {}});
    assert_dispatch::<Wslc>(&value, Phase::Provision, Config::Wslc(None, None));
    for (config, expected) in [
        (json!({}), Config::Wslc(None, None)),
        (
            json!({"image": "custom"}),
            Config::Wslc(Some("custom".into()), None),
        ),
        (
            json!({"imageTarPath": "image.tar"}),
            Config::Wslc(None, Some("image.tar".into())),
        ),
        (
            json!({"image": "custom", "imageTarPath": "image.tar"}),
            Config::Wslc(Some("custom".into()), Some("image.tar".into())),
        ),
        (
            json!({"image": "", "imageTarPath": ""}),
            Config::Wslc(Some(String::new()), Some(String::new())),
        ),
    ] {
        value["experimental"] = json!({"wslc": config});
        assert_dispatch::<Wslc>(&value, Phase::Provision, expected);
    }
}

fn streaming_matrix<C: Case>() {
    for reject_validation in [false, true] {
        let mut value = input::<C>(Phase::Exec);
        value["_testBackend"] = json!(C::BACKEND);
        let parsed = parse_for_phase(&value, Phase::Exec);
        let common = common_snapshot(parsed.request());
        let mut backend = Recording::<C>::new(reject_validation);
        let result = dispatch_state_aware_exec(&mut backend, C::bind(parsed).unwrap());
        if reject_validation {
            assert_eq!(result.unwrap_err().code, MxcErrorCode::PolicyValidation);
        } else {
            assert_eq!((result.unwrap().waiter)().unwrap(), ExecOutcome::Exited(7));
        }
        let events = backend.events.into_inner();
        assert_eq!(events.len(), if reject_validation { 1 } else { 2 });
        for (index, event) in events.iter().enumerate() {
            assert_eq!(event.phase, Phase::Exec);
            assert_eq!(
                event.id.as_deref(),
                Some(format!("{}:test-id", C::PREFIX).as_str())
            );
            assert_eq!(event.common, common);
            assert_eq!(event.validation, index == 0);
            assert_eq!(event.config, Config::Absent);
            assert_eq!(event.stdio, (index == 1).then_some(ExecStdio::Piped));
        }
    }
    for phase in [
        Phase::Provision,
        Phase::Start,
        Phase::Stop,
        Phase::Deprovision,
    ] {
        let mut backend = Recording::<C>::new(false);
        let error = {
            let mut value = input::<C>(phase);
            value["_testBackend"] = json!(C::BACKEND);
            dispatch_state_aware_exec(
                &mut backend,
                C::bind(parse_for_phase(&value, phase)).unwrap(),
            )
        }
        .unwrap_err();
        assert_eq!(error.code, MxcErrorCode::MalformedRequest);
        assert_eq!(
            error.message,
            format!("streaming exec requires the exec phase, got {phase}")
        );
        assert!(backend.events.borrow().is_empty());
    }
}

#[test]
fn streaming_uses_the_same_binding_and_preserves_its_phase_and_validation_gates() {
    streaming_matrix::<Isolation>();
    streaming_matrix::<WindowsSandbox>();
    streaming_matrix::<Wslc>();
}

fn mismatch<C: Case, Other: Case>() {
    for phase in [
        Phase::Provision,
        Phase::Start,
        Phase::Exec,
        Phase::Stop,
        Phase::Deprovision,
    ] {
        let mut value = input::<Other>(phase);
        value["_testBackend"] = json!(Other::BACKEND);
        let error = C::bind(parse_for_phase(&value, phase)).unwrap_err();
        assert_eq!(error.code, MxcErrorCode::MalformedRequest);
        assert!(error.message.contains("incompatible"));
    }
}

#[test]
fn incompatible_backend_operations_never_bind_as_absent_configuration() {
    mismatch::<Isolation, WindowsSandbox>();
    mismatch::<Isolation, Wslc>();
    mismatch::<WindowsSandbox, Isolation>();
    mismatch::<WindowsSandbox, Wslc>();
    mismatch::<Wslc, Isolation>();
    mismatch::<Wslc, WindowsSandbox>();
}
