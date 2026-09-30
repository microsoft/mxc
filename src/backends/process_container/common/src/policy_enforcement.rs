// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Bounded, pre-launch CPSE negotiation. The OS remains the policy authority.

use std::collections::{hash_map::DefaultHasher, HashSet};
use std::hash::{Hash, Hasher};

use learning_mode_windows::LearningModeError;
use serde::Serialize;
use windows::Win32::Foundation::E_NOTIMPL;
use windows::Win32::System::JobObjects::{
    JOB_OBJECT_UILIMIT_DESKTOP, JOB_OBJECT_UILIMIT_DISPLAYSETTINGS, JOB_OBJECT_UILIMIT_EXITWINDOWS,
    JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES, JOB_OBJECT_UILIMIT_READCLIPBOARD,
    JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
};
use windows::Win32::System::SystemServices::JOB_OBJECT_UILIMIT_IME;
use windows_core::HRESULT;
use wxc_common::filesystem_canonical::{canonicalize_allowing_absent_tail, PathCanonical};
use wxc_common::models::{
    CaptureDenialsMode, ClipboardPolicy, ContainerPolicy, ExecutionRequest, FailurePhase,
    NetworkAction, NetworkPolicy, ScriptResponse,
};
use wxc_common::mxc_error::{ApiFailure, MxcError};
use wxc_common::policy_enforcement::{
    NativePolicyDetail, NativePolicyResult, PolicyChange, PolicyEnforcementAttempt,
    PolicyEnforcementAvailability, PolicyEnforcementMode, PolicyEnforcementReport,
    PolicyEnforcementTermination, DEFAULT_POLICY_ATTEMPTS,
};
use wxc_common::policy_identity::policy_hash;

use crate::base_container_helpers::build_psec_v1_security_environment_spec;
use crate::base_container_runner::BaseContainerRunner;
use crate::job_object::{ALL_DEFINED_UI_LIMITS, JOB_OBJECT_UILIMIT_INJECTION};
use crate::secenv::{
    PolicyCreateOutcome, ProcessSecurityEnvironment, SecurityEnvironmentApi,
    SecurityEnvironmentVersion, PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE,
};
use crate::secenv_policy::codes::{
    action, class, outcome, reason, resource as resource_kind, value,
};
use crate::secenv_policy::{
    BUFFER_TOO_SMALL, DETAILS_UNREPRESENTABLE, HAS_ACTIONABLE_DETAILS, KNOWN_FLAGS,
    RESOURCE_COMPLETE, RESOURCE_UNAVAILABLE,
};

const API: &str = "CreateProcessSecurityEnvironment2";
// Native resources are independently bounded by V1 and at most 64 attempts.
const MAX_CHANGE_HISTORY_BYTES: usize = 1024 * 1024;

pub(crate) fn ignored_report(request: &ExecutionRequest) -> Option<PolicyEnforcementReport> {
    request.policy.policy_enforcement.as_ref().map(|settings| {
        PolicyEnforcementReport::new(
            settings.mode.unwrap_or_default(),
            PolicyEnforcementAvailability::NotApplicable,
            policy_hash(request),
        )
    })
}

pub(crate) fn teardown_warnings(
    report: Option<&PolicyEnforcementReport>,
    result: &Option<Result<(), String>>,
) -> Vec<String> {
    match (report, result) {
        (Some(_), Some(Err(message))) => vec![message.clone()],
        _ => Vec::new(),
    }
}

pub(crate) fn log_effective_policy(
    request: &ExecutionRequest,
    logger: &mut wxc_common::logger::Logger,
) {
    if !request.policy_mutation_requested() {
        return;
    }
    let telemetry = wxc_common::telemetry::is_active();
    if !telemetry && !logger.has_diagnostic_sink() {
        return;
    }
    let hash = policy_hash(request);
    if telemetry {
        let identity = if request.container_id.is_empty() {
            "CLI"
        } else {
            &request.container_id
        };
        wxc_common::telemetry::log_policy_hash(
            &wxc_common::policy_identity::redact_identity(identity),
            &hash,
            request.source_contract_version(),
        );
    }
    logger.log_audit_event(
        &wxc_common::audit::AuditEvent::new(wxc_common::audit::AuditEventName::PolicyHash)
            .str("backend", request.containment.wire_name())
            .str("policy_hash", &hash)
            .str("policy_stage", "effective")
            .str("config_schema_version", request.source_contract_version()),
    );
}

#[derive(Debug)]
pub(crate) struct NegotiatedEnvironment {
    pub environment: ProcessSecurityEnvironment,
    pub report: Option<PolicyEnforcementReport>,
}

trait CreationApi {
    fn reports_policy(&self) -> Result<bool, LearningModeError>;
    fn legacy(
        &mut self,
        specification: &[u8],
    ) -> Result<ProcessSecurityEnvironment, LearningModeError>;
    fn reported(&mut self, specification: &[u8]) -> Result<PolicyCreateOutcome, LearningModeError>;
}

impl CreationApi for SecurityEnvironmentApi {
    fn reports_policy(&self) -> Result<bool, LearningModeError> {
        self.policy_results_available()
    }

    fn legacy(
        &mut self,
        specification: &[u8],
    ) -> Result<ProcessSecurityEnvironment, LearningModeError> {
        self.create(specification, PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE)
    }

    fn reported(&mut self, specification: &[u8]) -> Result<PolicyCreateOutcome, LearningModeError> {
        self.create_with_policy_result(specification, PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE)
    }
}

pub(crate) fn create_environment(
    request: &mut ExecutionRequest,
    version: SecurityEnvironmentVersion,
    supports_ingress: bool,
) -> Result<NegotiatedEnvironment, ScriptResponse> {
    let mut api = SecurityEnvironmentApi::load().map_err(native_error)?;
    negotiate(
        request,
        version,
        supports_ingress,
        &mut api,
        |candidate| {
            wxc_common::validator::validate_common(candidate)
                .map_err(|error| error.error_message)?;
            if !BaseContainerRunner::can_backend_service_request(candidate).can_service_request() {
                return Err(
                    "the tightened policy cannot be enforced by the selected CPSE tier".into(),
                );
            }
            Ok(())
        },
        canonicalize_allowing_absent_tail,
    )
}

fn native_error(error: LearningModeError) -> ScriptResponse {
    let message = error.to_string();
    native_error_with_message(error, message)
}

fn native_error_with_message(error: LearningModeError, message: String) -> ScriptResponse {
    let unavailable = error.is_api_unavailable();
    let mut structured = if unavailable {
        MxcError::backend_unavailable(message)
    } else {
        MxcError::backend_error(message)
    };
    if let LearningModeError::HResultCall { function, code } = error {
        structured = structured.with_api_failure(
            ApiFailure::new(function).with_native_code(format!("0x{:08X}", code as u32)),
        );
    }
    ScriptResponse::from_mxc_error(
        structured,
        if unavailable {
            FailurePhase::BackendUnavailable
        } else {
            FailurePhase::LaunchFailed
        },
    )
}

pub(crate) fn legacy_creation_error(error: LearningModeError, capture: bool) -> ScriptResponse {
    let message = crate::launch_diagnostics::security_environment_failure_message(&error, capture);
    ScriptResponse {
        exit_code: -1,
        error_message: message.clone(),
        standard_err: message,
        failure_phase: if error.is_api_unavailable() {
            FailurePhase::BackendUnavailable
        } else {
            FailurePhase::LaunchFailed
        },
        ..Default::default()
    }
}

fn failure(
    mut report: PolicyEnforcementReport,
    termination: PolicyEnforcementTermination,
    message: impl Into<String>,
    hresult: Option<HRESULT>,
) -> ScriptResponse {
    let message = message.into();
    report.termination = termination;
    report.message = Some(message.clone());
    let rejected = matches!(
        termination,
        PolicyEnforcementTermination::Rejected
            | PolicyEnforcementTermination::Unrepairable
            | PolicyEnforcementTermination::NoProgress
            | PolicyEnforcementTermination::AttemptLimit
    );
    let mut error = if rejected {
        MxcError::policy_validation(message)
    } else {
        MxcError::backend_error(message)
    };
    if let Some(hr) = hresult {
        error = error.with_api_failure(
            ApiFailure::new(API).with_native_code(format!("0x{:08X}", hr.0 as u32)),
        );
    }
    ScriptResponse::from_mxc_error(
        error,
        if rejected {
            FailurePhase::Rejected
        } else {
            FailurePhase::LaunchFailed
        },
    )
    .with_policy_report(&report)
}

fn legacy(
    api: &mut impl CreationApi,
    specification: &[u8],
    report: Option<PolicyEnforcementReport>,
) -> Result<NegotiatedEnvironment, ScriptResponse> {
    match api.legacy(specification) {
        Ok(environment) => Ok(NegotiatedEnvironment {
            environment,
            report: report.map(|mut report| {
                report.environment_created = true;
                report
            }),
        }),
        Err(error) => {
            let message =
                crate::launch_diagnostics::security_environment_failure_message(&error, false);
            let response = native_error_with_message(error, message);
            Err(match report {
                Some(report) => response.with_policy_report(&report),
                None => response,
            })
        }
    }
}

fn negotiate(
    request: &mut ExecutionRequest,
    version: SecurityEnvironmentVersion,
    supports_ingress: bool,
    api: &mut impl CreationApi,
    validate: impl Fn(&ExecutionRequest) -> Result<(), String>,
    resolve: impl Fn(&str) -> PathCanonical,
) -> Result<NegotiatedEnvironment, ScriptResponse> {
    let build = |request: &ExecutionRequest| {
        build_psec_v1_security_environment_spec(request, version, supports_ingress)
    };
    let Some(options) = request.policy.policy_enforcement.clone() else {
        return api
            .legacy(&build(request))
            .map(|environment| NegotiatedEnvironment {
                environment,
                report: None,
            })
            .map_err(|error| {
                legacy_creation_error(error, request.policy.capture_denials.is_some())
            });
    };
    options.validate().map_err(ScriptResponse::error)?;
    let mode = options.mode.unwrap_or_default();
    let max_attempts = options.max_attempts.unwrap_or(DEFAULT_POLICY_ATTEMPTS);
    let reports_policy = api.reports_policy().map_err(native_error)?;
    let mut report = PolicyEnforcementReport::new(
        mode,
        if reports_policy {
            PolicyEnforcementAvailability::Available
        } else {
            PolicyEnforcementAvailability::Unavailable
        },
        policy_hash(request),
    );
    if !reports_policy {
        return legacy(api, &build(request), Some(report));
    }
    if mode == PolicyEnforcementMode::Mutate && !request.experimental_enabled {
        report.mode_applied = false;
        return Err(failure(
            report,
            PolicyEnforcementTermination::Rejected,
            "processContainer.policyEnforcement.mode='mutate' requires experimental execution",
            None,
        ));
    }

    let mut fingerprints = HashSet::new();
    let mut previous_failure = None;
    let mut history_bytes = 0usize;
    loop {
        let specification = build(request);
        let mut hasher = DefaultHasher::new();
        specification.hash(&mut hasher);
        if !fingerprints.insert(hasher.finish()) {
            return Err(failure(
                report,
                PolicyEnforcementTermination::NoProgress,
                "policy mutation produced an unchanged or previously attempted PSEC request",
                None,
            ));
        }
        let outcome = api.reported(&specification).map_err(|error| {
            report.termination = PolicyEnforcementTermination::NativeFailure;
            report.message = Some(error.to_string());
            native_error(error).with_policy_report(&report)
        })?;
        let PolicyCreateOutcome {
            hresult,
            policy,
            environment,
            invalid_result,
        } = outcome;
        let index = report.attempts.len();
        report.attempts.push(PolicyEnforcementAttempt {
            attempt: (index + 1) as u8,
            hresult: format!("0x{:08X}", hresult.0 as u32),
            result: policy.clone(),
            changes: Vec::new(),
        });
        // Only an initial, decision-free unavailable response permits legacy
        // compatibility. Never downgrade after an earlier policy refusal.
        if index == 0
            && hresult == E_NOTIMPL
            && invalid_result.is_none()
            && environment.is_none()
            && policy.outcome.code == outcome::UNKNOWN
            && policy.details.is_empty()
            && policy.details_count == 0
            && policy.resource_chars_written == 0
            && policy.resource_chars_required == 0
        {
            report.mode_applied = false;
            report.availability = PolicyEnforcementAvailability::Unavailable;
            return legacy(api, &specification, Some(report));
        }
        if let Some(message) = invalid_result {
            return Err(failure(
                report,
                PolicyEnforcementTermination::InvalidResult,
                message,
                Some(hresult),
            ));
        }
        if hresult.is_ok() {
            if matches!(
                policy.outcome.code,
                outcome::NO_APPLICABLE_POLICY | outcome::PASSED
            ) {
                if let Some(environment) = environment {
                    report.environment_created = true;
                    report.termination = PolicyEnforcementTermination::Created;
                    report.effective_policy_hash = policy_hash(request);
                    return Ok(NegotiatedEnvironment {
                        environment,
                        report: Some(report),
                    });
                }
            }
            return Err(failure(
                report,
                PolicyEnforcementTermination::InvalidResult,
                "CPSE returned success without a valid environment and policy outcome",
                Some(hresult),
            ));
        }
        if environment.is_some() {
            return Err(failure(
                report,
                PolicyEnforcementTermination::InvalidResult,
                "CPSE returned an environment handle on failure",
                Some(hresult),
            ));
        }
        if policy.outcome.code != outcome::BLOCKED {
            return Err(failure(
                report,
                if policy.outcome.code == outcome::EVALUATION_FAILED {
                    PolicyEnforcementTermination::EvaluationFailed
                } else {
                    PolicyEnforcementTermination::NativeFailure
                },
                "process security environment creation failed; see the native policy result",
                Some(hresult),
            ));
        }
        if mode == PolicyEnforcementMode::PassThrough {
            return Err(failure(
                report,
                PolicyEnforcementTermination::Rejected,
                "the OS policy refused the requested process security environment",
                Some(hresult),
            ));
        }
        if index + 1 >= usize::from(max_attempts) {
            return Err(failure(
                report,
                PolicyEnforcementTermination::AttemptLimit,
                "the creation-policy attempt limit was reached without launching a workload",
                Some(hresult),
            ));
        }
        let signature: Vec<_> = policy
            .details
            .iter()
            .map(|detail| {
                (
                    detail.failure_class.code,
                    detail.failure_reason.code,
                    detail.required_action.code,
                    detail.resource.clone(),
                    detail.requested_value,
                    detail.required_value,
                )
            })
            .collect();
        if previous_failure.as_ref() == Some(&signature) {
            return Err(failure(
                report,
                PolicyEnforcementTermination::NoProgress,
                "the previous tightening did not resolve the reported policy conflict",
                Some(hresult),
            ));
        }
        previous_failure = Some(signature);
        let (candidate, changes) = plan_repair(request, &policy, &resolve).map_err(|message| {
            failure(
                report.clone(),
                PolicyEnforcementTermination::Unrepairable,
                message,
                Some(hresult),
            )
        })?;
        validate(&candidate).map_err(|message| {
            failure(
                report.clone(),
                PolicyEnforcementTermination::Unrepairable,
                message,
                Some(hresult),
            )
        })?;
        if changes.is_empty() || build(&candidate) == specification {
            return Err(failure(
                report,
                PolicyEnforcementTermination::NoProgress,
                "no effective tightening can be made for the reported policy conflict",
                Some(hresult),
            ));
        }
        let bytes = serde_json::to_vec(&changes)
            .map_err(|error| {
                failure(
                    report.clone(),
                    PolicyEnforcementTermination::Unrepairable,
                    format!("could not retain policy change details: {error}"),
                    Some(hresult),
                )
            })?
            .len();
        if bytes > MAX_CHANGE_HISTORY_BYTES.saturating_sub(history_bytes) {
            return Err(failure(
                report,
                PolicyEnforcementTermination::Unrepairable,
                "the policy change journal would exceed its 1 MiB bound",
                Some(hresult),
            ));
        }
        history_bytes += bytes;
        report.attempts[index].changes = changes;
        report.effective_policy_hash = policy_hash(&candidate);
        *request = candidate;
    }
}

fn change<T: Serialize>(
    field: &mut T,
    value: T,
    setting: &str,
    changes: &mut Vec<PolicyChange>,
) -> Result<(), String> {
    let before = serde_json::to_value(&*field).map_err(|error| error.to_string())?;
    let after = serde_json::to_value(&value).map_err(|error| error.to_string())?;
    if before != after {
        changes.push(PolicyChange {
            setting: setting.into(),
            before,
            after,
        });
        *field = value;
    }
    Ok(())
}

fn resource(result: &NativePolicyDetail, kind: u32) -> Result<&str, String> {
    if result.resource_kind.code != kind || result.flags & RESOURCE_COMPLETE == 0 {
        return Err("the policy action does not contain a complete, supported resource".into());
    }
    result
        .resource
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "the policy action does not contain a resource".into())
}

fn plan_repair(
    request: &ExecutionRequest,
    result: &NativePolicyResult,
    resolve: &impl Fn(&str) -> PathCanonical,
) -> Result<(ExecutionRequest, Vec<PolicyChange>), String> {
    if result.version != 1
        || result.outcome.code != outcome::BLOCKED
        || result.details.is_empty()
        || result.details.len() > crate::secenv_policy::MAX_DETAILS
        || result.details_count as usize != result.details.len()
    {
        return Err("the OS policy failure has no supported automatic repair batch".into());
    }
    let mut candidate = request.clone();
    let mut changes: Vec<PolicyChange> = Vec::new();
    for detail in &result.details {
        let next = plan_detail_repair(&mut candidate.policy, &request.policy, detail, resolve)?;
        for change in next {
            if let Some(existing) = changes
                .iter_mut()
                .find(|item| item.setting == change.setting)
            {
                existing.after = change.after;
            } else {
                changes.push(change);
            }
        }
    }
    changes.retain(|change| change.before != change.after);
    Ok((candidate, changes))
}

fn plan_detail_repair(
    policy: &mut ContainerPolicy,
    original: &ContainerPolicy,
    result: &NativePolicyDetail,
    resolve: &impl Fn(&str) -> PathCanonical,
) -> Result<Vec<PolicyChange>, String> {
    if result.flags & HAS_ACTIONABLE_DETAILS == 0
        || result.flags & !KNOWN_FLAGS != 0
        || result.flags & (BUFFER_TOO_SMALL | RESOURCE_UNAVAILABLE | DETAILS_UNREPRESENTABLE) != 0
    {
        return Err("the OS policy failure has no complete, supported automatic repair".into());
    }
    let mut changes = Vec::new();
    match (
        result.required_action.code,
        result.failure_class.code,
        result.failure_reason.code,
        result.value_kind.code,
        result.resource_kind.code,
    ) {
        (
            action::REMOVE_CAPABILITY,
            failure_class @ (class::NETWORK | class::FILESYSTEM | class::ENFORCEMENT_MODE),
            reason::CAPABILITY_NOT_ALLOWED,
            value::NONE,
            resource_kind::CAPABILITY,
        ) => {
            let capability = resource(result, resource_kind::CAPABILITY)?;
            remove_capability(policy, original, failure_class, capability, &mut changes)?;
        }
        (
            action::RESTRICT_FILESYSTEM_ACCESS,
            class::FILESYSTEM,
            reason::ACCESS_EXCEEDS_CEILING | reason::DENY_REQUIRED,
            value::ACCESS,
            resource_kind::PATH,
        ) => {
            restrict_path(policy, original, result, resolve, &mut changes)?;
        }
        (
            action::APPLY_UI_RESTRICTIONS,
            class::UI,
            reason::UI_RESTRICTIONS_REQUIRED,
            value::BITMASK,
            resource_kind::NONE,
        ) => {
            apply_ui_restrictions(policy, result.required_value, &mut changes)?;
        }
        (
            action::ENABLE_WIN32K_LOCKDOWN,
            class::WIN32K,
            reason::WIN32K_REQUIRED,
            value::BOOLEAN,
            resource_kind::NONE,
        ) if result.requested_value == 0 && result.required_value == 1 => {
            change(&mut policy.ui.disable, true, "/ui/disable", &mut changes)?;
        }
        (
            action::REDUCE_PATH_COUNT,
            class::FILESYSTEM,
            reason::REQUEST_PATH_LIMIT,
            value::PATH_COUNT,
            resource_kind::NONE,
        ) if result.required_value > 0 => {
            for (paths, setting) in [
                (&mut policy.readwrite_paths, "/filesystem/readwritePaths"),
                (&mut policy.readonly_paths, "/filesystem/readonlyPaths"),
                (&mut policy.denied_paths, "/filesystem/deniedPaths"),
            ] {
                let mut seen = HashSet::new();
                let unique = paths
                    .iter()
                    .filter(|path| seen.insert((*path).clone()))
                    .cloned()
                    .collect();
                change(paths, unique, setting, &mut changes)?;
            }
            let count = policy.readwrite_paths.len()
                + policy.readonly_paths.len()
                + policy.denied_paths.len();
            if count as u64 > result.required_value {
                return Err("distinct filesystem entries exceed the limit; MXC will not choose which access or deny to discard".into());
            }
        }
        _ => {
            return Err(
                "the OS policy action or value is not supported for automatic repair".into(),
            )
        }
    }
    Ok(changes)
}

fn remove_capability(
    policy: &mut ContainerPolicy,
    original: &ContainerPolicy,
    failure_class: u32,
    capability: &str,
    changes: &mut Vec<PolicyChange>,
) -> Result<(), String> {
    let name = capability.to_ascii_lowercase();
    let explicit = policy
        .capabilities
        .iter()
        .any(|value| value.eq_ignore_ascii_case(capability));
    let already_removed = !explicit
        && original
            .capabilities
            .iter()
            .any(|name| name.eq_ignore_ascii_case(capability));
    match (failure_class, name.as_str()) {
        (class::NETWORK, "internetclient" | "internetclientserver") => {
            if let Some(egress) = &mut policy.network_egress {
                change(
                    &mut egress.default,
                    NetworkAction::Deny,
                    "/network/egress/default",
                    changes,
                )?;
                change(
                    &mut egress.allow,
                    Vec::new(),
                    "/network/egress/allow",
                    changes,
                )?;
                policy.default_network_policy = NetworkPolicy::Block;
            } else {
                change(
                    &mut policy.default_network_policy,
                    NetworkPolicy::Block,
                    "/network/defaultPolicy",
                    changes,
                )?;
            }
            change(
                &mut policy.allowed_hosts,
                Vec::new(),
                "/network/allowedHosts",
                changes,
            )?;
            change(
                &mut policy.blocked_hosts,
                Vec::new(),
                "/network/blockedHosts",
                changes,
            )?;
        }
        (class::NETWORK, "privatenetworkclientserver") => {
            change(
                &mut policy.allow_local_network,
                false,
                "/network/allowLocalNetwork",
                changes,
            )?;
            if let Some(ingress) = &mut policy.network_ingress {
                change(
                    &mut ingress.default,
                    NetworkAction::Deny,
                    "/network/ingress/default",
                    changes,
                )?;
            }
            disable_proxy(policy, changes)?;
        }
        (class::NETWORK, "networkloopback") => {
            if let Some(ingress) = &mut policy.network_ingress {
                change(
                    &mut ingress.host_loopback,
                    NetworkAction::Deny,
                    "/network/ingress/hostLoopback",
                    changes,
                )?;
            }
            if policy.allowed_proxy_peer.is_none() {
                disable_proxy(policy, changes)?;
            }
        }
        (
            class::FILESYSTEM,
            "documentslibrary"
            | "pictureslibrary"
            | "videoslibrary"
            | "musiclibrary"
            | "downloadsfolder"
            | "removablestorage"
            | "broadfilesystemaccess",
        ) if explicit || already_removed => {}
        (class::ENFORCEMENT_MODE, "permissivelearningmode") if explicit || already_removed => {
            let capture = policy.capture_denials.as_mut().ok_or(
                "permissive learning has no capture-mode source that MXC can safely change",
            )?;
            if capture.mode != CaptureDenialsMode::Block {
                changes.push(PolicyChange {
                    setting: "/processContainer/captureDenials/mode".into(),
                    before: serde_json::json!("allow"),
                    after: serde_json::json!("block"),
                });
                capture.mode = CaptureDenialsMode::Block;
            }
        }
        _ => {
            return Err(
                "the forbidden capability has no supported tightening transformation".into(),
            )
        }
    }
    let mut capabilities: Vec<_> = policy
        .capabilities
        .iter()
        .filter(|value| !value.eq_ignore_ascii_case(capability))
        .cloned()
        .collect();
    if failure_class == class::ENFORCEMENT_MODE {
        crate::network_policy_helpers::ensure_capability(&mut capabilities, "learningModeLogging");
    }
    change(
        &mut policy.capabilities,
        capabilities,
        "/processContainer/capabilities",
        changes,
    )
}

fn disable_proxy(
    policy: &mut ContainerPolicy,
    changes: &mut Vec<PolicyChange>,
) -> Result<(), String> {
    if policy.network_proxy.is_enabled() {
        changes.push(PolicyChange {
            setting: "/runtimeConfig/networkProxy".into(),
            before: serde_json::json!("configured"),
            after: serde_json::Value::Null,
        });
        policy.network_proxy = Default::default();
        policy.runtime_network_proxy_specified = false;
        // Without the proxy's endpoint filter, hostLoopback=allow would expose
        // unrelated ports if a later policy evaluation accepts this candidate.
        if let Some(ingress) = &mut policy.network_ingress {
            change(
                &mut ingress.host_loopback,
                NetworkAction::Deny,
                "/network/ingress/hostLoopback",
                changes,
            )?;
        }
        change(
            &mut policy.allowed_proxy_peer,
            None,
            "/processContainer/network/allowedProxyPeer",
            changes,
        )?;
    }
    Ok(())
}

fn apply_ui_restrictions(
    policy: &mut ContainerPolicy,
    required: u64,
    changes: &mut Vec<PolicyChange>,
) -> Result<(), String> {
    if required == 0 || required & !u64::from(ALL_DEFINED_UI_LIMITS) != 0 {
        return Err("the required UI mask contains unsupported restriction bits".into());
    }
    let current = crate::job_object::to_job_object_uilimit_mask(
        &wxc_common::ui_policy::resolve_ui_restrictions(&policy.ui, &policy.base_process_ui),
    );
    let mask = u64::from(current) | required;
    let has = |flag: u32| mask & u64::from(flag) != 0;
    let clipboard = match (
        has(JOB_OBJECT_UILIMIT_READCLIPBOARD.0),
        has(JOB_OBJECT_UILIMIT_WRITECLIPBOARD.0),
    ) {
        (false, false) => ClipboardPolicy::All,
        (true, false) => ClipboardPolicy::Write,
        (false, true) => ClipboardPolicy::Read,
        _ => ClipboardPolicy::None,
    };
    change(
        &mut policy.ui.clipboard,
        clipboard,
        "/ui/clipboard",
        changes,
    )?;
    change(
        &mut policy.ui.injection,
        !has(JOB_OBJECT_UILIMIT_INJECTION),
        "/ui/injection",
        changes,
    )?;
    let ui = &mut policy.base_process_ui;
    change(
        &mut ui.ime,
        !has(JOB_OBJECT_UILIMIT_IME),
        "/processContainer/ui/ime",
        changes,
    )?;
    change(
        &mut ui.desktop_system_control,
        !has(JOB_OBJECT_UILIMIT_DESKTOP.0 | JOB_OBJECT_UILIMIT_EXITWINDOWS.0),
        "/processContainer/ui/desktopSystemControl",
        changes,
    )?;
    let isolation = match (
        has(JOB_OBJECT_UILIMIT_HANDLES.0),
        has(JOB_OBJECT_UILIMIT_GLOBALATOMS.0),
    ) {
        (false, false) => "desktop",
        (true, false) => "handles",
        (false, true) => "atoms",
        _ => "container",
    };
    change(
        &mut ui.isolation,
        isolation.into(),
        "/processContainer/ui/isolation",
        changes,
    )?;
    let settings = match (
        has(JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS.0),
        has(JOB_OBJECT_UILIMIT_DISPLAYSETTINGS.0),
    ) {
        (false, false) => "all",
        (true, false) => "display",
        (false, true) => "parameters",
        _ => "none",
    };
    change(
        &mut ui.system_settings,
        settings.into(),
        "/processContainer/ui/systemSettings",
        changes,
    )
}

fn literal_path(path: &str) -> Result<String, String> {
    let bytes = path.as_bytes();
    let drive =
        bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\';
    let unc = path.starts_with("\\\\") && !path.starts_with("\\\\?") && !path.starts_with("\\\\.");
    if (!drive && !unc) || path.contains('/') || path.chars().any(char::is_control) {
        return Err("filesystem repair requires an absolute literal DOS or UNC path".into());
    }
    let normalized = path.trim_end_matches('\\');
    let normalized = if drive && normalized.len() == 2 {
        &path[..3]
    } else {
        normalized
    };
    let tail = &normalized[2..];
    if tail
        .trim_start_matches('\\')
        .split('\\')
        .any(|part| part == "." || part == ".." || part.ends_with(['.', ' ']) || part.contains(':'))
    {
        return Err("filesystem repair cannot reinterpret non-canonical path components".into());
    }
    if unc
        && normalized[2..]
            .split('\\')
            .filter(|part| !part.is_empty())
            .count()
            < 2
    {
        return Err("filesystem repair requires a complete UNC share name".into());
    }
    Ok(normalized.to_owned())
}

fn contains(parent: &str, child: &str) -> bool {
    child.eq_ignore_ascii_case(parent)
        || (child
            .get(..parent.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(parent))
            && child.as_bytes().get(parent.len()) == Some(&b'\\'))
}

fn same_path(first: &str, second: &str) -> bool {
    first
        .trim_end_matches('\\')
        .eq_ignore_ascii_case(second.trim_end_matches('\\'))
}

fn access_at(policy: &ContainerPolicy, point: &str) -> u64 {
    let mut best = None;
    let mut access = 0;
    for (paths, value) in [
        (&policy.readwrite_paths, 2),
        (&policy.readonly_paths, 1),
        (&policy.denied_paths, 0),
    ] {
        for path in paths {
            let path = path.trim_end_matches('\\');
            if contains(path, point) && best.is_none_or(|length| path.len() >= length) {
                best = Some(path.len());
                access = value;
            }
        }
    }
    access
}

fn restrict_path(
    policy: &mut ContainerPolicy,
    original: &ContainerPolicy,
    result: &NativePolicyDetail,
    resolve: &impl Fn(&str) -> PathCanonical,
    changes: &mut Vec<PolicyChange>,
) -> Result<(), String> {
    let point = resource(result, resource_kind::PATH)?;
    if result.required_value > 1
        || result.requested_value > 2
        || result.required_value >= result.requested_value
        || !policy.enumerate_paths.is_empty()
    {
        return Err("the filesystem access result is not a supported narrowing instruction".into());
    }
    let point = literal_path(point)?;
    // Every detail describes the same submitted request. Earlier repairs in this
    // batch may already have narrowed the witness; never reinterpret it as a grant.
    if access_at(original, &point) != result.requested_value {
        return Err("the native filesystem witness disagrees with the submitted request".into());
    }
    if access_at(policy, &point) <= result.required_value {
        return Ok(());
    }
    let readonly_grants: Vec<_> = if result.required_value == 1 {
        policy
            .readwrite_paths
            .iter()
            .filter(|path| same_path(path, &point))
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    // A new grant name can be redirected outside the original request between
    // attempts. Only lower existing spellings; a transient path check is not a pin.
    if result.required_value == 1 && readonly_grants.is_empty() {
        return Err(
            "read-only repair requires an existing matching read/write grant; \
            MXC will not introduce a new grant name or downgrade an unrelated ancestor"
                .into(),
        );
    }
    let before = policy.clone();
    for path in policy
        .readwrite_paths
        .iter()
        .chain(&policy.readonly_paths)
        .chain(&policy.denied_paths)
        .map(String::as_str)
        .chain(std::iter::once(point.as_str()))
    {
        let spelling = literal_path(path)?;
        let resolved = match resolve(path) {
            PathCanonical::Canonical(path) => literal_path(&path)?,
            _ => return Err("filesystem repair cannot resolve every relevant path safely".into()),
        };
        if !spelling.eq_ignore_ascii_case(&resolved) {
            return Err(
                "filesystem repair would require guessing the provenance of an aliased path".into(),
            );
        }
    }
    if original.readwrite_paths.iter().any(|path| {
        let path = path.trim_end_matches('\\');
        path.len() == 2 || (path.starts_with("\\\\") && path[2..].split('\\').count() == 2)
    }) {
        return Err(
            "volume/share-root write grants have no supported automatic filesystem repair".into(),
        );
    }
    if access_at(policy, &point) > result.requested_value {
        return Err("an earlier repair increased filesystem access".into());
    }
    let mut rw = policy.readwrite_paths.clone();
    rw.retain(|path| !same_path(path, &point));
    change(
        &mut policy.readwrite_paths,
        rw,
        "/filesystem/readwritePaths",
        changes,
    )?;
    if result.required_value == 0 {
        let mut ro = policy.readonly_paths.clone();
        ro.retain(|path| !same_path(path, &point));
        change(
            &mut policy.readonly_paths,
            ro,
            "/filesystem/readonlyPaths",
            changes,
        )?;
        let mut denied = policy.denied_paths.clone();
        denied.push(point.clone());
        change(
            &mut policy.denied_paths,
            denied,
            "/filesystem/deniedPaths",
            changes,
        )?;
    } else {
        let mut ro = policy.readonly_paths.clone();
        for grant in readonly_grants {
            if !ro.contains(&grant) {
                ro.push(grant);
            }
        }
        change(
            &mut policy.readonly_paths,
            ro,
            "/filesystem/readonlyPaths",
            changes,
        )?;
    }
    let points = before
        .readwrite_paths
        .iter()
        .chain(&before.readonly_paths)
        .chain(&before.denied_paths)
        .map(String::as_str)
        .chain(std::iter::once(point.as_str()));
    if access_at(policy, &point) > result.required_value
        || points
            .into_iter()
            .any(|path| access_at(policy, path) > access_at(&before, path))
    {
        return Err("the proposed filesystem repair could increase effective access".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
