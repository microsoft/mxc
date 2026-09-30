// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Explicit pass-through creation-policy diagnostics. The OS remains the policy authority.

use learning_mode_windows::LearningModeError;
use windows::Win32::Foundation::E_NOTIMPL;
use windows_core::HRESULT;
use wxc_common::models::{ExecutionRequest, FailurePhase, ScriptResponse};
use wxc_common::mxc_error::{ApiFailure, MxcError};
use wxc_common::policy_enforcement::{
    PolicyEnforcementAttempt, PolicyEnforcementAvailability, PolicyEnforcementReport,
    PolicyEnforcementTermination,
};
use wxc_common::policy_identity::policy_hash;

use crate::base_container_helpers::build_psec_v1_security_environment_spec;
use crate::secenv::{
    PolicyCreateOutcome, ProcessSecurityEnvironment, SecurityEnvironmentApi,
    SecurityEnvironmentVersion, PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE,
};
use crate::secenv_policy::codes::outcome;

const API: &str = "CreateProcessSecurityEnvironment2";

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
    request: &ExecutionRequest,
    version: SecurityEnvironmentVersion,
    supports_ingress: bool,
) -> Result<NegotiatedEnvironment, ScriptResponse> {
    let mut api = SecurityEnvironmentApi::load().map_err(native_error)?;
    create_with_api(request, version, supports_ingress, &mut api)
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
    message: &str,
    hresult: HRESULT,
) -> ScriptResponse {
    report.termination = termination;
    report.message = Some(message.into());
    let rejected = termination == PolicyEnforcementTermination::Rejected;
    let error = if rejected {
        MxcError::policy_validation(message)
    } else {
        MxcError::backend_error(message)
    }
    .with_api_failure(ApiFailure::new(API).with_native_code(format!("0x{:08X}", hresult.0 as u32)));
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

fn create_with_api(
    request: &ExecutionRequest,
    version: SecurityEnvironmentVersion,
    supports_ingress: bool,
    api: &mut impl CreationApi,
) -> Result<NegotiatedEnvironment, ScriptResponse> {
    let specification = build_psec_v1_security_environment_spec(request, version, supports_ingress);
    let Some(options) = request.policy.policy_enforcement.as_ref() else {
        return api
            .legacy(&specification)
            .map(|environment| NegotiatedEnvironment {
                environment,
                report: None,
            })
            .map_err(|error| {
                legacy_creation_error(error, request.policy.capture_denials.is_some())
            });
    };
    options.validate().map_err(ScriptResponse::error)?;
    let available = api.reports_policy().map_err(native_error)?;
    let mut report = PolicyEnforcementReport::new(
        options.mode.unwrap_or_default(),
        if available {
            PolicyEnforcementAvailability::Available
        } else {
            PolicyEnforcementAvailability::Unavailable
        },
        policy_hash(request),
    );
    if !available {
        return legacy(api, &specification, Some(report));
    }
    let PolicyCreateOutcome {
        hresult,
        policy,
        environment,
        invalid_result,
    } = api.reported(&specification).map_err(|error| {
        report.termination = PolicyEnforcementTermination::NativeFailure;
        report.message = Some(error.to_string());
        native_error(error).with_policy_report(&report)
    })?;

    report.attempts.push(PolicyEnforcementAttempt {
        attempt: 1,
        hresult: format!("0x{:08X}", hresult.0 as u32),
        result: policy.clone(),
        changes: Vec::new(),
    });
    if hresult == E_NOTIMPL
        && policy.outcome.code == outcome::UNKNOWN
        && environment.is_none()
        && invalid_result.is_none()
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
            hresult,
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
            hresult,
        ));
    }
    if environment.is_some() {
        return Err(failure(
            report,
            PolicyEnforcementTermination::InvalidResult,
            "CPSE returned an environment handle on failure",
            hresult,
        ));
    }
    if policy.outcome.code == outcome::BLOCKED {
        return Err(failure(
            report,
            PolicyEnforcementTermination::Rejected,
            "the OS policy refused the requested process security environment",
            hresult,
        ));
    }
    Err(failure(
        report,
        if policy.outcome.code == outcome::EVALUATION_FAILED {
            PolicyEnforcementTermination::EvaluationFailed
        } else {
            PolicyEnforcementTermination::NativeFailure
        },
        "process security environment creation failed; see the native policy result",
        hresult,
    ))
}

#[cfg(test)]
mod tests;
