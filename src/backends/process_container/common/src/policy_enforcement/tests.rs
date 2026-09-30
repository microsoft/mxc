use super::*;
use std::cell::Cell;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use windows::Win32::Foundation::{E_FAIL, HANDLE, S_OK};
use wxc_common::policy_enforcement::{
    NativePolicyDetail, NativePolicyResult, PolicyEnforcementMode, PolicyEnforcementOptions,
    PolicyResultCode,
};

fn environment(closed: &Arc<AtomicUsize>) -> ProcessSecurityEnvironment {
    unsafe extern "system" fn close(handle: HANDLE) {
        // SAFETY: each fake handle owns the Box allocated below.
        let counter = unsafe { Box::from_raw(handle.0.cast::<Arc<AtomicUsize>>()) };
        counter.fetch_add(1, Ordering::SeqCst);
    }
    ProcessSecurityEnvironment::from_test_handle(
        HANDLE(Box::into_raw(Box::new(Arc::clone(closed))).cast()),
        close,
    )
}

struct FakeApi {
    available: bool,
    support_error: bool,
    support_calls: Cell<usize>,
    legacy_error: Option<i32>,
    result: Option<(HRESULT, NativePolicyResult)>,
    calls: usize,
    legacy_calls: usize,
    closed: Arc<AtomicUsize>,
    failure_handle: bool,
    missing_handle: bool,
    invalid_result: Option<&'static str>,
}

impl FakeApi {
    fn new(status: HRESULT, outcome: u32) -> Self {
        Self {
            available: true,
            support_error: false,
            support_calls: Cell::new(0),
            legacy_error: None,
            result: Some((
                status,
                NativePolicyResult {
                    version: 1,
                    outcome: PolicyResultCode::new(outcome, None),
                    details_capacity: 64,
                    resource_capacity_chars: 32_768,
                    ..Default::default()
                },
            )),
            calls: 0,
            legacy_calls: 0,
            closed: Arc::new(AtomicUsize::new(0)),
            failure_handle: false,
            missing_handle: false,
            invalid_result: None,
        }
    }
}

impl CreationApi for FakeApi {
    fn reports_policy(&self) -> Result<bool, LearningModeError> {
        self.support_calls.set(self.support_calls.get() + 1);
        if self.support_error {
            Err(LearningModeError::HResultCall {
                function: "QueryProcessSecurityEnvironmentSupport",
                code: E_FAIL.0,
            })
        } else {
            Ok(self.available)
        }
    }
    fn legacy(&mut self, _: &[u8]) -> Result<ProcessSecurityEnvironment, LearningModeError> {
        self.legacy_calls += 1;
        if let Some(code) = self.legacy_error {
            return Err(LearningModeError::HResultCall {
                function: "CreateProcessSecurityEnvironment",
                code,
            });
        }
        Ok(environment(&self.closed))
    }
    fn reported(&mut self, _: &[u8]) -> Result<PolicyCreateOutcome, LearningModeError> {
        self.calls += 1;
        let (hresult, policy) = self.result.take().expect("creation must not be retried");
        Ok(PolicyCreateOutcome {
            hresult,
            policy,
            invalid_result: self.invalid_result,
            environment: ((hresult.is_ok() && !self.missing_handle) || self.failure_handle)
                .then(|| environment(&self.closed)),
        })
    }
}

fn run(api: &mut FakeApi) -> Result<NegotiatedEnvironment, ScriptResponse> {
    let mut request = ExecutionRequest::default();
    request.policy.policy_enforcement = Some(PolicyEnforcementOptions::default());
    create_with_api(&request, SecurityEnvironmentVersion::V1_0, false, api)
}

fn report(response: ScriptResponse) -> PolicyEnforcementReport {
    serde_json::from_value(response.error.unwrap().details.unwrap()["policyEnforcement"].clone())
        .unwrap()
}

#[test]
fn policy_enforcement_live_teardown_warnings_require_explicit_reporting() {
    let report = PolicyEnforcementReport::new(
        PolicyEnforcementMode::PassThrough,
        PolicyEnforcementAvailability::Available,
        "hash".into(),
    );
    let failure = Some(Err("capture sealing failed".to_string()));
    assert!(teardown_warnings(None, &failure).is_empty());
    assert!(teardown_warnings(Some(&report), &None).is_empty());
    assert!(teardown_warnings(Some(&report), &Some(Ok(()))).is_empty());
    assert_eq!(
        teardown_warnings(Some(&report), &failure),
        ["capture sealing failed"]
    );
}

#[test]
fn pass_through_returns_the_entire_refusal_batch_without_legacy_fallback() {
    let mut api = FakeApi::new(HRESULT(0x800704ec_u32 as i32), outcome::BLOCKED);
    let native = &mut api.result.as_mut().unwrap().1;
    native.details = vec![
        NativePolicyDetail {
            resource: Some("forbidden-capability".into()),
            failure_class: PolicyResultCode::new(999, None),
            resource_chars_written: 21,
            resource_chars_required: 21,
            ..Default::default()
        },
        NativePolicyDetail {
            resource: Some("C:\\work".into()),
            resource_offset_chars: 21,
            resource_chars_written: 8,
            resource_chars_required: 8,
            requested_value: u64::MAX,
            required_value: 1,
            ..Default::default()
        },
    ];
    native.details_count = 2;
    native.resource_chars_written = 29;
    native.resource_chars_required = 29;
    let expected = native.clone();
    let result = report(run(&mut api).unwrap_err());
    assert_eq!((api.calls, api.legacy_calls), (1, 0));
    assert_eq!(result.termination, PolicyEnforcementTermination::Rejected);
    assert_eq!(result.original_policy_hash, result.effective_policy_hash);
    assert_eq!(result.report_version, 1);
    assert_eq!(result.attempts.len(), 1);
    assert_eq!(result.attempts[0].result, expected);
    assert!(result.attempts[0].changes.is_empty());
    assert!(!result.environment_created);
}

#[test]
fn successful_outcomes_preserve_the_native_decision_and_single_owned_environment() {
    for outcome in [outcome::PASSED, outcome::NO_APPLICABLE_POLICY] {
        let mut api = FakeApi::new(S_OK, outcome);
        let created = run(&mut api).unwrap();
        let report = created.report.as_ref().unwrap();
        assert_eq!(report.requested_mode, PolicyEnforcementMode::PassThrough);
        assert_eq!(report.attempts[0].result.outcome.code, outcome);
        assert!(report.attempts[0].result.details.is_empty());
        assert_eq!(report.attempts[0].result.details_count, 0);
        assert!(report.environment_created);
        assert_eq!(api.calls, 1);
        drop(created);
        assert_eq!(api.closed.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn provisioning_failure_does_not_erase_a_passed_policy() {
    let mut api = FakeApi::new(E_FAIL, outcome::PASSED);
    let report = report(run(&mut api).unwrap_err());
    assert_eq!(
        report.termination,
        PolicyEnforcementTermination::NativeFailure
    );
    assert_eq!(report.attempts[0].result.outcome.code, outcome::PASSED);
    assert_eq!(api.legacy_calls, 0);
}

#[test]
fn invalid_native_outcomes_close_any_environment() {
    for (status, outcome, failure_handle) in [(S_OK, 999, false), (E_FAIL, outcome::BLOCKED, true)]
    {
        let mut api = FakeApi::new(status, outcome);
        api.failure_handle = failure_handle;
        let report = report(run(&mut api).unwrap_err());
        assert_eq!(
            report.termination,
            PolicyEnforcementTermination::InvalidResult
        );
        assert_eq!(api.closed.load(Ordering::SeqCst), 1);
        assert_eq!(api.legacy_calls, 0);
    }
}

#[test]
fn successful_creation_requires_an_environment_handle() {
    let mut api = FakeApi::new(S_OK, outcome::PASSED);
    api.missing_handle = true;
    assert_eq!(
        report(run(&mut api).unwrap_err()).termination,
        PolicyEnforcementTermination::InvalidResult
    );
}

#[test]
fn unavailable_api_reports_explicit_controls_without_claiming_policy_evaluation() {
    let mut api = FakeApi::new(E_FAIL, outcome::UNKNOWN);
    api.available = false;
    let created = run(&mut api).unwrap();
    let report = created.report.as_ref().unwrap();
    assert_eq!(
        report.availability,
        PolicyEnforcementAvailability::Unavailable
    );
    assert!(!report.mode_applied);
    assert!(report.attempts.is_empty());
    assert_eq!((api.calls, api.legacy_calls), (0, 1));
}

#[test]
fn only_a_decision_free_unavailable_response_allows_legacy_compatibility() {
    let mut api = FakeApi::new(E_NOTIMPL, outcome::UNKNOWN);
    let created = run(&mut api).unwrap();
    let report = created.report.unwrap();
    assert_eq!((api.calls, api.legacy_calls), (1, 1));
    assert_eq!(
        report.availability,
        PolicyEnforcementAvailability::Unavailable
    );
    assert!(!report.mode_applied);
    assert_eq!(report.attempts.len(), 1);
    assert_eq!(report.attempts[0].result.outcome.code, outcome::UNKNOWN);
    assert!(report.attempts[0].result.details.is_empty());
    assert_eq!(report.attempts[0].result.details_count, 0);
    assert_eq!(report.attempts[0].result.resource_chars_written, 0);
    assert_eq!(report.attempts[0].result.resource_chars_required, 0);
}

#[test]
fn reported_legacy_denial_keeps_basic_guidance_on_both_unavailable_routes() {
    for unavailable_before_call in [true, false] {
        let mut api = FakeApi::new(E_NOTIMPL, outcome::UNKNOWN);
        api.available = !unavailable_before_call;
        api.legacy_error = Some(0x800704EC_u32 as i32);
        let error = run(&mut api).unwrap_err();
        assert!(error.error_message.contains("IT-managed policy rule"));
        assert!(error
            .error_message
            .contains("requested sandbox permissions"));
        assert!(error.error_message.contains("system administrator"));
        assert_eq!(error.failure_phase, FailurePhase::LaunchFailed);
        let structured = error.error.as_ref().unwrap();
        assert_eq!(structured.native_code.as_deref(), Some("0x800704EC"));
        assert_eq!(
            structured.operation.as_deref(),
            Some("CreateProcessSecurityEnvironment")
        );
        let report = report(error);
        assert_eq!(
            report.availability,
            PolicyEnforcementAvailability::Unavailable
        );
        assert_eq!(report.requested_mode, PolicyEnforcementMode::PassThrough);
        assert!(!report.mode_applied);
        assert!(!report.environment_created);
        assert_eq!(report.attempts.len(), usize::from(!unavailable_before_call));
        assert_eq!(api.legacy_calls, 1);
        assert_eq!(api.calls, usize::from(!unavailable_before_call));
    }
}

#[test]
fn empty_block_is_returned_without_mutation_or_fallback() {
    for mode in [None, Some(PolicyEnforcementMode::PassThrough)] {
        let mut request = ExecutionRequest::default();
        let mut settings = PolicyEnforcementOptions::default();
        settings.mode = mode;
        request.policy.policy_enforcement = Some(settings);
        let before = policy_hash(&request);
        let mut api = FakeApi::new(E_FAIL, outcome::BLOCKED);
        let error = create_with_api(&request, SecurityEnvironmentVersion::V1_0, false, &mut api)
            .unwrap_err();
        let report = report(error);
        assert_eq!(report.termination, PolicyEnforcementTermination::Rejected);
        assert_eq!(policy_hash(&request), before);
        assert_eq!(report.original_policy_hash, before);
        assert_eq!(report.effective_policy_hash, before);
        assert_eq!(report.attempts.len(), 1);
        assert!(report.attempts[0].result.details.is_empty());
        assert!(report.attempts[0].changes.is_empty());
        assert_eq!((api.calls, api.legacy_calls), (1, 0));
        assert_eq!(api.closed.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn invalid_batch_retains_fixed_details_and_closes_an_unexpected_handle() {
    let mut api = FakeApi::new(E_NOTIMPL, outcome::BLOCKED);
    let native = &mut api.result.as_mut().unwrap().1;
    native.details = vec![
        NativePolicyDetail {
            failure_class: PolicyResultCode::new(2, None),
            requested_value: 2,
            required_value: 1,
            ..Default::default()
        },
        NativePolicyDetail {
            failure_class: PolicyResultCode::new(999, None),
            required_value: u64::MAX,
            ..Default::default()
        },
    ];
    native.details_count = 2;
    native.resource_chars_required = u32::MAX;
    let expected = native.clone();
    api.invalid_result = Some("invalid resource counts");
    api.failure_handle = true;
    let report = report(run(&mut api).unwrap_err());
    assert_eq!(
        report.termination,
        PolicyEnforcementTermination::InvalidResult
    );
    assert_eq!(report.attempts[0].result, expected);
    assert!(report.attempts[0].changes.is_empty());
    assert_eq!((api.calls, api.legacy_calls), (1, 0));
    assert_eq!(api.closed.load(Ordering::SeqCst), 1);
}

#[test]
fn unavailable_status_with_detail_or_pool_data_never_allows_legacy_fallback() {
    for field in 0..4 {
        let mut api = FakeApi::new(E_NOTIMPL, outcome::UNKNOWN);
        let native = &mut api.result.as_mut().unwrap().1;
        match field {
            0 => native.details.push(NativePolicyDetail::default()),
            1 => native.details_count = 1,
            2 => native.resource_chars_written = 1,
            3 => native.resource_chars_required = 1,
            _ => unreachable!(),
        }
        let report = report(run(&mut api).unwrap_err());
        assert_eq!((api.calls, api.legacy_calls), (1, 0));
        assert_eq!(
            report.availability,
            PolicyEnforcementAvailability::Available
        );
        assert_eq!(
            report.termination,
            PolicyEnforcementTermination::NativeFailure
        );
    }
}

#[test]
fn support_query_failure_is_not_silently_treated_as_absence() {
    let mut api = FakeApi::new(S_OK, outcome::PASSED);
    api.support_error = true;
    let error = run(&mut api).unwrap_err().error.unwrap();
    assert_eq!(
        error.operation.as_deref(),
        Some("QueryProcessSecurityEnvironmentSupport")
    );
    assert_eq!((api.calls, api.legacy_calls), (0, 0));
}

#[test]
fn omitted_controls_never_query_reporting_support_or_call_ex() {
    for available in [false, true] {
        let mut api = FakeApi::new(S_OK, outcome::PASSED);
        api.available = available;
        api.support_error = true;
        let created = create_with_api(
            &ExecutionRequest::default(),
            SecurityEnvironmentVersion::V1_0,
            false,
            &mut api,
        )
        .unwrap();
        assert!(created.report.is_none());
        assert_eq!(
            (api.support_calls.get(), api.calls, api.legacy_calls),
            (0, 0, 1)
        );
    }
}

#[test]
fn omitted_controls_preserve_legacy_creation_error_text_and_shape() {
    for capture in [false, true] {
        let mut request = ExecutionRequest::default();
        if capture {
            request.policy.capture_denials = Some(Default::default());
        }
        let mut api = FakeApi::new(S_OK, outcome::PASSED);
        api.legacy_error = Some(E_FAIL.0);
        let error = create_with_api(&request, SecurityEnvironmentVersion::V1_0, false, &mut api)
            .unwrap_err();
        let prefix = if capture {
            "captureDenials: failed to start learning-mode capture:"
        } else {
            "failed to create the process security environment:"
        };
        assert!(error.error_message.starts_with(prefix));
        assert_eq!(error.error_message, error.standard_err);
        assert!(error.error.is_none());
        assert!(error.output_metadata.is_none());
        assert_eq!(
            (api.support_calls.get(), api.calls, api.legacy_calls),
            (0, 0, 1)
        );
    }
}

#[test]
fn empty_and_explicit_pass_through_need_no_experimental_authorization() {
    for mode in [None, Some(PolicyEnforcementMode::PassThrough)] {
        let mut request = ExecutionRequest::default();
        assert!(!request.experimental_enabled);
        let mut settings = PolicyEnforcementOptions::default();
        settings.mode = mode;
        request.policy.policy_enforcement = Some(settings);
        let before = policy_hash(&request);
        let mut api = FakeApi::new(S_OK, outcome::PASSED);
        let created =
            create_with_api(&request, SecurityEnvironmentVersion::V1_0, false, &mut api).unwrap();
        let report = created.report.unwrap();
        assert_eq!(report.requested_mode, PolicyEnforcementMode::PassThrough);
        assert_eq!(report.original_policy_hash, before);
        assert_eq!(report.effective_policy_hash, before);
        assert_eq!(report.attempts.len(), 1);
        assert!(report.attempts[0].changes.is_empty());
        assert_eq!((api.calls, api.legacy_calls), (1, 0));
    }
}

#[test]
fn mutation_is_rejected_before_capability_queries_even_when_unavailable() {
    for available in [false, true] {
        let mut request = ExecutionRequest::default();
        let mut settings = PolicyEnforcementOptions::default();
        settings.mode = Some(PolicyEnforcementMode::Mutate);
        request.policy.policy_enforcement = Some(settings);
        let mut api = FakeApi::new(S_OK, outcome::PASSED);
        api.available = available;
        let error = create_with_api(&request, SecurityEnvironmentVersion::V1_0, false, &mut api)
            .unwrap_err();
        assert!(error.error_message.contains("must be pass-through"));
        assert_eq!(
            (api.support_calls.get(), api.calls, api.legacy_calls),
            (0, 0, 0)
        );
    }
}
