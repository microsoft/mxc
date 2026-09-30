use super::*;
use std::cell::Cell;
use std::collections::VecDeque;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use windows::Win32::Foundation::{E_FAIL, HANDLE, S_OK};
use wxc_common::models::{NetworkEgressPolicy, NetworkIngressPolicy};
use wxc_common::policy_enforcement::{PolicyEnforcementOptions, PolicyResultCode};

fn environment(closed: &Arc<AtomicUsize>) -> ProcessSecurityEnvironment {
    unsafe extern "system" fn close(handle: HANDLE) {
        // SAFETY: this fake only receives a Box<Arc<AtomicUsize>> allocated below.
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
    availability_error: Option<i32>,
    availability_calls: Cell<usize>,
    legacy_error: Option<i32>,
    outcomes: VecDeque<(HRESULT, NativePolicyResult)>,
    calls: usize,
    legacy_calls: usize,
    closed: Arc<AtomicUsize>,
    omit_handle: bool,
    failure_handle: bool,
    specifications: Vec<Vec<u8>>,
    invalid_result: Option<&'static str>,
}

impl FakeApi {
    fn new(outcomes: Vec<(HRESULT, NativePolicyResult)>) -> Self {
        Self {
            available: true,
            availability_error: None,
            availability_calls: Cell::new(0),
            legacy_error: None,
            outcomes: outcomes.into(),
            calls: 0,
            legacy_calls: 0,
            closed: Arc::new(AtomicUsize::new(0)),
            omit_handle: false,
            failure_handle: false,
            specifications: Vec::new(),
            invalid_result: None,
        }
    }
}

impl CreationApi for FakeApi {
    fn reports_policy(&self) -> Result<bool, LearningModeError> {
        self.availability_calls
            .set(self.availability_calls.get() + 1);
        match self.availability_error {
            Some(code) => Err(LearningModeError::HResultCall {
                function: "QueryProcessSecurityEnvironmentSupport",
                code,
            }),
            None => Ok(self.available),
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

    fn reported(&mut self, specification: &[u8]) -> Result<PolicyCreateOutcome, LearningModeError> {
        self.specifications.push(specification.to_vec());
        self.calls += 1;
        let (hresult, policy) =
            self.outcomes
                .pop_front()
                .ok_or(LearningModeError::HResultCall {
                    function: API,
                    code: E_FAIL.0,
                })?;
        Ok(PolicyCreateOutcome {
            hresult,
            policy,
            invalid_result: self.invalid_result,
            environment: ((hresult.is_ok() && !self.omit_handle) || self.failure_handle)
                .then(|| environment(&self.closed)),
        })
    }
}

fn result(outcome: u32) -> NativePolicyResult {
    NativePolicyResult {
        version: 1,
        outcome: PolicyResultCode::new(outcome, None),
        ..Default::default()
    }
}

fn path_failure(path: &str, requested: u64, required: u64) -> NativePolicyResult {
    let resource_chars = path.encode_utf16().count() as u32 + 1;
    with_detail(NativePolicyDetail {
        failure_class: PolicyResultCode::new(2, None),
        failure_reason: PolicyResultCode::new(if required == 0 { 3 } else { 2 }, None),
        required_action: PolicyResultCode::new(2, None),
        resource_kind: PolicyResultCode::new(1, None),
        value_kind: PolicyResultCode::new(1, None),
        requested_value: requested,
        required_value: required,
        resource: Some(path.into()),
        resource_chars_written: resource_chars,
        resource_chars_required: resource_chars,
        flags: HAS_ACTIONABLE_DETAILS | RESOURCE_COMPLETE,
        ..Default::default()
    })
}

fn with_detail(detail: NativePolicyDetail) -> NativePolicyResult {
    NativePolicyResult {
        details_count: 1,
        details_capacity: crate::secenv_policy::MAX_DETAILS as u32,
        resource_capacity_chars: crate::secenv_policy::MAX_RESOURCE_CHARS as u32,
        resource_chars_written: detail.resource_chars_written,
        resource_chars_required: detail.resource_chars_required,
        details: vec![detail],
        ..result(3)
    }
}

fn batch(results: Vec<NativePolicyResult>) -> NativePolicyResult {
    let mut result = result(outcome::BLOCKED);
    result.details_capacity = crate::secenv_policy::MAX_DETAILS as u32;
    result.resource_capacity_chars = crate::secenv_policy::MAX_RESOURCE_CHARS as u32;
    for mut detail in results.into_iter().flat_map(|result| result.details) {
        if detail.resource_chars_written != 0 {
            detail.resource_offset_chars = result.resource_chars_written;
        }
        result.resource_chars_written += detail.resource_chars_written;
        result.resource_chars_required += detail.resource_chars_required;
        result.details.push(detail);
    }
    result.details_count = result.details.len() as u32;
    result
}

#[test]
fn policy_enforcement_repairs_a_snapshot_batch_before_one_retry() {
    let failure = batch(vec![
        path_failure("C:\\work", 2, 1),
        path_failure("C:\\work\\secret", 2, 0),
    ]);
    let mut candidate = request();
    let mut api = FakeApi::new(vec![(E_FAIL, failure), (S_OK, result(2))]);
    let created = run(&mut candidate, &mut api).unwrap();
    assert_eq!(api.calls, 2);
    assert!(candidate.policy.readwrite_paths.is_empty());
    assert_eq!(candidate.policy.readonly_paths, ["C:\\work"]);
    assert_eq!(candidate.policy.denied_paths, ["C:\\work\\secret"]);
    assert_eq!(
        api.specifications[1],
        build_psec_v1_security_environment_spec(
            &candidate,
            SecurityEnvironmentVersion::V1_0,
            false
        )
    );
    assert_ne!(api.specifications[0], api.specifications[1]);
    let report = created.report.unwrap();
    assert_eq!(report.attempts[0].result.details.len(), 2);
    assert_eq!(report.attempts[0].result.details[1].requested_value, 2);
    assert_eq!(report.attempts[1].result.details.len(), 0);
}

#[test]
fn policy_enforcement_batch_is_atomic_when_a_later_detail_is_unrepairable() {
    for incomplete in [false, true] {
        let mut second = path_failure("C:\\work\\second", 2, 0);
        if incomplete {
            second.details[0].flags = HAS_ACTIONABLE_DETAILS | BUFFER_TOO_SMALL;
            second.details[0].resource = None;
            second.details[0].resource_chars_written = 0;
        } else {
            second.details[0].required_action.code = 999;
        }
        let failure = batch(vec![
            path_failure("C:\\work\\first", 2, 0),
            second,
            path_failure("C:\\work\\third", 2, 0),
        ]);
        let mut candidate = request();
        let original_hash = policy_hash(&candidate);
        let mut api = FakeApi::new(vec![(E_FAIL, failure)]);
        let report = report(run(&mut candidate, &mut api).unwrap_err());
        assert_eq!(api.calls, 1);
        assert!(candidate.policy.denied_paths.is_empty());
        assert_eq!(policy_hash(&candidate), original_hash);
        assert_eq!(
            report.termination,
            PolicyEnforcementTermination::Unrepairable
        );
        assert!(report.attempts[0].changes.is_empty());
        assert_eq!(report.attempts[0].result.details.len(), 3);
    }
}

#[test]
fn policy_enforcement_duplicate_and_overlapping_details_only_tighten() {
    let failure = batch(vec![
        path_failure("C:\\work\\private", 2, 0),
        path_failure("C:\\work\\private", 2, 0),
        path_failure("C:\\work", 2, 1),
        path_failure("C:\\work\\private\\child", 2, 1),
    ]);
    let (candidate, changes) = plan_repair(&request(), &failure, &resolve).unwrap();
    assert_eq!(candidate.policy.denied_paths, ["C:\\work\\private"]);
    assert_eq!(candidate.policy.readonly_paths, ["C:\\work"]);
    assert_eq!(access_at(&candidate.policy, "C:\\work\\private\\child"), 0);
    assert_eq!(
        changes
            .iter()
            .filter(|change| change.setting == "/filesystem/deniedPaths")
            .count(),
        1
    );
}

#[test]
fn policy_enforcement_full_nonexhaustive_batches_can_reveal_more_conflicts() {
    let first = batch(
        (0..64)
            .map(|index| path_failure(&format!("C:\\work\\p{index}"), 2, 0))
            .collect(),
    );
    let second = path_failure("C:\\work\\last", 2, 0);
    let mut api = FakeApi::new(vec![(E_FAIL, first), (E_FAIL, second), (S_OK, result(2))]);
    let mut candidate = request();
    let created = run(&mut candidate, &mut api).unwrap();
    assert_eq!(api.calls, 3);
    assert_eq!(candidate.policy.denied_paths.len(), 65);
    let report = created.report.unwrap();
    let changes = &report.attempts[0].changes;
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].before, serde_json::json!([]));
    assert_eq!(changes[0].after.as_array().unwrap().len(), 64);
    assert_eq!(report.attempts[0].result.details.len(), 64);
}

#[test]
fn policy_enforcement_pass_through_keeps_the_whole_batch_without_repairs() {
    let failure = batch(vec![
        path_failure("C:\\work\\a", 2, 0),
        path_failure("C:\\work\\b", 2, 0),
    ]);
    let mut candidate = request();
    candidate.policy.policy_enforcement = Some(PolicyEnforcementOptions::default());
    let mut api = FakeApi::new(vec![(E_FAIL, failure.clone())]);
    let report = report(run(&mut candidate, &mut api).unwrap_err());
    assert_eq!(report.attempts[0].result, failure);
    assert!(report.attempts[0].changes.is_empty());
    assert_eq!(api.calls, 1);
    assert!(candidate.policy.denied_paths.is_empty());
}

#[test]
fn policy_enforcement_network_batch_revokes_each_direction() {
    let mut original = request();
    original.policy.network_egress = Some(NetworkEgressPolicy {
        default: NetworkAction::Allow,
        ..Default::default()
    });
    original.policy.network_ingress = Some(NetworkIngressPolicy {
        default: NetworkAction::Allow,
        host_loopback: NetworkAction::Allow,
    });
    let failure = batch(vec![
        capability_failure("internetclient", class::NETWORK),
        capability_failure("privatenetworkclientserver", class::NETWORK),
        capability_failure("networkloopback", class::NETWORK),
    ]);
    let (candidate, changes) = plan_repair(&original, &failure, &resolve).unwrap();
    assert_eq!(
        candidate.policy.network_egress.unwrap().default,
        NetworkAction::Deny
    );
    let ingress = candidate.policy.network_ingress.unwrap();
    assert_eq!(ingress.default, NetworkAction::Deny);
    assert_eq!(ingress.host_loopback, NetworkAction::Deny);
    for setting in [
        "/network/egress/default",
        "/network/ingress/default",
        "/network/ingress/hostLoopback",
    ] {
        assert_eq!(
            changes
                .iter()
                .filter(|change| change.setting == setting)
                .count(),
            1
        );
    }
}

#[test]
fn policy_enforcement_duplicate_permissive_removal_keeps_capture_blocked() {
    let mut original = request();
    original.policy.capabilities = vec!["permissiveLearningMode".into()];
    original.policy.capture_denials = Some(wxc_common::models::CaptureDenialsConfig {
        mode: CaptureDenialsMode::Allow,
        ..Default::default()
    });
    let failure = batch(vec![
        capability_failure("permissivelearningmode", class::ENFORCEMENT_MODE),
        capability_failure("permissivelearningmode", class::ENFORCEMENT_MODE),
    ]);
    let (candidate, changes) = plan_repair(&original, &failure, &resolve).unwrap();
    assert_eq!(
        candidate.policy.capture_denials.unwrap().mode,
        CaptureDenialsMode::Block
    );
    assert_eq!(candidate.policy.capabilities, ["learningModeLogging"]);
    assert_eq!(
        changes
            .iter()
            .filter(|change| change.setting == "/processContainer/capabilities")
            .count(),
        1
    );
}

#[test]
fn policy_enforcement_mixed_batch_keeps_each_supported_tightening() {
    let mut original = request();
    original.policy.network_egress = Some(NetworkEgressPolicy {
        default: NetworkAction::Allow,
        ..Default::default()
    });
    original.policy.ui.disable = false;
    let lockdown = with_detail(NativePolicyDetail {
        failure_class: PolicyResultCode::new(class::WIN32K, None),
        failure_reason: PolicyResultCode::new(reason::WIN32K_REQUIRED, None),
        required_action: PolicyResultCode::new(action::ENABLE_WIN32K_LOCKDOWN, None),
        value_kind: PolicyResultCode::new(value::BOOLEAN, None),
        flags: HAS_ACTIONABLE_DETAILS,
        required_value: 1,
        ..Default::default()
    });
    let result = batch(vec![
        capability_failure("internetclient", class::NETWORK),
        path_failure("C:\\work\\private", 2, 0),
        lockdown,
    ]);
    let (candidate, changes) = plan_repair(&original, &result, &resolve).unwrap();
    assert_eq!(
        candidate.policy.network_egress.unwrap().default,
        NetworkAction::Deny
    );
    assert_eq!(candidate.policy.denied_paths, ["C:\\work\\private"]);
    assert!(candidate.policy.ui.disable);
    assert!(changes.iter().any(|change| change.setting == "/ui/disable"));
}

#[test]
fn policy_enforcement_batch_preserves_explicit_child_grants_and_rejects_false_witnesses() {
    let mut original = request();
    original
        .policy
        .readwrite_paths
        .push("C:\\work\\allowed".into());
    let failure = batch(vec![
        path_failure("C:\\work", 2, 1),
        path_failure("C:\\work\\private", 2, 0),
    ]);
    let (candidate, _) = plan_repair(&original, &failure, &resolve).unwrap();
    assert_eq!(access_at(&candidate.policy, "C:\\work\\allowed"), 2);
    assert_eq!(access_at(&candidate.policy, "C:\\work\\other"), 1);
    assert_eq!(access_at(&candidate.policy, "C:\\work\\private"), 0);
    let invalid = batch(vec![
        path_failure("C:\\work", 2, 1),
        path_failure("C:\\work\\private", 1, 0),
    ]);
    assert!(plan_repair(&original, &invalid, &resolve).is_err());
}

fn journal_size_for_paths(paths: &[String]) -> usize {
    let mut candidate = request();
    paths
        .iter()
        .map(|path| {
            let (next, changes) =
                plan_repair(&candidate, &path_failure(path, 2, 0), &resolve).unwrap();
            candidate = next;
            serde_json::to_vec(&changes).unwrap().len()
        })
        .sum()
}

#[test]
fn policy_enforcement_journal_accepts_exact_limit_and_refuses_unreported_overflow() {
    let paths_with_length = |length: usize| -> Vec<String> {
        (0..6)
            .map(|index| {
                let mut path = "C:\\work".to_string();
                let segment = "a".repeat(180);
                while path.len() + segment.len() + 8 < length {
                    path.push('\\');
                    path.push_str(&segment);
                }
                path.push('\\');
                path.push(char::from(b'0' + index));
                path.push_str(&"x".repeat(length - path.len()));
                path
            })
            .collect()
    };
    let (mut low, mut high): (usize, usize) = (20_000, 32_000);
    while low < high {
        let middle = (low + high).div_ceil(2);
        if journal_size_for_paths(&paths_with_length(middle)) <= MAX_CHANGE_HISTORY_BYTES {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    let mut paths = paths_with_length(low);
    let remaining = MAX_CHANGE_HISTORY_BYTES - journal_size_for_paths(&paths);
    // The first path occurs eleven times across six before/after entries;
    // the last occurs once. Adjust valid leaf names to hit the exact byte bound.
    paths[0].push_str(&"x".repeat(remaining / 11));
    paths[5].push_str(&"x".repeat(remaining % 11));
    assert_eq!(journal_size_for_paths(&paths), MAX_CHANGE_HISTORY_BYTES);
    assert!(paths.iter().all(|path| {
        path.encode_utf16().count() < crate::secenv_policy::MAX_RESOURCE_CHARS
            && path.rsplit('\\').next().unwrap().len() <= 255
    }));

    let failures: Vec<_> = paths
        .iter()
        .map(|path| (E_FAIL, path_failure(path, 2, 0)))
        .collect();
    let mut api = FakeApi::new(
        failures
            .iter()
            .cloned()
            .chain([(S_OK, result(2))])
            .collect(),
    );
    let created = run(&mut request(), &mut api).unwrap();
    assert_eq!(api.calls, 7);
    let stored: usize = created
        .report
        .as_ref()
        .unwrap()
        .attempts
        .iter()
        .filter(|attempt| !attempt.changes.is_empty())
        .map(|attempt| serde_json::to_vec(&attempt.changes).unwrap().len())
        .sum();
    assert_eq!(stored, MAX_CHANGE_HISTORY_BYTES);
    drop(created);

    let mut candidate = request();
    let mut api = FakeApi::new(
        failures
            .into_iter()
            .chain([
                (E_FAIL, path_failure("C:\\work\\overflow", 2, 0)),
                (S_OK, result(2)),
            ])
            .collect(),
    );
    let result = run(&mut candidate, &mut api);
    assert!(
        result.is_err(),
        "journal overflow must stop before accepting another candidate"
    );
    let report = report(result.err().unwrap());
    assert_eq!(
        report.termination,
        PolicyEnforcementTermination::Unrepairable
    );
    assert!(report.message.as_ref().unwrap().contains("journal"));
    assert_eq!(api.calls, 7);
    assert!(
        candidate.policy.denied_paths == paths,
        "overflow must not change the candidate"
    );
    assert!(report.attempts.last().unwrap().changes.is_empty());
    assert_eq!(report.effective_policy_hash, policy_hash(&candidate));
    assert!(!report.environment_created);
}

fn capability_failure(name: &str, class: u32) -> NativePolicyResult {
    let chars = name.encode_utf16().count() as u32 + 1;
    with_detail(NativePolicyDetail {
        failure_class: PolicyResultCode::new(class, None),
        failure_reason: PolicyResultCode::new(1, None),
        required_action: PolicyResultCode::new(1, None),
        resource_kind: PolicyResultCode::new(2, None),
        resource: Some(name.into()),
        resource_chars_written: chars,
        resource_chars_required: chars,
        flags: HAS_ACTIONABLE_DETAILS | RESOURCE_COMPLETE,
        ..Default::default()
    })
}

fn request() -> ExecutionRequest {
    let mut request = ExecutionRequest {
        script_code: "must not run during negotiation".into(),
        experimental_enabled: true,
        ..Default::default()
    };
    let mut settings = PolicyEnforcementOptions::default();
    settings.mode = Some(PolicyEnforcementMode::Mutate);
    request.policy.policy_enforcement = Some(settings);
    request.policy.readwrite_paths = vec!["C:\\work".into()];
    request
}

fn resolve(path: &str) -> PathCanonical {
    PathCanonical::Canonical(path.into())
}

fn run(
    request: &mut ExecutionRequest,
    api: &mut FakeApi,
) -> Result<NegotiatedEnvironment, ScriptResponse> {
    negotiate(
        request,
        SecurityEnvironmentVersion::V1_0,
        false,
        api,
        |_| Ok(()),
        resolve,
    )
}

fn report(error: ScriptResponse) -> PolicyEnforcementReport {
    serde_json::from_value(error.error.unwrap().details.unwrap()["policyEnforcement"].clone())
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
fn policy_enforcement_peels_filesystem_failures_before_one_environment_is_returned() {
    let original = request();
    let mut candidate = original.clone();
    let mut api = FakeApi::new(vec![
        (E_FAIL, path_failure("C:\\work", 2, 1)),
        (E_FAIL, path_failure("C:\\work\\private", 1, 0)),
        (S_OK, result(2)),
    ]);
    let created = run(&mut candidate, &mut api).unwrap();
    assert_eq!(api.calls, 3);
    assert_eq!(api.legacy_calls, 0);
    assert_eq!(original.policy.readwrite_paths, ["C:\\work"]);
    assert!(candidate.policy.readwrite_paths.is_empty());
    assert_eq!(candidate.policy.readonly_paths, ["C:\\work"]);
    assert_eq!(candidate.policy.denied_paths, ["C:\\work\\private"]);
    let report = created.report.as_ref().unwrap();
    assert_eq!(report.termination, PolicyEnforcementTermination::Created);
    assert_eq!(report.attempts.len(), 3);
    assert!(!report.attempts[0].changes.is_empty());
    assert!(!report.attempts[1].changes.is_empty());
    assert!(report.attempts[2].changes.is_empty());
    assert_ne!(report.original_policy_hash, report.effective_policy_hash);
    assert_eq!(api.closed.load(Ordering::SeqCst), 0);
    drop(created);
    assert_eq!(api.closed.load(Ordering::SeqCst), 1);
}

#[test]
fn policy_enforcement_passthrough_preserves_the_first_refusal_without_editing() {
    let mut request = request();
    request.policy.policy_enforcement = Some(PolicyEnforcementOptions::default());
    request.experimental_enabled = false;
    let before = policy_hash(&request);
    let mut api = FakeApi::new(vec![(E_FAIL, path_failure("C:\\work", 2, 1))]);
    let error = run(&mut request, &mut api).unwrap_err();
    assert_eq!(error.failure_phase, FailurePhase::Rejected);
    assert_eq!(
        error.error.as_ref().unwrap().operation.as_deref(),
        Some("CreateProcessSecurityEnvironment2")
    );
    assert_eq!(
        error.error.as_ref().unwrap().native_code.as_deref(),
        Some("0x80004005")
    );
    assert_eq!(policy_hash(&request), before);
    let report = report(error);
    assert_eq!(report.termination, PolicyEnforcementTermination::Rejected);
    assert!(report.attempts[0].changes.is_empty());
    assert_eq!(api.calls, 1);
}

#[test]
fn policy_enforcement_omitted_controls_never_query_or_report() {
    for available in [false, true] {
        for availability_error in [None, Some(E_FAIL.0)] {
            let mut request = request();
            request.policy.policy_enforcement = None;
            request.experimental_enabled = false;
            let mut api = FakeApi::new(vec![(S_OK, result(2))]);
            api.available = available;
            api.availability_error = availability_error;
            let created = run(&mut request, &mut api).unwrap();
            assert!(created.report.is_none());
            assert_eq!(api.availability_calls.get(), 0);
            assert_eq!(api.calls, 0);
            assert_eq!(api.legacy_calls, 1);
            drop(created);
            assert_eq!(api.closed.load(Ordering::SeqCst), 1);
        }
    }
}

#[test]
fn policy_enforcement_explicit_empty_controls_report_without_authorization() {
    let mut request = request();
    request.policy.policy_enforcement = Some(PolicyEnforcementOptions::default());
    request.experimental_enabled = false;
    let mut api = FakeApi::new(vec![(S_OK, result(2))]);
    let created = run(&mut request, &mut api).unwrap();
    let report = created.report.as_ref().unwrap();
    assert_eq!(report.requested_mode, PolicyEnforcementMode::PassThrough);
    assert_eq!(report.attempts.len(), 1);
    assert_eq!(api.availability_calls.get(), 1);
    assert_eq!(api.calls, 1);
    assert_eq!(api.legacy_calls, 0);
}

#[test]
fn policy_enforcement_omitted_controls_keep_legacy_creation_failures() {
    for capture in [false, true] {
        for code in [E_FAIL.0, E_NOTIMPL.0, 0x800704EC_u32 as i32] {
            let mut request = request();
            request.policy.policy_enforcement = None;
            request.policy.capture_denials =
                capture.then(wxc_common::models::CaptureDenialsConfig::default);
            let mut api = FakeApi::new(vec![]);
            api.availability_error = Some(E_FAIL.0);
            api.legacy_error = Some(code);
            let error = run(&mut request, &mut api).unwrap_err();
            let native = LearningModeError::HResultCall {
                function: "CreateProcessSecurityEnvironment",
                code,
            };
            let prefix = if capture {
                "captureDenials: failed to start learning-mode capture"
            } else {
                "failed to create the process security environment"
            };
            if code == 0x800704EC_u32 as i32 {
                assert!(error
                    .error_message
                    .starts_with(&format!("{prefix}: {native}")));
                assert!(error.error_message.contains("IT-managed policy rule"));
                assert!(error
                    .error_message
                    .contains("requested sandbox permissions"));
            } else {
                assert_eq!(error.error_message, format!("{prefix}: {native}"));
            }
            assert_eq!(error.standard_err, error.error_message);
            assert!(error.error.is_none());
            assert_eq!(
                error.failure_phase,
                if native.is_api_unavailable() {
                    FailurePhase::BackendUnavailable
                } else {
                    FailurePhase::LaunchFailed
                }
            );
            assert_eq!(api.availability_calls.get(), 0);
            assert_eq!(api.calls, 0);
            assert_eq!(api.legacy_calls, 1);
        }
    }
}

#[test]
fn policy_enforcement_attempt_limits_count_creations_not_repairs() {
    for limit in [1, 8, 64] {
        let mut request = request();
        request
            .policy
            .policy_enforcement
            .as_mut()
            .unwrap()
            .max_attempts = Some(limit);
        let mut api = FakeApi::new(
            (0..limit)
                .map(|index| {
                    (
                        E_FAIL,
                        path_failure(&format!("C:\\work\\deny{index}"), 2, 0),
                    )
                })
                .collect(),
        );
        let report = report(run(&mut request, &mut api).unwrap_err());
        assert_eq!(
            report.termination,
            PolicyEnforcementTermination::AttemptLimit
        );
        assert_eq!(api.calls, usize::from(limit));
        assert_eq!(report.attempts.len(), usize::from(limit));
        assert!(report.attempts.last().unwrap().changes.is_empty());
        assert_eq!(request.policy.denied_paths.len(), usize::from(limit - 1));
        assert_eq!(api.legacy_calls, 0);
    }
}

#[test]
fn policy_enforcement_unavailable_ignores_mutation_and_the_experimental_gate() {
    let mut request = request();
    request.experimental_enabled = false;
    let mut api = FakeApi::new(vec![]);
    api.available = false;
    let created = run(&mut request, &mut api).unwrap();
    let report = created.report.as_ref().unwrap();
    assert!(!report.mode_applied);
    assert!(report.attempts.is_empty());
    assert_eq!(
        report.availability,
        PolicyEnforcementAvailability::Unavailable
    );
    assert_eq!(api.calls, 0);
    assert_eq!(api.legacy_calls, 1);
    drop(created);
    assert_eq!(api.closed.load(Ordering::SeqCst), 1);
}

#[test]
fn policy_enforcement_capable_host_requires_authorization_before_creation() {
    let mut request = request();
    request.experimental_enabled = false;
    let mut api = FakeApi::new(vec![]);
    let report = report(run(&mut request, &mut api).unwrap_err());
    assert_eq!(report.termination, PolicyEnforcementTermination::Rejected);
    assert!(!report.mode_applied);
    assert_eq!(api.calls + api.legacy_calls, 0);
}

#[test]
fn policy_enforcement_query_failure_does_not_silently_select_legacy() {
    let mut api = FakeApi::new(vec![]);
    api.availability_error = Some(E_FAIL.0);
    let failure = run(&mut request(), &mut api).unwrap_err();
    assert_eq!(api.calls + api.legacy_calls, 0);
    let error = failure.error.unwrap();
    assert_eq!(
        error.operation.as_deref(),
        Some("QueryProcessSecurityEnvironmentSupport")
    );
    assert_eq!(error.native_code.as_deref(), Some("0x80004005"));
}

#[test]
fn policy_enforcement_reviewed_ui_and_win32k_actions_select_the_correct_repairs() {
    let mut request = request();
    request.policy.ui.disable = false;
    request.policy.ui.clipboard = ClipboardPolicy::All;
    let mut failure = with_detail(NativePolicyDetail::default());
    failure.details[0].flags = HAS_ACTIONABLE_DETAILS;
    failure.details[0].failure_class.code = 4;
    failure.details[0].failure_reason.code = 4;
    failure.details[0].required_action.code = 3;
    failure.details[0].value_kind.code = 2;
    failure.details[0].required_value = 2;
    let (candidate, changes) = plan_repair(&request, &failure, &resolve).unwrap();
    assert_eq!(candidate.policy.ui.clipboard, ClipboardPolicy::Write);
    assert!(!candidate.policy.ui.disable);
    assert!(!changes.is_empty());

    failure.details[0].failure_class.code = 5;
    failure.details[0].failure_reason.code = 5;
    failure.details[0].required_action.code = 4;
    failure.details[0].value_kind.code = 3;
    failure.details[0].required_value = 1;
    let (candidate, changes) = plan_repair(&request, &failure, &resolve).unwrap();
    assert!(candidate.policy.ui.disable);
    assert!(!changes.is_empty());

    // A pre-review bitmask code is not a boolean lockdown instruction.
    failure.details[0].value_kind.code = 4;
    assert!(plan_repair(&request, &failure, &resolve).is_err());
}

#[test]
fn policy_enforcement_only_initial_decision_free_notimpl_can_use_legacy() {
    let mut request = request();
    let mut api = FakeApi::new(vec![(E_NOTIMPL, result(0))]);
    let created = run(&mut request, &mut api).unwrap();
    assert_eq!(api.legacy_calls, 1);
    let unavailable = created.report.as_ref().unwrap();
    assert!(!unavailable.mode_applied);
    assert_eq!(
        unavailable.availability,
        PolicyEnforcementAvailability::Unavailable
    );
    assert_eq!(unavailable.attempts.len(), 1);
    assert_eq!(unavailable.attempts[0].result.outcome.code, 0);
    assert_eq!(unavailable.attempts[0].hresult, "0x80004001");
    drop(created);

    let mut api = FakeApi::new(vec![
        (E_FAIL, path_failure("C:\\work", 2, 1)),
        (E_NOTIMPL, result(0)),
    ]);
    let report = report(run(&mut request, &mut api).unwrap_err());
    assert_eq!(
        report.termination,
        PolicyEnforcementTermination::NativeFailure
    );
    assert_eq!(api.calls, 2);
    assert_eq!(api.legacy_calls, 0);
}

#[test]
fn policy_enforcement_reported_legacy_denial_keeps_basic_guidance() {
    for unavailable_before_call in [true, false] {
        let mut api = FakeApi::new(vec![(E_NOTIMPL, result(0))]);
        api.available = !unavailable_before_call;
        api.legacy_error = Some(0x800704EC_u32 as i32);
        let error = run(&mut request(), &mut api).unwrap_err();
        assert!(error.error_message.contains("IT-managed policy rule"));
        assert!(error
            .error_message
            .contains("requested sandbox permissions"));
        assert!(error.error_message.contains("system administrator"));
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
        assert!(!report.mode_applied);
        assert_eq!(api.legacy_calls, 1);
        assert_eq!(api.calls, usize::from(!unavailable_before_call));
    }
}

#[test]
fn policy_enforcement_empty_block_is_not_repairable_or_a_fallback() {
    for mode in [
        PolicyEnforcementMode::PassThrough,
        PolicyEnforcementMode::Mutate,
    ] {
        let mut candidate = request();
        candidate.policy.policy_enforcement.as_mut().unwrap().mode = Some(mode);
        let before = policy_hash(&candidate);
        let mut api = FakeApi::new(vec![(E_FAIL, result(outcome::BLOCKED))]);
        let report = report(run(&mut candidate, &mut api).unwrap_err());
        assert_eq!(api.calls, 1);
        assert_eq!(api.legacy_calls, 0);
        assert_eq!(policy_hash(&candidate), before);
        assert!(report.attempts[0].result.details.is_empty());
        assert!(report.attempts[0].changes.is_empty());
        assert_eq!(
            report.termination,
            if mode == PolicyEnforcementMode::PassThrough {
                PolicyEnforcementTermination::Rejected
            } else {
                PolicyEnforcementTermination::Unrepairable
            }
        );
    }
}

#[test]
fn policy_enforcement_invalid_batch_retains_details_and_closes_an_unexpected_handle() {
    let mut failure = batch(vec![
        path_failure("C:\\work\\a", 2, 0),
        path_failure("C:\\work\\b", 2, 0),
    ]);
    failure.resource_chars_required = u32::MAX;
    let mut api = FakeApi::new(vec![(E_NOTIMPL, failure)]);
    api.invalid_result = Some("invalid resource counts");
    api.failure_handle = true;
    let report = report(run(&mut request(), &mut api).unwrap_err());
    assert_eq!(
        report.termination,
        PolicyEnforcementTermination::InvalidResult
    );
    assert_eq!(report.attempts[0].result.details.len(), 2);
    assert!(report.attempts[0].changes.is_empty());
    assert_eq!(api.calls, 1);
    assert_eq!(api.legacy_calls, 0);
    assert_eq!(api.closed.load(Ordering::SeqCst), 1);
}

#[test]
fn policy_enforcement_provisioning_and_evaluation_errors_do_not_retry() {
    for outcome in [0, 1, 2, 4, 999] {
        let mut api = FakeApi::new(vec![(E_FAIL, result(outcome))]);
        let report = report(run(&mut request(), &mut api).unwrap_err());
        assert_eq!(report.attempts[0].result.outcome.code, outcome);
        assert_eq!(api.calls, 1);
        assert_eq!(api.legacy_calls, 0);
    }
    let mut api = FakeApi::new(vec![(E_NOTIMPL, result(2))]);
    assert!(run(&mut request(), &mut api).is_err());
    assert_eq!(api.legacy_calls, 0);
}

#[test]
fn policy_enforcement_inconsistent_handles_are_closed_and_rejected() {
    let mut api = FakeApi::new(vec![(E_FAIL, result(3))]);
    api.failure_handle = true;
    let failure = report(run(&mut request(), &mut api).unwrap_err());
    assert_eq!(
        failure.termination,
        PolicyEnforcementTermination::InvalidResult
    );
    assert_eq!(api.closed.load(Ordering::SeqCst), 1);
    let mut api = FakeApi::new(vec![(S_OK, result(2))]);
    api.omit_handle = true;
    assert_eq!(
        report(run(&mut request(), &mut api).unwrap_err()).termination,
        PolicyEnforcementTermination::InvalidResult
    );
}

#[test]
fn policy_enforcement_repeated_ineffective_repairs_stop() {
    let mut request = request();
    let failure = path_failure("C:\\work", 2, 1);
    let mut api = FakeApi::new(vec![(E_FAIL, failure.clone()), (E_FAIL, failure)]);
    let report = report(run(&mut request, &mut api).unwrap_err());
    assert_eq!(report.termination, PolicyEnforcementTermination::NoProgress);
    assert_eq!(api.calls, 2);
}

#[test]
fn policy_enforcement_unknown_or_incomplete_details_never_drive_repairs() {
    for flags in [
        0,
        HAS_ACTIONABLE_DETAILS | RESOURCE_UNAVAILABLE,
        HAS_ACTIONABLE_DETAILS | BUFFER_TOO_SMALL,
        HAS_ACTIONABLE_DETAILS | DETAILS_UNREPRESENTABLE,
        HAS_ACTIONABLE_DETAILS | RESOURCE_COMPLETE | 0x8000,
    ] {
        let mut failure = path_failure("C:\\work", 2, 1);
        failure.details[0].flags = flags;
        assert!(plan_repair(&request(), &failure, &resolve).is_err());
    }
    let mut failure = path_failure("C:\\work", 2, 1);
    failure.details[0].required_action.code = 999;
    assert!(plan_repair(&request(), &failure, &resolve).is_err());
}

#[test]
fn policy_enforcement_network_repairs_edit_the_sources_of_synthesized_capabilities() {
    let mut request = request();
    request.policy.network_egress = Some(NetworkEgressPolicy {
        default: NetworkAction::Allow,
        ..Default::default()
    });
    request.policy.network_ingress = Some(NetworkIngressPolicy {
        default: NetworkAction::Allow,
        host_loopback: NetworkAction::Allow,
    });
    let (request, _) =
        plan_repair(&request, &capability_failure("internetclient", 1), &resolve).unwrap();
    assert_eq!(
        request.policy.network_egress.as_ref().unwrap().default,
        NetworkAction::Deny
    );
    let (request, _) = plan_repair(
        &request,
        &capability_failure("privatenetworkclientserver", 1),
        &resolve,
    )
    .unwrap();
    assert_eq!(
        request.policy.network_ingress.as_ref().unwrap().default,
        NetworkAction::Deny
    );
    assert_eq!(
        request
            .policy
            .network_ingress
            .as_ref()
            .unwrap()
            .host_loopback,
        NetworkAction::Allow
    );
    let (request, _) = plan_repair(
        &request,
        &capability_failure("networkloopback", 1),
        &resolve,
    )
    .unwrap();
    assert_eq!(
        request
            .policy
            .network_ingress
            .as_ref()
            .unwrap()
            .host_loopback,
        NetworkAction::Deny
    );
}

#[test]
fn policy_enforcement_proxy_removal_stays_restricted_if_the_next_policy_allows() {
    use wxc_common::models::{ProxyAddress, ProxyConfig};

    let mut candidate = request();
    candidate.policy.network_egress = Some(NetworkEgressPolicy::default());
    candidate.policy.network_ingress = Some(NetworkIngressPolicy {
        default: NetworkAction::Allow,
        host_loopback: NetworkAction::Allow,
    });
    candidate.policy.network_proxy = ProxyConfig {
        address: Some(ProxyAddress::new("127.0.0.1".into(), 49381)),
        builtin_test_server: false,
    };
    candidate.policy.runtime_network_proxy_specified = true;
    let original = candidate.clone();
    let mut api = FakeApi::new(vec![
        (E_FAIL, capability_failure("privatenetworkclientserver", 1)),
        (S_OK, result(2)),
    ]);

    let created = negotiate(
        &mut candidate,
        SecurityEnvironmentVersion::V1_1,
        true,
        &mut api,
        |_| Ok(()),
        resolve,
    )
    .unwrap();
    assert_eq!(api.calls, 2);
    assert!(!candidate.policy.network_proxy.is_enabled());
    assert_eq!(
        candidate
            .policy
            .network_ingress
            .as_ref()
            .unwrap()
            .host_loopback,
        NetworkAction::Deny,
        "removing endpoint-scoped proxy rules must not expose unrelated loopback ports"
    );
    assert_eq!(
        candidate.policy.network_egress.as_ref().unwrap().default,
        NetworkAction::Deny
    );
    assert!(original.policy.network_proxy.is_enabled());
    let changes = &created.report.as_ref().unwrap().attempts[0].changes;
    assert!(changes.iter().any(|change| {
        change.setting == "/network/ingress/hostLoopback"
            && change.before == serde_json::json!("allow")
            && change.after == serde_json::json!("deny")
    }));
    drop(created);
    assert_eq!(api.closed.load(Ordering::SeqCst), 1);
}

#[test]
fn policy_enforcement_capture_tightening_preserves_recording() {
    let mut request = request();
    request
        .policy
        .capabilities
        .push("permissiveLearningMode".into());
    request.policy.capture_denials = Some(wxc_common::models::CaptureDenialsConfig {
        mode: CaptureDenialsMode::Allow,
        retain_etl: true,
        ..Default::default()
    });
    let (candidate, changes) = plan_repair(
        &request,
        &capability_failure("permissivelearningmode", 3),
        &resolve,
    )
    .unwrap();
    let capture = candidate.policy.capture_denials.unwrap();
    assert_eq!(capture.mode, CaptureDenialsMode::Block);
    assert!(capture.retain_etl);
    assert_eq!(candidate.policy.capabilities, ["learningModeLogging"]);
    assert!(changes
        .iter()
        .any(|change| change.setting == "/processContainer/captureDenials/mode"));
}

#[test]
fn policy_enforcement_readonly_repair_does_not_introduce_a_new_grant_name() {
    let original = request();
    assert!(
        plan_repair(
            &original,
            &path_failure("C:\\work\\limited", 2, 1),
            &resolve
        )
        .is_err(),
        "a new RO name could be redirected outside the original RW root before retry"
    );
}

#[test]
fn policy_enforcement_readonly_repair_preserves_the_authored_grant_spelling() {
    let mut original = request();
    original.policy.readwrite_paths = vec!["C:\\Work\\Limited\\".into()];
    let (candidate, _) = plan_repair(
        &original,
        &path_failure("c:\\work\\limited", 2, 1),
        &resolve,
    )
    .unwrap();
    assert_eq!(candidate.policy.readonly_paths, ["C:\\Work\\Limited\\"]);
    assert!(candidate.policy.readwrite_paths.is_empty());
}

#[test]
fn policy_enforcement_fs_overlays_preserve_nested_restrictions_and_other_grants() {
    let mut request = request();
    request.policy.readonly_paths = vec!["C:\\work\\reference".into()];
    request.policy.denied_paths = vec!["C:\\work\\reference\\secret".into()];
    request.policy.readwrite_paths.push("C:\\other".into());
    let (candidate, _) = plan_repair(&request, &path_failure("C:\\work", 2, 1), &resolve).unwrap();
    for point in [
        "C:\\work",
        "C:\\work\\reference",
        "C:\\work\\reference\\secret",
        "C:\\work\\reference\\secret\\child",
        "C:\\other",
    ] {
        assert!(access_at(&candidate.policy, point) <= access_at(&request.policy, point));
    }
    assert_eq!(access_at(&candidate.policy, "C:\\other"), 2);
}

#[test]
fn policy_enforcement_readonly_drive_root_can_be_denied_without_losing_child_grants() {
    let mut original = request();
    original.policy.readwrite_paths.clear();
    original.policy.readonly_paths = vec!["C:\\".into(), "C:\\work\\allowed".into()];
    let (candidate, _) = plan_repair(&original, &path_failure("C:\\", 1, 0), &resolve)
        .expect("a root witness remains an absolute path");
    assert_eq!(candidate.policy.denied_paths, ["C:\\"]);
    assert_eq!(candidate.policy.readonly_paths, ["C:\\work\\allowed"]);
    assert_eq!(access_at(&candidate.policy, "C:\\other"), 0);
    assert_eq!(access_at(&candidate.policy, "C:\\work\\allowed\\file"), 1);
}

#[test]
fn policy_enforcement_fs_aliases_are_not_guessed() {
    let request = request();
    assert!(
        plan_repair(&request, &path_failure("C:\\work", 2, 1), &|_| {
            PathCanonical::Canonical("D:\\different".into())
        })
        .is_err()
    );
    assert!(
        plan_repair(&request, &path_failure("C:\\work", 2, 1), &|_| {
            PathCanonical::Unknown
        })
        .is_err()
    );
}

fn assert_root_write_repair_rejected(path: &str) {
    let mut root = request();
    root.policy.readwrite_paths = vec![path.into()];
    let result = plan_repair(&root, &path_failure(path, 2, 1), &resolve);
    assert!(result.is_err(), "root-write downgrade must be refused");
    let error = result.err().unwrap();
    assert!(error.contains("volume/share-root write grants"), "{error}");
}

#[test]
fn policy_enforcement_drive_root_write_repair_is_refused() {
    assert_root_write_repair_rejected("C:\\");
}

#[test]
fn policy_enforcement_share_root_write_repair_is_refused() {
    assert_root_write_repair_rejected("\\\\server\\share");
}

#[test]
fn policy_enforcement_path_count_only_deduplicates_within_the_same_list() {
    let mut failure = with_detail(NativePolicyDetail::default());
    failure.details[0].failure_class.code = 2;
    failure.details[0].failure_reason.code = 6;
    failure.details[0].required_action.code = 5;
    failure.details[0].value_kind.code = 4;
    failure.details[0].flags = HAS_ACTIONABLE_DETAILS;
    failure.details[0].requested_value = 1001;
    failure.details[0].required_value = 1000;
    let mut request = request();
    request.policy.readwrite_paths = vec!["C:\\work".into(); 1001];
    let (candidate, _) = plan_repair(&request, &failure, &resolve).unwrap();
    assert_eq!(candidate.policy.readwrite_paths, ["C:\\work"]);

    request.policy.readwrite_paths = vec!["C:\\work".into()];
    request.policy.readonly_paths = vec!["C:\\work\\reference".into()];
    failure.details[0].required_value = 1;
    assert!(plan_repair(&request, &failure, &resolve).is_err());
    assert_eq!(access_at(&request.policy, "C:\\work\\reference"), 1);
}

#[test]
fn policy_enforcement_ui_repairs_union_bits_instead_of_replacing_restrictions() {
    for previous in [0, 1, 2, 4, 0x20, 0x40, 0x100, 0x200, 0x3ff] {
        let mut request = request();
        request.policy.ui.disable = false;
        request.policy.ui.clipboard = ClipboardPolicy::All;
        request.policy.ui.injection = true;
        request.policy.base_process_ui.isolation = "desktop".into();
        request.policy.base_process_ui.desktop_system_control = true;
        request.policy.base_process_ui.system_settings = "all".into();
        request.policy.base_process_ui.ime = true;
        if previous != 0 {
            apply_ui_restrictions(&mut request.policy, previous, &mut Vec::new()).unwrap();
        }
        for required in [1, 2, 4, 0x10, 0x20, 0x40, 0x100, 0x200, 0x3ff] {
            let mut policy = request.policy.clone();
            apply_ui_restrictions(&mut policy, required, &mut Vec::new()).unwrap();
            let mask = u64::from(crate::job_object::to_job_object_uilimit_mask(
                &wxc_common::ui_policy::resolve_ui_restrictions(
                    &policy.ui,
                    &policy.base_process_ui,
                ),
            ));
            assert_eq!(mask & (previous | required), previous | required);
        }
    }
    assert!(apply_ui_restrictions(&mut request().policy, 0x400, &mut Vec::new()).is_err());
}
