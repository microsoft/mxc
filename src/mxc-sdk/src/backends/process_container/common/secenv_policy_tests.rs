// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use std::cell::{Cell, RefCell};
use windows::Win32::Foundation::{E_FAIL, E_INVALIDARG, E_NOTIMPL, E_UNEXPECTED, S_OK};

const POLICY_DENIED: HRESULT = HRESULT(0x800704ec_u32 as i32);
const NO_SNAPSHOT: HRESULT = HRESULT(0x80070490_u32 as i32);
const SHORT_BUFFER: HRESULT = HRESULT(0x8007007a_u32 as i32);

struct FakeState {
    creation_result: HRESULT,
    creation_handle: bool,
    retrieval_result: HRESULT,
    outcome: u32,
    details_count: u32,
    snapshot: Option<(u32, u32)>,
    capture_snapshot: bool,
    invalid_header: bool,
    invalid_pool: bool,
    support: u32,
    support_result: HRESULT,
    calls: Vec<&'static str>,
    threads: Vec<std::thread::ThreadId>,
    inputs: Vec<(Vec<u8>, u32)>,
    contracts: Vec<(u32, u32, u32, u32)>,
    closes: usize,
}

impl Default for FakeState {
    fn default() -> Self {
        Self {
            creation_result: POLICY_DENIED,
            creation_handle: false,
            retrieval_result: S_OK,
            outcome: 1,
            details_count: 2,
            snapshot: None,
            capture_snapshot: true,
            invalid_header: false,
            invalid_pool: false,
            support: 0x10,
            support_result: S_OK,
            calls: Vec::new(),
            threads: Vec::new(),
            inputs: Vec::new(),
            contracts: Vec::new(),
            closes: 0,
        }
    }
}

thread_local! {
    static STATE: RefCell<FakeState> = RefCell::new(FakeState::default());
    static INJECTED_API: Cell<Option<SecurityEnvironmentApi>> = const { Cell::new(None) };
}

pub(super) fn injected_api() -> Option<SecurityEnvironmentApi> {
    INJECTED_API.with(Cell::get)
}

struct ApiScope(Option<SecurityEnvironmentApi>);

impl ApiScope {
    fn new(api: SecurityEnvironmentApi) -> Self {
        Self(INJECTED_API.with(|slot| slot.replace(Some(api))))
    }
}

impl Drop for ApiScope {
    fn drop(&mut self) {
        INJECTED_API.with(|slot| slot.set(self.0));
    }
}

fn reset() -> SecurityEnvironmentApi {
    STATE.with(|state| *state.borrow_mut() = FakeState::default());
    let mut api = SecurityEnvironmentApi::from_raw_parts(create, query, close);
    api.get_last_policy_result = Some(get_policy_result);
    api
}

fn calls() -> Vec<&'static str> {
    STATE.with(|state| state.borrow().calls.clone())
}

fn closes() -> usize {
    STATE.with(|state| state.borrow().closes)
}

unsafe extern "system" fn query(flags: *mut u32) -> HRESULT {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.calls.push("support");
        if state.support_result.is_ok() {
            unsafe { *flags = state.support };
        }
        state.support_result
    })
}

unsafe extern "system" fn create(
    specification: *const c_void,
    size: u32,
    flags: u32,
    out: *mut HANDLE,
) -> HRESULT {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.snapshot = None;
        state.calls.push("create");
        state.threads.push(std::thread::current().id());
        let specification =
            unsafe { std::slice::from_raw_parts(specification.cast(), size as usize) };
        state.inputs.push((specification.to_vec(), flags));
        if state.creation_handle {
            unsafe { *out = HANDLE(std::ptr::dangling_mut()) };
        }
        if state.capture_snapshot
            && state.creation_result == POLICY_DENIED
            && matches!(state.outcome, 1 | 2)
        {
            state.snapshot = Some((state.outcome, state.details_count));
        }
        state.creation_result
    })
}

unsafe extern "system" fn get_policy_result(result: *mut RawPolicyResult) -> HRESULT {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.calls.push("get_policy_result");
        state.threads.push(std::thread::current().id());
        let result = unsafe { &mut *result };
        state.contracts.push((
            result.size,
            result.version,
            result.details_capacity,
            result.resource_capacity_chars,
        ));
        let header_size = if cfg!(target_pointer_width = "64") {
            48
        } else {
            40
        };
        if result.size < header_size
            || result.version != 1
            || result.details_capacity > 64
            || result.resource_capacity_chars > 32768
            || (result.details_capacity != 0 && result.details.is_null())
            || (result.resource_capacity_chars != 0 && result.resource_buffer.is_null())
        {
            return E_INVALIDARG;
        }
        result.outcome = 0;
        result.details_count = 0;
        result.resource_chars_written = 0;
        result.resource_chars_required = 0;
        let Some((outcome, count)) = state.snapshot else {
            return NO_SNAPSHOT;
        };
        result.outcome = outcome;
        result.details_count = count;
        result.resource_chars_required = if count == 2 { 14 } else { 0 };
        if state.retrieval_result.is_err() {
            return state.retrieval_result;
        }
        if result.details_capacity < count
            || result.resource_capacity_chars < result.resource_chars_required
        {
            return SHORT_BUFFER;
        }
        if count == 2 {
            let storage: Vec<u16> = "C:\\one\0C:\\two\0".encode_utf16().collect();
            unsafe {
                std::ptr::copy_nonoverlapping(
                    storage.as_ptr(),
                    result.resource_buffer,
                    storage.len(),
                );
                for index in 0..2 {
                    *result.details.add(index) = RawPolicyDetail {
                        failure_class: 2,
                        failure_reason: 3,
                        required_action: 2,
                        resource_kind: 1,
                        value_kind: 1,
                        flags: 3,
                        requested_value: 2,
                        required_value: 0,
                        resource_offset_chars: (index * 7) as u32,
                        resource_chars_written: 7,
                        resource_chars_required: 7,
                    };
                }
            }
            result.resource_chars_written = storage.len() as u32;
        }
        if state.invalid_header {
            result.version = 99;
        }
        if state.invalid_pool {
            result.resource_buffer = std::ptr::null_mut();
        }
        state.retrieval_result
    })
}

unsafe extern "system" fn close(_: HANDLE) {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.calls.push("close");
        state.closes += 1;
        // Detect retrieval deferred past native cleanup that could reenter CPSE.
        state.snapshot = None;
    });
}

#[test]
fn reports_each_action_from_the_failed_creation_on_the_same_thread() {
    let api = reset();
    let specification = b"unchanged PSEC specification";
    let error = api.create_with_diagnostics(specification, 7).unwrap_err();
    let message = error.message(false);
    assert!(message.starts_with("failed to create the process security environment:"));
    assert!(message.contains("CreateProcessSecurityEnvironment failed"));
    assert!(message.contains("0x800704EC"));
    assert!(message.contains("IT-managed policy rule"));
    assert!(message.contains("Windows creation-policy outcome: blocked (1)"));
    assert!(message.contains("Returned constraints: 2 (non-exhaustive"));
    assert!(message.contains("Resource 1: \"C:\\\\one\""));
    assert!(message.contains("Resource 2: \"C:\\\\two\""));
    assert!(!error.is_api_unavailable());
    assert_eq!(calls(), ["create", "get_policy_result"]);
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.inputs, [(specification.to_vec(), 7)]);
        assert_eq!(state.threads, vec![std::thread::current().id(); 2]);
    });
    assert_eq!(closes(), 0);
}

#[test]
fn getter_export_is_optional_and_legacy_denial_text_is_unchanged_when_absent() {
    let mut api = reset();
    assert_eq!(
        POLICY_RESULT_NAME.to_bytes(),
        b"GetLastProcessSecurityEnvironmentPolicyResult"
    );
    api.get_last_policy_result = None;
    let error = api.create_with_diagnostics(b"spec", 0).unwrap_err();
    assert_eq!(calls(), ["create"]);
    for capture in [false, true] {
        assert_eq!(
            error.message(capture),
            crate::process_container_common::launch_diagnostics::security_environment_failure_message(&error.cause, capture)
        );
    }
}

#[test]
fn diagnostic_retrieval_never_requires_a_support_query() {
    for support in [0, 1, 0x0f, 0x10, 0x1f, 0x20] {
        let api = reset();
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.support = support;
            state.support_result = E_FAIL;
        });
        let error = api.create_with_diagnostics(b"spec", 0).unwrap_err();
        assert!(error.message(false).contains("blocked (1)"));
        assert_eq!(calls(), ["create", "get_policy_result"]);
    }
}

#[test]
fn retrieval_supplies_the_exact_native_v1_header_and_maximum_capacities() {
    let api = reset();
    let error = api.create_with_diagnostics(b"spec", 0).unwrap_err();
    assert!(
        matches!(error.cause, LearningModeError::HResultCall { code, .. } if code == POLICY_DENIED.0)
    );
    let size = if cfg!(target_pointer_width = "64") {
        48
    } else {
        40
    };
    STATE.with(|state| assert_eq!(state.borrow().contracts, [(size, 1, 64, 32768)]));
}

#[test]
fn successful_creation_does_not_retrieve_a_policy_snapshot() {
    let api = reset();
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.snapshot = Some((1, 2));
        state.creation_result = S_OK;
        state.creation_handle = true;
        state.retrieval_result = E_FAIL;
    });
    let environment = api.create_with_diagnostics(b"spec", 0).unwrap();
    assert_eq!(calls(), ["create"]);
    STATE.with(|state| assert!(state.borrow().snapshot.is_none()));
    assert_eq!(closes(), 0);
    drop(environment);
    assert_eq!(closes(), 1);
}

#[test]
fn non_policy_failures_never_read_a_snapshot_or_change_the_original_error() {
    for status in [
        E_FAIL,
        E_INVALIDARG,
        E_NOTIMPL,
        HRESULT(1260),
        HRESULT(0x80070005_u32 as i32),
    ] {
        let api = reset();
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.snapshot = Some((1, 2));
            state.creation_result = status;
        });
        let error = api.create_with_diagnostics(b"spec", 0).unwrap_err();
        let expected = if status.is_ok() { E_UNEXPECTED } else { status };
        assert!(matches!(error.cause, LearningModeError::HResultCall {
            function: "CreateProcessSecurityEnvironment", code,
        } if code == expected.0));
        assert_eq!(calls(), ["create"]);
        assert_eq!(error.is_api_unavailable(), status == E_NOTIMPL);
        assert!(error.diagnostic.is_none());
        STATE.with(|state| assert!(state.borrow().snapshot.is_none()));
    }
}

#[test]
fn retrieval_failures_cannot_mask_the_original_policy_denial_or_trigger_a_retry() {
    for status in [NO_SNAPSHOT, SHORT_BUFFER, E_FAIL, E_NOTIMPL, E_INVALIDARG] {
        let api = reset();
        STATE.with(|state| state.borrow_mut().retrieval_result = status);
        let error = api.create_with_diagnostics(b"spec", 0).unwrap_err();
        let message = error.message(true);
        assert!(matches!(error.cause, LearningModeError::HResultCall {
            function: "CreateProcessSecurityEnvironment", code,
        } if code == POLICY_DENIED.0));
        assert!(!error.is_api_unavailable());
        assert!(message.contains("0x800704EC"));
        assert!(message.contains("IT-managed policy rule"));
        assert!(message.contains("GetLastProcessSecurityEnvironmentPolicyResult failed"));
        assert!(message.contains(&format!("0x{:08X}", status.0 as u32)));
        assert!(!message.contains("Returned constraints:"));
        assert!(!message.contains("Resource 1:"));
        assert_eq!(calls(), ["create", "get_policy_result"]);
        STATE.with(|state| assert_eq!(state.borrow().inputs.len(), 1));
    }
}

#[test]
fn best_effort_snapshot_absence_is_explicit_without_inventing_a_verdict() {
    let api = reset();
    STATE.with(|state| state.borrow_mut().capture_snapshot = false);
    let error = api.create_with_diagnostics(b"spec", 0).unwrap_err();
    assert!(error
        .message(false)
        .contains("No cached policy diagnostic is available."));
    assert!(!error
        .message(false)
        .contains("Windows creation-policy outcome:"));
    assert_eq!(calls(), ["create", "get_policy_result"]);
}

#[test]
fn blocked_and_evaluation_failed_use_the_refusal_only_contract() {
    for (outcome, name) in [(1, "blocked"), (2, "evaluationFailed")] {
        let api = reset();
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.outcome = outcome;
            state.details_count = 0;
        });
        let error = api.create_with_diagnostics(b"spec", 0).unwrap_err();
        let message = error.message(false);
        assert!(message.contains(&format!(
            "Windows creation-policy outcome: {name} ({outcome})."
        )));
        assert!(message.contains("No caller-action details"));
        assert!(!message.contains("action="));
        assert_eq!(calls(), ["create", "get_policy_result"]);
    }
}

#[test]
fn malformed_retrieval_does_not_change_the_denial_or_retry_creation() {
    for header in [false, true] {
        let api = reset();
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.invalid_header = header;
            state.invalid_pool = !header;
        });
        let error = api.create_with_diagnostics(b"spec", 0).unwrap_err();
        let message = error.message(false);
        assert!(message.contains("0x800704EC"));
        assert!(message.contains("diagnostics unavailable"));
        assert!(!message.contains("\"C:\\\\one\""));
        assert_eq!(calls(), ["create", "get_policy_result"]);
    }
}

#[test]
fn refusal_snapshot_is_copied_before_unexpected_handle_cleanup() {
    let api = reset();
    STATE.with(|state| state.borrow_mut().creation_handle = true);
    let error = api.create_with_diagnostics(b"spec", 0).unwrap_err();
    assert!(error.message(false).contains("Resource 2: \"C:\\\\two\""));
    assert_eq!(calls(), ["create", "get_policy_result", "close"]);
    assert_eq!(closes(), 1);
    STATE.with(|state| assert!(state.borrow().snapshot.is_none()));
}

#[test]
fn failed_non_policy_creation_closes_unexpected_handles_without_retrieval() {
    let api = reset();
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.creation_result = E_FAIL;
        state.creation_handle = true;
    });
    let error = api.create_with_diagnostics(b"spec", 0).unwrap_err();
    assert!(matches!(error.cause, LearningModeError::HResultCall { code, .. } if code == E_FAIL.0));
    assert_eq!(calls(), ["create", "close"]);
    assert_eq!(closes(), 1);
}

#[test]
fn successful_hresult_without_an_environment_is_not_a_policy_refusal() {
    let api = reset();
    STATE.with(|state| state.borrow_mut().creation_result = S_OK);
    let error = api.create_with_diagnostics(b"spec", 0).unwrap_err();
    assert!(
        matches!(error.cause, LearningModeError::HResultCall { code, .. } if code == E_UNEXPECTED.0)
    );
    assert_eq!(calls(), ["create"]);
    assert_eq!(closes(), 0);
}

#[test]
fn retrieved_text_is_owned_before_another_creation_clears_the_snapshot() {
    let api = reset();
    let error = api.create_with_diagnostics(b"denied", 0).unwrap_err();
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.creation_result = S_OK;
        state.creation_handle = true;
    });
    drop(api.create_with_diagnostics(b"allowed", 0).unwrap());
    assert!(error.message(false).contains("Resource 1: \"C:\\\\one\""));
    assert_eq!(calls(), ["create", "get_policy_result", "create", "close"]);
}

#[test]
fn snapshots_are_thread_local_and_retrieval_does_not_consume_them() {
    let api = reset();
    api.create(b"main refusal", 0).unwrap_err();
    std::thread::spawn(move || {
        assert!(
            policy_failure_diagnostic(get_policy_result).contains("No cached policy diagnostic")
        );
        let api = reset();
        STATE.with(|state| state.borrow_mut().outcome = 2);
        let error = api
            .create_with_diagnostics(b"worker refusal", 0)
            .unwrap_err();
        assert!(error.message(false).contains("evaluationFailed (2)"));
        STATE
            .with(|state| assert_eq!(state.borrow().threads, vec![std::thread::current().id(); 2]));
    })
    .join()
    .unwrap();
    let first = policy_failure_diagnostic(get_policy_result);
    let second = policy_failure_diagnostic(get_policy_result);
    assert_eq!(first, second);
    assert!(first.contains("blocked (1)"));
    assert_eq!(
        calls(),
        ["create", "get_policy_result", "get_policy_result"]
    );
}

#[test]
fn trace_errors_and_public_api_debug_preserve_their_existing_shapes() {
    let mut api = reset();
    let debug = format!("{api:?}");
    api.get_last_policy_result = None;
    assert_eq!(format!("{api:?}"), debug);
    let cause = LearningModeError::HResultCall {
        function: "StartLearningModeTrace",
        code: E_NOTIMPL.0,
    };
    let expected =
        crate::process_container_common::launch_diagnostics::security_environment_failure_message(
            &cause, true,
        );
    let error = CreationError::from(cause);
    assert_eq!(error.message(true), expected);
    assert!(error.is_api_unavailable());
}

#[test]
fn real_runner_propagates_policy_refusal_snapshots_with_and_without_capture() {
    use crate::mxc_common::logger::{Logger, Mode};
    use crate::mxc_common::models::{ExecutionRequest, FailurePhase};
    use crate::mxc_common::sandbox_process::{SandboxBackend, StdioMode};
    use crate::process_container_common::base_container_runner::BaseContainerRunner;

    let directory = tempfile::tempdir().unwrap();
    let system_root = std::env::var("SystemRoot").unwrap();
    for capture in [false, true] {
        for complete_environment in [true, false] {
            let api = reset();
            let _scope = ApiScope::new(api);
            let mut request = ExecutionRequest {
                script_code: "cmd.exe /d /c exit 0".into(),
                working_directory: directory.path().to_string_lossy().into_owned(),
                env: Some(if complete_environment {
                    vec![
                        format!("SystemRoot={system_root}"),
                        format!("LOCALAPPDATA={}", directory.path().display()),
                    ]
                } else {
                    Vec::new()
                }),
                ..Default::default()
            };
            if capture {
                request.policy.capture_denials = Some(Default::default());
            }
            let before = serde_json::to_value(&request).unwrap();
            let mut runner = BaseContainerRunner::new_for_selected_request();
            let mut logger = Logger::new(Mode::Buffer);
            let response = match runner.spawn(&request, &mut logger, StdioMode::Pipes) {
                Ok(_) => panic!("the injected refusal must not produce a live process"),
                Err(response) => response,
            };
            assert_eq!(serde_json::to_value(&request).unwrap(), before);
            assert!(response.output_metadata.is_none());
            assert_eq!(closes(), 0);
            if !complete_environment {
                assert_eq!(response.exit_code, 1);
                assert_eq!(response.failure_phase, FailurePhase::Rejected);
                assert!(response.error_message.contains("SYSTEMROOT"));
                assert!(calls().is_empty(), "preparation must fail before creation");
                continue;
            }
            assert_eq!(response.exit_code, -1, "{}", response.error_message);
            assert_eq!(response.failure_phase, FailurePhase::LaunchFailed);
            assert_eq!(response.standard_err, response.error_message);
            assert_eq!(
                response.error_message.starts_with("captureDenials:"),
                capture
            );
            assert!(response
                .error_message
                .contains("CreateProcessSecurityEnvironment failed"));
            assert!(response
                .error_message
                .contains("Returned constraints: 2 (non-exhaustive"));
            assert!(response.error_message.contains("Resource 1: \"C:\\\\one\""));
            assert!(response.error_message.contains("Resource 2: \"C:\\\\two\""));
            assert_eq!(calls(), ["create", "get_policy_result"]);
            STATE.with(|state| assert_eq!(state.borrow().inputs.len(), 1));
        }
    }
}
