// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::core_modules::process_security_environment_policy_result::experimental_process_security_environment_policy_result as layout;
use std::cell::{Cell, RefCell};
use windows::Win32::Foundation::{E_FAIL, E_INVALIDARG, E_NOTIMPL, E_UNEXPECTED, S_OK};
use windows::Win32::System::Com::CoTaskMemAlloc;

const POLICY_DENIED: HRESULT = HRESULT(0x800704ec_u32 as i32);
const NO_SNAPSHOT: HRESULT = HRESULT(0x80070490_u32 as i32);
const SHORT_BUFFER: HRESULT = HRESULT(0x8007007a_u32 as i32);

struct FakeState {
    creation_result: HRESULT,
    creation_handle: bool,
    retrieval_result: HRESULT,
    outcome: u32,
    details_count: u32,
    capability: Option<String>,
    snapshot: Option<(u32, u32)>,
    capture_snapshot: bool,
    invalid_header: bool,
    invalid_pool: bool,
    support: u32,
    support_result: HRESULT,
    calls: Vec<&'static str>,
    threads: Vec<std::thread::ThreadId>,
    inputs: Vec<(Vec<u8>, u32)>,
    contracts: Vec<u32>,
    allocations: Vec<usize>,
    frees: Vec<usize>,
    allocate_on_failure: bool,
    output_size: Option<u32>,
    null_output: bool,
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
            capability: None,
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
            allocations: Vec::new(),
            frees: Vec::new(),
            allocate_on_failure: false,
            output_size: None,
            null_output: false,
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
            && flags & 0x2 != 0
            && state.creation_result == POLICY_DENIED
            && matches!(state.outcome, 1 | 2)
        {
            state.snapshot = Some((state.outcome, state.details_count));
        }
        state.creation_result
    })
}

pub(super) fn policy_buffer_freed(pointer: *mut u8) {
    STATE.with(|state| state.borrow_mut().frees.push(pointer as usize));
}

unsafe extern "system" fn get_policy_result(
    requested_version: u32,
    size: *mut u32,
    output: *mut *mut u8,
) -> HRESULT {
    if size.is_null() || output.is_null() {
        return E_INVALIDARG;
    }
    unsafe {
        *size = 0;
        *output = ptr::null_mut();
    }
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.calls.push("get_policy_result");
        state.threads.push(std::thread::current().id());
        state.contracts.push(requested_version);
        if requested_version != 1 {
            return E_INVALIDARG;
        }
        let Some((outcome, count)) = state.snapshot else {
            return NO_SNAPSHOT;
        };
        if state.retrieval_result.is_err() && !state.allocate_on_failure {
            return state.retrieval_result;
        }
        let details = if let Some(capability) = &state.capability {
            vec![layout::PolicyDetailT {
                failure_class: layout::FailureClass::Network,
                failure_reason: layout::FailureReason::CapabilityNotAllowed,
                required_action: layout::RequiredAction::RemoveCapability,
                resource_kind: layout::ResourceKind::Capability,
                flags: 3,
                resource: Some(capability.encode_utf16().collect()),
                ..Default::default()
            }]
        } else if count == 2 {
            [r"C:\one", r"C:\two"]
                .iter()
                .map(|path| layout::PolicyDetailT {
                    failure_class: layout::FailureClass::Filesystem,
                    failure_reason: layout::FailureReason::DenyRequired,
                    required_action: layout::RequiredAction::RestrictFilesystemAccess,
                    resource_kind: layout::ResourceKind::Path,
                    value_kind: layout::ValueKind::Access,
                    flags: 3,
                    requested_value: 2,
                    required_value: 0,
                    resource: Some(path.encode_utf16().collect()),
                })
                .collect()
        } else {
            vec![layout::PolicyDetailT::default(); count as usize]
        };
        let result = layout::PolicyResultT {
            version: if state.invalid_header { 99 } else { 1 },
            minimum_reader_version: 1,
            outcome: layout::PolicyOutcome(outcome),
            details: Some(details),
        };
        let mut builder = flatbuffers::FlatBufferBuilder::new();
        let root = result.pack(&mut builder);
        layout::finish_policy_result_buffer(&mut builder, root);
        let mut bytes = builder.finished_data().to_vec();
        if state.invalid_pool {
            bytes[0] = 0xff;
        }
        unsafe {
            *size = state.output_size.unwrap_or(bytes.len() as u32);
            if !state.null_output {
                let memory = CoTaskMemAlloc(bytes.len()).cast::<u8>();
                assert!(!memory.is_null());
                ptr::copy_nonoverlapping(bytes.as_ptr(), memory, bytes.len());
                *output = memory;
                state.allocations.push(memory as usize);
            }
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
    let error = api
        .create_with_diagnostics(specification, 1, None, false)
        .unwrap_err();
    let message = error.message(false);
    assert!(message
        .contains("Native creation failure: failed to create the process security environment:"));
    assert!(message.contains("CreateProcessSecurityEnvironment failed"));
    assert!(message.contains("0x800704EC"));
    assert!(message.contains("IT-managed policy rule"));
    assert!(
        message.starts_with("Sandbox creation failed: blocked by IT policy."),
        "{message}"
    );
    assert!(message.contains("Returned constraints: 2 (non-exhaustive"));
    assert!(message.contains("Resource 1: \"C:\\\\one\""));
    assert!(message.contains("Resource 2: \"C:\\\\two\""));
    assert!(!error.is_api_unavailable());
    assert_eq!(calls(), ["support", "create", "get_policy_result"]);
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.inputs, [(specification.to_vec(), 3)]);
        assert_eq!(state.threads, vec![std::thread::current().id(); 2]);
    });
    assert_eq!(closes(), 0);
}

#[test]
fn getter_export_is_optional_and_legacy_denial_text_is_unchanged_when_absent() {
    let mut api = reset();
    assert_eq!(
        POLICY_RESULT_NAME.to_bytes(),
        b"Experimental_GetLastProcessSecurityEnvironmentPolicyResult"
    );
    api.get_last_policy_result = None;
    let error = api
        .create_with_diagnostics(b"spec", 1, None, false)
        .unwrap_err();
    assert_eq!(calls(), ["create"]);
    STATE.with(|state| assert_eq!(state.borrow().inputs, [(b"spec".to_vec(), 1)]));
    for capture in [false, true] {
        assert_eq!(
            error.message(capture),
            crate::process_container_common::launch_diagnostics::security_environment_failure_message(&error.cause, capture)
        );
    }
}

#[test]
fn policy_result_capture_requires_advertised_support() {
    for support in [0, 1, 0x0f, 0x10, 0x1f, 0x20, 0x30] {
        let api = reset();
        STATE.with(|state| state.borrow_mut().support = support);
        let error = api
            .create_with_diagnostics(b"spec", 1, None, false)
            .unwrap_err();
        let captured = support & 0x10 != 0;
        assert_eq!(
            error
                .message(false)
                .starts_with("Sandbox creation failed: blocked by IT policy."),
            captured
        );
        assert_eq!(
            calls(),
            if captured {
                vec!["support", "create", "get_policy_result"]
            } else {
                vec!["support", "create"]
            }
        );
        STATE.with(|state| {
            assert_eq!(
                state.borrow().inputs,
                [(b"spec".to_vec(), if captured { 0x3 } else { 0x1 })]
            );
        });
    }
}

#[test]
fn retrieval_requests_v1_and_releases_the_independent_allocation() {
    let api = reset();
    let error = api
        .create_with_diagnostics(b"spec", 0, None, false)
        .unwrap_err();
    assert!(
        matches!(error.cause, LearningModeError::HResultCall { code, .. } if code == POLICY_DENIED.0)
    );
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.contracts, [1]);
        assert_eq!(state.allocations.len(), 1);
        assert_eq!(state.frees, state.allocations);
    });
}

#[test]
fn returned_allocations_are_freed_on_hresult_decode_and_size_failures() {
    for (status, invalid, size, null) in [
        (E_FAIL, false, None, false),
        (S_OK, true, None, false),
        (S_OK, false, Some(0), false),
        (S_OK, false, Some(MAX_RESULT_BYTES as u32 + 1), false),
        (S_OK, false, Some(100), true),
    ] {
        let api = reset();
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.retrieval_result = status;
            state.allocate_on_failure = true;
            state.invalid_pool = invalid;
            state.output_size = size;
            state.null_output = null;
        });
        let error = api
            .create_with_diagnostics(b"spec", 0, None, false)
            .unwrap_err();
        assert!(error.message(false).contains("diagnostics unavailable"));
        assert!(error.message(false).contains("0x800704EC"));
        assert_eq!(calls(), ["support", "create", "get_policy_result"]);
        STATE.with(|state| {
            let state = state.borrow();
            assert_eq!(state.allocations.len(), usize::from(!null));
            assert_eq!(state.frees, state.allocations);
        });
    }
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
    let environment = api
        .create_with_diagnostics(b"spec", 0, None, false)
        .unwrap();
    assert_eq!(calls(), ["support", "create"]);
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
        let error = api
            .create_with_diagnostics(b"spec", 0, None, false)
            .unwrap_err();
        let expected = if status.is_ok() { E_UNEXPECTED } else { status };
        assert!(matches!(error.cause, LearningModeError::HResultCall {
            function: "CreateProcessSecurityEnvironment", code,
        } if code == expected.0));
        assert_eq!(calls(), ["support", "create"]);
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
        let error = api
            .create_with_diagnostics(b"spec", 0, None, false)
            .unwrap_err();
        let message = error.message(true);
        assert!(matches!(error.cause, LearningModeError::HResultCall {
            function: "CreateProcessSecurityEnvironment", code,
        } if code == POLICY_DENIED.0));
        assert!(!error.is_api_unavailable());
        assert!(message.contains("0x800704EC"));
        assert!(message.contains("IT-managed policy rule"));
        assert!(
            message.contains("Experimental_GetLastProcessSecurityEnvironmentPolicyResult failed")
        );
        assert!(message.contains(&format!("0x{:08X}", status.0 as u32)));
        assert!(!message.contains("Returned constraints:"));
        assert!(!message.contains("Resource 1:"));
        assert_eq!(calls(), ["support", "create", "get_policy_result"]);
        STATE.with(|state| assert_eq!(state.borrow().inputs.len(), 1));
    }
}

#[test]
fn best_effort_snapshot_absence_is_explicit_without_inventing_a_verdict() {
    let api = reset();
    STATE.with(|state| state.borrow_mut().capture_snapshot = false);
    let error = api
        .create_with_diagnostics(b"spec", 0, None, false)
        .unwrap_err();
    assert!(error
        .message(false)
        .contains("No cached policy diagnostic is available."));
    assert!(!error.message(false).contains("Returned constraints:"));
    assert_eq!(calls(), ["support", "create", "get_policy_result"]);
}

#[test]
fn blocked_and_evaluation_failed_use_the_refusal_only_contract() {
    for (outcome, summary) in [
        (1, "blocked by IT policy"),
        (2, "IT policy evaluation failed"),
    ] {
        let api = reset();
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.outcome = outcome;
            state.details_count = 0;
        });
        let error = api
            .create_with_diagnostics(b"spec", 0, None, false)
            .unwrap_err();
        let message = error.message(false);
        assert!(message.starts_with(&format!("Sandbox creation failed: {summary}.")));
        assert!(message.contains("CreateProcessSecurityEnvironment"));
        assert!(message.contains("0x800704EC"));
        assert!(error
            .to_string()
            .starts_with(&format!("Sandbox creation failed: {summary}.")));
        assert!(message.contains("No caller-action details"));
        assert!(!message.contains("action="));
        assert_eq!(calls(), ["support", "create", "get_policy_result"]);
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
        let error = api
            .create_with_diagnostics(b"spec", 0, None, false)
            .unwrap_err();
        let message = error.message(false);
        assert!(message.contains("0x800704EC"));
        assert!(message.contains("diagnostics unavailable"));
        assert!(!message.contains("\"C:\\\\one\""));
        assert_eq!(calls(), ["support", "create", "get_policy_result"]);
    }
}

#[test]
fn refusal_snapshot_is_copied_before_unexpected_handle_cleanup() {
    let api = reset();
    STATE.with(|state| state.borrow_mut().creation_handle = true);
    let error = api
        .create_with_diagnostics(b"spec", 0, None, false)
        .unwrap_err();
    assert!(error.message(false).contains("Resource 2: \"C:\\\\two\""));
    assert_eq!(calls(), ["support", "create", "get_policy_result", "close"]);
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
    let error = api
        .create_with_diagnostics(b"spec", 0, None, false)
        .unwrap_err();
    assert!(matches!(error.cause, LearningModeError::HResultCall { code, .. } if code == E_FAIL.0));
    assert_eq!(calls(), ["support", "create", "close"]);
    assert_eq!(closes(), 1);
}

#[test]
fn successful_hresult_without_an_environment_is_not_a_policy_refusal() {
    let api = reset();
    STATE.with(|state| state.borrow_mut().creation_result = S_OK);
    let error = api
        .create_with_diagnostics(b"spec", 0, None, false)
        .unwrap_err();
    assert!(
        matches!(error.cause, LearningModeError::HResultCall { code, .. } if code == E_UNEXPECTED.0)
    );
    assert_eq!(calls(), ["support", "create"]);
    assert_eq!(closes(), 0);
}

#[test]
fn retrieved_text_is_owned_before_another_creation_clears_the_snapshot() {
    let api = reset();
    let error = api
        .create_with_diagnostics(b"denied", 0, None, false)
        .unwrap_err();
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.creation_result = S_OK;
        state.creation_handle = true;
    });
    drop(
        api.create_with_diagnostics(b"allowed", 0, None, false)
            .unwrap(),
    );
    assert!(error.message(false).contains("Resource 1: \"C:\\\\one\""));
    assert_eq!(
        calls(),
        [
            "support",
            "create",
            "get_policy_result",
            "support",
            "create",
            "close"
        ]
    );
}

#[test]
fn request_guidance_is_owned_and_does_not_mutate_the_request() {
    use crate::mxc_common::models::{ContainerPolicy, NetworkAction, NetworkEgressPolicy};

    let api = reset();
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.capability = Some("internetclient".into());
        state.details_count = 1;
        state.creation_handle = true;
    });
    let mut policy = ContainerPolicy {
        network_egress: Some(NetworkEgressPolicy {
            default: NetworkAction::Allow,
            ..Default::default()
        }),
        ..Default::default()
    };
    let original = serde_json::to_value(&policy).unwrap();
    let error = api
        .create_with_diagnostics(b"unchanged spec", 0, Some(&policy), false)
        .unwrap_err();
    assert_eq!(serde_json::to_value(&policy).unwrap(), original);
    policy.network_egress = None;
    let message = error.message(false);
    assert!(message.contains("network.egress.default='allow'"));
    assert!(message.contains("set network.egress.default='deny'"));
    assert!(message.contains("0x800704EC"));
    assert_eq!(calls(), ["support", "create", "get_policy_result", "close"]);
    assert_eq!(closes(), 1);
}

#[test]
fn network_capture_provenance_reaches_owned_creation_errors_without_retry() {
    use crate::mxc_common::models::{ContainerPolicy, NetworkEgressPolicy};

    for capture_network_decisions in [false, true] {
        let api = reset();
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.capability = Some("internetclient".into());
            state.details_count = 1;
            state.creation_handle = true;
        });
        let mut policy = ContainerPolicy {
            capture_denials: Some(Default::default()),
            network_egress: Some(NetworkEgressPolicy::default()),
            ..Default::default()
        };
        let original = serde_json::to_value(&policy).unwrap();
        let error = api
            .create_with_diagnostics(
                b"unchanged spec",
                0,
                Some(&policy),
                capture_network_decisions,
            )
            .unwrap_err();
        assert_eq!(serde_json::to_value(&policy).unwrap(), original);
        policy.capture_denials = None;
        let message = error.message(true);
        assert_eq!(
            message.contains("processContainer.captureDenials (network-decision capture)"),
            capture_network_decisions
        );
        assert!(message.contains("0x800704EC"));
        assert_eq!(calls(), ["support", "create", "get_policy_result", "close"]);
        assert_eq!(closes(), 1);
    }
}

#[test]
fn snapshots_are_thread_local_and_retrieval_does_not_consume_them() {
    let api = reset();
    api.create(b"main refusal", 0x2).unwrap_err();
    std::thread::spawn(move || {
        assert!(policy_failure_diagnostic(get_policy_result, None, false)
            .contains("No cached policy diagnostic"));
        let api = reset();
        STATE.with(|state| state.borrow_mut().outcome = 2);
        let error = api
            .create_with_diagnostics(b"worker refusal", 0, None, false)
            .unwrap_err();
        assert!(error
            .message(false)
            .starts_with("Sandbox creation failed: IT policy evaluation failed."));
        STATE
            .with(|state| assert_eq!(state.borrow().threads, vec![std::thread::current().id(); 2]));
    })
    .join()
    .unwrap();
    let first = policy_failure_diagnostic(get_policy_result, None, false);
    let second = policy_failure_diagnostic(get_policy_result, None, false);
    assert_eq!(first, second);
    assert!(first.starts_with("Sandbox creation failed: blocked by IT policy."));
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
            assert!(response
                .error_message
                .starts_with("Sandbox creation failed: blocked by IT policy."));
            assert_eq!(response.error_message.contains("captureDenials:"), capture);
            assert!(response
                .error_message
                .contains("CreateProcessSecurityEnvironment failed"));
            assert!(response
                .error_message
                .contains("Returned constraints: 2 (non-exhaustive"));
            assert!(response.error_message.contains("Resource 1: \"C:\\\\one\""));
            assert!(response.error_message.contains("Resource 2: \"C:\\\\two\""));
            assert_eq!(calls(), ["support", "create", "get_policy_result"]);
            STATE.with(|state| {
                let state = state.borrow();
                assert_eq!(state.inputs.len(), 1);
                assert_eq!(state.inputs[0].1, 0x2);
            });
        }
    }
}

#[test]
fn real_runner_maps_effective_loopback_with_and_without_capture() {
    use crate::mxc_common::logger::{Logger, Mode};
    use crate::mxc_common::models::{
        ExecutionRequest, FailurePhase, NetworkAction, NetworkIngressPolicy,
    };
    use crate::mxc_common::sandbox_process::{SandboxBackend, StdioMode};
    use crate::process_container_common::base_container_runner::BaseContainerRunner;

    unsafe extern "system" fn version(major: u32, available: *mut u8, minor: *mut u32) -> HRESULT {
        unsafe {
            *available = u8::from(major == 1);
            if !minor.is_null() {
                *minor = 1;
            }
        }
        S_OK
    }

    let directory = tempfile::tempdir().unwrap();
    for capture in [false, true] {
        let mut api = reset();
        api.version_support = Some(version);
        let _scope = ApiScope::new(api);
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.capability = Some("networkloopback".into());
            state.details_count = 1;
            state.support = 0x1f;
        });
        let mut request = ExecutionRequest {
            script_code: "cmd.exe /d /c exit 0".into(),
            working_directory: directory.path().to_string_lossy().into_owned(),
            env: Some(vec![
                format!("SystemRoot={}", std::env::var("SystemRoot").unwrap()),
                format!("LOCALAPPDATA={}", directory.path().display()),
            ]),
            ..Default::default()
        };
        request.policy.network_ingress = Some(NetworkIngressPolicy {
            default: NetworkAction::Deny,
            host_loopback: NetworkAction::Allow,
        });
        if capture {
            request.policy.capture_denials = Some(Default::default());
        }
        let original = serde_json::to_value(&request).unwrap();
        let mut runner = BaseContainerRunner::new_for_selected_request();
        let mut logger = Logger::new(Mode::Buffer);
        let response = match runner.spawn(&request, &mut logger, StdioMode::Pipes) {
            Ok(_) => panic!("a policy refusal must not launch the process"),
            Err(response) => response,
        };
        assert_eq!(response.failure_phase, FailurePhase::LaunchFailed);
        assert!(response
            .error_message
            .contains("network.ingress.hostLoopback='allow'"));
        assert!(response
            .error_message
            .contains("set network.ingress.hostLoopback='deny'"));
        assert_eq!(response.standard_err, response.error_message);
        assert_eq!(serde_json::to_value(&request).unwrap(), original);
        let native_calls: Vec<_> = calls()
            .into_iter()
            .filter(|call| *call != "support")
            .collect();
        assert_eq!(native_calls, ["create", "get_policy_result"]);
        STATE.with(|state| {
            let state = state.borrow();
            let layout =
                crate::process_security_environment_spec::process_security_environment_layout::root_as_process_security_environment(
                    &state.inputs[0].0,
                )
                .unwrap();
            assert!(layout
                .capabilities()
                .unwrap_or_default()
                .to_ascii_lowercase()
                .contains("networkloopback"));
        });
        assert!(!request
            .policy
            .capabilities
            .iter()
            .any(|capability| capability.eq_ignore_ascii_case("networkLoopback")));
    }
}

#[test]
fn support_query_failure_cannot_mask_creation_or_authorize_a_repair() {
    for support_result in [E_FAIL, E_NOTIMPL] {
        for creation_result in [POLICY_DENIED, E_FAIL, S_OK] {
            let api = reset();
            STATE.with(|state| {
                let mut state = state.borrow_mut();
                state.support_result = support_result;
                state.creation_result = creation_result;
                state.creation_handle = creation_result.is_ok();
            });
            let result = api.create_with_diagnostics(b"spec", 0, None, false);
            if creation_result.is_ok() {
                drop(result.unwrap());
                assert_eq!(calls(), ["support", "create", "close"]);
            } else {
                let error = result.unwrap_err();
                assert!(matches!(error.cause,
                    LearningModeError::HResultCall {
                        function: "CreateProcessSecurityEnvironment", code,
                    } if code == creation_result.0
                ));
                if creation_result == POLICY_DENIED {
                    let message = error.message(false);
                    assert!(message.contains("Creation-policy diagnostics unavailable"));
                    assert!(message.contains("QueryProcessSecurityEnvironmentSupport failed"));
                    assert!(message.contains("0x800704EC"));
                } else {
                    assert!(error.diagnostic.is_none());
                }
                assert_eq!(calls(), ["support", "create"]);
            }
            STATE.with(|state| {
                let state = state.borrow();
                assert_eq!(state.inputs, [(b"spec".to_vec(), 0)]);
                assert!(state.allocations.is_empty());
                assert!(state.snapshot.is_none());
            });
        }
    }
}

#[test]
fn unflagged_creation_skips_capture_and_clears_an_earlier_snapshot() {
    let api = reset();
    api.create(b"captured refusal", 0x2).unwrap_err();
    assert!(policy_failure_diagnostic(get_policy_result, None, false)
        .starts_with("Sandbox creation failed: blocked by IT policy."));
    api.create(b"unflagged refusal", 0).unwrap_err();
    assert!(policy_failure_diagnostic(get_policy_result, None, false)
        .contains("No cached policy diagnostic is available."));
    assert_eq!(
        calls(),
        ["create", "get_policy_result", "create", "get_policy_result"]
    );
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(
            state.inputs,
            [
                (b"captured refusal".to_vec(), 0x2),
                (b"unflagged refusal".to_vec(), 0)
            ]
        );
        assert_eq!(state.frees, state.allocations);
    });
}
