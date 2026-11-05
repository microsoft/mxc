// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::core_modules::process_security_environment_policy_result::experimental_process_security_environment_policy_result as layout;
use crate::mxc_common::policy_failures::PolicyFailureDetail;
use std::cell::{Cell, RefCell};
use windows::Win32::Foundation::{E_FAIL, S_OK};
use windows::Win32::System::Com::CoTaskMemAlloc;

const POLICY_DENIED: HRESULT = HRESULT(0x800704ecu32 as i32);

struct FakeState {
    status: HRESULT,
    handle: bool,
    support_status: HRESULT,
    support_flags: u32,
    getter_status: HRESULT,
    report: PolicyFailureResult,
    payload_override: Option<Vec<u8>>,
    reported_size: Option<u32>,
    flags: Vec<u32>,
    specifications: Vec<Vec<u8>>,
    calls: Vec<&'static str>,
    threads: Vec<std::thread::ThreadId>,
    frees: usize,
    closes: usize,
}

impl Default for FakeState {
    fn default() -> Self {
        Self {
            status: POLICY_DENIED,
            handle: false,
            support_status: S_OK,
            support_flags: 0x10,
            getter_status: S_OK,
            report: PolicyFailureResult {
                outcome: 1,
                details: vec![PolicyFailureDetail {
                    failure_class: 2,
                    failure_reason: 2,
                    required_action: 2,
                    resource_kind: 1,
                    value_kind: 1,
                    flags: 3,
                    requested_value: 2,
                    required_value: 1,
                    resource: Some(r"C:\work".encode_utf16().collect()),
                }],
                ..Default::default()
            },
            payload_override: None,
            reported_size: None,
            flags: Vec::new(),
            specifications: Vec::new(),
            calls: Vec::new(),
            threads: Vec::new(),
            frees: 0,
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

pub(super) fn policy_buffer_freed(_: *mut u8) {
    STATE.with(|state| state.borrow_mut().frees += 1);
}

fn reset() -> SecurityEnvironmentApi {
    STATE.with(|state| *state.borrow_mut() = FakeState::default());
    let mut api = SecurityEnvironmentApi::from_raw_parts(create, query, close);
    api.get_last_policy_result = Some(get_result);
    api
}

unsafe extern "system" fn query(flags: *mut u32) -> HRESULT {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.calls.push("support");
        // SAFETY: the tested API passes valid output storage.
        unsafe { *flags = state.support_flags };
        state.support_status
    })
}

unsafe extern "system" fn create(
    specification: *const c_void,
    size: u32,
    flags: u32,
    output: *mut HANDLE,
) -> HRESULT {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.calls.push("create");
        state.threads.push(std::thread::current().id());
        state.flags.push(flags);
        // SAFETY: the tested API supplies the complete input buffer.
        state.specifications.push(unsafe {
            std::slice::from_raw_parts(specification.cast::<u8>(), size as usize).to_vec()
        });
        if state.handle {
            // SAFETY: fake output storage is provided by the tested API.
            unsafe { *output = HANDLE(0x1000usize as *mut c_void) };
        }
        state.status
    })
}

struct ApiScope(Option<SecurityEnvironmentApi>);

impl Drop for ApiScope {
    fn drop(&mut self) {
        INJECTED_API.with(|slot| slot.set(self.0));
    }
}

unsafe extern "system" fn version(_: u32, available: *mut u8, minor: *mut u32) -> HRESULT {
    // SAFETY: native version-query outputs are valid for this fake.
    unsafe {
        *available = 1;
        *minor = 3;
    }
    S_OK
}

struct UnusedCapture;

impl crate::process_container_common::base_container_runner::CaptureSessionFactory
    for UnusedCapture
{
    fn trace_sources(
        &self,
    ) -> Result<crate::learning_mode_windows::LearningModeTraceSources, LearningModeError> {
        Ok(crate::learning_mode_windows::LearningModeTraceSources::AccessOnly)
    }

    fn begin(
        &self,
        _: &[u8],
        _: u32,
        _: &ContainerPolicy,
        _: bool,
    ) -> Result<
        Box<dyn crate::process_container_common::base_container_runner::CaptureSessionOps>,
        CreationError,
    > {
        Err(LearningModeError::HResultCall {
            function: "unexpected test capture",
            code: E_FAIL.0,
        }
        .into())
    }
}

fn launch_fixed_fixture(
    launch: crate::process_container_common::base_container_runner::BaseProcessLaunch<'_>,
) -> windows_core::Result<()> {
    use windows::Win32::System::Threading::{
        CreateProcessW, CREATE_NO_WINDOW, EXTENDED_STARTUPINFO_PRESENT, PROCESS_CREATION_FLAGS,
        STARTUPINFOW,
    };
    use windows_core::{PCWSTR, PWSTR};
    assert_eq!(launch.startup.environment_for_test().0 as usize, 0x1000);
    assert_ne!(launch.creation_flags.0 & CREATE_NO_WINDOW.0, 0);
    assert_eq!(
        String::from_utf16(launch.command_line)
            .unwrap()
            .trim_end_matches('\0'),
        "cmd.exe /d /c echo mxc-feedback-child",
    );
    STATE.with(|state| state.borrow_mut().calls.push("launch"));
    let mut startup = launch.startup.startup_info().StartupInfo;
    startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    // The native environment is fake. Execute only the fixed trusted fixture,
    // without the fake PSEC attribute, retaining pipes/suspension/job cleanup.
    unsafe {
        CreateProcessW(
            PCWSTR::null(),
            Some(PWSTR(launch.command_line.as_mut_ptr())),
            None,
            None,
            launch.inherit_handles,
            PROCESS_CREATION_FLAGS(launch.creation_flags.0 & !EXTENDED_STARTUPINFO_PRESENT.0),
            launch
                .environment
                .map(|block| block.as_ptr().cast::<c_void>()),
            PCWSTR(launch.working_directory.as_ptr()),
            &startup,
            launch.process_information,
        )
    }
}

#[test]
fn policy_feedback_backend_app_loop_accumulates_and_launches_exactly_once() {
    use crate::mxc_common::logger::{Logger, Mode};
    use crate::mxc_common::models::ExecutionRequest;
    use crate::mxc_common::sandbox_process::{SandboxBackend, StdioMode};
    use crate::process_container_common::base_container_runner::BaseContainerRunner;
    use crate::process_container_common::test_env::CaptureCapabilityGuard;
    use std::io::Read;
    use std::sync::Arc;

    let _host = CaptureCapabilityGuard::set(true, true);
    let mut api = reset();
    api.version_support = Some(version);
    let _scope = ApiScope(INJECTED_API.with(|slot| slot.replace(Some(api))));
    let directory = tempfile::tempdir().unwrap();
    let mut request = ExecutionRequest {
        script_code: "cmd.exe /d /c echo mxc-feedback-child".into(),
        working_directory: directory.path().to_string_lossy().into(),
        script_timeout: 5_000,
        ..Default::default()
    };
    request.policy.capabilities = vec!["registryRead".into(), "registryWrite".into()];
    let original = serde_json::to_string(&request).unwrap();
    let mut runner = BaseContainerRunner::with_capture_factory(Arc::new(UnusedCapture))
        .with_process_launcher(launch_fixed_fixture);
    let mut feedback = None;
    for (index, capability) in ["registryRead", "registryWrite"].into_iter().enumerate() {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.report.details = vec![PolicyFailureDetail {
                failure_class: 2,
                failure_reason: 1,
                required_action: 1,
                resource_kind: 2,
                flags: 3,
                resource: Some(capability.encode_utf16().collect()),
                ..Default::default()
            }];
        });
        request.policy_failures = feedback
            .as_ref()
            .map(|feedback: &PolicyFailures| Arc::new(feedback.clone()));
        let error = match runner.spawn(&request, &mut Logger::new(Mode::Buffer), StdioMode::Pipes) {
            Err(error) => error,
            Ok(_) => panic!("a refusal must not launch a workload"),
        };
        let error = crate::mxc_engine::Error::from(error.into_mxc_error());
        let next = PolicyFailures::from_error(&error).unwrap().unwrap();
        assert_eq!(next.results.len(), index + 1);
        feedback = Some(PolicyFailures::from_json(&next.to_json().unwrap()).unwrap());
        STATE.with(|state| {
            let state = state.borrow();
            assert_eq!(state.specifications.len(), index + 1);
            assert!(!state.calls.contains(&"launch"));
        });
    }
    request.policy_failures = feedback.map(Arc::new);
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.status = S_OK;
        state.handle = true;
    });
    let mut process = runner
        .spawn(&request, &mut Logger::new(Mode::Buffer), StdioMode::Pipes)
        .expect("cumulative feedback is applied before the third creation");
    let mut stdout = String::new();
    process
        .take_stdout()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    assert_eq!(stdout.trim(), "mxc-feedback-child");
    assert_eq!(process.wait().unwrap(), 0);
    assert!(process.warnings().is_empty());
    drop(process);
    assert_eq!(serde_json::to_string(&request).unwrap(), original);
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.specifications.len(), 3);
        assert_eq!(
            state.calls.iter().filter(|call| **call == "launch").count(),
            1
        );
        assert_eq!(state.closes, 1);
        use crate::core_modules::process_security_environment_spec::process_security_environment_layout as psec;
        for (index, bytes) in state.specifications.iter().enumerate() {
            let spec = psec::root_as_process_security_environment(bytes).unwrap();
            let capabilities: Vec<_> = spec.capabilities().unwrap_or("").split(',').collect();
            assert_eq!(capabilities.contains(&"registryRead"), index == 0);
            assert_eq!(capabilities.contains(&"registryWrite"), index < 2);
        }
    });
}

unsafe extern "system" fn close(_: HANDLE) {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.calls.push("close");
        state.closes += 1;
    });
}

unsafe extern "system" fn get_result(
    version: u32,
    size: *mut u32,
    output: *mut *mut u8,
) -> HRESULT {
    assert_eq!(version, POLICY_RESULT_VERSION);
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.calls.push("get");
        state.threads.push(std::thread::current().id());
        let native = PolicyResult::from(&state.report);
        let mut builder = flatbuffers::FlatBufferBuilder::new();
        let root = native.pack(&mut builder);
        layout::finish_policy_result_buffer(&mut builder, root);
        let bytes = state
            .payload_override
            .as_deref()
            .unwrap_or(builder.finished_data());
        // SAFETY: this fake implements the native owned-allocation contract.
        let allocation = unsafe { CoTaskMemAlloc(bytes.len()) }.cast::<u8>();
        assert!(!allocation.is_null());
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), allocation, bytes.len());
            *output = allocation;
            *size = state.reported_size.unwrap_or(bytes.len() as u32);
        }
        state.getter_status
    })
}

#[test]
fn policy_feedback_native_invalid_payloads_stop_and_free_without_text_specifics() {
    for fault in [
        "identifier",
        "table",
        "version",
        "resourceFlags",
        "byteLimit",
        "resourceLimit",
        "zeroSize",
    ] {
        let api = reset();
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            match fault {
                "identifier" => state.payload_override = Some(vec![0; 8]),
                "table" => {
                    let mut bytes = vec![0; 8];
                    bytes[4..].copy_from_slice(b"PSEP");
                    state.payload_override = Some(bytes);
                }
                "version" => state.report.minimum_reader_version = 2,
                "resourceFlags" => state.report.details[0].flags = 1,
                "byteLimit" => state.reported_size = Some(MAX_RESULT_BYTES as u32 + 1),
                "resourceLimit" => state.report.details[0].resource = Some(vec![65; 32_768]),
                "zeroSize" => state.reported_size = Some(0),
                _ => unreachable!(),
            }
        });
        let failure = api
            .create_with_diagnostics(b"spec", 0, None, false)
            .unwrap_err();
        let error = crate::mxc_engine::Error::from(failure.response(false, None).into_mxc_error());
        assert!(
            PolicyFailures::from_error(&error).unwrap().is_none(),
            "{fault}"
        );
        assert!(
            error
                .details
                .as_deref()
                .unwrap()
                .get("policyResultUnavailable")
                .is_some(),
            "{fault}"
        );
        assert_eq!(error.native_code.as_deref(), Some("0x800704EC"));
        assert!(!error.message.contains("native result"), "{fault}");
        STATE.with(|state| assert_eq!(state.borrow().frees, 1, "{fault}"));
    }
}

#[test]
fn policy_feedback_native_maximum_byte_count_remains_usable() {
    let api = reset();
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        let native = PolicyResult::from(&state.report);
        let mut builder = flatbuffers::FlatBufferBuilder::new();
        let root = native.pack(&mut builder);
        layout::finish_policy_result_buffer(&mut builder, root);
        let mut bytes = builder.finished_data().to_vec();
        bytes.resize(MAX_RESULT_BYTES, 0);
        state.payload_override = Some(bytes);
    });
    let failure = api
        .create_with_diagnostics(b"spec", 0, None, false)
        .unwrap_err();
    let error = crate::mxc_engine::Error::from(failure.response(false, None).into_mxc_error());
    assert_eq!(
        PolicyFailures::from_error(&error)
            .unwrap()
            .unwrap()
            .results
            .len(),
        1
    );
    STATE.with(|state| assert_eq!(state.borrow().frees, 1));
}

#[test]
fn policy_feedback_native_terminal_batch_keeps_all_prior_observations() {
    let api = reset();
    let mut prior = PolicyFailures::default();
    for index in 0..64 {
        let mut result = STATE.with(|state| state.borrow().report.clone());
        result.details[0].resource = Some(format!(r"C:\history\{index}").encode_utf16().collect());
        prior.append(result);
    }
    prior.validate().unwrap();
    let failure = api
        .create_with_diagnostics(b"spec", 0, None, false)
        .unwrap_err();
    let error =
        crate::mxc_engine::Error::from(failure.response(false, Some(&prior)).into_mxc_error());
    let diagnostic = &error.details.as_deref().unwrap()["policyFeedbackError"];
    assert_eq!(diagnostic["code"], "feedbackLimitExceeded");
    assert!(diagnostic["reason"]
        .as_str()
        .is_some_and(|reason| !reason.is_empty()));
    assert_eq!(error.native_code.as_deref(), Some("0x800704EC"));
    assert_eq!(
        error.operation.as_deref(),
        Some("CreateProcessSecurityEnvironment")
    );
    let complete = PolicyFailures::from_error(&error).unwrap().unwrap();
    assert_eq!(complete.results.len(), 65);
    assert_eq!(&complete.results[..64], &prior.results);
    assert_eq!(
        PolicyFailures::from_json(&complete.to_json().unwrap()).unwrap(),
        complete
    );
    assert!(complete.validate().is_err());
    STATE.with(|state| assert_eq!(state.borrow().frees, 1));
}

#[test]
fn policy_feedback_complete_capture_constraints_submit_no_logging_capabilities() {
    use crate::core_modules::process_security_environment_spec::process_security_environment_layout as psec;
    use crate::mxc_common::logger::{Logger, Mode};
    use crate::mxc_common::models::{CaptureDenialsConfig, CaptureDenialsMode, ExecutionRequest};
    use crate::mxc_common::sandbox_process::{SandboxBackend, StdioMode};
    use crate::process_container_common::base_container_runner::BaseContainerRunner;
    use crate::process_container_common::test_env::CaptureCapabilityGuard;
    use std::{io::Read, sync::Arc};

    let _host = CaptureCapabilityGuard::set(true, true);
    let mut api = reset();
    api.version_support = Some(version);
    let _scope = ApiScope(INJECTED_API.with(|slot| slot.replace(Some(api))));
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.status = S_OK;
        state.handle = true;
    });
    let mut feedback = PolicyFailures::default();
    for capability in ["learningModeLogging", "permissiveLearningMode"] {
        feedback.append(PolicyFailureResult {
            outcome: 1,
            details: vec![PolicyFailureDetail {
                failure_class: 3,
                failure_reason: 1,
                required_action: 1,
                resource_kind: 2,
                flags: 3,
                resource: Some(capability.encode_utf16().collect()),
                ..Default::default()
            }],
            ..Default::default()
        });
    }
    let directory = tempfile::tempdir().unwrap();
    let mut request = ExecutionRequest {
        script_code: "cmd.exe /d /c echo mxc-feedback-child".into(),
        working_directory: directory.path().to_string_lossy().into(),
        script_timeout: 5_000,
        policy_failures: Some(Arc::new(feedback)),
        ..Default::default()
    };
    request.policy.capabilities = vec!["permissiveLearningMode".into()];
    request.policy.capture_denials = Some(CaptureDenialsConfig {
        mode: CaptureDenialsMode::Allow,
        ..Default::default()
    });
    let original = serde_json::to_string(&request).unwrap();
    let mut runner = BaseContainerRunner::with_capture_factory(Arc::new(UnusedCapture))
        .with_process_launcher(launch_fixed_fixture);
    let mut process = runner
        .spawn(&request, &mut Logger::new(Mode::Buffer), StdioMode::Pipes)
        .unwrap();
    let mut stdout = String::new();
    process
        .take_stdout()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    assert_eq!(stdout.trim(), "mxc-feedback-child");
    assert_eq!(process.wait().unwrap(), 0);
    drop(process);
    assert_eq!(serde_json::to_string(&request).unwrap(), original);
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.specifications.len(), 1);
        let specification =
            psec::root_as_process_security_environment(&state.specifications[0]).unwrap();
        let capabilities = specification.capabilities().unwrap_or("");
        assert!(!capabilities.contains("learningModeLogging"));
        assert!(!capabilities.contains("permissiveLearningMode"));
        assert_eq!(
            state.calls.iter().filter(|call| **call == "launch").count(),
            1
        );
        assert_eq!(state.closes, 1);
    });
}

#[test]
fn policy_feedback_native_capture_preserves_data_status_and_cleanup_not_prose() {
    let api = reset();
    STATE.with(|state| state.borrow_mut().handle = true);
    let error = api
        .create_with_diagnostics(b"spec", 0x40, None, false)
        .unwrap_err();
    let error = crate::mxc_engine::Error::from(error.response(false, None).into_mxc_error());
    let feedback = PolicyFailures::from_error(&error).unwrap().unwrap();
    assert_eq!(
        error.operation.as_deref(),
        Some("CreateProcessSecurityEnvironment")
    );
    assert_eq!(error.native_code.as_deref(), Some("0x800704EC"));
    assert!(!error.message.contains(r"C:\work"));
    assert!(!error.message.contains("requested="));
    assert_eq!(
        feedback.results[0].details[0]
            .resource_text()
            .unwrap()
            .as_deref(),
        Some(r"C:\work")
    );
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(
            state.calls.iter().filter(|call| **call == "create").count(),
            1
        );
        assert!(
            state.calls.iter().position(|call| *call == "get").unwrap()
                < state
                    .calls
                    .iter()
                    .position(|call| *call == "close")
                    .unwrap()
        );
        assert_eq!(state.flags, [0x42]);
        assert_eq!(state.frees, 1);
        assert_eq!(state.closes, 1);
        assert!(state
            .threads
            .iter()
            .all(|id| *id == std::thread::current().id()));
    });
}

#[test]
fn policy_feedback_does_not_query_success_or_unrelated_failure() {
    for status in [S_OK, E_FAIL] {
        let api = reset();
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.status = status;
            state.handle = status.is_ok();
        });
        drop(api.create_with_diagnostics(b"spec", 0, None, false));
        STATE.with(|state| {
            let state = state.borrow();
            assert!(!state.calls.contains(&"get"));
            assert_eq!(state.frees, 0);
            assert_eq!(state.closes, usize::from(status.is_ok()));
        });
    }
}

#[test]
fn policy_feedback_getter_failure_frees_outputs_and_retains_prior_observations() {
    let api = reset();
    let prior = STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.getter_status = E_FAIL;
        let mut prior = PolicyFailures::default();
        prior.append(state.report.clone());
        prior
    });
    let failure = api
        .create_with_diagnostics(b"spec", 0, None, false)
        .unwrap_err();
    let error =
        crate::mxc_engine::Error::from(failure.response(false, Some(&prior)).into_mxc_error());
    assert_eq!(PolicyFailures::from_error(&error).unwrap(), Some(prior));
    assert!(error
        .details
        .as_deref()
        .unwrap()
        .get("policyResultUnavailable")
        .is_some());
    assert_eq!(error.native_code.as_deref(), Some("0x800704EC"));
    STATE.with(|state| assert_eq!(state.borrow().frees, 1));
}

#[test]
fn policy_feedback_missing_getter_reports_unavailability_only_as_structured_data() {
    let mut api = reset();
    api.get_last_policy_result = None;
    let failure = api
        .create_with_diagnostics(b"spec", 0, None, false)
        .unwrap_err();
    let error = crate::mxc_engine::Error::from(failure.response(false, None).into_mxc_error());
    assert!(PolicyFailures::from_error(&error).unwrap().is_none());
    assert!(error
        .details
        .as_deref()
        .unwrap()
        .get("policyResultUnavailable")
        .is_some());
    assert!(!error.message.contains("reporting is unavailable"));
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.flags, [0]);
        assert!(!state.calls.contains(&"get"));
    });
}

#[test]
fn policy_feedback_unadvertised_or_failed_support_preserves_creation_and_prior_data() {
    for (support_status, support_flags) in [(S_OK, 0), (S_OK, 0x0f), (E_FAIL, 0x10)] {
        let api = reset();
        let prior = STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.support_status = support_status;
            state.support_flags = support_flags;
            let mut prior = PolicyFailures::default();
            prior.append(state.report.clone());
            prior
        });
        let caller_flags = 0x40;
        let failure = api
            .create_with_diagnostics(b"spec", caller_flags, None, false)
            .unwrap_err();
        STATE.with(|state| {
            let state = state.borrow();
            assert_eq!(state.flags, [caller_flags]);
            assert_eq!(state.calls, ["support", "create"]);
            assert_eq!(state.frees, 0);
        });
        let error =
            crate::mxc_engine::Error::from(failure.response(false, Some(&prior)).into_mxc_error());
        assert_eq!(error.native_code.as_deref(), Some("0x800704EC"));
        assert_eq!(
            error.operation.as_deref(),
            Some("CreateProcessSecurityEnvironment")
        );
        assert_eq!(PolicyFailures::from_error(&error).unwrap(), Some(prior));
        assert!(error.details.as_deref().unwrap()["policyResultUnavailable"]
            .as_str()
            .is_some_and(|reason| !reason.is_empty()));
        assert!(!error.message.contains("unavailable"));
        assert!(!error
            .message
            .contains("QueryProcessSecurityEnvironmentSupport"));
    }
}
