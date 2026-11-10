// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::core_modules::process_security_environment_policy_result::experimental_process_security_environment_policy_result as layout;
use crate::mxc_common::policy_failures::PolicyFailureDetail;
use std::cell::{Cell, RefCell};
use windows::Win32::Foundation::{E_FAIL, S_OK};
use windows::Win32::System::Com::CoTaskMemAlloc;

#[path = "policy_preparation_backend_tests.rs"]
mod preparation;

const POLICY_DENIED: HRESULT = HRESULT(0x800704ecu32 as i32);
const POLICY_DENIED_MESSAGE: &str = concat!(
    "failed to create the process security environment: ",
    "CreateProcessSecurityEnvironment failed (HRESULT = 0x800704EC). ",
    "Windows blocked creation of the requested sandbox because of an IT-managed policy rule ",
    "(ERROR_ACCESS_DISABLED_BY_POLICY, 1260). Review the requested sandbox permissions or ",
    "contact your system administrator.",
);

struct FakeState {
    status: HRESULT,
    handle: bool,
    support_status: HRESULT,
    support_flags: u64,
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
    capture_sources: crate::learning_mode_windows::LearningModeTraceSources,
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
            capture_sources: crate::learning_mode_windows::LearningModeTraceSources::AccessOnly,
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

pub(super) fn injected_capture_trace_sources(
) -> Option<crate::learning_mode_windows::LearningModeTraceSources> {
    injected_api().map(|_| STATE.with(|state| state.borrow().capture_sources))
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

unsafe extern "system" fn query(flags: *mut u64) -> HRESULT {
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
        "cmd.exe /d /c echo mxc-policy-child",
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

fn parsed_request(json: &str) -> crate::mxc_common::models::ExecutionRequest {
    use crate::mxc_common::logger::{Logger, Mode};
    use crate::mxc_common::state_aware_request::MxcRequest;
    match crate::mxc_common::config_parser::load_mxc_request_from_json(
        json,
        &mut Logger::new(Mode::Buffer),
    )
    .unwrap()
    {
        MxcRequest::OneShot(request) => request,
        MxcRequest::StateAware(_) => panic!("expected a create-and-run request"),
    }
}

fn prepare_candidate(
    original: &str,
    failures: &PolicyFailures,
) -> crate::v1::dev::PreparedPolicyRequest {
    fn resource_calls(state: &FakeState) -> Vec<&'static str> {
        state
            .calls
            .iter()
            .copied()
            .filter(|call| matches!(*call, "create" | "get" | "launch" | "close"))
            .collect()
    }
    let before = STATE.with(|state| {
        let state = state.borrow();
        (
            state.specifications.len(),
            resource_calls(&state),
            state.frees,
            state.closes,
        )
    });
    let prepared = crate::v1::dev::prepare_policy_json(original, failures, Default::default())
        .expect("prepare without creation or workload execution");
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.specifications.len(), before.0);
        assert_eq!(resource_calls(&state), before.1);
        assert_eq!(state.frees, before.2);
        assert_eq!(state.closes, before.3);
    });
    assert_eq!(
        crate::v1::dev::PreparedPolicyRequest::from_json(&prepared.to_json().unwrap()).unwrap(),
        prepared,
    );
    prepared
}

#[test]
fn policy_preparation_app_loop_merges_observations_then_accepts_strict_creation() {
    use crate::mxc_common::logger::{Logger, Mode};
    use crate::mxc_common::sandbox_process::{SandboxBackend, StdioMode};
    use crate::process_container_common::base_container_runner::BaseContainerRunner;
    use crate::process_container_common::test_env::CaptureCapabilityGuard;
    use crate::v1::dev::PolicyChangeOperation;
    use std::io::Read;
    use std::sync::Arc;

    let _host = CaptureCapabilityGuard::set(true, true);
    let mut api = reset();
    api.version_support = Some(version);
    let _scope = ApiScope(INJECTED_API.with(|slot| slot.replace(Some(api))));
    let directory = tempfile::tempdir().unwrap();
    let original = serde_json::json!({
        "version": "1.0.0",
        "containerId": "policy-preparation-fixture",
        "containment": "processcontainer",
        "process": {
            "commandLine": "cmd.exe /d /c echo mxc-policy-child",
            "cwd": directory.path(), "timeout": 5000,
        },
        "processContainer": { "capabilities": ["registryRead", "registryWrite"] },
    })
    .to_string();
    let mut selected = original.clone();
    let mut runner = BaseContainerRunner::with_capture_factory(Arc::new(UnusedCapture))
        .with_process_launcher(launch_fixed_fixture);
    let mut failures = PolicyFailures::default();
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
        let request = parsed_request(&selected);
        let error = match runner.spawn(&request, &mut Logger::new(Mode::Buffer), StdioMode::Pipes) {
            Err(error) => error,
            Ok(_) => panic!("a refusal must not launch a workload"),
        };
        let error = crate::mxc_engine::Error::from(error.into_mxc_error());
        let next = PolicyFailures::from_error(&error).unwrap().unwrap();
        assert_eq!(
            next.results.len(),
            1,
            "strict creation returns only its own observation"
        );
        assert_eq!(
            error.native_code.as_deref(),
            Some(PolicyFailures::NATIVE_CODE_POLICY_BLOCKED)
        );
        failures = failures.merged_with(&next).unwrap();
        assert_eq!(failures.results.len(), index + 1);
        STATE.with(|state| {
            let state = state.borrow();
            assert_eq!(state.specifications.len(), index + 1);
            assert!(!state.calls.contains(&"launch"));
        });
        let prepared = prepare_candidate(&original, &failures);
        assert_eq!(prepared.changes.len(), 1);
        let change = &prepared.changes[0];
        assert_eq!(change.operation, PolicyChangeOperation::Replace);
        assert_eq!(change.path, "/processContainer/capabilities");
        assert_eq!(
            change.before,
            serde_json::json!(["registryRead", "registryWrite"])
        );
        assert_eq!(
            change.after,
            if index == 0 {
                serde_json::json!(["registryWrite"])
            } else {
                serde_json::json!([])
            },
        );
        selected = prepared.request_json; // The caller explicitly accepts the checked capability removals.
    }
    let request = parsed_request(&selected);
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.status = S_OK;
        state.handle = true;
    });
    let mut process = runner
        .spawn(&request, &mut Logger::new(Mode::Buffer), StdioMode::Pipes)
        .expect("submit the accepted candidate through ordinary strict creation");
    let mut stdout = String::new();
    process
        .take_stdout()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    assert_eq!(stdout.trim(), "mxc-policy-child");
    assert_eq!(process.wait().unwrap(), 0);
    assert!(process.warnings().is_empty());
    drop(process);
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.specifications.len(), 3);
        assert_eq!(
            state.calls.iter().filter(|call| **call == "launch").count(),
            1
        );
        assert_eq!(state.closes, 1);
        assert_eq!(state.frees, 2);
        use crate::core_modules::process_security_environment_spec::process_security_environment_layout as psec;
        for (index, bytes) in state.specifications.iter().enumerate() {
            let spec = psec::root_as_process_security_environment(bytes).unwrap();
            let expected = ["registryRead,registryWrite", "registryWrite"].get(index);
            assert_eq!(spec.capabilities(), expected.copied());
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
fn policy_failures_native_invalid_payloads_stop_and_free_without_text_specifics() {
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
        let failure = api.create_with_diagnostics(b"spec", 0).unwrap_err();
        let error = crate::mxc_engine::Error::from(failure.response(false).into_mxc_error());
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
        assert_eq!(error.message, POLICY_DENIED_MESSAGE, "{fault}");
        STATE.with(|state| assert_eq!(state.borrow().frees, 1, "{fault}"));
    }
}

#[test]
fn policy_failures_native_maximum_byte_count_remains_usable() {
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
    let failure = api.create_with_diagnostics(b"spec", 0).unwrap_err();
    let error = crate::mxc_engine::Error::from(failure.response(false).into_mxc_error());
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
fn policy_failures_from_malformed_error_details_use_one_canonical_error() {
    let api = reset();
    let failure = api.create_with_diagnostics(b"spec", 0).unwrap_err();
    let valid = crate::mxc_engine::Error::from(failure.response(false).into_mxc_error());
    let stored = valid.details.as_deref().unwrap()["policyFailures"].clone();
    let mut wrong_version = stored.clone();
    wrong_version["formatVersion"] = 2.into();
    let mut over_limit = stored.clone();
    let result = stored["results"][0].clone();
    over_limit["results"] =
        vec![result; crate::mxc_common::policy_failures::MAX_RESULTS + 2].into();
    for (case, policy_failures) in [
        ("formatVersion", wrong_version),
        ("resultLimit", over_limit),
        ("shape", serde_json::json!([])),
    ] {
        let mut error = valid.clone();
        error.details = Some(Box::new(
            serde_json::json!({ "policyFailures": policy_failures }),
        ));
        let malformed = PolicyFailures::from_error(&error).unwrap_err();
        assert_eq!(
            malformed.code,
            crate::mxc_engine::ErrorCode::BackendError,
            "{case}"
        );
        assert_eq!(
            malformed.message, "native policy failures are malformed",
            "{case}"
        );
    }
}

#[test]
fn policy_failures_caller_merge_keeps_a_complete_terminal_batch() {
    let api = reset();
    let mut prior = PolicyFailures::default();
    for index in 0..64 {
        let mut result = STATE.with(|state| state.borrow().report.clone());
        result.details[0].resource = Some(format!(r"C:\history\{index}").encode_utf16().collect());
        prior.append(result);
    }
    prior.validate().unwrap();
    let failure = api.create_with_diagnostics(b"spec", 0).unwrap_err();
    let error = crate::mxc_engine::Error::from(failure.response(false).into_mxc_error());
    assert!(error
        .details
        .as_deref()
        .unwrap()
        .get("policyFeedbackError")
        .is_none());
    assert_eq!(error.native_code.as_deref(), Some("0x800704EC"));
    assert_eq!(
        error.operation.as_deref(),
        Some("CreateProcessSecurityEnvironment")
    );
    let current = PolicyFailures::from_error(&error).unwrap().unwrap();
    assert_eq!(current.results.len(), 1);
    let complete = prior.merged_with(&current).unwrap();
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
fn policy_preparation_capture_removal_is_authorable_and_strictly_submitted() {
    use crate::core_modules::process_security_environment_spec::process_security_environment_layout as psec;
    use crate::mxc_common::logger::{Logger, Mode};
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
    let mut failures = PolicyFailures::default();
    for capability in ["learningModeLogging", "permissiveLearningMode"] {
        failures.append(PolicyFailureResult {
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
    let original = serde_json::json!({
        "version": "1.1.0-alpha",
        "containment": "process",
        "process": {
            "commandLine": "cmd.exe /d /c echo mxc-policy-child",
            "cwd": directory.path(), "timeout": 5000,
        },
        "processContainer": {
            "learningMode": true,
            "captureDenials": {
                "mode": "allow", "retainEtl": true,
                "outputPath": directory.path().join("capture.json"),
            }
        }
    })
    .to_string();
    let prepared = prepare_candidate(&original, &failures);
    let candidate: serde_json::Value = serde_json::from_str(&prepared.request_json).unwrap();
    assert_eq!(candidate["version"], "1.1.0-alpha");
    assert_eq!(candidate["processContainer"]["learningMode"], false);
    assert!(candidate["processContainer"]
        .get("captureDenials")
        .is_none());
    assert!(candidate["processContainer"].get("capabilities").is_none());
    assert!(prepared.changes.iter().any(|change| {
        change.path == "/processContainer/captureDenials"
            && change.operation == crate::v1::dev::PolicyChangeOperation::Remove
            && change.before.is_object()
            && change.after.is_null()
    }));
    let request = parsed_request(&prepared.request_json);
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
    assert_eq!(stdout.trim(), "mxc-policy-child");
    assert_eq!(process.wait().unwrap(), 0);
    drop(process);
    assert_eq!(
        parsed_request(&original)
            .policy
            .capture_denials
            .unwrap()
            .mode,
        crate::mxc_common::models::CaptureDenialsMode::Allow
    );
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.specifications.len(), 1);
        let specification =
            psec::root_as_process_security_environment(&state.specifications[0]).unwrap();
        assert_eq!(specification.capabilities(), None);
        assert_eq!(
            state.calls.iter().filter(|call| **call == "launch").count(),
            1
        );
        assert_eq!(state.closes, 1);
    });
}

#[test]
fn policy_failures_native_capture_preserves_data_status_and_cleanup_not_prose() {
    let api = reset();
    STATE.with(|state| state.borrow_mut().handle = true);
    let error = api.create_with_diagnostics(b"spec", 0x40).unwrap_err();
    let rendered = format!("{error:?}");
    assert!(!rendered.contains("67, 58, 92, 119"), "{rendered}");
    assert!(rendered.contains("<redacted>"), "{rendered}");
    let error = crate::mxc_engine::Error::from(error.response(false).into_mxc_error());
    let failures = PolicyFailures::from_error(&error).unwrap().unwrap();
    assert_eq!(
        error.operation.as_deref(),
        Some("CreateProcessSecurityEnvironment")
    );
    assert_eq!(error.native_code.as_deref(), Some("0x800704EC"));
    assert_eq!(error.message, POLICY_DENIED_MESSAGE);
    assert_eq!(
        failures.results[0].details[0]
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
fn policy_failures_are_not_queried_after_success_or_unrelated_failure() {
    for status in [S_OK, E_FAIL] {
        let api = reset();
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.status = status;
            state.handle = status.is_ok();
        });
        drop(api.create_with_diagnostics(b"spec", 0));
        STATE.with(|state| {
            let state = state.borrow();
            assert!(!state.calls.contains(&"get"));
            assert_eq!(state.frees, 0);
            assert_eq!(state.closes, usize::from(status.is_ok()));
        });
    }
}

#[test]
fn policy_failures_getter_failure_frees_outputs_and_reports_unavailability() {
    let api = reset();
    STATE.with(|state| state.borrow_mut().getter_status = E_FAIL);
    let failure = api.create_with_diagnostics(b"spec", 0).unwrap_err();
    let error = crate::mxc_engine::Error::from(failure.response(false).into_mxc_error());
    assert!(PolicyFailures::from_error(&error).unwrap().is_none());
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
fn policy_failures_missing_getter_reports_unavailability_only_as_structured_data() {
    let mut api = reset();
    api.get_last_policy_result = None;
    let failure = api.create_with_diagnostics(b"spec", 0).unwrap_err();
    let error = crate::mxc_engine::Error::from(failure.response(false).into_mxc_error());
    assert!(PolicyFailures::from_error(&error).unwrap().is_none());
    assert!(error
        .details
        .as_deref()
        .unwrap()
        .get("policyResultUnavailable")
        .is_some());
    assert_eq!(error.message, POLICY_DENIED_MESSAGE);
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.flags, [0]);
        assert!(!state.calls.contains(&"get"));
    });
}

#[test]
fn policy_failures_unadvertised_or_failed_support_preserves_strict_creation() {
    for (support_status, support_flags) in [(S_OK, 0), (S_OK, 0x0f), (E_FAIL, 0x10)] {
        let api = reset();
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.support_status = support_status;
            state.support_flags = support_flags;
        });
        let caller_flags = 0x40;
        let failure = api
            .create_with_diagnostics(b"spec", caller_flags)
            .unwrap_err();
        STATE.with(|state| {
            let state = state.borrow();
            assert_eq!(state.flags, [caller_flags]);
            assert_eq!(state.calls, ["support", "create"]);
            assert_eq!(state.frees, 0);
        });
        let error = crate::mxc_engine::Error::from(failure.response(false).into_mxc_error());
        assert_eq!(error.native_code.as_deref(), Some("0x800704EC"));
        assert_eq!(
            error.operation.as_deref(),
            Some("CreateProcessSecurityEnvironment")
        );
        assert!(PolicyFailures::from_error(&error).unwrap().is_none());
        assert!(error.details.as_deref().unwrap()["policyResultUnavailable"]
            .as_str()
            .is_some_and(|reason| !reason.is_empty()));
        assert_eq!(error.message, POLICY_DENIED_MESSAGE);
    }
}
