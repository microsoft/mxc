// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use std::io::Read;
use std::sync::Arc;

use crate::learning_mode_windows::LearningModeTraceSources;
use crate::mxc_common::logger::{Logger, Mode};
use crate::mxc_common::models::{
    ExecutionRequest, NetworkAction, NetworkEgressPolicy, NetworkIngressPolicy, ProxyAddress,
};
use crate::mxc_common::sandbox_process::{SandboxBackend, StdioMode};
use crate::process_container_common::base_container_runner::{
    BaseContainerRunner, BaseProcessLaunch, CaptureSessionFactory, CaptureSessionOps,
};
use crate::process_container_common::test_env::CaptureCapabilityGuard;
use windows::Win32::Foundation::{SetLastError, ERROR_ACCESS_DENIED};
use windows::Win32::System::Threading::{
    CreateProcessW, EXTENDED_STARTUPINFO_PRESENT, PROCESS_CREATION_FLAGS, STARTUPINFOW,
};
use windows_core::{PCWSTR, PWSTR};

#[derive(Default)]
struct LaunchObservations {
    environments: Vec<usize>,
    environment_blocks: Vec<String>,
    working_directories: Vec<String>,
}

thread_local! {
    static LAUNCHES: RefCell<LaunchObservations> = RefCell::new(LaunchObservations::default());
}

fn record_launch(launch: &BaseProcessLaunch<'_>) {
    let handle = launch.startup.environment_for_test().0 as usize;
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        assert!(
            !state.closed_handles.contains(&handle),
            "owner closed before attachment"
        );
        state.calls.push("launch");
    });
    LAUNCHES.with(|observations| {
        let mut observations = observations.borrow_mut();
        observations.environments.push(handle);
        observations
            .environment_blocks
            .push(String::from_utf16(launch.environment.unwrap()).unwrap());
        observations.working_directories.push(
            String::from_utf16(launch.working_directory)
                .unwrap()
                .trim_end_matches('\0')
                .into(),
        );
    });
}

fn launch_trusted_test_child(launch: BaseProcessLaunch<'_>) -> windows_core::Result<()> {
    record_launch(&launch);
    assert_eq!(
        String::from_utf16(launch.command_line)
            .unwrap()
            .trim_end_matches('\0'),
        "cmd.exe /d /c echo mxc-mutation-child",
    );
    let mut startup = launch.startup.startup_info().StartupInfo;
    startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    // The environment is a fake native owner. Launch only this fixed trusted
    // fixture without its PSEC attribute; keep suspension, stdio and job setup.
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

fn fail_test_launch(launch: BaseProcessLaunch<'_>) -> windows_core::Result<()> {
    record_launch(&launch);
    // SAFETY: this changes only the test thread's last-error slot.
    unsafe { SetLastError(ERROR_ACCESS_DENIED) };
    Err(windows_core::Error::from_hresult(
        ERROR_ACCESS_DENIED.to_hresult(),
    ))
}

struct OwnedCaptureFactory {
    fail_start: bool,
    sources: LearningModeTraceSources,
}

struct OwnedCapture(ProcessSecurityEnvironment);

impl CaptureSessionOps for OwnedCapture {
    fn environment(&self) -> HANDLE {
        self.0.raw()
    }

    fn finish(self: Box<Self>, _output: Option<&std::path::Path>) -> Result<(), LearningModeError> {
        STATE.with(|state| state.borrow_mut().calls.push("trace_finish"));
        self.0.close();
        // No fabricated ETL is analyzed. This also proves a later capture
        // failure does not replay creation or the already-completed workload.
        Err(LearningModeError::HResultCall {
            function: "StopLearningModeTrace",
            code: E_FAIL.0,
        })
    }
}

impl CaptureSessionFactory for OwnedCaptureFactory {
    fn trace_sources(&self) -> Result<LearningModeTraceSources, LearningModeError> {
        Ok(self.sources)
    }

    fn begin(
        &self,
        specification: &[u8],
        flags: u32,
        policy: &ContainerPolicy,
        capture_network_decisions: bool,
    ) -> Result<Box<dyn CaptureSessionOps>, CreationError> {
        let environment = crate::process_container_common::secenv::create_with_diagnostics(
            specification,
            flags,
            Some(policy),
            capture_network_decisions,
        )?;
        self.begin_with_environment(environment)
    }

    fn begin_with_environment(
        &self,
        environment: ProcessSecurityEnvironment,
    ) -> Result<Box<dyn CaptureSessionOps>, CreationError> {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            assert_eq!(environment.raw().0 as usize, state.inputs.len() * 16);
            state.calls.push("trace_start");
        });
        if self.fail_start {
            return Err(LearningModeError::HResultCall {
                function: "StartLearningModeTrace",
                code: POLICY_DENIED.0,
            }
            .into());
        }
        Ok(Box::new(OwnedCapture(environment)))
    }
}

fn fixture(capture: bool, mutate: bool, directory: &std::path::Path) -> ExecutionRequest {
    let mut request = ExecutionRequest {
        script_code: "cmd.exe /d /c echo mxc-mutation-child".into(),
        working_directory: directory.to_string_lossy().into_owned(),
        script_timeout: 5_000,
        policy_mutation_enabled: mutate,
        env: Some(vec![
            format!("SystemRoot={}", std::env::var("SystemRoot").unwrap()),
            format!("LOCALAPPDATA={}", directory.display()),
        ]),
        ..Default::default()
    };
    request.policy.network_egress = Some(NetworkEgressPolicy::default());
    request.policy.network_ingress = Some(NetworkIngressPolicy {
        default: NetworkAction::Allow,
        host_loopback: NetworkAction::Allow,
    });
    request.policy.network_proxy.address = Some(ProxyAddress::new("127.0.0.1".into(), 8080));
    request.policy.runtime_network_proxy_specified = true;
    if capture {
        request
            .policy
            .capabilities
            .push("learningModeLogging".into());
        request.policy.capture_denials = Some(Default::default());
    }
    request
}

fn inject_creation_plan(refusal: bool) -> ApiScope {
    let mut api = reset();
    api.version_support = Some(loopback_test_version);
    LAUNCHES.with(|observations| *observations.borrow_mut() = LaunchObservations::default());
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.support = 0x1f;
        if refusal {
            state
                .creation_plan
                .push_back((POLICY_DENIED, false, Some("networkLoopback".into())));
        }
        state.creation_plan.push_back((S_OK, true, None));
    });
    ApiScope::new(api)
}

#[test]
fn mutation_runner_reuses_owner_prepares_effective_environment_and_launches_once() {
    let _capabilities = CaptureCapabilityGuard::set(true, true);
    for capture in [false, true] {
        let _scope = inject_creation_plan(true);
        let directory = tempfile::tempdir().unwrap();
        let request = fixture(capture, true, directory.path());
        let original = request.clone();
        let mut runner = BaseContainerRunner::with_capture_factory(Arc::new(OwnedCaptureFactory {
            fail_start: false,
            sources: LearningModeTraceSources::AccessOnly,
        }))
        .with_process_launcher(launch_trusted_test_child);
        let mut logger = Logger::new(Mode::Buffer);
        let audit_path = directory.path().join("mutation-audit.log");
        logger.enable_file_sink(&audit_path).unwrap();
        crate::mxc_common::policy_identity::log_policy_hash(&request, &mut logger);
        let mut process = runner
            .spawn(&request, &mut logger, StdioMode::Pipes)
            .unwrap();
        let mut stdout = String::new();
        process
            .take_stdout()
            .unwrap()
            .read_to_string(&mut stdout)
            .unwrap();
        assert_eq!(stdout.trim(), "mxc-mutation-child");
        if capture {
            assert!(process
                .wait()
                .unwrap_err()
                .to_string()
                .contains("StopLearningModeTrace"));
        } else {
            assert_eq!(process.wait().unwrap(), 0);
        }
        drop(process);
        assert!(logger
            .warnings()
            .iter()
            .any(|text| text.contains("runtimeConfig.networkProxy")));
        assert_eq!(
            request
                .policy
                .network_proxy
                .address
                .as_ref()
                .unwrap()
                .to_url(),
            original
                .policy
                .network_proxy
                .address
                .as_ref()
                .unwrap()
                .to_url()
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
        LAUNCHES.with(|observations| {
            let observations = observations.borrow();
            assert_eq!(observations.environments, [32]);
            assert_eq!(
                observations.working_directories,
                [directory.path().to_string_lossy()]
            );
            assert!(!observations.environment_blocks[0]
                .to_ascii_lowercase()
                .contains("http_proxy="));
        });
        STATE.with(|state| {
            let state = state.borrow();
            assert_eq!(state.inputs.len(), 2);
            assert_eq!(state.closed_handles, [32]);
        });
        let actual: Vec<_> = calls()
            .into_iter()
            .filter(|call| *call != "support")
            .collect();
        assert_eq!(
            actual,
            if capture {
                vec![
                    "create",
                    "get_policy_result",
                    "create",
                    "trace_start",
                    "launch",
                    "trace_finish",
                    "close",
                ]
            } else {
                vec!["create", "get_policy_result", "create", "launch", "close"]
            }
        );
        let mut effective = request.clone();
        effective.policy.network_ingress.as_mut().unwrap().default = NetworkAction::Deny;
        effective
            .policy
            .network_ingress
            .as_mut()
            .unwrap()
            .host_loopback = NetworkAction::Deny;
        effective.policy.network_proxy = Default::default();
        effective.policy.runtime_network_proxy_specified = false;
        let audit = std::fs::read_to_string(&audit_path).unwrap();
        let hashes: Vec<_> = audit
            .lines()
            .filter(|line| line.contains("\"event\":\"mxc.PolicyHash\""))
            .map(|line| {
                let (_, json) = line.split_once("] ").unwrap();
                serde_json::from_str::<serde_json::Value>(json).unwrap()["policy_hash"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(
            hashes,
            [
                crate::mxc_common::policy_identity::policy_hash(&request),
                crate::mxc_common::policy_identity::policy_hash(&effective),
            ]
        );
    }
}

#[test]
fn mutation_runner_silent_cache_hits_record_the_effective_policy_hash() {
    use crate::mxc_common::policy_identity::{log_policy_hash, policy_hash};

    let _capabilities = CaptureCapabilityGuard::set(true, true);
    let _scope = inject_creation_plan(true);
    STATE.with(|state| {
        state
            .borrow_mut()
            .creation_plan
            .push_back((S_OK, true, None));
    });
    let directory = tempfile::tempdir().unwrap();
    let request = fixture(false, true, directory.path());
    let mut effective = request.clone();
    effective.policy.network_ingress.as_mut().unwrap().default = NetworkAction::Deny;
    effective
        .policy
        .network_ingress
        .as_mut()
        .unwrap()
        .host_loopback = NetworkAction::Deny;
    effective.policy.network_proxy = Default::default();
    effective.policy.runtime_network_proxy_specified = false;
    let mut runner =
        BaseContainerRunner::default().with_process_launcher(launch_trusted_test_child);

    // Fixture file I/O can change the creator token's ModifiedId.
    // Keep audit opens and reads outside the cache-reuse interval.
    let mut audits: Vec<_> = (0..2)
        .map(|creation| {
            let audit_path = directory.path().join(format!("creation-{creation}.log"));
            let mut logger = Logger::new(Mode::Buffer);
            logger.enable_file_sink(&audit_path).unwrap();
            (audit_path, logger)
        })
        .collect();
    for (creation, (_, logger)) in audits.iter_mut().enumerate() {
        log_policy_hash(&request, logger);
        let mut process = runner.spawn(&request, logger, StdioMode::Pipes).unwrap();
        let mut stdout = String::new();
        process
            .take_stdout()
            .unwrap()
            .read_to_string(&mut stdout)
            .unwrap();
        assert_eq!(stdout.trim(), "mxc-mutation-child");
        assert_eq!(process.wait().unwrap(), 0);
        drop(process);
        if creation == 0 {
            assert!(logger.warnings().iter().any(
                |warning| warning.starts_with("Sandbox configuration updated due to IT policy")
            ));
        } else {
            assert!(logger.warnings().is_empty());
        }
        STATE.with(|state| {
            let state = state.borrow();
            assert_eq!(state.inputs.len(), 2 + creation);
            if creation == 1 {
                assert_eq!(state.inputs[1], state.inputs[2]);
                assert_eq!(state.closed_handles, [32, 48]);
            }
        });
    }
    for (audit_path, _) in &audits {
        let audit = std::fs::read_to_string(audit_path).unwrap();
        let hashes: Vec<_> = audit
            .lines()
            .filter(|line| line.contains("\"event\":\"mxc.PolicyHash\""))
            .map(|line| {
                let (_, json) = line.split_once("] ").unwrap();
                serde_json::from_str::<serde_json::Value>(json).unwrap()["policy_hash"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(hashes, [policy_hash(&request), policy_hash(&effective)]);
    }
    LAUNCHES.with(|observations| {
        assert_eq!(observations.borrow().environments, [32, 48]);
    });
}

#[test]
fn mutation_runner_prefix_only_unc_failure_preserves_cached_restrictions() {
    use crate::mxc_common::config_parser::load_mxc_request_from_json;
    use crate::mxc_common::filesystem_canonical::{
        canonicalize_allowing_absent_tail, PathCanonical,
    };
    use crate::mxc_common::state_aware_request::MxcRequest;
    use crate::process_security_environment_spec::process_security_environment_layout as psec;

    let _capabilities = CaptureCapabilityGuard::set(true, true);
    let mut api = reset();
    api.version_support = Some(loopback_test_version);
    let _scope = ApiScope::new(api);
    LAUNCHES.with(|observations| *observations.borrow_mut() = LaunchObservations::default());
    let directory = tempfile::tempdir().unwrap();
    let path = match canonicalize_allowing_absent_tail(directory.path().to_str().unwrap()) {
        PathCanonical::Canonical(path) => path,
        resolution => panic!("test directory must have a canonical path: {resolution:?}"),
    };
    // Keep normalization's filesystem probes outside the same-creator reuse interval.
    let requests: Vec<_> = [None, Some(r"\\"), Some(r"\\\\")]
        .into_iter()
        .map(|extra| {
            let readonly: Vec<_> = extra.into_iter().collect();
            let json = serde_json::json!({
                "version": "1.0.0",
                "containment": "processcontainer",
                "process": { "commandLine": "cmd.exe /d /c echo mxc-mutation-child" },
                "filesystem": { "readwritePaths": [&path], "readonlyPaths": readonly },
            });
            let MxcRequest::OneShot(mut request) =
                load_mxc_request_from_json(&json.to_string(), &mut Logger::new(Mode::Buffer))
                    .unwrap()
            else {
                panic!("expected an ordinary creation request");
            };
            assert_eq!(request.policy.readonly_paths, readonly);
            request.policy_mutation_enabled = true;
            request.working_directory = path.clone();
            request.script_timeout = 5_000;
            request.env = Some(vec![
                format!("SystemRoot={}", std::env::var("SystemRoot").unwrap()),
                format!("LOCALAPPDATA={path}"),
            ]);
            request
        })
        .collect();
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.support = 0x1f;
        state.policy_details = Some(vec![layout::PolicyDetailT {
            failure_class: layout::FailureClass::Filesystem,
            failure_reason: layout::FailureReason::AccessExceedsCeiling,
            required_action: layout::RequiredAction::RestrictFilesystemAccess,
            resource_kind: layout::ResourceKind::Path,
            value_kind: layout::ValueKind::Access,
            flags: 3,
            requested_value: 2,
            required_value: 1,
            resource: Some(path.encode_utf16().collect()),
        }]);
        state.creation_plan.extend([
            (POLICY_DENIED, false, None),
            (S_OK, true, None),
            (E_INVALIDARG, false, None),
            (E_INVALIDARG, false, None),
            (S_OK, true, None),
        ]);
    });
    let mut runner =
        BaseContainerRunner::default().with_process_launcher(launch_trusted_test_child);
    for (index, request) in [&requests[0], &requests[1], &requests[2], &requests[0]]
        .into_iter()
        .enumerate()
    {
        let before = serde_json::to_value(request).unwrap();
        let mut logger = Logger::new(Mode::Buffer);
        if index == 0 || index == 3 {
            let mut process = runner
                .spawn(request, &mut logger, StdioMode::Pipes)
                .unwrap();
            let mut stdout = String::new();
            process
                .take_stdout()
                .unwrap()
                .read_to_string(&mut stdout)
                .unwrap();
            assert_eq!(stdout.trim(), "mxc-mutation-child");
            assert_eq!(process.wait().unwrap(), 0);
            drop(process);
            if index == 0 {
                assert!(logger
                    .warnings()
                    .iter()
                    .any(|warning| warning
                        .starts_with("Sandbox configuration updated due to IT policy")));
            } else {
                assert!(logger.warnings().is_empty(), "{:?}", logger.warnings());
            }
        } else {
            let error = match runner.spawn(request, &mut logger, StdioMode::Pipes) {
                Ok(_) => panic!("malformed current paths must retain the native creation failure"),
                Err(error) => error,
            };
            assert_eq!(
                error.failure_phase,
                crate::mxc_common::models::FailurePhase::LaunchFailed
            );
            assert!(error
                .error_message
                .contains("CreateProcessSecurityEnvironment"));
            assert!(
                error.error_message.contains("0x80070057"),
                "{}",
                error.error_message
            );
            LAUNCHES.with(|observations| {
                assert_eq!(observations.borrow().environments, [32]);
            });
        }
        assert_eq!(serde_json::to_value(request).unwrap(), before);
        STATE.with(|state| {
            let state = state.borrow();
            assert_eq!(state.inputs.len(), index + 2);
            let spec = psec::root_as_process_security_environment(&state.inputs.last().unwrap().0)
                .unwrap();
            if index == 0 || index == 3 {
                assert!(spec.fs_read_write().is_none_or(|paths| paths.is_empty()));
                assert_eq!(
                    spec.fs_read_only().unwrap().iter().collect::<Vec<_>>(),
                    [path.as_str()]
                );
            } else {
                assert_eq!(
                    spec.fs_read_write().unwrap().iter().collect::<Vec<_>>(),
                    [path.as_str()]
                );
                assert_eq!(
                    spec.fs_read_only().unwrap().iter().collect::<Vec<_>>(),
                    request.policy.readonly_paths,
                );
            }
        });
    }
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.inputs[1], state.inputs[4]);
        assert_eq!(state.closed_handles, [32, 80]);
        assert_eq!(state.allocations, state.frees);
        assert!(state.creation_plan.is_empty());
    });
    LAUNCHES.with(|observations| {
        assert_eq!(observations.borrow().environments, [32, 80]);
    });
}

#[test]
fn mutation_runner_cache_hits_preserve_fresh_psec_fields() {
    use crate::process_security_environment_spec::process_security_environment_layout as psec;

    let _capabilities = CaptureCapabilityGuard::set(true, true);
    let _scope = inject_creation_plan(true);
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.creation_plan.front_mut().unwrap().2 = Some("registryRead".into());
        state
            .creation_plan
            .extend([(S_OK, true, None), (S_OK, true, None)]);
    });
    let directory = tempfile::tempdir().unwrap();
    // Finish fixture file I/O before recording the first cached creator key.
    let paths: Vec<_> = (0..3)
        .map(|creation| {
            let ca_path = directory
                .path()
                .join(format!("credential-ca-{creation}.pem"));
            let readonly_path = directory.path().join(format!("readonly-{creation}"));
            let readwrite_path = directory.path().join(format!("readwrite-{creation}"));
            std::fs::write(&ca_path, "test CA fixture").unwrap();
            std::fs::create_dir(&readonly_path).unwrap();
            std::fs::create_dir(&readwrite_path).unwrap();
            (ca_path, readonly_path, readwrite_path)
        })
        .collect();
    let mut runner =
        BaseContainerRunner::default().with_process_launcher(launch_trusted_test_child);

    let mut attempts = 0;
    for (creation, (ca_path, readonly_path, readwrite_path)) in paths.iter().enumerate() {
        let mut request = fixture(false, true, directory.path());
        request.policy.capabilities = vec!["registryRead".into(), "registryWrite".into()];
        request.policy.readonly_paths = vec![
            ca_path.to_string_lossy().into_owned(),
            readonly_path.to_string_lossy().into_owned(),
        ];
        request.policy.readwrite_paths = vec![readwrite_path.to_string_lossy().into_owned()];
        if creation == 1 {
            request.policy.enumerate_paths = vec![directory.path().to_string_lossy().into_owned()];
        }
        request.policy.network_proxy.address = Some(ProxyAddress::new(
            "127.0.0.1".into(),
            8080 + creation as u16,
        ));
        let original = serde_json::to_value(&request).unwrap();
        let mut logger = Logger::new(Mode::Buffer);
        let mut process = runner
            .spawn(&request, &mut logger, StdioMode::Pipes)
            .unwrap();
        let mut stdout = String::new();
        process
            .take_stdout()
            .unwrap()
            .read_to_string(&mut stdout)
            .unwrap();
        assert_eq!(stdout.trim(), "mxc-mutation-child");
        assert_eq!(process.wait().unwrap(), 0);
        drop(process);
        if creation == 0 {
            assert!(logger.warnings().iter().any(
                |warning| warning.starts_with("Sandbox configuration updated due to IT policy")
            ));
        } else {
            assert!(logger.warnings().is_empty());
        }
        STATE.with(|state| {
            let state = state.borrow();
            let current = &state.inputs[attempts..];
            assert_eq!(current.len(), if creation == 0 { 2 } else { 1 });
            for (attempt, (bytes, flags)) in current.iter().enumerate() {
                assert_eq!(*flags, 0x2);
                let spec = psec::root_as_process_security_environment(bytes).unwrap();
                assert_eq!(
                    (spec.version().major(), spec.version().minor()),
                    (1, u16::from(creation == 1))
                );
                assert_eq!(
                    spec.fs_read_only().unwrap().iter().collect::<Vec<_>>(),
                    request
                        .policy
                        .readonly_paths
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                );
                assert_eq!(
                    spec.fs_read_write().unwrap().iter().collect::<Vec<_>>(),
                    request
                        .policy
                        .readwrite_paths
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                );
                assert!(spec.fs_deny().is_none());
                assert_eq!(
                    spec.fs_enumerate()
                        .map(|paths| paths.iter().collect::<Vec<_>>())
                        .unwrap_or_default(),
                    request
                        .policy
                        .enumerate_paths
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                );
                let network = spec.network_policy().unwrap();
                assert_eq!(
                    network.proxy().unwrap().url().unwrap(),
                    request
                        .policy
                        .network_proxy
                        .address
                        .as_ref()
                        .unwrap()
                        .to_url()
                );
                assert!(network.egress().is_none());
                assert!(network.ingress().is_none());
                assert_eq!(network.allowed_appcontainer_peer(), Some("MXC-Loopback"));
                let capabilities: Vec<_> = spec.capabilities().unwrap().split(',').collect();
                let before_repair = creation == 0 && attempt == 0;
                assert_eq!(capabilities.contains(&"registryRead"), before_repair);
                assert!(capabilities.contains(&"registryWrite"));
                assert!(capabilities.contains(&"privateNetworkClientServer"));
                assert!(capabilities.contains(&"networkLoopback"));
                assert_eq!(capabilities.len(), if before_repair { 4 } else { 3 });
            }
            assert_eq!(state.closed_handles, [32, 48, 64][..=creation]);
            assert_eq!(state.closes, creation + 1);
            attempts = state.inputs.len();
        });
        assert_eq!(serde_json::to_value(&request).unwrap(), original);
    }
    LAUNCHES.with(|observations| {
        assert_eq!(observations.borrow().environments, [32, 48, 64]);
    });
    let events: Vec<_> = calls()
        .into_iter()
        .filter(|event| *event != "support")
        .collect();
    assert_eq!(
        events,
        [
            "create",
            "get_policy_result",
            "create",
            "launch",
            "close",
            "create",
            "launch",
            "close",
            "create",
            "launch",
            "close",
        ]
    );
}

#[test]
fn mutation_runner_submits_the_actual_proxy_retry_without_network_capture_or_allowances() {
    use crate::process_security_environment_spec::process_security_environment_layout as psec;

    let _capabilities = CaptureCapabilityGuard::set(true, true);
    for capability in ["privateNetworkClientServer", "networkLoopback"] {
        let _scope = inject_creation_plan(true);
        STATE.with(|state| {
            state.borrow_mut().creation_plan.front_mut().unwrap().2 = Some(capability.into());
        });
        let directory = tempfile::tempdir().unwrap();
        let request = fixture(true, true, directory.path());
        let mut runner = BaseContainerRunner::with_capture_factory(Arc::new(OwnedCaptureFactory {
            fail_start: false,
            sources: LearningModeTraceSources::AccessAndNetwork,
        }))
        .with_process_launcher(launch_trusted_test_child);
        let mut logger = Logger::new(Mode::Buffer);
        let mut process = runner
            .spawn(&request, &mut logger, StdioMode::Pipes)
            .unwrap();
        let mut stdout = String::new();
        process
            .take_stdout()
            .unwrap()
            .read_to_string(&mut stdout)
            .unwrap();
        assert_eq!(stdout.trim(), "mxc-mutation-child");
        assert_eq!(process.wait().unwrap(), 0);
        assert!(process.output_metadata().is_none());
        drop(process);

        STATE.with(|state| {
            let state = state.borrow();
            assert_eq!(state.inputs.len(), 2);
            let first = psec::root_as_process_security_environment(&state.inputs[0].0).unwrap();
            assert_eq!((first.version().major(), first.version().minor()), (1, 0));
            let first_network = first.network_policy().unwrap();
            assert!(first_network.proxy().is_some());
            assert!(first_network.egress().is_none());
            assert!(first_network.ingress().is_none());

            let retry = psec::root_as_process_security_environment(&state.inputs[1].0).unwrap();
            assert_eq!((retry.version().major(), retry.version().minor()), (1, 0));
            assert!(retry.capabilities().is_none());
            let network = retry.network_policy().unwrap();
            assert!(network.proxy().is_none());
            assert!(network.allowed_appcontainer_peer().is_none());
            assert!(network.ingress().is_none());
            let egress = network.egress().unwrap();
            assert_eq!(egress.default_action(), psec::FilterAction::deny);
            assert!(egress.allow().is_none());
            assert!(egress.deny().is_none());
            assert_eq!(state.closed_handles, [32]);
        });
        assert!(logger.warnings().iter().any(|text| {
            text.contains("processContainer.captureDenials") && text.ends_with("-> null")
        }));
        assert!(request.policy.capture_denials.is_some());
        assert!(request.policy.network_proxy.is_enabled());
        let events: Vec<_> = calls()
            .into_iter()
            .filter(|event| *event != "support")
            .collect();
        assert_eq!(
            events,
            ["create", "get_policy_result", "create", "launch", "close"]
        );
        LAUNCHES.with(|observations| assert_eq!(observations.borrow().environments, [32]));
    }
}

#[test]
fn mutation_runner_rejects_contradictory_in_memory_proxy_posture_before_creation() {
    let _capabilities = CaptureCapabilityGuard::set(true, true);
    let _scope = inject_creation_plan(true);
    let directory = tempfile::tempdir().unwrap();
    let mut request = fixture(false, true, directory.path());
    request.policy.network_egress.as_mut().unwrap().default = NetworkAction::Allow;
    let mut runner = BaseContainerRunner::with_capture_factory(Arc::new(OwnedCaptureFactory {
        fail_start: false,
        sources: LearningModeTraceSources::AccessOnly,
    }))
    .with_process_launcher(fail_test_launch);
    let response = runner
        .spawn(&request, &mut Logger::new(Mode::Buffer), StdioMode::Pipes)
        .err()
        .unwrap();
    assert_eq!(
        response.failure_phase,
        crate::mxc_common::models::FailurePhase::Rejected
    );
    assert!(response
        .error_message
        .contains("no direct allow or deny rules"));
    assert!(calls().is_empty());
    LAUNCHES.with(|observations| assert!(observations.borrow().environments.is_empty()));
}

#[test]
fn mutation_runner_never_retries_trace_start_or_launch_failures() {
    let _capabilities = CaptureCapabilityGuard::set(true, true);
    for (capture, fail_start) in [(false, false), (true, false), (true, true)] {
        let _scope = inject_creation_plan(true);
        let directory = tempfile::tempdir().unwrap();
        let request = fixture(capture, true, directory.path());
        let mut runner = BaseContainerRunner::with_capture_factory(Arc::new(OwnedCaptureFactory {
            fail_start,
            sources: LearningModeTraceSources::AccessOnly,
        }))
        .with_process_launcher(fail_test_launch);
        let mut logger = Logger::new(Mode::Buffer);
        let response = runner
            .spawn(&request, &mut logger, StdioMode::Pipes)
            .err()
            .unwrap();
        assert!(response
            .error_message
            .contains("Attempted creation-policy changes"));
        assert!(response.standard_err.is_empty());
        assert!(!logger.warnings().is_empty());
        STATE.with(|state| {
            let state = state.borrow();
            assert_eq!(state.inputs.len(), 2);
            assert_eq!(state.closed_handles, [32]);
        });
        assert_eq!(
            calls()
                .iter()
                .filter(|call| **call == "get_policy_result")
                .count(),
            1
        );
        LAUNCHES.with(|observations| {
            assert_eq!(
                observations.borrow().environments.len(),
                usize::from(!fail_start)
            );
        });
    }
}

#[test]
fn mutation_runner_strict_control_stops_at_first_refusal_and_does_not_emit_mutations() {
    let _capabilities = CaptureCapabilityGuard::set(true, true);
    for capture in [false, true] {
        let _scope = inject_creation_plan(true);
        let directory = tempfile::tempdir().unwrap();
        let request = fixture(capture, false, directory.path());
        let mut runner = BaseContainerRunner::with_capture_factory(Arc::new(OwnedCaptureFactory {
            fail_start: false,
            sources: LearningModeTraceSources::AccessOnly,
        }))
        .with_process_launcher(fail_test_launch);
        let mut logger = Logger::new(Mode::Buffer);
        let response = runner
            .spawn(&request, &mut logger, StdioMode::Pipes)
            .err()
            .unwrap();
        assert!(response.error_message.contains("0x800704EC"));
        assert!(response.standard_err.is_empty());
        assert!(!response.error_message.contains("Policy mutation"));
        assert!(!response
            .error_message
            .contains("Sandbox configuration updated due to IT policy"));
        assert!(logger.warnings().is_empty());
        assert_eq!(calls().iter().filter(|call| **call == "create").count(), 1);
        LAUNCHES.with(|observations| assert!(observations.borrow().environments.is_empty()));
        assert_eq!(closes(), 0);
    }
}
