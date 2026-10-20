#![cfg(all(windows, target_arch = "x86_64", feature = "microvm"))]

// Phase 3 lifecycle and streaming coverage for the signed NVX agent.

use std::time::{SystemTime, UNIX_EPOCH};
use std::{io::Read, io::Write};

use mxc_sdk::v1::{
    self, ContainerRequest, Containment, DeprovisionOptions, ErrorCode, ExecutionRequest,
    FilesystemPolicy, NetworkAction, NetworkEgressPolicy, NetworkIngressPolicy, NetworkPeerPolicy,
    NetworkPolicy, NetworkPortPolicy, NetworkProtocol, NetworkRulePolicy, NetworkRuntimeConfig,
    ProvisionOptions, ProvisionRequest, RunInContainerOptions, RunOptions, SpawnInContainerOptions,
    SpawnInContainerWithPtyOptions, SpawnOptions, StartOptions, StopOptions, WaitResult,
};

#[test]
fn discovery_without_bundle_is_read_only() {
    const CHILD: &str = "MXC_NVX_DISCOVERY_CHILD";
    if std::env::var_os(CHILD).is_some() {
        assert!(!v1::available_backends()
            .iter()
            .any(|backend| backend.backend == "microvm"));
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let local = root.path().join("absent-local-app-data");
    let bundle = root.path().join("absent-bundle");
    let temp = root.path().join("absent-temp");
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "discovery_without_bundle_is_read_only",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .env("LOCALAPPDATA", &local)
        .env("TEMP", &temp)
        .env("TMP", &temp)
        .env(aci_edge_sandboxes::agent::BundledAgent::ENV_DIR, &bundle)
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "discovery child failed: {status}");
            break;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("read-only discovery child exceeded deadline");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(!local.exists());
    assert!(!bundle.exists());
    assert!(!temp.exists());
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}

fn process_only_request(command: &str) -> serde_json::Value {
    serde_json::json!({
        "version": "1.1.0-alpha",
        "containment": "microvm",
        "microvm": {"image": "mcr.microsoft.com/azurelinux/base/core:3.0"},
        "process": {
            "commandLine": command,
            "timeout": 30_000
        }
    })
}

fn lifecycle_provision_request() -> serde_json::Value {
    serde_json::json!({
        "version": "1.1.0-alpha",
        "phase": "provision",
        "containment": "microvm",
        "microvm": {"image": "mcr.microsoft.com/azurelinux/base/core:3.0"}
    })
}

fn assert_provision_image(
    parsed: &mxc_sdk::mxc_common::state_aware_request::ParsedStateAwareRequest,
) {
    use mxc_sdk::mxc_common::state_aware_operation::{StateAwareOperation, StateAwareProvision};
    match parsed.operation() {
        StateAwareOperation::Provision(StateAwareProvision::MicroVm(Some(config))) => {
            assert_eq!(config.image, "mcr.microsoft.com/azurelinux/base/core:3.0");
            assert_eq!(config.memory_mib, None);
        }
        other => panic!("expected image-bearing MicroVM provision, got {other:?}"),
    }
}

#[test]
fn ignored_vm_lifecycle_payload_parses_with_required_image_without_a_runtime() {
    use mxc_sdk::mxc_common::{
        config_parser::load_mxc_request_from_json,
        logger::{Logger, Mode},
        state_aware_request::MxcRequest,
    };
    let request = lifecycle_provision_request();
    let parsed =
        load_mxc_request_from_json(&request.to_string(), &mut Logger::new(Mode::Buffer)).unwrap();
    match parsed {
        MxcRequest::StateAware(parsed) => assert_provision_image(&parsed),
        other => panic!("expected lifecycle provision, got {other:?}"),
    }
    let mut invalid = request;
    invalid.as_object_mut().unwrap().remove("microvm");
    let error = mxc_sdk::__ffi::run_lifecycle_json(&invalid.to_string(), false, true).unwrap_err();
    assert_eq!(error.code, ErrorCode::MalformedRequest);
    assert!(error.message.contains("microvm"));
}

#[test]
fn powershell_authored_lifecycle_payload_parses_without_executing_the_cli() {
    use mxc_sdk::mxc_common::{
        config_parser::load_state_aware_request_from_json_with_options,
        logger::{Logger, Mode},
        state_aware_request::Phase,
    };
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("scripts")
        .join("run_microvm_state_aware_tests.ps1");
    let output_file = tempfile::tempfile().unwrap();
    let mut child = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(script)
        .args([
            "-PrintProvisionPayload",
            "-WxcExePath",
            "must-not-execute.exe",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(output_file.try_clone().unwrap())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("read-only PowerShell payload export exceeded deadline");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    use std::io::{Seek, SeekFrom};
    let mut output_file = output_file;
    output_file.seek(SeekFrom::Start(0)).unwrap();
    let mut json = String::new();
    output_file.read_to_string(&mut json).unwrap();
    let parsed = load_state_aware_request_from_json_with_options(
        &json,
        &mut Logger::new(Mode::Buffer),
        Phase::Provision,
        None,
        &[],
    )
    .unwrap();
    assert_provision_image(&parsed);
    let mut invalid: serde_json::Value = serde_json::from_str(&json).unwrap();
    invalid["microvm"].as_object_mut().unwrap().remove("image");
    let error = load_state_aware_request_from_json_with_options(
        &invalid.to_string(),
        &mut Logger::new(Mode::Buffer),
        Phase::Provision,
        None,
        &[],
    )
    .unwrap_err();
    match error {
        mxc_sdk::mxc_common::config_parser::ParseError::StateAware(error) => {
            assert_eq!(
                error.code,
                mxc_sdk::mxc_common::mxc_error::MxcErrorCode::MalformedRequest
            );
            assert!(error.message.contains("missing field `image`"), "{error}");
        }
        other => panic!("expected malformed lifecycle image, got {other:?}"),
    }
}

#[test]
fn powershell_lifecycle_failures_report_both_streams_and_preserve_cleanup() {
    use std::io::{Seek, SeekFrom};
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(r"..\..\tests\scripts\run_microvm_state_aware_tests.ps1");
    let root = tempfile::Builder::new()
        .prefix("nvx host fixture ")
        .tempdir()
        .unwrap();
    let executor = root.path().join("fake-executor.cmd");
    std::fs::write(
        &executor,
        r#"@echo off
        echo %2>>"%MXC_NVX_PHASE_EVENTS%"
        if "%2"=="%MXC_NVX_FAIL_PHASE%" (
          echo {"error":{"code":"BackendError","message":"STDOUT_%2_JSON_ERROR"}}
          echo STDERR_%2_MARKER 1>&2
          exit /b 23
        )
        if "%2"=="provision" (
          echo {"result":{"sandboxId":"microvm:fake-host-only"}}
        ) else if "%2"=="exec" (
          echo EXECUTOR_NVX_OK
        ) else (
          echo {"result":{}}
        )
        exit /b 0
        "#,
    )
    .unwrap();
    for (failure, expected) in [
        ("provision", vec!["provision"]),
        ("start", vec!["provision", "start", "deprovision"]),
        ("exec", vec!["provision", "start", "exec", "deprovision"]),
        (
            "stop",
            vec!["provision", "start", "exec", "stop", "deprovision"],
        ),
        (
            "deprovision",
            vec!["provision", "start", "exec", "stop", "deprovision"],
        ),
        (
            "none",
            vec!["provision", "start", "exec", "stop", "deprovision"],
        ),
    ] {
        let events = root.path().join(format!("{failure}-events.txt"));
        let mut stdout = tempfile::tempfile().unwrap();
        let mut stderr = tempfile::tempfile().unwrap();
        let mut child = std::process::Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(&script)
            .arg("-WxcExePath")
            .arg(&executor)
            .env("MXC_NVX_FAIL_PHASE", failure)
            .env("MXC_NVX_PHASE_EVENTS", &events)
            .stdin(std::process::Stdio::null())
            .stdout(stdout.try_clone().unwrap())
            .stderr(stderr.try_clone().unwrap())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("fake executor {failure} exceeded deadline");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        stdout.seek(SeekFrom::Start(0)).unwrap();
        stderr.seek(SeekFrom::Start(0)).unwrap();
        let mut out = String::new();
        let mut err = String::new();
        stdout.read_to_string(&mut out).unwrap();
        stderr.read_to_string(&mut err).unwrap();
        let actual = std::fs::read_to_string(events).unwrap();
        assert_eq!(
            actual.lines().collect::<Vec<_>>(),
            expected,
            "{failure}: {err}"
        );
        if failure == "none" {
            assert!(status.success(), "{out}\n{err}");
            assert!(out.contains("MicroVM state-aware executor E2E passed: microvm:fake-host-only"));
        } else {
            assert!(!status.success(), "{failure}");
            for required in [
                format!("{failure} failed: exit=23"),
                format!("STDOUT_{failure}_JSON_ERROR"),
                format!("STDERR_{failure}_MARKER"),
            ] {
                assert!(err.contains(&required), "missing {required}: {out}\n{err}");
            }
        }
    }
}
#[test]
fn microvm_sample_creation_corpus_parses_with_explicit_images() {
    use mxc_sdk::mxc_common::{
        config_parser::load_mxc_request_from_json,
        logger::{Logger, Mode},
        state_aware_request::MxcRequest,
    };
    let configs = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("configs");
    let mut count = 0;
    for entry in std::fs::read_dir(configs).unwrap() {
        let path = entry.unwrap().path();
        if !path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("microvm_")
            || path.extension().is_none_or(|extension| extension != "json")
        {
            continue;
        }
        let json = std::fs::read_to_string(&path).unwrap();
        let parsed = load_mxc_request_from_json(&json, &mut Logger::new(Mode::Buffer))
            .unwrap_or_else(|error| panic!("{}: {error:?}", path.display()));
        match parsed {
            MxcRequest::OneShot(request) => assert!(
                request
                    .microvm_image
                    .as_ref()
                    .is_some_and(|image| !image.is_empty()),
                "{} lost its explicit image",
                path.display()
            ),
            other => panic!("{}: unexpected {other:?}", path.display()),
        }
        count += 1;
    }
    assert_eq!(
        count, 16,
        "creation corpus changed; review explicit image coverage"
    );
}

fn run_nonce(label: &str) {
    let nonce = format!(
        "{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos()
    );
    let command = format!("printf '{}\\n'; uname -s", nonce.replace('\'', "'\"'\"'"));
    let result = mxc_sdk::__ffi::run_json(&process_only_request(&command).to_string(), true)
        .expect("exact alpha MicroVM request should run through the signed NVX agent");
    assert_eq!(
        result.outcome,
        WaitResult::Exited(0),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert!(
        stdout.contains(&nonce),
        "stdout did not contain nonce: {stdout}"
    );
    assert!(
        stdout.contains("Linux"),
        "stdout did not identify Linux: {stdout}"
    );
}

fn guest_path(host: &std::path::Path) -> String {
    let path = std::path::absolute(host).expect("absolute host path");
    let text = path.to_string_lossy().replace('\\', "/");
    assert!(text.as_bytes().get(1) == Some(&b':'), "{text}");
    format!("/mnt/{}/{}", text[..1].to_ascii_lowercase(), &text[3..])
}

#[test]
fn image_admission_precedes_runtime_setup_for_public_creation_paths() {
    for image in ["", " ", "python:\n3.12", "python:\u{0}3.12"] {
        let mut request = ContainerRequest::new("echo should-not-run");
        request.containment = Containment::MicroVm {
            image: image.to_owned(),
        };
        let error = v1::experimental::run(request, RunOptions::default()).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedRequest);
        assert!(error.message.contains("microvm.image"));

        let mut request = ContainerRequest::new("echo should-not-run");
        request.containment = Containment::MicroVm {
            image: image.to_owned(),
        };
        let error = v1::experimental::spawn(request, SpawnOptions::default())
            .err()
            .expect("invalid image must prevent streaming setup");
        assert_eq!(error.code, ErrorCode::MalformedRequest);
        assert!(error.message.contains("microvm.image"));

        let error = v1::experimental::container::provision_container(
            ProvisionRequest::microvm(image, None),
            ProvisionOptions::default(),
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedRequest);
        assert!(error.message.contains("microvm.image"));

        let mut json = process_only_request("echo should-not-run");
        json["microvm"]["image"] = serde_json::json!(image);
        let error = mxc_sdk::__ffi::run_json(&json.to_string(), true).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedRequest);
        assert!(error.message.contains("microvm.image"));

        let json = serde_json::json!({
            "version":"1.1.0-alpha", "phase":"provision", "containment":"microvm",
            "microvm":{"image":image}
        });
        let error = mxc_sdk::__ffi::run_lifecycle_json(&json.to_string(), false, true).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedRequest);
        assert!(error.message.contains("microvm.image"));
    }
}

#[test]
fn experimental_opt_in_is_required_before_backend_discovery() {
    let request = process_only_request("printf ok");
    let error = mxc_sdk::__ffi::run_json(&request.to_string(), false).unwrap_err();
    assert_eq!(error.code, ErrorCode::BackendUnavailable);
    assert!(error.message.contains("experimental"));
}

#[test]
fn exec_network_policy_is_rejected_before_runtime_setup_on_public_lifecycle_paths() {
    const CHILD: &str = "MXC_NVX_EXEC_NETWORK_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let root = tempfile::tempdir().unwrap();
        let local = root.path().join("absent-local");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "exec_network_policy_is_rejected_before_runtime_setup_on_public_lifecycle_paths",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("LOCALAPPDATA", &local)
            .env(
                aci_edge_sandboxes::agent::BundledAgent::ENV_DIR,
                root.path().join("absent-bundle"),
            )
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "exec-network child failed: {status}");
                break;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("exec-network child exceeded deadline");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        return;
    }

    let base = serde_json::json!({
        "version": "1.1.0-alpha", "phase": "exec",
        "sandboxId": "microvm:0123456789abcdef0123456789abcdef",
        "process": {"commandLine": "printf forbidden"}
    });
    let state_root = std::path::PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap());
    for network in [
        serde_json::json!({}),
        serde_json::json!({"egress": {"default": "deny"}}),
        serde_json::json!({"egress": {"default": "allow"}}),
        serde_json::json!({"ingress": {"default": "deny", "hostLoopback": "deny"}}),
        serde_json::json!({"ingress": {"default": "allow", "hostLoopback": "allow"}}),
        serde_json::json!({"egress": {"allow": []}}),
        serde_json::json!({"egress": {"deny": []}}),
        serde_json::json!({"egress": {"allow": [{"to": [{"cidr": "10.0.0.0/8"}]}]}}),
        serde_json::json!({"egress": {"deny": [{"to": [{"cidr": "192.0.2.0/24"}]}]}}),
    ] {
        let mut request = base.clone();
        request["network"] = network;
        let error =
            mxc_sdk::__ffi::run_lifecycle_json(&request.to_string(), true, true).unwrap_err();
        assert_eq!(error.code, ErrorCode::PolicyValidation);
        assert_eq!(
            error.message,
            "MicroVM network policy is fixed at provision"
        );
        let error = mxc_sdk::__ffi::execute_lifecycle_json(&request.to_string(), true)
            .err()
            .expect("piped exec must reject provision-time network policy");
        assert_eq!(error.code, ErrorCode::PolicyValidation);
        assert_eq!(
            error.message,
            "MicroVM network policy is fixed at provision"
        );
        assert!(
            !state_root.exists(),
            "network refusal created lifecycle state"
        );
    }
    for invalid in [
        serde_json::Value::Null,
        serde_json::json!({"egress": {"default": "invalid"}}),
        serde_json::json!({"unknown": true}),
    ] {
        let mut request = base.clone();
        request["network"] = invalid;
        let error =
            mxc_sdk::__ffi::run_lifecycle_json(&request.to_string(), true, true).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedRequest);
    }
    let mut proxy = base.clone();
    proxy["network"] = serde_json::json!({});
    proxy["runtimeConfig"] = serde_json::json!({"networkProxy": "http://127.0.0.1:3128"});
    let error = mxc_sdk::__ffi::run_lifecycle_json(&proxy.to_string(), true, true).unwrap_err();
    assert_eq!(error.code, ErrorCode::PolicyValidation);
    assert_eq!(
        error.message,
        "MicroVM network proxy policy is fixed at provision"
    );
    assert!(!state_root.exists());

    // Typed exec exposes only runtime proxy settings, not egress or ingress policy.
    let id = v1::ContainerId::parse("microvm:0123456789abcdef0123456789abcdef").unwrap();
    let mut request = ExecutionRequest::new("printf forbidden");
    request.network = Some(v1::ProcessNetworkPolicy {
        runtime_config: Some(NetworkRuntimeConfig {
            network_proxy: Some("http://127.0.0.1:3128".to_owned()),
        }),
    });
    let error = v1::experimental::container::validate_process(
        &id,
        request.clone(),
        SpawnInContainerOptions::default(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::PolicyValidation);
    assert_eq!(
        error.message,
        "MicroVM network proxy policy is fixed at provision"
    );
    let error = v1::experimental::container::spawn_in_container(
        &id,
        request.clone(),
        SpawnInContainerOptions::default(),
    )
    .err()
    .expect("typed runtime proxy must still fail before discovery");
    assert_eq!(error.code, ErrorCode::PolicyValidation);
    assert_eq!(
        error.message,
        "MicroVM network proxy policy is fixed at provision"
    );
    let error = v1::experimental::container::run_in_container(
        &id,
        request,
        RunInContainerOptions::default(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::PolicyValidation);
    assert_eq!(
        error.message,
        "MicroVM network proxy policy is fixed at provision"
    );
    assert!(!state_root.exists());

    let error = mxc_sdk::__ffi::run_lifecycle_json(&base.to_string(), true, true).unwrap_err();
    assert_eq!(error.code, ErrorCode::BackendUnavailable);
    assert!(error.message.contains("NVX"), "{error}");
    let error = mxc_sdk::__ffi::execute_lifecycle_json(&base.to_string(), true)
        .err()
        .expect("missing bundle must prevent omitted-network execution");
    assert_eq!(error.code, ErrorCode::BackendUnavailable);
    for network in [None, Some(v1::ProcessNetworkPolicy::default())] {
        for operation in ["validate", "spawn", "run"] {
            let mut request = ExecutionRequest::new("printf forbidden");
            request.network = network.clone();
            let error = match operation {
                "validate" => v1::experimental::container::validate_process(
                    &id,
                    request,
                    SpawnInContainerOptions::default(),
                )
                .err()
                .unwrap(),
                "spawn" => v1::experimental::container::spawn_in_container(
                    &id,
                    request,
                    SpawnInContainerOptions::default(),
                )
                .err()
                .unwrap(),
                "run" => v1::experimental::container::run_in_container(
                    &id,
                    request,
                    RunInContainerOptions::default(),
                )
                .unwrap_err(),
                _ => unreachable!(),
            };
            assert_eq!(error.code, ErrorCode::BackendUnavailable);
            assert!(error.message.contains("NVX"), "{error}");
        }
    }
}

#[test]
fn unsupported_ui_policy_is_rejected_before_runtime_discovery() {
    let mut request = process_only_request("printf ok");
    request["ui"] = serde_json::json!({"disable": true});
    let error = mxc_sdk::__ffi::run_json(&request.to_string(), true).unwrap_err();
    assert_eq!(error.code, ErrorCode::PolicyValidation);
    assert_eq!(error.message, "NVX does not support UI policy");
}

#[test]
#[ignore = "requires Windows x64, WHP, the staged signed NVX bundle, and MCR access"]
fn exact_alpha_json_runs_twice_through_signed_nvx_agent() {
    run_nonce("mxc-nvx-first");
    run_nonce("mxc-nvx-second");
}

#[test]
#[ignore = "requires Windows x64, WHP, the staged signed NVX bundle, and MCR access"]
fn typed_lifecycle_reuses_running_microvm() {
    assert!(
        v1::available_backends()
            .iter()
            .any(|backend| backend.backend == "microvm"),
        "configured signed NVX runtime should be discoverable"
    );
    let provisioned = v1::experimental::container::provision_container(
        ProvisionRequest::microvm("mcr.microsoft.com/azurelinux/base/core:3.0", Some(512)),
        ProvisionOptions::default(),
    )
    .expect("provision MicroVM");
    assert!(provisioned.container_id.as_str().starts_with("microvm:"));
    v1::experimental::container::start_container(
        &provisioned.container_id,
        StartOptions::default(),
    )
    .expect("start MicroVM");

    let first = v1::experimental::container::run_in_container(
        &provisioned.container_id,
        ExecutionRequest::new("printf first > /tmp/mxc-state"),
        RunInContainerOptions::default(),
    )
    .expect("first exec");
    assert_eq!(first.outcome, WaitResult::Exited(0));
    let second = v1::experimental::container::run_in_container(
        &provisioned.container_id,
        ExecutionRequest::new("cat /tmp/mxc-state"),
        RunInContainerOptions::default(),
    )
    .expect("second exec");
    assert_eq!(second.outcome, WaitResult::Exited(0));
    assert_eq!(second.stdout, b"first");

    v1::experimental::container::stop_container(&provisioned.container_id, StopOptions::default())
        .expect("stop MicroVM");
    v1::experimental::container::deprovision_container(
        &provisioned.container_id,
        DeprovisionOptions::default(),
    )
    .expect("deprovision MicroVM");
}

#[test]
#[ignore = "requires Windows x64, WHP, the staged signed NVX bundle, and MCR access"]
fn deprovisioning_one_microvm_does_not_disrupt_another() {
    let first = v1::experimental::container::provision_container(
        ProvisionRequest::microvm("mcr.microsoft.com/azurelinux/base/core:3.0", None),
        ProvisionOptions::default(),
    )
    .expect("provision first MicroVM");
    let second = v1::experimental::container::provision_container(
        ProvisionRequest::microvm("mcr.microsoft.com/azurelinux/base/core:3.0", None),
        ProvisionOptions::default(),
    )
    .expect("provision second MicroVM");
    v1::experimental::container::start_container(&first.container_id, StartOptions::default())
        .expect("start first MicroVM");
    v1::experimental::container::start_container(&second.container_id, StartOptions::default())
        .expect("start second MicroVM");

    let seeded = v1::experimental::container::run_in_container(
        &second.container_id,
        ExecutionRequest::new("printf second > /tmp/mxc-concurrent-state"),
        RunInContainerOptions::default(),
    )
    .expect("seed second MicroVM");
    assert_eq!(seeded.outcome, WaitResult::Exited(0));

    v1::experimental::container::stop_container(&first.container_id, StopOptions::default())
        .expect("stop first MicroVM");
    v1::experimental::container::deprovision_container(
        &first.container_id,
        DeprovisionOptions::default(),
    )
    .expect("deprovision first MicroVM");

    let surviving = v1::experimental::container::run_in_container(
        &second.container_id,
        ExecutionRequest::new("cat /tmp/mxc-concurrent-state"),
        RunInContainerOptions::default(),
    )
    .expect("exec in surviving MicroVM");
    assert_eq!(surviving.outcome, WaitResult::Exited(0));
    assert_eq!(surviving.stdout, b"second");

    v1::experimental::container::stop_container(&second.container_id, StopOptions::default())
        .expect("stop second MicroVM");
    v1::experimental::container::deprovision_container(
        &second.container_id,
        DeprovisionOptions::default(),
    )
    .expect("deprovision second MicroVM");
}

#[test]
#[ignore = "requires Windows x64, WHP, the staged signed NVX bundle, and MCR access"]
fn typed_lifecycle_streams_stdin_stdout_and_cancels() {
    let provisioned = v1::experimental::container::provision_container(
        ProvisionRequest::microvm("mcr.microsoft.com/azurelinux/base/core:3.0", None),
        ProvisionOptions::default(),
    )
    .expect("provision MicroVM");
    v1::experimental::container::start_container(
        &provisioned.container_id,
        StartOptions::default(),
    )
    .expect("start MicroVM");

    let mut process = v1::experimental::container::spawn_in_container(
        &provisioned.container_id,
        ExecutionRequest::new("cat"),
        SpawnInContainerOptions::default(),
    )
    .expect("spawn cat");
    let mut stdin = process.take_stdin().expect("piped stdin");
    let mut stdout = process.take_stdout().expect("piped stdout");
    let input = vec![b'x'; 2 * 1024 * 1024];
    let reader = std::thread::spawn(move || {
        let mut output = Vec::new();
        stdout.read_to_end(&mut output).unwrap();
        output
    });
    stdin.write_all(&input).unwrap();
    drop(stdin);
    assert_eq!(process.wait().unwrap(), WaitResult::Exited(0));
    assert_eq!(reader.join().unwrap(), input);

    let mut sleeper = v1::experimental::container::spawn_in_container(
        &provisioned.container_id,
        ExecutionRequest::new("sleep 120"),
        SpawnInContainerOptions::default(),
    )
    .expect("spawn sleeper");
    sleeper.kill().expect("cancel sleeper");
    assert_eq!(sleeper.wait().unwrap(), WaitResult::Exited(137));

    let mut timed_request = ExecutionRequest::new("sleep 120");
    timed_request.timeout_ms = Some(100);
    let timed = v1::experimental::container::run_in_container(
        &provisioned.container_id,
        timed_request,
        RunInContainerOptions::default(),
    )
    .expect("timed exec");
    assert_eq!(timed.outcome, WaitResult::TimedOut);

    v1::experimental::container::stop_container(&provisioned.container_id, StopOptions::default())
        .expect("stop MicroVM");
    v1::experimental::container::deprovision_container(
        &provisioned.container_id,
        DeprovisionOptions::default(),
    )
    .expect("deprovision MicroVM");
}

#[test]
#[ignore = "requires Windows x64, WHP, the staged signed NVX bundle, and MCR access"]
fn typed_create_and_run_requires_experimental_and_streams() {
    let mut denied = ContainerRequest::new("printf should-not-run");
    denied.containment = Containment::MicroVm {
        image: "mcr.microsoft.com/azurelinux/base/core:3.0".to_owned(),
    };
    let error = v1::run(denied, RunOptions::default()).unwrap_err();
    assert_eq!(error.code, ErrorCode::BackendUnavailable);
    assert!(error.message.contains("experimental"));

    let mut request = ContainerRequest::new("cat");
    request.containment = Containment::MicroVm {
        image: "mcr.microsoft.com/azurelinux/base/core:3.0".to_owned(),
    };
    let mut process =
        v1::experimental::spawn(request, SpawnOptions::default()).expect("spawn one-shot cat");
    let mut stdin = process.take_stdin().expect("one-shot stdin");
    let mut stdout = process.take_stdout().expect("one-shot stdout");
    stdin.write_all(b"one-shot-stream").unwrap();
    drop(stdin);
    assert_eq!(process.wait().unwrap(), WaitResult::Exited(0));
    let mut output = Vec::new();
    stdout.read_to_end(&mut output).unwrap();
    assert_eq!(output, b"one-shot-stream");
}

#[test]
#[ignore = "requires Windows x64, WHP, the staged signed NVX bundle, and MCR access"]
fn lifecycle_filesystem_policy_is_enforced() {
    let root = tempfile::tempdir().unwrap();
    let readonly = root.path().join("readonly");
    let readwrite = root.path().join("readwrite");
    std::fs::create_dir_all(&readonly).unwrap();
    std::fs::create_dir_all(&readwrite).unwrap();
    let input = readonly.join("input.txt");
    let secret = readonly.join("secret.txt");
    let output = readwrite.join("output.txt");
    std::fs::write(&input, "READ_ONLY").unwrap();
    std::fs::write(&secret, "SECRET").unwrap();

    let mut provision =
        ProvisionRequest::microvm("mcr.microsoft.com/azurelinux/base/core:3.0", None);
    provision.set_filesystem(FilesystemPolicy {
        readonly_paths: vec![readonly.to_string_lossy().into_owned()],
        readwrite_paths: vec![readwrite.to_string_lossy().into_owned()],
        denied_paths: vec![secret.to_string_lossy().into_owned()],
        clear_policy_on_exit: None,
    });
    let provisioned =
        v1::experimental::container::provision_container(provision, ProvisionOptions::default())
            .unwrap();
    v1::experimental::container::start_container(
        &provisioned.container_id,
        StartOptions::default(),
    )
    .unwrap();
    let command = format!(
        "test \"$(cat '{}')\" = READ_ONLY && ! printf bad > '{}' && printf GUEST_OUTPUT > '{}' && ! cat '{}'",
        guest_path(&input),
        guest_path(&input),
        guest_path(&output),
        guest_path(&secret)
    );
    let result = v1::experimental::container::run_in_container(
        &provisioned.container_id,
        ExecutionRequest::new(command),
        RunInContainerOptions::default(),
    )
    .unwrap();
    assert_eq!(result.outcome, WaitResult::Exited(0));
    assert_eq!(std::fs::read_to_string(output).unwrap(), "GUEST_OUTPUT");
    assert_eq!(std::fs::read_to_string(input).unwrap(), "READ_ONLY");
    v1::experimental::container::stop_container(&provisioned.container_id, StopOptions::default())
        .unwrap();
    v1::experimental::container::deprovision_container(
        &provisioned.container_id,
        DeprovisionOptions::default(),
    )
    .unwrap();
}

#[test]
#[ignore = "requires Windows x64, WHP, the staged signed NVX bundle, and MCR access"]
fn exact_json_lifecycle_routes_microvm_end_to_end() {
    let provision = lifecycle_provision_request();
    let response = mxc_sdk::__ffi::run_lifecycle_json(&provision.to_string(), false, true).unwrap();
    let envelope: serde_json::Value = serde_json::from_str(&response).unwrap();
    let id = envelope["result"]["sandboxId"].as_str().unwrap();
    assert!(id.starts_with("microvm:"));

    for phase in ["start", "stop", "deprovision"] {
        if phase == "stop" {
            let exec = serde_json::json!({
                "version": "1.1.0-alpha",
                "phase": "exec",
                "sandboxId": id,
                "process": {"commandLine": "printf JSON_LIFECYCLE"}
            });
            let result = mxc_sdk::__ffi::execute_lifecycle_json(&exec.to_string(), true).unwrap();
            let output = result.wait_with_output().unwrap();
            assert_eq!(output.outcome, WaitResult::Exited(0));
            assert_eq!(output.stdout, b"JSON_LIFECYCLE");
        }

        let request = serde_json::json!({
            "version": "1.1.0-alpha",
            "phase": phase,
            "sandboxId": id
        });
        mxc_sdk::__ffi::run_lifecycle_json(&request.to_string(), false, true).unwrap();
    }
}

fn run_with_network(network: NetworkPolicy, command: &str) -> v1::ExecutionResult {
    let mut provision =
        ProvisionRequest::microvm("mcr.microsoft.com/azurelinux/base/core:3.0", None);
    provision.set_network(network);
    let provisioned =
        v1::experimental::container::provision_container(provision, ProvisionOptions::default())
            .unwrap();
    v1::experimental::container::start_container(
        &provisioned.container_id,
        StartOptions::default(),
    )
    .unwrap();
    let result = v1::experimental::container::run_in_container(
        &provisioned.container_id,
        ExecutionRequest::new(command),
        RunInContainerOptions::default(),
    )
    .unwrap();
    v1::experimental::container::stop_container(&provisioned.container_id, StopOptions::default())
        .unwrap();
    v1::experimental::container::deprovision_container(
        &provisioned.container_id,
        DeprovisionOptions::default(),
    )
    .unwrap();
    result
}

#[test]
#[ignore = "requires Windows x64, WHP, the staged signed NVX bundle, MCR access, and internet egress"]
fn lifecycle_directional_network_policy_is_enforced() {
    let deny = NetworkPolicy {
        egress: Some(NetworkEgressPolicy {
            default: Some(NetworkAction::Deny),
            ..Default::default()
        }),
        ingress: Some(NetworkIngressPolicy {
            default: Some(NetworkAction::Deny),
            host_loopback: Some(NetworkAction::Deny),
        }),
        runtime_config: None,
    };
    let blocked = run_with_network(
        deny,
        "if curl -k --connect-timeout 3 --silent https://1.1.1.1 >/dev/null; then exit 1; else printf NETWORK_BLOCKED; fi",
    );
    assert_eq!(blocked.outcome, WaitResult::Exited(0));
    assert_eq!(blocked.stdout, b"NETWORK_BLOCKED");

    let allow = NetworkPolicy {
        egress: Some(NetworkEgressPolicy {
            default: Some(NetworkAction::Deny),
            allow: Some(vec![NetworkRulePolicy {
                to: Some(vec![NetworkPeerPolicy::new("1.1.1.1/32")]),
                ports: Some(vec![NetworkPortPolicy {
                    protocol: Some(NetworkProtocol::Tcp),
                    port: Some(443),
                    end_port: None,
                }]),
            }]),
            deny: None,
        }),
        ingress: Some(NetworkIngressPolicy {
            default: Some(NetworkAction::Deny),
            host_loopback: Some(NetworkAction::Deny),
        }),
        runtime_config: None,
    };
    let allowed = run_with_network(
        allow,
        "curl -k --fail --connect-timeout 5 --silent https://1.1.1.1 >/dev/null && printf NETWORK_ALLOWED",
    );
    assert_eq!(allowed.outcome, WaitResult::Exited(0));
    assert_eq!(allowed.stdout, b"NETWORK_ALLOWED");
}

#[test]
#[ignore = "requires Windows x64, WHP, the staged signed NVX bundle, and MCR access"]
fn lifecycle_proxy_routes_guest_http() {
    use std::net::TcpListener;
    use std::time::{Duration, Instant};

    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let proxy = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut request = Vec::new();
                    let mut buffer = [0u8; 1024];
                    loop {
                        let read = stream.read(&mut buffer).unwrap();
                        if read == 0 {
                            break;
                        }
                        request.extend_from_slice(&buffer[..read]);
                        if request.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                    }
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nPROXY_OK",
                        )
                        .unwrap();
                    return;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "guest never reached proxy");
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(error) => panic!("proxy accept failed: {error}"),
            }
        }
    });
    let network = NetworkPolicy {
        egress: Some(NetworkEgressPolicy {
            default: Some(NetworkAction::Deny),
            ..Default::default()
        }),
        ingress: Some(NetworkIngressPolicy {
            default: Some(NetworkAction::Deny),
            host_loopback: Some(NetworkAction::Deny),
        }),
        runtime_config: Some(NetworkRuntimeConfig {
            network_proxy: Some(format!("http://127.0.0.1:{port}")),
        }),
    };
    let result = run_with_network(
        network,
        "curl --fail --silent http://example.invalid/proxy-test",
    );
    proxy.join().unwrap();
    assert_eq!(result.outcome, WaitResult::Exited(0));
    assert_eq!(result.stdout, b"PROXY_OK");
}

#[test]
#[ignore = "requires Windows x64, WHP, the staged signed NVX bundle, and MCR access"]
fn pty_and_exec_time_proxy_fail_before_workload_launch() {
    let provisioned = v1::experimental::container::provision_container(
        ProvisionRequest::microvm("mcr.microsoft.com/azurelinux/base/core:3.0", None),
        ProvisionOptions::default(),
    )
    .unwrap();
    v1::experimental::container::start_container(
        &provisioned.container_id,
        StartOptions::default(),
    )
    .unwrap();

    let pty = v1::experimental::container::spawn_in_container_with_pty(
        &provisioned.container_id,
        ExecutionRequest::new("touch /tmp/pty-ran"),
        SpawnInContainerWithPtyOptions::default(),
    )
    .unwrap_err();
    assert_eq!(pty.code, ErrorCode::UnsupportedPhase);

    let proxy_exec = serde_json::json!({
        "version": "1.1.0-alpha",
        "phase": "exec",
        "sandboxId": provisioned.container_id.as_str(),
        "process": {"commandLine": "touch /tmp/proxy-ran"},
        "runtimeConfig": {"networkProxy": "http://127.0.0.1:3128"}
    });
    let proxy_error = match mxc_sdk::__ffi::execute_lifecycle_json(&proxy_exec.to_string(), true) {
        Ok(_) => panic!("exec-time proxy must be rejected before launch"),
        Err(error) => error,
    };
    assert_eq!(proxy_error.code, ErrorCode::PolicyValidation);

    let result = v1::experimental::container::run_in_container(
        &provisioned.container_id,
        ExecutionRequest::new("test ! -e /tmp/pty-ran && test ! -e /tmp/proxy-ran"),
        RunInContainerOptions::default(),
    )
    .unwrap();
    assert_eq!(result.outcome, WaitResult::Exited(0));

    v1::experimental::container::stop_container(&provisioned.container_id, StopOptions::default())
        .unwrap();
    v1::experimental::container::deprovision_container(
        &provisioned.container_id,
        DeprovisionOptions::default(),
    )
    .unwrap();
}
