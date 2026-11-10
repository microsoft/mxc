// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows ProcessContainer streaming integration test, in its own
//! Windows-gated file. The sibling `streaming.rs` is `#![cfg(macos)]`, which
//! would otherwise make a `#[cfg(windows)]` test there impossible to compile.
//! Requires a PSEC-capable Windows host, so
//! it is `#[ignore]`d.

#![cfg(target_os = "windows")]

use mxc_sdk::v1::configs::ProcessContainerConfig;
use mxc_sdk::v1::WaitResult;
use mxc_sdk::v1::{spawn, ContainerRequest, Containment, FilesystemPolicy};

#[test]
#[ignore = "requires a PSEC-capable Windows host"]
fn dev_json_processcontainer_capture_and_pipes() {
    use mxc_sdk::v1::dev::{self, JsonOptions};
    use std::io::{Read, Write};

    for version in ["1.0.0", "1.1.0-alpha"] {
        let captured = serde_json::json!({
            "version": version,
            "containment": "process",
            "process": {
                "commandLine": "cmd.exe /c \"echo DEV_CAPTURE_OK & echo DEV_CAPTURE_ERR 1>&2 & exit /b 7\"",
                "timeout": 30000,
            },
        })
        .to_string();
        let output = dev::run_json(&captured, JsonOptions::default()).expect("capture exact JSON");
        assert_eq!(output.outcome, WaitResult::Exited(7));
        assert!(String::from_utf8_lossy(&output.stdout).contains("DEV_CAPTURE_OK"));
        assert!(String::from_utf8_lossy(&output.stderr).contains("DEV_CAPTURE_ERR"));

        let request = serde_json::json!({
            "version": version,
            "containment": "process",
            "process": {
                "commandLine": "cmd.exe /v:on /c \"set /p L= & echo DEV_PIPE:!L! & exit /b 9\"",
                "timeout": 30000,
            },
        })
        .to_string();
        let mut process = dev::spawn_json(&request, JsonOptions { experimental: true })
            .expect("spawn exact JSON");
        let mut stdin = process.take_stdin().expect("stdin");
        let mut stdout = process.take_stdout().expect("stdout");
        stdin.write_all(b"ping-pong\r\n").expect("write input");
        drop(stdin);
        let mut text = String::new();
        stdout.read_to_string(&mut text).expect("read output");
        assert!(text.contains("DEV_PIPE:ping-pong"), "{text}");
        assert_eq!(process.wait().expect("wait"), WaitResult::Exited(9));
    }
}

#[test]
#[ignore = "requires a PSEC-capable Windows host"]
fn dev_json_processcontainer_policy_feedback_restricts_current_request() {
    use mxc_sdk::v1::dev::{
        self, JsonOptions, PolicyChangeOperation, PolicyFailureDetail as D,
        PolicyFailureResult as R, PolicyFailures, PreparedPolicyRequest,
    };

    let directory = tempfile::tempdir().expect("policy preparation workspace");
    let restricted = directory.path().join("restricted");
    let unrelated = directory.path().join("unrelated");
    std::fs::create_dir(&restricted).unwrap();
    std::fs::create_dir(&unrelated).unwrap();
    let target = restricted.join("target.txt");
    let control = unrelated.join("control.txt");
    std::fs::write(&target, b"seed").unwrap();
    std::fs::write(&control, b"seed").unwrap();
    std::fs::write(restricted.join("relative.txt"), b"ORIGINAL_CWD").unwrap();
    std::fs::write(unrelated.join("relative.txt"), b"WRONG_CWD").unwrap();
    let resource: Vec<u16> = restricted.to_string_lossy().encode_utf16().collect();
    let failures = PolicyFailures::from_json(
        &serde_json::json!({
            "formatVersion": 1,
            "results": [{
                "version": 1, "minimumReaderVersion": 1, "outcome": R::OUTCOME_BLOCKED,
                "details": [{
                    "failureClass": D::CLASS_FILESYSTEM,
                    "failureReason": D::REASON_ACCESS_EXCEEDS_CEILING,
                    "requiredAction": D::ACTION_RESTRICT_FILESYSTEM_ACCESS,
                    "resourceKind": D::RESOURCE_KIND_PATH, "valueKind": D::VALUE_KIND_ACCESS,
                    "flags": D::FLAG_HAS_ACTIONABLE_DETAILS | D::FLAG_RESOURCE_COMPLETE,
                    "requestedValue": D::ACCESS_READ_WRITE.to_string(),
                    "requiredValue": D::ACCESS_READ_ONLY.to_string(), "resource": resource,
                }],
            }],
        })
        .to_string(),
    )
    .unwrap();
    let failures = PolicyFailures::default().merged_with(&failures).unwrap();
    let failures = PolicyFailures::from_json(&failures.to_json().unwrap()).unwrap();
    assert_eq!(failures.merged_with(&failures).unwrap(), failures);
    let accepts = |prepared: &PreparedPolicyRequest| {
        prepared.changes.len() == 3
            && prepared
                .changes
                .iter()
                .all(|change| match change.path.as_str() {
                    "/filesystem/readwritePaths" => {
                        change.operation == PolicyChangeOperation::Replace
                            && change.before == serde_json::json!([restricted, unrelated])
                            && change.after == serde_json::json!([unrelated])
                    }
                    "/filesystem/readonlyPaths" => {
                        change.operation == PolicyChangeOperation::Add
                            && change.before.is_null()
                            && change.after == serde_json::json!([restricted])
                    }
                    "/process/cwd" => {
                        change.operation == PolicyChangeOperation::Add
                            && change.before.is_null()
                            && change.after == serde_json::json!(restricted)
                    }
                    _ => false,
                })
    };
    for version in ["0.9.0-alpha", "1.0.0", "1.1.0-alpha"] {
        std::fs::write(&target, b"seed").unwrap();
        std::fs::write(&control, b"seed").unwrap();
        let request = serde_json::json!({
            "version": version, "containerId": "policy-preparation-public-test",
            "containment": "processcontainer",
            "process": {
                "commandLine": format!(
                    "cmd.exe /d /c echo CHANGED>>\"{}\" & echo CONTROL>>\"{}\"",
                    target.display(), control.display(),
                ),
                "timeout": 30000,
            },
            "filesystem": { "readwritePaths": [restricted, unrelated] },
        })
        .to_string();
        let options = JsonOptions {
            experimental: false,
        };
        let baseline = dev::run_json(&request, options).expect("strict writable control");
        assert_eq!(baseline.outcome, WaitResult::Exited(0));
        assert!(std::fs::read_to_string(&target)
            .unwrap()
            .contains("CHANGED"));
        std::fs::write(&target, b"seed").unwrap();
        std::fs::write(&control, b"seed").unwrap();

        // Observations are supplied, so the result does not depend on host policy.
        let prepared = dev::prepare_policy_json(&request, &failures, Default::default())
            .expect("prepare a candidate without executing");
        assert_eq!(std::fs::read(&target).unwrap(), b"seed");
        assert_eq!(std::fs::read(&control).unwrap(), b"seed");
        let prepared = PreparedPolicyRequest::from_json(&prepared.to_json().unwrap()).unwrap();
        assert!(
            accepts(&prepared),
            "caller rejects changes outside this explicit policy"
        );
        let candidate: serde_json::Value = serde_json::from_str(&prepared.request_json).unwrap();
        assert_eq!(candidate["version"], version);
        assert_eq!(candidate["containerId"], "policy-preparation-public-test");
        let output =
            dev::run_json(&prepared.request_json, options).expect("strict accepted creation");
        assert_eq!(output.outcome, WaitResult::Exited(0));
        assert_eq!(std::fs::read(&target).unwrap(), b"seed");
        assert!(std::fs::read_to_string(&control)
            .unwrap()
            .contains("CONTROL"));
        assert!(output
            .warnings
            .iter()
            .all(|warning| { !warning.contains("configuration updated due to IT policy") }));

        let mut changed_request: serde_json::Value = serde_json::from_str(&request).unwrap();
        changed_request["process"]["commandLine"] = format!(
            "cmd.exe /d /c type relative.txt & echo FRESH>>\"{}\"",
            control.display(),
        )
        .into();
        let before_control = std::fs::read(&control).unwrap();
        let prepared =
            dev::prepare_policy_json(&changed_request.to_string(), &failures, Default::default())
                .expect("prepare retained observations against the fresh request");
        assert_eq!(std::fs::read(&control).unwrap(), before_control);
        assert!(
            accepts(&prepared),
            "caller checks the fresh report before accepting"
        );
        let changed =
            dev::run_json(&prepared.request_json, options).expect("strict fresh candidate");
        assert_eq!(changed.outcome, WaitResult::Exited(0));
        let stdout = String::from_utf8_lossy(&changed.stdout);
        assert!(stdout.contains("ORIGINAL_CWD"), "{stdout}");
        assert!(!stdout.contains("WRONG_CWD"), "{stdout}");
        assert!(std::fs::read_to_string(&control).unwrap().contains("FRESH"));
        assert_eq!(std::fs::read(&target).unwrap(), b"seed");
        println!("MXC_POLICY_PREPARATION_STRICT_CREATE_OK:{version}");
    }
}

#[test]
#[ignore = "requires a PSEC-capable Windows host"]
fn streaming_processcontainer_bidirectional_stdio() {
    use std::io::{Read, Write};

    let request = ContainerRequest {
        filesystem: Some(FilesystemPolicy {
            readwrite_paths: vec!["C:\\Windows\\Temp".to_string()],
            readonly_paths: vec![],
            denied_paths: vec![],
            clear_policy_on_exit: None,
        }),
        containment: Containment::ProcessContainer(ProcessContainerConfig::default()),
        ..ContainerRequest::new("cmd /c more")
    };
    // `cmd /c more` echoes stdin to stdout until EOF, then exits.
    let mut proc = spawn(request, Default::default()).expect("spawn");

    let mut stdin = proc.take_stdin().expect("stdin available");
    let mut stdout = proc.take_stdout().expect("stdout available");

    stdin.write_all(b"ping-pong\r\n").expect("write stdin");
    drop(stdin);

    let mut out = String::new();
    stdout.read_to_string(&mut out).expect("read stdout");
    assert!(out.contains("ping-pong"), "got: {:?}", out);

    assert_eq!(proc.wait().expect("wait"), WaitResult::Exited(0));
}

#[test]
#[ignore = "requires a ProcessContainer proxy host and MXC_TEST_PROXY_* fixture variables"]
fn processcontainer_unpackaged_proxy_reaches_origin() {
    use mxc_sdk::v1::policy::{
        NetworkAction, NetworkEgressPolicy, NetworkIngressPolicy, NetworkPolicy,
        NetworkRuntimeConfig, UiPolicy,
    };

    let proxy_url = std::env::var("MXC_TEST_PROXY_URL").expect("running unpackaged proxy URL");
    let origin_url = std::env::var("MXC_TEST_PROXY_ORIGIN_URL").expect("proxy test origin URL");
    let expected_body =
        std::env::var("MXC_TEST_PROXY_EXPECTED_BODY").expect("expected proxy origin response");
    assert!(!expected_body.is_empty());
    let command = format!(
        "powershell.exe -NoProfile -Command \"\
        $ErrorActionPreference = 'Stop'; \
        $h = New-Object -ComObject WinHttp.WinHttpRequest.5.1; \
        $h.SetTimeouts(5000,5000,5000,5000); \
        $h.Open('GET','{origin_url}',$false); $h.Send(); \
        if ($h.Status -ne 200) {{ throw ('HTTP status ' + $h.Status) }}; \
        Write-Output ('PROXY_RESPONSE: ' + $h.ResponseText)\""
    );
    let request = ContainerRequest {
        containment: Containment::ProcessContainer(ProcessContainerConfig::default()),
        ui: Some(UiPolicy {
            disable: false,
            ..Default::default()
        }),
        timeout_ms: Some(30000),
        network: Some(NetworkPolicy {
            egress: Some(NetworkEgressPolicy {
                default: Some(NetworkAction::Deny),
                ..Default::default()
            }),
            ingress: Some(NetworkIngressPolicy {
                default: Some(NetworkAction::Allow),
                host_loopback: Some(NetworkAction::Allow),
            }),
            runtime_config: Some(NetworkRuntimeConfig {
                network_proxy: Some(proxy_url),
            }),
        }),
        ..ContainerRequest::new(command)
    };

    let result = mxc_sdk::v1::run(request, Default::default()).expect("proxy container run");
    assert_eq!(
        result.outcome,
        WaitResult::Exited(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert!(stdout.contains("PROXY_RESPONSE: "), "{}", stdout);
    assert!(stdout.contains(&expected_body), "{}", stdout);
}
