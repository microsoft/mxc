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
