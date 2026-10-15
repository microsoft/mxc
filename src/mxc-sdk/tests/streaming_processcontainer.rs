// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows ProcessContainer streaming integration test, in its own
//! Windows-gated file. The sibling `streaming.rs` is `#![cfg(macos)]`, which
//! would otherwise make a `#[cfg(windows)]` test there impossible to compile.
//! Requires an elevated, host-prepped Windows host (see docs/backends/process-container/host-prep.md), so
//! it is `#[ignore]`d.

#![cfg(target_os = "windows")]

use mxc_sdk::v1::configs::ProcessContainerConfig;
use mxc_sdk::v1::WaitResult;
use mxc_sdk::v1::{spawn, ContainerRequest, Containment, FilesystemPolicy};

#[test]
#[ignore = "requires an elevated, host-prepped Windows host (see docs/backends/process-container/host-prep.md)"]
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

/// A raw `1.1.0-alpha` ProcessContainer request with the given `resources`.
fn processcontainer_resources_json(command: &str, resources: &str) -> String {
    serde_json::json!({
        "version": "1.1.0-alpha",
        "containment": "processcontainer",
        "process": { "commandLine": command, "timeout": 60_000, "cwd": "C:\\Windows\\Temp" },
        "filesystem": { "readwritePaths": ["C:\\Windows\\Temp"] },
        "resources": serde_json::from_str::<serde_json::Value>(resources).unwrap(),
    })
    .to_string()
}

/// Run `command` under `resources`, returning its exit, stdout, and usage.
fn run_with_resources(
    command: &str,
    resources: &str,
) -> (WaitResult, String, Option<mxc_sdk::v1::ResourceUsage>) {
    use std::io::Read;

    let mut proc = mxc_sdk::__ffi::spawn_container_json(
        &processcontainer_resources_json(command, resources),
        false,
    )
    .expect("spawn");
    let mut stdout = proc.take_stdout().expect("stdout available");
    let mut out = String::new();
    stdout.read_to_string(&mut out).expect("read stdout");
    let outcome = proc.wait().expect("wait");
    let usage = proc
        .output_metadata()
        .and_then(|metadata| metadata.resource_usage);
    (outcome, out, usage)
}

#[test]
#[ignore = "requires an elevated, host-prepped Windows host (see docs/backends/process-container/host-prep.md)"]
fn processcontainer_empty_resources_report_usage() {
    let (outcome, out, usage) =
        run_with_resources("cmd /c \"for /l %i in (1,1,2000) do @echo %i\"", "{}");

    assert_eq!(outcome, WaitResult::Exited(0));
    assert!(out.contains("2000"), "{out:?}");
    let usage = usage.expect("resource usage reported");
    assert!(usage.user_cpu_time_us + usage.system_cpu_time_us > 0);
    assert!(usage.peak_memory_bytes.is_some_and(|bytes| bytes > 0));
    assert_eq!(usage.limit_exceeded, None);
}

#[test]
#[ignore = "requires an elevated, host-prepped Windows host (see docs/backends/process-container/host-prep.md)"]
fn processcontainer_cpu_time_limit_stops_the_workload() {
    let start = std::time::Instant::now();
    let (outcome, _, usage) = run_with_resources(
        "cmd /c \"for /l %i in (0,0,1) do @rem\"",
        r#"{"cpuTimeMs": 1000}"#,
    );

    assert_ne!(outcome, WaitResult::Exited(0));
    assert!(start.elapsed() < std::time::Duration::from_secs(30));
    assert_eq!(
        usage.expect("resource usage reported").limit_exceeded,
        Some(mxc_sdk::v1::ResourceLimit::CpuTime)
    );
}

#[test]
#[ignore = "requires an elevated, host-prepped Windows host (see docs/backends/process-container/host-prep.md)"]
fn processcontainer_max_processes_allows_up_to_the_limit() {
    let (outcome, out, usage) =
        run_with_resources("cmd /c \"cmd /c echo inner\"", r#"{"maxProcesses": 2}"#);

    assert_eq!(outcome, WaitResult::Exited(0));
    assert!(out.contains("inner"), "{out:?}");
    assert_eq!(usage.expect("resource usage reported").limit_exceeded, None);
}

#[test]
#[ignore = "requires an elevated, host-prepped Windows host (see docs/backends/process-container/host-prep.md)"]
fn processcontainer_max_processes_refuses_another_process() {
    let (outcome, _, usage) =
        run_with_resources("cmd /c \"cmd /c exit 0\"", r#"{"maxProcesses": 1}"#);

    assert_ne!(outcome, WaitResult::Exited(0));
    assert_eq!(
        usage.expect("resource usage reported").limit_exceeded,
        Some(mxc_sdk::v1::ResourceLimit::MaxProcesses)
    );
}

#[test]
#[ignore = "requires an elevated, host-prepped Windows host (see docs/backends/process-container/host-prep.md)"]
fn processcontainer_reports_no_usage_without_resources() {
    let request = ContainerRequest {
        containment: Containment::ProcessContainer(ProcessContainerConfig::default()),
        ..ContainerRequest::new("cmd /c exit 0")
    };
    let mut proc = spawn(request, Default::default()).expect("spawn");

    assert_eq!(proc.wait().expect("wait"), WaitResult::Exited(0));
    assert!(proc
        .output_metadata()
        .and_then(|metadata| metadata.resource_usage)
        .is_none());
}
