// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows ProcessContainer streaming integration test, in its own
//! Windows-gated file. The sibling `streaming.rs` is `#![cfg(macos)]`, which
//! would otherwise make a `#[cfg(windows)]` test there impossible to compile.
//! Requires an elevated, host-prepped Windows host (see docs/host-prep.md), so
//! it is `#[ignore]`d.

#![cfg(target_os = "windows")]

use mxc_sdk::{
    build_request, build_request_with_containment, spawn_sandbox, Containment,
    ProcessContainerSection, SandboxPolicy, WaitOutcome,
};

#[test]
#[ignore = "requires an elevated, host-prepped Windows host (see docs/host-prep.md)"]
fn streaming_processcontainer_bidirectional_stdio() {
    use std::io::{Read, Write};

    let policy = SandboxPolicy {
        version: "0.7.0-alpha".to_string(),
        filesystem: Some(mxc_sdk::policy::FilesystemSection {
            readwrite_paths: vec!["C:\\Windows\\Temp".to_string()],
            readonly_paths: vec![],
            denied_paths: vec![],
            clear_policy_on_exit: None,
        }),
        network: None,
        ui: None,
        timeout_ms: None,
    };
    let mut request = build_request(&policy, None).expect("build_request");
    // `cmd /c more` echoes stdin to stdout until EOF, then exits.
    request.set_script("cmd /c more");
    let mut proc = spawn_sandbox(request).expect("spawn");

    let mut stdin = proc.take_stdin().expect("stdin available");
    let mut stdout = proc.take_stdout().expect("stdout available");

    stdin.write_all(b"ping-pong\r\n").expect("write stdin");
    drop(stdin);

    let mut out = String::new();
    stdout.read_to_string(&mut out).expect("read stdout");
    assert!(out.contains("ping-pong"), "got: {:?}", out);

    assert_eq!(proc.wait().expect("wait"), WaitOutcome::Exited(0));
}

#[test]
#[ignore = "requires an elevated, host-prepped Windows host with captureDenials support"]
fn processcontainer_capture_denials_returns_metadata() {
    use mxc_sdk::policy::CaptureDenialsSection;

    let output_dir =
        std::env::temp_dir().join(format!("mxc-sdk-capture-denials-{}", std::process::id()));
    std::fs::create_dir_all(&output_dir).expect("create capture output directory");

    let policy = SandboxPolicy {
        version: "0.8.0-alpha".to_string(),
        filesystem: Some(mxc_sdk::policy::FilesystemSection {
            readwrite_paths: vec!["C:\\Windows\\Temp".to_string()],
            readonly_paths: vec![],
            denied_paths: vec![],
            clear_policy_on_exit: None,
        }),
        network: None,
        ui: None,
        timeout_ms: Some(30_000),
    };
    let process_container = ProcessContainerSection {
        capture_denials: Some(CaptureDenialsSection {
            output_path: Some(
                output_dir
                    .join("denials.json")
                    .to_string_lossy()
                    .into_owned(),
            ),
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut request = build_request_with_containment(
        &policy,
        &Containment::ProcessContainer(process_container),
        None,
    )
    .expect("build explicit ProcessContainer request");
    request.set_script("cmd /c echo capture-denials-integration");

    let output = mxc_sdk::run(request).expect("run ProcessContainer with captureDenials");
    let capture = output
        .output_metadata
        .as_ref()
        .and_then(|metadata| metadata.capture_denials.as_ref())
        .expect("captureDenials output metadata");

    assert_eq!(output.outcome, WaitOutcome::Exited(0));
    assert!(
        std::path::Path::new(&capture.output_path).is_file(),
        "capture output should exist: {}",
        capture.output_path
    );

    std::fs::remove_dir_all(&output_dir).expect("remove capture output directory");
}
