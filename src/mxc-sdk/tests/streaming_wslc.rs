// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(all(windows, feature = "wslc"))]

use std::io::{Read, Write};
use std::path::Path;

use mxc_sdk::v1::configs::WslcConfig;
use mxc_sdk::v1::container::{
    deprovision_container, provision_container, run_in_container, spawn_in_container,
    start_container, stop_container,
};
use mxc_sdk::v1::{
    run, spawn, ContainerId, ContainerRequest, Containment, ExecutionRequest, MxcProcess,
    ProvisionRequest, WaitResult,
};

const SPAWN_COMMAND: &str = "sh -c 'readlink /proc/self/fd/0; cat'";
const RUN_COMMAND: &str = "sh -c 'readlink /proc/self/fd/0; cat; echo RUN_SAW_EOF'";

#[test]
#[ignore = "requires WSL2 with the WSLC runtime and alpine:latest in the create-and-run image store"]
#[serial_test::serial(wslc)]
fn streaming_wslc_spawn_forwards_stdin() {
    place_wslc_runtime_beside_test_binary();
    let process = spawn(wslc_request(SPAWN_COMMAND), Default::default()).expect("spawn");
    let output = write_stdin_and_read_to_end(process, b"SPAWN_INPUT\n");
    assert_read_a_stdin_pipe(&output, "SPAWN_INPUT");
}

#[test]
#[ignore = "requires WSL2 with the WSLC runtime and alpine:latest in the create-and-run image store"]
#[serial_test::serial(wslc)]
fn streaming_wslc_run_reads_end_of_file() {
    place_wslc_runtime_beside_test_binary();
    let output = run(wslc_request(RUN_COMMAND), Default::default()).expect("run");
    assert_eq!(output.outcome, WaitResult::Exited(0));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim_end(),
        "/dev/null\nRUN_SAW_EOF",
        "run must start the command with stdin at end-of-file"
    );
}

#[test]
#[ignore = "requires WSL2 with the WSLC runtime and alpine:latest in the daemon image store"]
#[serial_test::serial(wslc)]
fn streaming_wslc_lifecycle_stdin() {
    place_wslc_runtime_beside_test_binary();
    let container = StartedContainer::new();

    let process = spawn_in_container(&container.id, execution(SPAWN_COMMAND), Default::default())
        .expect("spawn in container");
    let output = write_stdin_and_read_to_end(process, b"LIFECYCLE_INPUT\n");
    assert_read_a_stdin_pipe(&output, "LIFECYCLE_INPUT");

    let output = run_in_container(&container.id, execution(RUN_COMMAND), Default::default())
        .expect("run in container");
    assert_eq!(output.outcome, WaitResult::Exited(0));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim_end(),
        "/dev/null\nRUN_SAW_EOF",
        "run_in_container must start the command with stdin at end-of-file"
    );
}

fn wslc_request(command: &str) -> ContainerRequest {
    ContainerRequest {
        containment: Containment::Wslc(WslcConfig::default()),
        timeout_ms: Some(60_000),
        ..ContainerRequest::new(command)
    }
}

fn execution(command: &str) -> ExecutionRequest {
    ExecutionRequest {
        timeout_ms: Some(60_000),
        ..ExecutionRequest::new(command)
    }
}

fn write_stdin_and_read_to_end(mut process: MxcProcess, input: &[u8]) -> String {
    let mut stdin = process
        .take_stdin()
        .expect("spawn must give a WSLC command a writable stdin");
    let mut stdout = process.take_stdout().expect("stdout");
    stdin.write_all(input).expect("write stdin");
    drop(stdin);
    let mut output = String::new();
    stdout.read_to_string(&mut output).expect("read stdout");
    assert_eq!(process.wait().expect("wait"), WaitResult::Exited(0));
    output
}

fn assert_read_a_stdin_pipe(output: &str, echoed: &str) {
    let (stdin, rest) = output
        .trim_end()
        .split_once('\n')
        .expect("the stdin readlink line, then the echoed input");
    assert!(
        stdin.starts_with("pipe:["),
        "spawn must give the command a stdin pipe, got {stdin}"
    );
    assert_eq!(rest, echoed);
}

fn place_wslc_runtime_beside_test_binary() {
    let built = Path::new(env!("CARGO_BIN_EXE_wxc-wslc-daemon"))
        .parent()
        .expect("Cargo's output directory");
    let test_binary = std::env::current_exe().expect("locate the test binary");
    let modified = |path: &Path| std::fs::metadata(path).and_then(|m| m.modified()).ok();

    // The SDK loads wslcsdk.dll and starts its daemon from beside the running
    // binary, and Cargo builds both one directory up from a test binary.
    for name in ["wxc-wslc-daemon.exe", "wslcsdk.dll"] {
        let (source, target) = (built.join(name), test_binary.with_file_name(name));

        // A bundled copy of this test runs where Cargo's output no longer exists.
        if source.exists() && modified(&target) < modified(&source) {
            std::fs::copy(&source, &target)
                .unwrap_or_else(|error| panic!("copy {name} beside the test binary: {error}"));
        }
    }
}

struct StartedContainer {
    id: ContainerId,
}

impl StartedContainer {
    fn new() -> Self {
        let id = provision_container(
            ProvisionRequest::wslc(Some("alpine:latest".to_string()), None),
            Default::default(),
        )
        .expect("provision")
        .container_id;
        let container = Self { id };
        start_container(&container.id, Default::default()).expect("start");
        container
    }
}

impl Drop for StartedContainer {
    fn drop(&mut self) {
        let _ = stop_container(&self.id, Default::default());
        if let Err(error) = deprovision_container(&self.id, Default::default()) {
            eprintln!("WARNING: WSLC deprovision failed: {error}");
        }
    }
}
