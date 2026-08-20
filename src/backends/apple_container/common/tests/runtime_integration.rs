// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(target_os = "macos")]

use std::io::{Read, Write};

use apple_container_common::AppleContainerBackend;
use wxc_common::logger::{Logger, Mode};
use wxc_common::models::{
    AppleContainerConfig, ContainmentBackend, ExecutionRequest, ExperimentalConfig, NetworkPolicy,
};
use wxc_common::sandbox_process::{SandboxBackend, StdioMode};

#[test]
#[ignore = "requires Apple Container 1.2.2 and the alpine:3.22 image"]
fn streams_stdin_stdout_stderr_and_propagates_exit_code() {
    let request = ExecutionRequest {
        container_id: "runtime-integration".to_string(),
        script_code:
            "read value; printf 'stdout:%s\\n' \"$value\"; printf 'stderr:%s\\n' \"$value\" >&2; exit 9"
                .to_string(),
        containment: ContainmentBackend::AppleContainer,
        script_timeout: 30_000,
        experimental_enabled: true,
        experimental: ExperimentalConfig {
            apple_container: Some(AppleContainerConfig {
                image: "docker.io/library/alpine:3.22".to_string(),
                cpu_count: Some(1),
                memory_mb: Some(512),
            }),
            ..Default::default()
        },
        policy: wxc_common::models::ContainerPolicy {
            default_network_policy: NetworkPolicy::Allow,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut backend = AppleContainerBackend::new();
    let mut logger = Logger::new(Mode::Buffer);
    let mut process = backend
        .spawn(&request, &mut logger, StdioMode::Pipes)
        .expect("spawn Apple Container");

    let mut stdin = process.take_stdin().expect("stdin pipe");
    stdin.write_all(b"stream-value\n").expect("write stdin");
    drop(stdin);

    let mut stdout = process.take_stdout().expect("stdout pipe");
    let mut stderr = process.take_stderr().expect("stderr pipe");
    let stdout_thread = std::thread::spawn(move || {
        let mut output = String::new();
        stdout.read_to_string(&mut output).expect("read stdout");
        output
    });
    let stderr_thread = std::thread::spawn(move || {
        let mut output = String::new();
        stderr.read_to_string(&mut output).expect("read stderr");
        output
    });

    assert_eq!(process.wait().expect("wait"), 9);
    assert_eq!(
        stdout_thread.join().expect("stdout thread"),
        "stdout:stream-value\n"
    );
    assert_eq!(
        stderr_thread.join().expect("stderr thread"),
        "stderr:stream-value\n"
    );
}
