// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(target_os = "macos")]

use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use apple_container_common::cli::NETWORK_BLOCK_INIT_IMAGE;
use apple_container_common::AppleContainerBackend;
use wxc_common::logger::{Logger, Mode};
use wxc_common::models::{
    AppleContainerConfig, ContainmentBackend, ExecutionRequest, ExperimentalConfig, NetworkPolicy,
};
use wxc_common::sandbox_process::{SandboxBackend, StdioMode};

const ALPINE_IMAGE: &str = "docker.io/library/alpine:3.22";
const PYTHON_IMAGE: &str = "docker.io/library/python:3.13-alpine";
const INTEGRATION_REQUIREMENTS: &str =
    "requires Apple Container 1.2.2 and the qualification images";

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

struct RunOutput {
    exit_code: i32,
    stdout: String,
    stderr: String,
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "mxc-apple-qualification-{}-{sequence}-{label}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create qualification temp directory");
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn request(script: impl Into<String>, image: &str, network: NetworkPolicy) -> ExecutionRequest {
    ExecutionRequest {
        container_id: "runtime-integration".to_string(),
        script_code: script.into(),
        containment: ContainmentBackend::AppleContainer,
        script_timeout: 30_000,
        experimental_enabled: true,
        experimental: ExperimentalConfig {
            apple_container: Some(AppleContainerConfig {
                image: image.to_string(),
                cpu_count: Some(1),
                memory_mb: Some(512),
            }),
            ..Default::default()
        },
        policy: wxc_common::models::ContainerPolicy {
            default_network_policy: network,
            ..Default::default()
        },
        ..Default::default()
    }
}

fn spawn_request(
    request: &ExecutionRequest,
) -> Result<Box<dyn wxc_common::sandbox_process::SandboxProcess>, String> {
    let mut backend = AppleContainerBackend::new();
    let mut logger = Logger::new(Mode::Buffer);
    backend
        .spawn(request, &mut logger, StdioMode::Pipes)
        .map_err(|response| response.error_message)
}

fn resource_ids(args: &[&str], prefix: &str) -> Vec<String> {
    let output = Command::new("/usr/local/bin/container")
        .args(args)
        .output()
        .expect("list Apple Container resources");
    assert!(
        output.status.success(),
        "resource listing failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice::<serde_json::Value>(&output.stdout)
        .expect("parse resource listing")
        .as_array()
        .expect("resource listing must be an array")
        .iter()
        .filter_map(|resource| resource.get("id")?.as_str())
        .filter(|id| id.starts_with(prefix))
        .map(str::to_string)
        .collect()
}

fn crash_recovery_records() -> Vec<PathBuf> {
    let directory = PathBuf::from(std::env::var_os("HOME").expect("HOME"))
        .join("Library/Application Support/Microsoft/MXC/apple-container/recovery");
    match fs::read_dir(directory) {
        Ok(entries) => entries
            .map(|entry| entry.expect("read recovery entry").path())
            .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
            .filter(|path| {
                fs::read_to_string(path)
                    .expect("read recovery record")
                    .contains("\"containerHint\":\"crash-orphan\"")
            })
            .collect(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => panic!("read recovery directory: {error}"),
    }
}

fn run_request(request: &ExecutionRequest, input: &[u8]) -> io::Result<RunOutput> {
    let mut process = spawn_request(request).map_err(io::Error::other)?;
    let mut stdin = process.take_stdin().expect("stdin pipe");
    let mut stdout = process.take_stdout().expect("stdout pipe");
    let mut stderr = process.take_stderr().expect("stderr pipe");
    let stdout_thread = thread::spawn(move || {
        let mut output = String::new();
        stdout.read_to_string(&mut output)?;
        Ok::<_, io::Error>(output)
    });
    let stderr_thread = thread::spawn(move || {
        let mut output = String::new();
        stderr.read_to_string(&mut output)?;
        Ok::<_, io::Error>(output)
    });

    stdin.write_all(input)?;
    drop(stdin);
    let exit_code = process.wait();
    let stdout = stdout_thread
        .join()
        .map_err(|_| io::Error::other("stdout reader panicked"))??;
    let stderr = stderr_thread
        .join()
        .map_err(|_| io::Error::other("stderr reader panicked"))??;

    Ok(RunOutput {
        exit_code: exit_code?,
        stdout,
        stderr,
    })
}

#[test]
#[ignore = "requires Apple Container 1.2.2 and the qualification images"]
fn streams_stdin_stdout_stderr_and_propagates_exit_code() {
    let output = run_request(
        &request(
            "read value; printf 'stdout:%s\\n' \"$value\"; \
             printf 'stderr:%s\\n' \"$value\" >&2; exit 9",
            ALPINE_IMAGE,
            NetworkPolicy::Allow,
        ),
        b"stream-value\n",
    )
    .expect(INTEGRATION_REQUIREMENTS);

    assert_eq!(output.exit_code, 9);
    assert_eq!(output.stdout, "stdout:stream-value\n");
    assert_eq!(output.stderr, "stderr:stream-value\n");
}

#[test]
#[ignore = "requires Apple Container 1.2.2 and the qualification images"]
fn honors_environment_working_directory_and_mount_access() {
    let root = TempDir::new("policy");
    let readwrite = root.path.join("readwrite");
    let readonly = root.path.join("readonly");
    fs::create_dir(&readwrite).unwrap();
    fs::create_dir(&readonly).unwrap();
    fs::write(readonly.join("input.txt"), "read-only-input\n").unwrap();

    let script = format!(
        "test \"$MXC_QUALIFICATION\" = expected && \
         test \"$PWD\" = \"{readwrite}\" && \
         cat \"{readonly}/input.txt\" && \
         printf 'written\\n' > output.txt && \
         if printf 'forbidden\\n' > \"{readonly}/forbidden.txt\" 2>/dev/null; then \
           exit 41; \
         fi && \
         cat output.txt",
        readwrite = readwrite.display(),
        readonly = readonly.display(),
    );
    let mut request = request(script, ALPINE_IMAGE, NetworkPolicy::Allow);
    request.working_directory = readwrite.to_string_lossy().into_owned();
    request.env = vec!["MXC_QUALIFICATION=expected".to_string()];
    request.policy.readwrite_paths = vec![readwrite.to_string_lossy().into_owned()];
    request.policy.readonly_paths = vec![readonly.to_string_lossy().into_owned()];

    let output = run_request(&request, b"").expect(INTEGRATION_REQUIREMENTS);

    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert_eq!(output.stdout, "read-only-input\nwritten\n");
    assert_eq!(
        fs::read_to_string(readwrite.join("output.txt")).unwrap(),
        "written\n"
    );
    assert!(!readonly.join("forbidden.txt").exists());
}

#[test]
#[ignore = "requires Apple Container 1.2.2 and the qualification images"]
fn timeout_terminates_the_workload_and_cleans_up() {
    let mut request = request("sleep 60", ALPINE_IMAGE, NetworkPolicy::Allow);
    request.script_timeout = 500;
    let mut process = spawn_request(&request).expect(INTEGRATION_REQUIREMENTS);

    let error = process.wait().expect_err("workload should time out");

    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(error.to_string().contains("timed out"), "{error}");
}

#[test]
#[ignore = "requires Apple Container 1.2.2 and the qualification images"]
fn concurrent_runs_keep_streams_and_resources_isolated() {
    let runs = ["first", "second", "third"].map(|marker| {
        thread::spawn(move || {
            run_request(
                &request(
                    format!("sleep 1; printf '{marker}\\n'"),
                    ALPINE_IMAGE,
                    NetworkPolicy::Allow,
                ),
                b"",
            )
        })
    });

    for (run, expected) in runs.into_iter().zip(["first\n", "second\n", "third\n"]) {
        let output = run
            .join()
            .expect("qualification thread")
            .expect(INTEGRATION_REQUIREMENTS);
        assert_eq!(output.exit_code, 0, "{}", output.stderr);
        assert_eq!(output.stdout, expected);
    }
}

#[test]
#[ignore = "helper invoked by crash_recovery_reclaims_orphaned_resources"]
fn crash_recovery_helper() {
    if std::env::var_os("MXC_APPLE_CRASH_HELPER").is_none() {
        return;
    }
    let mut crash_request = request("sleep 60", ALPINE_IMAGE, NetworkPolicy::Block);
    crash_request.container_id = "crash-orphan".to_string();
    let _process = spawn_request(&crash_request).expect(INTEGRATION_REQUIREMENTS);
    thread::sleep(Duration::from_secs(3));
    std::process::exit(86);
}

#[test]
#[ignore = "requires Apple Container 1.2.2 and the qualification images"]
fn crash_recovery_reclaims_orphaned_resources() {
    let status = Command::new(std::env::current_exe().expect("current test executable"))
        .args([
            "--ignored",
            "--exact",
            "crash_recovery_helper",
            "--nocapture",
        ])
        .env("MXC_APPLE_CRASH_HELPER", "1")
        .status()
        .expect("launch crash helper");
    assert_eq!(status.code(), Some(86));

    assert_eq!(
        resource_ids(&["list", "--all", "--format", "json"], "mxc-crash-orphan-").len(),
        1,
        "crash helper must leave exactly one owned container"
    );
    assert_eq!(
        resource_ids(
            &["network", "list", "--format", "json"],
            "mxc-crash-orphan-"
        )
        .len(),
        1,
        "crash helper must leave exactly one owned network"
    );
    assert_eq!(
        crash_recovery_records().len(),
        1,
        "crash helper must leave exactly one recovery record"
    );

    let output = run_request(
        &request("printf 'recovered\\n'", ALPINE_IMAGE, NetworkPolicy::Allow),
        b"",
    )
    .expect("next run must reclaim the orphan before launching");

    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert_eq!(output.stdout, "recovered\n");
    assert!(
        resource_ids(&["list", "--all", "--format", "json"], "mxc-crash-orphan-").is_empty(),
        "recovery must remove the orphaned container"
    );
    assert!(
        resource_ids(
            &["network", "list", "--format", "json"],
            "mxc-crash-orphan-"
        )
        .is_empty(),
        "recovery must remove the orphaned network"
    );
    assert!(
        crash_recovery_records().is_empty(),
        "recovery must remove the orphaned recovery record"
    );
}

#[test]
#[ignore = "requires Apple Container 1.2.2 and the qualification images"]
fn blocked_network_preserves_loopback_and_denies_public_egress() {
    let script = r#"python3 - <<'PY'
import socket
import threading

for family, address in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
    listener = socket.socket(family, socket.SOCK_STREAM)
    listener.bind((address, 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve():
        connection, _ = listener.accept()
        connection.sendall(b"pong")
        connection.close()

    thread = threading.Thread(target=serve)
    thread.start()
    client = socket.create_connection((address, port), timeout=3)
    assert client.recv(4) == b"pong"
    client.close()
    thread.join(3)
    assert not thread.is_alive()
    listener.close()

try:
    socket.create_connection(("1.1.1.1", 443), timeout=3)
except OSError:
    print("blocked-network-qualified")
else:
    raise SystemExit("public direct-IP egress unexpectedly succeeded")
PY"#;
    let output = run_request(&request(script, PYTHON_IMAGE, NetworkPolicy::Block), b"")
        .expect(INTEGRATION_REQUIREMENTS);

    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert_eq!(output.stdout, "blocked-network-qualified\n");
}

#[test]
#[ignore = "requires Apple Container 1.2.2 and the qualification images"]
fn workload_root_cannot_remove_block_network_firewall() {
    let output = run_request(
        &request(
            "test -x /usr/sbin/iptables || { echo 'iptables is missing' >&2; exit 41; }; \
             if /usr/sbin/iptables -w -F >/tmp/flush.out 2>&1; then \
               cat /tmp/flush.out >&2; exit 42; \
             fi; \
             grep -Eiq 'permission denied|operation not permitted' /tmp/flush.out || { \
               cat /tmp/flush.out >&2; exit 43; \
             }; \
             printf 'firewall-protected\\n'",
            NETWORK_BLOCK_INIT_IMAGE,
            NetworkPolicy::Block,
        ),
        b"",
    )
    .expect(INTEGRATION_REQUIREMENTS);

    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert_eq!(output.stdout, "firewall-protected\n");
}
