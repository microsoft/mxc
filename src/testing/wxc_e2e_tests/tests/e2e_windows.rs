// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows E2E integration tests.
//!
//! These tests invoke MXC binaries directly instead of routing through
//! PowerShell test scripts, so failures can be debugged from Rust test code.
//! Tests skip gracefully when prerequisites (binaries or features) are missing.

use std::fs::File;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use wxc_e2e_tests::{
    assert_exit, assert_pwsh, assert_python, assert_success,
    assert_success_or_skip_missing_prerequisite, examples_dir, find_binary, has_daemon,
    has_hyperlight_snapshot, has_nanvix_binaries, has_test_driver, has_windows_sandbox_feature,
    has_wxc_exe, repo_root, run_test_driver, run_wxc_config, run_wxc_config_value, run_wxc_example,
    run_wxc_state_aware, test_configs_dir, TempDirs,
};

static HAS_WXC_EXE: OnceLock<bool> = OnceLock::new();
static HAS_TEST_DRIVER: OnceLock<bool> = OnceLock::new();
static HAS_NANVIX_BINARIES: OnceLock<bool> = OnceLock::new();
static HAS_DAEMON: OnceLock<bool> = OnceLock::new();
static HAS_WINDOWS_SANDBOX: OnceLock<bool> = OnceLock::new();
static HAS_HYPERLIGHT: OnceLock<bool> = OnceLock::new();
static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// Caches the `wxc-exec.exe` prerequisite probe so repeated tests do not
/// rescan the filesystem or print duplicate status lines.
fn cached_has_wxc_exe() -> bool {
    *HAS_WXC_EXE.get_or_init(has_wxc_exe)
}

/// Caches the test driver probe for the duration of the test process.
fn cached_has_test_driver() -> bool {
    *HAS_TEST_DRIVER.get_or_init(has_test_driver)
}

/// Caches the NanVix binary probe to avoid repeated prerequisite work.
fn cached_has_nanvix_binaries() -> bool {
    *HAS_NANVIX_BINARIES.get_or_init(has_nanvix_binaries)
}

/// Caches the daemon probe to keep logs readable across multiple tests.
fn cached_has_daemon() -> bool {
    *HAS_DAEMON.get_or_init(has_daemon)
}

/// Caches the Windows Sandbox feature probe.
fn cached_has_windows_sandbox_feature() -> bool {
    *HAS_WINDOWS_SANDBOX.get_or_init(has_windows_sandbox_feature)
}

/// Caches the Hyperlight snapshot probe.
fn cached_has_hyperlight() -> bool {
    *HAS_HYPERLIGHT.get_or_init(has_hyperlight_snapshot)
}

fn with_test_lock(run: impl FnOnce()) {
    let lock = TEST_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    run();
}

fn assert_wxc_success(config_file: &str, extra_args: &[&str]) {
    let result = run_wxc_config(config_file, extra_args);
    assert_success_or_skip_missing_prerequisite(&result);
}

fn processcontainer_basic() {
    assert_wxc_success("basic_processcontainer.json", &["--debug"]);
}

fn processcontainer_lpac() {
    assert_wxc_success("basic_lpac.json", &["--debug"]);
}

fn filesystem_bfs() {
    let _temp = TempDirs::create(&["C:\\temp\\wxc_test_allowed", "C:\\temp\\wxc_test_denied"]);
    assert_wxc_success("filesystem_bfs_test.json", &["--debug"]);
}

fn filesystem_bfs_readonly() {
    let temp = TempDirs::create(&["C:\\temp\\wxc_test_allowedreadonly"]);
    temp.write_absolute_file(
        "C:\\temp\\wxc_test_allowedreadonly\\test_input.txt",
        "Test Input",
    );
    assert_wxc_success("filesystem_bfs_readonly_test.json", &["--debug"]);
}

fn filesystem_bfs_spaces() {
    let _temp = TempDirs::create(&["C:\\Users\\Public\\wxc bfs test"]);
    assert_wxc_success("filesystem_bfs_spaces_test.json", &["--debug"]);
}

fn pwsh_setlocation() {
    assert_wxc_success("pwsh_setlocation.json", &["--debug"]);
}

fn test_configs() {
    let temp = TempDirs::create(&[
        "C:\\temp\\wxc_test_allowed",
        "C:\\temp\\wxc_test_allowedreadonly",
        "C:\\temp\\wxc_test_denied",
        "C:\\temp\\wxc_test_gitproj",
        "C:\\temp\\wxc_test_gitexisting",
        "C:\\temp\\wxc_test_outside",
    ]);
    temp.write_absolute_file(
        "C:\\temp\\wxc_test_allowedreadonly\\test_input.txt",
        "Test Input",
    );
    // Pre-seed a protected child inside a writable parent (the `.git` protection
    // regression scenario) and an out-of-policy secret for the deny tests.
    temp.write_absolute_file("C:\\temp\\wxc_test_gitexisting\\.git\\config", "ORIGINAL");
    temp.write_absolute_file("C:\\temp\\wxc_test_outside\\secret.txt", "SECRET");

    let result = run_test_driver(&test_configs_dir(), &[]);
    assert_success(&result);
}

fn examples() {
    let _temp = TempDirs::create(&["C:\\temp\\wxc_sandbox", "C:\\temp\\wxc_combined_test"]);
    let result = run_test_driver(&examples_dir(), &[]);
    assert_success(&result);
}

fn microvm_basic() {
    assert_wxc_success("microvm_hello.json", &["--debug", "--experimental"]);
}

fn microvm_network() {
    // Drives the `-allow-host-networking` path: the guest opens a loopback TCP
    // socket, completes a ping/pong round-trip, and prints NET_OK. Without host
    // networking enabled the guest's socket() call fails (errno 134) and the
    // process exits non-zero, so a clean exit + marker proves the flag wiring.
    let result = run_wxc_config("microvm_network.json", &["--debug", "--experimental"]);
    assert_eq!(
        result.code,
        Some(0),
        "expected exit 0, got {:?}\nstdout: {}\nstderr: {}",
        result.code,
        result.stdout,
        result.stderr
    );
    let combined = result.combined_output_with_decoded_base64();
    assert!(
        combined.contains("NET_OK"),
        "guest network round-trip marker missing\ncombined: {}",
        combined
    );
}

/// Discovers a non-loopback IPv4 address of the host. nanvixd proxies guest
/// `connect()` calls through the host network stack, so a host-routable IP
/// gives a deterministic, internet-independent target for egress-filter tests.
fn host_lan_ipv4() -> Option<std::net::Ipv4Addr> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    // Connecting a UDP socket sends no packets; it just selects the outbound
    // interface so `local_addr` reports this host's routable address.
    sock.connect("10.255.255.255:9").ok()?;
    match sock.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified() => Some(v4),
        _ => None,
    }
}

/// Returns a TCP port that is very likely closed: bind an ephemeral port, read
/// it, then drop the listener. A guest connecting there while egress is
/// permitted gets `ECONNREFUSED`, distinguishing "allowed but unreachable"
/// from "blocked by the filter" (`EACCES`).
fn likely_closed_tcp_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().expect("read ephemeral port").port();
    drop(listener);
    port
}

/// Builds the guest Python that connects to `host:port` and prints the result
/// as `RESULT CONNECT_OK` or `RESULT ERRNO <n>`. A blocked egress surfaces as
/// `PermissionError`/`EACCES` (errno 13); an allowed-but-closed target as
/// `ECONNREFUSED` (errno 111).
fn egress_probe_source(host: std::net::Ipv4Addr, port: u16) -> String {
    format!(
        "import _socket\n\
         s = _socket.socket(2, 1, 0)\n\
         try:\n\
         \x20   s.connect(('{host}', {port}))\n\
         \x20   print('RESULT CONNECT_OK', flush=True)\n\
         except OSError as e:\n\
         \x20   print('RESULT ERRNO %d' % (e.errno,), flush=True)\n",
        host = host,
        port = port
    )
}

/// Negative egress test: a blocklisted host must be rejected by the guest
/// filter (Part B `-block-host`). Drives the host-networking path, asks the
/// guest to connect to a blocked host IP, and asserts the connection is denied
/// with `EACCES` (errno 13). A positive control connects to the same target
/// under an allow-all policy and asserts it is *not* denied, proving the
/// `EACCES` in the negative case comes from the filter rather than the network.
fn microvm_network_blocked() {
    let Some(host_ip) = host_lan_ipv4() else {
        println!("SKIPPED: microvm_network_blocked needs a non-loopback host IPv4");
        return;
    };
    let port = likely_closed_tcp_port();
    let source = egress_probe_source(host_ip, port);

    // Negative case: host is on the blocklist -> guest egress denied (EACCES).
    let blocked = serde_json::json!({
        "process": { "commandLine": source, "timeout": 30000 },
        "containment": "microvm",
        "network": { "blockedHosts": [host_ip.to_string()] }
    });
    let blocked_result = run_wxc_config_value(
        "microvm_network_blocked",
        &blocked,
        &["--debug", "--experimental"],
    );
    let blocked_out = blocked_result.combined_output_with_decoded_base64();
    assert_eq!(
        blocked_result.code,
        Some(0),
        "blocked-egress run should exit cleanly (the guest catches the error)\ncombined: {}",
        blocked_out
    );
    assert!(
        blocked_out.contains("RESULT ERRNO 13"),
        "blocklisted host should be denied with EACCES (errno 13)\ncombined: {}",
        blocked_out
    );

    // Positive control: allow-all policy -> egress permitted, so the same
    // closed target yields a connection error other than EACCES (typically
    // ECONNREFUSED / errno 111), never the filter's EACCES.
    let allowed = serde_json::json!({
        "process": { "commandLine": source, "timeout": 30000 },
        "containment": "microvm",
        "network": { "defaultPolicy": "allow" }
    });
    let allowed_result = run_wxc_config_value(
        "microvm_network_allowed_control",
        &allowed,
        &["--debug", "--experimental"],
    );
    let allowed_out = allowed_result.combined_output_with_decoded_base64();
    assert_eq!(
        allowed_result.code,
        Some(0),
        "allow-all control run should exit cleanly\ncombined: {}",
        allowed_out
    );
    assert!(
        allowed_out.contains("RESULT "),
        "allow-all control should produce a connect result\ncombined: {}",
        allowed_out
    );
    assert!(
        !allowed_out.contains("RESULT ERRNO 13"),
        "allow-all egress must not be denied with EACCES (proves filter, not network, blocks)\ncombined: {}",
        allowed_out
    );
}

fn processcontainer_proxy() {
    let config = test_configs_dir().join("proxy_builtin_test.json");
    if !config.exists() {
        println!("SKIPPED: proxy config not found: {}", config.display());
        return;
    }

    let result = run_test_driver(&config, &["--debug", "--proxy"]);
    assert_success(&result);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
#[ignore] // Requires velocity key 61714527 (BFS deadlock fix) enabled
fn test_processcontainer_basic() {
    if !cached_has_wxc_exe() {
        return;
    }
    assert_python();
    with_test_lock(processcontainer_basic);
}

#[test]
#[ignore] // Requires velocity key 61714527 (BFS deadlock fix) enabled
fn test_processcontainer_lpac() {
    if !cached_has_wxc_exe() {
        return;
    }
    assert_python();
    with_test_lock(processcontainer_lpac);
}

#[test]
#[ignore] // Requires velocity key 61714527 (BFS deadlock fix) enabled
fn test_filesystem_bfs() {
    if !cached_has_wxc_exe() {
        return;
    }
    assert_python();
    with_test_lock(filesystem_bfs);
}

#[test]
#[ignore] // Requires velocity key 61714527 (BFS deadlock fix) enabled
fn test_filesystem_bfs_readonly() {
    if !cached_has_wxc_exe() {
        return;
    }
    assert_python();
    with_test_lock(filesystem_bfs_readonly);
}

#[test]
#[ignore] // Requires velocity key 61714527 (BFS deadlock fix) enabled
fn test_filesystem_bfs_spaces() {
    if !cached_has_wxc_exe() {
        return;
    }
    assert_python();
    with_test_lock(filesystem_bfs_spaces);
}

#[test]
#[ignore] // Requires velocity key 61714527 (BFS deadlock fix) enabled
fn test_pwsh_setlocation() {
    if !cached_has_wxc_exe() {
        return;
    }
    assert_pwsh();
    with_test_lock(pwsh_setlocation);
}

#[test]
#[ignore] // Requires velocity key 61714527 (BFS deadlock fix) enabled
fn test_test_configs() {
    if !cached_has_test_driver() {
        return;
    }
    with_test_lock(test_configs);
}

#[test]
#[ignore] // Requires velocity key 61714527 (BFS deadlock fix) enabled
fn test_examples() {
    if !cached_has_test_driver() {
        return;
    }
    with_test_lock(examples);
}

#[test]
fn test_microvm_basic() {
    if !cached_has_wxc_exe() {
        return;
    }
    if !cached_has_nanvix_binaries() {
        return;
    }
    with_test_lock(microvm_basic);
}

#[test]
fn test_microvm_network() {
    if !cached_has_wxc_exe() {
        return;
    }
    if !cached_has_nanvix_binaries() {
        return;
    }
    with_test_lock(microvm_network);
}

#[test]
fn test_microvm_network_blocked() {
    if !cached_has_wxc_exe() {
        return;
    }
    if !cached_has_nanvix_binaries() {
        return;
    }
    with_test_lock(microvm_network_blocked);
}

#[test]
fn test_windows_sandbox() {
    if !cached_has_wxc_exe() {
        return;
    }
    if !cached_has_daemon() {
        return;
    }
    if !cached_has_windows_sandbox_feature() {
        return;
    }
    with_test_lock(windows_sandbox_suite);
}

#[test]
fn test_microvm_suite() {
    if !cached_has_wxc_exe() {
        return;
    }
    if !cached_has_nanvix_binaries() {
        return;
    }
    with_test_lock(microvm_suite);
}

#[test]
#[ignore] // Requires velocity key 61714527 (BFS deadlock fix) enabled and elevation
fn test_processcontainer_proxy() {
    if !cached_has_test_driver() {
        return;
    }
    with_test_lock(processcontainer_proxy);
}

#[test]
#[ignore] // Stress test — run explicitly with `cargo test -p wxc_e2e_tests -- --ignored`
fn test_on_repeat() {
    if !cached_has_wxc_exe() {
        return;
    }
    assert_python();

    with_test_lock(|| {
        for pass in 1..=10 {
            println!("=== Pass {pass} of 10 ===");
            processcontainer_basic();
            filesystem_bfs();
            filesystem_bfs_readonly();
            processcontainer_lpac();
        }
    });
}

// ---------------------------------------------------------------------------
// Telemetry tests
// ---------------------------------------------------------------------------

fn telemetry_enabled() {
    let result = run_wxc_example("28_telemetry_enabled.json", &["--debug", "--experimental"]);
    assert_success_or_skip_missing_prerequisite(&result);
}

fn telemetry_disabled() {
    // Run a basic config without telemetry — verifies the disabled path doesn't
    // regress when telemetry code is linked in.
    assert_wxc_success("basic_processcontainer.json", &["--debug"]);
}

#[test]
#[ignore] // Requires AppContainer support
fn test_telemetry_enabled() {
    if !cached_has_wxc_exe() {
        return;
    }
    assert_python();
    with_test_lock(telemetry_enabled);
}

#[test]
#[ignore] // Requires AppContainer support
fn test_telemetry_disabled() {
    if !cached_has_wxc_exe() {
        return;
    }
    assert_python();
    with_test_lock(telemetry_disabled);
}

// ---------------------------------------------------------------------------
// Windows Sandbox suite
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct SandboxCase {
    config: &'static str,
    expected_exit: Option<i32>,
    output_contains: Option<&'static str>,
    expect_non_zero: bool,
}

fn windows_sandbox_suite() {
    let _daemon = SandboxDaemon::start();
    let cases = [
        SandboxCase {
            config: "windows_sandbox_echo.json",
            expected_exit: Some(0),
            output_contains: Some("Hello from sandbox!"),
            expect_non_zero: false,
        },
        SandboxCase {
            config: "basic_windows_sandbox.json",
            expected_exit: Some(0),
            output_contains: Some("executed successfully"),
            expect_non_zero: false,
        },
        SandboxCase {
            config: "windows_sandbox_powershell.json",
            expected_exit: Some(0),
            output_contains: Some("PowerShell works"),
            expect_non_zero: false,
        },
        SandboxCase {
            config: "windows_sandbox_powershell_env.json",
            expected_exit: Some(0),
            output_contains: Some("ComputerName="),
            expect_non_zero: false,
        },
        SandboxCase {
            config: "windows_sandbox_stderr.json",
            expected_exit: Some(0),
            output_contains: Some("stdout-message"),
            expect_non_zero: false,
        },
        SandboxCase {
            config: "windows_sandbox_exit_code.json",
            expected_exit: Some(42),
            output_contains: None,
            expect_non_zero: false,
        },
        SandboxCase {
            config: "windows_sandbox_timeout.json",
            expected_exit: None,
            output_contains: None,
            expect_non_zero: true,
        },
    ];

    for case in cases {
        run_sandbox_case(&case);
    }

    for iteration in 1..=3 {
        println!("Running multi-exec #{iteration}");
        run_sandbox_case(&SandboxCase {
            config: "windows_sandbox_echo.json",
            expected_exit: Some(0),
            output_contains: Some("Hello from sandbox!"),
            expect_non_zero: false,
        });
    }
}

fn run_sandbox_case(case: &SandboxCase) {
    let result = run_wxc_config(case.config, &["--debug", "--experimental"]);
    if case.expect_non_zero {
        if result.code == Some(0) {
            panic!(
                "{} failed: expected non-zero exit\n--- stdout ---\n{}\n--- stderr ---\n{}",
                case.config, result.stdout, result.stderr
            );
        }
        return;
    }

    assert_exit(
        &result,
        case.expected_exit.unwrap_or(0),
        case.output_contains,
    );
}

struct SandboxDaemon {
    child: Child,
}

impl SandboxDaemon {
    fn start() -> Self {
        let daemon = find_binary("wxc-windows-sandbox-daemon.exe")
            .expect("wxc-windows-sandbox-daemon.exe should be available");
        let log_path = std::env::temp_dir().join("wxc-windows-sandbox-daemon.log");
        let stderr = File::create(&log_path).unwrap_or_else(|error| {
            panic!(
                "failed to create daemon log {}: {error}",
                log_path.display()
            )
        });

        let mut child = Command::new(&daemon)
            .args(["wxc-windows-sandbox", "300000"])
            .stderr(Stdio::from(stderr))
            .spawn()
            .unwrap_or_else(|error| panic!("failed to start {}: {error}", daemon.display()));

        thread::sleep(Duration::from_secs(2));
        if let Some(status) = child
            .try_wait()
            .unwrap_or_else(|error| panic!("failed to inspect daemon process: {error}"))
        {
            panic!(
                "sandbox daemon exited immediately with {status}; log: {}",
                log_path.display()
            );
        }

        println!("Started sandbox daemon with PID {}", child.id());
        Self { child }
    }
}

impl Drop for SandboxDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------------------
// MicroVM suite
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct MicrovmCase {
    config: &'static str,
    expected_exit: Option<i32>,
    description: &'static str,
    output_contains: Option<&'static str>,
    expect_non_zero: bool,
}

#[derive(Debug, Serialize)]
struct MicrovmPerfOutput {
    commit: String,
    timestamp: String,
    results: Vec<MicrovmPerfEntry>,
}

#[derive(Debug, Serialize)]
struct MicrovmPerfEntry {
    test: String,
    description: String,
    wall_time_ms: u128,
    exit_code: Option<i32>,
    status: String,
}

fn microvm_suite() {
    let cases = [
        MicrovmCase {
            config: "microvm_hello.json",
            expected_exit: Some(0),
            description: "Hello world",
            output_contains: Some("sum=100"),
            expect_non_zero: false,
        },
        MicrovmCase {
            config: "microvm_exit_code.json",
            expected_exit: Some(42),
            description: "Exit code propagation",
            output_contains: None,
            expect_non_zero: false,
        },
        MicrovmCase {
            config: "microvm_multiline.json",
            expected_exit: Some(0),
            description: "Multi-line script (fibonacci)",
            output_contains: Some("fib("),
            expect_non_zero: false,
        },
        MicrovmCase {
            config: "microvm_stdlib.json",
            expected_exit: Some(0),
            description: "Stdlib (json, math, hashlib)",
            output_contains: Some("pi"),
            expect_non_zero: false,
        },
        MicrovmCase {
            config: "microvm_large_output.json",
            expected_exit: Some(0),
            description: "Large stdout (1000 lines)",
            output_contains: Some("line 999"),
            expect_non_zero: false,
        },
        MicrovmCase {
            config: "microvm_error.json",
            expected_exit: Some(1),
            description: "Python exception",
            output_contains: Some("ValueError"),
            expect_non_zero: false,
        },
        MicrovmCase {
            config: "microvm_timeout.json",
            expected_exit: None,
            description: "Timeout kills VM",
            output_contains: None,
            expect_non_zero: true,
        },
    ];

    let mut perf_entries = Vec::new();
    let mut failures = Vec::new();

    for case in cases {
        let config_path = test_configs_dir().join(case.config);
        if !config_path.exists() {
            println!("SKIPPED: config not found: {}", config_path.display());
            continue;
        }

        println!("--- {} ({}) ---", case.description, case.config);
        let result = run_wxc_config(case.config, &["--debug", "--experimental"]);
        let status = if command_matches(&result, &case) {
            "PASS"
        } else {
            failures.push(format!(
                "{} expected {}, got {:?}",
                case.config,
                expected_exit_description(&case),
                result.code
            ));
            "FAIL"
        };

        perf_entries.push(MicrovmPerfEntry {
            test: case.config.to_string(),
            description: case.description.to_string(),
            wall_time_ms: result.wall_time_ms,
            exit_code: result.code,
            status: status.to_string(),
        });

        if status == "FAIL" {
            println!(
                "--- stdout ---\n{}\n--- stderr ---\n{}",
                result.stdout, result.stderr
            );
        }
    }

    write_microvm_perf_results(perf_entries);

    if !failures.is_empty() {
        panic!("MicroVM E2E failures:\n{}", failures.join("\n"));
    }
}

fn command_matches(result: &wxc_e2e_tests::CommandResult, case: &MicrovmCase) -> bool {
    if case.expect_non_zero {
        if result.code == Some(0) {
            return false;
        }
    } else if result.code != case.expected_exit {
        return false;
    }

    let Some(expected) = case.output_contains else {
        return true;
    };

    result
        .combined_output_with_decoded_base64()
        .contains(expected)
}

fn expected_exit_description(case: &MicrovmCase) -> String {
    if case.expect_non_zero {
        "non-zero exit".to_string()
    } else {
        format!("exit {}", case.expected_exit.unwrap_or(0))
    }
}

// ---------------------------------------------------------------------------
// Hyperlight suite
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct HyperlightCase {
    config: &'static str,
    description: &'static str,
    expected_exit: i32,
    output_contains: Option<&'static str>,
}

fn hyperlight_suite() {
    let cases = [
        HyperlightCase {
            config: "hyperlight_hello.json",
            description: "Hello world",
            expected_exit: 0,
            output_contains: Some("Hello from Hyperlight!"),
        },
        HyperlightCase {
            config: "hyperlight_pandas.json",
            description: "numpy + pandas",
            expected_exit: 0,
            output_contains: Some("'x':"),
        },
        HyperlightCase {
            config: "hyperlight_exit_code.json",
            description: "sys.exit(42) propagates exit code",
            expected_exit: 42,
            output_contains: None,
        },
        HyperlightCase {
            config: "hyperlight_networking.json",
            description: "HTTP GET with allowedHosts network policy",
            expected_exit: 0,
            output_contains: Some("200"),
        },
        HyperlightCase {
            config: "hyperlight_networking_blocked.json",
            description: "HTTP GET to unlisted host is blocked by allowedHosts",
            expected_exit: 0,
            output_contains: Some("BLOCKED"),
        },
        HyperlightCase {
            config: "hyperlight_timeout.json",
            description: "time.sleep(120) killed by 1s timeout",
            expected_exit: -1,
            output_contains: Some("timed out"),
        },
    ];

    let mut failures = Vec::new();
    for case in cases {
        println!("--- {} ({}) ---", case.description, case.config);
        let result = run_wxc_config(case.config, &["--debug", "--experimental"]);

        if result.code != Some(case.expected_exit) {
            failures.push(format!(
                "{}: expected exit {}, got {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
                case.config, case.expected_exit, result.code, result.stdout, result.stderr
            ));
        } else if let Some(expected) = case.output_contains {
            let combined = result.combined_output_with_decoded_base64();
            if !combined.contains(expected) {
                failures.push(format!(
                    "{}: output missing '{}'\n--- combined ---\n{}",
                    case.config, expected, combined
                ));
            } else {
                println!("  PASS ({} ms)", result.wall_time_ms);
            }
        } else {
            println!("  PASS ({} ms)", result.wall_time_ms);
        }
    }

    // Filesystem test — uses an absolute temp dir to avoid relative-path issues.
    {
        println!("--- hostfs read/write (hyperlight_fs) ---");
        let mount_dir = std::env::temp_dir().join("hyperlight-fs-e2e");
        let _ = std::fs::remove_dir_all(&mount_dir);
        std::fs::create_dir_all(&mount_dir).unwrap();

        let script = format!(
            "import os\n\
             BASE = '/host/{}'\n\
             path = f'{{BASE}}/hello.txt'\n\
             with open(path, 'w') as f:\n\
             \x20   f.write('hyperlight was here\\n')\n\
             print(f'wrote: {{path}}')\n\
             with open(path, 'r') as f:\n\
             \x20   print(f'read: {{f.read().strip()}}')\n\
             print('done')\n",
            mount_dir.file_name().unwrap().to_string_lossy()
        );

        let config = serde_json::json!({
            "process": { "commandLine": script, "timeout": 30000 },
            "containment": "hyperlight",
            "filesystem": { "readwritePaths": [mount_dir.to_string_lossy()] }
        });

        let result = run_wxc_state_aware("hyperlight-fs", &config, &["--debug", "--experimental"]);

        if result.code != Some(0) {
            failures.push(format!(
                "hyperlight-fs: expected exit 0, got {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
                result.code, result.stdout, result.stderr
            ));
        } else {
            let written = mount_dir.join("hello.txt");
            if !written.exists() {
                failures.push("hyperlight-fs: hello.txt not created on host".to_string());
            } else {
                let contents = std::fs::read_to_string(&written).unwrap_or_default();
                if !contents.contains("hyperlight was here") {
                    failures.push(format!(
                        "hyperlight-fs: hello.txt missing expected content, got: {contents}"
                    ));
                } else {
                    println!("  PASS ({} ms)", result.wall_time_ms);
                }
            }
        }

        let _ = std::fs::remove_dir_all(&mount_dir);
    }

    // Read-only mount enforcement test.
    {
        println!("--- hostfs readonly enforcement (hyperlight_fs_readonly) ---");
        let ro_dir = std::env::temp_dir().join("hyperlight-fs-ro-e2e");
        let rw_dir = std::env::temp_dir().join("hyperlight-fs-rw-e2e");
        let _ = std::fs::remove_dir_all(&ro_dir);
        let _ = std::fs::remove_dir_all(&rw_dir);
        std::fs::create_dir_all(&ro_dir).unwrap();
        std::fs::create_dir_all(&rw_dir).unwrap();
        std::fs::write(ro_dir.join("input.txt"), "readonly content\n").unwrap();

        let ro_basename = ro_dir.file_name().unwrap().to_string_lossy();
        let rw_basename = rw_dir.file_name().unwrap().to_string_lossy();

        let script = format!(
            "import os\n\
             ro = '/host/{ro_basename}'\n\
             rw = '/host/{rw_basename}'\n\
             with open(f'{{ro}}/input.txt') as f:\n\
             \x20   print(f'read: {{f.read().strip()}}')\n\
             with open(f'{{rw}}/output.txt', 'w') as f:\n\
             \x20   f.write('rw ok')\n\
             print('wrote to rw')\n\
             try:\n\
             \x20   with open(f'{{ro}}/forbidden.txt', 'w') as f:\n\
             \x20       f.write('should fail')\n\
             \x20   print('READONLY_BYPASSED')\n\
             except Exception as e:\n\
             \x20   print(f'write blocked: {{e}}')\n\
             \x20   print('READONLY_ENFORCED')\n"
        );

        let config = serde_json::json!({
            "process": { "commandLine": script, "timeout": 30000 },
            "containment": "hyperlight",
            "filesystem": {
                "readonlyPaths": [ro_dir.to_string_lossy()],
                "readwritePaths": [rw_dir.to_string_lossy()],
            }
        });

        let result = run_wxc_state_aware(
            "hyperlight-fs-readonly",
            &config,
            &["--debug", "--experimental"],
        );
        let combined = result.combined_output();

        if result.code != Some(0) {
            failures.push(format!(
                "hyperlight-fs-readonly: expected exit 0, got {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
                result.code, result.stdout, result.stderr
            ));
        } else if !combined.contains("readonly content") {
            failures.push(format!(
                "hyperlight-fs-readonly: could not read from readonly mount\n--- combined ---\n{combined}"
            ));
        } else if !rw_dir.join("output.txt").exists() {
            failures.push(
                "hyperlight-fs-readonly: readwrite mount did not produce output.txt".to_string(),
            );
        } else if ro_dir.join("forbidden.txt").exists() {
            failures.push(
                "hyperlight-fs-readonly: readonly mount was writable — forbidden.txt was created"
                    .to_string(),
            );
        } else if !combined.contains("READONLY_ENFORCED") {
            failures.push(format!(
                "hyperlight-fs-readonly: guest did not confirm enforcement\n--- combined ---\n{combined}"
            ));
        } else {
            println!("  PASS ({} ms)", result.wall_time_ms);
        }

        let _ = std::fs::remove_dir_all(&ro_dir);
        let _ = std::fs::remove_dir_all(&rw_dir);
    }

    if !failures.is_empty() {
        panic!("Hyperlight E2E failures:\n{}", failures.join("\n"));
    }
}

#[test]
fn test_hyperlight_suite() {
    if !cached_has_wxc_exe() {
        return;
    }
    if !cached_has_hyperlight() {
        return;
    }
    with_test_lock(hyperlight_suite);
}

// ---------------------------------------------------------------------------
// MicroVM perf results
// ---------------------------------------------------------------------------

fn write_microvm_perf_results(results: Vec<MicrovmPerfEntry>) {
    let output = MicrovmPerfOutput {
        commit: std::env::var("GITHUB_SHA").unwrap_or_else(|_| "local".to_string()),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs().to_string())
            .unwrap_or_else(|_| "unknown".to_string()),
        results,
    };
    let json = serde_json::to_string_pretty(&output)
        .expect("microvm performance results should serialize");
    let path = repo_root().join("microvm-perf-results.json");
    std::fs::write(&path, json)
        .unwrap_or_else(|error| panic!("failed to write {}: {error}", path.display()));
    println!("Performance results written to {}", path.display());
}
