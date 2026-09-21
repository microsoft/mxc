// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows E2E integration tests.
//!
//! These tests invoke MXC binaries directly instead of routing through
//! PowerShell test scripts, so failures can be debugged from Rust test code.
//! Tests skip gracefully when prerequisites (binaries or features) are missing.

use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use wxc_e2e_tests::{
    assert_exit, assert_pwsh, assert_python, assert_success,
    assert_success_or_skip_missing_prerequisite, examples_dir, has_hyperlight_snapshot,
    has_test_driver, has_windows_sandbox_feature, has_wxc_exe, run_test_driver, run_wxc_config,
    run_wxc_config_value, run_wxc_example, run_wxc_state_aware, test_configs_dir, TempDirs,
};

static HAS_WXC_EXE: OnceLock<bool> = OnceLock::new();
static HAS_TEST_DRIVER: OnceLock<bool> = OnceLock::new();
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

fn processcontainer_proxy() {
    let config = test_configs_dir().join("proxy_builtin_test.json");
    if !config.exists() {
        println!("SKIPPED: proxy config not found: {}", config.display());
        return;
    }

    let result = run_test_driver(&config, &["--debug", "--proxy"]);
    assert_success(&result);
}

/// Drives `processContainer.captureDenials` end to end and asserts the
/// output-file contract: after the child exits, MXC writes a single JSON
/// denials document (`{ "denials": [...], "summary": {...} }`) to the
/// caller-named `outputPath`, and prints a one-line structured pointer
/// (`{"type":"captureDenials",...}`) to stderr.
///
/// Skips cleanly on hosts without the brokered learning-mode trace API (any
/// unsupported build), where capture surfaces a `BackendUnavailable`
/// error instead of running.
fn processcontainer_capture_denials_output_file() {
    let output_path = std::env::temp_dir().join(format!(
        "mxc_e2e_denials_{}.json",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_file(&output_path);

    let config = serde_json::json!({
        "version": "0.9.0-alpha",
        "process": { "commandLine": "cmd.exe /c echo capture-denials-e2e", "timeout": 30000 },
        "containment": "processcontainer",
        "processContainer": {
            "captureDenials": {
                "mode": "block",
                "outputPath": output_path.to_string_lossy(),
            }
        }
    });

    let result = run_wxc_config_value(
        "processcontainer_capture_denials_output_file",
        &config,
        &["--debug"],
    );
    let combined = result.combined_output_with_decoded_base64();

    // Hosts without the brokered learning-mode API can't run capture at all.
    if combined.contains("learning-mode trace API is not available") {
        println!(
            "SKIPPED: processcontainer_capture_denials_output_file requires the brokered \
             learning-mode trace API"
        );
        let _ = std::fs::remove_file(&output_path);
        return;
    }
    if result.is_missing_process_prerequisite() {
        println!(
            "SKIPPED: processcontainer_capture_denials_output_file requires local sandbox \
             runtime prerequisites not available here"
        );
        let _ = std::fs::remove_file(&output_path);
        return;
    }

    assert_success(&result);

    // The runner prints exactly one structured pointer line on stderr. Parse
    // it: the actual deliverable path has a per-run identifier stamped into
    // the stem, so we must read the path the pointer reports, not the one we
    // requested.
    let pointer_line = result
        .stderr
        .lines()
        .find(|l| l.contains(r#""type":"captureDenials""#))
        .unwrap_or_else(|| {
            panic!(
                "stderr should carry the captureDenials pointer line\n--- stderr ---\n{}",
                result.stderr
            )
        });
    let pointer: serde_json::Value =
        serde_json::from_str(pointer_line.trim()).expect("pointer line should be valid JSON");
    let emitted_path = pointer
        .get("outputPath")
        .and_then(|v| v.as_str())
        .expect("pointer must carry outputPath");

    // The emitted path must differ from the requested one by the injected
    // per-run identifier, so concurrent and sequential captures don't clash.
    let requested_stem = output_path
        .file_stem()
        .and_then(|s| s.to_str())
        .expect("requested stem");
    assert!(
        emitted_path.contains(requested_stem) && emitted_path != output_path.to_string_lossy(),
        "emitted outputPath {emitted_path} should be the requested path with a run id stamped in"
    );

    // The deliverable is a single JSON document with denials + summary.
    let bytes = std::fs::read(emitted_path)
        .unwrap_or_else(|e| panic!("captureDenials output file {emitted_path} should exist: {e}"));
    let doc: serde_json::Value =
        serde_json::from_slice(&bytes).expect("captureDenials output file should be valid JSON");
    let denials = doc
        .get("denials")
        .and_then(|d| d.as_array())
        .unwrap_or_else(|| panic!("output document must have a `denials` array: {doc}"));
    // Every denial identifies its resource under the `resource` key (file path
    // or capability name); `path` is retired.
    for denial in denials {
        assert!(
            denial.get("resource").is_some(),
            "each denial must carry a `resource` key: {denial}"
        );
        assert!(
            denial.get("path").is_none(),
            "denials must not use the retired `path` key: {denial}"
        );
    }
    let summary = doc
        .get("summary")
        .expect("output document must have a `summary`");
    assert!(
        summary.get("totalDenials").is_some()
            && summary.get("exitCode").is_some()
            && summary.get("deniedResourcesTruncated").is_some(),
        "summary must carry exitCode/totalDenials/deniedResourcesTruncated: {summary}"
    );

    let _ = std::fs::remove_file(emitted_path);
}

/// PSEC capture must preserve the runtime proxy's unrestricted loopback peer;
/// omitting that sentinel makes CreateProcessSecurityEnvironment reject the
/// otherwise valid policy with E_INVALIDARG.
fn processcontainer_proxy_capture_uses_native_capture() {
    let config = serde_json::json!({
        "version": "0.9.0-alpha",
        "process": {
            "commandLine": "cmd.exe /d /c echo proxy-capture-launched",
            "timeout": 30000
        },
        "containment": "processcontainer",
        "network": {
            "egress": { "default": "deny" },
            "ingress": { "default": "allow", "hostLoopback": "allow" }
        },
        "runtimeConfig": {
            "networkProxy": "http://127.0.0.1:8080"
        },
        "processContainer": {
            "captureDenials": { "mode": "block" }
        }
    });

    let result = run_wxc_config_value(
        "processcontainer_proxy_capture_uses_native_capture",
        &config,
        &["--debug"],
    );
    let combined = result.combined_output_with_decoded_base64();

    if combined.contains("captureDenials requires either") {
        println!(
            "SKIPPED: processcontainer_proxy_capture_uses_native_capture requires native capture \
             APIs"
        );
        return;
    }
    if result.is_missing_process_prerequisite() {
        println!(
            "SKIPPED: processcontainer_proxy_capture_uses_native_capture requires local sandbox \
             runtime prerequisites not available here"
        );
        return;
    }

    assert_success(&result);
    assert!(
        combined.contains("proxy-capture-launched"),
        "the native proxy-capture child did not launch\n--- combined output ---\n{combined}"
    );
}

/// Exercises timeout -> capture teardown -> retained metadata end to end.
fn processcontainer_capture_denials_timeout_retention() {
    let output_path = std::env::temp_dir().join(format!(
        "mxc_e2e_timeout_denials_{}.json",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_file(&output_path);

    let config = serde_json::json!({
        "version": "0.9.0-alpha",
        "process": {
            "commandLine": "cmd.exe /d /c \"for /L %i in (1,1,100000000) do @rem\"",
            "timeout": 1000
        },
        "containment": "processcontainer",
        "processContainer": {
            "captureDenials": {
                "mode": "block",
                "outputPath": output_path.to_string_lossy(),
                "retainEtl": true,
            }
        }
    });

    let result = run_wxc_config_value(
        "processcontainer_capture_denials_timeout_retention",
        &config,
        &["--debug"],
    );
    let combined = result.combined_output_with_decoded_base64();
    if combined.contains("learning-mode trace API is not available") {
        println!(
            "SKIPPED: processcontainer_capture_denials_timeout_retention requires the brokered \
             learning-mode trace API"
        );
        return;
    }
    if result.is_missing_process_prerequisite() {
        println!(
            "SKIPPED: processcontainer_capture_denials_timeout_retention requires local sandbox \
             runtime prerequisites not available here"
        );
        return;
    }

    assert_ne!(
        result.code,
        Some(0),
        "the long-running command should time out\n--- stderr ---\n{}",
        result.stderr
    );
    assert!(
        result.stderr.contains("script timed out after 1000ms"),
        "stderr should report the timeout\n--- stderr ---\n{}",
        result.stderr
    );

    let pointer_line = result
        .stderr
        .lines()
        .find(|line| line.contains(r#""type":"captureDenials""#))
        .unwrap_or_else(|| {
            panic!(
                "stderr should carry capture metadata after timeout\n--- stderr ---\n{}",
                result.stderr
            )
        });
    let pointer: serde_json::Value =
        serde_json::from_str(pointer_line.trim()).expect("pointer line should be valid JSON");
    let emitted_path = pointer
        .get("outputPath")
        .and_then(|value| value.as_str())
        .expect("timeout pointer must carry outputPath");
    let etl_path = pointer
        .get("etlPath")
        .and_then(|value| value.as_str())
        .expect("timeout pointer must carry the retained etlPath");

    assert!(
        std::path::Path::new(emitted_path).is_file(),
        "timeout denial output should exist: {emitted_path}"
    );
    assert!(
        std::path::Path::new(etl_path).is_file(),
        "retained timeout ETL should exist: {etl_path}"
    );

    let _ = std::fs::remove_file(emitted_path);
    let _ = std::fs::remove_file(etl_path);
    if let Some(directory) = std::path::Path::new(etl_path).parent() {
        let _ = std::fs::remove_dir(directory);
    }
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
#[ignore] // Live capture needs the brokered learning-mode API + BFS velocity key; skips otherwise
fn test_processcontainer_capture_denials_output_file() {
    if !cached_has_wxc_exe() {
        return;
    }
    with_test_lock(processcontainer_capture_denials_output_file);
}

#[test]
#[ignore] // Live capture needs the brokered learning-mode API + PSEC 1.1 on a compatible host
fn test_processcontainer_proxy_capture_uses_native_capture() {
    if !cached_has_wxc_exe() {
        return;
    }
    with_test_lock(processcontainer_proxy_capture_uses_native_capture);
}

#[test]
#[ignore] // Live capture needs the brokered learning-mode API + BFS velocity key; skips otherwise
fn test_processcontainer_capture_denials_timeout_retention() {
    if !cached_has_wxc_exe() {
        return;
    }
    with_test_lock(processcontainer_capture_denials_timeout_retention);
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
fn test_windows_sandbox() {
    if !cached_has_wxc_exe() {
        return;
    }
    if !cached_has_windows_sandbox_feature() {
        return;
    }
    // State-aware coverage lives in run_windows_sandbox_state_aware_tests.ps1.
    with_test_lock(windows_sandbox_suite);
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
    let result = run_wxc_example("28_telemetry_enabled.json", &["--debug"]);
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
        // The legacy hostname-policy fixtures are intentional v0.9 parser
        // rejections covered by run_hyperlight_network_migration_test.ps1.
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
            "version": "0.9.0-alpha",
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
            "version": "0.9.0-alpha",
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
