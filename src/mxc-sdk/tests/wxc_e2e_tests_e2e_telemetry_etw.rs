// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end proof that MXC actually writes telemetry to ETW.
//!
//! Every other telemetry test asserts only that a run *succeeds* with
//! `telemetry.enabled: true`, which passes just as happily when nothing is
//! emitted at all. That blind spot hid two real defects: a build with no
//! provider group never routes anywhere, and a run can succeed without
//! telemetry being collected. This test closes it by observing the
//! events themselves.
//!
//! It builds a private local-only `wxc-exec.exe` (an empty
//! `MXC_TELEMETRY_COMPONENT_PATH`, so no routing), grants MXC telemetry consent
//! to that binary through the debug-only consent-store override, enables local
//! keyword test mode, and runs a real sandboxed execution while an ETW session
//! is collecting, and decodes the trace. Routing through the signed telemetry
//! component is covered by the Windows build job, not here.
//!
//! Required events must be collected with consent granted or denied.
//! Verbose denial artifacts stay local and must not be sent as telemetry.
//!
//! `#[ignore]` by default: it shells out to a full `cargo build` and needs
//! rights to create an ETW session.

#![cfg(target_os = "windows")]

use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "support/wxc_e2e_tests.rs"]
mod wxc_e2e_tests;
use wxc_e2e_tests::{examples_dir, repo_root};

/// GUID that ETW derives from the provider name `"Microsoft.MXC"`. The
/// `tracelogging` crate hashes the name rather than taking a literal, so this
/// is the only handle an out-of-process collector has on the provider.
const PROVIDER_GUID: &str = "{7f10def4-a258-5fea-510e-2c3bb976687f}";

static ETW_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Target directory for the instrumented build. Kept apart from `target/debug`
/// so the group-joined binary can never be picked up by `find_binary` and so
/// this build does not contend for the main target directory's lock.
fn build_target_dir() -> PathBuf {
    repo_root().join("src").join("target").join("telemetry-e2e")
}

fn skip(reason: &str) {
    println!("SKIPPED: {reason}");
}

/// Stops the ETW session on drop. A session outlives the process that created
/// it, so an early panic without this would leave a live collector (and its
/// buffers) behind on the host until someone stopped it by hand.
struct EtwSession {
    name: String,
    stopped: bool,
}

impl EtwSession {
    /// Starts a private ETW session collecting the MXC provider into `etl`.
    /// Returns `None` when the session cannot be created — typically because
    /// the test is not running with the rights ETW requires — so the caller can
    /// skip rather than fail on an environmental limitation.
    fn start(name: &str, etl: &Path) -> Option<Self> {
        // A stale session from an aborted earlier run would make `create` fail;
        // clearing it first makes the test re-runnable.
        let _ = Command::new("logman")
            .args(["stop", name, "-ets"])
            .output()
            .ok();

        let output = Command::new("logman")
            .args([
                "create",
                "trace",
                name,
                "-ets",
                "-p",
                PROVIDER_GUID,
                "0xffffffffffffffff",
                "0xff",
                "-o",
            ])
            .arg(etl)
            .args(["-bs", "64", "-nb", "16", "64"])
            .output()
            .ok()?;

        if !output.status.success() {
            println!(
                "logman create failed: {}",
                String::from_utf8_lossy(&output.stdout)
            );
            return None;
        }

        Some(Self {
            name: name.to_string(),
            stopped: false,
        })
    }

    /// Flushes and closes the session so the `.etl` is complete and readable.
    fn stop(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        let _ = Command::new("logman")
            .args(["stop", &self.name, "-ets"])
            .output();
    }
}

impl Drop for EtwSession {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Builds a local-only `wxc-exec.exe` with the telemetry component disabled,
/// and with the debug-only consent-store override enabled so the
/// test can grant consent without touching the developer's real consent state.
fn build_instrumented_wxc_exec() -> PathBuf {
    let target_dir = build_target_dir();
    let output = Command::new("cargo")
        .current_dir(repo_root().join("src"))
        .args([
            "build",
            "-p",
            "wxc",
            // `test-support` is what makes `MXC_TEST_LOCALAPPDATA_OVERRIDE`
            // observable to the child; without it the consent store is the real
            // per-user one and this test would mutate developer state.
            "--features",
            "test-support",
            "--target-dir",
        ])
        .arg(&target_dir)
        .env("MXC_TELEMETRY_COMPONENT_PATH", "")
        .env("MXC_TELEMETRY_TEST_KEYWORDS", "1")
        .env_remove("MXC_TELEMETRY_PROVIDER_GROUP_GUID")
        .output()
        .expect("failed to invoke cargo");

    assert!(
        output.status.success(),
        "building a local-only wxc failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let exe = target_dir.join("debug").join("wxc-exec.exe");
    assert!(exe.exists(), "instrumented wxc-exec.exe not at {exe:?}");
    exe
}

/// Reads back the build script's generated provider definition, which shows
/// whether the build is routed. An ETW collector cannot tell a routed provider
/// from an unrouted one, so this is the only check on the build's routing.
fn generated_provider_def() -> String {
    let build_dir = build_target_dir().join("debug").join("build");
    let entry = std::fs::read_dir(&build_dir)
        .expect("build directory missing")
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with("mxc-sdk-"))
        .map(|e| e.path().join("out").join("provider_def.rs"))
        .find(|p| p.exists())
        .expect("generated provider_def.rs not found");
    std::fs::read_to_string(entry).expect("failed to read provider_def.rs")
}

/// Writes a consent record directly into the overridden consent store.
///
/// Seeding the file is deliberate: the supported way to grant consent is an
/// interactive prompt exchange, which a test cannot drive, and the goal here is
/// to test *emission* under a given consent state rather than the consent
/// protocol itself (`run_telemetry_consent_smoke_test.ps1` covers that).
fn seed_consent(local_app_data: &Path, state: &str) {
    let dir = local_app_data.join("mxc");
    std::fs::create_dir_all(&dir).expect("failed to create consent directory");
    let record = format!(
        r#"{{"schemaVersion":2,"consent":"{state}","source":"telemetry-etw-e2e",
"promptedMxcVersion":"0.0.0-e2e","promptResourceVersion":4,
"promptLocale":"en-US","updatedAtEpoch":0}}"#
    );
    std::fs::write(dir.join("telemetry-consent.json"), record.replace('\n', ""))
        .expect("failed to write consent record");
}

/// Confirms the child actually observed the seeded consent state. Without this
/// a silently ineffective override would turn the "denied" case into a
/// vacuous pass — it would record no events for the wrong reason.
fn assert_effective_consent(exe: &Path, local_app_data: &Path, expected: &str) {
    let output = Command::new(exe)
        .args(["--telemetry-consent", "status"])
        .env("MXC_TEST_LOCALAPPDATA_OVERRIDE", local_app_data)
        .env(
            "MXC_TEST_LOCALAPPDATA_OVERRIDE_OWNER_PID",
            std::process::id().to_string(),
        )
        .output()
        .expect("failed to query consent status");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&format!("\"effectiveState\":\"{expected}\"")),
        "consent override did not take effect (wanted {expected}): {stdout}"
    );
}

/// Runs one sandboxed execution with telemetry requested.
fn run_traced_execution(exe: &Path, local_app_data: &Path) -> std::process::Output {
    Command::new(exe)
        .arg("--config")
        .arg(examples_dir().join("28_telemetry_enabled.json"))
        .env("MXC_TEST_LOCALAPPDATA_OVERRIDE", local_app_data)
        .env(
            "MXC_TEST_LOCALAPPDATA_OVERRIDE_OWNER_PID",
            std::process::id().to_string(),
        )
        .output()
        .expect("failed to run wxc-exec")
}

fn write_capture_config(workdir: &Path) -> PathBuf {
    let config_path = workdir.join("capture-config.json");
    let output_path = workdir.join("denials.json");
    let denied_file = workdir.join("denied.txt");
    std::fs::write(&denied_file, "telemetry E2E fixture").expect("failed to write denied fixture");
    let config = serde_json::json!({
        "version": "0.9.0-alpha",
        "containerId": "TelemetryVerboseDenialsE2E",
        "containment": "processcontainer",
        "process": {
            "commandLine": format!("cmd.exe /d /c type \"{}\" & exit /b 0", denied_file.display())
        },
        "processContainer": {
            "captureDenials": {
                "mode": "block",
                "outputPath": output_path
            }
        },
        "telemetry": {
            "enabled": true
        }
    });
    std::fs::write(
        &config_path,
        serde_json::to_vec_pretty(&config).expect("failed to serialize capture config"),
    )
    .expect("failed to write capture config");
    config_path
}

fn run_traced_config(
    exe: &Path,
    local_app_data: &Path,
    config_path: &Path,
) -> std::process::Output {
    Command::new(exe)
        .arg("--config")
        .arg(config_path)
        .env("MXC_TEST_LOCALAPPDATA_OVERRIDE", local_app_data)
        .env(
            "MXC_TEST_LOCALAPPDATA_OVERRIDE_OWNER_PID",
            std::process::id().to_string(),
        )
        .output()
        .expect("failed to run wxc-exec capture config")
}

fn capture_denials_is_unavailable(stderr: &[u8]) -> bool {
    String::from_utf8_lossy(stderr).contains("captureDenials requires")
}

fn find_verbose_artifact(workdir: &Path) -> Option<PathBuf> {
    std::fs::read_dir(workdir)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("denials.") && name.ends_with(".verbose.json"))
        })
}

/// Decodes an `.etl` to XML and returns the text, or `None` if it holds no
/// decodable events (`tracerpt` reports failure on an empty trace).
fn decode_trace(etl: &Path, workdir: &Path) -> Option<String> {
    let dump = workdir.join(etl.file_name()?).with_extension("xml");
    let _ = std::fs::remove_file(&dump);
    Command::new("tracerpt")
        .arg(etl)
        .arg("-o")
        .arg(&dump)
        .args(["-of", "XML", "-y"])
        .output()
        .ok()?;
    std::fs::read_to_string(&dump).ok()
}

/// Asserts the decoded trace contains a real MXC execution event.
///
/// The assertion is on the **provider** GUID: it is the only reliable
/// subscription for an out-of-process collector.
fn assert_events_recorded(dump: &str) {
    assert!(
        dump.contains("Microsoft.MXC"),
        "no Microsoft.MXC Required events were recorded"
    );
    for name in ["MXC.ExecutionStart", "MXC.ExecutionEnd"] {
        assert!(
            dump.contains(&format!("<Task>{name}</Task>")),
            "the execution pair is missing {name}"
        );
    }
    assert!(
        !dump.contains("<Task>MXC.Execution</Task>"),
        "the retired execution event must not be emitted"
    );
    assert!(
        !dump.contains("mxc.host_app"),
        "MXC events must not include host application attribution"
    );
    // Field-level checks, so the test fails if the event is emitted but its
    // payload has been gutted.
    for field in [
        "mxc.session_id",
        "mxc.capture_denials",
        "mxc.sandbox_kind",
        "mxc.outcome",
        "PartA_PrivacyProduct",
        "PartA_PrivacyDataCategory",
        "PartA_PrivTags",
    ] {
        assert!(
            dump.contains(field),
            "recorded MXC event is missing the {field} field"
        );
    }
}

fn assert_required_inventory(dump: &str) {
    assert_events_recorded(dump);
    for event in [
        "MXC.VerboseDenials",
        "MXC.ProcessTimedOut",
        "MXC.ProcessKillFailed",
        "MXC.PolicyHash",
        "MXC.SandboxNetworkPolicyApplied",
        "MXC.SandboxTornDown",
        "MXC.ConfigRejected",
    ] {
        assert!(
            !dump.contains(&format!("<Task>{event}</Task>")),
            "excluded event {event} was emitted"
        );
    }
}

#[test]
#[ignore] // Builds a second wxc-exec.exe and needs rights to create an ETW session.
fn test_required_telemetry_emits_etw_events_independently_of_consent() {
    let _etw_test_guard = ETW_TEST_LOCK.lock().expect("ETW test lock was poisoned");
    let exe = build_instrumented_wxc_exec();

    let provider_def = generated_provider_def();
    assert!(
        provider_def.contains("IS_UTC_ROUTED: bool = false"),
        "a build with the component disabled must be local-only: {provider_def}"
    );
    assert!(
        !provider_def.contains("group_id("),
        "a local-only build must not join a provider group: {provider_def}"
    );

    let workdir = build_target_dir().join("etw-e2e");
    let _ = std::fs::remove_dir_all(&workdir);
    std::fs::create_dir_all(&workdir).expect("failed to create work directory");

    // ---- granted: events must be recorded ---------------------------------
    let granted_store = workdir.join("granted");
    seed_consent(&granted_store, "granted");
    assert_effective_consent(&exe, &granted_store, "granted");

    let granted_etl = workdir.join("granted.etl");
    let session_name = format!("MxcTelemetryE2E_{}", std::process::id());
    let Some(mut session) = EtwSession::start(&session_name, &granted_etl) else {
        skip("could not create an ETW session — rerun with rights to collect traces");
        return;
    };
    let run = run_traced_execution(&exe, &granted_store);
    session.stop();

    if !run.status.success() {
        skip(&format!(
            "sandboxed execution did not run on this host: {}",
            String::from_utf8_lossy(&run.stderr)
        ));
        return;
    }

    let granted_dump = decode_trace(&granted_etl, &workdir)
        .expect("tracerpt produced no output for the granted run");
    assert_required_inventory(&granted_dump);

    // ---- denied: Required events must still be recorded -------------------
    let denied_store = workdir.join("denied");
    seed_consent(&denied_store, "denied");
    assert_effective_consent(&exe, &denied_store, "denied");

    let denied_etl = workdir.join("denied.etl");
    let Some(mut denied_session) = EtwSession::start(&session_name, &denied_etl) else {
        skip("could not create the second ETW session");
        return;
    };
    let denied_run = run_traced_execution(&exe, &denied_store);
    denied_session.stop();
    assert!(
        denied_run.status.success(),
        "sandboxed execution failed under denied consent: {}",
        String::from_utf8_lossy(&denied_run.stderr)
    );

    let denied_dump = decode_trace(&denied_etl, &workdir)
        .expect("tracerpt produced no output for the denied run");
    assert_required_inventory(&denied_dump);
}

#[test]
#[ignore] // Builds a second wxc-exec.exe and needs captureDenials plus ETW privileges.
fn test_required_telemetry_keeps_verbose_denials_local() {
    let _etw_test_guard = ETW_TEST_LOCK.lock().expect("ETW test lock was poisoned");
    let exe = build_instrumented_wxc_exec();
    let workdir = build_target_dir().join("verbose-etw-e2e");
    let _ = std::fs::remove_dir_all(&workdir);
    std::fs::create_dir_all(&workdir).expect("failed to create verbose ETW work directory");
    let config_path = write_capture_config(&workdir);
    let session_name = format!("MxcVerboseTelemetryE2E_{}", std::process::id());

    let granted_store = workdir.join("granted");
    seed_consent(&granted_store, "granted");
    assert_effective_consent(&exe, &granted_store, "granted");

    let granted_etl = workdir.join("granted.etl");
    let Some(mut session) = EtwSession::start(&session_name, &granted_etl) else {
        skip("could not create an ETW session for verbose telemetry");
        return;
    };
    let granted_run = run_traced_config(&exe, &granted_store, &config_path);
    session.stop();
    if !granted_run.status.success() {
        if capture_denials_is_unavailable(&granted_run.stderr) {
            skip(&format!(
                "captureDenials is unavailable on this host: {}",
                String::from_utf8_lossy(&granted_run.stderr)
            ));
            return;
        }
        panic!(
            "verbose telemetry execution failed: {}",
            String::from_utf8_lossy(&granted_run.stderr)
        );
    }

    let verbose_path = find_verbose_artifact(&workdir)
        .expect("captureDenials succeeded without publishing denials.verbose.json");
    let verbose: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&verbose_path).expect("failed to read verbose artifact"),
    )
    .expect("verbose artifact was not valid JSON");
    assert_eq!(verbose["version"], 4);

    let granted_dump = decode_trace(&granted_etl, &workdir)
        .expect("tracerpt produced no output for the verbose telemetry run");
    assert_required_inventory(&granted_dump);

    let denied_store = workdir.join("denied");
    seed_consent(&denied_store, "denied");
    assert_effective_consent(&exe, &denied_store, "denied");

    let denied_etl = workdir.join("denied.etl");
    let Some(mut denied_session) = EtwSession::start(&session_name, &denied_etl) else {
        skip("could not create the denied-consent ETW session");
        return;
    };
    let denied_run = run_traced_config(&exe, &denied_store, &config_path);
    denied_session.stop();
    assert!(
        denied_run.status.success(),
        "captureDenials failed under denied consent: {}",
        String::from_utf8_lossy(&denied_run.stderr)
    );
    let denied_dump = decode_trace(&denied_etl, &workdir)
        .expect("tracerpt produced no output for the denied run");
    assert_required_inventory(&denied_dump);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(
            &std::fs::read(&verbose_path).expect("local verbose artifact was removed"),
        )
        .expect("local verbose artifact was not valid JSON")["version"],
        4
    );
}
