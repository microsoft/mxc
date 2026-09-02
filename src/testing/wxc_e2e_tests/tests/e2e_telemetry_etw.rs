// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end proof that MXC actually writes telemetry to ETW.
//!
//! Every other telemetry test asserts only that a run *succeeds* with
//! `telemetry.enabled: true`, which passes just as happily when nothing is
//! emitted at all. That blind spot hid two real defects: a build with no
//! provider group GUID never routes anywhere, and a run whose consent is
//! `undetermined` is silently suppressed. This test closes it by observing the
//! events themselves.
//!
//! It builds a private `wxc-exec.exe` with a **fake** provider group GUID (so
//! the group-joined code path — the one internal builds ship — is the one under
//! test), grants MXC telemetry consent to that binary through the debug-only
//! consent-store override, runs a real sandboxed execution while an ETW session
//! is collecting, and decodes the trace.
//!
//! Two directions are asserted, because only the pair is meaningful:
//! consent granted must produce a decodable `Microsoft.MXC` event, and consent
//! denied must produce none.
//!
//! `#[ignore]` by default: it shells out to a full `cargo build` and needs
//! rights to create an ETW session.

#![cfg(target_os = "windows")]

use std::path::{Path, PathBuf};
use std::process::Command;

use wxc_e2e_tests::{examples_dir, repo_root};

/// A syntactically valid GUID that is deliberately **not** the real Microsoft
/// telemetry group. The real value is injected by internal build pipelines and
/// must never be committed; what this test needs is only that *some* group is
/// compiled in, so the `group_id(...)` provider definition is exercised.
const FAKE_GROUP_GUID: &str = "4d584354-0000-4000-8000-e2e7e57fa4e0";

/// GUID that ETW derives from the provider name `"Microsoft.MXC"`. The
/// `tracelogging` crate hashes the name rather than taking a literal, so this
/// is the only handle an out-of-process collector has on the provider.
const PROVIDER_GUID: &str = "{7f10def4-a258-5fea-510e-2c3bb976687f}";

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

/// Builds `wxc-exec.exe` with `FAKE_GROUP_GUID` compiled into the provider
/// definition, and with the debug-only consent-store override enabled so the
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
            "wxc_common/test-support",
            "--target-dir",
        ])
        .arg(&target_dir)
        .env("MXC_TELEMETRY_PROVIDER_GROUP_GUID", FAKE_GROUP_GUID)
        .output()
        .expect("failed to invoke cargo");

    assert!(
        output.status.success(),
        "building wxc with a provider group GUID failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let exe = target_dir.join("debug").join("wxc-exec.exe");
    assert!(exe.exists(), "instrumented wxc-exec.exe not at {exe:?}");
    exe
}

/// Reads back the build script's generated provider definition.
///
/// This is the direct evidence that the environment variable reached codegen.
/// It matters on its own: an ETW collector cannot distinguish "provider is in
/// group X" from "provider is in no group" (see the note on
/// `assert_events_recorded`), so without this check a build that silently
/// dropped the group would still pass the trace assertions.
fn generated_provider_def() -> String {
    let build_dir = build_target_dir().join("debug").join("build");
    let entry = std::fs::read_dir(&build_dir)
        .expect("build directory missing")
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("mxc_telemetry-")
        })
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
"promptedMxcVersion":"0.0.0-e2e","promptResourceVersion":1,
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

/// Decodes an `.etl` to XML and returns the text, or `None` if it holds no
/// decodable events (`tracerpt` reports failure on an empty trace).
fn decode_trace(etl: &Path, workdir: &Path) -> Option<String> {
    let dump = workdir.join("dump.xml");
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
/// The assertion is on the **provider** GUID, not the group GUID, because a
/// trace session enabled on a group GUID does not deliver the group's members'
/// events on this host — the provider GUID is the only reliable subscription.
/// Group membership is therefore verified at the source, in
/// `generated_provider_def`.
fn assert_events_recorded(dump: &str) {
    assert!(
        dump.contains("Microsoft.MXC"),
        "no Microsoft.MXC events were recorded while telemetry consent was granted"
    );
    // Field-level checks, so the test fails if the event is emitted but its
    // payload has been gutted.
    for field in [
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

#[test]
#[ignore] // Builds a second wxc-exec.exe and needs rights to create an ETW session.
fn test_telemetry_emits_etw_events_when_consent_granted() {
    let exe = build_instrumented_wxc_exec();

    let provider_def = generated_provider_def();
    assert!(
        provider_def.contains(&format!("group_id(\"{FAKE_GROUP_GUID}\")")),
        "the provider group GUID did not reach codegen: {provider_def}"
    );
    assert!(
        provider_def.contains("IS_UTC_ROUTED: bool = true"),
        "a group-joined build must report itself as UTC-routed: {provider_def}"
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
    assert_events_recorded(&granted_dump);

    // ---- denied: the same run must record nothing --------------------------
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

    // An empty trace decodes to nothing at all, which is itself a pass.
    if let Some(denied_dump) = decode_trace(&denied_etl, &workdir) {
        assert!(
            !denied_dump.contains("Microsoft.MXC"),
            "telemetry was emitted despite consent being denied"
        );
    }
}
