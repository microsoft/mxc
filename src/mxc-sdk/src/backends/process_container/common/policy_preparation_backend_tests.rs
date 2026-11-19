// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::mxc_common::filesystem_canonical::{canonicalize_path, PathCanonical};
use crate::mxc_common::logger::{Logger, Mode};
use crate::mxc_common::sandbox_process::{SandboxBackend, StdioMode};
use crate::process_container_common::base_container_runner::BaseContainerRunner;
use crate::process_container_common::test_env::PolicyCapabilityGuard;
use crate::process_security_environment_spec::process_security_environment_layout as psec;
use crate::v1::dev::{PolicyChangeOperation, PolicyFailureDetail as D, PolicyFailureResult as R};
use serde_json::{json, Value};
use std::io::Read;
use std::sync::Arc;

fn failures(detail: D) -> PolicyFailures {
    PolicyFailures {
        results: vec![R {
            outcome: R::OUTCOME_BLOCKED,
            details: vec![detail],
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn remove_capability(capability: &str) -> PolicyFailures {
    failures(D {
        failure_class: D::CLASS_ENFORCEMENT_MODE,
        failure_reason: D::REASON_CAPABILITY_NOT_ALLOWED,
        required_action: D::ACTION_REMOVE_CAPABILITY,
        resource_kind: D::RESOURCE_KIND_CAPABILITY,
        flags: D::FLAG_HAS_ACTIONABLE_DETAILS | D::FLAG_RESOURCE_COMPLETE,
        resource: Some(capability.to_string()),
        ..Default::default()
    })
}

fn execute_accepted_candidate(json: &str) {
    let request = parsed_request(json);
    let mut runner = BaseContainerRunner::with_capture_factory(Arc::new(UnusedCapture))
        .with_process_launcher(launch_fixed_fixture);
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.status = S_OK;
        state.handle = true;
    });
    let mut process = runner
        .spawn(&request, &mut Logger::new(Mode::Buffer), StdioMode::Pipes)
        .expect("strictly create the accepted JSON request");
    let mut stdout = String::new();
    process
        .take_stdout()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    assert_eq!(stdout.trim(), "mxc-policy-child");
    assert_eq!(process.wait().unwrap(), 0);
    drop(process);
}

fn filesystem_ceiling(path: &str, maximum: u64) -> PolicyFailures {
    failures(D {
        failure_class: D::CLASS_FILESYSTEM,
        failure_reason: D::REASON_ACCESS_EXCEEDS_CEILING,
        required_action: D::ACTION_RESTRICT_FILESYSTEM_ACCESS,
        resource_kind: D::RESOURCE_KIND_PATH,
        value_kind: D::VALUE_KIND_ACCESS,
        flags: D::FLAG_HAS_ACTIONABLE_DETAILS | D::FLAG_RESOURCE_COMPLETE,
        requested_value: D::ACCESS_READ_WRITE,
        required_value: maximum,
        resource: Some(path.to_owned()),
        ..Default::default()
    })
}

#[test]
fn policy_refusal_through_public_dispatch_preserves_owned_details_without_starting_work() {
    let _host = PolicyCapabilityGuard::set(true, true, true);
    for capture in [false, true] {
        let mut api = reset();
        api.version_support = Some(version);
        let _scope = ApiScope(INJECTED_API.with(|slot| slot.replace(Some(api))));
        let expected = STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.handle = true;
            state.report.details[0].resource = Some(r"C:\PUBLIC_DISPATCH_POLICY_RESOURCE".into());
            state.report.clone()
        });
        let mut request = json!({
            "version": "1.1.0-alpha", "containment": "processcontainer",
            "process": { "commandLine": "cmd.exe /d /c exit 0" },
        });
        if capture {
            request["processContainer"] = json!({ "captureDenials": { "mode": "block" } });
        }
        let error = crate::v1::dev::spawn_json(&request.to_string(), Default::default())
            .err()
            .expect("public dispatch must return the injected native refusal");
        assert_eq!(error.code, crate::v1::ErrorCode::BackendError);
        assert_eq!(
            error.operation.as_deref(),
            Some("CreateProcessSecurityEnvironment")
        );
        assert_eq!(error.native_code.as_deref(), Some("0x800704EC"));
        assert!(!format!("{error} {error:?}").contains("PUBLIC_DISPATCH_POLICY_RESOURCE"));
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            let effects: Vec<_> = state
                .calls
                .iter()
                .copied()
                .filter(|call| matches!(*call, "create" | "get" | "close" | "launch" | "trace"))
                .collect();
            assert_eq!(effects, ["create", "get", "close"], "capture={capture}");
            assert_eq!(state.frees, 1);
            assert_eq!(state.closes, 1);
            state.report.details.clear();
        });
        let owned = crate::v1::dev::PolicyFailures::from_error(&error)
            .unwrap()
            .unwrap();
        assert_eq!(owned.results, [expected]);
        assert_eq!(
            crate::v1::dev::PolicyFailures::from_json(&owned.to_json().unwrap()).unwrap(),
            owned,
        );
    }
}

#[test]
fn policy_preparation_projects_equivalent_and_suppressed_filesystem_grants() {
    let _host = PolicyCapabilityGuard::set(true, true, true);
    let mut api = reset();
    api.version_support = Some(version);
    let _scope = ApiScope(INJECTED_API.with(|slot| slot.replace(Some(api))));
    let directory = tempfile::tempdir().unwrap();
    let PathCanonical::Canonical(root) = canonicalize_path(directory.path().to_str().unwrap())
    else {
        panic!("resolve the fixture directory");
    };
    let work = std::path::Path::new(&root).join("work");
    std::fs::create_dir(&work).unwrap();
    let path = work.to_str().unwrap();
    for (writable, readonly, maximum) in [
        (
            path.to_owned(),
            path.to_ascii_uppercase(),
            D::ACCESS_READ_ONLY,
        ),
        (format!("{path}\\"), path.to_owned(), D::ACCESS_READ_ONLY),
        (format!("{path}\\"), format!("{path}\\"), D::ACCESS_NONE),
    ] {
        let original = json!({
            "version": "1.1.0-alpha", "containment": "processcontainer",
            "process": { "commandLine": "must-not-run", "cwd": root },
            "filesystem": { "readwritePaths": [writable], "readonlyPaths": [readonly] },
        });
        let observed = filesystem_ceiling(path, maximum);
        let prepared = prepare_candidate(&original.to_string(), &observed);
        let candidate: Value = serde_json::from_str(&prepared.request_json).unwrap();
        assert_eq!(candidate["filesystem"]["readwritePaths"], json!([]));
        if maximum == D::ACCESS_NONE {
            assert_eq!(candidate["filesystem"]["readonlyPaths"], json!([]));
            assert_eq!(candidate["filesystem"]["deniedPaths"], json!([path]));
        }
        let repeated = prepare_candidate(&prepared.request_json, &observed);
        assert!(repeated.changes.is_empty());
        assert_eq!(original["filesystem"]["readwritePaths"], json!([writable]));
    }
}

#[test]
fn policy_preparation_projects_only_enumeration_entries_conflicting_with_new_denies() {
    let _host = PolicyCapabilityGuard::set(true, true, true);
    let mut api = reset();
    api.version_support = Some(version);
    let _scope = ApiScope(INJECTED_API.with(|slot| slot.replace(Some(api))));
    let directory = tempfile::tempdir().unwrap();
    let PathCanonical::Canonical(root) = canonicalize_path(directory.path().to_str().unwrap())
    else {
        panic!("resolve the fixture directory");
    };
    let work = std::path::Path::new(&root).join("work");
    let denied = work.join("sub");
    let unrelated = std::path::Path::new(&root).join("unrelated");
    for path in [&work, &denied, &unrelated] {
        std::fs::create_dir(path).unwrap();
    }
    let original = json!({
        "version": "1.1.0-alpha", "containment": "processcontainer",
        "process": { "commandLine": "must-not-run", "cwd": root },
        "filesystem": { "readwritePaths": [work] },
        "processContainer": { "filesystem": { "enumeratePaths": [denied, unrelated] } },
    });
    let prepared = prepare_candidate(
        &original.to_string(),
        &filesystem_ceiling(denied.to_str().unwrap(), D::ACCESS_NONE),
    );
    let candidate: Value = serde_json::from_str(&prepared.request_json).unwrap();
    assert_eq!(
        candidate["processContainer"]["filesystem"]["enumeratePaths"],
        json!([unrelated])
    );
    assert_eq!(
        candidate["filesystem"]["readwritePaths"],
        original["filesystem"]["readwritePaths"]
    );
    assert_eq!(candidate["filesystem"]["deniedPaths"], json!([denied]));
}

#[test]
fn policy_preparation_projects_removal_of_authored_padded_learning_capabilities() {
    let _host = PolicyCapabilityGuard::set(true, true, true);
    let mut api = reset();
    api.version_support = Some(version);
    let _scope = ApiScope(INJECTED_API.with(|slot| slot.replace(Some(api))));
    let original = json!({
        "version": "1.1.0-alpha", "containment": "processcontainer",
        "process": { "commandLine": "must-not-run" },
        "processContainer": { "capabilities": [" learningModeLogging ", "registryRead"] },
    });
    let prepared = prepare_candidate(
        &original.to_string(),
        &remove_capability("learningModeLogging"),
    );
    let candidate: Value = serde_json::from_str(&prepared.request_json).unwrap();
    assert_eq!(
        candidate["processContainer"]["capabilities"],
        json!(["registryRead"])
    );
    assert_eq!(prepared.changes.len(), 1);
}

#[test]
fn policy_preparation_rejects_aliases_before_treating_a_ceiling_as_satisfied() {
    use std::os::windows::process::CommandExt;
    let _host = PolicyCapabilityGuard::set(true, true, true);
    let mut api = reset();
    api.version_support = Some(version);
    let _scope = ApiScope(INJECTED_API.with(|slot| slot.replace(Some(api))));
    let directory = tempfile::tempdir().unwrap();
    let PathCanonical::Canonical(root) = canonicalize_path(directory.path().to_str().unwrap())
    else {
        panic!("resolve the fixture directory");
    };
    let real = std::path::Path::new(&root).join("real");
    let alias = std::path::Path::new(&root).join("alias");
    std::fs::create_dir(&real).unwrap();
    let output = std::process::Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&alias)
        .arg(&real)
        .creation_flags(windows::Win32::System::Threading::CREATE_NO_WINDOW.0)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "junction fixture failed: {output:?}"
    );
    let original = json!({
        "version": "1.1.0-alpha", "containment": "processcontainer",
        "process": { "commandLine": "must-not-run", "cwd": root },
        "filesystem": { "readwritePaths": [alias] },
    });
    let error = crate::v1::dev::prepare_policy_json(
        &original.to_string(),
        &filesystem_ceiling(real.to_str().unwrap(), D::ACCESS_READ_ONLY),
        Default::default(),
    )
    .expect_err("an alias must not make an unapplied ceiling look satisfied");
    assert_eq!(error.code, crate::v1::ErrorCode::PolicyValidation);
    assert!(
        error.details.as_deref().unwrap()["policyFeedbackError"]["reason"]
            .as_str()
            .unwrap()
            .contains("aliased")
    );
    STATE.with(|state| assert!(state.borrow().specifications.is_empty()));
}

#[test]
fn policy_preparation_preserves_contract_metadata_presence_and_inferred_cwd_in_submitted_psec() {
    let _host = PolicyCapabilityGuard::set(true, true, true);
    let mut api = reset();
    api.version_support = Some(version);
    let _scope = ApiScope(INJECTED_API.with(|slot| slot.replace(Some(api))));
    let directory = tempfile::tempdir().unwrap();
    // TEMP may contain an 8.3 alias; this scenario requires literal grants.
    let PathCanonical::Canonical(root) = canonicalize_path(directory.path().to_str().unwrap())
    else {
        panic!("resolve the fixture's temporary directory");
    };
    let root = std::path::Path::new(&root);
    let work = root.join("work");
    let unrelated = root.join("unrelated");
    let denied = root.join("denied");
    let enumerated = root.join("enumerated");
    for path in [&work, &unrelated, &denied, &enumerated] {
        std::fs::create_dir(path).unwrap();
    }
    let observed = failures(D {
        failure_class: D::CLASS_FILESYSTEM,
        failure_reason: D::REASON_ACCESS_EXCEEDS_CEILING,
        required_action: D::ACTION_RESTRICT_FILESYSTEM_ACCESS,
        resource_kind: D::RESOURCE_KIND_PATH,
        value_kind: D::VALUE_KIND_ACCESS,
        flags: D::FLAG_HAS_ACTIONABLE_DETAILS | D::FLAG_RESOURCE_COMPLETE,
        requested_value: D::ACCESS_READ_WRITE,
        required_value: D::ACCESS_READ_ONLY,
        resource: Some(work.to_string_lossy().into_owned()),
        ..Default::default()
    });
    for (index, version) in ["0.9.0-alpha", "1.0.0", "1.1.0-alpha"].iter().enumerate() {
        let original = json!({
            "version": version, "containerId": "preserved-container", "containment": "process",
            "lifecycle": { "destroyOnExit": true, "preservePolicy": false },
            "process": {
                "commandLine": "cmd.exe /d /c echo mxc-policy-child",
                "inheritDefaultEnv": false, "timeout": 5000,
            },
            "filesystem": {
                "readwritePaths": [work, unrelated, denied],
                "readonlyPaths": [], "deniedPaths": [denied],
            },
            "processContainer": { "filesystem": { "enumeratePaths": [enumerated] } },
        });
        let original_json = original.to_string();
        let _ = parsed_request(&original_json);
        let prepared = prepare_candidate(&original_json, &observed);
        let candidate: Value = serde_json::from_str(&prepared.request_json).unwrap();
        assert_eq!(candidate["version"], original["version"]);
        assert_eq!(candidate["containerId"], original["containerId"]);
        assert_eq!(candidate["containment"], original["containment"]);
        assert_eq!(candidate["lifecycle"], original["lifecycle"]);
        assert!(candidate["process"].get("env").is_none());
        assert_eq!(
            candidate["process"]["inheritDefaultEnv"],
            original["process"]["inheritDefaultEnv"]
        );
        assert_eq!(
            candidate["process"]["commandLine"],
            original["process"]["commandLine"]
        );
        assert_eq!(
            candidate["filesystem"]["readwritePaths"],
            json!([unrelated, denied])
        );
        assert_eq!(candidate["filesystem"]["readonlyPaths"], json!([work]));
        assert_eq!(
            candidate["filesystem"]["deniedPaths"],
            original["filesystem"]["deniedPaths"]
        );
        assert_eq!(candidate["processContainer"], original["processContainer"]);
        assert_eq!(candidate["process"]["cwd"], json!(work));
        assert_eq!(prepared.changes.len(), 3);
        for change in &prepared.changes {
            if change.path == "/process/cwd" {
                assert_eq!(change.operation, PolicyChangeOperation::Add);
                assert!(original.pointer(&change.path).is_none());
                assert!(change.before.is_null());
            } else {
                assert_eq!(change.operation, PolicyChangeOperation::Replace);
                assert_eq!(original.pointer(&change.path), Some(&change.before));
            }
            assert_eq!(candidate.pointer(&change.path), Some(&change.after));
        }
        let unchanged = prepare_candidate(&prepared.request_json, &observed);
        assert!(unchanged.changes.is_empty());
        assert_eq!(unchanged.request_json, prepared.request_json);
        execute_accepted_candidate(&prepared.request_json);
        STATE.with(|state| {
            let state = state.borrow();
            assert_eq!(state.specifications.len(), index + 1);
            assert_eq!(state.closes, index + 1);
            assert_eq!(state.frees, 0);
            let spec =
                psec::root_as_process_security_environment(state.specifications.last().unwrap())
                    .unwrap();
            assert_eq!(spec.version().minor(), 1);
            assert_eq!(
                spec.fs_read_write().unwrap().iter().collect::<Vec<_>>(),
                [unrelated.to_str().unwrap()]
            );
            assert_eq!(
                spec.fs_read_only().unwrap().iter().collect::<Vec<_>>(),
                [work.to_str().unwrap()]
            );
            assert_eq!(
                spec.fs_deny().unwrap().iter().collect::<Vec<_>>(),
                [denied.to_str().unwrap()]
            );
            assert_eq!(
                spec.fs_enumerate().unwrap().iter().collect::<Vec<_>>(),
                [enumerated.to_str().unwrap()]
            );
        });
    }
}

#[test]
fn policy_preparation_preserves_current_proxy_certificate_and_capture_fields() {
    let _host = PolicyCapabilityGuard::set(true, true, true);
    let mut api = reset();
    api.version_support = Some(version);
    let _scope = ApiScope(INJECTED_API.with(|slot| slot.replace(Some(api))));
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    for (index, port) in [7011, 7022].iter().enumerate() {
        let certificate = root.join(format!("certificate-{port}.pem"));
        std::fs::write(&certificate, b"certificate grant fixture").unwrap();
        let proxy = format!("http://127.0.0.1:{port}");
        let peer = format!("mxc-preparation-peer-{port}");
        let original = json!({
            "version":"1.1.0-alpha", "containment":"processcontainer",
            "process": {
                "commandLine": "cmd.exe /d /c echo mxc-policy-child",
                "cwd": root, "timeout": 5000,
            },
            "filesystem": { "readonlyPaths": [certificate] },
            "network": {
                "egress": { "default":"deny" },
                "ingress": { "default":"allow", "hostLoopback":"deny" },
            },
            "runtimeConfig": { "networkProxy":proxy },
            "processContainer": {
                "capabilities":["registryRead", "registryWrite"],
                "network": { "allowedProxyPeer":peer },
            }
        });
        let prepared = prepare_candidate(&original.to_string(), &remove_capability("registryRead"));
        let candidate: Value = serde_json::from_str(&prepared.request_json).unwrap();
        assert_eq!(prepared.changes.len(), 1);
        assert_eq!(candidate["runtimeConfig"], original["runtimeConfig"]);
        assert_eq!(candidate["network"], original["network"]);
        assert_eq!(candidate["filesystem"], original["filesystem"]);
        assert_eq!(
            candidate["processContainer"]["network"],
            original["processContainer"]["network"]
        );
        execute_accepted_candidate(&prepared.request_json);
        STATE.with(|state| {
            let state = state.borrow();
            assert_eq!(state.specifications.len(), index + 1);
            assert_eq!(state.closes, index + 1);
            let spec =
                psec::root_as_process_security_environment(state.specifications.last().unwrap())
                    .unwrap();
            assert_eq!(
                spec.fs_read_only().unwrap().get(0),
                certificate.to_str().unwrap()
            );
            let network = spec.network_policy().unwrap();
            assert_eq!(network.proxy().unwrap().url(), Some(proxy.as_str()));
            assert_eq!(network.allowed_appcontainer_peer(), Some(peer.as_str()));
            assert!(network.egress().is_none());
            assert!(network.ingress().is_none());
            assert_eq!(
                spec.capabilities(),
                Some("registryWrite,privateNetworkClientServer")
            );
        });
        for sources in [
            crate::learning_mode_windows::LearningModeTraceSources::AccessOnly,
            crate::learning_mode_windows::LearningModeTraceSources::AccessAndNetwork,
        ] {
            STATE.with(|state| state.borrow_mut().capture_sources = sources);
            let mut capture = original.clone();
            capture["processContainer"]["learningMode"] = json!(true);
            capture["processContainer"]["captureDenials"] = json!({
                "mode":"allow", "outputPath":root.join(format!("capture-{port}.json")), "retainEtl":true,
            });
            let prepared = prepare_candidate(
                &capture.to_string(),
                &remove_capability("permissiveLearningMode"),
            );
            let candidate: Value = serde_json::from_str(&prepared.request_json).unwrap();
            assert_eq!(prepared.changes.len(), 1);
            assert_eq!(
                prepared.changes[0].path,
                "/processContainer/captureDenials/mode"
            );
            capture["processContainer"]["captureDenials"]["mode"] = json!("block");
            assert_eq!(candidate, capture);
            assert!(!candidate["processContainer"]["capabilities"]
                .as_array()
                .unwrap()
                .iter()
                .any(|capability| capability == "learningModeLogging"));
            let request = parsed_request(&prepared.request_json);
            let effective =
                crate::process_container_common::base_container_helpers::effective_capabilities(
                    &request,
                    sources.includes_network(),
                );
            assert!(effective.iter().any(|entry| entry == "learningModeLogging"));
            assert!(!effective
                .iter()
                .any(|entry| entry == "permissiveLearningMode"));
            assert!(!effective.iter().any(|entry| entry == "internetClient"));
        }
    }
}

#[test]
fn policy_preparation_preserves_supported_process_container_alias_for_capability_and_capture_edits()
{
    let _host = PolicyCapabilityGuard::set(true, true, true);
    let mut api = reset();
    api.version_support = Some(version);
    let _scope = ApiScope(INJECTED_API.with(|slot| slot.replace(Some(api))));
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    STATE.with(|state| {
        state.borrow_mut().capture_sources =
            crate::learning_mode_windows::LearningModeTraceSources::AccessOnly;
    });
    for section in ["appContainer", "processContainer"] {
        let mut original = json!({
            "version": "0.9.0-alpha",
            "containment": "processcontainer",
            "process": { "commandLine": "must-not-run", "cwd": root },
            "network": {
                "egress": { "default": "deny" },
                "ingress": { "default": "deny", "hostLoopback": "deny" },
            },
        });
        original[section] = json!({ "capabilities": ["registryRead", "registryWrite"] });
        let prepared = prepare_candidate(&original.to_string(), &remove_capability("registryRead"));
        let mut expected = original.clone();
        expected[section]["capabilities"] = json!(["registryWrite"]);
        assert_eq!(
            serde_json::from_str::<Value>(&prepared.request_json).unwrap(),
            expected
        );
        assert_eq!(prepared.changes.len(), 1);
        assert_eq!(prepared.changes[0].path, format!("/{section}/capabilities"));
        original[section]["learningMode"] = json!(true);
        original[section]["captureDenials"] = json!({
            "mode": "allow", "outputPath": root.join("capture.json"), "retainEtl": true,
        });
        let prepared = prepare_candidate(
            &original.to_string(),
            &remove_capability("permissiveLearningMode"),
        );
        let mut expected = original.clone();
        expected[section]["captureDenials"]["mode"] = json!("block");
        assert_eq!(
            serde_json::from_str::<Value>(&prepared.request_json).unwrap(),
            expected
        );
        assert_eq!(
            prepared.changes[0].path,
            format!("/{section}/captureDenials/mode")
        );
        original[section]["captureDenials"]["mode"] = json!("block");
        let prepared = prepare_candidate(
            &original.to_string(),
            &remove_capability("learningModeLogging"),
        );
        let mut expected = original.clone();
        expected[section]["learningMode"] = json!(false);
        expected[section]
            .as_object_mut()
            .unwrap()
            .remove("captureDenials");
        assert_eq!(
            serde_json::from_str::<Value>(&prepared.request_json).unwrap(),
            expected
        );
        assert!(prepared
            .changes
            .iter()
            .all(|change| change.path.starts_with(&format!("/{section}/"))));
    }
    STATE.with(|state| {
        let state = state.borrow();
        assert!(state.specifications.is_empty());
        assert!(!state.calls.contains(&"create"));
        assert!(!state.calls.contains(&"launch"));
    });
}

#[test]
fn policy_preparation_keeps_unchanged_member_text_verbatim() {
    let _host = PolicyCapabilityGuard::set(true, true, true);
    let mut api = reset();
    api.version_support = Some(version);
    let _scope = ApiScope(INJECTED_API.with(|slot| slot.replace(Some(api))));
    let directory = tempfile::tempdir().unwrap();
    let comment = r#"{"big":123456789012345678901234567890,"dup":1,"dup":2}"#;
    let original = format!(
        r#"{{"version":"0.9.0-alpha","_comment":{comment},"containment":"processcontainer","process":{{"commandLine":"must-not-run","cwd":{}}},"network":{{"egress":{{"default":"deny"}},"ingress":{{"default":"deny","hostLoopback":"deny"}}}},"processContainer":{{"capabilities":["registryRead","registryWrite"]}}}}"#,
        serde_json::to_string(directory.path()).unwrap()
    );
    let prepared = prepare_candidate(&original, &remove_capability("registryRead"));
    assert_eq!(prepared.changes.len(), 1);
    assert!(
        prepared
            .request_json
            .contains(&format!(r#""_comment":{comment}"#)),
        "{}",
        prepared.request_json
    );
    assert_eq!(
        serde_json::from_str::<Value>(&prepared.request_json).unwrap()["processContainer"]
            ["capabilities"],
        json!(["registryWrite"])
    );
}

#[test]
fn policy_preparation_unknown_or_unsafe_observations_fail_before_native_creation() {
    let _host = PolicyCapabilityGuard::set(true, true, true);
    let mut api = reset();
    api.version_support = Some(version);
    let _scope = ApiScope(INJECTED_API.with(|slot| slot.replace(Some(api))));
    let request = r#"{"version":"1.0.0","process":{"commandLine":"INPUT_SECRET_MARKER"},"processContainer":{"capabilities":["registryRead"]}}"#;
    for fault in ["version", "outcome", "action", "flags", "resource"] {
        let mut observed = remove_capability("registryRead");
        match fault {
            "version" => observed.results[0].minimum_reader_version = u32::MAX,
            "outcome" => observed.results[0].outcome = R::OUTCOME_EVALUATION_FAILED,
            "action" => observed.results[0].details[0].required_action = u32::MAX,
            "flags" => observed.results[0].details[0].flags = D::FLAG_RESOURCE_UNAVAILABLE,
            "resource" => {
                let detail = &mut observed.results[0].details[0];
                detail.resource = None;
            }
            _ => unreachable!(),
        }
        let error = crate::v1::dev::prepare_policy_json(request, &observed, Default::default())
            .unwrap_err();
        assert_eq!(
            error.code,
            crate::v1::ErrorCode::PolicyValidation,
            "{fault}"
        );
        assert_eq!(
            error.message, "policy preparation cannot safely enforce the requested policy",
            "{fault}"
        );
        assert_eq!(
            PolicyFailures::from_error(&error).unwrap(),
            Some(observed),
            "{fault}"
        );
        STATE.with(|state| {
            let state = state.borrow();
            assert!(state.specifications.is_empty());
            assert!(!state.calls.contains(&"create"));
            assert!(!state.calls.contains(&"launch"));
            assert_eq!(state.frees, 0);
            assert_eq!(state.closes, 0);
        });
    }
}
