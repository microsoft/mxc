// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::v1::dev;

#[test]
fn public_rust_sdk_lifecycle_fixture() {
    let _lock = ENV.lock().unwrap();
    let env = Environment::new();
    let fixture = Fixture::new();
    fixture.configure(&env);
    let options = dev::JsonOptions { experimental: true };
    let mut local = provision();
    local["w365Agents"]["provision"]["userType"] = json!("Local");
    let json = local.to_string();
    assert_eq!(
        dev::provision_container_json(&json, dev::JsonOptions::default())
            .unwrap_err()
            .code,
        crate::v1::ErrorCode::BackendUnavailable
    );
    dev::validate_provision_json(&json, options).unwrap();
    let mut invalid = local.clone();
    invalid["filesystem"] = json!({});
    assert!(dev::provision_container_json(&invalid.to_string(), options).is_err());
    assert!(dev::start_container_json(&request("start", A).to_string(), options).is_err());
    assert!(dev::run_in_container_json(&request("exec", A).to_string(), options).is_err());
    assert_eq!(fixture.count(), 0);

    fixture.reply(
        200,
        &json!({"sessionId":A,"status":"Succeeded"}).to_string(),
    );
    let value: Value =
        serde_json::from_str(&dev::provision_container_json(&json, options).unwrap()).unwrap();
    assert_eq!(value["result"]["sandboxId"], format!("w365:{POOL}:{A}"));
    assert!(fixture
        .request(0)
        .to_ascii_lowercase()
        .contains("user-type: local"));
    env.set("W365A_CP_TOKEN", "renewed-fixture-token");
    fixture.reply(408, "");
    let error = dev::deprovision_container_json(&request("deprovision", A).to_string(), options)
        .unwrap_err();
    let details = error.details.as_ref().unwrap();
    assert_eq!(details["sandboxId"], format!("w365:{POOL}:{A}"));
    assert_eq!(details["possiblySucceeded"], true);
    assert_eq!(details["requestId"], "fixture-request");
    assert!(!format!("{error:?}").contains(A));
    assert_eq!(fixture.count(), 2);
    fixture.reply(202, "");
    let value: Value = serde_json::from_str(
        &dev::stop_container_json(&request("stop", A).to_string(), options).unwrap(),
    )
    .unwrap();
    assert_eq!(value["result"]["metadata"]["releaseRequested"], true);
    assert_eq!(value["result"]["metadata"]["restartable"], false);
    assert!(fixture.request(2).contains("renewed-fixture-token"));
    assert!(fixture
        .request(2)
        .starts_with(&format!("DELETE /api/sessions/{A}?")));

    fixture.reply(
        200,
        &json!({"sessionId":A,"computerId":B,"status":"Succeeded"}).to_string(),
    );
    let error = dev::provision_container_json(&json, options).unwrap_err();
    assert_eq!(
        error.details.as_ref().unwrap()["sandboxId"],
        format!("w365:{POOL}:{A}")
    );
    fixture.reply(204, "");
    dev::deprovision_container_json(&request("deprovision", A).to_string(), options).unwrap();
    fixture.reply(200, r#"{"status":"Succeeded"}"#);
    let error = dev::provision_container_json(&provision().to_string(), options).unwrap_err();
    assert_eq!(error.details.as_ref().unwrap()["possiblySucceeded"], true);
    assert!(error.details.as_ref().unwrap().get("sandboxId").is_none());
    assert_eq!(
        fixture.count(),
        6,
        "SDK must not replay checkout or release"
    );
    assert!(!fixture
        .request(5)
        .to_ascii_lowercase()
        .contains("user-type:"));
}

// The managed/Node test command is supplied by the offline SDK CI selector.
#[test]
#[ignore = "requires a separately built public SDK test caller"]
fn sdk_fresh_caller_fixture() {
    let _lock = ENV.lock().unwrap();
    let env = Environment::new();
    let fixture = Fixture::new();
    fixture.configure(&env);
    let command: Vec<String> = serde_json::from_str(
        &std::env::var("MXC_W365_TEST_SDK_COMMAND").expect("SDK fixture command required"),
    )
    .unwrap();
    assert!(!command.is_empty());
    for (mode, reply, expected_count) in [
        ("validate", None, 0),
        (
            "provision",
            Some((200, json!({"sessionId":A,"status":"Succeeded"}).to_string())),
            1,
        ),
        ("uncertain-release", Some((408, String::new())), 2),
        ("stop", Some((202, String::new())), 3),
        (
            "rejected",
            Some((
                200,
                json!({"sessionId":A,"computerId":B,"status":"Succeeded"}).to_string(),
            )),
            4,
        ),
        ("cleanup", Some((204, String::new())), 5),
        (
            "unknown",
            Some((200, r#"{"status":"Succeeded"}"#.into())),
            6,
        ),
    ] {
        if let Some((status, body)) = reply {
            fixture.reply(status, &body);
        }
        let marker_dir = tempfile::tempdir().unwrap();
        let marker = marker_dir.path().join("completed");
        let mut child = std::process::Command::new(&command[0])
            .args(&command[1..])
            .env("MXC_W365_TEST_SDK_MODE", mode)
            .env("MXC_W365_TEST_SDK_MARKER", &marker)
            .env(
                "W365A_CP_TOKEN",
                if expected_count <= 1 {
                    "initial-fixture-token"
                } else {
                    "renewed-fixture-token"
                },
            )
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let until = Instant::now() + Duration::from_secs(90);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= until {
                child.kill().unwrap();
                panic!("public SDK fixture timed out: {mode}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{mode}: status={} {}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::read_to_string(&marker).unwrap(),
            mode,
            "SDK test must execute its assertions"
        );
        assert_eq!(
            fixture.count(),
            expected_count,
            "no replay or unexpected network: {mode}"
        );
    }
    let checkout = fixture.request(0).to_ascii_lowercase();
    assert!(checkout.starts_with(&format!("post /api/pools/{POOL}/sessions?api-version=2.0 ")));
    assert!(checkout.contains("user-type: local"));
    assert!(checkout.contains("initial-fixture-token"));
    assert_eq!(checkout.split_once("\r\n\r\n").unwrap().1, "");
    for n in [1, 2, 4] {
        let sent = fixture.request(n);
        assert!(sent.starts_with(&format!("DELETE /api/sessions/{A}?api-version=2.0")));
        assert!(sent.contains("renewed-fixture-token"));
    }
    assert!(!fixture
        .request(5)
        .to_ascii_lowercase()
        .contains("user-type:"));
}
