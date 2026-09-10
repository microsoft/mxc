// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_config_contract::dev::IsolationSessionProvisionRequest;
use serde_json::{json, Value};

fn request() -> Value {
    json!({
        "version": "0.9.0-alpha",
        "phase": "provision",
        "containment": "isolation_session",
        "experimental": {
            "isolation_session": {
                "provision": {"acknowledgeUnrestrictedNetwork": true}
            }
        }
    })
}

fn accepts(value: &Value) -> bool {
    serde_json::from_str::<IsolationSessionProvisionRequest>(&value.to_string()).is_ok()
}

#[test]
fn accepts_required_acknowledgment_and_optional_fields() {
    assert!(accepts(&request()));
    for app_id in [None, Some(""), Some("Contoso.App")] {
        for comment in [
            Value::Null,
            json!("comment"),
            json!([]),
            json!({}),
            json!(42),
        ] {
            for enabled in [true, false] {
                let mut value = request();
                value["$schema"] = json!("https://example.com/schema");
                value["_comment"] = comment.clone();
                value["telemetry"] = json!({"enabled": enabled});
                if let Some(app_id) = app_id {
                    value["experimental"]["isolation_session"]["provision"]["appId"] =
                        json!(app_id);
                }
                assert!(accepts(&value), "{value}");
            }
        }
    }
}

#[test]
fn every_required_field_rejects_absence_null_and_wrong_type() {
    for pointer in [
        "/version",
        "/phase",
        "/containment",
        "/experimental",
        "/experimental/isolation_session",
        "/experimental/isolation_session/provision",
        "/experimental/isolation_session/provision/acknowledgeUnrestrictedNetwork",
    ] {
        let (parent, name) = pointer.rsplit_once('/').unwrap();
        let mut absent = request();
        absent
            .pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(name);
        assert!(!accepts(&absent), "{absent}");
        for invalid in [Value::Null, json!(false), json!(42), json!([])] {
            let mut value = request();
            *value.pointer_mut(pointer).unwrap() = invalid;
            assert!(!accepts(&value), "{value}");
        }
    }
}

#[test]
fn acknowledgment_is_true_only_and_app_id_is_optional_string() {
    for value in [
        json!("true"),
        json!(0),
        json!({}),
        json!([]),
        Value::Null,
        json!(false),
    ] {
        let mut invalid = request();
        invalid["experimental"]["isolation_session"]["provision"]
            ["acknowledgeUnrestrictedNetwork"] = value;
        assert!(!accepts(&invalid), "{invalid}");
    }
    for app_id in [Value::Null, json!(42), json!(false), json!([]), json!({})] {
        let mut invalid = request();
        invalid["experimental"]["isolation_session"]["provision"]["appId"] = app_id;
        assert!(!accepts(&invalid), "{invalid}");
    }
}

#[test]
fn rejects_unknown_fields_at_every_level_and_foreign_phase_fields() {
    for pointer in [
        "",
        "/experimental",
        "/experimental/isolation_session",
        "/experimental/isolation_session/provision",
    ] {
        let mut value = request();
        value.pointer_mut(pointer).unwrap()["unknown"] = json!(true);
        assert!(!accepts(&value), "{value}");
    }
    for name in [
        "process",
        "lifecycle",
        "containerId",
        "sandboxId",
        "correlationVector",
        "processContainer",
        "appContainer",
        "lxc",
        "fallback",
        "filesystem",
        "ui",
        "seatbelt",
        "macos_sandbox",
        "runtimeConfig",
        "network",
    ] {
        let mut value = request();
        value[name] = json!({});
        assert!(!accepts(&value), "{value}");
    }
}

#[test]
fn rejects_legacy_network_even_with_acknowledgment() {
    let mut value = request();
    value["network"] = json!({"defaultPolicy": "allow", "allowLocalNetwork": true});
    assert!(!accepts(&value));
    value.as_object_mut().unwrap().remove("experimental");
    assert!(!accepts(&value));
}

#[test]
fn source_deserialization_preserves_escaped_spellings_and_duplicate_rejection() {
    let source = request().to_string();
    for (from, to) in [
        ("provision", "pr\\u006fvision"),
        ("isolation_session", "is\\u006flation_session"),
    ] {
        assert!(serde_json::from_str::<IsolationSessionProvisionRequest>(
            &source.replace(from, to)
        )
        .is_ok());
    }
    for (from, to) in [
        (
            "\"acknowledgeUnrestrictedNetwork\":true",
            "\"acknowledgeUnrestrictedNetwork\":true,\"acknowledgeUnrestrictedNetwork\":true",
        ),
        (
            "\"phase\":\"provision\"",
            "\"phase\":\"provision\",\"phase\":\"provision\"",
        ),
    ] {
        let error =
            serde_json::from_str::<IsolationSessionProvisionRequest>(&source.replace(from, to))
                .unwrap_err();
        assert!(error.to_string().contains("duplicate field"), "{error}");
        assert!(error.line() > 0);
        assert!(error.column() > 0);
    }
}
