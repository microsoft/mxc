// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_sdk::mxc_common::{
    config_parser::load_mxc_request_from_json,
    logger::{Logger, Mode},
    mxc_error::MxcErrorCode,
};
use mxc_sdk::mxc_contract::{dev, published};
use serde_json::{json, Value};

const ID: &str = "w365:11111111-1111-1111-1111-111111111111:22222222-2222-2222-2222-222222222222";
const PHASES: [&str; 5] = ["provision", "start", "exec", "stop", "deprovision"];

fn request(phase: &str) -> Value {
    let mut value = json!({"version":"1.1.0-alpha", "phase":phase});
    if phase == "provision" {
        value["containment"] = json!("w365_agents");
    } else {
        value["sandboxId"] = json!(ID);
    }
    if phase == "exec" {
        value["process"] = json!({"commandLine":"cmd.exe /c echo fixture"});
    }
    value
}

fn settings(phase: &str) -> Value {
    if phase == "provision" {
        json!({"poolId":"11111111-1111-1111-1111-111111111111"})
    } else {
        json!({})
    }
}

fn assert_rejected(value: &Value) {
    let source = value.to_string();
    assert!(dev::parse_request(&source).is_err(), "{source}");
    let error = load_mxc_request_from_json(&source, &mut Logger::new(Mode::Buffer))
        .expect_err("the normal parser must enforce the same contract");
    assert_eq!(
        error.to_mxc_error().code,
        MxcErrorCode::MalformedRequest,
        "{source}"
    );
}

#[test]
fn w365_agents_contract_acceptance_never_enables_execution() {
    for phase in PHASES {
        let baseline = request(phase);
        for wrapper in [None, Some(json!({})), Some(json!({phase: settings(phase)}))] {
            if phase != "provision" && wrapper.is_some() {
                continue;
            }
            let mut value = baseline.clone();
            if let Some(wrapper) = wrapper {
                value["w365Agents"] = wrapper;
            }
            let source = value.to_string();
            dev::parse_request(&source)
                .expect("structural acceptance is independent of availability");
            let parsed = load_mxc_request_from_json(&source, &mut Logger::new(Mode::Buffer))
                .expect("valid contracts use normal lifecycle adaptation");
            let mxc_sdk::mxc_common::state_aware_request::MxcRequest::StateAware(parsed) =
                parsed
            else {
                panic!("expected lifecycle request");
            };
            if phase != "provision" {
                assert_eq!(parsed.sandbox_id(), Some(ID));
                let error = mxc_sdk::mxc_common::state_aware_dispatch::resolve_backend(&parsed)
                    .expect_err("W365 is not registered");
                assert_eq!(error.code, MxcErrorCode::UnsupportedContainment);
                continue;
            }
            let error = mxc_sdk::mxc_common::state_aware_dispatch::resolve_backend(&parsed)
                .expect_err("contract acceptance must not enable execution");
            assert_eq!(error.code, MxcErrorCode::BackendUnavailable);
            assert!(error.message.contains("not implemented"));
        }
    }
}

#[test]
fn w365_agents_settings_are_closed_and_phase_specific_in_both_parsers() {
    {
        let phase = "provision";
        for bad in [Value::Null, json!(false), json!(""), json!(1), json!([])] {
            let mut value = request(phase);
            value["w365Agents"] = bad.clone();
            assert_rejected(&value);
            value["w365Agents"] = json!({phase: bad});
            assert_rejected(&value);
        }
        for other in PHASES.into_iter().filter(|other| *other != phase) {
            let mut value = request(phase);
            value["w365Agents"] = json!({phase: settings(phase), other: settings(other)});
            assert_rejected(&value);
        }
        let mut value = request(phase);
        value["w365Agents"] = json!({phase: settings(phase), "unknown": {}});
        assert_rejected(&value);
        value["w365Agents"] = json!({phase: settings(phase)});
        value["w365Agents"][phase]["unknown"] = json!("unsupported");
        assert_rejected(&value);
        for authorization in ["experimental", "experimentalEnabled"] {
            let mut value = request(phase);
            value[authorization] = json!(true);
            assert_rejected(&value);
        }
    }
}

#[test]
fn w365_agents_later_phases_reject_backend_settings_on_every_container() {
    for phase in ["start", "exec", "stop", "deprovision"] {
        for id in [ID, "iso:fixture"] {
            let mut value = request(phase);
            value["sandboxId"] = json!(id);
            value["w365Agents"] = json!({});
            assert_rejected(&value);
        }
    }
}

#[test]
fn w365_agents_identity_field_types_are_enforced() {
    for field in ["poolId", "userObjectId"] {
        for invalid in [
            Value::Null,
            json!(""),
            json!(" "),
            json!("11111111111111111111111111111111"),
            json!("g1111111-1111-1111-1111-111111111111"),
            json!(true),
        ] {
            let mut value = request("provision");
            value["w365Agents"] = json!({"provision":settings("provision")});
            value["w365Agents"]["provision"][field] = invalid;
            assert_rejected(&value);
        }
    }
    for invalid in [
        Value::Null,
        json!(""),
        json!("local"),
        json!("Unsupported"),
        json!({"HumanUser":null}),
    ] {
        let mut value = request("provision");
        value["w365Agents"] = json!({"provision":settings("provision")});
        value["w365Agents"]["provision"]["userType"] = invalid;
        assert_rejected(&value);
    }
}

#[test]
fn w365_agents_supported_user_types_remain_unavailable() {
    for user_type in ["Local", "HumanUser", "Agentic"] {
        let mut value = request("provision");
        value["w365Agents"] = json!({"provision":settings("provision")});
        value["w365Agents"]["provision"]["userType"] = json!(user_type);
        let source = value.to_string();
        dev::parse_request(&source).expect("supported user type");
        let error = mxc_sdk::v1::dev::provision_container_json(
            &source,
            mxc_sdk::v1::dev::JsonOptions { experimental: true },
        )
        .expect_err("contract support must not enable backend execution");
        assert_eq!(error.code, mxc_sdk::v1::ErrorCode::BackendUnavailable);
    }
}

#[test]
fn w365_agents_object_deserialization_retains_duplicate_field_rejection() {
    for source in [
        r#"{"version":"1.1.0-alpha","phase":"provision","containment":"w365_agents",
            "w365Agents":{"provision":{"poolId":"11111111-1111-1111-1111-111111111111",
            "poolId":"22222222-2222-2222-2222-222222222222"}}}"#,
        r#"{"version":"1.1.0-alpha","phase":"provision","containment":"w365_agents",
            "w365Agents":{"provision":{"poolId":"11111111-1111-1111-1111-111111111111"},
            "provision":{"poolId":"22222222-2222-2222-2222-222222222222"}}}"#,
        r#"{"version":"1.1.0-alpha","phase":"provision","containment":"w365_agents",
            "w365Agents":{"provision":{"poolId":"11111111-1111-1111-1111-111111111111",
            "userType":"HumanUser","userType":"HumanUser"}}}"#,
    ] {
        assert!(dev::parse_request(source).is_err());
        let error = load_mxc_request_from_json(source, &mut Logger::new(Mode::Buffer)).unwrap_err();
        assert_eq!(error.to_mxc_error().code, MxcErrorCode::MalformedRequest);
        assert!(error.to_mxc_error().message.contains("duplicate field"));
    }
}

#[test]
fn w365_agents_does_not_expand_published_or_other_operation_contracts() {
    for phase in PHASES {
        let mut value = request(phase);
        value["w365Agents"] = json!({phase: settings(phase)});
        value["version"] = json!("1.0.0");
        assert!(published::v1_0_0::parse_request(&value.to_string()).is_err());
        value["version"] = json!("0.9.0-alpha");
        assert!(published::v0_9_0_alpha::parse_request(&value.to_string()).is_err());
    }
    for phase in ["provision-session", "deprovision-session"] {
        let value = json!({"version":"1.1.0-alpha","phase":phase,"containment":"w365_agents"});
        assert!(dev::parse_request(&value.to_string()).is_err());
        let error = load_mxc_request_from_json(&value.to_string(), &mut Logger::new(Mode::Buffer))
            .unwrap_err();
        assert_eq!(
            error.to_mxc_error().code,
            MxcErrorCode::UnsupportedContainment
        );
    }
    assert_rejected(
        &json!({"version":"1.1.0-alpha","containment":"w365_agents","process":{"commandLine":"echo no"}}),
    );
    assert_rejected(
        &json!({"version":"1.1.0-alpha","process":{"commandLine":"echo no"},"w365Agents":{}}),
    );
    for phase in ["provision", "start", "stop", "deprovision"] {
        for policy in ["filesystem", "network", "runtimeConfig", "ui", "process"] {
            let mut value = request(phase);
            value[policy] = json!({});
            assert_rejected(&value);
        }
    }
}

#[test]
fn w365_agents_create_and_run_apis_reject_lifecycle_requests_before_dispatch() {
    use mxc_sdk::v1::{dev as sdk, ErrorCode};

    let source = request("provision").to_string();
    for experimental in [false, true] {
        let options = sdk::JsonOptions { experimental };
        let errors = [
            sdk::run_json(&source, options).unwrap_err(),
            sdk::spawn_json(&source, options).err().expect("lifecycle request"),
            sdk::spawn_with_pty_json(
                &source,
                sdk::PtyJsonOptions {
                    experimental,
                    ..Default::default()
                },
            )
            .expect_err("lifecycle request"),
        ];
        for error in errors {
            assert_eq!(error.code, ErrorCode::MalformedRequest);
            assert!(error.message.contains("expected a one-shot request"));
        }
    }
}

#[test]
fn w365_agents_dev_sdk_refuses_every_phase_with_or_without_opt_in() {
    use mxc_sdk::v1::dev as sdk;
    for experimental in [false, true] {
        for phase in PHASES {
            let source = request(phase).to_string();
            let options = sdk::JsonOptions { experimental };
            let error = match phase {
                "provision" => sdk::provision_container_json(&source, options).unwrap_err(),
                "start" => sdk::start_container_json(&source, options).unwrap_err(),
                "exec" => sdk::run_in_container_json(&source, options).unwrap_err(),
                "stop" => sdk::stop_container_json(&source, options).unwrap_err(),
                "deprovision" => sdk::deprovision_container_json(&source, options).unwrap_err(),
                _ => unreachable!(),
            };
            let expected = if phase == "provision" {
                mxc_sdk::v1::ErrorCode::BackendUnavailable
            } else {
                mxc_sdk::v1::ErrorCode::UnsupportedContainment
            };
            assert_eq!(error.code, expected, "{phase}, experimental={experimental}");
            if phase == "exec" {
                let error = sdk::spawn_in_container_json(&source, options)
                    .err()
                    .expect("piped spawn must also remain unavailable");
                assert_eq!(error.code, expected);
            }
        }
    }
}
