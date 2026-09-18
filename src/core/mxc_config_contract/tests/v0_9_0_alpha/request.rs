// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_config_contract::dev::{
    parse_operation_request, parse_request, Request, RequestParseError,
};

#[test]
fn one_shot_request_requires_process() {
    let error = parse_request(r#"{"version":"0.9.0-alpha"}"#).unwrap_err();
    assert!(matches!(
        error,
        RequestParseError::InvalidCombination {
            contract: "one-shot",
            message: "one-shot execution requires process.commandLine",
        }
    ));
}

#[test]
fn one_shot_request_with_process_is_accepted() {
    let request =
        parse_request(r#"{"version":"0.9.0-alpha","process":{"commandLine":"echo"}}"#).unwrap();
    assert!(matches!(request, Request::OneShot(_)));
}

#[test]
fn operation_request_may_omit_process() {
    parse_operation_request(r#"{"version":"0.9.0-alpha","containment":"wslc"}"#).unwrap();
}

#[test]
fn operation_request_accepts_direct_backend_configuration() {
    parse_operation_request(
        r#"{
            "version":"0.9.0-alpha",
            "containment":"wslc",
            "experimental":{"wslc":{"image":"alpine:latest"}}
        }"#,
    )
    .unwrap();
    parse_operation_request(
        r#"{
            "version":"0.9.0-alpha",
            "containment":"isolation_session",
            "experimental":{"isolation_session":{"appId":"PFN:example"}}
        }"#,
    )
    .unwrap();
}

#[test]
fn lifecycle_dispatch_fields_are_rejected() {
    for field in [r#""phase":"provision""#, r#""sandboxId":"wslc:abcd1234""#] {
        let json = format!(r#"{{"version":"0.9.0-alpha",{field}}}"#);
        let error = parse_operation_request(&json).unwrap_err();
        let RequestParseError::InvalidRequest { source, .. } = error else {
            panic!("expected an invalid request");
        };
        assert!(source.to_string().contains("unknown field"));
    }
}

#[test]
fn isolation_session_one_shot_requires_network() {
    let error = parse_request(
        r#"{
            "version":"0.9.0-alpha",
            "containment":"isolation_session",
            "process":{"commandLine":"echo"}
        }"#,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        RequestParseError::InvalidCombination {
            contract: "one-shot",
            message: "IsolationSession requires an explicit network policy",
        }
    ));
}

#[test]
fn isolation_session_lifecycle_config_is_rejected_by_one_shot() {
    let error = parse_request(
        r#"{
            "version":"0.9.0-alpha",
            "containment":"isolation_session",
            "process":{"commandLine":"echo"},
            "network":{"egress":{"default":"allow"},"ingress":{"default":"allow","hostLoopback":"allow"}},
            "experimental":{"isolation_session":{"appId":"PFN:example"}}
        }"#,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        RequestParseError::InvalidCombination {
            contract: "one-shot",
            message: "experimental.isolation_session is accepted only by lifecycle provision",
        }
    ));
}
