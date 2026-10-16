// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_sdk::mxc_contract::dev::{
    parse_request, DeprovisionRequest, ExecRequest, IsolationSessionProvisionRequest, Request,
    StartRequest, StopRequest, WindowsSandboxProvisionRequest, WslcDeprovisionSessionRequest,
    WslcProvisionRequest, WslcProvisionSessionRequest,
};

const VERSION: &str = "v1_1_0_alpha";

fn read_fixtures(root: &str, kind: &str) -> Vec<(String, String)> {
    crate::exact_test_support::read_fixtures(env!("CARGO_MANIFEST_DIR"), VERSION, root, kind)
}

fn assert_root_fixtures<T: serde::de::DeserializeOwned>(root: &str) {
    crate::exact_test_support::assert_root_fixtures::<T>(env!("CARGO_MANIFEST_DIR"), VERSION, root);
}

fn assert_one_shot_fixtures() {
    for (name, json) in read_fixtures("one_shot", "valid") {
        assert!(
            matches!(parse_request(&json), Ok(Request::OneShot(_))),
            "valid fixture 'one_shot/valid/{name}' failed"
        );
    }
    for (name, json) in read_fixtures("one_shot", "invalid") {
        if let Ok(request) = parse_request(&json) {
            panic!("invalid fixture 'one_shot/invalid/{name}' was accepted as {request:?}");
        }
    }
}

#[test]
fn accepts_and_rejects_every_discovered_fixture() {
    assert_one_shot_fixtures();
    assert_root_fixtures::<WslcProvisionSessionRequest>("wslc_provision_session");
    assert_root_fixtures::<WindowsSandboxProvisionRequest>("windows_sandbox_provision");
    assert_root_fixtures::<IsolationSessionProvisionRequest>("isolation_session_provision");
    assert_root_fixtures::<WslcProvisionRequest>("wslc_provision");
    assert_root_fixtures::<StartRequest>("start");
    assert_root_fixtures::<ExecRequest>("exec");
    assert_root_fixtures::<StopRequest>("stop");
    assert_root_fixtures::<DeprovisionRequest>("deprovision");
    assert_root_fixtures::<WslcDeprovisionSessionRequest>("wslc_deprovision_session");
}

#[test]
fn the_request_parser_selects_each_session_root() {
    for (root, expect_provision_session) in
        [("wslc_provision_session", true), ("wslc_deprovision_session", false)]
    {
        for (name, json) in read_fixtures(root, "valid") {
            let request = parse_request(&json)
                .unwrap_or_else(|error| panic!("valid fixture '{root}/valid/{name}': {error}"));
            let selected = if expect_provision_session {
                matches!(request, Request::ProvisionSession(_))
            } else {
                matches!(request, Request::DeprovisionSession(_))
            };
            assert!(selected, "'{root}/valid/{name}' selected {request:?}");
        }
    }
}

#[test]
fn the_request_parser_refuses_a_session_phase_for_a_foreign_containment() {
    for phase in ["provision-session", "deprovision-session"] {
        for containment in ["isolation_session", "windows_sandbox"] {
            let json = format!(
                r#"{{"version":"1.1.0-alpha","phase":"{phase}","containment":"{containment}",
                     "sessionId":"wslcsess:0123456789abcdef0123456789abcdef"}}"#
            );
            let error = parse_request(&json)
                .err()
                .unwrap_or_else(|| panic!("{containment} must not satisfy {phase}"));
            assert!(
                matches!(
                    error,
                    mxc_sdk::mxc_contract::dev::RequestParseError::Containment(_)
                ),
                "{phase}/{containment} must be refused as an unsupported containment: {error}"
            );
        }
    }
}
