// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_config_contract::dev::{
    parse_request, DeprovisionRequest, ExecRequest, IsolationSessionProvisionRequest, Request,
    StartRequest, StopRequest, WindowsSandboxProvisionRequest, WslcProvisionRequest,
};

const VERSION: &str = "v0_10_0_alpha";

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
    assert_root_fixtures::<WindowsSandboxProvisionRequest>("windows_sandbox_provision");
    assert_root_fixtures::<IsolationSessionProvisionRequest>("isolation_session_provision");
    assert_root_fixtures::<WslcProvisionRequest>("wslc_provision");
    assert_root_fixtures::<StartRequest>("start");
    assert_root_fixtures::<ExecRequest>("exec");
    assert_root_fixtures::<StopRequest>("stop");
    assert_root_fixtures::<DeprovisionRequest>("deprovision");
}
