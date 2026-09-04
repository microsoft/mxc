// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_config_contract::dev::OneShotRequest as V09Request;
use mxc_config_contract::published::v0_6_0_alpha::Request as V06Request;
use mxc_config_contract::published::v0_7_0_alpha::Request as V07Request;
use mxc_config_contract::published::v0_8_0_alpha::Request as V08Request;

fn assert_v07_valid(json: &str) {
    serde_json::from_str::<V07Request>(json).unwrap();
}

fn assert_v08_valid(json: &str) {
    serde_json::from_str::<V08Request>(json).unwrap();
}

fn assert_v09_valid(json: &str) {
    serde_json::from_str::<V09Request>(json).unwrap();
}

fn one_shot_request(version: &str, additional_fields: &str) -> String {
    format!(
        r#"{{
            "version": "{version}",
            "process": {{"commandLine": "echo"}},
            {additional_fields}
        }}"#
    )
}

fn assert_well_formed(json: &str, context: &str) {
    serde_json::from_str::<serde_json::Value>(json)
        .unwrap_or_else(|error| panic!("{context} used malformed JSON: {error}"));
}

pub(crate) fn assert_v06_rejects_v07_accepts(v06_json: &str, v07_json: &str) {
    assert_well_formed(v06_json, "0.6 boundary input");
    assert_well_formed(v07_json, "0.7 boundary input");
    assert!(serde_json::from_str::<V06Request>(v06_json).is_err());
    assert_v07_valid(v07_json);
}

fn assert_v07_rejects_v08_accepts(v07_json: &str, v08_json: &str) {
    assert_well_formed(v07_json, "0.7 boundary input");
    assert_well_formed(v08_json, "0.8 boundary input");
    assert!(serde_json::from_str::<V07Request>(v07_json).is_err());
    assert_v08_valid(v08_json);
}

fn assert_v08_rejects_v09_accepts(v08_json: &str, v09_json: &str) {
    assert_well_formed(v08_json, "0.8 boundary input");
    assert_well_formed(v09_json, "0.9 boundary input");
    assert!(serde_json::from_str::<V08Request>(v08_json).is_err());
    assert_v09_valid(v09_json);
}

pub(crate) fn assert_v07_introduces(additional_fields: &str) {
    let v06_json = one_shot_request("0.6.0-alpha", additional_fields);
    let v07_json = one_shot_request("0.7.0-alpha", additional_fields);
    assert_v06_rejects_v07_accepts(&v06_json, &v07_json);
}

pub(crate) fn assert_v08_introduces(additional_fields: &str) {
    let v06_json = one_shot_request("0.6.0-alpha", additional_fields);
    let v07_json = one_shot_request("0.7.0-alpha", additional_fields);
    let v08_json = one_shot_request("0.8.0-alpha", additional_fields);
    assert_well_formed(&v06_json, "0.6 boundary input");
    assert!(serde_json::from_str::<V06Request>(&v06_json).is_err());
    assert_v07_rejects_v08_accepts(&v07_json, &v08_json);
}

pub(crate) fn assert_v09_introduces(additional_fields: &str) {
    let v08_json = one_shot_request("0.8.0-alpha", additional_fields);
    let v09_json = one_shot_request("0.9.0-alpha", additional_fields);
    assert_v08_rejects_v09_accepts(&v08_json, &v09_json);
}
