// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_sdk::mxc_contract::{
    dev::OneShotRequest as V11Request,
    published::{v0_9_0_alpha::OneShotRequest as V09Request, v1_0_0::OneShotRequest as V10Request},
};

fn assert_v09_valid(json: &str) {
    serde_json::from_str::<V09Request>(json).unwrap();
}

fn assert_v11_valid(json: &str) {
    serde_json::from_str::<V11Request>(json).unwrap();
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

pub(crate) fn assert_v09_introduces(additional_fields: &str) {
    let v09_json = one_shot_request("0.9.0-alpha", additional_fields);
    assert_well_formed(&v09_json, "0.9 boundary input");
    assert_v09_valid(&v09_json);
}

pub(crate) fn assert_v11_introduces(additional_fields: &str) {
    let v09_json = one_shot_request("0.9.0-alpha", additional_fields);
    let v10_json = one_shot_request("1.0.0", additional_fields);
    let v11_json = one_shot_request("1.1.0-alpha", additional_fields);
    assert_well_formed(&v09_json, "0.9 boundary input");
    assert_well_formed(&v10_json, "1.0 boundary input");
    assert_well_formed(&v11_json, "1.1 boundary input");
    assert!(serde_json::from_str::<V09Request>(&v09_json).is_err());
    assert!(serde_json::from_str::<V10Request>(&v10_json).is_err());
    assert_v11_valid(&v11_json);
}
