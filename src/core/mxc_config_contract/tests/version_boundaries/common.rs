// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_config_contract::published::v0_6_0_alpha::Request as V06Request;
use mxc_config_contract::published::v0_7_0_alpha::Request as V07Request;

pub(crate) fn assert_v06_rejects_v07_accepts(v06_json: &str, v07_json: &str) {
    assert!(serde_json::from_str::<V06Request>(v06_json).is_err());
    assert_valid(v07_json);
}

pub(crate) fn assert_valid(json: &str) {
    serde_json::from_str::<V07Request>(json).unwrap();
}
