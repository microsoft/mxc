// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_config_contract::published::v0_8_0_alpha::Request;

pub(crate) fn assert_valid(json: &str) {
    serde_json::from_str::<Request>(json).unwrap();
}

pub(crate) fn assert_invalid(json: &str) {
    assert_invalid_with_context(json, "invalid configuration");
}

pub(crate) fn assert_invalid_cases<'a>(
    cases: impl IntoIterator<Item = (&'a str, &'a str, &'a str)>,
    failure_kind: &str,
) {
    for (name, required_fields, invalid_fields) in cases {
        let json = format!(
            r#"{{
                {required_fields},
                {invalid_fields}
            }}"#
        );

        assert_invalid_with_context(&json, &format!("{failure_kind} '{name}'"));
    }
}

fn assert_invalid_with_context(json: &str, context: &str) {
    if let Err(error) = serde_json::from_str::<serde_json::Value>(json) {
        panic!("{context} used malformed test JSON: {error}");
    }

    assert!(
        serde_json::from_str::<Request>(json).is_err(),
        "{context} was accepted"
    );
}
