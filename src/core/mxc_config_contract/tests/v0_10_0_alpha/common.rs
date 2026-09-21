// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_config_contract::dev::OneShotRequest;

pub(crate) fn assert_valid(json: &str) {
    crate::exact_test_support::assert_valid::<OneShotRequest>(json);
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
    crate::exact_test_support::assert_invalid::<OneShotRequest>(json, context);
}
