// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

pub(crate) use crate::OneShotRequest;

pub(crate) fn assert_valid(json: &str) {
    crate::exact_test_support::assert_versioned_valid::<OneShotRequest>(
        json,
        crate::CONTRACT_VERSION,
    );
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
    let json = crate::exact_test_support::with_contract_version(json, crate::CONTRACT_VERSION);
    crate::exact_test_support::assert_invalid::<OneShotRequest>(&json, context);
}
