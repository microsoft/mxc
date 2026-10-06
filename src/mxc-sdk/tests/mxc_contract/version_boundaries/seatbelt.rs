// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::assert_v09_introduces;

#[test]
fn seatbelt_section_is_introduced_in_v09() {
    assert_v09_introduces(r#""seatbelt": {}"#);
}

#[test]
fn seatbelt_containment_value_is_introduced_in_v09() {
    assert_v09_introduces(r#""containment": "seatbelt", "seatbelt": {}"#);
}

#[test]
fn macos_sandbox_section_alias_is_introduced_in_v09() {
    assert_v09_introduces(r#""macos_sandbox": {}"#);
}

#[test]
fn macos_sandbox_containment_value_alias_is_introduced_in_v09() {
    assert_v09_introduces(r#""containment": "macos_sandbox", "macos_sandbox": {}"#);
}
