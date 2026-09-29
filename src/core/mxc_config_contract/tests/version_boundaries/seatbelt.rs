// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::{assert_v07_introduces, assert_v10_introduces};

#[test]
fn seatbelt_path_exclusions_are_introduced_in_v010() {
    assert_v10_introduces(r#""seatbelt": {"deniedPathNames": [".ssh"]}"#);
    assert_v10_introduces(r#""seatbelt": {"deniedUnixSocketPaths": ["/work"]}"#);
}

#[test]
fn seatbelt_section_is_introduced_in_v07() {
    assert_v07_introduces(r#""seatbelt": {}"#);
}

#[test]
fn seatbelt_containment_value_is_introduced_in_v07() {
    assert_v07_introduces(r#""containment": "seatbelt", "seatbelt": {}"#);
}

#[test]
fn macos_sandbox_section_alias_is_introduced_in_v07() {
    assert_v07_introduces(r#""macos_sandbox": {}"#);
}

#[test]
fn macos_sandbox_containment_value_alias_is_introduced_in_v07() {
    assert_v07_introduces(r#""containment": "macos_sandbox", "macos_sandbox": {}"#);
}
