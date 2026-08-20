// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::assert_v09_introduces;

#[test]
fn experimental_test_is_introduced_in_v09() {
    assert_v09_introduces(r#""experimental": {"test": {}}"#);
}

#[test]
fn experimental_telemetry_is_introduced_in_v09() {
    assert_v09_introduces(r#""experimental": {"telemetry": {}}"#);
}

#[test]
fn experimental_windows_sandbox_is_introduced_in_v09() {
    assert_v09_introduces(r#""experimental": {"windows_sandbox": {}}"#);
}

#[test]
fn experimental_wslc_is_introduced_in_v09() {
    assert_v09_introduces(r#""experimental": {"wslc": {}}"#);
}
