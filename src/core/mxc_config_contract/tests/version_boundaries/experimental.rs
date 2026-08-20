// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::assert_v08_introduces;

#[test]
fn experimental_test_is_introduced_in_v08() {
    assert_v08_introduces(r#""experimental": {"test": {}}"#);
}

#[test]
fn telemetry_is_introduced_in_v08() {
    assert_v08_introduces(r#""telemetry": {}"#);
}

#[test]
fn experimental_windows_sandbox_is_introduced_in_v08() {
    assert_v08_introduces(r#""experimental": {"windows_sandbox": {}}"#);
}

#[test]
fn experimental_wslc_is_introduced_in_v08() {
    assert_v08_introduces(r#""experimental": {"wslc": {}}"#);
}
