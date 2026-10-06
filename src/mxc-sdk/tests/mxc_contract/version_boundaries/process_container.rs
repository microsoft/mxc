// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::assert_v09_introduces;

#[test]
fn learning_mode_is_introduced_in_v09() {
    assert_v09_introduces(r#""processContainer": {"learningMode": true}"#);
}

#[test]
fn capture_denials_is_introduced_in_v09() {
    assert_v09_introduces(r#""processContainer": {"captureDenials": {}}"#);
}
