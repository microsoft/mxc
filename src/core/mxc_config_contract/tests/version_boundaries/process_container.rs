// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::assert_v08_introduces;

#[test]
fn learning_mode_is_introduced_in_v08() {
    assert_v08_introduces(r#""processContainer": {"learningMode": true}"#);
}

#[test]
fn capture_denials_is_introduced_in_v08() {
    assert_v08_introduces(r#""processContainer": {"captureDenials": {}}"#);
}
