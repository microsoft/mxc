// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::assert_v07_introduces;

#[test]
fn schema_is_available_starting_in_v07() {
    assert_v07_introduces(
        r#""$schema": "https://github.com/microsoft/mxc/blob/main/schemas/stable/mxc-config.schema.0.7.0-alpha.json""#,
    );
}

#[test]
fn comment_is_available_starting_in_v07() {
    assert_v07_introduces(r#""_comment": "This is a comment""#);
}
