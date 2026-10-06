// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::assert_v09_introduces;

#[test]
fn schema_is_available_starting_in_v09() {
    assert_v09_introduces(
        r#""$schema": "https://github.com/microsoft/mxc/blob/main/schemas/stable/mxc-config.schema.0.9.0-alpha.json""#,
    );
}

#[test]
fn comment_is_available_starting_in_v09() {
    assert_v09_introduces(r#""_comment": "This is a comment""#);
}
