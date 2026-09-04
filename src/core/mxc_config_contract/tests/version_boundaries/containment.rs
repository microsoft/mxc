// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::assert_v09_introduces;

#[test]
fn development_containment_values_are_introduced_in_v09() {
    for containment in [
        "vm",
        "windows_sandbox",
        "microvm",
        "hyperlight",
        "isolation_session",
        "wslc",
    ] {
        assert_v09_introduces(&format!(r#""containment": "{containment}""#));
    }
}
