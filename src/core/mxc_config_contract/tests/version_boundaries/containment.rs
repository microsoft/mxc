// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::{assert_v09_introduces, assert_v11_introduces};

#[test]
fn isolation_session_containment_is_introduced_in_v09() {
    assert_v09_introduces(r#""containment": "isolation_session""#);
}

#[test]
fn wslc_containment_is_introduced_in_v09() {
    assert_v09_introduces(r#""containment": "wslc""#);
}

#[test]
fn development_containment_values_are_introduced_in_v11() {
    for containment in ["vm", "windows_sandbox", "microvm", "hyperlight"] {
        assert_v11_introduces(&format!(r#""containment": "{containment}""#));
    }
}
