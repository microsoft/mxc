// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::{assert_v09_introduces, assert_v10_introduces};

#[test]
fn isolation_session_containment_is_introduced_in_v09() {
    assert_v09_introduces(r#""containment": "isolation_session""#);
}

#[test]
fn wslc_containment_is_introduced_in_v09() {
    assert_v09_introduces(r#""containment": "wslc""#);
}

#[test]
fn development_containment_values_are_introduced_in_v010() {
    for containment in ["vm", "windows_sandbox", "microvm", "hyperlight"] {
        assert_v10_introduces(&format!(r#""containment": "{containment}""#));
    }
}
