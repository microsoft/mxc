// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::assert_invalid;

#[test]
fn rejects_state_aware_backend_sections() {
    let isolation_session = r#"{
        "version": "0.10.0-alpha",
        "process": {"commandLine": "echo"},
        "isolationSession": {"provision": {}}
    }"#;
    let wslc = r#"{
        "version": "0.10.0-alpha",
        "process": {"commandLine": "echo"},
        "wslc": {"provision": {}}
    }"#;

    assert_invalid(isolation_session);
    assert_invalid(wslc);
}
