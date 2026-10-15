// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::assert_v11_introduces;

#[test]
fn resources_are_introduced_in_v11() {
    assert_v11_introduces(
        r#""resources": {
            "cpuTimeMs": 120000, "memoryMb": 2048, "maxProcesses": 64, "priority": "low"
        }"#,
    );
}

#[test]
fn empty_resources_are_introduced_in_v11() {
    assert_v11_introduces(r#""resources": {}"#);
}
