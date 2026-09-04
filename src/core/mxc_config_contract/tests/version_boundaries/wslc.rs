// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::assert_v09_introduces;

#[test]
fn wslc_section_is_introduced_in_v09() {
    assert_v09_introduces(
        r#""wslc": {
            "targetOs": "linux",
            "image": "ubuntu",
            "cpuCount": 2,
            "memoryMb": 4096,
            "gpu": false,
            "storagePath": "C:\\mxc",
            "portMappings": [
                {"windowsPort": 8080, "containerPort": 80, "protocol": "tcp"}
            ]
        }"#,
    );
}

#[test]
fn wslc_containment_value_is_introduced_in_v09() {
    assert_v09_introduces(r#""containment": "wslc", "wslc": {}"#);
}
