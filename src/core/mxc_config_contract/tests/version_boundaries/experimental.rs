// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::{assert_v09_introduces, assert_v10_introduces};

#[test]
fn telemetry_is_introduced_in_v09() {
    assert_v09_introduces(r#""telemetry": {"enabled": true}"#);
}

#[test]
fn test_feature_is_introduced_in_v010() {
    assert_v10_introduces(r#""test": {"message": "version boundary test"}"#);
}

#[test]
fn windows_sandbox_config_is_introduced_in_v010() {
    assert_v10_introduces(
        r#""windowsSandbox": {
            "idleTimeoutMs": 60000, "daemonPipeName": "mxc-boundary-test"
        }"#,
    );
}

#[test]
fn wslc_config_is_introduced_in_v09() {
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
