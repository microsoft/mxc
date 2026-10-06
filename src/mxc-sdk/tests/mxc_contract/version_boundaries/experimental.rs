// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::{assert_v09_introduces, assert_v11_introduces};

#[test]
fn telemetry_is_introduced_in_v09() {
    assert_v09_introduces(r#""telemetry": {"enabled": true}"#);
}

#[test]
fn test_feature_is_introduced_in_v11() {
    assert_v11_introduces(r#""test": {"message": "version boundary test"}"#);
}

#[test]
fn windows_sandbox_config_is_introduced_in_v11() {
    assert_v11_introduces(
        r#""windowsSandbox": {
            "idleTimeoutMs": 60000, "daemonPipeName": "mxc-boundary-test"
        }"#,
    );
}

#[test]
fn hyperlight_config_is_introduced_in_v11() {
    assert_v11_introduces(r#""hyperlight": {"runtime": "node"}"#);
}
