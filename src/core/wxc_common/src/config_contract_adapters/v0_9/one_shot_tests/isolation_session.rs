// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::common::adapt;

#[test]
fn isolation_session_containment_maps_to_runtime_wire_value() {
    let wire = adapt(
        r#"{
            "version":"0.9.0-alpha",
            "containment":"isolation_session",
            "process":{"commandLine":"echo hello"},
            "network":{
                "egress":{"default":"allow"},
                "ingress":{"default":"allow","hostLoopback":"allow"}
            }
        }"#,
    );

    assert!(matches!(
        wire.containment,
        Some(super::wire::Containment::IsolationSession)
    ));
    assert!(wire.test_feature.is_none());
    assert!(wire.windows_sandbox.is_none());
}
