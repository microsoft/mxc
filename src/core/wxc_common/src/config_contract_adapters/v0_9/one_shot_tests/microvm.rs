// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::{contract, into_common_request_ir, wire};

#[test]
fn microvm_maps_to_the_public_wire_identity() {
    let request = serde_json::from_str::<contract::OneShotRequest>(
        r#"{
            "version": "0.9.0-alpha",
            "containment": "microvm",
            "process": {"commandLine": "echo hello"}
        }"#,
    )
    .unwrap();

    let adapted = into_common_request_ir(request);
    assert!(matches!(
        adapted.containment,
        Some(wire::Containment::Microvm)
    ));
}
