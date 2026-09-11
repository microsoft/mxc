// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::common::{adapt, assert_clean_common, assert_common_matches_legacy};
use crate::state_aware_operation::StateAwareOperation;
use crate::wire;

#[test]
fn exec_preserves_process_network_telemetry_and_empty_values() {
    for id in [
        "",
        "sandbox-id",
        "iso:example",
        "wsb:example",
        "wslc:example",
    ] {
        for extra in [
            "",
            r#","experimental":{}"#,
            r#","telemetry":{}"#,
            r#","network":{}"#,
            r#","_comment":null"#,
            r#","$schema":"https://example.com/schema","_comment":"comment","telemetry":{"enabled":false},"network":{"egress":{"default":"deny"},"ingress":{"default":"deny"}},"runtimeConfig":{"networkProxy":"http://127.0.0.1:8080"}"#,
        ] {
            let source = format!(
                r#"{{"version":"0.9.0-alpha","phase":"exec","sandboxId":"{id}","process":{{"commandLine":"echo hello","cwd":"/work","env":["FIRST=one","SECOND=two"],"timeout":60}}{extra}}}"#
            );
            let (common, operation) = adapt(&source);
            assert_eq!(
                operation,
                StateAwareOperation::Exec {
                    sandbox_id: id.to_owned()
                }
            );
            assert_clean_common(&common);
            assert_common_matches_legacy(&source, &common);
            let process = common.process.unwrap();
            assert_eq!(process.command_line.as_deref(), Some("echo hello"));
            assert_eq!(process.cwd.as_deref(), Some("/work"));
            assert_eq!(process.env.unwrap(), ["FIRST=one", "SECOND=two"]);
            assert_eq!(process.timeout, Some(60));
            if extra.contains("networkProxy") {
                let network = common.network.unwrap();
                assert!(matches!(
                    network.egress.unwrap().default,
                    Some(wire::NetworkAction::Deny)
                ));
                assert!(matches!(
                    network.ingress.unwrap().default,
                    Some(wire::NetworkAction::Deny)
                ));
                assert!(network.allow_local_network.is_none());
                assert!(network.allowed_hosts.is_none());
                assert!(network.blocked_hosts.is_none());
                assert_eq!(
                    common.runtime_config.unwrap().network_proxy.as_deref(),
                    Some("http://127.0.0.1:8080")
                );
                assert_eq!(common.telemetry.unwrap().enabled, Some(false));
            }
        }
    }
}

#[test]
fn minimal_exec_keeps_omitted_process_fields_absent() {
    let (common, operation) = adapt(
        r#"{"version":"0.9.0-alpha","phase":"exec","sandboxId":"id","process":{"commandLine":"echo"}}"#,
    );
    assert!(matches!(operation, StateAwareOperation::Exec { .. }));
    let process = common.process.unwrap();
    assert_eq!(process.command_line.as_deref(), Some("echo"));
    assert!(process.cwd.is_none());
    assert!(process.env.is_none());
    assert!(process.timeout.is_none());
    assert!(common.network.is_none());
    assert!(common.telemetry.is_none());
}
