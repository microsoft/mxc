// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::common::{adapt, assert_clean_common};
use crate::state_aware_operation::{StateAwareOperation, StateAwareProvision};
use crate::wire;

fn source(fields: &str) -> String {
    format!(
        r#"{{"version":"0.9.0-alpha","phase":"provision","containment":"isolation_session","network":{{"egress":{{"default":"allow"}},"ingress":{{"default":"allow","hostLoopback":"allow"}}}}{fields}}}"#
    )
}

#[test]
fn isolation_session_configuration_presence_matches_explicit_values() {
    for (fields, expected) in [
        ("", None),
        (r#","isolationSession":{}"#, None),
        (r#","isolationSession":{"provision":{}}"#, Some(None)),
        (
            r#","isolationSession":{"provision":{"appId":""}}"#,
            Some(Some("")),
        ),
        (
            r#","isolationSession":{"provision":{"appId":"example"}}"#,
            Some(Some("example")),
        ),
    ] {
        let json = source(fields);
        let (common, operation) = adapt(&json);
        assert_clean_common(&common);
        assert!(common.filesystem.is_none());
        assert!(common.process.is_none());
        let network = common.network.unwrap();
        assert!(matches!(
            network.egress.as_ref().unwrap().default,
            Some(wire::NetworkAction::Allow)
        ));
        assert!(matches!(
            network.ingress.as_ref().unwrap().default,
            Some(wire::NetworkAction::Allow)
        ));
        assert!(matches!(
            network.ingress.as_ref().unwrap().host_loopback,
            Some(wire::NetworkAction::Allow)
        ));
        let StateAwareOperation::Provision(StateAwareProvision::IsolationSession(config)) =
            operation
        else {
            panic!("wrong operation");
        };
        assert_eq!(
            config.as_ref().map(|config| config.app_id.as_deref()),
            expected
        );
    }
}

#[test]
fn isolation_session_common_fields_are_preserved() {
    let json = source(
        r#","$schema":"https://example.com/schema","_comment":"comment","telemetry":{"enabled":false}"#,
    );
    let (common, operation) = adapt(&json);

    assert_clean_common(&common);
    assert_eq!(common.schema.as_deref(), Some("https://example.com/schema"));
    assert_eq!(common.comment, Some(serde_json::json!("comment")));
    assert_eq!(common.telemetry.unwrap().enabled, Some(false));
    assert!(matches!(
        operation,
        StateAwareOperation::Provision(StateAwareProvision::IsolationSession(None))
    ));
}
