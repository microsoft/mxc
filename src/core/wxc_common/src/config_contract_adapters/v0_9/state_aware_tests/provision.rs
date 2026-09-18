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

fn wslc_source(fields: &str) -> String {
    format!(r#"{{"version":"0.9.0-alpha","phase":"provision","containment":"wslc"{fields}}}"#)
}

#[test]
fn wslc_configuration_presence_matches_explicit_values() {
    for (fields, expected) in [
        ("", None),
        (r#","wslc":{}"#, None),
        (r#","wslc":{"provision":{}}"#, Some((None, None))),
        (
            r#","wslc":{"provision":{"image":"image"}}"#,
            Some((Some("image"), None)),
        ),
        (
            r#","wslc":{"provision":{"imageTarPath":"archive.tar"}}"#,
            Some((None, Some("archive.tar"))),
        ),
        (
            r#","wslc":{"provision":{"image":"image","imageTarPath":"archive.tar"}}"#,
            Some((Some("image"), Some("archive.tar"))),
        ),
    ] {
        let (common, operation) = adapt(&wslc_source(fields));
        assert_clean_common(&common);
        assert!(common.filesystem.is_none());
        assert!(common.network.is_none());

        let StateAwareOperation::Provision(StateAwareProvision::Wslc(config)) = operation else {
            panic!("wrong operation");
        };
        let observed = config
            .as_ref()
            .map(|config| (config.image.as_deref(), config.image_tar_path.as_deref()));
        assert_eq!(observed, expected);
    }
}

#[test]
fn wslc_common_policy_fields_are_preserved() {
    let json = wslc_source(
        r#","$schema":"https://example.com/schema","_comment":"comment",
        "filesystem":{"readonlyPaths":["/read"],"readwritePaths":["/write"],"deniedPaths":["/deny"]},
        "network":{"egress":{"default":"deny"},"ingress":{"default":"deny","hostLoopback":"deny"}},
        "telemetry":{"enabled":false}"#,
    );
    let (common, operation) = adapt(&json);

    assert_clean_common(&common);
    assert_eq!(common.schema.as_deref(), Some("https://example.com/schema"));
    assert_eq!(common.comment, Some(serde_json::json!("comment")));
    assert_eq!(common.telemetry.unwrap().enabled, Some(false));

    let filesystem = common.filesystem.unwrap();
    assert_eq!(filesystem.readonly_paths.unwrap(), ["/read"]);
    assert_eq!(filesystem.readwrite_paths.unwrap(), ["/write"]);
    assert_eq!(filesystem.denied_paths.unwrap(), ["/deny"]);

    let network = common.network.unwrap();
    assert!(matches!(
        network.egress.unwrap().default,
        Some(wire::NetworkAction::Deny)
    ));
    assert!(matches!(
        network.ingress.unwrap().default,
        Some(wire::NetworkAction::Deny)
    ));
    assert!(matches!(
        operation,
        StateAwareOperation::Provision(StateAwareProvision::Wslc(None))
    ));
}
