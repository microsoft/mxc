// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::config_contract_adapters::dev::{adapt_request, AdaptedWireRequest};
use crate::config_parser::parse_rolling_state_aware_wire_input;
use crate::state_aware_operation::StateAwareOperation;
use crate::state_aware_wire::StateAwareInput;
use crate::wire;
use mxc_config_contract::dev as contract;
use serde_json::value::RawValue;

pub(super) fn adapt(source: &str) -> (wire::MxcConfig, StateAwareOperation) {
    let AdaptedWireRequest::StateAware(input) =
        adapt_request(contract::parse_request(source).unwrap()).unwrap()
    else {
        panic!("expected state-aware request");
    };
    input.into_parts()
}

pub(super) fn assert_common_matches_legacy(source: &str, common: &wire::MxcConfig) {
    #[derive(serde::Deserialize)]
    struct Probe<'a> {
        #[serde(borrow, default)]
        experimental: Option<&'a RawValue>,
    }
    let probe: Probe<'_> = serde_json::from_str(source).unwrap();
    let mut legacy = parse_rolling_state_aware_wire_input(source, probe.experimental)
        .unwrap()
        .config;
    // Routing and payload observations are asserted separately, not serialized.
    legacy.phase = None;
    legacy.containment = None;
    legacy.sandbox_id = None;
    assert_eq!(
        serde_json::to_value(common).unwrap(),
        serde_json::to_value(legacy).unwrap()
    );
}

pub(super) fn assert_clean_common(common: &wire::MxcConfig) {
    assert!(common.phase.is_none());
    assert!(common.sandbox_id.is_none());
    assert!(common.containment.is_none());
    assert!(common.experimental.is_none());
    assert!(common.container_id.is_none());
    assert!(common.lifecycle.is_none());
    assert!(common.process_container.is_none());
    assert!(common.lxc.is_none());
    assert!(common.seatbelt.is_none());
    assert!(common.fallback.is_none());
    assert!(common.ui.is_none());
}

#[test]
fn controlled_input_rejects_every_routing_and_one_shot_field() {
    for field in [
        r#""phase":"start""#,
        r#""sandboxId":"""#,
        r#""containment":"wslc""#,
        r#""experimental":{}"#,
        r#""containerId":"container""#,
        r#""fallback":{}"#,
        r#""seatbelt":{}"#,
        r#""processContainer":{}"#,
        r#""lxc":{}"#,
        r#""lifecycle":{}"#,
    ] {
        let common = serde_json::from_str(&format!("{{{field}}}")).unwrap();
        assert!(
            StateAwareInput::new(
                common,
                StateAwareOperation::Start {
                    sandbox_id: "iso:example".to_owned(),
                }
            )
            .is_err(),
            "{field}"
        );
    }
}

pub(super) fn assert_no_config_phase(phase: &str) {
    for id in [
        "",
        "unvalidated-id",
        "iso:example",
        "wsb:example",
        "wslc:example",
    ] {
        for fields in [
            "",
            r#","experimental":{}"#,
            r#","telemetry":{}"#,
            r#","telemetry":{"enabled":false},"_comment":null"#,
            r#","$schema":"https://example.com/schema","_comment":"comment","telemetry":{"enabled":true}"#,
        ] {
            let source = format!(
                r#"{{"version":"0.9.0-alpha","phase":"{phase}","sandboxId":"{id}"{fields}}}"#
            );
            let (common, operation) = adapt(&source);
            assert_eq!(operation.phase().as_str(), phase);
            assert_eq!(operation.sandbox_id(), Some(id));
            assert!(operation.containment().is_none());
            assert_clean_common(&common);
            assert!(common.process.is_none());
            assert!(common.filesystem.is_none());
            assert!(common.network.is_none());
            assert_eq!(common.version.as_deref(), Some("0.9.0-alpha"));
            assert_common_matches_legacy(&source, &common);
            if fields.contains("$schema") {
                assert_eq!(common.schema.as_deref(), Some("https://example.com/schema"));
                assert_eq!(common.comment, Some(serde_json::json!("comment")));
                assert_eq!(common.telemetry.unwrap().enabled, Some(true));
            } else if fields.contains("null") {
                assert_eq!(common.comment, Some(serde_json::Value::Null));
                assert_eq!(common.telemetry.unwrap().enabled, Some(false));
            } else if fields.contains("telemetry") {
                assert_eq!(common.telemetry.unwrap().enabled, None);
            } else {
                assert!(common.schema.is_none());
                assert!(common.comment.is_none());
                assert!(common.telemetry.is_none());
            }
        }
    }
}
