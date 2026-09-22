// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::config_contract_adapters::v0_9::{adapt_request, AdaptedConfigRequest};
use crate::state_aware_input::StateAwareInput;
use crate::state_aware_operation::StateAwareOperation;
use crate::wire;
use mxc_config_contract::published::v0_9_0_alpha as contract;

pub(super) fn adapt(
    source: &str,
) -> (
    crate::common_request_ir::CommonRequestIR,
    StateAwareOperation,
) {
    let AdaptedConfigRequest::StateAware(input) =
        adapt_request(contract::parse_request(source).unwrap()).unwrap()
    else {
        panic!("expected state-aware request");
    };
    input.into_parts()
}
pub(super) fn assert_clean_common(common: &crate::common_request_ir::CommonRequestIR) {
    assert!(common.phase.is_none());
    assert!(common.sandbox_id.is_none());
    assert!(common.containment.is_none());
    assert!(common.test_feature.is_none());
    assert!(common.windows_sandbox.is_none());
    assert!(common.container_id.is_none());
    assert!(common.lifecycle.is_none());
    assert!(common.process_container.is_none());
    assert!(common.lxc.is_none());
    assert!(common.wslc.is_none());
    assert!(common.seatbelt.is_none());
    assert!(common.fallback.is_none());
    assert!(common.ui.is_none());
}

#[test]
fn controlled_input_rejects_every_routing_and_one_shot_field() {
    for field in [
        "phase",
        "sandboxId",
        "containment",
        "test",
        "windowsSandbox",
        "containerId",
        "fallback",
        "seatbelt",
        "processContainer",
        "lxc",
        "wslc",
        "lifecycle",
    ] {
        let (mut common, _) =
            adapt(r#"{"version":"0.9.0-alpha","phase":"start","sandboxId":"iso:example"}"#);
        match field {
            "phase" => common.phase = Some(wire::Phase::Start),
            "sandboxId" => common.sandbox_id = Some(String::new()),
            "containment" => common.containment = Some(wire::Containment::Wslc),
            "test" => common.test_feature = Some(wire::TestFeature::default()),
            "windowsSandbox" => common.windows_sandbox = Some(wire::WindowsSandbox::default()),
            "containerId" => common.container_id = Some("container".to_string()),
            "fallback" => common.fallback = Some(wire::Fallback::default()),
            "seatbelt" => common.seatbelt = Some(wire::Seatbelt::default()),
            "processContainer" => {
                common.process_container = Some(wire::ProcessContainer::default())
            }
            "lxc" => common.lxc = Some(wire::Lxc::default()),
            "wslc" => common.wslc = Some(wire::Wslc::default()),
            "lifecycle" => common.lifecycle = Some(wire::Lifecycle::default()),
            _ => unreachable!(),
        }
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
            assert_eq!(
                common.source_contract,
                mxc_config_contract::ContractVersion::V0_9_0Alpha
            );
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
