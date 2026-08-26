// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod common;
mod one_shot;
mod state_aware;

use crate::state_aware_wire::StateAwareWireInput;
use crate::wire;

use mxc_config_contract::dev as contract;

pub(crate) enum AdaptedWireRequest {
    OneShot(wire::MxcConfig),
    StateAware(StateAwareWireInput),
}

fn adapt_state_aware_wire(
    config: wire::MxcConfig,
    source_text: &str,
) -> Result<AdaptedWireRequest, serde_json::Error> {
    state_aware::into_state_aware_wire_input(config, source_text)
        .map(AdaptedWireRequest::StateAware)
}

pub(crate) fn adapt_request(
    request: contract::Request,
    source_text: &str,
) -> Result<AdaptedWireRequest, serde_json::Error> {
    match request {
        contract::Request::OneShot(request) => {
            Ok(AdaptedWireRequest::OneShot(one_shot::into_wire(*request)))
        }
        contract::Request::Provision(request) => {
            adapt_state_aware_wire(state_aware::provision_into_wire(request), source_text)
        }
        contract::Request::Start(request) => {
            adapt_state_aware_wire(state_aware::start_into_wire(request), source_text)
        }
        contract::Request::Exec(request) => {
            adapt_state_aware_wire(state_aware::exec_into_wire(request), source_text)
        }
        contract::Request::Stop(request) => {
            adapt_state_aware_wire(state_aware::stop_into_wire(request), source_text)
        }
        contract::Request::Deprovision(request) => {
            adapt_state_aware_wire(state_aware::deprovision_into_wire(request), source_text)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapt_json(json: &str) -> AdaptedWireRequest {
        let request = contract::parse_request(json).unwrap();
        adapt_request(request, json).unwrap()
    }

    #[test]
    fn one_shot_request_adapts_to_one_shot() {
        let json = r#"{
            "version": "0.9.0-alpha",
            "process": {
                "commandLine": "echo hello"
            }
        }"#;

        let AdaptedWireRequest::OneShot(adapted) = adapt_json(json) else {
            panic!("expected one-shot request");
        };

        assert_eq!(adapted.version, Some("0.9.0-alpha".to_string()));
        assert!(adapted.process.is_some());

        let process = adapted.process.unwrap();
        assert_eq!(process.command_line, Some("echo hello".to_string()));
        assert!(process.cwd.is_none());
        assert!(process.env.is_none());
        assert!(process.timeout.is_none());
    }

    #[test]
    fn provision_request_adapts_to_state_aware() {
        let json = r#"{
            "version": "0.9.0-alpha",
            "phase": "provision",
            "containment": "windows_sandbox",
            "experimental": {
                "telemetry": {
                    "enabled": false
                }
            }
        }"#;

        let AdaptedWireRequest::StateAware(adapted) = adapt_json(json) else {
            panic!("expected state-aware request");
        };

        assert_eq!(adapted.config.version, Some("0.9.0-alpha".to_string()));
        assert!(matches!(adapted.config.phase, Some(wire::Phase::Provision)));
        assert_eq!(
            adapted.experimental_raw,
            Some(serde_json::json!({
                "telemetry": {"enabled": false}
            }))
        );
        assert_eq!(adapted.source_text.as_ref(), json);
    }

    #[test]
    fn start_request_adapts_to_state_aware() {
        let json = r#"{
            "version": "0.9.0-alpha",
            "phase": "start",
            "sandboxId": "sandbox-id",
            "experimental": {
                "telemetry": {
                    "enabled": false
                }
            }
        }"#;

        let AdaptedWireRequest::StateAware(adapted) = adapt_json(json) else {
            panic!("expected state-aware request");
        };

        assert_eq!(adapted.config.version, Some("0.9.0-alpha".to_string()));
        assert!(matches!(adapted.config.phase, Some(wire::Phase::Start)));
        assert_eq!(adapted.config.sandbox_id, Some("sandbox-id".to_string()));
        assert_eq!(
            adapted.experimental_raw,
            Some(serde_json::json!({
                "telemetry": {"enabled": false}
            }))
        );
        assert_eq!(adapted.source_text.as_ref(), json);
    }

    #[test]
    fn exec_request_adapts_to_state_aware() {
        let json = r#"{
            "version": "0.9.0-alpha",
            "phase": "exec",
            "sandboxId": "sandbox-id",
            "process": {
                "commandLine": "echo hello"
            },
            "experimental": {
                "telemetry": {
                    "enabled": false
                }
            }
        }"#;

        let AdaptedWireRequest::StateAware(adapted) = adapt_json(json) else {
            panic!("expected state-aware request");
        };

        assert_eq!(adapted.config.version, Some("0.9.0-alpha".to_string()));
        assert!(matches!(adapted.config.phase, Some(wire::Phase::Exec)));
        assert_eq!(adapted.config.sandbox_id, Some("sandbox-id".to_string()));
        assert!(adapted.config.process.is_some());

        let process = adapted.config.process.unwrap();
        assert_eq!(process.command_line, Some("echo hello".to_string()));
        assert!(process.cwd.is_none());
        assert!(process.env.is_none());
        assert!(process.timeout.is_none());

        assert_eq!(
            adapted.experimental_raw,
            Some(serde_json::json!({
                "telemetry": {"enabled": false}
            }))
        );
        assert_eq!(adapted.source_text.as_ref(), json);
    }

    #[test]
    fn stop_request_adapts_to_state_aware() {
        let json = r#"{
            "version": "0.9.0-alpha",
            "phase": "stop",
            "sandboxId": "sandbox-id",
            "experimental": {
                "telemetry": {
                    "enabled": false
                }
            }
        }"#;

        let AdaptedWireRequest::StateAware(adapted) = adapt_json(json) else {
            panic!("expected state-aware request");
        };

        assert_eq!(adapted.config.version, Some("0.9.0-alpha".to_string()));
        assert!(matches!(adapted.config.phase, Some(wire::Phase::Stop)));
        assert_eq!(adapted.config.sandbox_id, Some("sandbox-id".to_string()));
        assert_eq!(
            adapted.experimental_raw,
            Some(serde_json::json!({
                "telemetry": {"enabled": false}
            }))
        );
        assert_eq!(adapted.source_text.as_ref(), json);
    }

    #[test]
    fn deprovision_request_adapts_to_state_aware() {
        let json = r#"{
            "version": "0.9.0-alpha",
            "phase": "deprovision",
            "sandboxId": "sandbox-id",
            "experimental": {
                "telemetry": {
                    "enabled": false
                }
            }
        }"#;

        let AdaptedWireRequest::StateAware(adapted) = adapt_json(json) else {
            panic!("expected state-aware request");
        };

        assert_eq!(adapted.config.version, Some("0.9.0-alpha".to_string()));
        assert!(matches!(
            adapted.config.phase,
            Some(wire::Phase::Deprovision)
        ));
        assert_eq!(adapted.config.sandbox_id, Some("sandbox-id".to_string()));
        assert_eq!(
            adapted.experimental_raw,
            Some(serde_json::json!({
                "telemetry": {"enabled": false}
            }))
        );
        assert_eq!(adapted.source_text.as_ref(), json);
    }
}
