// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Private input for a backend that is not implemented yet.

use crate::mxc_contract::dev as contract;

#[derive(Debug)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Contract-only normalization input; runtime binding is a later slice"
    )
)]
pub(crate) struct Provision {
    pub pool_id: String,
    pub user_type: Option<String>,
    pub user_object_id: Option<String>,
}

impl From<contract::W365AgentsProvision> for Provision {
    fn from(value: contract::W365AgentsProvision) -> Self {
        Self {
            pool_id: value.pool_id.into_inner(),
            user_type: value.user_type.into_option().map(|value| match value {
                contract::W365AgentsUserType::Local => "Local".to_owned(),
                contract::W365AgentsUserType::HumanUser => "HumanUser".to_owned(),
                contract::W365AgentsUserType::Agentic => "Agentic".to_owned(),
            }),
            user_object_id: value
                .user_object_id
                .into_option()
                .map(contract::W365AgentsGuid::into_inner),
        }
    }
}

#[derive(Debug)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Contract-only normalization input; runtime binding is a later slice"
    )
)]
pub(crate) enum Input {
    /// The outer option is wrapper presence; the inner option is provision presence.
    Provision(Option<Option<Provision>>),
}

impl Input {
    pub(crate) fn unavailable(self) -> crate::mxc_common::error::WxcError {
        // Runtime registration and checked binding are a later implementation slice.
        drop(self);
        crate::mxc_common::mxc_error::MxcError::backend_unavailable(
            "w365_agents has a development request contract but its backend is not implemented",
        )
        .into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_common::common_request_ir::CommonRequestIR;
    use crate::mxc_common::config_contract_adapters::dev::{adapt_request, AdaptedConfigRequest};
    use crate::mxc_common::state_aware_input::StateAwareInput;
    use serde_json::json;

    fn adapt(source: &str) -> (CommonRequestIR, Input) {
        let AdaptedConfigRequest::StateAware(StateAwareInput::W365Agents { common, operation }) =
            adapt_request(contract::parse_request(source).unwrap()).unwrap()
        else {
            panic!("expected private W365 normalization input");
        };
        (common, operation)
    }

    macro_rules! fixture {
        ($root:literal) => {
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/mxc_contract/v1_1_0_alpha/fixtures/",
                $root
            ))
        };
    }

    #[test]
    fn w365_agents_adapters_preserve_provision_settings_and_later_phase_inputs() {
        let (common, provision) = adapt(fixture!("w365_agents_provision/valid/complete.json"));
        assert_eq!(common.telemetry.unwrap().enabled, Some(false));
        let Input::Provision(Some(Some(config))) = provision else {
            panic!("provision")
        };
        assert_eq!(config.pool_id, "AAAAAAAA-bbbb-CCCC-dddd-EEEEEEEEEEEE");
        assert_eq!(config.user_type.as_deref(), Some("HumanUser"));
        assert_eq!(
            config.user_object_id.as_deref(),
            Some("22222222-2222-2222-2222-222222222222")
        );

        for source in [
            fixture!("start/valid/w365-agents.json"),
            fixture!("exec/valid/w365-agents.json"),
            fixture!("stop/valid/w365-agents.json"),
            fixture!("deprovision/valid/w365-agents.json"),
        ] {
            let AdaptedConfigRequest::StateAware(input) =
                adapt_request(contract::parse_request(source).unwrap()).unwrap()
            else {
                panic!("expected lifecycle request");
            };
            let (common, operation) = input.into_parts().unwrap();
            if matches!(
                operation,
                crate::mxc_common::state_aware_operation::StateAwareOperation::Exec { .. }
            ) {
                let process = common.process.unwrap();
                assert_eq!(
                    process.command_line.as_deref(),
                    Some("cmd.exe /c echo fixture")
                );
                assert_eq!(process.cwd.as_deref(), Some("C:\\work"));
                assert_eq!(process.env, Some(vec![]));
                assert_eq!(process.inherit_default_env, Some(true));
                assert_eq!(process.timeout, Some(u32::MAX));
            }
            assert_eq!(
                operation.sandbox_id(),
                Some("w365:11111111-1111-1111-1111-111111111111:22222222-2222-2222-2222-222222222222")
            );
        }
    }

    #[test]
    fn w365_agents_provision_omission_and_empty_wrapper_stay_distinct() {
        for presence in 0..3 {
            let mut value = json!({
                "version":"1.1.0-alpha",
                "phase":"provision",
                "containment":"w365_agents"
            });
            if presence > 0 {
                value["w365Agents"] = json!({});
            }
            if presence == 2 {
                value["w365Agents"]["provision"] =
                    json!({"poolId":"11111111-1111-1111-1111-111111111111"});
            }
            let (common, input) = adapt(&value.to_string());
            assert!(common.containment.is_none());
            assert!(common.sandbox_id.is_none());
            assert!(common.phase.is_none());
            let Input::Provision(settings) = input;
            if let Some(Some(ref config)) = settings {
                assert!(config.user_type.is_none());
                assert!(config.user_object_id.is_none());
            }
            assert_eq!(
                settings.map(|inner| inner.is_some()),
                match presence {
                    0 => None,
                    1 => Some(false),
                    _ => Some(true),
                }
            );
        }
    }

    #[test]
    fn w365_agents_additional_user_types_are_preserved() {
        for (source, expected) in [
            (
                fixture!("w365_agents_provision/valid/local-user.json"),
                "Local",
            ),
            (
                fixture!("w365_agents_provision/valid/agentic-user.json"),
                "Agentic",
            ),
        ] {
            let (_, input) = adapt(source);
            let Input::Provision(Some(Some(config))) = input else {
                panic!("expected provision settings");
            };
            assert_eq!(config.user_type.as_deref(), Some(expected));
            assert!(config.user_object_id.is_none());
        }
    }
}
