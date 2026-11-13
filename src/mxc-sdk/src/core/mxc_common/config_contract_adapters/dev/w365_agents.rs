// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Mechanical adaptation of W365 provision settings.

use crate::mxc_contract::dev as contract;

use crate::mxc_common::models::W365AgentsProvisionConfig as Provision;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_common::common_request_ir::CommonRequestIR;
    use crate::mxc_common::config_contract_adapters::dev::{adapt_request, AdaptedConfigRequest};
    use crate::mxc_common::state_aware_operation::{StateAwareOperation, StateAwareProvision};
    use serde_json::json;

    fn adapt(source: &str) -> (CommonRequestIR, StateAwareProvision) {
        let AdaptedConfigRequest::StateAware(input) =
            adapt_request(contract::parse_request(source).unwrap()).unwrap()
        else {
            panic!("expected private W365 normalization input");
        };
        let (common, operation) = input.into_parts();
        let StateAwareOperation::Provision(provision) = operation else {
            panic!("expected provision operation")
        };
        (common, provision)
    }

    macro_rules! fixture {
        ($root:literal) => {
            include_str!(concat!(
                env!("MXC_SDK_SOURCE_DIR"),
                "/tests/mxc_contract/v1_1_0_alpha/fixtures/",
                $root
            ))
        };
    }

    #[test]
    fn w365_agents_adapters_preserve_provision_settings_and_later_phase_inputs() {
        let (common, provision) = adapt(fixture!("w365_agents_provision/valid/complete.json"));
        assert_eq!(common.telemetry.unwrap().enabled, Some(false));
        let StateAwareProvision::W365Agents(Some(Some(config))) = provision else {
            panic!("expected W365 provision")
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
            let (common, operation) = input.into_parts();
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
            let StateAwareProvision::W365Agents(settings) = input else {
                panic!("expected W365 provision")
            };
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
            let (_, provision) = adapt(source);
            let StateAwareProvision::W365Agents(Some(Some(config))) = provision else {
                panic!("expected provision settings");
            };
            assert_eq!(config.user_type.as_deref(), Some(expected));
            assert!(config.user_object_id.is_none());
        }
    }
}
