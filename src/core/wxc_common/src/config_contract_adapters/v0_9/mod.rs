// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod common;
mod one_shot;
mod state_aware;

use crate::error::WxcError;
use crate::state_aware_input::StateAwareInput;
use mxc_config_contract::published::v0_9_0_alpha as contract;

pub(crate) enum AdaptedConfigRequest {
    OneShot(crate::common_request_ir::CommonRequestIR),
    StateAware(StateAwareInput),
}

pub(crate) fn adapt_request(request: contract::Request) -> Result<AdaptedConfigRequest, WxcError> {
    let input = match request {
        contract::Request::OneShot(request) => {
            return Ok(AdaptedConfigRequest::OneShot(
                one_shot::into_common_request_ir(*request),
            ));
        }
        contract::Request::Provision(request) => state_aware::provision_into_input(request),
        contract::Request::Start(request) => state_aware::start_into_input(request),
        contract::Request::Exec(request) => state_aware::exec_into_input(request),
        contract::Request::Stop(request) => state_aware::stop_into_input(request),
        contract::Request::Deprovision(request) => state_aware::deprovision_into_input(request),
    }?;
    Ok(AdaptedConfigRequest::StateAware(input))
}

pub(crate) fn one_shot_into_common_request_ir(
    request: contract::OneShotRequest,
) -> crate::common_request_ir::CommonRequestIR {
    one_shot::into_common_request_ir(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_shot_request_adapts_to_one_shot() {
        let request = contract::parse_request(
            r#"{"version":"0.9.0-alpha","process":{"commandLine":"echo hello"}}"#,
        )
        .unwrap();
        let AdaptedConfigRequest::OneShot(common) = adapt_request(request).unwrap() else {
            panic!("expected one-shot request");
        };
        assert_eq!(
            common.source_contract,
            mxc_config_contract::ContractVersion::V0_9_0Alpha
        );
        let process = common.process.unwrap();
        assert_eq!(process.command_line.as_deref(), Some("echo hello"));
        assert!(process.cwd.is_none());
        assert!(process.env.is_none());
        assert!(process.timeout.is_none());
    }
}
