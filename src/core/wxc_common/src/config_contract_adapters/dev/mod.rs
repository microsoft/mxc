// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod common;
mod one_shot;
mod state_aware;

use crate::error::WxcError;
use crate::state_aware_input::StateAwareInput;
use mxc_config_contract::dev as contract;

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
            r#"{"version":"0.10.0-alpha","process":{"commandLine":"echo hello"}}"#,
        )
        .unwrap();
        let AdaptedConfigRequest::OneShot(common) = adapt_request(request).unwrap() else {
            panic!("expected one-shot request");
        };
        assert_eq!(
            common.source_contract,
            mxc_config_contract::ContractVersion::V0_10_0Alpha
        );
        let process = common.process.unwrap();
        assert_eq!(process.command_line.as_deref(), Some("echo hello"));
        assert!(process.cwd.is_none());
        assert!(process.env.is_none());
        assert!(process.timeout.is_none());
    }

    #[test]
    fn one_shot_preserves_process_container_enumerate_paths() {
        let request = contract::parse_request(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../mxc_config_contract/tests/v0_10_0_alpha/fixtures/one_shot/valid/complete.json"
        )))
        .unwrap();
        let AdaptedConfigRequest::OneShot(common) = adapt_request(request).unwrap() else {
            panic!("expected one-shot request");
        };
        assert_eq!(
            common
                .process_container
                .unwrap()
                .filesystem
                .unwrap()
                .enumerate_paths,
            Some(vec!["/metadata".to_string()])
        );
    }
}
