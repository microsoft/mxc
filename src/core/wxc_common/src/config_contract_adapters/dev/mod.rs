// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod common;
mod one_shot;
mod state_aware;

use crate::error::WxcError;
use crate::state_aware_wire::StateAwareInput;
use crate::wire;
use mxc_config_contract::dev as contract;

pub(crate) fn adapt_request(request: contract::Request) -> wire::MxcConfig {
    let contract::Request::OneShot(request) = request;
    one_shot::into_wire(*request)
}

pub(crate) fn one_shot_into_wire(request: contract::OneShotRequest) -> wire::MxcConfig {
    one_shot::into_wire(request)
}

pub(crate) fn state_aware_into_input(
    request: contract::OneShotRequest,
    phase: crate::state_aware_request::Phase,
    sandbox_id: Option<&str>,
) -> Result<StateAwareInput, WxcError> {
    state_aware::operation_into_input(request, phase, sandbox_id)
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
        let common = adapt_request(request);
        assert_eq!(common.version.as_deref(), Some("0.9.0-alpha"));
        let process = common.process.unwrap();
        assert_eq!(process.command_line.as_deref(), Some("echo hello"));
        assert!(process.cwd.is_none());
        assert!(process.env.is_none());
        assert!(process.timeout.is_none());
    }
}
