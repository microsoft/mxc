// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// Fuzz the external request boundary for the reserved Bubblewrap procfs
// control. External JSON must never be able to select the SDK's internal
// procfs policy through process.env.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mxc_sdk::mxc_common::config_parser::load_mxc_request;
use mxc_sdk::mxc_common::logger::{Logger, Mode};
use mxc_sdk::mxc_common::state_aware_request::MxcRequest;

const RESERVED_PROCFS_ENV: &str = "MXC_INTERNAL_MOUNT_PROCFS";

fuzz_target!(|data: &[u8]| {
    let Ok(json) = std::str::from_utf8(data) else {
        return;
    };
    let mut logger = Logger::new(Mode::Buffer);
    if let Ok(MxcRequest::OneShot(request)) = load_mxc_request(json, &mut logger, false) {
        if let Some(environment) = request.env {
            assert!(!environment.iter().any(|entry| {
                entry
                    .split_once('=')
                    .is_some_and(|(key, _)| key == RESERVED_PROCFS_ENV)
            }));
        }
    }
});
