// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// Fuzz target for `wxc_common::config_parser::load_mxc_request` with
// `is_base64 = true`. This exercises the SDK -> binary code path: the SDK
// base64-encodes a JSON config and passes it on the command line, so this
// target covers `encoding::base64_decode` plus the downstream UTF-8 / JSON /
// model-conversion stages on a single integrated path.

#![no_main]

use libfuzzer_sys::fuzz_target;
use wxc_common::config_parser::load_mxc_request;
use wxc_common::logger::{Logger, Mode};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let mut logger = Logger::new(Mode::Buffer);
    let _ = load_mxc_request(s, &mut logger, true);
});
