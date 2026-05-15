// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// Fuzz target for the request validator. We parse the fuzzer input first
// (most inputs short-circuit here), and when a one-shot request parses
// successfully we run it through `validate_common`. This lets the fuzzer
// explore the validator's behaviour on real, well-shaped requests rather
// than only garbage that the parser rejects.

#![no_main]

use libfuzzer_sys::fuzz_target;
use wxc_common::config_parser::load_mxc_request;
use wxc_common::logger::{Logger, Mode};
use wxc_common::state_aware_request::MxcRequest;
use wxc_common::validator::validate_common;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let mut logger = Logger::new(Mode::Buffer);
    if let Ok(MxcRequest::OneShot(req)) = load_mxc_request(s, &mut logger, false) {
        let _ = validate_common(&req);
    }
});
