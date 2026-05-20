// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// Fuzz target for `wxc_common::config_parser::load_mxc_request`.
//
// This exercises the full parse pipeline for a one-shot or state-aware MXC
// request supplied as raw (non-base64) JSON: the serde_json deserializer for
// `RawMxcRequest`, followed by the `Raw*` -> validated model conversion. Any
// panic or memory-safety violation discovered here is a real bug because the
// `wxc-exec` / `lxc-exec` binaries call this function with attacker-influenced
// configuration data from the SDK.

#![no_main]

use libfuzzer_sys::fuzz_target;
use wxc_common::config_parser::{load_mxc_request, ParseOptions};
use wxc_common::logger::{Logger, Mode};

fuzz_target!(|data: &[u8]| {
    // The real entry point accepts a `&str`, so reject non-UTF-8 input the
    // same way the driver would.
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let mut logger = Logger::new(Mode::Buffer);
    let _ = load_mxc_request(s, &mut logger, false, ParseOptions::default());
});
