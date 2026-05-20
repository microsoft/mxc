// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// Fuzz target for the request validator. Parses fuzzer input, runs
// `validate_common`, then dispatches to runner-specific `validate_runner`
// based on the containment backend. This exercises the same validation
// path that `--dry-run` takes through the binary.
//
// Runner-specific validation coverage:
//   - NanVix (MicroVm): always (no extra features)
//   - Hyperlight: requires `--features hyperlight`
//   - IsolationSession: requires `--features isolation_session`
//   - Seatbelt: macOS-only, not available in Windows fuzz builds
//   - BaseContainer: skipped (probes platform API availability)

#![no_main]

use libfuzzer_sys::fuzz_target;
use wxc_common::config_parser::{load_mxc_request, ParseOptions};
use wxc_common::logger::{Logger, Mode};
use wxc_common::models::ContainmentBackend;
use wxc_common::script_runner::ScriptRunner;
use wxc_common::state_aware_request::MxcRequest;
use wxc_common::validator::validate_common;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let mut logger = Logger::new(Mode::Buffer);
    if let Ok(MxcRequest::OneShot(req)) = load_mxc_request(s, &mut logger, false, ParseOptions::default()) {
        let _ = validate_common(&req);

        // Dispatch to runner-specific validation based on backend.
        #[cfg(target_os = "windows")]
        match req.containment {
            ContainmentBackend::MicroVm => {
                let runner = wxc_common::nanvix_runner::NanVixScriptRunner::new();
                let _ = runner.validate_runner(&req);
            }
            #[cfg(feature = "hyperlight")]
            ContainmentBackend::Hyperlight => {
                let runner = wxc_common::hyperlight_runner::HyperlightScriptRunner::new();
                let _ = runner.validate_runner(&req);
            }
            #[cfg(feature = "isolation_session")]
            ContainmentBackend::IsolationSession => {
                let runner =
                    wxc_common::isolation_session_runner::IsolationSessionRunner::new();
                let _ = runner.validate_runner(&req);
            }
            _ => {}
        }
    }
});
