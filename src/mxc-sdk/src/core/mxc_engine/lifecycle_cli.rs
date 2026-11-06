// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared lifecycle shell for executors without Windows-specific telemetry.

use crate::mxc_common::config_parser::{
    decode_request_input, load_state_aware_request_from_json_with_options, CliTargetId,
};
use crate::mxc_common::logger::Logger;
use crate::mxc_common::mxc_error::MxcError;
use crate::mxc_common::state_aware_dispatch::DispatchOutcome;
use crate::mxc_common::state_aware_request::Phase;

/// Executor invocation controls, separate from request JSON.
#[doc(hidden)]
#[derive(Debug)]
pub struct LifecycleCliOptions<'a> {
    pub phase: Phase,
    pub target_id: Option<CliTargetId<'a>>,
    pub experimental: bool,
    pub dry_run: bool,
}

/// Parse, authorize and dispatch one native executor lifecycle invocation.
///
/// Returns its exit status; envelope responses use stdout and exec failures
/// use stderr, matching the Windows executor. This is not a public SDK API.
#[doc(hidden)]
pub fn run_state_aware_cli(
    input: &str,
    is_base64: bool,
    options: LifecycleCliOptions<'_>,
    logger: &mut Logger,
) -> i32 {
    let outcome = (|| {
        let source = decode_request_input(input, is_base64)
            .map_err(|error| MxcError::malformed_request(error.to_string()))?;
        let mut parsed = load_state_aware_request_from_json_with_options(
            &source,
            logger,
            options.phase,
            options.target_id,
            &[],
        )
        .map_err(|error| error.to_mxc_error())?;
        parsed.set_experimental_enabled(options.experimental);
        super::state_aware::run_state_aware(parsed, options.dry_run)
    })();
    match outcome {
        Ok(DispatchOutcome::Envelope(value)) => {
            println!("{value}");
            0
        }
        Ok(DispatchOutcome::ExecCompleted { exit_code }) => exit_code,
        Err(error) => {
            let envelope = error.to_envelope_string();
            if options.phase == Phase::Exec && !options.dry_run {
                eprintln!("\n{envelope}");
            } else {
                println!("{envelope}");
            }
            error.code.exit_code()
        }
    }
}
