// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Exact-JSON one-shot execution operations.

use crate::mxc_engine::Error;
use crate::sandbox::{ExecutionResult, MxcProcess, MxcPtyProcess};

use super::{JsonOptions, PtyJsonOptions};

/// Run a caller-authored exact-version one-shot request to completion and capture its output.
///
/// The registered `version` and one-shot request root are parsed by the engine
/// without stamping or reserializing the input. `options.experimental` only
/// authorizes an experimental backend; it does not select a contract version.
/// The engine uses pipes or backend-owned capture. MicroVM capture requires
/// Windows x64, the `microvm` Cargo feature, experimental authorization, and
/// the signed NVX bundle and host prerequisites.
/// Nonzero workload exit and timeout are results, not API errors. Parser,
/// launch, and output-read failures return [`Error`].
pub fn run_json(json: &str, options: JsonOptions) -> Result<ExecutionResult, Error> {
    crate::__ffi::run_json(json, options.experimental)
}

/// Spawn a caller-authored exact-version one-shot request with live pipes.
pub fn spawn_json(json: &str, options: JsonOptions) -> Result<MxcProcess, Error> {
    crate::__ffi::spawn_container_json(json, options.experimental)
}

/// Spawn a caller-authored exact-version one-shot request with a PTY.
pub fn spawn_with_pty_json(json: &str, options: PtyJsonOptions) -> Result<MxcPtyProcess, Error> {
    crate::__ffi::spawn_with_pty_json(json, options.experimental, options.size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_engine::ErrorCode;

    #[test]
    fn one_shot_spawns_use_exact_parser() {
        let json = "{}";
        let options = JsonOptions::default();
        let pty = PtyJsonOptions::default();
        let pipe_error = match spawn_json(json, options) {
            Err(error) => error,
            Ok(_) => panic!("missing version must fail"),
        };
        let pty_error = match spawn_with_pty_json(json, pty) {
            Err(error) => error,
            Ok(_) => panic!("missing version must fail"),
        };
        assert_eq!(pipe_error.code, ErrorCode::MalformedRequest);
        assert_eq!(pty_error.code, ErrorCode::MalformedRequest);
    }

    #[test]
    fn run_json_uses_exact_parser_and_rejects_invalid_requests() {
        for json in [
            "{ not json",
            r#"{"version":"999.0.0","process":{"commandLine":"echo hi"}}"#,
            r#"{"version":"1.0.0","process":{"commandLine":"echo hi"},"extra":true}"#,
        ] {
            let error = crate::v1::dev::run_json(json, JsonOptions::default()).unwrap_err();
            assert_eq!(error.code, ErrorCode::MalformedRequest, "{json}: {error}");
        }
    }

    #[test]
    fn run_json_rejects_lifecycle_root() {
        let json = r#"{"version":"1.0.0","phase":"start","sandboxId":"iso:unused"}"#;
        let error = crate::v1::dev::run_json(json, JsonOptions::default()).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedRequest);
    }

    #[test]
    fn run_json_experimental_option_does_not_select_a_contract_version() {
        let json = r#"{"version":"999.0.0","process":{"commandLine":"echo must-not-run"}}"#;
        for experimental in [false, true] {
            let error = crate::v1::dev::run_json(json, JsonOptions { experimental }).unwrap_err();
            assert_eq!(error.code, ErrorCode::MalformedRequest);
        }
    }
}
