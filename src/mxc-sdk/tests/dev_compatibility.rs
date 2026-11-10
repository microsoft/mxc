// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Source compatibility with the supported V1.Dev options and creation calls.

use mxc_sdk::v1::{
    dev::{self, JsonOptions},
    Error, ExecutionResult, MxcProcess,
};

fn saved_options() -> Vec<JsonOptions> {
    vec![
        JsonOptions {
            experimental: false,
        },
        JsonOptions { experimental: true },
    ]
}

#[test]
fn supported_v1_dev_literals_storage_and_creation_signatures_compile() {
    let run: fn(&str, JsonOptions) -> Result<ExecutionResult, Error> = dev::run_json;
    let spawn: fn(&str, JsonOptions) -> Result<MxcProcess, Error> = dev::spawn_json;
    for options in saved_options() {
        let error = run("{}", options).expect_err("an empty request must be rejected");
        assert_eq!(error.code, mxc_sdk::v1::ErrorCode::MalformedRequest);
        let error = spawn("{}", options)
            .err()
            .expect("an empty request must be rejected");
        assert_eq!(error.code, mxc_sdk::v1::ErrorCode::MalformedRequest);
    }
}
