// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Schema codegen tool. Emits the MXC config JSON Schema generated from the
//! dedicated `wxc_common::wire` model.
//!
//! Usage (run from the repo root; the Cargo workspace lives in `src/`):
//!   cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- [output-path]
//!
//! With no argument the schema is written to stdout.

use std::process::ExitCode;

fn main() -> ExitCode {
    let json = wxc_common::wire::generate_config_schema_json();

    match std::env::args().nth(1) {
        Some(path) => {
            if let Err(e) = std::fs::write(&path, format!("{json}\n")) {
                eprintln!("failed to write schema to {path}: {e}");
                return ExitCode::FAILURE;
            }
            // Status goes to stdout so callers that suppress stdout (the CI
            // codegen gate) stay quiet, while write errors above stay on stderr.
            println!("wrote generated schema to {path}");
        }
        None => println!("{json}"),
    }
    ExitCode::SUCCESS
}
