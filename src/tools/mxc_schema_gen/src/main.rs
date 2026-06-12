// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Phase 2 schema codegen. Emits the MXC config JSON Schema generated from the
//! Rust wire types. The generated schema is a by-product of the single source
//! of truth: it can never describe a shape the parser does not accept.
//!
//! Usage:
//!   cargo run -p mxc_schema_gen -- [output-path]
//!
//! With no argument the schema is written to stdout.

use std::process::ExitCode;

fn main() -> ExitCode {
    let json = wxc_common::config_parser::generate_config_schema_json();

    match std::env::args().nth(1) {
        Some(path) => {
            if let Err(e) = std::fs::write(&path, format!("{json}\n")) {
                eprintln!("failed to write schema to {path}: {e}");
                return ExitCode::FAILURE;
            }
            eprintln!("wrote generated schema to {path}");
        }
        None => println!("{json}"),
    }
    ExitCode::SUCCESS
}
