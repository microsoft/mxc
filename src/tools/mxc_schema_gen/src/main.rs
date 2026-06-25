// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Schema codegen tool. Emits the MXC config JSON Schema — or, with `--ts`, the
//! SDK wire TypeScript types — generated from the dedicated `wxc_common::wire`
//! model.
//!
//! Usage (run from the repo root; the Cargo workspace lives in `src/`):
//!   cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- [output-path]
//!   cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- --ts [output-path]
//!
//! With no path the artifact is written to stdout.

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let first = args.next();

    let (emit_ts, path) = match first.as_deref() {
        Some("--ts") => (true, args.next()),
        Some(other) => (false, Some(other.to_string())),
        None => (false, None),
    };

    let content = if emit_ts {
        wxc_common::wire::generate_sdk_types_ts()
    } else {
        // Preserve the historical schema output: the rendered string + trailing
        // newline, byte-for-byte (the schema codegen gate diffs against it).
        format!("{}\n", wxc_common::wire::generate_config_schema_json())
    };
    let label = if emit_ts {
        "SDK TypeScript types"
    } else {
        "generated schema"
    };

    match path {
        Some(path) => {
            if let Err(e) = std::fs::write(&path, &content) {
                eprintln!("failed to write {label} to {path}: {e}");
                return ExitCode::FAILURE;
            }
            // Status goes to stdout so callers that suppress stdout (the CI
            // codegen gates) stay quiet, while write errors above stay on stderr.
            println!("wrote {label} to {path}");
        }
        None => print!("{content}"),
    }
    ExitCode::SUCCESS
}
