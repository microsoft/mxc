// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Schema codegen tool. Emits execution-config or telemetry-consent JSON
//! Schema/TypeScript artifacts generated from `wxc_common::wire`.
//!
//! Usage (run from the repo root; the Cargo workspace lives in `src/`):
//!   cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- [output-path]
//!   cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- --ts [output-path]
//!   cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- --telemetry-consent [output-path]
//!   cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- --telemetry-consent-ts [output-path]
//!
//! With no path the artifact is written to stdout.

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let first = args.next();

    enum Artifact {
        ConfigSchema,
        ConfigTypes,
        TelemetryConsentSchema,
        TelemetryConsentTypes,
    }

    let (artifact, path) = match first.as_deref() {
        Some("--ts") => (Artifact::ConfigTypes, args.next()),
        Some("--telemetry-consent") => (Artifact::TelemetryConsentSchema, args.next()),
        Some("--telemetry-consent-ts") => (Artifact::TelemetryConsentTypes, args.next()),
        Some(other) => (Artifact::ConfigSchema, Some(other.to_string())),
        None => (Artifact::ConfigSchema, None),
    };

    let (content, label) = match artifact {
        Artifact::ConfigSchema => (
            // Preserve the historical schema output: the rendered string +
            // trailing newline, byte-for-byte.
            format!("{}\n", wxc_common::wire::generate_config_schema_json()),
            "generated schema",
        ),
        Artifact::ConfigTypes => (
            wxc_common::wire::generate_sdk_types_ts(),
            "SDK TypeScript types",
        ),
        Artifact::TelemetryConsentSchema => (
            format!(
                "{}\n",
                wxc_common::wire::generate_telemetry_consent_schema_json()
            ),
            "telemetry consent schema",
        ),
        Artifact::TelemetryConsentTypes => (
            wxc_common::wire::generate_telemetry_consent_sdk_types_ts(),
            "telemetry consent TypeScript types",
        ),
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
