// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Version-aware JSON Schema and TypeScript wire-oracle generator.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use mxc_config_contract::{descriptor, supported_versions, ContractDescriptor, ContractVersion};
use serde_json::{json, Value};

#[derive(Debug, Parser)]
#[command(about = "Generate MXC configuration contract artifacts")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate a JSON Schema.
    Schema(GenerateArgs),
    /// Generate a TypeScript wire oracle.
    Types(GenerateArgs),
    /// List registered contract versions and artifact metadata.
    Versions {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Args)]
struct GenerateArgs {
    /// Exact registered contract version.
    #[arg(long)]
    version: String,
    /// Output path. Omit to write the artifact to standard output.
    #[arg(long)]
    out: Option<PathBuf>,
}

fn target(args: &GenerateArgs) -> Result<ContractVersion, String> {
    ContractVersion::parse_exact(&args.version)
        .ok_or_else(|| format!("unsupported exact contract version: {}", args.version))
}

fn exact_schema(version: ContractVersion) -> Result<(Value, ContractDescriptor), String> {
    let descriptor = descriptor(version);
    if !descriptor.generates_artifacts() {
        return Err(format!(
            "published contract {} has no renderable exact model",
            version.as_str()
        ));
    }
    let mut schema = renderable_exact_schema(version)?;
    mxc_schema_support::prepare_schema(&mut schema, descriptor.schema_id());
    Ok((schema, descriptor))
}

fn renderable_exact_schema(version: ContractVersion) -> Result<Value, String> {
    match version {
        ContractVersion::V0_9_0Alpha => {
            Ok(mxc_config_contract::published::v0_9_0_alpha::published_schema())
        }
        ContractVersion::V0_10_0Alpha => Ok(mxc_config_contract::dev::development_schema()),
        ContractVersion::V0_6_0Alpha
        | ContractVersion::V0_7_0Alpha
        | ContractVersion::V0_8_0Alpha => Err(format!(
            "contract registry marks {} as renderable, but no exact model is available",
            version.as_str()
        )),
    }
}

fn schema_content(version: ContractVersion) -> Result<String, String> {
    let (schema, _) = exact_schema(version)?;
    let root = schema
        .as_object()
        .ok_or_else(|| "generated contract schema root is not an object".to_string())?;
    Ok(format!(
        "{}\n",
        mxc_schema_support::render_root_ordered(root)
    ))
}

fn types_content(version: ContractVersion) -> Result<String, String> {
    let (schema, _) = exact_schema(version)?;
    Ok(mxc_schema_support::emit_contract_ts(
        &schema,
        version.as_str(),
    ))
}

fn write_artifact(content: &str, path: Option<&Path>, label: &str) -> Result<(), String> {
    match path {
        Some(path) => {
            if let Some(parent) = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                std::fs::create_dir_all(parent).map_err(|error| {
                    format!(
                        "failed to create output directory {}: {error}",
                        parent.display()
                    )
                })?;
            }
            std::fs::write(path, content).map_err(|error| {
                format!("failed to write {label} to {}: {error}", path.display())
            })?;
            println!("wrote {label} to {}", path.display());
        }
        None => print!("{content}"),
    }
    Ok(())
}

fn versions_json() -> Value {
    Value::Array(
        supported_versions()
            .iter()
            .map(|version| {
                let descriptor = descriptor(*version);
                json!({
                    "version": version.as_str(),
                    "status": descriptor.status().as_str(),
                    "schemaId": descriptor.schema_id(),
                    "schemaPath": descriptor.schema_path(),
                    "typescriptPath": descriptor.typescript_path(),
                    "generatesArtifacts": descriptor.generates_artifacts(),
                    "requestRoots": descriptor.request_roots().iter().map(|root| json!({
                        "fixtureDirectory": root.fixture_directory(),
                        "schemaDefinition": root.schema_definition()
                    })).collect::<Vec<_>>()
                })
            })
            .collect(),
    )
}

fn print_versions(json_output: bool) -> Result<(), String> {
    if json_output {
        let output = serde_json::to_string_pretty(&versions_json())
            .map_err(|error| format!("failed to serialize contract registry: {error}"))?;
        println!("{output}");
    } else {
        for version in supported_versions() {
            let descriptor = descriptor(*version);
            println!(
                "{}\t{}\t{}",
                version.as_str(),
                descriptor.status().as_str(),
                descriptor.schema_path()
            );
        }
    }
    Ok(())
}

fn run() -> Result<(), String> {
    match Cli::parse().command {
        Command::Schema(args) => {
            let content = schema_content(target(&args)?)?;
            write_artifact(&content, args.out.as_deref(), "generated schema")
        }
        Command::Types(args) => {
            let content = types_content(target(&args)?)?;
            write_artifact(&content, args.out.as_deref(), "TypeScript wire types")
        }
        Command::Versions { json } => print_versions(json),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_json_contains_exact_development_artifacts() {
        let records = versions_json();
        let development = records
            .as_array()
            .unwrap()
            .iter()
            .find(|record| record["version"] == "0.10.0-alpha")
            .unwrap();

        assert_eq!(development["status"], "development");
        assert_eq!(
            development["schemaPath"],
            "schemas/dev/mxc-config.schema.0.10.0-alpha.json"
        );
        assert_eq!(
            development["typescriptPath"],
            "sdk/node/src/generated/v0_10_0_alpha/wire.ts"
        );
        assert_eq!(development["generatesArtifacts"], true);
        assert!(development["requestRoots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|root| root["fixtureDirectory"] == "wslc_provision"
                && root["schemaDefinition"] == "WslcProvisionRequest"));
    }

    #[test]
    fn published_v0_9_generation_is_supported() {
        let (schema, descriptor) = exact_schema(ContractVersion::V0_9_0Alpha).unwrap();

        assert_eq!(descriptor.status().as_str(), "published");
        assert_eq!(
            schema["$id"],
            "https://github.com/microsoft/mxc/schemas/stable/mxc-config.schema.0.9.0-alpha.json"
        );
        assert!(schema["definitions"]["OneShotRequest"].is_object());
        let types = types_content(ContractVersion::V0_9_0Alpha).unwrap();
        assert!(types.contains("Emitted from the exact MXC 0.9.0-alpha contract"));
        assert!(types.contains("export type OneShotRequest"));
    }

    #[test]
    fn older_non_renderable_published_generation_is_rejected() {
        let error = exact_schema(ContractVersion::V0_8_0Alpha).unwrap_err();
        assert!(
            error.contains("published contract 0.8.0-alpha has no renderable exact model"),
            "{error}"
        );
    }

    #[test]
    fn inconsistent_renderable_registry_metadata_is_rejected() {
        let error = renderable_exact_schema(ContractVersion::V0_8_0Alpha).unwrap_err();
        assert!(
            error.contains(
                "contract registry marks 0.8.0-alpha as renderable, but no exact model is available"
            ),
            "{error}"
        );
    }
}
