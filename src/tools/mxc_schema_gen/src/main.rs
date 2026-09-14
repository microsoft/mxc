// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Version-aware JSON Schema and TypeScript wire-oracle generator.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use mxc_config_contract::{descriptor, supported_versions, ContractDescriptor, ContractVersion};
use serde_json::{json, Value};

const REGISTRY_ARTIFACT_PATH: &str = "schemas/contract-registry.generated.json";

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
    /// Generate machine-readable lifecycle metadata from the Rust registry.
    Registry {
        /// Repository root receiving the generated registry artifact.
        #[arg(long)]
        repo_root: Option<PathBuf>,
        /// Output path. Defaults to schemas/contract-registry.generated.json.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Publish the current stable candidate and register the next development version.
    Publish(PublishArgs),
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

#[derive(Debug, Args)]
struct PublishArgs {
    /// Current development contract to publish.
    #[arg(long)]
    version: String,
    /// Exact version to register as the next mutable development contract.
    #[arg(long)]
    next_dev: String,
    /// Repository root. Defaults to the root containing this crate.
    #[arg(long)]
    repo_root: Option<PathBuf>,
    /// Validate and report the publication transaction without writing files.
    #[arg(long)]
    dry_run: bool,
}

fn target(args: &GenerateArgs) -> Result<ContractVersion, String> {
    ContractVersion::parse_exact(&args.version)
        .ok_or_else(|| format!("unsupported exact contract version: {}", args.version))
}

fn development_schema(version: ContractVersion) -> Result<(Value, ContractDescriptor), String> {
    let descriptor = descriptor(version);
    if !descriptor.is_development() {
        return Err(format!(
            "published contract generation for {} is not supported",
            version.as_str()
        ));
    }

    // Keep this exhaustive after the status gate so every future development
    // contract must explicitly wire its schema source into the generator.
    let mut schema = match version {
        ContractVersion::V0_10_0Alpha => mxc_config_contract::dev::development_schema(),
        ContractVersion::V0_8_0Alpha
        | ContractVersion::V0_6_0Alpha
        | ContractVersion::V0_7_0Alpha
        | ContractVersion::V0_9_0Alpha => {
            unreachable!("published contracts were rejected above")
        }
    };
    mxc_schema_support::prepare_schema(&mut schema, descriptor.schema_id());
    Ok((schema, descriptor))
}

fn publication_schema(version: ContractVersion) -> Result<(Value, ContractDescriptor), String> {
    let descriptor = descriptor(version);
    if !descriptor.is_development() {
        return Err(format!(
            "{} is already published and cannot be published again",
            version.as_str()
        ));
    }

    let schema = match version {
        ContractVersion::V0_10_0Alpha => mxc_config_contract::dev::publication_schema()?,
        ContractVersion::V0_8_0Alpha
        | ContractVersion::V0_6_0Alpha
        | ContractVersion::V0_7_0Alpha
        | ContractVersion::V0_9_0Alpha => {
            unreachable!("published contracts were rejected above")
        }
    };
    Ok((schema, descriptor))
}

fn schema_content(version: ContractVersion) -> Result<String, String> {
    let (schema, _) = development_schema(version)?;
    let root = schema
        .as_object()
        .ok_or_else(|| "generated contract schema root is not an object".to_string())?;
    Ok(format!(
        "{}\n",
        mxc_schema_support::render_root_ordered(root)
    ))
}

fn types_content(version: ContractVersion) -> Result<String, String> {
    let (schema, _) = development_schema(version)?;
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
                    "rustModule": descriptor.rust_module(),
                    "contractModulePath": descriptor.contract_module_path(),
                    "adapterPath": descriptor.adapter_path(),
                    "builderPath": descriptor.builder_path(),
                    "fixturePath": descriptor.fixture_path(),
                    "schemaSha256": descriptor.schema_sha256(),
                    "publicationProfile": publication_profile_json(*version)
                })
            })
            .collect(),
    )
}

fn publication_profile_json(version: ContractVersion) -> Value {
    match version {
        ContractVersion::V0_10_0Alpha => {
            let profile = mxc_config_contract::dev::V0_10_0_ALPHA_PUBLICATION_PROFILE;
            json!({
                "oneShot": profile.one_shot,
                "stateAwareBackends": profile
                    .state_aware_backends
                    .iter()
                    .map(|backend| backend.as_str())
                    .collect::<Vec<_>>()
            })
        }
        ContractVersion::V0_6_0Alpha
        | ContractVersion::V0_7_0Alpha
        | ContractVersion::V0_8_0Alpha
        | ContractVersion::V0_9_0Alpha => Value::Null,
    }
}

fn registry_json() -> Value {
    json!({
        "$comment": "GENERATED FILE - DO NOT EDIT. Regenerate from the Rust exact-contract registry with: cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- registry.",
        "formatVersion": 1,
        "contracts": versions_json()
    })
}

fn default_repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
}

fn registry_output_path(repo_root: Option<PathBuf>, out: Option<PathBuf>) -> PathBuf {
    let root = repo_root.unwrap_or_else(default_repo_root);
    out.unwrap_or_else(|| root.join(REGISTRY_ARTIFACT_PATH))
}

fn generate_registry(repo_root: Option<PathBuf>, out: Option<PathBuf>) -> Result<(), String> {
    let output = registry_output_path(repo_root, out);
    let mut content = serde_json::to_string_pretty(&registry_json())
        .map_err(|error| format!("failed to serialize contract registry: {error}"))?;
    content.push('\n');
    write_artifact(&content, Some(&output), "generated contract registry")
}

fn sha256(content: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    format!("{:x}", Sha256::digest(content))
}

fn publish(args: PublishArgs) -> Result<(), String> {
    let root = args.repo_root.unwrap_or_else(default_repo_root);
    let version = ContractVersion::parse_exact(&args.version)
        .ok_or_else(|| format!("unregistered contract version {}", args.version))?;
    if !descriptor(version).is_development() {
        return Err(format!("{} is not the development contract", args.version));
    }
    if ContractVersion::parse_exact(&args.next_dev).is_some() {
        return Err(format!(
            "next development version {} is already registered",
            args.next_dev
        ));
    }
    if version_order(&args.next_dev)? <= version_order(&args.version)? {
        return Err(format!(
            "next development version {} must be newer than {}",
            args.next_dev, args.version
        ));
    }
    let (mut schema, _) = publication_schema(version)?;
    let stable_schema_id = format!(
        "https://github.com/microsoft/mxc/schemas/stable/mxc-config.schema.{}.json",
        args.version
    );
    let stable_schema_path = format!("schemas/stable/mxc-config.schema.{}.json", args.version);
    mxc_schema_support::prepare_schema(&mut schema, &stable_schema_id);
    let schema_root = schema
        .as_object()
        .ok_or_else(|| "generated publication schema root is not an object".to_string())?;
    let schema_content = format!("{}\n", mxc_schema_support::render_root_ordered(schema_root));
    let digest = sha256(schema_content.as_bytes());

    if args.dry_run {
        println!(
            "would write published schema {} with SHA-256 {}; then update the Rust registry to publish {} and register {} as development",
            stable_schema_path, digest, args.version, args.next_dev
        );
        return Ok(());
    }

    let stable_path = root.join(&stable_schema_path);
    if stable_path.exists() {
        return Err(format!(
            "refusing to overwrite existing published schema {}",
            stable_path.display()
        ));
    }
    write_artifact(&schema_content, Some(&stable_path), "published schema")?;
    println!(
        "published schema SHA-256: {digest}\nupdate the Rust ContractVersion/CONTRACTS registry to publish {} and register {} as development, then regenerate {}",
        args.version, args.next_dev, REGISTRY_ARTIFACT_PATH
    );
    Ok(())
}

fn version_order(version: &str) -> Result<(u64, u64, u64), String> {
    let core = version.split_once('-').map_or(version, |(core, _)| core);
    let mut parts = core.split('.');
    let parse = |part: Option<&str>| {
        part.ok_or_else(|| format!("invalid exact contract version {version:?}"))?
            .parse::<u64>()
            .map_err(|_| format!("invalid exact contract version {version:?}"))
    };
    let result = (
        parse(parts.next())?,
        parse(parts.next())?,
        parse(parts.next())?,
    );
    if parts.next().is_some() {
        return Err(format!("invalid exact contract version {version:?}"));
    }
    Ok(result)
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
        Command::Registry { repo_root, out } => generate_registry(repo_root, out),
        Command::Publish(args) => publish(args),
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
        assert_eq!(development["publicationProfile"]["oneShot"], true);
        assert_eq!(
            development["publicationProfile"]["stateAwareBackends"],
            json!([])
        );
    }

    #[test]
    fn published_generation_is_rejected() {
        let error = development_schema(ContractVersion::V0_8_0Alpha).unwrap_err();
        assert!(error.contains("not supported"), "{error}");
    }

    #[test]
    fn publication_schema_is_narrower_than_development() {
        let (schema, _) = publication_schema(ContractVersion::V0_10_0Alpha).unwrap();
        let serialized = serde_json::to_string(&schema).unwrap();
        assert!(!serialized.contains("\"experimental\""));
        assert!(!serialized.contains("\"windows_sandbox\""));
        assert!(serialized.contains("\"processcontainer\""));
    }

    #[test]
    fn next_development_version_must_advance() {
        assert!(version_order("0.10.0-alpha").unwrap() > version_order("0.9.0-alpha").unwrap());
        assert!(version_order("0.8-alpha").is_err());
    }
}
