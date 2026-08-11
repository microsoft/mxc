// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows-only PLM command-line entry point.
//!
//! The public process always runs as the caller. Only the hidden `__elevated`
//! mode is launched through UAC, and that mode accepts only a guarded start
//! plus authenticated named-pipe coordinates—never filesystem paths selected
//! by the caller.

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("plm is Windows-only; this stub binary does nothing on non-Windows targets.");
    std::process::exit(1);
}

#[cfg(target_os = "windows")]
use anyhow::{Context, Result};
#[cfg(target_os = "windows")]
use clap::{Parser, Subcommand};
#[cfg(target_os = "windows")]
use plm::elevated::{self, Operation};
#[cfg(target_os = "windows")]
use plm::{extract_caps, log, stop};
#[cfg(target_os = "windows")]
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "plm",
    about = "Capture and analyze permissive learning mode events.",
    version
)]
#[cfg(target_os = "windows")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
#[cfg(target_os = "windows")]
enum Cmd {
    /// Analyze an ETL captured by a retained elevated guardian.
    Stop {
        /// Directory for trace.etl, denials.json, and config outputs.
        #[arg(long)]
        log_dir: Option<PathBuf>,
        /// Application binary location used by the self-access filter.
        #[arg(long)]
        bin_path: Option<PathBuf>,
        /// MXC config to snapshot and adjust.
        #[arg(long)]
        config_path: Option<PathBuf>,
        /// Analyze an existing ETL without invoking elevated WPR control.
        #[arg(long, required = true)]
        trace_file: Option<PathBuf>,
        /// Workload exit code recorded in denials.json.
        #[arg(long, default_value_t = 0, allow_hyphen_values = true)]
        exit_code: i32,
        /// Emit per-event/per-ACE diagnostics.
        #[arg(long)]
        verbose_logging: bool,
    },
    /// Decode a hex-encoded ACE blob.
    ExtractCaps {
        #[arg(long)]
        hex_bytes: String,
        #[arg(long)]
        verbose_logging: bool,
    },
    /// Interactively start, stop, and analyze a trace.
    Log {
        #[arg(long)]
        verbose_logging: bool,
    },
    /// Restricted UAC child. Not a public interface.
    #[command(name = "__elevated", hide = true)]
    InternalElevated {
        #[command(subcommand)]
        operation: InternalOperation,
    },
}

#[derive(Subcommand, Debug)]
#[cfg(target_os = "windows")]
enum InternalOperation {
    Start {
        #[arg(long)]
        pipe_name: String,
        #[arg(long)]
        server_pid: u32,
        #[arg(long)]
        owner_pid: u32,
    },
}

#[cfg(target_os = "windows")]
fn exe_dir() -> Result<PathBuf> {
    let executable = std::env::current_exe().context("failed to resolve current exe path")?;
    Ok(executable
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".")))
}

#[cfg(target_os = "windows")]
fn internal_operation(operation: InternalOperation) -> Result<()> {
    match operation {
        InternalOperation::Start {
            pipe_name,
            server_pid,
            owner_pid,
        } => elevated::run_child(Operation::Start, &pipe_name, server_pid, Some(owner_pid)),
    }
}

#[cfg(target_os = "windows")]
fn main() -> Result<()> {
    let Cli { cmd } = Cli::parse();
    let cmd = match cmd {
        Cmd::InternalElevated { operation } => return internal_operation(operation),
        public => public,
    };
    match cmd {
        Cmd::Stop {
            log_dir,
            bin_path,
            config_path,
            trace_file,
            exit_code,
            verbose_logging,
        } => {
            // Existing-trace analysis never controls the host WPR session and
            // therefore does not need the live-capture singleton.
            let result = stop::run(
                stop::StopOptions {
                    log_dir,
                    bin_path,
                    config_path,
                    trace_file,
                    exit_code,
                    verbose: verbose_logging,
                },
                &exe_dir()?,
            )?;
            println!("{}", serde_json::to_string(&result)?);
            Ok(())
        }
        Cmd::ExtractCaps {
            hex_bytes,
            verbose_logging,
        } => {
            for capability in extract_caps::sorted_capability_names(&extract_caps::extract_caps(
                &hex_bytes,
                verbose_logging,
            )?) {
                println!("{capability}");
            }
            Ok(())
        }
        Cmd::Log { verbose_logging } => {
            let owner_pid = unsafe { windows::Win32::System::Threading::GetCurrentProcessId() };
            let result = log::run(owner_pid, verbose_logging, || {});
            if let Err(error) = result {
                if let Err(cancel_error) = elevated::cancel_current_guarded_start() {
                    return Err(error)
                        .context(format!("guarded PLM cleanup also failed: {cancel_error:#}"));
                }
                return Err(error);
            }
            Ok(())
        }
        Cmd::InternalElevated { .. } => unreachable!("handled before public dispatch"),
    }
}
