// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows-only PLM command-line entry point.
//!
//! The public process always runs as the caller. Only the hidden `__elevated`
//! mode is launched through UAC, and that mode accepts fixed start/stop/cancel
//! operations plus authenticated named-pipe coordinates—never filesystem
//! paths selected by the caller.

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
use std::path::PathBuf;
#[cfg(target_os = "windows")]
use std::sync::atomic::AtomicIsize;

#[cfg(target_os = "windows")]
use plm::elevated::{self, Operation};
#[cfg(target_os = "windows")]
use plm::{extract_caps, log, stop};

#[cfg(target_os = "windows")]
static PLM_SINGLETON_HANDLE: AtomicIsize = AtomicIsize::new(0);

#[cfg(target_os = "windows")]
fn release_plm_singleton() {
    plm::coordination::singleton::release(&PLM_SINGLETON_HANDLE);
}

#[cfg(target_os = "windows")]
struct AcquiredSingleton;

#[cfg(target_os = "windows")]
impl Drop for AcquiredSingleton {
    fn drop(&mut self) {
        release_plm_singleton();
    }
}

#[cfg(target_os = "windows")]
fn acquire_singleton_if_needed(parent_authorized: bool) -> Result<Option<AcquiredSingleton>> {
    if parent_authorized {
        return Ok(None);
    }
    use plm::coordination::singleton::{try_acquire, AcquireError};
    match try_acquire(&PLM_SINGLETON_HANDLE) {
        Ok(()) => Ok(Some(AcquiredSingleton)),
        Err(AcquireError::AlreadyHeld) => anyhow::bail!(
            "another PLM trace is already in progress (Global\\Mxc_Plm_Audit held); \
             refusing to interfere with its NT Kernel Logger session"
        ),
        Err(AcquireError::CreateFailed(error)) => {
            Err(error).context("CreateMutexW failed for Global\\Mxc_Plm_Audit")
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "plm",
    about = "Capture and analyze permissive learning mode events.",
    version
)]
#[cfg(target_os = "windows")]
struct Cli {
    /// One-shot, mutually authenticated singleton handoff from wxc-exec.
    #[arg(long, hide = true)]
    wxc_parent_auth: Option<String>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
#[cfg(target_os = "windows")]
enum Cmd {
    /// Start a trace using PLM's embedded WPR profile.
    Start,
    /// Stop the trace and analyze it under the caller's token.
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
        #[arg(long, conflicts_with = "trace_output")]
        trace_file: Option<PathBuf>,
        /// Exact ETL destination written by the unelevated parent.
        #[arg(long, conflicts_with = "trace_file")]
        trace_output: Option<PathBuf>,
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
    /// Internal cleanup entry point used for explicit recovery.
    #[command(hide = true)]
    Cancel,
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
        owner_pid: Option<u32>,
    },
    Stop {
        #[arg(long)]
        pipe_name: String,
        #[arg(long)]
        server_pid: u32,
    },
    Cancel {
        #[arg(long)]
        pipe_name: String,
        #[arg(long)]
        server_pid: u32,
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
    let (operation, pipe_name, server_pid) = match operation {
        InternalOperation::Start {
            pipe_name,
            server_pid,
            owner_pid,
        } => return elevated::run_child(Operation::Start, &pipe_name, server_pid, owner_pid),
        InternalOperation::Stop {
            pipe_name,
            server_pid,
        } => (Operation::Stop, pipe_name, server_pid),
        InternalOperation::Cancel {
            pipe_name,
            server_pid,
        } => (Operation::Cancel, pipe_name, server_pid),
    };
    elevated::run_child(operation, &pipe_name, server_pid, None)
}

#[cfg(target_os = "windows")]
fn main() -> Result<()> {
    let Cli {
        wxc_parent_auth,
        cmd,
    } = Cli::parse();
    let cmd = match cmd {
        Cmd::InternalElevated { operation } => return internal_operation(operation),
        public => public,
    };
    let authorized_parent_pid = match wxc_parent_auth.as_deref() {
        Some(pipe_name) => Some(plm::parent_auth::claim(pipe_name).map_err(anyhow::Error::msg)?),
        None => None,
    };
    match cmd {
        Cmd::Start => {
            let _singleton = acquire_singleton_if_needed(authorized_parent_pid.is_some())?;
            elevated::invoke(Operation::Start, None)
        }
        Cmd::Stop {
            log_dir,
            bin_path,
            config_path,
            trace_file,
            trace_output,
            exit_code,
            verbose_logging,
        } => {
            let _singleton = acquire_singleton_if_needed(authorized_parent_pid.is_some())?;
            let result = stop::run(
                stop::StopOptions {
                    log_dir,
                    bin_path,
                    config_path,
                    trace_file,
                    trace_output,
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
            let _singleton = acquire_singleton_if_needed(authorized_parent_pid.is_some())?;
            let owner_pid = unsafe { windows::Win32::System::Threading::GetCurrentProcessId() };
            let disarm_error = std::cell::RefCell::new(None);
            let result = log::run(
                owner_pid,
                verbose_logging,
                || {},
                || {
                    if let Err(error) = elevated::disarm_current_guarded_start() {
                        *disarm_error.borrow_mut() = Some(error);
                    }
                },
            );
            if result.is_err() {
                elevated::cancel_current_guarded_start();
            }
            if let Some(error) = disarm_error.into_inner() {
                return Err(error).context("failed to disarm interactive guarded PLM session");
            }
            result
        }
        Cmd::Cancel => {
            let _singleton = acquire_singleton_if_needed(authorized_parent_pid.is_some())?;
            elevated::invoke(Operation::Cancel, None)
        }
        Cmd::InternalElevated { .. } => unreachable!("handled before public dispatch"),
    }
}
