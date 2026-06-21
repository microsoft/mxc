//! Rust port of the permissive learning mode (PLM) PowerShell scripts.
//!
//! Subcommands:
//! - `start`: cancel any active WPR trace and start a new one using
//!   `PLM.wprp!AccessFailureProfile` (port of `start_plm_logging.ps1`).
//! - `stop`: stop the trace, parse events, merge findings into a config
//!   (port of `stop_plm_logging.ps1`).
//!
//! Windows-only: the binary wraps WPR / ETW / EventLog APIs that have no
//! cross-platform equivalent. The crate is excluded from the workspace's
//! `default-members`, so `cargo build` on Linux/macOS never reaches this
//! file; the build script (`build.bat`) opts it in explicitly with
//! `-p plm`.

#![cfg(target_os = "windows")]

mod access_event;
mod config;
mod event_parser;
mod extract_caps;
mod log;
mod start;
mod stop;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "plm",
    about = "Rust port of the permissive learning mode PowerShell scripts.",
    version
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Start a new WPR trace using PLM.wprp!AccessFailureProfile.
    Start {
        /// Override path to PLM.wprp. Defaults to <exe dir>\PLM.wprp.
        #[arg(long)]
        wprp: Option<PathBuf>,
    },
    /// Stop the trace and (optionally) merge findings into a config.
    Stop {
        /// Directory for trace.etl, copied input config, and Adjusted_*.json.
        #[arg(long)]
        log_dir: Option<PathBuf>,
        /// Path treated as the application binary's location. Defaults
        /// to the directory containing the plm executable.
        #[arg(long)]
        bin_path: Option<PathBuf>,
        /// Path to the MXC container config (JSON) to update.
        #[arg(long)]
        config_path: Option<PathBuf>,
        /// Override for the adjusted config output path.
        #[arg(long)]
        adjusted_config_path: Option<PathBuf>,
        /// Emit per-event/per-ACE diagnostic output.
        #[arg(long)]
        verbose_logging: bool,
    },
    /// Run extract_caps on a hex-encoded ACE blob and print matched
    /// capability names. Mirrors the standalone usage of extract_caps.ps1.
    ExtractCaps {
        /// Hex-encoded ACE buffer (whitespace allowed, even length).
        #[arg(long)]
        hex_bytes: String,
        /// Emit per-ACE diagnostic output.
        #[arg(long)]
        verbose_logging: bool,
    },
    /// Interactive: press Enter to start logging, press Enter again to
    /// stop, then print the changes a blank config would receive.
    Log {
        /// Override path to PLM.wprp. Defaults to <exe dir>\PLM.wprp.
        #[arg(long)]
        wprp: Option<PathBuf>,
        /// Emit per-event/per-ACE diagnostic output.
        #[arg(long)]
        verbose_logging: bool,
    },
}

fn exe_dir() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("failed to resolve current exe path")?;
    Ok(exe
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".")))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let exe = exe_dir()?;

    match cli.cmd {
        Cmd::Start { wprp } => {
            let wprp_path = wprp.unwrap_or_else(|| exe.join("PLM.wprp"));
            start::start_plm_trace(&wprp_path)
        }
        Cmd::Stop {
            log_dir,
            bin_path,
            config_path,
            adjusted_config_path,
            verbose_logging,
        } => stop::run(
            stop::StopOptions {
                log_dir,
                bin_path,
                config_path,
                adjusted_config_path,
                verbose: verbose_logging,
            },
            &exe,
        ),
        Cmd::ExtractCaps {
            hex_bytes,
            verbose_logging,
        } => {
            let caps = extract_caps::extract_caps(&hex_bytes, verbose_logging)?;
            let mut sorted: Vec<&String> = caps.iter().collect();
            sorted.sort();
            for c in sorted {
                println!("{c}");
            }
            Ok(())
        }
        Cmd::Log {
            wprp,
            verbose_logging,
        } => {
            let wprp_path = wprp.unwrap_or_else(|| exe.join("PLM.wprp"));
            log::run(&wprp_path, verbose_logging)
        }
    }
}
