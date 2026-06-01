// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Top-level subcommand dispatch.
//!
//! Exit-code convention is shared across subcommands so callers
//! (scheduled tasks, registration scripts, humans) can interpret a
//! non-zero exit uniformly:
//!
//! | Code | Meaning                                                  |
//! |-----:|----------------------------------------------------------|
//! | 0    | success — match, applied, or idempotent no-change        |
//! | 1    | semantic mismatch (`verify-null-device` only) or generic |
//! |      | non-fatal error                                          |
//! | 2    | could not open the target object                          |
//! | 3    | required privilege is missing (e.g. `SeSecurityPrivilege`)|
//! | 4    | `SetKernelObjectSecurity` / DACL write failed             |
//! | 5    | SDDL parse failure                                        |
//! | 6    | filesystem DACL operation failed (`system_drive`)         |
//! | 64   | CLI parse error (clap default)                            |
//! | 65   | elevation missing (manifest contract was bypassed)        |

use clap::{Parser, Subcommand};

use crate::elevation_check;

#[derive(Parser)]
#[command(
    name = "wxc-host-prep",
    about = "MXC host-side setup operations. Requires elevation (declared in the application manifest)."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Grant the AppContainer well-known SIDs the minimum rights needed
    /// to stat the system-drive root (e.g. `C:\`). Persistent — survives
    /// reboots until `unprepare-system-drive` is run.
    PrepareSystemDrive(SystemDriveArgs),

    /// Remove the ACEs added by `prepare-system-drive`. Uses precise
    /// tuple matching; other explicit ACEs for the same SIDs are
    /// preserved.
    UnprepareSystemDrive(SystemDriveArgs),

    /// Reapply the documented `\Device\Null` security descriptor.
    /// Idempotent: a no-op when the current SD already matches.
    PrepareNullDevice(PrepareNullDeviceArgs),

    /// Compare the current `\Device\Null` security descriptor against
    /// the documented target. Exit code 0 = match, 1 = mismatch.
    VerifyNullDevice(VerifyNullDeviceArgs),

    /// Print the current `\Device\Null` security descriptor in SDDL
    /// form (and optionally as JSON).
    DumpNullDevice(DumpNullDeviceArgs),
}

#[derive(clap::Args)]
struct SystemDriveArgs {
    /// Target drive root (e.g. `C:\`). Defaults to `%SystemDrive%\`.
    /// Only literal drive roots are accepted.
    #[arg(long)]
    target: Option<String>,
}

#[derive(clap::Args)]
struct PrepareNullDeviceArgs {
    /// Skip writing the SACL. Set this when running without
    /// `SeSecurityPrivilege` (the DACL alone is enough to fix the
    /// AppContainer access path).
    #[arg(long = "no-sacl")]
    no_sacl: bool,

    /// Suppress informational output. Errors still go to stderr.
    #[arg(long)]
    quiet: bool,

    /// Emit machine-readable JSON results on stdout (overrides
    /// human-readable output; honored alongside `--quiet`).
    #[arg(long)]
    json: bool,

    /// Override the log file path. Defaults to
    /// `%ProgramData%\mxc\null-device-acl.log`.
    #[arg(long)]
    log: Option<String>,
}

#[derive(clap::Args)]
struct VerifyNullDeviceArgs {
    /// Emit machine-readable JSON results on stdout.
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args)]
struct DumpNullDeviceArgs {
    /// Emit machine-readable JSON results on stdout.
    #[arg(long)]
    json: bool,
}

pub fn run() -> i32 {
    let cli = Cli::parse();

    if let Err(e) = elevation_check::require_elevated() {
        eprintln!("error: {e}");
        return 65;
    }

    match cli.command {
        Command::PrepareSystemDrive(args) => {
            crate::system_drive::run_prepare(args.target.as_deref())
        }
        Command::UnprepareSystemDrive(args) => {
            crate::system_drive::run_unprepare(args.target.as_deref())
        }
        Command::PrepareNullDevice(args) => {
            crate::null_device::run_apply(!args.no_sacl, args.quiet, args.json, args.log.as_deref())
        }
        Command::VerifyNullDevice(args) => crate::null_device::run_verify(args.json),
        Command::DumpNullDevice(args) => crate::null_device::run_dump(args.json),
    }
}
