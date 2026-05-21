// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Generates Rust bindings for the Isolation Session API from a WinMD file.
//!
//! Usage:
//!   cargo run --manifest-path tools/generate-isolation-session-bindings/Cargo.toml -- <winmd-path>
//!
//! The WinMD file is produced by an internal Microsoft Windows OS build and is
//! not publicly redistributable. Provide a local path to it via <winmd-path>.

use std::path::{Path, PathBuf};
use std::process;

use clap::Parser;

#[derive(Parser)]
#[command(about = "Generate Isolation Session API Rust bindings from a WinMD file.")]
struct Cli {
    /// Path to the Isolation Session WinMD file produced by a Microsoft Windows
    /// OS build. Combined with windows-bindgen's bundled Windows metadata.
    winmd_path: PathBuf,
}

fn main() {
    let cli = Cli::parse();

    if !cli.winmd_path.exists() {
        eprintln!("Error: WinMD file not found: {}", cli.winmd_path.display());
        process::exit(1);
    }

    let winmd_path = cli.winmd_path.to_str().expect("winmd path is valid UTF-8");

    // Resolve the output path relative to the MXC repo root.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let repo_root = Path::new(manifest_dir)
        .parent() // tools/
        .and_then(|p| p.parent()) // repo root
        .expect("Could not resolve repo root from CARGO_MANIFEST_DIR");

    let output_path = repo_root
        .join("src")
        .join("isolation_session_bindings")
        .join("src")
        .join("bindings.rs");

    println!("WinMD:  {}", winmd_path);
    println!("Output: {}", output_path.display());
    println!();

    // Generate bindings for the Session namespace only.
    // The literal "default" input tells windows-bindgen to combine the
    // user-provided WinMD with its bundled Windows metadata, so the binding
    // can resolve Windows.Foundation types (IAsyncOperation, etc.).
    let warnings = windows_bindgen::bindgen([
        "--in",
        winmd_path,
        "--in",
        "default",
        "--out",
        output_path.to_str().expect("output path is valid UTF-8"),
        "--filter",
        "Windows.AI.IsolationSession",
        "--flat",
        "--implement",
    ]);

    let warning_text = format!("{warnings}");
    if !warning_text.is_empty() {
        println!("Warnings:\n{}", warning_text);
    }

    println!("Done. Generated bindings at {}", output_path.display());
    println!();
    println!("Next steps:");
    println!("  1. Review the generated bindings.rs");
    println!("  2. Update external/windows-sdk/isolation-session/GENERATION_INFO.toml");
    println!("  3. Build: cd src && cargo build --workspace");
}
