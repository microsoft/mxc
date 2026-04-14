// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Generates Rust bindings for the IsoEnvBroker Session API from a WinMD file.
//!
//! Usage:
//!   cargo run --manifest-path tools/generate-agent-session-bindings/Cargo.toml -- <winmd-path>
//!
//! The WinMD file is built from the OS repo (amd64chk flavor):
//!   obj/<flavor>/onecoreuap/windows/core/isoenvbroker/src/published/objchk/amd64/windows.ai.isolationenvironment.winmd

use std::env;
use std::path::Path;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <winmd-path>", args[0]);
        eprintln!();
        eprintln!("Generates Rust bindings from the IsoEnvBroker WinMD file.");
        eprintln!("Output is written to src/agent_session_bindings/src/bindings.rs");
        process::exit(1);
    }

    let winmd_path = &args[1];
    if !Path::new(winmd_path).exists() {
        eprintln!("Error: WinMD file not found: {}", winmd_path);
        process::exit(1);
    }

    // Resolve the output path relative to the MXC repo root.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let repo_root = Path::new(manifest_dir)
        .parent() // tools/
        .and_then(|p| p.parent()) // repo root
        .expect("Could not resolve repo root from CARGO_MANIFEST_DIR");

    let output_path = repo_root
        .join("src")
        .join("agent_session_bindings")
        .join("src")
        .join("bindings.rs");

    println!("WinMD:  {}", winmd_path);
    println!("Output: {}", output_path.display());
    println!();

    // Locate the default Windows metadata bundled with windows-bindgen.
    // This is needed because the custom IsoEnvBroker WinMD references
    // Windows.Foundation types (IAsyncOperation, IAsyncAction, etc.).
    let bindgen_manifest = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .ancestors()
        .find_map(|dir| {
            // Walk up to find the cargo registry cache for windows-bindgen.
            let candidate = dir.join("default").join("Windows.winmd");
            if candidate.exists() {
                return Some(candidate);
            }
            None
        });

    // Fallback: search the cargo registry directly.
    let default_winmd = bindgen_manifest.unwrap_or_else(|| {
        let cargo_home = env::var("CARGO_HOME")
            .or_else(|_| env::var("USERPROFILE").map(|h| format!("{}/.cargo", h)))
            .expect("Could not determine CARGO_HOME");
        let registry_src = Path::new(&cargo_home).join("registry").join("src");
        // Find the windows-bindgen-0.62.* directory.
        if let Ok(entries) = std::fs::read_dir(&registry_src) {
            for index_dir in entries.flatten() {
                if let Ok(crates) = std::fs::read_dir(index_dir.path()) {
                    for krate in crates.flatten() {
                        let name = krate.file_name();
                        let name_str = name.to_string_lossy();
                        if name_str.starts_with("windows-bindgen-0.62") {
                            let candidate = krate.path().join("default").join("Windows.winmd");
                            if candidate.exists() {
                                return candidate;
                            }
                        }
                    }
                }
            }
        }
        eprintln!("Error: Could not find default Windows.winmd in cargo registry.");
        eprintln!("Ensure windows-bindgen 0.62.x is downloaded (cargo build should do this).");
        process::exit(1);
    });

    println!("Default Windows metadata: {}", default_winmd.display());
    let default_winmd_str = default_winmd.to_str().expect("path is valid UTF-8");

    // Generate bindings for the Session namespace only.
    // Pass both the custom IsoEnvBroker WinMD and the default Windows metadata
    // so that Windows.Foundation types can be resolved.
    let warnings = windows_bindgen::bindgen([
        "--in",
        winmd_path,
        "--in",
        default_winmd_str,
        "--out",
        output_path.to_str().expect("output path is valid UTF-8"),
        "--filter",
        "Windows.AI.IsolationEnvironment.Session",
        "--flat",
        "--implement",
    ]);

    // Print any warnings from the generator.
    let warning_text = format!("{warnings}");
    if !warning_text.is_empty() {
        println!("Warnings:\n{}", warning_text);
    }

    println!("Done. Generated bindings at {}", output_path.display());
    println!();
    println!("Next steps:");
    println!("  1. Review the generated bindings.rs");
    println!("  2. Update external/windows-sdk/isolation-environment-session/GENERATION_INFO.toml");
    println!("  3. Build: cd src && cargo build --workspace");
}
