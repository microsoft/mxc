// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::env;
use std::fs;
use std::process::Command;

const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const RESET: &str = "\x1b[0m";

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: wxc-test-driver <config_path_dir>");
        std::process::exit(1);
    }
    let config_dir = &args[1];

    // Find wxc-exec.exe next to this executable
    let exe_dir = env::current_exe()?
        .parent()
        .expect("Failed to get executable directory")
        .to_path_buf();
    let wxc_path = exe_dir.join("wxc-exec.exe");

    if !wxc_path.exists() {
        eprintln!("Error: wxc-exec.exe not found at {}", wxc_path.display());
        std::process::exit(1);
    }

    for entry in fs::read_dir(config_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().map_or(false, |e| e == "json") {
            let output = Command::new(&wxc_path).arg(&path).output()?;
            let exit_code = output.status.code().unwrap_or(-1);

            if exit_code != 0 {
                println!(
                    "{RED}wxc-exec failed for config: {} with exit code: 0x{:x}{RESET}",
                    path.display(),
                    exit_code
                );
            } else {
                println!(
                    "{GREEN}wxc-exec succeeded for config: {}{RESET}",
                    path.display()
                );
            }

            if !output.stdout.is_empty() {
                println!("STDOUT:\n{}", String::from_utf8_lossy(&output.stdout));
            }
            if !output.stderr.is_empty() {
                println!("STDERR:\n{}", String::from_utf8_lossy(&output.stderr));
            }
        }
    }

    Ok(())
}
