// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod test_proxy;

use std::env;
use std::fs;
use std::process::Command;

const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const RESET: &str = "\x1b[0m";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: wxc-test-driver <config_path|config_dir> [--debug] [--proxy]");
        std::process::exit(1);
    }
    let config_path = std::path::Path::new(&args[1]);
    let debug = args.iter().any(|arg| arg == "--debug");
    let use_proxy = args.iter().any(|arg| arg == "--proxy");

    let proxy_port = if use_proxy {
        let port = test_proxy::start().await;
        println!("Test proxy started on 127.0.0.1:{}", port);
        Some(port)
    } else {
        None
    };

    run_configs(config_path, debug, proxy_port)
}

fn run_configs(
    config_path: &std::path::Path,
    debug: bool,
    proxy_port: Option<u16>,
) -> anyhow::Result<()> {
    let exe_dir = env::current_exe()?
        .parent()
        .expect("Failed to get executable directory")
        .to_path_buf();
    let wxc_path = exe_dir.join("wxc-exec.exe");

    if !wxc_path.exists() {
        eprintln!("Error: wxc-exec.exe not found at {}", wxc_path.display());
        std::process::exit(1);
    }

    let configs: Vec<std::path::PathBuf> = if config_path.is_file() {
        vec![config_path.to_path_buf()]
    } else {
        let mut entries: Vec<_> = fs::read_dir(config_path)?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
            .collect();
        entries.sort();
        entries
    };

    for (index, path) in configs.iter().enumerate() {
        // When --proxy is used, patch the config's proxy.localhost with the actual port.
        let config_arg = if let Some(port) = proxy_port {
            let content = fs::read_to_string(path)?;
            let patched = patch_proxy_port(&content, port);
            let temp =
                env::temp_dir().join(format!("wxc-test-{}-{}.json", std::process::id(), index));
            fs::write(&temp, &patched)?;
            temp
        } else {
            path.clone()
        };

        let mut cmd = Command::new(&wxc_path);
        cmd.arg(&config_arg);
        if debug {
            cmd.arg("--debug");
        }

        let output = cmd.output()?;
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

        // Clean up patched temp config.
        if proxy_port.is_some() {
            let _ = fs::remove_file(&config_arg);
        }
    }

    Ok(())
}

/// Patch a JSON config string to set network.proxy.localhost to the given port.
fn patch_proxy_port(json_str: &str, port: u16) -> String {
    let mut value = match serde_json::from_str::<serde_json::Value>(json_str) {
        Ok(val) => val,
        Err(_) => return json_str.to_string(),
    };

    let proxy = serde_json::json!({ "localhost": port });

    if let Some(network) = value.get_mut("network").and_then(|val| val.as_object_mut()) {
        network.insert("proxy".to_string(), proxy);
    } else if let Some(root) = value.as_object_mut() {
        root.insert("network".to_string(), serde_json::json!({ "proxy": proxy }));
    }

    serde_json::to_string_pretty(&value).unwrap_or_else(|_| json_str.to_string())
}
