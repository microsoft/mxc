// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Standalone binary for the Linux builtin test proxy.
//!
//! **Testing-only tool.** Launches a minimal HTTP CONNECT proxy on an
//! OS-assigned port, atomically writes the port to a ready file, then waits
//! for SIGTERM or parent death before shutting down.
//!
//! Designed to be spawned by `wxc_common::linux_proxy_coordinator` to provide
//! cooperative, unprivileged proxy-based enforcement of `allowedHosts` /
//! `blockedHosts` for the Bubblewrap backend.

#[cfg(target_os = "linux")]
mod proxy;

#[cfg(target_os = "linux")]
mod linux_main {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;

    use clap::Parser;

    use crate::proxy;

    #[derive(Parser)]
    #[command(
        name = "linux-test-proxy",
        about = "Builtin test proxy for MXC Bubblewrap integration testing (NOT for production use)"
    )]
    pub struct Cli {
        /// Path where the proxy atomically writes its port number once ready.
        #[arg(long = "ready-file")]
        pub ready_file: PathBuf,

        /// Address to bind on. Defaults to loopback. Future LXC/Seatbelt
        /// callers can pass the bridge gateway IP so the proxy is reachable
        /// from inside a separate netns.
        #[arg(long = "bind-address", default_value = "127.0.0.1")]
        pub bind_address: String,

        /// Hosts permitted by the proxy. May be repeated. When empty, all
        /// hosts are permitted (subject to `--block-host`).
        #[arg(long = "allow-host")]
        pub allow_host: Vec<String>,

        /// Hosts denied by the proxy. May be repeated. Block takes precedence
        /// over allow.
        #[arg(long = "block-host")]
        pub block_host: Vec<String>,
    }

    pub async fn run() -> std::process::ExitCode {
        // 1. Tie our lifetime to the parent so a crash of `lxc-exec` cannot
        //    leave us behind. Must happen before any work — and we must check
        //    for the parent-already-dead race immediately after.
        unsafe {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM, 0, 0, 0);
            if libc::getppid() == 1 {
                // Parent died before prctl took effect. Bail before binding
                // anything to avoid leaking a listening socket.
                return std::process::ExitCode::from(0);
            }
        }

        eprintln!(
            "[linux-test-proxy] *** SECURITY WARNING ***: testing-only proxy. Do NOT use in production."
        );

        let cli = Cli::parse();

        let filter = Arc::new(proxy::HostFilter::new(
            cli.allow_host.clone(),
            cli.block_host.clone(),
        ));

        let port = match proxy::start(&cli.bind_address, filter).await {
            Ok(port) => port,
            Err(err) => {
                eprintln!(
                    "[linux-test-proxy] failed to bind {}: {}",
                    cli.bind_address, err
                );
                return std::process::ExitCode::from(1);
            }
        };

        eprintln!(
            "[linux-test-proxy] Listening on {}:{}",
            cli.bind_address, port
        );

        // 2. Atomic ready-file: write to `<file>.tmp`, then rename. This
        //    eliminates partial-read windows when the parent polls the file.
        let tmp_path = cli.ready_file.with_extension("tmp");
        if let Err(err) = fs::write(&tmp_path, port.to_string()) {
            eprintln!(
                "[linux-test-proxy] Failed to write ready tmp file {}: {}",
                tmp_path.display(),
                err
            );
            return std::process::ExitCode::from(1);
        }
        if let Err(err) = fs::rename(&tmp_path, &cli.ready_file) {
            eprintln!(
                "[linux-test-proxy] Failed to rename ready file to {}: {}",
                cli.ready_file.display(),
                err
            );
            let _ = fs::remove_file(&tmp_path);
            return std::process::ExitCode::from(1);
        }

        // 3. Wait for SIGTERM (parent's explicit stop signal) or SIGINT
        //    (ctrl-C during manual testing). PR_SET_PDEATHSIG above also
        //    delivers SIGTERM if the parent dies.
        let mut term =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(s) => s,
                Err(err) => {
                    eprintln!(
                        "[linux-test-proxy] failed to install SIGTERM handler: {}",
                        err
                    );
                    return std::process::ExitCode::from(1);
                }
            };
        let mut interrupt =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()) {
                Ok(s) => s,
                Err(err) => {
                    eprintln!(
                        "[linux-test-proxy] failed to install SIGINT handler: {}",
                        err
                    );
                    return std::process::ExitCode::from(1);
                }
            };

        tokio::select! {
            _ = term.recv() => eprintln!("[linux-test-proxy] received SIGTERM, shutting down"),
            _ = interrupt.recv() => eprintln!("[linux-test-proxy] received SIGINT, shutting down"),
        }

        std::process::ExitCode::from(0)
    }
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> std::process::ExitCode {
    linux_main::run().await
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!(
        "linux-test-proxy: this binary is only supported on Linux. Use wxc-test-proxy on Windows."
    );
    std::process::exit(1);
}
