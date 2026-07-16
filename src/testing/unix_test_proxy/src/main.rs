// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Standalone binary for the Unix builtin test proxy.
//!
//! **Testing-only tool.** Launches a minimal HTTP CONNECT proxy on an
//! OS-assigned port, atomically writes the port to a ready file, then waits
//! for SIGTERM, SIGINT, or EOF on its parent-lifetime pipe before shutting
//! down.
//!
//! Designed to be spawned by `wxc_common::unix_proxy_coordinator` to provide
//! cooperative, unprivileged proxy-based enforcement of `allowedHosts` /
//! `blockedHosts`. Used by the Bubblewrap backend on Linux and the Seatbelt
//! backend on macOS. It builds and runs on any Unix; the CONNECT proxy itself
//! (`proxy`) is platform-neutral.

#[cfg(unix)]
mod proxy;

#[cfg(unix)]
mod unix_main {
    use std::fs;
    use std::io::Read;
    use std::path::PathBuf;
    use std::sync::Arc;

    use clap::{Parser, ValueEnum};

    use crate::proxy;

    #[derive(Copy, Clone, Debug, ValueEnum)]
    pub enum DefaultPolicyArg {
        Allow,
        Block,
    }

    impl From<DefaultPolicyArg> for proxy::DefaultPolicy {
        fn from(value: DefaultPolicyArg) -> Self {
            match value {
                DefaultPolicyArg::Allow => proxy::DefaultPolicy::Allow,
                DefaultPolicyArg::Block => proxy::DefaultPolicy::Block,
            }
        }
    }

    #[derive(Parser)]
    #[command(
        name = "unix-test-proxy",
        about = "Builtin test proxy for MXC Bubblewrap/Seatbelt integration testing (NOT for production use)"
    )]
    pub struct Cli {
        /// Path where the proxy atomically writes its port number once ready.
        #[arg(long = "ready-file")]
        pub ready_file: PathBuf,

        /// Address to bind on. Bubblewrap and Seatbelt use loopback; an LXC
        /// caller can pass its bridge gateway to cross a separate netns.
        #[arg(long = "bind-address", default_value = "127.0.0.1")]
        pub bind_address: String,

        /// Hosts permitted by the proxy. May be repeated. When empty, the
        /// default policy (see `--default-policy`) decides.
        #[arg(long = "allow-host")]
        pub allow_host: Vec<String>,

        /// Hosts denied by the proxy. May be repeated. Block takes precedence
        /// over allow.
        #[arg(long = "block-host")]
        pub block_host: Vec<String>,

        /// Policy applied when the allow list is empty.
        ///
        /// - `allow` — permit any host that isn't explicitly blocked.
        /// - `block` — deny any host that isn't explicitly allowed.
        ///
        /// Ignored when `--allow-host` is non-empty (only listed hosts pass).
        #[arg(long = "default-policy", value_enum, default_value_t = DefaultPolicyArg::Allow)]
        pub default_policy: DefaultPolicyArg,
    }

    /// Spawn a background thread that fires the returned receiver when the
    /// parent process disconnects.
    ///
    /// The proxy inherits a pipe on stdin whose write end is held open by the
    /// coordinator (its parent). When the parent exits — normally, on a crash,
    /// or on `SIGKILL` — the kernel closes that write end, the watcher's
    /// `read` returns EOF (`Ok(0)`), and the receiver is signalled so [`run`]
    /// can shut down. This is the portable replacement for Linux's
    /// `PR_SET_PDEATHSIG` and behaves identically on Linux and macOS.
    ///
    /// # Caveats versus `PR_SET_PDEATHSIG`
    ///
    /// - **fd inheritance**: the signal is tied to the *write end of the stdin
    ///   pipe*, not to the parent pid. If that fd is duplicated into another
    ///   process that outlives the parent, killing the direct parent will not
    ///   produce EOF and the proxy keeps running. The coordinator spawns the
    ///   child with `Stdio::piped()`, whose parent-side handle is `CLOEXEC`,
    ///   so sibling processes do not inherit it — but callers that dup stdin
    ///   must be aware of this.
    /// - **startup race**: the watcher runs on its own thread, so there is a
    ///   brief window in which the child can bind and publish its port before
    ///   an already-dead parent's EOF is observed. [`run`] narrows this with a
    ///   non-blocking [`parent_already_disconnected`] check before binding and
    ///   before publishing; the `select!` closes any residual window.
    fn parent_disconnect_signal() -> Result<tokio::sync::oneshot::Receiver<()>, std::io::Error> {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        std::thread::Builder::new()
            .name("mxc-proxy-parent-watch".into())
            .spawn(move || {
                let mut stdin = std::io::stdin();
                let mut buffer = [0u8; 256];
                loop {
                    match stdin.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(_) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(_) => break,
                    }
                }
                let _ = sender.send(());
            })?;
        Ok(receiver)
    }

    /// Best-effort, non-blocking check of whether the parent has already
    /// disconnected (stdin EOF observed by the watcher thread).
    ///
    /// This is the portable analog of the old Linux-only `getppid() == 1`
    /// guard: it lets [`run`] bail out before binding a socket or publishing
    /// the ready file when the parent dies during startup. It is inherently
    /// racy — the watcher thread may not have observed EOF yet — so the
    /// authoritative shutdown still happens on the `parent_disconnected` arm
    /// of the run loop's `select!`.
    fn parent_already_disconnected(receiver: &mut tokio::sync::oneshot::Receiver<()>) -> bool {
        matches!(receiver.try_recv(), Ok(()))
    }

    pub async fn run() -> std::process::ExitCode {
        let mut parent_disconnected = match parent_disconnect_signal() {
            Ok(signal) => signal,
            Err(error) => {
                eprintln!("[unix-test-proxy] failed to start parent watcher: {error}");
                return std::process::ExitCode::from(1);
            }
        };

        eprintln!(
            "[unix-test-proxy] *** SECURITY WARNING ***: testing-only proxy. Do NOT use in production."
        );

        let Cli {
            ready_file,
            bind_address,
            allow_host,
            block_host,
            default_policy,
        } = Cli::parse();

        let filter = Arc::new(proxy::HostFilter::new(
            allow_host,
            block_host,
            default_policy.into(),
        ));

        // Portable analog of the old Linux `getppid() == 1` guard: if the
        // parent already disconnected before we bind, bail out before opening
        // a listening socket so we never leak one.
        if parent_already_disconnected(&mut parent_disconnected) {
            eprintln!("[unix-test-proxy] parent disconnected before bind, exiting");
            return std::process::ExitCode::from(0);
        }

        let port = match proxy::start(&bind_address, filter).await {
            Ok(port) => port,
            Err(err) => {
                eprintln!("[unix-test-proxy] failed to bind {}: {}", bind_address, err);
                return std::process::ExitCode::from(1);
            }
        };

        eprintln!("[unix-test-proxy] Listening on {}:{}", bind_address, port);

        // 2. Atomic ready-file: write to `<file>.tmp`, then rename. This
        //    eliminates partial-read windows when the parent polls the file.
        //    Re-check the parent first so a parent that died during bind does
        //    not get a published port for a proxy that is about to exit.
        if parent_already_disconnected(&mut parent_disconnected) {
            eprintln!("[unix-test-proxy] parent disconnected before publish, exiting");
            return std::process::ExitCode::from(0);
        }
        let tmp_path = ready_file.with_extension("tmp");
        if let Err(err) = fs::write(&tmp_path, port.to_string()) {
            eprintln!(
                "[unix-test-proxy] Failed to write ready tmp file {}: {}",
                tmp_path.display(),
                err
            );
            return std::process::ExitCode::from(1);
        }
        if let Err(err) = fs::rename(&tmp_path, &ready_file) {
            eprintln!(
                "[unix-test-proxy] Failed to rename ready file to {}: {}",
                ready_file.display(),
                err
            );
            let _ = fs::remove_file(&tmp_path);
            return std::process::ExitCode::from(1);
        }

        // 3. Wait for the parent's explicit stop signal, ctrl-C during manual
        //    testing, or EOF if the parent exits without running cleanup.
        let mut term =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(s) => s,
                Err(err) => {
                    eprintln!(
                        "[unix-test-proxy] failed to install SIGTERM handler: {}",
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
                        "[unix-test-proxy] failed to install SIGINT handler: {}",
                        err
                    );
                    return std::process::ExitCode::from(1);
                }
            };

        tokio::select! {
            _ = term.recv() => eprintln!("[unix-test-proxy] received SIGTERM, shutting down"),
            _ = interrupt.recv() => eprintln!("[unix-test-proxy] received SIGINT, shutting down"),
            _ = parent_disconnected => {
                eprintln!("[unix-test-proxy] parent disconnected, shutting down")
            },
        }

        std::process::ExitCode::from(0)
    }
}

#[cfg(unix)]
#[tokio::main]
async fn main() -> std::process::ExitCode {
    unix_main::run().await
}

#[cfg(not(unix))]
fn main() {
    eprintln!(
        "unix-test-proxy: this binary is only supported on Unix (Linux/macOS). Use wxc-test-proxy on Windows."
    );
    std::process::exit(1);
}
