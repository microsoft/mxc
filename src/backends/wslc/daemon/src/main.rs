// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `wxc-wslc-daemon` — the long-lived per-user daemon that owns the WSLc SDK
//! session + container handles across state-aware lifecycle phases.
//!
//! Each state-aware phase (`provision` / `start` / `exec` / `stop` /
//! `deprovision`) runs as a separate short-lived `wxc-exec` process, but the
//! WSLc SDK has no cross-process re-attach for its `WslcSession` /
//! `WslcContainer` handles. This daemon holds those handles on a single worker
//! thread ([`session_manager`]) and serves the phase processes over an
//! owner-only named pipe ([`control_server`]).
//!
//! Boot sequence:
//! 1. Secure the record root and mint a unique pipe name.
//! 2. Spawn the WSLc worker thread.
//! 3. Bind the first control-pipe instance, then publish a `ready` `daemon.json`
//!    record — the pipe is listening before any client can discover it.
//! 4. Run an idle watchdog: when the live-container count stays at zero with no
//!    in-flight requests past the idle timeout, shut down.
//! 5. On exit, remove the record.

#[cfg(windows)]
mod control_server;
#[cfg(windows)]
mod session_manager;

#[cfg(windows)]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(windows)]
use std::sync::Arc;
#[cfg(windows)]
use std::time::Duration;

#[cfg(windows)]
use anyhow::{Context, Result};
#[cfg(windows)]
use tokio::sync::Notify;

#[cfg(windows)]
use wslc_common::daemon_protocol::PROTOCOL_VERSION;
#[cfg(windows)]
use wslc_common::daemon_record::{
    mint_pipe_name, process_creation_time, remove_daemon_record, secure_record_root,
    write_daemon_record, DaemonRecord, TransitionLock, RECORD_SCHEMA_VERSION,
};

/// How long the live-container count must stay at zero before the daemon exits.
#[cfg(windows)]
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Poll cadence for the idle watchdog.
#[cfg(windows)]
const IDLE_POLL: Duration = Duration::from_secs(15);

/// Bound on how long shutdown waits for the transition lock before tearing down
/// without it, so a phase process holding the lock cannot hang daemon exit.
#[cfg(windows)]
const SHUTDOWN_LOCK_TIMEOUT: Duration = Duration::from_secs(10);

// The daemon owns the WSLc SDK's live session/container handles, which only
// exist on Windows. The Windows-only dependencies are target-gated in
// Cargo.toml so non-Windows workspace commands (`cargo build/test --workspace`)
// still resolve and compile this crate down to the stub below.
#[cfg(not(windows))]
fn main() {
    eprintln!("wxc-wslc-daemon is Windows-only.");
    std::process::exit(64);
}

#[cfg(windows)]
fn main() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;
    runtime.block_on(run())
}

#[cfg(windows)]
async fn run() -> Result<()> {
    secure_record_root().context("secure state-aware record root")?;

    let pid = std::process::id();
    // Stamp the record with our own verifiable identity. If we cannot read our
    // creation time, fail startup rather than publish an unverifiable record: a
    // record with a bogus creation time fails its own `daemon_alive` liveness
    // check, so discovery clients would treat this daemon as dead and spawn a
    // duplicate while it is still serving.
    let pid_creation_time = process_creation_time(pid).context("read own process creation time")?;
    let pipe_name = mint_pipe_name();

    let session = session_manager::spawn().context("spawn WSLc session worker")?;

    // Bind the first pipe instance before advertising the record, so a client
    // never discovers a ready record for a pipe that is not yet listening.
    let (security, first_instance) =
        control_server::bind(&pipe_name).context("bind control pipe")?;

    let record = DaemonRecord {
        schema_version: RECORD_SCHEMA_VERSION,
        pid,
        pid_creation_time,
        pipe_name: pipe_name.clone(),
        ready: true,
        protocol_version: PROTOCOL_VERSION,
    };
    write_daemon_record(&record).context("publish daemon record")?;

    let shutdown = Arc::new(Notify::new());
    let active_clients = Arc::new(AtomicUsize::new(0));

    let server = tokio::spawn(control_server::run(
        session.clone(),
        pipe_name.clone(),
        security,
        first_instance,
        active_clients.clone(),
        shutdown.clone(),
    ));

    let watchdog = tokio::spawn(idle_watchdog(
        session.clone(),
        active_clients,
        shutdown.clone(),
    ));

    // Wait for the control server to finish: it stops accepting when `shutdown`
    // fires and then drains its in-flight handlers, so once this returns no
    // handler is still using the session.
    let server_result = server.await;

    // Stop the idle watchdog (it may still be sleeping between polls).
    watchdog.abort();

    // Teardown order matters. Take the transition lock so a concurrent phase
    // process's spawn/discovery serialises against us, then remove the discovery
    // record BEFORE releasing the session — a client must never find a `ready`
    // record for a daemon whose session is being torn down; with the record
    // gone it spawns a fresh daemon once we release the lock. If the lock cannot
    // be taken promptly (a phase process holds it mid-spawn), proceed anyway:
    // record removal and session release are still correct on their own.
    {
        let _lock = TransitionLock::acquire(SHUTDOWN_LOCK_TIMEOUT)
            .map_err(|e| eprintln!("[wslc-daemon] shutdown: {e:#}; proceeding without the lock"))
            .ok();
        let _ = remove_daemon_record();
        let _ = session.shutdown().await;
    }

    server_result
        .context("control server task panicked")?
        .context("control server failed")
}

/// Poll the live-container count; once it has been zero for `IDLE_TIMEOUT` with
/// no in-flight requests, notify shutdown.
///
/// The signal is delivered with [`Notify::notify_one`], not `notify_waiters`:
/// the control server only awaits `shutdown.notified()` inside its `select!`, so
/// a wakeup raised while it is executing another branch (accepting or spawning a
/// handler) would be dropped by `notify_waiters` (it retains no permit when no
/// task is parked). `notify_one` stores a permit, so the server's next
/// `notified()` completes regardless of when the signal was raised — the
/// watchdog can then return without leaving the daemon alive forever.
#[cfg(windows)]
async fn idle_watchdog(
    session: session_manager::SessionHandle,
    active_clients: Arc<AtomicUsize>,
    shutdown: Arc<Notify>,
) {
    let mut idle_for = Duration::ZERO;
    loop {
        tokio::time::sleep(IDLE_POLL).await;
        match session.container_count().await {
            // A provision holds the count at zero while it runs, so also require
            // no in-flight client requests before counting as idle.
            Ok(0) if active_clients.load(Ordering::SeqCst) == 0 => {
                idle_for += IDLE_POLL;
                if idle_for >= IDLE_TIMEOUT {
                    shutdown.notify_one();
                    return;
                }
            }
            Ok(_) => idle_for = Duration::ZERO,
            Err(_) => {
                // Worker gone: nothing left to serve.
                shutdown.notify_one();
                return;
            }
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use std::time::Duration;

    use tokio::sync::Notify;

    /// Regression for the lost idle-shutdown wakeup: the watchdog may fire while
    /// the control server is executing a non-`notified()` `select!` branch. With
    /// `notify_one` the signal is retained as a permit, so the server's *next*
    /// `notified()` still completes. (`notify_waiters` would drop it here and
    /// hang the daemon alive forever.)
    #[tokio::test]
    async fn notify_one_is_observed_when_raised_before_the_waiter_parks() {
        let shutdown = Notify::new();

        // Signal raised while no task is parked (server busy elsewhere).
        shutdown.notify_one();

        // The server later reaches its `notified()`; it must complete promptly.
        tokio::time::timeout(Duration::from_secs(5), shutdown.notified())
            .await
            .expect("a permit raised before the waiter parked must not be lost");
    }
}
