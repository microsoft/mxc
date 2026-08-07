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

mod control_server;
mod session_manager;

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::Notify;

use wslc_common::daemon_protocol::PROTOCOL_VERSION;
use wslc_common::daemon_record::{
    mint_pipe_name, process_creation_time, remove_daemon_record, secure_record_root,
    write_daemon_record, DaemonRecord, RECORD_SCHEMA_VERSION,
};

/// How long the live-container count must stay at zero before the daemon exits.
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Poll cadence for the idle watchdog.
const IDLE_POLL: Duration = Duration::from_secs(15);

fn main() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;
    runtime.block_on(run())
}

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
    // Monotonic connection counter. The idle watchdog compares it across polls
    // so a client that connects *and* finishes entirely between two polls (both
    // `active_clients` and the container count momentarily back at zero) still
    // resets the idle streak instead of being missed.
    let activity = Arc::new(AtomicU64::new(0));

    let server = tokio::spawn(control_server::run(
        session.clone(),
        pipe_name.clone(),
        security,
        first_instance,
        active_clients.clone(),
        activity.clone(),
        shutdown.clone(),
    ));

    let watchdog = tokio::spawn(idle_watchdog(
        session.clone(),
        active_clients,
        activity,
        shutdown.clone(),
    ));

    // Wait for the control server to finish (it stops when `shutdown` fires).
    let server_result = server.await;

    // Ensure the watchdog and worker are torn down.
    shutdown.notify_waiters();
    watchdog.abort();
    let _ = session.shutdown().await;

    // Best-effort record cleanup so a later client does not find a stale record.
    let _ = remove_daemon_record();

    server_result
        .context("control server task panicked")?
        .context("control server failed")
}

/// Poll the live-container count; once it has been zero for `IDLE_TIMEOUT` with
/// no in-flight requests and no new connections since the previous poll, notify
/// shutdown.
///
/// Idle is only declared when three signals agree: the container count is zero,
/// no client request is in flight (`active_clients`), and the monotonic
/// `activity` counter has not advanced since the last poll. The last guard
/// closes the window where a client connects and completes entirely between two
/// polls — the count and `active_clients` would both read zero again, but the
/// bumped `activity` generation still resets the idle streak.
async fn idle_watchdog(
    session: session_manager::SessionHandle,
    active_clients: Arc<AtomicUsize>,
    activity: Arc<AtomicU64>,
    shutdown: Arc<Notify>,
) {
    let mut idle_for = Duration::ZERO;
    let mut last_activity = activity.load(Ordering::SeqCst);
    loop {
        tokio::time::sleep(IDLE_POLL).await;
        // Query the count first: it is serialized on the worker, so it cannot
        // observe zero while a provision that will make it non-zero is in flight.
        let count = match session.container_count().await {
            Ok(count) => count,
            Err(_) => {
                // Worker gone: nothing left to serve.
                shutdown.notify_waiters();
                return;
            }
        };
        // Read the monotonic generation last — after count and active_clients —
        // so a client that connects and completes entirely within this poll
        // (bumping `activity`, then dropping `active_clients` back to zero) is
        // still observed here as `generation != last_activity`, instead of
        // slipping through with both zero-reads while the generation bump goes
        // unsampled.
        let active = active_clients.load(Ordering::SeqCst);
        let generation = activity.load(Ordering::SeqCst);
        let idle = count == 0 && active == 0 && generation == last_activity;
        last_activity = generation;

        if idle {
            idle_for += IDLE_POLL;
            if idle_for >= IDLE_TIMEOUT {
                shutdown.notify_waiters();
                return;
            }
        } else {
            idle_for = Duration::ZERO;
        }
    }
}
