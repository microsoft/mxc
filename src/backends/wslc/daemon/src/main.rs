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
//! 3. Publish a `daemon.json` record with `ready = false` so a racing client can
//!    discover us but knows not to send work yet.
//! 4. Start the control server; once it is listening, flip the record to
//!    `ready = true`.
//! 5. Run an idle watchdog: when the live-container count stays at zero past the
//!    idle timeout, shut down.
//! 6. On exit, remove the record.

mod control_server;
mod session_manager;

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
    let pid_creation_time = process_creation_time(pid).unwrap_or(0);
    let pipe_name = mint_pipe_name();

    let session = session_manager::spawn().context("spawn WSLc session worker")?;

    // Publish a not-yet-ready record so a racing client can find us but waits.
    let mut record = DaemonRecord {
        schema_version: RECORD_SCHEMA_VERSION,
        pid,
        pid_creation_time,
        pipe_name: pipe_name.clone(),
        ready: false,
        protocol_version: PROTOCOL_VERSION,
    };
    write_daemon_record(&record).context("publish initial daemon record")?;

    let shutdown = Arc::new(Notify::new());

    // Start the control server. It creates the first pipe instance eagerly, so
    // once `spawn` returns the pipe exists and clients can connect.
    let server = tokio::spawn(control_server::run(
        session.clone(),
        pipe_name.clone(),
        shutdown.clone(),
    ));

    // Flip the record to ready now that the pipe is being served.
    record.ready = true;
    write_daemon_record(&record).context("publish ready daemon record")?;

    // Idle watchdog: exit after IDLE_TIMEOUT with no live containers.
    let watchdog = tokio::spawn(idle_watchdog(session.clone(), shutdown.clone()));

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

/// Poll the live-container count; once it has been zero for `IDLE_TIMEOUT`,
/// notify shutdown.
async fn idle_watchdog(session: session_manager::SessionHandle, shutdown: Arc<Notify>) {
    let mut idle_for = Duration::ZERO;
    loop {
        tokio::time::sleep(IDLE_POLL).await;
        match session.container_count().await {
            Ok(0) => {
                idle_for += IDLE_POLL;
                if idle_for >= IDLE_TIMEOUT {
                    shutdown.notify_waiters();
                    return;
                }
            }
            Ok(_) => idle_for = Duration::ZERO,
            Err(_) => {
                // Worker gone: nothing left to serve.
                shutdown.notify_waiters();
                return;
            }
        }
    }
}
