//! Windows Sandbox state-aware daemon (host-side).
//!
//! The persistent host-side holder of a single state-aware Windows Sandbox.
//! Spawned (detached) by the backend's `start` phase, it:
//!   1. Reads the per-sandbox record for its `--token` to recover the
//!      filesystem-policy snapshot.
//!   2. Reconciles any orphaned VM (single-instance host).
//!   3. Binds an OS-assigned localhost IPC port and **immediately** publishes a
//!      `ready:false` global `daemon.json` record — claiming the single-instance
//!      slot before the VM exists and serving IPC throughout boot so a `STOP`
//!      can gracefully abort an in-flight launch.
//!   4. Launches the VM with the snapshotted mapped folders, waits for the guest
//!      to advertise its address, and connects the guest control channel — which
//!      it holds open for the sandbox's whole lifetime (the guest exits the
//!      instant that connection drops).
//!   5. Re-publishes the record as `ready:true`, then serves `PING` / `STOP`
//!      until told to stop.
//!
//! Teardown is guaranteed: once the IPC port is bound, **every** exit path
//! (graceful STOP, launch failure, record-write failure, IPC error) tears the
//! VM down and removes the daemon record, so a live VM is never orphaned by a
//! daemon that is about to die. There is no idle watchdog — a state-aware
//! sandbox is torn down only by explicit `stop` / `deprovision`.

mod control_server;

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::Notify;
use windows_sandbox_lifecycle::control_plane::{
    self, daemon_record_path, process_creation_time, DaemonRecord, MappedFolderRecord,
    RECORD_SCHEMA_VERSION,
};
use windows_sandbox_lifecycle::{bridge as tcp_bridge, rendezvous, vm as sandbox_vm};

/// Maximum time to wait for the guest agent's rendezvous file. First VM boot
/// can take several minutes; 360s covers worst-case cold starts.
const RENDEZVOUS_TIMEOUT_SECS: u64 = 360;

/// Polling interval when checking for the rendezvous file.
const RENDEZVOUS_POLL_INTERVAL_MS: u64 = 500;

/// Maximum time to connect to the guest agent after rendezvous.
const GUEST_CONNECT_TIMEOUT_SECS: u64 = 30;

/// Parsed daemon command-line arguments.
struct Args {
    token: String,
    nonce: String,
}

fn parse_args() -> Result<Args> {
    let mut token = None;
    let mut nonce = None;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--token" => token = it.next(),
            "--nonce" => nonce = it.next(),
            other => anyhow::bail!("unexpected daemon argument {:?}", other),
        }
    }
    Ok(Args {
        token: token.context("--token is required")?,
        nonce: nonce.context("--nonce is required")?,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args()?;
    eprintln!(
        "[wsb-daemon] starting for token={} (pid={})",
        args.token,
        std::process::id()
    );

    // Recover the provisioned filesystem-policy snapshot.
    let record = control_plane::read_sandbox_record(&args.token)
        .context("read sandbox record")?
        .with_context(|| format!("no provisioned record for token {}", args.token))?;
    let sandbox_id = record.sandbox_id.clone();
    let mapped = to_mapped_folders(&record.mapped_folders);

    // Best-effort orphan reconciliation. A freshly-started daemon cannot own an
    // existing Windows Sandbox VM — we have not launched one yet. A live VM at
    // this point is an orphan from a previous daemon that died without tearing
    // down, and would block our launch with "Only one running instance of
    // Windows Sandbox is allowed". Because this backend requires exclusive
    // ownership of the single WSB slot, we tear it down before launching.
    if sandbox_vm::is_sandbox_vm_running().await {
        eprintln!(
            "[wsb-daemon] WARNING: a live Windows Sandbox VM was found at startup that we did not \
             launch; tearing it down to reclaim the single-instance slot"
        );
        sandbox_vm::teardown().await;
    }

    // Bind the IPC control channel on an OS-assigned localhost port BEFORE
    // launching the VM, so the record we publish next carries a reachable port
    // and a STOP can abort an in-flight boot.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind daemon IPC")?;
    let ipc_port = listener.local_addr().context("ipc local_addr")?.port();
    eprintln!("[wsb-daemon] IPC listening on 127.0.0.1:{ipc_port}");

    let pid = std::process::id();
    let pid_creation_time =
        process_creation_time(pid).context("query own process creation time")?;

    // Publish the `ready:false` record now: this claims the single-instance
    // slot for `sandbox_id` from this instant (defeating a double-spawn race),
    // even though the VM is not up yet.
    let starting = DaemonRecord {
        schema_version: RECORD_SCHEMA_VERSION,
        pid,
        pid_creation_time,
        ipc_port,
        nonce: args.nonce.clone(),
        active_sandbox_id: sandbox_id.clone(),
        ready: false,
    };
    control_plane::atomic_write_json(&daemon_record_path(), &starting)
        .context("write starting daemon record")?;

    // From here the IPC port is bound and a VM may come up, so guarantee
    // teardown + record removal on every exit path.
    let outcome = serve(listener, &args.nonce, &sandbox_id, starting, &mapped).await;

    eprintln!("[wsb-daemon] tearing down VM and clearing record");
    sandbox_vm::teardown().await;
    let _ = std::fs::remove_file(daemon_record_path());
    eprintln!("[wsb-daemon] exiting");
    outcome
}

/// Run the daemon's serving lifetime: launch the VM (cancellable by a STOP that
/// arrives mid-boot), publish the `ready:true` record, then hold the guest
/// connection and serve IPC until STOP. Any error here propagates to `main`,
/// which performs the guaranteed teardown.
async fn serve(
    listener: tokio::net::TcpListener,
    nonce: &str,
    sandbox_id: &str,
    mut record: DaemonRecord,
    mapped: &[sandbox_vm::MappedFolder],
) -> Result<()> {
    let shutdown = Arc::new(Notify::new());

    // Serve IPC concurrently from the start so a STOP can abort the boot.
    let mut server = tokio::spawn(control_server::run(
        listener,
        nonce.to_string(),
        shutdown.clone(),
    ));

    let guest = tokio::select! {
        launched = launch_and_connect(mapped) => launched?,
        joined = &mut server => {
            // STOP (or a server error) arrived during boot. Propagate any
            // server error; otherwise return so `main` tears the (possibly
            // half-launched) VM down.
            joined.context("control server task panicked")??;
            eprintln!("[wsb-daemon] STOP received during boot; aborting launch");
            return Ok(());
        }
    };
    eprintln!("[wsb-daemon] guest connected at {}", guest.addr);

    // The VM + guest are ready. Re-publish the record as ready so the backend's
    // start poll unblocks.
    record.ready = true;
    control_plane::atomic_write_json(&daemon_record_path(), &record)
        .context("write ready daemon record")?;
    eprintln!("[wsb-daemon] ready; holding {sandbox_id}");

    // Hold the guest connection alive while serving IPC until STOP.
    server.await.context("control server task panicked")??;

    eprintln!("[wsb-daemon] STOP received; releasing guest");
    drop(guest);
    Ok(())
}

/// A live guest connection plus the address it was reached at. Holding this
/// keeps the guest's control channel open (the guest exits when it drops).
struct HeldGuest {
    _conn: tcp_bridge::GuestConnection,
    addr: std::net::SocketAddr,
}

/// Launch the VM and connect to the guest agent. Returns the held connection.
async fn launch_and_connect(mapped: &[sandbox_vm::MappedFolder]) -> Result<HeldGuest> {
    let exe_dir = std::env::current_exe()
        .context("current_exe")?
        .parent()
        .context("exe parent dir")?
        .to_path_buf();

    let rendezvous_dir = std::env::temp_dir().join("wxc-wsb-stateaware-rendezvous");
    std::fs::create_dir_all(&rendezvous_dir).context("create rendezvous dir")?;
    rendezvous::cleanup(&rendezvous_dir).await?;

    let python_dir = sandbox_vm::find_host_python()
        .context("Python is required on the host for sandbox execution")?;

    let config_dir = std::env::temp_dir().join("wxc-wsb-stateaware-config");
    std::fs::create_dir_all(&config_dir).context("create .wsb config dir")?;

    let wsb_path =
        sandbox_vm::generate_wsb(&exe_dir, &rendezvous_dir, &python_dir, &config_dir, mapped)?;
    sandbox_vm::launch(&wsb_path).await.context("launch VM")?;

    let guest_addr = rendezvous::wait_for_rendezvous(
        &rendezvous_dir,
        std::time::Duration::from_secs(RENDEZVOUS_TIMEOUT_SECS),
        std::time::Duration::from_millis(RENDEZVOUS_POLL_INTERVAL_MS),
    )
    .await
    .context("rendezvous failed")?;

    let conn = tcp_bridge::connect_to_guest(
        guest_addr,
        std::time::Duration::from_secs(GUEST_CONNECT_TIMEOUT_SECS),
    )
    .await
    .context("connect to guest agent")?;

    Ok(HeldGuest {
        _conn: conn,
        addr: guest_addr,
    })
}

/// Convert the durable record's mapped-folder snapshot into the VM type.
fn to_mapped_folders(records: &[MappedFolderRecord]) -> Vec<sandbox_vm::MappedFolder> {
    records
        .iter()
        .map(|m| sandbox_vm::MappedFolder {
            host: m.host.clone(),
            sandbox: m.sandbox.clone(),
            read_only: m.read_only,
        })
        .collect()
}
