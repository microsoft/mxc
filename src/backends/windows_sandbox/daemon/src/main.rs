//! Windows Sandbox state-aware daemon (host-side).
//!
//! The persistent host-side holder of a single state-aware Windows Sandbox.
//! Spawned (detached) by the backend's `start` phase, it:
//!   1. Reads the per-sandbox record for its `--token` to recover the
//!      filesystem-policy snapshot.
//!   2. Reconciles a running VM by *positive ownership proof*: tears one down
//!      only when a prior daemon record's recorded host-process identities
//!      intersect the live set; otherwise refuses to disturb a foreign VM.
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
//! Teardown is ownership-scoped: once the IPC port is bound, every exit path
//! removes the daemon record, and tears the VM down **whenever this daemon
//! actually issued the launch**. Exit paths that never launched a VM (pre-launch
//! setup failure, STOP before launch) deliberately skip teardown so they cannot
//! kill a VM this daemon did not start. There is no idle watchdog — a
//! state-aware sandbox is torn down only by explicit `stop` / `deprovision`.

mod control_server;

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::{Mutex, Notify};
use windows_sandbox_lifecycle::control_plane::{
    self, daemon_record_path, process_creation_time, DaemonRecord, MappedFolderRecord,
    RECORD_SCHEMA_VERSION,
};
use windows_sandbox_lifecycle::{bridge as tcp_bridge, rendezvous, vm as sandbox_vm};

use control_server::GuestSlot;

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

    // Ownership-based startup reconcile. A freshly-started daemon has not
    // launched a VM yet, so any running Windows Sandbox VM predates us. We tear
    // one down ONLY when we can positively prove it is our own orphan (a prior
    // daemon record whose recorded host-process identities intersect the live
    // set). Anything we cannot prove is ours — no prior record, a prior that
    // never reached `ready` (empty `vm_processes`), or a disjoint set — is
    // treated as foreign (e.g. a user's manually-opened sandbox) and left
    // untouched; we refuse to start rather than risk killing it.
    let prior = control_plane::read_daemon_record().ok().flatten();

    // Defensive: if the prior record describes a *still-live* daemon, another
    // daemon owns the slot. start() should have rejected before spawning us;
    // bail loudly (before binding IPC / launching) rather than disturb it.
    if let Some(p) = &prior {
        if control_plane::daemon_alive(p) {
            anyhow::bail!(
                "another live daemon (pid {}) already owns the slot; refusing",
                p.pid
            );
        }
    }

    // Enumeration failure is "unknown", not "no VM": fail safe by refusing
    // rather than proceeding blind into a launch that could either fail on the
    // single-instance limit or, worse, lead us to tear down a VM we cannot
    // account for.
    let current_vm = sandbox_vm::enumerate_sandbox_vm_processes()
        .await
        .context("enumerate running Windows Sandbox processes at startup")?;
    match control_plane::classify_startup(prior.as_ref(), &current_vm) {
        control_plane::StartupAction::Proceed => {}
        control_plane::StartupAction::ReclaimOrphan => {
            eprintln!(
                "[wsb-daemon] reclaiming our orphaned Windows Sandbox VM (process identity matched \
                 a prior daemon record); tearing it down"
            );
            sandbox_vm::teardown().await;
        }
        control_plane::StartupAction::RefuseForeign => {
            anyhow::bail!(
                "a Windows Sandbox VM is already running that mxc cannot prove it launched; \
                 refusing to disturb it. Close the existing sandbox and retry."
            );
        }
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
        // Populated once the VM is up and its host processes are known.
        vm_processes: Vec::new(),
    };
    control_plane::atomic_write_json(&daemon_record_path(), &starting)
        .context("write starting daemon record")?;

    // Tracks whether we actually issued the VM launch. The cleanup teardown is
    // gated on this so that exit paths which never launched a VM (pre-launch
    // setup failure, STOP before launch) do not blanket-kill a Windows Sandbox
    // VM — which, post-reconcile, could only be a user's concurrently-opened
    // sandbox, never ours.
    let we_launched = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // From here the IPC port is bound and a VM may come up, so guarantee
    // record removal on every exit path, and teardown whenever we launched.
    let outcome = serve(
        listener,
        &args.nonce,
        &sandbox_id,
        starting,
        &mapped,
        we_launched.clone(),
    )
    .await;

    if we_launched.load(std::sync::atomic::Ordering::SeqCst) {
        eprintln!("[wsb-daemon] tearing down our VM and clearing record");
        sandbox_vm::teardown().await;
    } else {
        eprintln!(
            "[wsb-daemon] no VM was launched by this daemon; clearing record without teardown"
        );
    }
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
    we_launched: Arc<std::sync::atomic::AtomicBool>,
) -> Result<()> {
    let shutdown = Arc::new(Notify::new());

    // The held guest connection, shared with the control server's EXEC handler.
    // It starts `Booting`: any EXEC that races the boot gets `ERR not ready`.
    let guest = Arc::new(Mutex::new(GuestSlot::Booting));

    // Serve IPC concurrently from the start so a STOP can abort the boot.
    let mut server = tokio::spawn(control_server::run(
        listener,
        nonce.to_string(),
        shutdown.clone(),
        guest.clone(),
    ));

    let (conn, addr) = tokio::select! {
        launched = launch_and_connect(mapped, &we_launched) => launched?,
        joined = &mut server => {
            // STOP (or a server error) arrived during boot. Propagate any
            // server error; otherwise return so `main` tears the (possibly
            // half-launched) VM down — gated on whether `launch_and_connect`
            // already issued the launch (recorded via `we_launched`).
            joined.context("control server task panicked")??;
            eprintln!("[wsb-daemon] STOP received during boot; aborting launch");
            return Ok(());
        }
    };
    eprintln!("[wsb-daemon] guest connected at {addr}");

    // Publish the live connection so EXEC requests can run on it.
    *guest.lock().await = GuestSlot::Ready { conn, addr };

    // The VM + guest are ready. Capture the VM host-process identities as our
    // positive ownership proof, then re-publish the record as ready so the
    // backend's start poll unblocks and a future daemon can reclaim only this
    // exact VM if we crash without tearing it down.
    record.vm_processes = match sandbox_vm::enumerate_sandbox_vm_processes().await {
        Ok(procs) => procs,
        Err(e) => {
            // Non-fatal: the VM is demonstrably up (guest connected). Proceed
            // with an empty proof set, but log it — a later daemon could not
            // prove ownership and would refuse rather than reclaim this VM.
            eprintln!("[wsb-daemon] WARNING: could not enumerate VM processes at ready: {e}");
            Vec::new()
        }
    };
    if record.vm_processes.is_empty() {
        eprintln!(
            "[wsb-daemon] WARNING: no Windows Sandbox host processes recorded at ready; \
             crash-reclaim of this VM will not be possible"
        );
    }
    record.ready = true;
    control_plane::atomic_write_json(&daemon_record_path(), &record)
        .context("write ready daemon record")?;
    eprintln!("[wsb-daemon] ready; holding {sandbox_id}");

    // Hold the guest connection alive while serving IPC until STOP.
    server.await.context("control server task panicked")??;

    eprintln!("[wsb-daemon] STOP received; releasing guest");
    // Dropping the slot drops the held GuestConnection, closing the guest
    // control channel (the guest exits the instant it drops).
    drop(guest);
    Ok(())
}

/// Launch the VM and connect to the guest agent. Returns the live connection
/// and the address it was reached at (needed to re-establish data streams
/// between executions).
///
/// Sets `we_launched` to `true` the instant the VM launch is issued, so the
/// caller's cleanup can scope teardown to a VM this daemon actually started.
async fn launch_and_connect(
    mapped: &[sandbox_vm::MappedFolder],
    we_launched: &std::sync::atomic::AtomicBool,
) -> Result<(tcp_bridge::GuestConnection, std::net::SocketAddr)> {
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
    // Mark that we are issuing the launch BEFORE the call: from here a VM may
    // exist that is ours, so the caller's cleanup must be allowed to tear it
    // down even if `launch` itself or any subsequent step returns an error.
    we_launched.store(true, std::sync::atomic::Ordering::SeqCst);
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

    Ok((conn, guest_addr))
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
