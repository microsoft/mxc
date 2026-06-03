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
    self, daemon_record_path, decide_cleanup, process_creation_time, CleanupAction, DaemonRecord,
    MappedFolderRecord, VmOwnership, RECORD_SCHEMA_VERSION,
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

/// Bounded wait to acquire the host VM-slot mutex at startup. On contention
/// (another VM owner holds it) the daemon bails rather than block. Generous
/// enough to ride out a previous owner's teardown but not so long as to wedge.
const HOST_VM_LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// Parsed daemon command-line arguments.
struct Args {
    token: String,
    nonce: String,
}

/// Upper bound on the auth nonce read from stdin. The nonce the backend
/// generates is a short hex token; cap the read defensively so a wedged or
/// hostile parent cannot stream an unbounded line into the daemon at startup.
const MAX_NONCE_LEN: usize = 256;

/// Read the auth nonce from the daemon's stdin (first line, trimmed).
///
/// The nonce is passed over stdin rather than on the command line so it is not
/// observable cross-process via the PEB / `Win32_Process` command line. The
/// parent writes `"<nonce>\n"` then closes the pipe; we read a single bounded
/// line. An empty or oversized nonce is rejected.
fn read_nonce_from_stdin() -> Result<String> {
    use std::io::Read;
    let mut buf = Vec::with_capacity(MAX_NONCE_LEN);
    let mut byte = [0u8; 1];
    let mut stdin = std::io::stdin().lock();
    loop {
        match stdin
            .read(&mut byte)
            .context("read nonce byte from stdin")?
        {
            0 => break, // EOF before newline; accept what we have.
            _ => {
                if byte[0] == b'\n' {
                    break;
                }
                if buf.len() >= MAX_NONCE_LEN {
                    anyhow::bail!("auth nonce on stdin exceeds {MAX_NONCE_LEN} bytes");
                }
                buf.push(byte[0]);
            }
        }
    }
    let nonce = String::from_utf8(buf)
        .context("auth nonce on stdin is not valid UTF-8")?
        .trim()
        .to_string();
    if nonce.is_empty() {
        anyhow::bail!("auth nonce on stdin is empty");
    }
    Ok(nonce)
}

fn parse_args() -> Result<String> {
    let mut token = None;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--token" => token = it.next(),
            other => anyhow::bail!("unexpected daemon argument {:?}", other),
        }
    }
    token.context("--token is required")
}

#[tokio::main]
async fn main() -> Result<()> {
    let token = parse_args()?;
    // Receive the auth nonce over stdin (kept off argv so it is not readable
    // cross-process via the command line). The parent writes it immediately
    // after spawn and closes the pipe.
    let nonce = read_nonce_from_stdin()?;
    let args = Args { token, nonce };
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

    // Acquire the host VM-slot mutex for the daemon's whole life. The host
    // permits a single running Windows Sandbox VM; holding this for our entire
    // lifetime serialises us against a concurrent one-shot run (which holds the
    // same mutex), so the two modes can never both launch / own the singleton
    // VM. A modest timeout bounds the wait; on contention we bail rather than
    // block indefinitely. Held until `main` returns (after teardown).
    let _vm_lock = control_plane::HostVmLock::acquire(HOST_VM_LOCK_TIMEOUT)
        .context("acquire host Windows Sandbox VM slot")?;

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
            sandbox_vm::teardown_owned(&current_vm).await;
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

    // Tracks how far VM ownership has progressed within this daemon. The
    // cleanup path derives its teardown decision purely from this state
    // (`decide_cleanup`) so it never tears down a VM it cannot prove it owns:
    //   - `NotLaunched`           -> no launch issued (setup failure / STOP early)
    //   - `LaunchInFlight`        -> launch in flight, outcome unknown
    //                                (a foreign VM could have won the contest)
    //                                -> leak, never kill
    //   - `LaunchSucceededNoProof`-> launch returned Ok (VM is ours) but no
    //                                host-process proof yet -> teardown by
    //                                enumeration
    //   - `Owned(pids)`           -> launched and proven ours -> scoped teardown
    let ownership = Arc::new(std::sync::Mutex::new(VmOwnership::NotLaunched));

    // From here the IPC port is bound and a VM may come up, so guarantee
    // record removal on every exit path, and teardown only what we own.
    let outcome = serve(
        listener,
        &args.nonce,
        &sandbox_id,
        starting,
        &mapped,
        ownership.clone(),
    )
    .await;

    let action = decide_cleanup(&ownership.lock().expect("ownership mutex poisoned"));
    match action {
        CleanupAction::Noop => {
            eprintln!("[wsb-daemon] no VM was launched by this daemon; clearing record");
        }
        CleanupAction::LeakUnowned => {
            // A launch was issued but never proven ours. A VM may exist, but we
            // cannot prove we own it (a foreign sandbox could have won the
            // single-instance contest and failed our launch), so we must NOT
            // kill it. Fail safe: leave it for the operator / next reconcile.
            eprintln!(
                "[wsb-daemon] WARNING: a VM launch was issued but ownership was never proven; \
                 leaving any running VM untouched (fail-safe) and clearing record"
            );
        }
        CleanupAction::Teardown(pids) => {
            eprintln!(
                "[wsb-daemon] tearing down our VM ({} recorded process(es)) and clearing record",
                pids.len()
            );
            sandbox_vm::teardown_owned(&pids).await;
        }
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
    ownership: Arc<std::sync::Mutex<VmOwnership>>,
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
        launched = launch_and_connect(mapped, &ownership, &mut record) => launched?,
        joined = &mut server => {
            // STOP (or a server error) arrived during boot. Propagate any
            // server error; otherwise return so `main` tears the (possibly
            // half-launched) VM down — scoped to whatever ownership state
            // `launch_and_connect` reached before the abort.
            joined.context("control server task panicked")??;
            eprintln!("[wsb-daemon] STOP received during boot; aborting launch");
            return Ok(());
        }
    };
    eprintln!("[wsb-daemon] guest connected at {addr}");

    // Publish the live connection so EXEC requests can run on it.
    *guest.lock().await = GuestSlot::Ready { conn, addr };

    // The VM + guest are ready. Refresh the VM host-process proof (it was first
    // captured right after launch, inside `launch_and_connect`). Keep the
    // after-launch proof as a fallback if this enumeration fails so the record
    // — and the in-memory ownership — never regress to empty.
    match sandbox_vm::enumerate_sandbox_vm_processes().await {
        Ok(procs) if !procs.is_empty() => {
            record.vm_processes = procs.clone();
            *ownership.lock().expect("ownership mutex poisoned") = VmOwnership::Owned(procs);
        }
        Ok(_) => {
            eprintln!(
                "[wsb-daemon] WARNING: no Windows Sandbox host processes at ready; \
                 keeping after-launch proof ({} process(es))",
                record.vm_processes.len()
            );
        }
        Err(e) => {
            eprintln!(
                "[wsb-daemon] WARNING: could not enumerate VM processes at ready: {e}; \
                 keeping after-launch proof ({} process(es))",
                record.vm_processes.len()
            );
        }
    }
    if record.vm_processes.is_empty() {
        eprintln!(
            "[wsb-daemon] WARNING: no Windows Sandbox host processes recorded; \
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
/// Drives the ownership state machine and writes the durable proof record:
///   1. Before issuing the launch, transition to `LaunchInFlight` (ambiguous:
///      a foreign VM could win the single-instance contest and fail us).
///   2. The instant `launch()` returns Ok, transition to
///      `LaunchSucceededNoProof` — the VM is ours by the single-instance
///      invariant — so cleanup tears it down even if proof is slow / we are
///      cancelled before proof.
///   3. Poll briefly for the VM's host processes; on success stamp them into
///      `record.vm_processes`, atomically re-write the (still `ready:false`)
///      record so a crash during the multi-minute rendezvous wait leaves a
///      *reclaimable* record, and transition to `Owned(proof)`. A failure to
///      persist the proof is fatal (returns an error) so cleanup tears the VM
///      down via the in-memory proof rather than orphaning it.
async fn launch_and_connect(
    mapped: &[sandbox_vm::MappedFolder],
    ownership: &Arc<std::sync::Mutex<VmOwnership>>,
    record: &mut DaemonRecord,
) -> Result<(tcp_bridge::GuestConnection, std::net::SocketAddr)> {
    let exe_dir = std::env::current_exe()
        .context("current_exe")?
        .parent()
        .context("exe parent dir")?
        .to_path_buf();

    let rendezvous_dir = std::env::temp_dir().join("wxc-wsb-stateaware-rendezvous");
    std::fs::create_dir_all(&rendezvous_dir).context("create rendezvous dir")?;
    control_plane::set_owner_only_dir(&rendezvous_dir).context("secure rendezvous dir")?;
    rendezvous::cleanup(&rendezvous_dir).await?;

    let python_dir = sandbox_vm::find_host_python()
        .context("Python is required on the host for sandbox execution")?;

    let config_dir = std::env::temp_dir().join("wxc-wsb-stateaware-config");
    std::fs::create_dir_all(&config_dir).context("create .wsb config dir")?;
    control_plane::set_owner_only_dir(&config_dir).context("secure .wsb config dir")?;

    let wsb_path =
        sandbox_vm::generate_wsb(&exe_dir, &rendezvous_dir, &python_dir, &config_dir, mapped)?;
    // Mark the launch as in flight BEFORE the call. If we are cancelled here or
    // `launch()` errors, ownership is ambiguous (a foreign VM could have won
    // the single-instance contest), so cleanup must leak rather than kill.
    *ownership.lock().expect("ownership mutex poisoned") = VmOwnership::LaunchInFlight;
    sandbox_vm::launch(&wsb_path).await.context("launch VM")?;

    // `launch()` returned Ok: by the OS single-instance guarantee plus startup
    // reconcile, the running VM is ours. Record that immediately so even if the
    // host processes are slow to appear (or we are cancelled before proof),
    // cleanup tears the VM down by enumeration instead of leaking it.
    *ownership.lock().expect("ownership mutex poisoned") = VmOwnership::LaunchSucceededNoProof;

    // Capture ownership proof now, before the long rendezvous wait. Persist it
    // into the (still not-ready) record so a crash mid-boot leaves a
    // reclaimable orphan record. If we cannot persist the proof, tear the VM
    // down now (we still hold in-memory proof) rather than risk a durable-less
    // orphan: surface the error so `main`'s cleanup runs scoped teardown.
    let proof = sandbox_vm::capture_launch_proof().await;
    if proof.is_empty() {
        eprintln!(
            "[wsb-daemon] WARNING: no Windows Sandbox host processes appeared after launch; \
             a crash before ready would leave this VM unreclaimable"
        );
    } else {
        record.vm_processes = proof.clone();
        *ownership.lock().expect("ownership mutex poisoned") = VmOwnership::Owned(proof);
        control_plane::atomic_write_json(&daemon_record_path(), record)
            .context("persist after-launch ownership proof record")?;
    }

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
