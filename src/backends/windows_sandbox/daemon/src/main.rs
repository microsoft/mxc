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
//!      until told to stop — while a watchdog concurrently polls for the VM's
//!      host processes, so if the sandbox is closed / crashes out from under the
//!      daemon, it stops holding a dead slot and exits (rather than answering
//!      PING/STOP and admitting EXECs against a half-dead connection).
//!
//! Teardown is ownership-scoped: once the IPC port is bound, every exit path
//! removes the daemon record, and tears the VM down **whenever this daemon
//! actually issued the launch**. Exit paths that never launched a VM (pre-launch
//! setup failure, STOP before launch) deliberately skip teardown so they cannot
//! kill a VM this daemon did not start. There is no *idle* watchdog — a healthy
//! state-aware sandbox is torn down only by explicit `stop` / `deprovision`; the
//! VM-crash watchdog fires only on confirmed VM death, never on mere idleness.

mod control_server;

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::{Mutex, Notify};
use windows_sandbox_lifecycle::control_plane::{
    self, process_creation_time, DaemonRecord, MappedFolderRecord, VmOwnership, VmProcId,
    RECORD_SCHEMA_VERSION,
};
use windows_sandbox_lifecycle::rendezvous::{
    GUEST_CONNECT_TIMEOUT, RENDEZVOUS_POLL_INTERVAL, RENDEZVOUS_TIMEOUT,
};
use windows_sandbox_lifecycle::{bridge as tcp_bridge, rendezvous, vm as sandbox_vm};

use control_server::GuestSlot;

/// Interval at which the VM-crash watchdog polls for live Windows Sandbox host
/// processes once the sandbox is `ready`.
const VM_WATCHDOG_POLL_INTERVAL_SECS: u64 = 5;

/// Number of *consecutive* polls that must confirm zero Windows Sandbox host
/// processes before the watchdog declares the VM gone. Requiring a streak (and
/// treating an enumeration error as "unknown", not "gone") prevents a transient
/// Toolhelp32 hiccup from shutting down a healthy daemon.
const VM_WATCHDOG_GONE_CONFIRMATIONS: u32 = 3;

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
        control_plane::StartupAction::ReclaimOrphan { proof } => {
            eprintln!(
                "[wsb-daemon] reclaiming our orphaned Windows Sandbox VM (prior daemon record's \
                 {} recorded host process identity/identities intersect the live set); tearing it \
                 down",
                proof.len()
            );
            // Seed teardown with the PRIOR recorded proof, NOT the live
            // snapshot. plan_kill_set then unions snapshot processes only
            // when at least one identity intersects — so any foreign
            // WindowsSandbox* process in the snapshot is excluded from the
            // kill set. (Review GPT catch: the previous design passed
            // &current_vm here, which promoted observed live processes into
            // "proof" once the daemon-side teardown gained an intersection
            // check.)
            let snapshot = current_vm.clone();
            let plan = control_plane::plan_kill_set(&VmOwnership::Owned(proof), &snapshot)
                .unwrap_or_default();
            let outcome = sandbox_vm::teardown_via_plan(&plan).await;
            match outcome {
                control_plane::TeardownOutcome::ConfirmedGone => {
                    eprintln!("[wsb-daemon] orphan reclaim confirmed gone");
                }
                control_plane::TeardownOutcome::StillRunning(remaining) => {
                    anyhow::bail!(
                        "orphan reclaim failed: {} WindowsSandbox* process(es) still alive after \
                         teardown ({:?}); refusing to start a daemon on top of a partially-torn-down \
                         VM",
                        remaining.len(),
                        remaining
                    );
                }
                control_plane::TeardownOutcome::ProbeFailed => {
                    anyhow::bail!(
                        "orphan reclaim could not confirm the VM is gone (liveness probe failed); \
                         refusing to start a daemon while VM state is unknown"
                    );
                }
            }
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
    //
    // The record carries the daemon's IPC nonce (`args.nonce`, which auths
    // wxc-exec phase processes to this daemon) and its localhost IPC port.
    // Both are persisted via [`control_plane::write_daemon_record`] under
    // an owner-only DACL — see `windows_sandbox_common::auth` for the
    // scope: this protects cross-user readers on a shared host but **does
    // not** protect against a same-user attacker (consistent with the
    // rest of the Windows Sandbox backend's single-user developer-
    // workstation threat model).
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
    control_plane::write_daemon_record(&starting).context("write starting daemon record")?;

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

    // Take a fresh snapshot of WindowsSandbox* host processes so the kill
    // planner can decide (per `plan_kill_set` semantics):
    //   - NotLaunched / LaunchInFlight       -> never kill
    //   - Owned(proof)                       -> proof ∪ snap-if-intersect, else proof
    //   - LaunchSucceededNoProof + non-empty -> snapshot (we provably hold the slot)
    //   - LaunchSucceededNoProof + empty     -> nothing to kill
    //
    // The record is removed ONLY on TeardownOutcome::ConfirmedGone (and on
    // the leak/noop branches where there is nothing to confirm). On
    // StillRunning / ProbeFailed the record persists so the next daemon's
    // classify_startup can reclaim by positive proof intersection.
    let snapshot = sandbox_vm::enumerate_sandbox_vm_processes()
        .await
        .unwrap_or_default();
    let ownership_now = ownership.lock().expect("ownership mutex poisoned").clone();
    let plan = control_plane::plan_kill_set(&ownership_now, &snapshot);
    let may_clear_record = match plan {
        None => {
            // NotLaunched / LaunchInFlight / LaunchSucceededNoProof + empty
            // snapshot. Nothing to kill. Removing the record is safe in the
            // first two cases (we never launched / we cannot prove anything).
            // For LaunchSucceededNoProof + empty snapshot, removing the
            // record matches the existing behaviour: there is no live VM and
            // no proof to preserve for reclaim.
            match &ownership_now {
                VmOwnership::NotLaunched => {
                    eprintln!("[wsb-daemon] no VM was launched by this daemon; clearing record");
                }
                VmOwnership::LaunchInFlight => {
                    eprintln!(
                        "[wsb-daemon] WARNING: a VM launch was issued but ownership was never \
                         proven; leaving any running VM untouched (fail-safe) and clearing record"
                    );
                }
                VmOwnership::LaunchSucceededNoProof => {
                    eprintln!(
                        "[wsb-daemon] no live WindowsSandbox* processes after launch-succeeded; \
                         clearing record (nothing to reclaim)"
                    );
                }
                VmOwnership::Owned(_) => unreachable!("Owned with snapshot always plans a kill"),
            }
            true
        }
        Some(kill) => {
            eprintln!(
                "[wsb-daemon] tearing down our VM ({} target process(es))",
                kill.len()
            );
            let outcome = sandbox_vm::teardown_via_plan(&kill).await;
            match &outcome {
                control_plane::TeardownOutcome::ConfirmedGone => {
                    eprintln!("[wsb-daemon] teardown confirmed VM gone; clearing record");
                    true
                }
                control_plane::TeardownOutcome::StillRunning(remaining) => {
                    eprintln!(
                        "[wsb-daemon] WARNING: teardown timed out with {} WindowsSandbox* \
                         process(es) still alive ({:?}); preserving record for next daemon to \
                         reclaim",
                        remaining.len(),
                        remaining
                    );
                    false
                }
                control_plane::TeardownOutcome::ProbeFailed => {
                    eprintln!(
                        "[wsb-daemon] WARNING: liveness probe failed during teardown; preserving \
                         record for next daemon to reclaim"
                    );
                    false
                }
            }
        }
    };
    if may_clear_record {
        let _ = control_plane::remove_daemon_record();
    }
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

    // Per-launch authentication nonce for the daemon<->guest TCP channel.
    // Distinct from the daemon's IPC nonce (`nonce` arg above, which auths
    // wxc-exec phase processes to this daemon); this one auths the daemon
    // to the in-VM guest agent on every accept. Generated once per VM
    // lifetime, written to the rendezvous folder for the guest to pick up
    // (and immediately delete), and re-used on every post-StreamsReady data
    // stream reconnect. See review C2.
    let guest_nonce = Arc::new(windows_sandbox_common::auth::generate_nonce());

    // The held guest connection, shared with the control server's EXEC handler.
    // It starts `Booting`: any EXEC that races the boot gets `ERR not ready`.
    let guest = Arc::new(Mutex::new(GuestSlot::Booting));

    // Serve IPC concurrently from the start so a STOP can abort the boot.
    let mut server = tokio::spawn(control_server::run(
        listener,
        nonce.to_string(),
        shutdown.clone(),
        guest.clone(),
        guest_nonce.clone(),
    ));

    let (conn, addr) = tokio::select! {
        launched = launch_and_connect(mapped, &ownership, &mut record, &guest_nonce) => launched?,
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
    control_plane::write_daemon_record(&record).context("write ready daemon record")?;
    eprintln!("[wsb-daemon] ready; holding {sandbox_id}");

    // Hold the guest connection alive while serving IPC until either an
    // explicit STOP arrives (the control server task returns) OR the VM dies
    // under us (the crash watchdog fires). Racing the two means a sandbox that
    // is closed / crashes is not held as a dead slot answering PING/STOP and
    // admitting EXECs against a half-dead connection.
    tokio::select! {
        joined = &mut server => {
            joined.context("control server task panicked")??;
            eprintln!("[wsb-daemon] STOP received; releasing guest");
        }
        reason = vm_crash_watchdog(record.vm_processes.clone()) => {
            eprintln!("[wsb-daemon] {reason}; shutting down (the VM is gone)");
            // Best-effort: poison the slot so a racing/next EXEC fails fast with
            // a clear reason instead of dispatching to a dead guest. Use a
            // non-blocking lock — if an exec is mid-flight it holds the lock and
            // will itself poison the slot when its guest I/O fails, so we must
            // not block shutdown waiting on it.
            if let Ok(mut slot) = guest.try_lock() {
                *slot = GuestSlot::Poisoned(reason);
            }
            // Tell the control server to stop accepting and reap its task.
            shutdown.notify_one();
            let _ = (&mut server).await;
        }
    }

    // Dropping the slot drops the held GuestConnection, closing the guest
    // control channel (the guest exits the instant it drops).
    drop(guest);
    Ok(())
}

/// Watch for unexpected death of the Windows Sandbox VM this daemon holds.
///
/// Polls every [`VM_WATCHDOG_POLL_INTERVAL_SECS`] and resolves (with a
/// human-readable reason) only once [`VM_WATCHDOG_GONE_CONFIRMATIONS`]
/// *consecutive* polls confirm the VM is gone.
///
/// Detection is **identity-based**: the VM is considered gone once none of the
/// `owned` host-process identities (pid + creation_time, captured at ready)
/// remain live. The `WindowsSandboxServer` / `WindowsSandboxRemoteSession` host
/// processes live for the whole life of the VM, so this never false-fires on a
/// healthy VM, and — because Windows Sandbox is single-instance — a *foreign*
/// replacement VM that appears after ours crashed has different identities and
/// therefore cannot mask our VM's death (a prefix-only check could). If no
/// ownership proof was recorded (degraded), fall back to prefix liveness so a
/// crash is still detectable without false-firing on a healthy VM.
///
/// Fail-safe posture: an enumeration error is treated as "unknown" — it resets
/// the streak and never counts as "gone" — so a transient Toolhelp32 hiccup
/// cannot tear down a healthy daemon. Never resolves while the VM is alive, so
/// an idle-but-healthy sandbox is held until an explicit STOP.
async fn vm_crash_watchdog(owned: Vec<VmProcId>) -> String {
    let interval = std::time::Duration::from_secs(VM_WATCHDOG_POLL_INTERVAL_SECS);
    let mut gone_streak = 0u32;
    loop {
        tokio::time::sleep(interval).await;
        // `None` = enumeration failed (unknown); `Some(live)` = the live set.
        let live = sandbox_vm::enumerate_sandbox_vm_processes().await.ok();
        gone_streak = advance_watchdog_streak(&owned, live.as_deref(), gone_streak);
        if gone_streak >= VM_WATCHDOG_GONE_CONFIRMATIONS {
            return "Windows Sandbox VM exited unexpectedly (host processes gone)".to_string();
        }
    }
}

/// Pure streak-advance step for [`vm_crash_watchdog`]. Extracted so the
/// security-sensitive decision logic (identity match, prefix fallback, error
/// reset) is unit-testable without Win32 enumeration.
///
/// - `live = None` means enumeration failed → "unknown": reset the streak (an
///   error never counts as "gone").
/// - With a recorded `owned` proof, the VM is "gone" for this poll only when
///   NONE of the owned identities remain in `live` (a foreign single-instance
///   replacement VM has different identities and cannot mask our VM's death).
/// - With no `owned` proof (degraded), fall back to prefix liveness: "gone"
///   only when `live` is empty.
///
/// Returns the next streak count; the caller fires once it reaches the
/// confirmation threshold.
fn advance_watchdog_streak(owned: &[VmProcId], live: Option<&[VmProcId]>, streak: u32) -> u32 {
    let Some(live) = live else {
        // Enumeration failed: unknown — never count as gone.
        return 0;
    };
    let gone = if owned.is_empty() {
        live.is_empty()
    } else {
        !owned.iter().any(|p| live.contains(p))
    };
    if gone {
        streak + 1
    } else {
        0
    }
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
    guest_nonce: &windows_sandbox_common::auth::Nonce,
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

    // The nonce-write + launch + capture-proof + rendezvous + connect
    // sequence is shared with one_shot::drive via vm::launch_managed_vm
    // (review M7 DRY). The daemon's per-caller bookkeeping wires up:
    //   - ownership: the long-lived Arc<Mutex<VmOwnership>> that the
    //     daemon's cleanup path reads at exit;
    //   - persist_proof: write the daemon record on disk so a crashed
    //     daemon's orphan VM can be reclaimed by a later daemon's
    //     startup classifier.
    let mut observer = DaemonLaunchObserver { ownership, record };
    sandbox_vm::launch_managed_vm(
        &wsb_path,
        &rendezvous_dir,
        guest_nonce,
        RENDEZVOUS_TIMEOUT,
        RENDEZVOUS_POLL_INTERVAL,
        GUEST_CONNECT_TIMEOUT,
        &mut observer,
    )
    .await
}

/// Daemon's [`sandbox_vm::LaunchObserver`] adapter. Sibling of
/// `one_shot::OneShotLaunchObserver` -- see [`sandbox_vm::launch_managed_vm`]
/// docs for the shared sequence and the per-caller seam rationale
/// (review M7 DRY).
struct DaemonLaunchObserver<'a> {
    ownership: &'a Arc<std::sync::Mutex<VmOwnership>>,
    record: &'a mut DaemonRecord,
}

impl<'a> sandbox_vm::LaunchObserver for DaemonLaunchObserver<'a> {
    fn set_ownership(&mut self, state: VmOwnership) {
        *self.ownership.lock().expect("ownership mutex poisoned") = state;
    }

    fn persist_proof(&mut self, proof: &[control_plane::VmProcId]) -> Result<()> {
        self.record.vm_processes = proof.to_vec();
        control_plane::write_daemon_record(self.record)
            .context("persist after-launch ownership proof record")
    }

    fn note_empty_proof(&self) {
        eprintln!(
            "[wsb-daemon] WARNING: no Windows Sandbox host processes appeared after launch; \
             a crash before ready would leave this VM unreclaimable"
        );
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(pid: u32, creation_time: u64) -> VmProcId {
        VmProcId { pid, creation_time }
    }

    #[test]
    fn streak_resets_on_enumeration_error() {
        let owned = vec![proc(100, 1)];
        // A failed enumeration ("unknown") must never count as gone, even at a
        // high prior streak — it resets to 0.
        assert_eq!(advance_watchdog_streak(&owned, None, 2), 0);
    }

    #[test]
    fn streak_increments_only_when_all_owned_identities_absent() {
        let owned = vec![proc(100, 1), proc(101, 2)];
        // Owned proc still live → not gone → reset.
        assert_eq!(advance_watchdog_streak(&owned, Some(&[proc(100, 1)]), 2), 0);
        // None of the owned identities live → gone → increment.
        assert_eq!(advance_watchdog_streak(&owned, Some(&[]), 2), 3);
    }

    #[test]
    fn pid_reuse_with_different_creation_time_counts_as_gone() {
        let owned = vec![proc(100, 1)];
        // Same PID recycled to a different process (creation_time differs) is
        // NOT our process → the VM is gone.
        assert_eq!(
            advance_watchdog_streak(&owned, Some(&[proc(100, 999)]), 0),
            1
        );
    }

    #[test]
    fn foreign_replacement_vm_cannot_mask_our_death() {
        let owned = vec![proc(100, 1), proc(101, 2)];
        // Our VM died and a foreign single-instance VM took its place with new
        // identities. Identity-based detection still counts our VM as gone.
        let foreign = [proc(500, 50), proc(501, 51)];
        assert_eq!(advance_watchdog_streak(&owned, Some(&foreign), 0), 1);
    }

    #[test]
    fn degraded_no_proof_falls_back_to_prefix_liveness() {
        let owned: Vec<VmProcId> = vec![];
        // With no recorded proof, any live WSB host process means not-gone.
        assert_eq!(advance_watchdog_streak(&owned, Some(&[proc(7, 7)]), 1), 0);
        // Empty live set means gone.
        assert_eq!(advance_watchdog_streak(&owned, Some(&[]), 1), 2);
    }

    #[test]
    fn consecutive_gone_polls_reach_confirmation_threshold() {
        let owned = vec![proc(100, 1)];
        let mut streak = 0u32;
        for _ in 0..VM_WATCHDOG_GONE_CONFIRMATIONS {
            streak = advance_watchdog_streak(&owned, Some(&[]), streak);
        }
        assert!(streak >= VM_WATCHDOG_GONE_CONFIRMATIONS);
    }

    #[test]
    fn a_single_live_poll_resets_an_in_progress_streak() {
        let owned = vec![proc(100, 1)];
        // Two gone polls, then a live poll wipes the streak (must require a
        // fresh consecutive run), then an error also keeps it at 0.
        let s = advance_watchdog_streak(&owned, Some(&[]), 0);
        let s = advance_watchdog_streak(&owned, Some(&[]), s);
        assert_eq!(s, 2);
        let s = advance_watchdog_streak(&owned, Some(&[proc(100, 1)]), s);
        assert_eq!(s, 0);
    }
}
