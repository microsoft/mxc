// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Process-level cleanup so containers don't leak when `lxc-exec` is killed.
//!
//! `LxcScriptRunner::run_internal` calls `container.destroy()` after
//! `attach_run` returns, but if the runner is killed by SIGHUP/SIGTERM/SIGINT
//! (its parent exited or sent a kill) the in-flight `attach_run` is
//! interrupted and the destroy block is never reached. The container then
//! survives the runner and shows up forever in `lxc-ls`.
//!
//! This module installs a watchdog thread that synchronously waits for those
//! signals via `sigwait`, destroys whichever container the runner most
//! recently announced as active, and exits with `128 + signo` so the parent
//! observes a normal signal-style exit.

use std::sync::{Mutex, OnceLock};

#[cfg(target_os = "linux")]
use std::thread;

#[cfg(target_os = "linux")]
use nix::sys::signal::{SigSet, Signal};

#[cfg(target_os = "linux")]
use crate::lxc_bindings::LxcContainer;
#[cfg(target_os = "linux")]
use crate::network_ingress::IngressManager;
use crate::network_iptables::CreatedResources;
#[cfg(target_os = "linux")]
use crate::network_iptables::{EgressHookPoint, NetworkIptablesManager};
#[cfg(target_os = "linux")]
use wxc_common::logger::{Logger, Mode};

/// What the watchdog needs to roll back on a fatal signal: the container
/// name (so we can `lxc-destroy` it), the host-side veth interface when
/// known (so we can also remove the iptables FORWARD hook the runner
/// installed against it), the set of egress chains and hooks the runner has
/// actually created so far (so we remove only those), and the container's init
/// PID when known (so we can also remove the container-netns iptables INPUT
/// rules the inbound chain installed inside it, before the container is
/// destroyed).
///
/// All live behind one mutex on purpose. The watchdog takes a single
/// snapshot of the whole struct, so it can never pair one container's
/// identity with another's ownership record.
#[derive(Default)]
struct ActiveSandbox {
    name: Option<String>,
    created: CreatedResources,
    netns_pid: Option<u32>,
}

static ACTIVE_CONTAINER: OnceLock<Mutex<ActiveSandbox>> = OnceLock::new();
#[cfg(target_os = "linux")]
static INSTALLED: OnceLock<()> = OnceLock::new();

fn lock_slot() -> std::sync::MutexGuard<'static, ActiveSandbox> {
    ACTIVE_CONTAINER
        .get_or_init(|| Mutex::new(ActiveSandbox::default()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

/// Records `name` as the currently active container so the cleanup watchdog
/// can destroy it if a fatal signal arrives. Replaces any previous value
/// (including any previously registered created-resource record, since the
/// new container has not created anything yet).
pub fn set_active(name: &str) {
    let mut slot = lock_slot();
    slot.name = Some(name.to_owned());
    slot.created = CreatedResources::default();
    slot.netns_pid = None;
}

/// Records the container's init PID for the active container so the watchdog
/// can remove the iptables rules inside the container's network namespace on
/// a fatal signal, before the container is destroyed. No-op if no container is
/// currently registered.
pub fn set_active_pid(pid: u32) {
    let mut slot = lock_slot();
    if slot.name.is_some() {
        slot.netns_pid = Some(pid);
    }
}

/// Records which iptables chains and OUTPUT hooks the runner has created so
/// far, so signal-time cleanup removes exactly those and nothing else.
///
/// No-op when no container is registered. Backends that never call
/// [`set_active`] — Bubblewrap builds the same firewall manager but installs
/// no watchdog — therefore publish nothing, which keeps the watchdog from
/// acting on a lifecycle it does not manage.
pub(crate) fn set_active_created(created: CreatedResources) {
    let mut slot = lock_slot();
    if slot.name.is_some() {
        slot.created = created;
    }
}

/// Reads back what the watchdog would act on. Test-only: production code has
/// exactly one reader, and it is the watchdog itself.
#[cfg(test)]
fn active_snapshot() -> (Option<String>, CreatedResources, Option<u32>) {
    let slot = lock_slot();
    (slot.name.clone(), slot.created, slot.netns_pid)
}

/// Returns the slot to its process-start state so a test leaves nothing behind.
#[cfg(test)]
fn clear_active() {
    *lock_slot() = ActiveSandbox::default();
}

/// Block SIGHUP/SIGTERM/SIGINT in the calling thread and spawn a watchdog
/// that synchronously waits (`sigwait`) for any of them. On delivery the
/// watchdog destroys the active container, then exits with `128 + signo`.
///
/// MUST be called once, early in `main`, before any other threads are
/// spawned: `pthread_sigmask` only changes the mask of the calling thread,
/// but new threads inherit the mask at creation time. If a thread starts
/// before `install()`, that thread's mask leaves the signals unblocked and
/// the kernel may deliver them there instead of to the watchdog.
#[cfg(target_os = "linux")]
pub fn install() -> Result<(), String> {
    if INSTALLED.get().is_some() {
        return Ok(());
    }
    let mut mask = SigSet::empty();
    mask.add(Signal::SIGHUP);
    mask.add(Signal::SIGTERM);
    mask.add(Signal::SIGINT);
    mask.thread_block()
        .map_err(|e| format!("pthread_sigmask: {}", e))?;

    match thread::Builder::new()
        .name("lxc-signal-cleanup".into())
        .spawn(move || run_watchdog(mask))
    {
        Ok(_) => {
            // Only mark INSTALLED after the watchdog is actually running, so
            // a retry after a transient spawn failure can re-attempt install.
            let _ = INSTALLED.set(());
            Ok(())
        }
        Err(err) => {
            // The watchdog never started, so leaving the signals blocked
            // would make the whole process unkillable by SIGHUP/SIGTERM/SIGINT.
            // Restore the original mask before bubbling up the error.
            let _ = mask.thread_unblock();
            Err(format!("spawn lxc-signal-cleanup thread: {err}"))
        }
    }
}

/// Non-Linux stub. `lxc-exec` is Linux-only at runtime, but the workspace
/// still builds on Windows (clippy CI) and macOS (dev), so the signature
/// has to exist on every target. Signal-driven cleanup is a no-op on
/// non-Linux targets — the watchdog relies on POSIX `sigwait` semantics
/// that aren't meaningful on Windows.
#[cfg(not(target_os = "linux"))]
pub fn install() -> Result<(), String> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_watchdog(mask: SigSet) -> ! {
    loop {
        // sigwait isn't normally interruptible; on the unlikely failure, retry.
        let Ok(sig) = mask.wait() else { continue };
        let active = std::mem::take(&mut *lock_slot());
        if let Some(name) = active.name {
            // Remove the iptables rules first so neither chain outlives the
            // container. Both live inside the container's own network
            // namespace, which vanishes when it is destroyed below, so this
            // only runs while the init PID is still known. Best-effort with a
            // buffered logger so signal-time output doesn't interleave with
            // whatever else might still be writing to the host's stdio.
            let mut buf_logger = Logger::new(Mode::Buffer);
            if let Some(pid) = active.netns_pid {
                NetworkIptablesManager::force_cleanup(
                    &name,
                    EgressHookPoint::ContainerNetns(pid),
                    active.created,
                    &mut buf_logger,
                );
                IngressManager::force_cleanup(&name, pid, &mut buf_logger);
            }
            let _ = LxcContainer::new(&name, None).destroy();
        }
        std::process::exit(128 + sig as i32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ACTIVE_CONTAINER` is process-global and the test binary runs tests in
    /// parallel, so the whole publication contract is asserted in one test.
    /// Splitting it would let two tests race on the same slot.
    #[test]
    fn the_watchdogs_view_of_a_container_is_built_and_reset_as_a_single_unit() {
        clear_active();

        // Before any container registers, ownership publication is a no-op.
        // Bubblewrap builds the same firewall manager but never registers, so
        // its resources must not become something the watchdog would remove.
        set_active_created(CreatedResources::for_test(true, true, true, true));
        set_active_pid(4242);
        let (name, created, netns_pid) = active_snapshot();
        assert_eq!(name, None, "no container should be registered yet");
        assert_eq!(
            created,
            CreatedResources::default(),
            "ownership published with no registered container must be discarded"
        );
        assert_eq!(
            netns_pid, None,
            "a netns PID published with no registered container must be discarded"
        );

        // Registering a container opens the slot.
        set_active("ctr-a");
        set_active_pid(1234);
        let v4_chain_only = CreatedResources::for_test(true, false, false, false);
        set_active_created(v4_chain_only);
        assert_eq!(
            active_snapshot(),
            (Some("ctr-a".to_owned()), v4_chain_only, Some(1234)),
            "a registered container must see its own identity and ownership"
        );

        // Publication is incremental: each creation site republishes the whole
        // record, so a later publish supersedes an earlier one rather than
        // merging with it.
        let both_chains = CreatedResources::for_test(true, true, false, false);
        set_active_created(both_chains);
        assert_eq!(
            active_snapshot().1,
            both_chains,
            "the most recent publication is what the watchdog must act on"
        );

        // A new container must not inherit the previous one's ownership record.
        // The chain name depends only on the container name, so acting on a
        // stale record can tear down a chain that is still in use.
        set_active("ctr-b");
        assert_eq!(
            active_snapshot(),
            (Some("ctr-b".to_owned()), CreatedResources::default(), None),
            "registering a new container must reset ownership and netns PID"
        );

        clear_active();
    }
}
