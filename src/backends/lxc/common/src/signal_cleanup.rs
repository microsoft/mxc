// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Process-level cleanup for fatal signals.
//!
//! SIGHUP, SIGTERM, and SIGINT can interrupt the runner before normal cleanup
//! runs.  The watchdog waits for them through `sigwait`, destroys the active
//! container, and exits with the signal-style status code.

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

pub fn set_active(name: &str) {
    let mut slot = lock_slot();
    slot.name = Some(name.to_owned());
    slot.created = CreatedResources::default();
    slot.netns_pid = None;
}

pub fn set_active_pid(pid: u32) {
    let mut slot = lock_slot();
    if slot.name.is_some() {
        slot.netns_pid = Some(pid);
    }
}

pub(crate) fn set_active_created(created: CreatedResources) {
    let mut slot = lock_slot();
    if slot.name.is_some() {
        slot.created = created;
    }
}

#[cfg(test)]
fn active_snapshot() -> (Option<String>, CreatedResources, Option<u32>) {
    let slot = lock_slot();
    (slot.name.clone(), slot.created, slot.netns_pid)
}

#[cfg(test)]
fn clear_active() {
    *lock_slot() = ActiveSandbox::default();
}

/// Blocks fatal signals in this thread and spawns the cleanup watchdog.
///
/// `pthread_sigmask` changes only the calling thread's mask, and new threads
/// inherit their creator's mask.  Call this before spawning any thread that
/// should leave signal delivery to the watchdog.
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
            let _ = INSTALLED.set(());
            Ok(())
        }
        Err(err) => {
            let _ = mask.thread_unblock();
            Err(format!("spawn lxc-signal-cleanup thread: {err}"))
        }
    }
}

/// Non-Linux stub for workspace builds on Windows and macOS.
#[cfg(not(target_os = "linux"))]
pub fn install() -> Result<(), String> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_watchdog(mask: SigSet) -> ! {
    loop {
        let Ok(sig) = mask.wait() else { continue };
        let active = std::mem::take(&mut *lock_slot());
        if let Some(name) = active.name {
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

    #[test]
    fn the_watchdogs_view_of_a_container_is_built_and_reset_as_a_single_unit() {
        clear_active();

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

        set_active("ctr-a");
        set_active_pid(1234);
        let v4_chain_only = CreatedResources::for_test(true, false, false, false);
        set_active_created(v4_chain_only);
        assert_eq!(
            active_snapshot(),
            (Some("ctr-a".to_owned()), v4_chain_only, Some(1234)),
            "a registered container must see its own identity and ownership"
        );

        let both_chains = CreatedResources::for_test(true, true, false, false);
        set_active_created(both_chains);
        assert_eq!(
            active_snapshot().1,
            both_chains,
            "the most recent publication is what the watchdog must act on"
        );

        set_active("ctr-b");
        assert_eq!(
            active_snapshot(),
            (Some("ctr-b".to_owned()), CreatedResources::default(), None),
            "registering a new container must reset ownership and netns PID"
        );

        clear_active();
    }
}
