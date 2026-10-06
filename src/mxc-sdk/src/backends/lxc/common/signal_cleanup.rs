// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Process-level cleanup for fatal signals.
//!
//! SIGHUP, SIGTERM, and SIGINT can interrupt the runner before normal cleanup
//! runs.  The watchdog waits for them through `sigwait`, destroys the active
//! container, and exits with the signal-style status code.
//!
//! Only the executor binary installs it: one slot cannot describe the several
//! sandboxes a library host can hold, and a library may not exit its caller's
//! process.  There each sandbox handle tears itself down instead.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

#[cfg(target_os = "linux")]
use std::thread;

#[cfg(target_os = "linux")]
use nix::sys::signal::{SigSet, Signal};

#[cfg(target_os = "linux")]
use crate::lxc_common::lxc_bindings::LxcContainer;
#[cfg(target_os = "linux")]
use crate::lxc_common::network_ingress::IngressManager;
use crate::lxc_common::network_iptables::CreatedResources;
#[cfg(target_os = "linux")]
use crate::lxc_common::network_iptables::{EgressHookPoint, NetworkIptablesManager};
#[cfg(target_os = "linux")]
use crate::mxc_common::logger::{Logger, Mode};

#[derive(Default)]
struct ActiveSandbox {
    name: Option<String>,
    created: CreatedResources,
    netns_pid: Option<u32>,
}

static ACTIVE_CONTAINER: OnceLock<Mutex<ActiveSandbox>> = OnceLock::new();
static WATCHDOG_INSTALLED: AtomicBool = AtomicBool::new(false);

fn lock_slot() -> std::sync::MutexGuard<'static, ActiveSandbox> {
    ACTIVE_CONTAINER
        .get_or_init(|| Mutex::new(ActiveSandbox::default()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

#[cfg(test)]
thread_local! {
    /// Opens the gate for one test thread, leaving it shut for the tests
    /// running beside it.
    static WATCHDOG_OVERRIDE: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

fn watchdog_installed() -> bool {
    #[cfg(test)]
    if let Some(overridden) = WATCHDOG_OVERRIDE.with(std::cell::Cell::get) {
        return overridden;
    }
    WATCHDOG_INSTALLED.load(Ordering::Acquire)
}

/// Registers the container the watchdog destroys.
pub fn set_active(name: &str) {
    if !watchdog_installed() {
        return;
    }
    let mut slot = lock_slot();
    slot.name = Some(name.to_owned());
    slot.created = CreatedResources::default();
    slot.netns_pid = None;
}

pub fn set_active_pid(pid: u32) {
    if !watchdog_installed() {
        return;
    }
    let mut slot = lock_slot();
    if slot.name.is_some() {
        slot.netns_pid = Some(pid);
    }
}

pub(crate) fn set_active_created(created: CreatedResources) {
    if !watchdog_installed() {
        return;
    }
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
    if watchdog_installed() {
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
            WATCHDOG_INSTALLED.store(true, Ordering::Release);
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
    use std::sync::MutexGuard;

    /// Serializes the tests that share the watchdog's one registration slot.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// The watchdog flag one test needs.
    struct Watchdog {
        _lock: MutexGuard<'static, ()>,
    }

    impl Watchdog {
        fn installed() -> Self {
            Self::enter(true)
        }

        fn uninstalled() -> Self {
            Self::enter(false)
        }

        // The flag is set directly rather than through `install`, which spawns
        // a watchdog that would exit the test binary on the first Ctrl-C.
        fn enter(installed: bool) -> Self {
            let lock = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            clear_active();
            set_watchdog_override(Some(installed));
            Self { _lock: lock }
        }
    }

    impl Drop for Watchdog {
        fn drop(&mut self) {
            set_watchdog_override(None);
            clear_active();
        }
    }

    fn set_watchdog_override(value: Option<bool>) {
        WATCHDOG_OVERRIDE.with(|slot| slot.set(value));
    }

    #[test]
    fn the_watchdogs_view_of_a_container_is_built_and_reset_as_a_single_unit() {
        let _watchdog = Watchdog::installed();

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
    }

    #[test]
    fn a_host_that_installed_no_watchdog_registers_nothing() {
        let _watchdog = Watchdog::uninstalled();

        set_active("ctr-a");
        set_active_pid(1234);
        set_active_created(CreatedResources::for_test(true, true, true, true));

        assert_eq!(
            active_snapshot(),
            (None, CreatedResources::default(), None),
            "one slot cannot describe the several sandboxes a library host can hold, \
             and no watchdog is running to act on what it holds"
        );
    }

    #[test]
    fn an_open_gate_is_confined_to_the_thread_that_opened_it() {
        let _watchdog = Watchdog::installed();

        let seen_elsewhere = std::thread::spawn(watchdog_installed)
            .join()
            .expect("the probe thread must not panic");

        assert!(
            !seen_elsewhere,
            "a test running beside this one would publish its own chain ownership \
             into the slot, overwriting whichever container this one registered"
        );
    }

    #[test]
    fn each_setter_consults_the_watchdog_gate_for_itself() {
        let _watchdog = Watchdog::installed();

        set_active("ctr-a");
        let registered = CreatedResources::for_test(true, false, false, false);
        set_active_created(registered);
        set_active_pid(1234);
        assert_eq!(
            active_snapshot(),
            (Some("ctr-a".to_owned()), registered, Some(1234)),
            "the gates can only be tested against a slot that is fully populated"
        );

        WATCHDOG_OVERRIDE.with(|slot| slot.set(Some(false)));

        set_active_pid(9999);
        assert_eq!(
            active_snapshot().2,
            Some(1234),
            "set_active_pid must consult the gate rather than lean on the registered \
             container check, which passes here"
        );

        set_active_created(CreatedResources::for_test(true, true, true, true));
        assert_eq!(
            active_snapshot().1,
            registered,
            "set_active_created must consult the gate rather than lean on the \
             registered container check, which passes here"
        );

        set_active("ctr-b");
        assert_eq!(
            active_snapshot().0,
            Some("ctr-a".to_owned()),
            "set_active must consult the gate"
        );
    }

    /// Bubblewrap builds its egress chain through the LXC crate's manager, so
    /// its ownership publications reach this slot even inside `lxc-exec`, where
    /// the watchdog is installed.
    #[test]
    fn a_backend_that_registers_no_container_publishes_no_ownership() {
        use crate::lxc_common::network_iptables::{EgressHookPoint, NetworkIptablesManager};
        use crate::mxc_common::logger::{Logger, Mode};
        use crate::mxc_common::models::{ContainerPolicy, NetworkAction, NetworkEgressPolicy};

        let _watchdog = Watchdog::installed();
        let _fake = crate::lxc_common::network_iptables::test_firewall::install();

        let mut manager =
            NetworkIptablesManager::new("mxc-bwrap-publish-test", EgressHookPoint::Unhooked);
        let policy = ContainerPolicy {
            network_egress: Some(NetworkEgressPolicy {
                default: NetworkAction::Allow,
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut logger = Logger::new(Mode::Buffer);

        manager
            .apply_firewall_rules(&policy, &mut logger)
            .expect("the fake firewall accepts every command");
        assert!(
            manager.rules_applied(),
            "the chain must have been built, or nothing was published to the slot"
        );

        assert_eq!(
            active_snapshot(),
            (None, CreatedResources::default(), None),
            "the watchdog destroys a container by name and this backend has none to give \
             it, so taking the ownership record would aim the removal at whichever LXC \
             container registered last"
        );
    }
}
