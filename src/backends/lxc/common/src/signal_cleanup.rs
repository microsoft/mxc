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
use crate::network_iptables::NetworkIptablesManager;
#[cfg(target_os = "linux")]
use wxc_common::logger::{Logger, Mode};

/// What the watchdog needs to roll back on a fatal signal: the container
/// name (so we can `lxc-destroy` it) plus, when known, the host-side veth
/// interface (so we can also remove the iptables FORWARD hook the runner
/// installed against it).
#[derive(Default)]
struct ActiveSandbox {
    name: Option<String>,
    veth: Option<String>,
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
/// (including any previously registered veth, since the new container has
/// not had its veth discovered yet).
pub fn set_active(name: &str) {
    let mut slot = lock_slot();
    slot.name = Some(name.to_owned());
    slot.veth = None;
}

/// Records the host-side veth interface for the active container so the
/// watchdog can also remove the iptables FORWARD hook on a fatal signal.
/// No-op if no container is currently registered.
pub fn set_active_veth(veth: &str) {
    let mut slot = lock_slot();
    if slot.name.is_some() {
        slot.veth = Some(veth.to_owned());
    }
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
            // Remove iptables rules first so the FORWARD hook and chain
            // don't outlive the container. The veth disappears once the
            // container is destroyed below; cleaning up first avoids a
            // dangling reference. Best-effort with a buffered logger so
            // signal-time output doesn't interleave with whatever else
            // might still be writing to the host's stdio.
            let mut buf_logger = Logger::new(Mode::Buffer);
            NetworkIptablesManager::force_cleanup(&name, active.veth.as_deref(), &mut buf_logger);
            let _ = LxcContainer::new(&name, None).destroy();
        }
        std::process::exit(128 + sig as i32);
    }
}
