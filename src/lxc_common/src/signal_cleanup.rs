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

static ACTIVE_CONTAINER: OnceLock<Mutex<Option<String>>> = OnceLock::new();
static INSTALLED: OnceLock<()> = OnceLock::new();

fn lock_slot() -> std::sync::MutexGuard<'static, Option<String>> {
    ACTIVE_CONTAINER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

/// Records `name` as the currently active container so the cleanup watchdog
/// can destroy it if a fatal signal arrives. Replaces any previous value.
pub fn set_active(name: &str) {
    *lock_slot() = Some(name.to_owned());
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
    if INSTALLED.set(()).is_err() {
        return Ok(());
    }
    let mut mask = SigSet::empty();
    mask.add(Signal::SIGHUP);
    mask.add(Signal::SIGTERM);
    mask.add(Signal::SIGINT);
    mask.thread_block()
        .map_err(|e| format!("pthread_sigmask: {}", e))?;

    thread::Builder::new()
        .name("lxc-signal-cleanup".into())
        .spawn(move || run_watchdog(mask))
        .map_err(|err| format!("spawn lxc-signal-cleanup thread: {err}"))?;
    Ok(())
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
        if let Some(name) = lock_slot().take() {
            let _ = LxcContainer::new(&name, None).destroy();
        }
        std::process::exit(128 + sig as i32);
    }
}
