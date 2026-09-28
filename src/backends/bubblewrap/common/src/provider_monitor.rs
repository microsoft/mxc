// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Watches the sandbox's network provider for the lifetime of the workload.

use std::fs::File;
use std::io::{ErrorKind, Read};
use std::os::fd::OwnedFd;
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use wxc_common::sandbox_process::group_kill;

/// Also the longest a disarmed monitor keeps its thread alive.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Terminates the sandbox if its network provider dies while the workload runs.
///
/// The private-namespace modes route the sandbox entirely through
/// `slirp4netns`, so losing it leaves the workload running with no network.
pub(crate) struct ProviderMonitor {
    lost: Arc<AtomicBool>,
    disarmed: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl ProviderMonitor {
    /// Start watching `watch`, killing `child` if the provider goes away first.
    pub(crate) fn watch(watch: OwnedFd, child: Arc<Mutex<Child>>, group: bool) -> Self {
        let lost = Arc::new(AtomicBool::new(false));
        let disarmed = Arc::new(AtomicBool::new(false));
        let thread_lost = Arc::clone(&lost);
        let thread_disarmed = Arc::clone(&disarmed);

        let handle = thread::spawn(move || {
            let mut watch = File::from(watch);
            let mut byte = [0_u8; 1];
            let mut lost_provider = false;
            loop {
                match watch.read(&mut byte) {
                    // Every holder of the write end has exited, so neither the
                    // supervisor nor an orphaned slirp is left to carry traffic.
                    Ok(0) => {
                        lost_provider = true;
                        break;
                    }
                    Ok(_) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            ErrorKind::WouldBlock | ErrorKind::Interrupted
                        ) => {}
                    Err(_) => break,
                }

                // Read before this, never after: teardown disarms while the
                // supervisor is still up, so an already-pending EOF is a real
                // loss and must not be discarded here.
                if thread_disarmed.load(Ordering::SeqCst) {
                    return;
                }
                thread::sleep(POLL_INTERVAL);
            }

            if !lost_provider {
                return;
            }
            thread_lost.store(true, Ordering::SeqCst);
            if thread_disarmed.load(Ordering::SeqCst) {
                return;
            }

            let Ok(mut child) = child.lock() else {
                return;
            };
            // Signalling a reaped child could reach an unrelated process that
            // inherited its pid; holding the lock keeps the answer true.
            if matches!(child.try_wait(), Ok(None)) {
                let _ = if group {
                    group_kill(&mut child)
                } else {
                    child.kill()
                };
            }
        });

        Self {
            lost,
            disarmed,
            handle: Some(handle),
        }
    }

    /// Whether the provider was lost while the workload was running.
    pub(crate) fn provider_lost(&self) -> bool {
        self.lost.load(Ordering::SeqCst)
    }

    /// Stop watching, and report whether a loss had already been observed.
    pub(crate) fn disarm(&mut self) -> bool {
        self.disarmed.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        self.provider_lost()
    }
}

impl Drop for ProviderMonitor {
    fn drop(&mut self) {
        self.disarm();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use nix::fcntl::{fcntl, FcntlArg, OFlag};
    use nix::unistd::pipe2;
    use std::os::fd::AsRawFd;
    use std::process::Command;
    use std::time::Instant;

    /// The read end must not block, or a disarmed monitor could never notice.
    fn watch_pipe() -> (OwnedFd, OwnedFd) {
        let (reader, writer) = pipe2(OFlag::O_CLOEXEC).expect("pipe");
        let flags = fcntl(reader.as_raw_fd(), FcntlArg::F_GETFL).expect("read descriptor flags");
        fcntl(
            reader.as_raw_fd(),
            FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK),
        )
        .expect("set descriptor nonblocking");
        (reader, writer)
    }

    fn sleeping_sandbox() -> Arc<Mutex<Child>> {
        Arc::new(Mutex::new(
            Command::new("sleep").arg("30").spawn().expect("spawn"),
        ))
    }

    fn exited_within(child: &Arc<Mutex<Child>>, budget: Duration) -> bool {
        let deadline = Instant::now() + budget;
        while Instant::now() < deadline {
            let exited = child
                .lock()
                .map(|mut child| matches!(child.try_wait(), Ok(Some(_))))
                .unwrap_or(false);
            if exited {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        false
    }

    fn reap(child: &Arc<Mutex<Child>>) {
        if let Ok(mut child) = child.lock() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    #[test]
    fn a_lost_provider_takes_the_sandbox_down_with_it() {
        let (watch, writer) = watch_pipe();
        let child = sleeping_sandbox();
        let mut monitor = ProviderMonitor::watch(watch, Arc::clone(&child), false);

        drop(writer);

        assert!(
            exited_within(&child, Duration::from_secs(10)),
            "the sandbox outlived the provider carrying its only route"
        );
        assert!(
            monitor.disarm(),
            "the loss must reach the run rather than being reported as a workload exit"
        );
        reap(&child);
    }

    #[test]
    fn a_disarmed_monitor_leaves_the_sandbox_alone() {
        let (watch, writer) = watch_pipe();
        let child = sleeping_sandbox();
        let mut monitor = ProviderMonitor::watch(watch, Arc::clone(&child), false);

        monitor.disarm();
        drop(writer);

        assert!(
            !exited_within(&child, Duration::from_millis(500)),
            "teardown closing the watch must not be mistaken for a provider death"
        );
        assert!(!monitor.provider_lost());
        reap(&child);
    }

    #[test]
    fn a_monitor_over_an_already_reaped_sandbox_still_settles() {
        let (watch, writer) = watch_pipe();
        let child = Arc::new(Mutex::new(Command::new("true").spawn().expect("spawn")));
        reap(&child);
        let mut monitor = ProviderMonitor::watch(watch, Arc::clone(&child), true);

        drop(writer);

        assert!(monitor.disarm(), "the loss is still worth reporting");
    }
}
