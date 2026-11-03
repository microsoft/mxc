// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use super::config_deserialize::escape_diagnostic_text;

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PROBE_WORKERS: usize = 16;

#[cfg(test)]
#[path = "filesystem_probe_launch_tests.rs"]
pub(crate) mod launch_tests;

type ProbeJob = Box<dyn FnOnce() + Send>;

#[derive(Debug)]
pub(crate) struct FilesystemProbe {
    timeout: Duration,
    gate: Arc<WorkerGate>,
    worker: Option<SyncSender<ProbeJob>>,
}

impl Default for FilesystemProbe {
    fn default() -> Self {
        static GATE: OnceLock<Arc<WorkerGate>> = OnceLock::new();
        Self {
            timeout: PROBE_TIMEOUT,
            gate: Arc::clone(GATE.get_or_init(|| WorkerGate::new(MAX_PROBE_WORKERS))),
            worker: None,
        }
    }
}

impl FilesystemProbe {
    pub(crate) fn run<T: Send + 'static>(
        &mut self,
        path: &str,
        probe: impl FnOnce(&str) -> T + Send + 'static,
    ) -> Result<T, String> {
        let deadline = Instant::now() + self.timeout;
        let result = self
            .submit(path, probe, deadline)
            .and_then(|receiver| wait_for_probe(receiver, deadline, self.timeout));
        if result.is_err() {
            self.worker = None;
        }
        result.map_err(|error| {
            format!(
                "Filesystem path '{}' could not be checked: {error}. \
                 Refusing sandbox startup; check for an unreachable mount or blocked filesystem.",
                escape_diagnostic_text(path)
            )
        })
    }

    fn submit<T: Send + 'static>(
        &mut self,
        path: &str,
        probe: impl FnOnce(&str) -> T + Send + 'static,
        deadline: Instant,
    ) -> Result<mpsc::Receiver<Result<T, String>>, String> {
        #[cfg(windows)]
        let token = super::process_util::duplicate_thread_token()
            .map_err(|error| format!("could not capture the caller's access token: {error}"))?;

        if self.worker.is_none() {
            let permit = self.gate.acquire(deadline)?;
            super::module_lifetime::pin_current_module()?;
            let (sender, receiver) = mpsc::sync_channel::<ProbeJob>(1);
            std::thread::Builder::new()
                .name("filesystem-probe".to_string())
                .spawn(move || {
                    let _permit = permit;
                    while let Ok(job) = receiver.recv() {
                        job();
                    }
                })
                .map_err(|error| format!("could not start a filesystem probe worker: {error}"))?;
            self.worker = Some(sender);
        }

        let (sender, receiver) = mpsc::sync_channel(1);
        let path = path.to_string();
        let timeout = self.timeout;
        let job = Box::new(move || {
            let result = (|| {
                if Instant::now() >= deadline {
                    return Err(timeout_message(timeout));
                }

                #[cfg(windows)]
                {
                    use windows::Win32::System::Threading::SetThreadToken;

                    // SAFETY: the token is owned by this job; None clears any earlier impersonation.
                    unsafe { SetThreadToken(None, token.as_ref().map(|token| token.get())) }
                        .map_err(|error| {
                            format!("could not use the caller's access token: {error}")
                        })?;
                }

                Ok(probe(&path))
            })();
            let _ = sender.send(result);
        });
        self.worker
            .as_ref()
            .ok_or("filesystem probe worker is unavailable")?
            .try_send(job)
            .map_err(|_| "filesystem probe worker stopped accepting work".to_string())?;

        Ok(receiver)
    }

    #[cfg(test)]
    pub(crate) fn for_test(timeout: Duration) -> Self {
        Self {
            timeout,
            gate: WorkerGate::new(1),
            worker: None,
        }
    }
}

fn wait_for_probe<T>(
    receiver: mpsc::Receiver<Result<T, String>>,
    deadline: Instant,
    timeout: Duration,
) -> Result<T, String> {
    match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(_) if Instant::now() >= deadline => Err(timeout_message(timeout)),
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout) => Err(timeout_message(timeout)),
        Err(RecvTimeoutError::Disconnected) => {
            Err("filesystem probe worker stopped without a result".to_string())
        }
    }
}

fn timeout_message(timeout: Duration) -> String {
    format!("filesystem probe timed out after {}ms", timeout.as_millis())
}

#[derive(Debug)]
struct WorkerGate {
    active: Mutex<usize>,
    available: Condvar,
    limit: usize,
}

impl WorkerGate {
    fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            active: Mutex::new(0),
            available: Condvar::new(),
            limit,
        })
    }

    fn acquire(self: &Arc<Self>, deadline: Instant) -> Result<WorkerPermit, String> {
        self.acquire_with_budget(|| deadline.saturating_duration_since(Instant::now()))
    }

    fn acquire_with_budget(
        self: &Arc<Self>,
        mut remaining: impl FnMut() -> Duration,
    ) -> Result<WorkerPermit, String> {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        loop {
            let remaining = remaining();
            if remaining.is_zero() {
                return Err(format!(
                    "filesystem probe deadline expired waiting for a worker \
                     (limit {}); earlier probes may still be blocked",
                    self.limit
                ));
            }
            if *active < self.limit {
                *active += 1;
                return Ok(WorkerPermit(Arc::clone(self)));
            }
            let (next, _) = self
                .available
                .wait_timeout(active, remaining)
                .unwrap_or_else(|error| error.into_inner());
            active = next;
        }
    }
}

struct WorkerPermit(Arc<WorkerGate>);

impl Drop for WorkerPermit {
    fn drop(&mut self) {
        let mut active = self
            .0
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *active -= 1;
        self.0.available.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    const WATCHDOG: Duration = Duration::from_secs(5);

    #[test]
    fn fast_probes_reuse_one_worker() {
        let mut probe = FilesystemProbe::for_test(Duration::from_secs(2));
        let worker = probe
            .run("first", |path| {
                (path.to_string(), std::thread::current().id())
            })
            .unwrap();
        assert_eq!(worker.0, "first");
        assert_ne!(worker.1, std::thread::current().id());
        for _ in 0..20 {
            assert_eq!(
                probe.run("next", |_| std::thread::current().id()).unwrap(),
                worker.1
            );
        }
    }

    #[test]
    fn timeout_holds_capacity_until_the_blocked_worker_exits() {
        let timeout = Duration::from_millis(100);
        let mut blocked = FilesystemProbe::for_test(timeout);
        let gate = Arc::clone(&blocked.gate);
        let (release, wait) = mpsc::sync_channel(1);
        let (started, entered) = mpsc::sync_channel(1);
        let receiver = blocked
            .submit(
                "blocked",
                move |_| {
                    started.send(()).unwrap();
                    wait.recv_timeout(WATCHDOG * 2).unwrap();
                    123
                },
                Instant::now() + WATCHDOG,
            )
            .unwrap();
        entered.recv_timeout(WATCHDOG).unwrap();
        let start = Instant::now();
        let result = wait_for_probe(receiver, start, timeout);
        let elapsed = start.elapsed();
        drop(blocked);

        let executed = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&executed);
        let mut another = FilesystemProbe {
            gate: Arc::clone(&gate),
            timeout,
            worker: None,
        };
        let capacity_start = Instant::now();
        let exhausted = another.run("another", move |_| {
            observed.store(true, Ordering::SeqCst);
        });
        let capacity_elapsed = capacity_start.elapsed();
        let active = *gate.active.lock().unwrap();
        release.send(()).unwrap();

        another.timeout = WATCHDOG;
        assert_eq!(another.run("recovered", |_| 456).unwrap(), 456);
        let error = result.unwrap_err();
        assert!(error.contains("timed out after 100ms"), "{error}");
        assert!(elapsed < WATCHDOG, "{elapsed:?}");
        assert!(capacity_elapsed < WATCHDOG, "{capacity_elapsed:?}");
        assert_eq!(active, 1, "a timed-out worker must retain its permit");
        assert!(!executed.load(Ordering::SeqCst));
        let error = exhausted.unwrap_err();
        assert!(error.contains("limit 1"), "{error}");
    }

    #[test]
    fn releasing_capacity_wakes_expired_and_live_waiters() {
        let gate = WorkerGate::new(1);
        let expired = AtomicBool::new(false);
        let (started, ready) = mpsc::sync_channel(2);
        let (finished, results) = mpsc::sync_channel(2);
        let (first, second) = std::thread::scope(|scope| {
            let permit = gate.acquire(Instant::now() + WATCHDOG).unwrap();
            for should_expire in [true, false] {
                let (gate, expired) = (&gate, &expired);
                let (started, finished) = (started.clone(), finished.clone());
                scope.spawn(move || {
                    let deadline = Instant::now() + WATCHDOG * 4;
                    let mut started = Some(started);
                    let result = gate.acquire_with_budget(|| {
                        if let Some(started) = started.take() {
                            started.send(()).unwrap();
                        }
                        if should_expire && expired.load(Ordering::Acquire) {
                            Duration::ZERO
                        } else {
                            deadline.saturating_duration_since(Instant::now())
                        }
                    });
                    finished.send((should_expire, result)).unwrap();
                });
            }
            ready.recv_timeout(WATCHDOG).unwrap();
            ready.recv_timeout(WATCHDOG).unwrap();
            let active = gate.active.lock().unwrap();
            expired.store(true, Ordering::Release);
            drop(active);
            drop(permit);

            let first = results.recv_timeout(WATCHDOG);
            let second = results.recv_timeout(WATCHDOG);
            gate.available.notify_all();
            (first, second)
        });
        for result in [first, second] {
            let (expired, permit) = result.expect("both waiters must observe the capacity release");
            assert_eq!(permit.is_err(), expired);
        }
        assert_eq!(*gate.active.lock().unwrap(), 0);
    }

    #[test]
    fn a_panicked_probe_fails_and_releases_its_permit() {
        let mut probe = FilesystemProbe::for_test(Duration::from_secs(2));
        let result = probe.run::<()>("panic", |_| panic!("probe panic"));
        let error = result.unwrap_err();
        assert!(error.contains("stopped without a result"), "{error}");
        assert_eq!(probe.run("recovered", |_| 42).unwrap(), 42);
    }

    #[test]
    fn filesystem_errors_remain_distinct_from_probe_failures() {
        let mut probe = FilesystemProbe::for_test(Duration::from_secs(2));
        let result = probe
            .run("missing", |_| {
                Err::<(), _>(std::io::Error::from(std::io::ErrorKind::NotFound))
            })
            .unwrap();
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn an_expired_job_never_starts_filesystem_io() {
        let mut probe = FilesystemProbe::for_test(Duration::from_secs(2));
        probe.run("warm", |_| ()).unwrap();
        probe.timeout = Duration::ZERO;
        let executed = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&executed);
        let result = probe.run("expired\npath", move |_| {
            observed.store(true, Ordering::SeqCst);
        });

        probe.timeout = Duration::from_secs(2);
        probe.run("recovered", |_| ()).unwrap();
        assert!(!executed.load(Ordering::SeqCst));
        let error = result.unwrap_err();
        assert!(error.contains("timed out"), "{error}");
        assert!(error.contains(r"expired\npath"), "{error}");
        assert!(!error.contains('\n'), "{error}");
    }

    #[test]
    fn production_probes_share_the_worker_limit_and_start_lazily() {
        let first = FilesystemProbe::default();
        let second = FilesystemProbe::default();
        assert!(Arc::ptr_eq(&first.gate, &second.gate));
        assert_eq!(first.gate.limit, MAX_PROBE_WORKERS);
        assert!(first.worker.is_none());
        assert!(second.worker.is_none());
    }

    #[cfg(windows)]
    mod windows_tests {
        use super::*;
        use crate::mxc_common::process_util::OwnedHandle;
        use windows::Win32::Foundation::{ERROR_NO_TOKEN, HANDLE};
        use windows::Win32::Security::{
            ImpersonateSelf, RevertToSelf, SecurityIdentification, SecurityImpersonation,
            SECURITY_IMPERSONATION_LEVEL, TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

        struct Impersonation;

        impl Impersonation {
            fn enter(level: SECURITY_IMPERSONATION_LEVEL) -> Self {
                unsafe { ImpersonateSelf(level) }.unwrap();
                Self
            }
        }

        impl Drop for Impersonation {
            fn drop(&mut self) {
                unsafe { RevertToSelf() }.unwrap();
            }
        }

        fn is_impersonating() -> windows::core::Result<bool> {
            let mut token = HANDLE::default();

            // SAFETY: token is a writable handle slot for the current thread.
            match unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token) } {
                Ok(()) => {
                    let _token = OwnedHandle::new(token);
                    Ok(true)
                }
                Err(error) if error.code() == ERROR_NO_TOKEN.to_hresult() => Ok(false),
                Err(error) => Err(error),
            }
        }

        #[test]
        fn worker_applies_and_clears_the_callers_impersonation() {
            let mut probe = FilesystemProbe::for_test(Duration::from_secs(2));
            let identity = Impersonation::enter(SecurityImpersonation);
            assert!(probe.run("first", |_| is_impersonating()).unwrap().unwrap());
            assert!(is_impersonating().unwrap());
            drop(identity);

            assert!(!probe.run("next", |_| is_impersonating()).unwrap().unwrap());
            assert!(!is_impersonating().unwrap());
        }

        #[test]
        fn uncapturable_identity_fails_without_running_the_probe() {
            let mut probe = FilesystemProbe::for_test(Duration::from_secs(2));
            let identity = Impersonation::enter(SecurityIdentification);
            let error = probe
                .run::<()>("restricted", |_| panic!("must not run as the process"))
                .unwrap_err();
            drop(identity);

            assert!(error.contains("could not capture"), "{error}");
            assert!(probe.worker.is_none());
        }
    }
}
