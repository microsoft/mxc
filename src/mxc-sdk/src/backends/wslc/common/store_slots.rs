// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A bounded pool of reusable WSLc image stores for the container-lifecycle
//! daemon.
//!
//! A WSLc "store" is a host directory the caller hands to `WslcCreateSession`;
//! the SDK creates `storage.vhdx` inside it and mounts that VHDX into the
//! session's WSL2 utility VM, where it holds the session's pulled images. Two
//! facts about that VHDX shape this module:
//!
//! - Only one live session may hold it, and the SDK does not report the
//!   conflict at create time. `WslcCreateSession` against a held store returns
//!   a healthy-looking handle, and the violation surfaces on first use as
//!   `HRESULT 0x80070020` (`ERROR_SHARING_VIOLATION`).
//! - Releasing a session only unmounts the file, so the images a lease pulled
//!   are still there for the next one.
//!
//! The second fact is what makes a fixed set of leased slots work. A fresh
//! directory has no VHDX and therefore no images, and an uncached image under
//! the default deny-egress posture is refused before the VM is ever reached —
//! so minting a new directory per session would leave every session cold and
//! break isolated provisioning outright. Slots are leased and returned instead,
//! which also bounds disk at one multi-GiB VHDX per slot.
//!
//! Lease tracking is per-process and so cannot see a store another process
//! holds. The first fact means that cannot be delegated to the SDK either, so a
//! caller must probe the store itself after create — see
//! [`container_steps::validate_store_access`](super::container_steps::validate_store_access).

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Number of store slots the pool offers when the environment does not say.
pub const DEFAULT_SLOT_COUNT: usize = 4;

/// Environment override for the slot count, as a positive whole number.
pub const SLOT_COUNT_ENV: &str = "MXC_WSLC_STORE_SLOTS";

/// Directory holding the slots, beneath the per-user application data root.
const POOL_LEAF: &str = "wslc-store-slots";

/// Resolve the pool root beneath `local_app_data`, falling back to `temp`.
///
/// The fallback stays clear of `mxc-wslc-sessions`, the create-and-run runner's
/// default store: a daemon holding that directory fails every create-and-run
/// execution for as long as a sandbox is provisioned.
fn pool_root_in(local_app_data: Option<&OsStr>, temp: &Path) -> PathBuf {
    match local_app_data.filter(|dir| !dir.is_empty()) {
        Some(dir) => Path::new(dir).join("mxc").join(POOL_LEAF),
        None => temp.join("mxc").join(POOL_LEAF),
    }
}

/// The per-user directory holding this host's store slots.
pub fn pool_root() -> PathBuf {
    pool_root_in(
        std::env::var_os("LOCALAPPDATA").as_deref(),
        &std::env::temp_dir(),
    )
}

/// Read a slot count from `raw`, falling back to [`DEFAULT_SLOT_COUNT`] when it
/// is unset, empty, non-numeric, or zero.
fn slot_count_from(raw: Option<&OsStr>) -> usize {
    raw.and_then(OsStr::to_str)
        .and_then(|text| text.trim().parse::<usize>().ok())
        .filter(|count| *count > 0)
        .unwrap_or(DEFAULT_SLOT_COUNT)
}

/// The slot count this process uses, honouring [`SLOT_COUNT_ENV`].
pub fn configured_slot_count() -> usize {
    slot_count_from(std::env::var_os(SLOT_COUNT_ENV).as_deref())
}

/// The path of slot `index` beneath `root`.
fn slot_path_in(root: &Path, index: usize) -> PathBuf {
    root.join(format!("slot-{index}"))
}

/// The path of slot `index` in this host's pool.
pub fn slot_path(index: usize) -> PathBuf {
    slot_path_in(&pool_root(), index)
}

/// Why a slot could not be leased.
#[derive(Debug)]
pub enum StoreSlotError<E> {
    /// Every slot in the pool is already leased by this process.
    Exhausted { capacity: usize },

    /// The slot directory could not be created.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },

    /// The caller refused the slot, typically because another process holds it.
    Refused {
        index: usize,
        path: PathBuf,
        source: E,
    },
}

impl<E> std::fmt::Display for StoreSlotError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreSlotError::Exhausted { capacity } => write!(
                f,
                "all {capacity} WSLc store slots are in use; raise {SLOT_COUNT_ENV} to offer more"
            ),
            StoreSlotError::Io { path, source } => write!(
                f,
                "could not create the WSLc store slot at {}: {source}",
                path.display()
            ),

            // The refusal itself is in `source`, which carries the caller's own
            // error type and is reported by whoever asked for the lease.
            StoreSlotError::Refused { index, path, .. } => write!(
                f,
                "the WSLc store slot {index} at {} could not be opened",
                path.display()
            ),
        }
    }
}

impl<E: std::fmt::Debug> std::error::Error for StoreSlotError<E> {}

/// A fixed set of reusable image stores, leased one at a time.
#[derive(Debug)]
pub struct StoreSlotPool {
    root: PathBuf,
    capacity: usize,
    leased: Arc<Mutex<BTreeSet<usize>>>,
}

impl StoreSlotPool {
    /// A pool over the per-user slot directory at the configured capacity.
    pub fn new() -> Self {
        Self::with_root(pool_root(), configured_slot_count())
    }

    /// A pool over an explicit root, for tests and tools that place slots
    /// somewhere other than the per-user directory.
    pub fn with_root(root: PathBuf, capacity: usize) -> Self {
        Self {
            root,
            capacity,
            leased: Arc::new(Mutex::new(BTreeSet::new())),
        }
    }

    /// How many slots this pool can lease at once.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// The path of slot `index`, whether or not it is leased.
    pub fn slot_path(&self, index: usize) -> PathBuf {
        slot_path_in(&self.root, index)
    }

    /// Lease the lowest free slot and open it with `open`.
    ///
    /// A refusal fails the lease rather than moving to another slot: the
    /// remaining slots are cold, and an uncached image under the default
    /// deny-egress posture is refused, so relocating would report a missing
    /// image instead of the held store that actually caused it.
    pub fn lease_with<T, E>(
        &self,
        open: impl FnOnce(&Path) -> Result<T, E>,
    ) -> Result<(StoreSlotLease, T), StoreSlotError<E>> {
        let index = self.take_lowest_free().ok_or(StoreSlotError::Exhausted {
            capacity: self.capacity,
        })?;
        let path = self.slot_path(index);

        // Built before anything can fail, so every error path below returns the
        // slot as it unwinds.
        let lease = StoreSlotLease {
            index,
            path: path.clone(),
            leased: Arc::clone(&self.leased),
        };

        if let Err(source) = std::fs::create_dir_all(&path) {
            return Err(StoreSlotError::Io { path, source });
        }

        match open(&path) {
            Ok(opened) => Ok((lease, opened)),
            Err(source) => Err(StoreSlotError::Refused {
                index,
                path,
                source,
            }),
        }
    }

    fn take_lowest_free(&self) -> Option<usize> {
        let mut leased = self.leased.lock().ok()?;
        let free = (0..self.capacity).find(|index| !leased.contains(index))?;
        leased.insert(free);
        Some(free)
    }
}

impl Default for StoreSlotPool {
    fn default() -> Self {
        Self::new()
    }
}

/// A slot held for the lifetime of one session, returned to the pool on drop.
///
/// Forgetting a lease keeps its slot held. A caller that leaks the session
/// holding the store must leak the lease with it, since the VHDX stays mounted
/// and reissuing the slot would hand out a store nothing can open.
#[derive(Debug)]
pub struct StoreSlotLease {
    index: usize,
    path: PathBuf,
    leased: Arc<Mutex<BTreeSet<usize>>>,
}

impl StoreSlotLease {
    /// Which slot this lease holds.
    pub fn index(&self) -> usize {
        self.index
    }

    /// The store directory this lease holds.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for StoreSlotLease {
    fn drop(&mut self) {
        if let Ok(mut leased) = self.leased.lock() {
            leased.remove(&self.index);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pool of `capacity` slots under a directory that deletes itself.
    fn pool(capacity: usize) -> (tempfile::TempDir, StoreSlotPool) {
        let root = tempfile::tempdir().expect("create scratch pool root");
        let pool = StoreSlotPool::with_root(root.path().to_path_buf(), capacity);
        (root, pool)
    }

    /// Accepts whatever slot it is offered.
    fn accept(path: &Path) -> Result<PathBuf, String> {
        Ok(path.to_path_buf())
    }

    #[test]
    fn a_lease_takes_the_lowest_free_slot() {
        let (_root, pool) = pool(4);

        let (first, _) = pool.lease_with(accept).expect("first lease");
        let (second, _) = pool.lease_with(accept).expect("second lease");
        let (third, _) = pool.lease_with(accept).expect("third lease");

        assert_eq!(
            [first.index(), second.index(), third.index()],
            [0, 1, 2],
            "slots must be handed out lowest first, so warming slot 0 is enough \
             for a daemon that holds one session"
        );
    }

    #[test]
    fn a_live_lease_is_never_handed_out_twice() {
        let (_root, pool) = pool(4);

        let (held, _) = pool.lease_with(accept).expect("first lease");
        let (other, _) = pool.lease_with(accept).expect("second lease");

        assert_ne!(
            held.path(),
            other.path(),
            "two live sessions sharing one store is the sharing violation this \
             pool exists to prevent"
        );
    }

    #[test]
    fn a_returned_lease_frees_its_slot_for_the_next_caller() {
        let (_root, pool) = pool(4);

        let (first, _) = pool.lease_with(accept).expect("first lease");
        let returned = first.path().to_path_buf();
        drop(first);

        let (second, _) = pool.lease_with(accept).expect("re-lease after return");

        assert_eq!(
            second.path(),
            returned,
            "a returned slot must be re-leasable; its images survive the \
             release, and reusing it is what keeps a slot warm"
        );
    }

    #[test]
    fn a_forgotten_lease_keeps_its_slot_held() {
        let (_root, pool) = pool(2);

        let (leaked, _) = pool.lease_with(accept).expect("first lease");
        let leaked_path = leaked.path().to_path_buf();
        std::mem::forget(leaked);

        let (next, _) = pool.lease_with(accept).expect("second lease");

        assert_ne!(
            next.path(),
            leaked_path,
            "teardown leaks a lease when it leaks the session holding the store, \
             and that store stays mounted"
        );
    }

    #[test]
    fn a_full_pool_reports_exhaustion() {
        let (_root, pool) = pool(2);

        let (_first, _) = pool.lease_with(accept).expect("first lease");
        let (_second, _) = pool.lease_with(accept).expect("second lease");

        match pool.lease_with(accept) {
            Err(StoreSlotError::Exhausted { capacity }) => assert_eq!(capacity, 2),
            other => panic!("a full pool must report exhaustion, got {other:?}"),
        }
    }

    #[test]
    fn a_refused_slot_fails_the_lease_rather_than_moving_to_another() {
        let (_root, pool) = pool(4);

        let refusal = pool.lease_with(|_| Err::<(), _>("store is held".to_string()));

        match refusal {
            Err(StoreSlotError::Refused { index, source, .. }) => {
                assert_eq!(index, 0);
                assert_eq!(source, "store is held");
            }
            other => panic!("a refused slot must fail the lease, got {other:?}"),
        }

        let (next, _) = pool.lease_with(accept).expect("lease after a refusal");
        assert_eq!(
            next.index(),
            0,
            "a refused slot must be returned to the pool"
        );
    }

    #[test]
    fn a_lease_creates_its_slot_directory() {
        let (_root, pool) = pool(1);

        let (lease, _) = pool.lease_with(accept).expect("lease");

        assert!(
            lease.path().is_dir(),
            "the SDK is handed this path to create storage.vhdx in"
        );
    }

    #[test]
    fn an_io_failure_returns_the_slot() {
        let root = tempfile::tempdir().expect("create scratch pool root");
        let blocker = root.path().join("blocker");
        std::fs::write(&blocker, b"").expect("write blocker");

        // Rooting the pool at a regular file makes `create_dir_all` fail
        // without depending on permissions a test cannot rely on.
        let pool = StoreSlotPool::with_root(blocker, 1);

        match pool.lease_with(accept) {
            Err(StoreSlotError::Io { .. }) => {}
            other => panic!("an uncreatable slot must report the io failure, got {other:?}"),
        }

        match pool.lease_with(accept) {
            Err(StoreSlotError::Io { .. }) => {}
            other => panic!("the slot must have been returned, got {other:?}"),
        }
    }

    #[test]
    fn the_pool_root_lives_beside_the_users_other_application_data() {
        let root = pool_root_in(
            Some(OsStr::new(r"C:\Users\u\AppData\Local")),
            Path::new(r"C:\Temp"),
        );

        assert_eq!(
            root,
            PathBuf::from(r"C:\Users\u\AppData\Local\mxc\wslc-store-slots")
        );
    }

    #[test]
    fn the_pool_root_falls_back_without_local_application_data() {
        for unusable in [None, Some(OsStr::new(""))] {
            let root = pool_root_in(unusable, Path::new(r"C:\Temp"));

            assert_eq!(root, PathBuf::from(r"C:\Temp\mxc\wslc-store-slots"));
            assert!(
                !root.ends_with("mxc-wslc-sessions"),
                "falling back onto the create-and-run store would reintroduce the \
                 collision the pool exists to remove"
            );
        }
    }

    #[test]
    fn the_slot_count_falls_back_for_a_value_it_cannot_use() {
        for unusable in [
            None,
            Some(""),
            Some("  "),
            Some("four"),
            Some("0"),
            Some("-1"),
        ] {
            assert_eq!(
                slot_count_from(unusable.map(OsStr::new)),
                DEFAULT_SLOT_COUNT,
                "{unusable:?} must not change the slot count"
            );
        }

        assert_eq!(slot_count_from(Some(OsStr::new("6"))), 6);
        assert_eq!(slot_count_from(Some(OsStr::new(" 2 "))), 2);
    }

    #[test]
    fn slot_paths_are_numbered_from_zero() {
        let root = PathBuf::from(r"C:\pool");

        let paths: Vec<_> = (0..3).map(|index| slot_path_in(&root, index)).collect();

        assert_eq!(
            paths,
            [
                PathBuf::from(r"C:\pool\slot-0"),
                PathBuf::from(r"C:\pool\slot-1"),
                PathBuf::from(r"C:\pool\slot-2"),
            ]
        );
    }

    #[test]
    fn warming_targets_the_same_store_leasing_takes() {
        let pool = StoreSlotPool::new();

        for index in 0..pool.capacity() {
            assert_eq!(
                slot_path(index),
                pool.slot_path(index),
                "warming a slot the pool would not hand out leaves the daemon cold"
            );
        }
    }
}

/// Pool behaviour that only a live WSL2 host can answer.
///
/// These drive the real SDK, so they are `#[ignore]`d and run explicitly:
///
/// ```text
/// cargo test -p mxc-sdk --features wslc --lib store_slots -- --ignored --nocapture --test-threads=1
/// ```
///
/// `--test-threads=1` matters: every test here drives the same per-user WSL
/// service, and one of them deliberately contends for a store.
#[cfg(test)]
mod host_tests {
    use super::*;

    use crate::mxc_common::logger::{Logger, Mode};
    use crate::wslc_common::container_steps::{create_daemon_session, list_session_image_names};
    use crate::wslc_common::image::pull_image;
    use crate::wslc_common::sdk_init::init_and_load_sdk;

    /// Small, and the default the container-lifecycle backend uses, so a
    /// developer's warm cache likely already has it.
    const CACHE_IMAGE: &str = "alpine:latest";

    /// A pool rooted somewhere disposable, so a run leaves no multi-GiB stores
    /// behind in the real per-user pool.
    fn scratch_pool(capacity: usize) -> (tempfile::TempDir, StoreSlotPool) {
        let root = tempfile::tempdir().expect("create scratch pool root");
        let pool = StoreSlotPool::with_root(root.path().to_path_buf(), capacity);
        (root, pool)
    }

    #[test]
    #[ignore = "requires a WSL2 host with the WSLc SDK installed"]
    fn two_leased_slots_host_two_live_sessions() {
        let mut log = Logger::new(Mode::Console);
        let sdk = unsafe { init_and_load_sdk(&mut log) }.expect("load SDK");
        let (_root, pool) = scratch_pool(4);

        let (lease_a, session_a) = pool
            .lease_with(|path| {
                // SAFETY: `sdk` is live and the pool hands out a distinct store.
                unsafe {
                    create_daemon_session(
                        sdk,
                        "mxc-slot-probe-a",
                        &path.to_string_lossy(),
                        &mut log,
                    )
                }
            })
            .expect("first lease");
        let (lease_b, session_b) = pool
            .lease_with(|path| {
                // SAFETY: `sdk` is live and the pool hands out a distinct store.
                unsafe {
                    create_daemon_session(
                        sdk,
                        "mxc-slot-probe-b",
                        &path.to_string_lossy(),
                        &mut log,
                    )
                }
            })
            .expect("second concurrent lease");

        assert_ne!(lease_a.path(), lease_b.path());

        // Both handles have to be usable *while the other is live*, not merely
        // created: a session that cannot read its store is not a working one.
        // SAFETY: both sessions are live.
        unsafe { list_session_image_names(sdk, session_a.as_raw()) }
            .expect("session A must stay usable while B is live");
        // SAFETY: both sessions are live.
        unsafe { list_session_image_names(sdk, session_b.as_raw()) }
            .expect("session B must be usable while A is live");
        // SAFETY: session A is live.
        unsafe { list_session_image_names(sdk, session_a.as_raw()) }
            .expect("session A must still be usable after B was used");

        drop(session_b);
        drop(lease_b);

        // SAFETY: session A is live.
        unsafe { list_session_image_names(sdk, session_a.as_raw()) }
            .expect("session A must survive session B's release");
    }

    #[test]
    #[ignore = "requires a WSL2 host with the WSLc SDK installed"]
    fn a_session_is_refused_when_another_process_holds_its_store() {
        let mut log = Logger::new(Mode::Console);
        let sdk = unsafe { init_and_load_sdk(&mut log) }.expect("load SDK");
        let (_root, pool) = scratch_pool(1);

        let (lease, holder) = pool
            .lease_with(|path| {
                // SAFETY: `sdk` is live and the store is a fresh directory.
                unsafe {
                    create_daemon_session(sdk, "mxc-slot-holder", &path.to_string_lossy(), &mut log)
                }
            })
            .expect("first lease");
        let store = lease.path().to_string_lossy().to_string();

        // The pool would never hand this slot out again, so take it the way a
        // process outside this pool's bookkeeping would.
        // SAFETY: `sdk` is live; this targets the held store on purpose.
        let second = unsafe { create_daemon_session(sdk, "mxc-slot-intruder", &store, &mut log) };

        let refusal = match second {
            Err(resp) => resp,
            Ok(_) => panic!(
                "a session on a held store must be refused at create; letting it \
                 through mints a sandbox id that dies at an arbitrary later phase"
            ),
        };
        assert!(
            refusal.error_message.contains("80070020"),
            "the refusal must carry the sharing violation: {}",
            refusal.error_message
        );
        assert!(
            refusal.error_message.contains(&store),
            "the refusal must name the store that is held: {}",
            refusal.error_message
        );

        // SAFETY: the holder is still live.
        unsafe { list_session_image_names(sdk, holder.as_raw()) }
            .expect("refusing the second session must leave the holder usable");
    }

    #[test]
    #[ignore = "requires a WSL2 host and network egress to pull alpine:latest"]
    fn a_returned_slot_keeps_its_cache_for_the_next_lease() {
        let mut log = Logger::new(Mode::Console);
        let sdk = unsafe { init_and_load_sdk(&mut log) }.expect("load SDK");
        let (_root, pool) = scratch_pool(1);

        let (lease, session) = pool
            .lease_with(|path| {
                // SAFETY: `sdk` is live and the pool hands out a distinct store.
                unsafe {
                    create_daemon_session(sdk, "mxc-slot-lease", &path.to_string_lossy(), &mut log)
                }
            })
            .expect("first lease");
        let store = lease.path().to_string_lossy().to_string();

        // SAFETY: the session is live.
        let cold = unsafe { list_session_image_names(sdk, session.as_raw()) }.expect("list cold");
        assert!(
            cold.is_empty(),
            "a slot that has never been leased holds no images, which is why a \
             fresh store breaks deny-egress provisioning; got {cold:?}"
        );

        // SAFETY: the session is live and the store is the one it holds.
        unsafe {
            pull_image(
                sdk,
                session.as_raw(),
                CACHE_IMAGE,
                &crate::wslc_common::image::StoreHint::DaemonSlot(lease.index()),
                "[slot]",
                &mut log,
            )
        }
        .expect("pull must succeed; this test needs egress");
        // SAFETY: the session is live.
        let warmed = unsafe { list_session_image_names(sdk, session.as_raw()) }.expect("list warm");
        assert!(!warmed.is_empty(), "the pull must have filled the store");

        drop(session);
        drop(lease);

        let (next_lease, next_session) = pool
            .lease_with(|path| {
                // SAFETY: `sdk` is live and the pool hands out a distinct store.
                unsafe {
                    create_daemon_session(sdk, "mxc-slot-lease", &path.to_string_lossy(), &mut log)
                }
            })
            .expect("re-lease after return");
        assert_eq!(next_lease.path().to_string_lossy(), store);
        // SAFETY: the session is live.
        let reopened =
            unsafe { list_session_image_names(sdk, next_session.as_raw()) }.expect("list reopened");

        assert_eq!(
            warmed, reopened,
            "a re-leased slot must present the cache it had at release; losing it \
             would leave every lease cold and make the pool pointless"
        );
    }
}
