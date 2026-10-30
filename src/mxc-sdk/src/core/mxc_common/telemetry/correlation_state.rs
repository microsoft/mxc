// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Per-sandbox telemetry correlation with independent vectors for session operations.
//!
//! Missing sandbox records establish a new persistent random root. Unavailable
//! storage reports a diagnostic and falls back to disconnected correlation.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use crate::mxc_common::mxc_error::{MxcError, MxcErrorCode};
use crate::mxc_common::state_aware_dispatch::DispatchOutcome;
use crate::mxc_common::state_aware_request::Phase;

use super::correlation_vector::{is_relayable, seed, spin};

const RECORD_EXTENSION: &str = "cv";
const STALE_RECORD_MAX_AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const STALE_TMP_FILE_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);
const STORE_LOCK_RETRY_COUNT: usize = 200;
const STORE_LOCK_RETRY_DELAY: Duration = Duration::from_millis(5);
const PRUNE_DELETE_LIMIT: usize = 256;

/// Seed session/provision phases or recall and spin a sandbox's persisted root.
/// Inactive telemetry does not generate vectors or access correlation storage.
pub fn pre_dispatch_vector(active: bool, phase: Phase, sandbox_id: Option<&str>) -> String {
    if !active {
        return String::new();
    }
    if matches!(phase, Phase::ProvisionSession | Phase::DeprovisionSession) {
        return seed();
    }
    match sandbox_id {
        Some(id) if phase != Phase::Provision => {
            // Load and refresh the active lifecycle before sweeping abandoned
            // records. Otherwise a valid sandbox whose last phase was over the
            // retention threshold ago would delete its own root here.
            phase_vector(id)
        }
        _ => {
            prune_stale_records(None);
            seed()
        }
    }
}

/// After a `provision` dispatch, persist `root` (this phase's already-computed
/// vector, from [`pre_dispatch_vector`]) keyed by the freshly minted
/// `sandbox_id` extracted from the success envelope, so later phases of this
/// lifecycle can spin off it. An inactive successful provision removes stale
/// state for a reused id, without creating a new record. Failed dispatches and
/// envelopes without `result.sandboxId` leave existing state unchanged.
pub fn on_provision_outcome(active: bool, root: &str, outcome: &Result<DispatchOutcome, MxcError>) {
    if let Ok(DispatchOutcome::Envelope(value)) = outcome {
        if let Some(sandbox_id) = value
            .get("result")
            .and_then(|result| result.get("sandboxId"))
            .and_then(|id| id.as_str())
        {
            on_typed_provision_result(active, root, Some(sandbox_id));
        }
    }
}

/// Persist a typed provision result without requiring a JSON response envelope.
#[doc(hidden)]
pub fn on_typed_provision_result(active: bool, root: &str, sandbox_id: Option<&str>) {
    if let Some(sandbox_id) = sandbox_id {
        if active {
            persist(sandbox_id, root);
        } else {
            with_store(|store| store.forget(sandbox_id));
        }
    }
}

/// After a `deprovision` dispatch succeeds, forget `sandbox_id`'s persisted
/// lifecycle root. Dry runs keep the record intact, because the sandbox still
/// exists. Terminal `not_provisioned` outcomes are also safe to forget: the
/// backend has already proved the sandbox is absent, so the correlation record
/// is stale. Cleanup deliberately does **not** depend on `active`; a sandbox
/// can outlive telemetry authorization, and its best-effort correlation record
/// should still be reaped when the lifecycle ends.
pub fn on_deprovision_outcome(
    _active: bool,
    sandbox_id: &str,
    dry_run: bool,
    outcome: &Result<DispatchOutcome, MxcError>,
) {
    if dry_run || !should_forget_after_deprovision(outcome) {
        return;
    }
    with_store(|store| store.forget(sandbox_id));
}

/// Reap correlation state after a typed deprovision result.
#[doc(hidden)]
pub fn on_typed_deprovision_result(
    sandbox_id: &str,
    dry_run: bool,
    outcome: &Result<(), MxcError>,
) {
    if dry_run || !should_forget_after_deprovision(outcome) {
        return;
    }
    with_store(|store| store.forget(sandbox_id));
}

fn should_forget_after_deprovision<T>(outcome: &Result<T, MxcError>) -> bool {
    match outcome {
        Ok(_) => true,
        Err(error) => error.code == MxcErrorCode::NotProvisioned,
    }
}

/// Recall or atomically establish the lifecycle root, then spin a child.
fn phase_vector(sandbox_id: &str) -> String {
    match with_store(|store| store.load_and_prune(sandbox_id)) {
        Some(root) if is_relayable(&root) => spin(&root),
        _ => {
            report_store_failure();
            seed()
        }
    }
}

fn report_store_failure() {
    use std::io::Write;
    static REPORTED: std::sync::Once = std::sync::Once::new();
    REPORTED.call_once(|| {
        let _ = writeln!(
            std::io::stderr().lock(),
            "telemetry: lifecycle correlation state unavailable or invalid; session continuity is not guaranteed"
        );
    });
}

fn persist(sandbox_id: &str, root: &str) {
    with_store(|store| store.persist(sandbox_id, root));
}

/// Directory holding one record per live sandbox lifecycle. Uses the same
/// per-user root resolution as the telemetry consent store.
fn store_dir() -> Option<PathBuf> {
    store_dir_from_local_app_data(super::consent::local_app_data_dir())
}

fn store_dir_from_local_app_data(base: Option<PathBuf>) -> Option<PathBuf> {
    Some(base?.join("mxc").join("correlation"))
}

/// Filesystem-safe, non-reversible lookup key for `sandbox_id`.
///
/// Hashed rather than used verbatim so (a) an id containing characters unsafe
/// for a path component on some future backend can never reach the file
/// system, and (b) caller-supplied data a backend may embed in its sandbox id
/// (e.g. IsolationSession's `appId`) is never written to disk as a
/// directory-listable plaintext name. This hash is a local lookup key only —
/// it never appears in emitted telemetry.
fn record_key(sandbox_id: &str) -> String {
    crate::mxc_common::hashing::sha256_hex(sandbox_id.as_bytes())
}

fn prune_stale_records(protected_sandbox_id: Option<&str>) {
    with_store(|store| store.prune_stale(protected_sandbox_id));
}

fn with_store<R>(f: impl FnOnce(&dyn CorrelationStore) -> R) -> R {
    #[cfg(any(test, feature = "test-support", debug_assertions))]
    if let Some(store) = test_support::store_override() {
        return f(store.as_ref());
    }

    let store = FilesystemCorrelationStore::from_env();
    f(&store)
}

pub(crate) trait CorrelationStore: Send + Sync {
    fn persist(&self, sandbox_id: &str, root: &str);
    #[cfg(test)]
    fn load(&self, sandbox_id: &str) -> Option<String>;
    /// Load or create under the same operation lock, protecting the active record.
    fn load_and_prune(&self, sandbox_id: &str) -> Option<String>;
    fn forget(&self, sandbox_id: &str);
    fn prune_stale(&self, protected_sandbox_id: Option<&str>);
}

struct FilesystemCorrelationStore {
    dir: Option<PathBuf>,
}

struct StoreOperationLock {
    _file: fs::File,
}

#[cfg(unix)]
fn try_lock_file(file: &fs::File) -> bool {
    use std::os::fd::AsRawFd;

    // SAFETY: `file` owns a valid descriptor for the duration of this call.
    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) == 0 }
}

#[cfg(windows)]
fn try_lock_file(file: &fs::File) -> bool {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
    };
    use windows::Win32::System::IO::OVERLAPPED;

    // SAFETY: the handle remains valid for the lock's lifetime because the
    // returned guard owns `file`; the zeroed OVERLAPPED selects byte offset 0.
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    unsafe {
        LockFileEx(
            HANDLE(file.as_raw_handle()),
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            None,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
        .is_ok()
    }
}

impl FilesystemCorrelationStore {
    fn from_env() -> Self {
        Self { dir: store_dir() }
    }

    #[cfg(any(test, feature = "test-support", debug_assertions))]
    fn from_store_root(dir: PathBuf) -> Self {
        Self { dir: Some(dir) }
    }

    fn record_path(&self, sandbox_id: &str) -> Option<PathBuf> {
        self.dir
            .as_ref()
            .map(|dir| dir.join(format!("{}.{}", record_key(sandbox_id), RECORD_EXTENSION)))
    }

    fn tmp_path(&self, sandbox_id: &str) -> Option<PathBuf> {
        self.dir.as_ref().map(|dir| {
            dir.join(format!(
                ".{}.tmp-{}-{}",
                record_key(sandbox_id),
                std::process::id(),
                tmp_nonce(),
            ))
        })
    }

    fn operation_lock(&self) -> Option<StoreOperationLock> {
        let dir = self.dir.as_ref()?;
        if fs::create_dir_all(dir).is_err() {
            return None;
        }
        let path = dir.join(".store-lock");
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)
            .ok()?;
        for _ in 0..STORE_LOCK_RETRY_COUNT {
            if try_lock_file(&file) {
                return Some(StoreOperationLock { _file: file });
            }
            std::thread::sleep(STORE_LOCK_RETRY_DELAY);
        }
        None
    }

    fn read_record(path: &Path) -> Option<String> {
        fs::read_to_string(path).ok().map(|s| s.trim().to_string())
    }

    fn refresh_record(path: &Path) {
        let times = fs::FileTimes::new().set_modified(SystemTime::now());
        if let Ok(file) = fs::OpenOptions::new().write(true).open(path) {
            let _ = file.set_times(times);
        }
    }

    fn load_unlocked(&self, sandbox_id: &str) -> Option<String> {
        let path = self.record_path(sandbox_id)?;
        if let Some(root) = Self::read_record(&path) {
            if is_relayable(&root) {
                Self::refresh_record(&path);
                return Some(root);
            }
            report_store_failure();
            let _ = fs::remove_file(&path);
        } else if !matches!(path.try_exists(), Ok(false)) {
            report_store_failure();
        }
        None
    }

    fn write_record(&self, sandbox_id: &str, path: &Path, root: &str) -> bool {
        let Some(dir) = path.parent() else {
            return false;
        };
        if fs::create_dir_all(dir).is_err() {
            return false;
        }

        let Some(tmp) = self.tmp_path(sandbox_id) else {
            return false;
        };
        if fs::write(&tmp, root).is_err() {
            return false;
        }
        if fs::rename(&tmp, path).is_err() {
            let _ = fs::remove_file(path);
            if fs::rename(&tmp, path).is_err() {
                let _ = fs::remove_file(&tmp);
                return false;
            }
        }
        true
    }

    fn tmp_file(path: &Path) -> bool {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with('.') && name.contains(".tmp-"))
    }

    fn file_age(path: &Path, now: SystemTime) -> Option<Duration> {
        let Ok(metadata) = fs::metadata(path) else {
            return None;
        };
        let Ok(modified) = metadata.modified() else {
            return None;
        };
        now.duration_since(modified).ok()
    }

    fn stale_tmp_file(path: &Path, now: SystemTime) -> bool {
        Self::file_age(path, now)
            .map(|age| age > STALE_TMP_FILE_MAX_AGE)
            .unwrap_or(false)
    }

    fn stale_record(path: &Path, now: SystemTime) -> bool {
        Self::file_age(path, now)
            .map(|age| age > STALE_RECORD_MAX_AGE)
            .unwrap_or(false)
    }

    fn prune_stale_unlocked(&self, protected_sandbox_id: Option<&str>) {
        let Some(dir) = self.dir.as_ref() else {
            return;
        };
        let protected_path =
            protected_sandbox_id.and_then(|sandbox_id| self.record_path(sandbox_id));
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        let now = SystemTime::now();
        let mut deleted = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            if Self::tmp_file(&path) {
                if deleted < PRUNE_DELETE_LIMIT && Self::stale_tmp_file(&path, now) {
                    let _ = fs::remove_file(path);
                    deleted += 1;
                }
                continue;
            }
            if path.extension().and_then(|ext| ext.to_str()) != Some(RECORD_EXTENSION) {
                continue;
            }
            if protected_path.as_deref() == Some(path.as_path()) {
                continue;
            }
            if deleted < PRUNE_DELETE_LIMIT && Self::stale_record(&path, now) {
                let _ = fs::remove_file(path);
                deleted += 1;
            }
        }
    }
}

impl CorrelationStore for FilesystemCorrelationStore {
    fn persist(&self, sandbox_id: &str, root: &str) {
        let Some(_lock) = self.operation_lock() else {
            report_store_failure();
            return;
        };
        let Some(path) = self.record_path(sandbox_id) else {
            report_store_failure();
            return;
        };
        if !self.write_record(sandbox_id, &path, root) {
            report_store_failure();
        }
    }

    #[cfg(test)]
    fn load(&self, sandbox_id: &str) -> Option<String> {
        let _lock = self.operation_lock()?;
        self.load_unlocked(sandbox_id)
    }

    fn load_and_prune(&self, sandbox_id: &str) -> Option<String> {
        let _lock = self.operation_lock()?;
        let root = match self.load_unlocked(sandbox_id) {
            Some(root) => root,
            None => {
                let root = seed();
                let path = self.record_path(sandbox_id)?;
                if !self.write_record(sandbox_id, &path, &root) {
                    return None;
                }
                root
            }
        };
        self.prune_stale_unlocked(Some(sandbox_id));
        Some(root)
    }

    fn forget(&self, sandbox_id: &str) {
        let Some(path) = self.record_path(sandbox_id) else {
            return;
        };
        match path.try_exists() {
            Ok(false) => return,
            Ok(true) => {}
            Err(_) => {
                report_store_failure();
                return;
            }
        }
        let Some(_lock) = self.operation_lock() else {
            report_store_failure();
            return;
        };
        if let Err(error) = fs::remove_file(path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                report_store_failure();
            }
        }
    }

    fn prune_stale(&self, protected_sandbox_id: Option<&str>) {
        let Some(_lock) = self.operation_lock() else {
            return;
        };
        self.prune_stale_unlocked(protected_sandbox_id);
    }
}

#[cfg(any(test, feature = "test-support", debug_assertions))]
pub mod test_support {
    use std::path::Path;
    use std::sync::{Arc, Mutex, MutexGuard};

    use super::{CorrelationStore, FilesystemCorrelationStore};

    static STORE_OVERRIDE: Mutex<Option<Arc<dyn CorrelationStore>>> = Mutex::new(None);
    static OVERRIDE_LOCK: Mutex<()> = Mutex::new(());

    pub(crate) fn lock_test_environment() -> MutexGuard<'static, ()> {
        OVERRIDE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn store_override() -> Option<Arc<dyn CorrelationStore>> {
        STORE_OVERRIDE
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub(crate) fn replace_store(store: Arc<dyn CorrelationStore>) -> StoreGuard {
        let lock = lock_test_environment();
        let previous = STORE_OVERRIDE
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .replace(store);
        StoreGuard {
            previous,
            _lock: lock,
        }
    }

    pub(crate) struct StoreGuard {
        previous: Option<Arc<dyn CorrelationStore>>,
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for StoreGuard {
        fn drop(&mut self) {
            *STORE_OVERRIDE.lock().unwrap_or_else(|e| e.into_inner()) = self.previous.take();
        }
    }

    pub struct StoreDirGuard {
        _guard: StoreGuard,
    }

    impl StoreDirGuard {
        pub fn set(dir: &Path) -> Self {
            Self {
                _guard: replace_store(Arc::new(FilesystemCorrelationStore::from_store_root(
                    dir.to_path_buf(),
                ))),
            }
        }
    }
}

/// Process-wide monotonic nonce so concurrent persists within the same
/// process never collide on the same temp-file name.
fn tmp_nonce() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use filetime::FileTime;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use test_support::{replace_store, StoreDirGuard};

    #[derive(Default)]
    struct MemoryStore {
        records: Mutex<HashMap<String, String>>,
        prune_count: Mutex<usize>,
    }

    impl CorrelationStore for MemoryStore {
        fn persist(&self, sandbox_id: &str, root: &str) {
            self.records
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(sandbox_id.to_string(), root.to_string());
        }

        fn load(&self, sandbox_id: &str) -> Option<String> {
            self.records
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(sandbox_id)
                .cloned()
        }

        fn load_and_prune(&self, sandbox_id: &str) -> Option<String> {
            let root = self
                .records
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .entry(sandbox_id.to_owned())
                .or_insert_with(seed)
                .clone();
            self.prune_stale(Some(sandbox_id));
            Some(root)
        }

        fn forget(&self, sandbox_id: &str) {
            self.records
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(sandbox_id);
        }

        fn prune_stale(&self, _protected_sandbox_id: Option<&str>) {
            *self.prune_count.lock().unwrap_or_else(|e| e.into_inner()) += 1;
        }
    }

    impl MemoryStore {
        fn record(&self, sandbox_id: &str) -> Option<String> {
            self.records
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(sandbox_id)
                .cloned()
        }
    }

    fn provision_envelope(sandbox_id: &str) -> Result<DispatchOutcome, MxcError> {
        Ok(DispatchOutcome::Envelope(
            json!({ "result": { "sandboxId": sandbox_id } }),
        ))
    }

    #[test]
    fn inactive_pre_dispatch_vector_is_empty() {
        assert_eq!(pre_dispatch_vector(false, Phase::Provision, None), "");
        assert_eq!(
            pre_dispatch_vector(false, Phase::Exec, Some("wsb:abcdef01")),
            ""
        );
    }

    #[test]
    fn session_phases_seed_without_sweeping_sandbox_records() {
        let store = Arc::new(MemoryStore::default());
        let _guard = replace_store(store.clone());
        let root = seed();
        store.persist("wslc:existing", &root);

        for phase in [Phase::ProvisionSession, Phase::DeprovisionSession] {
            assert_eq!(pre_dispatch_vector(false, phase, None), "");
            let first = pre_dispatch_vector(true, phase, None);
            let second = pre_dispatch_vector(true, phase, None);
            assert!(is_relayable(&first));
            assert!(is_relayable(&second));
            assert_ne!(first, second);
        }
        assert_eq!(*store.prune_count.lock().unwrap(), 0);
        assert_eq!(
            store.record("wslc:existing").as_deref(),
            Some(root.as_str())
        );
    }

    #[test]
    fn session_phases_do_not_create_a_correlation_store_or_lock() {
        let directory = tempfile::tempdir().unwrap();
        let store = directory.path().join("correlation");
        let _guard = StoreDirGuard::set(&store);

        for phase in [Phase::ProvisionSession, Phase::DeprovisionSession] {
            assert!(is_relayable(&pre_dispatch_vector(true, phase, None)));
        }
        assert!(
            !store.exists(),
            "session phases must not access the sandbox correlation store"
        );
    }

    #[test]
    fn provision_seeds_and_non_provision_without_sandbox_id_seeds() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = StoreDirGuard::set(tmp.path());

        let provisioned = pre_dispatch_vector(true, Phase::Provision, None);
        assert!(is_relayable(&provisioned));

        // A non-provision phase with no sandbox_id (should never happen in
        // practice; the parser requires one) still degrades to a fresh seed
        // rather than panicking or emitting an empty vector.
        let no_id = pre_dispatch_vector(true, Phase::Exec, None);
        assert!(is_relayable(&no_id));
    }

    #[test]
    fn full_lifecycle_shares_one_root_until_deprovision() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = StoreDirGuard::set(tmp.path());
        let sandbox_id = "wsb:12345678";

        // provision: seed, then persist once the id is known.
        let provisioned = pre_dispatch_vector(true, Phase::Provision, None);
        on_provision_outcome(true, &provisioned, &provision_envelope(sandbox_id));

        let base_of = |cv: &str| cv.split('.').next().unwrap().to_string();
        let provisioned_base = base_of(&provisioned);

        // start / exec / stop all recall the same root and spin off it.
        for phase in [Phase::Start, Phase::Exec, Phase::Stop] {
            let spun = pre_dispatch_vector(true, phase, Some(sandbox_id));
            assert!(is_relayable(&spun));
            assert_eq!(base_of(&spun), provisioned_base);
            assert_ne!(
                spun, provisioned,
                "phase must spin, not pass the root through"
            );
        }

        // deprovision recalls the same root one last time, then forgets it.
        let deprovisioned = pre_dispatch_vector(true, Phase::Deprovision, Some(sandbox_id));
        assert_eq!(base_of(&deprovisioned), provisioned_base);
        on_deprovision_outcome(
            true,
            sandbox_id,
            false,
            &Ok(DispatchOutcome::Envelope(json!({}))),
        );

        // A later phase (e.g. a caller mistakenly reusing the id after
        // teardown) finds no record and gets a disconnected vector.
        let after_teardown = pre_dispatch_vector(true, Phase::Exec, Some(sandbox_id));
        assert_ne!(base_of(&after_teardown), provisioned_base);
    }

    #[test]
    fn typed_lifecycle_hooks_share_and_reap_the_correlation_root() {
        let store = Arc::new(MemoryStore::default());
        let _guard = replace_store(store.clone());
        let sandbox_id = "iso:typed000";
        let root = seed();

        on_typed_provision_result(true, &root, Some(sandbox_id));
        assert_eq!(store.record(sandbox_id).as_deref(), Some(root.as_str()));

        on_typed_deprovision_result(sandbox_id, false, &Ok(()));
        assert!(store.record(sandbox_id).is_none());
    }

    #[test]
    fn typed_deprovision_failure_keeps_the_correlation_root() {
        let store = Arc::new(MemoryStore::default());
        let _guard = replace_store(store.clone());
        let sandbox_id = "iso:typed001";
        let root = seed();

        on_typed_provision_result(true, &root, Some(sandbox_id));
        on_typed_deprovision_result(sandbox_id, false, &Err(MxcError::backend_error("retry")));

        assert_eq!(store.record(sandbox_id).as_deref(), Some(root.as_str()));
    }

    #[test]
    fn failed_deprovision_keeps_the_record_for_a_retry() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = StoreDirGuard::set(tmp.path());
        let sandbox_id = "wsb:87654321";

        let provisioned = pre_dispatch_vector(true, Phase::Provision, None);
        on_provision_outcome(true, &provisioned, &provision_envelope(sandbox_id));
        let provisioned_base = provisioned.split('.').next().unwrap().to_string();

        on_deprovision_outcome(
            true,
            sandbox_id,
            false,
            &Err(MxcError::backend_error("teardown failed, please retry")),
        );

        let retried = pre_dispatch_vector(true, Phase::Deprovision, Some(sandbox_id));
        assert_eq!(
            retried.split('.').next().unwrap(),
            provisioned_base,
            "a failed deprovision must not drop the lineage a retry needs"
        );
    }

    #[test]
    fn malformed_provision_envelope_persists_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = StoreDirGuard::set(tmp.path());

        let provisioned = pre_dispatch_vector(true, Phase::Provision, None);
        // No `result.sandboxId` at all.
        on_provision_outcome(
            true,
            &provisioned,
            &Ok(DispatchOutcome::Envelope(json!({}))),
        );

        // The first later authorized phase establishes a new lifecycle root.
        let a = pre_dispatch_vector(true, Phase::Exec, Some("wsb:abcdef01"));
        let b = pre_dispatch_vector(true, Phase::Exec, Some("wsb:abcdef01"));
        assert_eq!(
            a.split('.').next().unwrap(),
            b.split('.').next().unwrap(),
            "late-enabled phases must retain the same newly established root"
        );
    }

    #[test]
    fn failed_provision_persists_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = StoreDirGuard::set(tmp.path());

        let provisioned = pre_dispatch_vector(true, Phase::Provision, None);
        on_provision_outcome(
            true,
            &provisioned,
            &Err(MxcError::backend_error("provisioning failed")),
        );

        let a = pre_dispatch_vector(true, Phase::Exec, Some("wsb:abcdef01"));
        let b = pre_dispatch_vector(true, Phase::Exec, Some("wsb:abcdef01"));
        assert_eq!(a.split('.').next().unwrap(), b.split('.').next().unwrap());
        assert_ne!(
            a.split('.').next().unwrap(),
            provisioned.split('.').next().unwrap()
        );
    }

    #[test]
    fn inactive_provision_does_not_persist_and_terminal_deprovision_still_reaps() {
        let store = Arc::new(MemoryStore::default());
        let _guard = replace_store(store.clone());
        let sandbox_id = "wsb:00000000";

        on_provision_outcome(false, "unused", &provision_envelope(sandbox_id));
        assert!(store.record(sandbox_id).is_none());

        // Persist a record the normal way, then confirm the inactive
        // deprovision hook still reaps terminal state.
        store.persist(sandbox_id, &seed());
        on_deprovision_outcome(
            false,
            sandbox_id,
            false,
            &Ok(DispatchOutcome::Envelope(json!({}))),
        );
        assert!(store.record(sandbox_id).is_none());
    }

    #[test]
    fn corrupted_record_is_ignored_in_favor_of_a_fresh_seed() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = StoreDirGuard::set(tmp.path());
        let sandbox_id = "wsb:deadbeef";

        let store = FilesystemCorrelationStore::from_store_root(tmp.path().to_path_buf());
        let dir = store.dir.clone().unwrap();
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            store.record_path(sandbox_id).unwrap(),
            "not a correlation vector",
        )
        .unwrap();

        let cv = phase_vector(sandbox_id);
        assert!(is_relayable(&cv));
    }

    #[test]
    fn concurrent_persists_for_distinct_ids_do_not_collide_on_temp_names() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = StoreDirGuard::set(tmp.path());

        std::thread::scope(|scope| {
            for i in 0..8 {
                scope.spawn(move || {
                    let id = format!("wsb:{i:08x}");
                    with_store(|store| store.persist(&id, &seed()));
                    assert!(with_store(|store| store.load(&id)).is_some());
                });
            }
        });
    }

    #[test]
    fn record_key_is_stable_for_known_ids() {
        assert_eq!(
            record_key("wsb:12345678"),
            "a07f3dda1aa7493db2d1d4b1d1b4ed42c1d46b3065dca6f06213250159e1d508"
        );
        assert_eq!(
            record_key("iso:reg-abc:prov-1"),
            "d197043201237934ad09c7caf1e56ee322f07189c2c3918ee24e9243e355b959"
        );
    }

    #[test]
    fn pruning_runs_on_each_initialization() {
        let store = Arc::new(MemoryStore::default());
        let _guard = replace_store(store.clone());

        let _ = pre_dispatch_vector(true, Phase::Provision, None);
        let _ = pre_dispatch_vector(true, Phase::Provision, None);

        assert_eq!(
            *store.prune_count.lock().unwrap_or_else(|e| e.into_inner()),
            2
        );
    }

    #[test]
    fn dry_run_deprovision_preserves_the_record() {
        let store = Arc::new(MemoryStore::default());
        let _guard = replace_store(store.clone());
        let sandbox_id = "wsb:dryrun01";
        let root = seed();
        let base = root.split('.').next().unwrap().to_string();

        on_provision_outcome(true, &root, &provision_envelope(sandbox_id));
        on_deprovision_outcome(
            true,
            sandbox_id,
            true,
            &Ok(DispatchOutcome::Envelope(json!({}))),
        );

        assert_eq!(
            store.record(sandbox_id).unwrap().split('.').next().unwrap(),
            base
        );
        let later = pre_dispatch_vector(true, Phase::Exec, Some(sandbox_id));
        assert_eq!(later.split('.').next().unwrap(), base);
    }

    #[test]
    fn not_provisioned_deprovision_forgets_the_record() {
        let store = Arc::new(MemoryStore::default());
        let _guard = replace_store(store.clone());
        let sandbox_id = "wsb:missing01";
        on_provision_outcome(true, &seed(), &provision_envelope(sandbox_id));

        on_deprovision_outcome(
            true,
            sandbox_id,
            false,
            &Err(MxcError::not_provisioned("sandbox already removed")),
        );

        assert!(store.record(sandbox_id).is_none());
    }

    #[test]
    fn missing_localappdata_disables_persistence_instead_of_using_shared_temp() {
        assert_eq!(store_dir_from_local_app_data(None), None);
    }

    #[test]
    fn requested_long_lived_record_is_refreshed_while_unrelated_stale_record_is_pruned() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = StoreDirGuard::set(tmp.path());
        let sandbox_id = "wsb:active00";
        let abandoned_id = "wsb:stale000";
        let root = seed();
        let base = root.split('.').next().unwrap().to_string();
        let store = FilesystemCorrelationStore::from_store_root(tmp.path().to_path_buf());
        let path = store.record_path(sandbox_id).unwrap();
        let abandoned_path = store.record_path(abandoned_id).unwrap();
        fs::create_dir_all(tmp.path()).unwrap();
        fs::write(&path, &root).unwrap();
        fs::write(&abandoned_path, seed()).unwrap();
        let stale_time = SystemTime::now() - STALE_RECORD_MAX_AGE - Duration::from_secs(1);
        filetime::set_file_mtime(&path, FileTime::from_system_time(stale_time)).unwrap();
        filetime::set_file_mtime(&abandoned_path, FileTime::from_system_time(stale_time)).unwrap();

        let spun = pre_dispatch_vector(true, Phase::Exec, Some(sandbox_id));
        assert_eq!(spun.split('.').next().unwrap(), base);
        assert!(path.exists());
        assert!(
            FilesystemCorrelationStore::file_age(&path, SystemTime::now()).unwrap()
                < Duration::from_secs(10),
            "successful load must refresh the active record's age"
        );
        assert!(!abandoned_path.exists());
    }

    #[test]
    fn store_lock_excludes_a_second_file_handle_until_release() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(".store-lock");
        let first = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let second = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();

        assert!(try_lock_file(&first));
        assert!(!try_lock_file(&second));
        drop(first);
        assert!(try_lock_file(&second));
    }

    #[test]
    fn future_dated_record_survives_startup_sweep() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = StoreDirGuard::set(tmp.path());
        let sandbox_id = "wsb:future00";
        let root = seed();
        let base = root.split('.').next().unwrap().to_string();
        let store = FilesystemCorrelationStore::from_store_root(tmp.path().to_path_buf());
        let path = store.record_path(sandbox_id).unwrap();
        fs::create_dir_all(tmp.path()).unwrap();
        fs::write(&path, &root).unwrap();
        filetime::set_file_mtime(
            &path,
            FileTime::from_system_time(SystemTime::now() + Duration::from_secs(60)),
        )
        .unwrap();

        let spun = pre_dispatch_vector(true, Phase::Exec, Some(sandbox_id));
        assert_eq!(spun.split('.').next().unwrap(), base);
        assert!(path.exists());
    }

    #[test]
    fn startup_sweep_bounds_stale_deletions() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = StoreDirGuard::set(tmp.path());
        fs::create_dir_all(tmp.path()).unwrap();
        let stale_time = SystemTime::now() - STALE_RECORD_MAX_AGE - Duration::from_secs(1);
        for index in 0..(PRUNE_DELETE_LIMIT + 10) {
            let path = tmp.path().join(format!("{index}.{RECORD_EXTENSION}"));
            fs::write(&path, seed()).unwrap();
            filetime::set_file_mtime(&path, FileTime::from_system_time(stale_time)).unwrap();
        }

        let _ = pre_dispatch_vector(true, Phase::Provision, None);

        let remaining_records = fs::read_dir(tmp.path())
            .unwrap()
            .flatten()
            .filter(|entry| {
                entry.path().extension().and_then(|ext| ext.to_str()) == Some(RECORD_EXTENSION)
            })
            .count();
        assert_eq!(remaining_records, 10);
    }

    #[test]
    fn fresh_tmp_file_survives_startup_sweep() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = StoreDirGuard::set(tmp.path());
        let store = FilesystemCorrelationStore::from_store_root(tmp.path().to_path_buf());
        let tmp_path = store.tmp_path("wsb:fresh000").unwrap();
        fs::create_dir_all(tmp.path()).unwrap();
        fs::write(&tmp_path, seed()).unwrap();
        let _ = pre_dispatch_vector(true, Phase::Provision, None);

        assert!(
            tmp_path.exists(),
            "fresh in-progress temp files must not be reaped by startup pruning"
        );
    }

    #[test]
    fn stale_tmp_file_is_pruned_during_startup_sweep() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = StoreDirGuard::set(tmp.path());
        let store = FilesystemCorrelationStore::from_store_root(tmp.path().to_path_buf());
        let tmp_path = store.tmp_path("wsb:staletmp").unwrap();
        fs::create_dir_all(tmp.path()).unwrap();
        fs::write(&tmp_path, seed()).unwrap();
        filetime::set_file_mtime(
            &tmp_path,
            FileTime::from_system_time(
                SystemTime::now() - STALE_TMP_FILE_MAX_AGE - Duration::from_secs(1),
            ),
        )
        .unwrap();
        let _ = pre_dispatch_vector(true, Phase::Provision, None);

        assert!(
            !tmp_path.exists(),
            "stale temp files should still be reaped"
        );
    }

    #[test]
    fn concurrent_late_enabled_phases_establish_one_root() {
        let tmp = tempfile::tempdir().unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let dir = tmp.path().to_path_buf();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    FilesystemCorrelationStore::from_store_root(dir)
                        .load_and_prune("synthetic-container")
                        .expect("root persisted")
                })
            })
            .collect();
        let roots: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert!(roots.iter().all(|root| root == &roots[0]));
    }

    #[test]
    fn inactive_provision_clears_stale_state_for_a_reused_container_id() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = StoreDirGuard::set(tmp.path());
        let old = pre_dispatch_vector(true, Phase::Provision, None);
        on_typed_provision_result(true, &old, Some("synthetic-container"));
        on_typed_provision_result(false, "", Some("synthetic-container"));
        let store = FilesystemCorrelationStore::from_store_root(tmp.path().to_path_buf());
        assert_eq!(store.load("synthetic-container"), None);
        let next = pre_dispatch_vector(true, Phase::Exec, Some("synthetic-container"));
        assert_ne!(
            super::super::session::from_vector(&old),
            super::super::session::from_vector(&next)
        );
    }

    #[test]
    fn child_process_lifecycle_session_probe() {
        let Some(dir) = std::env::var_os("MXC_TEST_LIFECYCLE_SESSION_STORE") else {
            return;
        };
        let _guard = StoreDirGuard::set(Path::new(&dir));
        let vector = pre_dispatch_vector(true, Phase::Exec, Some("synthetic-container"));
        let mut logger =
            crate::mxc_common::logger::Logger::new(crate::mxc_common::logger::Mode::Buffer);
        let _session = super::super::session::start(true, &vector, &mut logger);
        let id = super::super::session::current().expect("valid session");
        fs::write(
            std::env::var_os("MXC_TEST_LIFECYCLE_SESSION_OUTPUT").unwrap(),
            id.to_string(),
        )
        .unwrap();
    }

    #[test]
    fn lifecycle_session_survives_separate_executor_processes_and_rotates_after_cleanup() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = StoreDirGuard::set(tmp.path());
        let root = pre_dispatch_vector(true, Phase::Provision, None);
        on_typed_provision_result(true, &root, Some("synthetic-container"));
        let expected = super::super::session::from_vector(&root)
            .unwrap()
            .to_string();
        let output = tmp.path().join("synthetic-session-result.txt");
        let child_session = || {
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "core_modules::mxc_common::telemetry::correlation_state::tests::child_process_lifecycle_session_probe",
                    "--test-threads=1",
                ])
                .env("MXC_TEST_LIFECYCLE_SESSION_STORE", tmp.path())
                .env("MXC_TEST_LIFECYCLE_SESSION_OUTPUT", &output)
                .output()
                .unwrap();
            assert!(child.status.success(), "{child:?}");
            fs::read_to_string(&output).unwrap()
        };
        for _phase in ["start", "exec", "exec", "stop", "deprovision"] {
            assert_eq!(child_session(), expected);
        }
        on_typed_deprovision_result("synthetic-container", false, &Ok(()));
        // Telemetry first enabled after provision still establishes one stable
        // new segment, shared by subsequent independent executor processes.
        let next = child_session();
        assert_ne!(next, expected);
        assert_eq!(child_session(), next);
    }
}
