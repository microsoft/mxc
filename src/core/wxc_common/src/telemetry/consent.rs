// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Persisted, per-user telemetry consent.
//!
//! See `docs/telemetry/telemetry-consent-design.md` for the full design and
//! privacy rationale. In short:
//!
//! - MXC does not and must not collect telemetry on any platform other than
//!   Windows, so this module is the **single** consent surface — and it is
//!   compiled out entirely on non-Windows targets, replaced by a stub that
//!   never touches disk and always reports [`ConsentState::NotApplicable`].
//! - On Windows, consent is a per-user choice persisted at
//!   `%LOCALAPPDATA%\mxc\telemetry-consent.json`. The default (no file, or an
//!   unreadable/corrupt one) is [`ConsentState::Undetermined`], which is
//!   treated as "not collecting" everywhere telemetry gating is decided
//!   ([`super::is_enabled`]) — MXC fails closed, never open.
//! - This module never emits a telemetry event for a consent transition
//!   itself; flipping the flag is a silent, local, atomic file write.

// Serde, the persisted record, and its helpers exist only for the Windows
// consent store; the non-Windows stub persists nothing.
#[cfg(target_os = "windows")]
use serde::{Deserialize, Serialize};
use std::fmt;

use super::consent_prompt::{prompt_for_locale, ConsentPrompt};

/// Current schema version for the persisted consent record. Bump when the
/// on-disk shape changes in a way that isn't purely additive; unknown/older
/// versions are treated as [`ConsentState::Undetermined`] on read (fail
/// closed) rather than guessed at.
#[cfg(target_os = "windows")]
const CONSENT_SCHEMA_VERSION: u32 = 2;

/// The user's telemetry consent decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentState {
    /// The user has explicitly agreed to telemetry collection.
    Granted,
    /// The user has explicitly declined telemetry collection.
    Denied,
    /// No decision has been recorded yet (fresh install, or a corrupt/missing
    /// store). Treated identically to `Denied` for gating purposes — the only
    /// difference is that a host application should offer a first-run prompt
    /// when it sees this state.
    Undetermined,
    /// Not a Windows host. MXC does not collect telemetry here, so consent is
    /// not a meaningful concept — hosts must not offer a consent prompt at
    /// all on these platforms.
    NotApplicable,
}

/// Why persisted consent does not currently authorize collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentStatusReason {
    /// No consent record exists for this user.
    NoRecord,
    /// The consent store could not be read.
    StoreUnreadable,
    /// The consent record was not valid JSON or did not have a recognized
    /// consent value.
    StoreMalformed,
    /// The persisted consent schema is not supported by this build.
    ConsentSchemaUnsupported,
    /// A stored grant predates versioned canonical consent language.
    PromptVersionMissing,
    /// A stored grant references a different canonical prompt version.
    PromptVersionUnsupported,
    /// Telemetry consent is not applicable on this platform.
    NotApplicable,
}

impl ConsentStatusReason {
    /// Stable wire representation used by status APIs and bindings.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoRecord => "no-record",
            Self::StoreUnreadable => "store-unreadable",
            Self::StoreMalformed => "store-malformed",
            Self::ConsentSchemaUnsupported => "consent-schema-unsupported",
            Self::PromptVersionMissing => "prompt-version-missing",
            Self::PromptVersionUnsupported => "prompt-version-unsupported",
            Self::NotApplicable => "not-applicable",
        }
    }
}

/// Persisted and effective telemetry consent at one point in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsentStatus {
    /// Decision found in the consent record, when one could be recovered.
    pub stored_state: ConsentState,
    /// State used by the telemetry gate after validating the record and prompt
    /// version.
    pub effective_state: ConsentState,
    /// Fail-closed reason when the record is absent, invalid, or inapplicable.
    pub reason: Option<ConsentStatusReason>,
}

impl ConsentStatus {
    /// Whether an explicit consent request may offer the canonical prompt.
    pub fn needs_prompt(&self) -> bool {
        matches!(self.effective_state, ConsentState::Undetermined)
    }
}

/// Explicit result returned by a consent presenter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentDecision {
    Yes,
    No,
    Dismissed,
}

/// Result of requesting or withdrawing telemetry consent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentActionResult {
    Granted,
    Denied,
    Dismissed,
    Withdrawn,
    AlreadyGranted,
    PolicyBlocked,
    NotApplicable,
}

/// Consent action result together with the resulting status and policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsentActionOutcome {
    pub result: ConsentActionResult,
    pub status: ConsentStatus,
    pub policy: super::policy::PolicyState,
}

/// Failure to present or persist a consent decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsentActionError {
    Presenter(String),
    Persist(String),
}

impl fmt::Display for ConsentActionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Presenter(message) => write!(formatter, "consent presenter failed: {message}"),
            Self::Persist(message) => write!(formatter, "failed to persist consent: {message}"),
        }
    }
}

impl std::error::Error for ConsentActionError {}

impl ConsentState {
    /// Stable, lowercase wire representation used by the CLI flags, the FFI
    /// boundary, and the SDKs. Kept separate from `Debug` so the on-the-wire
    /// strings never drift if the Rust variant names change.
    pub fn as_str(&self) -> &'static str {
        match self {
            ConsentState::Granted => "granted",
            ConsentState::Denied => "denied",
            ConsentState::Undetermined => "undetermined",
            ConsentState::NotApplicable => "not-applicable",
        }
    }

    /// Whether telemetry may be collected under this consent state alone
    /// (still subject to the explicit config kill-switch — see
    /// [`super::is_enabled`]).
    pub fn allows_collection(&self) -> bool {
        matches!(self, ConsentState::Granted)
    }

    /// Whether a hosting application should offer its own first-run consent
    /// prompt for this state.
    ///
    /// This shared predicate keeps all consumer surfaces consistent. It is
    /// false for [`NotApplicable`](ConsentState::NotApplicable), because MXC
    /// collects no telemetry off Windows.
    pub fn needs_prompt(&self) -> bool {
        matches!(self, ConsentState::Undetermined)
    }
}

/// Whether a hosting application should offer its own first-run telemetry
/// consent prompt right now.
///
/// This is [`get_consent`]`().`[`needs_prompt`](ConsentState::needs_prompt)`()`
/// additionally suppressed when an administrator has denied telemetry via
/// [`super::policy`]. Prompting under an administrative denial would be asking
/// the user to decide something MXC would then ignore, so the answer there is
/// always `false` — regardless of whether a decision has been recorded.
pub fn needs_consent_prompt() -> bool {
    if super::policy::is_blocked_by_policy() {
        return false;
    }
    get_consent().needs_prompt()
}

/// The on-disk consent record. Additive fields only; `source` and
/// `prompted_mxc_version` are provenance for support/debugging and are never
/// transmitted anywhere.
#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConsentRecord {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    consent: String,
    #[serde(default)]
    source: String,
    #[serde(rename = "promptedMxcVersion", default)]
    prompted_mxc_version: String,
    #[serde(rename = "promptResourceVersion", default)]
    prompt_resource_version: Option<u32>,
    #[serde(rename = "promptLocale", default)]
    prompt_locale: String,
    /// Unix seconds at the time of the last grant/revoke. Debug/support
    /// provenance only — never used for gating — so a plain epoch integer is
    /// enough; `#[serde(default)]` means older or foreign records missing
    /// this field just read back as `0` rather than failing to parse.
    #[serde(rename = "updatedAtEpoch", default)]
    updated_at_epoch: u64,
}

/// Returns the current, persisted telemetry consent state.
///
/// Fail-closed: a missing file, an unreadable file, unparseable JSON, or an
/// unrecognized `schemaVersion` all resolve to [`ConsentState::Undetermined`]
/// — never to `Granted`. Always [`ConsentState::NotApplicable`] on
/// non-Windows platforms, without any filesystem access.
pub fn get_consent() -> ConsentState {
    get_status().effective_state
}

/// Returns persisted and effective consent plus a typed fail-closed reason.
pub fn get_status() -> ConsentStatus {
    platform::read_status()
}

#[cfg(test)]
pub(crate) fn set_consent(granted: bool, source: &str) -> Result<(), String> {
    platform::write(granted, source)
}

/// Request telemetry consent through a host-owned presenter.
///
/// The presenter receives the complete canonical resource. Only an explicit
/// [`ConsentDecision::Yes`] returned from this invocation can create a grant.
pub fn request_consent<F>(
    locale: Option<&str>,
    presenter: F,
) -> Result<ConsentActionOutcome, ConsentActionError>
where
    F: FnOnce(&ConsentPrompt) -> Result<ConsentDecision, String>,
{
    let (prompt, policy, status) = match consent_preflight(locale) {
        ConsentPreflight::Complete(outcome) => return Ok(outcome),
        ConsentPreflight::Present {
            prompt,
            policy,
            status,
        } => (prompt, policy, status),
    };

    let decision = presenter(prompt).map_err(ConsentActionError::Presenter)?;
    persist_presented_decision(decision, prompt, policy, status)
}

/// Asynchronous counterpart to [`request_consent`].
///
/// The presenter callback is asynchronous. The surrounding synchronous
/// registry/filesystem work is offloaded to short-lived worker threads so the
/// caller's executor thread does not run the blocking persistence path itself.
pub async fn request_consent_async<F, Fut>(
    locale: Option<&str>,
    presenter: F,
) -> Result<ConsentActionOutcome, ConsentActionError>
where
    F: FnOnce(&ConsentPrompt) -> Fut,
    Fut: std::future::Future<Output = Result<ConsentDecision, String>>,
{
    let locale = locale.map(str::to_owned);
    match BlockingTask::spawn(move || consent_preflight(locale.as_deref())).await {
        ConsentPreflight::Complete(outcome) => Ok(outcome),
        ConsentPreflight::Present {
            prompt,
            policy,
            status,
        } => {
            let decision = presenter(prompt)
                .await
                .map_err(ConsentActionError::Presenter)?;
            BlockingTask::spawn(move || {
                persist_presented_decision(decision, prompt, policy, status)
            })
            .await
        }
    }
}

struct BlockingTask<T> {
    shared: std::sync::Arc<BlockingTaskState<T>>,
}

struct BlockingTaskState<T> {
    result: std::sync::Mutex<Option<std::thread::Result<T>>>,
    waker: std::sync::Mutex<Option<std::task::Waker>>,
}

impl<T: Send + 'static> BlockingTask<T> {
    fn spawn(operation: impl FnOnce() -> T + Send + 'static) -> Self {
        let shared = std::sync::Arc::new(BlockingTaskState {
            result: std::sync::Mutex::new(None),
            waker: std::sync::Mutex::new(None),
        });
        let worker = std::sync::Arc::clone(&shared);
        std::thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation));
            *worker.result.lock().unwrap_or_else(|e| e.into_inner()) = Some(result);
            if let Some(waker) = worker
                .waker
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
            {
                waker.wake();
            }
        });
        Self { shared }
    }
}

impl<T> std::future::Future for BlockingTask<T> {
    type Output = T;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        if let Some(result) = self
            .shared
            .result
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            return std::task::Poll::Ready(match result {
                Ok(value) => value,
                Err(payload) => std::panic::resume_unwind(payload),
            });
        }

        *self.shared.waker.lock().unwrap_or_else(|e| e.into_inner()) = Some(cx.waker().clone());

        match self
            .shared
            .result
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            Some(result) => {
                self.shared
                    .waker
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take();
                std::task::Poll::Ready(match result {
                    Ok(value) => value,
                    Err(payload) => std::panic::resume_unwind(payload),
                })
            }
            None => std::task::Poll::Pending,
        }
    }
}

enum ConsentPreflight {
    Complete(ConsentActionOutcome),
    Present {
        prompt: &'static ConsentPrompt,
        policy: super::policy::PolicyState,
        status: ConsentStatus,
    },
}

fn consent_preflight(locale: Option<&str>) -> ConsentPreflight {
    let policy = super::policy::get_policy();
    let status = get_status();

    if status.effective_state == ConsentState::NotApplicable {
        return ConsentPreflight::Complete(ConsentActionOutcome {
            result: ConsentActionResult::NotApplicable,
            status,
            policy,
        });
    }
    if !policy.allows_collection() {
        return ConsentPreflight::Complete(ConsentActionOutcome {
            result: ConsentActionResult::PolicyBlocked,
            status,
            policy,
        });
    }
    if status.effective_state == ConsentState::Granted {
        return ConsentPreflight::Complete(ConsentActionOutcome {
            result: ConsentActionResult::AlreadyGranted,
            status,
            policy,
        });
    }

    let prompt = prompt_for_locale(locale);
    ConsentPreflight::Present {
        prompt,
        policy,
        status,
    }
}

fn persist_presented_decision(
    decision: ConsentDecision,
    prompt: &ConsentPrompt,
    policy: super::policy::PolicyState,
    status: ConsentStatus,
) -> Result<ConsentActionOutcome, ConsentActionError> {
    platform::with_store_lock(|| {
        let current_policy = super::policy::get_policy();
        let current_status = platform::read_status_unlocked();
        if current_status.effective_state == ConsentState::NotApplicable {
            return Ok(ConsentActionOutcome {
                result: ConsentActionResult::NotApplicable,
                status: current_status,
                policy: current_policy,
            });
        }
        if !current_policy.allows_collection() {
            return Ok(ConsentActionOutcome {
                result: ConsentActionResult::PolicyBlocked,
                status: current_status,
                policy: current_policy,
            });
        }
        if current_status.effective_state == ConsentState::Granted
            && !matches!(decision, ConsentDecision::No)
        {
            return Ok(ConsentActionOutcome {
                result: ConsentActionResult::AlreadyGranted,
                status: current_status,
                policy: current_policy,
            });
        }
        let is_concurrent_grant_being_withdrawn = matches!(decision, ConsentDecision::No)
            && current_status.effective_state == ConsentState::Granted
            && status.effective_state != ConsentState::Granted;
        if current_policy != policy
            || (current_status.effective_state != status.effective_state
                && !is_concurrent_grant_being_withdrawn)
        {
            return Err(
                "consent state changed while the presenter was open; no decision was written"
                    .to_string(),
            );
        }

        match decision {
            ConsentDecision::Yes => {
                platform::write_presented(true, "prompt", prompt)?;
                Ok(ConsentActionOutcome {
                    result: ConsentActionResult::Granted,
                    status: platform::read_status_unlocked(),
                    policy: current_policy,
                })
            }
            ConsentDecision::No => {
                platform::write_presented(false, "prompt", prompt)?;
                Ok(ConsentActionOutcome {
                    result: ConsentActionResult::Denied,
                    status: platform::read_status_unlocked(),
                    policy: current_policy,
                })
            }
            ConsentDecision::Dismissed => Ok(ConsentActionOutcome {
                result: ConsentActionResult::Dismissed,
                status: current_status,
                policy: current_policy,
            }),
        }
    })
    .map_err(ConsentActionError::Persist)
}

/// Idempotently withdraw telemetry consent.
///
/// Withdrawal does not require a permitting administrative policy. Off
/// Windows it succeeds as a typed `NotApplicable` result without storage.
pub fn withdraw_consent() -> Result<ConsentActionOutcome, ConsentActionError> {
    let current_status = get_status();
    if current_status.effective_state == ConsentState::NotApplicable {
        return Ok(ConsentActionOutcome {
            result: ConsentActionResult::NotApplicable,
            status: current_status,
            policy: super::policy::get_policy(),
        });
    }

    platform::with_store_lock(|| {
        platform::begin_withdrawal()?;
        platform::write(false, "withdrawal")?;
        platform::finish_withdrawal()?;
        Ok(ConsentActionOutcome {
            result: ConsentActionResult::Withdrawn,
            status: platform::read_status_unlocked(),
            policy: super::policy::get_policy(),
        })
    })
    .map_err(ConsentActionError::Persist)
}

/// Current time as Unix seconds. Debug/support provenance only (see
/// [`ConsentRecord::updated_at_epoch`]) — a raw epoch avoids pulling in a
/// date-formatting dependency, or hand-rolling calendar math, just to stamp
/// a field nothing ever gates on.
#[cfg(target_os = "windows")]
fn now_epoch_seconds() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Windows implementation — real, persisted, per-user consent store.
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
mod platform {
    use super::{
        now_epoch_seconds, ConsentRecord, ConsentState, ConsentStatus, ConsentStatusReason,
        CONSENT_SCHEMA_VERSION,
    };
    use crate::telemetry::consent_prompt::{CONSENT_RESOURCE_VERSION, FALLBACK_LOCALE};
    use std::fs;
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    /// Number of attempts for filesystem operations that can transiently fail
    /// under Windows file-lock contention (AV real-time scanning, the search
    /// indexer, or a concurrent `wxc-exec` grant/revoke in another process).
    const IO_RETRY_ATTEMPTS: u32 = 5;
    #[cfg(test)]
    const IO_RETRY_DELAY: Duration = Duration::ZERO;
    #[cfg(not(test))]
    const IO_RETRY_DELAY: Duration = Duration::from_millis(20);
    #[cfg(test)]
    const STORE_LOCK_RETRY_DELAY: Duration = Duration::from_millis(1);
    #[cfg(not(test))]
    const STORE_LOCK_RETRY_DELAY: Duration = Duration::from_millis(20);

    /// `ERROR_SHARING_VIOLATION` — another handle holds the file with a
    /// conflicting share mode (AV scanner, indexer, racing sibling process).
    const ERROR_SHARING_VIOLATION: i32 = 32;
    /// `ERROR_LOCK_VIOLATION` — a byte-range lock is held on the file.
    const ERROR_LOCK_VIOLATION: i32 = 33;
    const MAX_CONSENT_FILE_BYTES: u64 = 16 * 1024;
    const WITHDRAWAL_PENDING_FILE: &str = "telemetry-consent.withdrawal-pending";
    const CONSENT_LOCK_FILE: &str = "telemetry-consent.lock";
    const WITHDRAWAL_MARKER_STALE_AFTER: Duration = Duration::from_secs(5);

    /// Resolves the per-user `%LocalAppData%` directory through the Windows
    /// known-folder API rather than trusting `LOCALAPPDATA`. A parent process
    /// controls the child's environment, so trusting that variable could
    /// redirect the consent store and forge a grant. The resolved path is
    /// cached for the process, but only after a successful resolution so a
    /// transient failure can be retried later in the same process.
    fn known_folder_local_app_data() -> Option<PathBuf> {
        static CACHED: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
        cache_successful_resolution(&CACHED, resolve_known_folder_local_app_data)
    }

    fn cache_successful_resolution(
        cache: &std::sync::OnceLock<PathBuf>,
        resolver: impl FnOnce() -> Option<PathBuf>,
    ) -> Option<PathBuf> {
        if let Some(cached) = cache.get() {
            return Some(cached.clone());
        }

        let resolved = resolver()?;
        let _ = cache.set(resolved.clone());
        Some(resolved)
    }

    /// Opens the current **process** token with `TOKEN_QUERY | TOKEN_IMPERSONATE`.
    ///
    /// Passing `None` to `SHGetKnownFolderPath` would resolve against the
    /// calling *thread's* token — the impersonated one, if the host has
    /// impersonated another user. That would both invalidate the memoization
    /// above and let an embedding host redirect the consent store simply by
    /// impersonating, which is the same class of attack the known-folder API
    /// is being used to prevent in the first place. Binding explicitly to the
    /// process token keeps the answer a stable property of the process.
    ///
    /// `SHGetKnownFolderPath` requires the token it is handed to be opened
    /// with both `TOKEN_QUERY` *and* `TOKEN_IMPERSONATE` (it duplicates the
    /// handle into an impersonation token internally); on systems that
    /// enforce that contract, a `TOKEN_QUERY`-only handle makes resolution
    /// fail, so consent would always read as `Undetermined` and every
    /// grant/revoke would fail closed.
    fn process_token() -> Option<crate::process_util::OwnedHandle> {
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Security::{TOKEN_IMPERSONATE, TOKEN_QUERY};
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        let mut token = HANDLE::default();
        // SAFETY: `GetCurrentProcess` returns a pseudo-handle that needs no
        // release, and `token` is a valid out-pointer for the duration of the
        // call. On success the returned handle is immediately wrapped in
        // `OwnedHandle`, whose `Drop` closes it exactly once.
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_IMPERSONATE,
                &mut token,
            )
        }
        .ok()?;
        Some(crate::process_util::OwnedHandle::new(token))
    }

    fn resolve_known_folder_local_app_data() -> Option<PathBuf> {
        use crate::string_util::CoTaskMemPWSTR;
        use windows::Win32::UI::Shell::{
            FOLDERID_LocalAppData, SHGetKnownFolderPath, KF_FLAG_DEFAULT,
        };

        // SAFETY: `FOLDERID_LocalAppData` is a valid, static, well-known GUID
        // constant. The token argument is this process's own token, so the
        // result is independent of any thread impersonation the host may have
        // in effect (see `process_token`); it stays alive for the duration of
        // the call because `token` is still in scope. The returned `PWSTR` is
        // COM-allocated and is immediately wrapped in `CoTaskMemPWSTR`, whose
        // `Drop` frees it via `CoTaskMemFree` exactly once.
        let token = process_token()?;
        let pwstr = unsafe {
            SHGetKnownFolderPath(&FOLDERID_LocalAppData, KF_FLAG_DEFAULT, Some(token.get()))
        }
        .ok()?;
        let owned = CoTaskMemPWSTR::new(pwstr.0);
        let resolved = owned.to_string_lossy();
        if resolved.is_empty() {
            None
        } else {
            Some(PathBuf::from(resolved))
        }
    }

    /// Test-only escape hatch so deterministic tests — this crate's own unit
    /// tests, `mxc_ffi`'s Rust tests, and a local `dotnet test`/`npm test` run
    /// against a debug-profile native binary — can redirect the consent store
    /// to a throwaway temp directory.
    ///
    /// Active only under `cfg(test)` (this crate's own test harness, which is
    /// how CI exercises it — CI runs `cargo test --release`, so gating on
    /// `debug_assertions` alone would silently drop every consent test from
    /// CI *and* let them read and overwrite the real store) or in a debug
    /// build (which is what lets `mxc_ffi`'s cross-crate tests, where
    /// `cfg(test)` does not apply to this crate, redirect it).
    ///
    /// Neither condition holds for a binary MXC ships: a release
    /// `wxc-exec.exe` is not compiled with `--test` and has
    /// `debug_assertions` off, so this branch and the env-var read backing it
    /// are compiled out entirely, and a parent process has no way to redirect
    /// the store.
    #[cfg(any(test, all(feature = "test-support", debug_assertions)))]
    fn debug_local_app_data_override() -> Option<PathBuf> {
        crate::telemetry::consent::test_support::current_local_app_data_override()
            .or_else(crate::telemetry::consent::test_support::inherited_local_app_data_override)
    }

    fn local_app_data_dir() -> Option<PathBuf> {
        #[cfg(any(test, all(feature = "test-support", debug_assertions)))]
        if let Some(over) = debug_local_app_data_override() {
            return Some(over);
        }
        known_folder_local_app_data()
    }

    struct StoreLock {
        file: Option<fs::File>,
    }

    impl Drop for StoreLock {
        fn drop(&mut self) {
            self.file.take();
        }
    }

    pub(super) fn with_store_lock<T>(
        operation: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String> {
        use std::os::windows::fs::OpenOptionsExt;

        let path = consent_file_path().ok_or_else(|| {
            "could not resolve %LocalAppData%; cannot lock telemetry consent".to_string()
        })?;
        let dir = path
            .parent()
            .ok_or_else(|| "invalid telemetry consent path".to_string())?;
        fs::create_dir_all(dir).map_err(|e| format!("failed to create {}: {e}", dir.display()))?;
        let lock_path = dir.join(CONSENT_LOCK_FILE);
        let mut attempts = 0;
        let file = loop {
            let mut options = fs::OpenOptions::new();
            options
                .write(true)
                .create_new(true)
                .custom_flags(windows::Win32::Storage::FileSystem::FILE_FLAG_DELETE_ON_CLOSE.0);
            match options.open(&lock_path) {
                Ok(file) => break file,
                Err(error)
                    if attempts + 1 < IO_RETRY_ATTEMPTS
                        && (error.kind() == std::io::ErrorKind::AlreadyExists
                            || is_transient_io_error(&error)) =>
                {
                    attempts += 1;
                    std::thread::sleep(STORE_LOCK_RETRY_DELAY);
                }
                Err(error) => {
                    return Err(format!("failed to lock telemetry consent: {error}"));
                }
            }
        };
        let _lock = StoreLock { file: Some(file) };
        operation()
    }

    /// Test-only accessor for [`known_folder_local_app_data`], which is
    /// otherwise private to this module.
    #[cfg(test)]
    pub(super) fn known_folder_local_app_data_for_test() -> Option<PathBuf> {
        known_folder_local_app_data()
    }

    #[cfg(test)]
    pub(super) fn local_app_data_dir_for_test() -> Option<PathBuf> {
        local_app_data_dir()
    }

    #[cfg(test)]
    pub(super) fn cache_successful_resolution_for_test(
        cache: &std::sync::OnceLock<PathBuf>,
        resolver: impl FnOnce() -> Option<PathBuf>,
    ) -> Option<PathBuf> {
        cache_successful_resolution(cache, resolver)
    }

    /// Per-user consent store path: `<LocalAppData>\mxc\telemetry-consent.json`.
    /// Per-user (not `%ProgramData%`) because consent is a personal choice —
    /// multiple people sharing one machine each control their own, with no
    /// elevation required to change it (mirrors `wxc-exec.exe` never
    /// self-elevating; see `docs/host-prep.md`).
    fn consent_file_path() -> Option<PathBuf> {
        local_app_data_dir().map(|dir| dir.join("mxc").join("telemetry-consent.json"))
    }

    /// Whether an I/O error is plausibly a *transient* lock/share conflict
    /// worth waiting out, as opposed to a settled answer.
    ///
    /// This distinction is load-bearing for startup latency, not just tidiness:
    /// the overwhelmingly common state is "no consent file yet" (every fresh
    /// install, and every user who has not yet been prompted), which surfaces
    /// as `NotFound`. Retrying that would add `IO_RETRY_ATTEMPTS - 1` sleeps —
    /// 80 ms — to the consent read on the critical path of *every* sandbox
    /// launch, to re-confirm a result that cannot change.
    fn is_transient_io_error(e: &std::io::Error) -> bool {
        if matches!(
            e.raw_os_error(),
            Some(ERROR_SHARING_VIOLATION) | Some(ERROR_LOCK_VIOLATION)
        ) {
            return true;
        }
        matches!(
            e.kind(),
            std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::Interrupted
        )
    }

    /// Retries `op` up to [`IO_RETRY_ATTEMPTS`] times with a short fixed
    /// delay, to ride out transient Windows file-lock contention (AV
    /// scanning, indexing, a racing sibling process) rather than failing the
    /// very first time a lock is briefly held by someone else.
    ///
    /// Only [`is_transient_io_error`] failures are retried; anything else
    /// (notably `NotFound`) is returned immediately.
    fn with_io_retry<T>(mut op: impl FnMut() -> std::io::Result<T>) -> std::io::Result<T> {
        let mut attempt = 0;
        loop {
            match op() {
                Ok(v) => return Ok(v),
                Err(e) if attempt + 1 < IO_RETRY_ATTEMPTS && is_transient_io_error(&e) => {
                    attempt += 1;
                    std::thread::sleep(IO_RETRY_DELAY);
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Test-only accessor for [`with_io_retry`], which is otherwise private
    /// to this module.
    #[cfg(test)]
    pub(super) fn with_io_retry_for_test<T>(
        op: impl FnMut() -> std::io::Result<T>,
    ) -> std::io::Result<T> {
        with_io_retry(op)
    }

    /// Test-only constructor for a synthetic transient error, so retry tests
    /// don't have to guess which raw OS codes this module treats as transient.
    #[cfg(test)]
    pub(super) fn transient_io_error_for_test() -> std::io::Error {
        std::io::Error::from_raw_os_error(ERROR_SHARING_VIOLATION)
    }

    #[cfg(test)]
    pub(super) const IO_RETRY_ATTEMPTS_FOR_TEST: u32 = IO_RETRY_ATTEMPTS;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum WithdrawalMarkerState {
        Absent,
        Pending,
        Stale,
    }

    fn withdrawal_marker_state(marker: &Path) -> std::io::Result<WithdrawalMarkerState> {
        match with_io_retry(|| fs::metadata(marker)) {
            Ok(metadata) => {
                let is_stale = metadata
                    .modified()
                    .ok()
                    .and_then(|modified| std::time::SystemTime::now().duration_since(modified).ok())
                    .is_some_and(|age| age >= WITHDRAWAL_MARKER_STALE_AFTER);
                Ok(if is_stale {
                    WithdrawalMarkerState::Stale
                } else {
                    WithdrawalMarkerState::Pending
                })
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(WithdrawalMarkerState::Absent)
            }
            Err(error) => Err(error),
        }
    }

    #[cfg(test)]
    pub(super) fn read_status_unlocked_with_marker_for_test(
        marker_state: std::io::Result<WithdrawalMarkerState>,
    ) -> ConsentStatus {
        read_status_unlocked_inner(|_| marker_state, recover_stale_withdrawal_marker)
    }

    pub(super) fn read_status() -> ConsentStatus {
        read_status_unlocked_inner(withdrawal_marker_state, |path, marker| {
            with_store_lock(|| recover_stale_withdrawal_marker(path, marker))
        })
    }

    pub(super) fn read_status_unlocked() -> ConsentStatus {
        read_status_unlocked_inner(withdrawal_marker_state, recover_stale_withdrawal_marker)
    }

    fn read_status_unlocked_inner(
        marker_check: impl FnOnce(&Path) -> std::io::Result<WithdrawalMarkerState>,
        recover_stale: impl FnOnce(&Path, &Path) -> Result<(), String>,
    ) -> ConsentStatus {
        fn unreadable_status() -> ConsentStatus {
            ConsentStatus {
                stored_state: ConsentState::Undetermined,
                effective_state: ConsentState::Undetermined,
                reason: Some(ConsentStatusReason::StoreUnreadable),
            }
        }

        fn no_record_status() -> ConsentStatus {
            ConsentStatus {
                stored_state: ConsentState::Undetermined,
                effective_state: ConsentState::Undetermined,
                reason: Some(ConsentStatusReason::NoRecord),
            }
        }

        let Some(path) = consent_file_path() else {
            return unreadable_status();
        };
        let Some(dir) = path.parent() else {
            return unreadable_status();
        };
        let marker_path = dir.join(WITHDRAWAL_PENDING_FILE);
        match marker_check(&marker_path) {
            Ok(WithdrawalMarkerState::Absent) => {}
            Ok(WithdrawalMarkerState::Pending) | Err(_) => {
                return unreadable_status();
            }
            Ok(WithdrawalMarkerState::Stale) => {
                if recover_stale(&path, &marker_path).is_err() {
                    return unreadable_status();
                }
            }
        }
        let data = match with_io_retry(|| read_bounded(&path)) {
            Ok(data) => data,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return no_record_status()
            }
            Err(_) => return unreadable_status(),
        };
        let Ok(record) = serde_json::from_str::<ConsentRecord>(&data) else {
            return ConsentStatus {
                stored_state: ConsentState::Undetermined,
                effective_state: ConsentState::Undetermined,
                reason: Some(ConsentStatusReason::StoreMalformed),
            };
        };

        let stored_state = match record.consent.as_str() {
            "granted" => ConsentState::Granted,
            "denied" => ConsentState::Denied,
            _ => {
                return ConsentStatus {
                    stored_state: ConsentState::Undetermined,
                    effective_state: ConsentState::Undetermined,
                    reason: Some(ConsentStatusReason::StoreMalformed),
                };
            }
        };

        if stored_state == ConsentState::Denied {
            return ConsentStatus {
                stored_state,
                effective_state: ConsentState::Denied,
                reason: None,
            };
        }

        if record.schema_version != CONSENT_SCHEMA_VERSION {
            return ConsentStatus {
                stored_state,
                effective_state: ConsentState::Undetermined,
                reason: Some(if record.prompt_resource_version.is_none() {
                    ConsentStatusReason::PromptVersionMissing
                } else {
                    ConsentStatusReason::ConsentSchemaUnsupported
                }),
            };
        }

        match record.prompt_resource_version {
            Some(CONSENT_RESOURCE_VERSION) if !record.prompt_locale.is_empty() => ConsentStatus {
                stored_state,
                effective_state: ConsentState::Granted,
                reason: None,
            },
            None => ConsentStatus {
                stored_state,
                effective_state: ConsentState::Undetermined,
                reason: Some(ConsentStatusReason::PromptVersionMissing),
            },
            Some(_) => ConsentStatus {
                stored_state,
                effective_state: ConsentState::Undetermined,
                reason: Some(ConsentStatusReason::PromptVersionUnsupported),
            },
        }
    }

    fn read_bounded(path: &Path) -> std::io::Result<String> {
        let file = fs::File::open(path)?;
        let mut bytes = Vec::new();
        file.take(MAX_CONSENT_FILE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_CONSENT_FILE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "telemetry consent file exceeds the supported size",
            ));
        }
        String::from_utf8(bytes)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
    }

    fn recover_stale_withdrawal_marker(_path: &Path, marker: &Path) -> Result<(), String> {
        match withdrawal_marker_state(marker)
            .map_err(|e| format!("failed to inspect stale withdrawal marker: {e}"))?
        {
            WithdrawalMarkerState::Absent => Ok(()),
            WithdrawalMarkerState::Pending | WithdrawalMarkerState::Stale => write_record(
                false,
                "withdrawal-recovery",
                Some(CONSENT_RESOURCE_VERSION),
                FALLBACK_LOCALE,
            ),
        }
    }

    /// Best-effort cleanup of a leftover temp file; failures here are not
    /// reported since the operation they were cleaning up after has already
    /// failed (or, on the success path, this is a pure best-effort tidy-up).
    fn remove_best_effort(path: &Path) {
        let _ = fs::remove_file(path);
    }

    pub(super) fn write(granted: bool, source: &str) -> Result<(), String> {
        write_record(
            granted,
            source,
            Some(CONSENT_RESOURCE_VERSION),
            FALLBACK_LOCALE,
        )
    }

    pub(super) fn write_presented(
        granted: bool,
        source: &str,
        prompt: &crate::telemetry::consent_prompt::ConsentPrompt,
    ) -> Result<(), String> {
        write_record(
            granted,
            source,
            Some(prompt.resource_version),
            prompt.locale,
        )
    }

    pub(super) fn begin_withdrawal() -> Result<(), String> {
        let path = consent_file_path().ok_or_else(|| {
            "could not resolve %LocalAppData%; cannot persist telemetry consent".to_string()
        })?;
        let dir = path
            .parent()
            .ok_or_else(|| "invalid telemetry consent path".to_string())?;
        fs::create_dir_all(dir).map_err(|e| format!("failed to create {}: {e}", dir.display()))?;
        with_io_retry(|| fs::write(dir.join(WITHDRAWAL_PENDING_FILE), b"pending"))
            .map_err(|e| format!("failed to mark withdrawal pending: {e}"))
    }

    pub(super) fn finish_withdrawal() -> Result<(), String> {
        let path = consent_file_path().ok_or_else(|| {
            "could not resolve %LocalAppData%; cannot persist telemetry consent".to_string()
        })?;
        clear_withdrawal_marker(&path)
    }

    fn write_record(
        granted: bool,
        source: &str,
        prompt_resource_version: Option<u32>,
        prompt_locale: &str,
    ) -> Result<(), String> {
        let path = consent_file_path().ok_or_else(|| {
            "could not resolve %LocalAppData%; cannot persist telemetry consent".to_string()
        })?;
        let dir = path
            .parent()
            .ok_or_else(|| "invalid telemetry consent path".to_string())?;
        fs::create_dir_all(dir).map_err(|e| format!("failed to create {}: {e}", dir.display()))?;

        let record = ConsentRecord {
            schema_version: CONSENT_SCHEMA_VERSION,
            consent: if granted { "granted" } else { "denied" }.to_string(),
            source: source.to_string(),
            prompted_mxc_version: crate::telemetry::version().to_string(),
            prompt_resource_version,
            prompt_locale: prompt_locale.to_string(),
            updated_at_epoch: now_epoch_seconds(),
        };
        let json = serde_json::to_string_pretty(&record)
            .map_err(|e| format!("failed to serialize telemetry consent record: {e}"))?;

        // Atomic write: write to a *unique* temp file in the same directory
        // (process id + a random suffix, so two concurrent `wxc-exec`
        // grant/revoke invocations never share — and thus never race on —
        // the same temp path), then rename over the real path. A crash
        // mid-write never leaves a torn/corrupt file in place of a
        // previously-valid one; if the rename itself fails, the temp file is
        // removed rather than left behind as a leaked, orphaned artifact.
        let unique = format!("{}-{:x}", std::process::id(), random_suffix());
        let tmp_path = path.with_extension(format!("json.{unique}.tmp"));

        if let Err(e) = with_io_retry(|| {
            let mut file = fs::File::create(&tmp_path)?;
            file.write_all(json.as_bytes())?;
            file.sync_all()
        }) {
            remove_best_effort(&tmp_path);
            return Err(format!("failed to write {}: {e}", tmp_path.display()));
        }
        if let Err(e) = with_io_retry(|| fs::rename(&tmp_path, &path)) {
            remove_best_effort(&tmp_path);
            return Err(format!("failed to finalize {}: {e}", path.display()));
        }
        clear_withdrawal_marker(&path)
    }

    fn clear_withdrawal_marker(path: &Path) -> Result<(), String> {
        let dir = path
            .parent()
            .ok_or_else(|| "invalid telemetry consent path".to_string())?;
        match with_io_retry(|| fs::remove_file(dir.join(WITHDRAWAL_PENDING_FILE))) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("failed to clear withdrawal marker: {e}")),
        }
    }

    /// Returns a process-local unique suffix for a temporary filename.
    fn random_suffix() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT_SUFFIX: AtomicU64 = AtomicU64::new(0);

        NEXT_SUFFIX.fetch_add(1, Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// Non-Windows stub — no file, no prompt, no pretend consent.
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "windows"))]
mod platform {
    use super::{ConsentState, ConsentStatus, ConsentStatusReason};

    pub(super) fn with_store_lock<T>(
        operation: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String> {
        operation()
    }

    pub(super) fn read_status() -> ConsentStatus {
        ConsentStatus {
            stored_state: ConsentState::NotApplicable,
            effective_state: ConsentState::NotApplicable,
            reason: Some(ConsentStatusReason::NotApplicable),
        }
    }

    pub(super) fn read_status_unlocked() -> ConsentStatus {
        read_status()
    }

    pub(super) fn write(_granted: bool, _source: &str) -> Result<(), String> {
        Err("telemetry is Windows-only; consent is not applicable on this platform".to_string())
    }

    pub(super) fn begin_withdrawal() -> Result<(), String> {
        Err("telemetry is Windows-only; consent is not applicable on this platform".to_string())
    }

    pub(super) fn finish_withdrawal() -> Result<(), String> {
        Ok(())
    }

    pub(super) fn write_presented(
        _granted: bool,
        _source: &str,
        _prompt: &crate::telemetry::consent_prompt::ConsentPrompt,
    ) -> Result<(), String> {
        Err("telemetry is Windows-only; consent is not applicable on this platform".to_string())
    }
}

// ---------------------------------------------------------------------------
// Test support — shared with `telemetry::mod`'s `is_enabled` tests so both
// modules can safely mutate the process-global consent-store override
// without racing each other under parallel test execution.
//
// This redirects `MXC_TEST_LOCALAPPDATA_OVERRIDE`, a debug-build-only escape
// hatch (see `platform::debug_local_app_data_override` above) — never the
// real `LOCALAPPDATA` variable, and never present at all in a release build.
// ---------------------------------------------------------------------------

#[cfg(any(test, all(feature = "test-support", debug_assertions)))]
pub mod test_support {
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, MutexGuard};

    const LOCAL_APPDATA_OVERRIDE_ENV: &str = "MXC_TEST_LOCALAPPDATA_OVERRIDE";
    const LOCAL_APPDATA_OVERRIDE_OWNER_ENV: &str = "MXC_TEST_LOCALAPPDATA_OVERRIDE_OWNER_PID";

    /// `get_consent`/`set_consent` read the debug-only override, which is
    /// process-global state. Guarded internally by [`LocalAppDataGuard::set`]
    /// so a caller can never forget to hold it — see that type's doc comment.
    /// `pub(crate)` only so the rare test that must mutate the override
    /// directly (bypassing the guard, e.g. to test the "no override set"
    /// fallback path) can still serialize against guard-holding tests.
    pub(crate) static ENV_LOCK: Mutex<()> = Mutex::new(());
    static LOCAL_APP_DATA_OVERRIDE: Mutex<Option<PathBuf>> = Mutex::new(None);

    /// Redirects the consent store (Windows only) to a fresh temp directory
    /// for the lifetime of the guard, restoring the previous value on drop.
    /// Acquires and holds [`ENV_LOCK`] for the guard's entire lifetime, so
    /// tests cannot accidentally construct the guard without the lock.
    /// A no-op holder on non-Windows, where consent is `NotApplicable`
    /// regardless — kept as a real (if inert) guard type so callers don't
    /// need `#[cfg]` at every call site.
    pub struct LocalAppDataGuard {
        _lock: MutexGuard<'static, ()>,
        #[cfg(target_os = "windows")]
        previous: Option<std::ffi::OsString>,
        #[cfg(target_os = "windows")]
        previous_owner: Option<std::ffi::OsString>,
        #[cfg(target_os = "windows")]
        previous_override: Option<PathBuf>,
    }

    impl LocalAppDataGuard {
        #[cfg(target_os = "windows")]
        pub fn set(path: &Path) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let previous = std::env::var_os(LOCAL_APPDATA_OVERRIDE_ENV);
            let previous_owner = std::env::var_os(LOCAL_APPDATA_OVERRIDE_OWNER_ENV);
            let previous_override = LOCAL_APP_DATA_OVERRIDE
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            std::env::set_var(LOCAL_APPDATA_OVERRIDE_ENV, path);
            std::env::set_var(
                LOCAL_APPDATA_OVERRIDE_OWNER_ENV,
                std::process::id().to_string(),
            );
            *LOCAL_APP_DATA_OVERRIDE
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = Some(path.to_path_buf());
            Self {
                _lock: lock,
                previous,
                previous_owner,
                previous_override,
            }
        }

        #[cfg(not(target_os = "windows"))]
        pub fn set(_path: &Path) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            Self { _lock: lock }
        }
    }

    #[cfg(any(test, all(feature = "test-support", debug_assertions)))]
    pub(crate) fn current_local_app_data_override() -> Option<PathBuf> {
        LOCAL_APP_DATA_OVERRIDE
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    #[cfg(any(test, all(feature = "test-support", debug_assertions)))]
    pub(crate) fn inherited_local_app_data_override() -> Option<PathBuf> {
        let path = std::env::var_os(LOCAL_APPDATA_OVERRIDE_ENV)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)?;
        let owner_pid = std::env::var(LOCAL_APPDATA_OVERRIDE_OWNER_ENV)
            .ok()
            .and_then(|value| value.parse::<u32>().ok());
        if owner_pid == Some(std::process::id()) {
            return None;
        }
        Some(path)
    }

    #[cfg(target_os = "windows")]
    impl Drop for LocalAppDataGuard {
        fn drop(&mut self) {
            *LOCAL_APP_DATA_OVERRIDE
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = self.previous_override.clone();
            match &self.previous {
                Some(v) => std::env::set_var(LOCAL_APPDATA_OVERRIDE_ENV, v),
                None => std::env::remove_var(LOCAL_APPDATA_OVERRIDE_ENV),
            }
            match &self.previous_owner {
                Some(v) => std::env::set_var(LOCAL_APPDATA_OVERRIDE_OWNER_ENV, v),
                None => std::env::remove_var(LOCAL_APPDATA_OVERRIDE_OWNER_ENV),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::test_support::LocalAppDataGuard;
    use super::*;

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        fn raw_waker() -> std::task::RawWaker {
            fn clone(_: *const ()) -> std::task::RawWaker {
                raw_waker()
            }
            fn wake(_: *const ()) {}
            fn wake_by_ref(_: *const ()) {}
            fn drop(_: *const ()) {}

            std::task::RawWaker::new(
                std::ptr::null(),
                &std::task::RawWakerVTable::new(clone, wake, wake_by_ref, drop),
            )
        }

        let waker = unsafe { std::task::Waker::from_raw(raw_waker()) };
        let mut future = std::pin::pin!(future);
        let mut context = std::task::Context::from_waker(&waker);

        loop {
            match future.as_mut().poll(&mut context) {
                std::task::Poll::Ready(result) => return result,
                std::task::Poll::Pending => std::thread::sleep(std::time::Duration::from_millis(1)),
            }
        }
    }

    #[test]
    fn consent_state_as_str_is_stable() {
        assert_eq!(ConsentState::Granted.as_str(), "granted");
        assert_eq!(ConsentState::Denied.as_str(), "denied");
        assert_eq!(ConsentState::Undetermined.as_str(), "undetermined");
        assert_eq!(ConsentState::NotApplicable.as_str(), "not-applicable");
    }

    #[test]
    fn only_granted_allows_collection() {
        assert!(ConsentState::Granted.allows_collection());
        assert!(!ConsentState::Denied.allows_collection());
        assert!(!ConsentState::Undetermined.allows_collection());
        assert!(!ConsentState::NotApplicable.allows_collection());
    }

    #[test]
    fn only_undetermined_needs_prompt() {
        assert!(ConsentState::Undetermined.needs_prompt());
        assert!(!ConsentState::Granted.needs_prompt());
        assert!(!ConsentState::Denied.needs_prompt());
        // NotApplicable means "not Windows", where MXC collects nothing and
        // therefore must never ask. Prompting here would be a privacy defect,
        // not merely a redundant dialog.
        assert!(!ConsentState::NotApplicable.needs_prompt());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn now_epoch_seconds_is_plausible() {
        // Sanity bound: some time after this test was written, and not an
        // absurd far-future value from an overflow/unit bug.
        let secs = now_epoch_seconds();
        assert!(secs > 1_700_000_000, "epoch seconds too small: {secs}");
        assert!(secs < 4_000_000_000, "epoch seconds too large: {secs}");
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn non_windows_is_always_not_applicable_and_write_fails() {
        let _guard = LocalAppDataGuard::set(std::path::Path::new("unused"));
        assert_eq!(get_consent(), ConsentState::NotApplicable);
        assert_eq!(
            request_consent(None, |_| panic!("non-Windows consent must not present"))
                .unwrap()
                .result,
            ConsentActionResult::NotApplicable
        );
        assert_eq!(
            block_on(request_consent_async(None, |_| async {
                panic!("non-Windows async consent must not present")
            }))
            .unwrap()
            .result,
            ConsentActionResult::NotApplicable
        );
        assert_eq!(
            withdraw_consent().unwrap().result,
            ConsentActionResult::NotApplicable
        );
        assert!(set_consent(true, "cli").is_err());
        assert!(set_consent(false, "cli").is_err());
        assert!(
            !needs_consent_prompt(),
            "must never ask for consent where nothing is collected"
        );
    }

    #[cfg(target_os = "windows")]
    mod windows_tests {
        use super::{block_on, LocalAppDataGuard};
        use crate::telemetry::consent::{
            get_consent, get_status, needs_consent_prompt, platform, request_consent,
            request_consent_async, set_consent, withdraw_consent, ConsentActionError,
            ConsentActionResult, ConsentDecision, ConsentState, ConsentStatusReason,
        };

        fn age_withdrawal_marker(store_root: &std::path::Path) {
            let marker = store_root
                .join("mxc")
                .join("telemetry-consent.withdrawal-pending");
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(&marker)
                .expect("open withdrawal marker");
            let stale_time = std::time::SystemTime::now() - std::time::Duration::from_secs(10);
            file.set_times(std::fs::FileTimes::new().set_modified(stale_time))
                .expect("age withdrawal marker");
        }

        #[test]
        fn needs_consent_prompt_tracks_the_store() {
            let tmp = tempfile::tempdir().unwrap();
            // Also isolates the policy key: `needs_consent_prompt` consults it,
            // so without this the test reads the real machine policy and fails
            // on an administratively managed device.
            let _env = crate::telemetry::test_support::TelemetryTestEnv::new(tmp.path());
            assert!(needs_consent_prompt(), "fresh store must prompt");
            set_consent(false, "prompt").unwrap();
            assert!(
                !needs_consent_prompt(),
                "a recorded denial must not re-prompt"
            );
            set_consent(true, "settings-toggle").unwrap();
            assert!(
                !needs_consent_prompt(),
                "a recorded grant must not re-prompt"
            );
        }

        #[test]
        fn needs_consent_prompt_is_suppressed_by_blocking_policy() {
            let tmp = tempfile::tempdir().unwrap();
            let env = crate::telemetry::test_support::TelemetryTestEnv::new(tmp.path());
            env.set_policy_value(0);
            assert!(
                !needs_consent_prompt(),
                "a blocking policy must suppress a meaningless prompt"
            );
        }

        #[test]
        fn fresh_store_is_undetermined() {
            let tmp = tempfile::tempdir().unwrap();
            let _guard = LocalAppDataGuard::set(tmp.path());
            assert_eq!(get_consent(), ConsentState::Undetermined);
        }

        #[test]
        fn grant_then_read_round_trips() {
            let tmp = tempfile::tempdir().unwrap();
            let _guard = LocalAppDataGuard::set(tmp.path());
            set_consent(true, "cli").expect("grant should succeed");
            assert_eq!(get_consent(), ConsentState::Granted);
        }

        #[test]
        fn deny_then_read_round_trips() {
            let tmp = tempfile::tempdir().unwrap();
            let _guard = LocalAppDataGuard::set(tmp.path());
            set_consent(false, "cli").expect("deny should succeed");
            assert_eq!(get_consent(), ConsentState::Denied);
        }

        #[test]
        fn consent_can_be_flipped_repeatedly() {
            let tmp = tempfile::tempdir().unwrap();
            let _guard = LocalAppDataGuard::set(tmp.path());
            set_consent(true, "prompt").unwrap();
            assert_eq!(get_consent(), ConsentState::Granted);
            set_consent(false, "settings-toggle").unwrap();
            assert_eq!(get_consent(), ConsentState::Denied);
            set_consent(true, "settings-toggle").unwrap();
            assert_eq!(get_consent(), ConsentState::Granted);
        }

        #[test]
        fn presenter_yes_persists_a_current_version_grant() {
            let tmp = tempfile::tempdir().unwrap();
            let env = crate::telemetry::test_support::TelemetryTestEnv::new(tmp.path());
            env.set_policy_value(3);

            let outcome = request_consent(Some("en-US"), |prompt| {
                assert_eq!(prompt.resource_version, 1);
                assert_eq!(prompt.locale, "en-US");
                Ok(ConsentDecision::Yes)
            })
            .expect("consent request");

            assert_eq!(outcome.result, ConsentActionResult::Granted);
            assert_eq!(outcome.status.stored_state, ConsentState::Granted);
            assert_eq!(outcome.status.effective_state, ConsentState::Granted);
            assert_eq!(outcome.status.reason, None);
        }

        #[test]
        fn async_presenter_yes_persists_a_current_version_grant() {
            let tmp = tempfile::tempdir().unwrap();
            let env = crate::telemetry::test_support::TelemetryTestEnv::new(tmp.path());
            env.set_policy_value(3);

            let outcome = block_on(request_consent_async(Some("en-US"), |prompt| {
                assert_eq!(prompt.resource_version, 1);
                assert_eq!(prompt.locale, "en-US");
                async { Ok(ConsentDecision::Yes) }
            }))
            .expect("async consent request");

            assert_eq!(outcome.result, ConsentActionResult::Granted);
            assert_eq!(outcome.status.stored_state, ConsentState::Granted);
            assert_eq!(outcome.status.effective_state, ConsentState::Granted);
            assert_eq!(outcome.status.reason, None);
        }

        #[test]
        fn async_presenter_no_persists_a_denial() {
            let tmp = tempfile::tempdir().unwrap();
            let env = crate::telemetry::test_support::TelemetryTestEnv::new(tmp.path());
            env.set_policy_value(3);

            let outcome = block_on(request_consent_async(None, |_| async {
                Ok(ConsentDecision::No)
            }))
            .expect("async denial");

            assert_eq!(outcome.result, ConsentActionResult::Denied);
            assert_eq!(get_consent(), ConsentState::Denied);
        }

        #[test]
        fn async_dismissal_preserves_the_prior_state() {
            let tmp = tempfile::tempdir().unwrap();
            let env = crate::telemetry::test_support::TelemetryTestEnv::new(tmp.path());
            env.set_policy_value(3);
            set_consent(false, "prompt").unwrap();

            let outcome = block_on(request_consent_async(None, |_| async {
                Ok(ConsentDecision::Dismissed)
            }))
            .expect("async dismissal");

            assert_eq!(outcome.result, ConsentActionResult::Dismissed);
            assert_eq!(get_consent(), ConsentState::Denied);
        }

        #[test]
        fn async_presenter_error_preserves_the_prior_state() {
            let tmp = tempfile::tempdir().unwrap();
            let env = crate::telemetry::test_support::TelemetryTestEnv::new(tmp.path());
            env.set_policy_value(3);
            set_consent(false, "prompt").unwrap();

            let error = block_on(request_consent_async(None, |_| async {
                Err("host UI failed".to_string())
            }))
            .expect_err("async presenter failure");

            assert_eq!(
                error,
                ConsentActionError::Presenter("host UI failed".to_string())
            );
            assert_eq!(get_consent(), ConsentState::Denied);
        }

        #[test]
        fn async_policy_block_skips_the_presenter() {
            let tmp = tempfile::tempdir().unwrap();
            let env = crate::telemetry::test_support::TelemetryTestEnv::new(tmp.path());
            env.set_policy_value(0);

            let outcome = block_on(request_consent_async(None, |_| async {
                panic!("blocked policy must not present")
            }))
            .expect("blocked result");

            assert_eq!(outcome.result, ConsentActionResult::PolicyBlocked);
        }

        #[test]
        fn policy_change_while_presenter_is_open_blocks_stale_grant() {
            let tmp = tempfile::tempdir().unwrap();
            let env = crate::telemetry::test_support::TelemetryTestEnv::new(tmp.path());
            env.set_policy_value(3);

            let outcome = request_consent(Some("en-US"), |_| {
                env.set_policy_value(0);
                Ok(ConsentDecision::Yes)
            })
            .expect("policy change should produce a typed outcome");

            assert_eq!(outcome.result, ConsentActionResult::PolicyBlocked);
            assert_eq!(outcome.status.effective_state, ConsentState::Undetermined);
            assert_eq!(get_consent(), ConsentState::Undetermined);
        }

        #[test]
        fn consent_change_while_presenter_is_open_rejects_stale_decision() {
            let tmp = tempfile::tempdir().unwrap();
            let env = crate::telemetry::test_support::TelemetryTestEnv::new(tmp.path());
            env.set_policy_value(3);

            let error = request_consent(Some("en-US"), |_| {
                set_consent(false, "concurrent-withdrawal").unwrap();
                Ok(ConsentDecision::Yes)
            })
            .expect_err("stale presenter decision must not overwrite a newer denial");

            assert_eq!(
                error,
                ConsentActionError::Persist(
                    "consent state changed while the presenter was open; no decision was written"
                        .to_string()
                )
            );
            assert_eq!(get_consent(), ConsentState::Denied);
        }

        #[test]
        fn explicit_denial_withdraws_a_concurrent_grant() {
            let tmp = tempfile::tempdir().unwrap();
            let env = crate::telemetry::test_support::TelemetryTestEnv::new(tmp.path());
            env.set_policy_value(3);

            let outcome = request_consent(Some("en-US"), |_| {
                set_consent(true, "concurrent-grant").unwrap();
                Ok(ConsentDecision::No)
            })
            .expect("explicit denial should be persisted");

            assert_eq!(outcome.result, ConsentActionResult::Denied);
            assert_eq!(get_consent(), ConsentState::Denied);
        }

        #[test]
        fn explicit_request_can_replace_a_prior_denial() {
            let tmp = tempfile::tempdir().unwrap();
            let env = crate::telemetry::test_support::TelemetryTestEnv::new(tmp.path());
            env.set_policy_value(3);
            set_consent(false, "prompt").unwrap();

            let outcome = request_consent(None, |_| Ok(ConsentDecision::Yes)).unwrap();

            assert_eq!(outcome.result, ConsentActionResult::Granted);
            assert_eq!(get_consent(), ConsentState::Granted);
        }

        #[test]
        fn dismissed_or_failed_presenter_does_not_rewrite_prior_state() {
            let tmp = tempfile::tempdir().unwrap();
            let env = crate::telemetry::test_support::TelemetryTestEnv::new(tmp.path());
            env.set_policy_value(3);
            set_consent(false, "prompt").unwrap();

            let dismissed =
                request_consent(None, |_| Ok(ConsentDecision::Dismissed)).expect("dismissal");
            assert_eq!(dismissed.result, ConsentActionResult::Dismissed);
            assert_eq!(get_consent(), ConsentState::Denied);

            let error = request_consent(None, |_| Err("host UI failed".to_string()))
                .expect_err("presenter failure");
            assert_eq!(
                error,
                ConsentActionError::Presenter("host UI failed".to_string())
            );
            assert_eq!(get_consent(), ConsentState::Denied);
        }

        #[test]
        fn policy_block_and_current_grant_skip_the_presenter() {
            let tmp = tempfile::tempdir().unwrap();
            let env = crate::telemetry::test_support::TelemetryTestEnv::new(tmp.path());
            env.set_policy_value(0);
            let blocked = request_consent(None, |_| panic!("blocked policy must not present"))
                .expect("blocked result");
            assert_eq!(blocked.result, ConsentActionResult::PolicyBlocked);

            env.set_policy_value(3);
            set_consent(true, "prompt").unwrap();
            let granted = request_consent(None, |_| panic!("current grant must not re-present"))
                .expect("already granted result");
            assert_eq!(granted.result, ConsentActionResult::AlreadyGranted);
        }

        #[test]
        fn withdrawal_is_idempotent_and_ignores_blocking_policy() {
            let tmp = tempfile::tempdir().unwrap();
            let env = crate::telemetry::test_support::TelemetryTestEnv::new(tmp.path());
            env.set_policy_value(3);
            set_consent(true, "prompt").unwrap();
            env.set_policy_value(0);

            for _ in 0..2 {
                let outcome = withdraw_consent().expect("withdrawal");
                assert_eq!(outcome.result, ConsentActionResult::Withdrawn);
                assert_eq!(outcome.status.effective_state, ConsentState::Denied);
            }
        }

        #[test]
        fn withdrawal_reports_the_current_policy_after_waiting_for_the_store_lock() {
            let tmp = tempfile::tempdir().unwrap();
            let env = crate::telemetry::test_support::TelemetryTestEnv::new(tmp.path());
            env.set_policy_value(3);
            set_consent(true, "prompt").unwrap();

            let outcome = std::thread::scope(|scope| {
                let handle = platform::with_store_lock(|| {
                    let handle = scope.spawn(|| withdraw_consent().expect("withdrawal"));
                    env.set_policy_value(0);
                    Ok(handle)
                })
                .expect("store lock");
                handle.join().unwrap()
            });

            assert_eq!(outcome.result, ConsentActionResult::Withdrawn);
            assert_eq!(outcome.status.effective_state, ConsentState::Denied);
            assert_eq!(outcome.policy, crate::telemetry::PolicyState::Blocked);
        }

        #[test]
        fn consent_read_does_not_wait_for_the_store_lock() {
            let tmp = tempfile::tempdir().unwrap();
            let _guard = LocalAppDataGuard::set(tmp.path());
            set_consent(true, "prompt").unwrap();

            let (status_tx, status_rx) = std::sync::mpsc::channel();
            std::thread::scope(|scope| {
                let read_handle = platform::with_store_lock(|| {
                    let status_tx = status_tx.clone();
                    let handle = scope.spawn(move || {
                        status_tx.send(get_status()).expect("send consent status");
                    });
                    let status = status_rx
                        .recv_timeout(std::time::Duration::from_millis(100))
                        .expect("consent read must not wait for the store lock");
                    assert_eq!(status.effective_state, ConsentState::Granted);
                    Ok(handle)
                })
                .expect("store lock");
                read_handle.join().unwrap();
            });
        }

        #[test]
        fn corrupt_file_is_undetermined_not_granted() {
            let tmp = tempfile::tempdir().unwrap();
            let _guard = LocalAppDataGuard::set(tmp.path());
            let dir = tmp.path().join("mxc");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("telemetry-consent.json"), "not json at all").unwrap();
            assert_eq!(get_consent(), ConsentState::Undetermined);
        }

        #[test]
        fn oversized_file_is_rejected_without_unbounded_read() {
            let tmp = tempfile::tempdir().unwrap();
            let _guard = LocalAppDataGuard::set(tmp.path());
            let dir = tmp.path().join("mxc");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("telemetry-consent.json"),
                vec![b'x'; 16 * 1024 + 1],
            )
            .unwrap();
            let status = get_status();
            assert_eq!(status.effective_state, ConsentState::Undetermined);
            assert_eq!(status.reason, Some(ConsentStatusReason::StoreUnreadable));
        }

        #[test]
        fn pending_withdrawal_marker_fails_closed() {
            let tmp = tempfile::tempdir().unwrap();
            let _guard = LocalAppDataGuard::set(tmp.path());
            platform::begin_withdrawal().unwrap();

            let status = get_status();
            assert_eq!(status.effective_state, ConsentState::Undetermined);
            assert_eq!(status.reason, Some(ConsentStatusReason::StoreUnreadable));
        }

        #[test]
        fn pending_withdrawal_marker_metadata_errors_fail_closed() {
            let tmp = tempfile::tempdir().unwrap();
            let _guard = LocalAppDataGuard::set(tmp.path());
            set_consent(true, "prompt").unwrap();

            let status =
                platform::read_status_unlocked_with_marker_for_test(Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "marker temporarily unreadable",
                )));

            assert_eq!(status.stored_state, ConsentState::Undetermined);
            assert_eq!(status.effective_state, ConsentState::Undetermined);
            assert_eq!(status.reason, Some(ConsentStatusReason::StoreUnreadable));
        }

        #[test]
        fn successful_grant_repairs_a_stale_withdrawal_marker() {
            let tmp = tempfile::tempdir().unwrap();
            let env = crate::telemetry::test_support::TelemetryTestEnv::new(tmp.path());
            env.set_policy_value(3);
            platform::begin_withdrawal().unwrap();

            let outcome = request_consent(None, |_| Ok(ConsentDecision::Yes)).unwrap();

            assert_eq!(outcome.result, ConsentActionResult::Granted);
            assert_eq!(outcome.status.effective_state, ConsentState::Granted);
            assert_eq!(get_consent(), ConsentState::Granted);
        }

        #[test]
        fn stale_withdrawal_marker_recovers_to_denied() {
            let tmp = tempfile::tempdir().unwrap();
            let env = crate::telemetry::test_support::TelemetryTestEnv::new(tmp.path());
            env.set_policy_value(3);
            set_consent(true, "prompt").unwrap();
            platform::begin_withdrawal().unwrap();
            age_withdrawal_marker(tmp.path());

            let status = get_status();

            assert_eq!(status.stored_state, ConsentState::Denied);
            assert_eq!(status.effective_state, ConsentState::Denied);
            assert_eq!(status.reason, None);
            assert_eq!(get_consent(), ConsentState::Denied);
            let record =
                std::fs::read_to_string(tmp.path().join("mxc").join("telemetry-consent.json"))
                    .unwrap();
            assert!(record.contains(r#""source": "withdrawal-recovery""#));
            assert!(
                !tmp.path()
                    .join("mxc")
                    .join("telemetry-consent.withdrawal-pending")
                    .exists(),
                "recovery must clear the stale withdrawal marker"
            );
        }

        #[test]
        fn stale_withdrawal_marker_on_denied_record_is_cleared() {
            let tmp = tempfile::tempdir().unwrap();
            let env = crate::telemetry::test_support::TelemetryTestEnv::new(tmp.path());
            env.set_policy_value(3);
            set_consent(false, "cli").unwrap();
            platform::begin_withdrawal().unwrap();
            age_withdrawal_marker(tmp.path());

            let status = get_status();

            assert_eq!(status.stored_state, ConsentState::Denied);
            assert_eq!(status.effective_state, ConsentState::Denied);
            assert_eq!(status.reason, None);
            assert!(
                !tmp.path()
                    .join("mxc")
                    .join("telemetry-consent.withdrawal-pending")
                    .exists(),
                "recovery must eventually clear a leftover withdrawal marker"
            );
        }

        #[test]
        fn stale_withdrawal_recovery_is_serialized_with_concurrent_writers() {
            let tmp = tempfile::tempdir().unwrap();
            let env = crate::telemetry::test_support::TelemetryTestEnv::new(tmp.path());
            env.set_policy_value(3);
            set_consent(true, "prompt").unwrap();
            platform::begin_withdrawal().unwrap();
            age_withdrawal_marker(tmp.path());

            std::thread::scope(|scope| {
                let (reader, writer) = platform::with_store_lock(|| {
                    let (reader_started_tx, reader_started_rx) = std::sync::mpsc::channel();
                    let (writer_started_tx, writer_started_rx) = std::sync::mpsc::channel();
                    let reader = scope.spawn(move || {
                        reader_started_tx.send(()).unwrap();
                        get_status()
                    });
                    let writer = scope.spawn(move || {
                        writer_started_tx.send(()).unwrap();
                        withdraw_consent().map(|_| ())
                    });
                    reader_started_rx.recv().unwrap();
                    writer_started_rx.recv().unwrap();
                    assert!(
                        !reader.is_finished() && !writer.is_finished(),
                        "recovery and writer must wait for the store lock"
                    );
                    Ok((reader, writer))
                })
                .unwrap();

                let reader_status = reader.join().unwrap();
                writer.join().unwrap().unwrap();
                assert_eq!(reader_status.effective_state, ConsentState::Denied);
                assert_eq!(get_consent(), ConsentState::Denied);
                assert!(!tmp
                    .path()
                    .join("mxc")
                    .join("telemetry-consent.withdrawal-pending")
                    .exists());
            });
        }

        #[test]
        fn unknown_schema_version_is_undetermined() {
            let tmp = tempfile::tempdir().unwrap();
            let _guard = LocalAppDataGuard::set(tmp.path());
            let dir = tmp.path().join("mxc");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("telemetry-consent.json"),
                r#"{"schemaVersion":999,"consent":"granted"}"#,
            )
            .unwrap();
            assert_eq!(get_consent(), ConsentState::Undetermined);
        }

        #[test]
        fn unsupported_grant_schema_reports_a_typed_reason() {
            let tmp = tempfile::tempdir().unwrap();
            let _guard = LocalAppDataGuard::set(tmp.path());
            let dir = tmp.path().join("mxc");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("telemetry-consent.json"),
                r#"{"schemaVersion":999,"consent":"granted","promptResourceVersion":1,"promptLocale":"en-US"}"#,
            )
            .unwrap();

            let status = get_status();

            assert_eq!(status.stored_state, ConsentState::Granted);
            assert_eq!(status.effective_state, ConsentState::Undetermined);
            assert_eq!(
                status.reason,
                Some(ConsentStatusReason::ConsentSchemaUnsupported)
            );
        }

        #[test]
        fn unsupported_prompt_version_reports_a_typed_reason() {
            let tmp = tempfile::tempdir().unwrap();
            let _guard = LocalAppDataGuard::set(tmp.path());
            let dir = tmp.path().join("mxc");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("telemetry-consent.json"),
                r#"{"schemaVersion":2,"consent":"granted","promptResourceVersion":999,"promptLocale":"en-US"}"#,
            )
            .unwrap();

            let status = get_status();

            assert_eq!(status.stored_state, ConsentState::Granted);
            assert_eq!(status.effective_state, ConsentState::Undetermined);
            assert_eq!(
                status.reason,
                Some(ConsentStatusReason::PromptVersionUnsupported)
            );
        }

        #[test]
        fn concurrent_grant_revoke_never_corrupts_the_store() {
            // Regression test for the write-race finding: many threads
            // hammering set_consent() against the same redirected store
            // concurrently (the override env var is process-global, so
            // every spawned thread inherits the same redirected path from
            // the outer guard) must never leave a torn/missing file behind;
            // the final state must be a fully-formed, parseable record.
            let tmp = tempfile::tempdir().unwrap();
            let _guard = LocalAppDataGuard::set(tmp.path());

            // Every writer must *succeed*, not merely avoid corrupting the
            // file. Asserting only on the final file's parseability would
            // still pass if 15 of 16 writers lost a temp-name or rename
            // race, which is precisely the failure this fix targets.
            let results: Vec<Result<(), String>> = std::thread::scope(|scope| {
                let handles: Vec<_> = (0..16)
                    .map(|i| scope.spawn(move || set_consent(i % 2 == 0, "cli")))
                    .collect();
                handles.into_iter().map(|h| h.join().unwrap()).collect()
            });
            for (i, result) in results.iter().enumerate() {
                assert!(result.is_ok(), "concurrent writer {i} failed: {result:?}");
            }

            // Whatever the last writer's outcome was, the store must be
            // Granted or Denied — never Undetermined (which would mean a
            // corrupt/missing file from a torn write).
            let state = get_consent();
            assert!(matches!(
                state,
                ConsentState::Granted | ConsentState::Denied
            ));
        }

        /// Pre-versioned grants must be invalidated because they cannot prove
        /// the canonical prompt was shown. A prior denial remains denied.
        #[test]
        fn legacy_records_preserve_provenance_but_require_reconsent_for_grants() {
            for (stored, effective, reason) in [
                (
                    "granted",
                    ConsentState::Undetermined,
                    Some(ConsentStatusReason::PromptVersionMissing),
                ),
                ("denied", ConsentState::Denied, None),
            ] {
                let tmp = tempfile::tempdir().unwrap();
                let _guard = LocalAppDataGuard::set(tmp.path());
                let dir = tmp.path().join("mxc");
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(
                    dir.join("telemetry-consent.json"),
                    format!(
                        r#"{{"schemaVersion":1,"consent":"{stored}","source":"prompt","promptedMxcVersion":"0.7.0","updatedAtUtc":"2026-01-02T03:04:05Z"}}"#
                    ),
                )
                .unwrap();
                let status = get_status();
                assert_eq!(
                    status.stored_state,
                    if stored == "granted" {
                        ConsentState::Granted
                    } else {
                        ConsentState::Denied
                    }
                );
                assert_eq!(status.effective_state, effective);
                assert_eq!(status.reason, reason);
            }
        }

        /// `with_io_retry` must ride out transient lock contention but must
        /// not sleep through a settled answer. The `NotFound` case is the
        /// startup-latency one: it is the state of every machine that has
        /// never recorded a decision, on the critical path of every launch.
        #[test]
        fn io_retry_retries_transient_errors_then_succeeds() {
            use crate::telemetry::consent::platform;
            let mut calls = 0;
            let result = platform::with_io_retry_for_test(|| {
                calls += 1;
                if calls < 3 {
                    Err(platform::transient_io_error_for_test())
                } else {
                    Ok(calls)
                }
            });
            assert_eq!(result.unwrap(), 3);
            assert_eq!(calls, 3);
        }

        #[test]
        fn io_retry_gives_up_after_the_attempt_budget() {
            use crate::telemetry::consent::platform;
            let mut calls = 0;
            let result = platform::with_io_retry_for_test(|| {
                calls += 1;
                Err::<(), _>(platform::transient_io_error_for_test())
            });
            assert!(result.is_err());
            assert_eq!(calls, platform::IO_RETRY_ATTEMPTS_FOR_TEST);
        }

        #[test]
        fn io_retry_does_not_retry_not_found() {
            use crate::telemetry::consent::platform;
            let mut calls = 0;
            let started = std::time::Instant::now();
            let result = platform::with_io_retry_for_test(|| {
                calls += 1;
                Err::<(), _>(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "no consent file",
                ))
            });
            assert!(result.is_err());
            assert_eq!(calls, 1, "NotFound must not be retried");
            assert!(
                started.elapsed() < std::time::Duration::from_millis(20),
                "NotFound must not sleep on the retry delay"
            );
        }

        /// The whole point of the above: reading a fresh (nonexistent) store
        /// is the common case and must be effectively instant.
        #[test]
        fn fresh_store_read_does_not_sleep() {
            let tmp = tempfile::tempdir().unwrap();
            let _guard = LocalAppDataGuard::set(tmp.path());
            let started = std::time::Instant::now();
            assert_eq!(get_consent(), ConsentState::Undetermined);
            assert!(
                started.elapsed() < std::time::Duration::from_millis(40),
                "fresh-store read took {:?}; the retry loop is sleeping on NotFound again",
                started.elapsed()
            );
        }

        #[test]
        fn missing_local_app_data_resolution_falls_back_to_real_known_folder() {
            // With no debug override set, the real per-user known-folder
            // path must still resolve (it always exists on a real Windows
            // profile), so exercise that fallback without touching the real
            // consent file itself. Locks ENV_LOCK directly (rather than via
            // LocalAppDataGuard) since this test removes the override
            // entirely instead of redirecting it.
            let _lock = super::super::test_support::ENV_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let previous = std::env::var_os("MXC_TEST_LOCALAPPDATA_OVERRIDE");
            let previous_owner = std::env::var_os("MXC_TEST_LOCALAPPDATA_OVERRIDE_OWNER_PID");
            std::env::remove_var("MXC_TEST_LOCALAPPDATA_OVERRIDE");
            std::env::remove_var("MXC_TEST_LOCALAPPDATA_OVERRIDE_OWNER_PID");
            let resolved =
                crate::telemetry::consent::platform::known_folder_local_app_data_for_test();
            if let Some(v) = previous {
                std::env::set_var("MXC_TEST_LOCALAPPDATA_OVERRIDE", v);
            }
            if let Some(v) = previous_owner {
                std::env::set_var("MXC_TEST_LOCALAPPDATA_OVERRIDE_OWNER_PID", v);
            }
            assert!(
                resolved.is_some(),
                "known-folder API should resolve a real path"
            );
        }

        #[test]
        fn local_app_data_override_reaches_child_processes() {
            let tmp = tempfile::tempdir().unwrap();
            let _guard = LocalAppDataGuard::set(tmp.path());

            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("child_process_local_app_data_override_probe")
                .arg("--nocapture")
                .env("MXC_CHILD_OVERRIDE_PROBE", tmp.path())
                .status()
                .expect("spawn child test probe");

            assert!(status.success(), "child probe failed: {status}");
        }

        #[test]
        fn child_process_local_app_data_override_probe() {
            let Some(expected) = std::env::var_os("MXC_CHILD_OVERRIDE_PROBE") else {
                return;
            };

            assert_eq!(
                platform::local_app_data_dir_for_test(),
                Some(std::path::PathBuf::from(expected))
            );
            assert_eq!(get_status().reason, Some(ConsentStatusReason::NoRecord));
        }

        #[test]
        fn known_folder_resolution_only_caches_successful_results() {
            let cache = std::sync::OnceLock::new();
            let mut calls = 0;

            assert_eq!(
                platform::cache_successful_resolution_for_test(&cache, || {
                    calls += 1;
                    None
                }),
                None
            );
            assert_eq!(
                platform::cache_successful_resolution_for_test(&cache, || {
                    calls += 1;
                    Some(std::path::PathBuf::from(r"C:\Users\test\AppData\Local"))
                }),
                Some(std::path::PathBuf::from(r"C:\Users\test\AppData\Local"))
            );
            assert_eq!(
                platform::cache_successful_resolution_for_test(&cache, || {
                    calls += 1;
                    Some(std::path::PathBuf::from(r"C:\Users\test\AppData\Roaming"))
                }),
                Some(std::path::PathBuf::from(r"C:\Users\test\AppData\Local"))
            );
            assert_eq!(calls, 2, "a failed lookup must not be cached forever");
        }
    }
}
