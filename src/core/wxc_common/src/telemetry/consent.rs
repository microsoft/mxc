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
    /// This is the single definition of that policy for every MXC consumer
    /// surface — the Rust SDK, the C ABI, the C# SDK, the Node SDK, and the
    /// `wxc-exec --telemetry-consent-status` JSON all derive their answer
    /// from here rather than re-deriving `state == Undetermined` in their own
    /// language. If the policy ever grows (e.g. re-prompting after a
    /// materially changed data-collection scope), it changes here once.
    ///
    /// Never true for [`NotApplicable`](ConsentState::NotApplicable): MXC
    /// collects no telemetry off Windows, so there is nothing to consent to
    /// and a prompt would be asking the user to decide something moot.
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

/// Persists a new telemetry consent decision for the current Windows user.
///
/// `source` is free-form provenance (e.g. `"prompt"`, `"settings-toggle"`,
/// `"cli"`) recorded alongside the decision for support/debugging; it is
/// never transmitted anywhere and never affects gating.
///
/// Returns an error string suitable for CLI/log output. On non-Windows this
/// always fails with a descriptive "not applicable" error — MXC must not
/// silently accept a consent decision it can never act on.
pub fn set_consent(granted: bool, source: &str) -> Result<(), String> {
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
pub async fn request_consent_async<F, Fut>(
    locale: Option<&str>,
    presenter: F,
) -> Result<ConsentActionOutcome, ConsentActionError>
where
    F: FnOnce(&ConsentPrompt) -> Fut,
    Fut: std::future::Future<Output = Result<ConsentDecision, String>>,
{
    match consent_preflight(locale) {
        ConsentPreflight::Complete(outcome) => Ok(outcome),
        ConsentPreflight::Present {
            prompt,
            policy,
            status,
        } => {
            let decision = presenter(prompt)
                .await
                .map_err(ConsentActionError::Presenter)?;
            persist_presented_decision(decision, prompt, policy, status)
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
    match decision {
        ConsentDecision::Yes => {
            platform::write_presented(true, "prompt", prompt)
                .map_err(ConsentActionError::Persist)?;
            Ok(ConsentActionOutcome {
                result: ConsentActionResult::Granted,
                status: get_status(),
                policy,
            })
        }
        ConsentDecision::No => {
            platform::write_presented(false, "prompt", prompt)
                .map_err(ConsentActionError::Persist)?;
            Ok(ConsentActionOutcome {
                result: ConsentActionResult::Denied,
                status: get_status(),
                policy,
            })
        }
        ConsentDecision::Dismissed => Ok(ConsentActionOutcome {
            result: ConsentActionResult::Dismissed,
            status,
            policy,
        }),
    }
}

/// Idempotently withdraw telemetry consent.
///
/// Withdrawal does not require a permitting administrative policy. Off
/// Windows it succeeds as a typed `NotApplicable` result without storage.
pub fn withdraw_consent() -> Result<ConsentActionOutcome, ConsentActionError> {
    let policy = super::policy::get_policy();
    let status = get_status();
    if status.effective_state == ConsentState::NotApplicable {
        return Ok(ConsentActionOutcome {
            result: ConsentActionResult::NotApplicable,
            status,
            policy,
        });
    }

    platform::write(false, "withdrawal").map_err(ConsentActionError::Persist)?;
    Ok(ConsentActionOutcome {
        result: ConsentActionResult::Withdrawn,
        status: get_status(),
        policy,
    })
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
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    /// Number of attempts for filesystem operations that can transiently fail
    /// under Windows file-lock contention (AV real-time scanning, the search
    /// indexer, or a concurrent `wxc-exec` grant/revoke in another process).
    const IO_RETRY_ATTEMPTS: u32 = 5;
    const IO_RETRY_DELAY: Duration = Duration::from_millis(20);

    /// `ERROR_SHARING_VIOLATION` — another handle holds the file with a
    /// conflicting share mode (AV scanner, indexer, racing sibling process).
    const ERROR_SHARING_VIOLATION: i32 = 32;
    /// `ERROR_LOCK_VIOLATION` — a byte-range lock is held on the file.
    const ERROR_LOCK_VIOLATION: i32 = 33;

    /// Resolves the real, per-user `%LocalAppData%` directory via the Windows
    /// known-folder API (`SHGetKnownFolderPath`/`FOLDERID_LocalAppData`)
    /// rather than trusting the `LOCALAPPDATA` *environment variable*. A
    /// parent process launching `wxc-exec.exe` fully controls the child's
    /// environment, so trusting `LOCALAPPDATA` directly would let it point
    /// the consent store at an attacker-chosen directory and plant a fake
    /// "granted" record — undermining the very consent MXC is supposed to
    /// own. The known-folder API resolves the path registered for the
    /// process's own user token, independent of environment state.
    ///
    /// `SHGetKnownFolderPath` is COM IPC plus a registry read, and — because
    /// we bind it explicitly to the *process* token (see
    /// [`resolve_known_folder_local_app_data`]) — the answer cannot change for
    /// the lifetime of the process, so the result is memoized. A long-lived
    /// host application querying consent through the SDK/FFI on every
    /// operation should not pay that cost repeatedly.
    fn known_folder_local_app_data() -> Option<PathBuf> {
        static CACHED: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
        CACHED
            .get_or_init(resolve_known_folder_local_app_data)
            .clone()
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
    #[cfg(any(test, debug_assertions))]
    fn debug_local_app_data_override() -> Option<PathBuf> {
        std::env::var_os("MXC_TEST_LOCALAPPDATA_OVERRIDE").map(PathBuf::from)
    }

    fn local_app_data_dir() -> Option<PathBuf> {
        #[cfg(any(test, debug_assertions))]
        if let Some(over) = debug_local_app_data_override() {
            return Some(over);
        }
        known_folder_local_app_data()
    }

    /// Test-only accessor for [`known_folder_local_app_data`], which is
    /// otherwise private to this module.
    #[cfg(test)]
    pub(super) fn known_folder_local_app_data_for_test() -> Option<PathBuf> {
        known_folder_local_app_data()
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

    pub(super) fn read_status() -> ConsentStatus {
        let Some(path) = consent_file_path() else {
            return ConsentStatus {
                stored_state: ConsentState::Undetermined,
                effective_state: ConsentState::Undetermined,
                reason: Some(ConsentStatusReason::StoreUnreadable),
            };
        };
        let data = match with_io_retry(|| fs::read_to_string(&path)) {
            Ok(data) => data,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return ConsentStatus {
                    stored_state: ConsentState::Undetermined,
                    effective_state: ConsentState::Undetermined,
                    reason: Some(ConsentStatusReason::NoRecord),
                };
            }
            Err(_) => {
                return ConsentStatus {
                    stored_state: ConsentState::Undetermined,
                    effective_state: ConsentState::Undetermined,
                    reason: Some(ConsentStatusReason::StoreUnreadable),
                };
            }
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

        if let Err(e) = with_io_retry(|| fs::write(&tmp_path, &json)) {
            remove_best_effort(&tmp_path);
            return Err(format!("failed to write {}: {e}", tmp_path.display()));
        }
        if let Err(e) = with_io_retry(|| fs::rename(&tmp_path, &path)) {
            remove_best_effort(&tmp_path);
            return Err(format!("failed to finalize {}: {e}", path.display()));
        }
        Ok(())
    }

    /// A cheap, non-cryptographic source of per-call uniqueness for the temp
    /// filename. Only needs to avoid same-process, same-nanosecond
    /// collisions between concurrent threads — not to be unguessable — so
    /// the current time's subsecond component plus the thread id is enough.
    fn random_suffix() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0) as u64;
        let tid = {
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            std::thread::current().id().hash(&mut hasher);
            hasher.finish()
        };
        nanos ^ tid
    }
}

// ---------------------------------------------------------------------------
// Non-Windows stub — no file, no prompt, no pretend consent.
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "windows"))]
mod platform {
    use super::{ConsentState, ConsentStatus, ConsentStatusReason};

    pub(super) fn read_status() -> ConsentStatus {
        ConsentStatus {
            stored_state: ConsentState::NotApplicable,
            effective_state: ConsentState::NotApplicable,
            reason: Some(ConsentStatusReason::NotApplicable),
        }
    }

    pub(super) fn write(_granted: bool, _source: &str) -> Result<(), String> {
        Err("telemetry is Windows-only; consent is not applicable on this platform".to_string())
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

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::{Mutex, MutexGuard};

    /// `get_consent`/`set_consent` read the debug-only override, which is
    /// process-global state. Guarded internally by [`LocalAppDataGuard::set`]
    /// so a caller can never forget to hold it — see that type's doc comment.
    /// `pub(crate)` only so the rare test that must mutate the override
    /// directly (bypassing the guard, e.g. to test the "no override set"
    /// fallback path) can still serialize against guard-holding tests.
    pub(crate) static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Redirects the consent store (Windows only) to a fresh temp directory
    /// for the lifetime of the guard, restoring the previous value on drop.
    /// Acquires and holds [`ENV_LOCK`] for the guard's entire lifetime, so
    /// tests cannot accidentally construct the guard without the lock (the
    /// two were previously separate, and a test could forget to pair them).
    /// A no-op holder on non-Windows, where consent is `NotApplicable`
    /// regardless — kept as a real (if inert) guard type so callers don't
    /// need `#[cfg]` at every call site.
    pub(crate) struct LocalAppDataGuard {
        _lock: MutexGuard<'static, ()>,
        #[cfg(target_os = "windows")]
        previous: Option<std::ffi::OsString>,
    }

    impl LocalAppDataGuard {
        #[cfg(target_os = "windows")]
        pub(crate) fn set(path: &std::path::Path) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let previous = std::env::var_os("MXC_TEST_LOCALAPPDATA_OVERRIDE");
            std::env::set_var("MXC_TEST_LOCALAPPDATA_OVERRIDE", path);
            Self {
                _lock: lock,
                previous,
            }
        }

        #[cfg(not(target_os = "windows"))]
        pub(crate) fn set(_path: &std::path::Path) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            Self { _lock: lock }
        }
    }

    #[cfg(target_os = "windows")]
    impl Drop for LocalAppDataGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(v) => std::env::set_var("MXC_TEST_LOCALAPPDATA_OVERRIDE", v),
                None => std::env::remove_var("MXC_TEST_LOCALAPPDATA_OVERRIDE"),
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
        assert!(set_consent(true, "cli").is_err());
        assert!(set_consent(false, "cli").is_err());
        assert!(
            !needs_consent_prompt(),
            "must never ask for consent where nothing is collected"
        );
    }

    #[cfg(target_os = "windows")]
    mod windows_tests {
        use super::LocalAppDataGuard;
        use crate::telemetry::consent::{
            get_consent, get_status, needs_consent_prompt, request_consent, set_consent,
            withdraw_consent, ConsentActionError, ConsentActionResult, ConsentDecision,
            ConsentState, ConsentStatusReason,
        };

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
        fn corrupt_file_is_undetermined_not_granted() {
            let tmp = tempfile::tempdir().unwrap();
            let _guard = LocalAppDataGuard::set(tmp.path());
            let dir = tmp.path().join("mxc");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("telemetry-consent.json"), "not json at all").unwrap();
            assert_eq!(get_consent(), ConsentState::Undetermined);
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
            // profile) — this is exactly the fallback the security fix
            // relies on, so exercise it without touching the real consent
            // file itself. Locks ENV_LOCK directly (rather than via
            // LocalAppDataGuard) since this test removes the override
            // entirely instead of redirecting it.
            let _lock = super::super::test_support::ENV_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let previous = std::env::var_os("MXC_TEST_LOCALAPPDATA_OVERRIDE");
            std::env::remove_var("MXC_TEST_LOCALAPPDATA_OVERRIDE");
            let resolved =
                crate::telemetry::consent::platform::known_folder_local_app_data_for_test();
            if let Some(v) = previous {
                std::env::set_var("MXC_TEST_LOCALAPPDATA_OVERRIDE", v);
            }
            assert!(
                resolved.is_some(),
                "known-folder API should resolve a real path"
            );
        }
    }
}
