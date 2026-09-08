// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Administrative (MDM / Group Policy) telemetry policy.
//!
//! See `docs/telemetry/telemetry-administrative-policy.md` for the admin-facing reference and
//! `docs/telemetry/telemetry-consent-design.md` for how this composes with
//! user consent. In short:
//!
//! - An administrator (via Intune, another MDM, or Group Policy) may **deny**
//!   MXC telemetry machine-wide by setting
//!   `HKLM\SOFTWARE\Policies\Mxc\AllowTelemetry` (`REG_DWORD`).
//! - The policy is a **ceiling, never a grant**. An administrator who permits
//!   telemetry does not thereby consent on the user's behalf: MXC still
//!   requires an explicit, persisted [`super::consent::ConsentState::Granted`]
//!   from the user. There is no policy value that can turn telemetry on.
//! - MXC deliberately does **not** read the Windows-wide `AllowTelemetry`
//!   setting. Microsoft's Policy CSP documentation scopes that policy to "the
//!   operating system and apps that are considered part of Windows" and states
//!   it "doesn't apply to any additional apps installed by your organization",
//!   and the Windows Business Division privacy guidance requires that
//!   app-classified components "build their own notice and consent experience
//!   ... and should not rely on the Windows diagnostic consent". Reading the
//!   OS setting would also mean reading Windows *consent* state, which MXC is
//!   expressly forbidden from doing — the supported OS APIs for this
//!   (`TelIsTelemetryTypeAllowed` and friends) fold the user's Settings-app
//!   choice into their answer.
//! - Windows-only, like every other telemetry surface. On other platforms MXC
//!   collects nothing at all, so there is nothing for a policy to restrict and
//!   this module compiles down to a stub.
//! - Fails closed: an unreadable or unrecognized policy value denies.

/// The administrator's telemetry decision for this machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyState {
    /// No administrative policy is configured. Telemetry is governed solely by
    /// the user's own consent decision. This is *not* a grant.
    Unrestricted,
    /// An administrator has permitted optional (usage) telemetry, the category
    /// MXC emits. Still requires user consent before anything is collected.
    Allowed,
    /// An administrator has denied MXC telemetry, or the configured value could
    /// not be understood. Nothing is collected regardless of user consent, and
    /// hosts must not offer a consent prompt.
    Blocked,
    /// Not a Windows host. MXC collects no telemetry here, so administrative
    /// policy is not a meaningful concept.
    NotApplicable,
}

impl PolicyState {
    /// Stable, lowercase wire representation used by the CLI flags, the FFI
    /// boundary, and the SDKs. Kept separate from `Debug` so the on-the-wire
    /// strings never drift if the Rust variant names change.
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyState::Unrestricted => "unrestricted",
            PolicyState::Allowed => "allowed",
            PolicyState::Blocked => "blocked",
            PolicyState::NotApplicable => "not-applicable",
        }
    }

    /// Whether telemetry collection is administratively permitted.
    ///
    /// True for every state except [`Blocked`](PolicyState::Blocked) —
    /// including [`NotApplicable`](PolicyState::NotApplicable), because off
    /// Windows the *consent* gate is what stops collection, and double-denying
    /// here would wrongly imply an administrator had acted.
    ///
    /// This never means "collect": it is one conjunct of
    /// [`super::is_enabled`], which also requires user consent.
    pub fn allows_collection(&self) -> bool {
        !matches!(self, PolicyState::Blocked)
    }
}

/// The `REG_DWORD` value an administrator sets to permit the optional (usage)
/// telemetry category that MXC emits, mirroring the Windows diagnostic-data
/// scale where `3` is Optional/Full.
#[cfg(target_os = "windows")]
const POLICY_VALUE_OPTIONAL: u32 = 3;

#[cfg(all(
    target_os = "windows",
    any(test, all(feature = "test-support", debug_assertions))
))]
static DEBUG_POLICY_KEY_OVERRIDE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

#[cfg(all(
    target_os = "windows",
    any(test, all(feature = "test-support", debug_assertions))
))]
const POLICY_KEY_OVERRIDE_ENV: &str = "MXC_TEST_POLICY_KEY_OVERRIDE";
#[cfg(all(
    target_os = "windows",
    any(test, all(feature = "test-support", debug_assertions))
))]
const POLICY_KEY_OVERRIDE_OWNER_ENV: &str = "MXC_TEST_POLICY_KEY_OVERRIDE_OWNER_PID";

/// Returns the current administrative telemetry policy.
///
/// Fail-closed: a value that is present but not understood resolves to
/// [`PolicyState::Blocked`]. An *absent* policy resolves to
/// [`PolicyState::Unrestricted`] — the unmanaged default, where the user's own
/// consent decision governs. Registry failures and unrecognized values are
/// reported to stderr once per distinct failure so the fail-closed result does
/// not hide a broken policy deployment from operators.
pub fn get_policy() -> PolicyState {
    platform::read()
}

/// Whether an administrator has denied MXC telemetry on this machine.
///
/// Convenience over [`get_policy`]; the inverse of
/// [`PolicyState::allows_collection`].
pub fn is_blocked_by_policy() -> bool {
    !get_policy().allows_collection()
}

// ---------------------------------------------------------------------------
// Windows implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
mod platform {
    use super::{PolicyState, POLICY_VALUE_OPTIONAL};
    use crate::telemetry::FailureReporter;
    use std::io::Write;
    use std::sync::OnceLock;
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;

    /// Machine-wide policy key. Under `SOFTWARE\Policies`, so it is writable
    /// only by administrators — a standard user cannot forge a permit here.
    ///
    /// Deliberately *not* under `Policies\Microsoft`, even though MXC is a
    /// Microsoft product. Windows forbids ADMX-ingested policies from writing
    /// under `System`, `Software\Microsoft`, or `Software\Policies\Microsoft`
    /// except for a hardcoded allowlist (Office, Edge, OneDrive, VisualStudio,
    /// …) that MXC is not on and cannot join without a Windows servicing
    /// change. A key under those prefixes would make `Mxc.admx` un-ingestible
    /// by Intune and every other MDM. `SOFTWARE\Policies\<Vendor>` is the shape
    /// Microsoft's own ADMX-ingestion documentation uses for third-party apps.
    ///
    /// This is the administrator-facing contract documented in
    /// `docs/telemetry/telemetry-administrative-policy.md`; changing it breaks deployed
    /// policy.
    const POLICY_SUBKEY: &str = r"SOFTWARE\Policies\Mxc";
    const POLICY_VALUE_NAME: &str = "AllowTelemetry";

    /// The outcome of looking for the policy value.
    ///
    /// The distinction between [`Absent`](PolicyValue::Absent) and
    /// [`Unreadable`](PolicyValue::Unreadable) is load-bearing: only a
    /// genuinely missing policy means "unmanaged". Anything that exists but
    /// cannot be understood must deny, or an administrator who misconfigured
    /// the value would silently get collection instead of the block they
    /// intended.
    enum PolicyValue {
        /// The key or the value genuinely does not exist — no policy is
        /// configured, so the machine is unmanaged for MXC telemetry.
        Absent,
        /// A `REG_DWORD` was read successfully.
        Value(u32),
        /// A policy is configured but could not be read: wrong value type
        /// (e.g. `REG_SZ`), access denied, or a corrupt/failing registry.
        Unreadable,
    }

    fn report_policy_failure(signature: String) {
        static FAILURES: OnceLock<FailureReporter> = OnceLock::new();
        FAILURES
            .get_or_init(FailureReporter::default)
            .report(signature, |detail| {
                let stderr = std::io::stderr();
                let mut handle = stderr.lock();
                let _ = writeln!(
                    handle,
                    "mxc: telemetry administrative policy failure ({detail}); \
                     treating policy as blocked"
                );
                let _ = handle.flush();
            });
    }

    fn report_policy_read_failure(operation: &str, error: &std::io::Error) {
        report_policy_failure(format!(
            "{operation}: kind={:?}, os_error={:?}, error={error}",
            error.kind(),
            error.raw_os_error()
        ));
    }

    fn report_unrecognized_policy_value(value: u32) {
        report_policy_failure(format!(
            "read AllowTelemetry value: unrecognized DWORD value {value}"
        ));
    }

    pub(super) fn read() -> PolicyState {
        policy_state_from_value(read_policy_value())
    }

    fn policy_state_from_value(value: PolicyValue) -> PolicyState {
        policy_state_from_value_with_reporter(value, report_unrecognized_policy_value)
    }

    fn policy_state_from_value_with_reporter(
        value: PolicyValue,
        report_unrecognized: impl FnOnce(u32),
    ) -> PolicyState {
        match value {
            PolicyValue::Absent => PolicyState::Unrestricted,
            PolicyValue::Value(POLICY_VALUE_OPTIONAL) => PolicyState::Allowed,
            // Values `0` (off) and `1` (required-only, a category MXC does not
            // emit) are recognized blocking levels.
            PolicyValue::Value(0) | PolicyValue::Value(1) => PolicyState::Blocked,
            // Anything else is a broken deployment. Deny and report it rather
            // than silently guessing at the administrator's intent.
            PolicyValue::Value(value) => {
                report_unrecognized(value);
                PolicyState::Blocked
            }
            // Fail closed. An administrator who typed the value in as a string,
            // or a machine whose registry we cannot read, must not be treated
            // as unmanaged.
            PolicyValue::Unreadable => PolicyState::Blocked,
        }
    }

    #[cfg(test)]
    pub(super) fn unreadable_policy_state_for_test() -> PolicyState {
        policy_state_from_value(PolicyValue::Unreadable)
    }

    #[cfg(test)]
    pub(super) fn policy_value_report_for_test(value: u32) -> (PolicyState, Option<u32>) {
        let mut reported = None;
        let state = policy_state_from_value_with_reporter(PolicyValue::Value(value), |value| {
            reported = Some(value);
        });
        (state, reported)
    }

    /// Reads the policy value, distinguishing "not configured" from
    /// "configured but unreadable".
    ///
    /// `winreg` surfaces registry failures as [`std::io::Error`]; a missing key
    /// or value is `ERROR_FILE_NOT_FOUND`, which maps to
    /// [`std::io::ErrorKind::NotFound`]. Every other error — notably
    /// `ErrorKind::InvalidData` for a non-`REG_DWORD` value, and
    /// `PermissionDenied` for an ACL that hides the key — is a policy we cannot
    /// evaluate, and therefore a deny.
    fn read_policy_value() -> PolicyValue {
        let (hive, subkey) = policy_location();
        let key = match RegKey::predef(hive).open_subkey(subkey) {
            Ok(key) => key,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return PolicyValue::Absent,
            Err(error) => {
                report_policy_read_failure("open policy key", &error);
                return PolicyValue::Unreadable;
            }
        };
        match key.get_value::<u32, _>(POLICY_VALUE_NAME) {
            Ok(value) => PolicyValue::Value(value),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => PolicyValue::Absent,
            Err(error) => {
                report_policy_read_failure("read AllowTelemetry value", &error);
                PolicyValue::Unreadable
            }
        }
    }

    /// Resolves the hive and subkey to read the policy from.
    ///
    /// Always the real machine policy location, except under test where
    /// [`debug_policy_key_override`] can redirect it under `HKEY_CURRENT_USER`
    /// so tests can exercise the real registry code path without requiring
    /// administrator rights. The override is compiled out of every shipped
    /// binary, so a release build can never be pointed at a user-writable key.
    fn policy_location() -> (winreg::HKEY, String) {
        #[cfg(any(test, all(feature = "test-support", debug_assertions)))]
        if let Some(subkey) = debug_policy_key_override() {
            return (winreg::enums::HKEY_CURRENT_USER, subkey);
        }
        (HKEY_LOCAL_MACHINE, POLICY_SUBKEY.to_string())
    }

    /// Test-only hook: redirects the policy read to `HKCU\<value>`.
    ///
    /// Active under `cfg(test)` and debug `test-support` feature builds.
    /// Never present in shipped or release-profile binaries.
    #[cfg(any(test, all(feature = "test-support", debug_assertions)))]
    fn debug_policy_key_override() -> Option<String> {
        super::DEBUG_POLICY_KEY_OVERRIDE
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .or_else(|| {
                scoped_policy_key_override(
                    std::env::var_os(super::POLICY_KEY_OVERRIDE_ENV),
                    std::env::var_os(super::POLICY_KEY_OVERRIDE_OWNER_ENV),
                    std::process::id(),
                    direct_parent_process_id(),
                )
            })
    }

    #[cfg(any(test, all(feature = "test-support", debug_assertions)))]
    /// Environment bridge for language-binding tests and smoke-test children.
    ///
    /// The owner PID is mandatory so an unpaired ambient key override is
    /// ignored. It may identify this process (an in-process binding test) or
    /// the test harness that explicitly launched this child.
    fn scoped_policy_key_override(
        key: Option<std::ffi::OsString>,
        owner: Option<std::ffi::OsString>,
        process_id: u32,
        parent_process_id: Option<u32>,
    ) -> Option<String> {
        let owner = owner?.to_str()?.parse::<u32>().ok()?;
        if owner != process_id && Some(owner) != parent_process_id {
            return None;
        }
        let key = key?.into_string().ok()?;
        (!key.is_empty()).then_some(key)
    }

    #[cfg(any(test, all(feature = "test-support", debug_assertions)))]
    fn direct_parent_process_id() -> Option<u32> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.ok()?;
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut parent = None;
        unsafe {
            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    if entry.th32ProcessID == std::process::id() {
                        parent = Some(entry.th32ParentProcessID);
                        break;
                    }
                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snapshot);
        }
        parent
    }

    /// The production key path is not exercised by redirected policy tests, so
    /// this guards the one property that could silently break administrators.
    #[cfg(test)]
    mod key_path {
        use super::POLICY_SUBKEY;

        /// Windows refuses to let an ADMX-ingested policy write under these
        /// prefixes (outside a hardcoded allowlist MXC is not on). A key under
        /// one of them cannot be deployed by Intune or any other MDM, so moving
        /// MXC's key back under `Policies\Microsoft` — a natural-looking
        /// "correction" for a Microsoft product — must fail loudly here rather
        /// than at an administrator's next ADMX import.
        #[test]
        fn is_not_under_an_admx_ingestion_blocked_prefix() {
            const BLOCKED_PREFIXES: [&str; 3] = [
                r"SYSTEM\",
                r"SOFTWARE\MICROSOFT\",
                r"SOFTWARE\POLICIES\MICROSOFT\",
            ];

            let upper = POLICY_SUBKEY.to_ascii_uppercase();
            for blocked in BLOCKED_PREFIXES {
                assert!(
                    !upper.starts_with(blocked),
                    "policy key {POLICY_SUBKEY:?} sits under {blocked:?}, which Windows \
                     forbids ADMX-ingested policies from writing; see \
                     docs/telemetry/telemetry-administrative-policy.md"
                );
            }
        }
    }

    #[cfg(test)]
    mod scoped_override {
        use super::scoped_policy_key_override;

        #[test]
        fn accepts_an_explicit_same_process_or_parent_owner() {
            assert_eq!(
                scoped_policy_key_override(
                    Some("Software\\MxcTest".into()),
                    Some("42".into()),
                    42,
                    Some(41),
                ),
                Some("Software\\MxcTest".to_string())
            );
            assert_eq!(
                scoped_policy_key_override(
                    Some("Software\\MxcTest".into()),
                    Some("41".into()),
                    42,
                    Some(41),
                ),
                Some("Software\\MxcTest".to_string())
            );
            assert_eq!(
                scoped_policy_key_override(
                    Some("Software\\MxcTest".into()),
                    Some("40".into()),
                    42,
                    Some(41),
                ),
                None
            );
        }

        #[test]
        fn rejects_an_unowned_or_malformed_override() {
            assert_eq!(
                scoped_policy_key_override(Some("Software\\MxcTest".into()), None, 42, Some(41),),
                None
            );
            assert_eq!(
                scoped_policy_key_override(
                    Some("Software\\MxcTest".into()),
                    Some("not-a-pid".into()),
                    42,
                    Some(41),
                ),
                None
            );
            assert_eq!(
                scoped_policy_key_override(Some("".into()), Some("42".into()), 42, Some(41)),
                None
            );
        }
    }

    #[cfg(test)]
    mod failure_reporter {
        use crate::telemetry::FailureReporter;
        use std::sync::Mutex;

        #[test]
        fn reports_each_distinct_failure_once() {
            let reporter = FailureReporter::default();
            let emitted = Mutex::new(Vec::new());

            for signature in [
                "open: access denied",
                "open: access denied",
                "read: wrong type",
            ] {
                reporter.report(signature.to_string(), |message| {
                    emitted
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .push(message.to_string());
                });
            }

            assert_eq!(
                *emitted.lock().unwrap_or_else(|error| error.into_inner()),
                ["open: access denied", "read: wrong type"]
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Non-Windows stub — nothing is collected here, so nothing is restricted.
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "windows"))]
mod platform {
    use super::PolicyState;

    pub(super) fn read() -> PolicyState {
        PolicyState::NotApplicable
    }
}

// ---------------------------------------------------------------------------
// Test support — policy redirection stays in process and guard construction
// remains serialized to preserve the shared lock order.
// ---------------------------------------------------------------------------

#[cfg(any(test, all(feature = "test-support", debug_assertions)))]
pub mod test_support {
    use std::sync::{Mutex, MutexGuard};

    /// Serializes guard construction and preserves the lock order shared with
    /// the consent test environment.
    pub static POLICY_LOCK: Mutex<()> = Mutex::new(());

    /// Redirects the policy read (Windows only) to a freshly created, unique
    /// `HKCU` subkey for the lifetime of the guard, deleting it and restoring
    /// the previous override on drop.
    ///
    /// Using a real registry key rather than a stubbed value means the tests
    /// exercise the actual `winreg` read path. `HKCU` needs no elevation.
    ///
    /// An inert holder on non-Windows, where policy is `NotApplicable`
    /// regardless — kept as a real guard type so call sites need no `#[cfg]`.
    ///
    /// **Within `wxc_common`, never construct this directly alongside the
    /// consent guard** — use `crate::telemetry::test_support::TelemetryTestEnv`,
    /// which fixes the acquisition order of the two process-global locks.
    pub struct PolicyKeyGuard {
        _lock: MutexGuard<'static, ()>,
        #[cfg(target_os = "windows")]
        subkey: String,
        #[cfg(target_os = "windows")]
        previous_override: Option<String>,
    }

    // `Default` is deliberately not implemented: constructing this guard takes a
    // process-global lock and mutates the environment, which is not what a
    // caller reaching for `Default::default()` expects.
    #[allow(clippy::new_without_default)]
    impl PolicyKeyGuard {
        /// Creates the guard with no policy value set (the unmanaged default).
        #[cfg(target_os = "windows")]
        pub fn new() -> Self {
            use std::sync::atomic::{AtomicU32, Ordering};
            static COUNTER: AtomicU32 = AtomicU32::new(0);

            let lock = POLICY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let subkey = format!(
                r"Software\MxcTelemetryPolicyTest\{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            );
            let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
            // Remove any leftover from a previously crashed run before use.
            let _ = hkcu.delete_subkey_all(&subkey);
            hkcu.create_subkey(&subkey).expect("create test policy key");
            let previous_override = super::DEBUG_POLICY_KEY_OVERRIDE
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .replace(subkey.clone());

            Self {
                _lock: lock,
                subkey,
                previous_override,
            }
        }

        #[cfg(not(target_os = "windows"))]
        pub fn new() -> Self {
            let lock = POLICY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            Self { _lock: lock }
        }

        /// Writes the `AllowTelemetry` policy value into the redirected key.
        #[cfg(target_os = "windows")]
        pub fn set_value(&self, value: u32) {
            let (key, _) = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
                .create_subkey(&self.subkey)
                .expect("open test policy key");
            key.set_value("AllowTelemetry", &value)
                .expect("set test policy value");
        }

        #[cfg(not(target_os = "windows"))]
        pub fn set_value(&self, _value: u32) {}

        /// Writes `AllowTelemetry` as a `REG_SZ` instead of a `REG_DWORD`, to
        /// exercise the wrong-value-type path an administrator can easily hit
        /// by typing the value in by hand.
        #[cfg(target_os = "windows")]
        pub fn set_string_value(&self, value: &str) {
            let (key, _) = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
                .create_subkey(&self.subkey)
                .expect("open test policy key");
            key.set_value("AllowTelemetry", &value.to_string())
                .expect("set test policy string value");
        }

        #[cfg(not(target_os = "windows"))]
        pub fn set_string_value(&self, _value: &str) {}
    }

    #[cfg(target_os = "windows")]
    impl Drop for PolicyKeyGuard {
        fn drop(&mut self) {
            *super::DEBUG_POLICY_KEY_OVERRIDE
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = self.previous_override.take();
            let _ = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
                .delete_subkey_all(&self.subkey);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_strings_are_stable() {
        assert_eq!(PolicyState::Unrestricted.as_str(), "unrestricted");
        assert_eq!(PolicyState::Allowed.as_str(), "allowed");
        assert_eq!(PolicyState::Blocked.as_str(), "blocked");
        assert_eq!(PolicyState::NotApplicable.as_str(), "not-applicable");
    }

    #[test]
    fn only_blocked_denies_collection() {
        assert!(PolicyState::Unrestricted.allows_collection());
        assert!(PolicyState::Allowed.allows_collection());
        assert!(PolicyState::NotApplicable.allows_collection());
        assert!(!PolicyState::Blocked.allows_collection());
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn policy_is_not_applicable_off_windows() {
        assert_eq!(get_policy(), PolicyState::NotApplicable);
        assert!(!is_blocked_by_policy());
    }
}

#[cfg(all(test, target_os = "windows"))]
mod windows_tests {
    use super::test_support::PolicyKeyGuard;
    use super::*;

    #[test]
    fn absent_policy_is_unrestricted() {
        let _guard = PolicyKeyGuard::new();
        assert_eq!(get_policy(), PolicyState::Unrestricted);
        assert!(!is_blocked_by_policy());
    }

    #[test]
    fn optional_level_is_allowed() {
        let guard = PolicyKeyGuard::new();
        guard.set_value(3);
        assert_eq!(get_policy(), PolicyState::Allowed);
        assert!(!is_blocked_by_policy());
    }

    #[test]
    fn off_level_is_blocked() {
        let guard = PolicyKeyGuard::new();
        guard.set_value(0);
        assert_eq!(get_policy(), PolicyState::Blocked);
        assert!(is_blocked_by_policy());
    }

    /// Level 1 is "required diagnostic data only". MXC emits
    /// product-and-service-usage data, which is *optional*, so a
    /// required-only machine must collect nothing.
    #[test]
    fn required_only_level_is_blocked() {
        let guard = PolicyKeyGuard::new();
        guard.set_value(1);
        assert_eq!(get_policy(), PolicyState::Blocked);
    }

    /// Fail closed: a value outside the documented scale is a
    /// misconfiguration, and MXC must not read it as permission.
    #[test]
    fn unrecognized_value_is_blocked() {
        let guard = PolicyKeyGuard::new();
        for value in [2u32, 4, 99, u32::MAX] {
            guard.set_value(value);
            assert_eq!(
                get_policy(),
                PolicyState::Blocked,
                "value {value} must fail closed"
            );
        }
    }

    /// An administrator who sets `AllowTelemetry` as a string rather than a
    /// `REG_DWORD` has still expressed an intent to manage this machine. The
    /// value cannot be evaluated, so it must deny — never be mistaken for an
    /// unmanaged machine, which would let a prior consent grant re-enable
    /// collection the administrator meant to stop.
    #[test]
    fn wrong_value_type_is_blocked_not_unrestricted() {
        let guard = PolicyKeyGuard::new();
        for value in ["0", "3", "", "not-a-number"] {
            guard.set_string_value(value);
            assert_eq!(
                get_policy(),
                PolicyState::Blocked,
                "REG_SZ {value:?} must fail closed, not read as unmanaged"
            );
            assert!(is_blocked_by_policy());
        }
    }

    /// The precise regression this guards: a wrong-typed value must not
    /// resolve to the same state as no policy at all.
    #[test]
    fn wrong_value_type_is_distinguishable_from_absent() {
        let guard = PolicyKeyGuard::new();
        assert_eq!(get_policy(), PolicyState::Unrestricted);
        guard.set_string_value("0");
        assert_ne!(
            get_policy(),
            PolicyState::Unrestricted,
            "a malformed policy must not be indistinguishable from an unmanaged machine"
        );
    }

    #[test]
    fn unreadable_policy_read_fails_closed() {
        let state = crate::telemetry::policy::platform::unreadable_policy_state_for_test();
        assert_eq!(state, PolicyState::Blocked);
        assert!(!state.allows_collection());
    }

    #[test]
    fn only_unrecognized_dword_values_are_reported() {
        for value in [0, 1, 3] {
            let (_, reported) =
                crate::telemetry::policy::platform::policy_value_report_for_test(value);
            assert_eq!(reported, None, "recognized value {value} was reported");
        }

        for value in [2, 4, 99, u32::MAX] {
            let (state, reported) =
                crate::telemetry::policy::platform::policy_value_report_for_test(value);
            assert_eq!(state, PolicyState::Blocked);
            assert_eq!(reported, Some(value));
        }
    }
}
