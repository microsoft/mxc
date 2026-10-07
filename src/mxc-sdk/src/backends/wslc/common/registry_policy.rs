// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Administrative control over which registries a runtime image pull may contact.

use std::fmt;

/// Machine-wide policy key, alongside the telemetry policy. Under
/// `SOFTWARE\Policies`, so only an administrator can write it — a standard user
/// cannot widen the allowlist.
const POLICY_SUBKEY: &str = r"SOFTWARE\Policies\Mxc";

/// `REG_MULTI_SZ` naming the registry hosts a pull may contact.
const POLICY_VALUE_NAME: &str = "WslcAllowedImageRegistries";

/// Registry a bare reference like `alpine:latest` resolves against.
const DEFAULT_REGISTRY: &str = "docker.io";

/// Redirects the policy read for tests; see [`policy_location`].
#[cfg(all(
    target_os = "windows",
    any(test, all(feature = "test-support", debug_assertions))
))]
static DEBUG_POLICY_KEY_OVERRIDE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

#[cfg(all(
    target_os = "windows",
    any(test, all(feature = "test-support", debug_assertions))
))]
const POLICY_KEY_OVERRIDE_ENV: &str = "MXC_TEST_WSLC_POLICY_KEY_OVERRIDE";

#[cfg(all(
    target_os = "windows",
    any(test, all(feature = "test-support", debug_assertions))
))]
const POLICY_KEY_OVERRIDE_OWNER_ENV: &str = "MXC_TEST_WSLC_POLICY_KEY_OVERRIDE_OWNER_PID";

/// What administrative policy permits for runtime pulls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryPolicy {
    /// No policy is configured; any registry may be contacted.
    Unmanaged,
    /// Only these hosts may be contacted.
    Allowed(Vec<String>),
    /// A policy exists but could not be read, so nothing may be contacted.
    ///
    /// An administrator who misconfigured the value gets the block they were
    /// reaching for rather than the open default they were not.
    Unreadable,
}

impl RegistryPolicy {
    /// Whether `image` names a registry this machine may pull from.
    pub fn permits(&self, image: &str) -> bool {
        match self {
            RegistryPolicy::Unmanaged => true,
            RegistryPolicy::Unreadable => false,
            RegistryPolicy::Allowed(hosts) => {
                let host = registry_host(image);
                hosts.iter().any(|h| h.eq_ignore_ascii_case(host))
            }
        }
    }

    /// Why a pull was refused, for the caller's error message.
    pub fn refusal(&self, image: &str) -> String {
        match self {
            RegistryPolicy::Unreadable => format!(
                "WSLC image '{}' cannot be pulled: the administrative registry allowlist \
                 ({}\\{}) exists but could not be read, so no registry is permitted. \
                 Ask an administrator to correct it, or supply the image with \
                 wslc.imageTarPath.",
                image, POLICY_SUBKEY, POLICY_VALUE_NAME
            ),
            _ => format!(
                "WSLC image '{}' cannot be pulled: '{}' is not in the administrative \
                 registry allowlist ({}\\{}). Use a permitted registry, or supply the \
                 image with wslc.imageTarPath.",
                image,
                registry_host(image),
                POLICY_SUBKEY,
                POLICY_VALUE_NAME
            ),
        }
    }
}

impl fmt::Display for RegistryPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryPolicy::Unmanaged => f.write_str("unmanaged"),
            RegistryPolicy::Unreadable => f.write_str("unreadable"),
            RegistryPolicy::Allowed(hosts) => write!(f, "allowed: {}", hosts.join(", ")),
        }
    }
}

/// The registry host `image` resolves against.
///
/// A reference whose first path segment carries a dot, a colon, or is
/// `localhost` names a registry; anything else is a Docker Hub short name.
fn registry_host(image: &str) -> &str {
    match image.split_once('/') {
        Some((head, _)) if head.contains('.') || head.contains(':') || head == "localhost" => head,
        _ => DEFAULT_REGISTRY,
    }
}

/// Read the administrative allowlist.
pub fn get_policy() -> RegistryPolicy {
    platform::read()
}

/// Turn configured host entries into a policy, discarding blanks.
fn parse_hosts(hosts: Vec<String>) -> RegistryPolicy {
    let hosts: Vec<String> = hosts
        .into_iter()
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .collect();

    // An administrator who configured an empty list asked for no registry at
    // all, which is a policy that was read, not one that failed to read.
    RegistryPolicy::Allowed(hosts)
}

#[cfg(target_os = "windows")]
mod platform {
    use super::{parse_hosts, RegistryPolicy, POLICY_SUBKEY, POLICY_VALUE_NAME};
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;

    pub(super) fn read() -> RegistryPolicy {
        let (hive, subkey) = policy_location();
        let key = match RegKey::predef(hive).open_subkey(&subkey) {
            Ok(k) => k,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return RegistryPolicy::Unmanaged,
            Err(_) => return RegistryPolicy::Unreadable,
        };
        match key.get_value::<Vec<String>, _>(POLICY_VALUE_NAME) {
            Ok(hosts) => parse_hosts(hosts),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => RegistryPolicy::Unmanaged,
            Err(_) => RegistryPolicy::Unreadable,
        }
    }

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

    /// Environment bridge for script-driven tests that launch a child binary.
    ///
    /// The owner PID is mandatory so an unpaired ambient key override is
    /// ignored. It may identify this process or the harness that launched it.
    #[cfg(any(test, all(feature = "test-support", debug_assertions)))]
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

        // SAFETY: the snapshot handle is closed below on every path.
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
        /// one of them cannot be deployed by Intune or any other MDM.
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
                    "{POLICY_SUBKEY} is under {blocked}, which no MDM can deploy; see \
                     docs/backends/wslc/wslc-registry-allowlist-policy.md"
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
                    Some(r"Software\MxcTest".into()),
                    Some("42".into()),
                    42,
                    Some(41),
                ),
                Some(r"Software\MxcTest".to_string())
            );
            assert_eq!(
                scoped_policy_key_override(
                    Some(r"Software\MxcTest".into()),
                    Some("41".into()),
                    42,
                    Some(41),
                ),
                Some(r"Software\MxcTest".to_string())
            );
        }

        /// An ambient variable nobody claimed must not redirect the read.
        #[test]
        fn rejects_an_unowned_or_foreign_override() {
            assert_eq!(
                scoped_policy_key_override(Some(r"Software\MxcTest".into()), None, 42, Some(41)),
                None
            );
            assert_eq!(
                scoped_policy_key_override(
                    Some(r"Software\MxcTest".into()),
                    Some("99".into()),
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
}

#[cfg(not(target_os = "windows"))]
mod platform {
    use super::RegistryPolicy;

    pub(super) fn read() -> RegistryPolicy {
        RegistryPolicy::Unmanaged
    }
}

#[cfg(any(test, all(feature = "test-support", debug_assertions)))]
pub mod test_support {
    use std::sync::{Mutex, MutexGuard};

    /// Serializes guard construction, since the redirect is process-global.
    pub static POLICY_LOCK: Mutex<()> = Mutex::new(());

    /// Redirects the policy read to a freshly created, unique `HKCU` subkey for
    /// the lifetime of the guard, deleting it and restoring the previous
    /// override on drop.
    ///
    /// Using a real registry key rather than a stubbed value means the tests
    /// exercise the actual `winreg` read path. `HKCU` needs no elevation.
    pub struct RegistryPolicyKeyGuard {
        _lock: MutexGuard<'static, ()>,
        #[cfg(target_os = "windows")]
        subkey: String,
        #[cfg(target_os = "windows")]
        previous_override: Option<String>,
    }

    // `Default` is deliberately not implemented: constructing this guard takes a
    // process-global lock and mutates the registry.
    #[allow(clippy::new_without_default)]
    impl RegistryPolicyKeyGuard {
        #[cfg(target_os = "windows")]
        pub fn new() -> Self {
            use std::sync::atomic::{AtomicU32, Ordering};
            static COUNTER: AtomicU32 = AtomicU32::new(0);

            let lock = POLICY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let subkey = format!(
                r"Software\MxcWslcRegistryPolicyTest\{}-{}",
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

        /// Writes the allowlist into the redirected key.
        #[cfg(target_os = "windows")]
        pub fn set_hosts(&self, hosts: &[&str]) {
            let (key, _) = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
                .create_subkey(&self.subkey)
                .expect("open test policy key");
            let hosts: Vec<String> = hosts.iter().map(|h| h.to_string()).collect();
            key.set_value(super::POLICY_VALUE_NAME, &hosts)
                .expect("set test allowlist");
        }

        #[cfg(not(target_os = "windows"))]
        pub fn set_hosts(&self, _hosts: &[&str]) {}

        /// Writes the allowlist as a `REG_SZ` instead of a `REG_MULTI_SZ`, the
        /// wrong-type mistake an administrator makes by typing it in by hand.
        #[cfg(target_os = "windows")]
        pub fn set_wrong_value_type(&self, value: &str) {
            let (key, _) = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
                .create_subkey(&self.subkey)
                .expect("open test policy key");
            key.set_value(super::POLICY_VALUE_NAME, &value.to_string())
                .expect("set test allowlist");
        }

        #[cfg(not(target_os = "windows"))]
        pub fn set_wrong_value_type(&self, _value: &str) {}
    }

    #[cfg(target_os = "windows")]
    impl Drop for RegistryPolicyKeyGuard {
        fn drop(&mut self) {
            *super::DEBUG_POLICY_KEY_OVERRIDE
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = self.previous_override.take();
            let _ = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
                .delete_subkey_all(&self.subkey);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An empty list is a policy that was read and permits nothing, so its
    /// refusal must name the allowlist rather than claim a broken deployment.
    #[test]
    fn an_empty_allowlist_denies_without_reporting_a_read_failure() {
        let policy = parse_hosts(vec![String::new(), "  ".to_string()]);
        assert_eq!(policy, RegistryPolicy::Allowed(Vec::new()));
        assert!(!policy.permits("alpine:latest"));
        assert!(
            !policy
                .refusal("alpine:latest")
                .contains("could not be read"),
            "an empty list was read successfully: {}",
            policy.refusal("alpine:latest")
        );
    }

    #[test]
    fn an_unmanaged_machine_permits_any_registry() {
        let policy = RegistryPolicy::Unmanaged;
        assert!(policy.permits("alpine:latest"));
        assert!(policy.permits("ghcr.io/owner/img:1"));
    }

    #[test]
    fn an_unreadable_policy_permits_nothing() {
        // An administrator who misconfigured the value gets the block they were
        // reaching for, not the open default.
        let policy = RegistryPolicy::Unreadable;
        assert!(!policy.permits("alpine:latest"));
        assert!(!policy.permits("ghcr.io/owner/img:1"));
    }

    #[test]
    fn an_allowlist_admits_only_its_own_hosts() {
        let policy = RegistryPolicy::Allowed(vec!["ghcr.io".to_string()]);
        assert!(policy.permits("ghcr.io/owner/img:1"));
        assert!(!policy.permits("quay.io/owner/img:1"));
    }

    #[test]
    fn a_host_is_matched_without_regard_to_case() {
        let policy = RegistryPolicy::Allowed(vec!["GHCR.IO".to_string()]);
        assert!(policy.permits("ghcr.io/owner/img:1"));
    }

    #[test]
    fn a_short_name_resolves_against_docker_hub() {
        assert_eq!(registry_host("alpine:latest"), "docker.io");
        assert_eq!(registry_host("library/alpine"), "docker.io");
        let policy = RegistryPolicy::Allowed(vec!["docker.io".to_string()]);
        assert!(policy.permits("alpine:latest"));
        assert!(policy.permits("library/alpine:3.21"));
    }

    #[test]
    fn a_registry_host_is_read_from_the_first_segment() {
        assert_eq!(registry_host("ghcr.io/owner/img:1"), "ghcr.io");
        assert_eq!(
            registry_host("mcr.microsoft.com/a/b:1"),
            "mcr.microsoft.com"
        );
        assert_eq!(registry_host("localhost:5000/img"), "localhost:5000");
        assert_eq!(registry_host("localhost/img"), "localhost");
    }

    #[test]
    fn an_allowlist_of_blanks_permits_nothing() {
        let policy = parse_hosts(vec!["".to_string(), "  ".to_string()]);
        assert_eq!(policy, RegistryPolicy::Allowed(Vec::new()));
        assert!(!policy.permits("alpine:latest"));
    }

    #[test]
    fn configured_hosts_are_trimmed() {
        assert_eq!(
            parse_hosts(vec!["  ghcr.io  ".to_string(), String::new()]),
            RegistryPolicy::Allowed(vec!["ghcr.io".to_string()])
        );
    }

    #[test]
    fn a_refusal_names_the_host_and_the_policy_value() {
        let policy = RegistryPolicy::Allowed(vec!["ghcr.io".to_string()]);
        let msg = policy.refusal("quay.io/owner/img:1");
        assert!(msg.contains("quay.io"));
        assert!(msg.contains(POLICY_VALUE_NAME));
        assert!(msg.contains("imageTarPath"));
    }
}

#[cfg(all(test, target_os = "windows"))]
mod windows_tests {
    use super::test_support::RegistryPolicyKeyGuard;
    use super::*;

    #[test]
    fn an_absent_policy_leaves_the_machine_unmanaged() {
        let _guard = RegistryPolicyKeyGuard::new();
        assert_eq!(get_policy(), RegistryPolicy::Unmanaged);
    }

    #[test]
    fn a_configured_allowlist_is_read_back() {
        let guard = RegistryPolicyKeyGuard::new();
        guard.set_hosts(&["ghcr.io", "mcr.microsoft.com"]);

        let policy = get_policy();
        assert!(policy.permits("ghcr.io/owner/img:1"));
        assert!(!policy.permits("alpine:latest"));
    }

    /// A value of the wrong type is a policy that cannot be evaluated, so it
    /// must deny rather than fall back to the unmanaged default.
    #[test]
    fn a_wrong_value_type_denies_rather_than_falling_open() {
        let guard = RegistryPolicyKeyGuard::new();
        guard.set_wrong_value_type("ghcr.io");

        let policy = get_policy();
        assert_eq!(policy, RegistryPolicy::Unreadable);
        assert!(!policy.permits("ghcr.io/owner/img:1"));
    }

    /// A list an administrator deliberately emptied is a policy that was read
    /// and permits nothing, not a deployment that failed to read.
    #[test]
    fn an_empty_configured_list_denies_every_registry() {
        let guard = RegistryPolicyKeyGuard::new();
        guard.set_hosts(&[]);

        let policy = get_policy();
        assert!(!policy.permits("alpine:latest"));
        assert!(!policy.permits("ghcr.io/owner/img:1"));
        assert!(
            !policy
                .refusal("alpine:latest")
                .contains("could not be read"),
            "an empty list read back cleanly: {}",
            policy.refusal("alpine:latest")
        );
    }

    /// User state must never widen an administrator's allowlist.
    #[test]
    fn a_user_environment_variable_cannot_widen_the_allowlist() {
        let guard = RegistryPolicyKeyGuard::new();
        guard.set_hosts(&["ghcr.io"]);

        std::env::set_var("MXC_TEST_WSLC_REGISTRY_ALLOWLIST", "docker.io");
        let policy = get_policy();
        std::env::remove_var("MXC_TEST_WSLC_REGISTRY_ALLOWLIST");

        assert!(
            !policy.permits("alpine:latest"),
            "an environment variable must not add docker.io to an administrator's list"
        );
    }
}
