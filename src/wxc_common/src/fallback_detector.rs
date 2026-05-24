// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Fallback tier detector.
//!
//! Pure detection module that, given a parsed [`ContainerPolicy`] and a few
//! runtime probes, produces a [`TierDecision`]. Tiers are described in
//! `docs/proposals/downlevel_support/basecontainer-fallback-plan-v2.md`:
//!
//! 1. **Tier 1 — BaseContainer** (`Experimental_CreateProcessInSandbox`)
//! 2. **Tier 2 — AppContainer + BFS** (`bfscfg.exe`-driven filesystem policy)
//! 3. **Tier 3 — AppContainer + DACL** (host-side DACL ACE augmentation)
//!
//! This module does not log, emit telemetry, or have any side effects. It is
//! intentionally Logger-free so it can be unit-tested in isolation. Phase 4
//! will wire it into the dispatcher in `main.rs`.

use std::path::{Path, PathBuf};

use crate::models::ContainerPolicy;

/// Selected isolation tier. The variant order corresponds to descending
/// security strength.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationTier {
    /// Tier 1 — `Experimental_CreateProcessInSandbox` from `processmodel.dll`.
    BaseContainer,
    /// Tier 2 — AppContainer + `bfscfg.exe` BFS filesystem policy.
    ///
    /// Only selectable when the `bfs` Cargo feature is enabled — see the
    /// feature comment in `wxc_common/Cargo.toml`.
    #[cfg(feature = "bfs")]
    AppContainerBfs,
    /// Tier 3 — AppContainer + DACL-based filesystem policy on host paths.
    AppContainerDacl,
}

impl IsolationTier {
    /// Stable kebab-case identifier for serialization.
    pub fn as_str(self) -> &'static str {
        match self {
            IsolationTier::BaseContainer => "base-container",
            #[cfg(feature = "bfs")]
            IsolationTier::AppContainerBfs => "appcontainer-bfs",
            IsolationTier::AppContainerDacl => "appcontainer-dacl",
        }
    }
}

/// Outcome of [`detect`]: the chosen tier plus any operator-visible warnings
/// gathered while walking the decision algorithm.
#[derive(Debug, Clone)]
pub struct TierDecision {
    /// The selected isolation tier.
    pub tier: IsolationTier,
    /// `true` if this tier needs DACL augmentation on host paths to enforce
    /// the policy. T3 always sets this; T1/T2 set it when `denied_paths` is
    /// non-empty (since neither BaseContainer nor BFS currently models a
    /// "deny" semantic and we have to fall back to host DACLs for those).
    pub needs_dacl_augmentation: bool,
    /// Absolute path to `bfscfg.exe` as resolved at probe time.
    ///
    /// Populated only when [`IsolationTier::AppContainerBfs`] is selected.
    /// Callers MUST pass this exact path to [`crate::filesystem_bfs`] so
    /// that probe and execution agree on the binary — preventing
    /// executable-search-order hijacking by an attacker who can plant a
    /// rogue `bfscfg.exe` next to `wxc-exec.exe`, in the CWD, or in a
    /// `PATH` entry that precedes `System32`.
    #[cfg(feature = "bfs")]
    pub bfscfg_path: Option<PathBuf>,
    /// Human-readable degradation messages explaining why a higher tier was
    /// rejected. Empty when the preferred tier was selected.
    pub warnings: Vec<String>,
}

/// Errors that abort tier selection.
#[derive(Debug, thiserror::Error)]
pub enum FallbackError {
    /// The chosen tier needs to modify host DACLs but the caller set
    /// `fallback.allow_dacl_mutation = false`.
    #[error("DACL fallback required but fallback.allowDaclMutation is false")]
    DaclFallbackDisabled,

    /// The current process lacks `WRITE_DAC` on a path that needs ACE
    /// augmentation (or the path could not be opened at all).
    #[error("WRITE_DAC unavailable on path {path}: {reason}")]
    WriteDacUnavailable {
        /// The path that failed the probe.
        path: PathBuf,
        /// The OS-level reason (typically a Win32 error description).
        reason: String,
    },

    /// Neither the `GetWindowsDirectoryW` Win32 API call nor (in debug
    /// builds) the `MXC_BFSCFG_PATH` override could identify a usable
    /// Windows installation directory. We refuse to fall back to a
    /// hardcoded `C:\Windows` guess because doing so would allow an
    /// attacker who can scrub the process environment to silently
    /// downgrade Tier 2 → Tier 3 on hosts where Windows lives elsewhere.
    #[cfg(feature = "bfs")]
    #[error("could not resolve %SystemRoot%: {reason}")]
    SystemRootUnresolved {
        /// Human-readable description of why resolution failed.
        reason: String,
    },
}

/// Decide which isolation tier to use for a run.
///
/// The algorithm matches the design doc:
///
/// 1. If `MXC_FORCE_TIER` is set in a test build, honor it (test seam).
/// 2. Try Tier 1 (BaseContainer) when `prefer_base_container` is true and the
///    API surface is detected.
/// 3. Otherwise try Tier 2 (AppContainer + BFS) when there's no filesystem
///    policy at all, or `bfscfg.exe` is on disk.
/// 4. Otherwise fall back to Tier 3 (AppContainer + DACL).
///
/// Any tier that needs to modify host DACLs (T3 always; T1/T2 when
/// `denied_paths` is non-empty) requires `fallback.allow_dacl_mutation = true`
/// and `WRITE_DAC` on every target path. If either check fails the function
/// returns the corresponding [`FallbackError`].
///
/// Probing for Tier 2 resolves `%SystemRoot%` exclusively via the
/// `GetWindowsDirectoryW` Win32 API — the `SystemRoot` environment
/// variable is deliberately ignored to deny attackers an
/// environment-driven Tier 2 → Tier 3 downgrade primitive. Callers can
/// receive [`FallbackError::SystemRootUnresolved`] when the OS API itself
/// fails, which on a healthy Windows host should never happen.
pub fn detect(
    policy: &ContainerPolicy,
    prefer_base_container: bool,
) -> Result<TierDecision, FallbackError> {
    let denied = !policy.denied_paths.is_empty();
    let has_fs_policy =
        !policy.readwrite_paths.is_empty() || !policy.readonly_paths.is_empty() || denied;

    // Test-only injection seam. An invalid value is silently ignored and we
    // proceed with the real probe chain — that lets tests assert
    // pass-through behavior without any error plumbing.
    //
    // Gate is `cfg(test)`, not `cfg(debug_assertions)`: production
    // `wxc-exec.exe` builds (release *and* dev binaries) must not honor
    // `MXC_FORCE_TIER` from the environment. `cfg(test)` ensures the
    // seam is compiled in only when the crate is built as a test binary
    // — which is exactly the case for unit tests under any profile,
    // including CI's `cargo test --profile release` invocation. The
    // dispatcher/fallback unit tests in this crate's `mod tests` thus
    // actually exercise tier selection under release-profile CI runs
    // (previously the seam was elided by `cfg(debug_assertions)` and
    // the tests silently no-op'd).
    #[cfg(test)]
    if let Ok(forced) = std::env::var("MXC_FORCE_TIER") {
        if let Some(tier) = parse_force_tier(&forced) {
            return forced_decision(tier, policy, denied);
        }
    }

    let mut warnings: Vec<String> = Vec::new();

    // Tier 1 — BaseContainer
    if prefer_base_container && is_base_container_api_present() {
        if denied {
            ensure_dacl_augmentation_allowed(policy)?;
            verify_write_dac_all(&policy.denied_paths)?;
        }
        return Ok(TierDecision {
            tier: IsolationTier::BaseContainer,
            needs_dacl_augmentation: denied,
            #[cfg(feature = "bfs")]
            bfscfg_path: None,
            warnings,
        });
    }
    #[cfg(feature = "bfs")]
    warnings.push(
        "BaseContainer API not present or not preferred; falling back to AppContainer + BFS"
            .to_string(),
    );
    #[cfg(not(feature = "bfs"))]
    warnings.push(
        "BaseContainer API not present or not preferred; falling back to AppContainer + DACL \
         (BFS support is disabled at build time)"
            .to_string(),
    );

    // Tier 2 — AppContainer + BFS
    //
    // When the policy has no filesystem rules at all there is nothing for
    // BFS to enforce, so we can stay on T2 without resolving bfscfg.exe.
    // Otherwise we need a real path: probe-time resolution doubles as the
    // execution path (see `TierDecision::bfscfg_path`).
    //
    // Compiled out unless the `bfs` Cargo feature is enabled — see the
    // feature comment in `wxc_common/Cargo.toml`.
    #[cfg(feature = "bfs")]
    {
        let bfscfg_path = if has_fs_policy {
            find_bfscfg_exe()?
        } else {
            None
        };
        if !has_fs_policy || bfscfg_path.is_some() {
            if denied {
                ensure_dacl_augmentation_allowed(policy)?;
                verify_write_dac_all(&policy.denied_paths)?;
            }
            return Ok(TierDecision {
                tier: IsolationTier::AppContainerBfs,
                needs_dacl_augmentation: denied,
                bfscfg_path,
                warnings,
            });
        }
        warnings.push("bfscfg.exe not present; falling back to AppContainer + DACL".to_string());
    }

    // Tier 3 — AppContainer + DACL
    //
    // When the policy declares no filesystem paths there is nothing to
    // augment, so we skip the DACL-consent / WRITE_DAC checks entirely.
    // This preserves the historical behavior of the Tier 2 path for
    // empty policies: a caller that set `allow_dacl_mutation = false`
    // should still get a working AppContainer when they ask for no
    // filesystem enforcement.
    if has_fs_policy {
        ensure_dacl_augmentation_allowed(policy)?;
        verify_write_dac_all(
            policy
                .readwrite_paths
                .iter()
                .chain(policy.readonly_paths.iter())
                .chain(policy.denied_paths.iter()),
        )?;
    }
    Ok(TierDecision {
        tier: IsolationTier::AppContainerDacl,
        needs_dacl_augmentation: has_fs_policy,
        #[cfg(feature = "bfs")]
        bfscfg_path: None,
        warnings,
    })
}

fn ensure_dacl_augmentation_allowed(policy: &ContainerPolicy) -> Result<(), FallbackError> {
    if policy.fallback.allow_dacl_mutation {
        Ok(())
    } else {
        Err(FallbackError::DaclFallbackDisabled)
    }
}

fn verify_write_dac_all<P: AsRef<Path>>(
    paths: impl IntoIterator<Item = P>,
) -> Result<(), FallbackError> {
    for p in paths {
        check_write_dac_path(p.as_ref())?;
    }
    Ok(())
}

fn check_write_dac_path(path: &Path) -> Result<(), FallbackError> {
    match has_write_dac(path) {
        Ok(true) => Ok(()),
        Ok(false) => Err(FallbackError::WriteDacUnavailable {
            path: path.to_path_buf(),
            reason: "ERROR_ACCESS_DENIED (WRITE_DAC not granted)".to_string(),
        }),
        Err(e) => Err(FallbackError::WriteDacUnavailable {
            path: path.to_path_buf(),
            reason: e.to_string(),
        }),
    }
}

#[cfg(test)]
fn parse_force_tier(s: &str) -> Option<IsolationTier> {
    match s {
        "base-container" => Some(IsolationTier::BaseContainer),
        #[cfg(feature = "bfs")]
        "appcontainer-bfs" => Some(IsolationTier::AppContainerBfs),
        "appcontainer-dacl" => Some(IsolationTier::AppContainerDacl),
        _ => None,
    }
}

#[cfg(test)]
fn forced_decision(
    tier: IsolationTier,
    policy: &ContainerPolicy,
    denied: bool,
) -> Result<TierDecision, FallbackError> {
    // Forced tiers honor the same DACL-fallback guard the real algorithm
    // does: if the operator forbade host DACL changes we must still refuse
    // any tier that would touch them.
    //
    // For `AppContainerDacl` specifically, we mirror the empty-policy
    // carve-out in `detect()` (see the Tier 3 block): when the policy
    // declares no filesystem paths there is nothing to augment, so we
    // do not require DACL mutation consent. This keeps the
    // `MXC_FORCE_TIER` test seam faithful to the real algorithm — a
    // caller forcing Tier 3 with an empty policy should not be
    // rejected just because `allow_dacl_mutation = false`.
    let has_fs_policy = !policy.readwrite_paths.is_empty()
        || !policy.readonly_paths.is_empty()
        || !policy.denied_paths.is_empty();
    let needs_dacl = match tier {
        IsolationTier::AppContainerDacl => has_fs_policy,
        #[cfg(feature = "bfs")]
        IsolationTier::BaseContainer | IsolationTier::AppContainerBfs => denied,
        #[cfg(not(feature = "bfs"))]
        IsolationTier::BaseContainer => denied,
    };
    if needs_dacl && !policy.fallback.allow_dacl_mutation {
        return Err(FallbackError::DaclFallbackDisabled);
    }
    Ok(TierDecision {
        tier,
        needs_dacl_augmentation: needs_dacl,
        #[cfg(feature = "bfs")]
        bfscfg_path: None,
        warnings: Vec::new(),
    })
}

// ---------------------------------------------------------------------------
// Probes
// ---------------------------------------------------------------------------

/// Returns `true` when `processmodel.dll!Experimental_CreateProcessInSandbox`
/// can be resolved — i.e. the BaseContainer (Tier 1) API is present on this
/// machine.
pub(crate) fn is_base_container_api_present() -> bool {
    crate::base_container_runner::BaseContainerRunner::is_base_container_api_present().is_ok()
}

/// Returns `Ok(Some(path))` when `bfscfg.exe` is present, where `path`
/// is the **absolute** path the caller MUST pass to
/// `CreateProcessW`'s `lpApplicationName` (or as a quoted absolute
/// argv[0]) so probe and execution agree on which binary they're
/// talking about.
///
/// Resolution policy:
///
/// - **Release builds** consult `GetWindowsDirectoryW` exclusively. The
///   `SystemRoot` environment variable is deliberately ignored to deny
///   an attacker who can scrub or rewrite the process environment a
///   Tier 2 → Tier 3 downgrade primitive.
/// - **Test builds** additionally honor `MXC_BFSCFG_PATH` as a narrow
///   test seam. Its value is used verbatim as the resolved path; an
///   empty value simulates "not present" by returning `Ok(None)`.
///   Production `wxc-exec.exe` (both release and dev binaries) cannot
///   read this variable at all — the seam is gated by `cfg(test)` so
///   it compiles in only when building this crate's test binary,
///   regardless of profile (so CI's `--profile release` test run
///   exercises these paths).
/// - We deliberately do not look in `SysWOW64`: `bfscfg.exe` is shipped
///   only in the native System32 directory.
///
/// Returns `Err(FallbackError::SystemRootUnresolved)` only when the
/// Win32 API itself fails — on a healthy Windows host this should never
/// happen.
///
/// Compiled out unless the `bfs` Cargo feature is enabled — see the
/// feature comment in `wxc_common/Cargo.toml`.
#[cfg(feature = "bfs")]
pub fn find_bfscfg_exe() -> Result<Option<PathBuf>, FallbackError> {
    #[cfg(test)]
    if let Ok(override_path) = std::env::var("MXC_BFSCFG_PATH") {
        if override_path.is_empty() {
            return Ok(None);
        }
        let p = PathBuf::from(override_path);
        return Ok(if p.exists() { Some(p) } else { None });
    }

    let mut p = resolve_windows_directory()?;
    p.push("System32");
    p.push(crate::filesystem_bfs::BFSCFG_EXE);
    Ok(if p.exists() { Some(p) } else { None })
}

/// Resolve the Windows install directory via `GetWindowsDirectoryW`.
///
/// The OS populates the answer from boot configuration; it does not
/// consult the process environment. Returns
/// [`FallbackError::SystemRootUnresolved`] when the API itself fails.
#[cfg(feature = "bfs")]
fn resolve_windows_directory() -> Result<PathBuf, FallbackError> {
    use windows::Win32::System::SystemInformation::GetWindowsDirectoryW;

    // The Windows directory path is always short in practice (e.g.
    // `C:\Windows`), but we size for MAX_PATH and grow once if the OS
    // asks for more.
    let mut buf = vec![0u16; 260];
    // SAFETY: `buf` is a contiguous, writable slice of `u16`. The slice
    // length is passed to the API via the `Option<&mut [u16]>` adapter,
    // so out-of-bounds writes are impossible.
    let len = unsafe { GetWindowsDirectoryW(Some(&mut buf)) } as usize;
    if len == 0 {
        return Err(FallbackError::SystemRootUnresolved {
            reason: "GetWindowsDirectoryW returned 0".to_string(),
        });
    }
    if len > buf.len() {
        buf.resize(len, 0);
        // SAFETY: same justification as above; `buf` has been resized to
        // the length the API requested.
        let len2 = unsafe { GetWindowsDirectoryW(Some(&mut buf)) } as usize;
        if len2 == 0 || len2 >= buf.len() {
            return Err(FallbackError::SystemRootUnresolved {
                reason: format!(
                    "GetWindowsDirectoryW retry failed (returned {len2}, buffer {})",
                    buf.len()
                ),
            });
        }
        return parse_utf16(&buf[..len2]);
    }
    parse_utf16(&buf[..len])
}

#[cfg(feature = "bfs")]
fn parse_utf16(slice: &[u16]) -> Result<PathBuf, FallbackError> {
    String::from_utf16(slice)
        .map(PathBuf::from)
        .map_err(|e| FallbackError::SystemRootUnresolved {
            reason: format!("invalid UTF-16 from GetWindowsDirectoryW: {e}"),
        })
}

// TODO(security follow-up): audit other native-binary lookups for
// executable/DLL search-order hijacking. In particular,
// `BaseContainerRunner::is_base_container_api_present` performs a
// `LoadLibrary` on `processmodel.dll`; verify it uses
// `LOAD_LIBRARY_SEARCH_SYSTEM32` (or an absolute path) so an attacker
// who can plant `processmodel.dll` next to `wxc-exec.exe`, in the CWD,
// or in `PATH` cannot impersonate the Tier 1 API surface. Tracked
// separately from this commit.

/// Returns `Ok(true)` if the current process holds (or can be granted)
/// `WRITE_DAC` on `path`, `Ok(false)` if the OS reported access denied, and
/// an `Err` for any other failure (e.g. the path does not exist).
pub(crate) fn has_write_dac(path: &Path) -> Result<bool, std::io::Error> {
    use windows::Win32::Foundation::{CloseHandle, ERROR_ACCESS_DENIED};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows_core::PCWSTR;

    const WRITE_DAC: u32 = 0x0004_0000;

    let path_str = path
        .to_str()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "non-UTF-8 path"))?;
    let wide = crate::string_util::to_wide(path_str);

    // SAFETY: `wide` lives for the duration of the call and is null-
    // terminated by `to_wide`. CreateFileW is documented to accept directory
    // handles when `FILE_FLAG_BACKUP_SEMANTICS` is set.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    };

    match handle {
        Ok(h) => {
            // SAFETY: `h` is a valid handle returned by CreateFileW.
            unsafe {
                let _ = CloseHandle(h);
            }
            Ok(true)
        }
        Err(e) => {
            if e.code() == ERROR_ACCESS_DENIED.to_hresult() {
                Ok(false)
            } else {
                // Only HRESULTs in FACILITY_WIN32 (0x8007xxxx) have a Win32
                // error code embedded in the low 16 bits. For any other
                // facility, the masked value is not a valid Win32 error and
                // would surface as a misleading `io::Error`.
                let hr = e.code().0 as u32;
                if (hr & 0xFFFF_0000) == 0x8007_0000 {
                    Err(std::io::Error::from_raw_os_error((hr & 0xFFFF) as i32))
                } else {
                    Err(std::io::Error::other(e.to_string()))
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ContainerPolicy;
    // Shared ENV_LOCK + guards live in `crate::test_env` so they're
    // honored uniformly across the dispatcher and fallback_detector
    // test modules. A per-module lock would let cross-module test
    // threads race on `MXC_FORCE_TIER` / `MXC_BFSCFG_PATH`.
    use crate::test_env::ForceTierGuard;
    #[cfg(feature = "bfs")]
    use crate::test_env::{BfscfgPathGuard, ENV_LOCK};

    fn empty_policy() -> ContainerPolicy {
        ContainerPolicy::default()
    }
    fn policy_with_denied() -> ContainerPolicy {
        let mut p = ContainerPolicy::default();
        p.denied_paths.push("C:\\Windows".to_string());
        p
    }
    #[test]
    fn empty_policy_t1_when_bc_present_and_preferred() {
        let _g = ForceTierGuard::set("base-container");
        let policy = empty_policy();
        let d = detect(&policy, true).expect("forced base-container should succeed");
        assert!(matches!(d.tier, IsolationTier::BaseContainer));
        assert!(!d.needs_dacl_augmentation);
        assert!(d.warnings.is_empty());
    }
    #[cfg(feature = "bfs")]
    #[test]
    fn empty_policy_no_filesystem_t2_path() {
        let _g = ForceTierGuard::set("appcontainer-bfs");
        let policy = empty_policy();
        let d = detect(&policy, true).expect("forced bfs should succeed");
        assert!(matches!(d.tier, IsolationTier::AppContainerBfs));
        assert!(!d.needs_dacl_augmentation);
    }
    #[test]
    fn denied_paths_disabled_blocks_t1() {
        let _g = ForceTierGuard::set("base-container");
        let mut policy = policy_with_denied();
        policy.fallback.allow_dacl_mutation = false;
        assert!(matches!(
            detect(&policy, true),
            Err(FallbackError::DaclFallbackDisabled)
        ));
    }
    #[cfg(feature = "bfs")]
    #[test]
    fn denied_paths_disabled_blocks_t2() {
        let _g = ForceTierGuard::set("appcontainer-bfs");
        let mut policy = policy_with_denied();
        policy.fallback.allow_dacl_mutation = false;
        assert!(matches!(
            detect(&policy, true),
            Err(FallbackError::DaclFallbackDisabled)
        ));
    }
    #[test]
    fn denied_paths_disabled_blocks_t3() {
        let _g = ForceTierGuard::set("appcontainer-dacl");
        let mut policy = policy_with_denied();
        policy.fallback.allow_dacl_mutation = false;
        assert!(matches!(
            detect(&policy, true),
            Err(FallbackError::DaclFallbackDisabled)
        ));
    }

    /// Mirrors the empty-policy carve-out in `detect()` for the forced
    /// `AppContainerDacl` path: when the policy declares no filesystem
    /// paths there is nothing to augment, so the DACL-fallback guard
    /// must not fire even with `allow_dacl_mutation = false`.
    #[test]
    fn forced_appcontainer_dacl_with_empty_policy_does_not_require_dacl_mutation() {
        let _g = ForceTierGuard::set("appcontainer-dacl");
        let mut policy = empty_policy();
        policy.fallback.allow_dacl_mutation = false;
        let d = detect(&policy, true)
            .expect("empty policy must not require DACL mutation under forced T3");
        assert_eq!(d.tier, IsolationTier::AppContainerDacl);
        assert!(!d.needs_dacl_augmentation);
    }

    #[test]
    fn force_tier_env_var_parses_all_three_values() {
        assert!(matches!(
            parse_force_tier("base-container"),
            Some(IsolationTier::BaseContainer)
        ));
        #[cfg(feature = "bfs")]
        assert!(matches!(
            parse_force_tier("appcontainer-bfs"),
            Some(IsolationTier::AppContainerBfs)
        ));
        #[cfg(not(feature = "bfs"))]
        assert!(
            parse_force_tier("appcontainer-bfs").is_none(),
            "`appcontainer-bfs` must not parse when the `bfs` feature is disabled"
        );
        assert!(matches!(
            parse_force_tier("appcontainer-dacl"),
            Some(IsolationTier::AppContainerDacl)
        ));
    }
    #[test]
    fn force_tier_env_var_invalid_value_falls_through_to_real_probes() {
        // An unrecognized value must NOT raise an error. The detector should
        // ignore it and run the real probe chain. Empty filesystem policy
        // means the probe chain succeeds regardless of which tier the host
        // can satisfy. We assert only the contract — `Ok(_)` — because the
        // resulting tier depends on host state (BC API presence, bfscfg
        // presence) and any tier-specific check here would be coincidental.
        let _g = ForceTierGuard::set("not-a-real-tier");
        let policy = empty_policy();
        detect(&policy, false).expect("invalid value should not error");
    }

    #[cfg(feature = "bfs")]
    #[test]
    fn find_bfscfg_exe_smoke() {
        // Tests run in parallel by default and other tests below mutate
        // `MXC_BFSCFG_PATH`. We must therefore observe the unset state
        // under `ENV_LOCK` so we don't race them.
        let _lock = {
            let lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            // SAFETY: env-var mutation in tests; serialized by ENV_LOCK.
            unsafe {
                std::env::remove_var("MXC_BFSCFG_PATH");
            }
            lock
        };
        let result = find_bfscfg_exe().expect("GetWindowsDirectoryW must succeed on Windows");
        if let Some(path) = result {
            assert!(
                path.is_absolute(),
                "find_bfscfg_exe must return an absolute path, got {path:?}"
            );
            assert!(
                path.ends_with("bfscfg.exe"),
                "resolved path {path:?} should end with bfscfg.exe"
            );
        }
    }

    #[cfg(feature = "bfs")]
    #[test]
    fn resolve_windows_directory_returns_existing_dir() {
        // `GetWindowsDirectoryW` always succeeds on any real Windows
        // host. We assert the returned path exists; absent that we have
        // bigger problems than this test can diagnose.
        let resolved = resolve_windows_directory()
            .expect("GetWindowsDirectoryW must succeed on a Windows test host");
        assert!(
            resolved.is_dir(),
            "resolved Windows directory {resolved:?} should be an existing directory"
        );
    }

    #[cfg(feature = "bfs")]
    #[test]
    fn mxc_bfscfg_path_empty_value_simulates_missing() {
        let _g = BfscfgPathGuard::set("");
        let result = find_bfscfg_exe().expect("empty override must succeed");
        assert!(
            result.is_none(),
            "empty MXC_BFSCFG_PATH must yield Ok(None), got {result:?}"
        );
    }
    #[cfg(feature = "bfs")]
    #[test]
    fn mxc_bfscfg_path_nonexistent_path_is_none() {
        let _g = BfscfgPathGuard::set("C:\\__mxc_does_not_exist__\\bfscfg.exe");
        let result = find_bfscfg_exe().expect("non-existent override must succeed");
        assert!(
            result.is_none(),
            "non-existent MXC_BFSCFG_PATH must yield Ok(None), got {result:?}"
        );
    }
    #[cfg(feature = "bfs")]
    #[test]
    fn mxc_bfscfg_path_existing_path_is_returned_verbatim() {
        // Use a file we know exists (this source file itself, via the
        // standard CARGO_MANIFEST_DIR mechanism is not portable here, so
        // pin to `cmd.exe` which is always present on Windows).
        let cmd_exe = PathBuf::from("C:\\Windows\\System32\\cmd.exe");
        if !cmd_exe.exists() {
            // Highly unusual; skip silently rather than fail.
            return;
        }
        let _g = BfscfgPathGuard::set(cmd_exe.to_str().unwrap());
        let result = find_bfscfg_exe().expect("existing override must succeed");
        assert_eq!(
            result.as_deref(),
            Some(cmd_exe.as_path()),
            "MXC_BFSCFG_PATH must be returned verbatim when it exists"
        );
    }

    #[test]
    fn base_container_api_probe_smoke() {
        let _ = is_base_container_api_present();
    }

    #[test]
    fn has_write_dac_on_temp_dir() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let ok = has_write_dac(dir.path()).expect("temp dir should be openable");
        assert!(ok, "expected WRITE_DAC on freshly-created temp dir");
    }

    #[test]
    fn has_write_dac_on_nonexistent_path() {
        let bogus = Path::new("C:\\__mxc_definitely_does_not_exist__\\nope.txt");
        let res = has_write_dac(bogus);
        assert!(
            res.is_err(),
            "expected error for non-existent path, got {res:?}"
        );
    }
    #[test]
    fn compute_decision_with_force_tier_carries_warnings_empty() {
        let _g = ForceTierGuard::set("appcontainer-dacl");
        let mut policy = empty_policy();
        policy.fallback.allow_dacl_mutation = true;
        let d = detect(&policy, true).expect("forced dacl with allow_dacl_mutation=true");
        assert!(matches!(d.tier, IsolationTier::AppContainerDacl));
        // Empty policy ⇒ no DACL augmentation required, matching the
        // empty-policy carve-out in `detect()`'s Tier 3 block. See
        // `forced_appcontainer_dacl_with_empty_policy_does_not_require_dacl_mutation`
        // for the dedicated regression test.
        assert!(!d.needs_dacl_augmentation);
        assert!(
            d.warnings.is_empty(),
            "forced decisions should not accumulate fallback-chain warnings"
        );
    }
}
