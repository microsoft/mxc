// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Fallback tier detector.
//!
//! Pure detection module that, given a parsed [`ContainerPolicy`] and a few
//! runtime probes, produces a [`TierDecision`]. Tiers are described in
//! `docs/proposals/downlevel_support/basecontainer-fallback-plan-v2.md`:
//!
//! 1. **Tier 1 — BaseContainer** (`Experimental_CreateProcessInSandbox`)
//! 2. **Tier 3 — AppContainer + DACL** (host-side DACL ACE augmentation)
//!
//! The intermediate Tier 2 (AppContainer + BFS via `bfscfg.exe`) used to
//! sit between these two but has been removed: known kernel-mode hangs
//! in `bfs.sys` / `bfsapi.dll` made the BFS path unsafe on most hosts.
//! Without a fixed broker we collapse straight from Tier 1 to Tier 3.
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
    /// Tier 3 — AppContainer + DACL-based filesystem policy on host paths.
    AppContainerDacl,
}

impl IsolationTier {
    /// Stable kebab-case identifier for serialization.
    pub fn as_str(self) -> &'static str {
        match self {
            IsolationTier::BaseContainer => "base-container",
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
    /// the policy. T3 always sets this when there is any filesystem policy
    /// to enforce; T1 sets it when `denied_paths` is non-empty (since
    /// BaseContainer does not model a "deny" semantic and we have to fall
    /// back to host DACLs for those).
    pub needs_dacl_augmentation: bool,
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
}

/// Decide which isolation tier to use for a run.
///
/// The algorithm matches the design doc:
///
/// 1. If `MXC_FORCE_TIER` is set in a test build, honor it (test seam).
/// 2. Try Tier 1 (BaseContainer) when `prefer_base_container` is true and the
///    API surface is detected.
/// 3. Otherwise fall back to Tier 3 (AppContainer + DACL).
///
/// Tier 2 (AppContainer + BFS, driven by `bfscfg.exe`) used to sit between
/// these two steps; it was removed because the underlying broker has
/// known kernel-mode hangs that can wedge the host.
///
/// Any tier that needs to modify host DACLs (T3 whenever there is any
/// filesystem policy to enforce; T1 when `denied_paths` is non-empty)
/// requires `fallback.allow_dacl_mutation = true` and `WRITE_DAC` on every
/// target path. If either check fails the function returns the
/// corresponding [`FallbackError`].
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
            warnings,
        });
    }
    warnings.push(
        "BaseContainer API not present or not preferred; falling back to AppContainer + DACL"
            .to_string(),
    );

    // Tier 3 — AppContainer + DACL
    //
    // When the policy declares no filesystem paths there is nothing to
    // augment, so we skip the DACL-consent / WRITE_DAC checks entirely:
    // a caller that set `allow_dacl_mutation = false` should still get a
    // working AppContainer when they ask for no filesystem enforcement.
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
    let needs_dacl = match tier {
        IsolationTier::AppContainerDacl => true,
        IsolationTier::BaseContainer => denied,
    };
    if needs_dacl && !policy.fallback.allow_dacl_mutation {
        return Err(FallbackError::DaclFallbackDisabled);
    }
    Ok(TierDecision {
        tier,
        needs_dacl_augmentation: needs_dacl,
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
    // threads race on `MXC_FORCE_TIER`.
    use crate::test_env::ForceTierGuard;

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
    #[test]
    fn force_tier_env_var_parses_known_values() {
        assert!(matches!(
            parse_force_tier("base-container"),
            Some(IsolationTier::BaseContainer)
        ));
        assert!(matches!(
            parse_force_tier("appcontainer-dacl"),
            Some(IsolationTier::AppContainerDacl)
        ));
        // `appcontainer-bfs` was retired along with the rest of the BFS
        // integration; make sure it no longer parses to any tier.
        assert!(
            parse_force_tier("appcontainer-bfs").is_none(),
            "`appcontainer-bfs` must no longer parse to a tier"
        );
    }
    #[test]
    fn force_tier_env_var_invalid_value_falls_through_to_real_probes() {
        // An unrecognized value must NOT raise an error. The detector should
        // ignore it and run the real probe chain. Empty filesystem policy
        // means the probe chain succeeds regardless of which tier the host
        // can satisfy. We assert only the contract — `Ok(_)` — because the
        // resulting tier depends on host state (BC API presence) and any
        // tier-specific check here would be coincidental.
        let _g = ForceTierGuard::set("not-a-real-tier");
        let policy = empty_policy();
        detect(&policy, false).expect("invalid value should not error");
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
        assert!(d.needs_dacl_augmentation);
        assert!(
            d.warnings.is_empty(),
            "forced decisions should not accumulate fallback-chain warnings"
        );
    }
}
