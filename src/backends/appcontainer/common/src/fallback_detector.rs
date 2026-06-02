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

use wxc_common::models::ContainerPolicy;

/// Selected isolation tier. The variant order corresponds to descending
/// security strength.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationTier {
    /// Tier 1 — `Experimental_CreateProcessInSandbox` from `processmodel.dll`.
    BaseContainer,
    /// Tier 2 — AppContainer + `bfscfg.exe` BFS filesystem policy.
    AppContainerBfs,
    /// Tier 3 — AppContainer + DACL-based filesystem policy on host paths.
    AppContainerDacl,
}

impl IsolationTier {
    /// Stable kebab-case identifier for serialization.
    pub fn as_str(self) -> &'static str {
        match self {
            IsolationTier::BaseContainer => "base-container",
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
    /// the policy. T3 always sets this; T2 sets it when `denied_paths` is
    /// non-empty (BFS models no "deny" semantic, so deny falls back to host
    /// DACLs). T1 (BaseContainer) never sets it: it enforces deny natively
    /// via the SandboxSpec `fs_deny` field, and is only selected for a
    /// denied-paths policy when the OS gate (`Feature_BfsPolicyDeny`) is
    /// enabled — otherwise selection falls through to T2/T3.
    pub needs_dacl_augmentation: bool,
    /// Absolute path to `bfscfg.exe` as resolved at probe time.
    ///
    /// Populated only when [`IsolationTier::AppContainerBfs`] is selected.
    /// Callers MUST pass this exact path to [`crate::filesystem_bfs`] so
    /// that probe and execution agree on the binary — preventing
    /// executable-search-order hijacking by an attacker who can plant a
    /// rogue `bfscfg.exe` next to `wxc-exec.exe`, in the CWD, or in a
    /// `PATH` entry that precedes `System32`.
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
/// 3. Otherwise try Tier 2 (AppContainer + BFS), but **only when this binary
///    was compiled with the `tier2_bfs` Cargo feature**. With the feature on,
///    Tier 2 is selected when there's no filesystem policy at all, or
///    `bfscfg.exe` is on disk. With the feature off, `bfscfg.exe` can never be
///    resolved, so Tier 2 is skipped entirely (rather than mis-reporting
///    `appcontainer-bfs` for the no-policy case) and we fall through to Tier 3.
/// 4. Otherwise fall back to Tier 3 (AppContainer + DACL). When Tier 3 is
///    selected we append `wxc-host-prep` recommendations to the decision's
///    warnings for any host-side preparation (system-drive metadata ACEs;
///    `\Device\Null` descriptor) that is read-only-detected as not already in
///    effect on this machine.
///
/// Any tier that needs to modify host DACLs (T3 always; T2 when
/// `denied_paths` is non-empty) requires `fallback.allow_dacl_mutation = true`
/// and `WRITE_DAC` on every target path. If either check fails the function
/// returns the corresponding [`FallbackError`].
///
/// Tier 1 (BaseContainer) enforces `denied_paths` natively via the SandboxSpec
/// `fs_deny` field rather than host DACLs, but the OS only honors that field
/// when the `Feature_BfsPolicyDeny` feature is enabled in the runtime
/// feature-configuration store. The OS *build number* is not a sound signal —
/// the enabling change ships per-branch independently of build label — so
/// Tier 1 is selected for a denied-paths policy only when
/// [`native_fs_deny_supported`] confirms the feature is enabled; otherwise
/// selection falls through to a DACL-enforcing tier (fail secure).
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
        // BaseContainer enforces denied paths natively through the SandboxSpec
        // `fs_deny` field — the dispatcher attaches no host DACL at T1 (the
        // sandbox principal is opaque, so a host ACE would be inert). The OS
        // only honors `fs_deny` when `Feature_BfsPolicyDeny` is enabled, so a
        // denied-paths policy can stay on T1 only when that feature is live.
        // When it isn't, we cannot enforce deny here and must fall through to
        // a DACL-enforcing tier.
        if !denied || native_fs_deny_supported() {
            return Ok(TierDecision {
                tier: IsolationTier::BaseContainer,
                needs_dacl_augmentation: false,
                bfscfg_path: None,
                warnings,
            });
        }
        warnings.push(
            "BaseContainer API present but Feature_BfsPolicyDeny is not enabled on this OS; \
             deniedPaths cannot be enforced natively (fs_deny) — falling back to AppContainer \
             for deniedPaths enforcement"
                .to_string(),
        );
    }
    // Tier 2 — AppContainer + BFS
    //
    // Reachable only when this binary was compiled with the `tier2_bfs`
    // feature. Without it, `find_bfscfg_exe` returns `Ok(None)`
    // unconditionally, so BFS could never enforce a filesystem policy.
    // Critically, the no-filesystem-policy short-circuit below would
    // otherwise return `appcontainer-bfs` on a binary that physically
    // cannot run BFS — so when the feature is absent we skip Tier 2
    // entirely and fall through to Tier 3 (AppContainer + DACL).
    if cfg!(feature = "tier2_bfs") {
        warnings.push(
            "BaseContainer API not present or not preferred; falling back to AppContainer + BFS"
                .to_string(),
        );

        // When the policy has no filesystem rules at all there is
        // nothing for BFS to enforce, so we can stay on T2 without
        // resolving bfscfg.exe. Otherwise we need a real path: probe-
        // time resolution doubles as the execution path (see
        // `TierDecision::bfscfg_path`).
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
    } else {
        warnings.push(
            "BaseContainer API not present or not preferred, and AppContainer + BFS is not \
             compiled into this binary; falling back to AppContainer + DACL"
                .to_string(),
        );
    }

    // Tier 3 — AppContainer + DACL
    ensure_dacl_augmentation_allowed(policy)?;
    // For RW / RO paths we only need `WRITE_DAC` if we'd actually have
    // to add an ACE. When the path's existing DACL already grants the
    // needed mask to the well-known AppContainer SIDs (typically
    // installer-set on system paths like `C:\Program Files\…`), the
    // per-run ACE is redundant — skip both the grant and the
    // `WRITE_DAC` requirement. See `ensure_path_grantable_for_ac`.
    // Denied paths always require `WRITE_DAC` because well-known SID
    // grants don't help us subtract access.
    for p in &policy.readwrite_paths {
        ensure_path_grantable_for_ac(Path::new(p), wxc_common::filesystem_dacl::RW_MASK)?;
    }
    for p in &policy.readonly_paths {
        ensure_path_grantable_for_ac(Path::new(p), wxc_common::filesystem_dacl::RO_MASK)?;
    }
    verify_write_dac_all(&policy.denied_paths)?;

    // Tier 3 leans on host-side preparation the kernel does not provide
    // by default (the system-drive metadata ACEs) or resets at every
    // boot (the `\Device\Null` descriptor). Surface actionable
    // `wxc-host-prep` recommendations, but only for the preparations
    // that are not already in effect on this machine.
    push_host_prep_warnings(&mut warnings);

    Ok(TierDecision {
        tier: IsolationTier::AppContainerDacl,
        needs_dacl_augmentation: true,
        bfscfg_path: None,
        warnings,
    })
}

/// Append `wxc-host-prep` recommendations to `warnings` for any
/// host-side preparation the AppContainer + DACL tier relies on that is
/// not currently in effect on this machine.
///
/// Each check is read-only and best-effort: if the machine state cannot
/// be determined we err on the side of surfacing the recommendation
/// rather than silently swallowing it.
fn push_host_prep_warnings(warnings: &mut Vec<String>) {
    if !system_drive_prepared() {
        warnings.push(
            "AppContainer + DACL tier selected: AppContainer processes may be unable to read \
             metadata of the system-drive root (e.g. `cmd.exe`, `pwsh.exe`, `node.exe` startup \
             stats of `C:\\`). Run `wxc-host-prep prepare-system-drive` (elevated) to grant the \
             minimal metadata ACEs."
                .to_string(),
        );
    }
    if !null_device_prepared() {
        warnings.push(
            "AppContainer + DACL tier selected: AppContainer processes may be unable to open the \
             NUL device (`\\Device\\Null`), which the kernel resets to an AppContainer-hostile \
             default at every boot. Run `wxc-host-prep prepare-null-device` (elevated) to reapply \
             the documented security descriptor."
                .to_string(),
        );
    }
}

/// Well-known AppContainer package SIDs that `wxc-host-prep` grants
/// access to. `Everyone` (`S-1-1-0`) is deliberately excluded — these
/// checks care specifically about the AppContainer package identities.
const HOST_PREP_AC_SIDS: &[&str] = &["S-1-15-2-1", "S-1-15-2-2"];

/// Metadata-read mask `wxc-host-prep prepare-system-drive` stamps on the
/// system-drive root (`FILE_READ_ATTRIBUTES | FILE_READ_EA |
/// READ_CONTROL | SYNCHRONIZE`). Must stay in sync with the
/// `STAT_ACCESS_MASK` constant in `wxc_host_prep`'s `system_drive`
/// module.
const SYSTEM_DRIVE_STAT_MASK: u32 = 0x0012_0088;

/// Resolve the system-drive root (e.g. `C:\`) for the read-only
/// host-prep state probe.
///
/// Unlike the elevated `prepare-system-drive` write path — which must
/// not trust `%SystemDrive%` from a potentially attacker-controlled
/// environment — this is a read-only DACL *read*, so deriving the root
/// from `%SystemDrive%` is acceptable. Falls back to `C:\`.
fn system_drive_root() -> std::path::PathBuf {
    let mut root = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
    if !root.ends_with('\\') {
        root.push('\\');
    }
    std::path::PathBuf::from(root)
}

/// Returns `true` when the `prepare-system-drive` ACEs are already
/// present for BOTH well-known AppContainer package SIDs on the
/// system-drive root.
///
/// Read-only and best-effort: a failed DACL read for any SID yields
/// `false`, so the caller surfaces the recommendation rather than
/// suppressing it on incomplete information.
fn system_drive_prepared() -> bool {
    let root = system_drive_root();
    HOST_PREP_AC_SIDS.iter().all(
        |sid| match wxc_common::filesystem_dacl::scan_explicit_aces_for_sid(&root, sid) {
            Ok(priors) => priors.iter().any(|p| {
                p.ace_type == wxc_common::filesystem_dacl::AceType::Allow
                    && p.access_mask == SYSTEM_DRIVE_STAT_MASK
                    && p.inherit_flags == 0
            }),
            Err(_) => false,
        },
    )
}

/// Returns `true` when `\Device\Null` already grants both well-known
/// AppContainer package SIDs access — i.e. `prepare-null-device` has
/// been applied since the last boot.
///
/// Read-only and best-effort: an unreadable DACL yields `false`, so the
/// caller surfaces the recommendation.
fn null_device_prepared() -> bool {
    wxc_common::filesystem_dacl::null_device_appcontainer_grants().unwrap_or(false)
}

/// Returns `Ok(true)` if a per-run ACE on `path` is unnecessary because
/// the path's existing DACL already grants `needed_mask` (or a
/// superset) to the well-known AppContainer SIDs that every
/// AppContainer process inherits. See
/// [`wxc_common::filesystem_dacl::compute_appcontainer_effective_access`].
///
/// Always returns `Ok(false)` for paths that don't exist or that fail
/// the DACL lookup — the caller will fall through to the `WRITE_DAC`
/// check, which produces a path-specific error.
pub(crate) fn appcontainer_already_grants(path: &Path, needed_mask: u32) -> bool {
    match wxc_common::filesystem_dacl::compute_appcontainer_effective_access(path) {
        Ok(effective) => (effective & needed_mask) == needed_mask,
        Err(_) => false,
    }
}

/// Verify that we can either add an ACE on `path` or skip it because
/// the AppContainer already has `needed_mask` access via well-known
/// SIDs. Returns the same [`FallbackError::WriteDacUnavailable`] as
/// the original blanket check when neither applies.
///
/// Order matters for typical-case cost: the WRITE_DAC check is a
/// single `CreateFileW`, while `appcontainer_already_grants` does a
/// full `GetNamedSecurityInfoW` + DACL walk + 3 SID allocations. For
/// the common installer-stamped path that *does* grant WRITE_DAC to
/// the current user (the case before `ce7713d`), trying WRITE_DAC
/// first short-circuits before we touch the DACL walk.
fn ensure_path_grantable_for_ac(path: &Path, needed_mask: u32) -> Result<(), FallbackError> {
    match check_write_dac_path(path) {
        Ok(()) => Ok(()),
        // Only fall through to the expensive walk when WRITE_DAC is
        // unavailable (the system-path / unowned-installer case that
        // motivated `ce7713d`). Other errors (e.g. ERROR_FILE_NOT_FOUND)
        // surface to the caller unchanged.
        Err(_) if appcontainer_already_grants(path, needed_mask) => Ok(()),
        Err(e) => Err(e),
    }
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
    // any tier that would touch them. BaseContainer (Tier 1) never touches
    // host DACLs — it enforces deny natively via `fs_deny` — so it never
    // needs augmentation regardless of `denied`.
    let needs_dacl = match tier {
        IsolationTier::AppContainerDacl => true,
        IsolationTier::AppContainerBfs => denied,
        IsolationTier::BaseContainer => false,
    };
    if needs_dacl && !policy.fallback.allow_dacl_mutation {
        return Err(FallbackError::DaclFallbackDisabled);
    }
    Ok(TierDecision {
        tier,
        needs_dacl_augmentation: needs_dacl,
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
pub fn is_base_container_api_present() -> bool {
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
/// - **`tier2_bfs` feature OFF (default)** — returns `Ok(None)`
///   unconditionally, before any disk or environment lookup. The
///   detector's existing T2→T3 fallback then drops to Tier 3. This is
///   the load-bearing safety guarantee: Tier 2 is compiled out, so no
///   code path in this binary can resolve `bfscfg.exe`.
/// - **`tier2_bfs` feature ON, release builds** consult
///   `GetWindowsDirectoryW` exclusively. The `SystemRoot` environment
///   variable is deliberately ignored to deny an attacker who can scrub
///   or rewrite the process environment a Tier 2 → Tier 3 downgrade
///   primitive.
/// - **`tier2_bfs` feature ON, test builds** additionally honor
///   `MXC_BFSCFG_PATH` as a narrow test seam. Its value is used
///   verbatim as the resolved path; an empty value simulates "not
///   present" by returning `Ok(None)`. The seam is gated by
///   `cfg(test)` so it compiles in only when building this crate's
///   test binary, regardless of profile (so CI's `--profile release`
///   test run exercises these paths).
/// - We deliberately do not look in `SysWOW64`: `bfscfg.exe` is shipped
///   only in the native System32 directory.
///
/// Returns `Err(FallbackError::SystemRootUnresolved)` only when the
/// Win32 API itself fails — on a healthy Windows host this should never
/// happen.
pub fn find_bfscfg_exe() -> Result<Option<PathBuf>, FallbackError> {
    #[cfg(not(feature = "tier2_bfs"))]
    {
        Ok(None)
    }
    #[cfg(feature = "tier2_bfs")]
    {
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
}

/// Resolve the Windows install directory via `GetWindowsDirectoryW`.
///
/// The OS populates the answer from boot configuration; it does not
/// consult the process environment. Returns
/// [`FallbackError::SystemRootUnresolved`] when the API itself fails.
#[cfg(feature = "tier2_bfs")]
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

#[cfg(feature = "tier2_bfs")]
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
        FILE_SHARE_WRITE, OPEN_EXISTING, WRITE_DAC,
    };
    use windows_core::PCWSTR;

    let path_str = path
        .to_str()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "non-UTF-8 path"))?;
    let wide = wxc_common::string_util::to_wide(path_str);

    // SAFETY: `wide` lives for the duration of the call and is null-
    // terminated by `to_wide`. CreateFileW is documented to accept directory
    // handles when `FILE_FLAG_BACKUP_SEMANTICS` is set.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            WRITE_DAC.0,
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
// Native fs_deny capability gate (Feature_BfsPolicyDeny)
// ---------------------------------------------------------------------------

/// Windows Feature-Staging feature ID for `Feature_BfsPolicyDeny` — the OS
/// gate that makes `Experimental_CreateProcessInSandbox` honor the SandboxSpec
/// `fs_deny` (deniedPaths) field. Enablement ships per-branch via the runtime
/// feature-configuration store independently of the OS build number, so
/// build/UBR is not a sound capability signal; we query the effective feature
/// state instead.
#[cfg_attr(test, allow(dead_code))]
const FEATURE_BFS_POLICY_DENY: u32 = 62_259_005;

/// Returns `true` when the OS will actually honor the SandboxSpec `fs_deny`
/// field — i.e. when `Feature_BfsPolicyDeny` resolves to *enabled* in the
/// runtime feature-configuration store.
///
/// Fails secure: a `disabled`/`default` state, a down-level OS that lacks the
/// feature-staging export, or any probe failure all yield `false`, so
/// deniedPaths fall through to a DACL-enforcing tier rather than being
/// silently dropped.
#[cfg(not(test))]
pub(crate) fn native_fs_deny_supported() -> bool {
    feature_staging::is_feature_enabled(FEATURE_BFS_POLICY_DENY)
}

/// Test build: avoid a machine-dependent feature probe so tier-selection tests
/// are deterministic. Defaults to "supported" (so tests that reach the real
/// Tier 1 branch with denied paths behave predictably); the
/// `MXC_FAKE_FS_DENY_FEATURE` seam — set via `test_env::FsDenyFeatureGuard` —
/// forces the disabled path.
#[cfg(test)]
pub(crate) fn native_fs_deny_supported() -> bool {
    match std::env::var("MXC_FAKE_FS_DENY_FEATURE") {
        Ok(v) => v == "1",
        Err(_) => true,
    }
}

/// Thin binding over the documented Windows Feature-Staging API
/// (`GetFeatureEnabledState`, `featurestagingapi.h`). It reads the same
/// runtime feature-configuration store that Velocity populates as a feature
/// rolls out, which is exactly how `Feature_BfsPolicyDeny` is being delivered.
///
/// The export is resolved from the feature-staging **API set contract**
/// (`api-ms-win-core-featurestaging-l1-1-0.dll`), not `kernelbase.dll`:
/// on current builds `GetProcAddress(kernelbase, "GetFeatureEnabledState")`
/// returns null even though the API is present, and `wxc-exec` does not
/// statically import the API set, so it must be `LoadLibrary`-loaded rather
/// than found via `GetModuleHandle`. `kernelbase.dll` is kept only as a
/// defensive secondary fallback.
mod feature_staging {
    /// `FEATURE_ENABLED_STATE_ENABLED` from `featurestagingapi.h`. The other
    /// states (`DEFAULT = 0`, `DISABLED = 1`) both fail secure here: `DEFAULT`
    /// means "no runtime-store override", leaving the value to the OS
    /// component's compiled-in default, which an external process cannot
    /// observe — so we treat anything but an explicit `ENABLED` as "off".
    const FEATURE_ENABLED_STATE_ENABLED: i32 = 2;

    /// `FEATURE_CHANGE_TIME_READ` from `featurestagingapi.h` — read the
    /// current effective state without pinning to a change boundary.
    #[cfg_attr(test, allow(dead_code))]
    const FEATURE_CHANGE_TIME_READ: i32 = 0;

    /// Maps a raw `FEATURE_ENABLED_STATE` value to "the feature is on". Only
    /// the explicit `ENABLED` state counts; every other (or unexpected) value
    /// fails secure to `false`. Pure, so it is unit-tested directly.
    pub(super) fn enabled_state_means_on(state: i32) -> bool {
        state == FEATURE_ENABLED_STATE_ENABLED
    }

    #[cfg(target_os = "windows")]
    type GetFeatureEnabledStateFn =
        unsafe extern "system" fn(feature_id: u32, change_time: i32) -> i32;

    /// DLLs to try, in order, when resolving `GetFeatureEnabledState`. The
    /// feature-staging API set contract is the documented home of the export
    /// on current builds; `kernelbase.dll` is a defensive fallback only.
    #[cfg(target_os = "windows")]
    #[cfg_attr(test, allow(dead_code))]
    const FEATURE_STAGING_DLLS: [windows::core::PCWSTR; 2] = [
        windows::core::w!("api-ms-win-core-featurestaging-l1-1-0.dll"),
        windows::core::w!("kernelbase.dll"),
    ];

    /// Resolve `GetFeatureEnabledState` from the first DLL in
    /// [`FEATURE_STAGING_DLLS`] that both loads and exports it. Returns `None`
    /// on down-level builds that lack the API entirely (fail secure).
    ///
    /// Uses `LoadLibraryExW` with `LOAD_LIBRARY_SEARCH_SYSTEM32` rather than
    /// `GetModuleHandleW`/`LoadLibraryW`: `wxc-exec` does not statically import
    /// the feature-staging API set, so the backing module may not already be
    /// loaded, and a bare-name `LoadLibraryW` would honor the default search
    /// order (executable dir, CWD, `PATH`) — a DLL-planting vector in the host
    /// process before sandbox launch. `LOAD_LIBRARY_SEARCH_SYSTEM32` restricts
    /// the load to `System32`, where both candidates live (the API-set
    /// contract resolves to its System32 host module; `kernelbase.dll` is in
    /// System32). This mirrors the hardened `processmodel.dll` loader in
    /// `base_container_runner`. If the export cannot be resolved from a trusted
    /// system module we fail closed (`None`), so a denied-paths policy falls
    /// through to the DACL-enforcing tier rather than trusting an
    /// unverifiable load. The loaded modules are core, process-lifetime system
    /// DLLs; the handle is intentionally leaked (no `FreeLibrary`) so the
    /// returned function pointer stays valid.
    #[cfg(target_os = "windows")]
    #[cfg_attr(test, allow(dead_code))]
    pub(super) fn resolve_get_feature_enabled_state() -> Option<GetFeatureEnabledStateFn> {
        use windows::Win32::System::LibraryLoader::{
            GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
        };
        for dll in FEATURE_STAGING_DLLS {
            // SAFETY: `dll` is a static NUL-terminated wide string. A failed
            // load or missing export simply moves on to the next candidate.
            unsafe {
                let Ok(module) = LoadLibraryExW(dll, None, LOAD_LIBRARY_SEARCH_SYSTEM32) else {
                    continue;
                };
                if let Some(proc) =
                    GetProcAddress(module, windows::core::s!("GetFeatureEnabledState"))
                {
                    // The transmuted signature matches the documented
                    // `featurestagingapi.h` prototype (`FEATURE_ENABLED_STATE
                    // GetFeatureEnabledState(UINT32, FEATURE_CHANGE_TIME)`),
                    // both enum parameter/return being C `int`.
                    return Some(std::mem::transmute::<
                        unsafe extern "system" fn() -> isize,
                        GetFeatureEnabledStateFn,
                    >(proc));
                }
            }
        }
        None
    }

    #[cfg(target_os = "windows")]
    #[cfg_attr(test, allow(dead_code))]
    pub(super) fn is_feature_enabled(feature_id: u32) -> bool {
        match resolve_get_feature_enabled_state() {
            // SAFETY: `get_state` is the resolved `GetFeatureEnabledState`
            // export; calling it with a feature id and `FEATURE_CHANGE_TIME`
            // is the documented usage.
            Some(get_state) => {
                enabled_state_means_on(unsafe { get_state(feature_id, FEATURE_CHANGE_TIME_READ) })
            }
            None => false,
        }
    }

    #[cfg(not(target_os = "windows"))]
    #[cfg_attr(test, allow(dead_code))]
    pub(super) fn is_feature_enabled(_feature_id: u32) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::models::ContainerPolicy;
    // Shared ENV_LOCK + guards live in `crate::test_env` so they're
    // honored uniformly across the dispatcher and fallback_detector
    // test modules. A per-module lock would let cross-module test
    // threads race on `MXC_FORCE_TIER` / `MXC_BFSCFG_PATH`.
    use crate::test_env::{ForceTierGuard, FsDenyFeatureGuard, ENV_LOCK};
    // `BfscfgPathGuard` is only meaningful when the `tier2_bfs` feature
    // is compiled in; without it, `find_bfscfg_exe` ignores the env var.
    #[cfg(feature = "tier2_bfs")]
    use crate::test_env::BfscfgPathGuard;

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
    fn empty_policy_no_filesystem_t2_path() {
        let _g = ForceTierGuard::set("appcontainer-bfs");
        let policy = empty_policy();
        let d = detect(&policy, true).expect("forced bfs should succeed");
        assert!(matches!(d.tier, IsolationTier::AppContainerBfs));
        assert!(!d.needs_dacl_augmentation);
    }
    #[test]
    fn forced_base_container_with_denied_enforces_natively() {
        // BaseContainer (Tier 1) enforces deniedPaths natively via the
        // SandboxSpec `fs_deny` field, so it needs no host DACL augmentation
        // and is unaffected by `allow_dacl_mutation = false`.
        let _g = ForceTierGuard::set("base-container");
        let mut policy = policy_with_denied();
        policy.fallback.allow_dacl_mutation = false;
        let d = detect(&policy, true).expect("base-container honors deny natively");
        assert!(matches!(d.tier, IsolationTier::BaseContainer));
        assert!(!d.needs_dacl_augmentation);
    }
    #[test]
    fn denied_does_not_select_base_container_when_feature_disabled() {
        // When `Feature_BfsPolicyDeny` is off, a denied-paths policy must not
        // land on Tier 1 (which would silently drop deny enforcement); it
        // falls through to a DACL-enforcing tier. Only meaningful where the
        // BaseContainer API is actually present — otherwise T1 is unreachable
        // regardless and the pure-function / forced tests provide coverage.
        // BaseContainer API presence is a pure probe (no env vars), so it
        // needs no lock; acquire the env guard only once we're going to use
        // the feature seam.
        if !is_base_container_api_present() {
            return;
        }
        let _g = FsDenyFeatureGuard::disabled();
        let policy = policy_with_denied();
        // The fall-through tier may either succeed (e.g. AppContainer + DACL)
        // or fail a downstream WRITE_DAC probe on the denied system path; the
        // load-bearing assertion is simply that we did NOT stay on T1.
        let result = detect(&policy, true);
        assert!(
            !matches!(
                result,
                Ok(TierDecision {
                    tier: IsolationTier::BaseContainer,
                    ..
                })
            ),
            "deny must not select BaseContainer when the feature is disabled"
        );
    }
    #[test]
    fn feature_enabled_state_mapping_is_fail_secure() {
        use super::feature_staging::enabled_state_means_on;
        assert!(enabled_state_means_on(2)); // FEATURE_ENABLED_STATE_ENABLED
        assert!(!enabled_state_means_on(0)); // FEATURE_ENABLED_STATE_DEFAULT
        assert!(!enabled_state_means_on(1)); // FEATURE_ENABLED_STATE_DISABLED
        assert!(!enabled_state_means_on(3)); // unexpected
        assert!(!enabled_state_means_on(-1)); // garbage
    }

    /// The real export-resolution path is normally hidden behind the
    /// `MXC_FAKE_FS_DENY_FEATURE` test seam (`native_fs_deny_supported`), so a
    /// wrong-DLL regression would not surface in tier-selection tests. This
    /// smoke test exercises the production resolver directly: every supported
    /// Windows host (and CI) ships the feature-staging API set, so the export
    /// MUST resolve. Resolving from `kernelbase.dll` (the prior behavior)
    /// returns null on current builds and would fail this assertion. Calling
    /// the resolved function must also not panic.
    #[cfg(target_os = "windows")]
    #[test]
    fn feature_staging_export_resolves_on_windows() {
        let f = super::feature_staging::resolve_get_feature_enabled_state()
            .expect("GetFeatureEnabledState must resolve from the feature-staging API set");
        // Exercise the call path; the concrete tri-state value is host- and
        // rollout-dependent, so we only assert it executes without UB/panic.
        let _state = unsafe { f(super::FEATURE_BFS_POLICY_DENY, 0) };
    }
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
    #[test]
    fn force_tier_env_var_parses_all_three_values() {
        assert!(matches!(
            parse_force_tier("base-container"),
            Some(IsolationTier::BaseContainer)
        ));
        assert!(matches!(
            parse_force_tier("appcontainer-bfs"),
            Some(IsolationTier::AppContainerBfs)
        ));
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

    #[cfg(feature = "tier2_bfs")]
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

    // The `MXC_BFSCFG_PATH` test seam only takes effect when the
    // `tier2_bfs` feature is enabled — without it, `find_bfscfg_exe`
    // returns `Ok(None)` unconditionally and the override is dead.
    #[cfg(feature = "tier2_bfs")]
    #[test]
    fn mxc_bfscfg_path_empty_value_simulates_missing() {
        let _g = BfscfgPathGuard::set("");
        let result = find_bfscfg_exe().expect("empty override must succeed");
        assert!(
            result.is_none(),
            "empty MXC_BFSCFG_PATH must yield Ok(None), got {result:?}"
        );
    }
    #[cfg(feature = "tier2_bfs")]
    #[test]
    fn mxc_bfscfg_path_nonexistent_path_is_none() {
        let _g = BfscfgPathGuard::set("C:\\__mxc_does_not_exist__\\bfscfg.exe");
        let result = find_bfscfg_exe().expect("non-existent override must succeed");
        assert!(
            result.is_none(),
            "non-existent MXC_BFSCFG_PATH must yield Ok(None), got {result:?}"
        );
    }
    #[cfg(feature = "tier2_bfs")]
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

    /// With `tier2_bfs` off, `find_bfscfg_exe` must return `Ok(None)`
    /// regardless of host state, `MXC_BFSCFG_PATH`, or anything else —
    /// this is the load-bearing safety invariant.
    #[cfg(not(feature = "tier2_bfs"))]
    #[test]
    fn find_bfscfg_exe_is_none_when_feature_off() {
        let result = find_bfscfg_exe().expect("find_bfscfg_exe must not error with feature off");
        assert!(
            result.is_none(),
            "find_bfscfg_exe must return None when tier2_bfs feature is off, got {result:?}"
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
        assert!(d.needs_dacl_augmentation);
        assert!(
            d.warnings.is_empty(),
            "forced decisions should not accumulate fallback-chain warnings"
        );
    }

    /// `appcontainer_already_grants` must return `false` on a plain
    /// temp dir (no AC-group ACEs) and `true` after we stamp a
    /// matching grant for `ALL APPLICATION PACKAGES`.
    #[test]
    fn appcontainer_already_grants_respects_explicit_grant() {
        use crate::test_env::ScopedStateDir;
        use windows::Win32::Storage::FileSystem::FILE_GENERIC_READ;
        use wxc_common::filesystem_dacl::DaclManager;

        let _scope = ScopedStateDir::new();
        let td = tempfile::tempdir().unwrap();
        let mask = FILE_GENERIC_READ.0;

        assert!(
            !appcontainer_already_grants(td.path(), mask),
            "fresh temp dir should not grant AC well-known SIDs"
        );

        let mut mgr = DaclManager::new().unwrap();
        mgr.grant_appcontainer_access("S-1-15-2-1", &[], &[td.path().to_path_buf()])
            .unwrap();
        assert!(
            appcontainer_already_grants(td.path(), mask),
            "after explicit grant on ALL APPLICATION PACKAGES, AC should be covered"
        );
        // mgr.Drop restores, returning the path to its original state.
    }

    #[test]
    fn system_drive_root_ends_with_backslash() {
        let root = system_drive_root();
        let s = root.to_string_lossy();
        assert!(
            s.ends_with('\\'),
            "system-drive root should end with a backslash, got {s}"
        );
    }

    /// The host-prep state is machine-dependent, so we assert only the
    /// contract: at most the two known recommendations, and each names
    /// the corresponding `wxc-host-prep` verb.
    #[test]
    fn push_host_prep_warnings_are_actionable_and_bounded() {
        let mut warnings = Vec::new();
        push_host_prep_warnings(&mut warnings);
        assert!(
            warnings.len() <= 2,
            "expected at most two host-prep warnings, got {warnings:?}"
        );
        for w in &warnings {
            assert!(
                w.contains("wxc-host-prep prepare-system-drive")
                    || w.contains("wxc-host-prep prepare-null-device"),
                "host-prep warning should name a wxc-host-prep verb, got: {w}"
            );
        }
    }

    /// Read-only `\Device\Null` probe must not panic; the result is
    /// host-dependent so we only assert it returns.
    #[test]
    fn null_device_grants_probe_smoke() {
        let _ = wxc_common::filesystem_dacl::null_device_appcontainer_grants();
    }

    /// With `tier2_bfs` compiled out, an empty policy on a host where
    /// Tier 1 is skipped must resolve to Tier 3 (AppContainer + DACL) —
    /// never `appcontainer-bfs` — and carry the BFS-not-compiled
    /// fall-through warning.
    #[cfg(not(feature = "tier2_bfs"))]
    #[test]
    fn no_bfs_feature_falls_through_to_dacl_for_empty_policy() {
        // Clear MXC_FORCE_TIER under ENV_LOCK so the test-only force
        // seam in `detect` doesn't observe a sibling test's value.
        let _lock = {
            let lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            // SAFETY: env-var mutation in tests; serialized by ENV_LOCK.
            unsafe {
                std::env::remove_var("MXC_FORCE_TIER");
            }
            lock
        };
        let mut policy = empty_policy();
        policy.fallback.allow_dacl_mutation = true;
        // `prefer_base_container = false` skips Tier 1 deterministically;
        // with `tier2_bfs` off, Tier 2 is skipped too.
        let d = detect(&policy, false).expect("empty policy must resolve");
        assert!(
            matches!(d.tier, IsolationTier::AppContainerDacl),
            "tier2_bfs off must select AppContainerDacl, got {:?}",
            d.tier
        );
        assert!(d.needs_dacl_augmentation);
        assert!(
            d.warnings
                .iter()
                .any(|w| w.contains("not compiled into this binary")),
            "expected BFS-not-compiled fall-through warning, got: {:?}",
            d.warnings
        );
    }

    /// With `tier2_bfs` compiled in, an empty policy on a host where
    /// Tier 1 is skipped stays on Tier 2 (AppContainer + BFS) via the
    /// no-filesystem-policy short-circuit.
    #[cfg(feature = "tier2_bfs")]
    #[test]
    fn bfs_feature_selects_bfs_for_empty_policy_when_bc_skipped() {
        let _lock = {
            let lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            // SAFETY: env-var mutation in tests; serialized by ENV_LOCK.
            unsafe {
                std::env::remove_var("MXC_FORCE_TIER");
            }
            lock
        };
        let policy = empty_policy();
        let d = detect(&policy, false).expect("empty policy must resolve");
        assert!(
            matches!(d.tier, IsolationTier::AppContainerBfs),
            "tier2_bfs on with empty policy must select AppContainerBfs, got {:?}",
            d.tier
        );
        assert!(!d.needs_dacl_augmentation);
    }
}
