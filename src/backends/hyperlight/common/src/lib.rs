// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// The Hyperlight + Unikraft micro-VM host library is x86_64-only (KVM
// on Linux, WHP on Windows) AND is an optional dependency gated by the
// `hyperlight` cargo feature. On other targets, or when the feature is
// disabled, this crate compiles to an empty library so workspace builds
// (`cargo build --workspace`) on ARM64 hosts and feature-less builds
// (e.g. `cargo build --features microvm`) succeed without pulling in
// hyperlight-host. Consumers gate their use of `HyperlightScriptRunner`
// on `target_arch = "x86_64"` and the `hyperlight` cargo feature.
#![cfg(all(feature = "hyperlight", target_arch = "x86_64"))]

//! `HyperlightScriptRunner` — executes Python code inside a Hyperlight + Unikraft
//! micro-VM, driven by the `hyperlight-unikraft` library.
//!
//! | Property            | Value                                                     |
//! |---------------------|-----------------------------------------------------------|
//! | Backing micro-VM    | Unikraft unikernel in a Hyperlight micro-VM               |
//! | Host platform       | Linux (KVM) + Windows (WHP)                               |
//! | Execution model     | Embedded library, in-process                              |
//! | Script delivery     | `AppSandbox::run`, or `submit` + `step` under a deadline  |
//! | Cold start          | Snapshot restore (~50–60 ms)                               |
//! | Filesystem          | Host dir mounts via `Mount`                               |
//! | Networking          | Host-proxied sockets via `NetworkPolicy`                  |
//! | Script I/O          | Host's stdout/stderr (HostPrint)                          |
//! | stdlib coverage     | Full CPython + preloaded ML stack (numpy, pandas, etc.)   |
//!
//! ## Image-home resolution
//!
//! The runner looks for a warmed image in this order, first hit wins:
//!
//!   1. `$MXC_HYPERLIGHT_HOME` (searched first when set)
//!   2. `~/.local/share/mxc-hyperlight/` on Linux (XDG_DATA_HOME compliant)
//!      `%LOCALAPPDATA%\mxc-hyperlight\` on Windows
//!   3. `<exe_dir>/mxc-hyperlight/` (dev build next to the target binary)
//!   4. `<cwd>/.mxc-hyperlight/` (dev fallback)
//!
//! Path #2 is the "default". `--setup-hyperlight` installs here when nothing
//! else is already populated — so one eager install persists across
//! shell sessions, across reboots, and across `cargo install` upgrades.
//!
//! An image home holds one directory per guest runtime (`agent/`, `node/`,
//! ...), each with that runtime's rootfs (`initrd.cpio`), its warmed
//! `snapshot/` directory, and a `VERSION` stamp naming the rootfs release.
//! The Unikraft kernel is embedded in the `hyperlight-unikraft` crate, so
//! nothing else is downloaded. A snapshot loads only under a build with
//! its snapshot key (the crate's kernel and host contract), and a rootfs
//! only boots on its own release's kernel, so a home whose stamp or
//! snapshot key is another build's is treated as not installed:
//! `--setup-hyperlight` rebuilds it, and a run warms a new snapshot by
//! itself when only the snapshot is stale.
//!
//! ## Setup
//!
//! `lxc-exec --setup-hyperlight[=RUNTIME,...]` (or `wxc-exec`) pulls each
//! runtime's published rootfs straight from GHCR (no container runtime
//! needed), boots it once, and persists the warmed guest as a snapshot in
//! the default home. `agent` is the default runtime; a request's
//! `hyperlight.runtime` selects another.
//!
//! On first `run` (if setup was skipped) the runner also does a lazy
//! auto-install if `initrd.cpio` is already in the resolved home but no
//! snapshot is — cheap safety net.
//!
//! ## Filesystem policy
//!
//! `policy.readwritePaths` and `policy.readonlyPaths` are translated to
//! [`Mount`] entries — the guest sees the host directories at
//! `/host/<basename>`. `readonlyPaths` are mounted read-only, which the
//! guest kernel enforces (`EROFS`) and the host's `fs_*` functions enforce
//! again.
//!
//! The persisted snapshot is warmed without mounts; the kernel builds its
//! mount table from the mounts a restore names, so every request restores
//! the same warm image, mounts or not.
//!
//! `policy.deniedPaths` is honored: any path that appears in the denied
//! list is rejected at preflight — including paths that also appear in
//! the allow lists.
//!
//! ## I/O model
//!
//! The guest's `print(...)` goes through Hyperlight's HostPrint callback,
//! which writes to the **host process's stdout**. `ScriptResponse.standard_out`
//! and `standard_err` stay empty; consumers that need captured output
//! redirect wxc-exec's stdout/stderr at the process level.
//!
//! ## Exit codes
//!
//! Guest exit code on clean completion (0 for normal exit, non-zero for
//! `sys.exit(N)` or unhandled exceptions), -1 on any runner error
//! (preflight, install, runtime, guest crash, timeout). The specific
//! failure mode is in `error_message`.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use wxc_common::logger::Logger;
use wxc_common::models::{ExecutionRequest, HyperlightRuntime, NetworkPolicy, ScriptResponse};
use wxc_common::script_runner::ScriptRunner;
use wxc_common::validator::{validate_network_policy_support, NetworkPolicySupport};

use hyperlight_unikraft::hyperlight_host::HyperlightError;
use hyperlight_unikraft::{
    AllowList, AppSandbox, BlockList, Mount, SandboxBuilder, Snapshot, Yield,
};

// -- Availability probe -------------------------------------------------------

/// Whether KVM is usable by this process: `/dev/kvm` opens for reading and
/// writing. Setup and a run check it before booting anything.
#[cfg(target_os = "linux")]
pub fn is_kvm_available() -> bool {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok()
}

/// WHP is delay-loaded; check before setup or a run boots a VM.
#[cfg(target_os = "windows")]
pub fn is_whp_available() -> bool {
    use windows::core::w;
    use windows::Win32::System::LibraryLoader::{LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32};

    // SAFETY: LOAD_LIBRARY_SEARCH_SYSTEM32 restricts to %SystemRoot%\system32.
    let module =
        unsafe { LoadLibraryExW(w!("winhvplatform.dll"), None, LOAD_LIBRARY_SEARCH_SYSTEM32) };
    module.is_ok()
}

// -- Error classification ----------------------------------------------------

#[derive(Debug)]
enum RunnerError {
    /// Pre-spawn validation failures (missing image, unsupported policy).
    Preflight(String),
    /// Runtime construction, install, or execution failure.
    Runtime(String),
}

impl std::fmt::Display for RunnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunnerError::Preflight(msg) => write!(f, "hyperlight preflight error: {msg}"),
            RunnerError::Runtime(msg) => write!(f, "hyperlight runtime error: {msg}"),
        }
    }
}

impl RunnerError {
    fn to_response(&self) -> ScriptResponse {
        ScriptResponse {
            exit_code: ERROR_EXIT_CODE,
            error_message: self.to_string(),
            ..Default::default()
        }
    }
}

const ERROR_EXIT_CODE: i32 = -1;

/// Env var override for the Hyperlight image home. Set this to force a
/// specific location; otherwise the runner uses a standard OS-local
/// data path (~/.local/share/mxc-hyperlight on Linux, %LOCALAPPDATA%\mxc-hyperlight on
/// Windows).
const HOME_ENV: &str = "MXC_HYPERLIGHT_HOME";
/// Subdirectory used next to the running executable (dev builds).
const EXE_RELATIVE_HOME: &str = "mxc-hyperlight";
/// Subdirectory used in the cwd as a last resort (dev fallback).
const CWD_RELATIVE_HOME: &str = ".mxc-hyperlight";
/// Final component of the default OS-local data path.
const DEFAULT_HOME_LEAF: &str = "mxc-hyperlight";

/// The guest rootfs (a CPIO archive) inside an image home. The kernel is
/// embedded in the `hyperlight-unikraft` crate, so this is the only
/// artifact an install needs.
const INITRD_FILE: &str = "initrd.cpio";
/// The warmed snapshot (an OCI image layout) inside an image home.
const SNAPSHOT_DIR: &str = "snapshot";
/// Stamp `setup` writes beside the rootfs, naming the release it holds.
const VERSION_FILE: &str = "VERSION";

/// Pinned to the `hyperlight-unikraft` release in Cargo.toml: a rootfs
/// only boots on the kernel and driver protocol of its own release.
const ROOTFS_TAG: &str = "initrd-v0.14.1";
const ROOTFS_PATH_IN_IMAGE: &str = "/initrd.cpio";
/// Where host directories appear in the guest: `/host/<basename>`.
const GUEST_MOUNT_ROOT: &str = "/host";
/// The executor whose `--setup-hyperlight` installs an image, for hints.
const SETUP_BIN: &str = if cfg!(windows) {
    "wxc-exec"
} else {
    "lxc-exec"
};

/// What a guest runtime is built from.
struct RuntimeImage {
    /// The published rootfs, `ghcr.io/<owner>/<repo>/<image>`, named as
    /// the runtime is. Its `:initrd-<version>` tag wraps the runnable CPIO
    /// in a scratch image at [`ROOTFS_PATH_IN_IMAGE`].
    image: String,
    /// Scratch memory for it: upstream's own figure, covering rootfs
    /// extraction plus runtime start-up.
    scratch_mb: usize,
}

fn runtime_image(runtime: HyperlightRuntime) -> RuntimeImage {
    // Upstream's own scratch figures per image: rootfs extraction plus
    // runtime start-up.
    let scratch_mb = match runtime {
        HyperlightRuntime::Agent => 1536,
        HyperlightRuntime::Python | HyperlightRuntime::PythonShell | HyperlightRuntime::Bash => 256,
        HyperlightRuntime::Node => 512,
        HyperlightRuntime::DotnetJit => 768,
    };
    RuntimeImage {
        image: format!(
            "ghcr.io/hyperlight-dev/hyperlight-unikraft/{}",
            runtime.name()
        ),
        scratch_mb,
    }
}

const ERR_PROXY_POLICY: &str = "network proxy is not supported by the hyperlight backend";
const ERR_WORKDIR: &str =
    "workingDirectory is not supported by the hyperlight backend -- guest has its own filesystem namespace";

fn no_install_source(runtime: HyperlightRuntime) -> String {
    let name = runtime.name();
    format!(
        "no warmed {name} snapshot and no rootfs to install from. drop `{INITRD_FILE}` into \
         the runtime's directory of the image home (or run `--setup-hyperlight={name}`)."
    )
}

// -- Runner ------------------------------------------------------------------

/// Script runner that executes Python code inside a Hyperlight+Unikraft
/// micro-VM.
///
/// Lazily brings up the guest on the first call (loading the persisted
/// snapshot, auto-installing it first if needed) and reuses it across
/// subsequent calls on the same runner instance. Every call rewinds the
/// guest to the post-warmup snapshot first, so consecutive calls are
/// hermetic.
pub struct HyperlightScriptRunner {
    guest: Option<Guest>,
    /// The persisted warm image, loaded once per home. Outlives `guest`:
    /// a call that fails or times out drops the guest, and the next call
    /// boots a fresh one from here instead of reloading it from disk.
    rewind: Option<Arc<Snapshot>>,
    active_home: Option<PathBuf>,
    active_mounts: Vec<Mount>,
    active_policy: Option<hyperlight_unikraft::NetworkPolicy>,
    active_network: NetworkKey,
}

/// The request's network policy as the runner keys a booted guest on it.
/// Both host lists are kept, so an allow list and a block list of the
/// same hosts key differently.
#[derive(Clone, Debug, PartialEq, Default)]
struct NetworkKey {
    allowed: Vec<String>,
    blocked: Vec<String>,
    default: NetworkPolicy,
}

impl NetworkKey {
    fn from_request(request: &ExecutionRequest) -> Self {
        let sorted = |hosts: &[String]| {
            let mut hosts = hosts.to_vec();
            hosts.sort();
            hosts.dedup();
            hosts
        };
        Self {
            allowed: sorted(&request.policy.allowed_hosts),
            blocked: sorted(&request.policy.blocked_hosts),
            default: request.policy.default_network_policy.clone(),
        }
    }
}

/// A booted guest, parked at a boundary between calls.
struct Guest {
    sandbox: AppSandbox,
    /// True until the first call: the guest is already at the rewind point.
    fresh: bool,
}

/// Wall-clock split of one call.
#[derive(Debug, Default)]
struct RunTiming {
    restore_ms: f64,
    call_ms: f64,
    exit_code: i32,
}

/// Why a call produced no exit code.
enum RunError {
    TimedOut(Duration),
    Failed(String),
}

impl Default for HyperlightScriptRunner {
    fn default() -> Self {
        Self::new()
    }
}

/// The runtimes `--setup-hyperlight` was given: the default runtime for
/// no names, otherwise each name parsed, the first unknown one reported.
pub fn parse_runtimes(names: &[String]) -> Result<Vec<HyperlightRuntime>, String> {
    if names.is_empty() {
        return Ok(vec![HyperlightRuntime::default()]);
    }
    names.iter().map(|name| name.parse()).collect()
}

/// Eagerly install the warmed snapshot so the *first* run later
/// pays no warmup cost. Intended to be called from a tool install
/// step (npm postinstall, a `--setup-hyperlight` CLI flag, CI, etc.).
///
/// Pulls the published rootfs from GHCR over the registry API, boots it
/// once, and persists the warmed guest as a snapshot.
///
/// # Destination
///
/// `$MXC_HYPERLIGHT_HOME` if set, otherwise the OS-local default
/// (`~/.local/share/mxc-hyperlight` on Linux, `%LOCALAPPDATA%\mxc-hyperlight` on
/// Windows), with one directory per runtime under it. We intentionally do NOT walk the runtime search chain
/// here — that would let a stale `<cwd>/.mxc-hyperlight/` from an old dev
/// session short-circuit the install and leave the default home
/// empty, which would make later runs from a different cwd fail.
///
/// # Force
///
/// When `force` is false, an existing install for this release is a
/// no-op; one left by another release is rebuilt. When `force` is true,
/// the snapshot is rebuilt regardless.
pub fn setup(
    force: bool,
    runtimes: &[HyperlightRuntime],
    logger: &mut Logger,
) -> Result<PathBuf, String> {
    let root = match std::env::var_os(HOME_ENV) {
        Some(v) => PathBuf::from(v),
        None => HyperlightScriptRunner::default_home(),
    };

    for &runtime in runtimes {
        let home = root.join(runtime.name());
        if !force && is_installed(&home, runtime) {
            logger.log_line(&format!(
                "hyperlight: {} snapshot already present at {:?}; nothing to do \
                 (pass --force to rebuild)",
                runtime.name(),
                home.join(SNAPSHOT_DIR)
            ));
            continue;
        }

        std::fs::create_dir_all(&home).map_err(|e| format!("create image home {home:?}: {e}"))?;

        // A rootfs of this release already in the home is kept, so a rebuild
        // (a stale snapshot, or --force after replacing it) only warms.
        if has_install_source(&home, runtime) {
            logger.log_line(&format!(
                "hyperlight setup: rootfs present at {:?}",
                home.join(INITRD_FILE)
            ));
        } else {
            logger.log_line(&format!(
                "hyperlight setup: pulling {}:{ROOTFS_TAG}",
                runtime_image(runtime).image
            ));
            pull_rootfs(&home.join(INITRD_FILE), runtime, logger)?;
            std::fs::write(home.join(VERSION_FILE), version_stamp(runtime))
                .map_err(|e| format!("write {VERSION_FILE}: {e}"))?;
        }

        let (_, persisted) = warm_snapshot(&home, runtime, logger).map_err(|e| e.to_string())?;
        if !persisted {
            return Err(format!(
                "the snapshot could not be put in place at {:?}; the log above says why",
                home.join(SNAPSHOT_DIR)
            ));
        }
    }
    Ok(root)
}

impl HyperlightScriptRunner {
    pub fn new() -> Self {
        Self {
            guest: None,
            rewind: None,
            active_home: None,
            active_mounts: Vec::new(),
            active_policy: None,
            active_network: NetworkKey::default(),
        }
    }

    /// Resolve the image home for a normal run. Walks the
    /// discovery chain (see module doc) and returns the first
    /// location that has at least the rootfs — snapshot may be
    /// missing, the runner will install it.
    fn resolve_home(runtime: HyperlightRuntime) -> Result<PathBuf, RunnerError> {
        let name = runtime.name();
        let mut stale = None;
        for root in Self::search_paths() {
            let cand = root.join(name);
            if is_installed(&cand, runtime) || has_install_source(&cand, runtime) {
                return Ok(cand);
            }
            if stale.is_none() && cand.join(INITRD_FILE).is_file() {
                stale = Some(cand);
            }
        }
        let default = Self::default_home();
        let hint = match stale {
            Some(home) => format!(
                "{home:?} holds a rootfs from another hyperlight-unikraft release; \
                 run `{SETUP_BIN} --setup-hyperlight={name}` to rebuild it."
            ),
            None => format!(
                "run `{SETUP_BIN} --setup-hyperlight={name}` \
                 (or drop `{INITRD_FILE}` into {:?}).",
                default.join(name)
            ),
        };
        Err(RunnerError::Preflight(format!(
            "no hyperlight image found for the {name} runtime. searched ${HOME_ENV}, \
             {default:?}, <exe>/{EXE_RELATIVE_HOME}/, <cwd>/{CWD_RELATIVE_HOME}/, each under \
             `{name}/`. {hint}"
        )))
    }

    /// Candidate locations, in priority order.
    fn search_paths() -> Vec<PathBuf> {
        let mut paths = Vec::with_capacity(4);
        if let Some(explicit) = std::env::var_os(HOME_ENV) {
            paths.push(PathBuf::from(explicit));
        }
        paths.push(Self::default_home());
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                paths.push(dir.join(EXE_RELATIVE_HOME));
            }
        }
        if let Ok(cwd) = std::env::current_dir() {
            paths.push(cwd.join(CWD_RELATIVE_HOME));
        }
        paths
    }

    /// The OS-local default data directory. Setup writes here
    /// when nothing else is already populated, and it's always second
    /// in the resolution chain (after $MXC_HYPERLIGHT_HOME).
    ///
    /// - Linux: `$XDG_DATA_HOME/mxc-hyperlight` (or `~/.local/share/mxc-hyperlight`)
    /// - Windows: `%LOCALAPPDATA%\mxc-hyperlight` (or `~\AppData\Local\mxc-hyperlight`)
    fn default_home() -> PathBuf {
        os_data_home().join(DEFAULT_HOME_LEAF)
    }

    /// Reject only policies that the hyperlight backend genuinely cannot honor.
    /// Filesystem mounts and network policies ARE supported.
    fn validate_policies(request: &ExecutionRequest) -> Result<(), RunnerError> {
        if request.policy.network_proxy.is_enabled() {
            return Err(RunnerError::Preflight(ERR_PROXY_POLICY.to_string()));
        }
        if !request.working_directory.is_empty() {
            return Err(RunnerError::Preflight(ERR_WORKDIR.to_string()));
        }
        if request.policy.default_network_policy == NetworkPolicy::Block
            && !request.policy.allowed_hosts.is_empty()
            && !request.policy.blocked_hosts.is_empty()
        {
            return Err(RunnerError::Preflight(
                "allowedHosts and blockedHosts are mutually exclusive".to_string(),
            ));
        }

        // Denied paths: block early if any appears in the allow lists.
        for denied in &request.policy.denied_paths {
            if request
                .policy
                .readwrite_paths
                .iter()
                .any(|p| same_path(p, denied))
                || request
                    .policy
                    .readonly_paths
                    .iter()
                    .any(|p| same_path(p, denied))
            {
                return Err(RunnerError::Preflight(format!(
                    "path {denied:?} appears in both deniedPaths and an allow list"
                )));
            }
        }

        Ok(())
    }

    /// Translate MXC's network policy fields into a guest `NetworkPolicy`.
    ///
    /// - `allowed_hosts` non-empty → `AllowList` (only listed hosts reachable)
    /// - `blocked_hosts` non-empty → `BlockList` (listed hosts denied, rest allowed)
    /// - `default_network_policy == Block`, no host lists → `None` (networking disabled)
    /// - `default_network_policy == Allow`, no host lists → `AllowAll`
    fn network_policy_from_key(
        key: &NetworkKey,
    ) -> Result<Option<hyperlight_unikraft::NetworkPolicy>, RunnerError> {
        if !key.allowed.is_empty() {
            let allow_list = AllowList::from_hosts(&key.allowed)
                .map_err(|e| RunnerError::Preflight(format!("resolve allowed_hosts: {e}")))?;
            return Ok(Some(hyperlight_unikraft::NetworkPolicy::AllowList(
                allow_list,
            )));
        }
        if !key.blocked.is_empty() {
            let block_list = BlockList::from_hosts(&key.blocked)
                .map_err(|e| RunnerError::Preflight(format!("resolve blocked_hosts: {e}")))?;
            return Ok(Some(hyperlight_unikraft::NetworkPolicy::BlockList(
                block_list,
            )));
        }
        if key.default == NetworkPolicy::Block {
            return Ok(None);
        }
        Ok(Some(hyperlight_unikraft::NetworkPolicy::AllowAll))
    }

    /// Translate `ContainerPolicy.{readwrite,readonly}Paths` into
    /// [`Mount`] entries. Each host path is exposed inside the guest at
    /// `/host/<basename>` so scripts can find mounts predictably.
    fn mounts_from_policy(request: &ExecutionRequest) -> Result<Vec<Mount>, RunnerError> {
        let mut mounts = Vec::new();
        let mut seen_guest_paths = std::collections::HashSet::new();

        let rw_iter = request.policy.readwrite_paths.iter().map(|p| (p, false));
        let ro_iter = request.policy.readonly_paths.iter().map(|p| (p, true));

        for (host, read_only) in rw_iter.chain(ro_iter) {
            let host_path = PathBuf::from(host);

            // Auto-create the mount dir if it doesn't exist yet. The
            // host path is canonicalized below, which fails on ENOENT —
            // so without this, a relative path like "../tmp/foo" fails
            // silently just because the dir wasn't pre-created. The
            // guest still needs a real dir to read/write against;
            // mkdir-ing now matches the "config is declaratively
            // requesting this mount" semantics.
            //
            // We only create if the parent already exists — prevents
            // accidentally materializing arbitrary paths on a typo.
            if !host_path.exists() {
                let parent_ok = host_path
                    .parent()
                    .map(|p| p.as_os_str().is_empty() || p.exists())
                    .unwrap_or(false);
                if !parent_ok {
                    return Err(RunnerError::Preflight(format!(
                        "mount path {host:?} does not exist and its parent doesn't either; \
                         refusing to auto-create (fix the path or `mkdir -p` manually)"
                    )));
                }
                std::fs::create_dir_all(&host_path).map_err(|e| {
                    RunnerError::Preflight(format!("auto-create mount dir {host:?}: {e}"))
                })?;
            }

            // Canonical so the mount set compares stably across calls and
            // so a relative path keeps meaning the same directory after a
            // cwd change.
            let host_path = std::fs::canonicalize(&host_path)
                .map_err(|e| RunnerError::Preflight(format!("resolve mount path {host:?}: {e}")))?;
            let basename = host_path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| {
                    RunnerError::Preflight(format!("mount path {host:?} has no filename component"))
                })?;
            // The guest path travels to the kernel in its `vfs.fstab`
            // list, which these characters would break; the library
            // refuses them at boot, we refuse them before booting.
            if basename
                .chars()
                .any(|c| c.is_whitespace() || matches!(c, ':' | '[' | ']'))
            {
                return Err(RunnerError::Preflight(format!(
                    "mount path {host:?}: the directory name may not contain whitespace, \
                     ':' or brackets (it names the guest mount point)"
                )));
            }
            let guest_path = format!("{GUEST_MOUNT_ROOT}/{basename}");
            if !seen_guest_paths.insert(guest_path.clone()) {
                return Err(RunnerError::Preflight(format!(
                    "two mount paths collide on guest path {guest_path:?}; \
                     rename one of the host directories"
                )));
            }
            mounts.push(if read_only {
                Mount::ro(host_path, guest_path)
            } else {
                Mount::rw(host_path, guest_path)
            });
        }

        Ok(mounts)
    }

    /// Lazily bring up the guest for this configuration.
    ///
    /// The guest restores the persisted snapshot (warming and persisting
    /// one first if only the rootfs is present, a cold boot once per
    /// image) with the request's mounts and network policy; the kernel
    /// builds its mount table from them on resume. Later calls on the
    /// same runner rewind rather than boot.
    ///
    /// The mount set and network policy are fixed at boot; a change in
    /// either boots another guest from the same image.
    fn ensure_runtime(
        &mut self,
        home: &Path,
        runtime: HyperlightRuntime,
        mounts: Vec<Mount>,
        network: NetworkKey,
        logger: &mut Logger,
    ) -> Result<(&mut Guest, Arc<Snapshot>), RunnerError> {
        let same_config = self.active_home.as_deref() == Some(home)
            && mounts_equal(&self.active_mounts, &mounts)
            && self.active_network == network;
        if !same_config {
            // Host lists resolve names here, once per configuration, so a
            // guest that is already up is not held to the resolver on
            // every call.
            let policy = Self::network_policy_from_key(&network)?;
            // Nothing booted so far applies to the new configuration; the
            // image still does, unless the home changed.
            self.guest = None;
            if self.active_home.as_deref() != Some(home) {
                self.rewind = None;
            }
            self.active_home = Some(home.to_path_buf());
            self.active_mounts = mounts;
            self.active_policy = policy;
            self.active_network = network;
        }
        let rewind = match self.rewind.clone() {
            Some(rewind) => rewind,
            None => {
                configure_surrogates();
                let rewind = load_persisted_snapshot(home, runtime, logger)?;
                self.rewind = Some(rewind.clone());
                rewind
            }
        };
        let guest = match self.guest.take() {
            Some(guest) => guest,
            None => {
                configure_surrogates();
                Self::boot_from_snapshot(rewind.clone(), &self.active_mounts, &self.active_policy)?
            }
        };
        Ok((self.guest.insert(guest), rewind))
    }

    /// Restore the warm image into a new sandbox with `mounts` and
    /// `policy`: the kernel builds its mount table from them on resume,
    /// and the host serves them.
    fn boot_from_snapshot(
        rewind: Arc<Snapshot>,
        mounts: &[Mount],
        policy: &Option<hyperlight_unikraft::NetworkPolicy>,
    ) -> Result<Guest, RunnerError> {
        let builder = SandboxBuilder::from_snapshot(rewind).mounts(mounts.iter().cloned());
        let sandbox = with_network(builder, policy)
            .boot()
            .map_err(|e| RunnerError::Runtime(format!("restore hyperlight snapshot: {e}")))?;
        Ok(Guest {
            sandbox,
            fresh: true,
        })
    }

    /// One hermetic call: rewind to the warmed state (unless the guest is
    /// fresh from boot), run `code`, and report the guest's exit status.
    fn run_once(
        guest: &mut Guest,
        rewind: &Arc<Snapshot>,
        code: &str,
        timeout: Option<Duration>,
    ) -> Result<RunTiming, RunError> {
        let mut timing = RunTiming::default();
        if !guest.fresh {
            let t = Instant::now();
            guest
                .sandbox
                .restore(rewind.clone())
                .map_err(|e| RunError::Failed(format!("rewind guest: {e}")))?;
            timing.restore_ms = t.elapsed().as_secs_f64() * 1000.0;
        }
        guest.fresh = false;

        let t = Instant::now();
        let result = match timeout {
            Some(timeout) => run_with_deadline(&mut guest.sandbox, code, timeout),
            None => match guest.sandbox.run(code) {
                Ok(()) => Ok(0),
                Err(hyperlight_unikraft::Error::CallFailed { status }) => Ok(status),
                Err(e) => Err(RunError::Failed(e.to_string())),
            },
        };
        timing.call_ms = t.elapsed().as_secs_f64() * 1000.0;
        // HostPrint already wrote the guest's output to our stdout; drop
        // the copy the library keeps so it never grows across calls.
        let _ = guest.sandbox.drain_output();

        timing.exit_code = result?;
        if timing.exit_code < 0 {
            // The driver's own signal that it could not run the call; the
            // guest's output has the details.
            return Err(RunError::Failed(format!(
                "the guest driver could not run the call (status {})",
                timing.exit_code
            )));
        }
        Ok(timing)
    }
}

impl ScriptRunner for HyperlightScriptRunner {
    fn validate_runner(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        Self::validate_policies(request).map_err(|e| e.to_response())?;
        validate_network_policy_support(request, NetworkPolicySupport::LEGACY)?;
        Ok(())
    }

    fn execute(&mut self, request: &ExecutionRequest, logger: &mut Logger) -> ScriptResponse {
        let runtime = request
            .hyperlight
            .as_ref()
            .map(|h| h.runtime)
            .unwrap_or_default();
        let home = match Self::resolve_home(runtime) {
            Ok(h) => h,
            Err(e) => {
                logger.log_line(&e.to_string());
                return e.to_response();
            }
        };
        let mounts = match Self::mounts_from_policy(request) {
            Ok(m) => m,
            Err(e) => {
                logger.log_line(&e.to_string());
                return e.to_response();
            }
        };
        let (guest, rewind) = match self.ensure_runtime(
            &home,
            runtime,
            mounts,
            NetworkKey::from_request(request),
            logger,
        ) {
            Ok(pair) => pair,
            Err(e) => {
                logger.log_line(&e.to_string());
                return e.to_response();
            }
        };

        let timeout = (request.script_timeout > 0).then(|| {
            logger.log_line(&format!(
                "hyperlight: timeout set to {}ms",
                request.script_timeout
            ));
            Duration::from_millis(u64::from(request.script_timeout))
        });
        match Self::run_once(guest, &rewind, &request.script_code, timeout) {
            Ok(timing) => {
                logger.log_line(&format!(
                    "hyperlight: run ok (restore={:.1}ms call={:.1}ms exit={})",
                    timing.restore_ms, timing.call_ms, timing.exit_code
                ));
                ScriptResponse {
                    exit_code: timing.exit_code,
                    ..Default::default()
                }
            }
            Err(failure) => {
                // The guest is mid-call (blocked, killed, exited or
                // deadlocked): nothing more will run in it. Drop it; the
                // next call boots another from the rewind point.
                self.guest = None;
                let err = match failure {
                    RunError::TimedOut(timeout) => RunnerError::Runtime(format!(
                        "execution timed out after {:.1}s",
                        timeout.as_secs_f64()
                    )),
                    RunError::Failed(msg) => RunnerError::Runtime(format!("run: {msg}")),
                };
                logger.log_line(&err.to_string());
                err.to_response()
            }
        }
    }
}

// -- Guest driving -----------------------------------------------------------

/// Run `code` and wait for it, giving up at `timeout`.
///
/// The guest hands the vCPU back whenever every thread is blocked, so a
/// sleeping script is caught by bounding each `step`. A script that never
/// blocks (a busy loop) holds the vCPU inside one entry, which only an
/// interrupt from another thread can end; the watchdog fires it at the
/// deadline, and keeps firing until this thread confirms it is out, in
/// case the guest was between entries the first time. An interrupted
/// sandbox is poisoned, a merely blocked one still has the call in
/// flight: the caller discards the guest either way.
fn run_with_deadline(
    sandbox: &mut AppSandbox,
    code: &str,
    timeout: Duration,
) -> Result<i32, RunError> {
    let deadline = Instant::now() + timeout;
    // Dropped by this thread once the call is over, however it ended,
    // which wakes the watchdog at once instead of on its next tick.
    let (finished_tx, finished_rx) = mpsc::channel::<()>();
    let watchdog = {
        let handle = sandbox.interrupt_handle();
        std::thread::spawn(move || {
            let mut wait = deadline.saturating_duration_since(Instant::now());
            loop {
                match finished_rx.recv_timeout(wait) {
                    Err(RecvTimeoutError::Timeout) => {}
                    // The call is over: finished before the deadline, or
                    // the caller is gone.
                    _ => return,
                }
                // Past the deadline. `kill` breaks an entry in progress;
                // between entries (in a host call, say) it only marks the
                // next one cancelled and reports nothing, so retry until
                // the call is over either way.
                if handle.kill() {
                    return;
                }
                wait = Duration::from_millis(10);
            }
        })
    };

    let outcome = drive_until(sandbox, code, deadline);
    drop(finished_tx);
    let _ = watchdog.join();

    match outcome {
        Ok(Some(status)) => Ok(status),
        Ok(None) => Err(RunError::TimedOut(timeout)),
        // Only the watchdog kills this sandbox, and Hyperlight clears a
        // kill at the start of every entry, so a cancelled entry is this
        // call's timeout however the kill landed.
        Err(hyperlight_unikraft::Error::Hyperlight(HyperlightError::ExecutionCanceledByHost())) => {
            Err(RunError::TimedOut(timeout))
        }
        Err(e) => Err(RunError::Failed(e.to_string())),
    }
}

/// Submit `code` and step the guest until the call returns (`Some(status)`)
/// or `deadline` passes (`None`).
fn drive_until(
    sandbox: &mut AppSandbox,
    code: &str,
    deadline: Instant,
) -> Result<Option<i32>, hyperlight_unikraft::Error> {
    sandbox.submit(code)?;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        match sandbox.step(remaining)? {
            Yield::CallDone => return Ok(Some(0)),
            Yield::CallFailed { status } => return Ok(Some(status)),
            Yield::Exited { status } => {
                return Err(hyperlight_unikraft::Error::GuestExited { status })
            }
            Yield::Blocked { .. } => {}
        }
    }
}

// -- Install -----------------------------------------------------------------

/// Boot the rootfs in `home`, save the warm image beside its snapshot
/// directory and publish it there. The flag says whether the new layout
/// is what now sits in the snapshot directory; when it is not, the image
/// in memory is still this warm's and the log says what happened on disk.
fn warm_snapshot(
    home: &Path,
    runtime: HyperlightRuntime,
    logger: &mut Logger,
) -> Result<(Arc<Snapshot>, bool), RunnerError> {
    let snapshot_dir = home.join(SNAPSHOT_DIR);
    logger.log_line(&format!(
        "hyperlight: booting {:?} to warm a snapshot",
        home.join(INITRD_FILE)
    ));
    let t = Instant::now();
    configure_surrogates();
    let mut sandbox = rootfs_builder(home, runtime)
        .boot()
        .map_err(|e| RunnerError::Runtime(format!("boot hyperlight rootfs: {e}")))?;
    // Saved beside the snapshot directory, so a failed save leaves whatever
    // is there standing, then published by rename.
    let staged = home.join(format!(".{SNAPSHOT_DIR}.{}.part", std::process::id()));
    let _ = std::fs::remove_dir_all(&staged);
    let snapshot = match sandbox.snapshot_to(&staged) {
        Ok(snapshot) => snapshot,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&staged);
            return Err(RunnerError::Runtime(format!(
                "save snapshot to {staged:?}: {e}"
            )));
        }
    };
    let persisted = publish_snapshot(home, &staged, &snapshot_dir, logger);
    logger.log_line(&format!(
        "hyperlight: warm-up took {:.1}ms; snapshot at {snapshot_dir:?}",
        t.elapsed().as_secs_f64() * 1000.0
    ));
    Ok((snapshot, persisted))
}

/// Move the layout saved at `staged` into `snapshot_dir`: the old layout is
/// set aside by rename first and dropped only once the new one is in place,
/// so the directory is absent only between two renames. Two warms at once
/// each save a whole layout, and the one whose move lands is the one that
/// stays. Returns whether a fresh layout is now in place: this warm's, or
/// another warm's that landed first. Otherwise the old layout is back, or,
/// if it could not be put back either, left at its `.old` path, which the
/// log names.
fn publish_snapshot(home: &Path, staged: &Path, snapshot_dir: &Path, logger: &mut Logger) -> bool {
    let old = home.join(format!(".{SNAPSHOT_DIR}.{}.old", std::process::id()));
    let had_old = match std::fs::rename(snapshot_dir, &old) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => {
            logger.log_line(&format!(
                "hyperlight: set aside old snapshot {snapshot_dir:?}: {e}"
            ));
            let _ = std::fs::remove_dir_all(staged);
            return false;
        }
    };
    let moved = std::fs::rename(staged, snapshot_dir);
    if let Err(e) = &moved {
        logger.log_line(&format!(
            "hyperlight: move snapshot into place at {snapshot_dir:?}: {e}"
        ));
        let _ = std::fs::remove_dir_all(staged);
    }
    match (moved, had_old) {
        (Ok(()), true) => {
            let _ = std::fs::remove_dir_all(&old);
            true
        }
        (Ok(()), false) => true,
        (Err(_), true) => {
            if std::fs::rename(&old, snapshot_dir).is_ok() {
                logger.log_line(&format!(
                    "hyperlight: old snapshot put back at {snapshot_dir:?}"
                ));
                return false;
            }
            if hyperlight_unikraft::load_snapshot(snapshot_dir).is_ok() {
                // Another warm landed in the meantime; its layout stays.
                logger.log_line(&format!(
                    "hyperlight: another warm published {snapshot_dir:?} first"
                ));
                let _ = std::fs::remove_dir_all(&old);
                return true;
            }
            logger.log_line(&format!("hyperlight: old snapshot left at {old:?}"));
            false
        }
        (Err(_), false) => {
            let landed = hyperlight_unikraft::load_snapshot(snapshot_dir).is_ok();
            if landed {
                logger.log_line(&format!(
                    "hyperlight: another warm published {snapshot_dir:?} first"
                ));
            }
            landed
        }
    }
}

/// The persisted snapshot in `home`, warming and persisting one first
/// when there is none this build loads.
fn load_persisted_snapshot(
    home: &Path,
    runtime: HyperlightRuntime,
    logger: &mut Logger,
) -> Result<Arc<Snapshot>, RunnerError> {
    let snapshot_dir = home.join(SNAPSHOT_DIR);
    let unloadable = match hyperlight_unikraft::load_snapshot(&snapshot_dir) {
        Ok(snapshot) => {
            logger.log_line(&format!("hyperlight: using image home {home:?}"));
            return Ok(snapshot);
        }
        Err(e) => e,
    };
    if !has_install_source(home, runtime) {
        return Err(RunnerError::Preflight(no_install_source(runtime)));
    }
    logger.log_line(&match unloadable {
        hyperlight_unikraft::Error::SnapshotRelease { saved_by, .. } => format!(
            "hyperlight: the snapshot at {snapshot_dir:?} was saved by hyperlight-unikraft \
             {saved_by}; warming one for this build from the rootfs"
        ),
        e => format!(
            "hyperlight: no snapshot to load at {snapshot_dir:?} ({e}); warming one from the \
             rootfs"
        ),
    });
    let (snapshot, persisted) = warm_snapshot(home, runtime, logger)?;
    if !persisted {
        logger.log_line(
            "hyperlight: running from the warm image in memory; the next run warms again",
        );
    }
    Ok(snapshot)
}

/// A builder for a fresh boot of the rootfs in `home`.
fn rootfs_builder(home: &Path, runtime: HyperlightRuntime) -> SandboxBuilder {
    SandboxBuilder::from_initrd(home.join(INITRD_FILE))
        .scratch_mb(runtime_image(runtime).scratch_mb)
}

fn with_network(
    builder: SandboxBuilder,
    policy: &Option<hyperlight_unikraft::NetworkPolicy>,
) -> SandboxBuilder {
    match policy {
        Some(policy) => builder.network(policy.clone()),
        None => builder,
    }
}

/// Pull the rootfs CPIO out of the published image into `dst`, straight
/// from the registry's distribution API: no container runtime needed.
/// Staged beside `dst` and renamed into place so a failed pull leaves no
/// half-written rootfs.
fn pull_rootfs(dst: &Path, runtime: HyperlightRuntime, logger: &mut Logger) -> Result<(), String> {
    // Staged per process, so two setups at once each pull their own copy.
    let staged = dst.with_file_name(format!(".{INITRD_FILE}.{}.part", std::process::id()));
    let pulled = oci::fetch_file(
        &runtime_image(runtime).image,
        ROOTFS_TAG,
        ROOTFS_PATH_IN_IMAGE,
        &staged,
        logger,
    );
    if pulled.is_err() {
        let _ = std::fs::remove_file(&staged);
    }
    pulled?;
    // Remove the old rootfs first: on Windows, rename cannot replace an
    // existing destination.
    let _ = std::fs::remove_file(dst);
    if let Err(e) = std::fs::rename(&staged, dst) {
        let _ = std::fs::remove_file(&staged);
        return Err(format!("move rootfs into place at {dst:?}: {e}"));
    }
    Ok(())
}

/// Just enough of the OCI distribution API to take one file out of a
/// public image: an anonymous pull token, the manifest (through an index
/// if the tag names one), and the layer tarballs, extracted as they
/// stream in and checked against their digests.
mod oci {
    use std::io::Read;
    use std::path::Path;
    use std::time::Duration;

    use sha2::{Digest, Sha256};
    use wxc_common::logger::Logger;

    const MANIFEST_TYPES: &str = "application/vnd.oci.image.manifest.v1+json, \
         application/vnd.oci.image.index.v1+json, \
         application/vnd.docker.distribution.manifest.v2+json, \
         application/vnd.docker.distribution.manifest.list.v2+json";

    /// Write the file at `path_in_image` inside `image:tag` to `dst`.
    /// `image` is `<registry host>/<repository>`.
    pub(super) fn fetch_file(
        image: &str,
        tag: &str,
        path_in_image: &str,
        dst: &Path,
        logger: &mut Logger,
    ) -> Result<(), String> {
        let (registry, repo) = image
            .split_once('/')
            .ok_or_else(|| format!("image {image:?} names no registry host"))?;
        // Bounded so a dead link fails instead of hanging setup; the body
        // bound covers the largest layer on a slow link.
        let agent = ureq::Agent::config_builder()
            .timeout_resolve(Some(Duration::from_secs(30)))
            .timeout_connect(Some(Duration::from_secs(30)))
            .timeout_recv_response(Some(Duration::from_secs(60)))
            .timeout_recv_body(Some(Duration::from_secs(30 * 60)))
            .build()
            .new_agent();
        let token = pull_token(&agent, registry, repo)?;
        let get = |url: String, accept: &str| -> Result<ureq::Body, String> {
            agent
                .get(&url)
                .header("Authorization", &format!("Bearer {token}"))
                .header("Accept", accept)
                .call()
                .map(|response| response.into_body())
                .map_err(|e| format!("GET {url}: {e}"))
        };

        // A tag may name an index of per-platform manifests (a buildx push
        // adds attestation manifests under an "unknown" platform too)
        // rather than the manifest itself; take the linux/amd64 one.
        let manifests_url = format!("https://{registry}/v2/{repo}/manifests");
        let mut manifest = read_json(get(format!("{manifests_url}/{tag}"), MANIFEST_TYPES)?)?;
        if let Some(entries) = manifest.get("manifests").and_then(|m| m.as_array()) {
            let digest = entries
                .iter()
                .find(|m| {
                    m["platform"]["os"] == "linux" && m["platform"]["architecture"] == "amd64"
                })
                .and_then(|m| m["digest"].as_str())
                .ok_or_else(|| format!("{image}:{tag} has no linux/amd64 manifest"))?
                .to_string();
            manifest = read_json(get(format!("{manifests_url}/{digest}"), MANIFEST_TYPES)?)?;
        }
        let layers = manifest["layers"]
            .as_array()
            .ok_or_else(|| format!("{image}:{tag}: manifest lists no layers"))?;

        let wanted = path_in_image.trim_start_matches('/');
        let mut found = false;
        for layer in layers {
            let digest = layer["digest"]
                .as_str()
                .ok_or_else(|| format!("{image}:{tag}: a layer has no digest"))?;
            let media_type = layer["mediaType"].as_str().unwrap_or_default();
            if media_type.ends_with("zstd") {
                return Err(format!(
                    "{image}:{tag}: zstd-compressed layers are not supported"
                ));
            }
            let size_mib = layer["size"].as_u64().unwrap_or(0) / (1024 * 1024);
            logger.log_line(&format!(
                "hyperlight setup: downloading {image}:{tag} layer {digest} ({size_mib} MiB)"
            ));
            let body = get(
                format!("https://{registry}/v2/{repo}/blobs/{digest}"),
                "application/octet-stream",
            )?;
            let mut blob = Digested::new(body.into_reader());
            // A later layer's copy of the file replaces an earlier one's,
            // as it does in the image.
            found |= extract(&mut blob, media_type.ends_with("gzip"), wanted, dst)?;
            // Read to the end so the digest covers the whole blob.
            std::io::copy(&mut blob, &mut std::io::sink())
                .map_err(|e| format!("read layer {digest}: {e}"))?;
            let actual = blob.digest();
            if actual != digest {
                return Err(format!("layer {digest} arrived with digest {actual}"));
            }
        }
        if found {
            Ok(())
        } else {
            Err(format!("{image}:{tag} has no {path_in_image}"))
        }
    }

    /// An anonymous pull token for `repo` from the registry's token
    /// endpoint, in the layout GHCR uses.
    fn pull_token(agent: &ureq::Agent, registry: &str, repo: &str) -> Result<String, String> {
        let url = format!("https://{registry}/token?scope=repository:{repo}:pull");
        let body = agent
            .get(&url)
            .call()
            .map(|response| response.into_body())
            .map_err(|e| format!("GET {url}: {e}"))?;
        read_json(body)?["token"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| format!("{registry} token response carries no token"))
    }

    fn read_json(mut body: ureq::Body) -> Result<serde_json::Value, String> {
        let bytes = body
            .read_to_vec()
            .map_err(|e| format!("read response: {e}"))?;
        serde_json::from_slice(&bytes).map_err(|e| format!("parse response: {e}"))
    }

    /// Walk one layer tarball, writing the `wanted` entry to `dst` if it
    /// is there.
    fn extract(
        blob: &mut impl Read,
        gzipped: bool,
        wanted: &str,
        dst: &Path,
    ) -> Result<bool, String> {
        let reader: Box<dyn Read + '_> = if gzipped {
            Box::new(flate2::read::GzDecoder::new(blob))
        } else {
            Box::new(blob)
        };
        let mut archive = tar::Archive::new(reader);
        let mut found = false;
        for entry in archive.entries().map_err(|e| format!("read layer: {e}"))? {
            let mut entry = entry.map_err(|e| format!("read layer entry: {e}"))?;
            let is_wanted = {
                let path = entry.path().map_err(|e| format!("read layer entry: {e}"))?;
                let name = path.to_string_lossy();
                name.trim_start_matches("./").trim_start_matches('/') == wanted
            };
            if !is_wanted {
                continue;
            }
            if !entry.header().entry_type().is_file() {
                return Err(format!("{wanted} in the layer is not a regular file"));
            }
            let mut file =
                std::fs::File::create(dst).map_err(|e| format!("create {dst:?}: {e}"))?;
            let written =
                std::io::copy(&mut entry, &mut file).map_err(|e| format!("write {dst:?}: {e}"))?;
            if written == 0 {
                return Err(format!("{wanted} in the layer is empty"));
            }
            found = true;
            break;
        }
        Ok(found)
    }

    /// A reader that keeps the SHA-256 of everything read through it.
    struct Digested<R> {
        inner: R,
        hasher: Sha256,
    }

    impl<R: Read> Digested<R> {
        fn new(inner: R) -> Self {
            Self {
                inner,
                hasher: Sha256::new(),
            }
        }

        /// The digest of everything read so far, in the registry's
        /// `sha256:<hex>` form.
        fn digest(&self) -> String {
            format!("sha256:{:x}", self.hasher.clone().finalize())
        }
    }

    impl<R: Read> Read for Digested<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.hasher.update(&buf[..n]);
            Ok(n)
        }
    }
}

/// One guest per process: the runner holds at most one sandbox, and the
/// warm boot is dropped before the restore boots, so Hyperlight's
/// single-VM mode fits and skips its 512 pre-spawned helper processes on
/// Windows (about 3.5 s on first boot). Must run before any sandbox
/// exists; later calls are no-ops.
fn configure_surrogates() {
    #[cfg(windows)]
    hyperlight_unikraft::configure_surrogates(0);
}

// -- Helpers -----------------------------------------------------------------

/// A home has a snapshot this build loads, beside no rootfs of another
/// release. The rootfs is only needed to warm, not to run.
fn is_installed(home: &Path, runtime: HyperlightRuntime) -> bool {
    stamp_matches(home, runtime)
        && hyperlight_unikraft::load_snapshot(home.join(SNAPSHOT_DIR)).is_ok()
}

/// A home has a rootfs of this release — enough to warm a snapshot from.
/// A rootfs with no stamp (dropped in by hand) is taken on trust; one
/// stamped for another release is not, since it will not boot on this
/// release's kernel.
fn has_install_source(home: &Path, runtime: HyperlightRuntime) -> bool {
    home.join(INITRD_FILE).is_file() && stamp_matches(home, runtime)
}

fn version_stamp(runtime: HyperlightRuntime) -> String {
    format!("rootfs: {}:{ROOTFS_TAG}\n", runtime_image(runtime).image)
}

fn stamp_matches(home: &Path, runtime: HyperlightRuntime) -> bool {
    match std::fs::read_to_string(home.join(VERSION_FILE)) {
        Ok(stamp) => stamp.trim() == version_stamp(runtime).trim(),
        Err(e) => e.kind() == std::io::ErrorKind::NotFound,
    }
}

/// Paths equal after canonicalization (best-effort).
fn same_path(a: &str, b: &str) -> bool {
    let ap = std::fs::canonicalize(a).unwrap_or_else(|_| PathBuf::from(a));
    let bp = std::fs::canonicalize(b).unwrap_or_else(|_| PathBuf::from(b));
    ap == bp
}

fn mounts_equal(a: &[Mount], b: &[Mount]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b.iter()).all(|(x, y)| {
            x.host_path == y.host_path && x.guest_path == y.guest_path && x.readonly == y.readonly
        })
}

/// OS-local data directory (the "user Application Data" root).
///
/// - Linux: `$XDG_DATA_HOME` if set and absolute, else `$HOME/.local/share`.
/// - Windows: `%LOCALAPPDATA%` if set, else `$USERPROFILE\AppData\Local`.
///
/// Returns `PathBuf::from(".")` if no candidate env vars are set (degrades
/// gracefully rather than panicking; caller can still override via
/// `$MXC_HYPERLIGHT_HOME`).
fn os_data_home() -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(v) = std::env::var_os("LOCALAPPDATA") {
            return PathBuf::from(v);
        }
        if let Some(v) = std::env::var_os("USERPROFILE") {
            return PathBuf::from(v).join("AppData").join("Local");
        }
        PathBuf::from(".")
    }
    #[cfg(not(windows))]
    {
        if let Some(v) = std::env::var_os("XDG_DATA_HOME") {
            let p = PathBuf::from(v);
            if p.is_absolute() {
                return p;
            }
        }
        if let Some(v) = std::env::var_os("HOME") {
            return PathBuf::from(v).join(".local").join("share");
        }
        PathBuf::from(".")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::logger::Mode;
    use wxc_common::models::{ContainerPolicy, NetworkPolicy};

    fn runner() -> HyperlightScriptRunner {
        HyperlightScriptRunner::new()
    }

    fn fresh_tmp(tag: &str) -> PathBuf {
        let tmp = std::env::temp_dir().join(format!("hl-runner-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        tmp
    }

    #[test]
    fn is_installed_false_on_empty_dir() {
        let tmp = fresh_tmp("empty");
        assert!(!is_installed(&tmp, HyperlightRuntime::Agent));
        assert!(!has_install_source(&tmp, HyperlightRuntime::Agent));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn has_install_source_true_when_rootfs_present() {
        let tmp = fresh_tmp("install-src");
        std::fs::write(tmp.join(INITRD_FILE), b"").unwrap();
        assert!(has_install_source(&tmp, HyperlightRuntime::Agent));
        assert!(!is_installed(&tmp, HyperlightRuntime::Agent)); // snapshot still absent
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn rootfs_stamped_for_another_release_is_not_an_install_source() {
        let tmp = fresh_tmp("stale");
        std::fs::write(tmp.join(INITRD_FILE), b"").unwrap();
        // A stamp from an earlier release than ROOTFS_TAG names.
        let agent = HyperlightRuntime::Agent;
        std::fs::write(
            tmp.join(VERSION_FILE),
            format!("rootfs: {}:initrd-v0.13.0\n", runtime_image(agent).image),
        )
        .unwrap();
        assert!(!has_install_source(&tmp, agent));
        assert!(!is_installed(&tmp, agent));

        std::fs::write(tmp.join(VERSION_FILE), version_stamp(agent)).unwrap();
        assert!(has_install_source(&tmp, agent));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn rootfs_tag_follows_the_pinned_crate_release() {
        let manifest =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap();
        let line = manifest
            .lines()
            .find(|l| l.starts_with("hyperlight-unikraft = "))
            .expect("the crate dependency line");
        let version = line
            .split("version = \"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .expect("a pinned version");
        assert_eq!(ROOTFS_TAG, format!("initrd-v{version}"));
    }

    #[test]
    fn a_runtime_only_takes_its_own_rootfs() {
        let tmp = fresh_tmp("runtimes");
        let agent = tmp.join(HyperlightRuntime::Agent.name());
        let node = tmp.join(HyperlightRuntime::Node.name());
        for dir in [&agent, &node] {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::write(dir.join(INITRD_FILE), b"").unwrap();
            std::fs::write(
                dir.join(VERSION_FILE),
                version_stamp(HyperlightRuntime::Agent),
            )
            .unwrap();
        }
        assert!(has_install_source(&agent, HyperlightRuntime::Agent));
        assert!(!has_install_source(&node, HyperlightRuntime::Node));
        std::fs::write(
            node.join(VERSION_FILE),
            version_stamp(HyperlightRuntime::Node),
        )
        .unwrap();
        assert!(has_install_source(&node, HyperlightRuntime::Node));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn resolve_home_errors_when_nothing_configured() {
        // Redirect every candidate away from any real install on the
        // test machine: MXC_HYPERLIGHT_HOME, XDG_DATA_HOME (Linux), LOCALAPPDATA
        // (Windows), HOME/USERPROFILE all get pointed into an empty
        // tmpdir for the duration of this test.
        let empty = fresh_tmp("resolve-empty");

        let saved: Vec<(&str, Option<std::ffi::OsString>)> = [
            HOME_ENV,
            "XDG_DATA_HOME",
            "HOME",
            "LOCALAPPDATA",
            "USERPROFILE",
        ]
        .iter()
        .map(|k| (*k, std::env::var_os(k)))
        .collect();
        // SAFETY: tests are serialized by default in this crate.
        unsafe {
            for (k, _) in &saved {
                std::env::remove_var(k);
            }
            std::env::set_var("HOME", &empty);
            std::env::set_var("USERPROFILE", &empty);
            std::env::set_var("XDG_DATA_HOME", &empty);
            std::env::set_var("LOCALAPPDATA", &empty);
        }

        let result = HyperlightScriptRunner::resolve_home(HyperlightRuntime::Agent);

        // Restore env before asserting so a failing assert can't leak.
        unsafe {
            for (k, v) in &saved {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
        let _ = std::fs::remove_dir_all(&empty);

        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("no hyperlight image found"),
            "got: {err}"
        );
    }

    #[test]
    fn policy_accepts_readwrite_paths_and_builds_mounts() {
        // We can't end-to-end test without a real image; just verify
        // the policy→Mount mapping.
        let tmp = fresh_tmp("mount");
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec![tmp.to_string_lossy().to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let mounts = HyperlightScriptRunner::mounts_from_policy(&request).unwrap();
        assert_eq!(mounts.len(), 1);
        assert_eq!(
            mounts[0].guest_path,
            format!("/host/{}", tmp.file_name().unwrap().to_string_lossy())
        );
        assert!(!mounts[0].readonly);
        assert_eq!(mounts[0].host_path, std::fs::canonicalize(&tmp).unwrap());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn policy_marks_readonly_paths() {
        let tmp = fresh_tmp("mount-ro");
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                readonly_paths: vec![tmp.to_string_lossy().to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let mounts = HyperlightScriptRunner::mounts_from_policy(&request).unwrap();
        assert_eq!(mounts.len(), 1);
        assert!(mounts[0].readonly);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn policy_rejects_mount_collision_on_same_basename() {
        let a = std::env::temp_dir().join(format!("hl-col-a-{}/same", std::process::id()));
        let b = std::env::temp_dir().join(format!("hl-col-b-{}/same", std::process::id()));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec![
                    a.to_string_lossy().to_string(),
                    b.to_string_lossy().to_string(),
                ],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = HyperlightScriptRunner::mounts_from_policy(&request).unwrap_err();
        assert!(
            err.to_string().contains("collide on guest path"),
            "got: {err}"
        );
        let _ = std::fs::remove_dir_all(a.parent().unwrap());
        let _ = std::fs::remove_dir_all(b.parent().unwrap());
    }

    #[test]
    fn policy_rejects_mount_name_the_kernel_cannot_carry() {
        let tmp = fresh_tmp("mount-bad").join("with space");
        std::fs::create_dir_all(&tmp).unwrap();
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec![tmp.to_string_lossy().to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = HyperlightScriptRunner::mounts_from_policy(&request).unwrap_err();
        assert!(
            err.to_string().contains("may not contain whitespace"),
            "got: {err}"
        );
        let _ = std::fs::remove_dir_all(tmp.parent().unwrap());
    }

    #[test]
    fn policy_rejects_denied_overlapping_allow() {
        let mut r = runner();
        let request = ExecutionRequest {
            script_code: "print('x')".to_string(),
            policy: ContainerPolicy {
                readwrite_paths: vec!["/tmp/x".to_string()],
                denied_paths: vec!["/tmp/x".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let mut logger = Logger::new(Mode::Buffer);
        let resp = r.run(&request, &mut logger);
        assert_eq!(resp.exit_code, ERROR_EXIT_CODE);
        assert!(resp.error_message.contains("deniedPaths"));
    }

    #[test]
    fn network_key_tells_an_allow_list_from_a_block_list() {
        let allow = ExecutionRequest {
            policy: ContainerPolicy {
                allowed_hosts: vec!["a.example".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let block = ExecutionRequest {
            policy: ContainerPolicy {
                blocked_hosts: vec!["a.example".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert_ne!(
            NetworkKey::from_request(&allow),
            NetworkKey::from_request(&block)
        );
        assert_eq!(
            NetworkKey::from_request(&allow),
            NetworkKey::from_request(&allow)
        );
    }

    #[test]
    fn network_policy_allow_all_when_default_allow() {
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                default_network_policy: NetworkPolicy::Allow,
                ..Default::default()
            },
            ..Default::default()
        };
        let policy =
            HyperlightScriptRunner::network_policy_from_key(&NetworkKey::from_request(&request))
                .unwrap();
        assert!(matches!(
            policy,
            Some(hyperlight_unikraft::NetworkPolicy::AllowAll)
        ));
    }

    #[test]
    fn network_policy_allowlist_from_allowed_hosts() {
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                allowed_hosts: vec!["127.0.0.1".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let policy =
            HyperlightScriptRunner::network_policy_from_key(&NetworkKey::from_request(&request))
                .unwrap();
        assert!(matches!(
            policy,
            Some(hyperlight_unikraft::NetworkPolicy::AllowList(_))
        ));
    }

    #[test]
    fn network_policy_none_when_blocked() {
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                default_network_policy: NetworkPolicy::Block,
                ..Default::default()
            },
            ..Default::default()
        };
        let policy =
            HyperlightScriptRunner::network_policy_from_key(&NetworkKey::from_request(&request))
                .unwrap();
        assert!(policy.is_none());
    }

    #[test]
    fn network_policy_blocklist_from_blocked_hosts() {
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                default_network_policy: NetworkPolicy::Allow,
                blocked_hosts: vec!["127.0.0.1".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let policy =
            HyperlightScriptRunner::network_policy_from_key(&NetworkKey::from_request(&request))
                .unwrap();
        assert!(matches!(
            policy,
            Some(hyperlight_unikraft::NetworkPolicy::BlockList(_))
        ));
    }

    #[test]
    fn policy_rejects_blocklist_without_allowlist_under_block_default() {
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                blocked_hosts: vec!["127.0.0.1".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        let error = runner().validate_runner(&request).unwrap_err();
        assert_eq!(
            error.error_message,
            "blockedHosts requires allowedHosts when network.defaultPolicy='block'"
        );
    }

    #[test]
    fn policy_rejects_allowlist_under_allow_default() {
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                default_network_policy: NetworkPolicy::Allow,
                allowed_hosts: vec!["127.0.0.1".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        let error = runner().validate_runner(&request).unwrap_err();
        assert_eq!(
            error.error_message,
            "allowedHosts requires network.defaultPolicy='block'"
        );
    }

    #[test]
    fn policy_rejects_allowed_and_blocked_hosts() {
        let mut r = runner();
        let request = ExecutionRequest {
            script_code: "print('x')".to_string(),
            policy: ContainerPolicy {
                allowed_hosts: vec!["a.com".to_string()],
                blocked_hosts: vec!["b.com".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let mut logger = Logger::new(Mode::Buffer);
        let resp = r.run(&request, &mut logger);
        assert_eq!(resp.exit_code, ERROR_EXIT_CODE);
        assert!(resp.error_message.contains("mutually exclusive"));
    }

    #[test]
    fn policy_rejects_working_directory() {
        let mut r = runner();
        let request = ExecutionRequest {
            script_code: "print('x')".to_string(),
            working_directory: "C:/tmp".to_string(),
            ..Default::default()
        };
        let mut logger = Logger::new(Mode::Buffer);
        let resp = r.run(&request, &mut logger);
        assert_eq!(resp.exit_code, ERROR_EXIT_CODE);
        assert!(resp.error_message.contains(ERR_WORKDIR));
    }
}
