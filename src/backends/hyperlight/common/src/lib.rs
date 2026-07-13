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
//! micro-VM, driven by the `hyperlight-unikraft::pyhl` library.
//!
//! | Property            | Value                                                     |
//! |---------------------|-----------------------------------------------------------|
//! | Backing micro-VM    | Unikraft unikernel in a Hyperlight micro-VM               |
//! | Host platform       | Linux (KVM) + Windows (WHP)                               |
//! | Execution model     | Embedded library, in-process                              |
//! | Script delivery     | Direct `Runtime::run_code(&str)`                          |
//! | Cold start          | Snapshot restore (~50–60 ms)                              |
//! | Filesystem          | Host dir mounts via `Preopen`                             |
//! | Networking          | Host-proxied sockets via `NetworkPolicy`                  |
//! | Script I/O          | Host's stdout/stderr (host_print)                         |
//! | stdlib coverage     | Full CPython + preloaded ML stack (numpy, pandas, etc.)   |
//!
//! ## Image-home resolution
//!
//! The runner looks for a warmed image in this order, first hit wins:
//!
//!   1. `$PYHL_HOME` (override — if set, must be a usable install)
//!   2. `~/.local/share/pyhl/` on Linux (XDG_DATA_HOME compliant)
//!      `%LOCALAPPDATA%\pyhl\` on Windows
//!   3. `<exe_dir>/pyhl/` (dev build next to the target binary)
//!   4. `<cwd>/.pyhl/` (dev fallback, same as pyhl's own CLI)
//!
//! Path #2 is the "default". `--setup-hyperlight` installs here when nothing
//! else is already populated — so one eager install persists across
//! shell sessions, across reboots, and across `cargo install` upgrades.
//!
//! ## Setup
//!
//! `lxc-exec --setup-hyperlight` (or `wxc-exec --setup-hyperlight`) installs the
//! warm snapshot. It pulls the published kernel + initrd from GHCR
//! via docker or podman, warms them
//! up, and persists a snapshot to the default home — zero
//! configuration beyond having docker/podman on `$PATH`.
//!
//! On first `run` (if setup was skipped) the runner also does a lazy
//! auto-install if kernel+initrd are already in the resolved home
//! but no snapshot is — cheap safety net.
//!
//! ## Filesystem policy
//!
//! `policy.readwritePaths` and `policy.readonlyPaths` are translated to
//! [`Preopen`] entries — the guest sees the host directories at
//! `/host/<basename>` and can read/write through them via `lib/hostfs`.
//! `readonlyPaths` are mounted with `Preopen::read_only()`, which blocks
//! all write operations (`fs_write`, `fs_mkdir`, `fs_unlink`, etc.) at
//! the host-function level.
//!
//! `policy.deniedPaths` is honored: any path that appears in the denied
//! list is rejected at preflight — including paths that also appear in
//! the allow lists.
//!
//! ## I/O model
//!
//! The guest's `print(...)` goes through Hyperlight's host_print callback,
//! which writes to the **host process's stdout**. `ScriptResponse.standard_out`
//! and `standard_err` stay empty; consumers that need captured output
//! redirect wxc-exec's stdout/stderr at the process level.
//!
//! ## Exit codes
//!
//! Guest exit code on clean `run_code` completion (0 for normal exit,
//! non-zero for `sys.exit(N)` or unhandled exceptions), -1 on any
//! runner error (preflight, install, runtime, guest crash). The specific
//! failure mode is in `error_message`.

use std::path::{Path, PathBuf};

use wxc_common::logger::Logger;
use wxc_common::models::{ExecutionRequest, NetworkPolicy, ScriptResponse};
use wxc_common::script_runner::ScriptRunner;

use hyperlight_unikraft::pyhl;
use hyperlight_unikraft::{AllowList, BlockList, Preopen};

// -- Error classification ----------------------------------------------------

#[derive(Debug)]
enum PyhlError {
    /// Pre-spawn validation failures (missing image, unsupported policy).
    Preflight(String),
    /// Runtime construction, install, or execution failure.
    Runtime(String),
}

impl std::fmt::Display for PyhlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PyhlError::Preflight(msg) => write!(f, "hyperlight preflight error: {msg}"),
            PyhlError::Runtime(msg) => write!(f, "hyperlight runtime error: {msg}"),
        }
    }
}

impl PyhlError {
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
/// data path (~/.local/share/pyhl on Linux, %LOCALAPPDATA%\pyhl on
/// Windows).
const PYHL_HOME_ENV: &str = "PYHL_HOME";
/// Subdirectory used next to the running executable (dev builds).
const EXE_RELATIVE_HOME: &str = "pyhl";
/// Subdirectory used in the cwd as a last resort (dev fallback).
const CWD_RELATIVE_HOME: &str = ".pyhl";
/// Final component of the default OS-local data path.
const DEFAULT_HOME_LEAF: &str = "pyhl";

// The filenames the installer writes; duplicated here to avoid a
// compile-time dep on internal path constants.
const KERNEL_FILE: &str = "kernel";
const INITRD_FILE: &str = "initrd.cpio";
const SNAPSHOT_DIR: &str = "snapshot";

const ERR_PROXY_POLICY: &str = "network proxy is not supported by the hyperlight backend";
const ERR_WORKDIR: &str =
    "workingDirectory is not supported by the hyperlight backend -- guest has its own filesystem namespace";
const ERR_NO_INSTALL_SOURCE: &str =
    "no warmed snapshot and no kernel/initrd to install from. drop `kernel` and `initrd.cpio` \
     into the image home (or run `--setup-hyperlight`).";

// -- Runner ------------------------------------------------------------------

/// Script runner that executes Python code inside a Hyperlight+Unikraft
/// micro-VM.
///
/// Lazily instantiates the runtime on the first call (loading the
/// persisted snapshot, auto-installing it first if needed) and reuses
/// it across subsequent calls on the same runner instance. Every
/// `run_code` rewinds the guest to the post-warmup snapshot so
/// consecutive calls are hermetic.
pub struct HyperlightScriptRunner {
    runtime: Option<pyhl::Runtime>,
    active_home: Option<PathBuf>,
    active_preopens: Vec<Preopen>,
    active_network_hosts: Vec<String>,
    active_network_default: NetworkPolicy,
}

impl Default for HyperlightScriptRunner {
    fn default() -> Self {
        Self::new()
    }
}

/// Eagerly install the warmed snapshot so the *first* run later
/// pays no warmup cost. Intended to be called from a tool install
/// step (npm postinstall, a `--setup-hyperlight` CLI flag, CI, etc.).
///
/// Pulls the published `kernel` + `initrd.cpio` from GHCR
/// via docker or podman, runs warmup, and
/// persists the snapshot to disk. Zero configuration beyond having
/// docker/podman on `$PATH`.
///
/// # Destination
///
/// `$PYHL_HOME` if set, otherwise the OS-local default
/// (`~/.local/share/pyhl` on Linux, `%LOCALAPPDATA%\pyhl` on
/// Windows). We intentionally do NOT walk the runtime search chain
/// here — that would let a stale `<cwd>/.pyhl/` from an old dev
/// session short-circuit the install and leave the default home
/// empty, which would make later runs from a different cwd fail.
///
/// # Force
///
/// When `force` is false, an existing snapshot is a no-op. When
/// `force` is true, the snapshot is rebuilt.
pub fn setup(force: bool, logger: &mut Logger) -> Result<PathBuf, String> {
    let home = match std::env::var_os(PYHL_HOME_ENV) {
        Some(v) => PathBuf::from(v),
        None => HyperlightScriptRunner::default_home(),
    };

    if !force && is_installed(&home) {
        logger.log_line(&format!(
            "hyperlight: snapshot already present at {:?}; nothing to do \
             (pass --force to rebuild)",
            home.join(SNAPSHOT_DIR)
        ));
        return Ok(home.join(SNAPSHOT_DIR));
    }

    std::fs::create_dir_all(&home).map_err(|e| format!("create image home {home:?}: {e}"))?;

    logger.log_line("hyperlight setup: pulling image from GHCR (docker/podman)");
    let opts = pyhl::InstallOptions {
        home: &home,
        source: pyhl::InstallSource::Ghcr {
            tag: Some("v0.12.1"),
        },
        mounts: &[],
        network: None,
        listen_ports: None,
        max_surrogates: None,
        force,
    };
    let report = pyhl::install(&opts).map_err(|e| format!("hyperlight install: {e:#}"))?;
    logger.log_line(&format!(
        "hyperlight: install complete (warmup={:.1}ms, snapshot at {:?})",
        report.warmup_ms, report.snapshot
    ));
    Ok(report.snapshot)
}

impl HyperlightScriptRunner {
    pub fn new() -> Self {
        Self {
            runtime: None,
            active_home: None,
            active_preopens: Vec::new(),
            active_network_hosts: Vec::new(),
            active_network_default: NetworkPolicy::default(),
        }
    }

    /// Resolve the image home for a normal run. Walks the
    /// discovery chain (see module doc) and returns the first
    /// location that has at least kernel + initrd — snapshot may be
    /// missing, the runner will install it.
    fn resolve_home() -> Result<PathBuf, PyhlError> {
        for cand in Self::search_paths() {
            if has_install_source(&cand) || is_installed(&cand) {
                return Ok(cand);
            }
        }
        let default = Self::default_home();
        Err(PyhlError::Preflight(format!(
            "no hyperlight image found. searched ${PYHL_HOME_ENV}, {default:?}, \
             <exe>/{EXE_RELATIVE_HOME}/, <cwd>/{CWD_RELATIVE_HOME}/. \
             run `lxc-exec --setup-hyperlight` \
             (or drop `{KERNEL_FILE}` and `{INITRD_FILE}` into {default:?})."
        )))
    }

    /// Candidate locations, in priority order.
    fn search_paths() -> Vec<PathBuf> {
        let mut paths = Vec::with_capacity(4);
        if let Some(explicit) = std::env::var_os(PYHL_HOME_ENV) {
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
    /// in the resolution chain (after $PYHL_HOME).
    ///
    /// - Linux: `$XDG_DATA_HOME/pyhl` (or `~/.local/share/pyhl`)
    /// - Windows: `%LOCALAPPDATA%\pyhl` (or `~\AppData\Local\pyhl`)
    fn default_home() -> PathBuf {
        os_data_home().join(DEFAULT_HOME_LEAF)
    }

    /// Reject only policies that the hyperlight backend genuinely cannot honor.
    /// Filesystem mounts and network policies ARE supported.
    fn validate_policies(request: &ExecutionRequest) -> Result<(), PyhlError> {
        if request.policy.network_proxy.is_enabled() {
            return Err(PyhlError::Preflight(ERR_PROXY_POLICY.to_string()));
        }
        if !request.working_directory.is_empty() {
            return Err(PyhlError::Preflight(ERR_WORKDIR.to_string()));
        }
        if !request.policy.allowed_hosts.is_empty() && !request.policy.blocked_hosts.is_empty() {
            return Err(PyhlError::Preflight(
                "allowedHosts and blockedHosts are mutually exclusive".to_string(),
            ));
        }

        // Denied paths: block early if any appears in the allow lists.
        // Also reject a config that only specifies denies — there's no
        // positive policy to apply and an attacker might be probing.
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
                return Err(PyhlError::Preflight(format!(
                    "path {denied:?} appears in both deniedPaths and an allow list"
                )));
            }
        }

        Ok(())
    }

    /// Translate MXC's network policy fields into a pyhl `NetworkPolicy`.
    ///
    /// - `allowed_hosts` non-empty → `AllowList` (only listed hosts reachable)
    /// - `blocked_hosts` non-empty → `BlockList` (listed hosts denied, rest allowed)
    /// - `default_network_policy == Block`, no host lists → `None` (networking disabled)
    /// - `default_network_policy == Allow`, no host lists → `AllowAll`
    fn network_policy_from_request(
        request: &ExecutionRequest,
    ) -> Result<Option<hyperlight_unikraft::NetworkPolicy>, PyhlError> {
        if !request.policy.allowed_hosts.is_empty() {
            let allow_list = AllowList::from_hosts(&request.policy.allowed_hosts)
                .map_err(|e| PyhlError::Preflight(format!("resolve allowed_hosts: {e:#}")))?;
            return Ok(Some(hyperlight_unikraft::NetworkPolicy::AllowList(
                allow_list,
            )));
        }
        if !request.policy.blocked_hosts.is_empty() {
            let block_list = BlockList::from_hosts(&request.policy.blocked_hosts)
                .map_err(|e| PyhlError::Preflight(format!("resolve blocked_hosts: {e:#}")))?;
            return Ok(Some(hyperlight_unikraft::NetworkPolicy::BlockList(
                block_list,
            )));
        }
        if request.policy.default_network_policy == NetworkPolicy::Block {
            return Ok(None);
        }
        Ok(Some(hyperlight_unikraft::NetworkPolicy::AllowAll))
    }

    /// Translate `ContainerPolicy.{readwrite,readonly}Paths` into
    /// `Preopen` entries. Each host path is exposed inside the guest at
    /// `/host/<basename>` — matches the `pyhl` CLI's `--mount <host>` default
    /// shape so scripts can find mounts predictably.
    ///
    /// `readonlyPaths` are mounted with `Preopen::read_only()`, blocking
    /// all write operations at the host-function level.
    fn preopens_from_policy(request: &ExecutionRequest) -> Result<Vec<Preopen>, PyhlError> {
        let mut preopens = Vec::new();
        let mut seen_guest_paths = std::collections::HashSet::new();

        let rw_iter = request.policy.readwrite_paths.iter().map(|p| (p, false));
        let ro_iter = request.policy.readonly_paths.iter().map(|p| (p, true));

        for (host, read_only) in rw_iter.chain(ro_iter) {
            let host_path = PathBuf::from(host);

            // Auto-create the mount dir if it doesn't exist yet.
            // `Preopen::new` canonicalizes the host path, which fails on
            // ENOENT — so without this, a relative path like
            // "../tmp/foo" fails silently just because the dir wasn't
            // pre-created. The guest's hostfs still needs a real dir to
            // read/write against; mkdir-ing now matches the "config is
            // declaratively requesting this mount" semantics.
            //
            // We only create if the parent already exists — prevents
            // accidentally materializing arbitrary paths on a typo.
            if !host_path.exists() {
                let parent_ok = host_path
                    .parent()
                    .map(|p| p.as_os_str().is_empty() || p.exists())
                    .unwrap_or(false);
                if !parent_ok {
                    return Err(PyhlError::Preflight(format!(
                        "mount path {host:?} does not exist and its parent doesn't either; \
                         refusing to auto-create (fix the path or `mkdir -p` manually)"
                    )));
                }
                std::fs::create_dir_all(&host_path).map_err(|e| {
                    PyhlError::Preflight(format!("auto-create mount dir {host:?}: {e}"))
                })?;
            }

            let basename = host_path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| {
                    PyhlError::Preflight(format!("mount path {host:?} has no filename component"))
                })?;
            let guest_path = format!("/host/{basename}");
            if !seen_guest_paths.insert(guest_path.clone()) {
                return Err(PyhlError::Preflight(format!(
                    "two mount paths collide on guest path {guest_path:?}; \
                     rename one of the host directories"
                )));
            }
            let mut pre = Preopen::new(&host_path, &guest_path).map_err(|e| {
                PyhlError::Preflight(format!(
                    "build Preopen for {host:?} -> {guest_path:?}: {e:#}"
                ))
            })?;
            if read_only {
                pre = pre.read_only();
            }
            preopens.push(pre);
        }

        Ok(preopens)
    }

    /// Lazily bring up the embedded Hyperlight runtime.
    ///
    /// If the persisted snapshot is missing but kernel + initrd are
    /// present, run install in-line (warmup boot + persist, cost
    /// ~1.5–2 s, once per image). Subsequent runners on the same home
    /// go straight to restore.
    ///
    /// The mount set is baked into the runtime at construction time;
    /// different preopens between calls force a full teardown + rebuild.
    fn ensure_runtime(
        &mut self,
        home: &Path,
        preopens: Vec<Preopen>,
        network: Option<hyperlight_unikraft::NetworkPolicy>,
        network_hosts: &[String],
        network_default: NetworkPolicy,
        logger: &mut Logger,
    ) -> Result<&mut pyhl::Runtime, PyhlError> {
        let same_home = self.active_home.as_deref() == Some(home);
        let same_mounts = preopens_equal(&self.active_preopens, &preopens);
        let mut sorted_hosts = network_hosts.to_vec();
        sorted_hosts.sort();
        sorted_hosts.dedup();
        let same_network = self.active_network_hosts == sorted_hosts
            && self.active_network_default == network_default;
        // `if let Some(rt) = self.runtime.as_mut()` trips the borrow
        // checker because a later branch reassigns `self.runtime`.
        #[allow(clippy::unnecessary_unwrap)]
        if same_home && same_mounts && same_network && self.runtime.is_some() {
            return Ok(self.runtime.as_mut().unwrap());
        }
        // Drop any prior runtime before rebuilding against new state.
        self.runtime = None;

        // Auto-install on first use. Install is idempotent when the
        // snapshot already exists (`force: false`).
        if !is_installed(home) {
            if !has_install_source(home) {
                return Err(PyhlError::Preflight(ERR_NO_INSTALL_SOURCE.to_string()));
            }
            logger.log_line(&format!(
                "hyperlight: no snapshot at {:?}; auto-installing from kernel + initrd",
                home.join(SNAPSHOT_DIR)
            ));
            let kernel = home.join(KERNEL_FILE);
            let initrd = home.join(INITRD_FILE);
            let opts = pyhl::InstallOptions {
                home,
                source: pyhl::InstallSource::Explicit {
                    kernel: &kernel,
                    initrd: &initrd,
                },
                mounts: &preopens,
                network: network.as_ref(),
                listen_ports: None,
                max_surrogates: None,
                force: false,
            };
            let report = pyhl::install(&opts)
                .map_err(|e| PyhlError::Runtime(format!("hyperlight install: {e:#}")))?;
            logger.log_line(&format!(
                "hyperlight: install complete (warmup={:.1}ms, snapshot at {:?})",
                report.warmup_ms, report.snapshot
            ));
        }

        logger.log_line(&format!("hyperlight: using image home {home:?}"));
        let rt = pyhl::Runtime::new(home, &preopens, network.as_ref(), None, None)
            .map_err(|e| PyhlError::Runtime(format!("open hyperlight runtime: {e:#}")))?;
        self.runtime = Some(rt);
        self.active_home = Some(home.to_path_buf());
        self.active_preopens = preopens;
        self.active_network_hosts = sorted_hosts;
        self.active_network_default = network_default;
        Ok(self.runtime.as_mut().unwrap())
    }
}

impl ScriptRunner for HyperlightScriptRunner {
    fn validate_runner(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        Self::validate_policies(request).map_err(|e| e.to_response())
    }

    fn execute(&mut self, request: &ExecutionRequest, logger: &mut Logger) -> ScriptResponse {
        let home = match Self::resolve_home() {
            Ok(h) => h,
            Err(e) => {
                logger.log_line(&e.to_string());
                return e.to_response();
            }
        };
        let preopens = match Self::preopens_from_policy(request) {
            Ok(p) => p,
            Err(e) => {
                logger.log_line(&e.to_string());
                return e.to_response();
            }
        };
        let network = match Self::network_policy_from_request(request) {
            Ok(n) => n,
            Err(e) => {
                logger.log_line(&e.to_string());
                return e.to_response();
            }
        };

        let network_hosts = if !request.policy.allowed_hosts.is_empty() {
            &request.policy.allowed_hosts
        } else {
            &request.policy.blocked_hosts
        };
        let rt = match self.ensure_runtime(
            &home,
            preopens,
            network,
            network_hosts,
            request.policy.default_network_policy.clone(),
            logger,
        ) {
            Ok(rt) => rt,
            Err(e) => {
                logger.log_line(&e.to_string());
                return e.to_response();
            }
        };

        let result = if request.script_timeout > 0 {
            let timeout = std::time::Duration::from_millis(u64::from(request.script_timeout));
            logger.log_line(&format!(
                "hyperlight: timeout set to {}ms",
                request.script_timeout
            ));
            rt.run_code_with_timeout(&request.script_code, timeout)
        } else {
            rt.run_code(&request.script_code)
        };

        match result {
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
            Err(e) => {
                let err = PyhlError::Runtime(format!("run_code: {e:#}"));
                logger.log_line(&err.to_string());
                err.to_response()
            }
        }
    }
}

// -- Helpers -----------------------------------------------------------------

/// A home has a warmed snapshot (plus kernel + initrd) — ready to load.
fn is_installed(home: &Path) -> bool {
    home.join(KERNEL_FILE).is_file()
        && home.join(INITRD_FILE).is_file()
        && home.join(SNAPSHOT_DIR).join("index.json").is_file()
}

/// A home has the raw inputs we need to auto-install a snapshot.
fn has_install_source(home: &Path) -> bool {
    home.join(KERNEL_FILE).is_file() && home.join(INITRD_FILE).is_file()
}

/// Paths equal after canonicalization (best-effort).
fn same_path(a: &str, b: &str) -> bool {
    let ap = std::fs::canonicalize(a).unwrap_or_else(|_| PathBuf::from(a));
    let bp = std::fs::canonicalize(b).unwrap_or_else(|_| PathBuf::from(b));
    ap == bp
}

fn preopens_equal(a: &[Preopen], b: &[Preopen]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .all(|(x, y)| x.host_dir == y.host_dir && x.guest_path == y.guest_path)
}

/// OS-local data directory (the "user Application Data" root).
///
/// - Linux: `$XDG_DATA_HOME` if set and absolute, else `$HOME/.local/share`.
/// - Windows: `%LOCALAPPDATA%` if set, else `$USERPROFILE\AppData\Local`.
///
/// Returns `PathBuf::from(".")` if no candidate env vars are set (degrades
/// gracefully rather than panicking; caller can still override via
/// `$PYHL_HOME`).
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

    #[test]
    fn is_installed_false_on_empty_dir() {
        let tmp = std::env::temp_dir().join(format!("hl-runner-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        assert!(!is_installed(&tmp));
        assert!(!has_install_source(&tmp));
    }

    #[test]
    fn has_install_source_true_when_kernel_and_initrd_present() {
        let tmp =
            std::env::temp_dir().join(format!("hl-runner-install-src-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join(KERNEL_FILE), b"").unwrap();
        std::fs::write(tmp.join(INITRD_FILE), b"").unwrap();
        assert!(has_install_source(&tmp));
        assert!(!is_installed(&tmp)); // snapshot still absent
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn resolve_home_errors_when_nothing_configured() {
        // Redirect every candidate away from any real install on the
        // test machine: PYHL_HOME, XDG_DATA_HOME (Linux), LOCALAPPDATA
        // (Windows), HOME/USERPROFILE all get pointed into an empty
        // tmpdir for the duration of this test.
        let empty = std::env::temp_dir().join(format!("hl-resolve-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&empty);
        std::fs::create_dir_all(&empty).unwrap();

        let saved: Vec<(&str, Option<std::ffi::OsString>)> = [
            PYHL_HOME_ENV,
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

        let result = HyperlightScriptRunner::resolve_home();

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
    fn policy_accepts_readwrite_paths_and_builds_preopens() {
        // We can't end-to-end test without a real image; just verify
        // the policy→Preopen mapping.
        let tmp = std::env::temp_dir().join(format!("hl-mount-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec![tmp.to_string_lossy().to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let preopens = HyperlightScriptRunner::preopens_from_policy(&request).unwrap();
        assert_eq!(preopens.len(), 1);
        assert_eq!(
            preopens[0].guest_path,
            format!("/host/{}", tmp.file_name().unwrap().to_string_lossy())
        );
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
        let err = HyperlightScriptRunner::preopens_from_policy(&request).unwrap_err();
        assert!(
            err.to_string().contains("collide on guest path"),
            "got: {err}"
        );
        let _ = std::fs::remove_dir_all(a.parent().unwrap());
        let _ = std::fs::remove_dir_all(b.parent().unwrap());
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
    fn network_policy_allow_all_when_default_allow() {
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                default_network_policy: NetworkPolicy::Allow,
                ..Default::default()
            },
            ..Default::default()
        };
        let policy = HyperlightScriptRunner::network_policy_from_request(&request).unwrap();
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
        let policy = HyperlightScriptRunner::network_policy_from_request(&request).unwrap();
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
        let policy = HyperlightScriptRunner::network_policy_from_request(&request).unwrap();
        assert!(policy.is_none());
    }

    #[test]
    fn network_policy_blocklist_from_blocked_hosts() {
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                blocked_hosts: vec!["127.0.0.1".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let policy = HyperlightScriptRunner::network_policy_from_request(&request).unwrap();
        assert!(matches!(
            policy,
            Some(hyperlight_unikraft::NetworkPolicy::BlockList(_))
        ));
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
