// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Policy discovery and config building — the Rust port of the SDK's
//! policy discovery helpers and request construction.
//!
//! - [`available_tools_policy`], [`user_profile_policy`], and
//!   [`temporary_files_policy`] enumerate the host environment to discover
//!   tool/SDK/profile/temp directories as filesystem-policy fragments.
//! - [`ContainerPolicy`] describes cross-platform restrictions, and
//!   [`build_request`] maps it to an [`ExecutionRequest`] for Seatbelt,
//!   Bubblewrap, and ProcessContainer.

mod exact;
pub(crate) mod network;
#[cfg(test)]
mod sdk_v1_conformance;

use std::borrow::Cow;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[cfg(test)]
use crate::configs::{CaptureDenials, CaptureDenialsMode};
use crate::configs::{ProcessContainerConfig, WslcConfig};
#[cfg(test)]
use crate::mxc_common::logger::{Logger, Mode};
use crate::mxc_common::models::{ExecutionRequest, TelemetryConfig};
pub use network::{
    NetworkAction, NetworkEgressPolicy, NetworkIngressPolicy, NetworkPeerPolicy, NetworkPolicy,
    NetworkPortPolicy, NetworkProtocol, NetworkRulePolicy, NetworkRuntimeConfig,
};
// ---------------------------------------------------------------------------
// Filesystem policy discovery
// ---------------------------------------------------------------------------

/// A composable fragment of filesystem policy. Callers merge one or more into
/// a [`ContainerRequest`]'s filesystem section.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilesystemPolicyResult {
    /// Paths to grant read-only access inside the sandbox.
    pub readonly_paths: Vec<String>,
    /// Paths to grant read-write access inside the sandbox.
    pub readwrite_paths: Vec<String>,
}

/// Optional tool-policy filtering controls.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ToolsPolicyOptions {
    /// Exclude directories already accessible to the selected container type.
    pub container_type: Option<ToolsPolicyContainerType>,
}

/// Container types with additional tool-policy filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolsPolicyContainerType {
    /// Filter Windows ALL APPLICATION PACKAGES grants.
    ProcessContainer,
}

/// Well-known tool/SDK environment variables and how to extract directories
/// from each. Mirrors the SDK's `KNOWN_ENV_VARS`. The `bool` is whether the
/// value is a path-list (split on the platform separator) vs a single path.
const KNOWN_ENV_VARS: &[(&str, bool)] = &[
    ("PYTHONPATH", true),
    ("PYTHONHOME", false),
    ("VCINSTALLDIR", false),
    ("VSINSTALLDIR", false),
    ("PSModulePath", true),
    ("VCPKG_ROOT", false),
    ("GOPATH", false),
    ("GOROOT", false),
    ("CARGO_HOME", false),
    ("RUSTUP_HOME", false),
    ("JAVA_HOME", false),
    ("NVM_HOME", false),
    ("NVM_SYMLINK", false),
    ("NODE_PATH", true),
    ("DOTNET_ROOT", false),
    ("CONDA_PREFIX", false),
    ("LD_LIBRARY_PATH", true),
    ("VIRTUAL_ENV", false),
    ("PYENV_ROOT", false),
];

fn is_windows() -> bool {
    cfg!(target_os = "windows")
}

/// Split a path-list value on the platform separator (`;` on Windows, `:`
/// elsewhere), dropping empty entries.
fn split_path_list(value: &str) -> Vec<String> {
    let sep = if is_windows() { ';' } else { ':' };
    value
        .split(sep)
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect()
}

fn single_path(value: &str) -> Vec<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Vec::new()
    } else {
        vec![trimmed.to_string()]
    }
}

fn directory_exists(dir: &str) -> bool {
    std::fs::metadata(dir).map(|m| m.is_dir()).unwrap_or(false)
}

/// Join `base` with successive path segments, returning an owned `String`.
/// Windows policy paths are always valid UTF-16/UTF-8, so the lossy conversion
/// never actually substitutes characters in practice.
fn join_str(base: &str, segments: &[&str]) -> String {
    let mut path = PathBuf::from(base);
    for segment in segments {
        path.push(segment);
    }
    path.to_string_lossy().into_owned()
}

/// Resolve a path to absolute, lexically-normalized form — the equivalent of
/// the SDK's `path.resolve`. Purely lexical (no filesystem access, no symlink
/// resolution): a relative path is joined with the cwd, then `.`/`..` segments
/// are collapsed. Crucially it does *not* canonicalize, so on Windows it keeps
/// the plain `C:\...` form (no `\\?\` verbatim prefix) — otherwise
/// [`is_system_critical_path`]'s `C:\Windows` prefix check would never match.
fn resolve_path(p: &str) -> String {
    let path = Path::new(p);
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(path),
            Err(_) => path.to_path_buf(),
        }
    };
    normalize_lexically(&absolute)
        .to_string_lossy()
        .into_owned()
}

/// Collapse `.`/`..` segments without touching the filesystem, preserving the
/// path prefix/root (the well-known lexical-normalize pattern).
fn normalize_lexically(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut components = path.components().peekable();
    let mut out = if let Some(c @ Component::Prefix(..)) = components.peek().copied() {
        components.next();
        PathBuf::from(c.as_os_str())
    } else {
        PathBuf::new()
    };
    for component in components {
        match component {
            Component::Prefix(..) => unreachable!("prefix only appears first"),
            Component::RootDir => out.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => match out.components().next_back() {
                // Pop a real directory name.
                Some(Component::Normal(_)) => {
                    out.pop();
                }
                // At a root/prefix: `..` can't go above it — ignore the segment
                // (so `/a/../../b` stays `/b`, and `C:\..` stays `C:\`).
                Some(Component::RootDir | Component::Prefix(..)) => {}
                // Relative path (empty or already leading with `..`): preserve.
                _ => out.push(component.as_os_str()),
            },
            Component::Normal(c) => out.push(c),
        }
    }
    out
}

/// Deduplicate resolved paths, case-insensitively on Windows.
fn deduplicate_paths(paths: &[String]) -> Vec<String> {
    let windows = is_windows();
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for p in paths {
        let resolved = resolve_path(p);
        let key = if windows {
            resolved.to_lowercase()
        } else {
            resolved.clone()
        };
        if seen.insert(key) {
            out.push(resolved);
        }
    }
    out
}

/// Whether `dir` is under a system-critical location that must not be exposed.
fn is_system_critical_path(dir: &str) -> bool {
    let normalized = resolve_path(dir);
    if is_windows() {
        // A set-but-empty `WINDIR` must not disable the filter: treat empty as
        // unset and fall back (the same `WINDIR` handling `powershell_policy`
        // uses).
        let win_dir = std::env::var("WINDIR")
            .ok()
            .or_else(|| std::env::var("windir").ok())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "C:\\Windows".to_string())
            .to_lowercase();
        // Strip a verbatim (`\\?\`, `\\?\UNC\`) prefix so a path supplied in
        // that form still matches the plain `C:\Windows` comparison.
        let n = normalized.to_lowercase();
        let n = n
            .strip_prefix(r"\\?\unc\")
            .or_else(|| n.strip_prefix(r"\\?\"))
            .unwrap_or(&n);
        return n == win_dir || n.starts_with(&format!("{win_dir}\\"));
    }
    const CRITICAL: &[&str] = &[
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/boot",
        "/proc",
        "/sys",
        "/dev",
    ];
    CRITICAL
        .iter()
        .any(|cp| normalized == *cp || normalized.starts_with(&format!("{cp}/")))
}

fn env_get<'a>(env: &'a [(String, String)], name: &str) -> Option<&'a str> {
    // Windows environment variable names are case-insensitive (matching the OS
    // and Node's `process.env`, which the TS SDK relies on); Unix names are
    // case-sensitive.
    env.iter()
        .find(|(k, _)| {
            if cfg!(windows) {
                k.eq_ignore_ascii_case(name)
            } else {
                k == name
            }
        })
        .map(|(_, v)| v.as_str())
}

/// Borrow the caller-supplied env, or snapshot the process environment when
/// `None`.
fn env_or_process(env: Option<&[(String, String)]>) -> Cow<'_, [(String, String)]> {
    match env {
        Some(e) => Cow::Borrowed(e),
        None => Cow::Owned(std::env::vars().collect()),
    }
}

#[cfg(test)]
fn environment_keys_equal(existing_key: &str, override_key: &str) -> bool {
    if cfg!(target_os = "windows") {
        existing_key.eq_ignore_ascii_case(override_key)
    } else {
        existing_key == override_key
    }
}

#[cfg(test)]
fn apply_environment_overrides<K, V>(
    entries: &mut Vec<(String, String)>,
    overrides: impl IntoIterator<Item = (K, V)>,
) where
    K: Into<String>,
    V: Into<String>,
{
    for (key, value) in overrides {
        let key = key.into();
        entries.retain(|(existing, _)| !environment_keys_equal(existing, &key));
        entries.push((key, value.into()));
    }
}

/// PowerShell-specific policy: when `pwsh.exe` is found on `path_dirs`
/// (Windows only), grant the system-drive root (`C:\`) read-only — `pwsh.exe`
/// enumerates the drive root on startup — plus the PSReadLine history directory
/// read-write so the module can persist command history.
///
/// Mirrors the SDK's `getPowerShellPolicy`. The system drive is read from the
/// supplied environment (`SystemDrive`, defaulting to `C:`), as does `USERPROFILE`.
///
/// On non-Windows, or when `pwsh.exe` is not on `path_dirs`, returns an empty
/// policy.
fn powershell_policy(path_dirs: &[String], env: &[(String, String)]) -> FilesystemPolicyResult {
    if !is_windows() {
        return FilesystemPolicyResult::default();
    }

    let pwsh_found = path_dirs
        .iter()
        .any(|dir| Path::new(dir).join("pwsh.exe").exists());
    if !pwsh_found {
        return FilesystemPolicyResult::default();
    }

    let system_drive = env_get(env, "SystemDrive")
        .filter(|s| !s.is_empty())
        .unwrap_or("C:");
    let readonly_paths = vec![format!("{system_drive}\\")];

    let mut readwrite_paths: Vec<String> = Vec::new();
    if let Some(user_profile) = env_get(env, "USERPROFILE") {
        // PSReadLine command-history directory (read-write).
        readwrite_paths.push(join_str(
            user_profile,
            &[
                "AppData",
                "Roaming",
                "Microsoft",
                "Windows",
                "PowerShell",
                "PSReadLine",
            ],
        ));
    }

    FilesystemPolicyResult {
        readonly_paths,
        readwrite_paths,
    }
}

/// Discover tool and SDK directories from `environment` (defaults to the process
/// environment) as read-only policy paths.
///
/// Reads `PATH` plus a registry of well-known tool/SDK variables, then filters
/// out non-existent and system-critical directories, and adds PowerShell paths
/// when `pwsh.exe` is on `PATH`. The Rust port of `getAvailableToolsPolicy`.
/// ProcessContainer filtering excludes existing ALL APPLICATION PACKAGES
/// grants on Windows. If ACL inspection fails, retain the directory and emit
/// a diagnostic warning rather than assume it is already accessible.
pub fn available_tools_policy(
    environment: Option<&[(String, String)]>,
    options: ToolsPolicyOptions,
) -> FilesystemPolicyResult {
    let env = env_or_process(environment);
    let env: &[(String, String)] = &env;

    let mut collected = Vec::new();
    let path_value = env_get(env, "PATH")
        .or_else(|| env_get(env, "Path"))
        .unwrap_or("");
    let path_dirs = split_path_list(path_value);
    collected.extend(path_dirs.iter().cloned());

    for (name, is_list) in KNOWN_ENV_VARS {
        if let Some(value) = env_get(env, name) {
            let extracted = if *is_list {
                split_path_list(value)
            } else {
                single_path(value)
            };
            collected.extend(extracted);
        }
    }

    let filtered: Vec<String> = deduplicate_paths(&collected)
        .into_iter()
        .filter(|dir| directory_exists(dir) && !is_system_critical_path(dir))
        .filter(|dir| {
            options.container_type != Some(ToolsPolicyContainerType::ProcessContainer)
                || !has_all_application_packages_access(dir)
        })
        .collect();

    let pwsh = powershell_policy(&path_dirs, env);

    let mut readonly = filtered;
    readonly.extend(pwsh.readonly_paths);

    FilesystemPolicyResult {
        readonly_paths: deduplicate_paths(&readonly),
        readwrite_paths: deduplicate_paths(&pwsh.readwrite_paths),
    }
}

#[cfg(target_os = "windows")]
fn has_all_application_packages_access(directory: &str) -> bool {
    use std::io::Read;
    use std::os::windows::process::CommandExt;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let inspect = || -> std::io::Result<Vec<u8>> {
        let system_root = std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        let mut child = std::process::Command::new(system_root.join("System32").join("icacls.exe"))
            .arg(directory)
            .creation_flags(0x0800_0000) // CREATE_NO_WINDOW: discovery must not open a console.
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("missing icacls stdout"))?;
        std::thread::scope(|scope| {
            let reader = scope.spawn(move || {
                let mut bytes = Vec::new();
                let mut stdout = stdout;
                stdout.read_to_end(&mut bytes)?;
                Ok::<_, std::io::Error>(bytes)
            });
            let deadline = Instant::now() + Duration::from_secs(5);
            let status = loop {
                match child.try_wait() {
                    Ok(Some(status)) => break Ok(status),
                    Ok(None) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    result => {
                        let error = result.err().unwrap_or_else(|| {
                            std::io::Error::new(std::io::ErrorKind::TimedOut, "icacls timed out")
                        });
                        child.kill()?;
                        child.wait()?;
                        break Err(error);
                    }
                }
            };
            let output = reader
                .join()
                .map_err(|_| std::io::Error::other("icacls output reader panicked"))??;
            let status = status?;
            if !status.success() {
                return Err(std::io::Error::other(format!(
                    "icacls exited with {status}"
                )));
            }
            Ok(output)
        })
    };
    match inspect() {
        Ok(output) => {
            let output = String::from_utf8_lossy(&output);
            output.contains("ALL APPLICATION PACKAGES") || output.contains("S-1-15-2-1")
        }
        Err(error) => {
            crate::mxc_common::logger::Logger::inherit_thread_diagnostic_sink().warning_line(
                &format!("Tool-policy ACL inspection failed; retaining directory: {error}"),
            );
            false
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn has_all_application_packages_access(_directory: &str) -> bool {
    false
}

/// Read-only policy for standard user-profile application data locations.
///
/// Windows: immediate subdirectories of `%LOCALAPPDATA%\Programs`. Other
/// platforms: `~/.local/bin` and `~/.local/lib`. The Rust port of
/// `getUserProfilePolicy`.
pub fn user_profile_policy(environment: Option<&[(String, String)]>) -> FilesystemPolicyResult {
    let environment = env_or_process(environment);
    let mut readonly_paths = Vec::new();

    if is_windows() {
        if let Some(local_app_data) = env_get(&environment, "LOCALAPPDATA") {
            if directory_exists(local_app_data) {
                let programs = Path::new(&local_app_data).join("Programs");
                if let Ok(entries) = std::fs::read_dir(&programs) {
                    for entry in entries.flatten() {
                        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                            readonly_paths.push(entry.path().to_string_lossy().into_owned());
                        }
                    }
                }
            }
        }
    } else if let Some(home) = env_get(&environment, "HOME") {
        for sub in [".local/bin", ".local/lib"] {
            let dir = Path::new(&home).join(sub);
            let dir = dir.to_string_lossy().into_owned();
            if directory_exists(&dir) {
                readonly_paths.push(dir);
            }
        }
    }

    FilesystemPolicyResult {
        readonly_paths,
        readwrite_paths: Vec::new(),
    }
}

/// Read-write policy for the host temporary directory.
///
/// Windows: `TEMP` or `TMP`. Other platforms: `TMPDIR` or `/tmp`. Returns an
/// empty fragment when the resolved directory does not exist. The Rust port of
/// `getTemporaryFilesPolicy`.
pub fn temporary_files_policy(environment: Option<&[(String, String)]>) -> FilesystemPolicyResult {
    let env = env_or_process(environment);
    let env: &[(String, String)] = &env;

    let temp_root = if is_windows() {
        env_get(env, "TEMP").or_else(|| env_get(env, "TMP"))
    } else {
        Some(env_get(env, "TMPDIR").unwrap_or("/tmp"))
    };

    match temp_root {
        Some(root) if directory_exists(root) => FilesystemPolicyResult {
            readonly_paths: Vec::new(),
            readwrite_paths: vec![root.to_string()],
        },
        _ => FilesystemPolicyResult::default(),
    }
}

// ---------------------------------------------------------------------------
// ContainerPolicy -> ExecutionRequest
// ---------------------------------------------------------------------------

/// Clipboard access level, mirroring the SDK `ClipboardPolicy`
/// (`"none" | "read" | "write" | "all"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClipboardPolicy {
    /// No clipboard access.
    #[default]
    None,
    /// Read-only clipboard access.
    Read,
    /// Write-only clipboard access.
    Write,
    /// Read and write clipboard access.
    All,
}

/// Filesystem section of a [`ContainerRequest`].
#[derive(Debug, Clone, Default)]
pub struct FilesystemPolicy {
    pub readwrite_paths: Vec<String>,
    pub readonly_paths: Vec<String>,
    pub denied_paths: Vec<String>,
    /// Clear the filesystem policy when the shell exits (default `true`).
    pub clear_policy_on_exit: Option<bool>,
}

/// UI section of a [`ContainerRequest`]. All flags default to denied.
#[derive(Debug, Clone)]
pub struct UiPolicy {
    pub disable: bool,
    pub clipboard: ClipboardPolicy,
    pub allow_input_injection: bool,
}

impl Default for UiPolicy {
    fn default() -> Self {
        Self {
            disable: true,
            clipboard: ClipboardPolicy::None,
            allow_input_injection: false,
        }
    }
}

/// The containment backend selected by a [`ContainerRequest`].
///
/// Only the backends this library can actually run are listed; select a
/// concrete backend when you specifically need it, and prefer
/// [`Containment::Process`] otherwise.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Containment {
    /// Abstract "OS-native process isolation" intent, resolved per host:
    /// ProcessContainer (Windows), Bubblewrap (Linux), Seatbelt (macOS).
    #[default]
    Process,
    /// Windows ProcessContainer with explicit AppContainer/BaseContainer
    /// settings.
    ProcessContainer(ProcessContainerConfig),
    /// macOS Seatbelt with explicit backend-specific settings.
    Seatbelt(crate::configs::SeatbeltConfig),
    /// Linux LXC with explicit distribution settings.
    Lxc(crate::configs::LxcConfig),
    /// Linux Bubblewrap backend.
    Bubblewrap,
    /// WSL Container backend: a Linux container on a Windows host, via the WSLC
    /// SDK, configured by the carried [`crate::v1::configs::WslcConfig`]
    /// (`crate::v1::configs::WslcConfig::default()` matches the SDK's defaults).
    ///
    /// Requires the `wslc` build feature but no runtime experimental opt-in.
    Wslc(WslcConfig),
    /// IsolationSession backend: a Windows isolated user session.
    ///
    /// Requires the `isolation_session` build feature but no runtime
    /// experimental opt-in. Uses piped stdio. Manual lifecycle operations are
    /// available through [`crate::v1::container`].
    IsolationSession,
}

impl Containment {
    fn telemetry_kind(&self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::ProcessContainer(_) => "processcontainer",
            Self::Seatbelt(_) => "seatbelt",
            Self::Lxc(_) => "lxc",
            Self::Bubblewrap => "bubblewrap",
            Self::Wslc(_) => "wslc",
            Self::IsolationSession => "isolation_session",
        }
    }
}

/// Cross-platform sandbox policy — the Rust analogue of the SDK
/// `ContainerPolicy`. Describes *what* to restrict; omitted fields are
/// most-restrictive (default-deny).
///
/// Telemetry is intentionally not a policy field. It is invocation
/// instrumentation rather than a sandbox restriction, matching the global
/// sandbox-policy design. Set telemetry through the operation's options.
///
/// This is an authoring type, not a JSON contract. SDK builders construct exact
/// contract values; raw JSON APIs parse documents under their declared version.
///
/// ```compile_fail
/// let _: mxc_engine::policy::ContainerPolicy = serde_json::from_str("{}").unwrap();
/// ```
///
/// ```compile_fail
/// serde_json::to_string(&mxc_engine::policy::ContainerPolicy::default()).unwrap();
/// ```
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub(crate) struct ContainerPolicy {
    pub filesystem: Option<FilesystemPolicy>,
    pub network: Option<NetworkPolicy>,
    pub ui: Option<UiPolicy>,
    /// Execution timeout in milliseconds (`None` = no timeout).
    pub timeout_ms: Option<u32>,
}

/// Request for creating a container and running a workload.
#[derive(Debug, Clone)]
pub struct ContainerRequest {
    /// Command line to execute.
    pub command: String,
    /// Cross-backend filesystem restrictions.
    pub filesystem: Option<FilesystemPolicy>,
    /// Cross-backend network restrictions and runtime network values.
    pub network: Option<NetworkPolicy>,
    /// Cross-backend UI restrictions.
    pub ui: Option<UiPolicy>,
    /// Execution timeout in milliseconds; `None` uses the backend default.
    pub timeout_ms: Option<u32>,
    /// Backend selection and backend-specific configuration.
    pub containment: Containment,
    /// Optional caller-selected container identifier.
    pub container_name: Option<String>,
    /// Initial working directory for the sandboxed process.
    pub working_directory: Option<String>,
    /// Optional environment entries. `None` uses the backend default;
    /// `Some(Vec::new())` requests an explicitly empty environment.
    pub environment: Option<Vec<(String, String)>>,
    /// Whether supplied environment entries layer over the backend default.
    pub inherit_default_environment: Option<bool>,
}

impl ContainerRequest {
    /// Create a [`ContainerRequest`] for `command`.
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            filesystem: None,
            network: None,
            ui: None,
            timeout_ms: None,
            containment: Containment::Process,
            container_name: None,
            working_directory: None,
            environment: None,
            inherit_default_environment: None,
        }
    }
}

/// Internal normalized request consumed by the execution engine.
#[derive(Debug, Clone)]
pub(crate) struct PreparedContainerRequest {
    /// The internal execution model. `pub(crate)` so the SDK's own modules and
    /// unit tests can map/inspect it, while it stays out of the public API.
    pub(crate) inner: ExecutionRequest,
    #[cfg(test)]
    requested_sandbox_kind: &'static str,
}

#[cfg(test)]
impl PreparedContainerRequest {
    /// Override the working directory the sandboxed child starts in. Left unset,
    /// it defaults to the policy's resolution.
    pub fn set_working_directory(&mut self, working_directory: impl Into<String>) -> &mut Self {
        self.inner.working_directory = working_directory.into();
        self
    }

    /// Set the child's environment from `(key, value)` pairs.
    ///
    /// Each pair is stored as a `KEY=VALUE` entry — the same wire form the SDK's
    /// env channel produces (`injectEnvIntoConfig` joins a `{ key: value }` map
    /// the same way), so behavior is identical across the SDK and this crate.
    /// Iteration order is preserved, so on a duplicate key the later entry wins,
    /// matching the SDK.
    ///
    /// The environment you set is used **verbatim**: MXC does not merge the
    /// calling process's variables or the user's profile block into it. On the
    /// Windows process container that includes the variables Windows requires
    /// to be present, so a sparse environment fails the launch with a
    /// diagnostic naming them — see [`Self::inherit_default_env`] and
    /// [`Self::inherit_process_env`] for the supported ways to start from a
    /// complete environment. IsolationSession cannot launch a process without
    /// the agent user's default environment, so it refuses an environment set
    /// here; use [`Self::inherit_default_env`] to layer entries over it.
    ///
    /// Calling this with an empty iterator requests an *empty* environment,
    /// which is distinct from never calling it at all (see [`Self::clear_env`]).
    pub fn set_env<K, V>(&mut self, env: impl IntoIterator<Item = (K, V)>) -> &mut Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        self.inner.inherit_default_env = false;
        self.inner.env = Some(
            env.into_iter()
                .map(|(k, v)| {
                    let (k, v): (String, String) = (k.into(), v.into());
                    format!("{k}={v}")
                })
                .collect(),
        );
        self
    }

    /// Drop any environment set on this request, returning it to the backend
    /// default.
    ///
    /// This is *not* the same as `set_env([])`: that asks for an empty
    /// environment, whereas this asks for the backend's default one.
    pub fn clear_env(&mut self) -> &mut Self {
        self.inner.env = None;
        self.inner.inherit_default_env = false;
        self
    }

    /// Start from the backend's default environment and append `extra` on top,
    /// so the child gets a complete environment plus your additions.
    ///
    /// This is the supported way to express "the usual environment, plus these"
    /// on the Windows process container: the default block is the user's
    /// profile block, obtainable only from the OS, so it cannot be assembled by
    /// a caller. Entries in `extra` override same-named defaults.
    ///
    /// From schema 0.9 LXC, Bubblewrap, and Seatbelt supply `PATH` + `HOME` +
    /// `TERM`. Below 0.9 their default is empty and this is equivalent to
    /// [`Self::set_env`]. WSLc supplies the container image's own `ENV` at
    /// every version, so `extra` always layers over it. IsolationSession
    /// supplies the agent user's default environment.
    pub fn inherit_default_env<K, V>(
        &mut self,
        extra: impl IntoIterator<Item = (K, V)>,
    ) -> &mut Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        self.set_env(extra);
        self.inner.inherit_default_env = true;
        self
    }

    /// Enable or disable telemetry for this invocation.
    ///
    /// Enabling this per-request switch is necessary but not sufficient:
    /// telemetry still requires persisted user consent and an administrative
    /// policy that permits collection. It is independent of experimental mode.
    pub fn set_telemetry_opt_in(&mut self, enabled: bool) -> &mut Self {
        self.inner.telemetry = Some(TelemetryConfig {
            enabled: Some(enabled),
            requested_sandbox_kind: Some(self.requested_sandbox_kind),
        });
        self
    }

    /// Return the explicit per-request telemetry switch for this invocation.
    pub fn telemetry_enabled(&self) -> Option<bool> {
        self.inner
            .telemetry
            .as_ref()
            .and_then(|telemetry| telemetry.enabled)
    }
}

/// Build a [`ContainerRequest`] from a [`ContainerPolicy`], resolving the host's
/// containment backend — the Rust port of the SDK's `createConfigFromPolicy`.
///
/// The `script` becomes the request's command line, so the returned request is
/// complete and needs no post-build patching before streaming it via
/// [`crate::v1::spawn`]. An empty script is rejected.
///
/// Maps the V1 high-level policy into the SDK-owned v1 contract,
/// then adapts that contract through the shared semantic validation path.
///
/// Targets the host's native process containment; use
/// [`build_request_with_containment`] to select a specific backend.
#[cfg(test)]
pub(crate) fn build_request(
    policy: &ContainerPolicy,
    script: &str,
    container_name: Option<&str>,
) -> Result<PreparedContainerRequest, crate::Error> {
    build_request_with_containment(policy, &Containment::Process, script, container_name)
}

/// Build a [`ContainerRequest`] for an explicitly chosen [`Containment`] backend
/// — the Rust port of `createConfigFromPolicy(policy, containment, name)`.
///
/// Same mapping and validation as [`build_request`]; the containment argument
/// picks the backend rather than always resolving the host's native one.
///
/// ```no_run
/// use mxc_sdk::v1::{configs::WslcConfig, ContainerRequest, Containment};
///
/// let wslc = WslcConfig { image: "python:3.12".to_string(), ..Default::default() };
/// let request = ContainerRequest {
///     containment: Containment::Wslc(wslc),
///     ..ContainerRequest::new("python3 -c 'print(1)'")
/// };
/// ```
pub(crate) fn build_request_with_containment(
    policy: &ContainerPolicy,
    containment: &Containment,
    script: &str,
    container_name: Option<&str>,
) -> Result<PreparedContainerRequest, crate::Error> {
    exact::build_request(policy, containment, script, container_name)
}

pub(crate) fn prepare_request(
    request: &ContainerRequest,
) -> Result<PreparedContainerRequest, crate::Error> {
    let policy = ContainerPolicy {
        filesystem: request.filesystem.clone(),
        network: request.network.clone(),
        ui: request.ui.clone(),
        timeout_ms: request.timeout_ms,
    };
    let mut prepared = build_request_with_containment(
        &policy,
        &request.containment,
        &request.command,
        request.container_name.as_deref(),
    )?;
    prepared.inner.working_directory = request.working_directory.clone().unwrap_or_default();
    prepared.inner.env = request.environment.as_ref().map(|environment| {
        environment
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect()
    });
    prepared.inner.inherit_default_env = request.inherit_default_environment.unwrap_or(false);
    Ok(prepared)
}

pub(crate) fn prepare_creation_request(
    request: &ContainerRequest,
    telemetry: Option<crate::options::TelemetryConfig>,
) -> Result<PreparedContainerRequest, crate::Error> {
    let mut prepared = prepare_request(request)?;
    prepared.inner.experimental_enabled = false;
    if let Some(telemetry) = telemetry {
        prepared.inner.telemetry = Some(TelemetryConfig {
            enabled: telemetry.enabled,
            requested_sandbox_kind: Some(request.containment.telemetry_kind()),
        });
    }
    Ok(prepared)
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "windows")]
    #[test]
    fn discovery_map_cannot_override_host_windows_safety_exclusion() {
        let host_windows = std::env::var("WINDIR")
            .or_else(|_| std::env::var("windir"))
            .unwrap_or_else(|_| r"C:\Windows".to_string());
        for windir in ["", r"C:\SpoofedWindows"] {
            let environment = vec![
                ("PATH".to_string(), host_windows.clone()),
                ("WINDIR".to_string(), windir.to_string()),
            ];
            let result = super::available_tools_policy(
                Some(&environment),
                super::ToolsPolicyOptions::default(),
            );
            assert!(result.readonly_paths.is_empty());
        }
    }

    const TEST_COMMAND: &str = "echo hello";

    #[test]
    fn creation_options_preserve_telemetry_presence_and_containment_intent() {
        let request = super::ContainerRequest {
            containment: super::Containment::Bubblewrap,
            ..super::ContainerRequest::new(TEST_COMMAND)
        };
        for enabled in [None, Some(true), Some(false)] {
            let telemetry = enabled.map(|enabled| crate::options::TelemetryConfig {
                enabled: Some(enabled),
            });
            let prepared = super::prepare_creation_request(&request, telemetry).unwrap();
            assert!(!prepared.inner.experimental_enabled);
            assert_eq!(
                prepared.inner.telemetry.as_ref().and_then(|t| t.enabled),
                enabled
            );
            if let Some(telemetry) = prepared.inner.telemetry {
                assert_eq!(
                    telemetry.requested_sandbox_kind,
                    Some(request.containment.telemetry_kind())
                );
            }
        }
        assert!(super::prepare_request(&request)
            .unwrap()
            .inner
            .telemetry
            .is_none());
    }

    #[test]
    fn empty_creation_telemetry_config_does_not_enable_telemetry() {
        let request = super::ContainerRequest::new(TEST_COMMAND);
        let prepared = super::prepare_creation_request(
            &request,
            Some(crate::options::TelemetryConfig::default()),
        )
        .unwrap();
        assert_eq!(prepared.inner.telemetry.unwrap().enabled, None);
    }

    #[test]
    fn rust_sdk_builds_directional_networking() {
        let network = NetworkPolicy {
            egress: Some(NetworkEgressPolicy {
                default: Some(NetworkAction::Deny),
                ..Default::default()
            }),
            ingress: Some(NetworkIngressPolicy {
                default: Some(NetworkAction::Deny),
                host_loopback: Some(NetworkAction::Deny),
            }),
            ..Default::default()
        };

        let request = super::ContainerRequest {
            network: Some(network),
            ..super::ContainerRequest::new("echo hello")
        };
        super::prepare_request(&request).expect("the Rust SDK should build directional networking");
    }

    #[test]
    fn public_request_environment_preserves_omission_empty_and_layering() {
        let omitted = super::prepare_request(&super::ContainerRequest::new(TEST_COMMAND))
            .expect("the default request should prepare");
        assert_eq!(omitted.inner.env, None);
        assert!(!omitted.inner.inherit_default_env);

        let empty = super::ContainerRequest {
            environment: Some(Vec::new()),
            inherit_default_environment: Some(true),
            working_directory: Some("C:\\work".to_string()),
            timeout_ms: Some(500),
            ..super::ContainerRequest::new(TEST_COMMAND)
        };
        let prepared =
            super::prepare_request(&empty).expect("explicit environment settings should prepare");
        assert_eq!(prepared.inner.env, Some(Vec::new()));
        assert!(prepared.inner.inherit_default_env);
        assert_eq!(prepared.inner.working_directory, "C:\\work");
        assert_eq!(prepared.inner.script_timeout, 500);

        let layered = super::ContainerRequest {
            environment: Some(vec![("EXTRA".into(), "value".into())]),
            inherit_default_environment: Some(true),
            ..super::ContainerRequest::new(TEST_COMMAND)
        };
        let prepared =
            super::prepare_request(&layered).expect("layered environment settings should prepare");
        assert_eq!(prepared.inner.env, Some(vec!["EXTRA=value".to_string()]));
        assert!(prepared.inner.inherit_default_env);
    }

    #[test]
    fn rust_sdk_builds_directional_process_container_networking_and_capture() {
        use crate::configs::{CaptureDenials, ProcessContainerNetwork};

        let network = NetworkPolicy {
            egress: Some(NetworkEgressPolicy {
                default: Some(NetworkAction::Deny),
                ..Default::default()
            }),
            ingress: Some(NetworkIngressPolicy {
                default: Some(NetworkAction::Allow),
                host_loopback: Some(NetworkAction::Deny),
            }),
            runtime_config: Some(NetworkRuntimeConfig {
                network_proxy: Some("http://127.0.0.1:8080".to_string()),
            }),
        };

        let process_container = ProcessContainerConfig {
            capture_denials: Some(CaptureDenials::default()),
            network: Some(ProcessContainerNetwork {
                allowed_proxy_peer: Some("Contoso.Proxy_123".to_string()),
            }),
            ..Default::default()
        };
        let request = super::ContainerRequest {
            network: Some(network),
            containment: Containment::ProcessContainer(process_container),
            ..super::ContainerRequest::new("echo hello")
        };

        super::prepare_request(&request)
            .expect("public request types should build directional networking and capture");
    }

    #[test]
    fn exact_contract_bridge_is_available_to_policy_builders() {
        let request: crate::mxc_contract::published::v0_9_0_alpha::OneShotRequest =
            serde_json::from_str(
                r#"{
                    "version": "0.9.0-alpha",
                    "process": {"commandLine": "echo hello"}
                }"#,
            )
            .unwrap();
        let mut logger =
            crate::mxc_common::logger::Logger::new(crate::mxc_common::logger::Mode::Buffer);

        let execution = crate::mxc_common::config_parser::load_one_shot_request_from_contract(
            crate::mxc_common::config_parser::ExactOneShotContract::V0_9(Box::new(request)),
            &mut logger,
        )
        .unwrap();

        assert_eq!(
            execution.source_contract,
            Some(crate::mxc_contract::ContractVersion::V0_9_0Alpha)
        );
        assert_eq!(execution.script_code, "echo hello");
    }

    #[test]
    fn v1_builder_preserves_absent_empty_and_runtime_only_network_presence() {
        let mut policy = minimal_policy();
        let absent =
            build_request_with_containment(&policy, &Containment::Process, TEST_COMMAND, None)
                .unwrap();
        assert!(!absent.inner.policy.network_specified);
        policy.network = Some(NetworkPolicy::default());
        let empty =
            build_request_with_containment(&policy, &Containment::Process, TEST_COMMAND, None)
                .unwrap();
        assert!(empty.inner.policy.network_specified);
        assert!(!empty.inner.policy.network_mode_specified);
        policy.network = Some(NetworkPolicy {
            runtime_config: Some(NetworkRuntimeConfig {
                network_proxy: Some("http://proxy.example:8080".into()),
            }),
            ..Default::default()
        });
        // Construction preserves runtime-only intent. Execution still requires
        // a provisioned bridged route; the backend owns that validation.
        let runtime_only = build_request_with_containment(
            &policy,
            &Containment::Wslc(WslcConfig::default()),
            TEST_COMMAND,
            None,
        )
        .unwrap();
        assert!(!runtime_only.inner.policy.network_specified);
        assert!(!runtime_only.inner.policy.network_mode_specified);
        assert!(runtime_only.inner.policy.runtime_network_proxy_specified);
    }
    #[test]
    fn v1_policy_builder_accepts_wslc() {
        let policy = ContainerPolicy {
            filesystem: None,
            network: None,
            ui: None,
            timeout_ms: None,
        };

        let request = build_request_with_containment(
            &policy,
            &Containment::Wslc(WslcConfig::default()),
            TEST_COMMAND,
            None,
        )
        .expect("v0.9 should support WSLC");
        assert_eq!(request.inner.containment, ContainmentBackend::Wslc);
    }

    #[test]
    fn v1_policy_builder_enforces_capability_construction_rules() {
        let policy = ContainerPolicy {
            filesystem: None,
            network: None,
            ui: None,
            timeout_ms: None,
        };
        let containment = Containment::ProcessContainer(ProcessContainerConfig {
            capabilities: vec!["internetClient,privateNetworkClientServer".to_string()],
            ..ProcessContainerConfig::default()
        });

        let error =
            build_request_with_containment(&policy, &containment, TEST_COMMAND, None).unwrap_err();
        assert!(error.message.contains("must not contain a comma"));
    }

    // `ui` must be emitted only when the caller supplied one.
    //
    // These pin the fix for a defect that was invisible by value: the builder
    // used to synthesize a `ui` object unconditionally, and because
    // `UiPolicy::default()` is full lockdown the synthesized block was
    // value-identical to an explicit lockdown. The resulting request therefore
    // carried `ui_specified = true` even when the caller never mentioned `ui`,
    // and a backend that refuses a UI posture on *presence* would reject it.
    //
    // The assertion is deliberately about key presence rather than content —
    // that is the only thing that distinguishes the two states downstream.
    #[test]
    fn exact_builder_preserves_absent_ui() {
        let policy = super::ContainerPolicy::default();
        assert!(policy.ui.is_none(), "precondition: no ui supplied");

        let request =
            super::build_request(&policy, TEST_COMMAND, None).expect("minimal policy builds");

        assert!(
            !request.inner.policy.ui_specified,
            "exact builder synthesized a UI policy the caller did not supply"
        );
    }

    #[test]
    fn exact_builder_preserves_explicit_ui() {
        // An explicitly-supplied lockdown `ui` — value-identical to the old
        // synthesized block, which is exactly why presence is what matters.
        let policy = super::ContainerPolicy {
            ui: Some(super::UiPolicy::default()),
            ..Default::default()
        };
        assert!(policy.ui.is_some(), "precondition: ui supplied");

        let request =
            super::build_request(&policy, TEST_COMMAND, None).expect("policy with ui builds");

        assert!(
            request.inner.policy.ui_specified,
            "exact builder dropped a UI policy the caller supplied"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn powershell_policy_grants_system_drive_root() {
        use super::powershell_policy;
        use std::fs;
        use std::path::PathBuf;

        // Simulate a `$PSHOME` by creating a temp dir containing a fake pwsh.exe.
        let unique = format!(
            "mxc_pwsh_policy_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let ps_home: PathBuf = std::env::temp_dir().join(unique);
        fs::create_dir_all(&ps_home).expect("create temp $PSHOME");
        fs::write(ps_home.join("pwsh.exe"), b"").expect("create fake pwsh.exe");
        let ps_home_str = ps_home.to_string_lossy().into_owned();

        let env = vec![("USERPROFILE".to_string(), "C:\\Users\\example".to_string())];
        let result = powershell_policy(std::slice::from_ref(&ps_home_str), &env);

        // Clean up before asserting so a failing assertion still leaves nothing.
        let _ = fs::remove_dir_all(&ps_home);

        // The system-drive root (e.g. `C:\`) is granted read-only — pwsh
        // enumerates the drive root on startup (mirrors `getPowerShellPolicy`).
        // A bare drive root normalizes to a 2-char `X:` after trimming separators.
        assert!(
            result.readonly_paths.iter().any(|p| {
                let trimmed = p.trim_end_matches(['\\', '/']);
                trimmed.len() == 2 && trimmed.ends_with(':')
            }),
            "expected system-drive root in readonly paths: {:?}",
            result.readonly_paths
        );
        // PSReadLine command history stays read-write.
        assert!(
            result
                .readwrite_paths
                .iter()
                .any(|p| p.contains("PSReadLine")),
            "expected PSReadLine history in readwrite paths: {:?}",
            result.readwrite_paths
        );
    }

    use super::{
        build_request, CaptureDenials, CaptureDenialsMode, ContainerPolicy, NetworkAction,
        NetworkEgressPolicy, NetworkIngressPolicy, NetworkPolicy, NetworkRuntimeConfig,
        PreparedContainerRequest,
    };

    #[test]
    fn build_request_maps_filesystem_and_timeout() {
        let policy = ContainerPolicy {
            filesystem: Some(super::FilesystemPolicy {
                readwrite_paths: vec!["/tmp".to_string()],
                readonly_paths: vec![],
                denied_paths: vec![],
                clear_policy_on_exit: None,
            }),
            network: None,
            ui: None,
            timeout_ms: Some(5000),
        };

        // Inspect the internal model the SDK maps to — a unit concern; the public
        // API only hands back the opaque `ContainerRequest`.
        let request = build_request(&policy, TEST_COMMAND, Some("test-container"))
            .expect("build_request should succeed");
        assert_eq!(request.inner.script_timeout, 5000);
        assert!(request
            .inner
            .policy
            .readwrite_paths
            .contains(&"/tmp".to_string()));
        assert!(request.inner.script_code.contains(TEST_COMMAND));
        assert_eq!(request.inner.container_id, "test-container".to_string());
    }

    #[test]
    fn build_request_maps_enumerate_paths_for_v1() {
        let policy = ContainerPolicy {
            filesystem: None,
            network: None,
            ui: None,
            timeout_ms: None,
        };
        let containment = Containment::ProcessContainer(crate::configs::ProcessContainerConfig {
            filesystem: Some(crate::configs::ProcessContainerFilesystem {
                enumerate_paths: vec!["C:\\tools".to_string()],
            }),
            ..Default::default()
        });

        let request = build_request_with_containment(&policy, &containment, TEST_COMMAND, None)
            .expect("0.9 enumeratePaths should build");

        assert_eq!(request.inner.policy.enumerate_paths, vec!["C:\\tools"]);
    }

    #[test]
    fn set_env_formats_pairs_as_key_value_in_order() {
        // The structured `(key, value)` setter mirrors the SDK env channel
        // (`injectEnvIntoConfig`): each pair becomes a `KEY=VALUE` wire entry, in
        // iteration order so a later duplicate key wins downstream.
        let policy = ContainerPolicy {
            filesystem: None,
            network: None,
            ui: None,
            timeout_ms: None,
        };
        let mut request =
            build_request(&policy, TEST_COMMAND, None).expect("build_request should succeed");
        request.set_env([("FIRST", "1"), ("SECOND", "2")]);
        assert_eq!(
            env_of(&request),
            Some(vec!["FIRST=1".to_string(), "SECOND=2".to_string()])
        );
    }

    /// The request's environment as an owned value, so tests can compare it
    /// against a literal without borrowing a temporary.
    fn env_of(request: &PreparedContainerRequest) -> Option<Vec<String>> {
        request.inner.env.clone()
    }

    #[test]
    fn set_env_replaces_rather_than_merging() {
        let policy = ContainerPolicy {
            filesystem: None,
            network: None,
            ui: None,
            timeout_ms: None,
        };
        let mut request =
            build_request(&policy, TEST_COMMAND, None).expect("build_request should succeed");

        // No environment set yet: the backend supplies its default.
        assert_eq!(env_of(&request), None::<Vec<String>>);

        request.set_env([("ONLY", "me")]);
        assert_eq!(env_of(&request), Some(vec!["ONLY=me".to_string()]));
        assert!(!request.inner.inherit_default_env);

        request.inherit_default_env([("EXTRA", "1")]);
        request.set_env([("REPLACEMENT", "2")]);
        assert_eq!(env_of(&request), Some(vec!["REPLACEMENT=2".to_string()]));
        assert!(!request.inner.inherit_default_env);

        // An empty iterator is a request for an empty environment, which is
        // distinct from never having set one.
        request.set_env(Vec::<(String, String)>::new());
        assert_eq!(env_of(&request), Some(Vec::<String>::new()));

        // clear_env goes back to the backend default.
        request.inherit_default_env([("EXTRA", "1")]);
        request.clear_env();
        assert_eq!(env_of(&request), None::<Vec<String>>);
        assert!(!request.inner.inherit_default_env);
    }

    #[test]
    fn inherit_default_env_flags_the_request_and_keeps_the_extras() {
        let policy = ContainerPolicy {
            filesystem: None,
            network: None,
            ui: None,
            timeout_ms: None,
        };
        let mut request =
            build_request(&policy, TEST_COMMAND, None).expect("build_request should succeed");
        request.inherit_default_env([("EXTRA", "1")]);

        assert!(request.inner.inherit_default_env);
        assert_eq!(env_of(&request), Some(vec!["EXTRA=1".to_string()]));
    }

    #[test]
    fn environment_overrides_replace_exact_duplicate_names() {
        let mut entries = vec![
            ("PATH".to_string(), "old".to_string()),
            ("KEEP".to_string(), "value".to_string()),
        ];
        super::apply_environment_overrides(&mut entries, [("PATH", "new")]);

        assert_eq!(
            entries,
            vec![
                ("KEEP".to_string(), "value".to_string()),
                ("PATH".to_string(), "new".to_string()),
            ]
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn environment_overrides_replace_windows_names_case_insensitively() {
        let mut entries = vec![("Path".to_string(), "old".to_string())];
        super::apply_environment_overrides(&mut entries, [("PATH", "new")]);

        assert_eq!(entries, vec![("PATH".to_string(), "new".to_string())]);
    }

    #[test]
    fn build_request_preserves_clipboard_policy() {
        use super::ClipboardPolicy as P;
        use crate::mxc_common::models::ClipboardPolicy as Wire;

        for (input, expected) in [
            (P::None, Wire::None),
            (P::Read, Wire::Read),
            (P::Write, Wire::Write),
            (P::All, Wire::All),
        ] {
            let policy = ContainerPolicy {
                filesystem: None,
                network: None,
                ui: Some(super::UiPolicy {
                    disable: false,
                    clipboard: input,
                    allow_input_injection: false,
                }),
                timeout_ms: None,
            };
            let request =
                build_request(&policy, TEST_COMMAND, None).expect("build_request should succeed");
            assert_eq!(
                request.inner.policy.ui.clipboard, expected,
                "clipboard {input:?} should map to {expected:?}"
            );
        }
    }

    #[test]
    fn request_builders_reject_an_empty_script() {
        let policy = ContainerPolicy::default();

        let errors = [
            (
                "build_request",
                build_request(&policy, "", None).expect_err("empty script should be rejected"),
            ),
            (
                "build_request_with_containment",
                build_request_with_containment(&policy, &Containment::Process, "", None)
                    .expect_err("empty script should be rejected"),
            ),
        ];

        for (entry_point, error) in errors {
            assert_eq!(
                error.code,
                crate::ErrorCode::MalformedRequest,
                "{entry_point}"
            );
            assert!(
                error.message.contains("script parameter is required"),
                "{entry_point} unexpected error: {error:?}"
            );
        }
    }

    #[test]
    fn explicit_seatbelt_configuration_reaches_the_request() {
        use crate::configs::SeatbeltConfig;

        let policy = ContainerPolicy {
            filesystem: None,
            network: None,
            ui: None,
            timeout_ms: None,
        };
        let seatbelt = SeatbeltConfig {
            profile_override: Some("(version 1)".to_string()),
            gui_access: true,
            nested_pty: false,
            keychain_access: true,
            extra_mach_lookups: vec!["com.example.service".to_string()],
        };

        let request = build_request_with_containment(
            &policy,
            &Containment::Seatbelt(seatbelt),
            TEST_COMMAND,
            None,
        )
        .expect("explicit Seatbelt request builds");
        let config = request
            .inner
            .seatbelt
            .expect("explicit Seatbelt config is preserved");

        assert_eq!(config.profile_override.as_deref(), Some("(version 1)"));
        assert!(config.gui_access);
        assert!(!config.nested_pty);
        assert!(config.keychain_access);
        assert_eq!(config.extra_mach_lookups, ["com.example.service"]);
    }

    #[test]
    fn explicit_lxc_configuration_reaches_the_request() {
        use crate::configs::LxcConfig;

        let lxc = LxcConfig {
            distribution: "ubuntu".to_string(),
            release: "24.04".to_string(),
        };
        let request = build_request_with_containment(
            &minimal_policy(),
            &Containment::Lxc(lxc),
            TEST_COMMAND,
            None,
        )
        .expect("explicit LXC request builds");

        assert_eq!(request.inner.containment, ContainmentBackend::Lxc);
        assert_eq!(request.inner.lxc_config.distribution, "ubuntu");
        assert_eq!(request.inner.lxc_config.release, "24.04");
    }

    #[test]
    fn explicit_bubblewrap_configuration_reaches_the_request() {
        let request = build_request_with_containment(
            &minimal_policy(),
            &Containment::Bubblewrap,
            TEST_COMMAND,
            None,
        )
        .expect("explicit Bubblewrap request builds");

        assert_eq!(request.inner.containment, ContainmentBackend::Bubblewrap);
    }

    #[cfg(target_os = "windows")]
    fn process_container_with_capture_denials(config: CaptureDenials) -> Containment {
        Containment::ProcessContainer(ProcessContainerConfig {
            capture_denials: Some(config),
            ..Default::default()
        })
    }

    #[test]
    fn capture_denials_config_defaults_to_block_without_output_path() {
        let config = CaptureDenials::default();

        assert_eq!(config.mode, CaptureDenialsMode::Block);
        assert!(config.output_path.is_none());
        assert!(!config.retain_etl);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn capture_denials_reaches_the_container_policy() {
        use crate::mxc_common::models::CaptureDenialsMode as DomainMode;

        // `build_request` validates that the parent directory exists, so anchor
        // the path somewhere guaranteed to be present.
        let output_path = std::env::temp_dir().join("denials.json");
        let expected = output_path.to_string_lossy().into_owned();
        let policy = minimal_policy();
        let containment = process_container_with_capture_denials(CaptureDenials {
            mode: CaptureDenialsMode::Allow,
            output_path: Some(expected.clone()),
            retain_etl: true,
        });
        let request = build_request_with_containment(&policy, &containment, TEST_COMMAND, None)
            .expect("build_request_with_containment");

        let captured = request
            .inner
            .policy
            .capture_denials
            .as_ref()
            .expect("captureDenials enabled");
        assert_eq!(captured.mode, DomainMode::Allow);
        assert_eq!(captured.output_path.as_deref(), Some(expected.as_str()));
        assert!(captured.retain_etl);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn capture_denials_absent_leaves_the_container_policy_untouched() {
        let policy = minimal_policy();
        let containment = process_container_with_capture_denials(CaptureDenials::default());
        let request = build_request_with_containment(&policy, &containment, TEST_COMMAND, None)
            .expect("build_request_with_containment");
        assert!(request.inner.policy.capture_denials.is_some());

        let request = build_request_with_containment(
            &policy,
            &Containment::ProcessContainer(ProcessContainerConfig::default()),
            TEST_COMMAND,
            None,
        )
        .expect("build_request_with_containment");
        assert!(request.inner.policy.capture_denials.is_none());
    }

    // The emitted `processContainer.captureDenials` object is Windows-gated, so
    // pin its shape against the exact development-contract type it has to
    // satisfy.
    #[test]
    fn emitted_capture_denials_json_matches_the_exact_contract() {
        use crate::mxc_contract::dev::{
            CaptureDenials as ContractCaptureDenials,
            CaptureDenialsMode as ContractCaptureDenialsMode,
        };

        fn wire_mode(mode: CaptureDenialsMode) -> &'static str {
            match mode {
                CaptureDenialsMode::Block => "block",
                CaptureDenialsMode::Allow => "allow",
            }
        }

        for (mode, expected) in [
            (CaptureDenialsMode::Block, ContractCaptureDenialsMode::Block),
            (CaptureDenialsMode::Allow, ContractCaptureDenialsMode::Allow),
        ] {
            let emitted = serde_json::json!({
                "mode": wire_mode(mode),
                "outputPath": Some("/tmp/denials.json"),
                "retainEtl": true,
            });
            let parsed: ContractCaptureDenials = serde_json::from_value(emitted)
                .expect("emitted object satisfies the exact contract");

            assert!(matches!(
                (expected, parsed.mode.into_option()),
                (
                    ContractCaptureDenialsMode::Block,
                    Some(ContractCaptureDenialsMode::Block)
                ) | (
                    ContractCaptureDenialsMode::Allow,
                    Some(ContractCaptureDenialsMode::Allow)
                )
            ));
            assert_eq!(
                parsed.output_path.into_option().as_deref(),
                Some("/tmp/denials.json")
            );
            assert_eq!(parsed.retain_etl.into_option(), Some(true));
        }

        let omitted = serde_json::json!({
            "mode": wire_mode(CaptureDenialsMode::Block),
            "retainEtl": false,
        });
        let parsed: ContractCaptureDenials = serde_json::from_value(omitted)
            .expect("omitted outputPath satisfies the exact contract");
        assert!(parsed.output_path.into_option().is_none());
        assert_eq!(parsed.retain_etl.into_option(), Some(false));
    }

    // `captureDenials` and `network.proxy` are independent: capture records
    // ungranted access checks, while the proxy is a cooperative egress route.
    // The shared parser owns the wire contract and its `captureDenials` branch
    // is not Windows-gated, so drive it directly to pin the combination on
    // every platform. The only documented mutual exclusion is with the
    // `--audit` CLI flag (docs/logging-access-denied.md), which
    // `wxc-exec` enforces in `validate_audit_request`.
    #[test]
    fn wire_contract_accepts_capture_denials_together_with_a_network_proxy() {
        let config = serde_json::json!({
            "version": "0.9.0-alpha",
            "process": { "commandLine": TEST_COMMAND },
            "containment": "processcontainer",
            "network": {
                "egress": {"default": "deny"},
                "ingress": {"default": "allow", "hostLoopback": "allow"},
            },
            "runtimeConfig": {"networkProxy": "http://127.0.0.1:8080"},
            "processContainer": {
                "captureDenials": { "mode": "allow" },
            },
        });

        let mut logger = super::Logger::new(super::Mode::Buffer);
        let json = serde_json::to_string(&config).unwrap();
        let request =
            match crate::mxc_common::config_parser::load_mxc_request_from_json(&json, &mut logger)
                .expect("captureDenials alongside network.proxy satisfies the exact contract")
            {
                crate::mxc_common::state_aware_request::MxcRequest::OneShot(request) => request,
                crate::mxc_common::state_aware_request::MxcRequest::StateAware(_) => {
                    panic!("expected a one-shot request")
                }
            };

        assert!(
            request.policy.capture_denials.is_some(),
            "captureDenials must survive alongside a proxy"
        );
        assert!(
            request.policy.network_proxy.is_enabled(),
            "network.proxy must survive alongside captureDenials"
        );
    }

    // The end-to-end counterpart of the contract test above: the typed policy
    // emits both sections and the parser accepts the result unchanged.
    use super::{build_request_with_containment, Containment, ProcessContainerConfig, WslcConfig};
    use crate::mxc_common::models::ContainmentBackend;

    fn minimal_policy() -> ContainerPolicy {
        ContainerPolicy::default()
    }

    fn policy_with_network(network: NetworkPolicy) -> ContainerPolicy {
        ContainerPolicy {
            network: Some(network),
            ..ContainerPolicy::default()
        }
    }

    #[test]
    fn default_containment_resolves_the_host_backend() {
        // `build_request` must keep resolving the host's native backend — the
        // WSLC selection is explicit and must not change the default.
        let request = build_request(&minimal_policy(), TEST_COMMAND, None).expect("build_request");
        assert_ne!(request.inner.containment, ContainmentBackend::Wslc);
    }

    #[test]
    fn wslc_containment_maps_config_to_the_request() {
        // Mirrors `createConfigFromPolicy(policy, 'wslc')` plus a tweaked
        // `wslc` block: the wire config goes through the shared
        // parser, so the mapped request carries the WSLC settings verbatim.
        let wslc = WslcConfig {
            image: "python:3.12".to_string(),
            cpu_count: Some(2),
            memory_mb: Some(2048),
            gpu: true,
            storage_path: Some("C:\\wslc-store".to_string()),
            port_mappings: vec![(8080, 80)],
            ..Default::default()
        };
        let request = build_request_with_containment(
            &minimal_policy(),
            &Containment::Wslc(wslc),
            TEST_COMMAND,
            None,
        )
        .expect("build_request_with_containment");

        assert_eq!(request.inner.containment, ContainmentBackend::Wslc);
        let config = request.inner.wslc.as_ref().expect("wslc config");
        assert_eq!(config.image, "python:3.12");
        assert_eq!(config.cpu_count, Some(2));
        assert_eq!(config.memory_mb, Some(2048));
        assert!(config.gpu);
        assert_eq!(config.storage_path.as_deref(), Some("C:\\wslc-store"));
        assert_eq!(config.port_mappings.len(), 1);
        assert_eq!(config.port_mappings[0].windows_port, 8080);
        assert_eq!(config.port_mappings[0].container_port, 80);
        assert_eq!(config.port_mappings[0].protocol, "tcp");
    }

    #[test]
    fn wslc_defaults_match_the_sdk() {
        // `WslcConfig::default()` must produce the same block the TypeScript
        // SDK's `buildWslcContainerConfig` emits (image only, alpine:latest).
        let request = build_request_with_containment(
            &minimal_policy(),
            &Containment::Wslc(WslcConfig::default()),
            TEST_COMMAND,
            None,
        )
        .expect("build_request_with_containment");
        let config = request.inner.wslc.as_ref().expect("wslc config");
        assert_eq!(config.image, "alpine:latest");
        assert_eq!(config.target_os, "linux");
        assert!(config.port_mappings.is_empty());
        assert!(!config.gpu);
    }

    #[test]
    fn wslc_does_not_enable_experimental_features() {
        let request = build_request_with_containment(
            &minimal_policy(),
            &Containment::Wslc(WslcConfig::default()),
            TEST_COMMAND,
            None,
        )
        .expect("build_request_with_containment");
        assert!(!request.inner.experimental_enabled);
    }

    #[test]
    fn telemetry_enablement_is_stable_and_independent_of_experimental_mode() {
        let mut request =
            build_request(&minimal_policy(), TEST_COMMAND, None).expect("build_request");
        assert!(request.inner.telemetry.is_none());
        assert!(!request.inner.experimental_enabled);

        request.set_telemetry_opt_in(true);
        assert_eq!(request.telemetry_enabled(), Some(true));
        assert_eq!(
            request
                .inner
                .telemetry
                .as_ref()
                .and_then(|telemetry| telemetry.requested_sandbox_kind),
            Some("process")
        );
        assert!(
            !request.inner.experimental_enabled,
            "stable telemetry enablement must not opt into experimental features"
        );

        request.set_telemetry_opt_in(false);
        assert_eq!(request.telemetry_enabled(), Some(false));
        assert!(!request.inner.experimental_enabled);
    }

    #[test]
    fn telemetry_enablement_preserves_explicit_containment_intent() {
        let containment = ProcessContainerConfig::default();
        let mut request = build_request_with_containment(
            &minimal_policy(),
            &Containment::ProcessContainer(containment),
            TEST_COMMAND,
            None,
        )
        .expect("build_request_with_containment");

        request.set_telemetry_opt_in(true);

        assert_eq!(
            request
                .inner
                .telemetry
                .as_ref()
                .and_then(|telemetry| telemetry.requested_sandbox_kind),
            Some("processcontainer")
        );
    }

    #[test]
    fn wslc_rejects_an_invalid_port_mapping() {
        // Validation is the shared parser's, so a bad mapping is rejected at
        // build time rather than at spawn.
        let wslc = WslcConfig {
            port_mappings: vec![(8080, 80), (8080, 81)],
            ..Default::default()
        };
        let err = build_request_with_containment(
            &minimal_policy(),
            &Containment::Wslc(wslc),
            TEST_COMMAND,
            None,
        )
        .expect_err("duplicate windowsPort must be rejected");
        assert!(
            err.message.contains("duplicate windowsPort"),
            "got: {}",
            err.message
        );
    }

    /// The canonical unrestricted-network acknowledgment the IsolationSession
    /// backend requires: outbound allowed, local network allowed, no host
    /// rules, no proxy.
    fn isolation_session_directional_network() -> NetworkPolicy {
        NetworkPolicy {
            egress: Some(NetworkEgressPolicy {
                default: Some(NetworkAction::Allow),
                ..Default::default()
            }),
            ingress: Some(NetworkIngressPolicy {
                default: Some(NetworkAction::Allow),
                host_loopback: Some(NetworkAction::Allow),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn isolation_session_names_the_backend_and_carries_no_section() {
        // The one-shot surface takes no backend configuration at all.
        let policy = policy_with_network(isolation_session_directional_network());
        let request = build_request_with_containment(
            &policy,
            &Containment::IsolationSession,
            TEST_COMMAND,
            None,
        )
        .expect("build request");
        assert_eq!(
            request.inner.containment,
            crate::mxc_common::models::ContainmentBackend::IsolationSession
        );
        assert!(request.inner.test_feature.is_none());
        assert!(request.inner.windows_sandbox.is_none());
        assert!(request.inner.wslc.is_none());
    }

    #[test]
    fn isolation_session_does_not_enable_the_generic_experimental_flag() {
        let policy = policy_with_network(isolation_session_directional_network());
        let request = build_request_with_containment(
            &policy,
            &Containment::IsolationSession,
            TEST_COMMAND,
            None,
        )
        .expect("build_request_with_containment");
        assert!(!request.inner.experimental_enabled);
    }

    #[test]
    fn isolation_session_selects_the_backend() {
        let policy = policy_with_network(isolation_session_directional_network());
        let request = build_request_with_containment(
            &policy,
            &Containment::IsolationSession,
            TEST_COMMAND,
            None,
        )
        .expect("build_request_with_containment");
        assert_eq!(
            request.inner.containment,
            ContainmentBackend::IsolationSession
        );
    }

    #[test]
    fn isolation_session_requires_an_explicit_network_policy() {
        let error = build_request_with_containment(
            &minimal_policy(),
            &Containment::IsolationSession,
            TEST_COMMAND,
            None,
        )
        .expect_err("IsolationSession must require its unrestricted network acknowledgment");

        assert!(
            error
                .message
                .contains("IsolationSession requires an explicit network policy"),
            "unexpected error: {error}"
        );
    }
}
