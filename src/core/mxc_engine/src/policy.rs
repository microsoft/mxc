// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Policy discovery and config building — the Rust port of the SDK's
//! `policy.ts` helpers and `createConfigFromPolicy`.
//!
//! - [`available_tools_policy`], [`user_profile_policy`], and
//!   [`temporary_files_policy`] enumerate the host environment to discover
//!   tool/SDK/profile/temp directories as filesystem-policy fragments.
//! - [`SandboxPolicy`] mirrors the SDK's cross-platform policy type, and
//!   [`build_request`] maps it to an [`ExecutionRequest`] for the backends the
//!   crate supports (Seatbelt, Bubblewrap, ProcessContainer) — so callers no
//!   longer need the TypeScript SDK to build a spawnable config.

use std::borrow::Cow;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use wxc_common::logger::{Logger, Mode};
use wxc_common::models::ExecutionRequest;
use wxc_common::mxc_error::MxcError;

// ---------------------------------------------------------------------------
// Filesystem policy discovery
// ---------------------------------------------------------------------------

/// A composable fragment of filesystem policy. Callers merge one or more into
/// a [`SandboxPolicy`]'s filesystem section.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilesystemPolicyResult {
    /// Paths to grant read-only access inside the sandbox.
    pub readonly_paths: Vec<String>,
    /// Paths to grant read-write access inside the sandbox.
    pub readwrite_paths: Vec<String>,
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

/// PowerShell-specific policy: when `pwsh.exe` is found on `path_dirs`
/// (Windows only), grant the system-drive root (`C:\`) read-only — `pwsh.exe`
/// enumerates the drive root on startup — plus the PSReadLine history directory
/// read-write so the module can persist command history.
///
/// Mirrors the SDK's `getPowerShellPolicy`. The system drive is read from the
/// process environment (`SystemDrive`, defaulting to `C:`); the user-scoped
/// `USERPROFILE` comes from the passed-in `env`.
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

    let system_drive = std::env::var("SystemDrive")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "C:".to_string());
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

/// Discover tool and SDK directories from `env` (defaults to the process
/// environment) as read-only policy paths.
///
/// Reads `PATH` plus a registry of well-known tool/SDK variables, then filters
/// out non-existent and system-critical directories, and adds PowerShell paths
/// when `pwsh.exe` is on `PATH`. The Rust port of `getAvailableToolsPolicy`.
/// (The SDK's `processcontainer` AAP-ACL filter is Windows-runtime-specific and
/// is applied server-side; it is not replicated here.)
pub fn available_tools_policy(env: Option<&[(String, String)]>) -> FilesystemPolicyResult {
    let env = env_or_process(env);
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
        .collect();

    let pwsh = powershell_policy(&path_dirs, env);

    let mut readonly = filtered;
    readonly.extend(pwsh.readonly_paths);

    FilesystemPolicyResult {
        readonly_paths: deduplicate_paths(&readonly),
        readwrite_paths: deduplicate_paths(&pwsh.readwrite_paths),
    }
}

/// Read-only policy for standard user-profile application data locations.
///
/// Windows: immediate subdirectories of `%LOCALAPPDATA%\Programs`. Other
/// platforms: `~/.local/bin` and `~/.local/lib`. The Rust port of
/// `getUserProfilePolicy`.
pub fn user_profile_policy() -> FilesystemPolicyResult {
    let mut readonly_paths = Vec::new();

    if is_windows() {
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            if directory_exists(&local_app_data) {
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
    } else if let Ok(home) = std::env::var("HOME") {
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
pub fn temporary_files_policy(env: Option<&[(String, String)]>) -> FilesystemPolicyResult {
    let env = env_or_process(env);
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
// SandboxPolicy -> ExecutionRequest
// ---------------------------------------------------------------------------

/// Clipboard access level, mirroring the SDK `ClipboardPolicy`
/// (`"none" | "read" | "write" | "all"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
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

impl ClipboardPolicy {
    /// Wire-format value accepted by the config parser.
    fn wire(self) -> &'static str {
        match self {
            ClipboardPolicy::None => "none",
            ClipboardPolicy::Read => "read",
            ClipboardPolicy::Write => "write",
            ClipboardPolicy::All => "all",
        }
    }
}

/// Filesystem section of a [`SandboxPolicy`].
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FilesystemSection {
    pub readwrite_paths: Vec<String>,
    pub readonly_paths: Vec<String>,
    pub denied_paths: Vec<String>,
    /// Clear the filesystem policy when the shell exits (default `true`).
    pub clear_policy_on_exit: Option<bool>,
}

/// Network proxy configuration, mirroring the SDK union type
/// `{ builtinTestServer: true } | { localhost: number } | { url: string }`.
#[derive(Debug, Clone)]
pub enum ProxySpec {
    /// Route through the built-in test proxy server.
    BuiltinTestServer,
    /// Route through `127.0.0.1:<port>`.
    Localhost(u16),
    /// Route through an explicit proxy URL.
    Url(String),
}

// Custom `Deserialize` matching the SDK's object union
// `{ builtinTestServer: true } | { localhost: number } | { url: string }`.
// serde's default derive can't express it, and an untagged enum would silently
// keep the first matching variant when several conflicting keys are present, so
// we parse all recognised modes and require exactly one — rejecting conflicts
// the way the shared wire-config parser does.
impl<'de> serde::Deserialize<'de> for ProxySpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Raw {
            #[serde(default)]
            builtin_test_server: Option<bool>,
            #[serde(default)]
            localhost: Option<u16>,
            #[serde(default)]
            url: Option<String>,
        }
        let raw = Raw::deserialize(deserializer)?;
        match (raw.builtin_test_server, raw.localhost, raw.url) {
            (Some(true), None, None) => Ok(ProxySpec::BuiltinTestServer),
            // The SDK union type is `{ builtinTestServer: true }`, so an explicit
            // `false` is malformed. Reject it rather than silently selecting the
            // (experimental, deliberately-permissive) built-in proxy — fail closed.
            (Some(false), None, None) => Err(serde::de::Error::custom(
                "network.proxy.builtinTestServer must be true; omit the proxy to disable it",
            )),
            (None, Some(port), None) => Ok(ProxySpec::Localhost(port)),
            (None, None, Some(url)) => Ok(ProxySpec::Url(url)),
            _ => Err(serde::de::Error::custom(
                "network.proxy must set exactly one of builtinTestServer, localhost, or url",
            )),
        }
    }
}

/// Network section of a [`SandboxPolicy`]. All flags default to deny.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct NetworkSection {
    pub allow_outbound: bool,
    pub allow_local_network: bool,
    pub allowed_hosts: Vec<String>,
    pub blocked_hosts: Vec<String>,
    pub proxy: Option<ProxySpec>,
}

/// UI section of a [`SandboxPolicy`]. All flags default to denied.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UiSection {
    pub allow_windows: bool,
    pub clipboard: ClipboardPolicy,
    pub allow_input_injection: bool,
}

/// Cross-platform sandbox policy — the Rust analogue of the SDK
/// `SandboxPolicy`. Describes *what* to restrict; omitted fields are
/// most-restrictive (default-deny).
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxPolicy {
    /// Policy/schema version (e.g. `"0.7.0-alpha"`).
    pub version: String,
    #[serde(default)]
    pub filesystem: Option<FilesystemSection>,
    #[serde(default)]
    pub network: Option<NetworkSection>,
    #[serde(default)]
    pub ui: Option<UiSection>,
    /// Execution timeout in milliseconds (`None` = no timeout).
    #[serde(default)]
    pub timeout_ms: Option<u32>,
}

/// A spawnable sandbox request, built from a [`SandboxPolicy`] by
/// [`build_request`]. Fill in the command with
/// [`set_script`](Self::set_script) — and optionally a working
/// directory or environment — then hand it to
/// [`spawn`](crate::spawn).
///
/// This is the SDK's own request type; the internal execution model it maps to
/// is an implementation detail callers don't depend on.
#[derive(Debug, Clone)]
pub struct SandboxRequest {
    /// The internal execution model. `pub(crate)` so the SDK's own modules and
    /// unit tests can map/inspect it, while it stays out of the public API.
    pub(crate) inner: ExecutionRequest,
}

impl SandboxRequest {
    /// Set the command the sandbox runs — the `/bin/sh -c` body on Unix, the
    /// command line on Windows.
    ///
    /// This is the raw command string, mapped to the same `script_code` the
    /// executor binaries run, so it is interpreted exactly as the SDK's
    /// `spawnSandbox(script)` / `process.commandLine` is — behavior is identical
    /// across the SDK and this crate.
    pub fn set_script(&mut self, script: impl Into<String>) -> &mut Self {
        self.inner.script_code = script.into();
        self
    }

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
    pub fn set_env<K, V>(&mut self, env: impl IntoIterator<Item = (K, V)>) -> &mut Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        self.inner.env = env
            .into_iter()
            .map(|(k, v)| {
                let (k, v): (String, String) = (k.into(), v.into());
                format!("{k}={v}")
            })
            .collect();
        self
    }

    /// The Seatbelt (macOS) extra Mach service names the sandbox profile lets the
    /// child look up. Empty when the request carries no Seatbelt config (i.e. a
    /// non-Seatbelt backend). Read these — e.g. to union with your own — before
    /// [`set_seatbelt_extra_mach_lookups`](Self::set_seatbelt_extra_mach_lookups).
    pub fn seatbelt_extra_mach_lookups(&self) -> &[String] {
        self.inner
            .seatbelt
            .as_ref()
            .map_or(&[], |s| s.extra_mach_lookups.as_slice())
    }

    /// Set the Seatbelt (macOS) extra Mach service names the child may look up.
    /// Creates a default Seatbelt config if the request carries none.
    pub fn set_seatbelt_extra_mach_lookups(&mut self, lookups: Vec<String>) -> &mut Self {
        self.inner
            .seatbelt
            .get_or_insert_default()
            .extra_mach_lookups = lookups;
        self
    }

    /// Allow (or deny) the Seatbelt-sandboxed (macOS) child access to the system
    /// keychain. Creates a default Seatbelt config if the request carries none.
    pub fn set_seatbelt_keychain_access(&mut self, allow: bool) -> &mut Self {
        self.inner.seatbelt.get_or_insert_default().keychain_access = allow;
        self
    }
}

/// Build a [`SandboxRequest`] from a [`SandboxPolicy`], resolving the host's
/// containment backend — the Rust port of the SDK's `createConfigFromPolicy`.
///
/// The returned request has an empty command line; set the command with
/// [`SandboxRequest::set_script`] (and any working directory / env) before
/// streaming it via [`crate::spawn`].
///
/// Mirrors the SDK field mapping and validation (network proxy/host-filtering
/// constraints) for the supported backends. Internally it builds the same
/// wire-format `ContainerConfig` the SDK emits and runs it through the shared
/// config parser, so validation and the wire→model mapping match production.
pub fn build_request(
    policy: &SandboxPolicy,
    container_name: Option<&str>,
) -> Result<SandboxRequest, crate::Error> {
    // The shared parser tolerates an empty schema version (treats it as
    // "unset"), but the SDK requires it; reject it here for parity.
    if policy.version.is_empty() {
        return Err(MxcError::malformed_request("Policy version is required").into());
    }
    let config = build_wire_config(policy, container_name)?;

    let mut logger = Logger::new(Mode::Buffer);
    // Map the wire config straight to a request — no base64/file round-trip.
    // The command line is intentionally empty here (the caller fills
    // `script_code` before running), so tolerate a missing command.
    let inner = wxc_common::config_parser::load_request_from_value(config, &mut logger, true)
        .map_err(|e| MxcError::malformed_request(format!("failed to build request: {e}")))?;
    Ok(SandboxRequest { inner })
}

/// Construct the wire-format `ContainerConfig` JSON value for the supported
/// backends, mirroring `createConfigFromPolicy` + the per-backend builders.
fn build_wire_config(
    policy: &SandboxPolicy,
    container_name: Option<&str>,
) -> Result<serde_json::Value, MxcError> {
    use serde_json::json;

    let container_id = container_name
        .map(str::to_string)
        .unwrap_or_else(wxc_common::id::mint_random_token);

    let fs = policy.filesystem.clone().unwrap_or_default();
    let clear_policy = fs.clear_policy_on_exit.unwrap_or(true);

    let mut config = json!({
        "version": policy.version,
        "containerId": container_id,
        "lifecycle": { "destroyOnExit": true, "preservePolicy": !clear_policy },
        "process": { "commandLine": "", "timeout": policy.timeout_ms.unwrap_or(0) },
        "filesystem": {
            "readwritePaths": fs.readwrite_paths,
            "readonlyPaths": fs.readonly_paths,
            "deniedPaths": fs.denied_paths,
        },
        "ui": {
            "disable": !policy.ui.as_ref().map(|u| u.allow_windows).unwrap_or(false),
            "clipboard": policy.ui.as_ref().map(|u| u.clipboard).unwrap_or_default().wire(),
            "injection": policy.ui.as_ref().map(|u| u.allow_input_injection).unwrap_or(false),
        },
    });

    // Mirror the SDK's `resolvesToHostFilteringBackend` (sdk/src/sandbox.ts):
    // Linux (Bubblewrap/LXC) and macOS (Seatbelt) are treated as host-filtering
    // backends, so `allowedHosts`/`blockedHosts` are accepted without
    // `allowOutbound`; only Windows ProcessContainer requires `allowOutbound`.
    // NB: Seatbelt can't actually enforce hostnames (`profile_builder` degrades a
    // non-empty `allowedHosts` to allow-all outbound), but we accept it on macOS
    // anyway to stay consistent with the SDK rather than diverging — keeping the
    // two ports reconciled matters more than being stricter here.
    let targets_host_filtering_backend = cfg!(any(target_os = "linux", target_os = "macos"));

    if let Some(net) = &policy.network {
        if net.proxy.is_some() && cfg!(target_os = "macos") {
            return Err(MxcError::malformed_request(
                "Proxy configuration is not supported on macOS",
            ));
        }

        if !targets_host_filtering_backend
            && (!net.allowed_hosts.is_empty() || !net.blocked_hosts.is_empty())
            && !net.allow_outbound
        {
            return Err(MxcError::malformed_request(
                "allowedHosts/blockedHosts require allowOutbound to be true",
            ));
        }

        let mut network = json!({
            "defaultPolicy": if net.allow_outbound { "allow" } else { "block" },
            "allowLocalNetwork": net.allow_local_network,
            "allowedHosts": net.allowed_hosts,
            "blockedHosts": net.blocked_hosts,
        });
        if let Some(proxy) = &net.proxy {
            network["proxy"] = proxy_to_wire(proxy);
        }
        config["network"] = network;
    } else {
        config["network"] = json!({ "defaultPolicy": "block" });
    }

    apply_backend(&mut config, policy, &container_id);
    Ok(config)
}

fn proxy_to_wire(proxy: &ProxySpec) -> serde_json::Value {
    use serde_json::json;
    match proxy {
        ProxySpec::BuiltinTestServer => json!({ "builtinTestServer": true }),
        ProxySpec::Localhost(port) => json!({ "localhost": port }),
        ProxySpec::Url(url) => json!({ "url": url }),
    }
}

/// Apply backend-specific fields, resolving the abstract `Process` intent the
/// same way the SDK does (Bubblewrap on Linux, Seatbelt on macOS,
/// ProcessContainer on Windows — which itself resolves to BaseContainer or
/// AppContainer at runtime by host capability).
fn apply_backend(config: &mut serde_json::Value, policy: &SandboxPolicy, container_id: &str) {
    use serde_json::json;

    // Resolve the abstract Process intent per host.
    config["containment"] = json!("process");

    #[cfg(target_os = "linux")]
    {
        let _ = (policy, container_id);
        apply_linux_network_policy(config);
    }

    #[cfg(target_os = "macos")]
    {
        let _ = (policy, container_id);
        config["containment"] = json!("seatbelt");
        if config.get("seatbelt").is_none() {
            config["seatbelt"] = json!({});
        }
    }

    #[cfg(target_os = "windows")]
    {
        let mut capabilities: Vec<&str> = Vec::new();
        if let Some(net) = &policy.network {
            if net.allow_outbound {
                capabilities.push("internetClient");
            }
            if net.allow_local_network {
                capabilities.push("privateNetworkClientServer");
            }
        }
        // The container id is carried only at the top level (`containerId`); the
        // wire `processContainer` object intentionally has no `name` field.
        let _ = container_id;
        config["processContainer"] = json!({
            "leastPrivilege": false,
            "capabilities": capabilities,
            "ui": {
                "isolation": "container",
                "desktopSystemControl": false,
                "systemSettings": "none",
                "ime": false,
            },
        });
        if let Some(network) = config.get_mut("network") {
            let mode = if has_host_rules(network) {
                "both"
            } else {
                "capabilities"
            };
            network["enforcementMode"] = json!(mode);
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = (policy, container_id);
    }
}

/// True when the network section carries any host allow/deny rules, deciding
/// whether host-level enforcement is engaged. (Linux + Windows only.)
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn has_host_rules(network: &serde_json::Value) -> bool {
    let non_empty = |key: &str| {
        network
            .get(key)
            .and_then(|v| v.as_array())
            .is_some_and(|a| !a.is_empty())
    };
    non_empty("allowedHosts") || non_empty("blockedHosts")
}

/// Promote network enforcement to `firewall` when host rules are present and
/// no cooperative proxy is configured — the Linux counterpart of the SDK's
/// `applyLinuxNetworkPolicy`.
#[cfg(target_os = "linux")]
fn apply_linux_network_policy(config: &mut serde_json::Value) {
    use serde_json::json;
    let Some(network) = config.get_mut("network") else {
        return;
    };
    let has_proxy = network.get("proxy").is_some();
    if has_host_rules(network) && !has_proxy {
        network["enforcementMode"] = json!("firewall");
    }
}

#[cfg(test)]
mod tests {
    use super::ProxySpec;

    #[test]
    fn proxy_builtin_test_server_true_is_accepted() {
        let spec: ProxySpec =
            serde_json::from_str(r#"{ "builtinTestServer": true }"#).expect("true is valid");
        assert!(matches!(spec, ProxySpec::BuiltinTestServer));
    }

    #[test]
    fn proxy_builtin_test_server_false_is_rejected() {
        // An explicit `false` must not silently select the (experimental,
        // deliberately-permissive) built-in proxy — it is rejected as malformed.
        let err = serde_json::from_str::<ProxySpec>(r#"{ "builtinTestServer": false }"#)
            .expect_err("false must be rejected");
        assert!(
            err.to_string().contains("builtinTestServer must be true"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn proxy_conflicting_modes_are_rejected() {
        // Several modes at once must be rejected (cr-005), not silently reduced
        // to the first matching one.
        let err = serde_json::from_str::<ProxySpec>(
            r#"{ "builtinTestServer": true, "localhost": 8080 }"#,
        )
        .expect_err("conflicting proxy modes must be rejected");
        assert!(
            err.to_string().contains("exactly one"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn proxy_localhost_and_url_still_parse() {
        assert!(matches!(
            serde_json::from_str::<ProxySpec>(r#"{ "localhost": 8080 }"#).expect("localhost"),
            ProxySpec::Localhost(8080)
        ));
        assert!(matches!(
            serde_json::from_str::<ProxySpec>(r#"{ "url": "http://proxy" }"#).expect("url"),
            ProxySpec::Url(_)
        ));
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

    use super::{build_request, NetworkSection, SandboxPolicy};

    fn policy_with_network(network: NetworkSection) -> SandboxPolicy {
        SandboxPolicy {
            version: "0.7.0-alpha".to_string(),
            filesystem: None,
            network: Some(network),
            ui: None,
            timeout_ms: None,
        }
    }

    // macOS Seatbelt is treated as a host-filtering backend to mirror the SDK
    // (`resolvesToHostFilteringBackend` in sdk/src/sandbox.ts), so `allowedHosts`
    // is accepted with or without `allowOutbound` — consistency with the SDK over
    // rejecting on macOS, even though Seatbelt can't actually filter by host.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_allowed_hosts_without_outbound_is_accepted() {
        // The SDK accepts allowedHosts without allowOutbound on Seatbelt, so the
        // Rust port must too (the guard only applies to Windows ProcessContainer).
        let policy = policy_with_network(NetworkSection {
            allow_outbound: false,
            allowed_hosts: vec!["example.com".to_string()],
            ..Default::default()
        });
        assert!(
            build_request(&policy, None).is_ok(),
            "macOS must accept allowedHosts without allowOutbound, matching the SDK"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_allowed_hosts_with_outbound_is_accepted() {
        // allowOutbound=true is the caller explicitly allowing outbound, so it
        // builds (allowedHosts simply isn't enforceable on Seatbelt).
        let policy = policy_with_network(NetworkSection {
            allow_outbound: true,
            allowed_hosts: vec!["example.com".to_string()],
            ..Default::default()
        });
        assert!(
            build_request(&policy, None).is_ok(),
            "outbound-allowed host filter should build"
        );
    }

    #[test]
    fn build_request_maps_filesystem_and_timeout() {
        let policy = SandboxPolicy {
            version: "0.7.0-alpha".to_string(),
            filesystem: Some(super::FilesystemSection {
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
        // API only hands back the opaque `SandboxRequest`.
        let request =
            build_request(&policy, Some("test-container")).expect("build_request should succeed");
        assert_eq!(request.inner.script_timeout, 5000);
        assert!(request
            .inner
            .policy
            .readwrite_paths
            .contains(&"/tmp".to_string()));
        assert!(request.inner.script_code.is_empty());
    }

    #[test]
    fn set_env_formats_pairs_as_key_value_in_order() {
        // The structured `(key, value)` setter mirrors the SDK env channel
        // (`injectEnvIntoConfig`): each pair becomes a `KEY=VALUE` wire entry, in
        // iteration order so a later duplicate key wins downstream.
        let policy = SandboxPolicy {
            version: "0.7.0-alpha".to_string(),
            filesystem: None,
            network: None,
            ui: None,
            timeout_ms: None,
        };
        let mut request = build_request(&policy, None).expect("build_request should succeed");
        request.set_env([("FIRST", "1"), ("SECOND", "2")]);
        assert_eq!(request.inner.env, vec!["FIRST=1", "SECOND=2"]);
    }

    #[test]
    fn build_request_preserves_clipboard_policy() {
        use super::ClipboardPolicy as P;
        use wxc_common::models::ClipboardPolicy as Wire;

        for (input, expected) in [
            (P::None, Wire::None),
            (P::Read, Wire::Read),
            (P::Write, Wire::Write),
            (P::All, Wire::All),
        ] {
            let policy = SandboxPolicy {
                version: "0.7.0-alpha".to_string(),
                filesystem: None,
                network: None,
                ui: Some(super::UiSection {
                    allow_windows: true,
                    clipboard: input,
                    allow_input_injection: false,
                }),
                timeout_ms: None,
            };
            let request = build_request(&policy, None).expect("build_request should succeed");
            assert_eq!(
                request.inner.policy.ui.clipboard, expected,
                "clipboard {input:?} should map to {expected:?}"
            );
        }
    }

    #[test]
    fn build_request_maps_network_hosts() {
        let policy = policy_with_network(NetworkSection {
            allow_outbound: true,
            allow_local_network: true,
            allowed_hosts: vec!["allowed.example".to_string()],
            blocked_hosts: vec!["blocked.example".to_string()],
            ..Default::default()
        });
        let request = build_request(&policy, None)
            .expect("build_request should accept host rules with allowOutbound");
        assert!(request
            .inner
            .policy
            .allowed_hosts
            .contains(&"allowed.example".to_string()));
        assert!(request
            .inner
            .policy
            .blocked_hosts
            .contains(&"blocked.example".to_string()));
        assert!(request.inner.policy.allow_local_network);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn seatbelt_extra_mach_lookups_and_keychain_round_trip() {
        let policy = SandboxPolicy {
            version: "0.7.0-alpha".to_string(),
            filesystem: None,
            network: None,
            ui: None,
            timeout_ms: None,
        };
        // build_request resolves Seatbelt on macOS, so the config is present and
        // the consumer can read its defaults and write back.
        let mut request = build_request(&policy, None).expect("build_request");
        let mut union: Vec<String> = request.seatbelt_extra_mach_lookups().to_vec();
        union.push("com.example.service".to_string());
        request.set_seatbelt_extra_mach_lookups(union.clone());
        request.set_seatbelt_keychain_access(true);

        assert_eq!(request.seatbelt_extra_mach_lookups(), union.as_slice());
        let cfg = request
            .inner
            .seatbelt
            .as_ref()
            .expect("seatbelt config on macOS");
        assert!(cfg.keychain_access);
        assert!(cfg
            .extra_mach_lookups
            .contains(&"com.example.service".to_string()));
    }
}
