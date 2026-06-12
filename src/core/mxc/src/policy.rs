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

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use wxc_common::config_parser::{load_request_with_options, LoadOptions};
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
        let win_dir = std::env::var("WINDIR")
            .or_else(|_| std::env::var("windir"))
            .unwrap_or_else(|_| "C:\\Windows".to_string())
            .to_lowercase();
        let n = normalized.to_lowercase();
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
    env.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

/// PowerShell-specific policy: when `pwsh.exe` is found on `path_dirs`
/// (Windows only), expose the drive root read-only and the PSReadLine history
/// dir read-write. Mirrors the SDK's `getPowerShellPolicy`.
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

    // `SystemDrive` is read from the process environment (matching the SDK,
    // which uses `process.env["SystemDrive"]` here even though USERPROFILE
    // comes from the passed-in `env`).
    let system_drive = std::env::var("SystemDrive")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "C:".to_string());
    let mut result = FilesystemPolicyResult {
        readonly_paths: vec![format!("{system_drive}\\")],
        readwrite_paths: Vec::new(),
    };
    if let Some(user_profile) = env_get(env, "USERPROFILE") {
        let ps_readline: PathBuf = [
            user_profile,
            "AppData",
            "Roaming",
            "Microsoft",
            "Windows",
            "PowerShell",
            "PSReadLine",
        ]
        .iter()
        .collect();
        result
            .readwrite_paths
            .push(ps_readline.to_string_lossy().into_owned());
    }
    result
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
    let owned_env;
    let env: &[(String, String)] = match env {
        Some(e) => e,
        None => {
            owned_env = std::env::vars().collect::<Vec<_>>();
            &owned_env
        }
    };

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
    let owned_env;
    let env: &[(String, String)] = match env {
        Some(e) => e,
        None => {
            owned_env = std::env::vars().collect::<Vec<_>>();
            &owned_env
        }
    };

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

/// Network proxy configuration, mirroring the SDK union type.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProxySpec {
    /// Route through the built-in test proxy server.
    BuiltinTestServer,
    /// Route through `127.0.0.1:<port>`.
    Localhost(u16),
    /// Route through an explicit proxy URL.
    Url(String),
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

/// Containment intent accepted by [`build_request`], restricted to the
/// backends the `mxc` library can run. `Process` is the abstract intent that
/// resolves per-host (Seatbelt on macOS, Bubblewrap on Linux, ProcessContainer
/// on Windows); `Bubblewrap` forces the Linux Bubblewrap backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Containment {
    #[default]
    Process,
    Bubblewrap,
}

/// Build an [`ExecutionRequest`] from a [`SandboxPolicy`] for a supported
/// containment backend — the Rust port of the SDK's `createConfigFromPolicy`.
///
/// The returned request has an empty command line; callers set `script_code`
/// (and `working_directory` / `env`) before running it via
/// [`crate::spawn_sandbox_from_request`] or streaming it via
/// [`crate::spawn_streaming_from_request`].
///
/// Mirrors the SDK field mapping and validation (network proxy/host-filtering
/// constraints) for the supported backends. Internally it builds the same
/// wire-format `ContainerConfig` the SDK emits and runs it through the shared
/// config parser, so validation and the wire→model mapping match production.
pub fn build_request(
    policy: &SandboxPolicy,
    containment: Containment,
    container_name: Option<&str>,
) -> Result<ExecutionRequest, MxcError> {
    let config = build_wire_config(policy, containment, container_name)?;
    let json = serde_json::to_string(&config)
        .map_err(|e| MxcError::malformed_request(format!("failed to serialise config: {e}")))?;
    let encoded = wxc_common::encoding::base64_encode(json.as_bytes());

    let mut logger = Logger::new(Mode::Buffer);
    // The command line is intentionally empty here — the caller fills
    // `script_code` before running — so tolerate a missing command.
    let opts = LoadOptions {
        is_base64: true,
        allow_missing_command: true,
    };
    load_request_with_options(&encoded, &mut logger, opts)
        .map_err(|e| MxcError::malformed_request(format!("failed to build request: {e}")))
}

/// Construct the wire-format `ContainerConfig` JSON value for the supported
/// backends, mirroring `createConfigFromPolicy` + the per-backend builders.
fn build_wire_config(
    policy: &SandboxPolicy,
    containment: Containment,
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

    let targets_host_filtering_backend = matches!(containment, Containment::Bubblewrap)
        || (matches!(containment, Containment::Process)
            && (cfg!(target_os = "linux") || cfg!(target_os = "macos")));

    if let Some(net) = &policy.network {
        if net.proxy.is_some() {
            if cfg!(target_os = "macos") {
                return Err(MxcError::malformed_request(
                    "Proxy configuration is not supported on macOS",
                ));
            }
            if cfg!(target_os = "linux") && !targets_host_filtering_backend {
                return Err(MxcError::malformed_request(
                    "Proxy configuration on Linux requires containment 'bubblewrap' or 'process'",
                ));
            }
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

    apply_backend(&mut config, policy, containment, &container_id);
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
/// BaseContainer on Windows).
fn apply_backend(
    config: &mut serde_json::Value,
    policy: &SandboxPolicy,
    containment: Containment,
    container_id: &str,
) {
    use serde_json::json;

    if matches!(containment, Containment::Bubblewrap) {
        config["containment"] = json!("bubblewrap");
        apply_linux_network_policy(config);
        return;
    }

    // Containment::Process — resolve per host.
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
        config["processContainer"] = json!({
            "name": container_id,
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
            let has_host_rules = network
                .get("allowedHosts")
                .and_then(|v| v.as_array())
                .map(|a| !a.is_empty())
                .unwrap_or(false)
                || network
                    .get("blockedHosts")
                    .and_then(|v| v.as_array())
                    .map(|a| !a.is_empty())
                    .unwrap_or(false);
            network["enforcementMode"] = json!(if has_host_rules {
                "both"
            } else {
                "capabilities"
            });
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = (policy, container_id);
    }
}

/// Promote network enforcement to `firewall` when host rules are present and
/// no cooperative proxy is configured — the Linux counterpart of the SDK's
/// `applyLinuxNetworkPolicy`.
fn apply_linux_network_policy(config: &mut serde_json::Value) {
    use serde_json::json;
    let Some(network) = config.get_mut("network") else {
        return;
    };
    let has_proxy = network.get("proxy").is_some();
    let has_host_rules = network
        .get("allowedHosts")
        .and_then(|v| v.as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false)
        || network
            .get("blockedHosts")
            .and_then(|v| v.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false);
    if has_host_rules && !has_proxy {
        network["enforcementMode"] = json!("firewall");
    }
}
