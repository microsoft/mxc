// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Policy discovery and config building — the Rust port of the SDK's
//! `policy.ts` helpers and `createConfigFromPolicy`.
//!
//! - [`available_tools_policy`], [`user_profile_policy`], and
//!   [`temporary_files_policy`] enumerate the host environment to discover
//!   tool/SDK/profile/temp directories as filesystem-policy fragments;
//!   [`materialize_tool_cache_writes`] then provisions the write-cache grants
//!   [`available_tools_policy`] returns so a first sandboxed build can use them.
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

/// [`KNOWN_ENV_VARS`] entries whose value points at a tool home holding a secret
/// at its root, so granting the whole directory would leak it. For these, grant
/// only the safe build-input subdirs `(var, readonly_subdirs, readwrite_files)`.
///
/// Only `CARGO_HOME` qualifies: `~/.cargo` holds `credentials.toml` beside the
/// caches, and its root (unlike a `bin` dir) is not normally on `PATH`, so
/// scoping it here suffices. Tool homes commonly on `PATH` (e.g. a user-local
/// `DOTNET_ROOT`) would still be granted wholesale by the `PATH` scan, so they
/// are left out until that interaction is addressed.
const CREDENTIAL_SCOPED_ENV_VARS: &[(&str, &[&str], &[&str])] = &[(
    "CARGO_HOME",
    &["registry", "git", "bin"],
    &[".package-cache", ".global-cache"],
)];

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

/// Discover the filesystem access common language toolchains need — the single
/// entry point for tool/SDK discovery. The Rust port of `getAvailableToolsPolicy`.
///
/// Merges (and de-duplicates) up to two sources:
///
/// 1. **Env-var + `PATH` discovery** (always on). `PATH` plus well-known tool/SDK
///    variables (`CARGO_HOME`, `GOPATH`, `RUSTUP_HOME`, …), read from `env`
///    (defaults to the process environment), for toolchains the user has
///    *relocated*. Existence- and system-critical-filtered; adds PowerShell paths
///    when `pwsh.exe` is on `PATH`. Credential-bearing homes (see
///    [`CREDENTIAL_SCOPED_ENV_VARS`]) are scoped to safe subdirs, not granted
///    wholesale.
/// 2. **Default-location home caches** (opt-in via `allow_dev_tool_caches`,
///    default off). The credential-safe cache/toolchain subdirs under the process
///    home, for toolchains the user has *not* relocated (see
///    [`home_tool_cache_policy_for`]). Read grants are existence-filtered; write
///    grants are returned as *candidates* that may not exist yet.
///
/// Both sources are needed in practice (most users export no env vars; a relocated
/// toolchain is invisible to the home-cache scan). The home caches are gated
/// because they add grants and create cache dirs; the env-var/`PATH` half only
/// narrows what a relocated toolchain already exposes, so it is unconditional.
///
/// **Pure**: never touches the filesystem beyond `stat`, so the policy can be
/// inspected/serialized without side effects. The write-cache candidates must be
/// created before a deny-by-default sandbox can use them; call
/// [`materialize_tool_cache_writes`] on the returned
/// [`readwrite_paths`](FilesystemPolicyResult::readwrite_paths) to do so.
pub fn available_tools_policy(
    env: Option<&[(String, String)]>,
    allow_dev_tool_caches: bool,
) -> FilesystemPolicyResult {
    let env = env_or_process(env);
    let env: &[(String, String)] = &env;

    let mut collected = Vec::new();
    let mut scoped_readwrite_files = Vec::new();
    let path_value = env_get(env, "PATH")
        .or_else(|| env_get(env, "Path"))
        .unwrap_or("");
    let path_dirs = split_path_list(path_value);
    collected.extend(path_dirs.iter().cloned());

    for (name, is_list) in KNOWN_ENV_VARS {
        if let Some(value) = env_get(env, name) {
            // Credential-bearing tool homes: grant only the safe subdirs, never
            // the root (which holds a token/key beside the caches).
            if let Some((_, readonly_subdirs, readwrite_files)) = CREDENTIAL_SCOPED_ENV_VARS
                .iter()
                .find(|(scoped, _, _)| scoped == name)
            {
                let base = value.trim();
                if !base.is_empty() {
                    collected.extend(readonly_subdirs.iter().map(|sub| join_str(base, &[sub])));
                    scoped_readwrite_files
                        .extend(readwrite_files.iter().map(|file| join_str(base, &[file])));
                }
                continue;
            }
            let extracted = if *is_list {
                split_path_list(value)
            } else {
                single_path(value)
            };
            collected.extend(extracted);
        }
    }

    let mut readonly: Vec<String> = deduplicate_paths(&collected)
        .into_iter()
        .filter(|dir| directory_exists(dir) && !is_system_critical_path(dir))
        .collect();

    let pwsh = powershell_policy(&path_dirs, env);
    readonly.extend(pwsh.readonly_paths);
    let mut readwrite = pwsh.readwrite_paths;

    // Opt-in: the default-location home caches plus the credential-scoped env
    // vars' lock-file *writes*. The read discovery above is always on — it only
    // narrows what a relocated toolchain already exposed.
    if allow_dev_tool_caches {
        readwrite.extend(scoped_readwrite_files);
        let home = process_home_tool_caches();
        readonly.extend(home.readonly);
        readwrite.extend(home.readwrite);
        readwrite.extend(home.readwrite_files);
    }

    FilesystemPolicyResult {
        readonly_paths: deduplicate_paths(&readonly),
        readwrite_paths: deduplicate_paths(&readwrite),
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
// Home-relative toolchain-cache discovery
// ---------------------------------------------------------------------------

/// Home-relative grants split by access mode, produced by
/// [`home_tool_cache_policy_for`] and folded into [`available_tools_policy`].
///
/// The third bucket beyond [`FilesystemPolicyResult`]'s two — read-write *files*
/// — is separate because it is materialized by a touch rather than
/// `create_dir_all`. Cargo's root-level lock/tracker files are the only such
/// files, granted individually so the credential-bearing `~/.cargo` root is never
/// exposed. [`available_tools_policy`] flattens both write buckets into
/// [`FilesystemPolicyResult::readwrite_paths`]; [`materialize_tool_cache_writes`]
/// recovers the file-vs-directory split via [`CARGO_RW_FILE_NAMES`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct HomeToolCachePolicy {
    /// Read-only build inputs. Existence-filtered by [`process_home_tool_caches`].
    readonly: Vec<String>,
    /// Read-write directories a build writes every run. Unfiltered candidates so
    /// `materialize_*` can create each before a downstream existence filter drops it.
    readwrite: Vec<String>,
    /// Read-write files (Cargo's root-level `.package-cache`/`.global-cache`).
    /// Unfiltered candidates, touched so the grant survives a first build.
    readwrite_files: Vec<String>,
}

/// The default-location toolchain caches under the *process* home, folded into
/// [`available_tools_policy`]. Read grants are existence-filtered; write grants
/// are (possibly not-yet-existing) candidates for [`materialize_tool_cache_writes`].
///
/// SECURITY: the home is always the calling process's own ([`std::env::home_dir`]),
/// never a caller- or command-env-controlled value — a child-controlled `HOME`
/// (e.g. an MCP server's `config.env`) could point `.cargo/.global-cache` at a
/// symlink to `~/.ssh` and have a downstream canonicalizing filter follow it. It
/// is present even when a sandboxed server's curated env omits `HOME`.
///
/// Empty on Windows (its layouts differ; [`available_tools_policy`]'s env-var
/// discovery covers the common `%LOCALAPPDATA%` cases).
fn process_home_tool_caches() -> HomeToolCachePolicy {
    #[cfg(not(target_os = "windows"))]
    {
        let Some(home) = std::env::home_dir() else {
            return HomeToolCachePolicy::default();
        };
        let home = home.to_string_lossy();
        if home.is_empty() {
            return HomeToolCachePolicy::default();
        }
        let mut policy = home_tool_cache_policy_for(&home, cfg!(target_os = "macos"));
        // Read-only inputs a tool the user doesn't have shouldn't be granted;
        // drop non-existent ones (matching the env-var discovery). The write
        // buckets stay unfiltered so `materialize_tool_cache_writes` can create
        // them before a first build needs them.
        policy.readonly.retain(|dir| directory_exists(dir));
        policy
    }
    #[cfg(target_os = "windows")]
    {
        HomeToolCachePolicy::default()
    }
}

/// Pure, side-effect-free path-table generator behind
/// [`process_home_tool_caches`]. Split out so the platform shapes can be tested
/// deterministically (`macos` is an explicit argument, not `cfg!`). Every
/// returned path is lexically contained within `home`.
///
/// Credential-safe: every entry targets a build-input *subdirectory*, never a
/// tool-home root, so secrets stored beside the caches (`~/.cargo/credentials.toml`,
/// `~/.npmrc`, `~/.m2/settings.xml`, the .NET X509 store, …) stay unreadable.
///
/// Read-only by default; only caches a build *writes* on every run are read-write
/// (the compiler scratch caches, `~/.gradle/caches` + `wrapper/dists`, and Cargo's
/// root-level lock files). Cold dependency fetches stay a per-command bypass.
#[cfg(not(target_os = "windows"))]
fn home_tool_cache_policy_for(home: &str, macos: bool) -> HomeToolCachePolicy {
    let home = home.trim_end_matches('/');
    let join = |rel: &str| format!("{home}/{rel}");

    // Read-only build inputs common to macOS and Linux.
    const COMMON_READONLY: &[&str] = &[
        // Rust — never all of `~/.cargo` (`credentials.toml` lives there);
        // `.rustup/settings.toml` is the non-secret default-toolchain selector.
        ".rustup/toolchains",
        ".rustup/settings.toml",
        ".cargo/registry",
        ".cargo/git",
        ".cargo/bin",
        // Go — module cache is read-only by design; `go/bin` for installed tools.
        "go/pkg/mod",
        "go/bin",
        // Node.js runtimes, package caches & version managers.
        ".npm",
        ".nvm/versions",
        ".nvm/alias",
        ".pnpm-store",
        ".local/share/pnpm",
        ".bun/install/cache",
        ".bun/bin",
        ".deno",
        ".volta/bin",
        ".volta/tools",
        // fnm — `~/.fnm` is the legacy dir; the current platform defaults
        // (`~/.local/share/fnm` / `~/Library/Application Support/fnm`) are added
        // per-platform below.
        ".fnm",
        // asdf — source installs run `~/.asdf/bin/asdf`, which delegates to
        // `~/.asdf/libexec`, so both are needed alongside the shims/installs.
        ".asdf/bin",
        ".asdf/libexec",
        ".asdf/installs/nodejs",
        ".asdf/shims",
        ".local/share/mise/installs/node",
        ".local/share/mise/shims",
        ".electron-gyp",
        ".node-gyp",
        ".yarn/berry",
        // Python. pyenv's source install delegates its shims to a bundled
        // `libexec/pyenv`, so grant that too or shimmed commands can't exec.
        ".local/share/virtualenv",
        ".local/share/pipx",
        ".pyenv/versions",
        ".pyenv/shims",
        ".pyenv/libexec",
        // JVM — never the `~/.m2`/`~/.gradle` roots (settings.xml /
        // gradle.properties). Gradle's caches + `wrapper/dists` are read-write
        // below (locked/written on every build).
        ".m2/repository",
        ".sdkman/candidates",
        // .NET — build/runtime subdirs only, never the `~/.dotnet` root:
        // `corefx/cryptography/x509stores` holds the CurrentUser X509 store (incl.
        // PFX keys) and the root also has a NuGet.Config. `dotnet` is on PATH.
        ".dotnet/sdk",
        ".dotnet/shared",
        ".dotnet/host",
        ".dotnet/packs",
        ".dotnet/templates",
        ".dotnet/sdk-manifests",
        ".dotnet/store",
        ".dotnet/tools",
        ".nuget/packages",
        // NuGet's v3 HTTP cache is `~/.local/share/NuGet/v3-cache` on *both*
        // macOS and Linux (not `~/Library/Caches` on macOS), so it is common.
        ".local/share/NuGet/v3-cache",
        // Ruby — `~/.gem/ruby` only; `~/.gem/credentials` holds the API key.
        // rbenv's source install delegates its shims to a bundled `libexec/rbenv`.
        ".gem/ruby",
        ".rbenv/versions",
        ".rbenv/shims",
        ".rbenv/libexec",
        ".rvm/rubies",
        // C/C++ (Conan) — package + build folders only, never the `.conan2` root.
        ".conan2/p",
        ".conan2/b",
    ];

    // Platform cache roots differ: macOS `~/Library/Caches`, Linux XDG `~/.cache`.
    let platform_readonly: &[&str] = if macos {
        &[
            "Library/Caches/node",
            "Library/Caches/electron",
            "Library/Caches/ms-playwright",
            "Library/Caches/Yarn",
            "Library/Caches/deno",
            "Library/pnpm",
            "Library/Caches/pip",
            "Library/Caches/pypoetry",
            "Library/Caches/uv",
            // fnm's current default on macOS ($XDG_DATA_HOME/fnm fallback).
            "Library/Application Support/fnm",
            // node-gyp's current default (env-paths) on macOS; `~/.node-gyp`
            // above is the legacy location.
            "Library/Caches/node-gyp",
        ]
    } else {
        &[
            ".cache/node",
            ".cache/node/corepack",
            ".cache/electron",
            ".cache/ms-playwright",
            ".cache/yarn",
            ".cache/deno",
            ".cache/pip",
            ".cache/pypoetry",
            ".cache/uv",
            // fnm's current default on Linux ($XDG_DATA_HOME/fnm fallback).
            ".local/share/fnm",
            // node-gyp's current default (env-paths) on Linux; `~/.node-gyp`
            // above is the legacy location.
            ".cache/node-gyp",
        ]
    };

    // Caches a build writes on every run → read-write (Gradle locks its caches
    // and rewrites the wrapper dist `.ok` marker even on warm builds). sccache's
    // macOS default is the org-qualified `Mozilla.sccache`, not bare `sccache`.
    const COMMON_READWRITE: &[&str] = &[".gradle/caches", ".gradle/wrapper/dists"];
    let platform_readwrite: &[&str] = if macos {
        &[
            "Library/Caches/go-build",
            "Library/Caches/ccache",
            "Library/Caches/Mozilla.sccache",
        ]
    } else {
        &[".cache/go-build", ".cache/ccache", ".cache/sccache"]
    };

    HomeToolCachePolicy {
        readonly: COMMON_READONLY
            .iter()
            .chain(platform_readonly)
            .map(|&rel| join(rel))
            .collect(),
        readwrite: COMMON_READWRITE
            .iter()
            .chain(platform_readwrite)
            .map(|&rel| join(rel))
            .collect(),
        // Cargo's root-level `.package-cache` flock + `.global-cache` tracker are
        // written on every build — granted as individual files, never the
        // `~/.cargo` root (which holds `credentials.toml`).
        readwrite_files: [".cargo/.package-cache", ".cargo/.global-cache"]
            .iter()
            .map(|&rel| join(rel))
            .collect(),
    }
}

/// Path suffixes marking a read-write grant as a *file* (create empty), not a
/// *directory* (`create_dir_all`) — Cargo's root-level lock/tracker files.
/// File names (not directories) among the read-write tool-cache grants: Cargo's
/// root-level lock/tracker files, which must be created empty (never
/// `create_dir_all`'d). [`materialize_tool_cache_writes`] uses these to recover
/// the file/dir split after [`available_tools_policy`] flattens the write
/// buckets. Matched on the final path component (via [`Path::file_name`], so it
/// is separator-agnostic and works for a relocated `CARGO_HOME` on any platform).
/// Granted individually so the `CARGO_HOME` root — which holds `credentials.toml`
/// — is never exposed.
const CARGO_RW_FILE_NAMES: &[&str] = &[".package-cache", ".global-cache"];

/// Create the read-write tool-cache grants from [`available_tools_policy`] so
/// they survive a downstream existence filter and a first build can populate
/// them: directories via `create_dir_all`, Cargo's lock/tracker files (see
/// [`CARGO_RW_FILE_NAMES`]) created empty only if absent.
///
/// Pass [`available_tools_policy`]'s
/// [`readwrite_paths`](FilesystemPolicyResult::readwrite_paths). This is the one
/// side-effecting step of discovery, kept separate so discovery stays pure;
/// idempotent and best-effort. Returns the subset that now exists.
pub fn materialize_tool_cache_writes(readwrite_paths: &[String]) -> Vec<String> {
    for path in readwrite_paths {
        let is_cargo_lock_file = Path::new(path)
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| CARGO_RW_FILE_NAMES.contains(&name));
        if is_cargo_lock_file {
            if let Some(parent) = Path::new(path).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            // `create_new` never truncates, so a `.package-cache`/`.global-cache`
            // populated concurrently (or by Cargo) is not clobbered as
            // `File::create` would; `AlreadyExists`/errors are ignored.
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path);
        } else {
            let _ = std::fs::create_dir_all(path);
        }
    }
    readwrite_paths
        .iter()
        .filter(|path| Path::new(path).exists())
        .cloned()
        .collect()
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

    // Mirror the SDK's host-rule validation: Unix backends accept host lists
    // without `allowOutbound`; only Windows ProcessContainer requires it.
    // NB: Seatbelt can't actually enforce hostnames (`profile_builder` degrades a
    // non-empty `allowedHosts` to allow-all outbound), but we accept it on macOS
    // anyway to stay consistent with the SDK rather than diverging — keeping the
    // two ports reconciled matters more than being stricter here.
    let accepts_host_rules_without_outbound = cfg!(any(target_os = "linux", target_os = "macos"));

    if let Some(net) = &policy.network {
        if !accepts_host_rules_without_outbound
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

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn home_tool_cache_policy_for_macos_uses_library_caches() {
        use super::home_tool_cache_policy_for;
        let p = home_tool_cache_policy_for("/Users/dev", true);
        assert!(p
            .readonly
            .contains(&"/Users/dev/.cargo/registry".to_string()));
        assert!(p
            .readonly
            .contains(&"/Users/dev/.rustup/toolchains".to_string()));
        assert!(p.readonly.contains(&"/Users/dev/go/pkg/mod".to_string()));
        assert!(p
            .readonly
            .contains(&"/Users/dev/Library/Caches/pip".to_string()));
        // macOS never uses the XDG `~/.cache` layout.
        assert!(!p.readonly.iter().any(|x| x.contains("/.cache/")));
        // fnm's current macOS default.
        assert!(p
            .readonly
            .contains(&"/Users/dev/Library/Application Support/fnm".to_string()));
        // node-gyp's current env-paths default on macOS.
        assert!(p
            .readonly
            .contains(&"/Users/dev/Library/Caches/node-gyp".to_string()));
        assert!(p
            .readwrite
            .contains(&"/Users/dev/Library/Caches/go-build".to_string()));
        assert!(!p.readwrite.iter().any(|x| x.contains("/.cache/")));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn home_tool_cache_policy_for_linux_uses_xdg_cache() {
        use super::home_tool_cache_policy_for;
        let p = home_tool_cache_policy_for("/home/dev", false);
        assert!(p
            .readonly
            .contains(&"/home/dev/.cargo/registry".to_string()));
        assert!(p.readonly.contains(&"/home/dev/.cache/pip".to_string()));
        // Linux never uses the macOS `~/Library/Caches` layout.
        assert!(!p.readonly.iter().any(|x| x.contains("Library/Caches")));
        // fnm's current Linux default.
        assert!(p
            .readonly
            .contains(&"/home/dev/.local/share/fnm".to_string()));
        // node-gyp's current env-paths default on Linux.
        assert!(p
            .readonly
            .contains(&"/home/dev/.cache/node-gyp".to_string()));
        assert!(p
            .readwrite
            .contains(&"/home/dev/.cache/go-build".to_string()));
        assert!(p
            .readwrite
            .contains(&"/home/dev/.cache/sccache".to_string()));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn home_tool_cache_policy_for_never_escapes_the_provided_home() {
        use super::home_tool_cache_policy_for;
        // Every derived candidate stays lexically inside the (trusted) home with
        // no `..` traversal — the complement to the trusted-home requirement in
        // `process_home_tool_caches`.
        for macos in [true, false] {
            let home = "/home/dev";
            let p = home_tool_cache_policy_for(home, macos);
            let all = p
                .readonly
                .iter()
                .chain(p.readwrite.iter())
                .chain(p.readwrite_files.iter());
            for path in all {
                assert!(
                    path.starts_with(&format!("{home}/")),
                    "path {path} escapes home {home} (macos={macos})"
                );
                assert!(
                    !path.split('/').any(|seg| seg == ".."),
                    "path {path} contains a `..` traversal (macos={macos})"
                );
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn home_tool_cache_policy_for_classifies_read_vs_write() {
        use super::home_tool_cache_policy_for;
        let p = home_tool_cache_policy_for("/home/dev", false);
        // Module cache & installed toolchains are read-only.
        assert!(p.readonly.contains(&"/home/dev/go/pkg/mod".to_string()));
        assert!(p
            .readonly
            .contains(&"/home/dev/.rustup/toolchains".to_string()));
        assert!(!p.readwrite.iter().any(|x| x.contains("pkg/mod")));
        // Pure compiler caches are read-write, never read-only.
        assert!(!p.readonly.iter().any(|x| x.ends_with("go-build")));
        assert!(p
            .readwrite
            .contains(&"/home/dev/.cache/go-build".to_string()));
        // Gradle's cache locks/writes on every build, so it is read-write, not
        // read-only (regression guard for the reviewer-reported failure).
        assert!(
            p.readwrite
                .contains(&"/home/dev/.gradle/caches".to_string()),
            "gradle caches must be read-write, got {:?}",
            p.readwrite
        );
        assert!(!p.readonly.iter().any(|x| x.ends_with(".gradle/caches")));
        // The Gradle wrapper writes an `.ok` marker into the dist dir on every
        // run, so `wrapper/dists` is read-write too — never read-only.
        assert!(
            p.readwrite
                .contains(&"/home/dev/.gradle/wrapper/dists".to_string()),
            "gradle wrapper/dists must be read-write, got {:?}",
            p.readwrite
        );
        assert!(!p.readonly.iter().any(|x| x.ends_with("wrapper/dists")));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn home_tool_cache_policy_for_grants_shim_libexec_and_narrows_dotnet() {
        use super::home_tool_cache_policy_for;
        for macos in [true, false] {
            let p = home_tool_cache_policy_for("/home/dev", macos);
            // pyenv/rbenv/asdf source installs delegate their shims to a bundled
            // libexec/launcher, so it must be granted or shimmed commands can't exec.
            assert!(p.readonly.contains(&"/home/dev/.pyenv/libexec".to_string()));
            assert!(p.readonly.contains(&"/home/dev/.rbenv/libexec".to_string()));
            assert!(p.readonly.contains(&"/home/dev/.asdf/bin".to_string()));
            assert!(p.readonly.contains(&"/home/dev/.asdf/libexec".to_string()));
            // .NET grants specific build subdirs, never the `.dotnet` root.
            assert!(p.readonly.contains(&"/home/dev/.dotnet/sdk".to_string()));
            assert!(!p.readonly.iter().any(|x| x.ends_with("/.dotnet")));
            // rustup's default-toolchain selector is read on every cargo run.
            assert!(p
                .readonly
                .contains(&"/home/dev/.rustup/settings.toml".to_string()));
            // NuGet's v3 HTTP cache is `~/.local/share/NuGet/v3-cache` on both
            // platforms, never `~/Library/Caches/NuGet` on macOS.
            assert!(p
                .readonly
                .contains(&"/home/dev/.local/share/NuGet/v3-cache".to_string()));
            assert!(!p
                .readonly
                .iter()
                .any(|x| x.contains("Library/Caches/NuGet")));
            // Cargo's root-level lock/tracker files are read-write *files* (never
            // the `.cargo` root), so warm-cache `cargo build` can lock/write them.
            assert!(p
                .readwrite_files
                .contains(&"/home/dev/.cargo/.package-cache".to_string()));
            assert!(p
                .readwrite_files
                .contains(&"/home/dev/.cargo/.global-cache".to_string()));
            assert!(!p.readwrite_files.iter().any(|x| x.ends_with("/.cargo")));
        }
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn home_tool_cache_policy_for_macos_sccache_uses_mozilla_dir() {
        use super::home_tool_cache_policy_for;
        let p = home_tool_cache_policy_for("/home/dev", true);
        // sccache's macOS default (via the `directories` crate) is the
        // org-qualified `Mozilla.sccache`, not a bare `sccache` dir.
        assert!(p
            .readwrite
            .contains(&"/home/dev/Library/Caches/Mozilla.sccache".to_string()));
        assert!(!p
            .readwrite
            .iter()
            .any(|x| x.ends_with("Library/Caches/sccache")));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn home_tool_cache_policy_for_trims_trailing_home_slash() {
        use super::home_tool_cache_policy_for;
        let p = home_tool_cache_policy_for("/home/dev/", false);
        assert!(p
            .readonly
            .contains(&"/home/dev/.cargo/registry".to_string()));
        assert!(!p.readonly.iter().any(|x| x.contains("//")));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn home_tool_cache_policy_for_excludes_credential_material() {
        use super::home_tool_cache_policy_for;
        let home = "/home/dev";
        for macos in [true, false] {
            let p = home_tool_cache_policy_for(home, macos);
            let all: Vec<&String> = p
                .readonly
                .iter()
                .chain(p.readwrite.iter())
                .chain(p.readwrite_files.iter())
                .collect();
            // Never grant a tool-home root or a known credential/config file that
            // sits beside the caches (read alone leaks the secret).
            for forbidden in [
                "/home/dev/.cargo",
                "/home/dev/.gem",
                "/home/dev/.m2",
                "/home/dev/.gradle",
                "/home/dev/.nuget",
                "/home/dev/.conan2",
                "/home/dev/.dotnet",
                "/home/dev/.dotnet/corefx/cryptography/x509stores",
                "/home/dev/.npmrc",
                "/home/dev/.m2/settings.xml",
                "/home/dev/.gradle/gradle.properties",
                "/home/dev/.gem/credentials",
                "/home/dev/.nuget/NuGet.Config",
                "/home/dev/.config/gh",
                "/home/dev/.ssh",
                "/home/dev/.gnupg",
            ] {
                assert!(
                    !all.iter().any(|x| x.as_str() == forbidden),
                    "must not grant {forbidden} (macos={macos})"
                );
            }
            // Defense in depth: nothing that names a secret store or the .NET
            // CurrentUser X509 certificate/key store.
            assert!(
                !all.iter().any(|x| x.contains("credentials")),
                "macos={macos}"
            );
            assert!(
                !all.iter()
                    .any(|x| x.contains("x509stores") || x.contains("cryptography")),
                "macos={macos}"
            );
            assert!(!all.iter().any(|x| x.ends_with(".npmrc")), "macos={macos}");
        }
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn available_tools_policy_folds_in_existing_home_read_caches() {
        use super::available_tools_policy;
        // Opt-in on, empty env: the read set is purely the existence-filtered
        // process-home caches, so every returned path must exist. Pure (no disk
        // writes); an empty result is valid on a host with no toolchains.
        let result = available_tools_policy(Some(&[]), true);
        for dir in &result.readonly_paths {
            assert!(
                std::path::Path::new(dir).exists(),
                "read-only grant does not exist: {dir}"
            );
        }
        // Credential-safety holds through the merged discovery too: no tool-home
        // root or credential file leaks into the read set.
        for forbidden in [".npmrc", "credentials.toml", ".gnupg"] {
            assert!(
                !result.readonly_paths.iter().any(|p| p.ends_with(forbidden)),
                "must not grant {forbidden}: {:?}",
                result.readonly_paths
            );
        }
        // Opt-in off: no home caches at all.
        assert!(
            available_tools_policy(Some(&[]), false)
                .readonly_paths
                .is_empty(),
            "no home caches must be granted when the opt-in is off"
        );
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn available_tools_policy_scopes_credential_bearing_cargo_home() {
        use super::available_tools_policy;

        // A relocated CARGO_HOME with a registry cache and a secret beside it.
        let base = std::env::temp_dir().join(format!(
            "mxc_cargo_home_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let base_str = base.to_string_lossy().into_owned();
        std::fs::create_dir_all(base.join("registry")).expect("create registry");
        std::fs::write(base.join("credentials.toml"), b"token").expect("write secret");

        // Empty PATH so only the scoped CARGO_HOME drives the env-var discovery.
        let env = vec![
            ("PATH".to_string(), String::new()),
            ("CARGO_HOME".to_string(), base_str.clone()),
        ];
        let result = available_tools_policy(Some(&env), true);

        let registry = format!("{base_str}/registry");
        let package_cache = format!("{base_str}/.package-cache");
        let root_granted = result.readonly_paths.iter().any(|p| p == &base_str);
        let registry_granted = result.readonly_paths.contains(&registry);
        let lockfile_scoped = result.readwrite_paths.contains(&package_cache);
        let secret_leak = result
            .readonly_paths
            .iter()
            .any(|p| p.contains("credentials"));

        // Opt-in off: read scoping still holds (it only narrows env-var
        // discovery), but the lock-file *write* grant is withheld.
        let off = available_tools_policy(Some(&env), false);
        let off_registry_granted = off.readonly_paths.contains(&registry);
        let off_root_granted = off.readonly_paths.iter().any(|p| p == &base_str);
        let off_lockfile_withheld = !off.readwrite_paths.contains(&package_cache);

        // Clean up before asserting so a failure leaves nothing behind.
        let _ = std::fs::remove_dir_all(&base);

        assert!(
            registry_granted,
            "the registry subdir must be granted: {:?}",
            result.readonly_paths
        );
        assert!(
            !root_granted,
            "the CARGO_HOME root must not be granted (it holds credentials.toml)"
        );
        assert!(
            !secret_leak,
            "no credential path may be granted: {:?}",
            result.readonly_paths
        );
        assert!(
            lockfile_scoped,
            "the Cargo lock file must be scoped under CARGO_HOME: {:?}",
            result.readwrite_paths
        );
        assert!(
            off_registry_granted && !off_root_granted && off_lockfile_withheld,
            "opt-in off: registry read scoping stays, lock-file write is withheld (ro={:?} rw={:?})",
            off.readonly_paths,
            off.readwrite_paths
        );
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn materialize_tool_cache_writes_creates_dirs_and_touches_cargo_files() {
        use super::{home_tool_cache_policy_for, materialize_tool_cache_writes};

        // Materialize against a temp home: creates the cache dirs, touches the
        // Cargo lock files, returns the now-existing subset. Built from the pure
        // table (flattened) so the real process home is untouched.
        let home = std::env::temp_dir().join(format!(
            "mxc_tool_cache_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let home_str = home.to_string_lossy().into_owned();
        std::fs::create_dir_all(&home).expect("create temp home");

        let table = home_tool_cache_policy_for(&home_str, false);
        let mut readwrite = table.readwrite.clone();
        readwrite.extend(table.readwrite_files.clone());
        let existing = materialize_tool_cache_writes(&readwrite);

        let gradle = format!("{home_str}/.gradle/caches");
        let package_cache = format!("{home_str}/.cargo/.package-cache");
        let created_ok = existing.contains(&gradle)
            && std::path::Path::new(&gradle).is_dir()
            // The Cargo lock file must be a *file* (touched), never a directory.
            && existing.contains(&package_cache)
            && std::path::Path::new(&package_cache).is_file();

        // Clean up before asserting so a failure leaves nothing behind.
        let _ = std::fs::remove_dir_all(&home);

        assert!(
            created_ok,
            "materialize must create the read-write cache dir and touch the Cargo lock file"
        );
    }

    #[test]
    fn materialize_tool_cache_writes_detects_cargo_lock_by_basename() {
        use super::materialize_tool_cache_writes;

        // Regression guard for the separator-agnostic lock-file detection: build
        // the paths with `PathBuf::join` so each platform uses its native
        // separator (`\` on Windows, `/` elsewhere). A relocated CARGO_HOME lock
        // file must be created as a *file*, and a plain cache dir as a *directory*.
        let base = std::env::temp_dir().join(format!(
            "mxc_cargo_sep_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&base).expect("create temp base");

        let lock = base.join(".package-cache");
        let cache_dir = base.join("go-build");
        let readwrite = vec![
            lock.to_string_lossy().into_owned(),
            cache_dir.to_string_lossy().into_owned(),
        ];
        let existing = materialize_tool_cache_writes(&readwrite);

        let lock_is_file = lock.is_file();
        let dir_is_dir = cache_dir.is_dir();
        let both_returned = existing.len() == 2;

        let _ = std::fs::remove_dir_all(&base);

        assert!(
            lock_is_file,
            "the Cargo lock file must be created as a file, not a directory"
        );
        assert!(
            dir_is_dir,
            "a non-lock cache path must be created as a directory"
        );
        assert!(
            both_returned,
            "both existing grants must be returned: {existing:?}"
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

    // Mirror the TypeScript SDK by accepting `allowedHosts` with or without
    // `allowOutbound`, even though Seatbelt cannot enforce the host list.
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

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_proxy_is_accepted_and_mapped() {
        let policy = policy_with_network(NetworkSection {
            proxy: Some(ProxySpec::Localhost(8080)),
            ..Default::default()
        });
        let request =
            build_request(&policy, None).expect("macOS must accept Seatbelt proxy configuration");
        let proxy = &request.inner.policy.network_proxy;

        assert!(proxy.is_enabled());
        assert_eq!(
            proxy.address.as_ref().map(|address| address.port()),
            Some(8080)
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
