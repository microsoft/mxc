// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared helpers for MXC end-to-end integration tests.
//!
//! Tests live in `tests/e2e_windows.rs` and invoke MXC executables directly so
//! failures can be debugged from Rust test code.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD, Engine};

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/// Locate the repository root.
/// `CARGO_MANIFEST_DIR` points to `src/testing/wxc_e2e_tests/` during `cargo test`.
pub fn repo_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent() // src/testing
        .and_then(|p| p.parent()) // src
        .and_then(|p| p.parent()) // repo root
        .expect("could not determine repo root")
        .to_path_buf()
}

/// Return the repository `tests/configs/` directory.
pub fn test_configs_dir() -> PathBuf {
    repo_root().join("tests").join("configs")
}

/// Return the repository `tests/examples/` directory.
pub fn examples_dir() -> PathBuf {
    repo_root().join("tests").join("examples")
}

fn src_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent() // src/testing
        .and_then(|p| p.parent()) // src
        .expect("could not find src/")
        .to_path_buf()
}

// ---------------------------------------------------------------------------
// Build-mode detection
// ---------------------------------------------------------------------------

/// Whether the test binary was compiled in release mode.
pub fn is_release_mode() -> bool {
    !cfg!(debug_assertions)
}

/// The target triple for the current platform (used for cross-compiled paths).
fn current_triple() -> &'static str {
    if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        "x86_64-pc-windows-msvc"
    } else if cfg!(all(target_os = "windows", target_arch = "aarch64")) {
        "aarch64-pc-windows-msvc"
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "x86_64-unknown-linux-gnu"
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        "aarch64-unknown-linux-gnu"
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "aarch64-apple-darwin"
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        "x86_64-apple-darwin"
    } else {
        ""
    }
}

/// Search for a binary in the target directory, checking multiple locations.
///
/// Two profile directories may both contain the binary on a given dev host —
/// the triple-prefixed `target/<triple>/<profile>/` from explicit-target
/// builds, and the plain `target/<profile>/` that `cargo build` /
/// `cargo test` write by default. Returning the *most recently modified*
/// candidate keeps tests aligned with the build the user just ran, instead
/// of latching onto a stale triple-prefixed copy from a previous session.
/// Profile preference (debug-vs-release) only resolves ties when neither
/// candidate has been built more recently than the other.
pub fn find_binary(name: &str) -> Option<PathBuf> {
    let src = src_dir();
    let (primary, fallback) = if is_release_mode() {
        ("release", "debug")
    } else {
        ("debug", "release")
    };
    let triple = current_triple();

    let mut candidates = Vec::new();
    if !triple.is_empty() {
        candidates.push(src.join("target").join(triple).join(primary).join(name));
    }
    candidates.push(src.join("target").join(primary).join(name));
    if !triple.is_empty() {
        candidates.push(src.join("target").join(triple).join(fallback).join(name));
    }
    candidates.push(src.join("target").join(fallback).join(name));

    // Pick the most recently modified candidate that exists. Falls back to
    // existence-order when mtimes are unavailable (read errors).
    candidates
        .into_iter()
        .filter(|p| p.exists())
        .max_by_key(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok())
}

// ---------------------------------------------------------------------------
// Prerequisite checks (has_* pattern — returns true when present)
// ---------------------------------------------------------------------------

/// Return whether `wxc-exec.exe` is available for direct E2E execution.
pub fn has_wxc_exe() -> bool {
    match find_binary("wxc-exec.exe") {
        Some(p) => {
            println!("Using wxc-exec.exe at {}", p.display());
            true
        }
        None => {
            println!("SKIPPED: wxc-exec.exe not found — build first");
            false
        }
    }
}

/// Return whether `wxc-test-driver.exe` is available for direct E2E execution.
pub fn has_test_driver() -> bool {
    match find_binary("wxc-test-driver.exe") {
        Some(p) => {
            println!("Using wxc-test-driver.exe at {}", p.display());
            true
        }
        None => {
            println!("SKIPPED: wxc-test-driver.exe not found — build first");
            false
        }
    }
}

/// Return whether the Windows Sandbox daemon binary is available.
pub fn has_daemon() -> bool {
    match find_binary("wxc-windows-sandbox-daemon.exe") {
        Some(p) => {
            println!("Using daemon at {}", p.display());
            true
        }
        None => {
            println!("SKIPPED: wxc-windows-sandbox-daemon.exe not found — build first");
            false
        }
    }
}

/// Return whether the NanVix runtime binaries are available next to wxc-exec.
pub fn has_nanvix_binaries() -> bool {
    let Some(exe) = find_binary("wxc-exec.exe") else {
        return false;
    };
    let exe_dir = exe.parent().unwrap_or(Path::new("."));
    // Flat binaries staged next to wxc-exec.exe by `nanvix_binaries`.
    let flat_present = ["nanvixd.exe", "nanvix_rootfs.img", "python3.initrd"]
        .iter()
        .all(|name| exe_dir.join(name).exists());
    // Kernel binary now lives under `bin/` (nanvixd locates it via -bin-dir).
    let bin_present = ["kernel.elf"]
        .iter()
        .all(|name| exe_dir.join("bin").join(name).exists());
    let present = flat_present && bin_present;
    if !present {
        println!("SKIPPED: NanVix binaries not found next to wxc-exec.exe");
    }
    present
}

/// Return whether `lxc-exec` is available for direct E2E execution.
pub fn has_lxc_exe() -> bool {
    match find_binary("lxc-exec") {
        Some(p) => {
            println!("Using lxc-exec at {}", p.display());
            true
        }
        None => {
            println!("SKIPPED: lxc-exec not found — build with `cargo build -p lxc --features microvm` first");
            false
        }
    }
}

/// Return whether the NanVix runtime binaries are available next to lxc-exec (Linux).
pub fn has_lxc_nanvix_binaries() -> bool {
    let Some(exe) = find_binary("lxc-exec") else {
        return false;
    };
    let exe_dir = exe.parent().unwrap_or(Path::new("."));
    // Flat binaries staged next to lxc-exec by `nanvix_binaries`.
    let flat_present = ["nanvixd.elf", "nanvix_rootfs.img", "python3.initrd"]
        .iter()
        .all(|name| exe_dir.join(name).exists());
    // Kernel binary under `bin/` (nanvixd locates it relative to cwd).
    let bin_present = ["kernel.elf"]
        .iter()
        .all(|name| exe_dir.join("bin").join(name).exists());
    let present = flat_present && bin_present;
    if !present {
        println!("SKIPPED: NanVix binaries not found next to lxc-exec — build with `cargo build -p lxc --features microvm`");
    }
    present
}

/// Return whether `/dev/kvm` is available for KVM-based execution.
pub fn has_kvm() -> bool {
    let available = Path::new("/dev/kvm").exists();
    if !available {
        println!("SKIPPED: /dev/kvm not available — KVM required for NanVix on Linux");
    }
    available
}

/// Run `lxc-exec` with the supplied config file and extra arguments.
pub fn run_lxc_config(config_file: &str, extra_args: &[&str]) -> CommandResult {
    let exe = find_binary("lxc-exec").expect("lxc-exec should be available");
    let config = test_configs_dir().join(config_file);
    let mut args: Vec<String> = extra_args.iter().map(|arg| (*arg).to_string()).collect();
    args.push(config.display().to_string());

    run_executable(config_file, &exe, args)
}

/// Return whether the Hyperlight snapshot is installed at the default
/// location (`%LOCALAPPDATA%\pyhl\snapshot\index.json`).
pub fn has_hyperlight_snapshot() -> bool {
    let home = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("USERPROFILE")
                .map(|v| PathBuf::from(v).join("AppData").join("Local"))
                .unwrap_or_default()
        });
    let snapshot = home.join("pyhl").join("snapshot").join("index.json");
    if snapshot.is_file() {
        println!("Using Hyperlight snapshot at {}", snapshot.display());
        true
    } else {
        println!(
            "SKIPPED: Hyperlight snapshot not found at {} — run --setup-hyperlight first",
            snapshot.display()
        );
        false
    }
}

/// Return whether the Windows Sandbox optional feature is enabled.
pub fn has_windows_sandbox_feature() -> bool {
    let available = Command::new("dism")
        .args([
            "/online",
            "/get-featureinfo",
            "/featurename:Containers-DisposableClientVM",
        ])
        .output()
        .map(|output| {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            output.status.success()
                && format!("{stdout}\n{stderr}")
                    .lines()
                    .any(|line| line.contains("State") && line.contains("Enabled"))
        })
        .unwrap_or(false);

    if !available {
        println!("SKIPPED: Windows Sandbox feature is not enabled");
    }

    available
}

/// Check whether `python.exe` is available and the *first* match in PATH
/// is NOT a Windows Store App Execution Alias. Store aliases are reparse
/// points under `WindowsApps` that cannot be launched inside
/// AppContainer/BaseContainer sandboxes. Even when a real Python exists
/// later in PATH, the sandbox will try to launch the first match and fail.
///
/// Panics with a clear remediation message when Python is missing or
/// the first PATH match is a Store alias.
pub fn assert_python() {
    let output = Command::new("where.exe").arg("python.exe").output().ok();

    let Some(output) = output else {
        panic!(
            "python.exe not found.\n\
             E2E tests require a system-wide Python install.\n\
             Fix: Run scripts\\setup-test-prereqs.ps1 (elevated) or install Python system-wide \
             (winget install Python.Python.3.12 --scope machine)"
        );
    };

    if !output.status.success() {
        panic!(
            "python.exe not found.\n\
             E2E tests require a system-wide Python install.\n\
             Fix: Run scripts\\setup-test-prereqs.ps1 (elevated) or install Python system-wide \
             (winget install Python.Python.3.12 --scope machine)"
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let first_path = stdout.lines().next().unwrap_or("");
    if first_path.to_ascii_lowercase().contains("windowsapps") {
        panic!(
            "python.exe first resolves to a Windows Store alias ({first_path}).\n\
             Store aliases shadow real installs and cannot be launched inside sandbox containers.\n\
             Fix: Run scripts\\setup-test-prereqs.ps1 (elevated) or disable App Execution Aliases for Python"
        );
    }
}

/// The hardcoded path used by `pwsh_setlocation.json`.
const PWSH_PATH: &str = r"C:\Program Files\PowerShell\7\pwsh.exe";

/// Check whether PowerShell 7 is available at the expected path.
/// The test config `pwsh_setlocation.json` uses a hardcoded fully-qualified
/// path, so we validate that specific path exists rather than relying on
/// PATH resolution.
///
/// Panics with a clear remediation message when pwsh is missing.
pub fn assert_pwsh() {
    if !std::path::Path::new(PWSH_PATH).exists() {
        panic!(
            "PowerShell 7 not found at {PWSH_PATH}.\n\
             The pwsh_setlocation test requires PowerShell 7 installed at this path.\n\
             Fix: Run scripts\\setup-test-prereqs.ps1 (elevated) or install PowerShell 7 system-wide"
        );
    }
}

// ---------------------------------------------------------------------------
// Direct process execution
// ---------------------------------------------------------------------------

/// Captured process result with decoded text output.
#[derive(Debug)]
pub struct CommandResult {
    /// Human-readable command label.
    pub label: String,
    /// Process exit code, or `None` if the process terminated without one.
    pub code: Option<i32>,
    /// Captured stdout as UTF-8 lossy text.
    pub stdout: String,
    /// Captured stderr as UTF-8 lossy text.
    pub stderr: String,
    /// Wall-clock process duration in milliseconds.
    pub wall_time_ms: u128,
}

impl CommandResult {
    /// Combine stdout and stderr.
    pub fn combined_output(&self) -> String {
        format!("{}\n{}", self.stdout, self.stderr)
    }

    /// Combine stdout, stderr, and any base64-encoded text lines found in them.
    pub fn combined_output_with_decoded_base64(&self) -> String {
        let combined = self.combined_output();
        let mut decoded = Vec::new();

        for line in combined
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            if !looks_like_base64_text(line) {
                continue;
            }

            let Ok(bytes) = STANDARD.decode(line) else {
                continue;
            };
            let Ok(text) = String::from_utf8(bytes) else {
                continue;
            };
            decoded.push(text);
        }

        if decoded.is_empty() {
            combined
        } else {
            format!("{combined}\n{}", decoded.join("\n"))
        }
    }

    /// Return whether the command failed because the local test environment is
    /// missing a runtime that the sandboxed process needs to launch.
    pub fn is_missing_process_prerequisite(&self) -> bool {
        let combined = self.combined_output();
        combined.contains("CreateProcessW failed: The system cannot find the file specified")
            || combined.contains("Unsupported Windows branch or build version")
    }
}

fn is_base64_byte(byte: u8) -> bool {
    matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'=')
}

fn looks_like_base64_text(line: &str) -> bool {
    line.len() >= 16 && line.len().is_multiple_of(4) && line.bytes().all(is_base64_byte)
}

/// Run an executable and capture its result.
pub fn run_executable<I, S>(label: &str, exe: &Path, args: I) -> CommandResult
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let start = Instant::now();
    let output = Command::new(exe)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("failed to execute {label}: {error}"));

    command_result(label, output, start.elapsed().as_millis())
}

fn command_result(label: &str, output: Output, wall_time_ms: u128) -> CommandResult {
    CommandResult {
        label: label.to_string(),
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        wall_time_ms,
    }
}

/// Run `wxc-exec.exe` with the supplied config file and extra arguments.
pub fn run_wxc_config(config_file: &str, extra_args: &[&str]) -> CommandResult {
    let exe = find_binary("wxc-exec.exe").expect("wxc-exec.exe should be available");
    let config = test_configs_dir().join(config_file);
    let mut args: Vec<String> = extra_args.iter().map(|arg| (*arg).to_string()).collect();
    args.push(config.display().to_string());

    run_executable(config_file, &exe, args)
}

/// Run `wxc-exec.exe` with a state-aware request envelope. The JSON value is
/// serialised, base64-encoded, and passed via `--config-base64`. Used by the
/// state-aware smoke tests.
pub fn run_wxc_state_aware(
    label: &str,
    request: &serde_json::Value,
    extra_args: &[&str],
) -> CommandResult {
    let exe = find_binary("wxc-exec.exe").expect("wxc-exec.exe should be available");
    let json = request.to_string();
    let encoded = STANDARD.encode(json.as_bytes());

    let mut args: Vec<String> = extra_args.iter().map(|s| (*s).to_string()).collect();
    args.push("--config-base64".to_string());
    args.push(encoded);

    run_executable(label, &exe, args)
}

/// Run `wxc-exec.exe` with a one-shot config supplied as an in-memory JSON
/// value. The value is serialised, base64-encoded, and passed via
/// `--config-base64`, so callers can build configs with values only known at
/// test time (e.g. a dynamically discovered host IP or port).
pub fn run_wxc_config_value(
    label: &str,
    config: &serde_json::Value,
    extra_args: &[&str],
) -> CommandResult {
    let exe = find_binary("wxc-exec.exe").expect("wxc-exec.exe should be available");
    let encoded = STANDARD.encode(config.to_string().as_bytes());

    let mut args: Vec<String> = extra_args.iter().map(|s| (*s).to_string()).collect();
    args.push("--config-base64".to_string());
    args.push(encoded);

    run_executable(label, &exe, args)
}

// ---------------------------------------------------------------------------
// Cross-platform executor characterization helpers
//
// These drive the *native* one-shot executor binary for the current OS
// (`mxc-exec-mac` on macOS, `lxc-exec` on Linux, `wxc-exec.exe` on Windows)
// with an in-memory config, optionally setting the child process's environment
// and working directory. They exist to lock in the current run-to-completion
// behavior (exit code, stdout, env/cwd inheritance, timeout) before the
// unified `SandboxBackend`/`Runner` refactor lands.
// ---------------------------------------------------------------------------

/// The native one-shot executor binary name for the current platform.
pub fn platform_exec_binary_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "wxc-exec.exe"
    } else if cfg!(target_os = "macos") {
        "mxc-exec-mac"
    } else {
        "lxc-exec"
    }
}

/// Locate the native one-shot executor binary for the current platform.
pub fn find_platform_exec() -> Option<PathBuf> {
    find_binary(platform_exec_binary_name())
}

/// Whether the native executor binary for this platform is available.
pub fn has_platform_exec() -> bool {
    match find_platform_exec() {
        Some(p) => {
            println!("Using {} at {}", platform_exec_binary_name(), p.display());
            true
        }
        None => {
            println!(
                "SKIPPED: {} not found — build the native executor first",
                platform_exec_binary_name()
            );
            false
        }
    }
}

/// Whether `bwrap` (Bubblewrap) is installed and runnable on this Linux host.
/// Bubblewrap characterization tests skip cleanly when it is absent (e.g. a CI
/// runner without `bubblewrap` installed).
pub fn has_bwrap() -> bool {
    let available = Command::new("bwrap")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !available {
        println!("SKIPPED: bwrap not found on PATH — install `bubblewrap` to run these tests");
    }
    available
}

/// Opt-in switch for the Windows ProcessContainer characterization tests.
///
/// AppContainer/BaseContainer execution requires an elevated, host-prepped
/// Windows host (see `docs/host-prep.md`). Standard CI runners are NOT capable,
/// so these tests are skipped unless a host-prepped lane explicitly sets
/// `MXC_E2E_HOST_PREPPED=1`. This keeps them from ever red-failing on incapable
/// CI while still being runnable on a prepared box.
pub fn host_prepped_optin() -> bool {
    let enabled = std::env::var("MXC_E2E_HOST_PREPPED").as_deref() == Ok("1");
    if !enabled {
        println!(
            "SKIPPED: ProcessContainer characterization requires a host-prepped Windows host; \
             set MXC_E2E_HOST_PREPPED=1 on a prepared lane to enable"
        );
    }
    enabled
}

/// Run the current platform's native executor binary with an in-memory config
/// value (serialised + base64-encoded via `--config-base64`), optionally
/// setting environment variables and a working directory on the *executor*
/// process. `extra_env`/`cwd` are how the inheritance characterization tests
/// observe whether the sandboxed child picks up the launcher's env/cwd.
pub fn run_platform_config_value(
    label: &str,
    config: &serde_json::Value,
    extra_env: &[(&str, &str)],
    cwd: Option<&Path>,
) -> CommandResult {
    let exe = find_platform_exec().expect("native executor binary should be available");
    let encoded = STANDARD.encode(config.to_string().as_bytes());

    let start = Instant::now();
    let mut cmd = Command::new(&exe);
    cmd.arg("--config-base64").arg(encoded);
    for (key, value) in extra_env {
        cmd.env(key, value);
    }
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let output = cmd
        .output()
        .unwrap_or_else(|error| panic!("failed to execute {label}: {error}"));

    command_result(label, output, start.elapsed().as_millis())
}

/// Run `wxc-test-driver.exe` against a directory or a single config file.
pub fn run_test_driver(target: &Path, extra_args: &[&str]) -> CommandResult {
    let exe = find_binary("wxc-test-driver.exe").expect("wxc-test-driver.exe should be available");
    let mut args = vec![target.display().to_string()];
    args.extend(extra_args.iter().map(|arg| (*arg).to_string()));

    run_executable(&format!("wxc-test-driver {}", target.display()), &exe, args)
}

/// Assert that a command exited successfully.
pub fn assert_success(result: &CommandResult) {
    assert_exit(result, 0, None);
}

/// Assert success, or skip when the local machine lacks sandbox runtime prerequisites.
pub fn assert_success_or_skip_missing_prerequisite(result: &CommandResult) {
    if result.is_missing_process_prerequisite() {
        println!(
            "SKIPPED: {} requires local sandbox runtime prerequisites not available here",
            result.label
        );
        return;
    }

    assert_success(result);
}

/// Assert that a command exited with the expected code and optional output.
pub fn assert_exit(result: &CommandResult, expected_exit: i32, output_contains: Option<&str>) {
    if result.code != Some(expected_exit) {
        panic!(
            "{} failed: expected exit {}, got {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            result.label, expected_exit, result.code, result.stdout, result.stderr
        );
    }

    if let Some(expected) = output_contains {
        let combined = result.combined_output_with_decoded_base64();
        if !combined.contains(expected) {
            panic!(
                "{} failed: output missing '{}'\n--- combined output ---\n{}",
                result.label, expected, combined
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Temporary filesystem setup
// ---------------------------------------------------------------------------

/// Temporary directories removed when the guard is dropped.
#[derive(Debug)]
pub struct TempDirs {
    paths: Vec<PathBuf>,
}

impl TempDirs {
    /// Create temporary directories, removing any stale versions first.
    pub fn create(paths: &[&str]) -> Self {
        let paths: Vec<PathBuf> = paths.iter().map(PathBuf::from).collect();
        for path in &paths {
            remove_dir_all_if_exists(path);
            fs::create_dir_all(path).unwrap_or_else(|error| {
                panic!("failed to create temp dir {}: {error}", path.display())
            });
        }
        Self { paths }
    }

    /// Write a UTF-8 text file to an absolute path.
    ///
    /// The file is cleaned up when its parent directory is one of this guard's
    /// tracked temporary directories.
    pub fn write_absolute_file(&self, absolute_path: &str, contents: &str) {
        let path = PathBuf::from(absolute_path);
        assert!(
            path.is_absolute(),
            "temporary test file path must be absolute: {}",
            path.display()
        );
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap_or_else(|error| {
                panic!("failed to create parent dir {}: {error}", parent.display())
            });
        }
        fs::write(&path, contents)
            .unwrap_or_else(|error| panic!("failed to write {}: {error}", path.display()));
    }
}

impl Drop for TempDirs {
    fn drop(&mut self) {
        for path in &self.paths {
            remove_dir_all_if_exists(path);
        }
    }
}

fn remove_dir_all_if_exists(path: &Path) {
    if !path.exists() {
        return;
    }

    if fs::remove_dir_all(path).is_ok() {
        return;
    }

    std::thread::sleep(Duration::from_millis(100));
    if path.exists() {
        fs::remove_dir_all(path).unwrap_or_else(|error| {
            panic!("failed to remove temp dir {}: {error}", path.display())
        });
    }
}
