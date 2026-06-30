// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Install / uninstall / inspect the `MxcLearningModeShim` Windows service.
//!
//! The shim itself lives in `mxc-learning-mode-shim.exe` (built from the
//! `mxc_learning_mode_shim` crate). `wxc-host-prep` is the supported way to
//! register / deregister it with SCM, matching the existing
//! `prepare-system-drive` / `prepare-null-device` admin-time-only
//! pattern.
//!
//! Conventions:
//! - **Service name**: `MxcLearningModeShim` (matches the constant the shim
//!   binary itself uses with `start_dispatcher`).
//! - **Display name**: `"MXC Denial Capture Shim"` (visible in
//!   services.msc).
//! - **Account**: `NT AUTHORITY\LocalService` — least-privilege. The
//!   account doesn't carry `SeSystemProfilePrivilege` by default, so
//!   `install-learning-mode-shim` grants it explicitly via the LSA
//!   `LsaAddAccountRights` API before creating the service. See the
//!   `privilege` submodule.
//! - **Start type**: `Demand` (manual). SCM idle-shutdown stops it
//!   ~60s after the last request; restart is automatic on the next
//!   inbound pipe connection (well, on the next `wxc-exec` invocation
//!   that opens the pipe — the service is started by either the
//!   caller or by an explicit `Start-Service MxcLearningModeShim`).
//! - **Install location**: the shim binary is **copied into a protected
//!   `Program Files` subdirectory** (`%ProgramFiles%\Mxc\mxc-learning-mode-shim.exe`)
//!   and the service is registered to run from there. `Program Files` is
//!   writable only by administrators / SYSTEM / TrustedInstaller, so
//!   unprivileged (Authenticated Users) callers cannot swap the registered
//!   service binary.
//! - **Source binary**: `mxc-learning-mode-shim.exe` next to
//!   `wxc-host-prep.exe` (the SDK bin dir). Override the *source* with
//!   `--shim-path`; install always copies that source into `Program Files`.

mod privilege;

use std::ffi::OsString;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::CopyFileW;
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::UI::Shell::{FOLDERID_ProgramFiles, SHGetKnownFolderPath, KNOWN_FOLDER_FLAG};
use windows_service::service::{
    ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

const SERVICE_NAME: &str = "MxcLearningModeShim";
const SERVICE_DISPLAY_NAME: &str = "MXC Denial Capture Shim";
const SHIM_BINARY_FILENAME: &str = "mxc-learning-mode-shim.exe";

/// `Program Files` subdirectory the shim binary is installed into.
const SHIM_INSTALL_SUBDIR: &str = "Mxc";

/// Service runs as `NT AUTHORITY\LocalService` (least-privilege).
/// `SeSystemProfilePrivilege` is granted to this account at install
/// time so the shim can call `StartTraceW`.
const SERVICE_ACCOUNT: &str = "NT AUTHORITY\\LocalService";

/// Default *source* path: `<wxc-host-prep dir>\mxc-learning-mode-shim.exe`.
fn default_shim_binary_path() -> Result<PathBuf, String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("could not determine wxc-host-prep path: {e}"))?;
    let dir = exe
        .parent()
        .ok_or_else(|| "wxc-host-prep has no parent directory".to_string())?;
    Ok(dir.join(SHIM_BINARY_FILENAME))
}

/// Resolves the *source* binary to copy into the install location. An
/// explicit `--shim-path` overrides the default SDK-bin-dir location; the
/// source must exist on disk.
fn resolve_source_shim_path(override_path: Option<&str>) -> Result<PathBuf, String> {
    match override_path {
        Some(p) => {
            let pb = PathBuf::from(p);
            if !pb.exists() {
                return Err(format!("shim binary not found at {}", pb.display()));
            }
            Ok(pb)
        }
        None => {
            let pb = default_shim_binary_path()?;
            if !pb.exists() {
                return Err(format!(
                    "shim binary not found at default path {}\n\
                     pass --shim-path <path> to specify an explicit source location",
                    pb.display()
                ));
            }
            Ok(pb)
        }
    }
}

/// Returns the machine's `Program Files` directory via the Known Folders
/// API (correct on localized / redirected installs, unlike a hardcoded
/// path). `wxc-host-prep` ships as a native binary, so this resolves the
/// real 64-bit `Program Files` (no WoW64 redirect to `Program Files (x86)`).
fn program_files_directory() -> Result<PathBuf, String> {
    unsafe {
        let pwstr = SHGetKnownFolderPath(&FOLDERID_ProgramFiles, KNOWN_FOLDER_FLAG(0), None)
            .map_err(|e| format!("SHGetKnownFolderPath(ProgramFiles) failed: {e}"))?;
        let result = pwstr
            .to_string()
            .map_err(|e| format!("Program Files path was not valid UTF-16: {e}"));
        // SHGetKnownFolderPath allocates with CoTaskMemAlloc — free it
        // regardless of whether the conversion above succeeded.
        CoTaskMemFree(Some(pwstr.0 as *const core::ffi::c_void));
        Ok(PathBuf::from(result?))
    }
}

/// `%ProgramFiles%\Mxc` — the install directory for the shim binary.
fn shim_install_dir() -> Result<PathBuf, String> {
    Ok(program_files_directory()?.join(SHIM_INSTALL_SUBDIR))
}

/// Wide, NUL-terminated form of a path for the `*W` Win32 APIs.
fn to_wide_nul(p: &Path) -> Vec<u16> {
    p.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Copies the source shim binary to the install target, overwriting any
/// existing copy. The destination inherits the `Program Files` DACL
/// (administrators / SYSTEM / TrustedInstaller write only).
fn copy_shim_to_target(source: &Path, target: &Path) -> Result<(), String> {
    let src_w = to_wide_nul(source);
    let dst_w = to_wide_nul(target);
    // bFailIfExists = false: install overwrites a stale copy in place.
    unsafe { CopyFileW(PCWSTR(src_w.as_ptr()), PCWSTR(dst_w.as_ptr()), false) }.map_err(|e| {
        format!(
            "CopyFile {} -> {} failed: {e}",
            source.display(),
            target.display()
        )
    })
}

/// Best-effort hardening audit of the installed binary. Confirms the
/// target lives under the resolved install root (so it inherits the
/// protected `Program Files` DACL) and warns if any broad principal still
/// holds an explicit write ACE on it. Never fails the install — it is a
/// diagnostic, not a gate.
fn verify_target_hardening(target: &Path, install_root: &Path) {
    if !target.starts_with(install_root) {
        eprintln!(
            "warning: shim target {} is not under {}; protected ACL inheritance is not guaranteed",
            target.display(),
            install_root.display()
        );
        return;
    }

    // Broad principals that must NOT have write on a privileged service
    // binary: Authenticated Users, BUILTIN\Users, Everyone.
    const BROAD_PRINCIPALS: &[(&str, &str)] = &[
        ("S-1-5-11", "Authenticated Users"),
        ("S-1-5-32-545", "Users"),
        ("S-1-1-0", "Everyone"),
    ];
    // Write-equivalent rights: FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE
    // | WRITE_DAC | WRITE_OWNER | GENERIC_ALL | GENERIC_WRITE.
    const BROAD_WRITE_BITS: u32 = 0x0000_0002
        | 0x0000_0004
        | 0x0001_0000
        | 0x0004_0000
        | 0x0008_0000
        | 0x1000_0000
        | 0x4000_0000;

    for (sid, label) in BROAD_PRINCIPALS {
        if let Ok(aces) = wxc_common::filesystem_dacl::scan_explicit_aces_for_sid(target, sid) {
            for ace in aces {
                if ace.ace_type == wxc_common::filesystem_dacl::AceType::Allow
                    && (ace.access_mask & BROAD_WRITE_BITS) != 0
                {
                    eprintln!(
                        "warning: installed shim {} grants write access to {label} \
                         (mask {:#010x}); unprivileged callers may be able to replace it",
                        target.display(),
                        ace.access_mask
                    );
                }
            }
        }
    }
}

/// Implements `wxc-host-prep install-learning-mode-shim`.
///
/// Copies the source shim binary into `%ProgramFiles%\Mxc` and registers
/// the service to run from there. Idempotent: if the service is already
/// registered with the same (install-target) binary path it refreshes the
/// copy and returns success. A service registered with a *different*
/// binary path is an explicit conflict — caller must
/// `uninstall-learning-mode-shim` first.
///
/// Always re-applies the `SeSystemProfilePrivilege` grant to
/// `LocalService` (no-op when already granted, per LSA semantics).
pub fn run_install(shim_path_override: Option<&str>) -> i32 {
    let source_path = match resolve_source_shim_path(shim_path_override) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };

    let install_dir = match shim_install_dir() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return 3;
        }
    };
    let target_path = install_dir.join(SHIM_BINARY_FILENAME);

    // 1. Grant SeSystemProfilePrivilege to LocalService BEFORE creating
    //    the service. If the privilege grant fails the service is
    //    useless anyway, so bail early without touching SCM.
    if let Err(e) = privilege::grant_se_system_profile_to_local_service() {
        eprintln!("error: could not grant SeSystemProfilePrivilege to LocalService: {e}");
        return 3;
    }
    println!("granted SeSystemProfilePrivilege to NT AUTHORITY\\LocalService");

    let manager = match ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    ) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: OpenSCManager failed: {e}");
            return 3;
        }
    };

    // If the service already exists, treat as idempotent when the binary
    // path matches the install target; otherwise tell the caller to
    // uninstall first.
    if let Ok(existing) = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_CONFIG) {
        match existing.query_config() {
            Ok(cfg) => {
                let existing_path = strip_quotes(&cfg.executable_path.to_string_lossy());
                let new_path = target_path.to_string_lossy().to_string();
                if paths_match(&existing_path, &new_path) {
                    // Same registration — refresh the on-disk copy so an
                    // install after a binary rebuild updates the bits.
                    if let Err(e) = copy_shim_to_target(&source_path, &target_path) {
                        eprintln!("error: {e}");
                        return 1;
                    }
                    verify_target_hardening(&target_path, &install_dir);
                    println!(
                        "service {SERVICE_NAME} already installed with binary {} (refreshed)",
                        existing_path
                    );
                    return 0;
                }
                eprintln!(
                    "error: service {SERVICE_NAME} already installed with a different binary:\n  \
                     existing: {existing_path}\n  requested: {new_path}\n\
                     run `wxc-host-prep uninstall-learning-mode-shim` first"
                );
                return 1;
            }
            Err(e) => {
                eprintln!("warning: could not read existing service config: {e}");
                // fall through — try to create; CreateService will fail
                // with ERROR_SERVICE_EXISTS which we surface verbatim.
            }
        }
    }

    // 2. Stage the binary in the protected install directory before
    //    registering the service so the SCM record never points at a
    //    missing file.
    if let Err(e) = std::fs::create_dir_all(&install_dir) {
        eprintln!(
            "error: could not create install directory {}: {e}",
            install_dir.display()
        );
        return 1;
    }
    if let Err(e) = copy_shim_to_target(&source_path, &target_path) {
        eprintln!("error: {e}");
        return 1;
    }
    println!(
        "staged shim binary {} -> {}",
        source_path.display(),
        target_path.display()
    );
    verify_target_hardening(&target_path, &install_dir);

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::OnDemand,
        error_control: ServiceErrorControl::Normal,
        executable_path: target_path.clone(),
        launch_arguments: vec![],
        dependencies: vec![],
        // Least-privilege account; privilege grant happened above.
        account_name: Some(OsString::from(SERVICE_ACCOUNT)),
        account_password: None,
    };

    match manager.create_service(&service_info, ServiceAccess::QUERY_CONFIG) {
        Ok(_svc) => {
            println!(
                "installed service {SERVICE_NAME}\n  display: {SERVICE_DISPLAY_NAME}\n  \
                 binary:  {}\n  account: {SERVICE_ACCOUNT} (Manual start, with SeSystemProfilePrivilege)",
                target_path.display()
            );
            0
        }
        Err(e) => {
            eprintln!("error: CreateService failed: {e}");
            1
        }
    }
}

/// Implements `wxc-host-prep uninstall-learning-mode-shim`.
///
/// Stops the service if it's running, then deletes the SCM record.
/// Idempotent: a service that doesn't exist is a successful exit.
pub fn run_uninstall() -> i32 {
    let manager = match ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
    {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: OpenSCManager failed: {e}");
            return 3;
        }
    };

    let service = match manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    ) {
        Ok(s) => s,
        Err(e) => {
            // Most common case: service doesn't exist. Treat as success.
            let msg = e.to_string();
            if msg.contains("does not exist") || msg.contains("1060") {
                println!("service {SERVICE_NAME} is not installed (no change)");
                return 0;
            }
            eprintln!("error: OpenService failed: {e}");
            return 1;
        }
    };

    // Best-effort stop. Failures here are non-fatal — DeleteService can
    // still mark the service for removal, and the OS reaps it on next
    // service restart.
    if let Ok(status) = service.query_status() {
        if status.current_state == ServiceState::Running {
            if let Err(e) = service.stop() {
                eprintln!("warning: failed to stop service before delete: {e}");
            }
        }
    }

    match service.delete() {
        Ok(_) => {
            println!("uninstalled service {SERVICE_NAME}");
            // Best-effort cleanup of the staged binary. The SCM record is
            // gone, so a leftover binary is harmless, but privileged
            // artifacts shouldn't linger.
            if let Ok(install_dir) = shim_install_dir() {
                let target = install_dir.join(SHIM_BINARY_FILENAME);
                match std::fs::remove_file(&target) {
                    Ok(_) => println!("removed {}", target.display()),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => eprintln!("warning: could not remove {}: {e}", target.display()),
                }
                // Remove the install directory only if now empty.
                let _ = std::fs::remove_dir(&install_dir);
            }
            0
        }
        Err(e) => {
            eprintln!("error: DeleteService failed: {e}");
            1
        }
    }
}

/// Implements `wxc-host-prep dump-learning-mode-shim`.
///
/// Reports installed-or-not, current state, and the registered binary
/// path. Exits 0 when installed, 1 when not.
pub fn run_dump(json: bool) -> i32 {
    let manager = match ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
    {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: OpenSCManager failed: {e}");
            return 3;
        }
    };

    let service = match manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS,
    ) {
        Ok(s) => s,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("does not exist") || msg.contains("1060") {
                if json {
                    println!("{{\"installed\":false}}");
                } else {
                    println!("service {SERVICE_NAME}: not installed");
                }
                return 1;
            }
            eprintln!("error: OpenService failed: {e}");
            return 2;
        }
    };

    let cfg = match service.query_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: QueryServiceConfig failed: {e}");
            return 2;
        }
    };
    let status = match service.query_status() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: QueryServiceStatusEx failed: {e}");
            return 2;
        }
    };

    let state = format!("{:?}", status.current_state);
    let binary = strip_quotes(&cfg.executable_path.to_string_lossy());
    let start_type = format!("{:?}", cfg.start_type);

    if json {
        println!(
            "{{\"installed\":true,\"name\":\"{SERVICE_NAME}\",\"state\":\"{state}\",\
             \"binary\":\"{}\",\"startType\":\"{start_type}\"}}",
            binary.replace('\\', "\\\\")
        );
    } else {
        println!("service {SERVICE_NAME}:");
        println!("  installed:  yes");
        println!("  state:      {state}");
        println!("  binary:     {binary}");
        println!("  start type: {start_type}");
    }
    0
}

/// SCM stores the binary path either bare or wrapped in quotes when it
/// contains spaces. Strip a single pair of surrounding quotes for
/// comparison / display.
fn strip_quotes(s: &str) -> String {
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

/// Compares two filesystem paths case-insensitively (Windows convention).
fn paths_match(a: &str, b: &str) -> bool {
    Path::new(a)
        .to_string_lossy()
        .eq_ignore_ascii_case(&Path::new(b).to_string_lossy())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_quotes_removes_surrounding_quotes() {
        assert_eq!(
            strip_quotes("\"C:\\Program Files\\app.exe\""),
            "C:\\Program Files\\app.exe"
        );
        assert_eq!(strip_quotes("C:\\nopath.exe"), "C:\\nopath.exe");
        assert_eq!(strip_quotes(""), "");
        assert_eq!(strip_quotes("\""), "\"");
    }

    #[test]
    fn paths_match_case_insensitive() {
        assert!(paths_match("c:\\foo\\bar.exe", "C:\\Foo\\Bar.EXE"));
        assert!(!paths_match("c:\\foo.exe", "c:\\bar.exe"));
    }
}
