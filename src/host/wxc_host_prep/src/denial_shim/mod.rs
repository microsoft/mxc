// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Install / uninstall / inspect the `MxcDenialShim` Windows service.
//!
//! The shim itself lives in `mxc-denial-shim.exe` (built from the
//! `mxc_denial_shim` crate). `wxc-host-prep` is the supported way to
//! register / deregister it with SCM, matching the existing
//! `prepare-system-drive` / `prepare-null-device` admin-time-only
//! pattern.
//!
//! Conventions:
//! - **Service name**: `MxcDenialShim` (matches the constant the shim
//!   binary itself uses with `start_dispatcher`).
//! - **Display name**: `"MXC Denial Capture Shim"` (visible in
//!   services.msc).
//! - **Account**: `NT AUTHORITY\LocalService` — least-privilege. The
//!   account doesn't carry `SeSystemProfilePrivilege` by default, so
//!   `install-denial-shim` grants it explicitly via the LSA
//!   `LsaAddAccountRights` API before creating the service. See the
//!   `privilege` submodule.
//! - **Start type**: `Demand` (manual). SCM idle-shutdown stops it
//!   ~60s after the last request; restart is automatic on the next
//!   inbound pipe connection (well, on the next `wxc-exec` invocation
//!   that opens the pipe — the service is started by either the
//!   caller or by an explicit `Start-Service MxcDenialShim`).
//! - **Default binary path**: same directory as `wxc-host-prep.exe`
//!   (i.e. the SDK bin dir). Override with `--shim-path`.

mod privilege;

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use windows_service::service::{
    ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

const SERVICE_NAME: &str = "MxcDenialShim";
const SERVICE_DISPLAY_NAME: &str = "MXC Denial Capture Shim";
const SHIM_BINARY_FILENAME: &str = "mxc-denial-shim.exe";

/// Service runs as `NT AUTHORITY\LocalService` (least-privilege).
/// `SeSystemProfilePrivilege` is granted to this account at install
/// time so the shim can call `StartTraceW`.
const SERVICE_ACCOUNT: &str = "NT AUTHORITY\\LocalService";

/// Default path: `<wxc-host-prep dir>\mxc-denial-shim.exe`.
fn default_shim_binary_path() -> Result<PathBuf, String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("could not determine wxc-host-prep path: {e}"))?;
    let dir = exe
        .parent()
        .ok_or_else(|| "wxc-host-prep has no parent directory".to_string())?;
    Ok(dir.join(SHIM_BINARY_FILENAME))
}

fn resolve_shim_path(override_path: Option<&str>) -> Result<PathBuf, String> {
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
                     pass --shim-path <path> to specify an explicit location",
                    pb.display()
                ));
            }
            Ok(pb)
        }
    }
}

/// Implements `wxc-host-prep install-denial-shim`.
///
/// Idempotent: if the service is already registered with the same
/// binary path it returns success. Differing binary paths are an
/// explicit conflict — caller must `uninstall-denial-shim` first.
///
/// Always re-applies the `SeSystemProfilePrivilege` grant to
/// `LocalService` (no-op when already granted, per LSA semantics).
pub fn run_install(shim_path_override: Option<&str>) -> i32 {
    let shim_path = match resolve_shim_path(shim_path_override) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };

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

    // If the service already exists, treat as idempotent if the binary
    // path matches; otherwise tell the caller to uninstall first.
    if let Ok(existing) = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_CONFIG) {
        match existing.query_config() {
            Ok(cfg) => {
                let existing_path = strip_quotes(&cfg.executable_path.to_string_lossy());
                let new_path = shim_path.to_string_lossy().to_string();
                if paths_match(&existing_path, &new_path) {
                    println!(
                        "service {SERVICE_NAME} already installed with binary {} (no change)",
                        existing_path
                    );
                    return 0;
                }
                eprintln!(
                    "error: service {SERVICE_NAME} already installed with a different binary:\n  \
                     existing: {existing_path}\n  requested: {new_path}\n\
                     run `wxc-host-prep uninstall-denial-shim` first"
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

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::OnDemand,
        error_control: ServiceErrorControl::Normal,
        executable_path: shim_path.clone(),
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
                shim_path.display()
            );
            0
        }
        Err(e) => {
            eprintln!("error: CreateService failed: {e}");
            1
        }
    }
}

/// Implements `wxc-host-prep uninstall-denial-shim`.
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
            0
        }
        Err(e) => {
            eprintln!("error: DeleteService failed: {e}");
            1
        }
    }
}

/// Implements `wxc-host-prep dump-denial-shim`.
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
