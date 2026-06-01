// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Registry-based sandbox lifecycle tracking for the BaseContainer backend.
//!
//! Each sandbox gets a random identity (`sandbox-{16 hex chars}`) and a registry
//! tracking entry so cleanup can proceed even after crashes or unexpected exits.
//!
//! ## Registry layout
//!
//! ```text
//! HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion
//!     \ProcessSandboxes\Mappings\{AppContainerSID}
//!         Identity        REG_SZ      "sandbox-a3f1c8e40029bd17"
//!         AppContainerSID REG_SZ      "S-1-15-2-..."
//!         DestroyOnExit   REG_DWORD   1 or 0
//!         CreatedTime     REG_QWORD   FILETIME as u64
//!         Active\                     (volatile -- auto-deleted on reboot)
//! ```
//!
//! If cleanup is skipped (e.g., network proxy configured), an additional value
//! `CleanupDeferred` (REG_SZ) is written with the reason.

use std::fmt::Write;

use windows::Win32::Security::FreeSid;
use windows::Win32::Security::Isolation::{
    DeleteAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_core::PCWSTR;
use winreg::enums::{HKEY_CURRENT_USER, KEY_ALL_ACCESS, REG_OPTION_VOLATILE};
use winreg::RegKey;

use wxc_common::logger::Logger;
use wxc_common::string_util;

/// Registry base path for sandbox tracking entries.
const TRACKING_BASE: &str = "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\ProcessSandboxes\\Mappings";

/// Generate a unique sandbox identity string: `sandbox-{16 lowercase hex chars}`.
///
/// Uses 8 bytes of CSPRNG randomness (64 bits), matching the format specified
/// in the MXC sandbox lifecycle design.
pub fn generate_sandbox_identity() -> String {
    let mut buf = [0u8; 8];
    getrandom::getrandom(&mut buf).expect("OS getrandom call failed");
    let value = u64::from_be_bytes(buf);
    format!("sandbox-{:016x}", value)
}

/// Derive the AppContainer SID string (e.g., `S-1-15-2-...`) from an identity.
///
/// Returns the SDDL SID string, or an error description. The underlying
/// `DeriveAppContainerSidFromAppContainerName` is deterministic and does not
/// require the AppContainer profile to already exist.
pub fn derive_sid_string(identity: &str) -> Result<String, String> {
    let wide_identity = string_util::to_wide(identity);
    let pcwstr = PCWSTR(wide_identity.as_ptr());

    // SAFETY: `wide_identity` is a valid null-terminated wide string that
    // outlives the call. The returned SID must be freed with `FreeSid`.
    let psid = unsafe {
        DeriveAppContainerSidFromAppContainerName(pcwstr)
            .map_err(|e| format!("DeriveAppContainerSidFromAppContainerName failed: {e}"))?
    };

    // Reuse the shared SID-to-string helper from string_util.
    let result = unsafe { string_util::sid_to_string(psid.0, "") };

    // SAFETY: SID was allocated by the OS and must be freed with FreeSid.
    unsafe {
        FreeSid(psid);
    }

    if result.is_empty() {
        return Err("ConvertSidToStringSidW failed".into());
    }

    Ok(result)
}

/// Information about a tracked sandbox entry, used for logging and cleanup.
pub struct TrackingEntry {
    /// The sandbox identity string (e.g., `sandbox-a3f1c8e40029bd17`).
    pub identity: String,
    /// The AppContainer SID as an SDDL string.
    pub sid_string: String,
    /// Whether `destroy_on_exit` was requested.
    pub destroy_on_exit: bool,
    /// The caller-provided container_id (may be empty if none was provided).
    pub requested_identity: String,
}

/// Write a registry tracking entry for a newly-created sandbox.
///
/// Creates the key tree and volatile `Active` subkey. Should be called
/// immediately before launching `CreateProcessInSandbox` so the entry exists
/// even if the process creation itself crashes the host.
///
/// Returns `Ok(())` on success. Errors are non-fatal (logged but not blocking).
pub fn write_tracking_entry(entry: &TrackingEntry, logger: &mut Logger) -> Result<(), String> {
    let key_path = format!("{}\\{}", TRACKING_BASE, entry.sid_string);

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _) = hkcu
        .create_subkey(&key_path)
        .map_err(|e| format!("create tracking key failed: {e}"))?;

    key.set_value("Identity", &entry.identity)
        .map_err(|e| format!("set Identity failed: {e}"))?;
    key.set_value("AppContainerSID", &entry.sid_string)
        .map_err(|e| format!("set AppContainerSID failed: {e}"))?;
    let dword_val: u32 = if entry.destroy_on_exit { 1 } else { 0 };
    key.set_value("DestroyOnExit", &dword_val)
        .map_err(|e| format!("set DestroyOnExit failed: {e}"))?;
    if !entry.requested_identity.is_empty() {
        key.set_value("RequestedIdentity", &entry.requested_identity)
            .map_err(|e| format!("set RequestedIdentity failed: {e}"))?;
    }
    key.set_value("Origin", &"mxc")
        .map_err(|e| format!("set Origin failed: {e}"))?;

    let filetime = get_current_filetime();
    key.set_value("CreatedTime", &filetime)
        .map_err(|e| format!("set CreatedTime failed: {e}"))?;

    // Create volatile Active subkey (auto-deleted on reboot for crash detection).
    key.create_subkey_with_flags("Active", KEY_ALL_ACCESS | REG_OPTION_VOLATILE)
        .map_err(|e| format!("create Active volatile subkey failed: {e}"))?;

    let _ = writeln!(
        logger,
        "tracking entry written: {}\\{}",
        TRACKING_BASE, entry.sid_string
    );

    Ok(())
}

/// Mark a tracking entry with a reason that cleanup was deferred.
///
/// Adds a `CleanupDeferred` REG_SZ value to the existing tracking key.
pub fn mark_cleanup_deferred(sid_string: &str, reason: &str, logger: &mut Logger) {
    let key_path = format!("{}\\{}", TRACKING_BASE, sid_string);

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    match hkcu.create_subkey(&key_path) {
        Ok((key, _)) => {
            let _ = key.set_value("CleanupDeferred", &reason);
        }
        Err(_) => {
            let _ = writeln!(
                logger,
                "warning: could not open tracking key to mark deferred"
            );
            return;
        }
    }

    let _ = writeln!(logger, "cleanup deferred: {}", reason);
}

/// Clean up a sandbox: clear BFS filesystem policies, delete the AppContainer
/// profile, and remove the tracking registry entry. Best-effort and idempotent
/// -- failures are logged but do not propagate as errors.
///
/// Order matters: BFS policies must be cleared before the AppContainer profile
/// is deleted (BFS needs the SID, which is derived from the profile identity).
pub fn cleanup_sandbox(identity: &str, sid_string: &str, logger: &mut Logger) {
    // Step 1: Clear BFS filesystem policies (must happen before profile deletion).
    crate::filesystem_bfs::FileSystemBfsManager::clear_policy(identity, logger);

    // Step 2: Delete the AppContainer profile.
    let Ok(wide_identity) = widestring::U16CString::from_str(identity) else {
        let _ = writeln!(
            logger,
            "warning: failed to convert AppContainer identity to UTF-16: {}",
            identity
        );
        return;
    };
    // SAFETY: `wide_identity` is a valid null-terminated UTF-16 string.
    match unsafe { DeleteAppContainerProfile(PCWSTR(wide_identity.as_ptr())) } {
        Ok(()) => {
            let _ = writeln!(logger, "deleted AppContainer profile: {}", identity);
        }
        Err(e) => {
            let _ = writeln!(
                logger,
                "warning: DeleteAppContainerProfile('{}') failed: {} (may already be deleted)",
                identity, e
            );
        }
    }

    // Step 3: Delete the registry tracking entry.
    delete_tracking_key(sid_string, logger);
}

/// Remove the registry tracking key and all its subkeys (including Active).
fn delete_tracking_key(sid_string: &str, logger: &mut Logger) {
    let key_path = format!("{}\\{}", TRACKING_BASE, sid_string);
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    match hkcu.delete_subkey_all(&key_path) {
        Ok(()) => {
            let _ = writeln!(logger, "deleted tracking key: {}", key_path);
        }
        Err(e) => {
            let _ = writeln!(
                logger,
                "warning: could not delete tracking key '{}': {}",
                key_path, e
            );
        }
    }
}

// --- Time helper ---

/// Get the current time as a FILETIME u64 value.
fn get_current_filetime() -> u64 {
    use windows::Win32::System::SystemInformation::GetSystemTimeAsFileTime;

    // SAFETY: no preconditions; returns the current system time as FILETIME.
    let ft = unsafe { GetSystemTimeAsFileTime() };
    ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64)
}

// --- Ctrl+C / console close cleanup handler ---

use std::sync::{Mutex, OnceLock};

/// State captured so the console-ctrl handler can run cleanup on Ctrl+C or
/// console close without any context pointer (Win32 handler is a bare fn).
/// Fields are currently unused because cleanup is disabled, but retained for
/// when child process tracking is implemented.
#[allow(dead_code)]
struct ActiveCleanup {
    identity: String,
    sid_string: String,
    proxy_enabled: bool,
}

static ACTIVE_CLEANUP: OnceLock<Mutex<Option<ActiveCleanup>>> = OnceLock::new();

fn cleanup_slot() -> &'static Mutex<Option<ActiveCleanup>> {
    ACTIVE_CLEANUP.get_or_init(|| Mutex::new(None))
}

/// Register the active sandbox so a Ctrl+C or console-close event can clean
/// it up. Installs the console ctrl handler on first call.
///
/// Call this after the sandbox process has been successfully created.
pub fn register_ctrl_c_cleanup(identity: &str, sid_string: &str, proxy_enabled: bool) {
    {
        let mut slot = cleanup_slot().lock().unwrap_or_else(|p| p.into_inner());
        *slot = Some(ActiveCleanup {
            identity: identity.to_owned(),
            sid_string: sid_string.to_owned(),
            proxy_enabled,
        });
    }
    install_ctrl_handler();
}

/// Clear the active sandbox registration (e.g., after normal cleanup has
/// already run, so the handler becomes a no-op).
pub fn unregister_ctrl_c_cleanup() {
    if let Some(mutex) = ACTIVE_CLEANUP.get() {
        let mut slot = mutex.lock().unwrap_or_else(|p| p.into_inner());
        *slot = None;
    }
}

static HANDLER_INSTALLED: OnceLock<()> = OnceLock::new();

fn install_ctrl_handler() {
    HANDLER_INSTALLED.get_or_init(|| {
        use windows::Win32::System::Console::SetConsoleCtrlHandler;
        // SAFETY: `ctrl_handler` has the correct `unsafe extern "system"` signature.
        unsafe {
            let _ = SetConsoleCtrlHandler(Some(ctrl_handler), true);
        }
    });
}

/// Console ctrl handler callback. Runs cleanup if a sandbox is registered,
/// then returns FALSE so the default handler terminates the process.
unsafe extern "system" fn ctrl_handler(ctrl_type: u32) -> windows_core::BOOL {
    use windows::Win32::System::Console::{CTRL_CLOSE_EVENT, CTRL_C_EVENT};

    if ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_CLOSE_EVENT {
        let active = {
            cleanup_slot()
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .take()
        };
        if let Some(_state) = active {
            // Cleanup is currently disabled (child process tracking not yet
            // implemented), so the Ctrl+C handler is a no-op beyond consuming
            // the active slot to prevent double-fire.
            let mut logger = wxc_common::logger::Logger::new(wxc_common::logger::Mode::Buffer);
            let _ = std::fmt::Write::write_str(
                &mut logger,
                "ctrl handler: skipping cleanup (child process tracking not yet implemented)\n",
            );
        }
    }
    // Return FALSE so the default handler terminates the process.
    windows_core::BOOL(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_format_is_correct() {
        let id = generate_sandbox_identity();
        assert!(id.starts_with("sandbox-"), "got: {id}");
        // "sandbox-" is 8 chars + 16 hex = 24 total
        assert_eq!(id.len(), 24, "got: {id}");
        let hex_part = &id[8..];
        assert!(
            hex_part
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "non-hex chars in: {hex_part}",
        );
    }

    #[test]
    fn identities_are_unique() {
        use std::collections::HashSet;
        let n = 256;
        let mut set = HashSet::with_capacity(n);
        for _ in 0..n {
            set.insert(generate_sandbox_identity());
        }
        // 64-bit space -- collisions in 256 draws are astronomically unlikely.
        assert_eq!(set.len(), n);
    }

    #[test]
    fn derive_sid_string_succeeds_for_valid_identity() {
        // DeriveAppContainerSidFromAppContainerName works for any name, even
        // without a pre-existing profile.
        let id = generate_sandbox_identity();
        let sid = derive_sid_string(&id);
        assert!(sid.is_ok(), "got error: {:?}", sid.err());
        let sid_str = sid.unwrap();
        assert!(
            sid_str.starts_with("S-1-15-2-"),
            "unexpected SID: {sid_str}"
        );
    }
}
