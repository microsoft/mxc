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

use windows::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HLOCAL};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::Isolation::{
    DeleteAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows::Win32::Security::{FreeSid, PSID};
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegSetValueExW, HKEY, HKEY_CURRENT_USER,
    KEY_ALL_ACCESS, REG_DWORD, REG_OPTION_NON_VOLATILE, REG_OPTION_VOLATILE, REG_QWORD, REG_SZ,
};
use windows_core::PCWSTR;

use crate::logger::Logger;
use crate::string_util;

/// Registry base path for sandbox tracking entries.
const TRACKING_BASE: &str = "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\ProcessSandboxes\\Mappings";

/// Generate a unique sandbox identity string: `sandbox-{16 lowercase hex chars}`.
///
/// Uses 8 bytes of CSPRNG randomness (64 bits), matching the format specified
/// in the Tessera sandbox lifecycle design.
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

    let sid_string = sid_to_sddl(psid);

    // SAFETY: SID was allocated by the OS and must be freed with FreeSid.
    unsafe {
        FreeSid(psid);
    }

    sid_string
}

/// Convert a PSID to its SDDL string representation.
fn sid_to_sddl(psid: PSID) -> Result<String, String> {
    let mut string_sid = windows_core::PWSTR::null();

    // SAFETY: `psid` is a valid SID pointer returned by the OS.
    unsafe {
        ConvertSidToStringSidW(psid, &mut string_sid)
            .map_err(|e| format!("ConvertSidToStringSidW failed: {e}"))?;
    }

    // SAFETY: `string_sid` is a valid OS-allocated wide string.
    let result = unsafe { string_sid.to_string() }
        .map_err(|e| format!("SID string conversion failed: {e}"))?;

    // SAFETY: Free the OS-allocated string buffer.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(string_sid.0 as *mut std::ffi::c_void)));
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
    let wide_path = string_util::to_wide(&key_path);

    // Create or open the tracking key.
    let mut hkey = HKEY::default();
    // SAFETY: `wide_path` is a valid null-terminated wide string. We create/open
    // a registry key under HKCU which is always writable for the current user.
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(wide_path.as_ptr()),
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS,
            None,
            &mut hkey,
            None,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(format!(
            "RegCreateKeyExW(tracking key) failed: {:?}",
            status
        ));
    }

    // Write Identity value.
    set_reg_sz(hkey, "Identity", &entry.identity)?;

    // Write AppContainerSID value.
    set_reg_sz(hkey, "AppContainerSID", &entry.sid_string)?;

    // Write DestroyOnExit value (DWORD).
    let dword_val: u32 = if entry.destroy_on_exit { 1 } else { 0 };
    set_reg_dword(hkey, "DestroyOnExit", dword_val)?;

    // Write RequestedIdentity (the caller-provided container_id, if any).
    if !entry.requested_identity.is_empty() {
        set_reg_sz(hkey, "RequestedIdentity", &entry.requested_identity)?;
    }

    // Write Origin to distinguish MXC-created entries from OS-created ones.
    set_reg_sz(hkey, "Origin", "mxc")?;

    // Write CreatedTime (QWORD as FILETIME).
    let filetime = get_current_filetime();
    set_reg_qword(hkey, "CreatedTime", filetime)?;

    // Create volatile Active subkey (auto-deleted on reboot for crash detection).
    let mut active_key = HKEY::default();
    // SAFETY: `hkey` is a valid open key.
    let active_status = unsafe {
        RegCreateKeyExW(
            hkey,
            PCWSTR(string_util::to_wide("Active").as_ptr()),
            None,
            PCWSTR::null(),
            REG_OPTION_VOLATILE,
            KEY_ALL_ACCESS,
            None,
            &mut active_key,
            None,
        )
    };
    if active_status != ERROR_SUCCESS {
        // SAFETY: close the parent key before returning.
        unsafe {
            let _ = RegCloseKey(hkey);
        }
        return Err(format!(
            "RegCreateKeyExW(Active volatile) failed: {:?}",
            active_status
        ));
    }

    // SAFETY: close both keys.
    unsafe {
        let _ = RegCloseKey(active_key);
        let _ = RegCloseKey(hkey);
    }

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
    let wide_path = string_util::to_wide(&key_path);

    let mut hkey = HKEY::default();
    // SAFETY: valid null-terminated path string, opening existing key.
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(wide_path.as_ptr()),
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS,
            None,
            &mut hkey,
            None,
        )
    };
    if status != ERROR_SUCCESS {
        let _ = writeln!(
            logger,
            "warning: could not open tracking key to mark deferred"
        );
        return;
    }

    let _ = set_reg_sz(hkey, "CleanupDeferred", reason);
    // SAFETY: close the key.
    unsafe {
        let _ = RegCloseKey(hkey);
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
    let wide_identity: Vec<u16> = identity.encode_utf16().chain(std::iter::once(0)).collect();
    let hstring = windows::core::HSTRING::from_wide(&wide_identity[..wide_identity.len() - 1]);
    // SAFETY: `hstring` contains the identity used to create the profile.
    match unsafe { DeleteAppContainerProfile(&hstring) } {
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

/// Remove the registry tracking key and its Active subkey.
fn delete_tracking_key(sid_string: &str, logger: &mut Logger) {
    let key_path = format!("{}\\{}", TRACKING_BASE, sid_string);

    // Delete Active subkey first (RegDeleteKeyW requires no subkeys).
    let active_path = format!("{}\\Active", key_path);
    let wide_active = string_util::to_wide(&active_path);
    // SAFETY: valid null-terminated path for deletion.
    unsafe {
        let _ = RegDeleteKeyW(HKEY_CURRENT_USER, PCWSTR(wide_active.as_ptr()));
    }

    // Delete the tracking key itself.
    let wide_key = string_util::to_wide(&key_path);
    // SAFETY: valid null-terminated path for deletion.
    let result = unsafe { RegDeleteKeyW(HKEY_CURRENT_USER, PCWSTR(wide_key.as_ptr())) };
    if result == ERROR_SUCCESS {
        let _ = writeln!(logger, "deleted tracking key: {}", key_path);
    } else {
        let _ = writeln!(
            logger,
            "warning: could not delete tracking key '{}': {:?}",
            key_path, result
        );
    }
}

// --- Registry helper functions ---

fn set_reg_sz(hkey: HKEY, name: &str, value: &str) -> Result<(), String> {
    let wide_name = string_util::to_wide(name);
    let wide_value = string_util::to_wide(value);
    // REG_SZ data includes the null terminator, in bytes.
    let byte_len = wide_value.len() * 2;
    // SAFETY: `hkey` is a valid open key, `wide_name` and `wide_value` are valid
    // null-terminated wide strings. Data length includes the null terminator.
    let status = unsafe {
        RegSetValueExW(
            hkey,
            PCWSTR(wide_name.as_ptr()),
            None,
            REG_SZ,
            Some(std::slice::from_raw_parts(
                wide_value.as_ptr() as *const u8,
                byte_len,
            )),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(format!("RegSetValueExW({name}) failed: {:?}", status));
    }
    Ok(())
}

fn set_reg_dword(hkey: HKEY, name: &str, value: u32) -> Result<(), String> {
    let wide_name = string_util::to_wide(name);
    let bytes = value.to_le_bytes();
    // SAFETY: `hkey` is a valid open key, writing 4 bytes of DWORD data.
    let status = unsafe {
        RegSetValueExW(
            hkey,
            PCWSTR(wide_name.as_ptr()),
            None,
            REG_DWORD,
            Some(&bytes),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(format!("RegSetValueExW({name}) failed: {:?}", status));
    }
    Ok(())
}

fn set_reg_qword(hkey: HKEY, name: &str, value: u64) -> Result<(), String> {
    let wide_name = string_util::to_wide(name);
    let bytes = value.to_le_bytes();
    // SAFETY: `hkey` is a valid open key, writing 8 bytes of QWORD data.
    let status = unsafe {
        RegSetValueExW(
            hkey,
            PCWSTR(wide_name.as_ptr()),
            None,
            REG_QWORD,
            Some(&bytes),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(format!("RegSetValueExW({name}) failed: {:?}", status));
    }
    Ok(())
}

/// Get the current time as a FILETIME u64 value.
/// Uses `std::time::SystemTime` to avoid needing `Win32_System_SystemInformation` feature.
fn get_current_filetime() -> u64 {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    // FILETIME epoch is 1601-01-01; UNIX epoch is 1970-01-01.
    // Difference: 11644473600 seconds.
    const FILETIME_UNIX_DIFF: u64 = 11_644_473_600;
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let secs = duration.as_secs() + FILETIME_UNIX_DIFF;
    let nanos_100 = (duration.subsec_nanos() as u64) / 100;
    secs * 10_000_000 + nanos_100
}

// --- Ctrl+C / console close cleanup handler ---

use std::sync::{Mutex, OnceLock};

/// State captured so the console-ctrl handler can run cleanup on Ctrl+C or
/// console close without any context pointer (Win32 handler is a bare fn).
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
        if let Some(state) = active {
            // Best-effort cleanup with a minimal logger (buffer mode; output
            // may not be visible since we're in a signal-like context).
            let mut logger = crate::logger::Logger::new(crate::logger::Mode::Buffer);
            if !state.proxy_enabled {
                cleanup_sandbox(&state.identity, &state.sid_string, &mut logger);
            } else {
                mark_cleanup_deferred(&state.sid_string, "network proxy configured", &mut logger);
            }
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
