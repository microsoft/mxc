//! Authenticode checks used before loading the Required-telemetry component.

use std::ffi::c_void;
use std::fs::File;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{HANDLE, HWND};
use windows::Win32::Security::Cryptography::{CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE};
use windows::Win32::Security::WinTrust::{
    WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData,
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};

/// Returns the signer's display name when `file` has an embedded Authenticode
/// signature that chains to a trusted root, otherwise `None`.
///
/// The check runs on the open handle so the verified bytes are the bytes the
/// caller holds. Revocation is not checked, keeping the check offline.
pub(super) fn trusted_signer(file: &File, path: &Path) -> Option<String> {
    let wide: Vec<u16> = path
        .as_os_str()
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide.as_ptr()),
        hFile: HANDLE(file.as_raw_handle()),
        ..Default::default()
    };
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: `data`, `file_info` and `wide` outlive both calls; the state
    // opened by VERIFY is released by the matching CLOSE below.
    let status = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            &mut data as *mut WINTRUST_DATA as *mut c_void,
        )
    };
    let name = if status == 0 {
        // SAFETY: the state handle is valid until CLOSE.
        unsafe { leaf_subject(data.hWVTStateData) }
    } else {
        None
    };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: closes the state opened above.
    unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            &mut data as *mut WINTRUST_DATA as *mut c_void,
        )
    };
    name
}

/// # Safety
/// `state` must be the state handle of a successful `WinVerifyTrust` call.
unsafe fn leaf_subject(state: HANDLE) -> Option<String> {
    let provider = WTHelperProvDataFromStateData(state);
    if provider.is_null() {
        return None;
    }
    let signer = WTHelperGetProvSignerFromChain(provider, 0, false, 0);
    if signer.is_null() {
        return None;
    }
    let cert = WTHelperGetProvCertFromChain(signer, 0);
    if cert.is_null() || (*cert).pCert.is_null() {
        return None;
    }
    let mut buffer = [0u16; 512];
    let len = CertGetNameStringW(
        (*cert).pCert,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        None,
        Some(&mut buffer),
    ) as usize;
    // The returned length includes the terminating NUL; 1 means no name.
    if len <= 1 || len > buffer.len() {
        return None;
    }
    String::from_utf16(&buffer[..len - 1]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsigned_file_has_no_trusted_signer() {
        let path = std::env::current_exe().expect("test executable path");
        let file = File::open(&path).expect("open test executable");
        assert_eq!(trusted_signer(&file, &path), None);
    }
}
