// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Reads Required-telemetry routing metadata from the signed component DLL.
// 
// `MXC_TELEMETRY_COMPONENT_PATH` names the DLL. It is optional: without it the
// build is unrouted. When it is set, any failure (missing file, bad signature,
// wrong signer, missing export, malformed metadata) fails the build rather than
// silently producing an unrouted binary. Values are never printed.
// 
// The export `mxc_telemetry_metadata_v1` returns a NUL-terminated UTF-8 string:
// `1;<group>;<keyword>;<privacy tag>;<critical keyword>;<critical privacy tag>`
// where the numbers are `0x`-prefixed hex.


#[cfg(windows)]
const EXPECTED_SIGNER: &str = "Microsoft Corporation";

#[cfg(windows)]
mod imp {
    use std::ffi::{c_void, CStr};
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;

    use windows::core::{PCSTR, PCWSTR};
    use windows::Win32::Foundation::{FreeLibrary, HANDLE, HWND};
    use windows::Win32::Security::Cryptography::{
        CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE,
    };
    use windows::Win32::Security::WinTrust::{
        WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain,
        WTHelperProvDataFromStateData, WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2,
        WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_NONE,
        WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };
    use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

    use super::{parse_component_metadata, ComponentMetadata, EXPECTED_SIGNER};

    /// Returns the signer's display name when `file` has an Authenticode
    /// signature that chains to a trusted root. Revocation is not checked so
    /// the build stays offline.
    fn trusted_signer(file: &std::fs::File, path: &Path) -> Option<String> {
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
        if len <= 1 || len > buffer.len() {
            return None;
        }
        String::from_utf16(&buffer[..len - 1]).ok()
    }

    pub(super) fn read(path: &Path) -> Result<ComponentMetadata, String> {
        // Verify and load the same absolute path; a bare file name would let
        // LoadLibrary search other directories and load an unverified DLL.
        let path = std::fs::canonicalize(path)
            .map_err(|e| format!("cannot resolve component path: {e}"))?;
        let path = path.as_path();
        // Deny writers while the signature is checked and the DLL is loaded,
        // so the verified bytes are the loaded bytes.
        let file = OpenOptions::new()
            .read(true)
            .share_mode(1) // FILE_SHARE_READ
            .open(path)
            .map_err(|e| format!("cannot open component: {e}"))?;
        match trusted_signer(&file, path) {
            Some(signer) if signer == EXPECTED_SIGNER => {}
            Some(_) => return Err("component is signed by an unexpected publisher".into()),
            None => return Err("component has no valid Authenticode signature".into()),
        }

        let wide: Vec<u16> = path
            .as_os_str()
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: the signed DLL is held write-locked; `wide` is NUL-terminated.
        let module = unsafe { LoadLibraryW(PCWSTR(wide.as_ptr())) }
            .map_err(|e| format!("cannot load component (host architecture must match): {e}"))?;
        // SAFETY: `module` is valid until FreeLibrary below.
        let export = unsafe { GetProcAddress(module, PCSTR(c"mxc_telemetry_metadata_v1".as_ptr().cast())) };
        let result = match export {
            None => Err("component does not export mxc_telemetry_metadata_v1".to_string()),
            Some(export) => {
                // SAFETY: the export has the documented signature.
                let export: unsafe extern "C" fn() -> *const std::ffi::c_char =
                    unsafe { std::mem::transmute(export) };
                let ptr = unsafe { export() };
                if ptr.is_null() {
                    Err("component returned no metadata".to_string())
                } else {
                    // SAFETY: the export returns a NUL-terminated static string.
                    let text = unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned();
                    parse_component_metadata(&text)
                }
            }
        };
        // SAFETY: `module` was returned by LoadLibraryW and is not used again.
        let _ = unsafe { FreeLibrary(module) };
        drop(file);
        result
    }
}

/// Reads the metadata from the DLL at `path`. Only Windows hosts can load it.
fn read_component_metadata(path: &std::path::Path) -> ComponentMetadata {
    #[cfg(windows)]
    {
        match imp::read(path) {
            Ok(metadata) => metadata,
            Err(reason) => panic!(
                "MXC_TELEMETRY_COMPONENT_PATH could not be used: {reason}. \
                 Set it to an empty value to build without Required telemetry routing."
            ),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        panic!("MXC_TELEMETRY_COMPONENT_PATH is only supported on Windows build hosts");
    }
}
