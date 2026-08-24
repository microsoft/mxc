// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows-only process launch helpers for proxy identity integration tests.

use std::ffi::c_void;
use std::path::Path;
use std::ptr;

use windows::core::{HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, ERROR_ALREADY_EXISTS, HLOCAL};
use windows::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows::Win32::Security::{FreeSid, PSID, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_LOCAL_SERVER, COINIT_APARTMENTTHREADED,
};
use windows::Win32::System::SystemServices::SE_GROUP_ENABLED;
use windows::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
    UpdateProcThreadAttribute, CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT,
    EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTUPINFOEXW, STARTUPINFOW,
};
use windows::Win32::UI::Shell::{
    ApplicationActivationManager, IApplicationActivationManager, ACTIVATEOPTIONS,
};

const RPC_E_CHANGED_MODE: u32 = 0x8001_0106;
const INTERNET_CLIENT_SID: &str = "S-1-15-3-1";
const PRIVATE_NETWORK_CLIENT_SERVER_SID: &str = "S-1-15-3-3";

struct ComApartment {
    owns_init: bool,
}

impl ComApartment {
    fn enter() -> Result<Self, String> {
        // SAFETY: The matching CoUninitialize runs on this thread when this call
        // acquires an initialization reference.
        let result = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
        if result.is_ok() {
            Ok(Self { owns_init: true })
        } else if result.0 as u32 == RPC_E_CHANGED_MODE {
            Ok(Self { owns_init: false })
        } else {
            Err(format!("CoInitializeEx failed: 0x{:08X}", result.0 as u32))
        }
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        if self.owns_init {
            // SAFETY: Balances the successful CoInitializeEx on this thread.
            unsafe { CoUninitialize() };
        }
    }
}

struct ProfileSid(PSID);

impl Drop for ProfileSid {
    fn drop(&mut self) {
        if !self.0 .0.is_null() {
            // SAFETY: AppContainer profile APIs return SIDs owned by the caller.
            unsafe {
                let _ = FreeSid(self.0);
            }
        }
    }
}

struct LocalSid(PSID);

impl Drop for LocalSid {
    fn drop(&mut self) {
        if !self.0 .0.is_null() {
            // SAFETY: ConvertStringSidToSidW allocates its result with LocalAlloc.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0 .0)));
            }
        }
    }
}

struct AttributeList(LPPROC_THREAD_ATTRIBUTE_LIST);

impl Drop for AttributeList {
    fn drop(&mut self) {
        // SAFETY: The list was initialized successfully and remains valid here.
        unsafe { DeleteProcThreadAttributeList(self.0) };
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn local_sid(value: &str) -> Result<LocalSid, String> {
    let value_wide = wide(value);
    let mut sid = PSID(ptr::null_mut());
    // SAFETY: value_wide is null-terminated and sid is a valid output pointer.
    unsafe {
        ConvertStringSidToSidW(PCWSTR(value_wide.as_ptr()), &mut sid)
            .map_err(|error| format!("ConvertStringSidToSidW({value}) failed: {error}"))?;
    }
    Ok(LocalSid(sid))
}

fn create_profile(
    profile: &str,
    capabilities: &[SID_AND_ATTRIBUTES],
) -> Result<ProfileSid, String> {
    let profile_wide = wide(profile);
    let display_wide = wide("MXC unpackaged AppContainer test proxy");
    let description_wide = wide("Profile for MXC proxy identity integration tests");

    let sid = match unsafe {
        CreateAppContainerProfile(
            PCWSTR(profile_wide.as_ptr()),
            PCWSTR(display_wide.as_ptr()),
            PCWSTR(description_wide.as_ptr()),
            Some(capabilities),
        )
    } {
        Ok(sid) => sid,
        Err(error) if error.code() == ERROR_ALREADY_EXISTS.to_hresult() => unsafe {
            DeriveAppContainerSidFromAppContainerName(PCWSTR(profile_wide.as_ptr())).map_err(
                |derive_error| {
                    format!(
                        "DeriveAppContainerSidFromAppContainerName({profile}) failed: \
                         {derive_error}"
                    )
                },
            )?
        },
        Err(error) => {
            return Err(format!(
                "CreateAppContainerProfile({profile}) failed: {error}"
            ));
        }
    };

    Ok(ProfileSid(sid))
}

pub fn activate_package(app_user_model_id: &str, port: u16) -> Result<u32, String> {
    let _apartment = ComApartment::enter()?;
    let app_user_model_id = wide(app_user_model_id);
    let arguments = wide(&format!("--port {port} --standalone"));

    // SAFETY: COM is initialized and both strings remain alive for the
    // synchronous activation call.
    let manager: IApplicationActivationManager = unsafe {
        CoCreateInstance(&ApplicationActivationManager, None, CLSCTX_LOCAL_SERVER).map_err(
            |error| format!("CoCreateInstance(ApplicationActivationManager) failed: {error}"),
        )?
    };
    let process_id = unsafe {
        manager
            .ActivateApplication(
                PCWSTR(app_user_model_id.as_ptr()),
                PCWSTR(arguments.as_ptr()),
                ACTIVATEOPTIONS::default(),
            )
            .map_err(|error| format!("ActivateApplication failed: {error}"))
    }?;
    if process_id == 0 {
        return Err("ActivateApplication returned process ID 0".to_string());
    }
    Ok(process_id)
}

pub fn derive_appcontainer_sid(profile: &str) -> Result<String, String> {
    let profile_wide = wide(profile);
    // SAFETY: profile_wide is null-terminated and remains alive for the call.
    let sid = unsafe {
        DeriveAppContainerSidFromAppContainerName(PCWSTR(profile_wide.as_ptr())).map_err(
            |error| format!("DeriveAppContainerSidFromAppContainerName({profile}) failed: {error}"),
        )?
    };
    let sid = ProfileSid(sid);
    let mut string_sid = PWSTR::null();

    // SAFETY: sid is valid and string_sid is a valid output pointer.
    unsafe {
        ConvertSidToStringSidW(sid.0, &mut string_sid)
            .map_err(|error| format!("ConvertSidToStringSidW failed: {error}"))?;
    }
    if string_sid.is_null() {
        return Err("ConvertSidToStringSidW returned a null string".to_string());
    }

    // SAFETY: ConvertSidToStringSidW returned a null-terminated LocalAlloc string.
    let result = unsafe { string_sid.to_string() }
        .map_err(|error| format!("Converting the AppContainer SID to UTF-8 failed: {error}"));
    unsafe {
        let _ = LocalFree(Some(HLOCAL(string_sid.0.cast())));
    }
    result
}

pub fn launch_appcontainer(profile: &str, port: u16) -> Result<u32, String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("Could not resolve the proxy executable: {error}"))?;
    let executable_string = executable.to_string_lossy();
    let mut command_line = wide(&format!(
        "\"{executable_string}\" --port {port} --standalone"
    ));
    let executable_wide = wide(&executable_string);
    let working_directory = executable
        .parent()
        .ok_or_else(|| "The proxy executable has no parent directory".to_string())?;
    let working_directory_wide = wide_path(working_directory);

    let internet_client = local_sid(INTERNET_CLIENT_SID)?;
    let private_network = local_sid(PRIVATE_NETWORK_CLIENT_SERVER_SID)?;
    let mut capability_sids = [
        SID_AND_ATTRIBUTES {
            Sid: internet_client.0,
            Attributes: SE_GROUP_ENABLED as u32,
        },
        SID_AND_ATTRIBUTES {
            Sid: private_network.0,
            Attributes: SE_GROUP_ENABLED as u32,
        },
    ];
    let profile_sid = create_profile(profile, &capability_sids)?;
    let security_capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: profile_sid.0,
        Capabilities: capability_sids.as_mut_ptr(),
        CapabilityCount: capability_sids.len() as u32,
        Reserved: 0,
    };

    let mut attribute_list_size = 0;
    // SAFETY: The first call intentionally queries the required buffer size.
    unsafe {
        let _ = InitializeProcThreadAttributeList(None, 1, None, &mut attribute_list_size);
    }
    if attribute_list_size == 0 {
        return Err("InitializeProcThreadAttributeList returned a zero buffer size".to_string());
    }

    let mut attribute_buffer = vec![0u8; attribute_list_size];
    let attribute_list =
        LPPROC_THREAD_ATTRIBUTE_LIST(attribute_buffer.as_mut_ptr().cast::<c_void>());
    // SAFETY: attribute_buffer is writable and remains alive through CreateProcessW.
    unsafe {
        InitializeProcThreadAttributeList(Some(attribute_list), 1, None, &mut attribute_list_size)
            .map_err(|error| format!("InitializeProcThreadAttributeList failed: {error}"))?;
    }
    let _attribute_list = AttributeList(attribute_list);

    // SAFETY: security_capabilities and all referenced SIDs remain alive through
    // the CreateProcessW call.
    unsafe {
        UpdateProcThreadAttribute(
            attribute_list,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            Some(&security_capabilities as *const SECURITY_CAPABILITIES as *const c_void),
            std::mem::size_of::<SECURITY_CAPABILITIES>(),
            None,
            None,
        )
        .map_err(|error| {
            format!("UpdateProcThreadAttribute(SECURITY_CAPABILITIES) failed: {error}")
        })?;
    }

    let startup = STARTUPINFOEXW {
        StartupInfo: STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOEXW>() as u32,
            ..Default::default()
        },
        lpAttributeList: attribute_list,
    };
    let mut process_information = PROCESS_INFORMATION::default();

    // SAFETY: All pointers reference live, null-terminated buffers. The process
    // and thread handles returned on success are closed before returning.
    unsafe {
        CreateProcessW(
            PCWSTR(executable_wide.as_ptr()),
            Some(PWSTR(command_line.as_mut_ptr())),
            None,
            None,
            false,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            None,
            PCWSTR(working_directory_wide.as_ptr()),
            &startup.StartupInfo,
            &mut process_information,
        )
        .map_err(|error| format!("CreateProcessW(AppContainer proxy) failed: {error}"))?;

        let _ = CloseHandle(process_information.hThread);
        let _ = CloseHandle(process_information.hProcess);
    }

    Ok(process_information.dwProcessId)
}

pub fn delete_appcontainer_profile(profile: &str) -> Result<(), String> {
    let profile = HSTRING::from(profile);
    // SAFETY: profile is a valid Windows string for the duration of the call.
    unsafe { DeleteAppContainerProfile(&profile) }
        .map_err(|error| format!("DeleteAppContainerProfile failed: {error}"))
}

fn wide_path(path: &Path) -> Vec<u16> {
    wide(&path.to_string_lossy())
}
