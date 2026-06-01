// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! C-compatible struct and constant definitions for undocumented WinHTTP
//! connection policy APIs. These are not in the public Windows SDK headers
//! and are not exposed by the windows-rs crate.

use windows_core::PWSTR;

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum WinHttpConnectionPolicyTag {
    /// Safe tag for per-AppContainer proxy policy. Does not interfere with
    /// WCM's own policies.
    Wwwpt = 2,
}

#[repr(C)]
pub struct WinHttpConnectionPolicyEntry {
    pub pwsz_host: *const u16,
    pub pwsz_app_id: *const u16,
    pub cb_app_sid: u32,
    pub pb_app_sid: *const u8,
    pub n_connections: u32,
    pub ppwsz_connections: *const *const u16,
    pub dw_policy_entry_flags: u32,
}

#[repr(C)]
pub struct WinHttpConnectionPolicyEntryList {
    pub p_policy_entries: *mut WinHttpConnectionPolicyEntry,
    pub n_entries: u32,
}

pub const WINHTTP_CONNECTION_PROXY_INFO_CURRENT_VERSION: u32 = 1;
pub const WINHTTP_CONNECTION_PROXY_TYPE_HTTP: u32 = 0;

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum WinHttpConnectionProxyInfoSwitch {
    Config = 0,
}

#[repr(C)]
pub struct WinHttpConnectionProxyInfoConfig {
    pub pwsz_server: PWSTR,
    pub pwsz_username: PWSTR,
    pub pwsz_password: PWSTR,
    pub pwsz_exception: PWSTR,
    pub pwsz_extra_info: PWSTR,
    pub port: u16,
}

#[repr(C)]
pub struct WinHttpConnectionProxyInfo {
    pub version: u32,
    pub pwsz_friendly_name: PWSTR,
    pub flags: u32,
    pub switch: WinHttpConnectionProxyInfoSwitch,
    pub config: WinHttpConnectionProxyInfoConfig,
}

pub type FnWinHttpConnectionSetPolicyEntries = unsafe extern "system" fn(
    h_session: *mut core::ffi::c_void,
    tag: WinHttpConnectionPolicyTag,
    policy_list: *mut WinHttpConnectionPolicyEntryList,
) -> u32;

pub type FnWinHttpConnectionDeletePolicyEntries = unsafe extern "system" fn(
    h_session: *mut core::ffi::c_void,
    tag: WinHttpConnectionPolicyTag,
) -> u32;

pub type FnWinHttpConnectionSetProxyInfo = unsafe extern "system" fn(
    connection_name: *const u16,
    proxy_type: u32,
    proxy_info: *mut WinHttpConnectionProxyInfo,
) -> u32;

pub type FnWinHttpConnectionDeleteProxyInfo =
    unsafe extern "system" fn(connection_name: *const u16, proxy_type: u32) -> u32;
