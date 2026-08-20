// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::io::IsTerminal;
use std::ptr;
use std::sync::Arc;

use windows::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, SetHandleInformation, ERROR_ACCESS_DISABLED_BY_POLICY,
    ERROR_ALREADY_EXISTS, HANDLE, HANDLE_FLAG_INHERIT, HLOCAL, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows::Win32::Security::{DeriveCapabilitySidsFromName, FreeSid, PSID, TOKEN_QUERY};
use windows::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows::Win32::System::SystemServices::SE_GROUP_ENABLED;
use windows::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetCurrentProcess, GetExitCodeProcess,
    InitializeProcThreadAttributeList, OpenProcessToken, ResumeThread, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED,
    CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROCESS_CREATION_FLAGS, PROCESS_INFORMATION,
    PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW,
};
use windows_core::{PCWSTR, PWSTR};

use crate::capture_output;
use crate::guarded_capture::{
    finalize_guarded_capture, validate_retain_etl_supported, GuardedCaptureFactory,
    GuardedCaptureSession, GuardedStop,
};
use crate::job_object::UiJobObject;
use crate::launch_diagnostics::diagnose_create_process_failure;
use crate::process_mitigation;
use wxc_common::error::WxcError;
use wxc_common::logger::Logger;
use wxc_common::models::{
    ExecutionRequest, FailurePhase, NetworkEnforcementMode, NetworkPolicy, SandboxOutputMetadata,
    ScriptResponse,
};
use wxc_common::process_util::{
    create_std_pipes, InterruptiblePipeReader, OwnedHandle, PipeReadCanceller, PipeWriter,
    SendOwnedHandle, SidAndAttributes,
};
use wxc_common::sandbox_process::{
    boxed_closer, cancel_and_join_discard, spawn_discard, take_boxed_read, take_boxed_write,
    SandboxBackend, SandboxProcess, StdioMode, StreamCloser,
};
use wxc_common::script_runner::get_timeout_milliseconds;
use wxc_common::validator::{validate_network_policy_support, NetworkPolicySupport};
use wxc_common::{string_util, ui_policy};

pub(crate) const CAPTURE_DENIALS_FALLBACK_UNSUPPORTED_MSG: &str =
    "captureDenials requires either the native BaseContainer learning-mode APIs or an \
     AppContainer runner explicitly configured with the guarded-WPR capture fallback \
     (see AppContainerScriptRunner::with_guarded_capture_factory)";

/// `UpdateProcThreadAttribute` value for
/// `PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY` that opts the
/// process out of inheriting `ALL APPLICATION PACKAGES` grants. This
/// specific *value* (not the attribute id) is not currently exported
/// by the windows crate.
const PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT: u32 = 1;

/// Proxy-related env var names to strip/override when building the child env block.
const PROXY_VAR_NAMES: &[&str] = &["HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY"];

fn create_process_failure(
    err: &windows_core::Error,
    command_line: &str,
    readonly_paths: &[String],
    working_directory: &str,
) -> WxcError {
    let message = if err.code() == ERROR_ACCESS_DISABLED_BY_POLICY.to_hresult() {
        diagnose_create_process_failure(
            ERROR_ACCESS_DISABLED_BY_POLICY.0,
            command_line,
            readonly_paths,
        )
        .message
    } else {
        format!("CreateProcessW failed: {err}")
    };

    WxcError::Process(format!(
        "{message} (working directory: {working_directory})"
    ))
}

/// Serialize `KEY=VALUE` pairs into a double-null-terminated UTF-16 environment block.
///
/// Entries are sorted case-insensitively by key as required by `CreateProcessW`.
pub(crate) fn encode_env_block(entries: &[(String, String)]) -> Vec<u16> {
    let mut sorted: Vec<&(String, String)> = entries.iter().collect();
    sorted.sort_by(|(a, _), (b, _)| a.to_ascii_uppercase().cmp(&b.to_ascii_uppercase()));

    let mut block = Vec::new();
    for (key, value) in sorted {
        for ch in format!("{}={}", key, value).encode_utf16() {
            block.push(ch);
        }
        block.push(0);
    }
    block.push(0);
    block
}

/// Create a default environment block for the current user without inheriting
/// the parent process's environment variables.
///
/// Calls `CreateEnvironmentBlock` with `bInherit = FALSE` so that only the
/// system/user profile variables are included (no process-level vars leak in).
/// Returns the entries as `(key, value)` pairs.
pub(crate) fn create_default_env_entries() -> Result<Vec<(String, String)>, WxcError> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .map_err(|e| WxcError::Process(format!("OpenProcessToken failed: {e}")))?;

        let mut block_ptr: *mut core::ffi::c_void = ptr::null_mut();
        // bInherit = FALSE: do not inherit the calling process's environment.
        let result = CreateEnvironmentBlock(&mut block_ptr, Some(token), false);
        // Close the token handle regardless of success.
        let _ = CloseHandle(token);
        result.map_err(|e| WxcError::Process(format!("CreateEnvironmentBlock failed: {e}")))?;

        let entries = parse_environment_block(block_ptr as *const u16);
        let _ = DestroyEnvironmentBlock(block_ptr);
        Ok(entries)
    }
}

/// Parse a double-null-terminated UTF-16 environment block into `(key, value)` pairs.
fn parse_environment_block(block: *const u16) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    let mut offset = 0usize;
    loop {
        // SAFETY: the block is a valid double-null-terminated UTF-16 string from the OS.
        let ch = unsafe { *block.add(offset) };
        if ch == 0 {
            break; // double-null terminator
        }
        // Find end of this entry (single null terminator).
        let start = offset;
        while unsafe { *block.add(offset) } != 0 {
            offset += 1;
        }
        let slice = unsafe { std::slice::from_raw_parts(block.add(start), offset - start) };
        let entry = String::from_utf16_lossy(slice);
        offset += 1; // skip the null terminator

        // Split on the first '=' (env vars can have '=' in the value).
        // Entries that start with '=' are hidden per-drive current-directory vars
        // (e.g. "=C:=C:\Users\foo"). For those, the key includes the leading '='
        // and we split on the second '='.
        if let Some(stripped) = entry.strip_prefix('=') {
            // Key is everything up to and including the drive colon, e.g. "=C:"
            if let Some(eq_pos) = stripped.find('=') {
                let key = format!("={}", &stripped[..eq_pos]);
                let value = stripped[eq_pos + 1..].to_string();
                entries.push((key, value));
            }
        } else if let Some(eq_pos) = entry.find('=') {
            let key = entry[..eq_pos].to_string();
            let value = entry[eq_pos + 1..].to_string();
            entries.push((key, value));
        }
    }
    entries
}

/// Parse explicit `KEY=VALUE` strings into entry pairs, optionally injecting
/// proxy env vars (stripping any pre-existing proxy vars first).
fn build_explicit_entries(
    env_vars: &[String],
    proxy_address: Option<&wxc_common::models::ProxyAddress>,
) -> Vec<(String, String)> {
    let mut entries: Vec<(String, String)> = env_vars
        .iter()
        .filter_map(|entry| {
            entry
                .split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect();

    if let Some(addr) = proxy_address {
        inject_proxy_vars(&mut entries, addr);
    }

    entries
}

/// Strip any pre-existing proxy env vars from `entries`, then inject the
/// configured proxy as `HTTP_PROXY` / `HTTPS_PROXY`.
fn inject_proxy_vars(entries: &mut Vec<(String, String)>, addr: &wxc_common::models::ProxyAddress) {
    entries.retain(|(key, _)| {
        !PROXY_VAR_NAMES
            .iter()
            .any(|name| key.eq_ignore_ascii_case(name))
    });
    let proxy_url = addr.to_url();
    entries.push(("HTTP_PROXY".to_string(), proxy_url.clone()));
    entries.push(("HTTPS_PROXY".to_string(), proxy_url));
}

/// Owned capability SID derived from a capability name. Frees the underlying
/// `LocalAlloc`'d SID with `LocalFree` on drop, so callers don't have to track
/// and free the raw pointer themselves.
struct OwnedCapabilitySid {
    sid: PSID,
}

impl OwnedCapabilitySid {
    fn new(sid: PSID) -> Self {
        Self { sid }
    }

    /// Derive the capability SID for a given capability name. Capability SIDs
    /// are an AppContainer concept, so this helper lives in the AppContainer
    /// backend rather than the shared foundation crate.
    fn from_capability_name(name: &str) -> Result<Self, WxcError> {
        let wide_name = string_util::to_wide(name);
        let pcwstr = PCWSTR(wide_name.as_ptr());

        let mut capability_sids: *mut PSID = std::ptr::null_mut();
        let mut capability_sid_count: u32 = 0;
        let mut group_sids: *mut PSID = std::ptr::null_mut();
        let mut group_sid_count: u32 = 0;

        // SAFETY: the Windows API writes LocalAlloc-compatible SID arrays and
        // counts. We read only within those counts, free each returned pointer
        // or array once, and transfer one capability SID into OwnedCapabilitySid.
        unsafe {
            DeriveCapabilitySidsFromName(
                pcwstr,
                &mut group_sids,
                &mut group_sid_count,
                &mut capability_sids,
                &mut capability_sid_count,
            )
            .map_err(|e| {
                WxcError::Process(format!("DeriveCapabilitySidsFromName({name}) failed: {e}"))
            })?;

            // Free group SIDs
            for i in 0..group_sid_count {
                let sid = *group_sids.add(i as usize);
                let _ = LocalFree(Some(HLOCAL(sid.0)));
            }
            let _ = LocalFree(Some(HLOCAL(group_sids as *mut _)));

            if capability_sid_count == 0 {
                let _ = LocalFree(Some(HLOCAL(capability_sids as *mut _)));
                return Err(WxcError::Process(format!(
                    "No capability SID returned for {}",
                    name
                )));
            }

            // Take the first capability SID
            let result_sid = *capability_sids;

            // Free remaining capability SIDs (index 1+)
            for i in 1..capability_sid_count {
                let sid = *capability_sids.add(i as usize);
                let _ = LocalFree(Some(HLOCAL(sid.0)));
            }
            let _ = LocalFree(Some(HLOCAL(capability_sids as *mut _)));

            Ok(Self::new(result_sid))
        }
    }

    /// Borrow the raw `PSID` for building a `SID_AND_ATTRIBUTES` array. The
    /// pointer is valid only while `self` is alive — keep the owner around
    /// until the process-creation call has returned.
    fn as_psid(&self) -> PSID {
        self.sid
    }
}

impl Drop for OwnedCapabilitySid {
    fn drop(&mut self) {
        let ptr = self.sid.0;

        if !ptr.is_null() {
            // SAFETY: `OwnedCapabilitySid` owns this SID pointer and frees it
            // exactly once using the allocator required by the Windows API.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(ptr)));
            }
        }
    }
}

/// A `SECURITY_CAPABILITIES`-compatible struct for `UpdateProcThreadAttribute`.
#[repr(C)]
struct SecurityCapabilities {
    app_container_sid: PSID,
    capabilities: *mut SidAndAttributes,
    capability_count: u32,
    reserved: u32,
}

/// Compute the number of `PROC_THREAD_ATTRIBUTE_*` entries the attribute
/// list will hold for a given policy.
///
/// Always at least 1 (`SECURITY_CAPABILITIES`). LPAC adds one
/// (`ALL_APPLICATION_PACKAGES_POLICY`); UI-disable adds one
/// (`MITIGATION_POLICY` for Win32k disable).
fn compute_attr_count(least_privilege_mode: bool, ui_disable: bool, pipe_mode: bool) -> u32 {
    let mut n = 1; // SECURITY_CAPABILITIES always present
    if least_privilege_mode {
        n += 1;
    }
    if ui_disable {
        n += 1;
    }
    if pipe_mode {
        n += 1; // one attribute slot for HANDLE_LIST (the list itself can hold 1..N handles)
    }
    n
}

/// Derive the AppContainer SID for `profile_name` and return it as a string
/// in `S-1-15-...` form.
///
/// Used by the Phase 4 dispatcher to target deny / grant ACEs at the same
/// AppContainer principal the runner will execute under. Co-located with
/// [`AppContainerScriptRunner::create_app_container_sid`] so any future
/// name normalization is added to a single place — keeping the dispatcher's
/// ACE target and the runner's process principal from drifting.
///
/// `profile_name` corresponds to the AppContainer profile name the runner
/// would create (matching the `request.container_id` mapping in the
/// AppContainer / BaseContainer runners — empty becomes `"CLI"` at the
/// caller; this function rejects empty input outright).
///
/// # Errors
///
/// Returns [`WxcError::Initialization`] if `profile_name` is empty, the
/// derivation Win32 call fails, or the returned SID cannot be converted to
/// a string.
pub(crate) fn derive_sid_string(profile_name: &str) -> Result<String, WxcError> {
    if profile_name.is_empty() {
        return Err(WxcError::Initialization(
            "AppContainer profile name is empty; cannot derive SID".to_string(),
        ));
    }

    let wide_name = string_util::to_wide(profile_name);
    let pcwstr_name = PCWSTR(wide_name.as_ptr());

    // SAFETY: `wide_name` is a valid null-terminated UTF-16 string and lives
    // for the duration of the call.
    let sid: PSID =
        unsafe { DeriveAppContainerSidFromAppContainerName(pcwstr_name) }.map_err(|e| {
            WxcError::Initialization(format!(
                "DeriveAppContainerSidFromAppContainerName failed for '{profile_name}': {e}"
            ))
        })?;

    let mut string_sid = PWSTR::null();
    // SAFETY: `sid` is a valid SID returned by the call above.
    let convert_result = unsafe { ConvertSidToStringSidW(sid, &mut string_sid) };

    let result = match convert_result {
        Ok(()) => {
            // Defensive null-check: `ConvertSidToStringSidW` documents
            // that it always allocates a valid pointer on success, but
            // matching the rest of the codebase's posture on raw Win32
            // pointers is cheap. If we ever see a null here it's a
            // real Win32 bug — surface it as an error rather than UB.
            if string_sid.is_null() {
                Err(WxcError::Initialization(
                    "ConvertSidToStringSidW returned success but produced a null string SID"
                        .to_string(),
                ))
            } else {
                // SAFETY: ConvertSidToStringSidW writes a null-terminated
                // wide string to `string_sid` on success and we just
                // verified non-null.
                let s = unsafe { string_sid.to_string() }
                    .map_err(|e| WxcError::Initialization(format!("SID-to-string failed: {e}")));
                // SAFETY: `string_sid` was allocated by ConvertSidToStringSidW;
                // free it with LocalFree per the Win32 contract.
                unsafe {
                    let _ = LocalFree(Some(HLOCAL(string_sid.0 as *mut std::ffi::c_void)));
                }
                s
            }
        }
        Err(e) => Err(WxcError::Initialization(format!(
            "ConvertSidToStringSidW failed: {e}"
        ))),
    };

    // SAFETY: SIDs returned by DeriveAppContainerSidFromAppContainerName
    // must be released with FreeSid.
    unsafe {
        let _ = FreeSid(sid);
    }

    result
}

/// Selects how filesystem policy is enforced for an AppContainer run.
///
/// Used by the Phase 4 dispatcher to skip the in-runner BFS configure when
/// the caller (Tier 3) is enforcing filesystem policy via host DACLs
/// instead.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemMode {
    /// Configure the AppContainer's BFS policy via `bfscfg.exe` (default
    /// historical behavior).
    #[default]
    Bfs,
    /// Skip BFS setup; the caller has handled filesystem policy via host
    /// DACL augmentation (Tier 3 path).
    Dacl,
}

/// Config capability string that enables **learning mode**: the OS logs every
/// *failed* access check for the AppContainer, but the access is still
/// **denied** (deny-and-record). Containment is unchanged.
pub(crate) const CAP_LEARNING_MODE_LOGGING: &str = "learningModeLogging";

/// Config capability string that enables **permissive learning mode**: the OS
/// logs every access check and **allows** it (audit / allow-all). This relaxes
/// deny-by-default for the run, so it is security-sensitive; the runner emits a
/// security warning whenever it is present.
pub(crate) const CAP_PERMISSIVE_LEARNING_MODE: &str = "permissiveLearningMode";

const LEARNING_MODE_INFORMATION: &str =
    "learningModeLogging is ENABLED: failed access attempts are logged; accesses are still denied \
     (deny-and-record).";
const PERMISSIVE_LEARNING_MODE_WARNING: &str =
    "*** SECURITY WARNING *** permissiveLearningMode is ENABLED: every access check is logged AND \
     ALLOWED (audit mode); the container is not enforcing deny-by-default.";
const PERMISSIVE_OVERRIDES_LEARNING_WARNING: &str =
    "*** SECURITY WARNING *** permissiveLearningMode overrides learningModeLogging: every access \
     check is logged AND ALLOWED (audit mode); the container is not enforcing deny-by-default.";

/// A recognized Windows learning-mode capability.
///
/// The two learning-mode capabilities are semantically **distinct** and must
/// not be conflated: [`Learning`](Self::Learning) only records denials (accesses
/// stay denied), while [`Permissive`](Self::Permissive) additionally *allows*
/// the accesses it logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LearningModeCapability {
    /// `learningModeLogging` — log *failed* accesses; accesses remain **denied**
    /// (deny-and-record). Containment is unchanged.
    Learning,
    /// `permissiveLearningMode` — log every access check and **allow** it
    /// (audit / allow-all). Does not enforce deny-by-default.
    Permissive,
}

impl LearningModeCapability {
    /// Classify a policy capability string as a learning-mode capability, or
    /// `None` if it is an unrelated capability. Matching is case-insensitive
    /// because Windows derives the capability SID case-insensitively, so a
    /// mis-cased spelling still takes effect and must be classified the same.
    pub(crate) fn from_capability_name(name: &str) -> Option<Self> {
        if name.eq_ignore_ascii_case(CAP_LEARNING_MODE_LOGGING) {
            Some(Self::Learning)
        } else if name.eq_ignore_ascii_case(CAP_PERMISSIVE_LEARNING_MODE) {
            Some(Self::Permissive)
        } else {
            None
        }
    }
}

enum LearningModeDiagnostic {
    Information(&'static str),
    SecurityWarning(&'static str),
}

impl LearningModeDiagnostic {
    #[cfg(test)]
    fn message(&self) -> &'static str {
        match self {
            Self::Information(message) | Self::SecurityWarning(message) => message,
        }
    }
}

fn effective_learning_mode_diagnostic(capabilities: &[String]) -> Option<LearningModeDiagnostic> {
    let mut learning = false;
    let mut permissive = false;
    for capability in capabilities {
        match LearningModeCapability::from_capability_name(capability) {
            Some(LearningModeCapability::Learning) => learning = true,
            Some(LearningModeCapability::Permissive) => permissive = true,
            None => {}
        }
    }

    if permissive {
        Some(LearningModeDiagnostic::SecurityWarning(if learning {
            PERMISSIVE_OVERRIDES_LEARNING_WARNING
        } else {
            PERMISSIVE_LEARNING_MODE_WARNING
        }))
    } else if learning {
        Some(LearningModeDiagnostic::Information(
            LEARNING_MODE_INFORMATION,
        ))
    } else {
        None
    }
}

/// Return the diagnostic lines the caller should log for the learning-mode
/// capabilities requested by a policy.
///
/// `learningModeLogging` (deny-and-record) is safe and emits an informational
/// note. `permissiveLearningMode` logs *and allows* every access check (audit
/// mode); it relaxes deny-by-default, so it emits a security warning.
#[cfg(test)]
pub(crate) fn learning_mode_capability_diagnostics(capabilities: &[String]) -> Vec<String> {
    effective_learning_mode_diagnostic(capabilities)
        .map(|diagnostic| vec![diagnostic.message().to_string()])
        .unwrap_or_default()
}

pub(crate) fn log_learning_mode_capability_diagnostics(
    capabilities: &[String],
    logger: &mut Logger,
) {
    match effective_learning_mode_diagnostic(capabilities) {
        Some(LearningModeDiagnostic::SecurityWarning(message)) => logger.warning_line(message),
        Some(LearningModeDiagnostic::Information(message)) => logger.log_line(message),
        None => {}
    }
}

/// Script runner that executes commands inside a Windows AppContainer.
pub struct AppContainerScriptRunner {
    app_container_name: String,
    app_container_sid: PSID,
    proxy_address: Option<wxc_common::models::ProxyAddress>,
    filesystem_mode: FilesystemMode,
    denied_paths_enforced_externally: bool,
    /// Optional pre-derived SID string supplied by the dispatcher.
    ///
    /// When `Some`, the runner uses this value for the firewall
    /// principal-id and any other capability-string lookups instead of
    /// re-running `ConvertSidToStringSidW` on its owned `PSID`. The
    /// `PSID` itself is still derived by [`create_app_container_sid`]
    /// at run time because `windows-rs` does not expose a safe
    /// "string → PSID" conversion with the same ownership semantics as
    /// [`DeriveAppContainerSidFromAppContainerName`] / `FreeSid`; that
    /// duplicate Win32 call is documented and left as a follow-up.
    preset_sid_string: Option<String>,
    /// Opts this runner into the guarded-WPR `captureDenials` fallback.
    ///
    /// `None` (the default for every plain constructor) means the
    /// runner behaves exactly as it always has: `captureDenials` is
    /// rejected in [`SandboxBackend::validate`]. Only a caller that
    /// explicitly chains [`Self::with_guarded_capture_factory`] (the
    /// dispatcher, when it selects a legacy tier for a request that
    /// asked for `captureDenials`) opts a runner into accepting it — see
    /// the module-level fallback docs on [`crate::guarded_capture`].
    guarded_capture_factory: Option<Arc<dyn GuardedCaptureFactory>>,
}

impl AppContainerScriptRunner {
    pub fn new() -> Self {
        Self {
            app_container_name: String::new(),
            app_container_sid: PSID(ptr::null_mut()),
            proxy_address: None,
            filesystem_mode: FilesystemMode::Bfs,
            denied_paths_enforced_externally: false,
            preset_sid_string: None,
            guarded_capture_factory: None,
        }
    }

    /// Construct a runner with an explicit [`FilesystemMode`].
    ///
    /// Used by the Phase 4 dispatcher to disable in-runner BFS setup for
    /// the Tier 3 (DACL-augmented) path.
    pub fn with_filesystem_mode(mode: FilesystemMode) -> Self {
        Self {
            app_container_name: String::new(),
            app_container_sid: PSID(ptr::null_mut()),
            proxy_address: None,
            filesystem_mode: mode,
            denied_paths_enforced_externally: false,
            preset_sid_string: None,
            guarded_capture_factory: None,
        }
    }

    /// Construct a runner with an explicit [`FilesystemMode`] and a
    /// pre-derived SID string.
    ///
    /// Used by the Phase 4 dispatcher to avoid a second
    /// `ConvertSidToStringSidW` round-trip when the dispatcher has
    /// already derived the SID string for ACE targeting. The `PSID`
    /// itself is still derived inside [`create_app_container_sid`] at
    /// run time — see [`Self::preset_sid_string`].
    pub fn with_filesystem_mode_and_sid_string(mode: FilesystemMode, sid_string: String) -> Self {
        Self {
            app_container_name: String::new(),
            app_container_sid: PSID(ptr::null_mut()),
            proxy_address: None,
            filesystem_mode: mode,
            denied_paths_enforced_externally: false,
            preset_sid_string: Some(sid_string),
            guarded_capture_factory: None,
        }
    }

    /// Opts this runner into the guarded-WPR `captureDenials` legacy-tier
    /// fallback, using `factory` to start an elevated, process-scoped WPR
    /// capture for each run.
    ///
    /// Must be called explicitly by the caller that selects this runner for
    /// a `captureDenials` request (the dispatcher, when the native
    /// BaseContainer tier is unavailable) — an `AppContainerScriptRunner`
    /// constructed any other way keeps rejecting `captureDenials` in
    /// [`SandboxBackend::validate`]. See [`crate::guarded_capture`] for the
    /// full rationale: `appcontainer_common` never depends on `plm`
    /// directly, so `factory` is a trait object implemented by a higher
    /// layer (`mxc_engine`) that does.
    pub fn with_guarded_capture_factory(mut self, factory: Arc<dyn GuardedCaptureFactory>) -> Self {
        self.guarded_capture_factory = Some(factory);
        self
    }

    /// Marks `deniedPaths` as enforced by the dispatcher's per-run DACL guard.
    pub(crate) fn with_external_denied_paths(mut self) -> Self {
        self.denied_paths_enforced_externally = true;
        self
    }

    /// Create or derive an AppContainer SID for the given container name.
    ///
    /// Returns a [`PSID`] owned by the runner (released via [`FreeSid`] in
    /// cleanup). If you only need the string form of the SID (e.g. to
    /// target ACEs at the same principal), call
    /// [`derive_sid_string`] — it shares the underlying derivation so the
    /// two paths can't drift in name normalization.
    fn create_app_container_sid(name: &str) -> Result<PSID, WxcError> {
        let wide_name = string_util::to_wide(name);
        let pcwstr_name = PCWSTR(wide_name.as_ptr());

        let display = string_util::to_wide("Agent scripting container");
        let pcwstr_display = PCWSTR(display.as_ptr());

        let desc = string_util::to_wide("Profile for agentic script execution");
        let pcwstr_desc = PCWSTR(desc.as_ptr());

        let result =
            unsafe { CreateAppContainerProfile(pcwstr_name, pcwstr_display, pcwstr_desc, None) };

        match result {
            Ok(sid) => Ok(sid),
            Err(e) if e.code() == ERROR_ALREADY_EXISTS.to_hresult() => {
                // Profile already exists — derive the SID from the name.
                let sid = unsafe {
                    DeriveAppContainerSidFromAppContainerName(pcwstr_name).map_err(|e2| {
                        WxcError::Initialization(format!(
                            "DeriveAppContainerSidFromAppContainerName failed: {}",
                            e2
                        ))
                    })?
                };
                Ok(sid)
            }
            Err(e) => Err(WxcError::Initialization(format!(
                "CreateAppContainerProfile failed: {}",
                e
            ))),
        }
    }

    /// Set up the AppContainer and create the sandboxed child **suspended**,
    /// returning a [`SpawnedChild`] the caller resumes and then either waits on
    /// (run-to-completion) or wraps in a streaming handle. When `capture` is set
    /// the child's stdio is wired to pipes the caller drives (the streaming
    /// path); otherwise the child inherits the parent's std handles / console
    /// (the run-to-completion path).
    fn spawn_suspended(
        &self,
        request: &ExecutionRequest,
        logger: &mut Logger,
        capture: bool,
    ) -> Result<SpawnedChild, WxcError> {
        // --- Learning-mode capabilities ---
        // `learningModeLogging` (deny-and-record) and `permissiveLearningMode`
        // (allow-all audit) are distinct. Emit per-capability diagnostics for
        // whichever are present (informational for `learningModeLogging`, a
        // security warning for `permissiveLearningMode`). See
        // [`learning_mode_capability_diagnostics`].
        log_learning_mode_capability_diagnostics(&request.policy.capabilities, logger);

        // --- Build capability list ---
        let mut capabilities_to_add: Vec<String> = request.policy.capabilities.clone();
        capabilities_to_add.push("AgenticAppContainer".to_string());

        let use_capabilities_for_network = matches!(
            request.policy.network_enforcement_mode,
            NetworkEnforcementMode::Capabilities | NetworkEnforcementMode::Both
        );
        if use_capabilities_for_network
            && request.policy.default_network_policy == NetworkPolicy::Allow
            && !capabilities_to_add.iter().any(|c| c == "internetClient")
        {
            capabilities_to_add.push("internetClient".to_string());
        }
        if request
            .policy
            .network_ingress
            .as_ref()
            .is_some_and(|ingress| ingress.default == wxc_common::models::NetworkAction::Allow)
            && !capabilities_to_add
                .iter()
                .any(|c| c == "privateNetworkClientServer")
        {
            capabilities_to_add.push("privateNetworkClientServer".to_string());
        }

        // --- Derive SIDs for each capability ---
        // `owned_capability_sids` owns the derived SIDs (freed on drop); it
        // must outlive `sid_attrs` / `security_capabilities`, which borrow the
        // raw pointers for the process-creation call below.
        let mut owned_capability_sids: Vec<OwnedCapabilitySid> = Vec::new();
        let mut sid_attrs: Vec<SidAndAttributes> = Vec::new();

        for cap_name in &capabilities_to_add {
            match OwnedCapabilitySid::from_capability_name(cap_name) {
                Ok(sid) => {
                    sid_attrs.push(SidAndAttributes {
                        sid: sid.as_psid(),
                        attributes: SE_GROUP_ENABLED as u32,
                    });
                    owned_capability_sids.push(sid);
                }
                Err(e) => {
                    logger.log_line(&format!(
                        "Warning: could not get SID for capability '{}': {}",
                        cap_name, e
                    ));
                }
            }
        }

        // --- Setup SECURITY_CAPABILITIES ---
        let security_capabilities = SecurityCapabilities {
            app_container_sid: self.app_container_sid,
            capabilities: if sid_attrs.is_empty() {
                ptr::null_mut()
            } else {
                sid_attrs.as_mut_ptr()
            },
            capability_count: sid_attrs.len() as u32,
            reserved: 0,
        };

        // --- Determine STDIO mode ---
        // If wxc-exec's stdout or stderr is not a terminal (i.e., piped by the SDK),
        // we forward our own std handles to the child via STARTF_USESTDHANDLES so the
        // child's output streams directly to the SDK in real time. Otherwise we use
        // console sharing (the ConPTY path).
        //
        // In capture mode (`StdioMode::Pipes`) we always take the pipe
        // path — but instead of forwarding our own std handles we wire the
        // child to capture pipes that the streaming handle reads from.
        let pipe_mode =
            capture || !std::io::stdout().is_terminal() || !std::io::stderr().is_terminal();

        if pipe_mode {
            if capture {
                logger
                    .log_line("STDIO mode: capture (piping child output to the streaming handle)");
            } else {
                logger.log_line("STDIO mode: passthrough (forwarding parent handles to child)");
            }
        }

        // --- Allocate and initialize attribute list ---
        let attr_count = compute_attr_count(
            request.policy.least_privilege_mode,
            request.policy.ui.disable,
            pipe_mode,
        );

        // Lifetime spans the attribute list and CreateProcessW:
        // PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY stores a pointer into this u64.
        let mitigation_value: u64 = process_mitigation::win32k_disable_value();

        let mut attr_list_size: usize = 0;

        // First call to get the required buffer size.
        unsafe {
            let _ = InitializeProcThreadAttributeList(None, attr_count, None, &mut attr_list_size);
        }

        let mut attr_list_buf: Vec<u8> = vec![0u8; attr_list_size];
        let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_list_buf.as_mut_ptr() as *mut _);

        unsafe {
            InitializeProcThreadAttributeList(
                Some(attr_list),
                attr_count,
                None,
                &mut attr_list_size,
            )
            .map_err(|e| WxcError::Process(format!("InitializeProcThreadAttributeList: {}", e)))?;
        }

        // RAII guard to call DeleteProcThreadAttributeList on exit.
        struct AttrListGuard(LPPROC_THREAD_ATTRIBUTE_LIST);
        impl Drop for AttrListGuard {
            fn drop(&mut self) {
                unsafe {
                    DeleteProcThreadAttributeList(self.0);
                }
            }
        }
        let _attr_guard = AttrListGuard(attr_list);

        // --- Update attributes ---

        // 1. SECURITY_CAPABILITIES
        unsafe {
            UpdateProcThreadAttribute(
                attr_list,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                Some(
                    &security_capabilities as *const SecurityCapabilities
                        as *const core::ffi::c_void,
                ),
                std::mem::size_of::<SecurityCapabilities>(),
                None,
                None,
            )
            .map_err(|e| {
                WxcError::Process(format!(
                    "UpdateProcThreadAttribute(SECURITY_CAPABILITIES): {}",
                    e
                ))
            })?;
        }

        // 2. ALL_APPLICATION_PACKAGES_POLICY (LPAC mode)
        let lpac_value = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
        if request.policy.least_privilege_mode {
            unsafe {
                UpdateProcThreadAttribute(
                    attr_list,
                    0,
                    PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY as usize,
                    Some(&lpac_value as *const u32 as *const core::ffi::c_void),
                    std::mem::size_of::<u32>(),
                    None,
                    None,
                )
                .map_err(|e| {
                    WxcError::Process(format!("UpdateProcThreadAttribute(LPAC): {}", e))
                })?;
            }
        }

        // 3. MITIGATION_POLICY (Win32k syscall disable) -- applied by the kernel
        // before the child runs any user-mode code, so there is no race window.
        if request.policy.ui.disable {
            unsafe {
                UpdateProcThreadAttribute(
                    attr_list,
                    0,
                    PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY as usize,
                    Some(&mitigation_value as *const u64 as *const core::ffi::c_void),
                    std::mem::size_of::<u64>(),
                    None,
                    None,
                )
                .map_err(|e| {
                    WxcError::Process(format!(
                        "UpdateProcThreadAttribute(MITIGATION_POLICY): {}",
                        e
                    ))
                })?;
            }
            logger.log_line("Win32k mitigation applied to child process");
        }

        // --- Setup handle passthrough / capture (pipe mode only) ---
        // In passthrough mode we forward wxc-exec's own std handles to the
        // child so its output streams to the caller. In capture mode we wire
        // the child to fresh capture pipes that the streaming handle reads from
        // (the `mxc` library path). Handle list for
        // PROC_THREAD_ATTRIBUTE_HANDLE_LIST. Must outlive CreateProcessW.
        let mut handle_list: Vec<HANDLE> = Vec::new();

        let h_stdin;
        let h_stdout;
        let h_stderr;

        // Capture pipe read-ends (parent side): kept alive until after the
        // wait, then drained. Child-side ends (stdin read, stdout/stderr
        // write): kept alive until after CreateProcessW, then dropped so the
        // read-ends observe EOF when the child exits.
        let mut capture_reads: Option<(OwnedHandle, OwnedHandle)> = None;
        let mut capture_child_ends: Vec<OwnedHandle> = Vec::new();
        // Parent's stdin write-end; in capture mode it is handed to the caller
        // so they can write to the child.
        let mut captured_stdin_write: Option<OwnedHandle> = None;

        if pipe_mode {
            if capture {
                // create_std_pipes(false): read-end inheritable (child stdin),
                // write-end non-inheritable (kept for streaming, else dropped).
                let (stdin_read, stdin_write) = create_std_pipes(false)?;
                // create_std_pipes(true): read-end non-inheritable (parent
                // reads it), write-end inheritable (child writes to it).
                let (stdout_read, stdout_write) = create_std_pipes(true)?;
                let (stderr_read, stderr_write) = create_std_pipes(true)?;

                h_stdin = stdin_read.get();
                h_stdout = stdout_write.get();
                h_stderr = stderr_write.get();

                capture_child_ends.push(stdin_read);
                capture_child_ends.push(stdout_write);
                capture_child_ends.push(stderr_write);
                captured_stdin_write = Some(stdin_write);
                capture_reads = Some((stdout_read, stderr_read));
            } else {
                h_stdin = unsafe { GetStdHandle(STD_INPUT_HANDLE) }
                    .map_err(|e| WxcError::Process(format!("GetStdHandle(STDIN): {e}")))?;
                h_stdout = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) }
                    .map_err(|e| WxcError::Process(format!("GetStdHandle(STDOUT): {e}")))?;
                h_stderr = unsafe { GetStdHandle(STD_ERROR_HANDLE) }
                    .map_err(|e| WxcError::Process(format!("GetStdHandle(STDERR): {e}")))?;

                if h_stdin.is_invalid() || h_stdin == HANDLE::default() {
                    return Err(WxcError::Process(
                        "GetStdHandle(STDIN) returned null/invalid handle".to_string(),
                    ));
                }
                if h_stdout.is_invalid() || h_stdout == HANDLE::default() {
                    return Err(WxcError::Process(
                        "GetStdHandle(STDOUT) returned null/invalid handle".to_string(),
                    ));
                }
                if h_stderr.is_invalid() || h_stderr == HANDLE::default() {
                    return Err(WxcError::Process(
                        "GetStdHandle(STDERR) returned null/invalid handle".to_string(),
                    ));
                }

                // Ensure the handles are inheritable.
                unsafe {
                    SetHandleInformation(h_stdin, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT)
                        .map_err(|e| {
                            WxcError::Process(format!("SetHandleInformation(STDIN): {e}"))
                        })?;
                    SetHandleInformation(h_stdout, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT)
                        .map_err(|e| {
                            WxcError::Process(format!("SetHandleInformation(STDOUT): {e}"))
                        })?;
                    SetHandleInformation(h_stderr, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT)
                        .map_err(|e| {
                            WxcError::Process(format!("SetHandleInformation(STDERR): {e}"))
                        })?;
                }
            }

            handle_list.push(h_stdin);
            handle_list.push(h_stdout);
            handle_list.push(h_stderr);

            // 4. HANDLE_LIST -- restrict which handles the child inherits.
            unsafe {
                UpdateProcThreadAttribute(
                    attr_list,
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    Some(handle_list.as_ptr() as *const core::ffi::c_void),
                    handle_list.len() * std::mem::size_of::<HANDLE>(),
                    None,
                    None,
                )
                .map_err(|e| {
                    WxcError::Process(format!("UpdateProcThreadAttribute(HANDLE_LIST): {}", e))
                })?;
            }
        } else {
            h_stdin = HANDLE::default();
            h_stdout = HANDLE::default();
            h_stderr = HANDLE::default();
        }

        // --- Setup STARTUPINFOEXW ---
        let mut desktop_wide = string_util::to_wide("winsta0\\default");

        let si_ex = STARTUPINFOEXW {
            StartupInfo: STARTUPINFOW {
                cb: std::mem::size_of::<STARTUPINFOEXW>() as u32,
                lpDesktop: PWSTR(desktop_wide.as_mut_ptr()),
                dwFlags: if pipe_mode {
                    STARTF_USESTDHANDLES
                } else {
                    Default::default()
                },
                hStdInput: h_stdin,
                hStdOutput: h_stdout,
                hStdError: h_stderr,
                ..Default::default()
            },
            lpAttributeList: attr_list,
        };

        // --- Build command line ---
        let mut cmd_line_wide = string_util::to_wide(&request.script_code);

        // Resolved via the shared helper so both Windows launch paths agree and
        // neither can pass a NULL cwd (see `working_directory`).
        let working_directory = crate::working_directory::launch_working_directory(request);
        logger.log_line(&format!(
            "working directory: {}",
            working_directory.describe()
        ));
        let working_dir_wide = string_util::to_wide(&working_directory.path);
        let working_dir_pcwstr = PCWSTR(working_dir_wide.as_ptr());

        // Environment block for the sandboxed child.
        // SECURITY: Never pass NULL (which would inherit the parent process's
        // full environment). Always build an explicit block:
        //   1. If explicit env vars were provided, use only those (+ proxy injection).
        //   2. Otherwise, call CreateEnvironmentBlock(bInherit=FALSE) for a clean
        //      default user environment and merge proxy vars if needed.
        let env_block: Vec<u16> = if !request.env.is_empty() {
            let entries = build_explicit_entries(&request.env, self.proxy_address.as_ref());
            encode_env_block(&entries)
        } else {
            // Get clean default user env without inheriting process env vars.
            let mut entries = create_default_env_entries()?;
            if let Some(addr) = self.proxy_address.as_ref() {
                inject_proxy_vars(&mut entries, addr);
            }
            encode_env_block(&entries)
        };

        let env_ptr = env_block.as_ptr() as *const core::ffi::c_void;

        // Suppress the empty console window for console-subsystem children when
        // stdio is piped (no console is shared). In console-sharing mode (ConPTY)
        // the child inherits the parent's live console for interactive I/O, so
        // CREATE_NO_WINDOW must not be set there.
        let no_window_flag = if pipe_mode { CREATE_NO_WINDOW.0 } else { 0 };
        let creation_flags = PROCESS_CREATION_FLAGS(
            EXTENDED_STARTUPINFO_PRESENT.0
                | CREATE_SUSPENDED.0
                | CREATE_UNICODE_ENVIRONMENT.0
                | no_window_flag,
        );

        // --- Create process ---
        //
        // In console-sharing mode (pipe_mode == false):
        //   stdin:  node-pty -> ConPTY -> wxc-exec -> child (AppContainer)
        //   stdout: node-pty <- ConPTY <----------- child (shares parent's console)
        //   bInheritHandles = false, no STARTF_USESTDHANDLES.
        //
        // In pipe-passthrough mode (pipe_mode == true):
        //   The child receives wxc-exec's own stdin/stdout/stderr handles directly.
        //   Child output streams to the SDK in real time (no intermediate buffering).
        //   bInheritHandles = true, with PROC_THREAD_ATTRIBUTE_HANDLE_LIST restricting
        //   which handles the child can access.
        let mut pi = PROCESS_INFORMATION::default();

        unsafe {
            CreateProcessW(
                PCWSTR::null(),
                Some(PWSTR(cmd_line_wide.as_mut_ptr())),
                None,
                None,
                pipe_mode, // bInheritHandles: true only in pipe mode (restricted by HANDLE_LIST)
                creation_flags,
                Some(env_ptr),
                working_dir_pcwstr,
                &si_ex.StartupInfo as *const STARTUPINFOW,
                &mut pi,
            )
        }
        .map_err(|err| {
            create_process_failure(
                &err,
                &request.script_code,
                &request.policy.readonly_paths,
                &working_directory.describe(),
            )
        })?;

        logger.log_line(&format!(
            "Process created successfully (PID: {})",
            pi.dwProcessId
        ));

        // The child has inherited the pipe handles, so close the parent's
        // child-side ends now (otherwise the read-ends would never see EOF).
        capture_child_ends.clear();

        let process_handle = OwnedHandle::new(pi.hProcess);
        let thread_handle = OwnedHandle::new(pi.hThread);

        // CRITICAL: child was created with CREATE_SUSPENDED. We must either
        // successfully attach the Job Object, OR TerminateProcess. Anything
        // that returns an error in this block must terminate first.
        let job = match (|| -> Result<UiJobObject, WxcError> {
            let job = UiJobObject::new()?;
            let restrictions = ui_policy::resolve_ui_restrictions(
                &request.policy.ui,
                &request.policy.base_process_ui,
            );
            job.set_ui_limits(&restrictions)?;
            job.assign_process(process_handle.get())?;
            Ok(job)
        })() {
            Ok(job) => {
                logger.log_line("UI Job Object assigned to child process");
                job
            }
            Err(e) => {
                unsafe {
                    let _ = TerminateProcess(process_handle.get(), u32::MAX);
                }
                return Err(e);
            }
        };

        // --- Guarded WPR captureDenials session (legacy-tier fallback) ---
        //
        // Started only now — after the job has been created, UI-limited,
        // and the still-suspended child assigned to it — but before the
        // caller resumes the child (`SpawnedChild::resume`, called by
        // `SandboxBackend::spawn` right after this function returns). That
        // ordering means a guardian-start failure can terminate the
        // still-suspended child without ever leaving an active host-wide
        // WPR trace running.
        let (capture_session, capture_output_path, capture_etl_path): (
            Option<Box<dyn GuardedCaptureSession>>,
            Option<std::path::PathBuf>,
            Option<std::path::PathBuf>,
        ) = match (
            self.guarded_capture_factory.as_ref(),
            request.policy.capture_denials.as_ref(),
        ) {
            (Some(factory), Some(capture_config)) => {
                let retain_etl = capture_config.retain_etl && factory.allows_trace_transfer();
                let output_paths = match capture_output::unique_denials_output_paths(
                    capture_config.output_path.as_deref(),
                    retain_etl,
                ) {
                    Ok(paths) => paths,
                    Err(e) => {
                        job.terminate_and_wait(u32::MAX)
                            .map_err(|terminate_error| {
                                WxcError::Process(format!(
                                "captureDenials failed to resolve the denials output path: {e}; \
                                 additionally failed to terminate the suspended sandbox: \
                                 {terminate_error}"
                            ))
                            })?;
                        return Err(WxcError::Process(format!(
                            "captureDenials failed to resolve the denials output path: {e}"
                        )));
                    }
                };
                let output_path = output_paths.denials;
                match factory.start(std::process::id()) {
                    Ok(session) => {
                        let session = attach_guarded_capture_or_cleanup(
                            session,
                            job.handle_value(),
                            process_handle.get().0 as usize,
                            || {
                                job.terminate_and_wait(u32::MAX)
                                    .err()
                                    .map(|error| error.to_string())
                            },
                        )
                        .map_err(WxcError::Process)?;
                        logger.log_line(&format!(
                            "guarded WPR captureDenials session started (output: {})",
                            output_path.display()
                        ));
                        (Some(session), Some(output_path), output_paths.etl)
                    }
                    Err(e) => {
                        // No active trace exists yet -- terminate the
                        // still-suspended child now, before it is ever
                        // resumed, so nothing runs unobserved.
                        job.terminate_and_wait(u32::MAX)
                            .map_err(|terminate_error| {
                                WxcError::Process(format!(
                                    "captureDenials guarded WPR session failed to start: {e}; \
                                 additionally failed to terminate the suspended sandbox: \
                                 {terminate_error}"
                                ))
                            })?;
                        return Err(WxcError::Process(format!(
                            "captureDenials guarded WPR session failed to start: {e}"
                        )));
                    }
                }
            }
            _ => (None, None, None),
        };

        let (stdout_read, stderr_read) = match capture_reads {
            Some((out, err)) => (Some(out), Some(err)),
            None => (None, None),
        };

        // The child is still suspended; the caller resumes it (after starting
        // any drain threads, for the run-to-completion path).
        Ok(SpawnedChild {
            process: process_handle,
            thread: thread_handle,
            job,
            pid: pi.dwProcessId,
            capture_session,
            capture_output_path,
            capture_etl_path,
            stdin_write: captured_stdin_write,
            stdout_read,
            stderr_read,
            timeout_ms: get_timeout_milliseconds(request.script_timeout),
        })
    }

    /// Create the AppContainer SID for the given request.
    fn initialize(&mut self, request: &ExecutionRequest) -> Result<(), WxcError> {
        let container_name = if request.container_id.is_empty() {
            "CLI".to_string()
        } else {
            request.container_id.clone()
        };
        self.app_container_sid = Self::create_app_container_sid(&container_name)?;
        self.app_container_name = container_name;
        Ok(())
    }

    /// Return the SID string for firewall rule association.
    fn get_principal_id(&self) -> String {
        // Prefer the dispatcher-supplied string when present — saves a
        // `ConvertSidToStringSidW` round-trip (the dispatcher has
        // already converted the underlying SID once for ACE targeting).
        if let Some(s) = &self.preset_sid_string {
            return s.clone();
        }
        if self.app_container_sid.0.is_null() {
            return "unknown-sid".to_string();
        }
        unsafe { string_util::sid_to_string(self.app_container_sid.0) }
            .unwrap_or_else(|| "unknown-sid".to_string())
    }
}

/// A sandboxed AppContainer child created **suspended** by
/// [`AppContainerScriptRunner::spawn_suspended`]. The caller resumes it and
/// then either runs it to completion (blocking) or wraps it in a streaming
/// handle. Owns the process/thread/job handles and the parent-side pipe ends.
struct SpawnedChild {
    process: OwnedHandle,
    thread: OwnedHandle,
    job: UiJobObject,
    /// OS process id of the child.
    pid: u32,
    /// Live guarded WPR capture session for `captureDenials`, started
    /// (while still suspended) by [`AppContainerScriptRunner::spawn_suspended`].
    /// `Some` only when the runner was configured via
    /// [`AppContainerScriptRunner::with_guarded_capture_factory`] and the
    /// request asked for `captureDenials`.
    capture_session: Option<Box<dyn GuardedCaptureSession>>,
    /// Resolved JSON denials deliverable path. `Some` iff `capture_session`
    /// is `Some`.
    capture_output_path: Option<std::path::PathBuf>,
    /// Caller-visible ETL destination when retention is requested.
    capture_etl_path: Option<std::path::PathBuf>,
    /// Parent's stdin write-end (Some only when spawned for streaming).
    stdin_write: Option<OwnedHandle>,
    /// Parent's stdout/stderr read-ends (Some only in streaming mode).
    stdout_read: Option<OwnedHandle>,
    stderr_read: Option<OwnedHandle>,
    timeout_ms: u32,
}

impl SpawnedChild {
    /// Resume the suspended child, terminating it on failure.
    ///
    /// If a guarded WPR capture was started for this child, a resume
    /// failure also discards it (see
    /// [`Self::discard_capture_session_after_launch_failure`]) before
    /// returning the resume error, so the elevated guardian is never left
    /// tracing a child that never ran.
    fn resume(&mut self) -> Result<(), WxcError> {
        let r = unsafe { ResumeThread(self.thread.get()) };
        if r == u32::MAX {
            let err = unsafe { GetLastError() };
            unsafe {
                let _ = TerminateProcess(self.process.get(), u32::MAX);
                let _ = WaitForSingleObject(self.process.get(), u32::MAX);
            }
            self.discard_capture_session_after_launch_failure();
            return Err(WxcError::Process(format!("ResumeThread failed: {:?}", err)));
        }
        Ok(())
    }

    /// Best-effort teardown of an armed-but-abandoned guarded WPR capture
    /// session, used when the sandboxed child failed to launch after the
    /// session was already started.
    ///
    /// The child never ran successfully, so there is no analysis result to
    /// preserve. Stop the trace through the authenticated discard protocol.
    fn discard_capture_session_after_launch_failure(&mut self) {
        let Some(mut session) = self.capture_session.take() else {
            return;
        };
        let _ = session.discard();
    }
}

/// Attach `session` to the sandbox job / root process, or perform the
/// security-sensitive abandonment cleanup on failure.
///
/// On attach failure the job is terminated (via `terminate_job`, which returns
/// `Some(message)` if termination failed) **before** the guarded session is
/// discarded — nothing may keep running once the trace is about to be torn
/// down — and the returned error reports the attach failure plus any
/// termination/discard failures, in that order. Returns the live session on
/// success. Extracted so the orchestration ordering can be unit-tested with a
/// fake session and a fake job terminator, without a real suspended process.
fn attach_guarded_capture_or_cleanup(
    mut session: Box<dyn GuardedCaptureSession>,
    job_handle: usize,
    root_process_handle: usize,
    terminate_job: impl FnOnce() -> Option<String>,
) -> Result<Box<dyn GuardedCaptureSession>, String> {
    let Err(attach_error) = session.attach_process_tree(job_handle, root_process_handle) else {
        return Ok(session);
    };
    let termination_error = terminate_job();
    let discard_error = session.discard().err();
    let mut message = format!(
        "captureDenials guarded WPR session failed to attach the sandbox process tree: \
         {attach_error}"
    );
    if let Some(terminate_error) = termination_error {
        message.push_str(&format!(
            "; additionally failed to terminate the suspended sandbox: {terminate_error}"
        ));
    }
    if let Some(discard_error) = discard_error {
        message.push_str(&format!(
            "; additionally failed to stop and discard guarded WPR: {discard_error}"
        ));
    }
    Err(message)
}

impl Default for AppContainerScriptRunner {
    fn default() -> Self {
        Self::new()
    }
}

/// Delete the AppContainer profile created via [`CreateAppContainerProfile`]
/// and clear any BFS policy registered against it.
///
/// This is the explicit cleanup entry point used by `wxc-exec --delete`,
/// kept next to the create/setup path on `AppContainerScriptRunner` so
/// both ends of the profile lifecycle live in the same module.
///
/// The BFS-clear step is best-effort: it delegates to
/// [`FileSystemBfsManager::clear_policy`], which resolves `bfscfg.exe`
/// itself and logs (rather than fails) when the resolver returns no
/// path. The profile delete is still attempted in that case.
pub fn delete_app_container_profile(name: &str, logger: &mut Logger) -> bool {
    crate::filesystem_bfs::FileSystemBfsManager::clear_policy(name, logger);

    let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let hstring = windows::core::HSTRING::from_wide(&wide_name[..wide_name.len() - 1]);
    match unsafe { DeleteAppContainerProfile(&hstring) } {
        Ok(()) => {
            logger.log_line(&format!("Deleted AppContainer profile: {}", name));
            true
        }
        Err(e) => {
            logger.log_line(&format!(
                "Failed to delete AppContainer profile '{}': {}",
                name, e
            ));
            false
        }
    }
}

impl Drop for AppContainerScriptRunner {
    fn drop(&mut self) {
        if !self.app_container_sid.0.is_null() {
            unsafe {
                // AppContainer SIDs from CreateAppContainerProfile /
                // DeriveAppContainerSidFromAppContainerName must be freed with FreeSid.
                windows::Win32::Security::FreeSid(self.app_container_sid);
            }
            self.app_container_sid = PSID(ptr::null_mut());
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Shared setup/teardown + streaming (handle-based) execution
// ───────────────────────────────────────────────────────────────────────────

/// Per-run resources (firewall + filesystem policy) whose lifetime is tied to
/// the sandboxed child. Created by [`AppContainerScriptRunner::prepare`] and
/// torn down by [`AppContainerScriptRunner::teardown`] after the child exits.
struct Prepared {
    network_manager: crate::network_manager::NetworkManager,
    bfs_manager: crate::filesystem_bfs::FileSystemBfsManager,
}

impl AppContainerScriptRunner {
    /// Set up the AppContainer for a run: initialise the SID, configure BFS
    /// filesystem policy, and start network enforcement. Shared by both stdio
    /// modes of [`SandboxBackend::spawn`].
    fn prepare(
        &mut self,
        request: &ExecutionRequest,
        logger: &mut Logger,
    ) -> Result<Prepared, ScriptResponse> {
        use crate::filesystem_bfs::FileSystemBfsManager;
        use crate::network_manager::NetworkManager;

        if request.experimental_enabled {
            if let Some(ref test) = request.experimental.test {
                logger.log_line(&format!(
                    "Experimental feature 'test' applied: {}",
                    test.message
                ));
            }
        }

        if let Err(e) = self.initialize(request) {
            return Err(ScriptResponse::error(&e.to_string()));
        }

        let principal_id = self.get_principal_id();
        logger.log_line(&format!("AppContainerSID: {principal_id}"));

        // Resolve `bfscfg.exe` by absolute path (defeats search-order
        // hijacking); only needed in BFS mode.
        let bfscfg_path = if self.filesystem_mode == FilesystemMode::Bfs {
            match crate::fallback_detector::find_bfscfg_exe() {
                Ok(p) => p,
                Err(e) => return Err(ScriptResponse::error(&e.to_string())),
            }
        } else {
            None
        };

        let mut bfs_manager =
            FileSystemBfsManager::new(self.app_container_name.clone(), bfscfg_path);
        if self.filesystem_mode == FilesystemMode::Bfs {
            if let Err(e) = bfs_manager.configure(&request.policy, logger) {
                let msg = if matches!(&e, WxcError::BfsNotAvailable) {
                    "Filesystem policy error: bfscfg.exe is not available on this Windows \
                     build, so the AppContainer + BFS filesystem tier cannot enforce your \
                     policy. Use an OS build that includes bfscfg.exe, or run on a host that \
                     supports the BaseContainer backend (which does not require bfscfg.exe)."
                        .to_string()
                } else {
                    e.to_string()
                };
                return Err(ScriptResponse::error(&msg));
            }
        }

        if request.policy.network_proxy.is_enabled() {
            logger.log_line(
                "warning: proxy support on Windows is best-effort -- only scripts that use \
                 the WinHTTP stack will be proxied; other HTTP stacks may bypass it. The \
                 AppContainer backend may also surface a UAC prompt.",
            );
        }

        let mut network_manager = NetworkManager::new();
        match network_manager.start(
            &principal_id,
            &self.app_container_name,
            &request.policy,
            self.app_container_sid,
            logger,
        ) {
            Ok(()) => {
                self.proxy_address = network_manager.proxy_address().cloned();
            }
            Err(err) => {
                return Err(ScriptResponse::error(&err.to_string()));
            }
        }

        Ok(Prepared {
            network_manager,
            bfs_manager,
        })
    }

    /// Tear down the per-run firewall and filesystem policy. Idempotent at the
    /// manager level; called once after the child exits.
    fn teardown(&self, prepared: &mut Prepared, preserve_policy: bool, logger: &mut Logger) {
        prepared.network_manager.stop_all(!preserve_policy, logger);
        if self.filesystem_mode == FilesystemMode::Bfs
            && prepared.bfs_manager.configured()
            && !preserve_policy
        {
            prepared.bfs_manager.remove_configuration(logger);
        }
    }
}

impl SandboxBackend for AppContainerScriptRunner {
    fn network_policy_support(&self) -> NetworkPolicySupport {
        NetworkPolicySupport::HOST_LOOPBACK | NetworkPolicySupport::RUNTIME_PROXY
    }

    fn validate(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        validate_network_policy_support(request, self.network_policy_support())?;
        if request.policy.allowed_proxy_peer.is_some() {
            return Err(ScriptResponse::error(
                "processContainer.network.allowedProxyPeer requires a BaseContainer path",
            ));
        }

        // AppContainer fallback tiers have no native capture path, so retainEtl
        // is honored only by a guarded-WPR provider that can transfer the ETL.
        validate_retain_etl_supported(
            request
                .policy
                .capture_denials
                .as_ref()
                .is_some_and(|config| config.retain_etl),
            self.guarded_capture_factory
                .as_ref()
                .is_some_and(|factory| factory.allows_trace_transfer()),
            false,
        )?;
        if request.policy.capture_denials.is_some() && self.guarded_capture_factory.is_none() {
            return Err(ScriptResponse {
                failure_phase: FailurePhase::BackendUnavailable,
                ..ScriptResponse::error(CAPTURE_DENIALS_FALLBACK_UNSUPPORTED_MSG)
            });
        }
        if !request.policy.denied_paths.is_empty()
            && self.filesystem_mode != FilesystemMode::Dacl
            && !self.denied_paths_enforced_externally
        {
            return Err(ScriptResponse::error(
                wxc_common::error::DENIED_PATHS_NOT_SUPPORTED_MSG,
            ));
        }
        if !request.policy.allowed_hosts.is_empty() || !request.policy.blocked_hosts.is_empty() {
            return Err(ScriptResponse::error(
                wxc_common::error::HOST_LISTS_NOT_SUPPORTED_MSG,
            ));
        }
        if request
            .policy
            .network_ingress
            .as_ref()
            .is_some_and(|ingress| {
                ingress.host_loopback == wxc_common::models::NetworkAction::Allow
            })
            && !request.policy.network_proxy.is_enabled()
        {
            return Err(ScriptResponse::error(
                "network.ingress.hostLoopback='allow' requires a BaseContainer path",
            ));
        }
        Ok(())
    }

    fn spawn(
        &mut self,
        request: &ExecutionRequest,
        logger: &mut Logger,
        stdio: StdioMode,
    ) -> Result<Box<dyn SandboxProcess>, ScriptResponse> {
        use wxc_common::validator::validate_common;

        validate_common(request)?;
        self.validate(request)?;

        let mut prepared = self.prepare(request, logger)?;

        // Pipes → capture pipes the caller drives; Inherit → the child inherits
        // the binary's own std handles / console (a TTY when the binary has one).
        let capture = stdio == StdioMode::Pipes;
        let mut child = match self.spawn_suspended(request, logger, capture) {
            Ok(c) => c,
            Err(e) => {
                self.teardown(&mut prepared, request.lifecycle.preserve_policy, logger);
                return Err(ScriptResponse::error(&e.to_string()));
            }
        };
        if let Err(e) = child.resume() {
            self.teardown(&mut prepared, request.lifecycle.preserve_policy, logger);
            return Err(ScriptResponse::error(&e.to_string()));
        }

        Ok(Box::new(AppContainerSandboxProcess::new(
            child,
            prepared,
            self.filesystem_mode,
            request,
        )))
    }

    fn diagnose_exit(&self, request: &ExecutionRequest, exit_code: i32) -> Option<String> {
        crate::launch_diagnostics::diagnose_process_exit(
            &request.script_code,
            &request.policy.readonly_paths,
            &request.policy.readwrite_paths,
            exit_code as u32,
        )
        .map(|diag| diag.message)
    }
}

/// A running AppContainer-sandboxed process exposed as a [`SandboxProcess`].
/// Owns the process/job handles, the parent-side pipes, and the per-run
/// firewall/filesystem policy, which it tears down once the child exits.
struct AppContainerSandboxProcess {
    process: SendOwnedHandle,
    _thread: SendOwnedHandle,
    job: crate::job_object::UiJobObject,
    pid: u32,
    stdin: Option<PipeWriter>,
    stdout: Option<InterruptiblePipeReader>,
    stderr: Option<InterruptiblePipeReader>,
    /// Cancellers for the stdout/stderr reads, kept so the `SandboxProcess`
    /// closers can mint a [`StreamCloser`] even after the stream is taken.
    stdout_canceller: Option<PipeReadCanceller>,
    stderr_canceller: Option<PipeReadCanceller>,
    prepared: Prepared,
    filesystem_mode: FilesystemMode,
    preserve_policy: bool,
    timeout_ms: u32,
    teardown_result: Option<Result<(), String>>,
    /// Live guarded WPR capture session, moved from the `SpawnedChild`.
    /// Stopped and analyzed in `run_teardown` once the child has exited and
    /// been reaped.
    capture_session: Option<Box<dyn GuardedCaptureSession>>,
    /// Resolved JSON denials deliverable path. `Some` iff `capture_session`
    /// is `Some`.
    capture_output_path: Option<std::path::PathBuf>,
    /// Caller-visible ETL destination when retention is requested.
    capture_etl_path: Option<std::path::PathBuf>,
    /// Exit code of the child, recorded by `wait` before teardown so the
    /// denials summary can carry it. `None` on the `Drop`/early-exit path.
    last_exit_code: Option<i32>,
    /// Structured output published after capture teardown succeeds.
    output_metadata: Option<SandboxOutputMetadata>,
}

// SAFETY: the fields are Windows HANDLEs / handle-owning managers and owned
// strings. HANDLEs are process-global and safe to use from any single thread,
// and this handle is owned exclusively by the caller (not shared), so it is
// only ever touched from one thread at a time.
//
// The one historically thread-affine field was the `NetworkManager` inside
// `prepared`: it used to cache an STA `INetFwPolicy2` interface plus its
// `CoInitializeEx` state and reuse them at teardown, which is unsound when
// `wait()`/`kill()`/`Drop` run on a different thread (e.g. a tokio
// `spawn_blocking` worker) than `spawn`. That no longer happens: each firewall
// apply/remove is apartment-self-contained (it opens its own COM apartment,
// creates a fresh interface, and uninitializes — all on whichever thread runs
// it), so no COM interface or apartment state is moved across threads. The only
// remaining OS state the manager keeps is the process-global Winsock refcount,
// which is thread-agnostic. Moving this handle across threads is therefore
// sound.
unsafe impl Send for AppContainerSandboxProcess {}

impl AppContainerSandboxProcess {
    fn new(
        mut child: SpawnedChild,
        prepared: Prepared,
        filesystem_mode: FilesystemMode,
        request: &ExecutionRequest,
    ) -> Self {
        let process = SendOwnedHandle::take(&mut child.process);
        let thread = SendOwnedHandle::take(&mut child.thread);
        let stdin = child.stdin_write.take().map(PipeWriter::new);
        let stdout = child.stdout_read.take().map(InterruptiblePipeReader::new);
        let stderr = child.stderr_read.take().map(InterruptiblePipeReader::new);
        let stdout_canceller = stdout.as_ref().map(InterruptiblePipeReader::canceller);
        let stderr_canceller = stderr.as_ref().map(InterruptiblePipeReader::canceller);
        Self {
            process,
            _thread: thread,
            job: child.job,
            pid: child.pid,
            stdin,
            stdout,
            stderr,
            stdout_canceller,
            stderr_canceller,
            prepared,
            filesystem_mode,
            preserve_policy: request.lifecycle.preserve_policy,
            timeout_ms: child.timeout_ms,
            teardown_result: None,
            capture_session: child.capture_session.take(),
            capture_output_path: child.capture_output_path.take(),
            capture_etl_path: child.capture_etl_path.take(),
            last_exit_code: None,
            output_metadata: None,
        }
    }

    fn run_teardown(&mut self, allow_trace_transfer: bool) -> std::io::Result<()> {
        if let Some(result) = &self.teardown_result {
            return result.clone().map_err(std::io::Error::other);
        }
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);
        self.prepared
            .network_manager
            .stop_all(!self.preserve_policy, &mut logger);
        if self.filesystem_mode == FilesystemMode::Bfs
            && self.prepared.bfs_manager.configured()
            && !self.preserve_policy
        {
            self.prepared.bfs_manager.remove_configuration(&mut logger);
        }

        // Stop and analyze the guarded WPR capture now that the child has
        // exited and been reaped (both `wait` and `Drop` kill + reap before
        // calling this). The shared finalizer owns every analysis-vs-retention
        // state transition (JSON write, metadata success/error, retention
        // failure surfacing) so this legacy tier and the BaseContainer guarded
        // tier cannot drift.
        let result: std::io::Result<()> = if let Some(mut session) = self.capture_session.take() {
            let output_path = self.capture_output_path.take();
            let etl_path = self
                .capture_etl_path
                .take()
                .filter(|_| allow_trace_transfer);
            let exit_code = self.last_exit_code.unwrap_or(-1);
            let stop = match etl_path.as_deref() {
                Some(destination) => GuardedStop::AnalyzeAndRetain { destination },
                None => GuardedStop::AnalyzeOnly,
            };
            let finalization =
                finalize_guarded_capture(session.as_mut(), output_path.as_deref(), stop, exit_code);
            self.output_metadata = finalization.metadata;
            finalization.result.map_err(std::io::Error::other)
        } else {
            Ok(())
        };
        let result = result.map_err(|error| error.to_string());
        self.teardown_result = Some(result.clone());
        result.map_err(std::io::Error::other)
    }

    fn release_guarded_capture_after_termination_failure(&mut self) {
        let Some(session) = self.capture_session.take() else {
            return;
        };
        // The trait contract keeps this call blocked until the elevated
        // guardian has released its duplicate job handle, even when discard
        // itself fails. Only then may Drop return and release enforcement.
        if let Err(error) = crate::guarded_capture::release_after_termination_failure(session) {
            capture_output::write_stderr_line_best_effort(format_args!(
                "failed to discard guarded WPR capture after sandbox termination failure: {error}"
            ));
        }
    }
}

impl SandboxProcess for AppContainerSandboxProcess {
    fn output_metadata(&self) -> Option<&SandboxOutputMetadata> {
        self.output_metadata.as_ref()
    }

    fn take_stdin(&mut self) -> Option<Box<dyn std::io::Write + Send>> {
        take_boxed_write(&mut self.stdin)
    }

    fn take_stdout(&mut self) -> Option<Box<dyn std::io::Read + Send>> {
        take_boxed_read(&mut self.stdout)
    }

    fn take_stderr(&mut self) -> Option<Box<dyn std::io::Read + Send>> {
        take_boxed_read(&mut self.stderr)
    }

    fn stdout_closer(&self) -> Option<Box<dyn StreamCloser>> {
        boxed_closer(&self.stdout_canceller)
    }

    fn stderr_closer(&self) -> Option<Box<dyn StreamCloser>> {
        boxed_closer(&self.stderr_canceller)
    }

    fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
        match unsafe { WaitForSingleObject(self.process.get(), 0) } {
            WAIT_OBJECT_0 => {
                let mut code: u32 = 0;
                if unsafe { GetExitCodeProcess(self.process.get(), &mut code) }.is_err() {
                    return Err(std::io::Error::other("GetExitCodeProcess failed"));
                }
                Ok(Some(code as i32))
            }
            WAIT_TIMEOUT => Ok(None),
            _ => Err(std::io::Error::other("WaitForSingleObject failed")),
        }
    }

    fn id(&self) -> u32 {
        self.pid
    }

    fn kill(&mut self) -> std::io::Result<()> {
        // Terminate the whole job: the child and every descendant assigned to
        // it die together (tree-kill).
        if self.capture_session.is_some() {
            // Guarded-WPR capture needs strict drain certainty before the trace
            // is stopped/discarded; a failure to drain is a hard error here.
            return self
                .job
                .terminate_and_wait(u32::MAX)
                .map_err(|error| std::io::Error::other(error.to_string()));
        }
        // Ordinary run: terminate the tree, but downgrade a slow drain to a
        // warning so it does not fail an otherwise valid result.
        match self.job.terminate_best_effort(u32::MAX) {
            Ok(Some(drain_warning)) => {
                capture_output::write_stderr_line_best_effort(format_args!(
                    "sandbox job did not fully drain within the teardown window (continuing): \
                     {drain_warning}"
                ));
                Ok(())
            }
            Ok(None) => Ok(()),
            Err(error) => Err(std::io::Error::other(error.to_string())),
        }
    }

    fn wait(&mut self) -> std::io::Result<i32> {
        // Close our copy of any not-taken stdin so the child sees EOF and can
        // exit reliably (an interactive command would otherwise block waiting
        // for input).
        self.stdin.take();

        // Drain (and discard) any not-taken streams concurrently to avoid the
        // child blocking on a full pipe buffer.
        let stdout_thread = spawn_discard(self.stdout.take());
        let stderr_thread = spawn_discard(self.stderr.take());

        let result = match unsafe { WaitForSingleObject(self.process.get(), self.timeout_ms) } {
            WAIT_OBJECT_0 => {
                let mut code: u32 = 0;
                if unsafe { GetExitCodeProcess(self.process.get(), &mut code) }.is_err() {
                    Err(std::io::Error::other("GetExitCodeProcess failed"))
                } else {
                    Ok(code as i32)
                }
            }
            WAIT_TIMEOUT => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("script timed out after {}ms", self.timeout_ms),
            )),
            _ => Err(std::io::Error::other("WaitForSingleObject failed")),
        };

        // Tree-kill the job so any backgrounded descendant dies *before*
        // `run_teardown()` removes the firewall / BFS enforcement (keyed to the
        // shared AppContainer package SID) — upholding the same invariant as
        // `Drop`. The foreground child has already exited on the success path; on
        // a timeout or wait failure this also terminates it. Then reap the root
        // (immediate once it has exited) before releasing the pipe drains — and
        // killing the tree closes the descendant's pipe write-ends, so the drains
        // can finish.
        let termination_result = self.kill();
        if termination_result.is_ok() {
            unsafe {
                let _ = WaitForSingleObject(self.process.get(), u32::MAX);
            }
        }
        cancel_and_join_discard(stdout_thread, &self.stdout_canceller);
        cancel_and_join_discard(stderr_thread, &self.stderr_canceller);
        termination_result?;
        // Record the child's exit code so `run_teardown` can stamp it into the
        // denials summary. On a timeout / wait failure there is no exit code.
        self.last_exit_code = result.as_ref().ok().copied();
        let teardown_result = self.run_teardown(true);
        capture_output::combine_process_and_teardown_results(result, teardown_result)
    }
}

impl Drop for AppContainerSandboxProcess {
    fn drop(&mut self) {
        // Kill the tree and reap before tearing down firewall/filesystem
        // policy, so an abandoned-but-running sandbox cannot outlive its
        // enforcement (or leak as an orphan). `kill()` terminates the job.
        if let Err(error) = self.kill() {
            capture_output::write_stderr_line_best_effort(format_args!(
                "failed to terminate sandbox job during drop: {error}"
            ));
            self.release_guarded_capture_after_termination_failure();
            return;
        }
        unsafe {
            let _ = WaitForSingleObject(self.process.get(), u32::MAX);
        }
        if let Err(error) = self.run_teardown(false) {
            capture_output::write_stderr_line_best_effort(format_args!(
                "captureDenials teardown failed during drop: {error}"
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn attr_count_neither() {
        assert_eq!(super::compute_attr_count(false, false, false), 1);
    }

    #[test]
    fn attr_count_lpac_only() {
        assert_eq!(super::compute_attr_count(true, false, false), 2);
    }

    #[test]
    fn attr_count_ui_disable_only() {
        assert_eq!(super::compute_attr_count(false, true, false), 2);
    }

    #[test]
    fn attr_count_both() {
        assert_eq!(super::compute_attr_count(true, true, false), 3);
    }

    #[test]
    fn attr_count_pipe_mode() {
        assert_eq!(super::compute_attr_count(false, false, true), 2);
        assert_eq!(super::compute_attr_count(true, true, true), 4);
    }

    #[test]
    fn learning_mode_capability_classification() {
        use super::LearningModeCapability;
        assert_eq!(
            LearningModeCapability::from_capability_name("learningModeLogging"),
            Some(LearningModeCapability::Learning)
        );
        assert_eq!(
            LearningModeCapability::from_capability_name("permissiveLearningMode"),
            Some(LearningModeCapability::Permissive)
        );
        assert_eq!(
            LearningModeCapability::from_capability_name("internetClient"),
            None
        );
    }

    #[test]
    fn learning_mode_diagnostic_is_deny_and_record() {
        let caps = vec!["learningModeLogging".to_string()];
        let out = super::learning_mode_capability_diagnostics(&caps);
        assert_eq!(out.len(), 1);
        assert!(out[0].contains("deny-and-record"));
        assert!(!out[0].contains("SECURITY WARNING"));
    }

    #[test]
    fn permissive_learning_mode_warns() {
        // Permissive mode must surface a distinct security warning because it
        // relaxes deny-by-default.
        let caps = vec!["permissiveLearningMode".to_string()];
        let out = super::learning_mode_capability_diagnostics(&caps);
        assert_eq!(out.len(), 1);
        assert!(out[0].contains("SECURITY WARNING"));
        assert!(out[0].contains("ALLOWED"));
    }

    #[test]
    fn permissive_learning_mode_uses_security_warning_channel() {
        let caps = vec!["permissiveLearningMode".to_string()];
        let mut logger = wxc_common::logger::Logger::new(wxc_common::logger::Mode::Buffer);

        super::log_learning_mode_capability_diagnostics(&caps, &mut logger);

        assert_eq!(logger.warnings().len(), 1);
        assert!(logger.warnings()[0].contains("SECURITY WARNING"));
        assert!(logger.get_buffer().is_empty());
    }

    #[test]
    fn learning_mode_capability_classification_is_case_insensitive() {
        use super::LearningModeCapability;
        // Windows derives the capability SID case-insensitively, so mis-cased
        // spellings must classify the same as the canonical form.
        assert_eq!(
            LearningModeCapability::from_capability_name("LearningModeLogging"),
            Some(LearningModeCapability::Learning)
        );
        assert_eq!(
            LearningModeCapability::from_capability_name("PermissiveLearningMode"),
            Some(LearningModeCapability::Permissive)
        );
        assert_eq!(
            LearningModeCapability::from_capability_name("PERMISSIVELEARNINGMODE"),
            Some(LearningModeCapability::Permissive)
        );
    }

    #[test]
    fn unrelated_capabilities_produce_no_diagnostics() {
        // Ordinary (non-learning-mode) capabilities must be ignored entirely.
        let caps = vec!["internetClient".to_string(), "registryRead".to_string()];
        assert!(super::learning_mode_capability_diagnostics(&caps).is_empty());
    }

    #[test]
    fn permissive_learning_mode_overrides_deny_and_record_diagnostic() {
        let caps = vec![
            "learningModeLogging".to_string(),
            "permissiveLearningMode".to_string(),
        ];
        let out = super::learning_mode_capability_diagnostics(&caps);
        assert_eq!(out.len(), 1);
        assert!(out[0].contains("SECURITY WARNING"));
        assert!(out[0].contains("overrides learningModeLogging"));
        assert!(out[0].contains("ALLOWED"));
        assert!(!out[0].contains("accesses are still denied"));
    }

    #[test]
    fn derive_sid_string_empty_profile_name_errors() {
        let res = super::derive_sid_string("");
        assert!(matches!(
            res,
            Err(wxc_common::error::WxcError::Initialization(_))
        ));
    }

    #[test]
    fn derive_sid_string_returns_appcontainer_prefix() {
        let sid =
            super::derive_sid_string("MxcDeriveSidTestSimple").expect("derivation should succeed");
        assert!(
            sid.starts_with("S-1-15-"),
            "expected AppContainer SID prefix S-1-15-, got: {sid}"
        );
    }

    #[test]
    fn derive_sid_string_is_stable_for_same_name() {
        let a = super::derive_sid_string("MxcDeriveSidTestStable").expect("first derivation");
        let b = super::derive_sid_string("MxcDeriveSidTestStable").expect("second derivation");
        assert_eq!(a, b);
    }

    /// Helper: build a double-null-terminated UTF-16 env block from strings.
    fn make_utf16_block(entries: &[&str]) -> Vec<u16> {
        let mut block = Vec::new();
        for entry in entries {
            for ch in entry.encode_utf16() {
                block.push(ch);
            }
            block.push(0);
        }
        block.push(0);
        block
    }

    #[test]
    fn parse_environment_block_basic_entries() {
        let block = make_utf16_block(&["FOO=bar", "PATH=C:\\Windows"]);
        let entries = super::parse_environment_block(block.as_ptr());
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], ("FOO".to_string(), "bar".to_string()));
        assert_eq!(entries[1], ("PATH".to_string(), "C:\\Windows".to_string()));
    }

    #[test]
    fn parse_environment_block_preserves_drive_letter_vars() {
        let block = make_utf16_block(&[
            "=C:=C:\\Users\\test",
            "=D:=D:\\Data",
            "HOME=C:\\Users\\test",
        ]);
        let entries = super::parse_environment_block(block.as_ptr());
        assert_eq!(entries.len(), 3);
        assert_eq!(
            entries[0],
            ("=C:".to_string(), "C:\\Users\\test".to_string())
        );
        assert_eq!(entries[1], ("=D:".to_string(), "D:\\Data".to_string()));
        assert_eq!(
            entries[2],
            ("HOME".to_string(), "C:\\Users\\test".to_string())
        );
    }

    #[test]
    fn parse_environment_block_value_with_equals() {
        let block = make_utf16_block(&["CONN=host=db;port=5432"]);
        let entries = super::parse_environment_block(block.as_ptr());
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0],
            ("CONN".to_string(), "host=db;port=5432".to_string())
        );
    }

    #[test]
    fn parse_environment_block_empty_block() {
        let block: Vec<u16> = vec![0]; // just the double-null (no entries)
        let entries = super::parse_environment_block(block.as_ptr());
        assert!(entries.is_empty());
    }

    #[test]
    fn encode_env_block_sorts_case_insensitively() {
        let entries = vec![
            ("Zebra".to_string(), "1".to_string()),
            ("alpha".to_string(), "2".to_string()),
        ];
        let block = super::encode_env_block(&entries);
        // Decode: "alpha=2\0Zebra=1\0\0"
        let parsed = super::parse_environment_block(block.as_ptr());
        assert_eq!(parsed[0].0, "alpha");
        assert_eq!(parsed[1].0, "Zebra");
    }

    #[test]
    fn encode_decode_round_trip_with_drive_vars() {
        let entries = vec![
            ("=C:".to_string(), "C:\\Users\\test".to_string()),
            ("PATH".to_string(), "C:\\Windows".to_string()),
        ];
        let block = super::encode_env_block(&entries);
        let parsed = super::parse_environment_block(block.as_ptr());
        assert_eq!(parsed, entries);
    }

    #[test]
    fn build_explicit_entries_no_proxy() {
        let env = vec!["FOO=bar".to_string(), "BAZ=qux".to_string()];
        let entries = super::build_explicit_entries(&env, None);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], ("FOO".to_string(), "bar".to_string()));
        assert_eq!(entries[1], ("BAZ".to_string(), "qux".to_string()));
    }

    #[test]
    fn build_explicit_entries_strips_and_injects_proxy() {
        let env = vec![
            "FOO=bar".to_string(),
            "HTTP_PROXY=old".to_string(),
            "https_proxy=old2".to_string(),
            "NO_PROXY=localhost".to_string(),
        ];
        let proxy = wxc_common::models::ProxyAddress::new("127.0.0.1".to_string(), 8080);
        let entries = super::build_explicit_entries(&env, Some(&proxy));

        // Original proxy vars should be stripped.
        assert!(!entries
            .iter()
            .any(|(k, _)| k == "http_proxy" || k == "https_proxy" || k == "NO_PROXY"));
        // FOO should remain.
        assert!(entries.iter().any(|(k, v)| k == "FOO" && v == "bar"));
        // Injected proxy vars should be present.
        let proxy_url = proxy.to_url();
        assert!(entries
            .iter()
            .any(|(k, v)| k == "HTTP_PROXY" && v == &proxy_url));
        assert!(entries
            .iter()
            .any(|(k, v)| k == "HTTPS_PROXY" && v == &proxy_url));
    }

    // ---- validate_runner: unsupported policy fields surface as errors. ----

    use super::{
        create_process_failure, AppContainerScriptRunner, FilesystemMode,
        CAPTURE_DENIALS_FALLBACK_UNSUPPORTED_MSG,
    };
    use crate::guarded_capture::{GuardedCaptureFactory, GuardedCaptureSession};
    use learning_mode_core::AnalysisResult;
    use std::sync::Arc;
    use windows::Win32::Foundation::{ERROR_ACCESS_DISABLED_BY_POLICY, ERROR_CALL_NOT_IMPLEMENTED};
    use wxc_common::models::{ExecutionRequest, FailurePhase};
    use wxc_common::sandbox_process::SandboxBackend;

    /// A fake [`GuardedCaptureFactory`] used only to exercise `validate()`'s
    /// factory-presence gate — its `start` is never called by these tests.
    struct FakeGuardedCaptureFactory;

    impl GuardedCaptureFactory for FakeGuardedCaptureFactory {
        fn start(&self, _owner_pid: u32) -> Result<Box<dyn GuardedCaptureSession>, String> {
            struct FakeSession;
            impl GuardedCaptureSession for FakeSession {
                fn attach_process_tree(
                    &mut self,
                    _job_handle: usize,
                    _root_process_handle: usize,
                ) -> Result<(), String> {
                    Ok(())
                }

                fn discard(&mut self) -> Result<(), String> {
                    Ok(())
                }

                fn stop_analyzed(&mut self) -> Result<AnalysisResult, String> {
                    Ok(AnalysisResult::complete(Vec::new()))
                }

                fn stop_analyzed_with_trace(
                    &mut self,
                    trace_destination: &std::path::Path,
                ) -> Result<crate::guarded_capture::AnalyzedTrace, String> {
                    std::fs::write(trace_destination, b"fake etl")
                        .map_err(|error| error.to_string())?;
                    Ok(crate::guarded_capture::AnalyzedTrace {
                        analysis: AnalysisResult::complete(Vec::new()),
                        trace_retention: Ok(()),
                    })
                }
            }
            Ok(Box::new(FakeSession))
        }
    }

    #[test]
    fn appcontainer_policy_block_uses_launch_diagnostic() {
        let err = windows_core::Error::from_hresult(ERROR_ACCESS_DISABLED_BY_POLICY.to_hresult());
        let mapped = create_process_failure(
            &err,
            r#""C:\Program Files\PowerShell\7\pwsh.exe" -NoProfile"#,
            &[],
            r"C:\work",
        );
        let message = mapped.to_string();

        assert!(message.contains("IT-managed policy rule"));
        assert!(message.contains("1260"));
        assert!(message.contains("system administrator"));
        assert!(message.contains(r"working directory: C:\work"));
        assert!(!message.contains("readonlyPaths"));
    }

    #[test]
    fn appcontainer_other_win32_error_preserves_create_process_message() {
        let err = windows_core::Error::from_hresult(ERROR_CALL_NOT_IMPLEMENTED.to_hresult());
        let mapped = create_process_failure(&err, "cmd.exe", &[], r"C:\work");
        let message = mapped.to_string();

        assert!(message.contains("CreateProcessW failed"));
        assert!(message.contains(r"working directory: C:\work"));
        assert!(!message.contains("BaseContainer"));
        assert!(!message.contains("Experimental_CreateProcessInSandbox"));
    }

    #[test]
    fn validate_runner_rejects_denied_paths_in_bfs_mode() {
        let runner = AppContainerScriptRunner::with_filesystem_mode(FilesystemMode::Bfs);
        let mut request = ExecutionRequest::default();
        request.policy.denied_paths = vec!["C:\\secret".into()];

        let err = runner
            .validate(&request)
            .expect_err("BFS mode must reject deniedPaths");
        assert!(
            err.error_message.contains("deniedPaths"),
            "expected message to mention deniedPaths, got: {}",
            err.error_message
        );
    }

    #[test]
    fn validate_runner_accepts_denied_paths_in_dacl_mode() {
        let runner = AppContainerScriptRunner::with_filesystem_mode(FilesystemMode::Dacl);
        let mut request = ExecutionRequest::default();
        request.policy.denied_paths = vec!["C:\\secret".into()];

        assert!(
            runner.validate(&request).is_ok(),
            "DACL mode supports deniedPaths and should not error"
        );
    }

    #[test]
    fn validate_runner_accepts_dispatcher_enforced_denied_paths_in_bfs_mode() {
        let runner = AppContainerScriptRunner::with_filesystem_mode(FilesystemMode::Bfs)
            .with_external_denied_paths();
        let mut request = ExecutionRequest::default();
        request.policy.denied_paths = vec!["C:\\secret".into()];

        assert!(runner.validate(&request).is_ok());
    }

    /// Records the order of guarded-capture callbacks so orchestration tests can
    /// assert the security-sensitive teardown ordering explicitly.
    struct RecordingSession {
        events: Arc<std::sync::Mutex<Vec<String>>>,
        attach_result: Result<(), String>,
        discard_result: Result<(), String>,
    }

    impl GuardedCaptureSession for RecordingSession {
        fn attach_process_tree(
            &mut self,
            _job_handle: usize,
            _root_process_handle: usize,
        ) -> Result<(), String> {
            self.events.lock().unwrap().push("attach".to_string());
            self.attach_result.clone()
        }

        fn discard(&mut self) -> Result<(), String> {
            self.events.lock().unwrap().push("discard".to_string());
            self.discard_result.clone()
        }

        fn stop_analyzed(&mut self) -> Result<AnalysisResult, String> {
            self.events
                .lock()
                .unwrap()
                .push("stop_analyzed".to_string());
            Ok(AnalysisResult::complete(Vec::new()))
        }

        fn stop_analyzed_with_trace(
            &mut self,
            _trace_destination: &std::path::Path,
        ) -> Result<crate::guarded_capture::AnalyzedTrace, String> {
            unreachable!()
        }
    }

    #[test]
    fn attach_failure_terminates_job_before_discarding_and_composes_message() {
        let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let session = Box::new(RecordingSession {
            events: Arc::clone(&events),
            attach_result: Err("attach boom".to_string()),
            discard_result: Err("discard boom".to_string()),
        });
        let events_for_kill = Arc::clone(&events);

        let error = match super::attach_guarded_capture_or_cleanup(session, 1, 2, || {
            events_for_kill
                .lock()
                .unwrap()
                .push("terminate".to_string());
            Some("terminate boom".to_string())
        }) {
            Ok(_) => panic!("attach failure must abandon the launch"),
            Err(error) => error,
        };

        // Ordering is load-bearing: attach is attempted, then the job is
        // terminated, and only then is the session discarded — nothing may keep
        // running once the trace is about to be torn down.
        assert_eq!(
            *events.lock().unwrap(),
            vec![
                "attach".to_string(),
                "terminate".to_string(),
                "discard".to_string()
            ]
        );
        // The composed message reports all three failures, terminate before
        // discard.
        assert!(error.contains("attach boom"), "got: {error}");
        let terminate_at = error.find("terminate boom").expect("terminate reported");
        let discard_at = error.find("discard boom").expect("discard reported");
        assert!(
            terminate_at < discard_at,
            "terminate must be reported before discard: {error}"
        );
    }

    #[test]
    fn attach_failure_reports_only_attach_when_cleanup_succeeds() {
        let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let session = Box::new(RecordingSession {
            events: Arc::clone(&events),
            attach_result: Err("attach boom".to_string()),
            discard_result: Ok(()),
        });

        let error = match super::attach_guarded_capture_or_cleanup(session, 1, 2, || None) {
            Ok(_) => panic!("attach failure must abandon the launch"),
            Err(error) => error,
        };

        assert!(error.contains("attach boom"), "got: {error}");
        assert!(
            !error.contains("additionally"),
            "clean cleanup must not append failure suffixes: {error}"
        );
        assert_eq!(
            *events.lock().unwrap(),
            vec!["attach".to_string(), "discard".to_string()]
        );
    }

    #[test]
    fn attach_success_returns_the_live_session_without_cleanup() {
        let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let session = Box::new(RecordingSession {
            events: Arc::clone(&events),
            attach_result: Ok(()),
            discard_result: Ok(()),
        });

        let session = super::attach_guarded_capture_or_cleanup(session, 1, 2, || {
            panic!("the job must not be terminated when attach succeeds")
        })
        .expect("attach success returns the live session");

        // The live session is returned undisturbed (no discard on success).
        assert_eq!(*events.lock().unwrap(), vec!["attach".to_string()]);
        drop(session);
    }

    #[test]
    fn discard_after_launch_failure_stops_the_trace_once() {
        // The resume-failure path abandons an already-started capture via
        // `discard`. Model that discard contract directly: it must be invoked
        // exactly once to stop the trace, with no analysis attempted.
        let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let mut session: Box<dyn GuardedCaptureSession> = Box::new(RecordingSession {
            events: Arc::clone(&events),
            attach_result: Ok(()),
            discard_result: Ok(()),
        });
        let _ = session.discard();
        assert_eq!(*events.lock().unwrap(), vec!["discard".to_string()]);
    }

    #[test]
    fn validate_runner_rejects_allowed_hosts() {
        let runner = AppContainerScriptRunner::new();
        let mut request = ExecutionRequest::default();
        request.policy.allowed_hosts = vec!["example.com".into()];

        let err = runner
            .validate(&request)
            .expect_err("allowedHosts is not yet supported");
        assert!(err.error_message.contains("allowedHosts"));
    }

    #[test]
    fn validate_runner_rejects_blocked_hosts() {
        let runner = AppContainerScriptRunner::new();
        let mut request = ExecutionRequest::default();
        request.policy.blocked_hosts = vec!["bad.example.com".into()];

        let err = runner
            .validate(&request)
            .expect_err("blockedHosts is not yet supported");
        assert!(err.error_message.contains("blockedHosts"));
    }

    #[test]
    fn validate_runner_rejects_identity_scoped_proxy() {
        let runner = AppContainerScriptRunner::new();
        let mut request = ExecutionRequest::default();
        request.policy.network_proxy = wxc_common::models::ProxyConfig {
            address: Some(wxc_common::models::ProxyAddress::new(
                "127.0.0.1".to_string(),
                8080,
            )),
            builtin_test_server: false,
        };
        request.policy.allowed_proxy_peer = Some("Contoso.Proxy_123".to_string());

        let error = runner
            .validate(&request)
            .expect_err("AppContainer cannot enforce proxy peer identity");
        assert!(error.error_message.contains("allowedProxyPeer"));
    }

    #[test]
    fn validate_runner_accepts_empty_policy() {
        let runner = AppContainerScriptRunner::new();
        let request = ExecutionRequest::default();
        assert!(runner.validate(&request).is_ok());
    }

    #[test]
    fn validate_runner_rejects_capture_denials_on_appcontainer_fallback() {
        let runner = AppContainerScriptRunner::new();
        let mut request = ExecutionRequest::default();
        request.policy.capture_denials = Some(Default::default());

        let error = runner
            .validate(&request)
            .expect_err("AppContainer fallback must not silently ignore captureDenials");
        assert_eq!(error.failure_phase, FailurePhase::BackendUnavailable);
        assert_eq!(
            error.error_message,
            CAPTURE_DENIALS_FALLBACK_UNSUPPORTED_MSG
        );
    }

    #[test]
    fn validate_runner_accepts_capture_denials_with_guarded_factory() {
        let runner = AppContainerScriptRunner::new()
            .with_guarded_capture_factory(Arc::new(FakeGuardedCaptureFactory));
        let mut request = ExecutionRequest::default();
        request.policy.capture_denials = Some(Default::default());

        assert!(
            runner.validate(&request).is_ok(),
            "a runner explicitly configured with a guarded capture factory must accept \
             captureDenials"
        );
    }

    #[test]
    fn validate_runner_rejects_etl_retention_with_guarded_capture() {
        let runner = AppContainerScriptRunner::new()
            .with_guarded_capture_factory(Arc::new(FakeGuardedCaptureFactory));
        let mut request = ExecutionRequest::default();
        request.policy.capture_denials = Some(wxc_common::models::CaptureDenialsConfig {
            retain_etl: true,
            ..Default::default()
        });

        let error = runner
            .validate(&request)
            .expect_err("the configured guarded provider cannot transfer ETL");

        assert_eq!(error.failure_phase, FailurePhase::BackendUnavailable);
        assert_eq!(
            error.error_message,
            crate::guarded_capture::RETAIN_ETL_UNSUPPORTED_MSG
        );
    }

    #[test]
    fn validate_runner_allows_guarded_etl_when_provider_supports_transfer() {
        struct RetainingGuardedCaptureFactory;
        impl GuardedCaptureFactory for RetainingGuardedCaptureFactory {
            fn allows_trace_transfer(&self) -> bool {
                true
            }

            fn start(&self, owner_pid: u32) -> Result<Box<dyn GuardedCaptureSession>, String> {
                FakeGuardedCaptureFactory.start(owner_pid)
            }
        }

        let runner = AppContainerScriptRunner::new()
            .with_guarded_capture_factory(Arc::new(RetainingGuardedCaptureFactory));
        let mut request = ExecutionRequest::default();
        request.policy.capture_denials = Some(wxc_common::models::CaptureDenialsConfig {
            retain_etl: true,
            ..Default::default()
        });

        runner
            .validate(&request)
            .expect("a transfer-capable guarded provider should permit ETL retention");
    }
}
