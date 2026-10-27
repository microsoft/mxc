// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Checked C ABI v1 bindings for the signed bundled `aci_edge_agent.dll`.

use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::ptr;
use std::slice;
use std::sync::{Mutex, OnceLock, PoisonError};

use libloading::Library as LoadedLibrary;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::mxc_common::mxc_error::{MxcError, MxcErrorCode};

pub(super) const SANDBOX_ABI_VERSION: u32 = 1;

pub(super) const STATUS_OK: i32 = 0;
pub(super) const STATUS_ERROR: i32 = 1;
pub(super) const STATUS_TIMEOUT: i32 = 2;
pub(super) const STATUS_INVALID_HANDLE: i32 = -1;
pub(super) const STATUS_INVALID_ARGUMENT: i32 = -2;
pub(super) const STATUS_PANIC: i32 = -3;

pub(super) const EVENT_STDOUT: u32 = 1;
pub(super) const EVENT_STDERR: u32 = 2;
pub(super) const EVENT_EXIT: u32 = 3;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(super) struct ExecEvent {
    pub kind: u32,
    pub data: *const u8,
    pub length: usize,
}

const _: () = assert!(std::mem::size_of::<ExecEvent>() == 24);

pub(super) type VersionFn = unsafe extern "C" fn() -> u32;
pub(super) type HostOpenFn =
    unsafe extern "C" fn(*const u8, usize, *mut u64, *mut *mut u8, *mut usize) -> i32;
pub(super) type ReleaseFn = unsafe extern "C" fn(u64) -> i32;
pub(super) type QueryFn = unsafe extern "C" fn(u64, *mut *mut u8, *mut usize) -> i32;
pub(super) type CallFn =
    unsafe extern "C" fn(u64, *const u8, usize, *mut *mut u8, *mut usize) -> i32;
pub(super) type ExecFn = unsafe extern "C" fn(
    u64,
    *const u8,
    usize,
    *const u8,
    usize,
    *mut u64,
    *mut *mut u8,
    *mut usize,
) -> i32;
pub(super) type ExecNextFn = unsafe extern "C" fn(u64, i64, *mut ExecEvent) -> i32;
pub(super) type ExecWriteFn =
    unsafe extern "C" fn(u64, *const u8, usize, i64, *mut usize, *mut *mut u8, *mut usize) -> i32;
pub(super) type BufferFreeFn = unsafe extern "C" fn(*mut u8, usize);

#[allow(dead_code)]
#[derive(Clone, Copy)]
pub(super) struct Exports {
    pub host_open: HostOpenFn,
    pub host_close: ReleaseFn,
    pub host_info: QueryFn,
    pub capabilities: QueryFn,
    pub probe: QueryFn,
    pub validate_provision: CallFn,
    pub validate_exec: CallFn,
    pub provision: CallFn,
    pub start: CallFn,
    pub stop: CallFn,
    pub deprovision: CallFn,
    pub diagnostics: CallFn,
    pub guest_logs: CallFn,
    pub exec: ExecFn,
    pub exec_next: ExecNextFn,
    pub exec_write: ExecWriteFn,
    pub exec_close_input: QueryFn,
    pub exec_cancel: QueryFn,
    pub exec_release: ReleaseFn,
    pub image_register: CallFn,
    pub image_list: QueryFn,
    pub image_verify: CallFn,
    pub image_unregister: CallFn,
    pub buffer_free: BufferFreeFn,
}

/// A verified `aci_edge_agent.dll` instance.
///
/// Once loaded, the library and its `FILE_SHARE_READ` lock handle stay open for the lifetime of
/// the process so internal threads/state inside the agent DLL remain valid and the verified file
/// on disk cannot be modified, deleted, or renamed.
pub(super) struct AgentLibrary {
    exports: Exports,
    verified_sha256: String,
    _library: Option<LoadedLibrary>,
    _lock_file: Option<File>,
}

impl fmt::Debug for AgentLibrary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentLibrary")
            .field("verified_sha256", &self.verified_sha256)
            .finish_non_exhaustive()
    }
}

pub(super) enum Event<'a> {
    Stdout(&'a [u8]),
    Stderr(&'a [u8]),
    Exit(&'a [u8]),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SetupConfig {
    pub schema_version: u32,
    pub state_root: PathBuf,
    pub runtime: RuntimeSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RuntimeSource {
    pub bundle: BundleSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BundleSource {
    pub path: PathBuf,
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct HostInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_image: Option<String>,
    pub runtime_digests: RuntimeDigests,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RuntimeDigests {
    pub initrd: String,
    pub kernel: String,
    pub openvmm: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProvisionRequest {}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SandboxSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<ImageSource>,
}

impl SandboxSpec {
    pub fn is_empty(&self) -> bool {
        self.image.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) enum ImageSource {
    Reference(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProvisionInput {
    pub request: ProvisionRequest,
    #[serde(default, skip_serializing_if = "SandboxSpec::is_empty")]
    pub spec: SandboxSpec,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProvisionReply {
    pub token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct StartResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct StopResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DeprovisionResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SandboxDiagnostics {
    pub vmm_log: PathBuf,
    pub console_log: PathBuf,
    pub outcome_report: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ExecInput {
    pub request: ExecRequest,
    #[serde(default)]
    pub stdin: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ExecRequest {
    pub process: ProcessSpec,
}

impl ExecRequest {
    pub fn command_line(command_line: impl Into<String>) -> Self {
        Self {
            process: ProcessSpec {
                command_line: command_line.into(),
                cwd: None,
                env: None,
                inherit_default_env: None,
                timeout: None,
            },
        }
    }

    pub fn with_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.process.timeout = Some(timeout_ms);
        self
    }

    pub fn with_cwd(mut self, cwd: impl Into<String>) -> Self {
        self.process.cwd = Some(cwd.into());
        self
    }

    pub fn with_envs(mut self, env: Vec<String>) -> Self {
        self.process.env = Some(env);
        self
    }

    pub fn with_inherit_default_env(mut self, inherit: bool) -> Self {
        self.process.inherit_default_env = Some(inherit);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProcessSpec {
    pub command_line: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inherit_default_env: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) enum ExecEnd {
    Outcome(ExecOutcome),
    Error(ErrorBody),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum ExecOutcome {
    Exited(i32),
    Signaled(i32),
    TimedOut,
    Cancelled,
    Failed(ExecFailure),
}

impl fmt::Display for ExecOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exited(code) => write!(formatter, "exited with status {code}"),
            Self::Signaled(signal) => write!(formatter, "terminated by signal {signal}"),
            Self::TimedOut => formatter.write_str("timed out"),
            Self::Cancelled => formatter.write_str("cancelled"),
            Self::Failed(failure) => write!(formatter, "failed: {failure}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum ExecFailure {
    LaunchFailed,
    WorkingDirectory,
    OutputLimitExceeded,
    Workload,
}

impl fmt::Display for ExecFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::LaunchFailed => "the workload could not be launched",
            Self::WorkingDirectory => {
                "the workload's working directory does not exist, is not a directory, or is not \
                 accessible to the workload"
            }
            Self::OutputLimitExceeded => "the workload exceeded the output limit",
            Self::Workload => "the workload's exit status could not be determined",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum WireErrorCode {
    MalformedRequest,
    MalformedId,
    StaleId,
    NotStarted,
    AlreadyStarted,
    AlreadyStopped,
    PolicyValidation,
    BackendUnavailable,
    Unsupported,
    BackendError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ErrorBody {
    pub code: WireErrorCode,
    pub message: String,
}

pub(super) fn map_error_body(body: ErrorBody) -> MxcError {
    let code = match body.code {
        WireErrorCode::MalformedRequest => MxcErrorCode::MalformedRequest,
        WireErrorCode::MalformedId => MxcErrorCode::MalformedId,
        WireErrorCode::StaleId => MxcErrorCode::StaleId,
        WireErrorCode::NotStarted => MxcErrorCode::NotStarted,
        WireErrorCode::AlreadyStarted => MxcErrorCode::AlreadyStarted,
        WireErrorCode::AlreadyStopped => MxcErrorCode::AlreadyStopped,
        WireErrorCode::PolicyValidation => MxcErrorCode::PolicyValidation,
        WireErrorCode::BackendUnavailable => MxcErrorCode::BackendUnavailable,
        WireErrorCode::Unsupported | WireErrorCode::BackendError => MxcErrorCode::BackendError,
    };
    MxcError::new(code, format!("NVX signed bundled agent: {}", body.message))
}

fn error_from_body(bytes: Option<&[u8]>) -> MxcError {
    match bytes.map(serde_json::from_slice::<ErrorBody>) {
        Some(Ok(body)) => map_error_body(body),
        _ => MxcError::backend_error(
            "NVX signed bundled agent: the agent library reported an error without a valid description",
        ),
    }
}

fn status_error(status: i32) -> MxcError {
    let detail = match status {
        STATUS_INVALID_HANDLE => {
            "the agent library rejected a released or unknown handle".to_owned()
        }
        STATUS_INVALID_ARGUMENT => "the agent library rejected an argument".to_owned(),
        STATUS_PANIC => "the agent library panicked; the operation's effect is unknown".to_owned(),
        other => format!("the agent library returned the unexpected status {other}"),
    };
    MxcError::backend_error(format!("NVX signed bundled agent: {detail}"))
}

fn encode_json(value: &impl Serialize) -> Result<Vec<u8>, MxcError> {
    serde_json::to_vec(value).map_err(|error| {
        MxcError::malformed_request(format!(
            "NVX signed bundled agent: cannot encode request: {error}"
        ))
    })
}

fn decode_json<T: DeserializeOwned>(bytes: Option<Vec<u8>>, what: &str) -> Result<T, MxcError> {
    let bytes = bytes.ok_or_else(|| {
        MxcError::backend_error(format!(
            "NVX signed bundled agent: the agent library returned no {what}"
        ))
    })?;
    serde_json::from_slice(&bytes).map_err(|error| {
        MxcError::backend_error(format!(
            "NVX signed bundled agent: the agent library returned a malformed {what}: {error}"
        ))
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Opens `path` for read with `FILE_SHARE_READ` (`1`) only, preventing any concurrent writer,
/// deletion, or rename of the DLL or its parent directories while the handle remains open.
pub(super) fn open_for_load(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 1;
        options.share_mode(FILE_SHARE_READ);
    }
    options.open(path)
}

fn resolve_export<T: Copy>(library: &LoadedLibrary, name: &[u8]) -> Result<T, MxcError> {
    unsafe { library.get::<T>(name) }
        .map(|symbol| *symbol)
        .map_err(|error| {
            MxcError::backend_unavailable(format!(
                "NVX signed bundled agent: the agent library is missing required export {}: {error}",
                String::from_utf8_lossy(name).trim_end_matches('\0')
            ))
        })
}

impl AgentLibrary {
    pub fn load_verified(path: &Path, expected_sha256: &str) -> Result<&'static Self, MxcError> {
        type LoadedMap = Mutex<HashMap<PathBuf, &'static AgentLibrary>>;
        static LOADED: OnceLock<LoadedMap> = OnceLock::new();

        if !path.is_absolute() {
            return Err(MxcError::backend_unavailable(
                "NVX signed bundled agent: the agent library path must be absolute",
            ));
        }

        // Open and lock the DLL with FILE_SHARE_READ before canonicalizing, hashing, or mapping it
        // so that no writer or rename can swap the file between verification and LoadLibraryW.
        let lock_file = open_for_load(path).map_err(|error| {
            MxcError::backend_unavailable(format!(
                "NVX signed bundled agent: cannot verify the agent library at {}: {error}",
                path.display()
            ))
        })?;
        let canonical = fs::canonicalize(path).map_err(|error| {
            MxcError::backend_unavailable(format!(
                "NVX signed bundled agent: cannot locate the agent library at {}: {error}",
                path.display()
            ))
        })?;

        let cache = LOADED.get_or_init(Default::default);
        let mut loaded = cache.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(&existing) = loaded.get(&canonical) {
            if !existing
                .verified_sha256
                .eq_ignore_ascii_case(expected_sha256)
            {
                return Err(MxcError::backend_unavailable(format!(
                    "NVX signed bundled agent: the agent library at {} does not match the approved SHA-256",
                    path.display()
                )));
            }
            return Ok(existing);
        }

        let instance = Self::open_locked(&canonical, lock_file, expected_sha256)?;
        let leaked: &'static Self = Box::leak(Box::new(instance));
        loaded.insert(canonical, leaked);
        Ok(leaked)
    }

    fn open_locked(
        path: &Path,
        mut lock_file: File,
        expected_sha256: &str,
    ) -> Result<Self, MxcError> {
        let mut bytes = Vec::new();
        lock_file.read_to_end(&mut bytes).map_err(|error| {
            MxcError::backend_unavailable(format!(
                "NVX signed bundled agent: cannot read the agent library at {}: {error}",
                path.display()
            ))
        })?;
        let actual_sha256 = sha256_hex(&bytes);
        if !actual_sha256.eq_ignore_ascii_case(expected_sha256) {
            return Err(MxcError::backend_unavailable(format!(
                "NVX signed bundled agent: the agent library at {} does not match the approved SHA-256",
                path.display()
            )));
        }

        let library = unsafe { LoadedLibrary::new(path) }.map_err(|error| {
            MxcError::backend_unavailable(format!(
                "NVX signed bundled agent: cannot load the agent library from {}: {error}",
                path.display()
            ))
        })?;

        let version: VersionFn = resolve_export(&library, b"aci_edge_sandbox_api_version\0")?;
        let actual_version = unsafe { version() };
        if actual_version != SANDBOX_ABI_VERSION {
            return Err(MxcError::backend_unavailable(format!(
                "NVX signed bundled agent: the agent library's sandbox ABI is {actual_version}, expected {SANDBOX_ABI_VERSION}"
            )));
        }

        let exports = Exports {
            host_open: resolve_export(&library, b"aci_edge_sandbox_host_open\0")?,
            host_close: resolve_export(&library, b"aci_edge_sandbox_host_close\0")?,
            host_info: resolve_export(&library, b"aci_edge_sandbox_host_info\0")?,
            capabilities: resolve_export(&library, b"aci_edge_sandbox_capabilities\0")?,
            probe: resolve_export(&library, b"aci_edge_sandbox_probe\0")?,
            validate_provision: resolve_export(&library, b"aci_edge_sandbox_validate_provision\0")?,
            validate_exec: resolve_export(&library, b"aci_edge_sandbox_validate_exec\0")?,
            provision: resolve_export(&library, b"aci_edge_sandbox_provision\0")?,
            start: resolve_export(&library, b"aci_edge_sandbox_start\0")?,
            stop: resolve_export(&library, b"aci_edge_sandbox_stop\0")?,
            deprovision: resolve_export(&library, b"aci_edge_sandbox_deprovision\0")?,
            diagnostics: resolve_export(&library, b"aci_edge_sandbox_diagnostics\0")?,
            guest_logs: resolve_export(&library, b"aci_edge_sandbox_guest_logs\0")?,
            exec: resolve_export(&library, b"aci_edge_sandbox_exec\0")?,
            exec_next: resolve_export(&library, b"aci_edge_exec_next\0")?,
            exec_write: resolve_export(&library, b"aci_edge_exec_write\0")?,
            exec_close_input: resolve_export(&library, b"aci_edge_exec_close_input\0")?,
            exec_cancel: resolve_export(&library, b"aci_edge_exec_cancel\0")?,
            exec_release: resolve_export(&library, b"aci_edge_exec_release\0")?,
            image_register: resolve_export(&library, b"aci_edge_image_register\0")?,
            image_list: resolve_export(&library, b"aci_edge_image_list\0")?,
            image_verify: resolve_export(&library, b"aci_edge_image_verify\0")?,
            image_unregister: resolve_export(&library, b"aci_edge_image_unregister\0")?,
            buffer_free: resolve_export(&library, b"aci_edge_buffer_free\0")?,
        };

        Ok(Self {
            exports,
            verified_sha256: actual_sha256,
            _library: Some(library),
            _lock_file: Some(lock_file),
        })
    }

    #[cfg(test)]
    pub(super) const fn from_exports_for_test(exports: Exports) -> Self {
        Self {
            exports,
            verified_sha256: String::new(),
            _library: None,
            _lock_file: None,
        }
    }

    fn take_buffer(
        &self,
        buffer: *mut u8,
        length: usize,
        limit: Option<usize>,
    ) -> Result<Option<Vec<u8>>, MxcError> {
        if buffer.is_null() {
            if length == 0 {
                return Ok(None);
            }
            return Err(MxcError::backend_error(
                "NVX signed bundled agent: the agent library returned a null buffer with a non-zero length",
            ));
        }
        if limit.is_some_and(|limit| length > limit) {
            unsafe { (self.exports.buffer_free)(buffer, length) };
            return Err(MxcError::backend_error(
                "NVX signed bundled agent: diagnostics response exceeds the 65536-byte limit",
            ));
        }
        let bytes = if length == 0 {
            Vec::new()
        } else {
            // SAFETY: `buffer` and `length` were returned by the agent DLL and have not been freed.
            unsafe { slice::from_raw_parts(buffer, length) }.to_vec()
        };
        unsafe { (self.exports.buffer_free)(buffer, length) };
        Ok(Some(bytes))
    }

    fn call(
        &self,
        invoke: impl FnOnce(*mut *mut u8, *mut usize) -> i32,
    ) -> Result<Option<Vec<u8>>, MxcError> {
        self.call_with_limit(invoke, None)
    }

    fn call_with_limit(
        &self,
        invoke: impl FnOnce(*mut *mut u8, *mut usize) -> i32,
        limit: Option<usize>,
    ) -> Result<Option<Vec<u8>>, MxcError> {
        let mut buffer = ptr::null_mut();
        let mut length = 0;
        let status = invoke(&mut buffer, &mut length);
        let bytes = self.take_buffer(buffer, length, limit)?;
        match status {
            STATUS_OK => Ok(bytes),
            STATUS_ERROR => Err(error_from_body(bytes.as_deref())),
            other => Err(status_error(other)),
        }
    }

    fn call_empty(
        &self,
        operation: &str,
        invoke: impl FnOnce(*mut *mut u8, *mut usize) -> i32,
    ) -> Result<(), MxcError> {
        match self.call(invoke)? {
            None => Ok(()),
            Some(_) => Err(MxcError::backend_error(format!(
                "NVX signed bundled agent: the agent library returned an unexpected {operation} payload"
            ))),
        }
    }

    fn query(&self, export: QueryFn, handle: u64) -> Result<Option<Vec<u8>>, MxcError> {
        self.call(|out, length| unsafe { export(handle, out, length) })
    }

    fn with_input(
        &self,
        export: CallFn,
        host: u64,
        input: &[u8],
    ) -> Result<Option<Vec<u8>>, MxcError> {
        self.call(|out, length| unsafe { export(host, input.as_ptr(), input.len(), out, length) })
    }

    pub fn host_open(&self, setup: &SetupConfig) -> Result<u64, MxcError> {
        let encoded = encode_json(setup)?;
        let mut host = 0u64;
        self.call_empty("host_open", |out, length| unsafe {
            (self.exports.host_open)(encoded.as_ptr(), encoded.len(), &mut host, out, length)
        })?;
        if host == 0 {
            return Err(MxcError::backend_error(
                "NVX signed bundled agent: the agent library returned an invalid zero host handle",
            ));
        }
        Ok(host)
    }

    pub fn host_close(&self, host: u64) -> Result<(), MxcError> {
        let status = unsafe { (self.exports.host_close)(host) };
        match status {
            STATUS_OK => Ok(()),
            other => Err(status_error(other)),
        }
    }

    pub fn host_info(&self, host: u64) -> Result<HostInfo, MxcError> {
        decode_json(
            self.query(self.exports.host_info, host)?,
            "host description",
        )
    }

    pub fn probe(&self, host: u64) -> Result<(), MxcError> {
        self.call_empty("probe", |out, length| unsafe {
            (self.exports.probe)(host, out, length)
        })
    }

    pub fn validate_exec(&self, host: u64, request: &ExecRequest) -> Result<(), MxcError> {
        let encoded = encode_json(request)?;
        self.call_empty("validate_exec", |out, length| unsafe {
            (self.exports.validate_exec)(host, encoded.as_ptr(), encoded.len(), out, length)
        })
    }

    pub fn provision(&self, host: u64, input: &ProvisionInput) -> Result<ProvisionReply, MxcError> {
        let encoded = encode_json(input)?;
        let reply = self.with_input(self.exports.provision, host, &encoded)?;
        decode_json(reply, "provision result")
    }

    pub fn start(&self, host: u64, token: &str) -> Result<StartResult, MxcError> {
        decode_json(
            self.with_input(self.exports.start, host, token.as_bytes())?,
            "start result",
        )
    }

    pub fn stop(&self, host: u64, token: &str) -> Result<StopResult, MxcError> {
        decode_json(
            self.with_input(self.exports.stop, host, token.as_bytes())?,
            "stop result",
        )
    }

    pub fn deprovision(&self, host: u64, token: &str) -> Result<DeprovisionResult, MxcError> {
        decode_json(
            self.with_input(self.exports.deprovision, host, token.as_bytes())?,
            "deprovision result",
        )
    }

    pub fn diagnostics(&self, host: u64, token: &str) -> Result<SandboxDiagnostics, MxcError> {
        decode_json(
            self.call_with_limit(
                |out, length| unsafe {
                    (self.exports.diagnostics)(host, token.as_ptr(), token.len(), out, length)
                },
                Some(64 * 1024),
            )?,
            "diagnostics",
        )
    }

    pub fn exec(&self, host: u64, token: &str, input: &ExecInput) -> Result<u64, MxcError> {
        let encoded = encode_json(input)?;
        let mut exec_handle = 0u64;
        self.call_empty("exec", |out, length| unsafe {
            (self.exports.exec)(
                host,
                token.as_ptr(),
                token.len(),
                encoded.as_ptr(),
                encoded.len(),
                &mut exec_handle,
                out,
                length,
            )
        })?;
        if exec_handle == 0 {
            return Err(MxcError::backend_error(
                "NVX signed bundled agent: the agent library returned an invalid zero execution handle",
            ));
        }
        Ok(exec_handle)
    }

    pub fn exec_next<T>(
        &self,
        exec: u64,
        timeout_ms: Option<u64>,
        deliver: impl FnOnce(Event<'_>) -> T,
    ) -> Result<Option<T>, MxcError> {
        let mut event = ExecEvent {
            kind: 0,
            data: ptr::null(),
            length: 0,
        };
        let timeout = timeout_ms.map_or(-1, |ms| i64::try_from(ms).unwrap_or(i64::MAX));
        match unsafe { (self.exports.exec_next)(exec, timeout, &mut event) } {
            STATUS_OK => {}
            STATUS_TIMEOUT => return Ok(None),
            other => return Err(status_error(other)),
        }
        let data = if event.length == 0 {
            &[][..]
        } else if event.data.is_null() {
            return Err(MxcError::backend_error(
                "NVX signed bundled agent: the agent library returned an execution event whose data is missing",
            ));
        } else {
            // SAFETY: the agent DLL keeps the event buffer valid until the next call on `exec`.
            unsafe { slice::from_raw_parts(event.data, event.length) }
        };
        match event.kind {
            EVENT_STDOUT => Ok(Some(deliver(Event::Stdout(data)))),
            EVENT_STDERR => Ok(Some(deliver(Event::Stderr(data)))),
            EVENT_EXIT => Ok(Some(deliver(Event::Exit(data)))),
            other => Err(MxcError::backend_error(format!(
                "NVX signed bundled agent: the agent library returned the unknown execution event {other}"
            ))),
        }
    }

    pub fn exec_cancel(&self, exec: u64) -> Result<(), MxcError> {
        self.call_empty("exec_cancel", |out, length| unsafe {
            (self.exports.exec_cancel)(exec, out, length)
        })
    }

    pub fn exec_release(&self, exec: u64) -> Result<(), MxcError> {
        let status = unsafe { (self.exports.exec_release)(exec) };
        match status {
            STATUS_OK => Ok(()),
            other => Err(status_error(other)),
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    #[test]
    fn open_for_load_blocks_writers_deletes_and_renames() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("agent");
        fs::create_dir(&directory).unwrap();
        let dll_path = directory.join("aci_edge_agent.dll");
        fs::write(&dll_path, b"verified-dll-bytes").unwrap();

        let lock_file = open_for_load(&dll_path).unwrap();
        assert!(OpenOptions::new().write(true).open(&dll_path).is_err());
        assert!(fs::remove_file(&dll_path).is_err());
        assert!(fs::rename(&dll_path, directory.join("renamed.dll")).is_err());
        assert!(fs::rename(&directory, root.path().join("renamed-dir")).is_err());

        drop(lock_file);
        fs::rename(&directory, root.path().join("renamed-dir")).unwrap();
    }

    #[test]
    fn load_verified_rejects_relative_missing_and_mismatched_digest_before_load() {
        let relative = AgentLibrary::load_verified(Path::new("relative.dll"), &"0".repeat(64));
        assert_eq!(relative.unwrap_err().code, MxcErrorCode::BackendUnavailable);

        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing.dll");
        assert_eq!(
            AgentLibrary::load_verified(&missing, &"0".repeat(64))
                .unwrap_err()
                .code,
            MxcErrorCode::BackendUnavailable
        );

        let fake_dll = root.path().join("not_a_pe.dll");
        fs::write(&fake_dll, b"not a valid PE image").unwrap();
        let err = AgentLibrary::load_verified(&fake_dll, &"0".repeat(64)).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::BackendUnavailable);
        assert!(err.message.contains("does not match the approved SHA-256"));
    }

    #[test]
    fn wire_types_round_trip_with_exact_contract_casing() {
        let setup = SetupConfig {
            schema_version: 1,
            state_root: PathBuf::from(r"C:\state"),
            runtime: RuntimeSource {
                bundle: BundleSource {
                    path: PathBuf::from(r"C:\bundle"),
                    manifest_sha256: "d5".repeat(32),
                },
            },
        };
        let setup_json = serde_json::to_value(&setup).unwrap();
        assert_eq!(setup_json["schemaVersion"], 1);
        assert_eq!(setup_json["stateRoot"], r"C:\state");
        assert_eq!(setup_json["runtime"]["bundle"]["path"], r"C:\bundle");
        assert_eq!(
            setup_json["runtime"]["bundle"]["manifestSha256"],
            "d5".repeat(32)
        );

        let prov = ProvisionInput {
            request: ProvisionRequest {},
            spec: SandboxSpec {
                image: Some(ImageSource::Reference(
                    "mcr.microsoft.com/azurelinux/base/core:3.0".to_owned(),
                )),
            },
        };
        assert_eq!(
            serde_json::to_string(&prov).unwrap(),
            r#"{"request":{},"spec":{"image":{"reference":"mcr.microsoft.com/azurelinux/base/core:3.0"}}}"#
        );

        for (outcome, text) in [
            (ExecOutcome::Exited(42), r#"{"exited":42}"#),
            (ExecOutcome::Signaled(9), r#"{"signaled":9}"#),
            (ExecOutcome::TimedOut, r#""timedOut""#),
            (ExecOutcome::Cancelled, r#""cancelled""#),
            (
                ExecOutcome::Failed(ExecFailure::WorkingDirectory),
                r#"{"failed":"workingDirectory"}"#,
            ),
        ] {
            assert_eq!(serde_json::to_string(&outcome).unwrap(), text);
            assert_eq!(serde_json::from_str::<ExecOutcome>(text).unwrap(), outcome);
        }
    }
}
