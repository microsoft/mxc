// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Consumer-side captureDenials logic for the native E2E tests.
//!
//! Since the SDK no longer ships a learning-mode wrapper, a captureDenials
//! consumer drives `wxc-exec` directly and owns:
//!   * parsing the `0x1E`-framed NDJSON denial stream (off stderr in pipe mode,
//!     or off the `MXC_DENIALS_PIPE` named pipe in console/PTY mode),
//!   * filtering OS background noise,
//!   * folding approved denials into an expanded filesystem policy, and
//!   * (PTY mode) standing up the named-pipe server + pseudoconsole.
//!
//! This module is a faithful Rust port of that contract, exercised by
//! `tests/e2e_windows_capture_denials.rs`. It is intentionally test-only and
//! Windows-only.

use serde::Deserialize;

/// ASCII Record Separator that prefixes every captureDenials envelope line.
pub const DENIAL_STREAM_MARKER: u8 = 0x1E;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// One denied access, as carried on the wire (`type:"denial"`).
#[derive(Debug, Clone, Deserialize)]
pub struct DeniedResource {
    pub path: String,
    #[serde(rename = "resourceType", default)]
    pub resource_type: String,
    #[serde(rename = "accessType", default)]
    pub access_type: String,
    #[serde(default)]
    pub pid: u64,
    #[serde(default)]
    pub filetime: u64,
}

/// The stream terminator (`type:"summary"`).
#[derive(Debug, Clone, Deserialize)]
pub struct DenialSummary {
    #[serde(rename = "exitCode")]
    pub exit_code: i64,
    #[serde(rename = "totalDenials")]
    pub total_denials: u64,
    #[serde(rename = "captureDenialsActive")]
    pub capture_denials_active: bool,
    #[serde(rename = "deniedResourcesTruncated", default)]
    pub denied_resources_truncated: bool,
    #[serde(rename = "childProcessesObserved", default)]
    pub child_processes_observed: u64,
    #[serde(rename = "descendantPidsCovered", default)]
    pub descendant_pids_covered: u64,
    #[serde(rename = "deniedResources", default)]
    pub denied_resources: Vec<DeniedResource>,
}

/// Result of draining a denial stream.
#[derive(Debug, Default)]
pub struct ParseResult {
    /// Filtered, in-order denial records.
    pub denials: Vec<DeniedResource>,
    /// The terminator summary, if one was seen.
    pub summary: Option<DenialSummary>,
    /// Envelopes that started with `0x1E` but failed to parse as JSON.
    pub parse_errors: usize,
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Strip the `\??\` NT DOS-device prefix so paths surface as `C:\…`.
pub fn strip_nt_prefix(path: &str) -> &str {
    path.strip_prefix(r"\??\").unwrap_or(path)
}

fn ci_eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn ci_starts_with(hay: &str, prefix: &str) -> bool {
    hay.len() >= prefix.len() && ci_eq(&hay[..prefix.len()], prefix)
}

fn ci_ends_with(hay: &str, suffix: &str) -> bool {
    hay.len() >= suffix.len() && ci_eq(&hay[hay.len() - suffix.len()..], suffix)
}

/// The two default noise filters the removed SDK applied: drop the
/// AppContainer-default `\REGISTRY\USER\.DEFAULT\` probes and the OS loader's
/// System32 DLL/MUI/etc. searches every sandboxed process trips. Returns
/// `true` to keep the record.
pub fn passes_default_filters(r: &DeniedResource) -> bool {
    if ci_starts_with(&r.path, r"\REGISTRY\USER\.DEFAULT\") {
        return false;
    }
    let p = strip_nt_prefix(&r.path);
    if ci_starts_with(p, r"C:\Windows\System32\") {
        for ext in [".dll", ".mui", ".mun", ".cat", ".cdf-ms", ".nls"] {
            if ci_ends_with(p, ext) {
                return false;
            }
        }
    }
    true
}

fn envelopes(bytes: &[u8]) -> Vec<&[u8]> {
    // Each envelope is `\x1e<json>\n`. The workload's own stdio writes never
    // contain 0x1E, so splitting on the marker reliably demuxes MXC envelopes
    // from interleaved workload output.
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == DENIAL_STREAM_MARKER {
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && bytes[j] != b'\n' {
                j += 1;
            }
            out.push(&bytes[start..j]);
            i = j + 1;
        } else {
            i += 1;
        }
    }
    out
}

/// Parse a captured denial stream. `apply_default_filters` mirrors the SDK's
/// default noise filtering; pass `false` for the raw stream.
pub fn parse_denial_stream(bytes: &[u8], apply_default_filters: bool) -> ParseResult {
    let mut result = ParseResult::default();
    for env in envelopes(bytes) {
        let value: serde_json::Value = match serde_json::from_slice(env) {
            Ok(v) => v,
            Err(_) => {
                result.parse_errors += 1;
                continue;
            }
        };
        match value.get("type").and_then(|t| t.as_str()) {
            Some("denial") => match serde_json::from_value::<DeniedResource>(value) {
                Ok(d) => {
                    if !apply_default_filters || passes_default_filters(&d) {
                        result.denials.push(d);
                    }
                }
                Err(_) => result.parse_errors += 1,
            },
            Some("summary") => match serde_json::from_value::<DenialSummary>(value) {
                Ok(s) => result.summary = Some(s),
                Err(_) => result.parse_errors += 1,
            },
            _ => result.parse_errors += 1,
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Policy expansion (the consent step a consumer owns)
// ---------------------------------------------------------------------------

fn norm_key(p: &str) -> String {
    p.trim_end_matches(['\\', '/']).to_ascii_lowercase()
}

/// Paths the expand step refuses to grant even when "approved" — granting these
/// would punch holes in OS security boundaries. Mirrors the removed SDK's
/// `SYSTEM_CRITICAL_PATTERNS` (filesystem subset).
fn is_system_critical(path: &str) -> bool {
    // Anything still carrying an NT device prefix after strip is refused.
    if ci_starts_with(path, r"\??\") || ci_starts_with(path, r"\Device\") {
        return true;
    }
    for sub in [
        r"C:\Windows\System32\",
        r"C:\Windows\SysWOW64\",
        r"C:\Windows\WinSxS\",
        r"C:\Windows\Boot\",
        r"C:\Windows\Resources\",
        r"C:\Windows\Fonts\",
        r"C:\Windows\servicing\",
        r"C:\Windows\Microsoft.NET\",
    ] {
        if ci_starts_with(path, sub) {
            return true;
        }
    }
    // Drive-rooted boot/system files and the recycle bin.
    if path.len() >= 3 && path.as_bytes()[1] == b':' && path.as_bytes()[2] == b'\\' {
        let rest = &path[3..];
        for name in [
            "bootmgr",
            "BOOTNXT",
            "pagefile.sys",
            "hiberfil.sys",
            "swapfile.sys",
        ] {
            if ci_eq(rest, name) {
                return true;
            }
        }
        if ci_starts_with(rest, r"$Recycle.Bin\") {
            return true;
        }
    }
    false
}

/// Outcome of folding approved denials into a policy's readonly grants.
#[derive(Debug, Default)]
pub struct ExpandResult {
    /// The resulting `readonlyPaths`, additively expanded.
    pub readonly_paths: Vec<String>,
    /// Paths newly granted this round (NT-prefix stripped, trailing-sep folded).
    pub added: Vec<String>,
    /// Paths refused (system-critical) or already present.
    pub skipped: Vec<String>,
}

/// Additively expand `readonly_paths` with the approved denials. Never removes
/// an existing grant. System-critical paths are refused. Each approved path is
/// NT-prefix stripped and trailing-separator folded before granting.
pub fn expand_readonly_paths(
    readonly_paths: &[String],
    readwrite_paths: &[String],
    approved: &[DeniedResource],
) -> ExpandResult {
    let mut out = ExpandResult {
        readonly_paths: readonly_paths.to_vec(),
        ..Default::default()
    };
    let mut have: std::collections::HashSet<String> = readonly_paths
        .iter()
        .chain(readwrite_paths.iter())
        .map(|p| norm_key(p))
        .collect();

    for d in approved {
        let path = strip_nt_prefix(&d.path)
            .trim_end_matches(['\\', '/'])
            .to_string();
        if is_system_critical(&path) {
            out.skipped.push(path);
            continue;
        }
        if have.contains(&norm_key(&path)) {
            out.skipped.push(path);
            continue;
        }
        have.insert(norm_key(&path));
        out.readonly_paths.push(path.clone());
        out.added.push(path);
    }
    out
}

/// Case-insensitive "is `candidate` the target dir, the target file, or under
/// the target dir" — the consumer's relevance check for a captured denial.
pub fn matches_subtree(candidate: &str, target_file: &str, target_dir: &str) -> bool {
    let got = norm_key(strip_nt_prefix(candidate));
    let file = norm_key(target_file);
    let dir = norm_key(target_dir);
    got == file || got == dir || got.starts_with(&format!("{dir}\\"))
}

// ---------------------------------------------------------------------------
// Windows transport: named-pipe server + pseudoconsole (PTY) spawn
// ---------------------------------------------------------------------------

mod win {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows::Win32::Storage::FileSystem::{ReadFile, PIPE_ACCESS_INBOUND};
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
        PIPE_TYPE_BYTE, PIPE_WAIT,
    };

    fn wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// A one-shot inbound named-pipe server that accepts a single client and
    /// reads everything it writes until the client disconnects.
    pub struct DenialPipeServer {
        pub base_name: String,
        reader: Option<JoinHandle<Vec<u8>>>,
    }

    impl DenialPipeServer {
        /// Create the pipe and start accepting on a background thread. The
        /// returned `base_name` is what `MXC_DENIALS_PIPE` should be set to
        /// (no `\\.\pipe\` prefix — wxc-exec prepends it).
        pub fn start() -> std::io::Result<Self> {
            let base_name = format!("mxc-denials-{}", uuid::Uuid::new_v4().simple());
            let full = format!(r"\\.\pipe\{base_name}");
            let wname = wide(&full);

            // Create synchronously so the pipe exists before the child opens it.
            let handle = unsafe {
                CreateNamedPipeW(
                    PCWSTR(wname.as_ptr()),
                    PIPE_ACCESS_INBOUND,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                    1,
                    0,
                    64 * 1024,
                    0,
                    None,
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                return Err(std::io::Error::last_os_error());
            }

            let raw = handle.0 as isize;
            let reader = std::thread::spawn(move || read_pipe_to_end(HANDLE(raw as *mut c_void)));

            Ok(Self {
                base_name,
                reader: Some(reader),
            })
        }

        /// Wait up to `timeout` for the client to connect, write, and
        /// disconnect, then return everything it wrote. If no client ever
        /// connects (e.g. wxc-exec fell back to stderr), a self-connect kick
        /// releases the pending accept so this never blocks indefinitely.
        pub fn join_timeout(mut self, timeout: Duration) -> Vec<u8> {
            let Some(reader) = self.reader.take() else {
                return Vec::new();
            };
            let deadline = Instant::now() + timeout;
            while !reader.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(50));
            }
            if !reader.is_finished() {
                // Connect to our own pipe as a write client to release a
                // pending ConnectNamedPipe, then immediately drop it so the
                // reader observes EOF.
                let full = format!(r"\\.\pipe\{}", self.base_name);
                let _ = std::fs::OpenOptions::new().write(true).open(&full);
            }
            reader.join().unwrap_or_default()
        }
    }

    fn read_pipe_to_end(handle: HANDLE) -> Vec<u8> {
        let mut collected = Vec::new();
        unsafe {
            // Wait for the client (wxc-exec) to connect. ERROR_PIPE_CONNECTED
            // means it connected between Create and Connect — also success.
            if let Err(e) = ConnectNamedPipe(handle, None) {
                if e.code() != ERROR_PIPE_CONNECTED.to_hresult() {
                    let _ = CloseHandle(handle);
                    return collected;
                }
            }

            let mut buf = [0u8; 8192];
            loop {
                let mut read = 0u32;
                match ReadFile(handle, Some(&mut buf), Some(&mut read), None) {
                    Ok(()) => {
                        if read == 0 {
                            break;
                        }
                        collected.extend_from_slice(&buf[..read as usize]);
                    }
                    Err(_) => {
                        // Broken pipe is the normal client-closed signal.
                        break;
                    }
                }
            }
            let _ = DisconnectNamedPipe(handle);
            let _ = CloseHandle(handle);
        }
        collected
    }
}

pub use win::DenialPipeServer;
