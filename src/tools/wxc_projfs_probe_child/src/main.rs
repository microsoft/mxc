// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AppContainer-side half of the ProjFS-T3 spike.
//!
//! Two modes:
//!
//! Step-1 mode (default, no `--check-dir`):
//!   enumerate the root + subdir, read `hello.txt` + `subdir/inner.txt`.
//!   Preserved for backward-compat with the step-1 findings.
//!
//! Step-2 mode (`--check-dir <name>`, repeatable):
//!   For each named branch under `--root`, run the two probes from
//!   `Test-PathEnumeration.ps1`:
//!     A. stat by name      `<root>\<name>\readme.txt`  -> VISIBLE | HIDDEN
//!     B. enumerate         `<root>\<name>\*`            -> ENUMERABLE entries[] | BLOCKED | EMPTY
//!
//! Always writes a JSON document to the named pipe and exits with code 0.

#![cfg(target_os = "windows")]

use std::ffi::c_void;
use std::fs::File;
use std::io::Write;
use std::os::windows::io::FromRawHandle;
use std::path::PathBuf;

use serde::Serialize;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_NO_MORE_FILES, GENERIC_READ, GENERIC_WRITE,
    INVALID_HANDLE_VALUE,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FindClose, FindFirstFileW, FindNextFileW, GetFileAttributesW, ReadFile, WriteFile,
    CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    INVALID_FILE_ATTRIBUTES, OPEN_EXISTING, WIN32_FIND_DATAW,
};

#[derive(Debug, Default, Serialize)]
struct ChildReport {
    schema: &'static str,
    arg_root: String,
    arg_pipe: String,
    /// Step-1-style fixed-target fields (only populated when no --check-dir).
    enum_root: Option<EnumResult>,
    read_hello: Option<ReadResult>,
    enum_subdir: Option<EnumResult>,
    read_inner: Option<ReadResult>,
    /// Step-2-style per-branch matrix probes.
    per_dir: Vec<DirProbe>,
    /// Step-2c write probes.
    write_probes: Vec<WriteProbe>,
}

#[derive(Debug, Default, Serialize)]
struct EnumResult {
    succeeded: bool,
    entries: Vec<String>,
    last_error: Option<u32>,
    failing_call: Option<&'static str>,
}

#[derive(Debug, Default, Serialize)]
struct ReadResult {
    succeeded: bool,
    content: Option<String>,
    bytes_read: Option<u32>,
    last_error: Option<u32>,
    failing_call: Option<&'static str>,
}

#[derive(Debug, Serialize)]
struct DirProbe {
    /// Branch name as a relative dir under arg_root.
    name: String,
    /// "VISIBLE" | "HIDDEN" — does `GetFileAttributesW` on
    /// `<root>\<name>\readme.txt` succeed?
    exist: ExistResult,
    /// "ENUMERABLE" | "BLOCKED" | "EMPTY"
    list: ListResult,
}

#[derive(Debug, Serialize)]
struct ExistResult {
    state: &'static str, // "VISIBLE" | "HIDDEN"
    attributes: Option<u32>,
    last_error: Option<u32>,
}

#[derive(Debug, Serialize)]
struct ListResult {
    state: &'static str, // "ENUMERABLE" | "BLOCKED" | "EMPTY"
    entries: Vec<String>,
    last_error: Option<u32>,
    failing_call: Option<&'static str>,
}

#[derive(Debug, Serialize)]
struct WriteProbe {
    /// Branch name (relative to arg_root).
    branch: String,
    /// Result of opening an existing file (`readme.txt`) for write +
    /// writing one byte. Demonstrates the "modify existing placeholder"
    /// path that ProjFS's PRE_CONVERT_TO_FULL notification can veto.
    modify_existing: WriteOpResult,
    /// Result of creating a new file (`probe-write-<pid>.txt`) under the
    /// branch and writing one byte. Documents the new-file-in-RO-branch
    /// limitation called out in virt.rs::cb_notification.
    create_new: WriteOpResult,
}

#[derive(Debug, Serialize)]
struct WriteOpResult {
    /// "SUCCEEDED" | "DENIED" | "OTHER_ERROR"
    state: &'static str,
    /// What we tried to open/create.
    target: String,
    last_error: Option<u32>,
    failing_call: Option<&'static str>,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut root: Option<PathBuf> = None;
    let mut pipe: Option<String> = None;
    let mut check_dirs: Vec<String> = Vec::new();
    let mut write_probes: Vec<String> = Vec::new();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--root" if i + 1 < args.len() => {
                root = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--pipe" if i + 1 < args.len() => {
                pipe = Some(args[i + 1].clone());
                i += 2;
            }
            "--check-dir" if i + 1 < args.len() => {
                check_dirs.push(args[i + 1].clone());
                i += 2;
            }
            "--write-probe" if i + 1 < args.len() => {
                write_probes.push(args[i + 1].clone());
                i += 2;
            }
            _ => i += 1,
        }
    }

    let root = root.expect("--root required");
    let pipe = pipe.expect("--pipe required");

    let mut report = ChildReport {
        schema: "projfs-probe-child/0.2",
        arg_root: root.to_string_lossy().into_owned(),
        arg_pipe: pipe.clone(),
        ..Default::default()
    };

    if check_dirs.is_empty() && write_probes.is_empty() {
        // Step-1 backward-compat mode.
        report.enum_root = Some(enumerate(&root));
        report.read_hello = Some(read_file(&root.join("hello.txt")));
        report.enum_subdir = Some(enumerate(&root.join("subdir")));
        report.read_inner = Some(read_file(&root.join("subdir").join("inner.txt")));
    } else {
        for d in &check_dirs {
            report.per_dir.push(probe_dir(&root, d));
        }
        for b in &write_probes {
            report.write_probes.push(probe_write(&root, b));
        }
    }

    let json = serde_json::to_string_pretty(&report)
        .unwrap_or_else(|e| format!("{{\"error\":\"json serialization: {e}\"}}"));
    write_to_pipe(&pipe, &json);
}

fn to_wide_z(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_to_string(s: &[u16]) -> String {
    let len = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    String::from_utf16_lossy(&s[..len])
}

/// Matrix probe A: stat `<root>\<name>\readme.txt`.
fn probe_exist(root: &std::path::Path, name: &str) -> ExistResult {
    let probe_target = root.join(name).join("readme.txt");
    let w = to_wide_z(&probe_target.to_string_lossy());
    let attrs = unsafe { GetFileAttributesW(PCWSTR(w.as_ptr())) };
    if attrs == INVALID_FILE_ATTRIBUTES {
        ExistResult {
            state: "HIDDEN",
            attributes: None,
            last_error: Some(unsafe { GetLastError().0 }),
        }
    } else {
        ExistResult {
            state: "VISIBLE",
            attributes: Some(attrs),
            last_error: None,
        }
    }
}

/// Matrix probe B: enumerate `<root>\<name>`.
fn probe_list(root: &std::path::Path, name: &str) -> ListResult {
    let er = enumerate(&root.join(name));
    if !er.succeeded {
        return ListResult {
            state: "BLOCKED",
            entries: er.entries,
            last_error: er.last_error,
            failing_call: er.failing_call,
        };
    }
    let state = if er.entries.is_empty() {
        "EMPTY"
    } else {
        "ENUMERABLE"
    };
    ListResult {
        state,
        entries: er.entries,
        last_error: None,
        failing_call: None,
    }
}

fn probe_dir(root: &std::path::Path, name: &str) -> DirProbe {
    DirProbe {
        name: name.to_string(),
        exist: probe_exist(root, name),
        list: probe_list(root, name),
    }
}

fn probe_write(root: &std::path::Path, branch: &str) -> WriteProbe {
    let modify_target = root.join(branch).join("readme.txt");
    let create_target = root
        .join(branch)
        .join(format!("probe-write-{}.txt", std::process::id()));
    WriteProbe {
        branch: branch.to_string(),
        modify_existing: do_modify(&modify_target),
        create_new: do_create(&create_target),
    }
}

/// Open an existing file with GENERIC_WRITE + write one byte. The
/// `OPEN_EXISTING` disposition is the right one for "modify existing
/// placeholder" — that's the path PRE_CONVERT_TO_FULL gates.
fn do_modify(path: &std::path::Path) -> WriteOpResult {
    let w = to_wide_z(&path.to_string_lossy());
    let h = unsafe {
        CreateFileW(
            PCWSTR(w.as_ptr()),
            GENERIC_WRITE.0,
            FILE_SHARE_MODE(0), // no sharing
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    };
    let handle = match h {
        Ok(h) if h != INVALID_HANDLE_VALUE => h,
        _ => {
            return classify_write_failure(path, "CreateFileW", unsafe { GetLastError().0 });
        }
    };

    let payload = b"X";
    let mut written = 0u32;
    let r = unsafe { WriteFile(handle, Some(payload), Some(&mut written), None) };
    let last_err = unsafe { GetLastError().0 };
    let _ = unsafe { CloseHandle(handle) };

    if r.is_err() {
        return classify_write_failure(path, "WriteFile", last_err);
    }
    WriteOpResult {
        state: "SUCCEEDED",
        target: path.to_string_lossy().into_owned(),
        last_error: None,
        failing_call: None,
    }
}

/// Create a brand-new file (CREATE_NEW) under the branch. See the comment
/// at `cb_notification` in virt.rs — new-file creation in an RO branch is
/// the known spike-scope limitation.
fn do_create(path: &std::path::Path) -> WriteOpResult {
    let w = to_wide_z(&path.to_string_lossy());
    let h = unsafe {
        CreateFileW(
            PCWSTR(w.as_ptr()),
            GENERIC_WRITE.0,
            FILE_SHARE_MODE(0),
            None,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    };
    let handle = match h {
        Ok(h) if h != INVALID_HANDLE_VALUE => h,
        _ => {
            return classify_write_failure(path, "CreateFileW", unsafe { GetLastError().0 });
        }
    };

    let payload = b"created\n";
    let mut written = 0u32;
    let r = unsafe { WriteFile(handle, Some(payload), Some(&mut written), None) };
    let last_err = unsafe { GetLastError().0 };
    let _ = unsafe { CloseHandle(handle) };

    if r.is_err() {
        return classify_write_failure(path, "WriteFile", last_err);
    }
    WriteOpResult {
        state: "SUCCEEDED",
        target: path.to_string_lossy().into_owned(),
        last_error: None,
        failing_call: None,
    }
}

fn classify_write_failure(path: &std::path::Path, call: &'static str, err: u32) -> WriteOpResult {
    // ERROR_ACCESS_DENIED = 5
    let state = if err == 5 { "DENIED" } else { "OTHER_ERROR" };
    WriteOpResult {
        state,
        target: path.to_string_lossy().into_owned(),
        last_error: Some(err),
        failing_call: Some(call),
    }
}

fn enumerate(dir: &std::path::Path) -> EnumResult {
    let pattern = dir.join("*");
    let w = to_wide_z(&pattern.to_string_lossy());
    let mut data: WIN32_FIND_DATAW = unsafe { std::mem::zeroed() };
    let h = unsafe { FindFirstFileW(PCWSTR(w.as_ptr()), &mut data) };
    let handle = match h {
        Ok(h) if h != INVALID_HANDLE_VALUE => h,
        Ok(_) | Err(_) => {
            return EnumResult {
                succeeded: false,
                last_error: Some(unsafe { GetLastError().0 }),
                failing_call: Some("FindFirstFileW"),
                ..Default::default()
            };
        }
    };

    let mut entries = Vec::new();
    loop {
        let name = wide_to_string(&data.cFileName);
        if name != "." && name != ".." {
            entries.push(name);
        }
        let ok = unsafe { FindNextFileW(handle, &mut data).is_ok() };
        if !ok {
            let err = unsafe { GetLastError().0 };
            if err == ERROR_NO_MORE_FILES.0 {
                break;
            }
            let _ = unsafe { FindClose(handle) };
            return EnumResult {
                succeeded: false,
                entries,
                last_error: Some(err),
                failing_call: Some("FindNextFileW"),
            };
        }
    }
    let _ = unsafe { FindClose(handle) };

    EnumResult {
        succeeded: true,
        entries,
        last_error: None,
        failing_call: None,
    }
}

fn read_file(path: &std::path::Path) -> ReadResult {
    let w = to_wide_z(&path.to_string_lossy());
    let h = unsafe {
        CreateFileW(
            PCWSTR(w.as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    };
    let handle = match h {
        Ok(h) if h != INVALID_HANDLE_VALUE => h,
        _ => {
            return ReadResult {
                succeeded: false,
                last_error: Some(unsafe { GetLastError().0 }),
                failing_call: Some("CreateFileW"),
                ..Default::default()
            };
        }
    };

    let mut buf = [0u8; 256];
    let mut read = 0u32;
    let ok = unsafe { ReadFile(handle, Some(&mut buf), Some(&mut read), None) };
    let _ = unsafe { CloseHandle(handle) };

    if ok.is_err() {
        return ReadResult {
            succeeded: false,
            last_error: Some(unsafe { GetLastError().0 }),
            failing_call: Some("ReadFile"),
            ..Default::default()
        };
    }

    let slice = &buf[..read as usize];
    ReadResult {
        succeeded: true,
        content: Some(String::from_utf8_lossy(slice).into_owned()),
        bytes_read: Some(read),
        last_error: None,
        failing_call: None,
    }
}

fn write_to_pipe(pipe: &str, payload: &str) {
    let w = to_wide_z(pipe);
    let h = unsafe {
        CreateFileW(
            PCWSTR(w.as_ptr()),
            GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    };
    let Ok(handle) = h else {
        eprintln!(
            "wxc-projfs-probe-child: pipe open failed (Win32 {}): could not deliver {} bytes",
            unsafe { GetLastError().0 },
            payload.len()
        );
        return;
    };

    let mut f = unsafe { File::from_raw_handle(handle.0 as *mut c_void) };
    let _ = f.write_all(payload.as_bytes());
    let _ = f.flush();
}
