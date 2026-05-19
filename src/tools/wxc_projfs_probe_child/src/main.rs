// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AppContainer-side half of the ProjFS-T3 step-1d spike.
//!
//! Spawned by `wxc-projfs-probe` with two arguments:
//!   --root <virt-root-path>   the projected directory to exercise
//!   --pipe <\\.\pipe\name>    where to write the JSON outcome
//!
//! Performs four operations exhaustively, capturing GetLastError on every
//! failure so the parent can attribute it precisely:
//!
//!   1. Enumerate the root      (FindFirstFileW / FindNextFileW on `\*`)
//!   2. Read hello.txt          (CreateFileW + ReadFile)
//!   3. Enumerate subdir        (FindFirstFileW / FindNextFileW on subdir\*)
//!   4. Read subdir\inner.txt
//!
//! Writes a single JSON document to the pipe and exits. Exit code is 0 even
//! on per-op failure — the parent inspects the JSON.

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
    CreateFileW, FindClose, FindFirstFileW, FindNextFileW, ReadFile, FILE_ATTRIBUTE_NORMAL,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, WIN32_FIND_DATAW,
};

#[derive(Debug, Default, Serialize)]
struct ChildReport {
    schema: &'static str,
    arg_root: String,
    arg_pipe: String,
    enum_root: EnumResult,
    read_hello: ReadResult,
    enum_subdir: EnumResult,
    read_inner: ReadResult,
}

#[derive(Debug, Default, Serialize)]
struct EnumResult {
    succeeded: bool,
    entries: Vec<String>,
    /// GetLastError captured at the moment of failure.
    last_error: Option<u32>,
    /// Which call failed if `succeeded == false`.
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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut root: Option<PathBuf> = None;
    let mut pipe: Option<String> = None;
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
            _ => i += 1,
        }
    }

    let root = root.expect("--root required");
    let pipe = pipe.expect("--pipe required");

    let mut report = ChildReport {
        schema: "projfs-probe-child/0.1",
        arg_root: root.to_string_lossy().into_owned(),
        arg_pipe: pipe.clone(),
        ..Default::default()
    };

    report.enum_root = enumerate(&root);
    report.read_hello = read_file(&root.join("hello.txt"));
    report.enum_subdir = enumerate(&root.join("subdir"));
    report.read_inner = read_file(&root.join("subdir").join("inner.txt"));

    let json = serde_json::to_string_pretty(&report).unwrap_or_else(|e| {
        format!("{{\"error\":\"json serialization: {e}\"}}")
    });
    write_to_pipe(&pipe, &json);
}

fn to_wide_z(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
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
            // Partial enumeration — capture and report.
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

fn wide_to_string(s: &[u16]) -> String {
    let len = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    String::from_utf16_lossy(&s[..len])
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
    let ok = unsafe {
        ReadFile(
            handle,
            Some(&mut buf),
            Some(&mut read),
            None,
        )
    };
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
    // Pipe is opened by name like a file. The parent created it; we connect
    // and write JSON. CreateFileW with OPEN_EXISTING is the documented
    // client-side primitive.
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
        // Fall back to stderr so the parent at least sees something on the
        // wait side. Exit cleanly so the parent observes a normal exit.
        eprintln!(
            "wxc-projfs-probe-child: pipe open failed (Win32 {}): could not deliver {} bytes",
            unsafe { GetLastError().0 },
            payload.len()
        );
        return;
    };

    // Wrap in a File for ergonomic write.
    let mut f = unsafe { File::from_raw_handle(handle.0 as *mut c_void) };
    let _ = f.write_all(payload.as_bytes());
    let _ = f.flush();
    // Dropping f closes the handle, signalling EOF to the parent.
}
