// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Step 1c — start a ProjFS virtualization instance with a tiny synthetic
//! namespace and prove the launching user can read + enumerate through it.
//!
//! The synthetic layout is intentionally trivial so the callback set we have
//! to implement here is minimal but complete:
//!
//! ```text
//!   <root>/
//!     hello.txt        ("hello from projfs\n")
//!     subdir/
//!       inner.txt      ("inner content\n")
//! ```
//!
//! Only five callbacks are required for a functioning provider:
//! `StartDirectoryEnumeration`, `EndDirectoryEnumeration`,
//! `GetDirectoryEnumeration`, `GetPlaceholderInfo`, and `GetFileData`.
//! The optional `Notification`, `QueryFileName`, and `CancelCommand`
//! callbacks are left null — adding them comes later (step 2, RO/RW + reparse
//! refusal in the real provider).
//!
//! Threading model: ProjFS dispatches callbacks on its own worker pool, so
//! all per-instance state lives behind a `Mutex` in a `OnceLock`. Per-
//! enumeration cursor state is keyed by the enumeration GUID we receive in
//! `StartDirectoryEnumeration`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use serde::Serialize;

use windows::core::{GUID, HRESULT, PCWSTR};
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, S_OK};
use windows::Win32::Storage::ProjectedFileSystem::{
    PrjAllocateAlignedBuffer, PrjFileNameCompare, PrjFileNameMatch, PrjFillDirEntryBuffer,
    PrjFreeAlignedBuffer, PrjMarkDirectoryAsPlaceholder, PrjStartVirtualizing, PrjStopVirtualizing,
    PrjWriteFileData, PrjWritePlaceholderInfo, PRJ_CALLBACKS, PRJ_CALLBACK_DATA,
    PRJ_CB_DATA_FLAG_ENUM_RESTART_SCAN, PRJ_DIR_ENTRY_BUFFER_HANDLE, PRJ_FILE_BASIC_INFO,
    PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT, PRJ_PLACEHOLDER_INFO,
};

// FILE_ATTRIBUTE_NORMAL / FILE_ATTRIBUTE_DIRECTORY — the windows crate's
// FileSystem feature would also bring these in, but we don't want to take
// the whole module just for two u32 constants.
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;

/// One entry in the synthetic namespace.
struct Entry {
    /// Path relative to the virt root, with `\` separators. Empty string is the root.
    rel_path: &'static str,
    /// Parent directory's `rel_path` ("" for children of the root).
    parent: &'static str,
    /// Final path component as the AC / NTFS sees it.
    name: &'static str,
    kind: EntryKind,
}

#[derive(Clone, Copy)]
enum EntryKind {
    Dir,
    File(&'static [u8]),
}

static LAYOUT: &[Entry] = &[
    Entry {
        rel_path: "hello.txt",
        parent: "",
        name: "hello.txt",
        kind: EntryKind::File(b"hello from projfs\n"),
    },
    Entry {
        rel_path: "subdir",
        parent: "",
        name: "subdir",
        kind: EntryKind::Dir,
    },
    Entry {
        rel_path: "subdir\\inner.txt",
        parent: "subdir",
        name: "inner.txt",
        kind: EntryKind::File(b"inner content\n"),
    },
];

/// Per-enumeration cursor.
struct EnumState {
    /// Children of the directory being enumerated, sorted via `PrjFileNameCompare`.
    children: Vec<&'static Entry>,
    /// Next index into `children` to deliver.
    cursor: usize,
    /// Optional wildcard search expression supplied by the kernel.
    pattern: Option<Vec<u16>>,
}

#[derive(Default)]
struct ProviderState {
    enumerations: HashMap<u128, EnumState>,
}

fn state() -> &'static Mutex<ProviderState> {
    static S: OnceLock<Mutex<ProviderState>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(ProviderState::default()))
}

fn guid_to_u128(g: &GUID) -> u128 {
    // Pack the 16 raw bytes. We don't care about Windows' on-the-wire layout —
    // we just need a stable Hash + Eq key for the duration of an enumeration.
    let mut bytes = [0u8; 16];
    bytes[0..4].copy_from_slice(&g.data1.to_le_bytes());
    bytes[4..6].copy_from_slice(&g.data2.to_le_bytes());
    bytes[6..8].copy_from_slice(&g.data3.to_le_bytes());
    bytes[8..16].copy_from_slice(&g.data4);
    u128::from_le_bytes(bytes)
}

unsafe fn pcwstr_to_string(p: PCWSTR) -> String {
    if p.0.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while *p.0.add(len) != 0 {
        len += 1;
        if len > 32_768 {
            break;
        }
    }
    let slice = std::slice::from_raw_parts(p.0, len);
    String::from_utf16_lossy(slice)
}

fn to_wide_z(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn lookup(rel_path: &str) -> Option<&'static Entry> {
    // PrjFileNameCompare is case-insensitive but locale-aware; for static
    // ASCII paths a plain eq_ignore_ascii_case match is correct and saves us
    // a Win32 call inside the hot lookup path.
    LAYOUT
        .iter()
        .find(|e| e.rel_path.eq_ignore_ascii_case(rel_path))
}

fn children_of(parent: &str) -> Vec<&'static Entry> {
    let mut v: Vec<&'static Entry> = LAYOUT
        .iter()
        .filter(|e| e.parent.eq_ignore_ascii_case(parent))
        .collect();
    // Sort with PrjFileNameCompare to match what NTFS would deliver.
    v.sort_by(|a, b| {
        let aw = to_wide_z(a.name);
        let bw = to_wide_z(b.name);
        let c = unsafe { PrjFileNameCompare(PCWSTR(aw.as_ptr()), PCWSTR(bw.as_ptr())) };
        c.cmp(&0)
    });
    v
}

// -------------------------------------------------------------------------
// Callbacks
// -------------------------------------------------------------------------

unsafe extern "system" fn cb_start_enum(
    callback_data: *const PRJ_CALLBACK_DATA,
    enumeration_id: *const GUID,
) -> HRESULT {
    let data = &*callback_data;
    let parent = pcwstr_to_string(data.FilePathName);
    let key = guid_to_u128(&*enumeration_id);
    let mut st = state().lock().unwrap();
    st.enumerations.insert(
        key,
        EnumState {
            children: children_of(&parent),
            cursor: 0,
            pattern: None,
        },
    );
    S_OK
}

unsafe extern "system" fn cb_end_enum(
    _callback_data: *const PRJ_CALLBACK_DATA,
    enumeration_id: *const GUID,
) -> HRESULT {
    let key = guid_to_u128(&*enumeration_id);
    state().lock().unwrap().enumerations.remove(&key);
    S_OK
}

unsafe extern "system" fn cb_get_enum(
    callback_data: *const PRJ_CALLBACK_DATA,
    enumeration_id: *const GUID,
    search_expression: PCWSTR,
    dir_entry_buffer: PRJ_DIR_ENTRY_BUFFER_HANDLE,
) -> HRESULT {
    let data = &*callback_data;
    let key = guid_to_u128(&*enumeration_id);
    let mut st = state().lock().unwrap();
    let Some(es) = st.enumerations.get_mut(&key) else {
        return HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0);
    };

    // Kernel may restart an existing enumeration mid-flight (e.g. caller
    // called FindFirstFile + FindClose + FindFirstFile on the same handle).
    let flags = data.Flags;
    if flags.0 & PRJ_CB_DATA_FLAG_ENUM_RESTART_SCAN.0 != 0 {
        es.cursor = 0;
        // The pattern is only meaningful at restart; on subsequent calls the
        // kernel re-sends the same pattern, but we cache it on first sight.
        if !search_expression.0.is_null() {
            es.pattern = Some(to_wide_z(&pcwstr_to_string(search_expression)));
        } else {
            es.pattern = None;
        }
    } else if es.pattern.is_none() && !search_expression.0.is_null() {
        es.pattern = Some(to_wide_z(&pcwstr_to_string(search_expression)));
    }

    // Snapshot the pattern PCWSTR so we don't reborrow `es` inside the loop.
    let pattern_ptr = es
        .pattern
        .as_ref()
        .map(|p| PCWSTR(p.as_ptr()))
        .unwrap_or(PCWSTR::null());

    while es.cursor < es.children.len() {
        let entry = es.children[es.cursor];
        let name_w = to_wide_z(entry.name);
        let name_pcwstr = PCWSTR(name_w.as_ptr());

        let matches = if pattern_ptr.0.is_null() {
            true
        } else {
            PrjFileNameMatch(name_pcwstr, pattern_ptr)
        };

        if matches {
            let basic = file_basic_info(entry);
            let r = PrjFillDirEntryBuffer(name_pcwstr, Some(&basic), dir_entry_buffer);
            match r {
                Ok(()) => { /* fall through, advance cursor */ }
                Err(e) if e.code() == HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0) => {
                    // Buffer full; do NOT advance cursor — kernel will call
                    // back for the next slot. Tell it we delivered what we
                    // could.
                    return S_OK;
                }
                Err(e) => return e.code(),
            }
        }
        es.cursor += 1;
    }
    S_OK
}

unsafe extern "system" fn cb_get_placeholder_info(
    callback_data: *const PRJ_CALLBACK_DATA,
) -> HRESULT {
    let data = &*callback_data;
    let rel = pcwstr_to_string(data.FilePathName);

    let Some(entry) = lookup(&rel) else {
        return HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0);
    };

    let mut info = PRJ_PLACEHOLDER_INFO::default();
    info.FileBasicInfo = file_basic_info(entry);

    let dest = to_wide_z(&rel);
    let r = PrjWritePlaceholderInfo(
        data.NamespaceVirtualizationContext,
        PCWSTR(dest.as_ptr()),
        &info,
        std::mem::size_of::<PRJ_PLACEHOLDER_INFO>() as u32,
    );
    match r {
        Ok(()) => S_OK,
        Err(e) => e.code(),
    }
}

unsafe extern "system" fn cb_get_file_data(
    callback_data: *const PRJ_CALLBACK_DATA,
    byte_offset: u64,
    length: u32,
) -> HRESULT {
    let data = &*callback_data;
    let rel = pcwstr_to_string(data.FilePathName);

    let Some(entry) = lookup(&rel) else {
        return HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0);
    };
    let bytes = match entry.kind {
        EntryKind::File(b) => b,
        EntryKind::Dir => return HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0),
    };

    let start = byte_offset as usize;
    let end = (byte_offset as usize).saturating_add(length as usize);
    if start >= bytes.len() || end > bytes.len() {
        return HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0);
    }
    let slice = &bytes[start..end];

    let buf = PrjAllocateAlignedBuffer(data.NamespaceVirtualizationContext, length as usize);
    if buf.is_null() {
        return HRESULT::from_win32(windows::Win32::Foundation::ERROR_OUTOFMEMORY.0);
    }
    std::ptr::copy_nonoverlapping(slice.as_ptr(), buf as *mut u8, length as usize);

    let r = PrjWriteFileData(
        data.NamespaceVirtualizationContext,
        &data.DataStreamId,
        buf,
        byte_offset,
        length,
    );
    PrjFreeAlignedBuffer(buf);
    match r {
        Ok(()) => S_OK,
        Err(e) => e.code(),
    }
}

fn file_basic_info(entry: &Entry) -> PRJ_FILE_BASIC_INFO {
    let mut bi = PRJ_FILE_BASIC_INFO::default();
    match entry.kind {
        EntryKind::Dir => {
            bi.IsDirectory = true;
            bi.FileSize = 0;
            bi.FileAttributes = FILE_ATTRIBUTE_DIRECTORY;
        }
        EntryKind::File(b) => {
            bi.IsDirectory = false;
            bi.FileSize = b.len() as i64;
            bi.FileAttributes = FILE_ATTRIBUTE_NORMAL;
        }
    }
    bi
}

// -------------------------------------------------------------------------
// Public driver
// -------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub(crate) struct VirtStartReport {
    pub root_path: PathBuf,
    pub instance_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct SmokeReadReport {
    pub enumerated_names: Vec<String>,
    pub read_hello_txt: Option<String>,
    pub read_inner_txt: Option<String>,
    pub errors: Vec<String>,
}

/// RAII wrapper — stops virtualization on drop.
pub(crate) struct VirtSession {
    ctx: PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT,
    pub root: PathBuf,
}

impl Drop for VirtSession {
    fn drop(&mut self) {
        if !self.ctx.is_invalid() {
            unsafe { PrjStopVirtualizing(self.ctx) };
        }
    }
}

/// Prepare an empty placeholder directory at `root` and start virtualizing it.
pub(crate) fn start(root: &Path) -> Result<(VirtSession, VirtStartReport), String> {
    // 1. Make sure the root exists and is empty.
    if root.exists() {
        // Best-effort cleanup of any stale projection.
        let _ = std::fs::remove_dir_all(root);
    }
    std::fs::create_dir_all(root).map_err(|e| format!("create_dir_all({}): {e}", root.display()))?;

    // 2. Mark as placeholder.  Per the official sample / docs:
    //    new virt root  -> rootPathName = target, targetPathName = NULL
    //    descendant inside existing root -> rootPathName = existing root,
    //                                       targetPathName = descendant
    let target = to_wide_z(&root.to_string_lossy());
    let instance_id = GUID::new().map_err(|e| format!("GUID::new: {e}"))?;
    unsafe {
        PrjMarkDirectoryAsPlaceholder(PCWSTR(target.as_ptr()), PCWSTR::null(), None, &instance_id)
            .map_err(|e| format!("PrjMarkDirectoryAsPlaceholder: {e} (0x{:08x})", e.code().0))?;
    }

    // 3. Build callback table and start virtualizing.
    let callbacks = PRJ_CALLBACKS {
        StartDirectoryEnumerationCallback: Some(cb_start_enum),
        EndDirectoryEnumerationCallback: Some(cb_end_enum),
        GetDirectoryEnumerationCallback: Some(cb_get_enum),
        GetPlaceholderInfoCallback: Some(cb_get_placeholder_info),
        GetFileDataCallback: Some(cb_get_file_data),
        QueryFileNameCallback: None,
        NotificationCallback: None,
        CancelCommandCallback: None,
    };

    let ctx = unsafe {
        PrjStartVirtualizing(PCWSTR(target.as_ptr()), &callbacks, None, None)
            .map_err(|e| format!("PrjStartVirtualizing: {e} (0x{:08x})", e.code().0))?
    };

    let report = VirtStartReport {
        root_path: root.to_path_buf(),
        instance_id: format!("{:?}", instance_id),
    };
    Ok((VirtSession { ctx, root: root.to_path_buf() }, report))
}

/// Launching-user smoke test against the projected namespace.
pub(crate) fn smoke_read_as_launching_user(session: &VirtSession) -> SmokeReadReport {
    let mut errs = Vec::new();

    let enumerated_names = match std::fs::read_dir(&session.root) {
        Ok(rd) => rd
            .filter_map(|r| r.ok())
            .map(|d| d.file_name().to_string_lossy().into_owned())
            .collect(),
        Err(e) => {
            errs.push(format!("read_dir(root): {e}"));
            Vec::new()
        }
    };

    let read_hello_txt = match std::fs::read(session.root.join("hello.txt")) {
        Ok(b) => Some(String::from_utf8_lossy(&b).into_owned()),
        Err(e) => {
            errs.push(format!("read hello.txt: {e}"));
            None
        }
    };

    let read_inner_txt = match std::fs::read(session.root.join("subdir").join("inner.txt")) {
        Ok(b) => Some(String::from_utf8_lossy(&b).into_owned()),
        Err(e) => {
            errs.push(format!("read subdir\\inner.txt: {e}"));
            None
        }
    };

    SmokeReadReport {
        enumerated_names,
        read_hello_txt,
        read_inner_txt,
        errors: errs,
    }
}
