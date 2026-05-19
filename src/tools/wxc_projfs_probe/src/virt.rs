// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Step 2 — ProjFS provider that projects **real host paths** into the
//! virtualization root.
//!
//! Built on top of step 1c's callback skeleton; replaces the static
//! synthetic layout with a [`Policy`] table mapping projected branch names
//! to host backing directories.
//!
//! Path model
//! ----------
//!
//! The projection root itself contains one entry per [`Branch`]:
//!
//! ```text
//!   <root>/
//!     rw/      ←  --rw <host-path>   (read-write)
//!     ro/      ←  --ro <host-path>   (read-only, enforced in step 2c)
//! ```
//!
//! When the AC child accesses `<root>\rw\foo\bar.txt`, callbacks resolve
//! the first component (`rw`) to its backing root and stat / read
//! `<host-root>\foo\bar.txt` directly. Paths that don't match any branch
//! return `ERROR_FILE_NOT_FOUND`, which is the mechanism by which
//! `deniedPaths` / paths-not-in-policy are kept invisible to the AC —
//! we simply do not project them.
//!
//! Threading model: unchanged from step 1. Callbacks run on ProjFS worker
//! threads; per-enumeration cursor state lives in a `Mutex<HashMap<GUID, …>>`.
//! Policy is registered once at `start()` time and read-only thereafter.
//!
//! Performance: every `GetFileData` call re-opens the host file. Production
//! would cache handles keyed by host path (with LRU eviction); for the
//! spike, simplicity > throughput.

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use serde::Serialize;

use windows::core::{GUID, HRESULT, PCWSTR};
use windows::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_OUTOFMEMORY, S_OK,
};
use windows::Win32::Storage::ProjectedFileSystem::{
    PrjAllocateAlignedBuffer, PrjFileNameCompare, PrjFileNameMatch, PrjFillDirEntryBuffer,
    PrjFreeAlignedBuffer, PrjMarkDirectoryAsPlaceholder, PrjStartVirtualizing, PrjStopVirtualizing,
    PrjWriteFileData, PrjWritePlaceholderInfo, PRJ_CALLBACKS, PRJ_CALLBACK_DATA,
    PRJ_CB_DATA_FLAG_ENUM_RESTART_SCAN, PRJ_DIR_ENTRY_BUFFER_HANDLE, PRJ_FILE_BASIC_INFO,
    PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT, PRJ_NOTIFICATION, PRJ_NOTIFICATION_FILE_PRE_CONVERT_TO_FULL,
    PRJ_NOTIFICATION_MAPPING, PRJ_NOTIFICATION_PARAMETERS, PRJ_NOTIFICATION_PRE_DELETE,
    PRJ_NOTIFICATION_PRE_RENAME, PRJ_NOTIFY_FILE_PRE_CONVERT_TO_FULL, PRJ_NOTIFY_PRE_DELETE,
    PRJ_NOTIFY_PRE_RENAME, PRJ_NOTIFY_TYPES, PRJ_PLACEHOLDER_INFO, PRJ_STARTVIRTUALIZING_OPTIONS,
};

const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;

// -------------------------------------------------------------------------
// Public types
// -------------------------------------------------------------------------

/// Read mode of a projected branch.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub(crate) enum BranchMode {
    /// Writes through to the host backing. (Spike: enforcement of the
    /// "through" part is step 2b — for now writes hydrate placeholders
    /// inside the projection and stay there.)
    ReadWrite,
    /// Read-only. RO enforcement via `PRJ_NOTIFY_FILE_PRE_CONVERT_TO_FULL`
    /// lands in step 2c; this commit only labels the intent.
    ReadOnly,
}

/// One mapped branch in the projection root.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Branch {
    /// Name as it appears as a directory under the projection root.
    pub name: String,
    /// Host directory whose contents are projected through this branch.
    pub host_root: PathBuf,
    pub mode: BranchMode,
}

/// Total projection policy. Captured at `start()` time; not mutated after.
#[derive(Debug, Default, Clone, Serialize)]
pub(crate) struct Policy {
    pub branches: Vec<Branch>,
}

impl Policy {
    pub fn from_flags(rw: &[PathBuf], ro: &[PathBuf]) -> Result<Self, String> {
        let mut branches = Vec::new();
        let mut seen_names: HashMap<String, usize> = HashMap::new();
        for (paths, mode) in [(rw, BranchMode::ReadWrite), (ro, BranchMode::ReadOnly)] {
            for p in paths {
                let canonical = fs::canonicalize(p)
                    .map_err(|e| format!("canonicalize({}): {e}", p.display()))?;
                let name = canonical
                    .file_name()
                    .ok_or_else(|| format!("path has no final component: {}", p.display()))?
                    .to_string_lossy()
                    .into_owned();
                let lower = name.to_ascii_lowercase();
                if let Some(prev_idx) = seen_names.get(&lower) {
                    let prev: &Branch = &branches[*prev_idx];
                    return Err(format!(
                        "branch name '{name}' is ambiguous between {} and {}",
                        prev.host_root.display(),
                        canonical.display()
                    ));
                }
                seen_names.insert(lower, branches.len());
                branches.push(Branch {
                    name,
                    host_root: canonical,
                    mode,
                });
            }
        }
        Ok(Self { branches })
    }
}

// -------------------------------------------------------------------------
// Internal state — registered before PrjStartVirtualizing, read-only after.
// -------------------------------------------------------------------------

struct ProviderState {
    policy: Policy,
    enumerations: HashMap<u128, EnumState>,
}

struct EnumState {
    /// Resolved children of the directory being enumerated, sorted via
    /// `PrjFileNameCompare`.
    children: Vec<ChildEntry>,
    /// Next index to deliver.
    cursor: usize,
    /// Wildcard pattern from the kernel, captured at first call.
    pattern: Option<Vec<u16>>,
}

/// A child of some directory the AC asked us to enumerate. Either a synthetic
/// branch directory at the root, or a real host filesystem entry inside a
/// branch.
struct ChildEntry {
    name: String,
    is_dir: bool,
    file_size: i64,
}

fn state() -> &'static Mutex<ProviderState> {
    static S: OnceLock<Mutex<ProviderState>> = OnceLock::new();
    S.get_or_init(|| {
        Mutex::new(ProviderState {
            policy: Policy::default(),
            enumerations: HashMap::new(),
        })
    })
}

fn install_policy(p: Policy) {
    let mut s = state().lock().unwrap();
    s.policy = p;
    s.enumerations.clear();
}

// -------------------------------------------------------------------------
// Path resolution
// -------------------------------------------------------------------------

/// Result of resolving a `PRJ_CALLBACK_DATA::FilePathName`.
enum Resolved {
    /// The virtualization root itself. Children are the policy's branches.
    Root,
    /// A real host path inside a branch. `mode` will be consulted by the
    /// notification callback once step 2c lands; ignored for now.
    Host {
        host_path: PathBuf,
        #[allow(dead_code)]
        mode: BranchMode,
    },
    /// Not in policy — return FILE_NOT_FOUND.
    NotInPolicy,
}

fn resolve(policy: &Policy, rel: &str) -> Resolved {
    if rel.is_empty() {
        return Resolved::Root;
    }
    let (first, rest) = match rel.find('\\') {
        Some(i) => (&rel[..i], &rel[i + 1..]),
        None => (rel, ""),
    };
    let Some(branch) = policy
        .branches
        .iter()
        .find(|b| b.name.eq_ignore_ascii_case(first))
    else {
        return Resolved::NotInPolicy;
    };
    let host_path = if rest.is_empty() {
        branch.host_root.clone()
    } else {
        branch.host_root.join(rest.replace('/', "\\"))
    };
    Resolved::Host {
        host_path,
        mode: branch.mode,
    }
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

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

fn guid_to_u128(g: &GUID) -> u128 {
    let mut bytes = [0u8; 16];
    bytes[0..4].copy_from_slice(&g.data1.to_le_bytes());
    bytes[4..6].copy_from_slice(&g.data2.to_le_bytes());
    bytes[6..8].copy_from_slice(&g.data3.to_le_bytes());
    bytes[8..16].copy_from_slice(&g.data4);
    u128::from_le_bytes(bytes)
}

fn sort_children(v: &mut [ChildEntry]) {
    v.sort_by(|a, b| {
        let aw = to_wide_z(&a.name);
        let bw = to_wide_z(&b.name);
        let c = unsafe { PrjFileNameCompare(PCWSTR(aw.as_ptr()), PCWSTR(bw.as_ptr())) };
        c.cmp(&0)
    });
}

fn collect_root_children(policy: &Policy) -> Vec<ChildEntry> {
    let mut v: Vec<ChildEntry> = policy
        .branches
        .iter()
        .map(|b| ChildEntry {
            name: b.name.clone(),
            is_dir: true,
            file_size: 0,
        })
        .collect();
    sort_children(&mut v);
    v
}

fn collect_host_children(host_dir: &Path) -> std::io::Result<Vec<ChildEntry>> {
    let mut v = Vec::new();
    for entry in fs::read_dir(host_dir)? {
        let entry = entry?;
        // Use `file_type()` (no link follow) so we can detect and skip
        // reparse points without dereferencing them. Threat-model item #7
        // is closed by not surfacing reparse points to the AC at all.
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            continue;
        }
        let md = entry.metadata()?;
        v.push(ChildEntry {
            name: entry.file_name().to_string_lossy().into_owned(),
            is_dir: md.is_dir(),
            file_size: if md.is_dir() { 0 } else { md.len() as i64 },
        });
    }
    sort_children(&mut v);
    Ok(v)
}

fn file_basic_info_dir() -> PRJ_FILE_BASIC_INFO {
    let mut bi = PRJ_FILE_BASIC_INFO::default();
    bi.IsDirectory = true;
    bi.FileAttributes = FILE_ATTRIBUTE_DIRECTORY;
    bi
}

fn file_basic_info_file(size: i64) -> PRJ_FILE_BASIC_INFO {
    let mut bi = PRJ_FILE_BASIC_INFO::default();
    bi.IsDirectory = false;
    bi.FileSize = size;
    bi.FileAttributes = FILE_ATTRIBUTE_NORMAL;
    bi
}

// -------------------------------------------------------------------------
// Callbacks
// -------------------------------------------------------------------------

unsafe extern "system" fn cb_start_enum(
    callback_data: *const PRJ_CALLBACK_DATA,
    enumeration_id: *const GUID,
) -> HRESULT {
    let data = &*callback_data;
    let rel = pcwstr_to_string(data.FilePathName);
    let key = guid_to_u128(&*enumeration_id);

    let mut st = state().lock().unwrap();
    let children = match resolve(&st.policy, &rel) {
        Resolved::Root => collect_root_children(&st.policy),
        Resolved::Host { host_path, .. } => match collect_host_children(&host_path) {
            Ok(v) => v,
            Err(_) => return HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0),
        },
        Resolved::NotInPolicy => return HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0),
    };

    st.enumerations.insert(
        key,
        EnumState {
            children,
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

    if data.Flags.0 & PRJ_CB_DATA_FLAG_ENUM_RESTART_SCAN.0 != 0 {
        es.cursor = 0;
        es.pattern = if search_expression.0.is_null() {
            None
        } else {
            Some(to_wide_z(&pcwstr_to_string(search_expression)))
        };
    } else if es.pattern.is_none() && !search_expression.0.is_null() {
        es.pattern = Some(to_wide_z(&pcwstr_to_string(search_expression)));
    }

    let pattern_ptr = es
        .pattern
        .as_ref()
        .map(|p| PCWSTR(p.as_ptr()))
        .unwrap_or(PCWSTR::null());

    while es.cursor < es.children.len() {
        let entry = &es.children[es.cursor];
        let name_w = to_wide_z(&entry.name);
        let name_pcwstr = PCWSTR(name_w.as_ptr());

        let matches = if pattern_ptr.0.is_null() {
            true
        } else {
            PrjFileNameMatch(name_pcwstr, pattern_ptr)
        };

        if matches {
            let basic = if entry.is_dir {
                file_basic_info_dir()
            } else {
                file_basic_info_file(entry.file_size)
            };
            let r = PrjFillDirEntryBuffer(name_pcwstr, Some(&basic), dir_entry_buffer);
            match r {
                Ok(()) => {}
                Err(e) if e.code() == HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0) => {
                    // Buffer full; do NOT advance cursor — the kernel will
                    // call us back for the next slot.
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

    let st = state().lock().unwrap();
    let basic = match resolve(&st.policy, &rel) {
        Resolved::Root => {
            // The kernel shouldn't call us for the root, but if it does,
            // describe it as a directory.
            file_basic_info_dir()
        }
        Resolved::Host { host_path, .. } => {
            // Use `symlink_metadata` so we *detect* reparse points without
            // following them. If the host file is a reparse point, refuse
            // to surface it — the AC sees `ERROR_FILE_NOT_FOUND`, which is
            // semantically identical to "the path is not in policy."
            // Threat-model item #7 (reparse-point follow-out from within a
            // granted directory) is closed by this refusal.
            let Ok(md) = fs::symlink_metadata(&host_path) else {
                return HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0);
            };
            if md.file_type().is_symlink() {
                return HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0);
            }
            if md.is_dir() {
                file_basic_info_dir()
            } else {
                file_basic_info_file(md.len() as i64)
            }
        }
        Resolved::NotInPolicy => return HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0),
    };

    let mut info = PRJ_PLACEHOLDER_INFO::default();
    info.FileBasicInfo = basic;

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

    let host_path = {
        let st = state().lock().unwrap();
        match resolve(&st.policy, &rel) {
            Resolved::Host { host_path, .. } => host_path,
            _ => return HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0),
        }
    };

    let mut f = match fs::File::open(&host_path) {
        Ok(f) => f,
        Err(_) => return HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0),
    };
    if f.seek(SeekFrom::Start(byte_offset)).is_err() {
        return HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0);
    }

    let buf = PrjAllocateAlignedBuffer(data.NamespaceVirtualizationContext, length as usize);
    if buf.is_null() {
        return HRESULT::from_win32(ERROR_OUTOFMEMORY.0);
    }

    let slice = std::slice::from_raw_parts_mut(buf as *mut u8, length as usize);
    let mut read_total = 0usize;
    while read_total < length as usize {
        match f.read(&mut slice[read_total..]) {
            Ok(0) => break,
            Ok(n) => read_total += n,
            Err(_) => {
                PrjFreeAlignedBuffer(buf);
                return HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0);
            }
        }
    }
    if read_total < length as usize {
        // Short read at EOF — ProjFS expects exactly `length` bytes for the
        // requested range. The placeholder's file size should have been
        // set correctly so this is unlikely; if it does happen, surface a
        // distinct error.
        PrjFreeAlignedBuffer(buf);
        return HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0);
    }

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

// -------------------------------------------------------------------------
// Notification callback — step 2 RO enforcement
// -------------------------------------------------------------------------
//
// We subscribe globally (entire virt root) to the three veto-able write
// notifications:
//
//   - PRE_CONVERT_TO_FULL  ←  modify-existing on a placeholder
//   - PRE_DELETE           ←  delete on a placeholder
//   - PRE_RENAME           ←  rename of a placeholder
//
// On callback, we resolve the path against the policy. If it lands in an
// RO branch, return E_ACCESSDENIED to veto. RW branches and out-of-policy
// paths fall through to S_OK so the kernel handles them normally.
//
// Known limitation (called out in the step-2 findings doc): there is no
// PRE_NEW_FILE_CREATED notification, so the AC can still *create* new
// files in an RO branch. The production fix is to attach a DACL on the
// branch's placeholder directory via PRJ_PLACEHOLDER_INFO_1 that denies
// FILE_ADD_FILE to the AC SID. Out of scope for this spike commit.

const E_ACCESSDENIED: HRESULT = HRESULT(0x8007_0005u32 as i32);

unsafe extern "system" fn cb_notification(
    callback_data: *const PRJ_CALLBACK_DATA,
    _is_directory: bool,
    notification: PRJ_NOTIFICATION,
    _destination_filename: PCWSTR,
    _operation_parameters: *mut PRJ_NOTIFICATION_PARAMETERS,
) -> HRESULT {
    // Only the three veto-able notifications are interesting; everything
    // else slips through.
    if notification != PRJ_NOTIFICATION_FILE_PRE_CONVERT_TO_FULL
        && notification != PRJ_NOTIFICATION_PRE_DELETE
        && notification != PRJ_NOTIFICATION_PRE_RENAME
    {
        return S_OK;
    }

    let data = &*callback_data;
    let rel = pcwstr_to_string(data.FilePathName);

    let st = state().lock().unwrap();
    match resolve(&st.policy, &rel) {
        Resolved::Host {
            mode: BranchMode::ReadOnly,
            ..
        } => E_ACCESSDENIED,
        _ => S_OK,
    }
}


#[derive(Debug, Clone, Serialize)]
pub(crate) struct VirtStartReport {
    pub root_path: PathBuf,
    pub instance_id: String,
    pub policy: Policy,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct SmokeReadReport {
    pub enumerated_branches: Vec<String>,
    pub per_branch_sample: HashMap<String, Vec<String>>,
    pub errors: Vec<String>,
}

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

pub(crate) fn start(
    root: &Path,
    policy: Policy,
) -> Result<(VirtSession, VirtStartReport), String> {
    install_policy(policy.clone());

    if root.exists() {
        let _ = fs::remove_dir_all(root);
    }
    fs::create_dir_all(root).map_err(|e| format!("create_dir_all({}): {e}", root.display()))?;

    let target = to_wide_z(&root.to_string_lossy());
    let instance_id = GUID::new().map_err(|e| format!("GUID::new: {e}"))?;
    unsafe {
        PrjMarkDirectoryAsPlaceholder(PCWSTR(target.as_ptr()), PCWSTR::null(), None, &instance_id)
            .map_err(|e| format!("PrjMarkDirectoryAsPlaceholder: {e} (0x{:08x})", e.code().0))?;
    }

    let callbacks = PRJ_CALLBACKS {
        StartDirectoryEnumerationCallback: Some(cb_start_enum),
        EndDirectoryEnumerationCallback: Some(cb_end_enum),
        GetDirectoryEnumerationCallback: Some(cb_get_enum),
        GetPlaceholderInfoCallback: Some(cb_get_placeholder_info),
        GetFileDataCallback: Some(cb_get_file_data),
        QueryFileNameCallback: None,
        NotificationCallback: Some(cb_notification),
        CancelCommandCallback: None,
    };

    // One global notification mapping subscribing to the three veto-able
    // write events across the entire virt root. The empty NotificationRoot
    // means "from the root down."
    let empty_root = to_wide_z("");
    let mut mappings = [PRJ_NOTIFICATION_MAPPING {
        NotificationBitMask: PRJ_NOTIFY_TYPES(
            PRJ_NOTIFY_FILE_PRE_CONVERT_TO_FULL.0 | PRJ_NOTIFY_PRE_DELETE.0 | PRJ_NOTIFY_PRE_RENAME.0,
        ),
        NotificationRoot: PCWSTR(empty_root.as_ptr()),
    }];
    let mut options = PRJ_STARTVIRTUALIZING_OPTIONS::default();
    options.NotificationMappings = mappings.as_mut_ptr();
    options.NotificationMappingsCount = mappings.len() as u32;

    let ctx = unsafe {
        PrjStartVirtualizing(PCWSTR(target.as_ptr()), &callbacks, None, Some(&options))
            .map_err(|e| format!("PrjStartVirtualizing: {e} (0x{:08x})", e.code().0))?
    };

    Ok((
        VirtSession {
            ctx,
            root: root.to_path_buf(),
        },
        VirtStartReport {
            root_path: root.to_path_buf(),
            instance_id: format!("{:?}", instance_id),
            policy,
        },
    ))
}

/// Launching-user smoke test: enumerate the projection root, then
/// enumerate each branch's top-level. Confirms host-backed reads work from
/// outside the AC before we spend cycles on the AC child.
pub(crate) fn smoke_read_as_launching_user(session: &VirtSession) -> SmokeReadReport {
    let mut errs = Vec::new();

    let branches: Vec<String> = match fs::read_dir(&session.root) {
        Ok(rd) => rd
            .filter_map(|r| r.ok())
            .map(|d| d.file_name().to_string_lossy().into_owned())
            .collect(),
        Err(e) => {
            errs.push(format!("read_dir(root): {e}"));
            Vec::new()
        }
    };

    let mut per_branch_sample = HashMap::new();
    for b in &branches {
        match fs::read_dir(session.root.join(b)) {
            Ok(rd) => {
                let v: Vec<String> = rd
                    .filter_map(|r| r.ok())
                    .map(|d| d.file_name().to_string_lossy().into_owned())
                    .collect();
                per_branch_sample.insert(b.clone(), v);
            }
            Err(e) => errs.push(format!("read_dir({b}): {e}")),
        }
    }

    SmokeReadReport {
        enumerated_branches: branches,
        per_branch_sample,
        errors: errs,
    }
}
