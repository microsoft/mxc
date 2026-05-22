// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ProjFS provider — promoted from `wxc_projfs_probe::virt`.
//!
//! Projects a curated set of host directories ([`OverlayPrimitive::ProjFsBranch`]s)
//! into a single projection root that lives inside the AppContainer's
//! profile folder. The AC's LowBox access check evaluates against the
//! placeholder DACLs we attach via `PRJ_PLACEHOLDER_INFO_1`, not against
//! the host file's DACL — that's the property that makes "broad RO of
//! `C:`-ish paths" enforce inside an AC without DACL mutation.
//!
//! # Threading model
//!
//! ProjFS callbacks fire on provider worker threads owned by the
//! kernel. We hold a per-process [`Mutex`]-protected [`ProviderState`]
//! that callbacks consult to resolve relative paths. Per-enumeration
//! cursor state lives in the same lock.
//!
//! # Per-process singleton
//!
//! The current MVP supports **one** active projection per process
//! (the `static OnceLock<Mutex<ProviderState>>`). That's sufficient
//! for `wxc-exec`: each process drives one contained child, so one
//! `OverlayManager`, so one virt session. If a future caller needs
//! multiple concurrent projections in the same process, this module
//! gets refactored to pass per-instance state through the callback's
//! `instance_context` pointer instead of via the static.
//!
//! # Promoted from the spike (`projfs-t3-spike-step{1,2,3}.md`)
//!
//! Callback bodies, the path-resolve scheme, the placeholder DACL
//! shape (DWORD-padded `OffsetToSecurityDescriptor` + `AU` Authenticated
//! Users grant, deliberately not `OW`), and the notification veto for
//! RO `PRE_CONVERT_TO_FULL` / `PRE_DELETE` / `PRE_RENAME` are all
//! taken verbatim from the spike. See the empirical receipts in
//! `docs/proposals/downlevel_support/projfs-t3-spike-step2.md`.

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use windows::core::{GUID, HRESULT, PCWSTR};
use windows::Win32::Foundation::{
    LocalFree, ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_OUTOFMEMORY, HLOCAL, S_OK,
};
use windows::Win32::Storage::ProjectedFileSystem::{
    PrjAllocateAlignedBuffer, PrjFileNameCompare, PrjFileNameMatch, PrjFillDirEntryBuffer,
    PrjFreeAlignedBuffer, PrjMarkDirectoryAsPlaceholder, PrjStartVirtualizing, PrjStopVirtualizing,
    PrjWriteFileData, PrjWritePlaceholderInfo, PRJ_CALLBACKS, PRJ_CALLBACK_DATA,
    PRJ_CB_DATA_FLAG_ENUM_RESTART_SCAN, PRJ_DIR_ENTRY_BUFFER_HANDLE, PRJ_FILE_BASIC_INFO,
    PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT, PRJ_NOTIFICATION,
    PRJ_NOTIFICATION_FILE_HANDLE_CLOSED_FILE_MODIFIED, PRJ_NOTIFICATION_FILE_PRE_CONVERT_TO_FULL,
    PRJ_NOTIFICATION_MAPPING, PRJ_NOTIFICATION_PARAMETERS, PRJ_NOTIFICATION_PRE_DELETE,
    PRJ_NOTIFICATION_PRE_RENAME, PRJ_NOTIFY_FILE_HANDLE_CLOSED_FILE_MODIFIED,
    PRJ_NOTIFY_FILE_PRE_CONVERT_TO_FULL, PRJ_NOTIFY_PRE_DELETE, PRJ_NOTIFY_PRE_RENAME,
    PRJ_NOTIFY_TYPES, PRJ_PLACEHOLDER_INFO, PRJ_STARTVIRTUALIZING_OPTIONS,
};

use crate::filesystem_overlay::error::OverlayError;
use crate::filesystem_overlay::plan::{BranchMode, OverlayPrimitive};

// -------------------------------------------------------------------------
// File attribute constants — re-exported from kernel32 / ntifs.h, not
// surfaced by `windows::Win32::Storage::FileSystem` constants we already
// pulled in.
// -------------------------------------------------------------------------

const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;

/// HRESULT for the notification callback to veto a write.
/// `windows-rs` doesn't surface `E_ACCESSDENIED` as a const we can use
/// directly; replicate it locally.
const E_ACCESSDENIED: HRESULT = HRESULT(0x8007_0005u32 as i32);

// -------------------------------------------------------------------------
// Public types
// -------------------------------------------------------------------------

/// One projected branch derived from an [`OverlayPrimitive::ProjFsBranch`].
#[derive(Debug, Clone)]
pub struct ResolvedBranch {
    /// Branch leaf name (canonicalized host path's file_name).
    pub name: String,
    /// Canonicalized host directory backing this branch.
    pub host_root: PathBuf,
    /// RO or RW.
    pub mode: BranchMode,
    /// Canonicalized subpaths (each is a prefix under `host_root`)
    /// the AC must not see. Populated from
    /// `OverlayPrimitive::ProjFsBranch::deny_subpaths`; checked by
    /// [`resolve`] and [`collect_host_children`] so callbacks
    /// return `ERROR_FILE_NOT_FOUND` and filter the host's entries.
    pub deny_subpaths: Vec<PathBuf>,
}

/// Set of projected branches plus the AC SID needed for placeholder
/// DACL construction. Read-only after virt session start.
#[derive(Debug, Clone, Default)]
pub struct ProjFsBranchSet {
    /// Branches in stable canonical order.
    pub branches: Vec<ResolvedBranch>,
    /// AC SID in `S-1-15-2-…` form. Empty disables the RO placeholder
    /// DACL trick — but Phase A always passes a real SID, so empty
    /// is a logic error.
    pub ac_sid_string: String,
}

impl ProjFsBranchSet {
    /// Build the branch set from a slice of `OverlayPrimitive` values.
    /// Non-`ProjFsBranch` variants are ignored (the caller is expected
    /// to pre-filter, but we re-check defensively).
    pub fn from_primitives(
        primitives: &[OverlayPrimitive],
        ac_sid: &str,
    ) -> Result<Self, OverlayError> {
        let mut branches = Vec::new();
        let mut seen_names: HashMap<String, usize> = HashMap::new();
        for p in primitives {
            let (host_path, branch_name, mode, deny_subpaths) = match p {
                OverlayPrimitive::ProjFsBranch {
                    host_path,
                    branch_name,
                    mode,
                    deny_subpaths,
                } => (host_path, branch_name, *mode, deny_subpaths),
                _ => continue,
            };
            let lower = branch_name.to_ascii_lowercase();
            if let Some(prev_idx) = seen_names.get(&lower) {
                let prev: &ResolvedBranch = &branches[*prev_idx];
                return Err(OverlayError::Classify(format!(
                    "branch name '{branch_name}' is ambiguous between {} and {}",
                    prev.host_root.display(),
                    host_path.display()
                )));
            }
            seen_names.insert(lower, branches.len());
            branches.push(ResolvedBranch {
                name: branch_name.clone(),
                host_root: host_path.clone(),
                mode,
                deny_subpaths: deny_subpaths.clone(),
            });
        }
        Ok(Self {
            branches,
            ac_sid_string: ac_sid.to_string(),
        })
    }
}

// -------------------------------------------------------------------------
// Internal state — registered before PrjStartVirtualizing, read-only after.
// -------------------------------------------------------------------------

struct ProviderState {
    branches: ProjFsBranchSet,
    enumerations: HashMap<u128, EnumState>,
    /// Projection root captured at `start()` time so the writeback
    /// callback (`PRJ_NOTIFICATION_FILE_HANDLE_CLOSED_FILE_MODIFIED`)
    /// can locate the projection-side file at
    /// `<projection_root>\<rel>` and copy it back to the branch's
    /// `host_root`. Empty until `install_branches` is called.
    projection_root: PathBuf,
}

struct EnumState {
    children: Vec<ChildEntry>,
    cursor: usize,
    pattern: Option<Vec<u16>>,
}

struct ChildEntry {
    name: String,
    is_dir: bool,
    file_size: i64,
}

fn state() -> &'static Mutex<ProviderState> {
    static S: OnceLock<Mutex<ProviderState>> = OnceLock::new();
    S.get_or_init(|| {
        Mutex::new(ProviderState {
            branches: ProjFsBranchSet::default(),
            enumerations: HashMap::new(),
            projection_root: PathBuf::new(),
        })
    })
}

fn install_branches(b: ProjFsBranchSet, projection_root: PathBuf) {
    let mut s = state().lock().unwrap();
    s.branches = b;
    s.enumerations.clear();
    s.projection_root = projection_root;
}

fn clear_branches() {
    let mut s = state().lock().unwrap();
    s.branches = ProjFsBranchSet::default();
    s.enumerations.clear();
    s.projection_root = PathBuf::new();
}

// -------------------------------------------------------------------------
// Path resolution
// -------------------------------------------------------------------------

enum Resolved {
    Root,
    Host {
        host_path: PathBuf,
        mode: BranchMode,
    },
    NotInPolicy,
}

fn resolve(branches: &ProjFsBranchSet, rel: &str) -> Resolved {
    if rel.is_empty() {
        return Resolved::Root;
    }
    let (first, rest) = match rel.find('\\') {
        Some(i) => (&rel[..i], &rel[i + 1..]),
        None => (rel, ""),
    };
    let Some(branch) = branches
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
    // Structural deny: if this host_path is under one of the
    // branch's `deny_subpaths`, return NotInPolicy so the AC sees
    // ERROR_FILE_NOT_FOUND. Each deny_subpath is canonicalized.
    if is_under_any(&host_path, &branch.deny_subpaths) {
        return Resolved::NotInPolicy;
    }
    Resolved::Host {
        host_path,
        mode: branch.mode,
    }
}

/// Case-insensitive Windows-style "is `child` under (or equal to) any
/// of the `parents`?". Mirrors `policy::canonical_starts_with` but
/// kept local to keep `virt.rs` self-contained.
///
/// Robust to the `\\?\` prefix difference between
/// `std::fs::canonicalize` outputs and `read_dir` entry paths — we
/// strip the prefix before component-wise comparison.
fn is_under_any(child: &Path, parents: &[PathBuf]) -> bool {
    if parents.is_empty() {
        return false;
    }
    let cs = path_components_for_compare(child);
    for parent in parents {
        let ps = path_components_for_compare(parent);
        if ps.len() > cs.len() {
            continue;
        }
        let mut matched = true;
        for (i, p) in ps.iter().enumerate() {
            if cs[i] != *p {
                matched = false;
                break;
            }
        }
        if matched {
            return true;
        }
    }
    false
}

/// Build a case-insensitive component list, stripping any leading
/// `\\?\` extended-path prefix so canonicalised and non-canonicalised
/// paths compare equal.
fn path_components_for_compare(p: &Path) -> Vec<String> {
    let s = p.to_string_lossy();
    let stripped = s.strip_prefix(r"\\?\").unwrap_or(&s);
    Path::new(stripped)
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_ascii_lowercase())
        .collect()
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

fn collect_root_children(branches: &ProjFsBranchSet) -> Vec<ChildEntry> {
    let mut v: Vec<ChildEntry> = branches
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

fn collect_host_children(
    host_dir: &Path,
    deny_subpaths: &[PathBuf],
) -> std::io::Result<Vec<ChildEntry>> {
    let mut v = Vec::new();
    for entry in fs::read_dir(host_dir)? {
        let entry = entry?;
        // Use `file_type()` (no link follow) so we can detect and skip
        // reparse points without dereferencing them.
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            continue;
        }
        // Structural deny: if this entry's full path is under any
        // of the branch's deny_subpaths, omit it from the
        // enumeration so the AC doesn't see denied subtrees in
        // listings.
        if is_under_any(&entry.path(), deny_subpaths) {
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
    PRJ_FILE_BASIC_INFO {
        IsDirectory: true,
        FileAttributes: FILE_ATTRIBUTE_DIRECTORY,
        ..Default::default()
    }
}

fn file_basic_info_file(size: i64) -> PRJ_FILE_BASIC_INFO {
    PRJ_FILE_BASIC_INFO {
        IsDirectory: false,
        FileSize: size,
        FileAttributes: FILE_ATTRIBUTE_NORMAL,
        ..Default::default()
    }
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
    let children = match resolve(&st.branches, &rel) {
        Resolved::Root => collect_root_children(&st.branches),
        Resolved::Host { host_path, .. } => {
            // Look up the branch the host_path belongs to so we can
            // pass its deny_subpaths through to the enumeration
            // filter. The first branch whose host_root is a prefix
            // of host_path wins (there's only ever one since
            // `policy::classify` rejects nesting).
            let denies = st
                .branches
                .branches
                .iter()
                .find(|b| host_path.starts_with(&b.host_root))
                .map(|b| b.deny_subpaths.clone())
                .unwrap_or_default();
            match collect_host_children(&host_path, &denies) {
                Ok(v) => v,
                Err(_) => return HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0),
            }
        }
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
                    // Buffer full; do NOT advance cursor.
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

    let (basic, mode_opt) = {
        let st = state().lock().unwrap();
        match resolve(&st.branches, &rel) {
            Resolved::Root => (file_basic_info_dir(), None),
            Resolved::Host { host_path, mode } => {
                // Detect reparse points without following them.
                // Refuse to surface them — closes threat-model item #7.
                let Ok(md) = fs::symlink_metadata(&host_path) else {
                    return HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0);
                };
                if md.file_type().is_symlink() {
                    return HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0);
                }
                let bi = if md.is_dir() {
                    file_basic_info_dir()
                } else {
                    file_basic_info_file(md.len() as i64)
                };
                (bi, Some(mode))
            }
            Resolved::NotInPolicy => return HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0),
        }
    };

    // RO branches: attach a placeholder DACL that grants the AC the
    // read+exec subset (no FILE_ADD_FILE), so CreateFileW(CREATE_NEW)
    // from inside the AC fails the access check before any notification
    // could fire. See spike step 3 (3/N) for the empirical derivation.
    let ac_sid_string = state().lock().unwrap().branches.ac_sid_string.clone();
    let is_dir = basic.IsDirectory;
    let sd_bytes = match mode_opt {
        Some(BranchMode::ReadOnly) if is_dir && !ac_sid_string.is_empty() => {
            build_ro_security_descriptor(&ac_sid_string)
        }
        _ => None,
    };

    if let Some(sd) = sd_bytes {
        // Variable-length PRJ_PLACEHOLDER_INFO + SD payload with
        // DWORD alignment for SeCaptureSecurityDescriptor's
        // ProbeForRead. See spike step 3 (3/N) commit message for the
        // root-cause walk through gvflt source.
        let var_offset = std::mem::offset_of!(PRJ_PLACEHOLDER_INFO, VariableData);
        let path_bytes = (rel.encode_utf16().count() + 1) * 2;
        let want_align = 8;
        let pad = (want_align - ((path_bytes + var_offset) % want_align)) % want_align;
        let sd_offset = var_offset + pad;
        let total = sd_offset + sd.len();
        let mut buf = vec![0u8; total];
        let info_ptr = buf.as_mut_ptr() as *mut PRJ_PLACEHOLDER_INFO;
        std::ptr::write(info_ptr, PRJ_PLACEHOLDER_INFO::default());
        (*info_ptr).FileBasicInfo = basic;
        (*info_ptr).SecurityInformation.SecurityBufferSize = sd.len() as u32;
        (*info_ptr).SecurityInformation.OffsetToSecurityDescriptor = sd_offset as u32;
        std::ptr::copy_nonoverlapping(sd.as_ptr(), buf.as_mut_ptr().add(sd_offset), sd.len());

        let dest = to_wide_z(&rel);
        let r = PrjWritePlaceholderInfo(
            data.NamespaceVirtualizationContext,
            PCWSTR(dest.as_ptr()),
            info_ptr,
            total as u32,
        );
        return match r {
            Ok(()) => S_OK,
            Err(e) => e.code(),
        };
    }

    let info = PRJ_PLACEHOLDER_INFO {
        FileBasicInfo: basic,
        ..Default::default()
    };

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

/// Build a self-relative security descriptor for an RO-branch
/// placeholder directory. Grants `SY` / `BA` / `AU` full, and the
/// AC SID a read+exec subset (no `FILE_ADD_FILE`).
///
/// The `AU` Authenticated Users grant is load-bearing: the kernel-side
/// `PrjfCopyAsPlaceHolder` issues a `FltCreateFileEx2` with
/// `IO_FORCE_ACCESS_CHECK`, evaluating the SD against the launching
/// user's token. Using `OW` (owner-rights, S-1-3-4) instead is
/// unreliable — most user tokens lack the S-1-3-4 group, especially
/// Entra-style S-1-12-1 logins. See spike step 3 (3/N) commit
/// message for the empirical derivation.
fn build_ro_security_descriptor(ac_sid: &str) -> Option<Vec<u8>> {
    use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows::Win32::Security::Authorization::SDDL_REVISION_1;
    use windows::Win32::Security::{GetSecurityDescriptorLength, PSECURITY_DESCRIPTOR};

    // Mask 0x001200a9 = FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES |
    // FILE_READ_EA | FILE_TRAVERSE | READ_CONTROL | SYNCHRONIZE.
    // OICI propagates to descendants without per-file SDs.
    let sddl = format!(
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;AU)(A;OICI;0x001200a9;;;{ac_sid})"
    );
    let sddl_w = to_wide_z(&sddl);

    let mut psd = PSECURITY_DESCRIPTOR::default();
    let r = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_w.as_ptr()),
            SDDL_REVISION_1,
            &mut psd,
            None,
        )
    };
    if r.is_err() {
        return None;
    }
    let len = unsafe { GetSecurityDescriptorLength(psd) } as usize;
    if len == 0 {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(psd.0)));
        }
        return None;
    }
    let mut out = vec![0u8; len];
    unsafe {
        std::ptr::copy_nonoverlapping(psd.0 as *const u8, out.as_mut_ptr(), len);
        let _ = LocalFree(Some(HLOCAL(psd.0)));
    }
    Some(out)
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
        match resolve(&st.branches, &rel) {
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
// Notification callback — RO enforcement + RW writeback
// -------------------------------------------------------------------------
//
// Subscribe to:
//
//   PRE-events (veto-able; we veto for RO branches):
//   - PRE_CONVERT_TO_FULL   ← modify-existing on a placeholder
//   - PRE_DELETE            ← delete on a placeholder
//   - PRE_RENAME            ← rename of a placeholder
//
//   POST-events (informational; we use them to propagate back to host):
//   - FILE_HANDLE_CLOSED_FILE_MODIFIED  ← RW branch writeback trigger
//
// Return E_ACCESSDENIED to veto, S_OK otherwise.
//
// Known limitation: there is no PRE_NEW_FILE_CREATED notification.
// New-file-in-RO is closed by the placeholder DACL (above) instead.

unsafe extern "system" fn cb_notification(
    callback_data: *const PRJ_CALLBACK_DATA,
    _is_directory: bool,
    notification: PRJ_NOTIFICATION,
    _destination_filename: PCWSTR,
    _operation_parameters: *mut PRJ_NOTIFICATION_PARAMETERS,
) -> HRESULT {
    let data = &*callback_data;
    let rel = pcwstr_to_string(data.FilePathName);

    // POST-event: file was modified and the handle was closed. For
    // RW branches we propagate the modified content back to the host
    // backing. Always returns S_OK — post-event notifications can't
    // veto.
    if notification == PRJ_NOTIFICATION_FILE_HANDLE_CLOSED_FILE_MODIFIED {
        let (host_path, projection_root) = {
            let st = state().lock().unwrap();
            match resolve(&st.branches, &rel) {
                Resolved::Host {
                    host_path,
                    mode: BranchMode::ReadWrite,
                } => (host_path, st.projection_root.clone()),
                // RO branches shouldn't get here because PRE_CONVERT_TO_FULL
                // vetoes the conversion; if a non-RW path does fire this
                // we ignore it (the host backing was never modified).
                _ => return S_OK,
            }
        };
        if let Err(e) = writeback_modified_file(&projection_root, &rel, &host_path) {
            // Best-effort: log to stderr and continue. The AC's view
            // already has the new content (the placeholder converted
            // to a full file); we just couldn't sync host-side. A
            // future restore / recovery pass picks this up via the
            // host-content drift.
            eprintln!(
                "filesystem_overlay::projfs: writeback {} -> {}: {e}",
                rel,
                host_path.display()
            );
        }
        return S_OK;
    }

    // PRE-events: veto when the target lives in an RO branch.
    if notification != PRJ_NOTIFICATION_FILE_PRE_CONVERT_TO_FULL
        && notification != PRJ_NOTIFICATION_PRE_DELETE
        && notification != PRJ_NOTIFICATION_PRE_RENAME
    {
        return S_OK;
    }

    let st = state().lock().unwrap();
    match resolve(&st.branches, &rel) {
        Resolved::Host {
            mode: BranchMode::ReadOnly,
            ..
        } => E_ACCESSDENIED,
        _ => S_OK,
    }
}

/// Copy a modified placeholder's content from
/// `<projection_root>\<rel>` to `<host_path>`. Creates parent
/// directories on the host side as needed.
///
/// Notes:
/// - `rel` is the projection-root-relative path the kernel handed us,
///   using backslash separators on Windows.
/// - This runs on a ProjFS worker thread, post-close, so the file is
///   no longer locked by the AC.
/// - We copy via `std::fs::copy` for simplicity. For large files a
///   future optimisation could stream / use `CopyFile2` with
///   `COPY_FILE_ALLOW_DECRYPTED_DESTINATION` semantics. The MVP
///   correctness goal is to make the host backing reflect the AC's
///   final write — not to compete with raw-disk throughput.
fn writeback_modified_file(
    projection_root: &Path,
    rel: &str,
    host_path: &Path,
) -> std::io::Result<()> {
    if projection_root.as_os_str().is_empty() {
        return Err(std::io::Error::other("projection root not installed"));
    }
    let source = projection_root.join(rel.replace('/', "\\"));
    if let Some(parent) = host_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(&source, host_path)?;
    Ok(())
}

// -------------------------------------------------------------------------
// Virt session lifecycle
// -------------------------------------------------------------------------

/// One active ProjFS session. `Drop` stops virtualization. Held inside
/// [`super::ProjFsApplied`] for the lifetime of the [`crate::filesystem_overlay::OverlayManager`].
pub struct VirtSession {
    ctx: PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT,
    /// Projection root path. Recorded for diagnostic / cleanup paths.
    pub root: PathBuf,
}

impl std::fmt::Debug for VirtSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtSession")
            .field("ctx", &"<opaque>")
            .field("root", &self.root)
            .finish()
    }
}

impl Drop for VirtSession {
    fn drop(&mut self) {
        if !self.ctx.is_invalid() {
            unsafe { PrjStopVirtualizing(self.ctx) };
            // Clear the per-process state so a subsequent start sees
            // a clean slate. Failures to remove the projection root
            // are non-fatal; the caller's cleanup pass handles it.
            clear_branches();
        }
    }
}

/// Start a virt session at `root`, projecting the given `branches`.
/// `root` should be a fresh per-run directory (we delete it first if
/// it exists, then recreate). The caller is responsible for placing
/// `root` somewhere the AC has traverse access (typically inside the
/// AC profile's `AC\` folder).
pub fn start(root: &Path, branches: ProjFsBranchSet) -> Result<VirtSession, OverlayError> {
    install_branches(branches, root.to_path_buf());

    if root.exists() {
        let _ = fs::remove_dir_all(root);
    }
    fs::create_dir_all(root)
        .map_err(|e| OverlayError::ProjFs(format!("create_dir_all({}): {e}", root.display())))?;

    let target = to_wide_z(&root.to_string_lossy());
    let instance_id =
        GUID::new().map_err(|e| OverlayError::ProjFs(format!("GUID::new for instance id: {e}")))?;
    unsafe {
        PrjMarkDirectoryAsPlaceholder(PCWSTR(target.as_ptr()), PCWSTR::null(), None, &instance_id)
            .map_err(|e| {
                OverlayError::ProjFs(format!(
                    "PrjMarkDirectoryAsPlaceholder: {e} (0x{:08x})",
                    e.code().0
                ))
            })?;
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

    // One global notification mapping covering the entire virt root.
    // The three PRE-events are vetoed for RO branches; the
    // FILE_HANDLE_CLOSED_FILE_MODIFIED post-event drives RW writeback
    // to the host backing.
    let empty_root = to_wide_z("");
    let mut mappings = [PRJ_NOTIFICATION_MAPPING {
        NotificationBitMask: PRJ_NOTIFY_TYPES(
            PRJ_NOTIFY_FILE_PRE_CONVERT_TO_FULL.0
                | PRJ_NOTIFY_PRE_DELETE.0
                | PRJ_NOTIFY_PRE_RENAME.0
                | PRJ_NOTIFY_FILE_HANDLE_CLOSED_FILE_MODIFIED.0,
        ),
        NotificationRoot: PCWSTR(empty_root.as_ptr()),
    }];
    let options = PRJ_STARTVIRTUALIZING_OPTIONS {
        NotificationMappings: mappings.as_mut_ptr(),
        NotificationMappingsCount: mappings.len() as u32,
        ..Default::default()
    };

    let ctx = unsafe {
        PrjStartVirtualizing(PCWSTR(target.as_ptr()), &callbacks, None, Some(&options)).map_err(
            |e| OverlayError::ProjFs(format!("PrjStartVirtualizing: {e} (0x{:08x})", e.code().0)),
        )?
    };

    Ok(VirtSession {
        ctx,
        root: root.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem_overlay::plan::OverlayPrimitive;

    #[test]
    fn from_primitives_filters_non_projfs_variants() {
        let prims = vec![
            OverlayPrimitive::BindFltTombstone {
                path: PathBuf::from(r"C:\not-projfs"),
            },
            OverlayPrimitive::ProjFsBranch {
                host_path: PathBuf::from(r"C:\Users\a"),
                branch_name: "a".into(),
                mode: BranchMode::ReadOnly,
                deny_subpaths: Vec::new(),
            },
        ];
        let set = ProjFsBranchSet::from_primitives(&prims, "S-1-15-2-test").unwrap();
        assert_eq!(set.branches.len(), 1);
        assert_eq!(set.branches[0].name, "a");
        assert_eq!(set.ac_sid_string, "S-1-15-2-test");
    }

    #[test]
    fn from_primitives_rejects_ambiguous_branch_names_case_insensitive() {
        let prims = vec![
            OverlayPrimitive::ProjFsBranch {
                host_path: PathBuf::from(r"D:\sources\repo"),
                branch_name: "repo".into(),
                mode: BranchMode::ReadOnly,
                deny_subpaths: Vec::new(),
            },
            OverlayPrimitive::ProjFsBranch {
                host_path: PathBuf::from(r"E:\backups\repo"),
                branch_name: "REPO".into(),
                mode: BranchMode::ReadWrite,
                deny_subpaths: Vec::new(),
            },
        ];
        let err = ProjFsBranchSet::from_primitives(&prims, "S-1-15-2-test").unwrap_err();
        match err {
            OverlayError::Classify(s) => assert!(s.contains("ambiguous"), "got {s}"),
            other => panic!("expected Classify, got {other:?}"),
        }
    }

    #[test]
    fn resolve_root_returns_root_variant() {
        let set = ProjFsBranchSet {
            branches: vec![ResolvedBranch {
                name: "x".into(),
                host_root: PathBuf::from(r"C:\x"),
                mode: BranchMode::ReadOnly,
                deny_subpaths: Vec::new(),
            }],
            ac_sid_string: "S-1-15-2-test".into(),
        };
        assert!(matches!(resolve(&set, ""), Resolved::Root));
    }

    #[test]
    fn resolve_matches_branch_case_insensitive_and_joins_rest() {
        let set = ProjFsBranchSet {
            branches: vec![ResolvedBranch {
                name: "Repo".into(),
                host_root: PathBuf::from(r"D:\sources\repo"),
                mode: BranchMode::ReadWrite,
                deny_subpaths: Vec::new(),
            }],
            ac_sid_string: "S-1-15-2-test".into(),
        };
        match resolve(&set, "repo\\src\\lib.rs") {
            Resolved::Host { host_path, mode } => {
                assert_eq!(host_path, PathBuf::from(r"D:\sources\repo\src\lib.rs"));
                assert_eq!(mode, BranchMode::ReadWrite);
            }
            other => panic!("expected Host, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[test]
    fn resolve_unknown_branch_returns_not_in_policy() {
        let set = ProjFsBranchSet::default();
        assert!(matches!(resolve(&set, "foo\\bar"), Resolved::NotInPolicy));
    }

    #[test]
    fn build_ro_security_descriptor_returns_self_relative_blob() {
        let sd = build_ro_security_descriptor("S-1-1-0")
            .expect("Everyone SID always builds to a valid SDDL");
        // Self-relative SD header is 20 bytes; we should have at least
        // that plus the four ACEs.
        assert!(sd.len() >= 20, "SD too short: {}", sd.len());
    }
}
