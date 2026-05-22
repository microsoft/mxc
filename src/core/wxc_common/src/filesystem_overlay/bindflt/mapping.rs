// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! BindFlt mapping helpers — wraps `CreateBindLink` /
//! `RemoveBindLink` with the policy-shaped signatures the rest of
//! the overlay enforcer wants.
//!
//! Phase B-1 supports the two overlay variants:
//!
//! - [`apply_ro_overlay`]: makes `virt_path` reflect `target_path`
//!   read-only, with writes vetoed at the namespace layer.
//! - [`apply_rw_overlay`]: makes `virt_path` reflect `target_path`
//!   read-write. The AC's writes propagate to the host backing
//!   directly because BindFlt resolves the namespace before the
//!   kernel's access check fires.
//!
//! Tombstones (`BindFltTombstone`) are not yet supported by the
//! public `CreateBindLink` surface — see the TODO in
//! [`super::apply_mapping`] for the path forward.

use std::path::Path;

use windows::core::PCWSTR;

use crate::filesystem_overlay::bindflt::api::{BindFltApi, CreateBindLinkFlags};
use crate::filesystem_overlay::error::OverlayError;

/// Apply a read-only BindFlt overlay binding `virt_path` to
/// `target_path`. Writes through `virt_path` are vetoed by BindFlt
/// itself (the `READ_ONLY` flag is enforced at the namespace layer
/// before the kernel's access check sees the request).
pub fn apply_ro_overlay(virt_path: &Path, target_path: &Path) -> Result<(), OverlayError> {
    apply(virt_path, target_path, CreateBindLinkFlags::ReadOnly)
}

/// Apply a read-write BindFlt overlay binding `virt_path` to
/// `target_path`. Writes pass through to the host backing.
pub fn apply_rw_overlay(virt_path: &Path, target_path: &Path) -> Result<(), OverlayError> {
    apply(virt_path, target_path, CreateBindLinkFlags::None)
}

/// Remove the BindFlt mapping rooted at `virt_path`. Idempotent
/// (returns Ok if no mapping exists). The underlying
/// `RemoveBindLink` returns a number of HRESULTs we choose to treat
/// as "mapping not present" so this function can be called blindly
/// during recovery without needing to first probe state.
pub fn restore(virt_path: &Path) -> Result<(), OverlayError> {
    let api = BindFltApi::get()?;
    let v = wide_z(virt_path);
    let hr = unsafe { (api.remove_bind_link)(PCWSTR(v.as_ptr())) };
    if hr.is_ok() {
        return Ok(());
    }
    // 0x80070002 = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)
    // 0x80070003 = HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND)
    let code = hr.0 as u32;
    if code == 0x8007_0002 || code == 0x8007_0003 {
        return Ok(());
    }
    Err(OverlayError::BindFlt(format!(
        "RemoveBindLink({}): HRESULT 0x{code:08x}",
        virt_path.display()
    )))
}

fn apply(
    virt_path: &Path,
    target_path: &Path,
    flags: CreateBindLinkFlags,
) -> Result<(), OverlayError> {
    let api = BindFltApi::get()?;
    let v = wide_z(virt_path);
    let t = wide_z(target_path);
    let hr = unsafe {
        (api.create_bind_link)(
            PCWSTR(v.as_ptr()),
            PCWSTR(t.as_ptr()),
            flags as u32,
            0,
            std::ptr::null(),
        )
    };
    if hr.is_ok() {
        return Ok(());
    }
    Err(OverlayError::BindFlt(format!(
        "CreateBindLink({} -> {}, flags={:?}): HRESULT 0x{:08x}",
        virt_path.display(),
        target_path.display(),
        flags,
        hr.0 as u32
    )))
}

fn wide_z(p: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    p.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem_overlay::bindflt::api::BindFltApi;

    /// End-to-end RW overlay: bind a fresh empty virt-path to a host
    /// directory we created, verify the contents are visible through
    /// the virt-path, then remove the binding.
    ///
    /// Gated by `#[ignore]` because BindFlt operations require
    /// `bindflt.sys` to be loaded (typically yes on Win10 1809+) and
    /// — depending on host policy — may need elevation to mutate the
    /// kernel filter's mapping table. Run explicitly with
    /// `cargo test -p wxc_common --lib -- --ignored bindflt`.
    #[test]
    #[ignore = "requires bindflt.sys; may need elevation; run with --ignored"]
    fn end_to_end_rw_overlay_apply_then_remove() {
        // Skip cleanly if the API isn't available at all on this host.
        if BindFltApi::get().is_err() {
            eprintln!("BindFltApi unavailable; skipping test");
            return;
        }

        let run_id = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_micros())
                .unwrap_or(0)
        );
        let host_scratch = std::env::temp_dir().join(format!("mxc-bindflt-host-{run_id}"));
        std::fs::create_dir_all(&host_scratch).expect("host scratch");
        std::fs::write(host_scratch.join("readme.txt"), b"hello bindflt").expect("readme");

        let virt_path = std::env::temp_dir().join(format!("mxc-bindflt-virt-{run_id}"));
        // `virt_path` must not exist beforehand — CreateBindLink
        // creates the entry.
        if virt_path.exists() {
            let _ = std::fs::remove_dir_all(&virt_path);
        }

        match apply_rw_overlay(&virt_path, &host_scratch) {
            Ok(()) => {
                // Now read through the virt path.
                let content =
                    std::fs::read(virt_path.join("readme.txt")).expect("read through virt");
                assert_eq!(content, b"hello bindflt");

                restore(&virt_path).expect("restore");
                // Cleanup the host side.
                let _ = std::fs::remove_dir_all(&host_scratch);
            }
            Err(OverlayError::BindFlt(reason))
                if reason.contains("0x80070005") || reason.contains("0x80070522") =>
            {
                // ACCESS_DENIED (5) or SE_PRIVILEGE_NOT_HELD (1314)
                // — operation requires elevation. Acceptable test
                // outcome on non-admin shells.
                eprintln!("BindFlt apply requires elevation: {reason}");
                let _ = std::fs::remove_dir_all(&host_scratch);
            }
            Err(other) => panic!("unexpected: {other:?}"),
        }
    }
}
