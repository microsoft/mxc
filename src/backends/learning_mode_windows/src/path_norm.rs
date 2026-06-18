// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Kernel-form -> user-visible path normalization.
//!
//! ETW emits filesystem paths in kernel form (e.g.
//! `\Device\HarddiskVolume3\Users\foo\file.txt`). User-visible paths use
//! drive letters (`C:\Users\foo\file.txt`). This module owns the mapping.
//!
//! Strategy: walk `A:` through `Z:` calling `QueryDosDeviceW` to discover
//! each drive's kernel mount (`\Device\HarddiskVolumeN`), then check the
//! input path for a prefix match. Cached for the lifetime of the process --
//! the mapping is stable in practice (drive-letter changes during a single
//! workload run are vanishingly rare).
//!
//! Non-file paths (registry `\REGISTRY\Machine\...`, MUP / network shares,
//! etc.) are returned unchanged.

use std::sync::OnceLock;

use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::QueryDosDeviceW;

/// Cached `(drive_letter, kernel_prefix)` table, e.g.
/// `[("C:", "\\Device\\HarddiskVolume3"), ...]`.
static DRIVE_MAP: OnceLock<Vec<(String, String)>> = OnceLock::new();

/// Maps a kernel-form path to its user-visible drive-letter form.
///
/// Returns `Some(canonical)` when the input starts with a known
/// `\Device\HarddiskVolumeN\...` prefix. Returns `None` when the path is not
/// a filesystem path that can be canonicalized (registry, MUP, unknown
/// device). Callers should fall back to the original input on `None`.
pub fn to_user_visible(kernel_path: &str) -> Option<String> {
    if !kernel_path.starts_with(r"\Device\") {
        return None;
    }

    let map = DRIVE_MAP.get_or_init(load_drive_map);

    for (letter, prefix) in map {
        if let Some(rest) = kernel_path.strip_prefix(prefix.as_str()) {
            return Some(format!("{letter}{rest}"));
        }
    }
    None
}

/// Test-only: rebuilds the drive map without consulting the cache.
#[cfg(test)]
pub(crate) fn rebuild_drive_map_for_tests() -> Vec<(String, String)> {
    load_drive_map()
}

fn load_drive_map() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut buf = [0u16; 260];

    for c in b'A'..=b'Z' {
        let letter = format!("{}:", c as char);
        let wide: Vec<u16> = letter.encode_utf16().chain(std::iter::once(0)).collect();

        // SAFETY: `wide` is a valid null-terminated wide string; `buf` is a
        // valid mutable slice. The function writes at most `buf.len()` u16s.
        let n = unsafe { QueryDosDeviceW(PCWSTR(wide.as_ptr()), Some(&mut buf)) };
        if n == 0 {
            continue;
        }

        // Result is a sequence of null-terminated strings ending in a double
        // null. We only care about the first entry.
        let end = buf
            .iter()
            .take(n as usize)
            .position(|&w| w == 0)
            .unwrap_or(n as usize);
        let device = String::from_utf16_lossy(&buf[..end]);

        // Common shapes: `\Device\HarddiskVolume3`, `\Device\Mup`, etc.
        // Only canonicalize filesystem volumes; skip non-Harddisk entries.
        if device.starts_with(r"\Device\HarddiskVolume") {
            out.push((letter, device));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_device_path_returns_none() {
        assert!(to_user_visible(r"C:\already\user\form").is_none());
        assert!(to_user_visible(r"\REGISTRY\Machine\SOFTWARE\Foo").is_none());
        assert!(to_user_visible("").is_none());
    }

    #[test]
    fn drive_map_populates() {
        // On any Windows machine running tests there is at least one volume
        // (the system drive). Verifies QueryDosDeviceW works and our parser
        // accepts at least one entry.
        let map = rebuild_drive_map_for_tests();
        assert!(
            !map.is_empty(),
            "drive map should have at least one HarddiskVolume entry"
        );
    }

    #[test]
    fn canonicalizes_system_drive_paths() {
        let map = rebuild_drive_map_for_tests();
        if let Some((letter, kernel_prefix)) = map.first() {
            let synthetic = format!(r"{kernel_prefix}\Windows\System32\drivers\etc\hosts");
            let canon = to_user_visible(&synthetic).expect("should canonicalize");
            assert_eq!(
                canon,
                format!(r"{letter}\Windows\System32\drivers\etc\hosts")
            );
        }
    }
}
