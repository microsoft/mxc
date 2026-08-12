// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Kernel-form -> user-visible path normalization.
//!
//! ETW emits filesystem paths in two kernel forms:
//!
//! - DOS-device forms (`\??\`, `\\?\`, or `\\.\`) followed by a drive
//!   path or `UNC\server\share`, and
//! - the device form `\Device\HarddiskVolume3\Users\foo\file.txt`.
//!
//! User-visible paths use drive letters (`C:\Users\foo\file.txt`). This
//! module owns both mappings.
//!
//! The DOS-device forms are pure textual prefix strips. For the `\Device\`
//! form we walk `A:` through `Z:` calling `QueryDosDeviceW` to discover each
//! drive's kernel mount (`\Device\HarddiskVolumeN`, `\Device\CdRomN`, etc.),
//! then check the input
//! path for a prefix match. The device map is cached for the lifetime of
//! the process -- the mapping is stable in practice (drive-letter changes
//! during a single workload run are vanishingly rare).
//!
//! MUP redirector paths are converted to UNC paths. Non-file paths such as
//! registry `\REGISTRY\Machine\...` are not recognized.

use std::sync::OnceLock;

use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::QueryDosDeviceW;

/// Cached `(drive_letter, kernel_prefix)` table, e.g.
/// `[("C:", "\\Device\\HarddiskVolume3"), ...]`.
static DRIVE_MAP: OnceLock<Vec<(String, String)>> = OnceLock::new();

/// Maps a kernel-form path to its user-visible drive-letter form.
///
/// Returns `Some(canonical)` when the input starts with the NT
/// DOS-devices prefix (`\??\`, `\\?\`, or `\\.\`) or a
/// known `\Device\HarddiskVolumeN\...` prefix, or the MUP redirector prefix.
/// Returns `None` when the path is not a filesystem path that can be
/// canonicalized (registry or unknown device).
pub fn to_user_visible(kernel_path: &str) -> Option<String> {
    if kernel_path.starts_with(r"\Device\") && !kernel_path.starts_with(r"\Device\Mup\") {
        to_user_visible_with_map(kernel_path, DRIVE_MAP.get_or_init(load_drive_map))
    } else {
        to_user_visible_with_map(kernel_path, &[])
    }
}

fn to_user_visible_with_map(kernel_path: &str, map: &[(String, String)]) -> Option<String> {
    // DOS-device prefixes map directly to the path that follows. The UNC
    // spelling retains its network-path leading slashes.
    if let Some(rest) = kernel_path
        .strip_prefix(r"\??\")
        .or_else(|| kernel_path.strip_prefix(r"\\?\"))
        .or_else(|| kernel_path.strip_prefix(r"\\.\"))
    {
        if let Some(prefix) = rest
            .get(..4)
            .filter(|prefix| prefix.eq_ignore_ascii_case(r"UNC\"))
        {
            let unc = &rest[prefix.len()..];
            return Some(format!(r"\\{unc}"));
        }
        return Some(rest.to_string());
    }

    if let Some(rest) = kernel_path.strip_prefix(r"\Device\Mup\") {
        let rest = if let Some(after_dfs) = rest.strip_prefix(r"DfsClient\") {
            if after_dfs.starts_with(';') {
                let (_, after_connection) = after_dfs.split_once('\\')?;
                after_connection
            } else {
                after_dfs
            }
        } else if rest.starts_with(';') {
            let (_, after_redirector) = rest.split_once('\\')?;
            if after_redirector.starts_with(';') {
                let (_, after_connection) = after_redirector.split_once('\\')?;
                after_connection
            } else {
                after_redirector
            }
        } else {
            rest
        };
        if !rest.is_empty() {
            return Some(format!(r"\\{rest}"));
        }
        return None;
    }

    if !kernel_path.starts_with(r"\Device\") {
        return None;
    }

    map_device_path(kernel_path, map)
}

fn map_device_path(kernel_path: &str, map: &[(String, String)]) -> Option<String> {
    for (letter, prefix) in map {
        if let Some(rest) = kernel_path.strip_prefix(prefix.as_str()) {
            if rest.is_empty() || rest.starts_with('\\') {
                return Some(format!("{letter}{rest}"));
            }
        }
    }
    None
}

/// Compares a device-form path (first argument) with a DOS-form path (second).
pub(crate) fn device_path_matches_dos(device_path: &str, dos_path: &str) -> bool {
    device_path_matches_dos_with_map(device_path, dos_path, DRIVE_MAP.get_or_init(load_drive_map))
}

fn device_path_matches_dos_with_map(
    device_path: &str,
    dos_path: &str,
    map: &[(String, String)],
) -> bool {
    map.iter().any(|(letter, prefix)| {
        device_path
            .strip_prefix(prefix.as_str())
            .filter(|rest| rest.is_empty() || rest.starts_with('\\'))
            .is_some_and(|rest| {
                dos_path
                    .get(..letter.len())
                    .is_some_and(|dos_letter| dos_letter.eq_ignore_ascii_case(letter))
                    && dos_path.get(letter.len()..).is_some_and(|dos_rest| {
                        wxc_common::string_util::windows_paths_equal_ignore_case(rest, dos_rest)
                    })
            })
    })
}

/// Returns whether `path` is already an absolute user-visible DOS or UNC path.
pub fn is_user_visible_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    (bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/'))
        || (path.starts_with(r"\\")
            && !path.starts_with(r"\\?\")
            && !path.starts_with(r"\\.\")
            && !is_unc_named_pipe(path))
}

fn is_unc_named_pipe(path: &str) -> bool {
    let mut components = path.trim_start_matches('\\').split('\\');
    let _server = components.next();
    components
        .next()
        .is_some_and(|share| share.eq_ignore_ascii_case("pipe"))
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

        // QueryDosDeviceW was invoked for a DOS drive letter, so every
        // returned target is a drive-backed namespace worth mapping (for
        // example HarddiskVolume, CdRom, or a redirector-backed drive).
        if !device.is_empty() {
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
    fn dos_devices_prefix_is_stripped() {
        assert_eq!(
            to_user_visible(r"\??\C:\data\test\bin\").as_deref(),
            Some(r"C:\data\test\bin\")
        );
        assert_eq!(to_user_visible(r"\??\C:\").as_deref(), Some(r"C:\"));
    }

    #[test]
    fn dos_devices_unc_prefix_becomes_unc_path() {
        assert_eq!(
            to_user_visible(r"\??\UNC\server\share\file.txt").as_deref(),
            Some(r"\\server\share\file.txt")
        );
    }

    #[test]
    fn win32_device_prefixes_are_normalized() {
        for path in [r"\\?\C:\data\file.txt", r"\\.\C:\data\file.txt"] {
            assert_eq!(to_user_visible(path).as_deref(), Some(r"C:\data\file.txt"));
        }

        for path in [
            r"\\?\UNC\server\share\file.txt",
            r"\\?\unc\server\share\file.txt",
            r"\\.\UNC\server\share\file.txt",
        ] {
            assert_eq!(
                to_user_visible(path).as_deref(),
                Some(r"\\server\share\file.txt")
            );
        }
    }

    #[test]
    fn mup_path_becomes_unc_path() {
        assert_eq!(
            to_user_visible(r"\Device\Mup\server\share\file.txt").as_deref(),
            Some(r"\\server\share\file.txt")
        );
        assert_eq!(
            to_user_visible(r"\Device\Mup\;LanmanRedirector\server\share\file.txt").as_deref(),
            Some(r"\\server\share\file.txt")
        );
        assert_eq!(
            to_user_visible(
                r"\Device\Mup\;LanmanRedirector\;Z:0000000000001234\server\share\file.txt"
            )
            .as_deref(),
            Some(r"\\server\share\file.txt")
        );
        assert_eq!(
            to_user_visible(r"\Device\Mup\DfsClient\;N:0000000000001234\server\share\file.txt")
                .as_deref(),
            Some(r"\\server\share\file.txt")
        );
    }

    #[test]
    fn recognizes_absolute_user_visible_paths() {
        assert!(is_user_visible_absolute(r"C:\data\file.txt"));
        assert!(is_user_visible_absolute(r"\\server\share\file.txt"));
        assert!(!is_user_visible_absolute(r"\\server\pipe\name"));
        assert!(!is_user_visible_absolute(r"\Device\Unknown\file.txt"));
        assert!(!is_user_visible_absolute(r"relative\file.txt"));
    }

    #[test]
    fn drive_map_populates() {
        // On any Windows machine running tests there is at least one volume
        // (the system drive). Verifies QueryDosDeviceW works and our parser
        // accepts at least one entry.
        let map = rebuild_drive_map_for_tests();
        assert!(
            !map.is_empty(),
            "drive map should have at least one DOS drive entry"
        );
    }

    #[test]
    fn maps_non_hard_disk_drive_devices() {
        let map = vec![("D:".to_string(), r"\Device\CdRom0".to_string())];
        assert_eq!(
            map_device_path(r"\Device\CdRom0\setup.exe", &map).as_deref(),
            Some(r"D:\setup.exe")
        );
    }

    #[test]
    fn canonicalizes_system_drive_paths() {
        let map = vec![("C:".to_string(), r"\Device\HarddiskVolume42".to_string())];
        assert_eq!(
            to_user_visible_with_map(
                r"\Device\HarddiskVolume42\Windows\System32\drivers\etc\hosts",
                &map
            )
            .as_deref(),
            Some(r"C:\Windows\System32\drivers\etc\hosts")
        );
    }

    #[test]
    fn device_prefix_requires_component_boundary() {
        let map = vec![("C:".to_string(), r"\Device\HarddiskVolume42".to_string())];
        assert!(to_user_visible_with_map(r"\Device\HarddiskVolume420\Windows", &map).is_none());
    }

    #[test]
    fn compares_device_and_dos_paths_without_materializing_a_path() {
        let map = vec![("C:".to_string(), r"\Device\HarddiskVolume42".to_string())];
        assert!(device_path_matches_dos_with_map(
            r"\Device\HarddiskVolume42\TÄST\App.exe",
            r"c:\täst\app.EXE",
            &map
        ));
        assert!(!device_path_matches_dos_with_map(
            r"\Device\HarddiskVolume42\Tools\App.exe",
            r"D:\Tools\App.exe",
            &map
        ));
        assert!(!device_path_matches_dos_with_map(
            r"\Device\HarddiskVolume420\Tools\App.exe",
            r"C:\Tools\App.exe",
            &map
        ));
    }
}
