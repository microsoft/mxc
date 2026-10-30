// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Finding and removing mounts below a directory.
//!
//! The shim mounts the container's root filesystem into the bundle and shares
//! directories under `/run/kata-containers`. On a clean shutdown it unmounts
//! them. When it is killed it cannot, so the backend sweeps the directories it
//! owns before deleting them.

use std::io;
use std::path::{Path, PathBuf};

use nix::mount::{umount2, MntFlags};

/// Decodes the octal escapes (`\040` for a space) that `/proc/self/mountinfo`
/// uses in mount point paths.
fn unescape(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 4 <= bytes.len()
            && bytes[i + 1..i + 4].iter().all(u8::is_ascii_digit)
        {
            let value = u32::from(bytes[i + 1] - b'0') * 64
                + u32::from(bytes[i + 2] - b'0') * 8
                + u32::from(bytes[i + 3] - b'0');
            out.push(value as u8);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The mount points in `mountinfo` (the text of `/proc/self/mountinfo`) that
/// are `root` or below it, deepest first so children unmount before parents.
pub(crate) fn mounts_under(mountinfo: &str, root: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = mountinfo
        .lines()
        .filter_map(|line| line.split(' ').nth(4))
        .map(|field| PathBuf::from(unescape(field)))
        .filter(|mount| mount.starts_with(root))
        .collect();
    found.sort_by_key(|mount| std::cmp::Reverse(mount.components().count()));
    found.dedup();
    found
}

/// Unmounts everything at or below `root`. Returns the mounts that could not
/// be removed.
pub(crate) fn unmount_under(root: &Path) -> io::Result<Vec<(PathBuf, io::Error)>> {
    // A mount can hide another at the same path, so look again after each
    // pass until nothing is left.
    for _ in 0..8 {
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")?;
        let mounts = mounts_under(&mountinfo, root);
        if mounts.is_empty() {
            return Ok(Vec::new());
        }
        let mut failed = Vec::new();
        for mount in mounts {
            // MNT_DETACH: the mount may still be busy for a moment after the
            // process using it was killed.
            if let Err(errno) = umount2(&mount, MntFlags::MNT_DETACH) {
                failed.push((mount, io::Error::from(errno)));
            }
        }
        if !failed.is_empty() {
            return Ok(failed);
        }
    }
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
24 1 0:21 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
31 24 0:27 / /run/mxc-kata/a1/layer rw,nosuid shared:2 - tmpfs tmpfs rw,size=524288k
32 24 0:28 / /run/mxc-kata/a1/bundle/rootfs rw shared:3 - overlay overlay rw,lowerdir=/x
33 24 0:29 / /run/mxc-kata/a1/with\\040space rw shared:4 - tmpfs tmpfs rw
34 24 0:30 / /run/mxc-kata/a10/layer rw shared:5 - tmpfs tmpfs rw
";

    #[test]
    fn only_mounts_below_the_root_are_returned_deepest_first() {
        let found = mounts_under(SAMPLE, Path::new("/run/mxc-kata/a1"));
        assert_eq!(
            found,
            [
                PathBuf::from("/run/mxc-kata/a1/bundle/rootfs"),
                PathBuf::from("/run/mxc-kata/a1/layer"),
                PathBuf::from("/run/mxc-kata/a1/with space"),
            ]
        );
    }

    #[test]
    fn a_sibling_that_shares_a_name_prefix_is_not_below_the_root() {
        let found = mounts_under(SAMPLE, Path::new("/run/mxc-kata/a1"));
        assert!(!found.iter().any(|p| p.ends_with("a10/layer")));
    }

    #[test]
    fn octal_escapes_are_decoded() {
        assert_eq!(unescape("a\\040b\\011c"), "a b\tc");
        assert_eq!(unescape("plain"), "plain");
        assert_eq!(unescape("trailing\\"), "trailing\\");
    }

    #[test]
    fn nothing_is_returned_when_the_root_has_no_mounts() {
        assert!(mounts_under(SAMPLE, Path::new("/run/mxc-kata/none")).is_empty());
    }
}
