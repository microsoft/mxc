// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! An empty network namespace for a sandbox.
//!
//! The Kata shim plugs every interface it finds in the sandbox's network
//! namespace into the VM. A fresh namespace holds only `lo`, so the VM gets no
//! network interface at all: that is how the backend enforces deny-all. MXC
//! creates the namespace itself, rather than leaving that to the shim, so it
//! owns the namespace's lifetime and can remove it on every error path even if
//! the shim was killed.

use std::io;
use std::path::{Path, PathBuf};

use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{unshare, CloneFlags};

/// A network namespace kept alive by a bind mount of its nsfs file.
#[derive(Debug)]
pub(crate) struct NetNs {
    path: PathBuf,
}

impl NetNs {
    /// Creates a new namespace and pins it at `path`.
    ///
    /// `unshare(CLONE_NEWNET)` moves only the calling thread, so it runs on a
    /// short-lived thread. The bind mount keeps the namespace alive after that
    /// thread exits.
    pub(crate) fn create(path: &Path) -> io::Result<Self> {
        std::fs::File::create(path)?;
        let target = path.to_path_buf();
        let pinned = std::thread::Builder::new()
            .name("mxc-kata-netns".to_string())
            .spawn(move || -> io::Result<()> {
                unshare(CloneFlags::CLONE_NEWNET).map_err(io::Error::from)?;
                mount(
                    Some("/proc/thread-self/ns/net"),
                    &target,
                    None::<&str>,
                    MsFlags::MS_BIND,
                    None::<&str>,
                )
                .map_err(io::Error::from)
            })?
            .join()
            .map_err(|_| io::Error::other("the network namespace thread panicked"))?;
        if let Err(error) = pinned {
            let _ = std::fs::remove_file(path);
            return Err(error);
        }
        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    /// Adopts a namespace pinned at `path` by an earlier [`NetNs::create`].
    pub(crate) fn at(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
        }
    }

    /// Unpins and removes the namespace. Succeeds when it is already gone.
    pub(crate) fn destroy(&self) -> io::Result<()> {
        match umount2(&self.path, MntFlags::MNT_DETACH) {
            // EINVAL: not a mount point, because creation failed part way or
            // a previous destroy already ran.
            Ok(()) | Err(nix::errno::Errno::EINVAL | nix::errno::Errno::ENOENT) => {}
            Err(errno) => return Err(errno.into()),
        }
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_root() -> bool {
        // SAFETY: `geteuid` has no preconditions and no side effects.
        unsafe { libc::geteuid() == 0 }
    }

    #[test]
    fn destroying_a_namespace_that_was_never_created_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        NetNs::at(&dir.path().join("none")).destroy().unwrap();
    }

    #[test]
    fn a_namespace_has_only_loopback_and_is_removed_by_destroy() {
        if !is_root() {
            println!("SKIPPED: creating a network namespace needs root");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("netns");
        let ns = NetNs::create(&path).unwrap();

        let out = std::process::Command::new("nsenter")
            .arg(format!("--net={}", path.display()))
            .args(["cat", "/proc/net/dev"])
            .output();
        if let Ok(out) = out {
            let table = String::from_utf8_lossy(&out.stdout);
            let interfaces = table
                .lines()
                .skip(2)
                .filter_map(|l| l.split(':').next())
                .map(str::trim)
                .collect::<Vec<_>>();
            assert_eq!(interfaces, ["lo"], "{table}");
        }

        ns.destroy().unwrap();
        assert!(!path.exists());
        ns.destroy().unwrap();
    }
}
