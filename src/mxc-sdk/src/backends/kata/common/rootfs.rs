// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The guest root filesystem and its writable layer.
//!
//! The caller's rootfs is never written. A directory is the lower layer of an
//! overlay whose upper layer lives on a size-capped tmpfs, so writes cost host
//! memory up to the cap. An image is copied once per sandbox and attached as a
//! loop device. Both layers belong to the sandbox and go with it.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use nix::mount::{mount, MsFlags};

use crate::kata_common::error::KataError;
use crate::kata_common::loopdev::{self, LoopDevice};
use crate::kata_common::policy::RootfsKind;
use crate::kata_common::task_api::Mount;

/// Most a sandbox can write to its root filesystem when it is a directory.
pub(crate) const WRITABLE_LAYER_MIB: u32 = 512;

/// `FICLONE`: share the data blocks of one file with another.
const FICLONE: libc::c_ulong = 0x4004_9409;

fn layer_dir(sandbox_dir: &Path) -> PathBuf {
    sandbox_dir.join("layer")
}

fn image_copy(sandbox_dir: &Path) -> PathBuf {
    sandbox_dir.join("rootfs.img")
}

/// Copies `source` to `dest`, sharing blocks when the filesystem can.
fn copy_image(source: &Path, dest: &Path) -> io::Result<()> {
    let from = File::open(source)?;
    let to = File::create(dest)?;
    // SAFETY: FICLONE takes the source descriptor and both are open.
    let cloned = unsafe { libc::ioctl(to.as_raw_fd(), FICLONE, from.as_raw_fd()) } == 0;
    if cloned {
        return Ok(());
    }
    drop((from, to));
    std::fs::copy(source, dest).map(drop)
}

/// Creates the sandbox's writable storage under `sandbox_dir`.
pub(crate) fn prepare(
    sandbox_dir: &Path,
    kind: RootfsKind,
    source: &Path,
) -> Result<(), KataError> {
    match kind {
        RootfsKind::Directory => {
            let layer = layer_dir(sandbox_dir);
            std::fs::create_dir(&layer)
                .map_err(|e| KataError::failed(format!("creating {}: {e}", layer.display())))?;
            mount(
                Some("tmpfs"),
                &layer,
                Some("tmpfs"),
                MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
                Some(format!("size={WRITABLE_LAYER_MIB}m,mode=0700").as_str()),
            )
            .map_err(|e| {
                KataError::failed(format!(
                    "mounting the {WRITABLE_LAYER_MIB} MiB writable layer at {}: {e}",
                    layer.display()
                ))
            })?;
            for sub in ["upper", "work"] {
                std::fs::create_dir(layer.join(sub)).map_err(|e| {
                    KataError::failed(format!("creating the layer's {sub} directory: {e}"))
                })?;
            }
        }
        RootfsKind::Image => {
            let copy = image_copy(sandbox_dir);
            copy_image(source, &copy).map_err(|e| {
                KataError::failed(format!(
                    "copying the rootfs image {} to {}: {e}",
                    source.display(),
                    copy.display()
                ))
            })?;
        }
    }
    Ok(())
}

/// The mount the shim receives as the container's root filesystem. For an
/// image the returned [`LoopDevice`] must stay open until the shim has created
/// the task, at which point the hypervisor holds the device itself.
pub(crate) fn root_mount(
    sandbox_dir: &Path,
    kind: RootfsKind,
    source: &Path,
) -> Result<(Mount, Option<LoopDevice>), KataError> {
    match kind {
        RootfsKind::Directory => {
            let layer = layer_dir(sandbox_dir);
            Ok((
                Mount {
                    kind: "overlay".to_string(),
                    source: "overlay".to_string(),
                    options: vec![
                        format!("lowerdir={}", source.display()),
                        format!("upperdir={}", layer.join("upper").display()),
                        format!("workdir={}", layer.join("work").display()),
                    ],
                },
                None,
            ))
        }
        RootfsKind::Image => {
            let copy = image_copy(sandbox_dir);
            let device = loopdev::attach(&copy).map_err(|e| {
                KataError::failed(format!(
                    "attaching {} to a loop device: {e}",
                    copy.display()
                ))
            })?;
            Ok((
                Mount {
                    kind: "ext4".to_string(),
                    source: device.path().display().to_string(),
                    options: Vec::new(),
                },
                Some(device),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_directory_root_is_an_overlay_over_the_callers_directory() {
        let (mount, device) = root_mount(
            Path::new("/run/mxc-kata/mxc-kata-1"),
            RootfsKind::Directory,
            Path::new("/srv/alpine"),
        )
        .unwrap();
        assert!(device.is_none());
        assert_eq!(mount.kind, "overlay");
        assert_eq!(
            mount.options,
            [
                "lowerdir=/srv/alpine",
                "upperdir=/run/mxc-kata/mxc-kata-1/layer/upper",
                "workdir=/run/mxc-kata/mxc-kata-1/layer/work",
            ]
        );
    }

    #[test]
    fn an_image_is_copied_so_the_callers_file_is_never_written() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("src.img");
        std::fs::write(&source, b"image bytes").unwrap();
        let sandbox = dir.path().join("sb");
        std::fs::create_dir(&sandbox).unwrap();

        prepare(&sandbox, RootfsKind::Image, &source).unwrap();

        let copy = image_copy(&sandbox);
        assert_eq!(std::fs::read(&copy).unwrap(), b"image bytes");
        std::fs::write(&copy, b"changed").unwrap();
        assert_eq!(std::fs::read(&source).unwrap(), b"image bytes");
    }

    #[test]
    fn a_missing_image_is_reported_with_both_paths() {
        let dir = tempfile::tempdir().unwrap();
        let err = prepare(dir.path(), RootfsKind::Image, &dir.path().join("gone.img")).unwrap_err();
        assert!(err.message().contains("gone.img"), "{err:?}");
        assert!(err.message().contains("rootfs.img"), "{err:?}");
    }
}
