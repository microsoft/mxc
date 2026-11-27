// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Loop devices for ext4 guest root images.
//!
//! Hypervisors without a shared filesystem (Firecracker) boot the container
//! from a block device. The backend presents the per-sandbox copy of the image
//! as a loop device.
//!
//! The device is attached with `LO_FLAGS_AUTOCLEAR`, so the kernel detaches it
//! once the last holder closes it. After the hypervisor opens the device, MXC
//! drops its own descriptor and the device lives exactly as long as the VM. A
//! crashed or killed VM therefore cannot leak a loop device.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const LOOP_CONTROL: &str = "/dev/loop-control";
const LOOP_SET_FD: libc::c_ulong = 0x4C00;
const LOOP_CLR_FD: libc::c_ulong = 0x4C01;
const LOOP_SET_STATUS64: libc::c_ulong = 0x4C04;
const LOOP_CTL_GET_FREE: libc::c_ulong = 0x4C82;
const LO_FLAGS_AUTOCLEAR: u32 = 4;
const LO_NAME_SIZE: usize = 64;
/// Another process may claim the free device between GET_FREE and SET_FD.
const ATTACH_ATTEMPTS: usize = 16;

/// Mirrors `struct loop_info64` from `<linux/loop.h>`.
#[repr(C)]
struct LoopInfo64 {
    lo_device: u64,
    lo_inode: u64,
    lo_rdevice: u64,
    lo_offset: u64,
    lo_sizelimit: u64,
    lo_number: u32,
    lo_encrypt_type: u32,
    lo_encrypt_key_size: u32,
    lo_flags: u32,
    lo_file_name: [u8; LO_NAME_SIZE],
    lo_crypt_name: [u8; LO_NAME_SIZE],
    lo_encrypt_key: [u8; 32],
    lo_init: [u64; 2],
}

/// An attached loop device. Dropping it closes MXC's descriptor only; the
/// kernel detaches the device when the last descriptor is gone.
#[derive(Debug)]
pub(crate) struct LoopDevice {
    path: PathBuf,
    _device: File,
}

impl LoopDevice {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

/// Attaches `image` read-write to a free loop device.
pub(crate) fn attach(image: &Path) -> io::Result<LoopDevice> {
    let backing = OpenOptions::new().read(true).write(true).open(image)?;
    let control = OpenOptions::new()
        .read(true)
        .write(true)
        .open(LOOP_CONTROL)
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("cannot open {LOOP_CONTROL} ({e}); is the loop kernel module available?"),
            )
        })?;

    let mut last_error = None;
    for _ in 0..ATTACH_ATTEMPTS {
        // SAFETY: LOOP_CTL_GET_FREE takes no argument and returns an index.
        let index = unsafe { libc::ioctl(control.as_raw_fd(), LOOP_CTL_GET_FREE) };
        if index < 0 {
            return Err(io::Error::last_os_error());
        }
        let path = PathBuf::from(format!("/dev/loop{index}"));
        let device = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(&path)?;
        // SAFETY: both descriptors are open for the duration of the call.
        let rc = unsafe { libc::ioctl(device.as_raw_fd(), LOOP_SET_FD, backing.as_raw_fd()) };
        if rc < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EBUSY) {
                last_error = Some(error);
                continue;
            }
            return Err(error);
        }
        if let Err(error) = set_autoclear(&device, image) {
            // Without autoclear, closing the descriptor leaves the image attached.
            // SAFETY: LOOP_CLR_FD takes no argument.
            if unsafe { libc::ioctl(device.as_raw_fd(), LOOP_CLR_FD) } < 0 {
                let detach = io::Error::last_os_error();
                return Err(io::Error::new(
                    error.kind(),
                    format!(
                        "{error}; detaching {} also failed: {detach}",
                        path.display()
                    ),
                ));
            }
            return Err(error);
        }
        return Ok(LoopDevice {
            path,
            _device: device,
        });
    }
    Err(last_error.unwrap_or_else(|| io::Error::other("no free loop device")))
}

fn set_autoclear(device: &File, image: &Path) -> io::Result<()> {
    // SAFETY: LoopInfo64 is plain data for which all-zero is a valid value.
    let mut info: LoopInfo64 = unsafe { std::mem::zeroed() };
    info.lo_flags = LO_FLAGS_AUTOCLEAR;
    let name = image.as_os_str().as_encoded_bytes();
    let keep = name.len().min(LO_NAME_SIZE - 1);
    info.lo_file_name[..keep].copy_from_slice(&name[name.len() - keep..]);
    // SAFETY: `info` is a valid, initialized loop_info64 for the call.
    let rc = unsafe { libc::ioctl(device.as_raw_fd(), LOOP_SET_STATUS64, &info) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Whether the file at `image` starts an ext4 filesystem: the superblock magic
/// `0xEF53` sits at byte 1080.
pub(crate) fn is_ext4_image(image: &Path) -> io::Result<bool> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = File::open(image)?;
    file.seek(SeekFrom::Start(1080))?;
    let mut magic = [0u8; 2];
    match file.read_exact(&mut magic) {
        Ok(()) => Ok(u16::from_le_bytes(magic) == 0xEF53),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn loop_info64_matches_the_kernel_layout() {
        assert_eq!(std::mem::size_of::<LoopInfo64>(), 232);
    }

    #[test]
    fn the_ext4_magic_is_recognized_at_the_superblock_offset() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("a.img");
        let mut bytes = vec![0u8; 4096];
        bytes[1080] = 0x53;
        bytes[1081] = 0xEF;
        std::fs::write(&image, &bytes).unwrap();
        assert!(is_ext4_image(&image).unwrap());

        let other = dir.path().join("b.img");
        std::fs::write(&other, vec![0u8; 4096]).unwrap();
        assert!(!is_ext4_image(&other).unwrap());
    }

    #[test]
    fn a_file_too_short_to_hold_a_superblock_is_not_ext4() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("short.img");
        let mut f = File::create(&image).unwrap();
        f.write_all(b"tiny").unwrap();
        assert!(!is_ext4_image(&image).unwrap());
    }
}
