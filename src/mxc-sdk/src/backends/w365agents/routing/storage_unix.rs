// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::{error, root_path, Identity, MxcError};
use std::ffi::CString;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

pub(crate) struct Directory(File);

fn io_error(error_value: std::io::Error) -> MxcError {
    error("routing_state_io", error_value)
}

fn name(value: &std::ffi::OsStr) -> Result<CString, MxcError> {
    CString::new(value.as_bytes()).map_err(|_| error("routing_state_path", "NUL in state path"))
}

impl Directory {
    pub(crate) fn root() -> Result<Self, MxcError> {
        Self::open(&root_path()?, 0)
    }

    pub(crate) fn session(identity: &Identity) -> Result<Self, MxcError> {
        Self::open(
            &root_path()?
                .join(&identity.pool_id)
                .join(&identity.session_id),
            2,
        )
    }

    fn open(path: &Path, trailing: usize) -> Result<Self, MxcError> {
        let components: Vec<_> = path.components().collect();
        let mut directory = Self(File::open("/").map_err(io_error)?);
        for (index, component) in components.iter().enumerate().skip(1) {
            let Component::Normal(component) = component else {
                return Err(error(
                    "routing_state_path",
                    "unsupported directory component",
                ));
            };
            let component = name(component)?;
            // All operations stay relative to held directory descriptors.
            let created =
                unsafe { libc::mkdirat(directory.0.as_raw_fd(), component.as_ptr(), 0o700) };
            if created != 0
                && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
            {
                return Err(io_error(std::io::Error::last_os_error()));
            }
            let fd = unsafe {
                libc::openat(
                    directory.0.as_raw_fd(),
                    component.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(io_error(std::io::Error::last_os_error()));
            }
            directory = Self(unsafe { File::from_raw_fd(fd) });
            let metadata = directory.0.metadata().map_err(io_error)?;
            if index >= components.len() - trailing - 1
                && (metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0)
            {
                return Err(error(
                    "routing_state_permissions",
                    "directory is not owner-only",
                ));
            }
        }
        Ok(directory)
    }

    fn file(&self, value: &str, flags: i32) -> Result<Option<File>, MxcError> {
        let value = name(value.as_ref())?;
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                value.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
                0o600,
            )
        };
        if fd < 0 {
            let error_value = std::io::Error::last_os_error();
            return if error_value.kind() == std::io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(io_error(error_value))
            };
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata().map_err(io_error)?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err(error(
                "routing_state_permissions",
                "file is not a private regular file",
            ));
        }
        Ok(Some(file))
    }

    pub(crate) fn read(&self, name: &str) -> Result<Option<File>, MxcError> {
        self.file(name, libc::O_RDONLY)
    }

    pub(crate) fn create(&self, name: &str) -> Result<File, MxcError> {
        self.file(name, libc::O_RDWR | libc::O_CREAT | libc::O_EXCL)?
            .ok_or_else(|| error("routing_state_write", "temporary file parent is missing"))
    }

    pub(crate) fn lock(&self) -> Result<File, MxcError> {
        let file = self
            .file("connection.lock", libc::O_RDWR | libc::O_CREAT)?
            .ok_or_else(|| error("routing_state_lock", "lock parent is missing"))?;
        file.try_lock()
            .map_err(|e| error("routing_state_lock", e))?;
        Ok(file)
    }

    pub(crate) fn publish(&self, source: &str, destination: &str) -> Result<(), MxcError> {
        let source = name(source.as_ref())?;
        let destination = name(destination.as_ref())?;
        let result = unsafe {
            libc::renameat(
                self.0.as_raw_fd(),
                source.as_ptr(),
                self.0.as_raw_fd(),
                destination.as_ptr(),
            )
        };
        if result != 0 {
            return Err(io_error(std::io::Error::last_os_error()));
        }
        self.0.sync_all().map_err(io_error)
    }

    pub(crate) fn remove(&self, value: &str) -> Result<(), MxcError> {
        let value = name(value.as_ref())?;
        if unsafe { libc::unlinkat(self.0.as_raw_fd(), value.as_ptr(), 0) } != 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(io_error(e));
            }
        }
        Ok(())
    }
}
