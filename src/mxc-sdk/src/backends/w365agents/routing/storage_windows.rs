// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::{error, root_path, Identity, MxcError};
use crate::mxc_common::filesystem_security::{
    lock_owner_only_directory_path, owner_is_current_user, set_current_user_owner,
    set_owner_only_dacl, LockedDirectoryPath,
};
use std::fs::{File, OpenOptions};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::{
    MoveFileExW, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
    FILE_SHARE_WRITE, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
};

pub(crate) struct Directory(LockedDirectoryPath);

fn failure(value: impl std::fmt::Display) -> MxcError {
    error("routing_state_io", value)
}

impl Directory {
    pub(crate) fn root() -> Result<Self, MxcError> {
        let root = root_path()?;
        let base = root
            .ancestors()
            .nth(3)
            .ok_or_else(|| failure("invalid state root"))?;
        let directory = lock_owner_only_directory_path(
            base,
            &["Microsoft".as_ref(), "MXC".as_ref(), "w365".as_ref()],
            2,
        )
        .map_err(failure)?;
        set_current_user_owner(directory.path()).map_err(failure)?;
        Ok(Self(directory))
    }

    pub(crate) fn session(identity: &Identity) -> Result<Self, MxcError> {
        let root = Self::root()?;
        let pool = lock_owner_only_directory_path(root.0.path(), &[identity.pool_id.as_ref()], 0)
            .map_err(failure)?;
        set_current_user_owner(pool.path()).map_err(failure)?;
        let session =
            lock_owner_only_directory_path(pool.path(), &[identity.session_id.as_ref()], 0)
                .map_err(failure)?;
        set_current_user_owner(session.path()).map_err(failure)?;
        Ok(Self(session))
    }

    fn file(&self, name: &str, create: bool, write: bool) -> Result<Option<File>, MxcError> {
        let path = self.0.path().join(name);
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(write)
            .create_new(create)
            .share_mode(
                FILE_SHARE_READ.0
                    | if name == "connection.lock" {
                        FILE_SHARE_WRITE.0
                    } else {
                        0
                    },
            )
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0);
        let file = match options.open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(failure(e)),
        };
        if create {
            set_owner_only_dacl(&path, false).map_err(failure)?;
            set_current_user_owner(&path).map_err(failure)?;
        }
        let metadata = file.metadata().map_err(failure)?;
        if !metadata.is_file()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
            || !owner_is_current_user(&path).map_err(failure)?
            || !crate::mxc_common::filesystem_security::file_is_owner_only(&file, &path)
                .map_err(failure)?
        {
            return Err(error("routing_state_permissions", "file is not owner-only"));
        }
        Ok(Some(file))
    }

    pub(crate) fn read(&self, name: &str) -> Result<Option<File>, MxcError> {
        self.file(name, false, false)
    }

    pub(crate) fn create(&self, name: &str) -> Result<File, MxcError> {
        self.file(name, true, true)?
            .ok_or_else(|| failure("temporary file parent is missing"))
    }

    pub(crate) fn lock(&self) -> Result<File, MxcError> {
        let file = match self.file("connection.lock", false, true)? {
            Some(file) => file,
            None => self.create("connection.lock")?,
        };
        file.try_lock()
            .map_err(|e| error("routing_state_lock", e))?;
        Ok(file)
    }

    pub(crate) fn publish(&self, source: &str, destination: &str) -> Result<(), MxcError> {
        let wide = |name: &str| {
            self.0
                .path()
                .join(name)
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect::<Vec<_>>()
        };
        let source = wide(source);
        let destination = wide(destination);
        unsafe {
            MoveFileExW(
                PCWSTR(source.as_ptr()),
                PCWSTR(destination.as_ptr()),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        }
        .map_err(failure)
    }

    pub(crate) fn remove(&self, name: &str) -> Result<(), MxcError> {
        match std::fs::remove_file(self.0.path().join(name)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(failure(e)),
        }
    }
}
