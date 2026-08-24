// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::plan::{CleanupPlan, RunPlan};
use crate::resource::{OwnedResource, OwnershipToken, ResourceNames};

const RECORD_VERSION: u32 = 1;
const MAX_RECOVERY_RECORDS: usize = 32;
const MAX_RECORD_BYTES: u64 = 64 * 1024;

#[derive(Debug, Error)]
pub enum RecoveryError {
    #[error("Apple Container recovery record error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Apple Container recovery record is malformed: {0}")]
    Malformed(#[from] serde_json::Error),
    #[error("unsupported Apple Container recovery record version {0}")]
    UnsupportedVersion(u32),
    #[error("too many Apple Container recovery records (maximum {MAX_RECOVERY_RECORDS})")]
    TooManyRecords,
    #[error("Apple Container recovery record exceeds {MAX_RECORD_BYTES} bytes")]
    RecordTooLarge,
    #[error("Apple Container recovery record name does not match its ownership token")]
    NameMismatch,
    #[error("{0}")]
    InvalidToken(#[from] crate::resource::ResourceError),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecoveryRecord {
    version: u32,
    owner_pid: u32,
    container_hint: String,
    ownership_token: String,
}

impl RecoveryRecord {
    fn from_plan(plan: &RunPlan, container_hint: &str) -> Self {
        Self {
            version: RECORD_VERSION,
            owner_pid: std::process::id(),
            container_hint: container_hint.to_string(),
            ownership_token: plan.ownership_token.as_str().to_string(),
        }
    }

    fn cleanup_plan(&self) -> Result<CleanupPlan, RecoveryError> {
        if self.version != RECORD_VERSION {
            return Err(RecoveryError::UnsupportedVersion(self.version));
        }
        let token = OwnershipToken::parse(&self.ownership_token)?;
        let names = ResourceNames::new(&self.container_hint, &token);
        Ok(CleanupPlan {
            container: OwnedResource::container(names.container, &token),
            network: Some(OwnedResource::network(names.network, &token)),
        })
    }
}

/// Locked record retained for the lifetime of one Apple Container execution.
pub struct RecoveryGuard {
    path: PathBuf,
    _file: File,
}

impl RecoveryGuard {
    pub fn create(plan: &RunPlan, container_hint: &str) -> Result<Self, RecoveryError> {
        let directory = recovery_directory()?;
        create_private_directory(&directory)?;
        let path = directory.join(format!("{}.json", plan.ownership_token.as_str()));
        let temporary_path = directory.join(format!(".{}.tmp", plan.ownership_token.as_str()));
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create_new(true).mode(0o600);
        #[cfg(target_os = "macos")]
        options.custom_flags(libc::O_EXLOCK);
        let mut file = options.open(&temporary_path)?;
        #[cfg(not(target_os = "macos"))]
        lock_exclusive(&file, false)?;
        let write_result = (|| {
            serde_json::to_writer(&mut file, &RecoveryRecord::from_plan(plan, container_hint))?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            fs::hard_link(&temporary_path, &path)?;
            fs::remove_file(&temporary_path)?;
            File::open(&directory)?.sync_all()?;
            Ok::<(), RecoveryError>(())
        })();
        if let Err(error) = write_result {
            let _ = fs::remove_file(&temporary_path);
            return Err(error);
        }
        Ok(Self { path, _file: file })
    }

    pub fn complete(self) -> Result<(), RecoveryError> {
        remove_completed_record(&self.path)
    }
}

/// One unlocked record whose creating executor has exited.
pub struct StaleRecovery {
    path: PathBuf,
    _file: File,
    cleanup: CleanupPlan,
}

impl StaleRecovery {
    pub fn cleanup_plan(&self) -> &CleanupPlan {
        &self.cleanup
    }

    pub fn complete(self) -> Result<(), RecoveryError> {
        remove_completed_record(&self.path)
    }
}

/// Find records whose kernel-held owner lock has been released.
pub fn stale_recoveries() -> Result<Vec<StaleRecovery>, RecoveryError> {
    let directory = recovery_directory()?;
    create_private_directory(&directory)?;
    let mut records = Vec::new();
    let mut record_count = 0;
    for entry in fs::read_dir(&directory)? {
        let entry = entry?;
        let path = entry.path();
        let extension = path.extension().and_then(|value| value.to_str());
        if !matches!(extension, Some("json" | "tmp")) {
            continue;
        }
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        record_count += 1;
        if record_count > MAX_RECOVERY_RECORDS {
            return Err(RecoveryError::TooManyRecords);
        }
        if !metadata.file_type().is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("recovery record {path:?} is not a regular file"),
            )
            .into());
        }
        let mut file = match fs::OpenOptions::new().read(true).write(true).open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if !lock_exclusive(&file, true)? {
            continue;
        }
        if extension == Some("tmp") {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            continue;
        }
        if file.metadata()?.len() > MAX_RECORD_BYTES {
            return Err(RecoveryError::RecordTooLarge);
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let record: RecoveryRecord = serde_json::from_slice(&bytes)?;
        let cleanup = record.cleanup_plan()?;
        let expected_name = format!("{}.json", record.ownership_token);
        if path.file_name().and_then(|value| value.to_str()) != Some(&expected_name) {
            return Err(RecoveryError::NameMismatch);
        }
        records.push(StaleRecovery {
            path,
            _file: file,
            cleanup,
        });
    }
    Ok(records)
}

fn remove_completed_record(path: &Path) -> Result<(), RecoveryError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn recovery_directory() -> Result<PathBuf, RecoveryError> {
    let home = std::env::var_os("HOME").ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "HOME is unavailable for Apple Container recovery records",
        )
    })?;
    let home = Path::new(&home);
    if !home.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "HOME must be absolute for Apple Container recovery records",
        )
        .into());
    }
    Ok(home.join("Library/Application Support/Microsoft/MXC/apple-container/recovery"))
}

fn create_private_directory(path: &Path) -> Result<(), std::io::Error> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    if !fs::symlink_metadata(path)?.file_type().is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("recovery path {path:?} is not a directory"),
        ));
    }
    Ok(())
}

fn lock_exclusive(file: &File, nonblocking: bool) -> Result<bool, std::io::Error> {
    let operation = libc::LOCK_EX | if nonblocking { libc::LOCK_NB } else { 0 };
    // SAFETY: `file` owns a valid descriptor and `flock` does not retain it.
    if unsafe { libc::flock(file.as_raw_fd(), operation) } == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if nonblocking && matches!(error.raw_os_error(), Some(libc::EWOULDBLOCK)) {
        Ok(false)
    } else {
        Err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_reconstructs_exact_owned_resource_names() {
        let token = OwnershipToken::parse("0123456789abcdef0123456789abcdef").unwrap();
        let plan = RunPlan::new(
            "alpine:3.22",
            "Build Job",
            &token,
            true,
            Vec::new(),
            None,
            Default::default(),
        )
        .unwrap();
        let record = RecoveryRecord::from_plan(&plan, "Build Job");
        let cleanup = record.cleanup_plan().unwrap();
        assert_eq!(
            cleanup.container.name.as_str(),
            plan.container.name.as_str()
        );
        assert_eq!(
            cleanup.network.as_ref().map(|value| value.name.as_str()),
            plan.cleanup_plan()
                .network
                .as_ref()
                .map(|value| value.name.as_str())
        );
    }
}
