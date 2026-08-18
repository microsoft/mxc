// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Transactional staging for the canonical and Data Loop output pair.

use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug)]
struct OutputPairLock {
    file: std::fs::File,
}

impl OutputPairLock {
    fn acquire(operation: &str, canonical_path: &Path) -> std::io::Result<Self> {
        let file_name = canonical_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                std::io::Error::other(format!(
                    "{operation} canonical output path has no usable file name: {}",
                    canonical_path.display()
                ))
            })?;
        let lock_name = format!(".{file_name}.pair.lock");
        let lock_path = canonical_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(lock_name);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|error| {
                std::io::Error::other(format!(
                    "{operation} failed to open output-pair lock {}: {error}",
                    lock_path.display()
                ))
            })?;
        file.try_lock().map_err(|error| {
            std::io::Error::other(format!(
                "{operation} output pair is being written by another process (lock {}): {error}",
                lock_path.display()
            ))
        })?;
        Ok(Self { file })
    }
}

impl Drop for OutputPairLock {
    fn drop(&mut self) {
        let _ = std::fs::File::unlock(&self.file);
    }
}

#[derive(Debug)]
struct PromotedOutput {
    handle: same_file::Handle,
}

impl PromotedOutput {
    fn matches_path(&self, path: &Path) -> std::io::Result<bool> {
        let path_handle = same_file::Handle::from_path(path)?;
        Ok(self.handle == path_handle)
    }
}

/// Controls how an existing output pair is handled during promotion.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ExistingOutputPolicy {
    /// Fail rather than overwrite either output.
    CreateNew,
    /// Atomically replace each individual output.
    Replace,
}

/// Stages, flushes, and promotes a canonical output and its Data Loop sibling.
///
/// Both documents are serialized before either final path is changed. Replace
/// mode retains the previous files until both new files are promoted, allowing
/// a failed promotion to restore the complete previous pair.
pub fn write_paired_output_files(
    operation: &str,
    canonical_path: &Path,
    data_loop_path: &Path,
    policy: ExistingOutputPolicy,
    write_canonical: impl FnOnce(&mut std::io::BufWriter<std::fs::File>) -> std::io::Result<()>,
    write_data_loop: impl FnOnce(&mut std::io::BufWriter<std::fs::File>) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let _pair_lock = OutputPairLock::acquire(operation, canonical_path)?;
    match policy {
        ExistingOutputPolicy::CreateNew => {
            ensure_output_absent(operation, canonical_path, "canonical")?;
            ensure_output_absent(operation, data_loop_path, "Data Loop")?;
        }
        ExistingOutputPolicy::Replace => {
            ensure_output_replaceable(operation, canonical_path, "canonical")?;
            ensure_output_replaceable(operation, data_loop_path, "Data Loop")?;
        }
    }

    let canonical_temp =
        stage_output_file(operation, canonical_path, "canonical", write_canonical)?;
    let data_loop_temp =
        stage_output_file(operation, data_loop_path, "Data Loop", write_data_loop)?;

    let canonical_backup = if policy == ExistingOutputPolicy::Replace {
        backup_existing_output(operation, canonical_path, "canonical")?
    } else {
        None
    };
    let data_loop_backup = if policy == ExistingOutputPolicy::Replace {
        match backup_existing_output(operation, data_loop_path, "Data Loop") {
            Ok(backup) => backup,
            Err(error) => {
                return Err(combine_error_with_cleanup(
                    error,
                    restore_output(canonical_path, canonical_backup.as_deref(), None),
                    canonical_path,
                ))
            }
        }
    } else {
        None
    };

    let data_loop_promoted =
        match promote_output_file(operation, data_loop_temp, data_loop_path, "Data Loop") {
            Ok(promoted) => promoted,
            Err(error) => {
                return Err(combine_error_with_cleanup(
                    error,
                    restore_output_pair(
                        canonical_path,
                        canonical_backup.as_deref(),
                        None,
                        data_loop_path,
                        data_loop_backup.as_deref(),
                        None,
                    ),
                    data_loop_path,
                ))
            }
        };
    let canonical_promoted =
        match promote_output_file(operation, canonical_temp, canonical_path, "canonical") {
            Ok(promoted) => promoted,
            Err(error) => {
                return Err(combine_error_with_cleanup(
                    error,
                    restore_output_pair(
                        canonical_path,
                        canonical_backup.as_deref(),
                        None,
                        data_loop_path,
                        data_loop_backup.as_deref(),
                        Some(data_loop_promoted),
                    ),
                    canonical_path,
                ))
            }
        };

    drop((canonical_promoted, data_loop_promoted));
    remove_backups(canonical_backup.as_deref(), data_loop_backup.as_deref())
}

fn ensure_output_absent(operation: &str, path: &Path, kind: &str) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "{operation} {kind} output file already exists: {}",
                path.display()
            ),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(std::io::Error::other(format!(
            "{operation} failed to inspect {kind} output file {}: {error}",
            path.display()
        ))),
    }
}

fn ensure_output_replaceable(operation: &str, path: &Path, kind: &str) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Ok(_) => Err(std::io::Error::other(format!(
            "{operation} cannot replace non-file {kind} output path {}",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(std::io::Error::other(format!(
            "{operation} failed to inspect {kind} output file {}: {error}",
            path.display()
        ))),
    }
}

fn stage_output_file(
    operation: &str,
    final_path: &Path,
    kind: &str,
    write: impl FnOnce(&mut std::io::BufWriter<std::fs::File>) -> std::io::Result<()>,
) -> std::io::Result<tempfile::NamedTempFile> {
    let parent = final_path.parent().unwrap_or_else(|| Path::new("."));
    let temp = tempfile::NamedTempFile::new_in(parent).map_err(|error| {
        std::io::Error::other(format!(
            "{operation} failed to create temporary {kind} output file in {}: {error}",
            parent.display()
        ))
    })?;
    let file = temp.as_file().try_clone().map_err(|error| {
        std::io::Error::other(format!(
            "{operation} failed to open temporary {kind} output file for {}: {error}",
            final_path.display()
        ))
    })?;
    let mut writer = std::io::BufWriter::new(file);
    write(&mut writer)
        .and_then(|()| writer.flush())
        .and_then(|()| writer.get_ref().sync_all())
        .map_err(|error| {
            std::io::Error::other(format!(
                "{operation} failed to write temporary {kind} output file for {}: {error}",
                final_path.display()
            ))
        })?;
    Ok(temp)
}

fn promote_output_file(
    operation: &str,
    temp: tempfile::NamedTempFile,
    final_path: &Path,
    kind: &str,
) -> std::io::Result<PromotedOutput> {
    let identity_file = temp.reopen().map_err(|error| {
        std::io::Error::other(format!(
            "{operation} failed to identify temporary {kind} output file for {}: {error}",
            final_path.display()
        ))
    })?;
    let handle = same_file::Handle::from_file(identity_file).map_err(|error| {
        std::io::Error::other(format!(
            "{operation} failed to identify temporary {kind} output file for {}: {error}",
            final_path.display()
        ))
    })?;
    temp.persist_noclobber(final_path)
        .map(|_| PromotedOutput { handle })
        .map_err(|error| {
            std::io::Error::other(format!(
                "{operation} failed to promote {kind} output file {}: {}",
                final_path.display(),
                error.error
            ))
        })
}

fn backup_existing_output(
    operation: &str,
    final_path: &Path,
    kind: &str,
) -> std::io::Result<Option<PathBuf>> {
    if !final_path.try_exists().map_err(|error| {
        std::io::Error::other(format!(
            "{operation} failed to inspect {kind} output file {}: {error}",
            final_path.display()
        ))
    })? {
        return Ok(None);
    }

    let backup_path = vacant_sibling_path(operation, final_path, kind)?;
    persist_existing_file_noclobber(final_path, &backup_path).map_err(|error| {
        std::io::Error::other(format!(
            "{operation} failed to back up {kind} output file {}: {error}",
            final_path.display()
        ))
    })?;
    Ok(Some(backup_path))
}

fn vacant_sibling_path(operation: &str, final_path: &Path, kind: &str) -> std::io::Result<PathBuf> {
    let parent = final_path.parent().unwrap_or_else(|| Path::new("."));
    let backup = tempfile::NamedTempFile::new_in(parent).map_err(|error| {
        std::io::Error::other(format!(
            "{operation} failed to reserve temporary path for {kind} output file {}: {error}",
            final_path.display()
        ))
    })?;
    let backup_path = backup.path().to_path_buf();
    backup.close().map_err(|error| {
        std::io::Error::other(format!(
            "{operation} failed to prepare temporary path for {kind} output file {}: {error}",
            final_path.display()
        ))
    })?;
    Ok(backup_path)
}

fn restore_output_pair(
    canonical_path: &Path,
    canonical_backup: Option<&Path>,
    canonical_promoted: Option<PromotedOutput>,
    data_loop_path: &Path,
    data_loop_backup: Option<&Path>,
    data_loop_promoted: Option<PromotedOutput>,
) -> std::io::Result<()> {
    let data_loop_result = restore_output(data_loop_path, data_loop_backup, data_loop_promoted);
    let canonical_result = restore_output(canonical_path, canonical_backup, canonical_promoted);
    match (data_loop_result, canonical_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(first), Err(second)) => Err(std::io::Error::other(format!(
            "{first}; additionally failed to restore {}: {second}",
            canonical_path.display()
        ))),
    }
}

fn restore_output(
    final_path: &Path,
    backup_path: Option<&Path>,
    promoted: Option<PromotedOutput>,
) -> std::io::Result<()> {
    if let Some(promoted) = promoted {
        remove_promoted_output_if_owned(final_path, promoted, backup_path)?;
    } else if backup_path.is_some() && final_path.try_exists()? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "cannot restore {} because another writer created it; backup retained at {}",
                final_path.display(),
                backup_path.map_or_else(|| "<none>".into(), |path| path.display().to_string())
            ),
        ));
    }
    if let Some(backup_path) = backup_path {
        restore_backup_noclobber(backup_path, final_path)?;
    }
    Ok(())
}

fn remove_promoted_output_if_owned(
    final_path: &Path,
    promoted: PromotedOutput,
    backup_path: Option<&Path>,
) -> std::io::Result<()> {
    let quarantine_path = vacant_sibling_path("paired output rollback", final_path, "promoted")?;
    match persist_existing_file_noclobber(final_path, &quarantine_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    }
    let matches = promoted.matches_path(&quarantine_path);
    drop(promoted);
    match matches {
        Ok(true) => remove_if_present(&quarantine_path),
        Ok(false) => {
            let restore_result = persist_existing_file_noclobber(&quarantine_path, final_path);
            if let Err(restore_error) = restore_result {
                return Err(std::io::Error::other(format!(
                    "cannot restore {} because another writer replaced the promoted output; \
                     unowned file retained at {} and backup retained at {}: {restore_error}",
                    final_path.display(),
                    quarantine_path.display(),
                    backup_path.map_or_else(|| "<none>".into(), |path| path.display().to_string())
                )));
            }
            Err(std::io::Error::other(format!(
                "cannot restore {} because another writer replaced the promoted output; backup retained at {}",
                final_path.display(),
                backup_path.map_or_else(|| "<none>".into(), |path| path.display().to_string())
            )))
        }
        Err(error) => {
            let _ = persist_existing_file_noclobber(&quarantine_path, final_path);
            Err(error)
        }
    }
}

fn restore_backup_noclobber(backup_path: &Path, final_path: &Path) -> std::io::Result<()> {
    persist_existing_file_noclobber(backup_path, final_path)
}

fn persist_existing_file_noclobber(source_path: &Path, final_path: &Path) -> std::io::Result<()> {
    let file = std::fs::OpenOptions::new().read(true).open(source_path)?;
    let temp_path = tempfile::TempPath::try_from_path(source_path.to_path_buf())?;
    let mut source = tempfile::NamedTempFile::from_parts(file, temp_path);
    // On a failed no-clobber promotion the original file is the recovery
    // artifact, so it must outlive the temporary wrapper.
    source.disable_cleanup(true);
    source
        .persist_noclobber(final_path)
        .map(|_| ())
        .map_err(|error| error.error)
}

fn remove_backups(
    canonical_backup: Option<&Path>,
    data_loop_backup: Option<&Path>,
) -> std::io::Result<()> {
    let canonical_result = canonical_backup.map_or(Ok(()), remove_if_present);
    let data_loop_result = data_loop_backup.map_or(Ok(()), remove_if_present);
    match (canonical_result, data_loop_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(first), Err(second)) => Err(std::io::Error::other(format!(
            "{first}; additionally failed to remove Data Loop backup: {second}"
        ))),
    }
}

fn remove_if_present(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn combine_error_with_cleanup(
    error: std::io::Error,
    cleanup: std::io::Result<()>,
    cleanup_path: &Path,
) -> std::io::Error {
    match cleanup {
        Ok(()) => error,
        Err(cleanup_error) => std::io::Error::other(format!(
            "{error}; additionally failed to remove {}: {cleanup_error}",
            cleanup_path.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replace_rejects_non_file_output_before_promoting_sibling() {
        let directory = tempfile::tempdir().unwrap();
        let canonical_path = directory.path().join("denials.json");
        let data_loop_path = directory.path().join("denials.data-loop.json");
        std::fs::create_dir(&canonical_path).unwrap();

        let error = write_paired_output_files(
            "test",
            &canonical_path,
            &data_loop_path,
            ExistingOutputPolicy::Replace,
            |writer| writer.write_all(b"canonical"),
            |writer| writer.write_all(b"data-loop"),
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("cannot replace non-file canonical"));
        assert!(!data_loop_path.exists());
    }

    #[test]
    fn failed_second_promotion_restores_previous_output() {
        let directory = tempfile::tempdir().unwrap();
        let shared_path = directory.path().join("denials.json");
        std::fs::write(&shared_path, b"previous").unwrap();

        let error = write_paired_output_files(
            "test",
            &shared_path,
            &shared_path,
            ExistingOutputPolicy::Replace,
            |writer| writer.write_all(b"canonical"),
            |writer| writer.write_all(b"data-loop"),
        )
        .unwrap_err();

        assert!(error.to_string().contains("failed to promote canonical"));
        assert_eq!(std::fs::read(shared_path).unwrap(), b"previous");
    }

    #[test]
    fn rollback_does_not_delete_unpromoted_collision() {
        let directory = tempfile::tempdir().unwrap();
        let final_path = directory.path().join("denials.json");
        let backup_path = directory.path().join("backup.json");
        std::fs::write(&final_path, b"concurrent").unwrap();
        std::fs::write(&backup_path, b"previous").unwrap();

        let error = restore_output(&final_path, Some(&backup_path), None).unwrap_err();

        assert!(error.to_string().contains("cannot restore"));
        assert_eq!(std::fs::read(final_path).unwrap(), b"concurrent");
        assert_eq!(std::fs::read(backup_path).unwrap(), b"previous");
    }

    #[test]
    fn rollback_does_not_delete_replacement_of_promoted_output() {
        let directory = tempfile::tempdir().unwrap();
        let final_path = directory.path().join("denials.json");
        let displaced_path = directory.path().join("displaced.json");
        let backup_path = directory.path().join("backup.json");
        std::fs::write(&final_path, b"promoted").unwrap();
        let promoted = PromotedOutput {
            handle: same_file::Handle::from_file(std::fs::File::open(&final_path).unwrap())
                .unwrap(),
        };
        std::fs::rename(&final_path, &displaced_path).unwrap();
        std::fs::write(&final_path, b"concurrent").unwrap();
        std::fs::write(&backup_path, b"previous").unwrap();

        let error = restore_output(&final_path, Some(&backup_path), Some(promoted)).unwrap_err();

        assert!(error.to_string().contains("another writer replaced"));
        assert_eq!(std::fs::read(final_path).unwrap(), b"concurrent");
        assert_eq!(std::fs::read(backup_path).unwrap(), b"previous");
    }

    #[test]
    fn rollback_restores_backup_when_promoted_output_was_deleted() {
        let directory = tempfile::tempdir().unwrap();
        let final_path = directory.path().join("denials.json");
        let backup_path = directory.path().join("backup.json");
        std::fs::write(&final_path, b"promoted").unwrap();
        let promoted = PromotedOutput {
            handle: same_file::Handle::from_file(std::fs::File::open(&final_path).unwrap())
                .unwrap(),
        };
        std::fs::remove_file(&final_path).unwrap();
        std::fs::write(&backup_path, b"previous").unwrap();

        restore_output(&final_path, Some(&backup_path), Some(promoted)).unwrap();

        assert_eq!(std::fs::read(final_path).unwrap(), b"previous");
        assert!(!backup_path.exists());
    }

    #[test]
    #[allow(clippy::permissions_set_readonly_false)]
    fn rollback_restores_read_only_backup() {
        let directory = tempfile::tempdir().unwrap();
        let backup_path = directory.path().join("backup.json");
        let final_path = directory.path().join("denials.json");
        std::fs::write(&backup_path, b"previous").unwrap();
        let mut permissions = std::fs::metadata(&backup_path).unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&backup_path, permissions).unwrap();

        persist_existing_file_noclobber(&backup_path, &final_path).unwrap();

        assert_eq!(std::fs::read(&final_path).unwrap(), b"previous");
        #[cfg(windows)]
        {
            let mut permissions = std::fs::metadata(&final_path).unwrap().permissions();
            permissions.set_readonly(false);
            std::fs::set_permissions(final_path, permissions).unwrap();
        }
    }

    #[test]
    fn output_pair_lock_rejects_concurrent_writer() {
        let directory = tempfile::tempdir().unwrap();
        let canonical_path = directory.path().join("denials.json");
        let first = OutputPairLock::acquire("test", &canonical_path).unwrap();

        let error = OutputPairLock::acquire("test", &canonical_path).unwrap_err();

        assert!(error.to_string().contains("another process"));
        drop(first);
        OutputPairLock::acquire("test", &canonical_path).unwrap();
    }
}
