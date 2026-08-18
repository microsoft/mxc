// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Transactional staging for the canonical and Data Loop output pair.

use sha2::{Digest, Sha256};
use std::io::{Read, Seek, Write};
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
    digest: [u8; 32],
}

impl PromotedOutput {
    fn from_file(mut file: std::fs::File) -> std::io::Result<Self> {
        let handle = same_file::Handle::from_file(file.try_clone()?)?;
        let digest = file_digest(&mut file)?;
        Ok(Self { handle, digest })
    }

    fn matches_path(&self, path: &Path) -> std::io::Result<bool> {
        let mut file = std::fs::File::open(path)?;
        let path_handle = same_file::Handle::from_file(file.try_clone()?)?;
        if self.handle != path_handle {
            return Ok(false);
        }
        Ok(self.digest == file_digest(&mut file)?)
    }
}

fn file_digest(reader: &mut (impl Read + Seek)) -> std::io::Result<[u8; 32]> {
    reader.rewind()?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(digest.finalize().into())
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
                return Err(combine_error_with_rollback(
                    error,
                    restore_output(canonical_path, canonical_backup.as_deref(), None),
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
                return Err(combine_error_with_rollback(
                    error,
                    restore_output_pair(
                        canonical_path,
                        canonical_backup.as_deref(),
                        None,
                        data_loop_path,
                        data_loop_backup.as_deref(),
                        None,
                    ),
                ))
            }
        };
    let canonical_promoted =
        match promote_output_file(operation, canonical_temp, canonical_path, "canonical") {
            Ok(promoted) => promoted,
            Err(error) => {
                return Err(combine_error_with_rollback(
                    error,
                    restore_output_pair(
                        canonical_path,
                        canonical_backup.as_deref(),
                        None,
                        data_loop_path,
                        data_loop_backup.as_deref(),
                        Some(data_loop_promoted),
                    ),
                ))
            }
        };

    drop((canonical_promoted, data_loop_promoted));
    remove_backups(canonical_backup.as_deref(), data_loop_backup.as_deref())
}

/// Copies an existing canonical/Data Loop pair to new no-clobber destinations,
/// then removes only source files whose identity and contents still match the
/// files that were copied.
///
/// The destination pair uses the same transactional promotion and rollback as
/// [`write_paired_output_files`]. Source cleanup quarantines and verifies each
/// file before deletion, so a concurrent replacement is restored rather than
/// removed.
///
/// # Errors
///
/// Returns an error when the source pair cannot be read, the destination pair
/// cannot be committed atomically, or verified source cleanup fails.
pub fn relocate_paired_output_files(
    operation: &str,
    canonical_source_path: &Path,
    data_loop_source_path: &Path,
    canonical_destination_path: &Path,
    data_loop_destination_path: &Path,
) -> std::io::Result<()> {
    if canonical_source_path == canonical_destination_path
        && data_loop_source_path == data_loop_destination_path
    {
        return Ok(());
    }
    if canonical_source_path == canonical_destination_path
        || data_loop_source_path == data_loop_destination_path
    {
        return Err(std::io::Error::other(format!(
            "{operation} cannot relocate only one member of an output pair"
        )));
    }

    let mut canonical_source = std::fs::File::open(canonical_source_path)?;
    let canonical_identity = PromotedOutput::from_file(canonical_source.try_clone()?)?;
    let mut data_loop_source = std::fs::File::open(data_loop_source_path)?;
    let data_loop_identity = PromotedOutput::from_file(data_loop_source.try_clone()?)?;

    write_paired_output_files(
        operation,
        canonical_destination_path,
        data_loop_destination_path,
        ExistingOutputPolicy::CreateNew,
        |writer| {
            canonical_source.rewind()?;
            std::io::copy(&mut canonical_source, writer).map(|_| ())
        },
        |writer| {
            data_loop_source.rewind()?;
            std::io::copy(&mut data_loop_source, writer).map(|_| ())
        },
    )?;

    drop((canonical_source, data_loop_source));
    let data_loop_cleanup =
        remove_promoted_output_if_owned(data_loop_source_path, data_loop_identity, None)
            .and_then(cleanup_result);
    let canonical_cleanup =
        remove_promoted_output_if_owned(canonical_source_path, canonical_identity, None)
            .and_then(cleanup_result);
    match (data_loop_cleanup, canonical_cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(first), Err(second)) => Err(std::io::Error::other(format!(
            "{first}; additionally failed to remove relocated canonical source {}: {second}",
            canonical_source_path.display()
        ))),
    }
}

fn cleanup_result(error: Option<std::io::Error>) -> std::io::Result<()> {
    error.map_or(Ok(()), Err)
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
    let promoted = PromotedOutput::from_file(identity_file).map_err(|error| {
        std::io::Error::other(format!(
            "{operation} failed to identify temporary {kind} output file for {}: {error}",
            final_path.display()
        ))
    })?;
    temp.persist_noclobber(final_path)
        .map(|_| promoted)
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
    let cleanup_error = if let Some(promoted) = promoted {
        remove_promoted_output_if_owned(final_path, promoted, backup_path)?
    } else if backup_path.is_some() && final_path.try_exists()? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "cannot restore {} because another writer created it; backup retained at {}",
                final_path.display(),
                backup_path.map_or_else(|| "<none>".into(), |path| path.display().to_string())
            ),
        ));
    } else {
        None
    };
    let restore_result = backup_path.map_or(Ok(()), |backup_path| {
        restore_backup_noclobber(backup_path, final_path)
    });
    finish_restore(final_path, cleanup_error, restore_result)
}

fn remove_promoted_output_if_owned(
    final_path: &Path,
    promoted: PromotedOutput,
    backup_path: Option<&Path>,
) -> std::io::Result<Option<std::io::Error>> {
    let quarantine_path = vacant_sibling_path("paired output rollback", final_path, "promoted")?;
    match persist_existing_file_noclobber(final_path, &quarantine_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(std::io::Error::other(format!(
                "failed to quarantine promoted output {} at {}: {error}",
                final_path.display(),
                quarantine_path.display()
            )))
        }
    }
    let matches = promoted.matches_path(&quarantine_path).map_err(|error| {
        std::io::Error::other(format!(
            "failed to verify ownership of quarantined output {}: {error}",
            quarantine_path.display()
        ))
    });
    drop(promoted);
    match matches {
        Ok(true) => Ok(remove_if_present(&quarantine_path).err().map(|error| {
            std::io::Error::other(format!(
                "failed to remove quarantined promoted output {}: {error}",
                quarantine_path.display()
            ))
        })),
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
        Err(error) => combine_error_with_restore(
            error,
            persist_existing_file_noclobber(&quarantine_path, final_path),
            &quarantine_path,
            final_path,
        ),
    }
}

fn combine_error_with_restore(
    error: std::io::Error,
    restore: std::io::Result<()>,
    source_path: &Path,
    final_path: &Path,
) -> std::io::Result<Option<std::io::Error>> {
    match restore {
        Ok(()) => Err(error),
        Err(restore_error) => Err(std::io::Error::other(format!(
            "{error}; additionally failed to restore {} to {}: {restore_error}",
            source_path.display(),
            final_path.display()
        ))),
    }
}

fn finish_restore(
    final_path: &Path,
    cleanup_error: Option<std::io::Error>,
    restore_result: std::io::Result<()>,
) -> std::io::Result<()> {
    match (cleanup_error, restore_result) {
        (None, Ok(())) => Ok(()),
        (None, Err(error)) | (Some(error), Ok(())) => Err(error),
        (Some(cleanup_error), Err(restore_error)) => Err(std::io::Error::other(format!(
            "{cleanup_error}; additionally failed to restore {}: {restore_error}",
            final_path.display()
        ))),
    }
}

fn restore_backup_noclobber(backup_path: &Path, final_path: &Path) -> std::io::Result<()> {
    persist_existing_file_noclobber(backup_path, final_path).map_err(|error| {
        std::io::Error::other(format!(
            "failed to restore backup {} to {}: {error}",
            backup_path.display(),
            final_path.display()
        ))
    })
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
    let canonical_result = canonical_backup.map_or(Ok(()), |path| {
        remove_if_present(path).map_err(|error| {
            std::io::Error::other(format!(
                "failed to remove canonical backup {}: {error}",
                path.display()
            ))
        })
    });
    let data_loop_result = data_loop_backup.map_or(Ok(()), |path| {
        remove_if_present(path).map_err(|error| {
            std::io::Error::other(format!(
                "failed to remove Data Loop backup {}: {error}",
                path.display()
            ))
        })
    });
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

fn combine_error_with_rollback(
    error: std::io::Error,
    rollback: std::io::Result<()>,
) -> std::io::Error {
    match rollback {
        Ok(()) => error,
        Err(rollback_error) => std::io::Error::other(format!(
            "{error}; additionally failed to roll back output pair: {rollback_error}"
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
    fn relocation_rolls_back_failed_second_promotion_and_keeps_sources() {
        let directory = tempfile::tempdir().unwrap();
        let canonical_source = directory.path().join("source-denials.json");
        let data_loop_source = directory.path().join("source-denials.data-loop.json");
        let shared_destination = directory.path().join("denials.json");
        std::fs::write(&canonical_source, b"canonical").unwrap();
        std::fs::write(&data_loop_source, b"data-loop").unwrap();

        let error = relocate_paired_output_files(
            "test relocation",
            &canonical_source,
            &data_loop_source,
            &shared_destination,
            &shared_destination,
        )
        .unwrap_err();

        assert!(error.to_string().contains("failed to promote canonical"));
        assert!(!shared_destination.exists());
        assert_eq!(std::fs::read(canonical_source).unwrap(), b"canonical");
        assert_eq!(std::fs::read(data_loop_source).unwrap(), b"data-loop");
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
        let promoted =
            PromotedOutput::from_file(std::fs::File::open(&final_path).unwrap()).unwrap();
        std::fs::rename(&final_path, &displaced_path).unwrap();
        std::fs::write(&final_path, b"concurrent").unwrap();
        std::fs::write(&backup_path, b"previous").unwrap();

        let error = restore_output(&final_path, Some(&backup_path), Some(promoted)).unwrap_err();

        assert!(error.to_string().contains("another writer replaced"));
        assert_eq!(std::fs::read(final_path).unwrap(), b"concurrent");
        assert_eq!(std::fs::read(backup_path).unwrap(), b"previous");
    }

    #[test]
    fn rollback_does_not_delete_in_place_overwrite_of_promoted_output() {
        let directory = tempfile::tempdir().unwrap();
        let final_path = directory.path().join("denials.json");
        let backup_path = directory.path().join("backup.json");
        std::fs::write(&final_path, b"promoted").unwrap();
        let promoted =
            PromotedOutput::from_file(std::fs::File::open(&final_path).unwrap()).unwrap();
        std::fs::write(&final_path, b"replaced").unwrap();
        std::fs::write(&backup_path, b"previous").unwrap();

        let error = restore_output(&final_path, Some(&backup_path), Some(promoted)).unwrap_err();

        assert!(error.to_string().contains("another writer replaced"));
        assert_eq!(std::fs::read(final_path).unwrap(), b"replaced");
        assert_eq!(std::fs::read(backup_path).unwrap(), b"previous");
    }

    #[test]
    fn rollback_restores_backup_when_promoted_output_was_deleted() {
        let directory = tempfile::tempdir().unwrap();
        let final_path = directory.path().join("denials.json");
        let backup_path = directory.path().join("backup.json");
        std::fs::write(&final_path, b"promoted").unwrap();
        let promoted =
            PromotedOutput::from_file(std::fs::File::open(&final_path).unwrap()).unwrap();
        std::fs::remove_file(&final_path).unwrap();
        std::fs::write(&backup_path, b"previous").unwrap();

        restore_output(&final_path, Some(&backup_path), Some(promoted)).unwrap();

        assert_eq!(std::fs::read(final_path).unwrap(), b"previous");
        assert!(!backup_path.exists());
    }

    #[test]
    fn rollback_reports_cleanup_failure_after_attempting_restore() {
        let cleanup_error = std::io::Error::other("quarantine cleanup failed");
        let restore_error = std::io::Error::other("backup restore failed");

        let error = finish_restore(
            Path::new("denials.json"),
            Some(cleanup_error),
            Err(restore_error),
        )
        .unwrap_err();

        assert!(error.to_string().contains("quarantine cleanup failed"));
        assert!(error.to_string().contains("backup restore failed"));
    }

    #[test]
    fn rollback_reports_failed_quarantine_restore() {
        let error = combine_error_with_restore(
            std::io::Error::other("identity check failed"),
            Err(std::io::Error::other("restore failed")),
            Path::new("quarantine.tmp"),
            Path::new("denials.json"),
        )
        .unwrap_err();

        assert!(error.to_string().contains("identity check failed"));
        assert!(error.to_string().contains("quarantine.tmp"));
        assert!(error.to_string().contains("restore failed"));
    }

    #[test]
    fn promotion_error_describes_rollback_failure() {
        let error = combine_error_with_rollback(
            std::io::Error::other("promotion failed"),
            Err(std::io::Error::other("restore failed")),
        );

        assert!(error.to_string().contains("promotion failed"));
        assert!(error
            .to_string()
            .contains("failed to roll back output pair"));
        assert!(error.to_string().contains("restore failed"));
    }

    #[test]
    fn backup_restore_error_names_source_and_destination() {
        let directory = tempfile::tempdir().unwrap();
        let backup_path = directory.path().join("backup.json");
        let final_path = directory.path().join("denials.json");
        std::fs::write(&backup_path, b"previous").unwrap();
        std::fs::write(&final_path, b"concurrent").unwrap();

        let error = restore_backup_noclobber(&backup_path, &final_path).unwrap_err();

        assert!(error
            .to_string()
            .contains(&backup_path.display().to_string()));
        assert!(error
            .to_string()
            .contains(&final_path.display().to_string()));
    }

    #[test]
    fn backup_cleanup_error_names_the_failed_path() {
        let directory = tempfile::tempdir().unwrap();
        let canonical_backup = directory.path().join("canonical-backup");
        std::fs::create_dir(&canonical_backup).unwrap();

        let error = remove_backups(Some(&canonical_backup), None).unwrap_err();

        assert!(error
            .to_string()
            .contains(&canonical_backup.display().to_string()));
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
