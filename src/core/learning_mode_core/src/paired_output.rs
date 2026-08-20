// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Transactional staging for the canonical and verbose logging output pair.

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

/// Result of a successfully committed output relocation.
///
/// Source cleanup happens after the destination is committed. Cleanup failures
/// are warnings rather than relocation failures so callers can publish the
/// authoritative destination path.
#[derive(Debug, Default)]
pub struct RelocationOutcome {
    cleanup_warnings: Vec<String>,
}

impl RelocationOutcome {
    /// Returns warnings produced while removing verified source artifacts.
    pub fn cleanup_warnings(&self) -> &[String] {
        &self.cleanup_warnings
    }

    /// Consumes the outcome and returns its source-cleanup warnings.
    pub fn into_cleanup_warnings(self) -> Vec<String> {
        self.cleanup_warnings
    }

    fn record_cleanup_error(&mut self, kind: &str, path: &Path, error: std::io::Error) {
        self.cleanup_warnings.push(format!(
            "relocation committed, but failed to remove {kind} source {}: {error}",
            path.display()
        ));
    }
}

/// Stages, flushes, and promotes a canonical output and its verbose logging sibling.
///
/// Both documents are serialized before either final path is changed. Replace
/// mode retains the previous files until both new files are promoted, allowing
/// a failed promotion to restore the complete previous pair.
pub fn write_paired_output_files(
    operation: &str,
    canonical_path: &Path,
    verbose_logging_path: &Path,
    policy: ExistingOutputPolicy,
    write_canonical: impl FnOnce(&mut std::io::BufWriter<std::fs::File>) -> std::io::Result<()>,
    write_verbose_logging: impl FnOnce(&mut std::io::BufWriter<std::fs::File>) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let _pair_lock = match policy {
        ExistingOutputPolicy::CreateNew => None,
        ExistingOutputPolicy::Replace => Some(OutputPairLock::acquire(operation, canonical_path)?),
    };
    match policy {
        ExistingOutputPolicy::CreateNew => {
            ensure_output_absent(operation, canonical_path, "canonical")?;
            ensure_output_absent(operation, verbose_logging_path, "verbose logging")?;
        }
        ExistingOutputPolicy::Replace => {
            ensure_output_replaceable(operation, canonical_path, "canonical")?;
            ensure_output_replaceable(operation, verbose_logging_path, "verbose logging")?;
        }
    }

    let canonical_temp =
        stage_output_file(operation, canonical_path, "canonical", write_canonical)?;
    let verbose_logging_temp = stage_output_file(
        operation,
        verbose_logging_path,
        "verbose logging",
        write_verbose_logging,
    )?;

    let canonical_backup = if policy == ExistingOutputPolicy::Replace {
        backup_existing_output(operation, canonical_path, "canonical")?
    } else {
        None
    };
    let verbose_logging_backup = if policy == ExistingOutputPolicy::Replace {
        match backup_existing_output(operation, verbose_logging_path, "verbose logging") {
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

    let verbose_logging_promoted = match promote_output_file(
        operation,
        verbose_logging_temp,
        verbose_logging_path,
        "verbose logging",
    ) {
        Ok(promoted) => promoted,
        Err(error) => {
            return Err(combine_error_with_rollback(
                error,
                restore_output_pair(
                    canonical_path,
                    canonical_backup.as_deref(),
                    None,
                    verbose_logging_path,
                    verbose_logging_backup.as_deref(),
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
                        verbose_logging_path,
                        verbose_logging_backup.as_deref(),
                        Some(verbose_logging_promoted),
                    ),
                ))
            }
        };

    drop((canonical_promoted, verbose_logging_promoted));
    remove_backups(
        canonical_backup.as_deref(),
        verbose_logging_backup.as_deref(),
    )
}

/// Copies an existing canonical/verbose logging pair to new no-clobber destinations,
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
/// Returns an error when the source pair cannot be read or the destination pair
/// cannot be committed atomically. Source-cleanup failures are returned as
/// warnings in [`RelocationOutcome`] after destination commit.
pub fn relocate_paired_output_files(
    operation: &str,
    canonical_source_path: &Path,
    verbose_logging_source_path: &Path,
    canonical_destination_path: &Path,
    verbose_logging_destination_path: &Path,
) -> std::io::Result<RelocationOutcome> {
    if canonical_source_path == canonical_destination_path
        && verbose_logging_source_path == verbose_logging_destination_path
    {
        return Ok(RelocationOutcome::default());
    }
    if canonical_source_path == canonical_destination_path
        || verbose_logging_source_path == verbose_logging_destination_path
    {
        return Err(std::io::Error::other(format!(
            "{operation} cannot relocate only one member of an output pair"
        )));
    }

    let mut canonical_source = std::fs::File::open(canonical_source_path)?;
    let canonical_identity = PromotedOutput::from_file(canonical_source.try_clone()?)?;
    let mut verbose_logging_source = std::fs::File::open(verbose_logging_source_path)?;
    let verbose_logging_identity = PromotedOutput::from_file(verbose_logging_source.try_clone()?)?;

    write_paired_output_files(
        operation,
        canonical_destination_path,
        verbose_logging_destination_path,
        ExistingOutputPolicy::CreateNew,
        |writer| {
            canonical_source.rewind()?;
            std::io::copy(&mut canonical_source, writer).map(|_| ())
        },
        |writer| {
            verbose_logging_source.rewind()?;
            std::io::copy(&mut verbose_logging_source, writer).map(|_| ())
        },
    )?;

    drop((canonical_source, verbose_logging_source));
    let verbose_logging_cleanup = remove_promoted_output_if_owned(
        verbose_logging_source_path,
        verbose_logging_identity,
        None,
    )
    .and_then(cleanup_result);
    let canonical_cleanup =
        remove_promoted_output_if_owned(canonical_source_path, canonical_identity, None)
            .and_then(cleanup_result);
    let mut outcome = RelocationOutcome::default();
    if let Err(error) = verbose_logging_cleanup {
        outcome.record_cleanup_error("verbose logging", verbose_logging_source_path, error);
    }
    if let Err(error) = canonical_cleanup {
        outcome.record_cleanup_error("canonical", canonical_source_path, error);
    }
    Ok(outcome)
}

/// Copies one existing output to a new no-clobber destination, then removes
/// the source only if its identity and contents still match the copied file.
///
/// # Errors
///
/// Returns an error when the source cannot be read or the destination cannot be
/// committed without clobbering. Source-cleanup failures are returned as
/// warnings in [`RelocationOutcome`] after destination commit.
pub fn relocate_output_file(
    operation: &str,
    kind: &str,
    source_path: &Path,
    destination_path: &Path,
) -> std::io::Result<RelocationOutcome> {
    if source_path == destination_path {
        return Ok(RelocationOutcome::default());
    }

    let mut source = std::fs::File::open(source_path)?;
    let source_identity = PromotedOutput::from_file(source.try_clone()?)?;
    ensure_output_absent(operation, destination_path, kind)?;
    let temp = stage_output_file(operation, destination_path, kind, |writer| {
        source.rewind()?;
        std::io::copy(&mut source, writer).map(|_| ())
    })?;
    let promoted = promote_output_file(operation, temp, destination_path, kind)?;
    drop((source, promoted));
    let mut outcome = RelocationOutcome::default();
    if let Err(error) =
        remove_promoted_output_if_owned(source_path, source_identity, None).and_then(cleanup_result)
    {
        outcome.record_cleanup_error(kind, source_path, error);
    }
    Ok(outcome)
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
    backup_existing_output_with(operation, final_path, kind, persist_existing_file_noclobber)
}

fn backup_existing_output_with(
    operation: &str,
    final_path: &Path,
    kind: &str,
    persist: impl FnOnce(&Path, &Path) -> std::io::Result<()>,
) -> std::io::Result<Option<PathBuf>> {
    let file = match std::fs::File::open(final_path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(std::io::Error::other(format!(
                "{operation} failed to inspect {kind} output file {}: {error}",
                final_path.display()
            )))
        }
    };
    let expected = PromotedOutput::from_file(file).map_err(|error| {
        std::io::Error::other(format!(
            "{operation} failed to identify existing {kind} output file {}: {error}",
            final_path.display()
        ))
    })?;
    let backup_path = vacant_sibling_path(operation, final_path, kind)?;
    persist(final_path, &backup_path).map_err(|error| {
        std::io::Error::other(format!(
            "{operation} failed to back up {kind} output file {}: {error}",
            final_path.display()
        ))
    })?;
    let matches = expected.matches_path(&backup_path).map_err(|error| {
        std::io::Error::other(format!(
            "{operation} failed to verify backed-up {kind} output file {}: {error}",
            backup_path.display()
        ))
    });
    drop(expected);

    match matches {
        Ok(true) => Ok(Some(backup_path)),
        Ok(false) => {
            let error = std::io::Error::other(format!(
                "{operation} detected that {kind} output {} was replaced while it was being backed up",
                final_path.display()
            ));
            match persist_existing_file_noclobber(&backup_path, final_path) {
                Ok(()) => Err(error),
                Err(restore_error) => Err(std::io::Error::other(format!(
                    "{error}; additionally failed to restore unowned file {} to {}: {restore_error}",
                    backup_path.display(),
                    final_path.display()
                ))),
            }
        }
        Err(error) => match persist_existing_file_noclobber(&backup_path, final_path) {
            Ok(()) => Err(error),
            Err(restore_error) => Err(std::io::Error::other(format!(
                "{error}; additionally failed to restore unverifiable file {} to {}: {restore_error}",
                backup_path.display(),
                final_path.display()
            ))),
        },
    }
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
    verbose_logging_path: &Path,
    verbose_logging_backup: Option<&Path>,
    verbose_logging_promoted: Option<PromotedOutput>,
) -> std::io::Result<()> {
    let verbose_logging_result = restore_output(
        verbose_logging_path,
        verbose_logging_backup,
        verbose_logging_promoted,
    );
    let canonical_result = restore_output(canonical_path, canonical_backup, canonical_promoted);
    match (verbose_logging_result, canonical_result) {
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
        Ok(true) => remove_quarantine_or_restore(final_path, &quarantine_path, remove_if_present),
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

fn remove_quarantine_or_restore(
    final_path: &Path,
    quarantine_path: &Path,
    remove: impl FnOnce(&Path) -> std::io::Result<()>,
) -> std::io::Result<Option<std::io::Error>> {
    match remove(quarantine_path) {
        Ok(()) => Ok(None),
        Err(error) => combine_error_with_restore(
            std::io::Error::other(format!(
                "failed to remove quarantined promoted output {}: {error}",
                quarantine_path.display()
            )),
            persist_existing_file_noclobber(quarantine_path, final_path),
            quarantine_path,
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
    verbose_logging_backup: Option<&Path>,
) -> std::io::Result<()> {
    let canonical_result = canonical_backup.map_or(Ok(()), |path| {
        remove_if_present(path).map_err(|error| {
            std::io::Error::other(format!(
                "failed to remove canonical backup {}: {error}",
                path.display()
            ))
        })
    });
    let verbose_logging_result = verbose_logging_backup.map_or(Ok(()), |path| {
        remove_if_present(path).map_err(|error| {
            std::io::Error::other(format!(
                "failed to remove verbose logging backup {}: {error}",
                path.display()
            ))
        })
    });
    match (canonical_result, verbose_logging_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(first), Err(second)) => Err(std::io::Error::other(format!(
            "{first}; additionally failed to remove verbose logging backup: {second}"
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
        let verbose_logging_path = directory.path().join("denials.verbose.json");
        std::fs::create_dir(&canonical_path).unwrap();

        let error = write_paired_output_files(
            "test",
            &canonical_path,
            &verbose_logging_path,
            ExistingOutputPolicy::Replace,
            |writer| writer.write_all(b"canonical"),
            |writer| writer.write_all(b"verbose"),
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("cannot replace non-file canonical"));
        assert!(!verbose_logging_path.exists());
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
            |writer| writer.write_all(b"verbose"),
        )
        .unwrap_err();

        assert!(error.to_string().contains("failed to promote canonical"));
        assert_eq!(std::fs::read(shared_path).unwrap(), b"previous");
    }

    #[test]
    fn relocation_rolls_back_failed_second_promotion_and_keeps_sources() {
        let directory = tempfile::tempdir().unwrap();
        let canonical_source = directory.path().join("source-denials.json");
        let verbose_logging_source = directory.path().join("source-denials.verbose.json");
        let shared_destination = directory.path().join("denials.json");
        std::fs::write(&canonical_source, b"canonical").unwrap();
        std::fs::write(&verbose_logging_source, b"verbose").unwrap();

        let error = relocate_paired_output_files(
            "test relocation",
            &canonical_source,
            &verbose_logging_source,
            &shared_destination,
            &shared_destination,
        )
        .unwrap_err();

        assert!(error.to_string().contains("failed to promote canonical"));
        assert!(!shared_destination.exists());
        assert_eq!(std::fs::read(canonical_source).unwrap(), b"canonical");
        assert_eq!(std::fs::read(verbose_logging_source).unwrap(), b"verbose");
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
    fn backup_restores_concurrent_replacement_instead_of_claiming_it() {
        let directory = tempfile::tempdir().unwrap();
        let final_path = directory.path().join("denials.json");
        std::fs::write(&final_path, b"original").unwrap();

        let error = backup_existing_output_with(
            "test",
            &final_path,
            "canonical",
            |source_path, backup_path| {
                std::fs::remove_file(source_path)?;
                std::fs::write(source_path, b"concurrent")?;
                persist_existing_file_noclobber(source_path, backup_path)
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("was replaced"));
        assert_eq!(std::fs::read(&final_path).unwrap(), b"concurrent");
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

    #[test]
    fn create_new_pair_does_not_leave_a_lock_artifact() {
        let directory = tempfile::tempdir().unwrap();
        let canonical_path = directory.path().join("denials.json");
        let verbose_logging_path = directory.path().join("denials.verbose.json");

        write_paired_output_files(
            "test",
            &canonical_path,
            &verbose_logging_path,
            ExistingOutputPolicy::CreateNew,
            |writer| writer.write_all(b"canonical"),
            |writer| writer.write_all(b"verbose"),
        )
        .unwrap();

        assert!(!directory.path().join(".denials.json.pair.lock").exists());
    }

    #[test]
    fn quarantine_cleanup_failure_restores_the_original_path() {
        let directory = tempfile::tempdir().unwrap();
        let final_path = directory.path().join("source.json");
        let quarantine_path = directory.path().join("source.quarantine");
        std::fs::write(&quarantine_path, b"source").unwrap();

        let error = remove_quarantine_or_restore(&final_path, &quarantine_path, |_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "injected cleanup failure",
            ))
        })
        .unwrap_err();

        assert!(error.to_string().contains("injected cleanup failure"));
        assert_eq!(std::fs::read(final_path).unwrap(), b"source");
        assert!(!quarantine_path.exists());
    }
}
