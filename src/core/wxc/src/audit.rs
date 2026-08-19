// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `wxc-exec --audit` compatibility artifacts built on `captureDenials`.

use std::path::{Path, PathBuf};

use wxc_common::models::{
    CaptureDenialsConfig, CaptureDenialsMode, ExecutionRequest, ScriptResponse,
};

#[derive(Debug)]
pub struct AuditContext {
    pub log_dir: PathBuf,
    pub config_path: Option<PathBuf>,
}

pub fn prepare_request(
    request: &mut ExecutionRequest,
    config_path: Option<PathBuf>,
) -> Result<AuditContext, String> {
    prepare_request_in(request, config_path, plm::stop::default_log_dir())
}

fn prepare_request_in(
    request: &mut ExecutionRequest,
    config_path: Option<PathBuf>,
    log_dir: PathBuf,
) -> Result<AuditContext, String> {
    std::fs::create_dir_all(&log_dir)
        .map_err(|error| format!("failed to create audit log directory: {error}"))?;
    request.policy.capture_denials = Some(CaptureDenialsConfig {
        mode: CaptureDenialsMode::Allow,
        output_path: Some(log_dir.join("denials.json").to_string_lossy().into_owned()),
        retain_etl: true,
    });
    Ok(AuditContext {
        log_dir,
        config_path,
    })
}

pub fn finalize(
    response: &mut ScriptResponse,
    context: &AuditContext,
    exe_dir: &Path,
    verbose: bool,
) -> Result<(), String> {
    let metadata = response
        .output_metadata
        .as_mut()
        .ok_or_else(|| "captureDenials returned no output metadata".to_string())?;
    if let Some(error) = metadata.capture_denials_error.as_ref() {
        return Err(format!(
            "captureDenials finalization failed: {}; retained ETL: {}",
            error.message, error.etl_path
        ));
    }
    let capture = metadata
        .capture_denials
        .as_mut()
        .ok_or_else(|| "captureDenials returned no successful output metadata".to_string())?;
    let source_denials = PathBuf::from(&capture.output_path);
    let source_verbose_logging = learning_mode_core::verbose_logging_sibling_path(&source_denials)
        .map_err(|error| {
            format!(
                "failed to derive verbose logging path from {}: {error}",
                source_denials.display()
            )
        })?;
    let source_etl = capture
        .etl_path
        .as_deref()
        .map(PathBuf::from)
        .ok_or_else(|| "captureDenials did not return the retained ETL path".to_string())?;
    if !source_denials.is_file() {
        return Err(format!(
            "captureDenials output file is missing: {}",
            source_denials.display()
        ));
    }
    if !source_etl.is_file() {
        return Err(format!(
            "captureDenials retained ETL is missing: {}",
            source_etl.display()
        ));
    }
    if !source_verbose_logging.is_file() {
        return Err(format!(
            "captureDenials verbose logging output file is missing: {}",
            source_verbose_logging.display()
        ));
    }

    let document: learning_mode_core::DenialsDocument =
        serde_json::from_slice(&std::fs::read(&source_denials).map_err(|error| {
            format!(
                "failed to read captureDenials output {}: {error}",
                source_denials.display()
            )
        })?)
        .map_err(|error| {
            format!(
                "captureDenials output {} is not valid canonical denials JSON: {error}",
                source_denials.display()
            )
        })?;
    validate_metadata(capture, &document)?;
    let _: learning_mode_core::VerboseLoggingDocument =
        serde_json::from_slice(&std::fs::read(&source_verbose_logging).map_err(|error| {
            format!(
                "failed to read captureDenials verbose logging output {}: {error}",
                source_verbose_logging.display()
            )
        })?)
        .map_err(|error| {
            format!(
                "captureDenials verbose logging output {} is not valid JSON: {error}",
                source_verbose_logging.display()
            )
        })?;

    let final_denials = context.log_dir.join("denials.json");
    let final_verbose_logging = learning_mode_core::verbose_logging_sibling_path(&final_denials)
        .map_err(|error| format!("failed to derive audit verbose logging output path: {error}"))?;
    let final_etl = context.log_dir.join("trace.etl");
    relocate_artifacts(
        capture,
        &ArtifactRelocation {
            source_denials: &source_denials,
            final_denials: &final_denials,
            source_verbose_logging: &source_verbose_logging,
            final_verbose_logging: &final_verbose_logging,
            source_etl: &source_etl,
            final_etl: &final_etl,
        },
        learning_mode_core::relocate_paired_output_files,
        move_new_file,
    )?;
    remove_empty_managed_directory(source_etl.parent(), &context.log_dir)?;

    plm::stop::postprocess_denials(
        &document,
        &plm::stop::PostProcessOptions {
            log_dir: context.log_dir.clone(),
            bin_path: None,
            config_path: context.config_path.clone(),
            trace_path: final_etl.clone(),
            denials_path: final_denials.clone(),
            verbose,
        },
        exe_dir,
    )
    .map_err(|error| format!("failed to generate audit compatibility artifacts: {error:#}"))?;

    Ok(())
}

fn validate_metadata(
    capture: &wxc_common::models::CaptureDenialsOutput,
    document: &learning_mode_core::DenialsDocument,
) -> Result<(), String> {
    if capture.kind != wxc_common::models::CaptureDenialsOutput::KIND
        || capture.exit_code != document.summary.exit_code
        || capture.total_denials != document.summary.total_denials
        || capture.denied_resources_truncated != document.summary.denied_resources_truncated
    {
        return Err(
            "captureDenials metadata does not match the canonical denials document".to_string(),
        );
    }
    Ok(())
}

/// Relocates the capture artifacts into the audit log directory, keeping the
/// on-disk state and the metadata paths mutually truthful even on partial
/// failure.
///
/// The JSON pair is relocated transactionally and its final canonical path is
/// published only after both siblings commit. The retained ETL moves last and
/// its final path is published immediately on success. A later move failure
/// therefore leaves every metadata path truthful.
///
/// `move_file` is injected so tests can force a second-move failure
/// deterministically; production passes [`move_new_file`].
struct ArtifactRelocation<'a> {
    source_denials: &'a Path,
    final_denials: &'a Path,
    source_verbose_logging: &'a Path,
    final_verbose_logging: &'a Path,
    source_etl: &'a Path,
    final_etl: &'a Path,
}

fn relocate_artifacts(
    capture: &mut wxc_common::models::CaptureDenialsOutput,
    paths: &ArtifactRelocation<'_>,
    relocate_pair: impl FnOnce(&str, &Path, &Path, &Path, &Path) -> std::io::Result<()>,
    mut move_file: impl FnMut(&Path, &Path) -> Result<(), String>,
) -> Result<(), String> {
    ensure_destination_available(paths.source_etl, paths.final_etl)?;

    relocate_pair(
        "audit output relocation",
        paths.source_denials,
        paths.source_verbose_logging,
        paths.final_denials,
        paths.final_verbose_logging,
    )
    .map_err(|error| format!("failed to relocate audit output pair: {error}"))?;
    capture.output_path = paths.final_denials.to_string_lossy().into_owned();

    // Retained ETL last: on failure it stays at its source and `etl_path`
    // still points there (unchanged), so each artifact remains individually
    // truthful even though the relocation as a whole failed.
    move_file(paths.source_etl, paths.final_etl)?;
    capture.etl_path = Some(paths.final_etl.to_string_lossy().into_owned());
    Ok(())
}

fn move_new_file(source: &Path, destination: &Path) -> Result<(), String> {
    learning_mode_core::relocate_output_file(
        "audit artifact relocation",
        "retained ETL",
        source,
        destination,
    )
    .map_err(|error| {
        format!(
            "failed to move audit artifact {} to {}: {error}",
            source.display(),
            destination.display()
        )
    })
}

fn ensure_destination_available(source: &Path, destination: &Path) -> Result<(), String> {
    if source != destination && destination.exists() {
        return Err(format!(
            "audit artifact destination already exists: {}",
            destination.display()
        ));
    }
    Ok(())
}

fn remove_empty_managed_directory(
    directory: Option<&Path>,
    audit_dir: &Path,
) -> Result<(), String> {
    let Some(directory) = directory else {
        return Ok(());
    };
    // Only prune a per-run directory promoted into the backend's retained-ETL
    // store; the predicate is owned by `appcontainer_common` so this does not
    // duplicate the store's private directory name.
    let is_retained_capture_dir =
        appcontainer_common::capture_output::is_retained_capture_run_dir(directory);
    if directory == audit_dir || !is_retained_capture_dir {
        return Ok(());
    }
    match std::fs::remove_dir(directory) {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(format!(
            "failed to remove empty retained-ETL directory {}: {error}",
            directory.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use learning_mode_core::{
        DenialSummary, DenialsDocument, VerboseLoggingDocument, VerboseLoggingSummary,
    };
    use wxc_common::models::{
        CaptureDenialsErrorOutput, CaptureDenialsOutput, SandboxOutputMetadata,
    };

    #[test]
    fn prepare_injects_allow_capture_and_retention() {
        let directory = tempfile::tempdir().unwrap();
        let log_dir = directory.path().join("audit");
        let config_path = PathBuf::from(r"C:\policy.json");
        let mut request = ExecutionRequest::default();

        let context =
            prepare_request_in(&mut request, Some(config_path.clone()), log_dir.clone()).unwrap();
        let capture = request.policy.capture_denials.as_ref().unwrap();

        assert_eq!(capture.mode, CaptureDenialsMode::Allow);
        assert!(capture.retain_etl);
        assert_eq!(
            capture.output_path.as_deref(),
            Some(log_dir.join("denials.json").to_string_lossy().as_ref())
        );
        assert_eq!(context.config_path, Some(config_path));
        assert!(context.log_dir.is_dir());
    }

    #[test]
    fn finalize_relocates_outputs_and_updates_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let log_dir = directory.path().join("audit");
        let retained_dir = directory.path().join("retained").join("run");
        std::fs::create_dir_all(&log_dir).unwrap();
        std::fs::create_dir_all(&retained_dir).unwrap();
        let source_denials = log_dir.join("denials.unique.json");
        let source_etl = retained_dir.join("capture.etl");
        let document = DenialsDocument::new(Vec::new(), DenialSummary::new(23, 0, false));
        std::fs::write(&source_denials, serde_json::to_vec(&document).unwrap()).unwrap();
        std::fs::write(&source_etl, b"etl").unwrap();
        let mut response = response_with_capture(&source_denials, &source_etl, 23);
        let context = AuditContext {
            log_dir: log_dir.clone(),
            config_path: None,
        };

        finalize(&mut response, &context, directory.path(), false).unwrap();

        assert!(!source_denials.exists());
        assert!(
            !learning_mode_core::verbose_logging_sibling_path(&source_denials)
                .unwrap()
                .exists()
        );
        assert!(!source_etl.exists());
        assert!(!retained_dir.exists());
        assert_eq!(std::fs::read(log_dir.join("trace.etl")).unwrap(), b"etl");
        assert!(log_dir.join("denials.verbose.json").is_file());
        let capture = response
            .output_metadata
            .as_ref()
            .unwrap()
            .capture_denials
            .as_ref()
            .unwrap();
        assert_eq!(
            Path::new(&capture.output_path),
            log_dir.join("denials.json")
        );
        assert_eq!(
            capture.etl_path.as_deref().map(Path::new),
            Some(log_dir.join("trace.etl").as_path())
        );
    }

    #[test]
    fn finalize_updates_metadata_before_postprocessing_failure() {
        let directory = tempfile::tempdir().unwrap();
        let log_dir = directory.path().join("audit");
        std::fs::create_dir_all(&log_dir).unwrap();
        let source_denials = log_dir.join("denials.unique.json");
        let source_etl = log_dir.join("denials.unique.etl");
        let document = DenialsDocument::new(Vec::new(), DenialSummary::new(0, 0, false));
        std::fs::write(&source_denials, serde_json::to_vec(&document).unwrap()).unwrap();
        std::fs::write(&source_etl, b"etl").unwrap();
        let mut response = response_with_capture(&source_denials, &source_etl, 0);
        let context = AuditContext {
            log_dir: log_dir.clone(),
            config_path: Some(directory.path().join("missing-policy.json")),
        };

        let error = finalize(&mut response, &context, directory.path(), false).unwrap_err();

        assert!(error.contains("audit compatibility artifacts"));
        let capture = response
            .output_metadata
            .as_ref()
            .unwrap()
            .capture_denials
            .as_ref()
            .unwrap();
        assert_eq!(
            Path::new(&capture.output_path),
            log_dir.join("denials.json")
        );
        assert_eq!(
            capture.etl_path.as_deref().map(Path::new),
            Some(log_dir.join("trace.etl").as_path())
        );
        assert!(log_dir.join("denials.json").is_file());
        assert!(log_dir.join("denials.verbose.json").is_file());
        assert!(log_dir.join("trace.etl").is_file());
    }

    #[test]
    fn finalize_rejects_missing_or_failed_capture_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let context = AuditContext {
            log_dir: directory.path().join("audit"),
            config_path: None,
        };
        let mut missing = ScriptResponse::default();
        assert!(finalize(&mut missing, &context, directory.path(), false)
            .unwrap_err()
            .contains("no output metadata"));

        let mut failed = ScriptResponse {
            output_metadata: Some(Box::new(SandboxOutputMetadata {
                capture_denials: None,
                capture_denials_error: Some(CaptureDenialsErrorOutput {
                    message: "decode failed".to_string(),
                    etl_path: r"C:\retained\capture.etl".to_string(),
                }),
            })),
            ..Default::default()
        };
        let error = finalize(&mut failed, &context, directory.path(), false).unwrap_err();
        assert!(error.contains("decode failed"));
        assert!(error.contains("capture.etl"));
    }

    #[test]
    fn finalize_rejects_malformed_json_without_moving_artifacts() {
        let directory = tempfile::tempdir().unwrap();
        let log_dir = directory.path().join("audit");
        std::fs::create_dir_all(&log_dir).unwrap();
        let source_denials = log_dir.join("denials.unique.json");
        let source_etl = log_dir.join("denials.unique.etl");
        std::fs::write(&source_denials, b"{").unwrap();
        std::fs::write(&source_etl, b"etl").unwrap();
        let mut response = response_with_capture(&source_denials, &source_etl, 0);
        let context = AuditContext {
            log_dir,
            config_path: None,
        };

        let error = finalize(&mut response, &context, directory.path(), false).unwrap_err();

        assert!(error.contains("canonical denials JSON"));
        assert!(source_denials.exists());
        assert!(
            learning_mode_core::verbose_logging_sibling_path(&source_denials)
                .unwrap()
                .exists()
        );
        assert!(source_etl.exists());
    }

    #[test]
    fn finalize_rejects_malformed_verbose_logging_without_moving_artifacts() {
        let directory = tempfile::tempdir().unwrap();
        let log_dir = directory.path().join("audit");
        std::fs::create_dir_all(&log_dir).unwrap();
        let source_denials = log_dir.join("denials.unique.json");
        let source_verbose_logging =
            learning_mode_core::verbose_logging_sibling_path(&source_denials).unwrap();
        let source_etl = log_dir.join("denials.unique.etl");
        let document = DenialsDocument::new(Vec::new(), DenialSummary::new(0, 0, false));
        std::fs::write(&source_denials, serde_json::to_vec(&document).unwrap()).unwrap();
        std::fs::write(&source_etl, b"etl").unwrap();
        let mut response = response_with_capture(&source_denials, &source_etl, 0);
        std::fs::write(&source_verbose_logging, b"{").unwrap();
        let context = AuditContext {
            log_dir: log_dir.clone(),
            config_path: None,
        };

        let error = finalize(&mut response, &context, directory.path(), false).unwrap_err();

        assert!(error.contains("verbose logging output"));
        assert!(error.contains("not valid JSON"));
        assert!(source_denials.is_file());
        assert!(source_verbose_logging.is_file());
        assert!(source_etl.is_file());
        assert!(!log_dir.join("denials.json").exists());
        assert!(!log_dir.join("denials.verbose.json").exists());
        assert!(!log_dir.join("trace.etl").exists());
    }

    #[test]
    fn finalize_preflights_both_destinations_before_moving_artifacts() {
        let directory = tempfile::tempdir().unwrap();
        let log_dir = directory.path().join("audit");
        std::fs::create_dir_all(&log_dir).unwrap();
        let source_denials = log_dir.join("denials.unique.json");
        let source_etl = log_dir.join("denials.unique.etl");
        let document = DenialsDocument::new(Vec::new(), DenialSummary::new(0, 0, false));
        std::fs::write(&source_denials, serde_json::to_vec(&document).unwrap()).unwrap();
        std::fs::write(&source_etl, b"etl").unwrap();
        std::fs::write(log_dir.join("denials.json"), b"existing").unwrap();
        let mut response = response_with_capture(&source_denials, &source_etl, 0);
        let context = AuditContext {
            log_dir: log_dir.clone(),
            config_path: None,
        };

        let error = finalize(&mut response, &context, directory.path(), false).unwrap_err();

        assert!(error.contains("canonical output file already exists"));
        assert!(source_denials.exists());
        assert!(
            learning_mode_core::verbose_logging_sibling_path(&source_denials)
                .unwrap()
                .exists()
        );
        assert!(source_etl.exists());
        assert!(!log_dir.join("trace.etl").exists());
    }

    #[test]
    fn etl_relocation_never_clobbers_an_existing_destination() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.json");
        let destination = directory.path().join("destination.json");
        std::fs::write(&source, b"new").unwrap();
        std::fs::write(&destination, b"existing").unwrap();

        let error = move_new_file(&source, &destination).unwrap_err();

        assert!(error.contains("already exists"));
        assert_eq!(std::fs::read(&source).unwrap(), b"new");
        assert_eq!(std::fs::read(&destination).unwrap(), b"existing");
    }

    #[test]
    fn finalize_rejects_missing_verbose_logging_output() {
        let directory = tempfile::tempdir().unwrap();
        let log_dir = directory.path().join("audit");
        std::fs::create_dir_all(&log_dir).unwrap();
        let source_denials = log_dir.join("denials.unique.json");
        let source_etl = log_dir.join("denials.unique.etl");
        let document = DenialsDocument::new(Vec::new(), DenialSummary::new(0, 0, false));
        std::fs::write(&source_denials, serde_json::to_vec(&document).unwrap()).unwrap();
        std::fs::write(&source_etl, b"etl").unwrap();
        let mut response = response_with_capture(&source_denials, &source_etl, 0);
        std::fs::remove_file(
            learning_mode_core::verbose_logging_sibling_path(&source_denials).unwrap(),
        )
        .unwrap();
        let context = AuditContext {
            log_dir,
            config_path: None,
        };

        let error = finalize(&mut response, &context, directory.path(), false).unwrap_err();

        assert!(error.contains("verbose logging output file is missing"));
        assert!(source_denials.exists());
        assert!(source_etl.exists());
    }

    #[test]
    fn relocate_keeps_metadata_truthful_when_etl_move_fails() {
        let directory = tempfile::tempdir().unwrap();
        let log_dir = directory.path().join("audit");
        std::fs::create_dir_all(&log_dir).unwrap();
        let source_denials = log_dir.join("denials.unique.json");
        let source_verbose_logging = log_dir.join("denials.unique.verbose.json");
        let source_etl = log_dir.join("denials.unique.etl");
        let final_denials = log_dir.join("denials.json");
        let final_verbose_logging = log_dir.join("denials.verbose.json");
        let final_etl = log_dir.join("trace.etl");
        std::fs::write(&source_denials, b"denials").unwrap();
        std::fs::write(&source_verbose_logging, b"verbose").unwrap();
        std::fs::write(&source_etl, b"etl").unwrap();
        let mut capture = CaptureDenialsOutput {
            kind: CaptureDenialsOutput::KIND.to_string(),
            output_path: source_denials.to_string_lossy().into_owned(),
            exit_code: 0,
            total_denials: 0,
            denied_resources_truncated: false,
            etl_path: Some(source_etl.to_string_lossy().into_owned()),
        };

        let mut calls = 0;
        let error = relocate_artifacts(
            &mut capture,
            &ArtifactRelocation {
                source_denials: &source_denials,
                final_denials: &final_denials,
                source_verbose_logging: &source_verbose_logging,
                final_verbose_logging: &final_verbose_logging,
                source_etl: &source_etl,
                final_etl: &final_etl,
            },
            learning_mode_core::relocate_paired_output_files,
            |source, destination| {
                calls += 1;
                if calls == 1 {
                    Err("injected ETL move failure".to_string())
                } else {
                    std::fs::rename(source, destination).map_err(|error| error.to_string())
                }
            },
        )
        .unwrap_err();

        assert!(error.contains("injected ETL move failure"));
        // Primary JSON moved; metadata truthfully points at the final path.
        assert!(final_denials.is_file());
        assert!(!source_denials.exists());
        assert_eq!(Path::new(&capture.output_path), final_denials);
        assert!(final_verbose_logging.is_file());
        assert!(!source_verbose_logging.exists());
        // ETL untouched; metadata still truthfully points at the source.
        assert!(source_etl.is_file());
        assert!(!final_etl.exists());
        assert_eq!(
            capture.etl_path.as_deref().map(Path::new),
            Some(source_etl.as_path())
        );
    }

    #[test]
    fn relocate_rolls_back_json_pair_before_publishing_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let source_denials = directory.path().join("denials.unique.json");
        let source_verbose_logging = directory.path().join("denials.unique.verbose.json");
        let source_etl = directory.path().join("denials.unique.etl");
        let shared_destination = directory.path().join("denials.json");
        let final_etl = directory.path().join("trace.etl");
        std::fs::write(&source_denials, b"denials").unwrap();
        std::fs::write(&source_verbose_logging, b"verbose").unwrap();
        std::fs::write(&source_etl, b"etl").unwrap();
        let mut capture = CaptureDenialsOutput {
            kind: CaptureDenialsOutput::KIND.to_string(),
            output_path: source_denials.to_string_lossy().into_owned(),
            exit_code: 0,
            total_denials: 0,
            denied_resources_truncated: false,
            etl_path: Some(source_etl.to_string_lossy().into_owned()),
        };

        let error = relocate_artifacts(
            &mut capture,
            &ArtifactRelocation {
                source_denials: &source_denials,
                final_denials: &shared_destination,
                source_verbose_logging: &source_verbose_logging,
                final_verbose_logging: &shared_destination,
                source_etl: &source_etl,
                final_etl: &final_etl,
            },
            learning_mode_core::relocate_paired_output_files,
            |_, _| panic!("ETL relocation must not run after JSON-pair failure"),
        )
        .unwrap_err();

        assert!(error.contains("failed to promote canonical"));
        assert_eq!(Path::new(&capture.output_path), source_denials);
        assert!(source_denials.is_file());
        assert!(source_verbose_logging.is_file());
        assert!(!shared_destination.exists());
        assert!(source_etl.is_file());
        assert!(!final_etl.exists());
    }

    fn response_with_capture(
        denials_path: &Path,
        etl_path: &Path,
        exit_code: i32,
    ) -> ScriptResponse {
        let verbose_logging_path =
            learning_mode_core::verbose_logging_sibling_path(denials_path).unwrap();
        let verbose_logging = VerboseLoggingDocument::new(&VerboseLoggingSummary::default());
        std::fs::write(
            verbose_logging_path,
            serde_json::to_vec(&verbose_logging).unwrap(),
        )
        .unwrap();
        ScriptResponse {
            exit_code,
            output_metadata: Some(Box::new(SandboxOutputMetadata {
                capture_denials: Some(CaptureDenialsOutput {
                    kind: CaptureDenialsOutput::KIND.to_string(),
                    output_path: denials_path.to_string_lossy().into_owned(),
                    exit_code,
                    total_denials: 0,
                    denied_resources_truncated: false,
                    etl_path: Some(etl_path.to_string_lossy().into_owned()),
                }),
                capture_denials_error: None,
            })),
            ..Default::default()
        }
    }
}
