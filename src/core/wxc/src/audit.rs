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
    let source_data_loop =
        learning_mode_core::data_loop_sibling_path(&source_denials).map_err(|error| {
            format!(
                "failed to derive Data Loop path from {}: {error}",
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
    if !source_data_loop.is_file() {
        return Err(format!(
            "captureDenials Data Loop output file is missing: {}",
            source_data_loop.display()
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
    let _: learning_mode_core::DataLoopDocument =
        serde_json::from_slice(&std::fs::read(&source_data_loop).map_err(|error| {
            format!(
                "failed to read captureDenials Data Loop output {}: {error}",
                source_data_loop.display()
            )
        })?)
        .map_err(|error| {
            format!(
                "captureDenials Data Loop output {} is not valid JSON: {error}",
                source_data_loop.display()
            )
        })?;

    let final_denials = context.log_dir.join("denials.json");
    let final_data_loop = context.log_dir.join("denials.data-loop.json");
    let final_etl = context.log_dir.join("trace.etl");
    relocate_artifacts(
        capture,
        &source_denials,
        &final_denials,
        &source_data_loop,
        &final_data_loop,
        &source_etl,
        &final_etl,
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
/// All destinations are preflighted (no-clobber) before anything moves. The
/// primary denials JSON moves first and its final path is published to the
/// metadata immediately; its Data Loop sibling moves second; the retained ETL
/// moves last and its final path is published immediately on success. A later
/// move failure therefore leaves every metadata path truthful.
///
/// `move_file` is injected so tests can force a second-move failure
/// deterministically; production passes [`move_new_file`].
fn relocate_artifacts(
    capture: &mut wxc_common::models::CaptureDenialsOutput,
    source_denials: &Path,
    final_denials: &Path,
    source_data_loop: &Path,
    final_data_loop: &Path,
    source_etl: &Path,
    final_etl: &Path,
    mut move_file: impl FnMut(&Path, &Path) -> Result<(), String>,
) -> Result<(), String> {
    ensure_destination_available(source_denials, final_denials)?;
    ensure_destination_available(source_data_loop, final_data_loop)?;
    ensure_destination_available(source_etl, final_etl)?;

    // Primary denials JSON first: publish its final path the instant it moves so
    // a later ETL failure can never leave `output_path` referencing a file that
    // has already been renamed away.
    move_file(source_denials, final_denials)?;
    capture.output_path = final_denials.to_string_lossy().into_owned();

    move_file(source_data_loop, final_data_loop)?;

    // Retained ETL second: on failure it stays at its source and `etl_path`
    // still points there (unchanged), so each artifact remains individually
    // truthful even though the relocation as a whole failed.
    move_file(source_etl, final_etl)?;
    capture.etl_path = Some(final_etl.to_string_lossy().into_owned());
    Ok(())
}

fn move_new_file(source: &Path, destination: &Path) -> Result<(), String> {
    if source == destination {
        return Ok(());
    }
    ensure_destination_available(source, destination)?;
    match std::fs::rename(source, destination) {
        Ok(()) => Ok(()),
        Err(rename_error) => {
            if let Err(copy_error) = std::fs::copy(source, destination) {
                let cleanup_error = std::fs::remove_file(destination)
                    .err()
                    .filter(|error| error.kind() != std::io::ErrorKind::NotFound);
                return Err(match cleanup_error {
                    Some(cleanup_error) => format!(
                        "failed to move audit artifact {} to {}: {rename_error}; \
                         copy fallback failed: {copy_error}; partial destination cleanup failed: \
                         {cleanup_error}",
                        source.display(),
                        destination.display()
                    ),
                    None => format!(
                        "failed to move audit artifact {} to {}: {rename_error}; \
                         copy fallback failed: {copy_error}",
                        source.display(),
                        destination.display()
                    ),
                });
            }
            std::fs::remove_file(source).map_err(|remove_error| {
                let _ = std::fs::remove_file(destination);
                format!(
                    "copied audit artifact to {}, but failed to remove source {}: {remove_error}",
                    destination.display(),
                    source.display()
                )
            })
        }
    }
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
    use learning_mode_core::{DataLoopDocument, DataLoopSummary, DenialSummary, DenialsDocument};
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
        assert!(!learning_mode_core::data_loop_sibling_path(&source_denials)
            .unwrap()
            .exists());
        assert!(!source_etl.exists());
        assert!(!retained_dir.exists());
        assert_eq!(std::fs::read(log_dir.join("trace.etl")).unwrap(), b"etl");
        assert!(log_dir.join("denials.data-loop.json").is_file());
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
        assert!(log_dir.join("denials.data-loop.json").is_file());
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
        assert!(learning_mode_core::data_loop_sibling_path(&source_denials)
            .unwrap()
            .exists());
        assert!(source_etl.exists());
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

        assert!(error.contains("destination already exists"));
        assert!(source_denials.exists());
        assert!(learning_mode_core::data_loop_sibling_path(&source_denials)
            .unwrap()
            .exists());
        assert!(source_etl.exists());
        assert!(!log_dir.join("trace.etl").exists());
    }

    #[test]
    fn finalize_rejects_missing_data_loop_output() {
        let directory = tempfile::tempdir().unwrap();
        let log_dir = directory.path().join("audit");
        std::fs::create_dir_all(&log_dir).unwrap();
        let source_denials = log_dir.join("denials.unique.json");
        let source_etl = log_dir.join("denials.unique.etl");
        let document = DenialsDocument::new(Vec::new(), DenialSummary::new(0, 0, false));
        std::fs::write(&source_denials, serde_json::to_vec(&document).unwrap()).unwrap();
        std::fs::write(&source_etl, b"etl").unwrap();
        let mut response = response_with_capture(&source_denials, &source_etl, 0);
        std::fs::remove_file(learning_mode_core::data_loop_sibling_path(&source_denials).unwrap())
            .unwrap();
        let context = AuditContext {
            log_dir,
            config_path: None,
        };

        let error = finalize(&mut response, &context, directory.path(), false).unwrap_err();

        assert!(error.contains("Data Loop output file is missing"));
        assert!(source_denials.exists());
        assert!(source_etl.exists());
    }

    #[test]
    fn relocate_keeps_metadata_truthful_when_etl_move_fails() {
        let directory = tempfile::tempdir().unwrap();
        let log_dir = directory.path().join("audit");
        std::fs::create_dir_all(&log_dir).unwrap();
        let source_denials = log_dir.join("denials.unique.json");
        let source_data_loop = log_dir.join("denials.unique.data-loop.json");
        let source_etl = log_dir.join("denials.unique.etl");
        let final_denials = log_dir.join("denials.json");
        let final_data_loop = log_dir.join("denials.data-loop.json");
        let final_etl = log_dir.join("trace.etl");
        std::fs::write(&source_denials, b"denials").unwrap();
        std::fs::write(&source_data_loop, b"data-loop").unwrap();
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
            &source_denials,
            &final_denials,
            &source_data_loop,
            &final_data_loop,
            &source_etl,
            &final_etl,
            |source, destination| {
                calls += 1;
                if calls <= 2 {
                    std::fs::rename(source, destination).map_err(|error| error.to_string())
                } else {
                    Err("injected ETL move failure".to_string())
                }
            },
        )
        .unwrap_err();

        assert!(error.contains("injected ETL move failure"));
        // Primary JSON moved; metadata truthfully points at the final path.
        assert!(final_denials.is_file());
        assert!(!source_denials.exists());
        assert_eq!(Path::new(&capture.output_path), final_denials);
        assert!(final_data_loop.is_file());
        assert!(!source_data_loop.exists());
        // ETL untouched; metadata still truthfully points at the source.
        assert!(source_etl.is_file());
        assert!(!final_etl.exists());
        assert_eq!(
            capture.etl_path.as_deref().map(Path::new),
            Some(source_etl.as_path())
        );
    }

    fn response_with_capture(
        denials_path: &Path,
        etl_path: &Path,
        exit_code: i32,
    ) -> ScriptResponse {
        let data_loop_path = learning_mode_core::data_loop_sibling_path(denials_path).unwrap();
        let data_loop = DataLoopDocument::new(&DataLoopSummary::default());
        std::fs::write(data_loop_path, serde_json::to_vec(&data_loop).unwrap()).unwrap();
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
