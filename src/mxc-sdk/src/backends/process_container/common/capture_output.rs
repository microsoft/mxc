// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Native `processContainer.captureDenials` JSON output and error composition.
//! Retained ETLs use the runner's protected managed-capture store, independently
//! of caller-selected JSON output paths.

use std::path::{Path, PathBuf};

use crate::learning_mode_core::{
    capture_diagnostics::{write_capture_verbose_logging_document, CaptureAnalysis},
    verbose_logging_sibling_path, write_document, write_paired_output_files, DenialSummary,
    DenialsDocument, DenialsOutputPointer, DeniedResource, ExistingOutputPolicy,
};
use crate::mxc_common::models::CaptureDenialsOutput;

/// Directory name of the protected retained-ETL store. Sealed ETLs are promoted
/// out of working storage into a per-run directory beneath a sibling directory
/// with this name (`.../capture-denials/retained/<run>/`). Owned here so
/// consumers that need to recognize a promoted retained-capture directory —
/// e.g. `wxc-exec --audit` relocating and pruning the run directory — do not
/// duplicate the literal.
pub const RETAINED_CAPTURE_DIR_NAME: &str = "retained";

/// Whether `directory` is a per-run directory sitting directly beneath the
/// retained-capture store (`.../retained/<run>`). Recognizes the promoted
/// location produced by the BaseContainer capture path so callers can safely
/// prune it once its ETL has moved out, without hard-coding the store name.
pub fn is_retained_capture_run_dir(directory: &Path) -> bool {
    directory
        .parent()
        .and_then(Path::file_name)
        .is_some_and(|name| name.eq_ignore_ascii_case(RETAINED_CAPTURE_DIR_NAME))
}

/// Writes native capture analysis with the complete internal v5 diagnostics.
pub(crate) fn write_capture_denials_document(
    analysis: CaptureAnalysis,
    exit_code: i32,
    output_path: &Path,
) -> std::io::Result<CaptureDenialsOutput> {
    let verbose_logging_document = analysis.verbose_document();
    write_denials_document_pair(
        analysis.denials,
        analysis.denied_resources_truncated,
        exit_code,
        output_path,
        |writer| write_capture_verbose_logging_document(writer, &verbose_logging_document),
    )
}

fn write_denials_document_pair(
    denials: Vec<DeniedResource>,
    denied_resources_truncated: bool,
    exit_code: i32,
    output_path: &Path,
    write_verbose: impl FnOnce(&mut std::io::BufWriter<std::fs::File>) -> std::io::Result<()>,
) -> std::io::Result<CaptureDenialsOutput> {
    let verbose_logging_path = verbose_logging_output_path(output_path)?;
    let summary = DenialSummary::new(exit_code, denials.len(), denied_resources_truncated);
    let document = DenialsDocument::new(denials, summary);
    write_paired_output_files(
        "captureDenials",
        output_path,
        &verbose_logging_path,
        ExistingOutputPolicy::CreateNew,
        |writer| write_document(writer, &document),
        write_verbose,
    )?;

    let pointer = DenialsOutputPointer::new(output_path.to_string_lossy(), &document.summary);
    Ok(CaptureDenialsOutput {
        kind: pointer.kind,
        output_path: pointer.output_path,
        exit_code: pointer.exit_code,
        total_denials: pointer.total_denials,
        denied_resources_truncated: pointer.denied_resources_truncated,
        etl_path: None,
    })
}

/// Derives the deterministic verbose logging sibling path for a denials output.
pub fn verbose_logging_output_path(output_path: &Path) -> std::io::Result<PathBuf> {
    verbose_logging_sibling_path(output_path)
        .map_err(|error| std::io::Error::other(format!("captureDenials {error}")))
}

/// Inserts a per-run identifier into a denials output path's file stem so
/// concurrent and sequential captures using the same configured `outputPath`
/// produce distinct files instead of clobbering one another.
///
/// `C:\app\denials.json` → `C:\app\denials.<run_id>.json`. A path with no
/// extension gets `<name>.<run_id>`; a bare filename (no parent) keeps its
/// directory-less form.
pub fn insert_run_id_into_stem(path: &Path, run_id: &str) -> PathBuf {
    let Some(file_name) = path.file_name().and_then(|s| s.to_str()) else {
        return path.to_path_buf();
    };
    let new_name = match path.extension().and_then(|s| s.to_str()) {
        Some(ext) => {
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or(file_name);
            format!("{stem}.{run_id}.{ext}")
        }
        None => format!("{file_name}.{run_id}"),
    };
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(new_name),
        _ => PathBuf::from(new_name),
    }
}

/// Resolve a unique caller-selected or temporary JSON output path.
pub fn unique_denials_output_path(configured_path: Option<&str>) -> Result<PathBuf, String> {
    let suffix = random_capture_suffix()?;
    let run_id = format!("{}_{suffix}", std::process::id());
    Ok(match configured_path {
        Some(path) => insert_run_id_into_stem(Path::new(path), &run_id),
        None => std::env::temp_dir().join(format!("mxc_denials_{run_id}.json")),
    })
}

/// A short random hex suffix used to keep per-run temp/output paths from
/// colliding across concurrent or sequential runs sharing the same PID.
pub fn random_capture_suffix() -> Result<String, String> {
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce).map_err(|error| {
        format!("captureDenials could not generate a unique output path: {error}")
    })?;
    Ok(nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>())
}

/// Removes an internal (runner-managed) capture temp file. Treats "already
/// gone" as success so a redundant cleanup call is harmless.
pub fn remove_internal_capture_file(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(std::io::Error::other(format!(
            "captureDenials failed to remove internal capture file {}: {error}",
            path.display()
        ))),
    }
}

/// Combines a primary result with a best-effort secondary `()` result, keeping
/// the four-arm pattern in one place. On success the primary value flows
/// through; if exactly one side fails its error is returned unchanged; if both
/// fail, `combine_errors` merges them (owning both errors so callers control
/// the resulting message and [`std::io::ErrorKind`]).
fn combine_results<T>(
    primary: std::io::Result<T>,
    secondary: std::io::Result<()>,
    combine_errors: impl FnOnce(std::io::Error, std::io::Error) -> std::io::Error,
) -> std::io::Result<T> {
    match (primary, secondary) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(primary_error), Ok(())) => Err(primary_error),
        (Ok(_), Err(secondary_error)) => Err(secondary_error),
        (Err(primary_error), Err(secondary_error)) => {
            Err(combine_errors(primary_error, secondary_error))
        }
    }
}

/// Combines a capture result with a best-effort cleanup result, preserving
/// both failure messages when both operations fail.
pub fn combine_capture_and_cleanup_results<T>(
    capture_result: std::io::Result<T>,
    cleanup_result: std::io::Result<()>,
) -> std::io::Result<T> {
    combine_results(
        capture_result,
        cleanup_result,
        |capture_error, cleanup_error| {
            std::io::Error::other(format!(
            "{capture_error}; additionally failed to clean up the internal capture state: {cleanup_error}"
        ))
        },
    )
}

/// Combines a sandboxed process's wait result with a best-effort
/// `captureDenials` teardown result, preferring the teardown error when both
/// are present so a capture failure is never silently swallowed by a
/// successful process exit. Used by native capture through
/// [`crate::mxc_common::sandbox_process::SandboxProcess::wait`].
///
/// When *both* the wait and teardown fail, the wait error kind is preserved
/// while both messages are returned. This keeps retained-ETL paths and other
/// capture recovery details discoverable.
pub fn combine_process_and_teardown_results(
    process_result: std::io::Result<i32>,
    teardown_result: std::io::Result<()>,
) -> std::io::Result<i32> {
    combine_results(
        process_result,
        teardown_result,
        |wait_error, teardown_error| {
            std::io::Error::new(
                wait_error.kind(),
                format!("{wait_error}; captureDenials teardown also failed: {teardown_error}"),
            )
        },
    )
}

/// Best-effort write of a single diagnostic line to stderr, used for failures
/// that occur too late (e.g. during `Drop`) to be returned as a `Result`.
pub fn write_stderr_line_best_effort(message: std::fmt::Arguments<'_>) {
    let stderr = std::io::stderr();
    let mut stderr = stderr.lock();
    let _ = std::io::Write::write_fmt(&mut stderr, format_args!("{message}\n"));
    let _ = std::io::Write::flush(&mut stderr);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::learning_mode_core::capture_diagnostics::{
        CaptureVerboseLoggingOutcomeReason, CaptureVerboseLoggingProvider,
        CaptureVerboseLoggingSignature, CaptureVerboseLoggingSummary, ConfigurationRecommendation,
        NetworkDecisionReason, NetworkEndpoint, CAPTURE_VERBOSE_LOGGING_VERSION,
    };
    use crate::learning_mode_core::{AccessType, DeniedResource, ResourceType};
    use std::io::Write;

    #[test]
    fn native_capture_writes_version_five_reason_specific_guidance() {
        let directory = tempfile::tempdir().expect("temp directory");
        let output_path = directory.path().join("denials.json");
        let mut network_verbose_logging = CaptureVerboseLoggingSummary::default();
        let mut retained_bytes = 0;
        network_verbose_logging.record_with_byte_budget(
            CaptureVerboseLoggingSignature {
                provider: CaptureVerboseLoggingProvider::LearningModeNetworkDecision,
                provider_guid: "{301EC03D-2951-5EFB-6D99-59C64628BBFC}".to_string(),
                event_id: 1,
                event_name: Some("NetworkDecisionV1".to_string()),
                reason: CaptureVerboseLoggingOutcomeReason::Actionable,
                pid: 0,
                access_type: Some(AccessType::Unknown),
                resource_type: Some(ResourceType::Network),
                network_decision_reason: Some(NetworkDecisionReason::DirectDefaultDeny),
                configuration_recommendation: Some(ConfigurationRecommendation::AddEgressAllow),
                network_endpoint: Some(NetworkEndpoint {
                    protocol: "tcp".to_string(),
                    remote_address: "203.0.113.10".to_string(),
                    remote_port: Some(443),
                }),
                properties: Vec::new(),
            },
            &mut retained_bytes,
            crate::learning_mode_core::MAX_VERBOSE_LOGGING_SIGNATURE_BYTES,
        );
        let analysis = CaptureAnalysis {
            denials: vec![DeniedResource {
                resource: "tcp://203.0.113.10:443".to_string(),
                resource_type: ResourceType::Network,
                access_type: AccessType::Unknown,
                pid: 0,
                filetime: 99,
            }],
            denied_resources_truncated: false,
            verbose_logging: Default::default(),
            network_verbose_logging,
        };

        let metadata = write_capture_denials_document(analysis, 7, &output_path).unwrap();
        assert_eq!(metadata.kind, CaptureDenialsOutput::KIND);
        assert_eq!(metadata.output_path, output_path.to_string_lossy());
        assert_eq!(metadata.exit_code, 7);
        assert_eq!(metadata.total_denials, 1);
        assert!(!metadata.denied_resources_truncated);
        assert!(metadata.etl_path.is_none());

        let verbose: serde_json::Value = serde_json::from_slice(
            &std::fs::read(verbose_logging_output_path(&output_path).unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(verbose["version"], CAPTURE_VERBOSE_LOGGING_VERSION);
        assert_eq!(
            verbose["signatures"][0]["signature"]["networkDecisionReason"],
            "directDefaultDeny"
        );
        assert_eq!(
            verbose["signatures"][0]["signature"]["configurationRecommendation"],
            "addEgressAllow"
        );
        assert_eq!(
            verbose["signatures"][0]["signature"]["networkEndpoint"]["remoteAddress"],
            "203.0.113.10"
        );
    }

    #[test]
    fn verbose_logging_path_is_a_deterministic_json_sibling() {
        assert_eq!(
            verbose_logging_output_path(Path::new(r"C:\out\denials.123.json")).unwrap(),
            PathBuf::from(r"C:\out\denials.123.verbose.json")
        );
        assert_eq!(
            verbose_logging_output_path(Path::new("denials")).unwrap(),
            PathBuf::from("denials.verbose.json")
        );
    }

    #[test]
    fn native_verbose_logging_collision_leaves_actionable_output_absent() {
        let directory = tempfile::tempdir().expect("temp directory");
        let output_path = directory.path().join("denials.json");
        let verbose_logging_path = verbose_logging_output_path(&output_path).unwrap();
        std::fs::write(&verbose_logging_path, b"existing").unwrap();
        let analysis = CaptureAnalysis {
            denials: Vec::new(),
            denied_resources_truncated: false,
            verbose_logging: Default::default(),
            network_verbose_logging: Default::default(),
        };

        write_capture_denials_document(analysis, 0, &output_path)
            .expect_err("collision should fail");

        assert!(!output_path.exists());
        assert_eq!(std::fs::read(verbose_logging_path).unwrap(), b"existing");
    }

    #[test]
    fn second_staged_write_failure_leaves_no_final_output() {
        let directory = tempfile::tempdir().expect("temp directory");
        let output_path = directory.path().join("denials.json");
        let verbose_logging_path = verbose_logging_output_path(&output_path).unwrap();

        let error = write_paired_output_files(
            "captureDenials",
            &output_path,
            &verbose_logging_path,
            ExistingOutputPolicy::CreateNew,
            |writer| writer.write_all(b"denials"),
            |writer| {
                writer.write_all(b"partial")?;
                Err(std::io::Error::other("simulated verbose logging failure"))
            },
        )
        .expect_err("paired write should fail");

        assert!(error
            .to_string()
            .contains("simulated verbose logging failure"));
        assert!(!output_path.exists());
        assert!(!verbose_logging_path.exists());
    }

    #[test]
    fn insert_run_id_into_stem_injects_id_before_extension() {
        let got = insert_run_id_into_stem(Path::new(r"C:\app\denials.json"), "1234_abcd");
        assert_eq!(got, PathBuf::from(r"C:\app\denials.1234_abcd.json"));
    }

    #[test]
    fn insert_run_id_into_stem_handles_no_extension() {
        let got = insert_run_id_into_stem(Path::new(r"C:\app\denials"), "77_abcd");
        assert_eq!(got, PathBuf::from(r"C:\app\denials.77_abcd"));
    }

    #[test]
    fn insert_run_id_into_stem_handles_bare_filename() {
        let got = insert_run_id_into_stem(Path::new("denials.json"), "9_abcd");
        assert_eq!(got, PathBuf::from("denials.9_abcd.json"));
    }

    #[test]
    fn insert_run_id_into_stem_preserves_multi_dot_stem() {
        let got = insert_run_id_into_stem(Path::new(r"C:\app\out.denials.json"), "5_abcd");
        assert_eq!(got, PathBuf::from(r"C:\app\out.denials.5_abcd.json"));
    }

    #[test]
    fn managed_denials_paths_are_unique_per_run() {
        let first = unique_denials_output_path(None).expect("first path");
        let second = unique_denials_output_path(None).expect("second path");

        assert_ne!(first, second);
        assert_eq!(first.parent(), Some(std::env::temp_dir().as_path()));
        assert_eq!(second.parent(), Some(std::env::temp_dir().as_path()));
        assert_eq!(first.extension().and_then(|ext| ext.to_str()), Some("json"));
    }

    #[test]
    fn explicit_denials_paths_are_unique_siblings() {
        let directory = tempfile::tempdir().expect("capture directory");
        let configured = directory.path().join("capture.json");
        let first = unique_denials_output_path(configured.to_str()).expect("first");
        let second = unique_denials_output_path(configured.to_str()).expect("second");
        assert_ne!(first, second);
        assert_eq!(first.parent(), configured.parent());
        assert_eq!(second.parent(), configured.parent());
        assert!(first
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("capture."));
        assert!(second
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("capture."));
    }

    #[test]
    fn missing_internal_capture_file_is_already_clean() {
        let directory = tempfile::tempdir().expect("temp directory");
        let missing = directory.path().join("missing.etl");
        remove_internal_capture_file(&missing).expect("missing file should be clean");
    }

    #[test]
    fn capture_and_cleanup_failures_are_both_preserved() {
        let error = combine_capture_and_cleanup_results::<()>(
            Err(std::io::Error::other("decode failed")),
            Err(std::io::Error::other("delete failed")),
        )
        .expect_err("combined operation should fail");

        let message = error.to_string();
        assert!(message.contains("decode failed"));
        assert!(message.contains("delete failed"));
    }

    #[test]
    fn successful_process_reports_capture_teardown_failure() {
        let error =
            combine_process_and_teardown_results(Ok(0), Err(std::io::Error::other("seal failed")))
                .expect_err("capture failure must override successful process exit");

        assert!(error.to_string().contains("seal failed"));
    }

    #[test]
    fn failed_process_result_is_preserved_over_successful_teardown() {
        let error =
            combine_process_and_teardown_results(Err(std::io::Error::other("wait failed")), Ok(()))
                .expect_err("wait failure should propagate");

        assert!(error.to_string().contains("wait failed"));
    }

    #[test]
    fn wait_failure_takes_precedence_when_teardown_also_fails() {
        let error = combine_process_and_teardown_results(
            Err(std::io::Error::other("wait failed")),
            Err(std::io::Error::other("teardown failed")),
        )
        .expect_err("wait failure should still propagate");

        assert!(error.to_string().contains("wait failed"));
        assert!(error.to_string().contains("teardown failed"));
    }
}
