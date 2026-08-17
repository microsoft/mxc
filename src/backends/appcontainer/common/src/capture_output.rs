// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared `processContainer.captureDenials` JSON-output plumbing.
//!
//! Both the native BaseContainer capture path (`base_container_runner`,
//! decoding its own sealed ETL) and the guarded-WPR legacy-tier fallback
//! (`appcontainer_runner`, consuming an already-decoded [`AnalysisResult`]
//! handed back by the elevated PLM guardian) must emit byte-for-byte the same
//! [`DenialsDocument`] JSON shape, [`CaptureDenialsOutput`] summary, and
//! resolved output-path convention. Centralizing that here is what guarantees
//! the two paths can't drift.
//!
//! Deliberately free of any Windows API or [`ScriptResponse`] coupling so it
//! can be shared by both runner modules without either owning the other's
//! error type; callers map the plain `String` errors into their own error
//! type at the call site.

use std::io::Write;
use std::path::{Path, PathBuf};

use learning_mode_core::{
    write_document, AnalysisResult, DenialSummary, DenialsDocument, DenialsOutputPointer,
};
use wxc_common::models::CaptureDenialsOutput;

#[derive(Debug, Eq, PartialEq)]
pub struct DenialsOutputPaths {
    pub denials: PathBuf,
    pub etl: Option<PathBuf>,
}

/// Writes a bounded [`AnalysisResult`] to `output_path` as the JSON denials
/// document and returns the caller-facing [`CaptureDenialsOutput`] summary.
///
/// Never overwrites an existing file: a run whose output path collides with a
/// leftover file from a previous run fails loudly rather than clobbering it.
pub fn write_denials_document(
    analysis: AnalysisResult,
    exit_code: i32,
    output_path: &Path,
) -> std::io::Result<CaptureDenialsOutput> {
    let summary = DenialSummary::new(
        exit_code,
        analysis.denials.len(),
        analysis.denied_resources_truncated,
    );
    let document = DenialsDocument::new(analysis.denials, summary);

    write_denials_output_file(output_path, |writer| write_document(writer, &document))?;

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

/// Creates `output_path` (failing if it already exists) and writes through
/// `write`, cleaning up a partial file if `write` fails.
pub fn write_denials_output_file(
    output_path: &Path,
    write: impl FnOnce(&mut std::io::BufWriter<std::fs::File>) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)
        .map_err(|error| {
            std::io::Error::other(format!(
                "captureDenials failed to create denials output file {}: {error}",
                output_path.display()
            ))
        })?;

    let write_result = {
        let mut writer = std::io::BufWriter::new(file);
        write(&mut writer).and_then(|()| writer.flush())
    };
    if let Err(error) = write_result {
        let write_error = std::io::Error::other(format!(
            "captureDenials failed to write denials output file {}: {error}",
            output_path.display()
        ));
        return match std::fs::remove_file(output_path) {
            Ok(()) => Err(write_error),
            Err(cleanup_error) if cleanup_error.kind() == std::io::ErrorKind::NotFound => {
                Err(write_error)
            }
            Err(cleanup_error) => Err(std::io::Error::other(format!(
                "{write_error}; additionally failed to remove incomplete output file {}: {cleanup_error}",
                output_path.display()
            ))),
        };
    }

    Ok(())
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

/// Resolves the paired denials and optional retained-ETL paths for one run.
///
/// Both names contain the same run identifier. The retained path is always
/// distinct, including when the configured denials path has no extension or
/// already ends in `.etl`.
pub fn unique_denials_output_paths(
    configured_path: Option<&str>,
    retain_etl: bool,
) -> Result<DenialsOutputPaths, String> {
    let suffix = random_capture_suffix()?;
    let run_id = format!("{}_{suffix}", std::process::id());
    Ok(denials_output_paths_for_run(
        configured_path,
        &run_id,
        retain_etl,
    ))
}

fn denials_output_paths_for_run(
    configured_path: Option<&str>,
    run_id: &str,
    retain_etl: bool,
) -> DenialsOutputPaths {
    let denials = match configured_path {
        Some(path) => insert_run_id_into_stem(Path::new(path), run_id),
        None => std::env::temp_dir().join(format!("mxc_denials_{run_id}.json")),
    };
    let etl = retain_etl.then(|| match configured_path {
        Some(path) => retained_etl_path(Path::new(path), run_id),
        None => std::env::temp_dir().join(format!("mxc_denials_{run_id}.etl")),
    });
    DenialsOutputPaths { denials, etl }
}

fn retained_etl_path(configured_path: &Path, run_id: &str) -> PathBuf {
    let file_name = configured_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("denials");
    let extension = configured_path.extension().and_then(|ext| ext.to_str());
    let stem = configured_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or(file_name);
    let retained_name = match extension {
        Some(ext) if ext.eq_ignore_ascii_case("etl") => {
            format!("{stem}.{run_id}.trace.etl")
        }
        Some(_) => format!("{stem}.{run_id}.etl"),
        None => format!("{file_name}.{run_id}.etl"),
    };
    match configured_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(retained_name),
        _ => PathBuf::from(retained_name),
    }
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
/// successful process exit. Shared by the native BaseContainer capture path
/// and the guarded-WPR legacy-tier fallback so both surface capture failures
/// through [`wxc_common::sandbox_process::SandboxProcess::wait`] identically.
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
    use learning_mode_core::{AccessType, DeniedResource, ResourceType};

    #[test]
    fn write_denials_document_writes_summary_and_document() {
        let directory = tempfile::tempdir().expect("temp directory");
        let output_path = directory.path().join("denials.json");
        let analysis = AnalysisResult::complete(vec![DeniedResource {
            resource: r"C:\blocked.txt".to_string(),
            resource_type: ResourceType::File,
            access_type: AccessType::Read,
            pid: 42,
            filetime: 99,
        }]);

        let metadata =
            write_denials_document(analysis, 7, &output_path).expect("write should succeed");

        assert_eq!(metadata.kind, CaptureDenialsOutput::KIND);
        assert_eq!(metadata.exit_code, 7);
        assert_eq!(metadata.total_denials, 1);
        assert!(!metadata.denied_resources_truncated);
        let document: DenialsDocument =
            serde_json::from_slice(&std::fs::read(output_path).unwrap()).unwrap();
        assert_eq!(document.denials.len(), 1);
    }

    #[test]
    fn write_denials_document_handles_empty_result() {
        let directory = tempfile::tempdir().expect("temp directory");
        let output_path = directory.path().join("denials.json");

        let metadata =
            write_denials_document(AnalysisResult::complete(Vec::new()), 0, &output_path)
                .expect("write should succeed");

        assert_eq!(metadata.total_denials, 0);
        assert!(output_path.exists());
    }

    #[test]
    fn failed_denials_write_removes_incomplete_output() {
        let directory = tempfile::tempdir().expect("temp directory");
        let output_path = directory.path().join("denials.json");

        let error = write_denials_output_file(&output_path, |writer| {
            std::io::Write::write_all(writer, b"{\"partial\":")?;
            Err(std::io::Error::other("simulated write failure"))
        })
        .expect_err("write should fail");

        assert!(error.to_string().contains("simulated write failure"));
        assert!(!output_path.exists());
    }

    #[test]
    fn denials_output_does_not_overwrite_an_existing_file() {
        let directory = tempfile::tempdir().expect("temp directory");
        let output_path = directory.path().join("denials.json");
        std::fs::write(&output_path, b"existing").expect("seed output");

        write_denials_output_file(&output_path, |_| Ok(())).expect_err("collision should fail");

        assert_eq!(
            std::fs::read(&output_path).expect("read existing output"),
            b"existing"
        );
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
        let first = unique_denials_output_paths(None, false)
            .expect("first path")
            .denials;
        let second = unique_denials_output_paths(None, false)
            .expect("second path")
            .denials;

        assert_ne!(first, second);
        assert_eq!(first.parent(), Some(std::env::temp_dir().as_path()));
        assert_eq!(second.parent(), Some(std::env::temp_dir().as_path()));
        assert_eq!(first.extension().and_then(|ext| ext.to_str()), Some("json"));
    }

    #[test]
    fn paired_paths_preserve_run_id_for_extensionless_output() {
        let paths = denials_output_paths_for_run(Some(r"C:\app\denials"), "77_abcd", true);

        assert_eq!(paths.denials, PathBuf::from(r"C:\app\denials.77_abcd"));
        assert_eq!(
            paths.etl,
            Some(PathBuf::from(r"C:\app\denials.77_abcd.etl"))
        );
    }

    #[test]
    fn paired_paths_are_distinct_for_etl_output() {
        let paths = denials_output_paths_for_run(Some(r"C:\app\denials.ETL"), "77_abcd", true);

        assert_eq!(paths.denials, PathBuf::from(r"C:\app\denials.77_abcd.ETL"));
        assert_eq!(
            paths.etl,
            Some(PathBuf::from(r"C:\app\denials.77_abcd.trace.etl"))
        );
        assert_ne!(
            paths.denials.to_string_lossy().to_ascii_lowercase(),
            paths
                .etl
                .as_ref()
                .expect("retained path")
                .to_string_lossy()
                .to_ascii_lowercase()
        );
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
