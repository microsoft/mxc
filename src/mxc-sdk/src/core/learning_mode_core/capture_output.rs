// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Backend-neutral `captureDenials` output paths, paired document writing, and
//! error composition shared by the Windows and macOS capture backends.

use std::path::{Path, PathBuf};

use super::capture_diagnostics::{write_capture_verbose_logging_document, CaptureAnalysis};
use super::{
    verbose_logging_sibling_path, write_document, write_paired_output_files, DenialSummary,
    DenialsDocument, DenialsOutputPointer, ExistingOutputPolicy,
};

/// Writes `denials.json` and its v5 verbose sibling. Fails without leaving
/// either file behind if either path already exists or either write fails.
#[cfg_attr(not(any(target_os = "windows", target_os = "macos")), allow(dead_code))]
pub(crate) fn write_capture_denials_document(
    analysis: CaptureAnalysis,
    exit_code: i32,
    output_path: &Path,
) -> std::io::Result<DenialsOutputPointer> {
    let verbose_logging_document = analysis.verbose_document();
    let verbose_logging_path = verbose_logging_output_path(output_path)?;
    let summary = DenialSummary::new(
        exit_code,
        analysis.denials.len(),
        analysis.denied_resources_truncated,
    );
    let document = DenialsDocument::new(analysis.denials, summary);
    write_paired_output_files(
        "captureDenials",
        output_path,
        &verbose_logging_path,
        ExistingOutputPolicy::CreateNew,
        |writer| write_document(writer, &document),
        |writer| write_capture_verbose_logging_document(writer, &verbose_logging_document),
    )?;
    Ok(DenialsOutputPointer::new(
        output_path.to_string_lossy(),
        &document.summary,
    ))
}

/// Checks a caller-selected `captureDenials.outputPath` (`field` names it):
/// it must be an absolute file path whose parent directory already exists.
pub fn validate_output_path(field: &str, path: &Path) -> Result<(), String> {
    let shown = path.display();
    if !path.is_absolute() {
        return Err(format!("{field} must be an absolute path: '{shown}'"));
    }
    match path.parent() {
        // A filesystem root ("/", "C:\\") has no parent or an empty one.
        None => Err(format!(
            "{field} must name a file, not a directory root: '{shown}'"
        )),
        Some(parent) if parent.as_os_str().is_empty() => Err(format!(
            "{field} must name a file, not a directory root: '{shown}'"
        )),
        Some(parent) if !parent.is_dir() => Err(format!(
            "{field} parent directory does not exist: '{}'",
            parent.display()
        )),
        Some(_) if path.is_dir() => Err(format!(
            "{field} must name a file, not an existing directory: '{shown}'"
        )),
        _ => Ok(()),
    }
}

/// Derives the deterministic verbose logging sibling path for a denials output.
pub fn verbose_logging_output_path(output_path: &Path) -> std::io::Result<PathBuf> {
    verbose_logging_sibling_path(output_path)
        .map_err(|error| std::io::Error::other(format!("captureDenials {error}")))
}

/// Inserts a per-run identifier into a denials output path's file stem so
/// runs sharing one configured `outputPath` don't overwrite each other.
///
/// `/app/denials.json` → `/app/denials.<run_id>.json`. A path with no
/// extension gets `<name>.<run_id>`.
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

/// A random 128-bit hex string used to keep per-run paths and tags unique.
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

/// Returns the primary value when both succeed, the single error when one
/// fails, or `combine_errors(primary, secondary)` when both fail.
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

/// Combines a process wait result with the `captureDenials` teardown result.
/// A teardown failure is never hidden by a successful exit; when both fail,
/// the wait error kind is kept and both messages are returned.
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
    use std::io::Write;

    fn empty_analysis() -> CaptureAnalysis {
        CaptureAnalysis {
            denials: Vec::new(),
            denied_resources_truncated: false,
            verbose_logging: Default::default(),
            network_verbose_logging: Default::default(),
        }
    }

    #[test]
    fn writes_pointer_matching_the_document_summary() {
        let directory = tempfile::tempdir().expect("temp directory");
        let output_path = directory.path().join("denials.json");

        let pointer = write_capture_denials_document(empty_analysis(), 3, &output_path).unwrap();

        assert_eq!(pointer.kind, DenialsOutputPointer::KIND);
        assert_eq!(pointer.output_path, output_path.to_string_lossy());
        assert_eq!(pointer.exit_code, 3);
        assert_eq!(pointer.total_denials, 0);
        assert!(output_path.exists());
        assert!(verbose_logging_output_path(&output_path).unwrap().exists());
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
    fn verbose_logging_collision_leaves_actionable_output_absent() {
        let directory = tempfile::tempdir().expect("temp directory");
        let output_path = directory.path().join("denials.json");
        let verbose_logging_path = verbose_logging_output_path(&output_path).unwrap();
        std::fs::write(&verbose_logging_path, b"existing").unwrap();

        write_capture_denials_document(empty_analysis(), 0, &output_path)
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
