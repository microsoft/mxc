// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Native audit output locations and compatibility artifacts.

use super::config::{
    deny_file_set, initialize_filesystem, load_config, merge_capabilities,
    resolve_adjusted_config_path, save_adjusted_config, update_from_access_events,
    write_added_paths_summary, write_requested_capabilities_summary,
};
use super::config_inputs::legacy_config_inputs;
use anyhow::{Context, Result};
use chrono::Local;
use mxc_sdk::learning_mode_core::DenialsDocument;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Inputs for generating compatibility artifacts from actionable denials.
#[derive(Debug, Clone)]
pub struct PostProcessOptions {
    pub log_dir: PathBuf,
    pub config_path: Option<PathBuf>,
    pub trace_path: PathBuf,
    pub denials_path: PathBuf,
    pub verbose: bool,
}

pub fn default_log_dir() -> PathBuf {
    default_log_dir_with_local_app_data(std::env::var_os("LOCALAPPDATA").as_deref())
}

fn default_log_dir_with_local_app_data(local_app_data: Option<&OsStr>) -> PathBuf {
    let stamp = format!(
        "{}_pid{}",
        Local::now().format("%Y-%m-%d_%H%M%S%.3f"),
        std::process::id()
    );
    local_app_data
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("Microsoft")
        .join("MXC")
        // Preserve the native audit output location used by existing callers.
        .join("PLM")
        .join("logs")
        .join(stamp)
}

#[derive(Debug)]
struct ConfigOutputPaths {
    source: PathBuf,
    snapshot: PathBuf,
    adjusted: PathBuf,
}

fn prepare_config_output_paths(
    config_path: Option<&Path>,
    log_dir: &Path,
    trace_path: &Path,
    denials_path: &Path,
) -> Result<Option<ConfigOutputPaths>> {
    let verbose_logging_path =
        mxc_sdk::learning_mode_core::verbose_logging_sibling_path(denials_path)
            .context("failed to derive verbose logging output path")?;
    if same_config_target(trace_path, denials_path)
        || same_config_target(trace_path, &verbose_logging_path)
    {
        anyhow::bail!(
            "trace output {} would be overwritten by a denials output derived from {}",
            trace_path.display(),
            denials_path.display()
        );
    }

    let Some(source) = config_path else {
        return Ok(None);
    };
    let leaf = source
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "config.json".into());
    let snapshot = log_dir.join(leaf);
    let adjusted = resolve_adjusted_config_path(&snapshot)?;

    for (label, path) in [
        ("source config", source),
        ("config snapshot", snapshot.as_path()),
        ("adjusted config", adjusted.as_path()),
    ] {
        if same_config_target(path, trace_path)
            || same_config_target(path, denials_path)
            || same_config_target(path, &verbose_logging_path)
        {
            anyhow::bail!(
                "{label} path {} collides with a capture output",
                path.display()
            );
        }
    }
    if same_config_target(source, &adjusted) || same_config_target(&snapshot, &adjusted) {
        anyhow::bail!(
            "adjusted config output {} collides with a source or snapshot config",
            adjusted.display()
        );
    }

    Ok(Some(ConfigOutputPaths {
        source: source.to_path_buf(),
        snapshot,
        adjusted,
    }))
}

/// Generates the source-config snapshot and adjusted config from actionable denials.
pub fn postprocess_denials(
    document: &DenialsDocument,
    opts: &PostProcessOptions,
    exe_dir: &Path,
) -> Result<Option<PathBuf>> {
    std::fs::create_dir_all(&opts.log_dir)
        .with_context(|| format!("failed to create log dir {}", opts.log_dir.display()))?;
    let config_outputs = prepare_config_output_paths(
        opts.config_path.as_deref(),
        &opts.log_dir,
        &opts.trace_path,
        &opts.denials_path,
    )?;
    postprocess_denials_with_paths(document, opts, exe_dir, config_outputs)
}

fn postprocess_denials_with_paths(
    document: &DenialsDocument,
    opts: &PostProcessOptions,
    exe_dir: &Path,
    config_outputs: Option<ConfigOutputPaths>,
) -> Result<Option<PathBuf>> {
    let Some(config_outputs) = config_outputs else {
        return Ok(None);
    };

    // Load the source config before copying or mutating it. The trace and
    // actionable denials remain useful even if this compatibility-only
    // adjusted-config phase fails.
    let base_config = load_config(&config_outputs.source)?;

    // Copy the original config alongside the trace unconditionally
    // so operators always have a snapshot of the exact input that
    // produced this run's `trace.etl`, even when the parse yielded
    // nothing mergeable. The copy MUST land on disk before we
    // attempt any edit-and-save cycle below: it's the operator's
    // only record of the pre-edit state, and losing it turns an
    // Adjusted_*.json into an un-auditable delta.
    if !same_config_target(&config_outputs.source, &config_outputs.snapshot) {
        std::fs::copy(&config_outputs.source, &config_outputs.snapshot)
            .with_context(|| format!("failed to copy {}", config_outputs.source.display()))?;
    }

    if document.summary.denied_resources_truncated {
        eprintln!(
            "[audit] warning: denial analysis was truncated; skipping adjusted-config \
             generation because the learned policy would be incomplete"
        );
        return Ok(None);
    }

    let current_directory = std::env::current_dir()
        .ok()
        .map(|path| path.to_string_lossy().into_owned());
    let (valid_access_events, requested_capabilities) =
        legacy_config_inputs(&document.denials, current_directory.as_deref());
    write_requested_capabilities_summary(&requested_capabilities, opts.verbose);

    if valid_access_events.is_empty() && requested_capabilities.is_empty() {
        // Nothing mergeable -- skip producing an Adjusted_*.json (which
        // would be byte-identical to the input and confuse the harness's
        // diff-based pass/fail signal).
        return Ok(None);
    }

    // Edit the pre-loaded copy of the config in memory rather than
    // re-reading the snapshot — this avoids a read-after-write on
    // Windows where an AV filter can occasionally serve a stale or
    // empty buffer for a file that `std::fs::copy` just wrote.
    let mut config = base_config;
    initialize_filesystem(&mut config)?;
    let deny = deny_file_set(&config);

    let bin_path_s = exe_dir.to_string_lossy().into_owned();
    let added = update_from_access_events(
        &mut config,
        &bin_path_s,
        &valid_access_events,
        &deny,
        opts.verbose,
    )?;

    if !requested_capabilities.is_empty() {
        merge_capabilities(&mut config, &requested_capabilities)?;
    }

    // Create the parent directory here — propagating any error — rather
    // than silently inside the (now pure) resolver. A missing parent is
    // surfaced instead of swallowed.
    if let Some(parent) = config_outputs.adjusted.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create parent directory {} for adjusted config",
                    parent.display()
                )
            })?;
        }
    }

    save_adjusted_config(&config, &config_outputs.adjusted)?;

    write_added_paths_summary(&added, opts.verbose);
    Ok(Some(config_outputs.adjusted))
}

/// True iff `a` and `b` denote the same Windows target.
///
/// Existing files are canonicalized directly. For a not-yet-created output,
/// the existing parent is canonicalized before the leaf is reattached, which
/// still resolves junctions, symlinks, short names, and `.`/`..`. Existing
/// targets are also compared by volume/file ID so hard links cannot bypass the
/// pre-capture check. The final path comparison is case-insensitive because
/// Windows paths are case-insensitive.
fn same_config_target(a: &Path, b: &Path) -> bool {
    use mxc_sdk::mxc_common::filesystem_object::{
        compare_existing_filesystem_objects, ExistingObjectComparison,
    };

    match compare_existing_filesystem_objects(a, b) {
        ExistingObjectComparison::Same | ExistingObjectComparison::Unknown => true,
        ExistingObjectComparison::Different => {
            windows_paths_equal_ignore_case(&target_comparison_key(a), &target_comparison_key(b))
        }
    }
}

fn windows_paths_equal_ignore_case(a: &str, b: &str) -> bool {
    mxc_sdk::mxc_common::string_util::windows_paths_equal_ignore_case(a, b)
}

fn target_comparison_key(path: &Path) -> String {
    let original = path.to_string_lossy().replace('/', "\\");
    let is_verbatim = original.starts_with(r"\\?\");
    let resolved = std::fs::canonicalize(path)
        .or_else(|_| {
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty());
            let parent = parent.unwrap_or_else(|| Path::new("."));
            let canonical_parent = std::fs::canonicalize(parent)?;
            Ok::<_, std::io::Error>(match path.file_name() {
                Some(file_name) => canonical_parent.join(file_name),
                None => canonical_parent,
            })
        })
        .or_else(|_| std::path::absolute(path))
        .unwrap_or_else(|_| path.to_path_buf());
    let key = resolved.to_string_lossy().replace('/', "\\");
    let key = strip_verbatim_prefix(key);
    normalize_win32_components(&key, !is_verbatim)
}

fn strip_verbatim_prefix(key: String) -> String {
    let Some(rest) = key.strip_prefix(r"\\?\") else {
        return key;
    };
    match rest.get(..4) {
        Some(prefix) if prefix.eq_ignore_ascii_case("UNC\\") => format!(r"\\{}", &rest[4..]),
        _ => rest.to_string(),
    }
}

fn normalize_win32_components(path: &str, trim_trailing_dots_and_spaces: bool) -> String {
    path.split('\\')
        .map(|component| {
            if component.is_empty() || component.ends_with(':') {
                component
            } else {
                let component = if trim_trailing_dots_and_spaces {
                    component.trim_end_matches([' ', '.'])
                } else {
                    component
                };
                let default_stream_suffix = "::$DATA";
                let component = component
                    .get(..component.len().saturating_sub(default_stream_suffix.len()))
                    .filter(|_| {
                        component
                            .get(component.len().saturating_sub(default_stream_suffix.len())..)
                            .is_some_and(|suffix| {
                                suffix.eq_ignore_ascii_case(default_stream_suffix)
                            })
                    })
                    .unwrap_or(component);
                if trim_trailing_dots_and_spaces {
                    component.trim_end_matches([' ', '.'])
                } else {
                    component
                }
            }
        })
        .collect::<Vec<_>>()
        .join("\\")
}

#[cfg(test)]
mod tests {
    use super::*;
    use mxc_sdk::learning_mode_core::{AccessType, DenialSummary, DeniedResource, ResourceType};

    fn postprocess_fixture(
        document: &DenialsDocument,
    ) -> (tempfile::TempDir, PathBuf, Option<PathBuf>) {
        let directory = tempfile::tempdir().unwrap();
        let source_dir = directory.path().join("source");
        let log_dir = directory.path().join("audit");
        std::fs::create_dir_all(&source_dir).unwrap();
        std::fs::create_dir_all(&log_dir).unwrap();
        let config_path = source_dir.join("policy.json");
        std::fs::write(&config_path, r#"{"processContainer":{"capabilities":[]}}"#).unwrap();
        let trace_path = log_dir.join("trace.etl");
        let denials_path = log_dir.join("denials.json");
        std::fs::write(&trace_path, b"etl").unwrap();
        std::fs::write(&denials_path, b"{}").unwrap();

        let adjusted = postprocess_denials(
            document,
            &PostProcessOptions {
                log_dir: log_dir.clone(),
                config_path: Some(config_path),
                trace_path,
                denials_path,
                verbose: false,
            },
            directory.path(),
        )
        .unwrap();
        (directory, log_dir, adjusted)
    }

    #[test]
    fn actionable_denials_generate_snapshot_and_adjusted_config() {
        let document = DenialsDocument::new(
            vec![DeniedResource {
                resource: "internetClient".to_string(),
                resource_type: ResourceType::Capability,
                access_type: AccessType::Unknown,
                pid: 42,
                filetime: 1,
            }],
            DenialSummary::new(7, 1, false),
        );

        let (_directory, log_dir, adjusted) = postprocess_fixture(&document);

        assert!(log_dir.join("policy.json").is_file());
        let adjusted = adjusted.expect("capability denial should produce adjusted config");
        let config: serde_json::Value =
            serde_json::from_slice(&std::fs::read(adjusted).unwrap()).unwrap();
        assert_eq!(
            config["processContainer"]["capabilities"],
            serde_json::json!(["internetClient"])
        );
    }

    #[test]
    fn truncated_actionable_denials_snapshot_but_skip_adjusted_config() {
        let document = DenialsDocument::new(
            vec![DeniedResource {
                resource: "internetClient".to_string(),
                resource_type: ResourceType::Capability,
                access_type: AccessType::Unknown,
                pid: 42,
                filetime: 1,
            }],
            DenialSummary::new(0, 1, true),
        );

        let (_directory, log_dir, adjusted) = postprocess_fixture(&document);

        assert!(log_dir.join("policy.json").is_file());
        assert!(adjusted.is_none());
        assert!(!log_dir.join("Adjusted_policy.json").exists());
    }

    #[test]
    fn default_log_dir_uses_per_user_local_app_data() {
        let root = Path::new(r"C:\Users\caller\AppData\Local");
        let log_dir = default_log_dir_with_local_app_data(Some(root.as_os_str()));
        assert!(log_dir.starts_with(root.join(r"Microsoft\MXC\PLM\logs")));
    }

    #[test]
    fn default_log_dir_falls_back_to_temp_directory() {
        let log_dir = default_log_dir_with_local_app_data(None);
        assert!(log_dir.starts_with(std::env::temp_dir().join(r"Microsoft\MXC\PLM\logs")));
    }

    #[test]
    fn lowercase_verbatim_unc_key_collides_with_normal_unc_key() {
        let verbatim = normalize_win32_components(
            &strip_verbatim_prefix(r"\\?\unc\server\share\denials.json".to_string()),
            false,
        );
        let normal = normalize_win32_components(r"\\server\share\denials.json", true);
        assert!(windows_paths_equal_ignore_case(&verbatim, &normal));
    }

    #[test]
    fn trace_input_cannot_collide_with_denials_output() {
        let path = Path::new(r"C:\captures\denials.json");
        let error =
            prepare_config_output_paths(None, Path::new(r"C:\captures"), path, path).unwrap_err();
        assert!(error.to_string().contains("would be overwritten"));
    }

    #[test]
    fn rejects_user_selected_trace_path_that_matches_derived_verbose_output() {
        // `--trace-file` is caller-controlled, while this sibling path is
        // derived from denials.json. Without this check, publishing the verbose
        // output would overwrite the retained ETL before post-processing ends.
        let trace = Path::new(r"C:\captures\denials.verbose.json");
        let error = prepare_config_output_paths(
            None,
            Path::new(r"C:\captures"),
            trace,
            Path::new(r"C:\captures\denials.json"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("would be overwritten"));
    }

    #[test]
    fn config_snapshot_cannot_collide_with_verbose_logging_output() {
        let source = Path::new(r"C:\source\denials.verbose.json");
        let error = prepare_config_output_paths(
            Some(source),
            Path::new(r"C:\captures"),
            Path::new(r"C:\captures\trace.etl"),
            Path::new(r"C:\captures\denials.json"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("config snapshot"));
    }

    #[test]
    fn trailing_dot_trace_alias_cannot_collide_with_denials_output() {
        let dir = std::env::temp_dir().join(format!("plm_alias_target_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let error = prepare_config_output_paths(
            None,
            &dir,
            &dir.join("denials.json."),
            &dir.join("denials.json"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("would be overwritten"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn default_stream_trace_alias_cannot_collide_with_denials_output() {
        let dir = std::env::temp_dir().join(format!("plm_stream_target_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let error = prepare_config_output_paths(
            None,
            &dir,
            &dir.join("denials.json::$DATA"),
            &dir.join("denials.json"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("would be overwritten"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn source_config_collision_is_rejected_before_capture() {
        let trace = Path::new(r"C:\captures\trace.etl");
        let error = prepare_config_output_paths(
            Some(trace),
            Path::new(r"C:\logs"),
            trace,
            Path::new(r"C:\logs\denials.json"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("source config"));
    }

    #[test]
    fn source_config_hard_link_collision_is_rejected_before_capture() {
        let dir = std::env::temp_dir().join(format!("plm_hard_link_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("config.json");
        let trace = dir.join("trace.etl");
        std::fs::write(&source, "{}").unwrap();
        std::fs::hard_link(&source, &trace).unwrap();

        let error =
            prepare_config_output_paths(Some(&source), &dir, &trace, &dir.join("denials.json"))
                .unwrap_err();
        assert!(error.to_string().contains("source config"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn same_config_target_matches_identical_existing_path() {
        // Two spellings of the same existing file must be detected as
        // the same target so the snapshot-clobber guard fires.
        let dir = std::env::temp_dir().join(format!("plm_same_target_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("config.json");
        std::fs::write(&a, b"{}").unwrap();
        let b = dir.join(".").join("config.json");
        assert!(
            same_config_target(&a, &b),
            "same file via different spelling"
        );
        let other = dir.join("Adjusted_config.json");
        assert!(
            !same_config_target(&a, &other),
            "distinct files must not collide"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn same_config_target_matches_existing_hard_links() {
        let dir = std::env::temp_dir().join(format!("plm_hard_link_key_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("source.json");
        let alias = dir.join("alias.json");
        std::fs::write(&source, "{}").unwrap();
        std::fs::hard_link(&source, &alias).unwrap();
        assert!(same_config_target(&source, &alias));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn same_config_target_is_case_insensitive_for_new_outputs() {
        let dir = std::env::temp_dir().join(format!("plm_case_target_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let lower = dir.join("denials.json");
        let upper = dir.join("DENIALS.JSON");
        assert!(same_config_target(&lower, &upper));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn same_config_target_is_unicode_case_insensitive_for_new_outputs() {
        let dir = std::env::temp_dir().join(format!("plm_unicode_target_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(same_config_target(&dir.join("Ä.etl"), &dir.join("ä.etl")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn same_config_target_normalizes_trailing_dot_for_new_outputs() {
        let dir = std::env::temp_dir().join(format!("plm_dot_target_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(same_config_target(
            &dir.join("denials.json."),
            &dir.join("denials.json")
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn same_config_target_normalizes_trailing_space_for_new_outputs() {
        let dir = std::env::temp_dir().join(format!("plm_space_target_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(same_config_target(
            &dir.join("denials.json "),
            &dir.join("denials.json")
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn same_config_target_normalizes_default_stream_for_new_outputs() {
        let dir = std::env::temp_dir().join(format!("plm_stream_key_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(same_config_target(
            &dir.join("denials.json::$data"),
            &dir.join("denials.json")
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn same_config_target_normalizes_trailing_characters_after_default_stream() {
        let dir = std::env::temp_dir().join(format!("plm_stream_trim_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for alias in ["denials.json::$DATA.", "denials.json::$DATA "] {
            assert!(same_config_target(
                &dir.join(alias),
                &dir.join("denials.json")
            ));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn same_config_target_normalizes_default_stream_for_verbatim_outputs() {
        assert!(same_config_target(
            Path::new(r"\\?\C:\captures\denials.json::$DATA"),
            Path::new(r"\\?\C:\captures\denials.json")
        ));
    }

    #[test]
    fn same_config_target_preserves_trailing_dot_for_verbatim_outputs() {
        assert!(!same_config_target(
            Path::new(r"\\?\C:\captures\denials.json."),
            Path::new(r"\\?\C:\captures\denials.json")
        ));
    }
}
