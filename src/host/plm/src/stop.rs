// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `plm stop` — keep caller-selected path handling and ETL analysis
//! unelevated. Only the fixed `wpr -stop` operation runs in the restricted
//! elevated child, which transfers the ETL back over an authenticated pipe.

use anyhow::{Context, Result};
use chrono::Local;
use learning_mode_core::DenialsDocument;
use serde::Serialize;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

use crate::analysis::{
    analyze_trace, legacy_config_inputs, write_denials, write_detection_summary,
};
use crate::config::{
    deny_file_set, initialize_filesystem, load_config, merge_capabilities,
    resolve_adjusted_config_path, save_adjusted_config, update_from_access_events,
    write_added_paths_summary, write_requested_capabilities_summary,
};
use crate::wpr_path::wpr_command;

pub struct StopOptions {
    pub log_dir: Option<PathBuf>,
    pub bin_path: Option<PathBuf>,
    pub config_path: Option<PathBuf>,
    /// When set, skip `wpr -stop` and treat the supplied .etl as the
    /// captured trace. Useful for re-processing a previously captured
    /// trace without an active WPR session.
    pub trace_file: Option<PathBuf>,
    /// Exit code recorded in the canonical denials document.
    pub exit_code: i32,
    pub verbose: bool,
}

/// Inputs for generating compatibility artifacts from canonical denials.
#[derive(Debug, Clone)]
pub struct PostProcessOptions {
    pub log_dir: PathBuf,
    pub bin_path: Option<PathBuf>,
    pub config_path: Option<PathBuf>,
    pub trace_path: PathBuf,
    pub denials_path: PathBuf,
    pub verbose: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StopResult {
    pub trace_path: PathBuf,
    pub denials_path: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adjusted_config_path: Option<PathBuf>,
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
    if same_config_target(trace_path, denials_path) {
        anyhow::bail!(
            "trace output {} would be overwritten by denials output {}",
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
        if same_config_target(path, trace_path) || same_config_target(path, denials_path) {
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

/// Abstraction over `wpr -stop` invocations so the failure-mapping
/// state machine in `stop_plm_trace_with` is testable without
/// actually spawning processes. Mirrors `start::WprLauncher`.
pub trait WprStopper {
    fn stop(&mut self, trace_file: &Path) -> Result<ExitStatus>;
}

pub struct WprExeStopper;

impl WprStopper for WprExeStopper {
    fn stop(&mut self, trace_file: &Path) -> Result<ExitStatus> {
        let mut cmd = wpr_command();
        let resolved = cmd.get_program().to_string_lossy().into_owned();
        let output = cmd
            .arg("-stop")
            .arg(trace_file)
            .output()
            .map_err(|e| anyhow::anyhow!("failed to spawn wpr -stop ({resolved}): {e}"))?;
        if !output.status.success() {
            return Err(crate::start::describe_wpr_failure("stop", &output));
        }
        Ok(output.status)
    }
}

/// Testable wrapper for `wpr -stop` status handling.
pub fn stop_plm_trace_with<S: WprStopper>(stopper: &mut S, trace_file: &Path) -> Result<()> {
    let status = stopper.stop(trace_file)?;
    if !status.success() {
        anyhow::bail!("wpr -stop exited with {status}");
    }
    Ok(())
}

/// Resolve `--bin-path` (or fall back to the calling exe directory)
/// to its canonical form. Consumed by `update_from_access_events` as
/// the self-access filter: events referencing this path are dropped
/// from the adjusted config so the container never grants itself
/// broad access to its own binary directory.
///
/// Fallback chain:
///   1. `canonicalize(opt.bin_path)` if `Some`
///   2. raw `opt.bin_path` if `Some` (with a warning)
///   3. `exe_dir` (no warning)
pub fn resolve_bin_path(opt: Option<&Path>, exe_dir: &Path) -> (PathBuf, Option<String>) {
    let Some(raw) = opt else {
        return (exe_dir.to_path_buf(), None);
    };
    match raw.canonicalize() {
        Ok(p) => (p, None),
        Err(e) => {
            let warning = format!(
                "could not canonicalize --bin-path {} ({}); self-access filter \
                 will use the raw path. Events referencing the binary via a \
                 different spelling (e.g. verbatim \\\\?\\) may leak into the \
                 adjusted config.",
                raw.display(),
                e
            );
            // Prefer the raw operator-supplied path over silently
            // substituting exe_dir; that would drop operator intent.
            (raw.to_path_buf(), Some(warning))
        }
    }
}

pub fn run(opts: StopOptions, exe_dir: &Path) -> Result<StopResult> {
    // $LogDir defaults to the caller-writable per-user local data directory.
    // Including PID + sub-second component avoids collisions when
    // parallel PLM tasks finish in the same second.
    let log_dir = opts.log_dir.unwrap_or_else(default_log_dir);
    std::fs::create_dir_all(&log_dir)
        .with_context(|| format!("failed to create log dir {}", log_dir.display()))?;

    // Resolve bin_path to its canonical form so the self-access filter
    // in `config::update_from_access_events` can compare it against the
    // verbatim-prefixed paths ETW emits. The fallback chain is in
    // `resolve_bin_path`.
    let trace_file = opts
        .trace_file
        .context("plm stop requires --trace-file from a retained guardian capture")?;
    let denials_path = log_dir.join("denials.json");
    let config_outputs = prepare_config_output_paths(
        opts.config_path.as_deref(),
        &log_dir,
        &trace_file,
        &denials_path,
    )?;

    if !trace_file.exists() {
        anyhow::bail!("trace file does not exist: {}", trace_file.display());
    }

    if opts.verbose {
        println!("Beginning event parsing, this may take several minutes");
    }

    let analysis = analyze_trace(&trace_file)?;
    write_detection_summary(&analysis);
    let document = write_denials(&denials_path, &analysis, opts.exit_code)?;

    let adjusted_config_path = postprocess_denials_with_paths(
        &document,
        &PostProcessOptions {
            log_dir,
            bin_path: opts.bin_path,
            config_path: opts.config_path,
            trace_path: trace_file.clone(),
            denials_path: denials_path.clone(),
            verbose: opts.verbose,
        },
        exe_dir,
        config_outputs,
    )?;

    Ok(StopResult {
        trace_path: trace_file,
        denials_path,
        adjusted_config_path,
    })
}

/// Generates the source-config snapshot and adjusted config from canonical denials.
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

    let (bin_path, warning) = resolve_bin_path(opts.bin_path.as_deref(), exe_dir);
    if let Some(warning) = warning {
        eprintln!("[plm] warning: {warning}");
    }

    // Load the source config before copying or mutating it. The trace and
    // canonical denials remain useful even if this compatibility-only
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
            "[plm] warning: denial analysis was truncated; skipping adjusted-config \
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

    let bin_path_s = bin_path.to_string_lossy().into_owned();
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
    use wxc_common::filesystem_object::{
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
    wxc_common::string_util::windows_paths_equal_ignore_case(a, b)
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
    use learning_mode_core::{AccessType, DenialSummary, DeniedResource, ResourceType};

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
                bin_path: None,
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
    fn canonical_denials_generate_snapshot_and_adjusted_config() {
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
    fn truncated_canonical_denials_snapshot_but_skip_adjusted_config() {
        let document = DenialsDocument::new(Vec::new(), DenialSummary::new(0, 0, true));

        let (_directory, log_dir, adjusted) = postprocess_fixture(&document);

        assert!(log_dir.join("policy.json").is_file());
        assert!(adjusted.is_none());
        assert!(!log_dir.join("Adjusted_policy.json").exists());
    }

    // ---- resolve_bin_path -----------------------------------------------

    #[test]
    fn resolve_bin_path_falls_back_to_exe_dir_when_no_override() {
        let exe = std::env::temp_dir();
        let (p, warn) = resolve_bin_path(None, &exe);
        assert_eq!(p, exe);
        assert!(warn.is_none(), "no operator intent means no warning");
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
    fn resolve_bin_path_canonicalizes_existing_override() {
        let exe = std::env::temp_dir();
        let override_path = std::env::temp_dir();
        let (p, warn) = resolve_bin_path(Some(&override_path), &exe);
        assert!(p.exists(), "canonicalized path should still exist");
        assert!(warn.is_none(), "successful canonicalize must not warn");
    }

    #[test]
    fn resolve_bin_path_warns_and_returns_raw_when_canonicalize_fails() {
        let exe = std::env::temp_dir();
        let bogus = std::path::PathBuf::from("Z:\\definitely-does-not-exist-plm-test");
        let (p, warn) = resolve_bin_path(Some(&bogus), &exe);
        assert_eq!(
            p, bogus,
            "must return the raw operator path rather than silently \
             substituting exe_dir (would drop operator intent)"
        );
        let w = warn.expect("canonicalize failure must surface a warning");
        assert!(
            w.contains("Z:\\definitely-does-not-exist-plm-test"),
            "warning must reference the failing path: {w}",
        );
    }

    // ---- WprStopper / stop_plm_trace_with -------------------------------

    use std::os::windows::process::ExitStatusExt;

    struct FakeStopper {
        result: std::cell::Cell<Option<Result<ExitStatus>>>,
        calls: std::cell::Cell<usize>,
    }
    impl FakeStopper {
        fn ok(code: u32) -> Self {
            Self {
                result: std::cell::Cell::new(Some(Ok(ExitStatus::from_raw(code)))),
                calls: std::cell::Cell::new(0),
            }
        }
        fn err(msg: &'static str) -> Self {
            Self {
                result: std::cell::Cell::new(Some(Err(anyhow::anyhow!(msg)))),
                calls: std::cell::Cell::new(0),
            }
        }
    }
    impl WprStopper for FakeStopper {
        fn stop(&mut self, _trace_file: &Path) -> Result<ExitStatus> {
            self.calls.set(self.calls.get() + 1);
            self.result
                .replace(None)
                .expect("FakeStopper.stop called more than once")
        }
    }

    #[test]
    fn stop_plm_trace_returns_ok_on_zero_exit() {
        let mut s = FakeStopper::ok(0);
        stop_plm_trace_with(&mut s, Path::new("trace.etl"))
            .expect("zero-exit must propagate as Ok");
        assert_eq!(s.calls.get(), 1);
    }

    #[test]
    fn stop_plm_trace_propagates_nonzero_exit_with_context() {
        let mut s = FakeStopper::ok(1);
        let err = stop_plm_trace_with(&mut s, Path::new("trace.etl"))
            .expect_err("non-zero exit must propagate as Err");
        let msg = format!("{err}");
        assert!(
            msg.contains("wpr -stop exited"),
            "error must name the failed command: {msg}",
        );
    }

    #[test]
    fn stop_plm_trace_propagates_spawn_error_verbatim() {
        let mut s = FakeStopper::err("simulated spawn failure: not found");
        let err = stop_plm_trace_with(&mut s, Path::new("trace.etl"))
            .expect_err("spawn error must propagate");
        let msg = format!("{err}");
        assert!(
            msg.contains("simulated spawn failure"),
            "error must surface the underlying io::Error context: {msg}",
        );
    }

    #[test]
    fn trace_input_cannot_collide_with_denials_output() {
        let path = Path::new(r"C:\captures\denials.json");
        let error =
            prepare_config_output_paths(None, Path::new(r"C:\captures"), path, path).unwrap_err();
        assert!(error.to_string().contains("would be overwritten"));
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
