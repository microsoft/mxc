// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Canonical Learning Mode analysis and compatibility views for `plm.exe`.

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use learning_mode_core::{
    write_document, AccessType, AnalysisResult, DenialAnalyzer, DenialSummary, DenialsDocument,
    DeniedResource, ResourceType,
};
use learning_mode_windows::EtlDenialAnalyzer;

use crate::access_event::LearningModeAccessEvent;

/// Analyze a sealed ETL through the same decoder used by `captureDenials`.
pub fn analyze_trace(trace_file: &Path) -> Result<AnalysisResult> {
    EtlDenialAnalyzer
        .analyze(trace_file)
        .map_err(anyhow::Error::new)
        .with_context(|| format!("failed to analyze {}", trace_file.display()))
}

/// Write canonical denials JSON atomically and return the document that was written.
pub fn write_denials(
    output_path: &Path,
    analysis: &AnalysisResult,
    exit_code: i32,
) -> Result<DenialsDocument> {
    let parent = output_path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create {}", parent.display()))?;

    let summary = DenialSummary::new(
        exit_code,
        analysis.denials.len(),
        analysis.denied_resources_truncated,
    );
    let document = DenialsDocument::new(analysis.denials.clone(), summary);
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("failed to create denials temp file in {}", parent.display()))?;
    write_document(&mut temp, &document)
        .with_context(|| format!("failed to write {}", output_path.display()))?;
    temp.flush()
        .and_then(|_| temp.as_file().sync_all())
        .with_context(|| format!("failed to flush {}", output_path.display()))?;
    temp.persist(output_path)
        .map_err(|error| error.error)
        .with_context(|| format!("failed to replace {}", output_path.display()))?;
    Ok(document)
}

/// Build the temporary legacy config-generator inputs from canonical denials.
///
/// The adjusted-config generator is removed in the regeneration work item.
/// Until then, this adapter preserves its existing file/capability behavior
/// without retaining a second ETL parser.
pub fn legacy_config_inputs(
    denials: &[DeniedResource],
    current_directory: Option<&str>,
) -> (Vec<LearningModeAccessEvent>, HashSet<String>) {
    let mut events: Vec<LearningModeAccessEvent> = Vec::new();
    let mut file_event_indices: HashMap<String, usize> = HashMap::new();
    let mut capabilities = HashSet::new();

    for denial in denials {
        match denial.resource_type {
            ResourceType::File => {
                let Some(file_path) = normalize_legacy_file_path(&denial.resource) else {
                    continue;
                };
                if is_current_directory_path(&file_path, current_directory) {
                    continue;
                }
                let access_mask = match denial.access_type {
                    AccessType::Read => 0x1,
                    AccessType::Write => 0x2,
                    AccessType::Execute => 0x20,
                    AccessType::Unknown => continue,
                };
                let key = file_path.to_ascii_lowercase();
                if let Some(index) = file_event_indices.get(&key).copied() {
                    events[index].access_mask |= access_mask;
                } else {
                    file_event_indices.insert(key, events.len());
                    events.push(LearningModeAccessEvent {
                        time_created: chrono::Utc::now(),
                        process_id: denial.pid,
                        thread_id: 0,
                        file_path,
                        access_mask,
                    });
                }
            }
            ResourceType::Capability => {
                if !denial.resource.starts_with("S-1-") {
                    capabilities.insert(denial.resource.clone());
                }
            }
            ResourceType::Ui | ResourceType::Network | ResourceType::Other => {}
        }
    }

    fn is_current_directory_path(path: &str, current_directory: Option<&str>) -> bool {
        let Some(current_directory) = current_directory else {
            return false;
        };
        let current_directory = current_directory.trim_end_matches('\\');
        let path = path.trim_end_matches('\\');
        if path.eq_ignore_ascii_case(current_directory) {
            return true;
        }

        let bytes = current_directory.as_bytes();
        let is_drive_root = bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
        let path_bytes = path.as_bytes();
        !is_drive_root
            && path_bytes.len() > bytes.len()
            && path_bytes[..bytes.len()]
                .iter()
                .zip(bytes)
                .all(|(path_byte, cwd_byte)| path_byte.eq_ignore_ascii_case(cwd_byte))
            && path_bytes[bytes.len()] == b'\\'
    }

    (events, capabilities)
}

fn normalize_legacy_file_path(path: &str) -> Option<String> {
    let path = path.trim();
    if path.is_empty()
        || path.chars().any(|character| {
            character.is_control() || matches!(character, '<' | '>' | '"' | '|' | '?' | '*')
        })
    {
        return None;
    }
    let without_trailing_separator = path.trim_end_matches(['\\', '/']);
    let normalized = if without_trailing_separator.len() == 2
        && without_trailing_separator.as_bytes()[0].is_ascii_alphabetic()
        && without_trailing_separator.as_bytes()[1] == b':'
    {
        format!("{without_trailing_separator}\\")
    } else {
        without_trailing_separator.to_string()
    };
    is_local_drive_path(&normalized).then_some(normalized)
}

fn is_local_drive_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/')
}

/// Print a concise human-readable view of canonical denials.
pub fn write_detection_summary(analysis: &AnalysisResult) {
    println!();
    println!("Detected denials ({}):", analysis.denials.len());
    if analysis.denials.is_empty() {
        println!("  (none)");
    } else {
        for denial in &analysis.denials {
            println!(
                "  [{:?}/{:?}] {}",
                denial.resource_type, denial.access_type, denial.resource
            );
        }
    }
    if analysis.denied_resources_truncated {
        println!("  (truncated)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn denial(
        resource: &str,
        resource_type: ResourceType,
        access_type: AccessType,
    ) -> DeniedResource {
        DeniedResource {
            resource: resource.to_string(),
            resource_type,
            access_type,
            pid: 42,
            filetime: 1,
        }
    }

    #[test]
    fn legacy_inputs_are_derived_only_from_canonical_file_and_capability_denials() {
        let denials = [
            denial(r"C:\read.txt", ResourceType::File, AccessType::Read),
            denial(r"C:\write.txt", ResourceType::File, AccessType::Write),
            denial(r"C:\both.txt", ResourceType::File, AccessType::Read),
            denial(r"c:\BOTH.txt", ResourceType::File, AccessType::Write),
            denial(
                "internetClient",
                ResourceType::Capability,
                AccessType::Unknown,
            ),
            denial("Clipboard", ResourceType::Ui, AccessType::Unknown),
            denial(
                "S-1-15-3-1024-1-2-3-4-5-6-7-8",
                ResourceType::Capability,
                AccessType::Unknown,
            ),
            denial(r"C:\unknown.txt", ResourceType::File, AccessType::Unknown),
            denial(
                r"\\server\share\remote.txt",
                ResourceType::File,
                AccessType::Write,
            ),
        ];

        let (events, capabilities) = legacy_config_inputs(&denials, None);
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].access_mask, 0x1);
        assert_eq!(events[1].access_mask, 0x2);
        assert_eq!(events[2].access_mask, 0x3);
        assert_eq!(capabilities, HashSet::from(["internetClient".to_string()]));
    }

    #[test]
    fn legacy_inputs_exclude_current_directory_but_not_siblings() {
        let denials = vec![
            denial(
                r"C:\work\repo\tool.log",
                ResourceType::File,
                AccessType::Write,
            ),
            denial(
                r"C:\work\repo2\data.txt",
                ResourceType::File,
                AccessType::Read,
            ),
        ];

        let (events, _) = legacy_config_inputs(&denials, Some(r"C:\work\repo"));

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].file_path, r"C:\work\repo2\data.txt");
    }

    #[test]
    fn legacy_inputs_reject_invalid_paths() {
        let denials = [
            denial("C:\\bad\\*.txt", ResourceType::File, AccessType::Write),
            denial("C:\\bad\\line\nfeed", ResourceType::File, AccessType::Read),
            denial(
                "C:\\bad\\pipe|name",
                ResourceType::File,
                AccessType::Execute,
            ),
        ];

        let (events, _) = legacy_config_inputs(&denials, None);

        assert!(events.is_empty());
    }

    #[test]
    fn legacy_inputs_normalize_before_deduplication() {
        let denials = [
            denial(
                "  C:\\data\\folder\\  ",
                ResourceType::File,
                AccessType::Read,
            ),
            denial("c:\\DATA\\folder", ResourceType::File, AccessType::Write),
        ];

        let (events, _) = legacy_config_inputs(&denials, None);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].file_path, "C:\\data\\folder");
        assert_eq!(events[0].access_mask, 0x3);
    }

    #[test]
    fn canonical_document_preserves_analysis_results() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("denials.json");
        let analysis = AnalysisResult {
            denials: vec![denial(r"C:\read.txt", ResourceType::File, AccessType::Read)],
            denied_resources_truncated: true,
        };

        write_denials(&path, &analysis, 7).unwrap();
        let document: DenialsDocument =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(document.denials, analysis.denials);
        assert_eq!(document.summary.exit_code, 7);
        assert!(document.summary.denied_resources_truncated);
    }
}
