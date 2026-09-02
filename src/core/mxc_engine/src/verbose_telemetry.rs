// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Telemetry transport for the canonical Learning Mode verbose JSON artifact.

use std::io::Read;
use std::path::Path;

use learning_mode_core::{verbose_logging_sibling_path, VerboseLoggingDocument};
use sha2::{Digest, Sha256};
use wxc_common::models::{ContainmentBackend, ScriptResponse};
use wxc_common::telemetry::{self, VerboseEvent};

/// Leaves room for TraceLogging metadata beneath ETW's approximately 64 KiB
/// event limit.
const MAX_CONTENT_BYTES: usize = 48 * 1024;
/// The pretty-printed file is bounded separately from its compact form.
const MAX_INPUT_BYTES: u64 = 32 * 1024 * 1024;
/// Property names describe provider schemas, but values can contain
/// workload-controlled object names and are never included in telemetry.
const REDACTED_PROPERTY_VALUE: &str = "<redacted>";

#[derive(Debug)]
struct PreparedVerboseDocument {
    document_id: String,
    version: u32,
    document_bytes: u64,
    document_sha256: String,
    summary: String,
    chunks: Vec<String>,
}

/// Emit the verbose artifact referenced by a successful capture-denials result.
///
/// `Ok(())` also covers responses with no capture artifact. Telemetry failures
/// never alter the sandbox result; callers may surface the bounded error only
/// through local diagnostics.
pub fn emit_verbose_telemetry(
    active: bool,
    containment: &ContainmentBackend,
    requested_sandbox_kind: Option<&'static str>,
    response: &ScriptResponse,
) -> Result<(), String> {
    if !active {
        return Ok(());
    }
    let Some(prepared) = prepare_from_response(response)? else {
        return Ok(());
    };

    let backend = containment.wire_name();
    let sandbox_kind = requested_sandbox_kind.unwrap_or(backend);
    let chunk_count = u32::try_from(prepared.chunks.len())
        .map_err(|_| "verbose artifact produced too many telemetry chunks".to_string())?;
    for (index, content) in prepared.chunks.iter().enumerate() {
        let chunk_index = u32::try_from(index)
            .map_err(|_| "verbose artifact chunk index exceeded u32".to_string())?;
        match telemetry::emit_verbose(
            true,
            &VerboseEvent {
                backend,
                sandbox_kind,
                phase: "",
                correlation_vector: "",
                document_id: &prepared.document_id,
                document_version: prepared.version,
                chunk_index,
                chunk_count,
                document_bytes: prepared.document_bytes,
                document_sha256: &prepared.document_sha256,
                content,
                summary: &prepared.summary,
            },
        ) {
            Ok(true) => {}
            Ok(false) => break,
            Err(status) => {
                return Err(format!(
                    "ETW rejected a verbose telemetry chunk with status {status}"
                ));
            }
        }
    }
    Ok(())
}

fn prepare_from_response(
    response: &ScriptResponse,
) -> Result<Option<PreparedVerboseDocument>, String> {
    let Some(capture) = response
        .output_metadata
        .as_deref()
        .and_then(|metadata| metadata.capture_denials.as_ref())
    else {
        return Ok(None);
    };
    let path = verbose_logging_sibling_path(Path::new(&capture.output_path))
        .map_err(|_| "could not derive the verbose artifact path".to_string())?;
    prepare_document(&path).map(Some)
}

fn prepare_document(path: &Path) -> Result<PreparedVerboseDocument, String> {
    let file =
        std::fs::File::open(path).map_err(|_| "could not open the verbose artifact".to_string())?;
    let metadata = file
        .metadata()
        .map_err(|_| "could not inspect the verbose artifact".to_string())?;
    if metadata.len() > MAX_INPUT_BYTES {
        return Err("verbose artifact exceeds the telemetry input bound".to_string());
    }

    let capacity = usize::try_from(metadata.len())
        .map_err(|_| "verbose artifact size exceeds this platform".to_string())?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "could not read the verbose artifact".to_string())?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err("verbose artifact exceeds the telemetry input bound".to_string());
    }

    let document: VerboseLoggingDocument = serde_json::from_slice(&bytes)
        .map_err(|_| "verbose artifact is not valid typed JSON".to_string())?;
    if document.version != VerboseLoggingDocument::VERSION {
        return Err("verbose artifact uses an unsupported document version".to_string());
    }
    let document = project_for_telemetry(document);

    let compact = serde_json::to_vec(&document)
        .map_err(|_| "could not compact the verbose artifact".to_string())?;
    let document_bytes = u64::try_from(compact.len())
        .map_err(|_| "verbose artifact byte count exceeded u64".to_string())?;
    let document_sha256 = format!("{:x}", Sha256::digest(&compact));
    let summary = serde_json::to_string(&document.summary)
        .map_err(|_| "could not serialize the verbose artifact summary".to_string())?;
    let chunks = chunk_signatures(&document)?;
    let document_id = random_document_id()?;

    Ok(PreparedVerboseDocument {
        document_id,
        version: document.version,
        document_bytes,
        document_sha256,
        summary,
        chunks,
    })
}

fn project_for_telemetry(mut document: VerboseLoggingDocument) -> VerboseLoggingDocument {
    for aggregate in &mut document.signatures {
        for (_, value) in &mut aggregate.signature.properties {
            REDACTED_PROPERTY_VALUE.clone_into(value);
        }
    }
    document
}

fn chunk_signatures(document: &VerboseLoggingDocument) -> Result<Vec<String>, String> {
    let mut chunks = Vec::new();
    let mut current = String::from("[");
    let mut current_count = 0usize;

    for signature in &document.signatures {
        let item = serde_json::to_string(signature)
            .map_err(|_| "could not serialize a verbose signature".to_string())?;
        let separator_bytes = usize::from(current_count > 0);
        let candidate_bytes = current
            .len()
            .saturating_add(separator_bytes)
            .saturating_add(item.len())
            .saturating_add(1);

        if candidate_bytes > MAX_CONTENT_BYTES && current_count > 0 {
            current.push(']');
            chunks.push(current);
            current = String::from("[");
            current_count = 0;
        }

        if item.len().saturating_add(2) > MAX_CONTENT_BYTES {
            return Err("one verbose signature exceeds the telemetry event bound".to_string());
        }
        if current_count > 0 {
            current.push(',');
        }
        current.push_str(&item);
        current_count += 1;
    }

    current.push(']');
    chunks.push(current);
    Ok(chunks)
}

fn random_document_id() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| "could not generate a verbose telemetry document id".to_string())?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use learning_mode_core::{
        VerboseLoggingAggregate, VerboseLoggingDocumentSummary, VerboseLoggingOutcomeReason,
        VerboseLoggingProvider, VerboseLoggingSignature,
    };
    use wxc_common::models::{CaptureDenialsOutput, SandboxOutputMetadata};

    fn aggregate(event_id: u16, value: &str) -> VerboseLoggingAggregate {
        VerboseLoggingAggregate {
            signature: VerboseLoggingSignature {
                provider: VerboseLoggingProvider::KernelGeneral,
                provider_guid: "{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}".to_string(),
                event_id,
                reason: VerboseLoggingOutcomeReason::UnsupportedEventSchema,
                pid: 42,
                access_type: None,
                resource_type: None,
                properties: vec![("Value".to_string(), value.to_string())],
            },
            count: 1,
        }
    }

    fn document(signatures: Vec<VerboseLoggingAggregate>) -> VerboseLoggingDocument {
        VerboseLoggingDocument {
            version: VerboseLoggingDocument::VERSION,
            signatures,
            summary: VerboseLoggingDocumentSummary {
                total_occurrences: 1,
                overflow_occurrences: 0,
                actionable_overflow_occurrences: 0,
                aggregate_groups_truncated: false,
                processed_events_truncated: false,
                actionable_limit_reached: false,
            },
        }
    }

    #[test]
    fn every_chunk_is_an_independently_parseable_json_array() {
        let doc = document(vec![aggregate(1, "one"), aggregate(2, "two")]);
        let chunks = chunk_signatures(&doc).unwrap();
        let rebuilt = chunks
            .iter()
            .flat_map(|chunk| serde_json::from_str::<Vec<VerboseLoggingAggregate>>(chunk).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(rebuilt, doc.signatures);
    }

    #[test]
    fn empty_document_emits_one_empty_array() {
        assert_eq!(chunk_signatures(&document(Vec::new())).unwrap(), ["[]"]);
    }

    #[test]
    fn chunks_only_between_complete_aggregates() {
        let large = "x".repeat(MAX_CONTENT_BYTES / 2);
        let doc = document(vec![aggregate(1, &large), aggregate(2, &large)]);
        let chunks = chunk_signatures(&doc).unwrap();
        assert_eq!(chunks.len(), 2);
        for chunk in chunks {
            let parsed: Vec<VerboseLoggingAggregate> = serde_json::from_str(&chunk).unwrap();
            assert_eq!(parsed.len(), 1);
        }
    }

    #[test]
    fn rejects_unsupported_document_version() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("denials.verbose.json");
        let mut doc = document(Vec::new());
        doc.version += 1;
        std::fs::write(&path, serde_json::to_vec(&doc).unwrap()).unwrap();
        assert!(prepare_document(&path)
            .unwrap_err()
            .contains("unsupported document version"));
    }

    #[test]
    fn prepared_chunks_reconstruct_the_telemetry_projection() {
        let directory = tempfile::tempdir().unwrap();
        let denials_path = directory.path().join("denials.json");
        let verbose_path = verbose_logging_sibling_path(&denials_path).unwrap();
        let doc = document(vec![
            aggregate(1, "customer-secret-one"),
            aggregate(2, "customer-secret-two"),
        ]);
        let mut pretty = Vec::new();
        learning_mode_core::write_verbose_logging_document(&mut pretty, &doc).unwrap();
        std::fs::write(&verbose_path, pretty).unwrap();

        let response = ScriptResponse {
            output_metadata: Some(Box::new(SandboxOutputMetadata {
                capture_denials: Some(CaptureDenialsOutput {
                    kind: CaptureDenialsOutput::KIND.to_string(),
                    output_path: denials_path.to_string_lossy().into_owned(),
                    exit_code: 0,
                    total_denials: 0,
                    denied_resources_truncated: false,
                    etl_path: None,
                }),
                capture_denials_error: None,
            })),
            ..Default::default()
        };
        let prepared = prepare_from_response(&response).unwrap().unwrap();
        let signatures = prepared
            .chunks
            .iter()
            .flat_map(|chunk| serde_json::from_str::<Vec<VerboseLoggingAggregate>>(chunk).unwrap())
            .collect();
        let summary = serde_json::from_str(&prepared.summary).unwrap();
        let reconstructed = VerboseLoggingDocument {
            version: prepared.version,
            signatures,
            summary,
        };
        let compact = serde_json::to_vec(&reconstructed).unwrap();

        assert_eq!(compact.len() as u64, prepared.document_bytes);
        assert_eq!(
            format!("{:x}", Sha256::digest(&compact)),
            prepared.document_sha256
        );
        assert_eq!(reconstructed, project_for_telemetry(doc));
        assert!(reconstructed.signatures.iter().all(|aggregate| {
            aggregate
                .signature
                .properties
                .iter()
                .all(|(_, value)| value == REDACTED_PROPERTY_VALUE)
        }));
    }

    #[test]
    fn malformed_artifact_never_falls_back_to_raw_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("denials.verbose.json");
        std::fs::write(&path, br#"{"secret":"do-not-send"}"#).unwrap();
        let error = prepare_document(&path).unwrap_err();
        assert_eq!(error, "verbose artifact is not valid typed JSON");
        assert!(!error.contains("do-not-send"));
    }
}
