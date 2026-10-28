// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Parses tagged Seatbelt reports from `log stream --style ndjson` output and
//! turns them into `captureDenials` results. Platform-agnostic so the parsing
//! is unit-tested on every host.

use std::collections::HashSet;

use serde::Deserialize;

use crate::learning_mode_core::capture_diagnostics::{
    CaptureAnalysis, CaptureVerboseLoggingOutcomeReason, CaptureVerboseLoggingProvider,
    CaptureVerboseLoggingSignature, CaptureVerboseLoggingSummary, SEATBELT_PROVIDER_ID,
};
use crate::learning_mode_core::{
    AccessType, DeniedResource, ResourceType, VerboseLoggingSummary,
    MAX_VERBOSE_LOGGING_SIGNATURE_BYTES,
};
use crate::seatbelt_common::profile_builder::GRANT_TAG_SUFFIX;

/// Same bound as the Windows decoder.
const MAX_UNIQUE_DENIALS: usize = 10_000;
const MAX_PROPERTY_CHARS: usize = 256;
const REDACTED_PATH: &str = "<REDACTED>";
/// Seconds between 1601-01-01 (FILETIME epoch) and 1970-01-01.
const FILETIME_UNIX_OFFSET_SECS: i64 = 11_644_473_600;
/// Reports every process triggers while loading; never actionable.
const NOISE_TARGETS: &[&str] = &["/dev/dtracehelper"];

/// Markers the collector emits around a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CaptureMarker {
    Ready,
    Done,
}

impl CaptureMarker {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Done => "done",
        }
    }
}

/// One tagged Seatbelt report from the run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SandboxLogEvent {
    /// Full `eventMessage`, including the trailing tag line.
    pub(crate) message: String,
    /// Unified-log timestamp, e.g. `2026-01-02 03:04:05.123456-0700`.
    pub(crate) timestamp: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum StreamLine {
    Marker(CaptureMarker),
    Event(SandboxLogEvent),
    Ignored,
}

#[derive(Deserialize)]
struct NdjsonEvent {
    #[serde(rename = "eventMessage")]
    event_message: Option<String>,
    timestamp: Option<String>,
}

/// Classifies one `log stream` output line for the run tagged `tag`.
pub(crate) fn parse_stream_line(line: &str, tag: &str) -> StreamLine {
    let Ok(event) = serde_json::from_str::<NdjsonEvent>(line.trim_end()) else {
        return StreamLine::Ignored;
    };
    let Some(message) = event.event_message else {
        return StreamLine::Ignored;
    };
    let Some(suffix) = message.rsplit_once('\n').map(|(_, suffix)| suffix) else {
        return StreamLine::Ignored;
    };
    let Some(rest) = suffix.strip_prefix(tag) else {
        return StreamLine::Ignored;
    };
    match rest.strip_prefix(':') {
        Some(name) if name == CaptureMarker::Ready.as_str() => {
            StreamLine::Marker(CaptureMarker::Ready)
        }
        Some(name) if name == CaptureMarker::Done.as_str() => {
            StreamLine::Marker(CaptureMarker::Done)
        }
        _ if rest.is_empty()
            || rest == crate::seatbelt_common::profile_builder::GRANT_TAG_SUFFIX =>
        {
            StreamLine::Event(SandboxLogEvent {
                message,
                timestamp: event.timestamp,
            })
        }
        _ => StreamLine::Ignored,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    Deny,
    Allow,
}

/// One parsed `Sandbox: name(pid) deny(1)|allow <operation> <target>` report.
#[derive(Debug, PartialEq, Eq)]
struct SandboxReport<'a> {
    process: &'a str,
    pid: u32,
    decision: Decision,
    operation: &'a str,
    target: &'a str,
    /// Reports with a `N duplicate reports for` prefix stand for N occurrences.
    occurrences: u64,
    /// Reported use of a broad guiAccess grant rather than a denial.
    grant: bool,
}

fn parse_report(message: &str) -> Option<SandboxReport<'_>> {
    let (body, tag_line) = message.rsplit_once('\n')?;
    let grant = tag_line.ends_with(GRANT_TAG_SUFFIX);
    let start = body.find("Sandbox: ")?;
    let occurrences = match body[..start].trim() {
        "" => 1,
        prefix => prefix.split_whitespace().next()?.parse().ok()?,
    };
    let rest = &body[start + "Sandbox: ".len()..];
    let (head, decision, after) = [(") deny(", Decision::Deny), (") allow ", Decision::Allow)]
        .into_iter()
        .filter_map(|(needle, decision)| rest.find(needle).map(|at| (at, needle, decision)))
        .min_by_key(|(at, _, _)| *at)
        .map(|(at, needle, decision)| (&rest[..at], decision, &rest[at + needle.len()..]))?;
    let (process, pid) = head.rsplit_once('(')?;
    let after = match decision {
        Decision::Deny => after.split_once(") ")?.1,
        Decision::Allow => after,
    };
    let (operation, target) = after.split_once(' ').unwrap_or((after, ""));
    if operation.is_empty() {
        return None;
    }
    Some(SandboxReport {
        process,
        pid: pid.parse().ok()?,
        decision,
        operation,
        target,
        occurrences,
        grant,
    })
}

/// Maps a Seatbelt operation onto the shared denial model. Files keep their
/// path; other resources are prefixed with the operation name.
fn classify(operation: &str, target: &str) -> (ResourceType, AccessType, String) {
    let prefixed = || {
        if target.is_empty() {
            operation.to_string()
        } else {
            format!("{operation}:{target}")
        }
    };
    let access = if operation.contains("read") || operation == "file-test-existence" {
        AccessType::Read
    } else if operation.contains("write") || operation == "file-link" {
        AccessType::Write
    } else if operation == "file-map-executable" || operation.starts_with("process-exec") {
        AccessType::Execute
    } else {
        AccessType::Unknown
    };
    let is_path_op = operation.starts_with("file-") || operation.starts_with("process-exec");
    if let Some(path) = target_path(target).filter(|_| is_path_op) {
        return (ResourceType::File, access, path.to_string());
    }
    let resource_type = if operation.starts_with("network-") {
        ResourceType::Network
    } else if is_ui_resource(operation, target) {
        ResourceType::Ui
    } else {
        ResourceType::Other
    };
    (resource_type, access, prefixed())
}

/// The path a report names, either bare (`/p`) or as `path:/p ioctl-command:...`.
fn target_path(target: &str) -> Option<&str> {
    if target.starts_with('/') {
        return Some(target);
    }
    let rest = target
        .strip_prefix("path:")
        .filter(|r| r.starts_with('/'))?;
    Some(
        rest.split_once(" ioctl-command:")
            .map_or(rest, |(path, _)| path),
    )
}

fn is_ui_resource(operation: &str, target: &str) -> bool {
    match operation {
        "hid-control" => true,
        "mach-lookup" => {
            target.starts_with("com.apple.pasteboard.")
                || target.starts_with("com.apple.windowserver.")
                || target == "com.apple.coreservices.launchservicesd"
        }
        "iokit-open" | "iokit-open-user-client" => target.starts_with("IOHID"),
        _ => false,
    }
}

fn filetime_from_log_timestamp(timestamp: Option<&str>) -> u64 {
    timestamp
        .and_then(|value| chrono::DateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f%z").ok())
        .and_then(|time| {
            let secs = u64::try_from(time.timestamp() + FILETIME_UNIX_OFFSET_SECS).ok()?;
            Some(secs * 10_000_000 + u64::from(time.timestamp_subsec_nanos() / 100))
        })
        .unwrap_or(0)
}

fn bounded_property(value: &str) -> String {
    value.chars().take(MAX_PROPERTY_CHARS).collect()
}

fn report_signature(
    report: &SandboxReport<'_>,
    reason: CaptureVerboseLoggingOutcomeReason,
    classified: Option<(ResourceType, AccessType)>,
) -> CaptureVerboseLoggingSignature {
    let target = if report.target.contains('/') {
        REDACTED_PATH.to_string()
    } else {
        bounded_property(report.target)
    };
    let decision = match report.decision {
        Decision::Deny => "deny",
        Decision::Allow if report.grant => "allowGrant",
        Decision::Allow => "allowReport",
    };
    CaptureVerboseLoggingSignature {
        provider: CaptureVerboseLoggingProvider::Seatbelt,
        provider_guid: SEATBELT_PROVIDER_ID.to_string(),
        event_id: 0,
        event_name: Some(bounded_property(report.operation)),
        reason,
        pid: report.pid,
        access_type: classified.map(|(_, access)| access),
        resource_type: classified.map(|(resource, _)| resource),
        network_decision_reason: None,
        configuration_recommendation: None,
        network_endpoint: None,
        properties: vec![
            ("decision".to_string(), decision.to_string()),
            ("process".to_string(), bounded_property(report.process)),
            ("target".to_string(), target),
        ],
    }
}

fn record_occurrences(
    summary: &mut CaptureVerboseLoggingSummary,
    retained_bytes: &mut usize,
    signature: CaptureVerboseLoggingSignature,
    occurrences: u64,
) {
    let actionable = signature.reason.is_actionable();
    summary.record_with_byte_budget(
        signature.clone(),
        retained_bytes,
        MAX_VERBOSE_LOGGING_SIGNATURE_BYTES,
    );
    let extra = occurrences.saturating_sub(1);
    if extra == 0 {
        return;
    }
    summary.total_occurrences = summary.total_occurrences.saturating_add(extra);
    match summary
        .signatures
        .binary_search_by(|group| group.signature.cmp(&signature))
    {
        Ok(index) => {
            summary.signatures[index].count = summary.signatures[index].count.saturating_add(extra);
        }
        Err(_) => {
            summary.overflow_occurrences = summary.overflow_occurrences.saturating_add(extra);
            if actionable {
                summary.actionable_overflow_occurrences = summary
                    .actionable_overflow_occurrences
                    .saturating_add(extra);
            }
        }
    }
}

/// Builds the run's denials and verbose diagnostics from collected reports.
///
/// Reports tagged with the run tag are denials (block mode) or would-be
/// denials (allow mode). `:grant` reports show use of a broad guiAccess grant
/// and appear only in the verbose document.
pub(crate) fn analyze_events(
    events: &[SandboxLogEvent],
    events_truncated: bool,
) -> CaptureAnalysis {
    let mut denials = Vec::new();
    let mut seen = HashSet::new();
    // Missing events may hide denials, so the report must not claim completeness.
    let mut denied_resources_truncated = events_truncated;
    let mut summary = CaptureVerboseLoggingSummary {
        processed_events_truncated: events_truncated,
        ..Default::default()
    };
    let mut retained_bytes = 0usize;

    for event in events {
        let Some(report) = parse_report(&event.message) else {
            denied_resources_truncated = true;
            let signature = CaptureVerboseLoggingSignature {
                provider: CaptureVerboseLoggingProvider::Seatbelt,
                provider_guid: SEATBELT_PROVIDER_ID.to_string(),
                event_id: 0,
                event_name: None,
                reason: CaptureVerboseLoggingOutcomeReason::EventPayloadMalformed,
                pid: 0,
                access_type: None,
                resource_type: None,
                network_decision_reason: None,
                configuration_recommendation: None,
                network_endpoint: None,
                properties: Vec::new(),
            };
            record_occurrences(&mut summary, &mut retained_bytes, signature, 1);
            continue;
        };
        let noise = target_path(report.target).is_some_and(|path| NOISE_TARGETS.contains(&path));
        if report.grant || noise {
            let signature = report_signature(
                &report,
                CaptureVerboseLoggingOutcomeReason::NotActionable,
                None,
            );
            record_occurrences(
                &mut summary,
                &mut retained_bytes,
                signature,
                report.occurrences,
            );
            continue;
        }

        let (resource_type, access_type, resource) = classify(report.operation, report.target);
        let signature = report_signature(
            &report,
            CaptureVerboseLoggingOutcomeReason::Actionable,
            Some((resource_type, access_type)),
        );
        record_occurrences(
            &mut summary,
            &mut retained_bytes,
            signature,
            report.occurrences,
        );
        if seen.contains(&(resource.clone(), access_type)) {
            continue;
        }
        if denials.len() >= MAX_UNIQUE_DENIALS {
            denied_resources_truncated = true;
            summary.actionable_limit_reached = true;
            continue;
        }
        seen.insert((resource.clone(), access_type));
        denials.push(DeniedResource {
            resource,
            resource_type,
            access_type,
            pid: report.pid,
            filetime: filetime_from_log_timestamp(event.timestamp.as_deref()),
        });
    }

    CaptureAnalysis {
        denials,
        denied_resources_truncated,
        verbose_logging: VerboseLoggingSummary::default(),
        network_verbose_logging: summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TAG: &str = "mxc-capture-0011aa";

    fn line(message: &str) -> String {
        serde_json::json!({
            "eventMessage": message,
            "timestamp": "2026-01-02 03:04:05.123456-0700",
            "processID": 0,
        })
        .to_string()
    }

    #[test]
    fn classifies_stream_lines() {
        assert_eq!(
            parse_stream_line(r#"Filtering the log data using "sender == ...""#, TAG),
            StreamLine::Ignored
        );
        assert_eq!(
            parse_stream_line(
                &line(&format!(
                    "Sandbox: ls(1) deny(1) file-read-metadata /x\n{TAG}:ready"
                )),
                TAG
            ),
            StreamLine::Marker(CaptureMarker::Ready)
        );
        assert_eq!(
            parse_stream_line(
                &line(&format!(
                    "Sandbox: ls(1) deny(1) file-read-metadata /x\n{TAG}:done"
                )),
                TAG
            ),
            StreamLine::Marker(CaptureMarker::Done)
        );
        for message in [
            format!("Sandbox: cat(7) deny(1) file-read-data /etc/hosts\n{TAG}"),
            format!("Sandbox: app(7) allow mach-lookup com.apple.x\n{TAG}:grant"),
        ] {
            assert_eq!(
                parse_stream_line(&line(&message), TAG),
                StreamLine::Event(SandboxLogEvent {
                    message,
                    timestamp: Some("2026-01-02 03:04:05.123456-0700".to_string()),
                })
            );
        }
        // Another run's tag that shares this tag as a prefix, and untagged reports.
        for message in [
            format!("Sandbox: cat(7) deny(1) file-read-data /a\n{TAG}ff"),
            "Sandbox: cat(7) deny(1) file-read-data /a".to_string(),
            format!("Sandbox: cat(7) deny(1) file-read-data /a\n{TAG}:other"),
        ] {
            assert_eq!(parse_stream_line(&line(&message), TAG), StreamLine::Ignored);
        }
    }

    fn event(message: &str) -> SandboxLogEvent {
        SandboxLogEvent {
            message: format!("{message}\n{TAG}"),
            timestamp: Some("2026-01-02 03:04:05.123456-0700".to_string()),
        }
    }

    #[test]
    fn parses_report_variants() {
        let report = parse_report(
            "3 duplicate reports for Sandbox: My App (beta)(42) deny(1) mach-lookup com.apple.x\nT",
        )
        .unwrap();
        assert_eq!(
            report,
            SandboxReport {
                process: "My App (beta)",
                pid: 42,
                decision: Decision::Deny,
                operation: "mach-lookup",
                target: "com.apple.x",
                occurrences: 3,
                grant: false,
            }
        );
        let report =
            parse_report("Sandbox: app(7) allow iokit-open IOSurfaceRootUserClient\nT:grant")
                .unwrap();
        assert_eq!((report.decision, report.grant), (Decision::Allow, true));
        let report = parse_report("Sandbox: app(7) deny(1) system-info\nT").unwrap();
        assert_eq!((report.operation, report.target), ("system-info", ""));
        assert!(parse_report("Sandbox: app(x) deny(1) file-read-data /a\nT").is_none());
        assert!(parse_report("unrelated text\nT").is_none());
    }

    #[test]
    fn analysis_maps_reports_to_denials_and_verbose_signatures() {
        let mut grant = event("Sandbox: app(7) allow mach-lookup com.apple.nsurlsessiond");
        grant.message.push_str(GRANT_TAG_SUFFIX);
        let mut events = vec![
            event("Sandbox: cat(7) deny(1) file-read-data /Users/me/secret.txt"),
            event("2 duplicate reports for Sandbox: cat(7) deny(1) file-read-data /Users/me/secret.txt"),
            event("Sandbox: cat(7) deny(1) file-write-create /tmp/out"),
            event("Sandbox: app(7) allow mach-lookup com.apple.pasteboard.1"),
            event("Sandbox: app(7) deny(1) mach-lookup com.apple.windowserver.active"),
            event("Sandbox: app(7) deny(1) network-outbound remote:*:80"),
            event("Sandbox: app(7) deny(1) user-preference-read com.apple.Safari"),
            event(r#"Sandbox: app(7) deny(1) file-ioctl path:/dev/dtracehelper ioctl-command:(_IO "h" 4)"#),
            event(r#"Sandbox: app(7) deny(1) file-ioctl path:/dev/ttys001 ioctl-command:(_IO "t" 1)"#),
            grant,
        ];

        assert!(!analyze_events(&events, false).denied_resources_truncated);
        events.push(event("not a sandbox report"));
        let analysis = analyze_events(&events, false);
        assert!(analysis.denied_resources_truncated);

        let denials: Vec<_> = analysis
            .denials
            .iter()
            .map(|d| (d.resource.as_str(), d.resource_type, d.access_type))
            .collect();
        assert_eq!(
            denials,
            [
                ("/Users/me/secret.txt", ResourceType::File, AccessType::Read),
                ("/tmp/out", ResourceType::File, AccessType::Write),
                (
                    "mach-lookup:com.apple.pasteboard.1",
                    ResourceType::Ui,
                    AccessType::Unknown
                ),
                (
                    "mach-lookup:com.apple.windowserver.active",
                    ResourceType::Ui,
                    AccessType::Unknown
                ),
                (
                    "network-outbound:remote:*:80",
                    ResourceType::Network,
                    AccessType::Unknown
                ),
                (
                    "user-preference-read:com.apple.Safari",
                    ResourceType::Other,
                    AccessType::Read
                ),
                ("/dev/ttys001", ResourceType::File, AccessType::Unknown),
            ]
        );
        assert_eq!(analysis.denials[0].pid, 7);
        // 2026-01-02T10:04:05.123456Z as FILETIME.
        assert_eq!(analysis.denials[0].filetime, 134_118_218_451_234_560);

        let verbose = &analysis.network_verbose_logging;
        assert_eq!(verbose.total_occurrences, 12);
        let group = |reason, op: &str| {
            verbose.signatures.iter().find(|g| {
                g.signature.reason == reason && g.signature.event_name.as_deref() == Some(op)
            })
        };
        let file_read = group(
            CaptureVerboseLoggingOutcomeReason::Actionable,
            "file-read-data",
        )
        .unwrap();
        assert_eq!(file_read.count, 3);
        assert!(file_read
            .signature
            .properties
            .contains(&("target".to_string(), REDACTED_PATH.to_string())));
        let grant = group(
            CaptureVerboseLoggingOutcomeReason::NotActionable,
            "mach-lookup",
        )
        .unwrap();
        assert!(grant
            .signature
            .properties
            .contains(&("target".to_string(), "com.apple.nsurlsessiond".to_string())));
        assert!(group(
            CaptureVerboseLoggingOutcomeReason::NotActionable,
            "file-ioctl"
        )
        .is_some());
        assert!(verbose.signatures.iter().any(|g| {
            g.signature.reason == CaptureVerboseLoggingOutcomeReason::EventPayloadMalformed
        }));
    }

    #[test]
    fn analysis_bounds_unique_denials() {
        let events: Vec<_> = (0..=MAX_UNIQUE_DENIALS)
            .map(|i| event(&format!("Sandbox: a(1) deny(1) file-read-data /f{i}")))
            .collect();
        let analysis = analyze_events(&events, true);
        assert_eq!(analysis.denials.len(), MAX_UNIQUE_DENIALS);
        assert!(analysis.denied_resources_truncated);
        assert!(analysis.network_verbose_logging.actionable_limit_reached);
        assert!(analysis.network_verbose_logging.processed_events_truncated);
    }
}
