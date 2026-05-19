// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Folder-sharing helpers for `ShareFolderBatchAsync`. The batch call does
//! not fail as a whole on per-path errors; aggregation is where per-path
//! failures become a single MXC error.

use std::fmt::Write;

use isolation_session_bindings::bindings::{
    IsoSessionFolderSharingAccessLevel, IsoSessionFolderSharingRequest,
    IsoSessionFolderSharingResult, IsoSessionFolderSharingStatus,
};
use windows_collections::IVectorView;
use windows_core::HSTRING;

use super::error::{lifecycle_err, IsolationSessionError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ShareFolderFailure {
    pub message: String,
    pub remediation: String,
    pub hresult: u32,
}

/// Per-path outcome from a folder-share batch. The WinRT batch result type
/// can't be built in unit tests; this struct is the test-friendly
/// equivalent that aggregation logic operates on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ShareFolderOutcome {
    pub folder_path: String,
    /// `Some` iff the per-path status was `Failed`.
    pub failure: Option<ShareFolderFailure>,
}

/// Builds the per-path WinRT requests with rw paths first, ro paths second.
/// A path appearing in both slices ends up read-only (the ro request is
/// applied second and overwrites the earlier rw ACE for the same SID).
/// Callers should keep the slices disjoint to avoid relying on this.
pub(super) fn build_share_folder_requests(
    rw: &[String],
    ro: &[String],
) -> Vec<IsoSessionFolderSharingRequest> {
    let mut requests = Vec::with_capacity(rw.len() + ro.len());
    for path in rw {
        requests.push(IsoSessionFolderSharingRequest {
            FolderPath: HSTRING::from(path),
            AccessLevel: IsoSessionFolderSharingAccessLevel::ReadWrite,
        });
    }
    for path in ro {
        requests.push(IsoSessionFolderSharingRequest {
            FolderPath: HSTRING::from(path),
            AccessLevel: IsoSessionFolderSharingAccessLevel::Read,
        });
    }
    requests
}

/// Extracts MXC-internal per-path outcomes from the WinRT result vector.
pub(super) fn extract_share_folder_outcomes(
    results: &IVectorView<IsoSessionFolderSharingResult>,
) -> Result<Vec<ShareFolderOutcome>, IsolationSessionError> {
    let size = results
        .Size()
        .map_err(|e| lifecycle_err(format!("ShareFolderBatch results.Size: {}", e)))?;
    let mut outcomes = Vec::with_capacity(size as usize);
    for i in 0..size {
        let result = results
            .GetAt(i)
            .map_err(|e| lifecycle_err(format!("ShareFolderBatch results.GetAt({}): {}", i, e)))?;
        let folder_path = result
            .FolderPath()
            .map_err(|e| lifecycle_err(format!("ShareFolderBatch result.FolderPath: {}", e)))?
            .to_string();
        let status = result
            .Status()
            .map_err(|e| lifecycle_err(format!("ShareFolderBatch result.Status: {}", e)))?;
        let failure = if status == IsoSessionFolderSharingStatus::Failed {
            let err = result
                .Error()
                .map_err(|e| lifecycle_err(format!("ShareFolderBatch result.Error: {}", e)))?;
            Some(ShareFolderFailure {
                message: err.Message().map(|h| h.to_string()).unwrap_or_default(),
                remediation: err.Remediation().map(|h| h.to_string()).unwrap_or_default(),
                hresult: err.Code().map(|h| h.0 as u32).unwrap_or(0),
            })
        } else {
            None
        };
        outcomes.push(ShareFolderOutcome {
            folder_path,
            failure,
        });
    }
    Ok(outcomes)
}

/// Aggregates per-path outcomes into a single `Result`. Ok iff every path
/// succeeded; otherwise a `Lifecycle` error listing every failed path with
/// its message, HRESULT, and (when non-empty) remediation hint.
pub(super) fn aggregate_share_folder_outcomes(
    outcomes: &[ShareFolderOutcome],
) -> Result<(), IsolationSessionError> {
    let any_failure = outcomes.iter().any(|o| o.failure.is_some());
    if !any_failure {
        return Ok(());
    }
    let mut msg = String::from("ShareFolderBatchAsync had per-path failures:");
    for outcome in outcomes {
        let Some(f) = &outcome.failure else {
            continue;
        };
        let _ = write!(
            msg,
            "\n  {}: {} (HRESULT: {:#010x})",
            outcome.folder_path, f.message, f.hresult,
        );
        if !f.remediation.is_empty() {
            let _ = write!(msg, " -- remediation: {}", f.remediation);
        }
    }
    Err(IsolationSessionError::Lifecycle(msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The runtime path (`share_folders` itself) needs a live `IsoSessionOps`,
    // exercised on the VM. These unit tests cover the two pure helpers that
    // bracket the COM call: request-building and outcome aggregation.

    #[test]
    fn build_requests_empty_inputs_returns_empty_vec() {
        let requests = build_share_folder_requests(&[], &[]);
        assert!(requests.is_empty());
    }

    #[test]
    fn build_requests_rw_only() {
        let rw = vec!["C:\\rw1".to_string(), "C:\\rw2".to_string()];
        let requests = build_share_folder_requests(&rw, &[]);
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].FolderPath.to_string(), "C:\\rw1");
        assert_eq!(
            requests[0].AccessLevel,
            IsoSessionFolderSharingAccessLevel::ReadWrite
        );
        assert_eq!(requests[1].FolderPath.to_string(), "C:\\rw2");
        assert_eq!(
            requests[1].AccessLevel,
            IsoSessionFolderSharingAccessLevel::ReadWrite
        );
    }

    #[test]
    fn build_requests_ro_only() {
        let ro = vec!["C:\\ro1".to_string()];
        let requests = build_share_folder_requests(&[], &ro);
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].FolderPath.to_string(), "C:\\ro1");
        assert_eq!(
            requests[0].AccessLevel,
            IsoSessionFolderSharingAccessLevel::Read
        );
    }

    #[test]
    fn build_requests_rw_then_ro_in_input_order() {
        let rw = vec!["C:\\a".to_string()];
        let ro = vec!["C:\\b".to_string(), "C:\\c".to_string()];
        let requests = build_share_folder_requests(&rw, &ro);
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].FolderPath.to_string(), "C:\\a");
        assert_eq!(
            requests[0].AccessLevel,
            IsoSessionFolderSharingAccessLevel::ReadWrite
        );
        assert_eq!(requests[1].FolderPath.to_string(), "C:\\b");
        assert_eq!(
            requests[1].AccessLevel,
            IsoSessionFolderSharingAccessLevel::Read
        );
        assert_eq!(requests[2].FolderPath.to_string(), "C:\\c");
        assert_eq!(
            requests[2].AccessLevel,
            IsoSessionFolderSharingAccessLevel::Read
        );
    }

    fn ok_outcome(path: &str) -> ShareFolderOutcome {
        ShareFolderOutcome {
            folder_path: path.to_string(),
            failure: None,
        }
    }

    fn fail_outcome(path: &str, msg: &str, hr: u32, remediation: &str) -> ShareFolderOutcome {
        ShareFolderOutcome {
            folder_path: path.to_string(),
            failure: Some(ShareFolderFailure {
                message: msg.to_string(),
                remediation: remediation.to_string(),
                hresult: hr,
            }),
        }
    }

    #[test]
    fn aggregate_empty_outcomes_is_ok() {
        // Defensive: the runtime path returns Ok early on empty inputs, but
        // if `extract_share_folder_outcomes` ever returns an empty Vec the
        // aggregator should still report success.
        assert!(matches!(aggregate_share_folder_outcomes(&[]), Ok(())));
    }

    #[test]
    fn aggregate_all_succeeded_is_ok() {
        let outcomes = vec![ok_outcome("C:\\a"), ok_outcome("C:\\b")];
        assert!(matches!(aggregate_share_folder_outcomes(&outcomes), Ok(())));
    }

    #[test]
    fn aggregate_single_failure_includes_path_message_and_hresult() {
        let outcomes = vec![fail_outcome("C:\\bad", "denied", 0x80070005, "")];
        let err = aggregate_share_folder_outcomes(&outcomes).unwrap_err();
        let IsolationSessionError::Lifecycle(msg) = err else {
            panic!("expected Lifecycle, got {:?}", err);
        };
        assert!(msg.contains("C:\\bad"), "missing path in: {}", msg);
        assert!(msg.contains("denied"), "missing message in: {}", msg);
        assert!(msg.contains("0x80070005"), "missing hresult in: {}", msg);
    }

    #[test]
    fn aggregate_mixed_outcomes_includes_all_failures_only() {
        let outcomes = vec![
            ok_outcome("C:\\good"),
            fail_outcome("C:\\bad1", "first failure", 0xdeadbeef, ""),
            ok_outcome("C:\\good2"),
            fail_outcome("C:\\bad2", "second failure", 0xfeedface, ""),
        ];
        let err = aggregate_share_folder_outcomes(&outcomes).unwrap_err();
        let IsolationSessionError::Lifecycle(msg) = err else {
            panic!("expected Lifecycle, got {:?}", err);
        };
        assert!(msg.contains("C:\\bad1"), "missing bad1 in: {}", msg);
        assert!(
            msg.contains("first failure"),
            "missing first msg in: {}",
            msg
        );
        assert!(msg.contains("C:\\bad2"), "missing bad2 in: {}", msg);
        assert!(
            msg.contains("second failure"),
            "missing second msg in: {}",
            msg
        );
        // Successful paths must not appear in the error message.
        assert!(
            !msg.contains("C:\\good"),
            "good path leaked into error: {}",
            msg
        );
        assert!(
            !msg.contains("C:\\good2"),
            "good2 path leaked into error: {}",
            msg
        );
    }

    #[test]
    fn aggregate_failure_with_remediation_appends_remediation() {
        let outcomes = vec![fail_outcome("C:\\rd", "denied", 0x80070005, "run as admin")];
        let err = aggregate_share_folder_outcomes(&outcomes).unwrap_err();
        let IsolationSessionError::Lifecycle(msg) = err else {
            panic!("expected Lifecycle, got {:?}", err);
        };
        assert!(
            msg.contains("remediation: run as admin"),
            "missing remediation in: {}",
            msg
        );
    }

    #[test]
    fn aggregate_failure_with_empty_remediation_omits_suffix() {
        let outcomes = vec![fail_outcome("C:\\nor", "msg", 0x80004005, "")];
        let err = aggregate_share_folder_outcomes(&outcomes).unwrap_err();
        let IsolationSessionError::Lifecycle(msg) = err else {
            panic!("expected Lifecycle, got {:?}", err);
        };
        assert!(
            !msg.contains("remediation:"),
            "unexpected remediation suffix in: {}",
            msg
        );
    }
}
