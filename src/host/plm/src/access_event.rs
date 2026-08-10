//! Port of the `LearningModeAccessEvent` PowerShell class from
//! `stop_plm_logging.ps1`. One file-access record from a PLM WPR trace.

use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
// `time_created`, `process_id` and `thread_id` are captured during parsing
// but only read by later pipeline stages (config generation / UI policy),
// so keep the allow to avoid a dead-code warning in builds that only
// consume `file_path` and `access_mask`.
#[allow(dead_code)]
pub struct LearningModeAccessEvent {
    pub time_created: DateTime<Utc>,
    pub process_id: u32,
    pub thread_id: u32,
    pub file_path: String,
    pub access_mask: u32,
}
