//! Port of the `LearningModeAccessEvent` PowerShell class from
//! `stop_plm_logging.ps1`. One file-access record from a PLM WPR trace.

use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
// Fields kept for parity with the PowerShell version even though the
// orchestrator currently only uses file_path and access_mask.
#[allow(dead_code)]
pub struct LearningModeAccessEvent {
    pub time_created: DateTime<Utc>,
    pub process_id: u32,
    pub thread_id: u32,
    pub learning_mode: String, // Permissive/Enforcing
    pub resource_type: String, // File/Directory
    pub file_path: String,
    pub app_path: String,
    pub access_mask: u32,
}
