//! Port of the `LearningModeAccessEvent` PowerShell class from
//! `stop_plm_logging.ps1`. One file-access record extracted from a
//! permissive learning-mode WPR trace.

use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
#[allow(dead_code)] // Several fields are populated for parity with the
                    // PowerShell version even though the orchestrator only
                    // currently uses file_path and access_mask.
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
