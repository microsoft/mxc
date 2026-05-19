// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! JSON report shape for the spike.
//!
//! Whatever steps run, we always emit a single JSON document on stdout so
//! the harness wrapper can record results across hosts without scraping
//! stderr.

use serde::Serialize;

use crate::ac_profile::AcProfile;
use crate::feature_detect::FeatureDetect;

#[derive(Debug, Default, Serialize)]
pub(crate) struct ProbeReport {
    pub schema: &'static str,
    pub feature_detect: Option<FeatureDetect>,
    pub ac_profile: Option<AcProfile>,
    pub ac_profile_error: Option<String>,
}

impl ProbeReport {
    pub fn new() -> Self {
        Self {
            schema: "projfs-probe/0.1",
            ..Default::default()
        }
    }

    pub fn set_feature_detect(&mut self, f: FeatureDetect) {
        self.feature_detect = Some(f);
    }

    pub fn set_ac_profile(&mut self, p: AcProfile) {
        self.ac_profile = Some(p);
    }

    pub fn set_ac_profile_error(&mut self, e: String) {
        self.ac_profile_error = Some(e);
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    }
}
