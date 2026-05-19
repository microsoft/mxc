// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! JSON report shape for the spike.
//!
//! Whatever steps run, we always emit a single JSON document on stdout so
//! the harness wrapper can record results across hosts without scraping
//! stderr.

use serde::Serialize;

use crate::ac_launch::AcChildReport;
use crate::ac_profile::AcProfile;
use crate::feature_detect::FeatureDetect;
use crate::virt::{SmokeReadReport, VirtStartReport};

#[derive(Debug, Default, Serialize)]
pub(crate) struct ProbeReport {
    pub schema: &'static str,
    pub feature_detect: Option<FeatureDetect>,
    pub ac_profile: Option<AcProfile>,
    pub ac_profile_error: Option<String>,
    pub virt_start: Option<VirtStartReport>,
    pub virt_start_error: Option<String>,
    pub smoke_read: Option<SmokeReadReport>,
    pub ac_child: Option<AcChildReport>,
    pub ac_child_error: Option<String>,
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

    pub fn set_virt_start(&mut self, v: VirtStartReport) {
        self.virt_start = Some(v);
    }

    pub fn set_virt_start_error(&mut self, e: String) {
        self.virt_start_error = Some(e);
    }

    pub fn set_smoke_read(&mut self, s: SmokeReadReport) {
        self.smoke_read = Some(s);
    }

    pub fn set_ac_child(&mut self, c: AcChildReport) {
        self.ac_child = Some(c);
    }

    pub fn set_ac_child_error(&mut self, e: String) {
        self.ac_child_error = Some(e);
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    }
}
