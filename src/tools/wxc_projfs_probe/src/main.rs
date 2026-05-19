// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ProjFS-T3 spike probe (Step 1).
//!
//! Answers — non-admin, no install side effects — the binary "does the
//! architecture work?" question:
//!
//! 1. Is `Client-ProjFS` enabled on this host?
//! 2. Can we create an AppContainer profile in our own user hive?
//! 3. Can we mark a directory inside that profile's `LocalCache` as a
//!    placeholder and start virtualizing it?
//! 4. Can an AppContainer process spawned with that profile's SID read +
//!    enumerate the virtualized root?
//!
//! Steps 1-2 ship in this initial commit. Steps 3-4 land in follow-up
//! commits on the spike branch.
//!
//! Output is JSON on stdout so the harness can be diffed across machines.
//! Human-readable per-step lines go to stderr.

#![cfg(target_os = "windows")]

mod ac_profile;
mod feature_detect;
mod report;

use std::process::ExitCode;

use report::ProbeReport;

const PROFILE_NAME: &str = "mxc.projfs.spike";

fn main() -> ExitCode {
    let mut report = ProbeReport::new();

    // Step 1a — Client-ProjFS feature detect.
    let feature = feature_detect::detect();
    report.set_feature_detect(feature.clone());
    eprintln!("[step 1a] feature-detect: {}", feature.summary());

    // If the optional feature is not enabled the rest of the probe is
    // meaningless; report cleanly and exit non-zero so CI / harness wrappers
    // can tell the difference between "answered no" and "crashed".
    if !feature.is_usable() {
        println!("{}", report.to_json());
        return ExitCode::from(2);
    }

    // Step 1b — create / derive a test AppContainer profile.
    let ac = match ac_profile::ensure_profile(PROFILE_NAME) {
        Ok(ac) => ac,
        Err(e) => {
            report.set_ac_profile_error(e.to_string());
            eprintln!("[step 1b] ac-profile: FAILED — {e}");
            println!("{}", report.to_json());
            return ExitCode::from(3);
        }
    };
    eprintln!(
        "[step 1b] ac-profile: ok — sid={}, folder={}",
        ac.sid_string,
        ac.folder_path.display()
    );
    report.set_ac_profile(ac);

    // Step 1c/1d land next commit. Emit interim report so the spike can be
    // staged.
    println!("{}", report.to_json());
    ExitCode::SUCCESS
}
