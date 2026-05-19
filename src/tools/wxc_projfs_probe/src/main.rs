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
mod virt;

use std::process::ExitCode;

use report::ProbeReport;

const PROFILE_NAME: &str = "mxc.projfs.spike";
const VIRT_ROOT_LEAF: &str = "projfs-probe";

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
    let virt_root = ac.folder_path.join(VIRT_ROOT_LEAF);
    report.set_ac_profile(ac);

    // Step 1c — set up virt root + PrjStartVirtualizing + launching-user smoke read.
    let session = match virt::start(&virt_root) {
        Ok((session, start_report)) => {
            eprintln!(
                "[step 1c] virt-start: ok — root={}, instance={}",
                start_report.root_path.display(),
                start_report.instance_id
            );
            report.set_virt_start(start_report);
            session
        }
        Err(e) => {
            eprintln!("[step 1c] virt-start: FAILED — {e}");
            report.set_virt_start_error(e);
            println!("{}", report.to_json());
            return ExitCode::from(4);
        }
    };

    let smoke = virt::smoke_read_as_launching_user(&session);
    eprintln!(
        "[step 1c] smoke-read: enumerated={:?}, hello={:?}, inner={:?}, errors={:?}",
        smoke.enumerated_names, smoke.read_hello_txt, smoke.read_inner_txt, smoke.errors
    );
    let smoke_ok = smoke.errors.is_empty()
        && smoke.read_hello_txt.is_some()
        && smoke.read_inner_txt.is_some();
    report.set_smoke_read(smoke);

    // Drop the session (PrjStopVirtualizing) before exiting.
    drop(session);

    println!("{}", report.to_json());
    if smoke_ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(5)
    }
}
