// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ProjFS-T3 spike probe.
//!
//! See:
//!   docs/proposals/downlevel_support/projfs-t3-spike-step1.md
//!   ~/.copilot/session-state/<id>/plan.md
//!
//! Step 1 (no policy flags):
//!   Defaults to the original synthetic layout for backward-compat with the
//!   step-1 findings — `hello.txt` + `subdir/inner.txt`. This path is
//!   removed in step 2 once the matrix harness is in.
//!
//! Step 2 (with `--rw` / `--ro` flags):
//!   Projects real host directories through the virt root. Optionally
//!   forwards `--check-dir` names to the AC child so it runs the
//!   Test-PathEnumeration matrix probes per branch + per absent branch.
//!
//! CLI:
//!   wxc-projfs-probe
//!     [--rw <host-path>] (repeatable)     project as a RW branch
//!     [--ro <host-path>] (repeatable)     project as a RO branch
//!     [--check-dir <name>] (repeatable)   AC-side probe target
//!     [--no-ac]                           skip step 1d (handy when debugging)
//!     [--keep-root]                       skip virt-root cleanup at exit
//!
//! Without any `--rw`/`--ro` flags, the probe falls back to step-1 mode:
//! a single synthetic branch with hello.txt + subdir/inner.txt, materialized
//! into a temp host directory under `%TEMP%`.

#![cfg(target_os = "windows")]

mod ac_launch;
mod ac_profile;
mod feature_detect;
mod report;
mod virt;

use std::path::PathBuf;
use std::process::ExitCode;

use report::ProbeReport;

const PROFILE_NAME: &str = "mxc.projfs.spike";
const VIRT_ROOT_LEAF_PREFIX: &str = "projfs-probe";
const CHILD_EXE_NAME: &str = "wxc-projfs-probe-child.exe";

struct CliArgs {
    rw: Vec<PathBuf>,
    ro: Vec<PathBuf>,
    check_dirs: Vec<String>,
    write_probes: Vec<String>,
    no_ac: bool,
    keep_root: bool,
}

fn parse_args() -> CliArgs {
    let mut rw = Vec::new();
    let mut ro = Vec::new();
    let mut check_dirs = Vec::new();
    let mut write_probes = Vec::new();
    let mut no_ac = false;
    let mut keep_root = false;

    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--rw" if i + 1 < args.len() => {
                rw.push(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--ro" if i + 1 < args.len() => {
                ro.push(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--check-dir" if i + 1 < args.len() => {
                check_dirs.push(args[i + 1].clone());
                i += 2;
            }
            "--write-probe" if i + 1 < args.len() => {
                write_probes.push(args[i + 1].clone());
                i += 2;
            }
            "--no-ac" => {
                no_ac = true;
                i += 1;
            }
            "--keep-root" => {
                keep_root = true;
                i += 1;
            }
            other => {
                eprintln!("warning: unrecognized argument: {other}");
                i += 1;
            }
        }
    }

    CliArgs {
        rw,
        ro,
        check_dirs,
        write_probes,
        no_ac,
        keep_root,
    }
}

fn main() -> ExitCode {
    let args = parse_args();
    let mut report = ProbeReport::new();

    // Step 1a — Client-ProjFS feature detect.
    let feature = feature_detect::detect();
    report.set_feature_detect(feature.clone());
    eprintln!("[step 1a] feature-detect: {}", feature.summary());
    if !feature.is_usable() {
        println!("{}", report.to_json());
        return ExitCode::from(2);
    }

    // Step 1b — AppContainer profile.
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
    let ac_sid_string = ac.sid_string.clone();
    let ac_folder = ac.folder_path.clone();
    report.set_ac_profile(ac);

    // Build the policy. If no flags given, fall back to a synthetic
    // step-1-style scratch.
    let policy_result = if args.rw.is_empty() && args.ro.is_empty() {
        synth_default_policy(&ac_folder)
    } else {
        virt::Policy::from_flags(&args.rw, &args.ro).map(|p| (p, None))
    };
    let (policy, _scratch_keeper) = match policy_result {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[step 2] policy: FAILED — {e}");
            report.set_virt_start_error(format!("policy: {e}"));
            println!("{}", report.to_json());
            return ExitCode::from(7);
        }
    };
    eprintln!(
        "[policy] {} branches: {:?}",
        policy.branches.len(),
        policy
            .branches
            .iter()
            .map(|b| format!("{}={}", b.name, b.host_root.display()))
            .collect::<Vec<_>>()
    );

    // Build the virt-root path inside the AC's profile.
    let virt_root = ac_folder.join(format!(
        "{VIRT_ROOT_LEAF_PREFIX}-{:08x}",
        std::process::id()
            ^ (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0))
    ));

    // Step 1c — PrjStartVirtualizing + launching-user smoke read.
    let session = match virt::start(&virt_root, policy) {
        Ok((s, r)) => {
            eprintln!(
                "[step 1c] virt-start: ok — root={}, instance={}",
                r.root_path.display(),
                r.instance_id
            );
            report.set_virt_start(r);
            s
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
        "[step 1c] smoke-read: branches={:?}, errors={:?}",
        smoke.enumerated_branches, smoke.errors
    );
    report.set_smoke_read(smoke);

    // Step 1d — AC child.
    if args.no_ac {
        eprintln!("[step 1d] ac-child: skipped (--no-ac)");
    } else {
        let child_exe = match std::env::current_exe() {
            Ok(p) => p
                .parent()
                .map(|d| d.join(CHILD_EXE_NAME))
                .unwrap_or_else(|| PathBuf::from(CHILD_EXE_NAME)),
            Err(e) => {
                report.set_ac_child_error(format!("current_exe: {e}"));
                drop(session);
                println!("{}", report.to_json());
                return ExitCode::from(6);
            }
        };
        if !child_exe.exists() {
            report.set_ac_child_error(format!(
                "child binary not found at {}",
                child_exe.display()
            ));
            drop(session);
            println!("{}", report.to_json());
            return ExitCode::from(6);
        }

        match ac_launch::run_child_in_appcontainer(
            &child_exe,
            &virt_root,
            &ac_sid_string,
            &args.check_dirs,
            &args.write_probes,
        ) {
            Ok(child_report) => {
                eprintln!(
                    "[step 1d] ac-child: exit={:?} wait={} errors={:?}",
                    child_report.exit_code, child_report.wait_status, child_report.errors
                );
                report.set_ac_child(child_report);
            }
            Err(e) => {
                eprintln!("[step 1d] ac-child: FAILED — {e}");
                report.set_ac_child_error(e);
            }
        }
    }

    // Drop the session before optionally leaving the root in place for
    // post-mortem inspection.
    drop(session);
    if !args.keep_root {
        let _ = std::fs::remove_dir_all(&virt_root);
    }

    println!("{}", report.to_json());
    ExitCode::SUCCESS
}

/// Default policy when no `--rw`/`--ro` flags are supplied: materialise the
/// step-1 synthetic content into a temp host dir and project it.
fn synth_default_policy(
    ac_folder: &std::path::Path,
) -> Result<(virt::Policy, Option<SynthKeeper>), String> {
    let scratch = ac_folder.join("synth-default");
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch)
        .map_err(|e| format!("create_dir_all({}): {e}", scratch.display()))?;
    let hello = scratch.join("hello.txt");
    std::fs::write(&hello, "hello from projfs\n").map_err(|e| format!("write hello.txt: {e}"))?;
    let subdir = scratch.join("subdir");
    std::fs::create_dir_all(&subdir).map_err(|e| format!("create_dir_all subdir: {e}"))?;
    std::fs::write(subdir.join("inner.txt"), "inner content\n")
        .map_err(|e| format!("write inner.txt: {e}"))?;

    let policy = virt::Policy::from_flags(&[scratch.clone()], &[])?;
    Ok((policy, Some(SynthKeeper { _path: scratch })))
}

/// Drop guard for the synthetic scratch directory — only relevant in the
/// no-flag fallback path. Currently unused (we leave the dir for inspection)
/// but kept as a structural marker.
struct SynthKeeper {
    _path: PathBuf,
}
