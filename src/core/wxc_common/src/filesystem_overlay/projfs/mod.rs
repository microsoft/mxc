// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ProjFS primitive: apply / restore for the `ProjFsBranch` variants of
//! an [`OverlayPrimitive`].
//!
//! Unlike BindFlt — where each mapping is independent — ProjFS opens
//! a single virt session whose callback set serves *every* projected
//! branch. So this module's apply entry point takes the **whole set
//! of ProjFS branches** at once and returns one [`ProjFsApplied`].
//!
//! Promoted from `wxc_projfs_probe::virt` in Phase A.2. See [`virt`]
//! for the callback implementation; see
//! `docs/proposals/downlevel_support/projfs-t3-spike-step{1,2,3}.md`
//! for the empirical backing.

pub mod virt;

use std::path::PathBuf;

use crate::filesystem_overlay::error::OverlayError;
use crate::filesystem_overlay::plan::OverlayPrimitive;

/// Bookkeeping for the one active ProjFS projection, owned by
/// [`crate::filesystem_overlay::OverlayManager`] for the lifetime of
/// the contained process.
#[derive(Debug)]
pub struct ProjFsApplied {
    /// The branch primitives this projection serves, in apply order.
    pub branches: Vec<OverlayPrimitive>,
    /// The projection root that the AC's cwd should land inside.
    pub projection_root: PathBuf,
    /// The live virt session. Dropping this calls `PrjStopVirtualizing`.
    /// Held in an `Option` so [`restore`] can take ownership and drop
    /// it explicitly while leaving `ProjFsApplied` in a consistent
    /// state for diagnostics.
    pub session: Option<virt::VirtSession>,
}

/// Start the ProjFS virt session backing the projection. `branches`
/// must contain only [`OverlayPrimitive::ProjFsBranch`] entries (the
/// caller is expected to pre-filter); any other variant is ignored.
///
/// `projection_root` is the directory the AC will see as its cwd
/// after `apply`. The caller is responsible for picking a location
/// the AC has traverse access to — typically inside the AC profile's
/// `AC\` subdir under `%LOCALAPPDATA%\Packages\<profile>\`.
pub fn apply_branches(
    branches: &[OverlayPrimitive],
    ac_sid: &str,
    projection_root: PathBuf,
) -> Result<ProjFsApplied, OverlayError> {
    let branch_set = virt::ProjFsBranchSet::from_primitives(branches, ac_sid)?;
    if branch_set.branches.is_empty() {
        // No-op: a plan with no ProjFs branches yields no projection.
        return Ok(ProjFsApplied {
            branches: branches.to_vec(),
            projection_root,
            session: None,
        });
    }
    let session = virt::start(&projection_root, branch_set)?;
    Ok(ProjFsApplied {
        branches: branches.to_vec(),
        projection_root,
        session: Some(session),
    })
}

/// Stop the projection and clean up the projection root directory.
/// Idempotent — calling `restore` twice on the same applied state is
/// a no-op the second time. Errors removing the projection-root
/// directory are returned but **not** considered fatal by
/// [`crate::filesystem_overlay::OverlayManager::restore`], which
/// collects them into its warnings list.
///
/// # Why the retry loop
///
/// After `PrjStopVirtualizing`, the kernel may still be tearing down
/// the virt instance asynchronously. A `remove_dir_all` issued
/// immediately can race the tear-down and surface error 369
/// (`STATUS_VIRTUALIZATION_TEMPORARILY_UNAVAILABLE`). A few short
/// retries close the window in practice; we cap at ~1 second total.
pub fn restore(applied: &mut ProjFsApplied) -> Result<(), OverlayError> {
    // Dropping the VirtSession calls PrjStopVirtualizing and clears
    // the per-process branch state.
    let _ = applied.session.take();

    if !applied.projection_root.exists() {
        return Ok(());
    }

    // Retry: try, then sleep+retry on 369. Total budget ~1 s.
    const RETRIES: u32 = 10;
    const DELAY_MS: u64 = 100;
    let mut last_err: Option<std::io::Error> = None;
    for attempt in 0..RETRIES {
        match std::fs::remove_dir_all(&applied.projection_root) {
            Ok(()) => return Ok(()),
            Err(e) => {
                // 369 = STATUS_VIRTUALIZATION_TEMPORARILY_UNAVAILABLE
                // surfaced as an io::Error from the Win32 layer.
                let is_temp_unavailable = e.raw_os_error() == Some(369);
                last_err = Some(e);
                if !is_temp_unavailable {
                    break;
                }
                if attempt + 1 < RETRIES {
                    std::thread::sleep(std::time::Duration::from_millis(DELAY_MS));
                }
            }
        }
    }
    let e = last_err.expect("loop body always sets last_err on Err path");
    Err(OverlayError::ProjFs(format!(
        "remove projection root {}: {e}",
        applied.projection_root.display()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem_overlay::plan::BranchMode;

    #[test]
    fn apply_with_no_projfs_primitives_is_a_noop() {
        let temp = std::env::temp_dir().join(format!(
            "mxc-overlay-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_micros())
                .unwrap_or(0)
        ));
        let only_bindflt = [OverlayPrimitive::BindFltTombstone {
            path: PathBuf::from(r"C:\not-projfs"),
        }];
        let applied =
            apply_branches(&only_bindflt, "S-1-15-2-test", temp.clone()).expect("noop applies");
        assert!(
            applied.session.is_none(),
            "no session when no projfs branches"
        );
        assert_eq!(applied.projection_root, temp);
        // The projection root was never created since there's no session.
        assert!(!temp.exists());
    }

    #[test]
    fn apply_rejects_ambiguous_branch_names() {
        let prims = vec![
            OverlayPrimitive::ProjFsBranch {
                host_path: PathBuf::from(r"D:\a"),
                branch_name: "x".into(),
                mode: BranchMode::ReadOnly,
                deny_subpaths: Vec::new(),
            },
            OverlayPrimitive::ProjFsBranch {
                host_path: PathBuf::from(r"D:\b"),
                branch_name: "X".into(),
                mode: BranchMode::ReadWrite,
                deny_subpaths: Vec::new(),
            },
        ];
        let err = apply_branches(
            &prims,
            "S-1-15-2-test",
            std::env::temp_dir().join("mxc-overlay-amb"),
        )
        .expect_err("ambiguous branch names should be rejected");
        match err {
            OverlayError::Classify(s) => assert!(s.contains("ambiguous"), "got {s}"),
            other => panic!("expected Classify, got {other:?}"),
        }
    }

    #[test]
    fn restore_is_idempotent_on_session_less_state() {
        let mut applied = ProjFsApplied {
            branches: Vec::new(),
            projection_root: std::env::temp_dir().join("mxc-nonexistent-projfs-root"),
            session: None,
        };
        restore(&mut applied).expect("first restore is a no-op");
        restore(&mut applied).expect("second restore is a no-op");
    }

    /// End-to-end smoke: apply a rw + ro branch projection backed by
    /// real host directories, enumerate through the projection as the
    /// launching user, and restore cleanly.
    ///
    /// Gated by `#[ignore]` because it requires the `Client-ProjFS`
    /// optional feature; run explicitly with
    /// `cargo test -p wxc_common --lib -- --ignored end_to_end_smoke`.
    /// This is the Phase A.2 promotion sanity check that the spike's
    /// matrix passes when driven from the new `filesystem_overlay`
    /// surface instead of `wxc_projfs_probe::virt` directly.
    #[test]
    #[ignore = "requires Client-ProjFS optional feature; run with --ignored"]
    fn end_to_end_smoke_projection_apply_read_restore() {
        let run_id = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_micros())
                .unwrap_or(0)
        );
        let host_scratch = std::env::temp_dir().join(format!("mxc-overlay-host-{run_id}"));
        let rw_host = host_scratch.join("rw");
        let ro_host = host_scratch.join("ro");
        std::fs::create_dir_all(rw_host.join("subdir")).expect("create rw scratch");
        std::fs::create_dir_all(ro_host.join("subdir")).expect("create ro scratch");
        // Create a "secret" subdir + file inside the RO branch that
        // we'll add to `deny_subpaths` — the AC must NOT see it
        // through enumeration or path stat.
        let secret_dir = ro_host.join("secret");
        std::fs::create_dir_all(&secret_dir).expect("create secret dir");
        std::fs::write(secret_dir.join("token.txt"), b"hidden-token").expect("secret file");
        std::fs::write(rw_host.join("readme.txt"), b"rw content").expect("rw readme");
        std::fs::write(ro_host.join("readme.txt"), b"ro content").expect("ro readme");

        let projection_root = std::env::temp_dir().join(format!("mxc-overlay-proj-{run_id}"));

        let primitives = vec![
            OverlayPrimitive::ProjFsBranch {
                host_path: rw_host.clone(),
                branch_name: "rw".into(),
                mode: BranchMode::ReadWrite,
                deny_subpaths: Vec::new(),
            },
            OverlayPrimitive::ProjFsBranch {
                host_path: ro_host.clone(),
                branch_name: "ro".into(),
                mode: BranchMode::ReadOnly,
                // The secret dir must not appear inside the RO
                // projection. Phase C's classifier produces a
                // canonical path here; the e2e test bypasses
                // classify and constructs the primitive directly,
                // so we pass the canonicalised secret path.
                deny_subpaths: vec![
                    std::fs::canonicalize(&secret_dir).expect("canonicalize secret")
                ],
            },
        ];

        // Use the well-known Everyone SID for the placeholder DACL —
        // this test runs as the launching user, not an AC, so an AC
        // SID grant wouldn't gate anything. The point of the test is
        // that the apply→restore cycle completes cleanly and the
        // projection serves real host content.
        let mut applied = apply_branches(&primitives, "S-1-1-0", projection_root.clone())
            .expect("apply_branches");
        assert!(applied.session.is_some(), "session must be live");

        // Enumerate the projection root: should list "rw" and "ro".
        let root_entries: Vec<String> = std::fs::read_dir(&projection_root)
            .expect("read projection root")
            .filter_map(|e| e.ok())
            .map(|d| d.file_name().to_string_lossy().into_owned())
            .collect();
        let mut root_entries_sorted = root_entries.clone();
        root_entries_sorted.sort();
        assert_eq!(
            root_entries_sorted,
            vec!["ro".to_string(), "rw".to_string()],
            "projection root should enumerate both branches; got {root_entries:?}"
        );

        // Enumerate inside rw: should see readme.txt + subdir.
        let rw_entries: Vec<String> = std::fs::read_dir(projection_root.join("rw"))
            .expect("read rw branch")
            .filter_map(|e| e.ok())
            .map(|d| d.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            rw_entries.iter().any(|n| n == "readme.txt"),
            "rw branch missing readme.txt; got {rw_entries:?}"
        );
        assert!(
            rw_entries.iter().any(|n| n == "subdir"),
            "rw branch missing subdir; got {rw_entries:?}"
        );

        // ----- Phase C structural-deny verification -----
        //
        // Enumerate inside the RO branch: the `secret` subdir was
        // added to deny_subpaths so it must NOT appear. The other
        // entries should be visible normally.
        let ro_entries: Vec<String> = std::fs::read_dir(projection_root.join("ro"))
            .expect("read ro branch")
            .filter_map(|e| e.ok())
            .map(|d| d.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            !ro_entries.iter().any(|n| n == "secret"),
            "ro branch should NOT enumerate the denied 'secret' subdir; got {ro_entries:?}"
        );
        assert!(
            ro_entries.iter().any(|n| n == "readme.txt"),
            "ro branch should still enumerate non-denied entries; got {ro_entries:?}"
        );
        // Direct stat-by-name on the denied path must return
        // not-found (Win32 ERROR_FILE_NOT_FOUND surfaces as
        // io::ErrorKind::NotFound).
        let secret_stat = std::fs::metadata(projection_root.join("ro").join("secret"));
        assert!(
            secret_stat.is_err(),
            "stat on denied 'secret' should fail; got {secret_stat:?}"
        );

        // Read content through the projection — drives cb_get_file_data.
        let read = std::fs::read(projection_root.join("rw").join("readme.txt"))
            .expect("read through projection");
        assert_eq!(read, b"rw content");

        // ----- A.5 writeback verification -----
        //
        // Modify a file in the RW branch through the projection,
        // then verify the host backing reflects the change. This
        // exercises the PRJ_NOTIFY_FILE_HANDLE_CLOSED_FILE_MODIFIED
        // path that lands the projection's content back on the host.
        //
        // NOTE: ProjFS suppresses notification callbacks for writes
        // originating from the provider's own process. The test
        // process IS the provider (it owns the virt session), so we
        // can't write directly with `std::fs::write` and expect the
        // callback to fire. Instead we spawn `cmd.exe /c >` as a
        // child process, which writes from a separate process and
        // does cause the kernel to fire the notification.
        let modified = "rw content modified by the projection writeback test";
        let target = projection_root.join("rw").join("readme.txt");
        // Use PowerShell rather than cmd.exe — cmd's redirection
        // parser is allergic to colons and backslashes in unquoted
        // arguments. PowerShell's `Set-Content` works cleanly on
        // arbitrary Win32 paths.
        let ps_script = format!(
            "[System.IO.File]::WriteAllText('{}', '{}')",
            target.display(),
            modified
        );
        let status = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-Command", &ps_script])
            .status()
            .expect("spawn powershell writer");
        assert!(status.success(), "child writer should succeed");
        // The post-event notification fires asynchronously on a
        // worker thread after the close. Give it up to ~2s to land
        // before asserting — exits the wait early on the first read
        // that sees the new content.
        let mut host_content = String::new();
        for _ in 0..40 {
            if let Ok(c) = std::fs::read_to_string(rw_host.join("readme.txt")) {
                host_content = c;
                if host_content == modified {
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert_eq!(
            host_content, modified,
            "host backing should reflect writeback within timeout"
        );

        // Verify the RO branch was NOT writable — overwriting
        // readme.txt should fail or the host content must remain
        // unchanged.
        let ro_target = projection_root.join("ro").join("readme.txt");
        let ro_ps_script = format!(
            "try {{ [System.IO.File]::WriteAllText('{}', 'should fail') }} catch {{ }}",
            ro_target.display()
        );
        let _ = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-Command", &ro_ps_script])
            .status();
        let ro_host_content =
            std::fs::read(ro_host.join("readme.txt")).expect("read ro host backing");
        assert_eq!(
            ro_host_content, b"ro content",
            "RO host backing must not be modified by ro write attempt"
        );

        // Restore the projection. Drops the VirtSession (→
        // PrjStopVirtualizing) and removes the projection root.
        restore(&mut applied).expect("restore");
        assert!(
            !projection_root.exists(),
            "projection root should be gone after restore"
        );
        // Host scratch left intact (we never modified it).
        assert!(rw_host.join("readme.txt").exists());

        // Clean up host scratch.
        let _ = std::fs::remove_dir_all(&host_scratch);
    }
}
