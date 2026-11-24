// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::bwrap_common::bwrap_command;
use crate::mxc_common::models::{ContainerPolicy, ExecutionRequest};

fn prepare(
    mounts: &mut Vec<PolicyMount>,
    baseline_links: &[BaselineLink],
    version: BwrapVersion,
) -> Result<DenyPreparation, FilesystemPolicyError> {
    super::prepare(mounts, baseline_links, &Default::default(), version, false)
}

fn prepare_with_files(
    mounts: &mut Vec<PolicyMount>,
    baseline_links: &[BaselineLink],
    files: &[&str],
    version: BwrapVersion,
) -> Result<DenyPreparation, FilesystemPolicyError> {
    let files: std::collections::HashSet<String> =
        files.iter().map(|path| (*path).to_string()).collect();
    super::prepare(mounts, baseline_links, &files, version, false)
}

fn mount(path: &Path, intent: FsIntent) -> PolicyMount {
    let path = path.to_str().unwrap().to_owned();
    PolicyMount {
        source: path.clone(),
        destination: path,
        intent,
        readonly_overlay: None,
    }
}

#[test]
fn missing_denials_use_private_layers_without_modifying_the_host() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    std::fs::write(root.join("visible"), "control").unwrap();
    std::fs::create_dir(root.join("tools")).unwrap();
    let mut mounts = vec![
        mount(root, FsIntent::ReadOnly),
        mount(&root.join(".env.local"), FsIntent::Denied),
        mount(&root.join("tools"), FsIntent::ReadWrite),
        mount(&root.join("nested/secret"), FsIntent::Denied),
    ];
    let preparation = prepare(&mut mounts, &[], BwrapVersion::new(0, 11, 0)).unwrap();
    let overlay = mounts[0].readonly_overlay.as_ref().unwrap();
    assert!(Path::new(overlay).join(".env.local").is_dir());
    assert!(Path::new(overlay).join("nested/secret").is_dir());
    assert!(!Path::new(overlay).join("visible").exists());
    assert!(!root.join(".env.local").exists());
    assert!(!root.join("nested").exists());
    assert_eq!(
        std::fs::read_to_string(root.join("visible")).unwrap(),
        "control"
    );
    assert!(mounts
        .iter()
        .find(|mount| mount.destination == root.join("tools").to_str().unwrap())
        .unwrap()
        .readonly_overlay
        .is_none());
    let overlay = overlay.clone();
    drop(preparation);
    assert!(!Path::new(&overlay).exists());
}

#[test]
fn existing_targets_and_missing_targets_under_writable_grants_need_no_overlay() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    std::fs::write(root.join("existing"), "secret").unwrap();
    std::fs::create_dir(root.join("tools")).unwrap();
    let mut mounts = vec![
        mount(root, FsIntent::ReadOnly),
        mount(&root.join("existing"), FsIntent::Denied),
        mount(&root.join("tools"), FsIntent::ReadWrite),
        mount(&root.join("tools/missing"), FsIntent::Denied),
    ];
    let preparation = prepare(&mut mounts, &[], BwrapVersion::new(0, 5, 0)).unwrap();
    assert!(preparation._storage.is_none());
    assert!(mounts.iter().all(|mount| mount.readonly_overlay.is_none()));
    // The grant is bound from the host as it is, so Bubblewrap leaves the mount
    // point it needs for `tools/missing` in the caller's own directory.
    assert_eq!(
        preparation.created_levels.len(),
        1,
        "a missing target under a writable grant still needs its mount point taken back"
    );
    // This run creates the mount point itself, which is what makes it ours: an
    // object that merely happens to sit at the same path is not.
    assert_eq!(
        preparation.created_levels.len(),
        1,
        "only the missing level is this run's"
    );
    assert_eq!(preparation.created_levels[0].0, root.join("tools/missing"));
    assert!(root.join("tools/missing").is_dir());
}

#[test]
fn an_empty_directory_the_caller_already_had_is_not_a_placeholder() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    let grant = root.join("tools");
    std::fs::create_dir_all(grant.join("sub")).unwrap();
    let mut mounts = vec![
        mount(root, FsIntent::ReadOnly),
        mount(&grant, FsIntent::ReadWrite),
        mount(&grant.join("sub/nested"), FsIntent::Denied),
    ];
    let preparation = prepare(&mut mounts, &[], BwrapVersion::new(0, 5, 0)).unwrap();
    assert_eq!(
        preparation.created_levels.len(),
        1,
        "only the missing level is Bubblewrap's to take back"
    );
    assert_eq!(
        preparation.created_levels.len(),
        1,
        "cleanup must stop at the directory that was already there"
    );
    assert_eq!(preparation.created_levels[0].0, grant.join("sub/nested"));

    // The preparation already created it, standing in for what bwrap reuses.
    remove_levels(&preparation.created_levels);

    assert!(
        !grant.join("sub/nested").exists(),
        "the placeholder Bubblewrap made is still on the host"
    );
    assert!(
        grant.join("sub").is_dir(),
        "cleanup removed an empty directory the caller already had"
    );
}

fn id_of(path: &Path) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path).unwrap();
    (metadata.dev(), metadata.ino())
}

#[test]
fn only_the_objects_this_run_created_are_removed() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("tools");
    std::fs::create_dir(&grant).unwrap();
    let mut mounts = vec![
        mount(&grant, FsIntent::ReadWrite),
        mount(&grant.join("missing/deep"), FsIntent::Denied),
        mount(&grant.join("planted.json"), FsIntent::Denied),
    ];
    let preparation = prepare_with_files(
        &mut mounts,
        &[],
        &[grant.join("planted.json").to_str().unwrap()],
        BwrapVersion::new(0, 5, 0),
    )
    .unwrap();
    assert!(grant.join("missing/deep").is_dir());
    assert!(grant.join("planted.json").is_file());

    remove_levels(&preparation.created_levels);

    assert!(
        !grant.join("missing").exists(),
        "placeholder left on the host"
    );
    assert!(
        !grant.join("planted.json").exists(),
        "empty placeholder file left on the host"
    );
}

#[test]
fn caller_content_written_into_a_placeholder_stops_the_removal() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("tools");
    std::fs::create_dir(&grant).unwrap();
    let mut mounts = vec![
        mount(&grant, FsIntent::ReadWrite),
        mount(&grant.join("missing/deep"), FsIntent::Denied),
    ];
    let preparation = prepare(&mut mounts, &[], BwrapVersion::new(0, 5, 0)).unwrap();
    // The workload wrote into the mount point while the sandbox ran.
    std::fs::write(grant.join("missing/deep/written-by-workload"), "data").unwrap();

    remove_levels(&preparation.created_levels);

    assert!(
        grant.join("missing/deep/written-by-workload").exists(),
        "a directory the workload wrote into is not a placeholder"
    );
    assert!(
        grant.join("missing").is_dir(),
        "nothing above a kept object may be removed"
    );
}

#[test]
fn caller_bytes_written_into_a_placeholder_file_stop_the_removal() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("tools");
    std::fs::create_dir(&grant).unwrap();
    let target = grant.join("missing/config.json");
    let mut mounts = vec![
        mount(&grant, FsIntent::ReadWrite),
        mount(&target, FsIntent::Denied),
    ];
    let preparation = prepare_with_files(
        &mut mounts,
        &[],
        &[target.to_str().unwrap()],
        BwrapVersion::new(0, 5, 0),
    )
    .unwrap();
    assert!(target.is_file());
    std::fs::write(&target, b"caller-owned content").unwrap();

    remove_levels(&preparation.created_levels);

    assert_eq!(
        std::fs::read(&target).unwrap(),
        b"caller-owned content",
        "a populated placeholder file is caller content, not an empty mount point"
    );
    assert!(target.parent().unwrap().is_dir());
}

#[test]
fn an_object_the_caller_replaced_is_left_alone() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("tools");
    std::fs::create_dir(&grant).unwrap();
    let mut mounts = vec![
        mount(&grant, FsIntent::ReadWrite),
        mount(&grant.join("missing"), FsIntent::Denied),
    ];
    let preparation = prepare(&mut mounts, &[], BwrapVersion::new(0, 5, 0)).unwrap();
    // The caller replaced the placeholder with its own empty directory. Moving a
    // fresh one into place guarantees a different inode; remove-and-recreate can
    // reuse the one that was just freed.
    let elsewhere = grant.join("theirs");
    std::fs::create_dir(&elsewhere).unwrap();
    std::fs::remove_dir(grant.join("missing")).unwrap();
    std::fs::rename(&elsewhere, grant.join("missing")).unwrap();
    let replacement = id_of(&grant.join("missing"));
    assert_ne!(replacement, preparation.created_levels[0].1);

    remove_levels(&preparation.created_levels);

    assert!(
        grant.join("missing").is_dir(),
        "a directory the caller put there is not this run's to remove"
    );
    assert_eq!(id_of(&grant.join("missing")), replacement);
}

#[test]
fn a_replacement_between_check_and_removal_is_not_deleted() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("tools");
    std::fs::create_dir(&grant).unwrap();
    let levels = created_placeholder(&grant);
    let target = levels[0].0.clone();
    let (checking, release) = test_control::hold_removal(target.clone());
    let worker = std::thread::spawn(move || {
        let mut preparation = prepared(levels);
        preparation.remove_placeholders();
    });
    checking
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("cleanup did not reach its identity check");
    let replacement = grant.join("replacement");
    std::fs::create_dir(&replacement).unwrap();
    std::fs::remove_dir(&target).unwrap();
    std::fs::rename(&replacement, &target).unwrap();
    let replacement_id = id_of(&target);
    release.send(()).unwrap();
    worker.join().unwrap();

    assert!(target.is_dir(), "cleanup deleted the caller's replacement");
    assert_eq!(id_of(&target), replacement_id);
}

#[test]
fn bytes_written_between_check_and_removal_are_not_deleted() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("tools");
    std::fs::create_dir(&grant).unwrap();
    let target = grant.join("missing/config.json");
    let mut mounts = vec![
        mount(&grant, FsIntent::ReadWrite),
        mount(&target, FsIntent::Denied),
    ];
    let preparation = prepare_with_files(
        &mut mounts,
        &[],
        &[target.to_str().unwrap()],
        BwrapVersion::new(0, 5, 0),
    )
    .unwrap();
    let (checking, release) = test_control::hold_file_removal(target.clone());
    let worker = std::thread::spawn(move || {
        let mut preparation = preparation;
        preparation.remove_placeholders();
    });
    checking
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("cleanup did not reach its file-size check");
    std::fs::write(&target, b"written after the check").unwrap();
    release.send(()).unwrap();
    worker.join().unwrap();

    assert_eq!(
        std::fs::read(&target).unwrap(),
        b"written after the check",
        "cleanup deleted content written after its zero-length check"
    );
}

#[test]
fn a_preexisting_denied_path_is_never_a_mount_point() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    std::fs::create_dir(root.join("tools")).unwrap();
    std::fs::write(root.join("tools/config.json"), "keep me").unwrap();
    let mut mounts = vec![
        mount(root, FsIntent::ReadOnly),
        mount(&root.join("tools"), FsIntent::ReadWrite),
        mount(&root.join("tools/config.json"), FsIntent::Denied),
    ];
    let preparation = prepare(&mut mounts, &[], BwrapVersion::new(0, 11, 0)).unwrap();
    assert!(
        preparation.created_levels.is_empty(),
        "an existing denied path is masked in place and needs no cleanup"
    );
    remove_levels(&preparation.created_levels);
    assert_eq!(
        std::fs::read_to_string(root.join("tools/config.json")).unwrap(),
        "keep me"
    );
}

#[test]
fn absent_optional_baseline_sources_are_not_used_as_overlay_parents() {
    let fixture = tempfile::tempdir().unwrap();
    let absent = fixture.path().join("missing-lib32");
    let path = absent.to_str().unwrap();
    let mut probe = crate::mxc_common::filesystem_probe::FilesystemProbe::default();
    let mounts = baseline_mounts(&[path], &[], &mut probe).unwrap();
    assert!(mounts.is_empty());
}

#[test]
fn missing_denials_require_overlay_support_only_when_needed() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    let mut mounts = vec![
        mount(root, FsIntent::ReadOnly),
        mount(&root.join("missing"), FsIntent::Denied),
    ];
    let error = prepare(&mut mounts, &[], BwrapVersion::new(0, 10, 0)).unwrap_err();
    assert!(error.message().contains("requires bwrap 0.11.0"));
    assert!(error
        .message()
        .contains(root.join("missing").to_str().unwrap()));
    assert!(!root.join("missing").exists());
}

#[test]
fn setuid_bwrap_is_rejected_only_when_an_overlay_is_needed() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    let mut missing = vec![
        mount(root, FsIntent::ReadOnly),
        mount(&root.join("missing"), FsIntent::Denied),
    ];
    let error = super::prepare(
        &mut missing,
        &[],
        &Default::default(),
        BwrapVersion::new(0, 11, 0),
        true,
    )
    .unwrap_err();
    assert!(error.message().contains("non-setuid bwrap"));

    std::fs::write(root.join("existing"), "secret").unwrap();
    let mut existing = vec![
        mount(root, FsIntent::ReadOnly),
        mount(&root.join("existing"), FsIntent::Denied),
    ];
    assert!(super::prepare(
        &mut existing,
        &[],
        &Default::default(),
        BwrapVersion::new(0, 5, 0),
        true
    )
    .unwrap()
    ._storage
    .is_none());
}

#[test]
fn mountinfo_decodes_nested_mountpoints() {
    let mountinfo = concat!(
        "1 0 8:1 / /mnt/source\\040root rw - ext4 /dev/root rw\n",
        "2 1 0:44 / /mnt/source\\040root/nested\\040mount rw - tmpfs tmpfs rw\n"
    );
    let entries = parse_mountinfo(mountinfo).unwrap();
    let nested = nested_mountpoint(Path::new("/mnt/source root"), &entries).unwrap();
    assert_eq!(nested, Path::new("/mnt/source root/nested mount"));
}

#[test]
fn malformed_or_oversized_mountinfo_is_rejected() {
    assert!(parse_mountinfo("not mount information").is_err());
    assert!(parse_mountinfo("1 0 8:1 /bad\\999 / rw - ext4 /dev/root rw").is_err());
    let entry = "1 0 8:1 / / rw - ext4 /dev/root rw\n";
    let contents = entry.repeat(MAX_MOUNTINFO_ENTRIES + 1);
    assert!(parse_mountinfo(&contents)
        .unwrap_err()
        .contains("entry limit"));
}

#[test]
fn writable_bind_aliases_of_private_storage_are_masked() {
    let mountinfo = concat!(
        "1 0 8:1 / / rw - ext4 /dev/root rw\n",
        "2 1 8:1 /tmp /tmp-alias rw - ext4 /dev/root rw\n"
    );
    let entries = parse_mountinfo(mountinfo).unwrap();
    let mut mounts = vec![mount(Path::new("/tmp-alias"), FsIntent::ReadWrite)];

    add_alias_masks(Path::new("/tmp/private-storage"), &entries, &mut mounts).unwrap();

    assert!(mounts.iter().any(|mount| {
        mount.destination == "/tmp-alias/private-storage" && mount.intent == FsIntent::Denied
    }));
}

#[test]
fn a_writable_policy_parent_supersedes_readonly_baseline_mounts() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    let target = root.join("missing");
    let mut mounts = vec![
        mount(root, FsIntent::ReadWrite),
        mount(&target, FsIntent::Denied),
    ];
    let preparation = prepare(&mut mounts, &[], BwrapVersion::new(0, 5, 0)).unwrap();
    assert!(preparation._storage.is_none());
    assert_eq!(preparation.created_levels.len(), 1);
    assert_eq!(preparation.created_levels[0].0, target);
    assert!(target.is_dir());

    drop(preparation);
    assert!(
        !target.exists(),
        "the fixture placeholder was not cleaned up"
    );
}

#[test]
fn overlays_are_emitted_before_child_grants_and_deny_masks() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    std::fs::create_dir(root.join("tools")).unwrap();
    let request = ExecutionRequest {
        policy: ContainerPolicy {
            readonly_paths: vec![root.to_str().unwrap().into()],
            readwrite_paths: vec![root.join("tools").to_str().unwrap().into()],
            denied_paths: vec![root.join("missing").to_str().unwrap().into()],
            ..Default::default()
        },
        ..Default::default()
    };
    let mut mounts = bwrap_command::policy_mounts(&request.policy);
    let preparation = prepare(&mut mounts, &[], BwrapVersion::new(0, 11, 0)).unwrap();
    let args = bwrap_command::build_args_classified_with_mode(
        &request,
        None,
        &std::collections::HashSet::new(),
        bwrap_command::ResolvedNetworkMode::Isolated,
        None,
        &[],
        &[],
        &mounts,
        true,
        |_| Vec::new(),
    );
    let overlay = args.iter().position(|arg| arg == "--ro-overlay").unwrap();
    let child = args
        .windows(3)
        .position(|args| args[0] == "--bind" && args[2] == root.join("tools").to_str().unwrap())
        .unwrap();
    let denied = args
        .windows(2)
        .position(|args| args[0] == "--tmpfs" && args[1] == root.join("missing").to_str().unwrap())
        .unwrap();
    assert!(overlay < child && overlay < denied);
    let layer = mounts
        .iter()
        .find_map(|mount| mount.readonly_overlay.as_deref())
        .unwrap();
    let source = root.to_str().unwrap();
    assert!(
        args.windows(6).any(|args| args
            == [
                "--overlay-src",
                layer,
                "--overlay-src",
                source,
                "--ro-overlay",
                source
            ]),
        "the host source must be the top layer so shared directories keep host metadata: {args:?}"
    );
    let hidden = std::fs::canonicalize(preparation._storage.as_ref().unwrap().path()).unwrap();
    let hidden = hidden.to_str().unwrap();
    assert!(args
        .windows(2)
        .any(|args| args[0] == "--tmpfs" && args[1] == hidden));
    assert!(args
        .windows(2)
        .any(|args| args[0] == "--remount-ro" && args[1] == hidden));
}

#[test]
fn a_denied_parent_is_not_a_host_grant_to_clean_under() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    std::fs::create_dir(root.join("data")).unwrap();
    // `/data/hidden` is denied and missing on the host, so bwrap masks it with a
    // tmpfs. `/data/hidden/new` is then created inside that tmpfs, never on the
    // host. Recording the host path for it would make cleanup delete whatever
    // the caller creates there while the sandbox runs.
    let mut mounts = vec![
        mount(root, FsIntent::ReadOnly),
        mount(&root.join("data"), FsIntent::ReadWrite),
        mount(&root.join("data/hidden"), FsIntent::Denied),
        mount(&root.join("data/hidden/new"), FsIntent::Denied),
    ];
    let preparation = prepare(&mut mounts, &[], BwrapVersion::new(0, 11, 0)).unwrap();
    // `data/hidden` itself still needs its mount point taken back: bwrap makes it
    // in the caller's `data` directory before masking it with a tmpfs.
    assert_eq!(
        preparation.created_levels.len(),
        1,
        "{:?}",
        preparation.created_levels
    );
    assert_eq!(preparation.created_levels[0].0, root.join("data/hidden"));
    // `data/hidden/new` is created inside that tmpfs, so nothing of it reaches
    // the host. Recording it would delete whatever the caller creates at that
    // path while the sandbox is running.
    assert!(
        preparation
            .created_levels
            .iter()
            .all(|(path, _)| *path != root.join("data/hidden/new")),
        "a path inside a denied parent never reaches the host: {:?}",
        preparation.created_levels
    );
}

fn prepared(levels: Vec<(PathBuf, (u64, u64))>) -> DenyPreparation {
    DenyPreparation {
        _storage: None,
        created_levels: levels,
        armed: true,
        cleanup_warnings: CleanupWarnings::default(),
    }
}

/// Create `grant/missing` and return what a preparation would have recorded.
fn created_placeholder(grant: &Path) -> Vec<(PathBuf, (u64, u64))> {
    let path = grant.join("missing");
    std::fs::create_dir_all(&path).unwrap();
    let id = id_of(&path);
    vec![(path, id)]
}

#[test]
fn an_abandoned_preparation_takes_its_placeholders_back() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("tools");
    std::fs::create_dir(&grant).unwrap();
    let levels = created_placeholder(&grant);
    let path = levels[0].0.clone();

    // A startup path that gives up before the sandbox owns the cleanup.
    drop(prepared(levels));

    assert!(
        !path.exists(),
        "a startup failure after the masks were created left the mount point on the host"
    );
}

#[test]
fn a_disarmed_preparation_leaves_cleanup_to_the_sandbox() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("tools");
    std::fs::create_dir(&grant).unwrap();
    let levels = created_placeholder(&grant);
    let path = levels[0].0.clone();

    let mut handed_over = prepared(levels);
    handed_over.disarm();
    drop(handed_over);
    assert!(
        path.exists(),
        "dropping a disarmed preparation must not touch the host"
    );

    // The sandbox removes them itself once it has stopped. A disarmed
    // preparation must still be able to do that: handing the cleanup over
    // changes who calls it, not whether it works.
    let mut owned = prepared(created_placeholder(&grant));
    owned.remove_placeholders();
    assert!(!path.exists());
    // Idempotent: a second call after teardown is a no-op.
    owned.remove_placeholders();
}

#[test]
fn a_handed_off_preparation_still_cleans_up_in_the_background() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("tools");
    std::fs::create_dir(&grant).unwrap();
    let levels = created_placeholder(&grant);
    let path = levels[0].0.clone();

    prepared(levels)
        .remove_placeholders_in_background()
        .expect("background cleanup handoff");

    // The cleanup runs on its own thread, so wait for the effect rather than
    // assuming it finished before the call returned.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while path.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(
        !path.exists(),
        "handing the cleanup off left the mount point on the host"
    );
}

#[test]
fn background_handoff_retains_storage_until_cleanup_finishes() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("tools");
    std::fs::create_dir(&grant).unwrap();
    let levels = created_placeholder(&grant);
    let path = levels[0].0.clone();
    let storage = tempfile::tempdir().unwrap();
    let storage_path = storage.path().to_path_buf();
    let (cleanup_started, release_cleanup) = test_control::hold_storage_cleanup(path.clone());
    let preparation = DenyPreparation {
        _storage: Some(std::sync::Arc::new(storage)),
        created_levels: levels,
        armed: true,
        cleanup_warnings: CleanupWarnings::default(),
    };

    preparation
        .remove_placeholders_in_background()
        .expect("background storage handoff");
    cleanup_started
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("background cleanup did not start");
    let retained_until_cleanup = storage_path.exists();
    release_cleanup.send(()).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while (path.exists() || storage_path.exists()) && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    assert!(
        retained_until_cleanup,
        "handoff dropped the overlay storage on the caller's thread"
    );
    assert!(!path.exists());
    assert!(!storage_path.exists());
}

#[test]
fn background_handoff_with_only_storage_drops_it_off_thread() {
    let storage = tempfile::tempdir().unwrap();
    let storage_path = storage.path().to_path_buf();
    let (job_started, release_job) = test_control::hold_storage_job();
    let preparation = DenyPreparation {
        _storage: Some(std::sync::Arc::new(storage)),
        created_levels: Vec::new(),
        armed: true,
        cleanup_warnings: CleanupWarnings::default(),
    };

    preparation
        .remove_placeholders_in_background()
        .expect("storage-only handoff");
    job_started
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("storage-only cleanup did not start");
    let retained_until_job = storage_path.exists();
    release_job.send(()).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while storage_path.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    assert!(
        retained_until_job,
        "an empty cleanup list dropped storage on the caller's thread"
    );
    assert!(!storage_path.exists());
}

#[test]
fn a_failed_handoff_returns_storage_with_its_cleanup_owner() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("tools");
    std::fs::create_dir(&grant).unwrap();
    let path = grant.join("missing");
    let levels = create_mount_point(&grant, &path, false).unwrap();
    let storage = tempfile::tempdir().unwrap();
    let storage_path = storage.path().to_path_buf();
    test_control::fail_cleanup_spawn_for(path.clone());
    let preparation = DenyPreparation {
        _storage: Some(std::sync::Arc::new(storage)),
        created_levels: levels,
        armed: true,
        cleanup_warnings: CleanupWarnings::default(),
    };

    let (_error, preparation) = preparation
        .remove_placeholders_in_background()
        .expect_err("the injected handoff must fail");
    assert!(path.exists());
    assert!(storage_path.exists());
    drop(preparation);

    assert!(!path.exists());
    assert!(!storage_path.exists());
}

#[test]
fn a_cleanup_thread_spawn_failure_does_not_block_the_caller() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("tools");
    std::fs::create_dir(&grant).unwrap();
    let path = grant.join("missing");
    let levels = create_mount_point(&grant, &path, false).unwrap();
    test_control::fail_cleanup_spawn_for(path.clone());

    let (_error, preparation) = prepared(levels)
        .remove_placeholders_in_background()
        .expect_err("the injected handoff must fail");

    assert!(
        path.exists(),
        "a failed background handoff must leave cleanup pending, not run it inline"
    );
    drop(preparation);
    assert!(
        !path.exists(),
        "the returned preparation did not release cleanup ownership"
    );
    let retry = create_mount_point(&grant, &path, false).unwrap();
    remove_levels(&retry);
    assert!(!path.exists());
}

#[test]
fn cleanup_spawn_failures_are_tracked_per_path() {
    let first = PathBuf::from("/first-cleanup-target");
    let second = PathBuf::from("/second-cleanup-target");
    test_control::fail_cleanup_spawn_for(first.clone());
    test_control::fail_cleanup_spawn_for(second.clone());

    assert!(test_control::take_spawn_failure(&[(first, (0, 0))]));
    assert!(test_control::take_spawn_failure(&[(second, (0, 0))]));
}

#[test]
fn cleanup_spawn_failure_is_scoped_to_its_placeholder() {
    let fixture = tempfile::tempdir().unwrap();
    let intended_grant = fixture.path().join("intended");
    let other_grant = fixture.path().join("other");
    std::fs::create_dir(&intended_grant).unwrap();
    std::fs::create_dir(&other_grant).unwrap();
    let intended = created_placeholder(&intended_grant);
    let intended_path = intended[0].0.clone();
    let other = created_placeholder(&other_grant);
    let other_path = other[0].0.clone();
    let wait_absent = |path: &Path| {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while path.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        !path.exists()
    };
    test_control::fail_cleanup_spawn_for(intended_path.clone());

    prepared(other)
        .remove_placeholders_in_background()
        .expect("other cleanup handoff");
    let other_was_cleaned = wait_absent(&other_path);
    let (_error, intended_preparation) = prepared(intended)
        .remove_placeholders_in_background()
        .expect_err("the intended handoff must fail");
    let intended_was_cleaned = wait_absent(&intended_path);

    assert!(
        other_was_cleaned,
        "another cleanup consumed the injected failure"
    );
    assert!(
        !intended_was_cleaned,
        "the intended cleanup did not receive its injected failure"
    );
    drop(intended_preparation);
}

#[test]
fn sibling_denials_share_an_ancestor_that_is_removed_once() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("tools");
    std::fs::create_dir(&grant).unwrap();
    let mut mounts = vec![
        mount(&grant, FsIntent::ReadWrite),
        mount(&grant.join("missing/a"), FsIntent::Denied),
        mount(&grant.join("missing/b"), FsIntent::Denied),
    ];
    let preparation = prepare(&mut mounts, &[], BwrapVersion::new(0, 5, 0)).unwrap();
    assert!(grant.join("missing/a").is_dir());
    assert!(grant.join("missing/b").is_dir());

    remove_levels(&preparation.created_levels);

    assert!(
        !grant.join("missing").exists(),
        "the ancestor the siblings shared is still on the host"
    );
}

#[test]
fn cleanup_uses_one_deadline_for_the_whole_walk() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("tools");
    std::fs::create_dir(&grant).unwrap();
    let levels: Vec<_> = ["a", "b", "c"]
        .into_iter()
        .map(|name| {
            let path = grant.join(name);
            std::fs::create_dir(&path).unwrap();
            (path, id_of(&grant.join(name)))
        })
        .collect();
    let (started, release) = test_control::hold_path(levels[0].0.clone());
    let timeout = std::time::Duration::from_millis(150);
    let probe = FilesystemProbe::for_test(timeout);

    let start = std::time::Instant::now();
    let result = remove_levels_with_probe(&levels, probe);
    let elapsed = start.elapsed();
    started
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("the blocked path was not reached");
    release.send(()).unwrap();

    assert!(result.is_err(), "the blocked cleanup must report a timeout");
    assert!(
        elapsed < timeout * 2 + std::time::Duration::from_millis(50),
        "three levels consumed separate cleanup deadlines: {elapsed:?}"
    );
}

#[test]
fn an_initial_staging_metadata_failure_rolls_back_the_staging_object() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("tools");
    std::fs::create_dir(&grant).unwrap();
    let target = grant.join("missing");
    test_control::fail_initial_staging_metadata_for(target.clone());

    let error = create_mount_point(&grant, &target, false).unwrap_err();

    let remaining: Vec<_> = std::fs::read_dir(&grant).unwrap().collect();
    assert!(
        remaining.is_empty(),
        "staging survived its first metadata failure: {error:?}; remaining={remaining:?}"
    );
}

#[test]
fn a_staging_directory_open_failure_rolls_back_the_staging_object() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("tools");
    std::fs::create_dir(&grant).unwrap();
    let target = grant.join("missing");
    test_control::fail_staging_open_for(target.clone());

    let error = create_mount_point(&grant, &target, false).unwrap_err();

    let remaining: Vec<_> = std::fs::read_dir(&grant).unwrap().collect();
    assert!(
        remaining.is_empty(),
        "staging survived an open failure: {error:?}; remaining={remaining:?}"
    );
}

#[test]
fn a_staging_file_metadata_failure_rolls_back_the_staging_object() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("tools");
    std::fs::create_dir(&grant).unwrap();
    let target = grant.join("missing");
    test_control::fail_staging_metadata_for(target.clone());

    let error = create_mount_point(&grant, &target, true).unwrap_err();

    let remaining: Vec<_> = std::fs::read_dir(&grant).unwrap().collect();
    assert!(
        remaining.is_empty(),
        "staging survived a metadata failure: {error:?}; remaining={remaining:?}"
    );
}

#[test]
fn unsupported_directory_publication_fails_preparation_and_removes_partial_levels() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("tools");
    std::fs::create_dir(&grant).unwrap();
    let target = grant.join("missing/deep");
    let mut mounts = vec![
        mount(&grant, FsIntent::ReadWrite),
        mount(&target, FsIntent::Denied),
    ];
    test_control::fail_rename_for(target.clone());

    let error = prepare(&mut mounts, &[], BwrapVersion::new(0, 5, 0))
        .expect_err("an atomic-create failure must reject sandbox startup");

    let message = format!("{error:?}");
    assert!(message.contains("could not create"), "{message}");
    assert!(
        !grant.join("missing").exists(),
        "the partial ancestor survived the failed preparation"
    );
}

#[test]
fn unsupported_cleanup_rename_is_reported_as_a_warning() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("tools");
    std::fs::create_dir(&grant).unwrap();
    let target = grant.join("missing");
    let mut mounts = vec![
        mount(&grant, FsIntent::ReadWrite),
        mount(&target, FsIntent::Denied),
    ];
    let mut preparation = prepare(&mut mounts, &[], BwrapVersion::new(0, 5, 0)).unwrap();
    let warnings = preparation.warnings();
    test_control::fail_rename_for(target.clone());

    preparation.remove_placeholders();

    let warnings = warnings.lock().unwrap();
    assert!(
        warnings.iter().any(|warning| warning.contains("missing")),
        "the cleanup failure was silent: {warnings:?}"
    );
    assert!(
        target.is_dir(),
        "an unsupported rename must not delete by path"
    );
    drop(warnings);
    test_control::clear_rename_failure_for(&target);
    let retry = create_mount_point(&grant, &target, false).unwrap();
    remove_levels(&retry);
    assert!(
        !target.exists(),
        "the failed final cleanup left a stale registry user and exclusive lock"
    );
}

#[test]
fn two_runs_release_their_shared_ancestor_after_the_last_run() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("tools");
    std::fs::create_dir(&grant).unwrap();
    let run_a = create_mount_point(&grant, &grant.join("missing/a"), false).unwrap();
    let run_b = create_mount_point(&grant, &grant.join("missing/b"), false).unwrap();

    remove_levels(&run_a);
    assert!(!grant.join("missing/a").exists());
    assert!(grant.join("missing/b").is_dir());
    remove_levels(&run_b);

    assert!(
        !grant.join("missing").exists(),
        "the first run discarded the shared ancestor record before the second run exited"
    );
}

#[test]
fn aliased_paths_retry_an_ancestor_after_its_real_children_are_removed() {
    let fixture = tempfile::tempdir().unwrap();
    let real = fixture.path().join("real/tree/branch");
    std::fs::create_dir_all(&real).unwrap();
    let alias = fixture.path().join("alias");
    std::os::unix::fs::symlink(&real, &alias).unwrap();

    let mut levels = create_mount_point(fixture.path(), &real.join("missing/a"), false).unwrap();
    levels
        .extend(create_mount_point(fixture.path(), &alias.join("missing/b/c/d/e"), false).unwrap());
    assert!(real.join("missing/b/c/d/e").is_dir());

    remove_levels(&levels);

    let registry = CleanupRegistry::global().lock().unwrap();
    let tracked: Vec<_> = registry
        .users
        .iter()
        .filter(|(id, _)| {
            registry
                .paths
                .get(id)
                .is_some_and(|path| path.starts_with(fixture.path()))
        })
        .map(|(key, users)| {
            (
                registry.paths.get(key).cloned(),
                *users,
                registry.removing.contains(key),
                registry.handles.contains_key(key),
                registry.parents.contains_key(key),
            )
        })
        .collect();
    drop(registry);
    assert!(
        !real.join("missing").exists(),
        "aliased ancestor remained; a={} b={} tracked={tracked:?}",
        real.join("missing/a").exists(),
        real.join("missing/b").exists()
    );
}

#[test]
fn a_level_another_process_created_is_not_recorded() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("tools");
    std::fs::create_dir(&grant).unwrap();
    // Stand in for a competing creation: the deepest level already exists, so
    // this run's create fails with AlreadyExists and must not claim it.
    std::fs::create_dir_all(grant.join("missing/deep")).unwrap();
    let theirs = id_of(&grant.join("missing/deep"));

    let created = create_mount_point(&grant, &grant.join("missing/deep"), false).unwrap();

    assert!(
        created.is_empty(),
        "a level another process made is not this run's: {created:?}"
    );
    assert_eq!(id_of(&grant.join("missing/deep")), theirs);
}

#[test]
fn identity_comes_from_the_object_created_not_a_later_path_lookup() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("tools");
    std::fs::create_dir(&grant).unwrap();
    let target = grant.join("missing");
    let (created, release) = test_control::hold_identity(target.clone());
    let worker_target = target.clone();
    let worker_root = grant.clone();
    let worker = std::thread::spawn(move || {
        create_mount_point(&worker_root, &worker_target, false).unwrap()
    });
    created
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("creation did not reach identity capture");
    let original = id_of(&target);
    let replacement = grant.join("replacement");
    std::fs::create_dir(&replacement).unwrap();
    std::fs::remove_dir(&target).unwrap();
    std::fs::rename(&replacement, &target).unwrap();
    let replacement_id = id_of(&target);
    assert_ne!(original, replacement_id);
    release.send(()).unwrap();
    let levels = worker.join().unwrap();

    assert_eq!(levels.len(), 1);
    assert!(
        CleanupRegistry::global()
            .lock()
            .unwrap()
            .handles
            .contains_key(&original),
        "the created object's handle was not retained"
    );
    assert_eq!(
        levels[0].1, original,
        "the path lookup captured the caller's replacement as this run's object"
    );
    remove_levels(&levels);
    assert!(target.is_dir(), "the caller's replacement was deleted");
}

#[test]
fn an_intermediate_symlink_swap_cannot_redirect_creation() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("grant");
    let original = fixture.path().join("original");
    let outside = fixture.path().join("outside");
    std::fs::create_dir(&grant).unwrap();
    std::fs::create_dir(&outside).unwrap();
    let target = grant.join("missing/deep");
    let (creating, release) = test_control::hold_root_swap_create(grant.join("missing"));
    let worker_target = target.clone();
    let worker_root = grant.clone();
    let worker = std::thread::spawn(move || {
        create_mount_point(&worker_root, &worker_target, false).unwrap()
    });
    creating
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("creation did not reach the root-swap barrier");
    std::fs::rename(&grant, &original).unwrap();
    std::os::unix::fs::symlink(&outside, &grant).unwrap();
    release.send(()).unwrap();
    let levels = worker.join().unwrap();

    assert!(
        !outside.join("missing").exists(),
        "creation followed the replacement symlink outside the original grant"
    );
    remove_levels(&levels);
    assert!(
        !original.join("missing").exists(),
        "cleanup did not follow the retained original grant"
    );
}

#[test]
fn an_intermediate_symlink_swap_cannot_redirect_cleanup() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("grant");
    let original = fixture.path().join("original");
    let outside = fixture.path().join("outside");
    std::fs::create_dir(&grant).unwrap();
    std::fs::create_dir(&outside).unwrap();
    let target = grant.join("missing/deep");
    let levels = create_mount_point(&grant, &target, false).unwrap();
    let (checking, release) = test_control::hold_root_swap_remove(target.clone());
    let worker = std::thread::spawn(move || remove_levels(&levels));
    checking
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("cleanup did not reach the root-swap barrier");
    std::fs::rename(&grant, &original).unwrap();
    std::os::unix::fs::symlink(&outside, &grant).unwrap();
    release.send(()).unwrap();
    worker.join().unwrap();

    assert!(
        !original.join("missing").exists(),
        "cleanup left the original grant's placeholders behind"
    );
    assert!(
        !outside.join("missing").exists(),
        "cleanup escaped through the replacement symlink"
    );
}

#[test]
fn an_existing_ancestor_does_not_skip_missing_descendants() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("tools");
    std::fs::create_dir(&grant).unwrap();
    let ancestor = grant.join("missing");
    let target = ancestor.join("deep");
    let (creating, release) = test_control::hold_before_create(ancestor.clone());
    let worker_target = target.clone();
    let worker_root = grant.clone();
    let worker = std::thread::spawn(move || {
        create_mount_point(&worker_root, &worker_target, false).unwrap()
    });
    creating
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("creation did not reach the ancestor");
    std::fs::create_dir(&ancestor).unwrap();
    release.send(()).unwrap();
    let levels = worker.join().unwrap();

    assert!(
        target.is_dir(),
        "creation stopped at the competing ancestor"
    );
    assert_eq!(levels.len(), 1);
    assert_eq!(levels[0].0, target);
    remove_levels(&levels);
    assert!(
        ancestor.is_dir(),
        "the untracked competing ancestor was claimed"
    );
}

#[test]
fn a_preparation_that_fails_later_takes_its_creations_back() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("tools");
    std::fs::create_dir(&grant).unwrap();
    let levels = created_placeholder(&grant);
    let path = levels[0].0.clone();

    // A preparation that gives up partway: the guard still holds what it made.
    let group = CreationGroup::default();
    group.record(levels);
    drop(group);

    assert!(
        !path.exists(),
        "a failed preparation left the mount point it already created on the host"
    );
}

#[test]
fn a_failed_preparation_releases_a_shared_ancestor_too() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("tools");
    std::fs::create_dir(&grant).unwrap();
    // Built by hand so the preparation's own drop cannot clean them first: the
    // list is in creation order, exactly what a preparation that failed partway
    // would hold.
    let shared = grant.join("missing");
    std::fs::create_dir_all(shared.join("a")).unwrap();
    std::fs::create_dir_all(shared.join("b")).unwrap();
    // The order the real preparation produces: each entry carries its own
    // levels deepest-first, and the shared ancestor appears with whichever
    // entry created it.
    let levels = vec![
        (shared.join("a"), id_of(&shared.join("a"))),
        (shared.clone(), id_of(&shared)),
        (shared.join("b"), id_of(&shared.join("b"))),
    ];

    let group = CreationGroup::default();
    group.record(levels);
    drop(group);

    assert!(
        !shared.exists(),
        "a failed preparation left the ancestor its siblings shared on the host"
    );
}

#[test]
fn a_creation_guard_cleans_up_whatever_it_still_owns() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("tools");
    std::fs::create_dir(&grant).unwrap();
    let target = grant.join("missing");

    // What the creation job holds while it runs. A result that never reaches
    // the caller — a probe timeout drops it — takes the guard's drop with it.
    let owned = CreationGroup::default();
    owned.record(create_mount_point(&grant, &target, false).unwrap());
    assert!(target.is_dir());
    drop(owned);

    assert!(
        !target.exists(),
        "a creation guard that never handed its levels back left them on the host"
    );
}

#[test]
fn a_stalled_creation_does_not_block_an_unrelated_grant() {
    let fixture = tempfile::tempdir().unwrap();
    let first_grant = fixture.path().join("first");
    let second_grant = fixture.path().join("second");
    std::fs::create_dir(&first_grant).unwrap();
    std::fs::create_dir(&second_grant).unwrap();
    let first = first_grant.join("missing/deep");
    let second = second_grant.join("missing/deep");
    let (creation_started, release_creation) = test_control::hold_stalled_creation(first.clone());
    let first_worker = {
        let first = first.clone();
        let root = first_grant.clone();
        std::thread::spawn(move || create_mount_point(&root, &first, false).unwrap())
    };
    creation_started
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("the first creation did not reach its barrier");

    let (second_done, second_result) = std::sync::mpsc::sync_channel(1);
    let second_root = second_grant.clone();
    let second_worker = std::thread::spawn(move || {
        let levels = create_mount_point(&second_root, &second, false).unwrap();
        second_done.send(()).unwrap();
        levels
    });
    let finished_while_first_was_stalled =
        second_result.recv_timeout(std::time::Duration::from_secs(1));
    release_creation.send(()).unwrap();
    let first_levels = first_worker.join().unwrap();
    let second_levels = second_worker.join().unwrap();
    remove_levels(&first_levels);
    remove_levels(&second_levels);

    assert!(
        finished_while_first_was_stalled.is_ok(),
        "an unrelated grant waited for the stalled creation"
    );
    assert!(!first_grant.join("missing").exists());
    assert!(!second_grant.join("missing").exists());
}

#[test]
fn unused_path_locks_are_reclaimed_without_replacing_live_locks() {
    let fixture = tempfile::tempdir().unwrap();
    let first = fixture.path().join("first");
    let second = fixture.path().join("second");
    let third = fixture.path().join("third");

    let first_lock = path_lock(&first);
    let first_weak = std::sync::Arc::downgrade(&first_lock);
    let second_lock = path_lock(&second);
    assert!(
        std::sync::Arc::ptr_eq(&first_lock, &path_lock(&first)),
        "acquiring an unrelated path replaced a lock that was still in use"
    );
    assert!(first_weak.upgrade().is_some());

    drop(second_lock);
    drop(first_lock);
    drop(path_lock(&third));
    assert!(
        first_weak.upgrade().is_none(),
        "the global path-lock table retained an unused path forever"
    );
}

#[test]
fn a_late_creation_result_finishes_the_failed_preparations_ancestors() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("tools");
    std::fs::create_dir(&grant).unwrap();
    let first = grant.join("missing/a");
    let second = grant.join("missing/b");
    let mut mounts = vec![
        mount(&grant, FsIntent::ReadWrite),
        mount(&first, FsIntent::Denied),
        mount(&second, FsIntent::Denied),
    ];
    let (creation_started, release_creation) = test_control::hold_creation(second.clone());
    let probe = FilesystemProbe::for_test(std::time::Duration::from_millis(150));

    let error = prepare_inner(
        &mut mounts,
        &[],
        &Default::default(),
        BwrapVersion::new(0, 5, 0),
        false,
        probe,
    )
    .expect_err("the second creation must exceed the probe deadline");
    assert!(error.message().contains("timed out"), "{error:?}");
    creation_started
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("the second creation did not reach its barrier");
    assert!(
        first.is_dir(),
        "cleanup must wait for the outstanding creation before the shared walk"
    );
    assert!(second.is_dir(), "the late creation has not settled yet");

    release_creation.send(()).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while grant.join("missing").exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(
        !grant.join("missing").exists(),
        "the late guard removed its leaf but stranded the failed preparation's ancestor"
    );
}
