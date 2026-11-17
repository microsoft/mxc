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
    let target = format!("/etc/mxc-missing-{}", uuid::Uuid::new_v4());
    let mut mounts = vec![
        mount(Path::new("/"), FsIntent::ReadWrite),
        mount(Path::new(&target), FsIntent::Denied),
    ];
    let preparation = prepare(&mut mounts, &[], BwrapVersion::new(0, 5, 0)).unwrap();
    assert!(preparation._storage.is_none());
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

    prepared(levels).remove_placeholders_in_background();

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
fn a_level_another_process_created_is_not_recorded() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("tools");
    std::fs::create_dir(&grant).unwrap();
    // Stand in for a competing creation: the deepest level already exists, so
    // this run's create fails with AlreadyExists and must not claim it.
    std::fs::create_dir_all(grant.join("missing/deep")).unwrap();
    let theirs = id_of(&grant.join("missing/deep"));

    let created = create_mount_point(&grant.join("missing/deep"), false);

    assert!(
        created.is_empty(),
        "a level another process made is not this run's: {created:?}"
    );
    assert_eq!(id_of(&grant.join("missing/deep")), theirs);
}

#[test]
fn a_preparation_that_fails_later_takes_its_creations_back() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("tools");
    std::fs::create_dir(&grant).unwrap();
    let levels = created_placeholder(&grant);
    let path = levels[0].0.clone();

    // A preparation that gives up partway: the guard still holds what it made.
    let mut pending = PendingCreations::default();
    pending.record(levels);
    drop(pending);

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

    let mut pending = PendingCreations::default();
    pending.record(levels);
    drop(pending);

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
    let mut owned = PendingCreations::default();
    owned.record(create_mount_point(&target, false));
    assert!(target.is_dir());
    drop(owned);

    assert!(
        !target.exists(),
        "a creation guard that never handed its levels back left them on the host"
    );
}

#[test]
fn dbg_probe_timing() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("tools");
    std::fs::create_dir(&grant).unwrap();
    let target = grant.join("missing");
    let mut probe = FilesystemProbe::for_test(std::time::Duration::from_millis(1));
    let t = target.clone();
    let started = std::time::Instant::now();
    let outcome = probe.run("job", move |_| {
        eprintln!("DBG job start");
        let r = create_mount_point(&t, false);
        eprintln!("DBG created {:?} exists={}", r, t2_exists(&t));
        std::thread::sleep(std::time::Duration::from_millis(300));
        eprintln!("DBG job end");
        r
    });
    eprintln!(
        "DBG outcome_err={} elapsed={:?}",
        outcome.is_err(),
        started.elapsed()
    );
    std::thread::sleep(std::time::Duration::from_millis(500));
    eprintln!("DBG final exists={}", target.exists());
}
fn t2_exists(p: &Path) -> bool {
    p.exists()
}
