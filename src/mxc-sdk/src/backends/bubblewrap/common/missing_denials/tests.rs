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
    super::prepare(mounts, baseline_links, version, false)
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
    let storage = prepare(&mut mounts, &[], BwrapVersion::new(0, 11, 0))
        .unwrap()
        ._storage
        .unwrap();
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
    drop(storage);
    assert!(!Path::new(overlay).exists());
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
        preparation.mount_points.len(),
        1,
        "a missing target under a writable grant still needs its mount point taken back"
    );
    assert_eq!(preparation.mount_points[0].path, root.join("tools/missing"));
    assert_eq!(
        preparation.mount_points[0].existing_ancestor,
        root.join("tools")
    );
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
        preparation.mount_points.len(),
        1,
        "only the missing level is Bubblewrap's to take back"
    );
    assert_eq!(
        preparation.mount_points[0].existing_ancestor,
        grant.join("sub"),
        "cleanup must stop at the directory that was already there"
    );

    // What Bubblewrap leaves behind, and then the cleanup.
    std::fs::create_dir(grant.join("sub/nested")).unwrap();
    remove_mount_points(&preparation.mount_points);

    assert!(
        !grant.join("sub/nested").exists(),
        "the placeholder Bubblewrap made is still on the host"
    );
    assert!(
        grant.join("sub").is_dir(),
        "cleanup removed an empty directory the caller already had"
    );
}

#[test]
fn placeholders_left_by_bubblewrap_are_removed_and_caller_content_is_kept() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("tools");
    std::fs::create_dir(&grant).unwrap();
    // What Bubblewrap leaves for a `--tmpfs` mask on a path that did not exist.
    std::fs::create_dir_all(grant.join("missing/deep")).unwrap();
    // What it leaves for a `--ro-bind /dev/null` mask.
    std::fs::write(grant.join("planted.json"), "").unwrap();
    let kept = grant.join("has-content");
    std::fs::create_dir(&kept).unwrap();
    std::fs::write(kept.join("written-by-workload"), "data").unwrap();
    let mount_points = vec![
        HostMountPoint {
            path: grant.join("missing/deep"),
            existing_ancestor: grant.clone(),
        },
        HostMountPoint {
            path: grant.join("planted.json"),
            existing_ancestor: grant.clone(),
        },
        HostMountPoint {
            path: grant.join("has-content"),
            existing_ancestor: grant.clone(),
        },
    ];

    remove_mount_points(&mount_points);

    assert!(
        !grant.join("missing").exists(),
        "placeholder left on the host"
    );
    assert!(
        !grant.join("planted.json").exists(),
        "empty file left on the host"
    );
    assert!(
        kept.join("written-by-workload").exists(),
        "a directory the workload wrote into is not a placeholder"
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
        preparation.mount_points.is_empty(),
        "an existing denied path is masked in place and needs no cleanup"
    );
    remove_mount_points(&preparation.mount_points);
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
    let error = super::prepare(&mut missing, &[], BwrapVersion::new(0, 11, 0), true).unwrap_err();
    assert!(error.message().contains("non-setuid bwrap"));

    std::fs::write(root.join("existing"), "secret").unwrap();
    let mut existing = vec![
        mount(root, FsIntent::ReadOnly),
        mount(&root.join("existing"), FsIntent::Denied),
    ];
    assert!(
        super::prepare(&mut existing, &[], BwrapVersion::new(0, 5, 0), true)
            .unwrap()
            ._storage
            .is_none()
    );
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
    let storage = prepare(&mut mounts, &[], BwrapVersion::new(0, 11, 0))
        .unwrap()
        ._storage
        .unwrap();
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
    let hidden = std::fs::canonicalize(storage.path()).unwrap();
    let hidden = hidden.to_str().unwrap();
    assert!(args
        .windows(2)
        .any(|args| args[0] == "--tmpfs" && args[1] == hidden));
    assert!(args
        .windows(2)
        .any(|args| args[0] == "--remount-ro" && args[1] == hidden));
}
