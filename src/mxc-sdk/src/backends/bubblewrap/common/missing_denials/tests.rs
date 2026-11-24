// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::bwrap_common::bwrap_command;
use crate::mxc_common::models::{ContainerPolicy, ExecutionRequest};

fn prepare(
    mounts: &mut Vec<PolicyMount>,
    baseline_links: &[BaselineLink],
    version: BwrapVersion,
) -> Result<Option<Vec<OverlayStorage>>, FilesystemPolicyError> {
    super::prepare(mounts, baseline_links, version, false)
}

fn mount(path: &Path, intent: FsIntent) -> PolicyMount {
    let path = path.to_str().unwrap().to_owned();
    PolicyMount {
        source: path.clone(),
        destination: path,
        intent,
        readonly_overlay: None,
        writable_overlay: None,
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
fn missing_targets_under_writable_grants_use_private_overlays() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    std::fs::write(root.join("existing"), "secret").unwrap();
    std::fs::create_dir(root.join("tools")).unwrap();
    let missing = root.join("tools/missing");
    let mut mounts = vec![
        mount(root, FsIntent::ReadOnly),
        mount(&root.join("existing"), FsIntent::Denied),
        mount(&root.join("tools"), FsIntent::ReadWrite),
        mount(&missing, FsIntent::Denied),
    ];
    let storage = prepare(&mut mounts, &[], BwrapVersion::new(0, 12, 0))
        .unwrap()
        .unwrap();
    let parent = mounts
        .iter()
        .find(|mount| mount.intent == FsIntent::ReadWrite)
        .unwrap();
    let overlay = parent.writable_overlay.as_ref().unwrap();
    assert!(Path::new(&overlay.lower).join("missing").is_dir());
    assert!(Path::new(&overlay.workdir).is_dir());
    assert_eq!(
        std::fs::metadata(&overlay.workdir).unwrap().dev(),
        std::fs::metadata(&parent.source).unwrap().dev()
    );
    assert!(!missing.exists());
    assert_eq!(
        std::fs::read_to_string(root.join("existing")).unwrap(),
        "secret"
    );
    assert!(mounts.iter().all(|mount| mount.readonly_overlay.is_none()));
    let lower = overlay.lower.clone();
    let workdir = overlay.workdir.clone();
    let internal = Path::new(&workdir).join("work");
    std::fs::create_dir(&internal).unwrap();
    std::fs::set_permissions(&internal, std::fs::Permissions::from_mode(0o000)).unwrap();
    drop(storage);
    assert!(!Path::new(&lower).exists());
    assert!(!Path::new(&workdir).exists());
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
fn writable_missing_denials_require_overlay_support() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("grant");
    std::fs::create_dir(&grant).unwrap();
    let missing = grant.join("missing");
    let mut mounts = vec![
        mount(&grant, FsIntent::ReadWrite),
        mount(&missing, FsIntent::Denied),
    ];
    let error = prepare(&mut mounts, &[], BwrapVersion::new(0, 11, 0)).unwrap_err();
    assert!(error.message().contains("requires bwrap 0.12.0"));
    assert!(error.message().contains("read-write"));
    assert!(!missing.exists());
    assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 1);
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
fn mountinfo_accepts_namespace_roots_only_for_nsfs() {
    let mountinfo = concat!(
        "1 0 8:1 / / rw - ext4 /dev/root rw\n",
        "2 1 0:44 net:[4026533000] /run/netns/persisted rw - nsfs nsfs rw\n"
    );
    let entries = parse_mountinfo(mountinfo).unwrap();
    assert_eq!(entries[1].root, PathBuf::from("net:[4026533000]"));
    assert_eq!(entries[1].mountpoint, PathBuf::from("/run/netns/persisted"));

    assert!(parse_mountinfo(
        "2 1 0:44 net:[4026533000] /run/netns/persisted rw - tmpfs tmpfs rw\n"
    )
    .is_err());
    assert!(
        parse_mountinfo("2 1 0:44 not-a-namespace /run/netns/persisted rw - nsfs nsfs rw\n")
            .is_err()
    );
}

#[test]
fn writable_storage_requires_mount_identity_not_only_device() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("grant");
    std::fs::create_dir(&grant).unwrap();
    let entries = vec![
        MountInfoEntry {
            id: 1,
            device: (8, 1),
            root: PathBuf::from("/"),
            mountpoint: PathBuf::from("/"),
        },
        MountInfoEntry {
            id: 2,
            device: (8, 1),
            root: PathBuf::from("/real"),
            mountpoint: grant.clone(),
        },
    ];
    let error = writable_storage(&grant, &[], &entries).unwrap_err();
    assert!(error.message().contains("same mount"));
    assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 1);
}

#[test]
#[cfg(target_os = "linux")]
fn writable_storage_preparation_obeys_the_probe_deadline() {
    let fixture = tempfile::tempdir().unwrap();
    let grant = fixture.path().join("grant");
    std::fs::create_dir(&grant).unwrap();
    crate::mxc_common::filesystem_probe::launch_tests::inject(
        "bwrap-writable-storage",
        grant.clone(),
    );
    let missing = grant.join("missing");
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut mounts = vec![
            mount(&grant, FsIntent::ReadWrite),
            mount(&missing, FsIntent::Denied),
        ];
        let result = prepare(&mut mounts, &[], BwrapVersion::new(0, 12, 0));
        let _ = sender.send(result.map(|_| ()));
    });
    let result = receiver
        .recv_timeout(std::time::Duration::from_secs(8))
        .expect("writable storage preparation ignored its probe deadline");
    let error = result.expect_err("a stalled writable storage probe must reject startup");
    assert!(error.message().contains("timed out after 5000ms"));
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
    let target = fixture.path().join("missing");
    let mut mounts = vec![
        mount(fixture.path(), FsIntent::ReadWrite),
        mount(&target, FsIntent::Denied),
    ];
    let _storage = prepare(&mut mounts, &[], BwrapVersion::new(0, 12, 0))
        .unwrap()
        .unwrap();
    let overlay = mounts[0].writable_overlay.as_ref().unwrap();
    assert!(Path::new(&overlay.lower).join("missing").is_dir());
    assert!(!target.exists());
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
    let hidden = std::fs::canonicalize(storage[0].path()).unwrap();
    let hidden = hidden.to_str().unwrap();
    assert!(args
        .windows(2)
        .any(|args| args[0] == "--tmpfs" && args[1] == hidden));
    assert!(args
        .windows(2)
        .any(|args| args[0] == "--remount-ro" && args[1] == hidden));
}
