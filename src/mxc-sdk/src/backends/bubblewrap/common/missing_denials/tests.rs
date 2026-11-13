// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::bwrap_common::bwrap_command;
use crate::mxc_common::models::{ContainerPolicy, ExecutionRequest};

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
    assert!(prepare(&mut mounts, &[], BwrapVersion::new(0, 5, 0))
        .unwrap()
        .is_none());
    assert!(mounts.iter().all(|mount| mount.readonly_overlay.is_none()));
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
fn a_writable_policy_parent_supersedes_readonly_baseline_mounts() {
    let target = format!("/etc/mxc-missing-{}", uuid::Uuid::new_v4());
    let mut mounts = vec![
        mount(Path::new("/"), FsIntent::ReadWrite),
        mount(Path::new(&target), FsIntent::Denied),
    ];
    assert!(prepare(&mut mounts, &[], BwrapVersion::new(0, 5, 0))
        .unwrap()
        .is_none());
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
    let hidden = std::fs::canonicalize(storage.path()).unwrap();
    let hidden = hidden.to_str().unwrap();
    assert!(args
        .windows(2)
        .any(|args| args[0] == "--tmpfs" && args[1] == hidden));
    assert!(args
        .windows(2)
        .any(|args| args[0] == "--remount-ro" && args[1] == hidden));
}
