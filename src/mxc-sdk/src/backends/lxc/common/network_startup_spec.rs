// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use std::fs;

#[test]
fn retained_fstab_mounts_preserve_the_resolver() {
    let root = tempfile::tempdir_in(".").expect("create mount fixture directory");
    let path = root.path().join("fstab");

    for target in ["etc", "/etc", "etc/resolv.conf", "/etc/resolv.conf"] {
        let fstab = format!("/host/config {target} none bind 0 0\n");
        fs::write(&path, &fstab).expect("write retained mount table");

        assert_eq!(
            resolver_is_mounted("", path.to_str().expect("UTF-8 mount table path")),
            Ok(true),
            "a retained mount covering the resolver must prevent replacing it; fstab={fstab:?}"
        );
    }
}

#[test]
fn unrelated_mounts_and_comments_do_not_preserve_the_resolver() {
    let root = tempfile::tempdir_in(".").expect("create mount fixture directory");
    let path = root.path().join("fstab");
    let fstab = concat!(
        "\n",
        "# /host/config etc none bind 0 0\n",
        "/host/assets opt/assets none bind 0 0\n",
        "/host/config etc-backup none bind 0 0\n",
    );
    fs::write(&path, fstab).expect("write unrelated and commented mounts");
    let entries = "/host/resolv.conf opt/resolv.conf none bind 0 0";

    assert_eq!(
        resolver_is_mounted(entries, path.to_str().expect("UTF-8 mount table path")),
        Ok(false),
        "only actual mount targets covering the resolver count; entries={entries:?}, fstab={fstab:?}"
    );
}

#[test]
fn unreadable_retained_fstab_is_an_error() {
    let root = tempfile::tempdir_in(".").expect("create mount fixture directory");
    let path = root.path().join("missing-fstab");

    assert!(
        resolver_is_mounted("", path.to_str().expect("UTF-8 mount table path")).is_err(),
        "an unreadable retained mount table must not be treated as having no resolver mount; path={path:?}"
    );
}
