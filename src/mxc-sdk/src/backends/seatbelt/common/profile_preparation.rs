// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! macOS filesystem and environment discovery for Seatbelt profile generation.

use std::fs;
use std::path::{Path, PathBuf};

use crate::mxc_common::models::ExecutionRequest;
use crate::seatbelt_common::profile_builder::ProfileInputs;

const DEVELOPER_DIR_LINKS: [&str; 2] = [
    "/private/var/db/xcode_select_link",
    "/private/var/select/developer_dir",
];

pub(crate) fn prepare_profile(request: &ExecutionRequest) -> Result<ProfileInputs, String> {
    if request
        .seatbelt
        .as_ref()
        .is_some_and(|config| config.profile_override.is_some())
    {
        return Ok(ProfileInputs::default());
    }

    let developer_dir = active_developer_dir()
        .map(|dir| developer_dir_grant_root(&dir))
        .and_then(|dir| dir.into_os_string().into_string().ok());
    let denied_paths = resolve_all(&request.policy.denied_paths)?;
    let readonly_paths = resolve_all(&request.policy.readonly_paths)?;
    let readwrite_paths = resolve_all(&request.policy.readwrite_paths)?;
    let user_keychains = if request.seatbelt.as_ref().is_some_and(|c| c.keychain_access) {
        let home = std::env::var("HOME").map_err(|_| {
            "HOME environment variable not set; cannot expand '~/Library/Keychains' for keychainAccess"
                .to_string()
        })?;
        Some(user_keychains_dir(&home)?)
    } else {
        None
    };

    Ok(ProfileInputs {
        readonly_paths,
        readwrite_paths,
        denied_paths,
        developer_dir,
        user_keychains,
    })
}

fn resolve_all(paths: &[String]) -> Result<Vec<String>, String> {
    paths.iter().map(|p| resolve_policy_path(p)).collect()
}

/// Seatbelt matches real paths, so a symlinked HOME must be resolved.
fn user_keychains_dir(home: &str) -> Result<String, String> {
    resolve_policy_path(&format!("{home}/Library/Keychains"))
}

/// Follow symlinks before applying `..`, retaining missing trailing names.
pub(crate) fn resolve_policy_path(path: &str) -> Result<String, String> {
    let expanded = expand_tilde(path)?;
    let resolution_error =
        |error| format!("Filesystem path '{path}' could not be resolved: {error}");
    let absolute = std::path::absolute(&expanded).map_err(resolution_error)?;
    let resolved = crate::mxc_common::filesystem_symlink::resolve_through_symlinks(&absolute)
        .ok_or_else(|| format!("Filesystem path '{path}' has no resolved target"))?;
    if let Some(error) = resolved.error {
        return Err(resolution_error(error));
    }
    resolved
        .path
        .into_os_string()
        .into_string()
        .map_err(|_| format!("Filesystem path '{path}' resolves to a non-UTF-8 path"))
}

pub(crate) fn expand_tilde(path: &str) -> Result<String, String> {
    if path == "~" || path.starts_with("~/") {
        let home = std::env::var("HOME").map_err(|_| {
            format!("HOME environment variable not set; cannot expand '{path}' in seatbelt profile")
        })?;
        if path == "~" {
            Ok(home)
        } else {
            Ok(format!("{home}/{}", &path[2..]))
        }
    } else {
        Ok(path.to_string())
    }
}

/// Ignore caller-controlled DEVELOPER_DIR; only trust the system's selection.
fn active_developer_dir() -> Option<PathBuf> {
    DEVELOPER_DIR_LINKS
        .iter()
        .map(Path::new)
        .filter(|link| link_is_root_controlled(link))
        .filter_map(|link| fs::read_link(link).ok())
        .find(|target| target.is_absolute() && target.is_dir())
}

/// Replacing a link is controlled by its parent, not just the link's owner.
fn link_is_root_controlled(link: &Path) -> bool {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let Ok(link_meta) = fs::symlink_metadata(link) else {
        return false;
    };
    if !link_meta.file_type().is_symlink() || link_meta.uid() != 0 {
        return false;
    }
    link.ancestors().skip(1).all(|dir| {
        fs::metadata(dir)
            .is_ok_and(|meta| dir_is_root_controlled(meta.uid(), meta.permissions().mode()))
    })
}

fn dir_is_root_controlled(uid: u32, mode: u32) -> bool {
    uid == 0 && mode & 0o022 == 0
}

/// Xcode shims also load frameworks outside Contents/Developer.
fn developer_dir_grant_root(dir: &Path) -> PathBuf {
    enclosing_app_bundle(dir).map_or_else(|| dir.to_path_buf(), Path::to_path_buf)
}

fn enclosing_app_bundle(dir: &Path) -> Option<&Path> {
    if dir.file_name()? != "Developer" {
        return None;
    }
    let contents = dir.parent()?;
    if contents.file_name()? != "Contents" {
        return None;
    }
    let bundle = contents.parent()?;
    bundle
        .extension()?
        .eq_ignore_ascii_case("app")
        .then_some(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_common::models::SeatbeltConfig;
    use crate::seatbelt_common::profile_builder::build_profile_with_proxy;

    #[test]
    fn lexical_spellings_normalize_to_the_same_rule() {
        for spelling in [
            "/tmp/secret",
            "//tmp/secret",
            "/./tmp/secret",
            "/tmp//secret",
            "/tmp/./secret/",
            "///tmp/secret//",
        ] {
            assert_eq!(
                resolve_policy_path(spelling).unwrap(),
                "/private/tmp/secret",
                "spelling {spelling} must normalize"
            );
        }
    }

    #[test]
    fn lexical_normalization_is_idempotent_and_preserves_root() {
        assert_eq!(resolve_policy_path("/").unwrap(), "/");
        assert_eq!(resolve_policy_path("//").unwrap(), "/");
        let once = resolve_policy_path("//tmp/./secret/").unwrap();
        assert_eq!(resolve_policy_path(&once).unwrap(), once);
    }

    #[test]
    fn parent_segments_follow_symlinked_roots() {
        for (path, expected) in [
            ("/private/var/../tmp", "/private/tmp"),
            ("/tmp/..", "/private"),
            ("/..", "/"),
            ("/a/b/../c", "/a/c"),
        ] {
            assert_eq!(resolve_policy_path(path).unwrap(), expected);
        }
        assert_eq!(
            resolve_policy_path("/tmp/..secret").unwrap(),
            "/private/tmp/..secret"
        );
    }

    #[test]
    fn user_symlinks_resolve_before_parent_segments_and_missing_tails() {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        fs::create_dir_all(root.join("real/nested")).unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink("real/nested", &link).unwrap();
        for suffix in ["../secret", "missing/../../secret"] {
            let path = link.join(suffix);
            assert_eq!(
                resolve_policy_path(path.to_str().unwrap()).unwrap(),
                root.join("real/secret").to_str().unwrap()
            );
        }
    }

    #[test]
    fn unresolved_symlinks_fail_before_parent_segments_can_hide_them() {
        let dir = tempfile::tempdir().unwrap();
        for (name, target) in [("dangling", "missing"), ("loop", "loop")] {
            let link = dir.path().join(name);
            std::os::unix::fs::symlink(target, &link).unwrap();
            for suffix in ["", "child", "../secret"] {
                let path = link.join(suffix);
                let error = resolve_policy_path(path.to_str().unwrap()).unwrap_err();
                assert!(error.contains("could not be resolved"), "{error}");
            }
        }
    }

    #[test]
    fn prepared_aliases_keep_the_strictest_profile_rules() {
        let dir = tempfile::tempdir().unwrap();
        let target = fs::canonicalize(dir.path()).unwrap().join("target");
        fs::write(&target, "secret").unwrap();
        let link = dir.path().join("alias");
        std::os::unix::fs::symlink("target", &link).unwrap();
        let mut request = ExecutionRequest::default();
        request.policy.readonly_paths = vec![target.to_str().unwrap().into()];
        request.policy.readwrite_paths = vec![link.to_str().unwrap().into()];
        let inputs = prepare_profile(&request).unwrap();
        let profile = build_profile_with_proxy(&request, None, &inputs).unwrap();
        let filter = format!("(subpath \"{}\")", target.display());
        assert!(profile.contains(&filter));
        assert!(!profile.contains("(allow file-read* file-write* network-bind network-outbound"));

        request.policy.denied_paths = vec![link.to_str().unwrap().into()];
        let inputs = prepare_profile(&request).unwrap();
        let profile = build_profile_with_proxy(&request, None, &inputs).unwrap();
        assert!(!profile.contains(";; --- policy.readonlyPaths / policy.readwritePaths"));
        assert!(profile.contains(&filter));
    }

    #[test]
    fn denied_path_with_redundant_spelling_still_denies() {
        let mut request = ExecutionRequest::default();
        request.policy.readwrite_paths = vec!["/tmp".into()];
        request.policy.denied_paths = vec!["//tmp/./secret/".into()];
        let inputs = prepare_profile(&request).unwrap();
        let profile = build_profile_with_proxy(&request, None, &inputs).unwrap();
        let deny = profile
            .find("(deny file-read* file-read-metadata file-write* network-bind network-outbound")
            .unwrap();
        assert!(profile[deny..].contains("(subpath \"/private/tmp/secret\")"));
    }

    #[test]
    fn profile_override_does_not_resolve_ignored_paths() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("loop");
        std::os::unix::fs::symlink("loop", &link).unwrap();
        let mut request = ExecutionRequest {
            seatbelt: Some(SeatbeltConfig {
                profile_override: Some("(version 1)\n(allow default)".into()),
                keychain_access: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        request.policy.denied_paths = vec![link.to_str().unwrap().into()];
        let inputs = prepare_profile(&request).unwrap();
        let profile = build_profile_with_proxy(&request, None, &inputs).unwrap();
        assert_eq!(profile, "(version 1)\n(allow default)");
    }

    #[test]
    fn keychains_under_a_symlinked_home_use_the_real_path() {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        fs::create_dir(root.join("real-home")).unwrap();
        let home = root.join("home");
        std::os::unix::fs::symlink("real-home", &home).unwrap();
        assert_eq!(
            user_keychains_dir(home.to_str().unwrap()).unwrap(),
            root.join("real-home/Library/Keychains").to_str().unwrap()
        );
    }

    #[test]
    fn only_a_root_owned_unwritable_dir_is_trusted() {
        assert!(dir_is_root_controlled(0, 0o755));
        assert!(dir_is_root_controlled(0, 0o700));
        for mode in [0o775, 0o757, 0o777, 0o1777] {
            assert!(!dir_is_root_controlled(0, mode), "mode {mode:o}");
        }
        for uid in [1, 501, 1000] {
            assert!(!dir_is_root_controlled(uid, 0o755), "uid {uid}");
        }
    }

    #[test]
    fn a_link_the_caller_controls_is_not_trusted() {
        use std::os::unix::fs::{symlink, MetadataExt as _};

        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("target")).unwrap();
        let link = dir.path().join("link");
        symlink(dir.path().join("target"), &link).unwrap();
        if fs::metadata(dir.path()).unwrap().uid() != 0 {
            assert!(!link_is_root_controlled(&link));
        }
        let plain = dir.path().join("plain");
        fs::write(&plain, "").unwrap();
        assert!(!link_is_root_controlled(&plain));
        assert!(!link_is_root_controlled(&dir.path().join("missing")));
    }

    #[test]
    fn the_real_xcode_select_links_are_trusted_when_present() {
        for link in DEVELOPER_DIR_LINKS.iter().map(Path::new) {
            if fs::symlink_metadata(link).is_ok() {
                assert!(
                    link_is_root_controlled(link),
                    "rejected a stock link: {}",
                    link.display()
                );
            }
        }
    }

    #[test]
    fn developer_directory_grants_cover_only_the_enclosing_xcode_bundle() {
        for (dir, expected) in [
            (
                "/Applications/Xcode_26.6.app/Contents/Developer",
                "/Applications/Xcode_26.6.app",
            ),
            (
                "/Library/Developer/CommandLineTools",
                "/Library/Developer/CommandLineTools",
            ),
            (
                "/Applications/Xcode.APP/Contents/Developer",
                "/Applications/Xcode.APP",
            ),
            (
                "/Applications/Xcode-beta.app/Contents/Developer",
                "/Applications/Xcode-beta.app",
            ),
            (
                "/Volumes/Build/Xcode.app/Contents/Developer",
                "/Volumes/Build/Xcode.app",
            ),
            (
                "/Applications/Evil.app/Contents/Developer/usr/bin",
                "/Applications/Evil.app/Contents/Developer/usr/bin",
            ),
            (
                "/Applications/Evil.app/a/b/Developer",
                "/Applications/Evil.app/a/b/Developer",
            ),
            (
                "/Applications/Evil.app/Contents/Developer2",
                "/Applications/Evil.app/Contents/Developer2",
            ),
            (
                "/Applications/Xcode.app/Contents/Developer/",
                "/Applications/Xcode.app",
            ),
            (
                "/Applications/Xcode.app/Contents//Developer",
                "/Applications/Xcode.app",
            ),
            (
                "/Applications/Xcode.app/Contents/./Developer",
                "/Applications/Xcode.app",
            ),
            (
                "/Applications/Xcode.app/Contents/Developer/..",
                "/Applications/Xcode.app/Contents/Developer/..",
            ),
        ] {
            assert_eq!(
                developer_dir_grant_root(Path::new(dir)),
                Path::new(expected)
            );
        }
    }

    #[test]
    fn baseline_profile_grants_the_active_developer_dir() {
        let Some(dir) = active_developer_dir() else {
            return;
        };
        let request = ExecutionRequest::default();
        let inputs = prepare_profile(&request).unwrap();
        let profile = build_profile_with_proxy(&request, None, &inputs).unwrap();
        let granted = developer_dir_grant_root(&dir);
        assert!(profile.contains(&format!("(subpath \"{}\")", granted.display())));
    }
}
