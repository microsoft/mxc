// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::ffi::OsStr;
use std::fmt;
use std::path::{Path, PathBuf};

// A desktop session's PATH often leaves out the sbin directories that hold
// iptables. The order matches the usual root PATH.
pub(crate) const FALLBACK_DIRECTORIES: [&str; 6] = [
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LookupError {
    NotFound,
    NotExecutable(PathBuf),
}

impl fmt::Display for LookupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(
                f,
                "was not found on PATH or in {}",
                FALLBACK_DIRECTORIES.join(", ")
            ),
            Self::NotExecutable(path) => {
                write!(f, "was found at {} but is not executable", path.display())
            }
        }
    }
}

pub(crate) fn find(name: &str) -> Result<PathBuf, LookupError> {
    find_in(
        name,
        std::env::var_os("PATH").as_deref(),
        &FALLBACK_DIRECTORIES.map(Path::new),
    )
}

fn find_in(name: &str, path: Option<&OsStr>, fallback: &[&Path]) -> Result<PathBuf, LookupError> {
    let mut not_executable = None;
    for directory in search_order(path, fallback) {
        let candidate = directory.join(name);
        if !std::fs::metadata(&candidate).is_ok_and(|metadata| metadata.is_file()) {
            continue;
        }
        if is_executable(&candidate) {
            return Ok(candidate);
        }
        not_executable.get_or_insert(candidate);
    }
    Err(not_executable.map_or(LookupError::NotFound, LookupError::NotExecutable))
}

fn search_order(path: Option<&OsStr>, fallback: &[&Path]) -> Vec<PathBuf> {
    let inherited = path.into_iter().flat_map(std::env::split_paths);
    let mut directories: Vec<PathBuf> = Vec::new();
    for directory in inherited.chain(fallback.iter().map(|directory| directory.to_path_buf())) {
        // Empty and relative entries resolve against the current directory,
        // which a host tool must never come from.
        if directory.is_absolute() && !directories.contains(&directory) {
            directories.push(directory);
        }
    }
    directories
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    nix::unistd::access(path, nix::unistd::AccessFlags::X_OK).is_ok()
}

// Bubblewrap runs only on Linux, so elsewhere no file counts as executable.
#[cfg(not(unix))]
fn is_executable(_path: &Path) -> bool {
    false
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn install(directory: &Path, name: &str, mode: u32) -> PathBuf {
        let path = directory.join(name);
        std::fs::write(&path, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    fn joined(directories: &[&Path]) -> std::ffi::OsString {
        std::env::join_paths(directories).unwrap()
    }

    #[test]
    fn a_tool_missing_from_path_is_found_in_a_fallback_directory() {
        let on_path = tempfile::tempdir().unwrap();
        let fallback = tempfile::tempdir().unwrap();
        let iptables = install(fallback.path(), "iptables", 0o755);

        assert_eq!(
            find_in(
                "iptables",
                Some(&joined(&[on_path.path()])),
                &[fallback.path()]
            ),
            Ok(iptables)
        );
    }

    #[test]
    fn a_tool_on_path_wins_over_the_fallback_directories() {
        let on_path = tempfile::tempdir().unwrap();
        let fallback = tempfile::tempdir().unwrap();
        let preferred = install(on_path.path(), "iptables", 0o755);
        install(fallback.path(), "iptables", 0o755);

        assert_eq!(
            find_in(
                "iptables",
                Some(&joined(&[on_path.path()])),
                &[fallback.path()]
            ),
            Ok(preferred)
        );
    }

    #[test]
    fn path_entries_are_searched_in_order() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        install(second.path(), "bwrap", 0o755);
        let preferred = install(first.path(), "bwrap", 0o755);

        assert_eq!(
            find_in("bwrap", Some(&joined(&[first.path(), second.path()])), &[]),
            Ok(preferred)
        );
    }

    #[test]
    fn an_absent_path_searches_only_the_fallback_directories() {
        let fallback = tempfile::tempdir().unwrap();
        let bwrap = install(fallback.path(), "bwrap", 0o755);

        assert_eq!(find_in("bwrap", None, &[fallback.path()]), Ok(bwrap));
    }

    #[test]
    fn empty_and_relative_path_entries_are_skipped() {
        let fallback = tempfile::tempdir().unwrap();

        assert_eq!(
            search_order(
                Some(OsStr::new(":.:bin:/usr/bin::/usr/bin")),
                &[Path::new("/usr/bin"), fallback.path()]
            ),
            [PathBuf::from("/usr/bin"), fallback.path().to_path_buf()]
        );
    }

    #[test]
    fn an_executable_copy_is_preferred_over_an_earlier_unexecutable_file() {
        let first = tempfile::tempdir().unwrap();
        let fallback = tempfile::tempdir().unwrap();
        install(first.path(), "nsenter", 0o644);
        let executable = install(fallback.path(), "nsenter", 0o755);

        assert_eq!(
            find_in(
                "nsenter",
                Some(&joined(&[first.path()])),
                &[fallback.path()]
            ),
            Ok(executable)
        );
    }

    #[test]
    fn an_unexecutable_file_is_reported_rather_than_missing() {
        let first = tempfile::tempdir().unwrap();
        let unexecutable = install(first.path(), "nsenter", 0o644);

        let error = find_in("nsenter", Some(&joined(&[first.path()])), &[]).unwrap_err();
        assert_eq!(error, LookupError::NotExecutable(unexecutable.clone()));
        assert!(
            error
                .to_string()
                .contains(&unexecutable.display().to_string()),
            "{error}"
        );
    }

    #[test]
    fn a_directory_with_the_tool_name_is_skipped() {
        let first = tempfile::tempdir().unwrap();
        let fallback = tempfile::tempdir().unwrap();
        std::fs::create_dir(first.path().join("ip")).unwrap();
        let ip = install(fallback.path(), "ip", 0o755);

        assert_eq!(
            find_in("ip", Some(&joined(&[first.path()])), &[fallback.path()]),
            Ok(ip)
        );
    }

    /// Multi-call binaries such as `xtables-nft-multi` choose what to run from
    /// the name they were started as.
    #[test]
    fn a_symlink_is_returned_as_the_link_rather_than_its_target() {
        let directory = tempfile::tempdir().unwrap();
        install(directory.path(), "xtables-nft-multi", 0o755);
        let link = directory.path().join("iptables-restore");
        std::os::unix::fs::symlink("xtables-nft-multi", &link).unwrap();

        assert_eq!(
            find_in("iptables-restore", Some(&joined(&[directory.path()])), &[]),
            Ok(link)
        );
    }

    #[test]
    fn a_tool_in_no_directory_is_not_found() {
        let empty = tempfile::tempdir().unwrap();

        let error = find_in("slirp4netns", Some(&joined(&[empty.path()])), &[]).unwrap_err();
        assert_eq!(error, LookupError::NotFound);
        for directory in FALLBACK_DIRECTORIES {
            assert!(error.to_string().contains(directory), "{error}");
        }
    }
}
