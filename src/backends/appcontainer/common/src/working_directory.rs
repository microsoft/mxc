// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Working-directory resolution shared by the two Windows ProcessContainer
//! launch paths (`AppContainerScriptRunner` -> `CreateProcessW` and
//! `BaseContainerRunner` -> `Experimental_CreateProcessInSandbox`).
//!
//! Both launch APIs treat a `NULL` current directory as "inherit the parent's
//! cwd". Under a deny-by-default sandbox token that directory is usually not
//! openable, and the kernel then silently restarts the child at the drive root
//! instead of failing the launch — a confusing, unlogged relocation.
//!
//! [`launch_working_directory`] therefore always yields a concrete directory,
//! so neither runner ever passes `NULL`. Keeping the mapping here (rather than
//! inline at each launch site) means it is covered by ordinary unit tests that
//! need no prepared host, and that the two runners cannot drift apart.

use wxc_common::models::{ExecutionRequest, WorkingDirectorySource};

/// Drive root used when neither `process.cwd` nor the filesystem policy yields
/// a usable directory. Matches what `wxc-host-prep prepare-system-drive` grants
/// sandbox tokens traverse access to.
const DEFAULT_DRIVE_ROOT: &str = "C:\\";

/// Where the launch working directory came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchCwdSource {
    /// The caller's explicit `process.cwd`.
    Explicit,
    /// The first filesystem-policy grant that is an existing directory.
    Policy,
    /// The drive root, because nothing else was usable.
    DriveRoot,
}

impl LaunchCwdSource {
    /// Short phrase naming the origin, for log lines and launch errors.
    pub fn describe(self) -> &'static str {
        match self {
            Self::Explicit => "process.cwd",
            Self::Policy => "filesystem policy (process.cwd omitted)",
            Self::DriveRoot => "drive-root fallback (no usable process.cwd or policy directory)",
        }
    }
}

/// The current directory to hand to the launch API, and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchWorkingDirectory {
    /// The directory to launch in. **Never empty**, so callers always pass a
    /// non-`NULL` pointer.
    pub path: String,
    /// Origin of `path`, for diagnostics.
    pub source: LaunchCwdSource,
}

impl LaunchWorkingDirectory {
    /// One-line description for logs and error context, e.g.
    /// `C:\workspace (from filesystem policy (process.cwd omitted))`.
    pub fn describe(&self) -> String {
        format!("{} (from {})", self.path, self.source.describe())
    }
}

/// Resolve the current directory for a ProcessContainer launch.
///
/// Precedence: explicit `process.cwd`, else the first filesystem-policy grant
/// that is an existing directory, else the system drive root. The result is
/// never empty — passing `NULL` to `CreateProcessW` /
/// `Experimental_CreateProcessInSandbox` would silently relocate the child.
pub fn launch_working_directory(request: &ExecutionRequest) -> LaunchWorkingDirectory {
    launch_working_directory_with(
        request,
        |path| std::path::Path::new(path).is_dir(),
        &system_drive_root(),
    )
}

/// [`launch_working_directory`] with the filesystem probe and drive root
/// injected, so unit tests cover the mapping without touching the host.
pub fn launch_working_directory_with(
    request: &ExecutionRequest,
    is_dir: impl Fn(&str) -> bool,
    drive_root: &str,
) -> LaunchWorkingDirectory {
    match request.resolved_working_directory_with(is_dir) {
        Some(resolved) => LaunchWorkingDirectory {
            path: resolved.path.to_string(),
            source: match resolved.source {
                WorkingDirectorySource::Explicit => LaunchCwdSource::Explicit,
                WorkingDirectorySource::Policy => LaunchCwdSource::Policy,
            },
        },
        None => LaunchWorkingDirectory {
            path: drive_root.to_string(),
            source: LaunchCwdSource::DriveRoot,
        },
    }
}

/// The system drive root (`%SystemDrive%\`), falling back to `C:\` when the
/// variable is unset or malformed.
fn system_drive_root() -> String {
    match std::env::var("SystemDrive") {
        Ok(drive) if drive.trim().len() >= 2 && drive.trim().ends_with(':') => {
            format!("{}\\", drive.trim())
        }
        _ => DEFAULT_DRIVE_ROOT.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::models::ContainerPolicy;

    fn request(cwd: &str, readwrite: &[&str], readonly: &[&str]) -> ExecutionRequest {
        ExecutionRequest {
            working_directory: cwd.to_string(),
            policy: ContainerPolicy {
                readwrite_paths: readwrite.iter().map(|s| s.to_string()).collect(),
                readonly_paths: readonly.iter().map(|s| s.to_string()).collect(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn resolve(request: &ExecutionRequest, dirs: &[&str]) -> LaunchWorkingDirectory {
        launch_working_directory_with(request, |path| dirs.contains(&path), "C:\\")
    }

    #[test]
    fn explicit_cwd_wins() {
        let req = request("C:\\explicit", &["C:\\rw"], &[]);
        let resolved = resolve(&req, &["C:\\explicit", "C:\\rw"]);
        assert_eq!(resolved.path, "C:\\explicit");
        assert_eq!(resolved.source, LaunchCwdSource::Explicit);
    }

    #[test]
    fn empty_cwd_falls_back_to_first_granted_directory() {
        let req = request("", &["C:\\rw1", "C:\\rw2"], &["C:\\ro"]);
        let resolved = resolve(&req, &["C:\\rw1", "C:\\rw2", "C:\\ro"]);
        assert_eq!(resolved.path, "C:\\rw1");
        assert_eq!(resolved.source, LaunchCwdSource::Policy);
    }

    #[test]
    fn empty_cwd_falls_back_to_readonly_when_no_readwrite() {
        let req = request("", &[], &["C:\\ro1"]);
        let resolved = resolve(&req, &["C:\\ro1"]);
        assert_eq!(resolved.path, "C:\\ro1");
        assert_eq!(resolved.source, LaunchCwdSource::Policy);
    }

    /// REGRESSION GUARD: the empty-policy case must not reintroduce a `NULL`
    /// current directory. Runs everywhere — no prepared host required.
    #[test]
    fn empty_policy_and_empty_cwd_never_yields_an_empty_path() {
        let req = request("", &[], &[]);
        let resolved = resolve(&req, &[]);
        assert!(!resolved.path.is_empty(), "cwd must never be empty (NULL)");
        assert_eq!(resolved.path, "C:\\");
        assert_eq!(resolved.source, LaunchCwdSource::DriveRoot);
    }

    /// A blank first entry is accepted by filesystem validation, so it must not
    /// be selected and turned back into a `NULL` pointer.
    #[test]
    fn blank_policy_entry_is_skipped() {
        let req = request("", &["", "C:\\workspace"], &[]);
        let resolved = resolve(&req, &["C:\\workspace"]);
        assert_eq!(resolved.path, "C:\\workspace");
        assert_eq!(resolved.source, LaunchCwdSource::Policy);
    }

    /// Policy grants may name files; launching in one fails with
    /// `ERROR_DIRECTORY`, so the next usable directory is chosen instead.
    #[test]
    fn policy_file_entry_is_skipped() {
        let req = request("", &["C:\\inputs\\config.json"], &["C:\\ro"]);
        let resolved = resolve(&req, &["C:\\ro"]);
        assert_eq!(resolved.path, "C:\\ro");
    }

    /// When every grant is unusable the drive root keeps the launch valid
    /// rather than failing a config that previously worked.
    #[test]
    fn unusable_policy_paths_fall_back_to_the_drive_root() {
        let req = request("", &["C:\\inputs\\config.json"], &["D:\\not-yet"]);
        let resolved = resolve(&req, &[]);
        assert_eq!(resolved.path, "C:\\");
        assert_eq!(resolved.source, LaunchCwdSource::DriveRoot);
    }

    #[test]
    fn drive_root_override_is_honored() {
        let req = request("", &[], &[]);
        let resolved = launch_working_directory_with(&req, |_| false, "D:\\");
        assert_eq!(resolved.path, "D:\\");
    }

    #[test]
    fn describe_names_the_origin() {
        let req = request("", &["C:\\rw"], &[]);
        assert_eq!(
            resolve(&req, &["C:\\rw"]).describe(),
            "C:\\rw (from filesystem policy (process.cwd omitted))"
        );
    }

    /// The real resolver must satisfy the same never-`NULL` guarantee as the
    /// injected-probe variant.
    #[test]
    fn real_resolver_never_yields_an_empty_path() {
        let req = request("", &[], &[]);
        assert!(!launch_working_directory(&req).path.is_empty());
    }

    #[test]
    fn system_drive_root_is_an_absolute_root() {
        let root = system_drive_root();
        assert!(
            root.ends_with('\\'),
            "expected a trailing separator: {root}"
        );
        assert!(root.len() >= 3, "expected a drive root: {root}");
    }
}
