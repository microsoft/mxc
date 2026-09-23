// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build-only helpers for locating and staging NVX artifacts.

use std::io;
use std::path::{Path, PathBuf};

use nvx_common::{WINDOWS_PLATFORM_ARTIFACTS, WORKLOAD_IMAGE_ARTIFACTS};

/// The only supported NVX package target triple.
pub const SUPPORTED_NVX_TARGET_TRIPLE: &str = "x86_64-pc-windows-msvc";

/// Category of an NVX release artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactKind {
    /// OpenVMM and guest boot artifacts.
    Platform,
    /// Optional workload filesystem images.
    WorkloadImage,
}

/// Returns every relative path in a complete NVX artifact bundle.
pub fn artifact_rel_paths() -> impl Iterator<Item = (ArtifactKind, &'static str)> {
    WINDOWS_PLATFORM_ARTIFACTS
        .into_iter()
        .map(|path| (ArtifactKind::Platform, path))
        .chain(
            WORKLOAD_IMAGE_ARTIFACTS
                .into_iter()
                .map(|path| (ArtifactKind::WorkloadImage, path)),
        )
}

/// Returns whether the NVX artifact pipeline supports the given target.
///
/// NVX packaging is intentionally restricted to the Windows x86_64 MSVC
/// target. That is the only target that is allowed to download, verify, and
/// stage the pinned WHP artifacts.
pub fn target_supports_nvx(target_os: &str, target_arch: &str, target_env: &str) -> bool {
    target_os == "windows" && target_arch == "x86_64" && target_env == "msvc"
}

/// Returns `Ok(())` for the only supported NVX target, or a clear error
/// message for anything else.
pub fn validate_nvx_target(
    target: &str,
    target_os: &str,
    target_arch: &str,
    target_env: &str,
) -> Result<(), String> {
    if target == SUPPORTED_NVX_TARGET_TRIPLE
        && target_supports_nvx(target_os, target_arch, target_env)
    {
        Ok(())
    } else {
        Err(unsupported_target_message(target))
    }
}

/// Determines whether an executor build should stage NVX artifacts.
///
/// Non-Windows targets do not package NVX. Windows targets must be the exact
/// supported x64 MSVC triple; unsupported Windows targets fail instead of
/// silently producing an incomplete NVX-enabled executor.
pub fn should_stage_nvx(
    target: &str,
    target_os: &str,
    target_arch: &str,
    target_env: &str,
) -> Result<bool, String> {
    if target_os != "windows" {
        return Ok(false);
    }

    validate_nvx_target(target, target_os, target_arch, target_env)?;
    Ok(true)
}

/// Formats the explicit error message used when NVX is requested for an
/// unsupported target.
pub fn unsupported_target_message(target: &str) -> String {
    format!(
        "nvx packaging is only supported for target {SUPPORTED_NVX_TARGET_TRIPLE}; current target is {target}"
    )
}

/// Returns the artifacts required by the currently configured release.
pub fn available_artifact_rel_paths(
    workload_images_available: bool,
) -> impl Iterator<Item = &'static str> {
    artifact_rel_paths().filter_map(move |(kind, path)| {
        (kind == ArtifactKind::Platform
            || (kind == ArtifactKind::WorkloadImage && workload_images_available))
            .then_some(path)
    })
}

/// Resolves the artifact cache, honouring the `NVX_BIN` offline override.
///
/// The returned boolean is `true` when the caller supplied `NVX_BIN`.
pub fn resolve_bin_dir(out_dir: &Path) -> io::Result<(PathBuf, bool)> {
    let prefetched = std::env::var_os("NVX_BIN")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);

    if let Some(dir) = prefetched {
        if !dir.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "NVX_BIN is set to '{}', but that directory does not exist",
                    dir.display()
                ),
            ));
        }
        return std::path::absolute(&dir).map(|absolute| (absolute, true));
    }

    let dir = out_dir.join("nvx-binaries");
    std::fs::create_dir_all(&dir)?;
    Ok((dir, false))
}

/// Copies selected artifacts while preserving their release-relative paths.
///
/// Missing artifacts and copy failures are returned as explicit errors. The
/// destination file is removed after a failed copy so a partial artifact is
/// never left staged.
pub fn copy_artifact_paths<'a>(
    src_dir: &Path,
    target_dir: &Path,
    relative_paths: impl IntoIterator<Item = &'a str>,
) -> io::Result<()> {
    let relative_paths: Vec<&str> = relative_paths.into_iter().collect();
    validate_artifact_paths(src_dir, relative_paths.iter().copied())?;
    copy_validated_artifact_paths(src_dir, target_dir, relative_paths)
}

fn validate_artifact_paths<'a>(
    src_dir: &Path,
    relative_paths: impl IntoIterator<Item = &'a str>,
) -> io::Result<()> {
    for relative_path in relative_paths {
        let source = src_dir.join(relative_path);
        if !source.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("required NVX artifact '{}' is missing", source.display()),
            ));
        }
    }
    Ok(())
}

fn copy_validated_artifact_paths<'a>(
    src_dir: &Path,
    target_dir: &Path,
    relative_paths: impl IntoIterator<Item = &'a str>,
) -> io::Result<()> {
    for relative_path in relative_paths {
        let source = src_dir.join(relative_path);
        let destination = target_dir.join(relative_path);
        let parent = destination.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "NVX artifact '{}' has no destination parent",
                    destination.display()
                ),
            )
        })?;
        std::fs::create_dir_all(parent)?;

        if let Err(error) = std::fs::copy(&source, &destination) {
            let _ = std::fs::remove_file(&destination);
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "failed to copy NVX artifact '{}' to '{}': {error}",
                    source.display(),
                    destination.display()
                ),
            ));
        }
    }
    Ok(())
}

fn remove_artifact_paths<'a>(
    target_dir: &Path,
    relative_paths: impl IntoIterator<Item = &'a str>,
) -> io::Result<()> {
    for relative_path in relative_paths {
        let destination = target_dir.join(relative_path);
        match std::fs::remove_file(&destination) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!(
                        "failed to remove stale NVX artifact '{}': {error}",
                        destination.display()
                    ),
                ))
            }
        }
    }
    Ok(())
}

/// Stages all artifacts available in the configured release.
pub fn copy_artifacts_to_target(
    src_dir: &Path,
    target_dir: &Path,
    workload_images_available: bool,
) -> io::Result<()> {
    let relative_paths: Vec<&str> =
        available_artifact_rel_paths(workload_images_available).collect();
    validate_artifact_paths(src_dir, relative_paths.iter().copied())?;

    if !workload_images_available {
        remove_artifact_paths(target_dir, WORKLOAD_IMAGE_ARTIFACTS)?;
    }

    copy_validated_artifact_paths(src_dir, target_dir, relative_paths)
}

/// Emits Cargo change tracking for every artifact available in this release.
pub fn emit_rerun_for_artifacts(src_dir: &Path, workload_images_available: bool) {
    for relative_path in available_artifact_rel_paths(workload_images_available) {
        println!(
            "cargo:rerun-if-changed={}",
            src_dir.join(relative_path).display()
        );
    }
}

/// Stages NVX artifacts beside the consuming executable.
pub fn stage_artifacts_next_to_exe(nvx_bin_dir: &Path) -> io::Result<()> {
    let workload_images_available =
        match std::env::var("DEP_NVX_BINARIES_WORKLOAD_IMAGES_AVAILABLE").as_deref() {
            Ok("1") => true,
            Ok("0") => false,
            Ok(value) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "DEP_NVX_BINARIES_WORKLOAD_IMAGES_AVAILABLE has invalid value '{value}'"
                    ),
                ))
            }
            Err(std::env::VarError::NotPresent) => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "DEP_NVX_BINARIES_WORKLOAD_IMAGES_AVAILABLE is not set",
                ))
            }
            Err(error) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("cannot read DEP_NVX_BINARIES_WORKLOAD_IMAGES_AVAILABLE: {error}"),
                ))
            }
        };
    let out_dir = PathBuf::from(
        std::env::var_os("OUT_DIR")
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "OUT_DIR is not set"))?,
    );
    let target_dir = out_dir
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "cannot determine target directory from '{}'",
                    out_dir.display()
                ),
            )
        })?;

    copy_artifacts_to_target(nvx_bin_dir, target_dir, workload_images_available)?;
    emit_rerun_for_artifacts(nvx_bin_dir, workload_images_available);
    println!("cargo:rerun-if-env-changed=DEP_NVX_BINARIES_BIN_DIR");
    println!("cargo:rerun-if-env-changed=DEP_NVX_BINARIES_WORKLOAD_IMAGES_AVAILABLE");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_artifact(root: &Path, relative_path: &str, contents: &[u8]) {
        let path = root.join(relative_path);
        std::fs::create_dir_all(path.parent().expect("artifact must have a parent"))
            .expect("failed to create artifact parent");
        std::fs::write(path, contents).expect("failed to write artifact");
    }

    #[test]
    fn artifact_paths_cover_complete_bundle_in_release_order() {
        assert_eq!(
            artifact_rel_paths().collect::<Vec<_>>(),
            vec![
                (ArtifactKind::Platform, "bin/openvmm.exe"),
                (ArtifactKind::Platform, "guest/vmlinux"),
                (ArtifactKind::Platform, "guest/initramfs.cpio.gz"),
                (ArtifactKind::WorkloadImage, "images/distro.erofs"),
                (ArtifactKind::WorkloadImage, "images/runtime.erofs"),
                (ArtifactKind::WorkloadImage, "images/scratch.ext4"),
            ]
        );
    }

    #[test]
    fn copy_artifacts_preserves_release_layout() {
        let source = tempfile::tempdir().expect("failed to create source directory");
        let target = tempfile::tempdir().expect("failed to create target directory");
        for relative_path in WINDOWS_PLATFORM_ARTIFACTS {
            write_artifact(source.path(), relative_path, relative_path.as_bytes());
        }
        for relative_path in WORKLOAD_IMAGE_ARTIFACTS {
            write_artifact(target.path(), relative_path, b"stale");
        }

        copy_artifacts_to_target(source.path(), target.path(), false)
            .expect("platform-only staging failed");

        for relative_path in WINDOWS_PLATFORM_ARTIFACTS {
            assert_eq!(
                std::fs::read(target.path().join(relative_path))
                    .expect("staged artifact is missing"),
                relative_path.as_bytes()
            );
        }
        for relative_path in WORKLOAD_IMAGE_ARTIFACTS {
            assert!(!target.path().join(relative_path).exists());
        }
    }

    #[test]
    fn complete_bundle_requires_every_workload_image() {
        let source = tempfile::tempdir().expect("failed to create source directory");
        let target = tempfile::tempdir().expect("failed to create target directory");
        for relative_path in WINDOWS_PLATFORM_ARTIFACTS {
            write_artifact(source.path(), relative_path, b"platform");
        }
        for relative_path in WORKLOAD_IMAGE_ARTIFACTS {
            write_artifact(target.path(), relative_path, b"existing");
        }

        let error = copy_artifacts_to_target(source.path(), target.path(), true)
            .expect_err("missing workload images must fail");

        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(error.to_string().contains("images/distro.erofs"));
        for relative_path in WINDOWS_PLATFORM_ARTIFACTS {
            assert!(!target.path().join(relative_path).exists());
        }
        for relative_path in WORKLOAD_IMAGE_ARTIFACTS {
            assert_eq!(
                std::fs::read(target.path().join(relative_path))
                    .expect("failed staging must preserve existing artifacts"),
                b"existing"
            );
        }
    }

    #[test]
    fn target_support_only_allows_windows_x86_64_msvc() {
        assert!(target_supports_nvx("windows", "x86_64", "msvc"));
        assert!(!target_supports_nvx("windows", "x86_64", "gnu"));
        assert!(!target_supports_nvx("windows", "aarch64", "msvc"));
        assert!(!target_supports_nvx("linux", "x86_64", "gnu"));
    }

    #[test]
    fn unsupported_target_message_names_supported_triple() {
        let message = unsupported_target_message("aarch64-pc-windows-msvc");

        assert!(message.contains(SUPPORTED_NVX_TARGET_TRIPLE));
        assert!(message.contains("aarch64-pc-windows-msvc"));
    }

    #[test]
    fn validate_nvx_target_rejects_unsupported_target() {
        let error = validate_nvx_target("aarch64-pc-windows-msvc", "windows", "aarch64", "msvc")
            .expect_err("unsupported target must fail closed");

        assert!(error.contains(SUPPORTED_NVX_TARGET_TRIPLE));
        assert!(error.contains("aarch64-pc-windows-msvc"));
    }

    #[test]
    fn validate_nvx_target_rejects_custom_target_with_matching_cfg_values() {
        let target = "custom-windows-x64-msvc";
        let error = validate_nvx_target(target, "windows", "x86_64", "msvc")
            .expect_err("only the exact supported target triple may stage NVX");

        assert!(error.contains(SUPPORTED_NVX_TARGET_TRIPLE));
        assert!(error.contains(target));
    }

    #[test]
    fn staging_decision_uses_target_not_build_host() {
        assert_eq!(
            should_stage_nvx("x86_64-pc-windows-msvc", "windows", "x86_64", "msvc"),
            Ok(true)
        );
        assert_eq!(
            should_stage_nvx("x86_64-unknown-linux-gnu", "linux", "x86_64", "gnu"),
            Ok(false)
        );

        for (target, arch, env) in [
            ("aarch64-pc-windows-msvc", "aarch64", "msvc"),
            ("x86_64-pc-windows-gnu", "x86_64", "gnu"),
            ("custom-windows-x64-msvc", "x86_64", "msvc"),
        ] {
            let error = should_stage_nvx(target, "windows", arch, env)
                .expect_err("unsupported Windows targets must fail closed");
            assert!(error.contains(SUPPORTED_NVX_TARGET_TRIPLE));
            assert!(error.contains(target));
        }
    }
}
