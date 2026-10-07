// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared build-time helpers for embedding Windows VersionInfo metadata in MXC binaries.
//!
//! Stamps `ProductName`, `FileDescription`, `OriginalFilename`, and
//! `ProductVersion` (with the git commit hash) into MXC PE executables and libraries.

// This source-included helper is also compiled by binaries that do not expose
// the lifted feature, so their Cargo manifests cannot declare this cfg value.
#![allow(unexpected_cfgs)]

use std::io;
use std::path::Path;
use std::process::Command;

#[cfg(all(windows, feature = "isolation_session_lifted"))]
pub mod isolation_session_sdk {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    mod package_validation {
        include!("isolation_session_bindings/package_validation.rs");
    }

    use package_validation::{
        package_file_name, package_runtime_instance, validate_runtime_architecture,
        validate_runtime_manifest,
    };

    pub const PACKAGE_ID: &str = "Microsoft.AI.IsolationSession.SDK";
    pub const PACKAGE_VERSION: &str = "0.202610.5";
    pub const PACKAGE_SHA256: &str =
        "b387c9d11808bf8864d3d7e4d6924f79bdcd6e7c4c54c4e2e49ab0e3525b3d2e";
    pub const PACKAGE_PATH_ENV: &str = "ISOLATION_SESSION_SDK_PACKAGE";

    const RESTORE_PROJECT: &str = "IsolationSessionSdk.Restore.csproj";
    const NUGET_CONFIG: &str = "NuGet.Config";
    const APP_DLL: &str = "IsoSessionApp.dll";
    const RUNTIME_MANIFEST: &str = "IsoSession.manifest";

    pub fn resolve_package() -> Result<PathBuf, String> {
        println!("cargo:rerun-if-env-changed={PACKAGE_PATH_ENV}");

        if let Ok(value) = std::env::var(PACKAGE_PATH_ENV) {
            let path = PathBuf::from(value);
            verify_package(&path)?;
            println!("cargo:rerun-if-changed={}", path.display());
            return Ok(path);
        }

        let package_name = package_file_name(PACKAGE_ID, PACKAGE_VERSION);
        let package_dir = mxc_nuget_cache_root()?
            .join(PACKAGE_ID.to_ascii_lowercase())
            .join(PACKAGE_VERSION);
        let package_path = package_dir.join(&package_name);

        if package_path.exists() {
            verify_package(&package_path)?;
            println!("cargo:rerun-if-changed={}", package_path.display());
            return Ok(package_path);
        }

        restore_package()?;
        verify_package(&package_path)?;

        println!("cargo:rerun-if-changed={}", package_path.display());
        Ok(package_path)
    }

    pub fn stage_runtime() -> Result<(), String> {
        let package = resolve_package()?;
        let app_dll = read_entry(&package, APP_DLL)?;
        let manifest = read_entry(&package, RUNTIME_MANIFEST)?;
        let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH")
            .map_err(|e| format!("CARGO_CFG_TARGET_ARCH is not set: {e}"))?;
        validate_runtime_architecture(&app_dll, &target_arch)?;
        let instance = package_runtime_instance(PACKAGE_VERSION)?;
        validate_runtime_manifest(&manifest, &instance)?;

        let target_dir = target_profile_dir()?;
        std::fs::write(target_dir.join(APP_DLL), app_dll)
            .map_err(|e| format!("stage {APP_DLL} to {}: {e}", target_dir.display()))?;
        std::fs::write(target_dir.join(RUNTIME_MANIFEST), manifest)
            .map_err(|e| format!("stage {RUNTIME_MANIFEST} to {}: {e}", target_dir.display()))?;
        Ok(())
    }

    pub fn read_entry(package: &Path, file_name: &str) -> Result<Vec<u8>, String> {
        let file = std::fs::File::open(package)
            .map_err(|e| format!("open NuGet package {}: {e}", package.display()))?;
        let mut archive = zip::ZipArchive::new(file)
            .map_err(|e| format!("read NuGet package {}: {e}", package.display()))?;
        let wanted = file_name.to_ascii_lowercase();
        let entry_name = (0..archive.len())
            .find_map(|index| {
                let name = archive.by_index(index).ok()?.name().to_string();
                let leaf = name.rsplit(['/', '\\']).next().unwrap_or(&name);
                (leaf.to_ascii_lowercase() == wanted).then_some(name)
            })
            .ok_or_else(|| {
                format!(
                    "{file_name} was not found in NuGet package {}",
                    package.display()
                )
            })?;
        let mut entry = archive
            .by_name(&entry_name)
            .map_err(|e| format!("open NuGet entry {entry_name}: {e}"))?;
        let mut bytes = Vec::new();
        entry
            .read_to_end(&mut bytes)
            .map_err(|e| format!("read NuGet entry {entry_name}: {e}"))?;
        Ok(bytes)
    }

    fn target_profile_dir() -> Result<PathBuf, String> {
        let out_dir = PathBuf::from(
            std::env::var("OUT_DIR").map_err(|e| format!("OUT_DIR is not set: {e}"))?,
        );
        out_dir
            .parent()
            .and_then(|path| path.parent())
            .and_then(|path| path.parent())
            .map(PathBuf::from)
            .ok_or_else(|| {
                format!(
                    "cannot resolve Cargo profile directory from {}",
                    out_dir.display()
                )
            })
    }

    fn mxc_nuget_cache_root() -> Result<PathBuf, String> {
        Ok(target_profile_dir()?.join(".mxc-nuget").join("packages"))
    }

    fn restore_package() -> Result<(), String> {
        let manifest_dir = PathBuf::from(
            std::env::var("CARGO_MANIFEST_DIR")
                .map_err(|e| format!("CARGO_MANIFEST_DIR is not set: {e}"))?,
        );
        let restore_inputs = restore_inputs_dir(&manifest_dir)?;
        let restore_project = restore_inputs.join(RESTORE_PROJECT);
        let nuget_config = restore_inputs.join(NUGET_CONFIG);
        let cache_root = target_profile_dir()?.join(".mxc-nuget");
        let packages_root = cache_root.join("packages");
        let restore_output = PathBuf::from(
            std::env::var("OUT_DIR").map_err(|e| format!("OUT_DIR is not set: {e}"))?,
        )
        .join("isolation-session-nuget-obj");

        println!("cargo:rerun-if-changed={}", restore_project.display());
        println!("cargo:rerun-if-changed={}", nuget_config.display());

        std::fs::create_dir_all(&cache_root).map_err(|e| {
            format!(
                "create IsolationSession NuGet restore directory {}: {e}",
                cache_root.display()
            )
        })?;

        let output = Command::new("dotnet")
            .arg("restore")
            .arg(&restore_project)
            .arg("--configfile")
            .arg(&nuget_config)
            .arg("--packages")
            .arg(&packages_root)
            .arg(format!(
                "--property:RestoreOutputPath={}",
                restore_output.display()
            ))
            .arg(format!(
                "--property:IsolationSessionSdkVersion={PACKAGE_VERSION}"
            ))
            .args(["--nologo", "--verbosity", "minimal"])
            .output()
            .map_err(|e| {
                format!(
                    "launch dotnet restore for {PACKAGE_ID} {PACKAGE_VERSION}: {e}; \
                     set {PACKAGE_PATH_ENV} to a pre-fetched package if dotnet is unavailable"
                )
            })?;

        if output.status.success() {
            return Ok(());
        }

        Err(format!(
            "restore {PACKAGE_ID} {PACKAGE_VERSION} through {} failed with {}:\n{}\n{}\
             \nSet {PACKAGE_PATH_ENV} to a pre-fetched package for an offline build.",
            nuget_config.display(),
            output.status,
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }

    fn restore_inputs_dir(manifest_dir: &Path) -> Result<PathBuf, String> {
        for ancestor in manifest_dir.ancestors() {
            for relative in [
                Path::new("build").join("isolation_session_bindings"),
                Path::new("mxc-sdk")
                    .join("build")
                    .join("isolation_session_bindings"),
            ] {
                let candidate = ancestor.join(relative);
                if candidate.join(RESTORE_PROJECT).is_file()
                    && candidate.join(NUGET_CONFIG).is_file()
                {
                    return Ok(candidate);
                }
            }
        }

        Err(format!(
            "cannot locate the shared IsolationSession NuGet restore inputs from {}",
            manifest_dir.display()
        ))
    }

    fn verify_package(path: &Path) -> Result<(), String> {
        let bytes = std::fs::read(path)
            .map_err(|e| format!("read IsolationSession SDK package {}: {e}", path.display()))?;
        let actual = Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if actual.eq_ignore_ascii_case(PACKAGE_SHA256) {
            Ok(())
        } else {
            Err(format!(
                "IsolationSession SDK package hash mismatch for {}: expected {}, got {}",
                path.display(),
                PACKAGE_SHA256,
                actual
            ))
        }
    }
}

/// Embed Windows VersionInfo resource metadata into the binary being compiled.
///
/// On non-Windows hosts and when building non-Windows targets on a Windows host
/// this is a no-op.
/// The `ProductVersion` field is set to `<cargo-pkg-version>+<short-git-hash>`
/// so that every build encodes the exact source commit.
pub fn embed_version_info(file_description: &str, original_filename: &str) {
    embed_version_info_with_manifest(file_description, original_filename, None);
}

/// Like [`embed_version_info`], but also fuses a side-by-side application
/// manifest into the binary in the **same** resource compile.
///
/// `manifest_xml`, when `Some`, is the full text of an application manifest
/// (e.g. an assembly manifest carrying `<comClass>` reg-free COM redirections).
/// It MUST be embedded in the same `winresource` compile as the version info:
/// two separate `.compile()` calls each emit a `.res` and the second linker
/// input silently clobbers the first, so the manifest and the version info have
/// to share one invocation.
///
/// On non-Windows hosts / targets the manifest is ignored (there is no PE
/// manifest resource to fuse), matching [`embed_version_info`]'s no-op shape.
pub fn embed_version_info_with_manifest(
    file_description: &str,
    original_filename: &str,
    manifest_xml: Option<&str>,
) {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");

    // Track git HEAD so the embedded commit hash updates on new commits.
    track_git_head();

    #[cfg(windows)]
    {
        if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
            embed_version_info_windows(file_description, original_filename, manifest_xml);
        }
    }

    // Suppress unused-variable warnings on non-Windows.
    #[cfg(not(windows))]
    {
        let _ = (file_description, original_filename, manifest_xml);
    }
}

/// Embed Windows VersionInfo metadata into one binary target in this package.
#[allow(dead_code)]
pub fn embed_version_info_for_binary(
    binary_name: &str,
    file_description: &str,
    original_filename: &str,
) -> io::Result<()> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");
    track_git_head();

    #[cfg(windows)]
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        return embed_version_info_for_binary_windows(
            binary_name,
            file_description,
            original_filename,
        );
    }

    #[cfg(not(windows))]
    let _ = (binary_name, file_description, original_filename);

    Ok(())
}

#[cfg(windows)]
fn embed_version_info_windows(
    file_description: &str,
    original_filename: &str,
    manifest_xml: Option<&str>,
) {
    let mut resource = version_resource(file_description, original_filename);
    if let Some(xml) = manifest_xml {
        resource.set_manifest(xml);
    }
    resource
        .compile()
        .expect("failed to embed Windows version info");
}

#[cfg(windows)]
#[allow(dead_code)]
fn embed_version_info_for_binary_windows(
    binary_name: &str,
    file_description: &str,
    original_filename: &str,
) -> io::Result<()> {
    let output_dir = Path::new(
        &std::env::var_os("OUT_DIR")
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "OUT_DIR is not set"))?,
    )
    .join(format!("{binary_name}-resource"));
    std::fs::create_dir_all(&output_dir)?;

    let resource_path = output_dir.join("resource.rc");
    let compiled_path = output_dir.join("resource.res");
    version_resource(file_description, original_filename).write_resource_file(&resource_path)?;

    let target =
        std::env::var("TARGET").map_err(|error| io::Error::new(io::ErrorKind::NotFound, error))?;
    let mut compiler = if let Some(path) = std::env::var_os("RC_PATH") {
        Command::new(path)
    } else {
        cc::windows_registry::find(&target, "rc.exe").ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("could not locate rc.exe for target {target}"),
            )
        })?
    };
    let output = compiler
        .arg("/nologo")
        .arg(format!("/fo{}", compiled_path.display()))
        .arg(&resource_path)
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "rc.exe failed for {binary_name}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    println!(
        "cargo:rustc-link-arg-bin={binary_name}={}",
        compiled_path.display()
    );
    Ok(())
}

#[cfg(windows)]
fn version_resource(
    file_description: &str,
    original_filename: &str,
) -> winresource::WindowsResource {
    const PRODUCT_NAME: &str = "Microsoft Execution Containers";

    let version = std::env::var("CARGO_PKG_VERSION").unwrap();
    let commit = git_short_hash();

    let mut resource = winresource::WindowsResource::new();
    if original_filename.to_ascii_lowercase().ends_with(".dll") {
        resource.set_version_info(winresource::VersionInfo::FILETYPE, 2);
    }
    resource
        .set("CompanyName", "Microsoft Corporation")
        .set("ProductName", PRODUCT_NAME)
        .set("FileDescription", file_description)
        .set("OriginalFilename", original_filename)
        .set("ProductVersion", &format!("{version}+{commit}"))
        .set(
            "LegalCopyright",
            "\u{00a9} Microsoft Corporation. All rights reserved.",
        );
    resource
}

/// Return the short git commit hash, or `"unknown"` when git is unavailable.
#[cfg(windows)]
fn git_short_hash() -> String {
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Emit `cargo:rerun-if-changed` directives for `.git/HEAD` and the ref it
/// points to, so Cargo re-runs the build script when the commit changes.
fn track_git_head() {
    let git_dir = Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

    let git_dir = match git_dir {
        Some(d) => d,
        None => return,
    };

    let git_dir_path = Path::new(&git_dir);
    let head = git_dir_path.join("HEAD");
    if head.exists() {
        println!("cargo:rerun-if-changed={}", head.display());

        if let Ok(content) = std::fs::read_to_string(&head) {
            if let Some(ref_path) = content.strip_prefix("ref: ") {
                let ref_file = git_dir_path.join(ref_path.trim());
                if ref_file.exists() {
                    println!("cargo:rerun-if-changed={}", ref_file.display());
                } else {
                    // When refs are packed, the loose ref file doesn't exist
                    // and changes are tracked in packed-refs instead.
                    let packed_refs = git_dir_path.join("packed-refs");
                    if packed_refs.exists() {
                        println!("cargo:rerun-if-changed={}", packed_refs.display());
                    }
                }
            }
        }
    }
}
