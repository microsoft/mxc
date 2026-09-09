// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared build-time helpers for embedding Windows VersionInfo metadata in MXC binaries.
//!
//! Used as a `[build-dependencies]` crate — call [`embed_version_info`] from each
//! binary crate's `build.rs` to stamp `ProductName`, `FileDescription`,
//! `OriginalFilename`, and `ProductVersion` (with the git commit hash) into the
//! resulting PE executable.

use std::path::Path;
use std::process::Command;

#[cfg(all(windows, feature = "isolation_session_sdk"))]
pub mod isolation_session_sdk {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    pub const PACKAGE_ID: &str = "Microsoft.Windows.AI.IsolationSession.SDK";
    pub const PACKAGE_VERSION: &str = "0.2608.0";
    pub const PACKAGE_SHA256: &str =
        "af609652e691e9f2ae47885bcfcfd29e8d8c05744482f50c104efd2f3ca1d8e5";
    pub const PACKAGE_PATH_ENV: &str = "ISOLATION_SESSION_SDK_PACKAGE";

    const APP_DLL: &str = "IsoSessionApp.dll";
    const RUNTIME_MANIFEST: &str = "IsoSession.manifest";
    const VERSION_SIDECAR: &str = "IsoSessionApp.runtimeversion";

    pub fn resolve_package() -> Result<PathBuf, String> {
        println!("cargo:rerun-if-env-changed={PACKAGE_PATH_ENV}");

        if let Ok(value) = std::env::var(PACKAGE_PATH_ENV) {
            let path = PathBuf::from(value);
            verify_package(&path)?;
            println!("cargo:rerun-if-changed={}", path.display());
            return Ok(path);
        }

        let package_name = format!(
            "{}.{}.nupkg",
            PACKAGE_ID.to_ascii_lowercase(),
            PACKAGE_VERSION
        );
        let package_dir = nuget_cache_root()?
            .join(PACKAGE_ID.to_ascii_lowercase())
            .join(PACKAGE_VERSION);
        let package_path = package_dir.join(&package_name);

        if package_path.exists() {
            verify_package(&package_path)?;
            println!("cargo:rerun-if-changed={}", package_path.display());
            return Ok(package_path);
        }

        std::fs::create_dir_all(&package_dir).map_err(|e| {
            format!(
                "create IsolationSession NuGet cache directory {}: {e}",
                package_dir.display()
            )
        })?;

        let download_path =
            package_dir.join(format!("{package_name}.download.{}", std::process::id()));
        let url = format!(
            "https://api.nuget.org/v3-flatcontainer/{}/{}/{}",
            PACKAGE_ID.to_ascii_lowercase(),
            PACKAGE_VERSION,
            package_name
        );
        let status = Command::new("curl")
            .args([
                "--fail",
                "--location",
                "--retry",
                "3",
                "--silent",
                "--show-error",
            ])
            .arg("--output")
            .arg(&download_path)
            .arg(&url)
            .status()
            .map_err(|e| format!("launch curl to download {PACKAGE_ID} {PACKAGE_VERSION}: {e}"))?;

        if !status.success() {
            let _ = std::fs::remove_file(&download_path);
            return Err(format!(
                "download {PACKAGE_ID} {PACKAGE_VERSION} from NuGet.org failed with {status}; \
                 set {PACKAGE_PATH_ENV} to a pre-fetched package for an offline build"
            ));
        }

        if let Err(e) = verify_package(&download_path) {
            let _ = std::fs::remove_file(&download_path);
            return Err(e);
        }

        match std::fs::rename(&download_path, &package_path) {
            Ok(()) => {}
            Err(e) if package_path.exists() => {
                let _ = std::fs::remove_file(&download_path);
                verify_package(&package_path).map_err(|verify_error| {
                    format!(
                        "another build populated {}, but it is invalid ({verify_error}); \
                         original rename error: {e}",
                        package_path.display()
                    )
                })?;
            }
            Err(e) => {
                let _ = std::fs::remove_file(&download_path);
                return Err(format!(
                    "publish downloaded package to {}: {e}",
                    package_path.display()
                ));
            }
        }

        println!("cargo:rerun-if-changed={}", package_path.display());
        Ok(package_path)
    }

    pub fn stage_runtime() -> Result<(), String> {
        let package = resolve_package()?;
        let app_dll = read_entry(&package, APP_DLL)?;
        let version_bytes = read_entry(&package, VERSION_SIDECAR)?;
        let instance = String::from_utf8(version_bytes)
            .map_err(|e| format!("{VERSION_SIDECAR} is not valid UTF-8: {e}"))?
            .trim()
            .replace('_', ".");
        validate_instance(&instance)?;

        let manifest = format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\n\
  <assemblyIdentity name=\"IsoSession.Runtime\" version=\"1.0.0.0\" type=\"win32\" />\n\
  <file name=\"IsoSessionApp.dll\" />\n\
  <iso:instance xmlns:iso=\"urn:schemas-microsoft-com:agentic-runtime.v1\" name=\"{instance}\" />\n\
</assembly>\n"
        );
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

    fn validate_instance(instance: &str) -> Result<(), String> {
        let bytes = instance.as_bytes();
        if bytes.len() == 7
            && bytes[4] == b'.'
            && bytes[..4].iter().all(u8::is_ascii_digit)
            && bytes[5..].iter().all(u8::is_ascii_digit)
        {
            Ok(())
        } else {
            Err(format!(
                "{VERSION_SIDECAR} must identify a YYYY_MM instance, got {instance:?}"
            ))
        }
    }

    fn nuget_cache_root() -> Result<PathBuf, String> {
        if let Ok(path) = std::env::var("NUGET_PACKAGES") {
            return Ok(PathBuf::from(path));
        }
        let home = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .map_err(|_| {
                format!(
                    "neither NUGET_PACKAGES, USERPROFILE, nor HOME is set; set \
                     {PACKAGE_PATH_ENV} to a pre-fetched package"
                )
            })?;
        Ok(PathBuf::from(home).join(".nuget").join("packages"))
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

#[cfg(windows)]
fn embed_version_info_windows(
    file_description: &str,
    original_filename: &str,
    manifest_xml: Option<&str>,
) {
    const PRODUCT_NAME: &str = "Microsoft Execution Containers";

    let version = std::env::var("CARGO_PKG_VERSION").unwrap();
    let commit = git_short_hash();

    let mut resource = winresource::WindowsResource::new();
    resource
        .set("ProductName", PRODUCT_NAME)
        .set("FileDescription", file_description)
        .set("OriginalFilename", original_filename)
        .set("ProductVersion", &format!("{version}+{commit}"))
        .set(
            "LegalCopyright",
            "\u{00a9} Microsoft Corporation. All rights reserved.",
        );

    // Fuse the reg-free COM manifest in the SAME compile as the version info.
    if let Some(xml) = manifest_xml {
        resource.set_manifest(xml);
    }

    resource
        .compile()
        .expect("failed to embed Windows version info");
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
