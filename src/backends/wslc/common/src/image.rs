// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Container image resolution shared by the one-shot runner and the state-aware daemon.

use std::ffi::c_void;
use std::fmt::Write;
use std::ptr;

use wxc_common::logger::Logger;
use wxc_common::models::ScriptResponse;
use wxc_common::string_util::{to_wide, CoTaskMemPWSTR};

use crate::container_steps::{cstr_bytes, sdk_error};
use crate::error::WslcError;
use crate::wsl_container_runner::WSLContainerRunner;
use crate::wslc_bindings::*;

/// Pull `image` from its registry into the session's local image cache.
///
/// # Safety
/// `sdk` must hold valid function pointers and `session` must be a live handle.
pub unsafe fn pull_image(
    sdk: &WslcSdk,
    session: WslcSession,
    image: &str,
    storage_path: Option<&str>,
    log_prefix: &str,
    logger: &mut Logger,
) -> Result<(), ScriptResponse> {
    let _ = writeln!(logger, "{} Pulling image '{}'", log_prefix, image);

    let uri_cstr = cstr_bytes("image", image)?;
    let pull_opts = WslcPullImageOptions {
        uri: uri_cstr.as_ptr() as PCSTR,
        progressCallback: None,
        progressCallbackContext: ptr::null_mut(),
        registryAuth: ptr::null(),
    };

    let mut pull_err = CoTaskMemPWSTR::null();
    let hr = sdk.WslcPullSessionImage(session, &pull_opts, pull_err.as_mut_ptr());
    if hr != S_OK {
        return Err(pull_failure(
            image,
            storage_path,
            hr,
            &pull_err.to_string_lossy(),
        ));
    }

    let _ = writeln!(logger, "{} Image '{}' pulled", log_prefix, image);
    Ok(())
}

/// Classify a `WslcPullSessionImage` failure and render it for the caller.
fn pull_failure(
    image: &str,
    storage_path: Option<&str>,
    hr: HRESULT,
    sdk_msg: &str,
) -> ScriptResponse {
    let detail = if sdk_msg.is_empty() {
        format!("HRESULT 0x{:08X}", hr as u32)
    } else {
        format!("{} (HRESULT 0x{:08X})", sdk_msg, hr as u32)
    };

    match hr {
        WSLC_E_IMAGE_NOT_FOUND => WslcError::Rejected(format!(
            "WSLC image '{}' could not be pulled: {}. Check the image name and tag. \
             For a private registry, MXC cannot supply credentials — set \
             wslc.imageTarPath to a local tar, or import the image out of band.",
            image, detail
        )),
        WSLC_E_REGISTRY_BLOCKED_BY_POLICY => WslcError::Rejected(format!(
            "WSLC image '{}' could not be pulled: {}. Administrative policy on this \
             host blocks the registry. Use a permitted registry, or set \
             wslc.imageTarPath to a local tar.",
            image, detail
        )),
        // Reaching the registry is what failed, so a later run, or a run on a
        // connected host, can still succeed.
        _ => WslcError::Host(format!(
            "WSLC image '{}' could not be pulled: {}. Restore network access and retry. \
             To run on a host that stays offline, set wslc.imageTarPath to a local tar, \
             or warm this cache from a connected machine with: wxc-exec.exe \
             --setup-wslc --image {}{}. See docs/wsl/wsl-container-getting-started.md.",
            image,
            detail,
            image,
            storage_arg(storage_path),
        )),
    }
    .into_response()
}

/// Render a storage-path override as a `--storage-path` argument for the
/// suggested command, or nothing when the run uses the default path.
fn storage_arg(storage_path: Option<&str>) -> String {
    match storage_path {
        None => String::new(),
        Some(sp) => format!(" --storage-path \"{}\"", sp),
    }
}

/// Detected tar file format for image import.
enum TarFormat {
    /// Docker image archive from `docker save` (contains `manifest.json`).
    DockerSave,
    /// Rootfs filesystem tar from `docker export` (contains Linux root directories).
    Rootfs,
    /// Unrecognized format — not a valid tar or missing expected entries.
    Unknown,
}

/// Detect the format of a tar file by scanning its entries in a single pass.
///
/// - `manifest.json` present → Docker image archive (`docker save`)
/// - Top-level Linux directories (`bin`, `etc`, `usr`, etc.) → rootfs (`docker export`)
/// - Neither found after a successful scan → `TarFormat::Unknown`
/// - Open/read/parse failures → propagated as `std::io::Error`
fn detect_tar_format(path: &str) -> std::io::Result<TarFormat> {
    let file = std::fs::File::open(path)?;
    let mut archive = tar::Archive::new(file);
    let entries = archive.entries()?;

    const ROOTFS_MARKERS: &[&str] = &["bin", "etc", "usr", "lib", "sbin", "var"];
    let mut has_rootfs_dirs = false;

    for entry in entries {
        let entry = entry?;
        let entry_path = entry.path().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to read tar entry path: {}", e),
            )
        })?;

        // Docker-save archives have `manifest.json` at the top level.
        // Match only the root entry — not nested `manifest.json` files
        // (e.g., from NPM packages). Handles both `manifest.json` and
        // `./manifest.json` (common tar prefix).
        let normalized: std::path::PathBuf = entry_path
            .components()
            .filter(|c| !matches!(c, std::path::Component::CurDir))
            .collect();
        if normalized.as_os_str() == "manifest.json" {
            return Ok(TarFormat::DockerSave);
        }

        if !has_rootfs_dirs {
            // Skip a leading `.` component that is commonly present
            // in tar archives (e.g., `./bin/...`).
            let first_component = entry_path
                .components()
                .find_map(|component| match component {
                    std::path::Component::CurDir => None,
                    other => Some(other),
                });

            if let Some(first) = first_component {
                let first_str = first.as_os_str().to_string_lossy();
                if ROOTFS_MARKERS
                    .iter()
                    .any(|marker| *marker == first_str.as_ref())
                {
                    has_rootfs_dirs = true;
                }
            }
        }
    }

    if has_rootfs_dirs {
        Ok(TarFormat::Rootfs)
    } else {
        Ok(TarFormat::Unknown)
    }
}

/// Import a container image from a local tar file.
///
/// Supports both rootfs tars (`docker export`) and Docker image archives
/// (`docker save`). The format is auto-detected via `detect_tar_format`.
/// Returns `Ok(())` on success or `Err(ScriptResponse)` on failure.
pub(crate) unsafe fn import_image_from_tar(
    sdk: &WslcSdk,
    session: WslcSession,
    image_name: &str,
    tar_path: &str,
    logger: &mut Logger,
) -> Result<(), ScriptResponse> {
    let path = std::path::Path::new(tar_path);
    if !path.exists() {
        return Err(WslcError::Rejected(format!(
            "Image tar file not found: '{}'. Provide a valid rootfs tar \
             (via 'docker export') or Docker image archive (via 'docker save').",
            tar_path
        ))
        .into_response());
    }

    // Resolve to absolute path, following symlinks. Fall back to the
    // original path if canonicalization fails (e.g., permissions).
    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let tar_path = canonical.to_string_lossy();

    let tar_format = match detect_tar_format(&tar_path) {
        Ok(fmt) => fmt,
        Err(e) => {
            return Err(WslcError::Rejected(format!(
                "Failed to read tar file '{}': {}",
                tar_path, e
            ))
            .into_response());
        }
    };
    let wide_path: Vec<u16> = to_wide(&tar_path);

    match tar_format {
        TarFormat::DockerSave => {
            let _ = writeln!(
                logger,
                "[WSLC] Loading Docker image archive from tar: {}",
                tar_path
            );
            let load_opts = WslcLoadImageOptions {
                progressCallback: None,
                progressCallbackContext: ptr::null_mut(),
            };
            let mut err_msg = CoTaskMemPWSTR::null();
            let hr = sdk.WslcLoadSessionImageFromFile(
                session,
                wide_path.as_ptr() as PCWSTR,
                &load_opts,
                err_msg.as_mut_ptr(),
            );
            if hr != S_OK {
                let msg = err_msg.to_string_lossy();
                return Err(sdk_error(
                    &format!("Failed to load Docker image archive from '{}'", tar_path),
                    hr,
                    &msg,
                ));
            }
            let _ = writeln!(
                logger,
                "[WSLC] Docker image archive loaded successfully from tar"
            );
            let _ = writeln!(
                logger,
                "[WSLC] Note: container will use image '{}' — ensure this \
                 matches the tag inside the Docker archive",
                image_name
            );
        }
        TarFormat::Rootfs => {
            let _ = writeln!(
                logger,
                "[WSLC] Importing rootfs image '{}' from tar: {}",
                image_name, tar_path
            );
            let name_cstr = format!("{}\0", image_name);
            let import_opts = WslcImportImageOptions {
                progressCallback: None,
                progressCallbackContext: ptr::null_mut(),
            };
            let mut err_msg = CoTaskMemPWSTR::null();
            let hr = sdk.WslcImportSessionImageFromFile(
                session,
                name_cstr.as_bytes().as_ptr() as PCSTR,
                wide_path.as_ptr() as PCWSTR,
                &import_opts,
                err_msg.as_mut_ptr(),
            );
            if hr != S_OK {
                let msg = err_msg.to_string_lossy();
                return Err(sdk_error(
                    &format!("Failed to import image '{}' from tar", image_name),
                    hr,
                    &msg,
                ));
            }
            let _ = writeln!(
                logger,
                "[WSLC] Image '{}' imported successfully from tar",
                image_name
            );
        }
        TarFormat::Unknown => {
            return Err(WslcError::Rejected(format!(
                "Unrecognized tar format: '{}'. Provide a rootfs tar \
                 (via 'docker export') or a Docker image archive (via 'docker save').",
                tar_path
            ))
            .into_response());
        }
    }

    Ok(())
}

/// Ensure `image` is in the session's local cache: import it from
/// `image_tar_path` when one is supplied, otherwise pull it from its registry.
///
/// # Safety
/// `sdk` must hold valid function pointers and `session` must be a live handle.
pub unsafe fn resolve_image(
    sdk: &WslcSdk,
    session: WslcSession,
    image: &str,
    image_tar_path: Option<&str>,
    storage_path: Option<&str>,
    log_prefix: &str,
    logger: &mut Logger,
) -> Result<(), ScriptResponse> {
    let mut images: *mut WslcImageInfo = ptr::null_mut();
    let mut image_count: u32 = 0;
    let hr = sdk.WslcListSessionImages(session, &mut images, &mut image_count);
    if hr != S_OK {
        return Err(sdk_error("WslcListSessionImages failed", hr, ""));
    }

    let mut image_found = false;
    if !images.is_null() {
        let images_slice = std::slice::from_raw_parts(images, image_count as usize);
        for info in images_slice {
            // `info.name` is a fixed-size, possibly-unterminated C buffer; read
            // up to the first NUL, or the whole buffer if there is none.
            let name_bytes =
                std::slice::from_raw_parts(info.name.as_ptr().cast::<u8>(), info.name.len());
            let end = name_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(name_bytes.len());
            if let Ok(name) = std::str::from_utf8(&name_bytes[..end]) {
                if name == image {
                    image_found = true;
                    break;
                }
            }
        }
        windows::Win32::System::Com::CoTaskMemFree(Some(images as *const c_void));
    }

    if image_found {
        if image_tar_path.is_some() {
            let _ = writeln!(
                logger,
                "{} Image '{}' already cached, skipping tar import",
                log_prefix, image
            );
        } else {
            let _ = writeln!(logger, "{} Image '{}' found", log_prefix, image);
        }
        return Ok(());
    }

    if let Some(tar_path) = image_tar_path {
        return import_image_from_tar(sdk, session, image, tar_path, logger);
    }

    pull_image(sdk, session, image, storage_path, log_prefix, logger)
}

/// Warm a storage path's image cache with `image_name` and release the session,
/// backing `wxc-exec.exe --setup-wslc`.
///
/// # Safety
/// Must be called once per process before any other WSLC SDK functions
/// (it initialises COM via `init_and_load_sdk`).
pub unsafe fn setup_pull_image(
    image_name: &str,
    storage_path: Option<&str>,
    logger: &mut Logger,
) -> Result<(), String> {
    let sdk = match WSLContainerRunner::init_and_load_sdk(logger) {
        Ok(s) => s,
        Err(resp) => return Err(resp.error_message),
    };

    let storage_path_str = storage_path.map(|s| s.to_string()).unwrap_or_else(|| {
        std::env::temp_dir()
            .join("mxc-wslc-sessions")
            .to_string_lossy()
            .to_string()
    });
    let session_name: Vec<u16> = to_wide("mxc-setup-wslc");
    let storage_path_wide: Vec<u16> = to_wide(&storage_path_str);

    let mut settings = std::mem::zeroed::<WslcSessionSettings>();
    let hr = sdk.WslcInitSessionSettings(
        session_name.as_ptr(),
        storage_path_wide.as_ptr(),
        &mut settings,
    );
    if hr != S_OK {
        return Err(format!(
            "WslcInitSessionSettings failed (HRESULT 0x{:08X})",
            hr as u32
        ));
    }

    let mut session: WslcSession = ptr::null_mut();
    let mut create_err = CoTaskMemPWSTR::null();
    let hr = sdk.WslcCreateSession(&mut settings, &mut session, create_err.as_mut_ptr());
    if hr != S_OK {
        return Err(format!(
            "WslcCreateSession failed (HRESULT 0x{:08X}): {}",
            hr as u32,
            create_err.to_string_lossy()
        ));
    }
    let _session_guard = WslcSessionGuard::from_raw(
        session,
        sdk.terminate_session_fn(),
        sdk.release_session_fn(),
    );

    let _ = writeln!(logger, "[WSLC setup] Target store: {}", storage_path_str);
    pull_image(
        sdk,
        session,
        image_name,
        storage_path,
        "[WSLC setup]",
        logger,
    )
    .map_err(|resp| resp.error_message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use wxc_common::models::FailurePhase;

    /// `E_FAIL`, which the SDK returns when it cannot reach the registry at all.
    const E_FAIL: HRESULT = -2147467259;

    #[test]
    fn a_refused_reference_is_not_worth_retrying() {
        let resp = pull_failure("ghcr.io/nope:1", None, WSLC_E_IMAGE_NOT_FOUND, "denied");
        assert_eq!(resp.failure_phase, FailurePhase::Rejected);
    }

    #[test]
    fn a_blocked_registry_is_not_worth_retrying() {
        let resp = pull_failure(
            "ghcr.io/nope:1",
            None,
            WSLC_E_REGISTRY_BLOCKED_BY_POLICY,
            "blocked",
        );
        assert_eq!(resp.failure_phase, FailurePhase::Rejected);
    }

    #[test]
    fn an_unreachable_registry_is_retryable() {
        let resp = pull_failure("alpine:latest", None, E_FAIL, "no such host");
        assert_eq!(resp.failure_phase, FailurePhase::LaunchFailed);
    }

    #[test]
    fn an_unreachable_registry_says_how_to_work_offline() {
        let resp = pull_failure("alpine:latest", None, E_FAIL, "no such host");
        assert!(resp
            .error_message
            .contains("Restore network access and retry"));
        assert!(resp.error_message.contains("imageTarPath"));
    }

    #[test]
    fn an_unreachable_registry_does_not_prescribe_the_pull_that_just_failed() {
        // `--setup-wslc` shares `pull_image`, so it fails the same way here.
        let resp = pull_failure("alpine:latest", None, E_FAIL, "no such host");
        let advice = &resp.error_message;
        let setup = advice
            .find("--setup-wslc")
            .expect("offers the warm-cache route");
        let connected = advice
            .find("from a connected machine")
            .expect("qualifies where that route has to run");
        assert!(
            connected < setup,
            "the connected-machine qualifier must precede the command: {advice}"
        );
    }

    #[test]
    fn an_overridden_store_travels_with_the_suggested_command() {
        let resp = pull_failure("alpine:latest", Some(r"C:\store"), E_FAIL, "down");
        assert!(resp.error_message.contains(r#"--storage-path "C:\store""#));
    }

    #[test]
    fn a_default_store_adds_no_path_argument() {
        let resp = pull_failure("alpine:latest", None, E_FAIL, "down");
        assert!(!resp.error_message.contains("--storage-path"));
    }

    #[test]
    fn every_rejection_names_a_way_forward() {
        for hr in [WSLC_E_IMAGE_NOT_FOUND, WSLC_E_REGISTRY_BLOCKED_BY_POLICY] {
            let resp = pull_failure("ghcr.io/nope:1", None, hr, "denied");
            assert!(
                resp.error_message.contains("imageTarPath"),
                "a rejection that only diagnoses leaves the caller stuck: {}",
                resp.error_message
            );
        }
    }

    #[test]
    fn a_failure_without_an_sdk_message_still_reports_the_code() {
        let resp = pull_failure("alpine:latest", None, WSLC_E_IMAGE_NOT_FOUND, "");
        assert!(resp.error_message.contains("0x80040601"));
    }

    /// Create a temporary tar file from in-memory entries and return its path.
    fn build_test_tar(entries: &[(&str, &[u8])]) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut ar = tar::Builder::new(file.as_file());
        for (path, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_cksum();
            ar.append_data(&mut header, path, *data).unwrap();
        }
        ar.into_inner().unwrap().flush().unwrap();
        file
    }

    #[test]
    fn detect_docker_save_tar() {
        let file = build_test_tar(&[("manifest.json", b"{}")]);
        let result = detect_tar_format(file.path().to_str().unwrap());
        assert!(matches!(result, Ok(TarFormat::DockerSave)));
    }

    #[test]
    fn detect_docker_save_tar_with_dot_prefix() {
        let file = build_test_tar(&[("./manifest.json", b"{}")]);
        let result = detect_tar_format(file.path().to_str().unwrap());
        assert!(matches!(result, Ok(TarFormat::DockerSave)));
    }

    #[test]
    fn detect_rootfs_tar() {
        let file = build_test_tar(&[("bin/sh", b""), ("etc/passwd", b"")]);
        let result = detect_tar_format(file.path().to_str().unwrap());
        assert!(matches!(result, Ok(TarFormat::Rootfs)));
    }

    #[test]
    fn detect_rootfs_tar_with_dot_prefix() {
        let file = build_test_tar(&[("./bin/sh", b""), ("./etc/passwd", b"")]);
        let result = detect_tar_format(file.path().to_str().unwrap());
        assert!(matches!(result, Ok(TarFormat::Rootfs)));
    }

    #[test]
    fn detect_unknown_tar() {
        let file = build_test_tar(&[("random/file.txt", b"hello")]);
        let result = detect_tar_format(file.path().to_str().unwrap());
        assert!(matches!(result, Ok(TarFormat::Unknown)));
    }

    #[test]
    fn detect_empty_tar() {
        let file = build_test_tar(&[]);
        let result = detect_tar_format(file.path().to_str().unwrap());
        assert!(matches!(result, Ok(TarFormat::Unknown)));
    }

    #[test]
    fn nested_manifest_json_is_not_docker_save() {
        let file = build_test_tar(&[("app/manifest.json", b"{}")]);
        let result = detect_tar_format(file.path().to_str().unwrap());
        assert!(!matches!(result, Ok(TarFormat::DockerSave)));
    }

    #[test]
    fn docker_save_takes_priority_over_rootfs_markers() {
        let file = build_test_tar(&[
            ("bin/sh", b""),
            ("etc/passwd", b""),
            ("manifest.json", b"{}"),
        ]);
        let result = detect_tar_format(file.path().to_str().unwrap());
        assert!(matches!(result, Ok(TarFormat::DockerSave)));
    }

    #[test]
    fn nonexistent_file_returns_error() {
        let result = detect_tar_format("/nonexistent/path.tar");
        assert!(result.is_err());
    }
}
