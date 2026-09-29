// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Container image resolution shared by the one-shot runner and the state-aware daemon.

use std::ffi::c_void;
use std::fmt::Write;
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use wxc_common::logger::Logger;
use wxc_common::models::ScriptResponse;
use wxc_common::string_util::{to_wide, CoTaskMemPWSTR};

use crate::container_steps::{cstr_bytes, sdk_error};
use crate::error::WslcError;
use crate::registry_policy;
use crate::sdk_init;
use crate::wslc_bindings::*;

/// How long a single pull may run before it is aborted.
///
/// Deliberately under the daemon client's 600s response deadline, so a wedged
/// pull surfaces as a failed provision the caller still receives rather than a
/// timeout that abandons a container nobody can name.
const PULL_TIMEOUT: Duration = Duration::from_secs(540);

/// Env override (positive whole seconds) for [`PULL_TIMEOUT`]. Lets a test drive
/// the abort path without waiting out the production budget.
const PULL_TIMEOUT_ENV: &str = "MXC_WSLC_PULL_TIMEOUT_SECS";

/// Gap between progress lines while a pull is running.
const PULL_REPORT_INTERVAL: Duration = Duration::from_secs(10);

/// `E_ABORT` — returned from the progress callback to stop a pull, and reported
/// back by the SDK as the pull's own result.
const E_ABORT: HRESULT = 0x8000_4004u32 as HRESULT;

/// The pull deadline, honouring [`PULL_TIMEOUT_ENV`].
fn pull_timeout() -> Duration {
    std::env::var(PULL_TIMEOUT_ENV)
        .ok()
        .as_deref()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&secs| secs > 0)
        .map(Duration::from_secs)
        .unwrap_or(PULL_TIMEOUT)
}

/// Shared with the SDK's progress callback for the duration of one pull.
struct PullWatch {
    deadline: Instant,
    started: Instant,
    /// Milliseconds since `started` at the last progress line, so the callback
    /// can rate-limit itself without a lock.
    last_report_ms: AtomicU64,
    image: String,
}

/// Called by the SDK as a pull advances; returns [`E_ABORT`] once the deadline
/// has passed, which stops the transfer.
///
/// # Safety
/// `context` must be the `*const PullWatch` handed to `WslcPullSessionImage`,
/// and must outlive the call.
unsafe extern "C" fn pull_progress(
    progress: *const WslcImageProgressMessage,
    context: PVOID,
) -> HRESULT {
    // This runs on an SDK thread across the C ABI, where an unwind would be
    // undefined behaviour. Reporting allocates, so the whole body is guarded.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let Some(watch) = (context as *const PullWatch).as_ref() else {
            return S_OK;
        };
        let now = Instant::now();
        if now >= watch.deadline {
            return E_ABORT;
        }

        let elapsed_ms = now.duration_since(watch.started).as_millis() as u64;
        let last = watch.last_report_ms.load(Ordering::Relaxed);
        if elapsed_ms.saturating_sub(last) >= PULL_REPORT_INTERVAL.as_millis() as u64
            && watch
                .last_report_ms
                .compare_exchange(last, elapsed_ms, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            let detail = progress.as_ref().map(|p| p.detail);
            let transferred = match detail {
                Some(d) if d.totalBytes > 0 => format!(
                    " {}/{} MiB",
                    d.currentBytes / 1_048_576,
                    d.totalBytes / 1_048_576
                ),
                _ => String::new(),
            };
            eprintln!(
                "[WSLC] Pulling '{}' — {}s elapsed{}",
                watch.image,
                elapsed_ms / 1000,
                transferred
            );
        }
        S_OK
    }));
    outcome.unwrap_or(S_OK)
}

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
    let budget = pull_timeout();
    let _ = writeln!(
        logger,
        "{} Pulling image '{}' (up to {}s)",
        log_prefix,
        image,
        budget.as_secs()
    );

    let uri_cstr = cstr_bytes("image", image)?;
    let started = Instant::now();
    // Stationary for the whole call: the SDK holds this pointer across it.
    let watch = PullWatch {
        deadline: started + budget,
        started,
        last_report_ms: AtomicU64::new(0),
        image: image.to_string(),
    };
    let pull_opts = WslcPullImageOptions {
        uri: uri_cstr.as_ptr() as PCSTR,
        progressCallback: Some(pull_progress),
        progressCallbackContext: &watch as *const PullWatch as PVOID,
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
            budget,
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
    budget: Duration,
) -> ScriptResponse {
    let sanitized = sanitize_sdk_message(sdk_msg);
    let detail = if sanitized.is_empty() {
        format!("HRESULT 0x{:08X}", hr as u32)
    } else {
        format!("{} (HRESULT 0x{:08X})", sanitized, hr as u32)
    };

    match hr {
        // Our own progress callback stopped this, so the registry is not at
        // fault and the SDK's text describes the abort rather than a cause.
        E_ABORT => WslcError::Host(format!(
            "WSLC image '{}' did not finish pulling within {}s and was stopped. \
             Retry, raise the budget with {}, or warm the cache from a machine \
             that can reach the registry with: wxc-exec.exe --setup-wslc --image {}{}.",
            image,
            budget.as_secs(),
            PULL_TIMEOUT_ENV,
            image,
            storage_arg(storage_path),
        )),
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
        // The cause is not one this code recognises, so the remedy is stated as
        // a possibility rather than a diagnosis: a full disk and a corrupt
        // download reach here too, and neither is fixed by restoring network.
        _ => WslcError::Host(format!(
            "WSLC image '{}' could not be pulled: {}. If the registry was unreachable, \
             retry once it is available. Otherwise set wslc.imageTarPath to a local tar, \
             or warm this cache from a machine that can reach the registry with: \
             wxc-exec.exe --setup-wslc --image {}{}. \
             See docs/wsl/wsl-container-getting-started.md.",
            image,
            detail,
            image,
            storage_arg(storage_path),
        )),
    }
    .into_response()
}

/// Longest run of registry-supplied text kept in a user-facing message.
const MAX_SDK_MESSAGE: usize = 400;

/// Make a registry's error text safe to print and to carry over the daemon pipe.
///
/// The string reaches here from whatever server the image reference named, so
/// it can carry terminal escapes or run arbitrarily long.
fn sanitize_sdk_message(sdk_msg: &str) -> String {
    let cleaned: String = sdk_msg
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let cleaned = cleaned.trim();
    match cleaned.char_indices().nth(MAX_SDK_MESSAGE) {
        None => cleaned.to_string(),
        Some((cut, _)) => format!("{}…", &cleaned[..cut]),
    }
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

/// Whether a cache miss may reach the image's registry.
///
/// A sandbox that declares no egress gets no pull: the fetch would run on the
/// host's network before the container exists, so the declared posture could
/// not constrain it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RegistryAccess {
    Allowed,
    Denied,
}

/// Ensure `image` is in the session's local cache: import it from
/// `image_tar_path` when one is supplied, otherwise pull it from its registry.
///
/// # Safety
/// `sdk` must hold valid function pointers and `session` must be a live handle.
#[allow(clippy::too_many_arguments)]
pub unsafe fn resolve_image(
    sdk: &WslcSdk,
    session: WslcSession,
    image: &str,
    image_tar_path: Option<&str>,
    storage_path: Option<&str>,
    registry: RegistryAccess,
    log_prefix: &str,
    logger: &mut Logger,
) -> Result<(), ScriptResponse> {
    let cached = list_cached_images(sdk, session)?;
    let matched = cached.iter().find(|entry| entry.satisfies(image));

    match select_action(matched.is_some(), image_tar_path.is_some(), registry) {
        ImageAction::UseCache => {
            let digest = matched.map(|e| e.digest_hex()).unwrap_or_default();
            if image_tar_path.is_some() {
                let _ = writeln!(
                    logger,
                    "{} Image '{}' already cached ({}), skipping tar import",
                    log_prefix, image, digest
                );
            } else {
                let _ = writeln!(
                    logger,
                    "{} Image '{}' found ({})",
                    log_prefix, image, digest
                );
            }
            Ok(())
        }
        ImageAction::ImportTar => import_image_from_tar(
            sdk,
            session,
            image,
            image_tar_path.expect("tar action implies a tar path"),
            logger,
        ),
        ImageAction::Pull => {
            // Administrative policy decides which registries this machine may
            // contact at all, independent of what the request asks for.
            let policy = registry_policy::get_policy();
            if !policy.permits(image) {
                return Err(WslcError::Rejected(policy.refusal(image)).into_response());
            }
            pull_image(sdk, session, image, storage_path, log_prefix, logger)?;
            // What the reference actually resolved to. A tag is mutable, so the
            // digest is the only record of which content this run executed.
            if let Some(entry) = list_cached_images(sdk, session)?
                .iter()
                .find(|entry| entry.is_same_repository(image))
            {
                let _ = writeln!(
                    logger,
                    "{} Image '{}' resolved to sha256:{}",
                    log_prefix,
                    image,
                    entry.digest_hex()
                );
            }
            Ok(())
        }
        ImageAction::RefuseNoEgress => Err(WslcError::Rejected(format!(
            "WSLC image '{}' is not cached, and this sandbox declares no egress. \
             Pulling it would reach the registry on the host's network, before the \
             container exists and outside the policy the request declares. Warm the \
             cache first with wxc-exec.exe --setup-wslc --image {}{}, set \
             wslc.imageTarPath to a local tar, or allow egress. \
             See docs/wsl/wsl-container-getting-started.md.",
            image,
            image,
            storage_arg(storage_path),
        ))
        .into_response()),
    }
}

/// An image the session's store already holds.
pub struct CachedImage {
    name: String,
    sha256: [u8; 32],
}

impl CachedImage {
    /// Whether this entry satisfies a request for `requested`.
    ///
    /// A reference pinning a digest never does. The store reports the config
    /// digest while the reference carries the manifest digest, and the SDK
    /// exposes no mapping between them, so honouring the pin from the cache is
    /// not possible — matching on the repository name would silently serve
    /// whatever was fetched first, which is the opposite of pinning. Such a
    /// reference goes to the registry every time, which is slower and correct.
    fn satisfies(&self, requested: &str) -> bool {
        digest_of(requested).is_none() && names_same_image(&self.name, requested)
    }

    /// Whether this entry is the repository `requested` names, pin aside.
    ///
    /// Only for reporting what a completed pull produced; too weak to decide a
    /// cache hit.
    fn is_same_repository(&self, requested: &str) -> bool {
        repository_of(&self.name) == repository_of(requested)
    }

    /// The stored content digest, as lowercase hex.
    fn digest_hex(&self) -> String {
        use std::fmt::Write as _;
        self.sha256.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{:02x}", b);
            out
        })
    }
}

/// A reference with any tag and digest stripped off.
fn repository_of(reference: &str) -> &str {
    let without_digest = reference
        .rsplit_once('@')
        .map_or(reference, |(head, _)| head);
    // A colon in the last path segment is a tag; one before a `/` is a
    // registry port, as in `localhost:5000/img`.
    match without_digest.rsplit_once('/') {
        Some((registry, last)) => match last.split_once(':') {
            Some((name, _)) => &without_digest[..registry.len() + 1 + name.len()],
            None => without_digest,
        },
        None => without_digest
            .split_once(':')
            .map_or(without_digest, |(name, _)| name),
    }
}

/// The `sha256:<hex>` a reference pins, if it carries one.
fn digest_of(reference: &str) -> Option<&str> {
    reference
        .rsplit_once('@')
        .and_then(|(_, digest)| digest.strip_prefix("sha256:"))
}

/// Read the session's image store.
///
/// # Safety
/// `sdk` must hold valid function pointers and `session` must be a live handle.
unsafe fn list_cached_images(
    sdk: &WslcSdk,
    session: WslcSession,
) -> Result<Vec<CachedImage>, ScriptResponse> {
    let mut images: *mut WslcImageInfo = ptr::null_mut();
    let mut image_count: u32 = 0;
    let hr = sdk.WslcListSessionImages(session, &mut images, &mut image_count);
    if hr != S_OK {
        return Err(sdk_error("WslcListSessionImages failed", hr, ""));
    }
    if images.is_null() {
        return Ok(Vec::new());
    }

    let mut cached = Vec::with_capacity(image_count as usize);
    for info in std::slice::from_raw_parts(images, image_count as usize) {
        // `info.name` is a fixed-size, possibly-unterminated C buffer; read up
        // to the first NUL, or the whole buffer if there is none.
        let name_bytes =
            std::slice::from_raw_parts(info.name.as_ptr().cast::<u8>(), info.name.len());
        let end = name_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name_bytes.len());
        if let Ok(name) = std::str::from_utf8(&name_bytes[..end]) {
            cached.push(CachedImage {
                name: name.to_string(),
                sha256: info.sha256,
            });
        }
    }
    windows::Win32::System::Com::CoTaskMemFree(Some(images as *const c_void));
    Ok(cached)
}

/// How `resolve_image` satisfies the request once the cache has been consulted.
#[derive(Debug, PartialEq, Eq)]
enum ImageAction {
    UseCache,
    ImportTar,
    Pull,
    RefuseNoEgress,
}

/// Choose between the cache, the caller's tar, and the registry.
fn select_action(cached: bool, has_tar: bool, registry: RegistryAccess) -> ImageAction {
    match (cached, has_tar, registry) {
        (true, _, _) => ImageAction::UseCache,
        (false, true, _) => ImageAction::ImportTar,
        (false, false, RegistryAccess::Allowed) => ImageAction::Pull,
        (false, false, RegistryAccess::Denied) => ImageAction::RefuseNoEgress,
    }
}

/// Whether a stored image name denotes the image `requested`.
///
/// A reference with no tag means `:latest`, which the store spells out, so
/// comparing the two literally would miss and re-pull on every run.
fn names_same_image(stored: &str, requested: &str) -> bool {
    stored == requested || stored == with_implicit_tag(requested)
}

/// `name` with the `:latest` the registry implies when a reference omits a tag.
fn with_implicit_tag(name: &str) -> String {
    // A colon in the final path segment is the tag; one before a `/` is a
    // registry port, as in `localhost:5000/img`. A digest pins its own content
    // and never takes an implicit tag.
    let last_segment = name.rsplit('/').next().unwrap_or(name);
    if last_segment.contains(':') || name.contains('@') {
        name.to_string()
    } else {
        format!("{}:latest", name)
    }
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
    let sdk = match sdk_init::init_and_load_sdk(logger) {
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

    /// `pull_failure` at the production budget, which most cases do not care about.
    fn failure(
        image: &str,
        storage_path: Option<&str>,
        hr: HRESULT,
        sdk_msg: &str,
    ) -> ScriptResponse {
        pull_failure(image, storage_path, hr, sdk_msg, PULL_TIMEOUT)
    }

    #[test]
    fn an_abort_is_reported_as_a_budget_overrun_not_a_registry_failure() {
        let resp = pull_failure(
            "alpine:latest",
            None,
            E_ABORT,
            "operation aborted",
            Duration::from_secs(90),
        );
        assert!(
            resp.error_message.contains("within 90s"),
            "the budget that was exceeded has to be in the message: {}",
            resp.error_message
        );
        assert!(
            resp.error_message.contains(PULL_TIMEOUT_ENV),
            "the operator needs the knob that raises it"
        );
        assert!(
            !resp.error_message.contains("registry was unreachable"),
            "we stopped this, so the registry must not be blamed: {}",
            resp.error_message
        );
        // Raising the budget or retrying can succeed, so this is not a rejection.
        assert_eq!(resp.failure_phase, FailurePhase::LaunchFailed);
    }

    #[test]
    fn the_pull_budget_is_under_the_daemon_response_deadline() {
        // A pull that outlives the client's wait produces a container whose id
        // never reaches anyone.
        assert!(
            PULL_TIMEOUT < Duration::from_secs(600),
            "PULL_TIMEOUT must stay below the daemon client's CALL_TIMEOUT"
        );
    }

    fn cached(name: &str) -> CachedImage {
        CachedImage {
            name: name.to_string(),
            sha256: [0u8; 32],
        }
    }

    #[test]
    fn a_digest_reference_never_satisfies_from_cache() {
        // The store reports a config digest; the reference carries a manifest
        // digest. Matching on the repository alone would serve whatever was
        // fetched first, which defeats the pin.
        let entry = cached("busybox");
        assert!(!entry.satisfies("busybox@sha256:ab33eacc"));
        assert!(entry.satisfies("busybox"));
    }

    #[test]
    fn a_repository_is_read_without_its_tag_or_digest() {
        assert_eq!(repository_of("busybox"), "busybox");
        assert_eq!(repository_of("busybox:1.36"), "busybox");
        assert_eq!(repository_of("busybox@sha256:abc"), "busybox");
        assert_eq!(repository_of("ghcr.io/owner/img:tag"), "ghcr.io/owner/img");
        assert_eq!(repository_of("localhost:5000/img"), "localhost:5000/img");
        assert_eq!(
            repository_of("localhost:5000/img:tag"),
            "localhost:5000/img"
        );
    }

    #[test]
    fn a_pulled_digest_is_reported_against_its_repository() {
        // The pull's audit line has to find the entry even though the store
        // filed it under the bare repository name.
        let entry = cached("busybox");
        assert!(entry.is_same_repository("busybox@sha256:ab33eacc"));
        assert!(!entry.is_same_repository("alpine@sha256:ab33eacc"));
    }

    #[test]
    fn a_digest_is_rendered_as_lowercase_hex() {
        let mut sha = [0u8; 32];
        sha[0] = 0x0e;
        sha[31] = 0xff;
        let hex = CachedImage {
            name: "x".to_string(),
            sha256: sha,
        }
        .digest_hex();
        assert_eq!(hex.len(), 64, "32 bytes render as 64 hex digits");
        assert!(hex.starts_with("0e"), "leading zero nibble is kept: {hex}");
        assert!(hex.ends_with("ff"));
    }

    #[test]
    fn a_cached_image_is_used_whatever_else_was_offered() {
        for has_tar in [false, true] {
            for registry in [RegistryAccess::Allowed, RegistryAccess::Denied] {
                assert_eq!(
                    select_action(true, has_tar, registry),
                    ImageAction::UseCache
                );
            }
        }
    }

    #[test]
    fn a_tar_is_imported_rather_than_pulled() {
        // A local tar needs no registry, so an isolated sandbox keeps working.
        assert_eq!(
            select_action(false, true, RegistryAccess::Denied),
            ImageAction::ImportTar
        );
        assert_eq!(
            select_action(false, true, RegistryAccess::Allowed),
            ImageAction::ImportTar
        );
    }

    #[test]
    fn a_miss_pulls_only_when_egress_is_allowed() {
        assert_eq!(
            select_action(false, false, RegistryAccess::Allowed),
            ImageAction::Pull
        );
        assert_eq!(
            select_action(false, false, RegistryAccess::Denied),
            ImageAction::RefuseNoEgress
        );
    }

    #[test]
    fn an_untagged_reference_matches_the_stored_latest_tag() {
        assert!(names_same_image("busybox:latest", "busybox"));
        assert!(names_same_image("busybox:latest", "busybox:latest"));
        assert!(names_same_image(
            "ghcr.io/owner/img:latest",
            "ghcr.io/owner/img"
        ));
    }

    #[test]
    fn a_registry_port_is_not_mistaken_for_a_tag() {
        assert_eq!(
            with_implicit_tag("localhost:5000/img"),
            "localhost:5000/img:latest"
        );
        assert!(names_same_image(
            "localhost:5000/img:latest",
            "localhost:5000/img"
        ));
    }

    #[test]
    fn an_explicit_tag_or_digest_is_left_alone() {
        assert_eq!(with_implicit_tag("busybox:1.36"), "busybox:1.36");
        assert_eq!(
            with_implicit_tag("busybox@sha256:abc"),
            "busybox@sha256:abc"
        );
        assert!(!names_same_image("busybox:latest", "busybox:1.36"));
    }

    #[test]
    fn a_different_image_never_matches() {
        assert!(!names_same_image("alpine:latest", "busybox"));
        assert!(!names_same_image("busyboxer:latest", "busybox"));
    }

    #[test]
    fn a_refused_reference_is_not_worth_retrying() {
        let resp = failure("ghcr.io/nope:1", None, WSLC_E_IMAGE_NOT_FOUND, "denied");
        assert_eq!(resp.failure_phase, FailurePhase::Rejected);
    }

    #[test]
    fn a_blocked_registry_is_not_worth_retrying() {
        let resp = failure(
            "ghcr.io/nope:1",
            None,
            WSLC_E_REGISTRY_BLOCKED_BY_POLICY,
            "blocked",
        );
        assert_eq!(resp.failure_phase, FailurePhase::Rejected);
    }

    #[test]
    fn an_unreachable_registry_is_retryable() {
        let resp = failure("alpine:latest", None, E_FAIL, "no such host");
        assert_eq!(resp.failure_phase, FailurePhase::LaunchFailed);
    }

    #[test]
    fn an_unreachable_registry_says_how_to_work_offline() {
        let resp = failure("alpine:latest", None, E_FAIL, "no such host");
        assert!(resp.error_message.contains("retry once it is available"));
        assert!(resp.error_message.contains("imageTarPath"));
    }

    #[test]
    fn an_unrecognised_failure_does_not_diagnose_the_network() {
        // A full disk reaches this arm too, so the wording offers the network
        // as one possibility rather than asserting it.
        let resp = failure("alpine:latest", None, E_FAIL, "no space left on device");
        assert!(
            resp.error_message
                .contains("If the registry was unreachable"),
            "unknown causes must be stated conditionally: {}",
            resp.error_message
        );
    }

    #[test]
    fn registry_text_cannot_smuggle_control_characters() {
        let hostile = "denied\u{1b}[2Jcleared\u{7}\nnext";
        let resp = failure("alpine:latest", None, E_FAIL, hostile);
        assert!(!resp.error_message.contains('\u{1b}'));
        assert!(!resp.error_message.contains('\u{7}'));
        assert!(!resp.error_message.contains('\n'));
        assert!(resp.error_message.contains("cleared"));
    }

    #[test]
    fn registry_text_is_capped() {
        let flood = "x".repeat(5_000);
        let resp = failure("alpine:latest", None, E_FAIL, &flood);
        assert!(resp.error_message.contains('…'));
        assert!(
            resp.error_message.len() < 1_500,
            "a hostile registry must not dictate the message length, got {}",
            resp.error_message.len()
        );
    }

    #[test]
    fn a_multibyte_registry_message_is_cut_on_a_character_boundary() {
        // Slicing by byte offset here would panic mid-character.
        let flood = "é".repeat(5_000);
        let resp = failure("alpine:latest", None, E_FAIL, &flood);
        assert!(resp.error_message.contains('…'));
    }

    #[test]
    fn an_unreachable_registry_does_not_prescribe_the_pull_that_just_failed() {
        // `--setup-wslc` shares `pull_image`, so it fails the same way here.
        let resp = failure("alpine:latest", None, E_FAIL, "no such host");
        let advice = &resp.error_message;
        let setup = advice
            .find("--setup-wslc")
            .expect("offers the warm-cache route");
        let elsewhere = advice
            .find("from a machine that can reach the registry")
            .expect("qualifies where that route has to run");
        assert!(
            elsewhere < setup,
            "the other-machine qualifier must precede the command: {advice}"
        );
    }

    #[test]
    fn an_overridden_store_travels_with_the_suggested_command() {
        let resp = failure("alpine:latest", Some(r"C:\store"), E_FAIL, "down");
        assert!(resp.error_message.contains(r#"--storage-path "C:\store""#));
    }

    #[test]
    fn a_default_store_adds_no_path_argument() {
        let resp = failure("alpine:latest", None, E_FAIL, "down");
        assert!(!resp.error_message.contains("--storage-path"));
    }

    #[test]
    fn every_rejection_names_a_way_forward() {
        for hr in [WSLC_E_IMAGE_NOT_FOUND, WSLC_E_REGISTRY_BLOCKED_BY_POLICY] {
            let resp = failure("ghcr.io/nope:1", None, hr, "denied");
            assert!(
                resp.error_message.contains("imageTarPath"),
                "a rejection that only diagnoses leaves the caller stuck: {}",
                resp.error_message
            );
        }
    }

    #[test]
    fn a_failure_without_an_sdk_message_still_reports_the_code() {
        let resp = failure("alpine:latest", None, WSLC_E_IMAGE_NOT_FOUND, "");
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
