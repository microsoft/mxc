// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Registration-free WinRT activation for the IsoSession client surface.
//!
//! By default MXC activates `Windows.AI.IsolationSession.IsoSessionOps`
//! through the system-installed registration (the OS image populates the
//! WinRT activation catalog). This module lets MXC instead load the in-proc
//! client (`IsoSessionApp.dll` -> `IsoSessionClient.dll`) from a known
//! relocatable location -- the same idea as the DevBypass inner loop, but
//! pointed at the folder a nuget package would lay down.
//!
//! Contract: when the environment variable [`RUNTIME_DIR_ENV`] is set, this
//! module loads `IsoSession.manifest` from that folder via a side-by-side
//! activation context before the first `IsoSessionOps` activation. The
//! manifest's `<file name="IsoSessionApp.dll">` therefore resolves to that
//! folder rather than `System32`. The activation context is intentionally
//! leaked (never deactivated) so it stays active for the process lifetime.
//!
//! COM/DCOM routing to the matching side-by-side *service* is handled by the
//! OS client via **coresidency**: IsoSessionClient.dll (loaded from this same
//! folder) reads the coresident `IsoSessionInstance.txt` descriptor (or the
//! leaf folder name) to pick the service instance CLSID. No per-EXE registry
//! routing key is involved -- the MSI's service/CLSID registration plus the
//! coresident files are sufficient.

use core::ffi::c_void;
use std::sync::OnceLock;

use windows::Win32::Foundation::{E_NOINTERFACE, HANDLE, HMODULE};
use windows::Win32::System::ApplicationInstallationAndServicing::{
    ActivateActCtx, CreateActCtxW, ACTCTXW,
};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::System::WinRT::IActivationFactory;
use windows_core::{Interface, RuntimeName, HSTRING, PCSTR, PCWSTR};

use super::error::IsolationSessionError;

/// Environment variable that points MXC at the folder holding the
/// side-by-side IsoSession runtime binaries and `IsoSession.manifest`.
/// A future nuget package / manifest sets this. When unset, MXC uses the
/// default system activation (no behavior change).
pub const RUNTIME_DIR_ENV: &str = "MXC_ISOSESSION_RUNTIME_DIR";

const MANIFEST_NAME: &str = "IsoSession.manifest";

/// Wrapper so the raw activation-context `HANDLE` can be cached in a static.
/// The handle is owned for the process lifetime and never released.
struct ActCtxHandle(HANDLE);

// SAFETY: the activation-context handle is an opaque, process-wide kernel
// handle; sharing it across threads to call ActivateActCtx is sound.
unsafe impl Send for ActCtxHandle {}
unsafe impl Sync for ActCtxHandle {}

static ACTCTX: OnceLock<Option<ActCtxHandle>> = OnceLock::new();

/// Idempotently establishes reg-free WinRT activation from
/// [`RUNTIME_DIR_ENV`], then activates the context on the calling thread.
///
/// Call this immediately before activating `IsoSessionOps`. It is a no-op
/// (system activation) when the env var is unset or the manifest is missing.
/// Activation is per-thread, so this is re-applied on every call to cover
/// callers that activate from more than one thread.
pub(crate) fn ensure_regfree_activation() {
    let handle = ACTCTX.get_or_init(create_actctx_from_env);

    if let Some(actctx) = handle {
        let mut cookie: usize = 0;

        // SAFETY: `actctx.0` is a valid activation context returned by
        // CreateActCtxW. We intentionally never call DeactivateActCtx -- the
        // context must remain active for this thread's WinRT activation.
        if let Err(e) = unsafe { ActivateActCtx(Some(actctx.0), &mut cookie) } {
            eprintln!("[mxc isosession] ActivateActCtx failed: {}", e);
        }
    }
}

/// Reads [`RUNTIME_DIR_ENV`] and, if set, creates an activation context from
/// the manifest in that folder. Returns `None` (system activation) on any
/// failure or when the var is unset.
fn create_actctx_from_env() -> Option<ActCtxHandle> {
    let dir = match std::env::var(RUNTIME_DIR_ENV) {
        Ok(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => return None,
    };

    let manifest = format!("{}\\{}", dir.trim_end_matches('\\'), MANIFEST_NAME);
    if !std::path::Path::new(&manifest).exists() {
        eprintln!(
            "[mxc isosession] {} = '{}' but '{}' not found; \
             using system activation.",
            RUNTIME_DIR_ENV, dir, manifest
        );
        return None;
    }

    let manifest_w = HSTRING::from(manifest.as_str());
    let ctx = ACTCTXW {
        cbSize: std::mem::size_of::<ACTCTXW>() as u32,
        lpSource: PCWSTR(manifest_w.as_ptr()),
        ..Default::default()
    };

    // SAFETY: `ctx` is a fully-initialised ACTCTXW and `manifest_w` outlives
    // the call, keeping `lpSource` valid.
    let handle = match unsafe { CreateActCtxW(&ctx) } {
        Ok(handle) => handle,
        Err(e) => {
            eprintln!(
                "[mxc isosession] CreateActCtxW failed for '{}': {}; \
                 using system activation.",
                manifest, e
            );
            return None;
        }
    };

    eprintln!(
        "[mxc isosession] reg-free WinRT activation active from '{}'",
        dir
    );

    Some(ActCtxHandle(handle))
}

/// Name of the WinRT activation DLL inside the runtime folder.
const APP_DLL_NAME: &str = "IsoSessionApp.dll";

/// Standard WinRT in-proc activation entrypoint exported by `IsoSessionApp.dll`.
const ACTIVATION_FACTORY_EXPORT: &[u8] = b"DllGetActivationFactory\0";

/// Signature of `DllGetActivationFactory`. The first parameter is an `HSTRING`
/// activatable class id (passed by value as its pointer-sized handle); the
/// second receives an `IActivationFactory*`.
type PfnDllGetActivationFactory =
    unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> windows_core::HRESULT;

/// Cached `HMODULE` of the explicitly-loaded `IsoSessionApp.dll`, stored as a
/// `usize` so the static is `Send + Sync`. `None` means the runtime dir is
/// unset or the DLL could not be loaded.
static APP_DLL: OnceLock<Option<usize>> = OnceLock::new();

/// Loads `<RUNTIME_DIR_ENV>\IsoSessionApp.dll` by full path exactly once and
/// returns its module handle. Returns `None` when the env var is unset/empty.
fn app_dll_handle() -> Option<HMODULE> {
    let cached = APP_DLL.get_or_init(|| {
        let dir = match std::env::var(RUNTIME_DIR_ENV) {
            Ok(value) if !value.trim().is_empty() => value.trim().to_string(),
            _ => return None,
        };

        let path = format!("{}\\{}", dir.trim_end_matches('\\'), APP_DLL_NAME);
        let path_w = HSTRING::from(path.as_str());

        // SAFETY: `path_w` is a valid NUL-terminated wide string that outlives
        // the call. Loading by full path makes the 2026.06 copy of the DLL the one
        // mapped regardless of any inbox WinRT catalog registration.
        match unsafe { LoadLibraryW(PCWSTR(path_w.as_ptr())) } {
            Ok(hmod) if !hmod.is_invalid() => {
                eprintln!(
                    "[mxc isosession] explicitly loaded {} from '{}'",
                    APP_DLL_NAME, path
                );
                Some(hmod.0 as usize)
            }
            Ok(_) => None,
            Err(e) => {
                eprintln!(
                    "[mxc isosession] LoadLibraryW('{}') failed: {}; \
                     using system activation.",
                    path, e
                );
                None
            }
        }
    });

    cached.map(|raw| HMODULE(raw as *mut c_void))
}

/// Activates the WinRT runtime class `T` by obtaining its activation factory
/// **directly** from the coresident `IsoSessionApp.dll` in [`RUNTIME_DIR_ENV`],
/// bypassing the WinRT activation catalog.
///
/// This is required on machines where the inbox `Windows.AI.IsolationSession.*`
/// classes are registered: there, a dynamic reg-free activation context is
/// shadowed by the system catalog, so `RoGetActivationFactory` would load the
/// `System32` binaries and bind the stable service instead of the side-by-side
/// 2026.06 build. Loading the factory by full DLL path guarantees the 2026.06
/// `IsoSessionApp.dll` is the one used; its coresidency logic then sibling-loads
/// the 2026.06 `IsoSessionClient.dll` and binds the matching service instance.
///
/// Returns `None` when [`RUNTIME_DIR_ENV`] is unset (caller falls back to the
/// default `T::new()` system activation). Returns `Some(Err(..))` when the
/// folder is configured but the explicit activation failed -- the caller should
/// surface that rather than silently fall back to a different binary set.
pub(crate) fn activate_from_runtime_dir<T>() -> Option<windows_core::Result<T>>
where
    T: Interface + RuntimeName,
{
    let hmod = app_dll_handle()?;
    Some(activate_via_factory::<T>(hmod))
}

fn activate_via_factory<T>(hmod: HMODULE) -> windows_core::Result<T>
where
    T: Interface + RuntimeName,
{
    // SAFETY: `hmod` is a valid module handle and the export name is a static
    // NUL-terminated byte string.
    let proc = unsafe { GetProcAddress(hmod, PCSTR(ACTIVATION_FACTORY_EXPORT.as_ptr())) }
        .ok_or_else(|| windows_core::Error::from(E_NOINTERFACE))?;

    // SAFETY: `DllGetActivationFactory` matches `PfnDllGetActivationFactory`.
    let factory_fn: PfnDllGetActivationFactory = unsafe { core::mem::transmute(proc) };

    let class_id = HSTRING::from(<T as RuntimeName>::NAME);
    // SAFETY: `HSTRING` is a transparent, pointer-sized handle. `transmute_copy`
    // reads the handle without taking ownership, so `class_id` remains valid and
    // is freed at end of scope -- after the call. The callee borrows, not owns.
    let class_id_raw: *mut c_void = unsafe { core::mem::transmute_copy(&class_id) };

    let mut factory_raw: *mut c_void = core::ptr::null_mut();
    // SAFETY: out-param receives a valid `IActivationFactory*` on success.
    let hr = unsafe { factory_fn(class_id_raw, &mut factory_raw) };
    hr.ok()?;

    // SAFETY: on success `factory_raw` is a valid, owned `IActivationFactory`.
    let factory = unsafe { IActivationFactory::from_raw(factory_raw) };

    // SAFETY: factory came from the runtime class's own DLL.
    let instance = unsafe { factory.ActivateInstance()? };

    instance.cast::<T>()
}

/// The IsoSession runtime instance this `wxc-exec` was **built** against.
///
/// Baked in at compile time by the bindings crate's `build.rs` (which reads
/// `instance` from the SDK NuGet's `GENERATION_INFO.toml` and emits
/// `cargo:rustc-env=ISOSESSION_INSTANCE`) and surfaced via
/// [`isolation_session_bindings::EXPECTED_INSTANCE`]. Returns `None` when the
/// build had no instance to bake (source-only build with no `instance` in the
/// committed provenance fallback), in which case the compatibility check is
/// skipped.
///
/// Read from the bindings crate rather than `option_env!` here because
/// `cargo:rustc-env` only reaches the crate whose build script emitted it.
fn expected_instance() -> Option<&'static str> {
    match isolation_session_bindings::EXPECTED_INSTANCE {
        Some(value) if !value.trim().is_empty() => Some(value.trim()),
        _ => None,
    }
}

/// The IsoSession runtime instance implied by the **leaf folder name** of the
/// configured runtime directory (`…\Agentic Runtime\2026.06` -> `2026.06`).
/// Returns `None` when the directory has no usable leaf component.
fn runtime_instance_from_dir(dir: &str) -> Option<String> {
    let trimmed = dir.trim().trim_end_matches(['\\', '/']);
    if trimmed.is_empty() {
        return None;
    }
    std::path::Path::new(trimmed)
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
}

/// Compatibility decision: compares the build-baked `expected` instance against
/// the instance the configured `runtime_dir` actually resolves to.
///
/// Skip conditions (return `Ok(())`, preserving today's behavior):
/// - unknown `expected` (no instance baked in -> source-only build);
/// - unset/empty `runtime_dir` (env unset -> system activation).
///
/// When `runtime_dir` **is** configured the check is strict — this is the
/// spoofing-resistant path a rename cannot defeat:
/// 1. the folder must exist, else [`IsolationSessionError::IncompatibleVersion`];
/// 2. it must contain an `IsoSession.manifest`, else `IncompatibleVersion`
///    (deliberately stricter than [`create_actctx_from_env`], which silently
///    degrades to system activation on a missing manifest — here an explicitly
///    configured runtime dir that is not a real runtime is an error, not a
///    silent fallback);
/// 3. the actual instance is the manifest's authoritative
///    `<iso:instance name="…">` marker, falling back to the leaf folder name
///    only when the manifest carries no such marker;
/// 4. a mismatch yields `IncompatibleVersion`.
fn evaluate_instance_compatibility(
    expected: Option<&str>,
    runtime_dir: Option<&str>,
) -> Result<(), IsolationSessionError> {
    let expected = match expected {
        Some(value) if !value.trim().is_empty() => value.trim(),
        _ => return Ok(()),
    };

    let dir = match runtime_dir {
        Some(value) if !value.trim().is_empty() => value.trim(),
        _ => return Ok(()),
    };

    let path = std::path::Path::new(dir);
    if !path.is_dir() {
        return Err(IsolationSessionError::IncompatibleVersion(format!(
            "this wxc-exec was built for IsoSession runtime instance '{}', but the \
             configured runtime folder ({} = '{}') does not exist. Install the \
             matching runtime or point {} at the '{}' runtime folder.",
            expected, RUNTIME_DIR_ENV, dir, RUNTIME_DIR_ENV, expected
        )));
    }

    let manifest = match read_manifest_text(&path.join(MANIFEST_NAME)) {
        Some(text) => text,
        None => {
            return Err(IsolationSessionError::IncompatibleVersion(format!(
                "this wxc-exec was built for IsoSession runtime instance '{}', but the \
                 configured runtime folder ({} = '{}') has no {} and is not a valid \
                 IsoSession runtime. Install the matching runtime or point {} at the \
                 '{}' runtime folder.",
                expected, RUNTIME_DIR_ENV, dir, MANIFEST_NAME, RUNTIME_DIR_ENV, expected
            )));
        }
    };

    // The manifest's embedded instance marker is authoritative and immune to a
    // folder rename; only fall back to the leaf name when it is absent.
    let actual = parse_manifest_instance(&manifest)
        .or_else(|| runtime_instance_from_dir(dir))
        .unwrap_or_default();

    if actual == expected {
        Ok(())
    } else {
        Err(IsolationSessionError::IncompatibleVersion(format!(
            "this wxc-exec was built for IsoSession runtime instance '{}', but the \
             configured runtime ({} = '{}') is instance '{}'. Install the matching \
             runtime or point {} at the '{}' runtime folder.",
            expected, RUNTIME_DIR_ENV, dir, actual, RUNTIME_DIR_ENV, expected
        )))
    }
}

/// Reads `IsoSession.manifest` as text, tolerating a UTF-16LE or UTF-8 byte
/// order mark. Returns `None` when the file is absent or unreadable.
fn read_manifest_text(path: &std::path::Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        return Some(String::from_utf16_lossy(&units));
    }
    let start = if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        3
    } else {
        0
    };
    Some(String::from_utf8_lossy(&bytes[start..]).into_owned())
}

/// Extracts the authoritative instance identity from an `IsoSession.manifest`:
/// the `name` attribute of the `<iso:instance …>` element that the runtime
/// bundle injects as the last child of `<assembly>`. Returns `None` when no such
/// element is present (legacy manifests without the marker).
///
/// Scoped to the `instance` element specifically: the manifest also carries
/// `<assemblyIdentity name="…">` and `<file name="…">`, so a naive first
/// `name="…"` scan would grab the wrong value.
fn parse_manifest_instance(manifest: &str) -> Option<String> {
    for chunk in manifest.split('<').skip(1) {
        // Bound to this element's own start tag (text up to the closing '>').
        let tag = match chunk.find('>') {
            Some(end) => &chunk[..end],
            None => chunk,
        };
        // Local element name = text up to the first whitespace or '/'.
        let name_end = tag
            .find(|c: char| c.is_whitespace() || c == '/')
            .unwrap_or(tag.len());
        let qname = &tag[..name_end];
        // Ignore any namespace prefix, e.g. `iso:instance` -> `instance`.
        let local = qname.rsplit(':').next().unwrap_or(qname);
        if !local.eq_ignore_ascii_case("instance") {
            continue;
        }
        let Some(value) = attr_value(tag, "name") else {
            continue;
        };
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    None
}

/// Value of attribute `attr` within a start-tag body (e.g. `name="2026.06"`).
/// The attribute name must stand alone — preceded by whitespace or the tag start
/// and followed by `=` — so `name` never matches inside `filename`.
fn attr_value(tag: &str, attr: &str) -> Option<String> {
    let mut search = 0;
    while let Some(rel) = tag[search..].find(attr) {
        let idx = search + rel;
        search = idx + attr.len();

        let standalone = tag[..idx]
            .chars()
            .next_back()
            .is_none_or(|c| c.is_whitespace());
        if !standalone {
            continue;
        }
        let Some(rest) = tag[search..].trim_start().strip_prefix('=') else {
            continue;
        };
        let rest = rest.trim_start();
        let mut chars = rest.chars();
        match chars.next() {
            Some(quote) if quote == '"' || quote == '\'' => {
                return Some(chars.take_while(|&c| c != quote).collect());
            }
            _ => continue,
        }
    }
    None
}

/// Verifies the installed IsoSession runtime instance matches the instance this
/// `wxc-exec` was built against, before any activation is attempted.
///
/// Reads the build-baked [`expected_instance`] and the runtime folder from
/// [`RUNTIME_DIR_ENV`], then defers to [`evaluate_instance_compatibility`].
/// When the runtime folder is configured this requires it to exist, to contain
/// an `IsoSession.manifest`, and for that manifest's authoritative instance
/// marker (or, absent a marker, the leaf folder name) to match; otherwise it
/// returns [`IsolationSessionError::IncompatibleVersion`]. With no instance
/// baked in, or `RUNTIME_DIR_ENV` unset, it returns `Ok(())` (preserving
/// today's behavior).
pub(crate) fn check_instance_compatibility() -> Result<(), IsolationSessionError> {
    let runtime_dir = std::env::var(RUNTIME_DIR_ENV).ok();
    evaluate_instance_compatibility(expected_instance(), runtime_dir.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn runtime_instance_parses_leaf_folder() {
        assert_eq!(
            runtime_instance_from_dir(r"C:\Program Files\Microsoft\Agentic Runtime\2026.06")
                .as_deref(),
            Some("2026.06"),
        );
    }

    #[test]
    fn runtime_instance_ignores_trailing_separators() {
        assert_eq!(
            runtime_instance_from_dir(r"C:\Program Files\Microsoft\Agentic Runtime\2026.06\")
                .as_deref(),
            Some("2026.06"),
        );
        assert_eq!(
            runtime_instance_from_dir("/opt/agentic-runtime/2026.06/").as_deref(),
            Some("2026.06"),
        );
    }

    #[test]
    fn runtime_instance_none_for_empty() {
        assert_eq!(runtime_instance_from_dir("   "), None);
        assert_eq!(runtime_instance_from_dir(""), None);
    }

    // --- Pure manifest parsing ---

    fn sample_manifest(instance: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity name="IsoSession.Runtime" version="1.0.0.0" type="win32" />
  <file name="IsoSessionApp.dll" />
  <iso:instance xmlns:iso="urn:schemas-microsoft-com:agentic-runtime.v1" name="{instance}" />
</assembly>
"#
        )
    }

    const MANIFEST_NO_MARKER: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity name="IsoSession.Runtime" version="1.0.0.0" type="win32" />
  <file name="IsoSessionApp.dll" />
</assembly>
"#;

    #[test]
    fn parse_manifest_instance_extracts_marker() {
        assert_eq!(
            parse_manifest_instance(&sample_manifest("2026.06")).as_deref(),
            Some("2026.06"),
        );
    }

    #[test]
    fn parse_manifest_instance_ignores_identity_and_file_names() {
        // Must return the <iso:instance> name, never "IsoSession.Runtime"
        // (assemblyIdentity) or "IsoSessionApp.dll" (file) -- both carry `name`.
        assert_eq!(
            parse_manifest_instance(&sample_manifest("2026.07")).as_deref(),
            Some("2026.07"),
        );
    }

    #[test]
    fn parse_manifest_instance_none_when_marker_absent() {
        assert_eq!(parse_manifest_instance(MANIFEST_NO_MARKER), None);
    }

    #[test]
    fn attr_value_requires_standalone_attribute_name() {
        // `name` must not be matched inside `filename`.
        assert_eq!(
            attr_value(r#"file name="app.dll""#, "name").as_deref(),
            Some("app.dll"),
        );
        assert_eq!(attr_value(r#"file filename="app.dll""#, "name"), None);
        // Single quotes are accepted too.
        assert_eq!(
            attr_value("iso:instance name='2026.06'", "name").as_deref(),
            Some("2026.06"),
        );
    }

    #[test]
    fn read_manifest_text_decodes_utf16le_bom() {
        let (root, dir) = make_runtime_dir("2026.06", None);
        let manifest = sample_manifest("2026.06");
        let mut bytes = vec![0xFF, 0xFE];
        for u in manifest.encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        let path = dir.join(MANIFEST_NAME);
        std::fs::write(&path, &bytes).unwrap();
        let text = read_manifest_text(&path);
        cleanup(&root);
        assert_eq!(
            parse_manifest_instance(&text.expect("utf-16 manifest should decode")).as_deref(),
            Some("2026.06"),
        );
    }

    // --- Strict runtime-dir checks (existence + manifest) ---

    #[test]
    fn compatible_when_manifest_instance_matches() {
        let (root, dir) = make_runtime_dir("2026.06", Some(&sample_manifest("2026.06")));
        let result = evaluate_instance_compatibility(Some("2026.06"), dir.to_str());
        cleanup(&root);
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn incompatible_when_manifest_instance_differs() {
        let (root, dir) = make_runtime_dir("2026.06", Some(&sample_manifest("2026.07")));
        let result = evaluate_instance_compatibility(Some("2026.06"), dir.to_str());
        cleanup(&root);
        let err = result.expect_err("mismatched instances must error");
        assert!(matches!(err, IsolationSessionError::IncompatibleVersion(_)));
        let msg = err.to_string();
        assert!(msg.contains("2026.06"), "message should name expected: {msg}");
        assert!(msg.contains("2026.07"), "message should name found: {msg}");
    }

    #[test]
    fn manifest_instance_wins_over_folder_name() {
        // Folder leaf is misleading; the manifest is authoritative. The baked
        // `expected` matches the MANIFEST, so it must pass -- the folder name is
        // ignored (this is the rename-spoofing-resistant path).
        let (root, dir) = make_runtime_dir("renamed-2999", Some(&sample_manifest("2026.06")));
        let result = evaluate_instance_compatibility(Some("2026.06"), dir.to_str());
        cleanup(&root);
        assert!(
            result.is_ok(),
            "manifest instance must win over folder name: {result:?}"
        );
    }

    #[test]
    fn falls_back_to_leaf_name_when_manifest_lacks_instance() {
        let (root, dir) = make_runtime_dir("2026.06", Some(MANIFEST_NO_MARKER));
        let result = evaluate_instance_compatibility(Some("2026.06"), dir.to_str());
        cleanup(&root);
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn errors_when_runtime_dir_missing() {
        let (root, dir) = make_runtime_dir("2026.06", Some(&sample_manifest("2026.06")));
        // Remove the tree, then evaluate against the now-missing dir.
        cleanup(&root);
        let err = evaluate_instance_compatibility(Some("2026.06"), dir.to_str())
            .expect_err("a missing runtime dir must error");
        assert!(matches!(err, IsolationSessionError::IncompatibleVersion(_)));
        assert!(
            err.to_string().contains("does not exist"),
            "message should explain the folder is missing: {err}"
        );
    }

    #[test]
    fn errors_when_manifest_missing() {
        // Directory exists but has no IsoSession.manifest.
        let (root, dir) = make_runtime_dir("2026.06", None);
        let result = evaluate_instance_compatibility(Some("2026.06"), dir.to_str());
        cleanup(&root);
        let err = result.expect_err("a runtime dir without a manifest must error");
        assert!(matches!(err, IsolationSessionError::IncompatibleVersion(_)));
        assert!(
            err.to_string().contains(MANIFEST_NAME),
            "message should name the missing manifest: {err}"
        );
    }

    #[test]
    fn skips_when_expected_unknown() {
        // Source-only build: nothing baked in -> never blocks, even for a bogus dir.
        assert!(evaluate_instance_compatibility(None, Some(r"X:\does\not\exist")).is_ok());
        assert!(evaluate_instance_compatibility(Some("   "), Some("anything")).is_ok());
    }

    #[test]
    fn skips_when_runtime_dir_unset() {
        // System activation path (env unset) -> no behavior change.
        assert!(evaluate_instance_compatibility(Some("2026.06"), None).is_ok());
        assert!(evaluate_instance_compatibility(Some("2026.06"), Some("   ")).is_ok());
    }

    // --- Test helpers ---

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Creates `<temp>/mxc-iso-<uniq>/<leaf>`, optionally writing
    /// `IsoSession.manifest` into it. Returns `(root_to_remove, leaf_dir)`.
    fn make_runtime_dir(leaf: &str, manifest: Option<&str>) -> (PathBuf, PathBuf) {
        let uniq = format!(
            "{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let root = std::env::temp_dir().join(format!("mxc-iso-{uniq}"));
        let dir = root.join(leaf);
        std::fs::create_dir_all(&dir).unwrap();
        if let Some(text) = manifest {
            std::fs::write(dir.join(MANIFEST_NAME), text).unwrap();
        }
        (root, dir)
    }

    fn cleanup(root: &std::path::Path) {
        let _ = std::fs::remove_dir_all(root);
    }
}
