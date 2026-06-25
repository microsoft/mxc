//! Port of the config-update logic from `stop_plm_logging.ps1`.
//!
//! Reads an MXC container config (JSON), merges discovered file-access
//! paths and capabilities into it, and writes an `Adjusted_*.json` next
//! to it.

use anyhow::{Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::access_event::LearningModeAccessEvent;

// Write Masks (mirror of Get-PlmAccessMasks in stop_plm_logging.ps1)
const FILE_WRITE_MASK: u32 = 0x2;
const FILE_APPEND_MASK: u32 = 0x4;
const WRITE_EXTENDED_ATTRIBUTE_WRITE_MASK: u32 = 0x10;
const DIRECTORY_DELETE_MASK: u32 = 0x40;
const WRITE_ATTRIBUTE_WRITE_MASK: u32 = 0x100;
const FILE_DELETE_MASK: u32 = 0x10000;
const FILE_WRITE_DAC: u32 = 0x40000;
const FILE_WRITE_OWNER: u32 = 0x80000;

pub const WRITE_MASK: u32 = FILE_WRITE_MASK
    | FILE_APPEND_MASK
    | WRITE_EXTENDED_ATTRIBUTE_WRITE_MASK
    | DIRECTORY_DELETE_MASK
    | WRITE_ATTRIBUTE_WRITE_MASK
    | FILE_DELETE_MASK
    | FILE_WRITE_DAC
    | FILE_WRITE_OWNER;

// Read Masks
const READ_DATA_MASK: u32 = 0x1;
const READ_EXTENDED_ATTRIBUTE_MASK: u32 = 0x8;
const DIRECTORY_TRAVERSE_MASK: u32 = 0x20;
const READ_ATTRIBUTE_MASK: u32 = 0x80;
const READ_CONTROL_MASK: u32 = 0x20000;
const SYNCHRONIZE_MASK: u32 = 0x100000;

pub const READ_MASK: u32 = READ_DATA_MASK
    | READ_EXTENDED_ATTRIBUTE_MASK
    | DIRECTORY_TRAVERSE_MASK
    | READ_ATTRIBUTE_MASK
    | READ_CONTROL_MASK
    | SYNCHRONIZE_MASK;

pub struct AddedPaths {
    pub readwrite: Vec<String>,
    pub readonly: Vec<String>,
}

pub fn load_config(path: &Path) -> Result<Value> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let v: Value = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse JSON {}", path.display()))?;
    Ok(v)
}

/// Ensure `config.filesystem.{readwritePaths,readonlyPaths}` exist.
///
/// Returns an error (rather than panicking) when the operator-supplied
/// config has the wrong JSON shape (root is not an object, or `filesystem`
/// exists but is not an object).
pub fn initialize_filesystem(config: &mut Value) -> Result<()> {
    let obj = config
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("config root must be a JSON object"))?;
    if !obj.contains_key("filesystem") {
        obj.insert("filesystem".into(), json!({}));
    }
    let fs = obj
        .get_mut("filesystem")
        .and_then(|v| v.as_object_mut())
        .ok_or_else(|| anyhow::anyhow!("`filesystem` must be a JSON object"))?;
    if !fs.contains_key("readwritePaths") {
        fs.insert("readwritePaths".into(), json!([]));
    } else if !fs["readwritePaths"].is_array() {
        anyhow::bail!("`filesystem.readwritePaths` must be a JSON array");
    }
    if !fs.contains_key("readonlyPaths") {
        fs.insert("readonlyPaths".into(), json!([]));
    } else if !fs["readonlyPaths"].is_array() {
        anyhow::bail!("`filesystem.readonlyPaths` must be a JSON array");
    }
    Ok(())
}

pub fn deny_file_set(config: &Value) -> HashSet<String> {
    let mut out = HashSet::new();
    if let Some(arr) = config
        .get("filesystem")
        .and_then(|fs| fs.get("deniedPaths"))
        .and_then(|v| v.as_array())
    {
        for v in arr {
            if let Some(s) = v.as_str() {
                out.insert(s.to_string());
            }
        }
    }
    out
}

/// Returns true iff `file_path` is equal to, or strictly nested under,
/// any of the entries in `paths`. The match is component-aware: a literal
/// `str::starts_with` would treat `C:\foobar\baz` as nested under `C:\foo`,
/// silently mishandling sibling directories that share a name prefix.
///
/// Both `file_path` and each entry are lowercased once. Trailing path
/// separators on either side are ignored so that `C:\foo` and `C:\foo\`
/// behave identically.
fn path_starts_with_any<I: AsRef<str>>(
    file_path: &str,
    paths: impl IntoIterator<Item = I>,
) -> bool {
    let lower = file_path.to_ascii_lowercase();
    let lower_trimmed = trim_trailing_separators(&lower);
    for p in paths {
        let pl = p.as_ref().to_ascii_lowercase();
        let pl_trimmed = trim_trailing_separators(&pl);
        if pl_trimmed.is_empty() {
            continue;
        }
        if lower_trimmed == pl_trimmed {
            return true;
        }
        if lower_trimmed.len() > pl_trimmed.len()
            && lower_trimmed.starts_with(pl_trimmed)
            && is_path_separator(lower_trimmed.as_bytes()[pl_trimmed.len()])
        {
            return true;
        }
    }
    false
}

fn is_path_separator(b: u8) -> bool {
    b == b'\\' || b == b'/'
}

fn trim_trailing_separators(s: &str) -> &str {
    s.trim_end_matches(['\\', '/'])
}

/// True iff `path` denotes a drive root like `C:\` (or `C:` / `C:/`).
/// We refuse to widen the policy to a bare drive root in
/// `parent_for_write` because that would grant the entire volume.
fn is_drive_root(path: &str) -> bool {
    let trimmed = trim_trailing_separators(path);
    let bytes = trimmed.as_bytes();
    bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn json_array_strings(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|e| e.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

/// Derive the writable-policy entry for `file_path` purely from the path
/// string -- the trace may reference paths that do not exist on the host
/// (sandbox-only paths, deleted files, paths under a virtual mount), so
/// querying the live filesystem with `Path::is_file()` / `is_dir()` would
/// silently drop those write findings.
///
/// Heuristic: if the final path segment contains a `.` it is treated as a
/// file and the parent directory is returned (so the directory becomes
/// writable). Otherwise the path itself is treated as a directory and
/// returned as-is. This matches the original PowerShell `extract_paths`
/// behavior and over-grants in the rare directory-with-a-dot case, which
/// is the safer side to err on.
///
/// One bound: if the computed parent is a bare drive root (e.g. `C:\`)
/// we refuse to widen the policy to the entire volume and fall back to
/// the file path itself. Without this, a single write to a dotted file at
/// a drive root (`C:\hiberfil.sys`, `C:\.git`, ...) would grant write
/// access to every directory under `C:`.
fn parent_for_write(file_path: &str) -> Option<String> {
    let p = Path::new(file_path);
    let file_name = p.file_name()?.to_string_lossy();
    let candidate = if file_name.contains('.') {
        p.parent()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| file_path.to_string())
    } else {
        file_path.to_string()
    };
    if is_drive_root(&candidate) {
        // Promoting to "C:\" would grant the entire volume; keep the
        // grant scoped to the original file path instead.
        return Some(file_path.to_string());
    }
    Some(candidate)
}

pub fn update_from_access_events(
    config: &mut Value,
    bin_path: &str,
    events: &[LearningModeAccessEvent],
    deny_set: &HashSet<String>,
    verbose: bool,
) -> Result<AddedPaths> {
    let mut added_rw: Vec<String> = Vec::new();
    let mut added_ro: Vec<String> = Vec::new();
    let mut seen_rw: HashSet<String> = HashSet::new();
    let mut seen_ro: HashSet<String> = HashSet::new();

    // Seed pre-lowercased shadows of the policy arrays *outside* the loop
    // so the hot path doesn't re-clone-and-lowercase the JSON array on
    // every event. We only push, never read back from the JSON arrays
    // while iterating.
    let mut rw_existing_lower: Vec<String> =
        json_array_strings(&config["filesystem"]["readwritePaths"])
            .into_iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
    let mut ro_existing_lower: Vec<String> =
        json_array_strings(&config["filesystem"]["readonlyPaths"])
            .into_iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
    let deny_lower: Vec<String> = deny_set.iter().map(|s| s.to_ascii_lowercase()).collect();

    for ev in events {
        if ev.file_path.eq_ignore_ascii_case(bin_path) {
            if verbose {
                println!("File {} is the binary path, skipping event.", ev.file_path);
            }
            continue;
        }

        if path_starts_with_any(&ev.file_path, &deny_lower) {
            continue;
        }

        if path_starts_with_any(&ev.file_path, &rw_existing_lower) {
            continue;
        }

        // Process Write Requests
        if (ev.access_mask & WRITE_MASK) != 0 {
            let parent = match parent_for_write(&ev.file_path) {
                Some(p) => p,
                None => {
                    if verbose {
                        println!("Only files and directories are currently supported");
                    }
                    continue;
                }
            };
            // The deny check above only covered the raw `ev.file_path`.
            // `parent_for_write` may widen to the parent directory, which
            // could equal-or-contain a denied entry; re-check before
            // pushing so a non-denied sibling write inside a directory
            // that holds a denied file does not silently grant write to
            // the denied file.
            if path_starts_with_any(&parent, &deny_lower)
                || deny_lower
                    .iter()
                    .any(|d| path_starts_with_any(d, std::iter::once(parent.as_str())))
            {
                if verbose {
                    println!(
                        "Refusing to widen `{}` to `{}` because the parent equals or \
                         contains a deniedPaths entry",
                        ev.file_path, parent
                    );
                }
                continue;
            }
            let arr = config["filesystem"]["readwritePaths"]
                .as_array_mut()
                .ok_or_else(|| {
                    anyhow::anyhow!("`filesystem.readwritePaths` must be a JSON array")
                })?;
            arr.push(Value::String(parent.clone()));
            let parent_lower = parent.to_ascii_lowercase();
            rw_existing_lower.push(parent_lower.clone());
            if seen_rw.insert(parent_lower) {
                added_rw.push(parent);
            }
            continue;
        }

        // Process Read Requests
        if (ev.access_mask & READ_MASK) != 0 {
            if path_starts_with_any(&ev.file_path, &ro_existing_lower) {
                continue;
            }
            let arr = config["filesystem"]["readonlyPaths"]
                .as_array_mut()
                .ok_or_else(|| {
                    anyhow::anyhow!("`filesystem.readonlyPaths` must be a JSON array")
                })?;
            arr.push(Value::String(ev.file_path.clone()));
            let path_lower = ev.file_path.to_ascii_lowercase();
            ro_existing_lower.push(path_lower.clone());
            if seen_ro.insert(path_lower) {
                added_ro.push(ev.file_path.clone());
            }
        }
    }

    Ok(AddedPaths {
        readwrite: added_rw,
        readonly: added_ro,
    })
}

/// Locate (case-insensitively) or create the containment sub-object on
/// `config` and ensure its `capabilities` array exists. Returns the key
/// the caller should use to subsequently reach the object.
fn resolve_containment_key(config: &mut Value, containment_name: &str) -> Result<String> {
    let obj = config
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("config root must be a JSON object"))?;
    let existing_key = obj
        .keys()
        .find(|k| k.eq_ignore_ascii_case(containment_name))
        .cloned();
    let key = match existing_key {
        Some(k) => k,
        None => {
            obj.insert(containment_name.to_string(), json!({}));
            containment_name.to_string()
        }
    };
    if !obj[&key].is_object() {
        obj[&key] = json!({});
    }
    let inner = obj
        .get_mut(&key)
        .and_then(|v| v.as_object_mut())
        .ok_or_else(|| anyhow::anyhow!("`{key}` must be a JSON object"))?;
    if !inner.contains_key("capabilities") {
        inner.insert("capabilities".into(), json!([]));
    } else if !inner["capabilities"].is_array() {
        anyhow::bail!("`{key}.capabilities` must be a JSON array");
    }
    Ok(key)
}

pub fn merge_capabilities(config: &mut Value, requested: &HashSet<String>) -> Result<()> {
    let containment_name = match config.get("containment").and_then(|v| v.as_str()) {
        Some(s) if !s.trim().is_empty() => s.to_string(),
        _ => return Ok(()),
    };

    let key = resolve_containment_key(config, &containment_name)?;
    let caps_arr = config[&key]["capabilities"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    let mut existing: HashSet<String> = HashSet::new();
    for v in &caps_arr {
        if let Some(s) = v.as_str() {
            if !s.trim().is_empty() {
                existing.insert(s.to_ascii_lowercase());
            }
        }
    }

    let mut included: Vec<String> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    for cap in requested {
        if existing.insert(cap.to_ascii_lowercase()) {
            included.push(cap.clone());
        } else {
            skipped.push(cap.clone());
        }
    }

    // Emit a sorted, case-insensitively-deduped capabilities array.
    let mut all_caps: Vec<String> = caps_arr
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .chain(included.iter().cloned())
        .collect();
    let mut seen_lower: HashSet<String> = HashSet::new();
    all_caps.retain(|c| seen_lower.insert(c.to_ascii_lowercase()));
    all_caps.sort_by_key(|c| c.to_ascii_lowercase());

    config[&key]["capabilities"] = Value::Array(all_caps.into_iter().map(Value::String).collect());

    if !included.is_empty() {
        included.sort();
        println!(
            "Capabilities included into '{containment_name}.capabilities' ({}):",
            included.len()
        );
        for c in &included {
            println!("  + {c}");
        }
    }

    if !skipped.is_empty() {
        skipped.sort();
        println!(
            "Capabilities skipped (already present) ({}):",
            skipped.len()
        );
        for c in &skipped {
            println!("  = {c}");
        }
    }
    Ok(())
}

/// Mirror of `Set-UISubsystemEnabled` in the PowerShell version.
pub fn set_ui_subsystem_enabled(config: &mut Value) -> Result<()> {
    let obj = config
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("config root must be a JSON object"))?;
    if !obj.contains_key("ui") {
        obj.insert("ui".into(), json!({}));
    }
    let ui = obj
        .get_mut("ui")
        .and_then(|v| v.as_object_mut())
        .ok_or_else(|| anyhow::anyhow!("`ui` must be a JSON object"))?;
    // CONVERT_TO_GUI violations mean the contained process needed the
    // Win32k GUI subsystem. Set `ui.disable = false` unconditionally so
    // the next run grants access (regardless of whether the key was
    // present before).
    ui.insert("disable".into(), Value::Bool(false));
    println!("Enabling access to GUI subsystem ");
    Ok(())
}

/// Apply the relaxations implied by the OR of `JOB_OBJECT_UILIMIT_*` bits
/// observed in `UI_OPERATION` violations. Each bit names a UI limit the
/// contained process tripped; the corresponding `ui.*` field is widened
/// just enough to let the operation succeed next time.
///
/// Per `docs/base-process-container/UIPolicy_Schema.md`:
/// * `READCLIPBOARD` / `WRITECLIPBOARD`  -> `ui.clipboard`
/// * `SYSTEMPARAMETERS` / `DISPLAYSETTINGS` -> `ui.systemSettings`
/// * `HANDLES` / `GLOBALATOMS` -> `ui.isolation`
/// * `DESKTOP` / `EXITWINDOWS` -> `ui.desktopSystemControl = true`
/// * `IME` -> `ui.ime = true`
/// * `INJECTION` -> `ui.injection = true`
///
/// The function is additive: when a field already grants the requested
/// operation it is left alone; when it grants the complementary half (e.g.
/// existing `clipboard: "read"` plus a fresh `WRITECLIPBOARD` violation)
/// the value is widened to `"all"`.
pub fn apply_ui_operation_flags(config: &mut Value, flags: u32) -> Result<()> {
    use crate::event_parser::{
        JOB_OBJECT_UILIMIT_DESKTOP, JOB_OBJECT_UILIMIT_DISPLAYSETTINGS,
        JOB_OBJECT_UILIMIT_EXITWINDOWS, JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES,
        JOB_OBJECT_UILIMIT_IME, JOB_OBJECT_UILIMIT_INJECTION, JOB_OBJECT_UILIMIT_READCLIPBOARD,
        JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
    };

    if flags == 0 {
        return Ok(());
    }

    let obj = config
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("config root must be a JSON object"))?;
    if !obj.contains_key("ui") {
        obj.insert("ui".into(), json!({}));
    }
    let ui = obj
        .get_mut("ui")
        .and_then(|v| v.as_object_mut())
        .ok_or_else(|| anyhow::anyhow!("`ui` must be a JSON object"))?;

    // -- clipboard ---------------------------------------------------------
    let need_read = flags & JOB_OBJECT_UILIMIT_READCLIPBOARD != 0;
    let need_write = flags & JOB_OBJECT_UILIMIT_WRITECLIPBOARD != 0;
    if need_read || need_write {
        let current = ui
            .get("clipboard")
            .and_then(|v| v.as_str())
            .unwrap_or("none")
            .to_string();
        let (cur_r, cur_w) = clipboard_capabilities(&current);
        let new = pick_clipboard(cur_r || need_read, cur_w || need_write);
        ui.insert("clipboard".into(), Value::String(new.into()));
    }

    // -- systemSettings ----------------------------------------------------
    let need_params = flags & JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS != 0;
    let need_display = flags & JOB_OBJECT_UILIMIT_DISPLAYSETTINGS != 0;
    if need_params || need_display {
        let current = ui
            .get("systemSettings")
            .and_then(|v| v.as_str())
            .unwrap_or("none")
            .to_string();
        let (cur_p, cur_d) = system_settings_capabilities(&current);
        let new = pick_system_settings(cur_p || need_params, cur_d || need_display);
        ui.insert("systemSettings".into(), Value::String(new.into()));
    }

    // -- isolation ---------------------------------------------------------
    let need_other_handles = flags & JOB_OBJECT_UILIMIT_HANDLES != 0;
    let need_global_atoms = flags & JOB_OBJECT_UILIMIT_GLOBALATOMS != 0;
    if need_other_handles || need_global_atoms {
        let current = ui
            .get("isolation")
            .and_then(|v| v.as_str())
            .unwrap_or("container")
            .to_string();
        // `(handles_restricted, atoms_restricted)` for the current value.
        let (cur_h, cur_a) = isolation_restrictions(&current);
        // Removing a restriction = the process now needs that access.
        let new_h = cur_h && !need_other_handles;
        let new_a = cur_a && !need_global_atoms;
        let new = pick_isolation(new_h, new_a);
        ui.insert("isolation".into(), Value::String(new.into()));
    }

    // -- desktopSystemControl (bundled DESKTOP + EXITWINDOWS) -------------
    if flags & (JOB_OBJECT_UILIMIT_DESKTOP | JOB_OBJECT_UILIMIT_EXITWINDOWS) != 0 {
        ui.insert("desktopSystemControl".into(), Value::Bool(true));
    }

    // -- ime ---------------------------------------------------------------
    if flags & JOB_OBJECT_UILIMIT_IME != 0 {
        ui.insert("ime".into(), Value::Bool(true));
    }

    // -- injection ---------------------------------------------------------
    if flags & JOB_OBJECT_UILIMIT_INJECTION != 0 {
        ui.insert("injection".into(), Value::Bool(true));
    }

    // A non-empty `ui.*` policy only makes sense with the GUI subsystem on.
    // Mirror `set_ui_subsystem_enabled` -- if `disable` is already present
    // we set it to false; otherwise leave it absent so the schema default
    // (no GUI) still applies when the operator has not explicitly enabled
    // GUI elsewhere. Operators using `--ui` flows always end up with
    // `disable: false` via the existing `set_ui_subsystem_enabled` call.
    if let Some(v) = ui.get_mut("disable") {
        *v = Value::Bool(false);
    }
    Ok(())
}

fn clipboard_capabilities(value: &str) -> (bool, bool) {
    // (can_read, can_write)
    match value {
        "all" => (true, true),
        "read" => (true, false),
        "write" => (false, true),
        _ => (false, false), // "none" or anything unrecognised
    }
}

fn pick_clipboard(read: bool, write: bool) -> &'static str {
    match (read, write) {
        (true, true) => "all",
        (true, false) => "read",
        (false, true) => "write",
        (false, false) => "none",
    }
}

fn system_settings_capabilities(value: &str) -> (bool, bool) {
    // (can_params, can_display)
    match value {
        "all" => (true, true),
        "parameters" => (true, false),
        "display" => (false, true),
        _ => (false, false),
    }
}

fn pick_system_settings(params: bool, display: bool) -> &'static str {
    match (params, display) {
        (true, true) => "all",
        (true, false) => "parameters",
        (false, true) => "display",
        (false, false) => "none",
    }
}

fn isolation_restrictions(value: &str) -> (bool, bool) {
    // (handles_restricted, atoms_restricted) for each isolation value.
    // Per UIPolicy_Schema.md:
    //   container = HANDLES + GLOBALATOMS
    //   handles   = HANDLES
    //   atoms     = GLOBALATOMS
    //   desktop   = neither
    match value {
        "container" => (true, true),
        "handles" => (true, false),
        "atoms" => (false, true),
        "desktop" => (false, false),
        _ => (true, true),
    }
}

fn pick_isolation(handles_restricted: bool, atoms_restricted: bool) -> &'static str {
    match (handles_restricted, atoms_restricted) {
        (true, true) => "container",
        (true, false) => "handles",
        (false, true) => "atoms",
        (false, false) => "desktop",
    }
}

pub fn resolve_adjusted_config_path(dest_config: &Path, override_path: Option<&Path>) -> PathBuf {
    if let Some(p) = override_path {
        if let Some(parent) = p.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        return p.to_path_buf();
    }
    let parent = dest_config.parent().unwrap_or_else(|| Path::new("."));
    let leaf = dest_config
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    parent.join(format!("Adjusted_{leaf}"))
}

pub fn save_adjusted_config(config: &Value, path: &Path) -> Result<()> {
    let pretty = serde_json::to_string_pretty(config)?;
    std::fs::write(path, pretty).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

/// Decode a Windows file access mask into a `|`-separated list of the
/// mnemonic flag names PLM cares about (the same constants used to
/// classify read vs. write above). Unknown bits are reported as a
/// trailing `OTHER(0x...)` token so nothing is silently dropped.
fn decode_access_mask(mask: u32) -> String {
    const NAMED: &[(u32, &str)] = &[
        (FILE_WRITE_MASK, "FILE_WRITE"),
        (FILE_APPEND_MASK, "FILE_APPEND"),
        (WRITE_EXTENDED_ATTRIBUTE_WRITE_MASK, "WRITE_EA"),
        (DIRECTORY_DELETE_MASK, "DIRECTORY_DELETE"),
        (WRITE_ATTRIBUTE_WRITE_MASK, "WRITE_ATTRIBUTES"),
        (FILE_DELETE_MASK, "FILE_DELETE"),
        (FILE_WRITE_DAC, "WRITE_DAC"),
        (FILE_WRITE_OWNER, "WRITE_OWNER"),
        (READ_DATA_MASK, "READ_DATA"),
        (READ_EXTENDED_ATTRIBUTE_MASK, "READ_EA"),
        (DIRECTORY_TRAVERSE_MASK, "DIRECTORY_TRAVERSE"),
        (READ_ATTRIBUTE_MASK, "READ_ATTRIBUTES"),
        (READ_CONTROL_MASK, "READ_CONTROL"),
        (SYNCHRONIZE_MASK, "SYNCHRONIZE"),
    ];

    let mut parts: Vec<&str> = Vec::new();
    let mut covered: u32 = 0;
    for (bit, name) in NAMED {
        if mask & bit != 0 {
            parts.push(name);
            covered |= bit;
        }
    }
    let leftover = mask & !covered;
    if leftover != 0 {
        // Render leftover bits as a hex token; allocate into a static-
        // lifetime-free string by appending after join.
        let joined = parts.join("|");
        if joined.is_empty() {
            return format!("OTHER(0x{leftover:X})");
        }
        return format!("{joined}|OTHER(0x{leftover:X})");
    }
    if parts.is_empty() {
        "NONE".to_string()
    } else {
        parts.join("|")
    }
}

fn classify_mask(mask: u32) -> &'static str {
    let w = mask & WRITE_MASK != 0;
    let r = mask & READ_MASK != 0;
    match (r, w) {
        (true, true) => "RW",
        (false, true) => "W",
        (true, false) => "R",
        (false, false) => "-",
    }
}

/// Print every unique file path observed in `events` with the OR-ed
/// access mask requested against it, plus the set of capabilities
/// discovered in the trace. Always emitted (independent of verbose).
pub fn write_detection_summary(
    events: &[LearningModeAccessEvent],
    capabilities: &HashSet<String>,
    ui_event_count: u32,
    ui_events: &[crate::event_parser::UiEvent],
    ui_operation_flags: u32,
) {
    use crate::event_parser::{ui_limit_name, CONVERT_TO_GUI, UI_OPERATION};
    use std::collections::BTreeMap;

    let mut per_path: BTreeMap<String, u32> = BTreeMap::new();
    for ev in events {
        *per_path.entry(ev.file_path.clone()).or_insert(0) |= ev.access_mask;
    }

    println!();
    println!("Detected file paths ({}):", per_path.len());
    if per_path.is_empty() {
        println!("  (none)");
    } else {
        for (path, mask) in &per_path {
            println!(
                "  [{:2}] 0x{:08X} {} {}",
                classify_mask(*mask),
                mask,
                decode_access_mask(*mask),
                path
            );
        }
    }

    println!();
    println!(
        "Detected UI injection events ({ui_event_count}, parsed {}):",
        ui_events.len()
    );
    if ui_event_count == 0 {
        println!("  (none)");
    } else {
        let mut convert_to_gui = 0u32;
        let mut ui_operation = 0u32;
        if ui_events.is_empty() {
            println!("  (no payloads could be decoded)");
        } else {
            for ui in ui_events {
                let denied = match ui.denied {
                    Some(true) => "denied",
                    Some(false) => "allowed",
                    None => "denied=(absent)",
                };
                let category_name = match ui.category {
                    CONVERT_TO_GUI => "CONVERT_TO_GUI",
                    UI_OPERATION => "UI_OPERATION",
                    _ => "UNKNOWN",
                };
                let detail_name = if ui.category == UI_OPERATION {
                    ui_limit_name(ui.detail).unwrap_or("UNKNOWN")
                } else {
                    "-"
                };
                println!(
                    "  + {} pid={} seq={} category=0x{:08X} ({}) detail=0x{:08X} ({}) {}",
                    if ui.process_name.is_empty() {
                        "(unknown)"
                    } else {
                        ui.process_name.as_str()
                    },
                    ui.process_id,
                    ui.sequence_number,
                    ui.category,
                    category_name,
                    ui.detail,
                    detail_name,
                    denied,
                );
                match ui.category {
                    CONVERT_TO_GUI => convert_to_gui += 1,
                    UI_OPERATION => ui_operation += 1,
                    _ => {}
                }
            }
        }
        if convert_to_gui > 0 {
            println!("  + ui.disable will be set to false (UI subsystem required)");
        }
        if ui_operation > 0 {
            println!(
                "  + ui.* policy will be relaxed for blocked operations (flags=0x{:04X}):",
                ui_operation_flags
            );
            for bit_pos in 0..16 {
                let bit = 1u32 << bit_pos;
                if ui_operation_flags & bit != 0 {
                    println!(
                        "      - 0x{:04X} ({})",
                        bit,
                        ui_limit_name(bit).unwrap_or("UNKNOWN")
                    );
                }
            }
        }
    }

    println!();
    println!("Detected capabilities ({}):", capabilities.len());
    if capabilities.is_empty() {
        println!("  (none)");
    } else {
        let mut sorted: Vec<&String> = capabilities.iter().collect();
        sorted.sort();
        for c in sorted {
            println!("  + {c}");
        }
    }
}

pub fn write_added_paths_summary(added: &AddedPaths) {
    println!();
    if !added.readwrite.is_empty() {
        println!("Added to readwritePaths ({}):", added.readwrite.len());
        for p in &added.readwrite {
            println!("  + {p}");
        }
    }
    if !added.readonly.is_empty() {
        println!("Added to readonlyPaths ({}):", added.readonly.len());
        for p in &added.readonly {
            println!("  + {p}");
        }
    }
}

pub fn write_requested_capabilities_summary(requested: &HashSet<String>, verbose: bool) {
    if !verbose {
        return;
    }
    println!();
    println!("All requested capabilities ({}):", requested.len());
    if requested.is_empty() {
        println!("  (none)");
        return;
    }
    let mut sorted: Vec<&String> = requested.iter().collect();
    sorted.sort();
    for c in sorted {
        println!("  {c}");
    }
}

// Map struct used for serde_json's `preserve_order` feature lookup.
#[allow(dead_code)]
type _Map = Map<String, Value>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access_event::LearningModeAccessEvent;
    use serde_json::json;

    fn ev_write(path: &str) -> LearningModeAccessEvent {
        LearningModeAccessEvent {
            time_created: chrono::Utc::now(),
            process_id: 0,
            thread_id: 0,
            learning_mode: String::new(),
            resource_type: String::new(),
            file_path: path.to_string(),
            app_path: String::new(),
            access_mask: FILE_WRITE_MASK,
        }
    }

    fn ev_read(path: &str) -> LearningModeAccessEvent {
        LearningModeAccessEvent {
            time_created: chrono::Utc::now(),
            process_id: 0,
            thread_id: 0,
            learning_mode: String::new(),
            resource_type: String::new(),
            file_path: path.to_string(),
            app_path: String::new(),
            access_mask: READ_DATA_MASK,
        }
    }

    // ---- parent_for_write -------------------------------------------------

    #[test]
    fn parent_for_write_promotes_file_to_parent() {
        assert_eq!(
            parent_for_write("C:\\a\\b\\c.txt").as_deref(),
            Some("C:\\a\\b")
        );
    }

    #[test]
    fn parent_for_write_treats_dotless_segment_as_directory() {
        assert_eq!(
            parent_for_write("C:\\a\\b\\Makefile").as_deref(),
            Some("C:\\a\\b\\Makefile")
        );
    }

    #[test]
    fn parent_for_write_refuses_drive_root_promotion() {
        // C:\hiberfil.sys would have promoted to "C:\" (whole volume);
        // we must fall back to the file path itself.
        assert_eq!(
            parent_for_write("C:\\hiberfil.sys").as_deref(),
            Some("C:\\hiberfil.sys")
        );
        assert_eq!(parent_for_write("C:\\.git").as_deref(), Some("C:\\.git"));
    }

    // ---- path_starts_with_any --------------------------------------------

    #[test]
    fn starts_with_any_rejects_sibling_with_shared_prefix() {
        // The historical bug: "c:\foobar\baz".starts_with("c:\foo") was
        // true, silently mishandling siblings sharing a name prefix.
        assert!(!path_starts_with_any(
            "C:\\foobar\\baz",
            ["C:\\foo".to_string()]
        ));
    }

    #[test]
    fn starts_with_any_matches_exact() {
        assert!(path_starts_with_any("C:\\foo", ["C:\\foo".to_string()]));
    }

    #[test]
    fn starts_with_any_matches_nested_child() {
        assert!(path_starts_with_any(
            "C:\\foo\\bar\\baz.txt",
            ["C:\\foo".to_string()]
        ));
    }

    #[test]
    fn starts_with_any_is_case_insensitive_and_separator_tolerant() {
        assert!(path_starts_with_any(
            "c:\\Foo\\bar",
            ["C:\\foo\\".to_string()]
        ));
    }

    #[test]
    fn is_drive_root_detects_variants() {
        assert!(is_drive_root("C:\\"));
        assert!(is_drive_root("C:"));
        assert!(is_drive_root("c:/"));
        assert!(!is_drive_root("C:\\foo"));
        assert!(!is_drive_root(""));
    }

    // ---- update_from_access_events ---------------------------------------

    fn run_update(
        config: &mut Value,
        events: &[LearningModeAccessEvent],
        deny: &[&str],
    ) -> AddedPaths {
        initialize_filesystem(config).unwrap();
        let deny_set: HashSet<String> = deny.iter().map(|s| (*s).to_string()).collect();
        update_from_access_events(config, "__never_matches__", events, &deny_set, false).unwrap()
    }

    #[test]
    fn write_to_denied_path_is_not_promoted() {
        let mut cfg = json!({
            "filesystem": { "deniedPaths": ["C:\\Secrets\\token.dat"] }
        });
        let added = run_update(
            &mut cfg,
            &[ev_write("C:\\Secrets\\token.dat")],
            &["C:\\Secrets\\token.dat"],
        );
        assert!(added.readwrite.is_empty());
        assert!(cfg["filesystem"]["readwritePaths"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn write_to_sibling_does_not_bypass_denied_via_parent() {
        // Regression: write to a non-denied sibling inside a directory
        // that holds a denied file must not promote the parent to
        // readwrite (which would transitively grant write to the denied
        // file).
        let mut cfg = json!({
            "filesystem": { "deniedPaths": ["C:\\Secrets"] }
        });
        let added = run_update(
            &mut cfg,
            &[ev_write("C:\\Secrets\\scratch.txt")],
            &["C:\\Secrets"],
        );
        assert!(
            added.readwrite.is_empty(),
            "expected no rw promotion, got: {:?}",
            added.readwrite
        );
    }

    #[test]
    fn write_at_drive_root_does_not_grant_whole_volume() {
        let mut cfg = json!({});
        let added = run_update(&mut cfg, &[ev_write("C:\\hiberfil.sys")], &[]);
        // Must NOT contain "C:\"
        assert!(
            !added.readwrite.iter().any(|p| is_drive_root(p)),
            "drive-root grant leaked: {:?}",
            added.readwrite
        );
    }

    #[test]
    fn read_under_existing_readonly_parent_is_not_duplicated() {
        let mut cfg = json!({
            "filesystem": { "readonlyPaths": ["C:\\src"] }
        });
        let added = run_update(&mut cfg, &[ev_read("C:\\src\\main.rs")], &[]);
        assert!(added.readonly.is_empty());
    }

    #[test]
    fn idempotent_on_already_writable_path() {
        let mut cfg = json!({
            "filesystem": { "readwritePaths": ["C:\\out"] }
        });
        let added = run_update(&mut cfg, &[ev_write("C:\\out\\foo.txt")], &[]);
        assert!(added.readwrite.is_empty());
    }

    // ---- typed-error behavior --------------------------------------------

    #[test]
    fn initialize_filesystem_rejects_non_object_root() {
        let mut cfg = json!([]);
        assert!(initialize_filesystem(&mut cfg).is_err());
    }

    #[test]
    fn initialize_filesystem_rejects_wrong_typed_filesystem() {
        let mut cfg = json!({ "filesystem": "deny" });
        assert!(initialize_filesystem(&mut cfg).is_err());
    }

    #[test]
    fn set_ui_subsystem_enabled_rejects_non_object_ui() {
        let mut cfg = json!({ "ui": "disabled" });
        assert!(set_ui_subsystem_enabled(&mut cfg).is_err());
    }

    #[test]
    fn set_ui_subsystem_enabled_always_writes_false() {
        // Was previously inverted -- this locks in the fix.
        let mut cfg = json!({});
        set_ui_subsystem_enabled(&mut cfg).unwrap();
        assert_eq!(cfg["ui"]["disable"], json!(false));

        let mut cfg2 = json!({ "ui": { "disable": true } });
        set_ui_subsystem_enabled(&mut cfg2).unwrap();
        assert_eq!(cfg2["ui"]["disable"], json!(false));
    }

    // ---- apply_ui_operation_flags ----------------------------------------

    #[test]
    fn apply_ui_flags_clipboard_widens_to_all() {
        use crate::event_parser::{
            JOB_OBJECT_UILIMIT_READCLIPBOARD, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
        };
        let mut cfg = json!({});
        apply_ui_operation_flags(
            &mut cfg,
            JOB_OBJECT_UILIMIT_READCLIPBOARD | JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
        )
        .unwrap();
        assert_eq!(cfg["ui"]["clipboard"], json!("all"));
    }

    #[test]
    fn apply_ui_flags_ime_sets_true() {
        use crate::event_parser::JOB_OBJECT_UILIMIT_IME;
        let mut cfg = json!({});
        apply_ui_operation_flags(&mut cfg, JOB_OBJECT_UILIMIT_IME).unwrap();
        assert_eq!(cfg["ui"]["ime"], json!(true));
    }

    #[test]
    fn apply_ui_flags_desktop_or_exitwindows_sets_desktop_system_control() {
        use crate::event_parser::{JOB_OBJECT_UILIMIT_DESKTOP, JOB_OBJECT_UILIMIT_EXITWINDOWS};
        let mut cfg = json!({});
        apply_ui_operation_flags(&mut cfg, JOB_OBJECT_UILIMIT_DESKTOP).unwrap();
        assert_eq!(cfg["ui"]["desktopSystemControl"], json!(true));

        let mut cfg2 = json!({});
        apply_ui_operation_flags(&mut cfg2, JOB_OBJECT_UILIMIT_EXITWINDOWS).unwrap();
        assert_eq!(cfg2["ui"]["desktopSystemControl"], json!(true));
    }

    #[test]
    fn apply_ui_flags_injection_sets_true() {
        use crate::event_parser::JOB_OBJECT_UILIMIT_INJECTION;
        let mut cfg = json!({});
        apply_ui_operation_flags(&mut cfg, JOB_OBJECT_UILIMIT_INJECTION).unwrap();
        assert_eq!(cfg["ui"]["injection"], json!(true));
    }

    #[test]
    fn apply_ui_flags_rejects_non_object_ui() {
        let mut cfg = json!({ "ui": null });
        use crate::event_parser::JOB_OBJECT_UILIMIT_IME;
        assert!(apply_ui_operation_flags(&mut cfg, JOB_OBJECT_UILIMIT_IME).is_err());
    }

    // ---- merge_capabilities ----------------------------------------------

    #[test]
    fn merge_capabilities_dedups_case_insensitively_and_sorts() {
        let mut cfg = json!({
            "containment": "processcontainer",
            "processcontainer": { "capabilities": ["InternetClient"] }
        });
        let req: HashSet<String> = ["internetclient", "registryRead"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        merge_capabilities(&mut cfg, &req).unwrap();
        let caps = cfg["processcontainer"]["capabilities"].as_array().unwrap();
        // Only one of {InternetClient, internetclient} survives, plus
        // registryRead. Result is case-insensitively sorted.
        let names: Vec<&str> = caps.iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(names.len(), 2);
        assert!(names
            .iter()
            .any(|n| n.eq_ignore_ascii_case("internetclient")));
        assert!(names.iter().any(|n| n.eq_ignore_ascii_case("registryRead")));
    }
}
