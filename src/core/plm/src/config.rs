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
pub fn initialize_filesystem(config: &mut Value) {
    let obj = config.as_object_mut().expect("config root must be object");
    if !obj.contains_key("filesystem") {
        obj.insert("filesystem".into(), json!({}));
    }
    let fs = obj
        .get_mut("filesystem")
        .and_then(|v| v.as_object_mut())
        .expect("filesystem must be object");
    if !fs.contains_key("readwritePaths") {
        fs.insert("readwritePaths".into(), json!([]));
    }
    if !fs.contains_key("readonlyPaths") {
        fs.insert("readonlyPaths".into(), json!([]));
    }
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

fn path_starts_with_any<I: AsRef<str>>(
    file_path: &str,
    paths: impl IntoIterator<Item = I>,
) -> bool {
    let lower = file_path.to_ascii_lowercase();
    for p in paths {
        let pl = p.as_ref().to_ascii_lowercase();
        if lower.starts_with(&pl) {
            return true;
        }
    }
    false
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

fn parent_for_write(file_path: &str) -> Option<String> {
    let p = Path::new(file_path);
    if p.is_file() {
        return p.parent().map(|s| s.to_string_lossy().into_owned());
    }
    if p.is_dir() {
        return Some(file_path.to_string());
    }
    None
}

pub fn update_from_access_events(
    config: &mut Value,
    bin_path: &str,
    events: &[LearningModeAccessEvent],
    deny_set: &HashSet<String>,
    verbose: bool,
) -> AddedPaths {
    let mut added_rw: Vec<String> = Vec::new();
    let mut added_ro: Vec<String> = Vec::new();
    let mut seen_rw: HashSet<String> = HashSet::new();
    let mut seen_ro: HashSet<String> = HashSet::new();

    for ev in events {
        if ev.file_path.eq_ignore_ascii_case(bin_path) {
            if verbose {
                println!("File {} is the binary path, skipping event.", ev.file_path);
            }
            continue;
        }

        if path_starts_with_any(&ev.file_path, deny_set) {
            continue;
        }

        let rw_existing = json_array_strings(&config["filesystem"]["readwritePaths"]);
        if path_starts_with_any(&ev.file_path, &rw_existing) {
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
            config["filesystem"]["readwritePaths"]
                .as_array_mut()
                .unwrap()
                .push(Value::String(parent.clone()));
            if seen_rw.insert(parent.to_ascii_lowercase()) {
                added_rw.push(parent);
            }
            continue;
        }

        // Process Read Requests
        if (ev.access_mask & READ_MASK) != 0 {
            let ro_existing = json_array_strings(&config["filesystem"]["readonlyPaths"]);
            if path_starts_with_any(&ev.file_path, &ro_existing) {
                continue;
            }
            config["filesystem"]["readonlyPaths"]
                .as_array_mut()
                .unwrap()
                .push(Value::String(ev.file_path.clone()));
            if seen_ro.insert(ev.file_path.to_ascii_lowercase()) {
                added_ro.push(ev.file_path.clone());
            }
        }
    }

    AddedPaths {
        readwrite: added_rw,
        readonly: added_ro,
    }
}

/// Locate (case-insensitively) or create the containment sub-object on
/// `config` and ensure its `capabilities` array exists. Returns the key
/// the caller should use to subsequently reach the object.
fn resolve_containment_key(config: &mut Value, containment_name: &str) -> String {
    let obj = config.as_object_mut().unwrap();
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
    let inner = obj.get_mut(&key).unwrap().as_object_mut().unwrap();
    if !inner.contains_key("capabilities") {
        inner.insert("capabilities".into(), json!([]));
    }
    key
}

pub fn merge_capabilities(config: &mut Value, requested: &HashSet<String>) {
    let containment_name = match config.get("containment").and_then(|v| v.as_str()) {
        Some(s) if !s.trim().is_empty() => s.to_string(),
        _ => return,
    };

    let key = resolve_containment_key(config, &containment_name);
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
}

/// Mirror of `Set-UISubsystemEnabled` in the PowerShell version.
pub fn set_ui_subsystem_enabled(config: &mut Value) {
    let obj = config.as_object_mut().unwrap();
    if !obj.contains_key("ui") {
        obj.insert("ui".into(), json!({}));
    }
    let ui = obj.get_mut("ui").unwrap().as_object_mut().unwrap();
    if !ui.contains_key("disable") {
        ui.insert("disable".into(), Value::Bool(true));
    } else {
        ui.insert("disable".into(), Value::Bool(false));
    }
    println!("Enabling access to GUI subsystem ");
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
) {
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
        if ui_events.is_empty() {
            println!("  (no payloads could be decoded)");
        } else {
            for ui in ui_events {
                let denied = match ui.denied {
                    Some(true) => "denied",
                    Some(false) => "allowed",
                    None => "denied=(absent)",
                };
                println!(
                    "  + {} pid={} seq={} category=0x{:08X} detail=0x{:08X} {}",
                    if ui.process_name.is_empty() {
                        "(unknown)"
                    } else {
                        ui.process_name.as_str()
                    },
                    ui.process_id,
                    ui.sequence_number,
                    ui.category,
                    ui.detail,
                    denied,
                );
            }
        }
        println!("  + ui.disable will be set to false (UI subsystem required)");
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
