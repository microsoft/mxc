//! Port of the config-update logic from `stop_plm_logging.ps1`.
//!
//! Reads an MXC container config (JSON), merges discovered file-access
//! paths and capabilities into it, and writes an `Adjusted_*.json` next
//! to it.

use anyhow::{Context, Result};
use serde_json::{json, Value};
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

#[derive(Debug)]
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

/// Strip a Windows verbatim (`\\?\`) or device (`\\.\`) prefix from `path`.
/// Returns `None` for UNC verbatim (`\\?\UNC\…`) — those paths are
/// network shares and never represent local drive roots.
///
/// Used by `is_drive_root` and `normalize_path` so the rest of the
/// comparison machinery only deals with plain drive-letter forms even
/// when ETW hands us the verbatim variant that an audited process
/// passed straight to NtCreateFile.
fn strip_verbatim_or_device_prefix(s: &str) -> Option<&str> {
    // UNC verbatim: never a drive root, never legal for policy widening.
    if let Some(head) = s.get(..8) {
        if head.eq_ignore_ascii_case("\\\\?\\UNC\\") {
            return None;
        }
    }
    if let Some(head) = s.get(..4) {
        if head == "\\\\?\\" || head == "\\\\.\\" {
            return Some(&s[4..]);
        }
        // `\??\` is the NT-object-manager equivalent of `\\?\`.
        // Strip it here so any call site that bypasses
        // `normalize_file_path` (e.g. the self-event filter on a raw
        // `file_path`) still produces a comparable form.
        if head == "\\??\\" {
            return Some(&s[4..]);
        }
    }
    Some(s)
}

/// Normalize a Windows path for comparison-only use (returned form is
/// lowercase ASCII, `\`-separated, trailing separators / dots /
/// spaces stripped from every component — mirrors
/// `RtlDosPathNameToNtPathName`).
///
/// Returns `None` for UNC verbatim (`\\?\UNC\…`) or paths containing
/// `:` outside the drive-letter separator (alternate data streams,
/// which the kernel resolves to the parent object — must not bypass
/// deny matching).
///
/// Not applied to strings stored in policy arrays — those keep their
/// original case for operator readability.
fn normalize_path(p: &str) -> Option<String> {
    // 1. Strip verbatim / device prefix (`\\?\`, `\\.\`, and the
    //    NT-object `\??\` prefix). UNC verbatim is rejected because
    //    we don't grant policy to network shares. The `\??\` prefix
    //    must be stripped here too (not only in `event_parser`), so
    //    events that bypass that layer don't leak the literal prefix
    //    into config storage.
    let stripped = strip_verbatim_or_device_prefix(p)?;

    // 2. Collapse `/` → `\`, lowercase ASCII in a single pass.
    let mut s = String::with_capacity(stripped.len());
    for c in stripped.chars() {
        let c = if c == '/' { '\\' } else { c };
        s.push(c.to_ascii_lowercase());
    }

    // 3. Reject `:` outside the drive-letter separator (s[1]).
    //    ADS-on-directory (`C:\Secrets:hidden`) escapes deny matching
    //    otherwise because the byte after the matched prefix is `:`,
    //    not a separator.
    for (i, b) in s.bytes().enumerate() {
        if b == b':' && i != 1 {
            return None;
        }
    }

    // 4. Trim trailing separators from the whole string, then per-component
    //    strip trailing dots and spaces. Leave the drive-letter component
    //    ("c:") untouched.
    //
    //    `..` and `.` segments break
    //    the deny-prefix invariant — `C:\Windows\.\System32\evil` and
    //    `C:\dir\..\Secrets\token.dat` would normalize to forms that
    //    miss a deny entry on the canonical parent. Rather than
    //    canonicalize (which requires filesystem access we don't
    //    have here), reject any input containing a `.` or `..`
    //    pure-segment. Callers fall back to "no match" semantics,
    //    which for a deny rule is the safe failure mode (the policy
    //    won't widen on an event we can't prove safe).
    let trimmed = s.trim_end_matches('\\');
    let mut parts: Vec<String> = Vec::new();
    let mut in_leading_unc = true;
    for (i, part) in trimmed.split('\\').enumerate() {
        if i == 0 && part.len() == 2 && part.as_bytes()[1] == b':' {
            parts.push(part.to_string());
            in_leading_unc = false;
            continue;
        }
        // Leading empty segments (UNC `\\server\share\x` splits to
        // `["", "", "server", ...]`) are preserved verbatim; deny
        // matching treats UNC as pass-through. Once we see a
        // non-empty segment, leave the leading-UNC mode and any
        // future empty segment is an error (doubled backslash etc).
        if part.is_empty() && in_leading_unc && i < 2 {
            parts.push(String::new());
            continue;
        }
        in_leading_unc = false;
        let stripped = part.trim_end_matches(['.', ' ']);
        // Reject pure traversal segments and other empty segments
        // (`..` or `.`, or empty after trim — these arise from
        // malformed inputs or doubled backslashes in non-UNC paths).
        if part == "." || part == ".." || stripped.is_empty() {
            return None;
        }
        parts.push(stripped.to_string());
    }
    Some(parts.join("\\"))
}

/// Returns true iff `file_path_norm` is equal to, or strictly nested
/// under, any of the entries in `paths_norm`.
///
/// **Both inputs must already be normalized via `normalize_path`.** The
/// hot path in `update_from_access_events` normalizes once per event and
/// once per shadow-vector seed; doing it again here would re-allocate
/// `2·(|rw|+|ro|+|deny|)` strings per event and dominate wall time on
/// long traces. Comparisons are pure byte-slice equality on already-
/// lowercased data.
///
/// Complexity is O(N) over `paths_norm`. The hot loop short-circuits
/// the exact-match case via a parallel `HashSet` before calling here,
/// so the practical cost is bounded by the number of *prefix* matches.
/// For traces that grow `readwritePaths` to >1k entries this is the
/// dominant CPU; a follow-up could switch to a path-component trie,
/// but a naive sorted-vec binary search is wrong here (multiple
/// distinct prefixes can match a single event path, and the
/// lexicographically-max element ≤ ev is not guaranteed to be one of
/// them — see `C:\foo bar` vs `C:\foo\baz`). The early-bail on first
/// byte below removes most cross-drive-letter false candidates.
fn path_starts_with_any_norm<I: AsRef<str>>(
    file_path_norm: &str,
    paths_norm: impl IntoIterator<Item = I>,
) -> bool {
    let fp_bytes = file_path_norm.as_bytes();
    let fp_first = fp_bytes.first().copied();
    for p in paths_norm {
        let pn = p.as_ref();
        if pn.is_empty() {
            continue;
        }
        let pn_bytes = pn.as_bytes();
        if pn_bytes.first().copied() != fp_first {
            continue;
        }
        if file_path_norm == pn {
            return true;
        }
        if fp_bytes.len() > pn_bytes.len()
            && fp_bytes[pn_bytes.len()] == b'\\'
            && file_path_norm.starts_with(pn)
        {
            return true;
        }
    }
    false
}

fn trim_trailing_separators(s: &str) -> &str {
    s.trim_end_matches(['\\', '/'])
}

/// Case-insensitive ASCII compare without allocation. Used by
/// `merge_capabilities` so the sort step doesn't allocate two lowercased
/// `String`s per comparison. Non-ASCII bytes are compared verbatim.
fn cmp_ci_ascii(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let mut ai = a.bytes();
    let mut bi = b.bytes();
    loop {
        match (ai.next(), bi.next()) {
            (None, None) => return Ordering::Equal,
            (None, _) => return Ordering::Less,
            (_, None) => return Ordering::Greater,
            (Some(x), Some(y)) => match x.to_ascii_lowercase().cmp(&y.to_ascii_lowercase()) {
                Ordering::Equal => continue,
                ord => return ord,
            },
        }
    }
}

/// True iff `path` denotes a drive root like `C:\` (or `C:` / `C:/` or
/// the verbatim/device variants `\\?\C:\` / `\\.\C:\`).
///
/// We refuse to widen the policy to a bare drive root in
/// `parent_for_write` because that would grant the entire volume.
/// Accepting only the bare `[A-Za-z]:` form would let `\\?\C:\hiberfil.sys`
/// (the form ETW emits when an audited process called `NtCreateFile`
/// with a verbatim path) bypass the guard.
fn is_drive_root(path: &str) -> bool {
    let stripped = match strip_verbatim_or_device_prefix(path) {
        Some(s) => s,
        // UNC verbatim is not a drive root.
        None => return false,
    };
    let trimmed = trim_trailing_separators(stripped);
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

    // Pre-normalize every comparison input exactly once (here, outside the
    // per-event loop). The hot path then does pure byte-slice compares
    // with no allocation. The JSON array clone is hoisted out of the
    // loop and the per-call `to_ascii_lowercase()` is eliminated. For
    // exact-match idempotence (the common
    // case after a few hundred events) we also maintain a `HashSet` of
    // already-covered normalized forms for O(1) short-circuit.
    let bin_path_norm = normalize_path(bin_path);
    let deny_norm: Vec<String> = deny_set.iter().filter_map(|s| normalize_path(s)).collect();
    let deny_set_norm: HashSet<&str> = deny_norm.iter().map(|s| s.as_str()).collect();

    let mut rw_existing_norm: Vec<String> =
        json_array_strings(&config["filesystem"]["readwritePaths"])
            .into_iter()
            .filter_map(|s| normalize_path(&s))
            .collect();
    let mut rw_existing_set: HashSet<String> = rw_existing_norm.iter().cloned().collect();
    let mut ro_existing_norm: Vec<String> =
        json_array_strings(&config["filesystem"]["readonlyPaths"])
            .into_iter()
            .filter_map(|s| normalize_path(&s))
            .collect();
    let mut ro_existing_set: HashSet<String> = ro_existing_norm.iter().cloned().collect();

    for ev in events {
        // Normalize this event's path once. Reject ADS-on-directory and
        // UNC-verbatim forms (`normalize_path` returns None) so they
        // can't bypass deny matching.
        let ev_norm = match normalize_path(&ev.file_path) {
            Some(n) => n,
            None => {
                if verbose {
                    println!(
                        "Skipping un-normalizable path (UNC verbatim or stream syntax): {}",
                        ev.file_path
                    );
                }
                continue;
            }
        };

        // Self-access filter: events whose path equals the wxc-exec
        // binary (in any spelling — raw, verbatim, lower/upper case)
        // are noise and skipped. The verbatim-prefixed variant matters
        // because `stop.rs` canonicalises bin_path via `canonicalize()`,
        // which on Windows returns the `\\?\C:\…` form while ETW
        // reports the plain `C:\…` form; comparing only the raw strings
        // let the binary path leak into the output
        // config as a readonly entry.
        let is_self_event = ev.file_path.eq_ignore_ascii_case(bin_path)
            || bin_path_norm
                .as_ref()
                .is_some_and(|bp_norm| bp_norm == &ev_norm);
        if is_self_event {
            if verbose {
                println!("File {} is the binary path, skipping event.", ev.file_path);
            }
            continue;
        }

        // Deny check: exact-set first (O(1)), then prefix scan over the
        // (typically very small) deny vector.
        if deny_set_norm.contains(ev_norm.as_str())
            || path_starts_with_any_norm(&ev_norm, &deny_norm)
        {
            continue;
        }

        // Already-covered short-circuit for readwrite policy.
        if rw_existing_set.contains(&ev_norm)
            || path_starts_with_any_norm(&ev_norm, &rw_existing_norm)
        {
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
            let parent_norm = match normalize_path(&parent) {
                Some(n) => n,
                None => continue,
            };
            // The deny check above only covered the raw `ev.file_path`.
            // `parent_for_write` may widen to the parent directory, which
            // could equal-or-contain a denied entry; re-check (using
            // normalized forms on both sides this time) before pushing so
            // a non-denied sibling write inside a directory that holds a
            // denied file does not silently grant write to the denied
            // file.
            if deny_set_norm.contains(parent_norm.as_str())
                || path_starts_with_any_norm(&parent_norm, &deny_norm)
                || deny_norm
                    .iter()
                    .any(|d| path_starts_with_any_norm(d, std::iter::once(parent_norm.as_str())))
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
            if rw_existing_set.insert(parent_norm.clone()) {
                rw_existing_norm.push(parent_norm.clone());
            }
            if seen_rw.insert(parent_norm) {
                added_rw.push(parent);
            }
            continue;
        }

        // Process Read Requests
        if (ev.access_mask & READ_MASK) != 0 {
            if ro_existing_set.contains(&ev_norm)
                || path_starts_with_any_norm(&ev_norm, &ro_existing_norm)
            {
                continue;
            }
            let arr = config["filesystem"]["readonlyPaths"]
                .as_array_mut()
                .ok_or_else(|| {
                    anyhow::anyhow!("`filesystem.readonlyPaths` must be a JSON array")
                })?;
            arr.push(Value::String(ev.file_path.clone()));
            if ro_existing_set.insert(ev_norm.clone()) {
                ro_existing_norm.push(ev_norm.clone());
            }
            if seen_ro.insert(ev_norm) {
                added_ro.push(ev.file_path.clone());
            }
        }
    }

    Ok(AddedPaths {
        readwrite: added_rw,
        readonly: added_ro,
    })
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

/// Decode a Windows file access mask into a |-separated list of the
/// mnemonic flag names PLM cares about. Unknown bits are reported as a
/// trailing OTHER(0x...) token so nothing is silently dropped.
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

/// Print every unique file path observed in vents with the OR-ed
/// access mask requested against it, plus the set of capabilities
/// discovered in the trace. UI-violation summary lands in a later PR.
pub fn write_detection_summary(events: &[LearningModeAccessEvent], capabilities: &HashSet<String>) {
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

/// Map a `containment` enum value (lowercase, matching the schema's
/// `containment` enum) to the JSON sub-object key that holds its
/// `capabilities` array, if any. Today only the ProcessContainer
/// backend has a `capabilities` array in its schema (see
/// `wxc_common::models::ContainmentBackend::section_path`); every
/// other backend either does not exist on Windows or does not accept
/// AppContainer-style capability SIDs at all.
///
/// Returns `Some(key)` for backends that support capability merge,
/// `None` for backends that don't — callers must skip the merge with
/// a diagnostic rather than misfiling capabilities into a section the
/// runner will ignore. A naive fallthrough to `processContainer` for
/// any unknown value silently produces a malformed config for
/// `seatbelt`/`lxc`/`wslc`/`windows_sandbox`/`isolation_session` etc.,
/// so unknown values return `None` instead.
fn capability_subobject_key(enum_value: &str) -> Option<&'static str> {
    match enum_value.to_ascii_lowercase().as_str() {
        "processcontainer" | "appcontainer" => Some("processContainer"),
        // Known backends without a `capabilities` array — merge is a
        // no-op for these (caller emits a warning).
        "lxc" | "wslc" | "windows_sandbox" | "seatbelt" | "isolation_session" | "bubblewrap"
        | "hyperlight" | "microvm" | "vm" => None,
        // Genuinely unknown value (e.g. a typo or a future backend
        // not yet wired into PLM): return None so we don't silently
        // pollute the config.
        _ => None,
    }
}

/// Locate (case-insensitively) or create the containment sub-object on
/// `config` and ensure its `capabilities` array exists. Returns the key
/// the caller should use to subsequently reach the object, or `None`
/// when the containment backend has no `capabilities` array at all.
fn resolve_containment_key(config: &mut Value, containment_name: &str) -> Result<Option<String>> {
    let canonical = match capability_subobject_key(containment_name) {
        Some(k) => k,
        None => return Ok(None),
    };
    let obj = config
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("config root must be a JSON object"))?;
    let existing_key = obj
        .keys()
        .find(|k| k.eq_ignore_ascii_case(canonical))
        .cloned();
    let key = match existing_key {
        Some(k) => k,
        None => {
            obj.insert(canonical.to_string(), json!({}));
            canonical.to_string()
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
    Ok(Some(key))
}

pub fn merge_capabilities(config: &mut Value, requested: &HashSet<String>) -> Result<()> {
    let containment_name = match config.get("containment").and_then(|v| v.as_str()) {
        Some(s) if !s.trim().is_empty() => s.to_string(),
        _ => return Ok(()),
    };

    let key = match resolve_containment_key(config, &containment_name)? {
        Some(k) => k,
        None => {
            // Backend has no `capabilities` array in its schema (or is
            // unknown to PLM). Emit a stderr warning so the operator
            // knows the discovered capabilities are being dropped on
            // the floor, rather than silently writing a section the
            // runner will reject.
            if !requested.is_empty() {
                eprintln!(
                    "[plm] warning: containment '{containment_name}' has no `capabilities` \
                     array in its schema; dropping {} discovered capabilit{}: {}",
                    requested.len(),
                    if requested.len() == 1 { "y" } else { "ies" },
                    {
                        let mut sorted: Vec<&String> = requested.iter().collect();
                        sorted.sort();
                        sorted
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    }
                );
            }
            return Ok(());
        }
    };
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
    // Custom case-insensitive ASCII compare so the per-element cost is
    // a byte-by-byte walk instead of two `to_ascii_lowercase()` clones
    // per comparison.
    all_caps.sort_unstable_by(|a, b| cmp_ci_ascii(a, b));

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
