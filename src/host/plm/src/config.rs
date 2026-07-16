//! Port of the config-update logic from `stop_plm_logging.ps1`.
//!
//! Reads an MXC container config (JSON) and merges discovered
//! file-access paths into it. Capability-merge and the Adjusted_*.json
//! writer arrive in the config-generation PR.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::path::Path;

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

/// True iff `path` denotes a drive root like `C:\` (or `C:` / `C:/` or
/// the verbatim/device variants `\\?\C:\` / `\\.\C:\`).
///
/// We refuse to emit a bare drive root into `filesystem.readwritePaths`
/// because that would grant the entire volume. Accepting only the
/// bare `[A-Za-z]:` form would let `\\?\C:\` (the form ETW emits when
/// an audited process called `NtCreateFile` with a verbatim path)
/// bypass the guard.
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

pub fn update_from_access_events(
    config: &mut Value,
    bin_path: &str,
    events: &[LearningModeAccessEvent],
    deny_set: &HashSet<String>,
    verbose: bool,
) -> Result<AddedPaths> {
    let mut added_rw: Vec<String> = Vec::new();
    let mut added_ro: Vec<String> = Vec::new();

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

        // Self-access filter: events whose path equals the audited
        // application's binary (in any spelling — raw, verbatim,
        // lower/upper case) are noise and skipped. The verbatim-prefixed
        // variant matters because `stop.rs` canonicalises bin_path via
        // `canonicalize()`, which on Windows returns the `\\?\C:\…` form
        // while ETW reports the plain `C:\…` form; comparing only the
        // raw strings let the binary path leak into the output
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
            // Emit a file-scope grant for the exact path the audited
            // process wrote to. The policy schema accepts individual
            // file entries in `filesystem.readwritePaths`, so there is
            // no need to widen the grant to the containing directory
            // (which would over-grant to unrelated siblings).
            //
            // Refuse to emit a bare drive root — that would grant the
            // entire volume. Legitimate write events target specific
            // files under a drive root, so a raw `C:\` event is either
            // a metadata operation we don't need to authorize or a
            // path we can't safely widen; either way, skip it.
            if is_drive_root(&ev.file_path) {
                if verbose {
                    println!("Skipping write event at bare drive root: {}", ev.file_path);
                }
                continue;
            }
            let arr = config["filesystem"]["readwritePaths"]
                .as_array_mut()
                .ok_or_else(|| {
                    anyhow::anyhow!("`filesystem.readwritePaths` must be a JSON array")
                })?;
            arr.push(Value::String(ev.file_path.clone()));
            // The top-of-loop short-circuit already `continue`d on any
            // `ev_norm` present in `rw_existing_set`, so this insert is
            // always the first sighting: record the added path and keep
            // the normalized prefix vector in sync. (`rw_existing_set`
            // subsumes the old separate `seen_rw` dedup set.)
            if rw_existing_set.insert(ev_norm.clone()) {
                rw_existing_norm.push(ev_norm);
                added_rw.push(ev.file_path.clone());
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
            // Same reasoning as the readwrite branch: the `ro_existing_set`
            // short-circuit above guarantees first sighting here, so
            // `ro_existing_set` alone subsumes the old `seen_ro` set.
            if ro_existing_set.insert(ev_norm.clone()) {
                ro_existing_norm.push(ev_norm);
                added_ro.push(ev.file_path.clone());
            }
        }
    }

    Ok(AddedPaths {
        readwrite: added_rw,
        readonly: added_ro,
    })
}

pub fn write_added_paths_summary(added: &AddedPaths, verbose: bool) {
    // The added-paths summary is diagnostic chatter on stdout; only emit
    // it when the caller asked for verbose output so a normal run leaves
    // stdout for the generated config alone.
    if !verbose {
        return;
    }
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

    // ---- path_starts_with_any --------------------------------------------

    fn norm(p: &str) -> String {
        normalize_path(p).expect("test input must normalize")
    }

    #[test]
    fn starts_with_any_rejects_sibling_with_shared_prefix() {
        // The historical bug: "c:\foobar\baz".starts_with("c:\foo") was
        // true, silently mishandling siblings sharing a name prefix.
        assert!(!path_starts_with_any_norm(
            &norm("C:\\foobar\\baz"),
            [norm("C:\\foo")]
        ));
    }

    #[test]
    fn starts_with_any_matches_exact() {
        assert!(path_starts_with_any_norm(
            &norm("C:\\foo"),
            [norm("C:\\foo")]
        ));
    }

    #[test]
    fn starts_with_any_matches_nested_child() {
        assert!(path_starts_with_any_norm(
            &norm("C:\\foo\\bar\\baz.txt"),
            [norm("C:\\foo")]
        ));
    }

    #[test]
    fn starts_with_any_is_case_insensitive_and_separator_tolerant() {
        assert!(path_starts_with_any_norm(
            &norm("c:\\Foo\\bar"),
            [norm("C:\\foo\\")]
        ));
    }

    // ---- normalize_path / is_drive_root ----------------------------------

    #[test]
    fn is_drive_root_detects_variants() {
        assert!(is_drive_root("C:\\"));
        assert!(is_drive_root("C:"));
        assert!(is_drive_root("c:/"));
        assert!(!is_drive_root("C:\\foo"));
        assert!(!is_drive_root(""));
    }

    #[test]
    fn is_drive_root_handles_verbatim_and_device_prefix() {
        // ETW emits these forms when a process opens
        // \??\C:\... directly; the drive-root guard must catch them.
        assert!(is_drive_root("\\\\?\\C:\\"));
        assert!(is_drive_root("\\\\?\\C:"));
        assert!(is_drive_root("\\\\.\\C:\\"));
        assert!(!is_drive_root("\\\\?\\C:\\hiberfil.sys"));
        // UNC verbatim is never a drive root.
        assert!(!is_drive_root("\\\\?\\UNC\\server\\share"));
    }

    #[test]
    fn normalize_path_strips_verbatim_prefix() {
        assert_eq!(normalize_path("\\\\?\\C:\\Foo").as_deref(), Some("c:\\foo"));
        assert_eq!(normalize_path("\\\\.\\C:\\Foo").as_deref(), Some("c:\\foo"));
    }

    #[test]
    fn normalize_path_collapses_separators_and_lowercase() {
        assert_eq!(
            normalize_path("C:/Foo/Bar").as_deref(),
            Some("c:\\foo\\bar")
        );
    }

    #[test]
    fn normalize_path_strips_trailing_dot_per_component() {
        // trailing dots map to the same NTFS
        // object as the base name, so deny matching must canonicalize.
        assert_eq!(
            normalize_path("C:\\Secrets.").as_deref(),
            Some("c:\\secrets")
        );
        assert_eq!(
            normalize_path("C:\\Secrets ").as_deref(),
            Some("c:\\secrets")
        );
        assert_eq!(
            normalize_path("C:\\Secrets\\token. ").as_deref(),
            Some("c:\\secrets\\token")
        );
    }

    #[test]
    fn normalize_path_rejects_ads_outside_drive_separator() {
        // ADS (alternate data stream) syntax on a directory resolves to
        // the directory itself; deny must not be bypassable via this.
        assert!(normalize_path("C:\\Secrets:hidden").is_none());
        assert!(normalize_path("C:\\Secrets\\token.dat:s").is_none());
    }

    #[test]
    fn normalize_path_rejects_unc_verbatim() {
        assert!(normalize_path("\\\\?\\UNC\\server\\share\\x").is_none());
    }

    // lock current behavior on path-normalization
    // corners that prior rounds did not cover. These are NOT
    // necessarily the *correct* answers in every case (see comments)
    // — they encode what `normalize_path` actually does today so a
    // future change cannot silently widen / narrow the surface.

    #[test]
    fn normalize_path_strips_nt_object_prefix() {
        // `\??\C:\foo` is the NT-object form
        // ETW occasionally emits. `config::normalize_path` now
        // explicitly strips the `\??\` prefix (mirroring `\\?\` /
        // `\\.\` handling) so call sites that bypass
        // `event_parser::normalize_file_path` still get a comparable
        // drive-letter form. Without this, the self-event filter
        // would miss `\??\C:\plm\plm.exe`.
        assert_eq!(normalize_path("\\??\\C:\\foo").as_deref(), Some("c:\\foo"));
    }

    #[test]
    fn normalize_path_passes_globalroot_through_unchanged() {
        // `\\?\GLOBALROOT\Device\HarddiskVolume3\foo` strips the `\\?\`
        // prefix and lowercases. The result is NOT a drive-letter
        // form and won't match any drive-rooted deny entry, but the
        // function currently returns Some(...) for it (no ADS-style
        // `:` rejection triggers). Operators who want to deny
        // GLOBALROOT volumes must add explicit deny entries.
        let got = normalize_path("\\\\?\\GLOBALROOT\\Device\\HarddiskVolume3\\foo");
        assert_eq!(
            got.as_deref(),
            Some("globalroot\\device\\harddiskvolume3\\foo")
        );
    }

    #[test]
    fn normalize_path_accepts_non_verbatim_unc() {
        // `\\server\share\x` is NOT `\\?\UNC\…` so it doesn't get
        // rejected. The leading `\\` survives lowercasing and the
        // result starts with the same prefix. Whether UNC paths are
        // policy-meaningful is a separate question — this test just
        // pins the current pass-through behavior.
        let got = normalize_path("\\\\server\\share\\x");
        assert_eq!(got.as_deref(), Some("\\\\server\\share\\x"));
    }

    #[test]
    fn normalize_path_passes_drive_relative_through() {
        // `C:foo` (no separator after the colon) is Win32 drive-
        // relative — Windows resolves it against the per-drive CWD.
        // `normalize_path` does not currently reject these; the `:`
        // at position 1 is the drive-letter separator so it passes
        // the ADS guard. Caller's responsibility to either canonicalize
        // upstream or accept that drive-relative events won't match
        // drive-rooted deny entries.
        let got = normalize_path("C:foo");
        assert_eq!(got.as_deref(), Some("c:foo"));
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

    fn run_update_with_bin(
        config: &mut Value,
        bin_path: &str,
        events: &[LearningModeAccessEvent],
        deny: &[&str],
    ) -> AddedPaths {
        initialize_filesystem(config).unwrap();
        let deny_set: HashSet<String> = deny.iter().map(|s| (*s).to_string()).collect();
        update_from_access_events(config, bin_path, events, &deny_set, false).unwrap()
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

    // ---- bin_path self-event filter -------------------
    //
    // The self-filter normalizes `bin_path` and compares both the raw
    // (verbatim or plain) form via `eq_ignore_ascii_case` AND the
    // normalized form against the event path. Every other test in this
    // module passes `"__never_matches__"` as bin_path; these four lock
    // the actual self-filter behavior so a regression isn't silent.

    #[test]
    fn self_event_filter_skips_raw_bin_path() {
        let mut cfg = json!({});
        let added = run_update_with_bin(
            &mut cfg,
            "C:\\bin\\plm.exe",
            &[ev_read("C:\\bin\\plm.exe")],
            &[],
        );
        assert!(
            added.readonly.is_empty(),
            "events referencing the PLM binary itself must be filtered"
        );
    }

    #[test]
    fn self_event_filter_skips_verbatim_bin_path_against_plain_event() {
        // canonicalize() may return the
        // verbatim form \\?\C:\..., while ETW emits the plain form.
        // Both must self-filter.
        let mut cfg = json!({});
        let added = run_update_with_bin(
            &mut cfg,
            "\\\\?\\C:\\bin\\plm.exe",
            &[ev_read("C:\\bin\\plm.exe")],
            &[],
        );
        assert!(
            added.readonly.is_empty(),
            "verbatim bin_path must self-filter plain-form events"
        );
    }

    #[test]
    fn self_event_filter_case_insensitive() {
        let mut cfg = json!({});
        let added = run_update_with_bin(
            &mut cfg,
            "C:\\bin\\plm.exe",
            &[ev_read("c:\\BIN\\PLM.EXE")],
            &[],
        );
        assert!(
            added.readonly.is_empty(),
            "self-filter must be case-insensitive on Windows paths"
        );
    }

    #[test]
    fn non_self_event_passes_through_self_filter() {
        let mut cfg = json!({});
        let added = run_update_with_bin(
            &mut cfg,
            "C:\\bin\\plm.exe",
            &[ev_read("C:\\Users\\foo\\bar.txt")],
            &[],
        );
        assert_eq!(
            added.readonly.len(),
            1,
            "non-self event must NOT be filtered: {added:?}"
        );
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

    // Windows-only because `normalize_path` uses Windows path
    // parsing rules; on non-Windows hosts `\` is not a separator and
    // these inputs would not normalize the way production expects.
    #[cfg(target_os = "windows")]
    #[test]
    fn write_at_drive_root_does_not_grant_whole_volume() {
        let mut cfg = json!({});
        let added = run_update(&mut cfg, &[ev_write("C:\\hiberfil.sys")], &[]);
        // Must be a file-scope grant, never the bare drive root.
        assert_eq!(added.readwrite, vec!["C:\\hiberfil.sys".to_string()]);
        assert!(
            !added.readwrite.iter().any(|p| is_drive_root(p)),
            "drive-root grant leaked: {:?}",
            added.readwrite
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn write_grants_exact_file_not_parent_directory() {
        // Regression: earlier passes widened writes to the parent
        // directory. The reviewer asked us to keep the grant scoped
        // to the file. This test locks that in.
        let mut cfg = json!({});
        let added = run_update(&mut cfg, &[ev_write("C:\\a\\b\\c.txt")], &[]);
        assert_eq!(added.readwrite, vec!["C:\\a\\b\\c.txt".to_string()]);
    }

    #[test]
    fn read_under_existing_readonly_parent_is_not_duplicated() {
        let mut cfg = json!({
            "filesystem": { "readonlyPaths": ["C:\\src"] }
        });
        let added = run_update(&mut cfg, &[ev_read("C:\\src\\main.rs")], &[]);
        assert!(added.readonly.is_empty());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn idempotent_on_already_writable_path() {
        let mut cfg = json!({
            "filesystem": { "readwritePaths": ["C:\\out"] }
        });
        let added = run_update(&mut cfg, &[ev_write("C:\\out\\foo.txt")], &[]);
        assert!(added.readwrite.is_empty());
    }

    // ---- ------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn write_via_verbatim_drive_root_does_not_grant_volume() {
        // `\\?\C:\` is the verbatim spelling of a drive root; the
        // `is_drive_root` guard on the write branch must skip it just
        // like `C:\`. Writes to files _under_ the verbatim root are
        // still granted at file scope.
        let mut cfg = json!({});
        let added = run_update(&mut cfg, &[ev_write("\\\\?\\C:\\hiberfil.sys")], &[]);
        for p in &added.readwrite {
            assert!(
                normalize_path(p).map(|n| n.len() > 2).unwrap_or(true),
                "verbatim drive-root grant leaked: {p}"
            );
        }
    }

    #[test]
    fn write_to_trailing_dot_variant_of_denied_dir_is_blocked() {
        // "C:\Secrets." resolves to the same NTFS
        // object as "C:\Secrets" but previously bypassed deny matching.
        let mut cfg = json!({
            "filesystem": { "deniedPaths": ["C:\\Secrets"] }
        });
        let added = run_update(
            &mut cfg,
            &[ev_write("C:\\Secrets.\\token.txt")],
            &["C:\\Secrets"],
        );
        assert!(
            added.readwrite.is_empty(),
            "deny bypass via trailing dot: {:?}",
            added.readwrite
        );
    }

    #[test]
    fn write_to_ads_on_denied_dir_is_rejected() {
        // ADS syntax on a directory resolves to the
        // directory and must not bypass deny matching. `normalize_path`
        // rejects the path entirely.
        let mut cfg = json!({
            "filesystem": { "deniedPaths": ["C:\\Secrets"] }
        });
        let added = run_update(
            &mut cfg,
            &[ev_write("C:\\Secrets:hidden")],
            &["C:\\Secrets"],
        );
        assert!(
            added.readwrite.is_empty(),
            "ADS on denied dir slipped through: {:?}",
            added.readwrite
        );
    }

    #[test]
    fn mixed_separators_do_not_cause_duplicates() {
        // `C:/foo` vs `C:\foo` previously broke dedup.
        let mut cfg = json!({
            "filesystem": { "readonlyPaths": ["C:\\src"] }
        });
        let added = run_update(&mut cfg, &[ev_read("C:/src/main.rs")], &[]);
        assert!(
            added.readonly.is_empty(),
            "mixed separators created duplicate: {:?}",
            added.readonly
        );
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

    // R5-31: load_config rejects malformed JSON files with a useful
    // error rather than panicking or silently returning the empty
    // object.
    #[test]
    fn load_config_rejects_malformed_json() {
        let tmp =
            std::env::temp_dir().join(format!("plm_load_cfg_test_{}.json", std::process::id()));
        std::fs::write(&tmp, b"{not valid json").unwrap();
        let err = load_config(&tmp).unwrap_err();
        let _ = std::fs::remove_file(&tmp);
        assert!(
            format!("{err}").to_ascii_lowercase().contains("json")
                || format!("{err}").contains("parse")
        );
    }
}
