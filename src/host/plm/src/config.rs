//! Port of the config-update logic from `stop_plm_logging.ps1`.
//!
//! Reads an MXC container config (JSON) and merges discovered
//! file-access paths into it. Capability-merge and the Adjusted_*.json
//! writer arrive in the config-generation PR.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::access_event::LearningModeAccessEvent;

/// How a single file-access-mask bit maps onto PLM's read/write policy
/// buckets. Kept as one axis so the decode table, `READ_MASK`, and
/// `WRITE_MASK` can all be derived from a single source of truth.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Access {
    /// Grants data / attribute read — contributes to `READ_MASK`.
    Read,
    /// Grants data / attribute / metadata write — contributes to
    /// `WRITE_MASK`.
    Write,
    /// Grants both (e.g. `GENERIC_ALL`) — contributes to both masks.
    ReadWrite,
    /// Recognized for *decoding* but grants neither data read nor
    /// write (`SYNCHRONIZE`, `READ_CONTROL`). Present so
    /// `decode_access_mask` prints the mnemonic instead of
    /// `OTHER(0x…)`, but deliberately excluded from `READ_MASK` /
    /// `WRITE_MASK` so `classify_mask` and `update_from_access_events`
    /// don't treat a synchronize- or read-control-only event as a read.
    None,
}

struct MaskFlag {
    bit: u32,
    name: &'static str,
    access: Access,
}

/// Single source of truth for the file-access-mask bits PLM recognizes
/// (mirror of `Get-PlmAccessMasks` in `stop_plm_logging.ps1`). Both the
/// decode names and the `READ_MASK` / `WRITE_MASK` classification masks
/// are derived from this table, so a newly-recognized bit is added in
/// exactly one place and can never be classified without also decoding
/// (or vice-versa).
const ACCESS_FLAGS: &[MaskFlag] = &[
    // Specific rights.
    MaskFlag {
        bit: 0x1,
        name: "READ_DATA",
        access: Access::Read,
    },
    MaskFlag {
        bit: 0x2,
        name: "FILE_WRITE",
        access: Access::Write,
    },
    MaskFlag {
        bit: 0x4,
        name: "FILE_APPEND",
        access: Access::Write,
    },
    MaskFlag {
        bit: 0x8,
        name: "READ_EA",
        access: Access::Read,
    },
    MaskFlag {
        bit: 0x10,
        name: "WRITE_EA",
        access: Access::Write,
    },
    MaskFlag {
        bit: 0x20,
        name: "DIRECTORY_TRAVERSE",
        access: Access::Read,
    },
    MaskFlag {
        bit: 0x40,
        name: "DIRECTORY_DELETE",
        access: Access::Write,
    },
    MaskFlag {
        bit: 0x80,
        name: "READ_ATTRIBUTES",
        access: Access::Read,
    },
    MaskFlag {
        bit: 0x100,
        name: "WRITE_ATTRIBUTES",
        access: Access::Write,
    },
    MaskFlag {
        bit: 0x10000,
        name: "FILE_DELETE",
        access: Access::Write,
    },
    // Standard rights. READ_CONTROL / SYNCHRONIZE are recognized so they
    // decode to a mnemonic, but classify as neither read nor write:
    // holding them grants no data access, so an event carrying only one
    // of them must not promote a path into readonlyPaths.
    MaskFlag {
        bit: 0x20000,
        name: "READ_CONTROL",
        access: Access::None,
    },
    MaskFlag {
        bit: 0x40000,
        name: "WRITE_DAC",
        access: Access::Write,
    },
    MaskFlag {
        bit: 0x80000,
        name: "WRITE_OWNER",
        access: Access::Write,
    },
    MaskFlag {
        bit: 0x100000,
        name: "SYNCHRONIZE",
        access: Access::None,
    },
    // Generic rights. EventID=14 usually carries specific rights (the
    // kernel maps generic→specific via the object's GENERIC_MAPPING
    // before the audit fires), but map them fail-closed so that a path
    // whose event *did* surface a generic bit still classifies and gets
    // promoted rather than silently decoding as OTHER(0x…) and being
    // dropped. GENERIC_EXECUTE implies traverse/read-attributes, so it
    // buckets as read.
    MaskFlag {
        bit: 0x1000_0000,
        name: "GENERIC_ALL",
        access: Access::ReadWrite,
    },
    MaskFlag {
        bit: 0x2000_0000,
        name: "GENERIC_EXECUTE",
        access: Access::Read,
    },
    MaskFlag {
        bit: 0x4000_0000,
        name: "GENERIC_WRITE",
        access: Access::Write,
    },
    MaskFlag {
        bit: 0x8000_0000,
        name: "GENERIC_READ",
        access: Access::Read,
    },
];

const fn compute_mask(want_write: bool) -> u32 {
    let mut m = 0u32;
    let mut i = 0;
    while i < ACCESS_FLAGS.len() {
        let hit = match ACCESS_FLAGS[i].access {
            Access::Write => want_write,
            Access::Read => !want_write,
            Access::ReadWrite => true,
            Access::None => false,
        };
        if hit {
            m |= ACCESS_FLAGS[i].bit;
        }
        i += 1;
    }
    m
}

/// Bits that, when present, mean the audited process requested write
/// access (derived from `ACCESS_FLAGS`).
pub const WRITE_MASK: u32 = compute_mask(true);

/// Bits that, when present, mean the audited process requested read
/// access (derived from `ACCESS_FLAGS`). Deliberately excludes
/// `READ_CONTROL` / `SYNCHRONIZE`, which are recognized but not
/// data-read-granting.
pub const READ_MASK: u32 = compute_mask(false);

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
    // Rebuild the normalized path in a single pre-allocated buffer
    // instead of collecting an owned `String` per component and then
    // `join`-ing them. `normalize_path` runs once per event on the hot
    // path, so the old `Vec<String>` + `join` cost roughly one heap
    // allocation per path component plus the join allocation; writing
    // straight into `out` reduces that to a single allocation. We emit
    // the `\` separator before every component after the first, which
    // reproduces `join("\\")` byte-for-byte (including the leading empty
    // UNC segments, which contribute an empty component each).
    let trimmed = s.trim_end_matches('\\');
    let mut out = String::with_capacity(trimmed.len());
    let mut in_leading_unc = true;
    let mut emitted = 0usize;
    for (i, part) in trimmed.split('\\').enumerate() {
        if i == 0 && part.len() == 2 && part.as_bytes()[1] == b':' {
            out.push_str(part);
            emitted += 1;
            in_leading_unc = false;
            continue;
        }
        // Leading empty segments (UNC `\\server\share\x` splits to
        // `["", "", "server", ...]`) are preserved verbatim; deny
        // matching treats UNC as pass-through. Once we see a
        // non-empty segment, leave the leading-UNC mode and any
        // future empty segment is an error (doubled backslash etc).
        if part.is_empty() && in_leading_unc && i < 2 {
            if emitted > 0 {
                out.push('\\');
            }
            emitted += 1;
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
        if emitted > 0 {
            out.push('\\');
        }
        out.push_str(stripped);
        emitted += 1;
    }
    Some(out)
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

/// True iff any component of the (already-normalized) path looks like
/// an NTFS 8.3 short name — a mangled base of the form `NAME~N`
/// (optionally with a `.EXT`), e.g. `progra~1`, `secret~1`.
///
/// `normalize_path` is deliberately filesystem-free: it strips
/// verbatim/device prefixes, lowercases, collapses separators, and
/// rejects ADS / `.` / `..`, but it does **not** resolve symlinks,
/// directory junctions / reparse points, or 8.3 short names. That
/// leaves an aliasing gap for deny matching — an access that reaches a
/// denied location through an 8.3 alias (`C:\secret~1\token.dat` for a
/// denied `C:\Secrets`) would normalize to a string that doesn't share
/// the deny prefix and would be promoted into the persisted
/// `Adjusted_*.json`. We can detect the 8.3 case lexically and refuse
/// to promote it (fail-closed); the reparse-point / symlink case can
/// only be resolved with filesystem access we don't have on this hot
/// path (paths come from ETW and the object may no longer exist), so it
/// remains a documented limitation — deny is enforced on the literal
/// normalized path only. See `readme.md`.
fn has_short_name_component(norm: &str) -> bool {
    norm.split('\\').any(|component| {
        // The mangled base precedes any extension dot.
        let base = component.split('.').next().unwrap_or(component);
        match base.find('~') {
            Some(tilde) => {
                let suffix = &base[tilde + 1..];
                !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit())
            }
            None => false,
        }
    })
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

        // Deny-alias fail-closed guard: an 8.3 short-name component can
        // alias a denied directory (`c:\secret~1\token.dat` for a denied
        // `C:\Secrets`) and slip past the purely-lexical deny match
        // below, then get baked into the persisted Adjusted_*.json.
        // Since we can't resolve the short name without filesystem
        // access here, refuse to promote the path at all — the safe
        // failure mode for anything we can't prove isn't a deny alias.
        if has_short_name_component(&ev_norm) {
            if verbose {
                println!(
                    "Skipping 8.3 short-name path (cannot prove it isn't a deny alias): {}",
                    ev.file_path
                );
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

        // Already-covered short-circuit for readwrite policy. The exact
        // set hit is O(1); the prefix scan is O(N) over the grant
        // vector. Cache a positive prefix match by inserting `ev_norm`
        // into `rw_existing_set`, so a later event for the same path
        // short-circuits on the cheap set lookup instead of re-scanning
        // `rw_existing_norm`. We deliberately do NOT extend
        // `rw_existing_norm`: the path is already subsumed by an
        // existing prefix, so it never needs to act as a prefix itself.
        if rw_existing_set.contains(&ev_norm) {
            continue;
        }
        if path_starts_with_any_norm(&ev_norm, &rw_existing_norm) {
            rw_existing_set.insert(ev_norm.clone());
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
            // Refuse to emit a bare drive root — that would grant read
            // of the entire volume. Mirrors the readwrite branch above.
            // The upstream `is_skippable` `len < 4` filter drops the
            // common `C:` / `C:\` spellings, but a root that reaches
            // here in a longer form (e.g. `C:\\`, which
            // `trim_backslashes_in_place` collapses to `C:`, or a
            // verbatim `\\?\C:\`) would otherwise be added verbatim.
            if is_drive_root(&ev.file_path) {
                if verbose {
                    println!("Skipping read event at bare drive root: {}", ev.file_path);
                }
                continue;
            }
            // Same prefix-cache optimization as the readwrite branch:
            // exact hit first, then cache a positive prefix match so
            // repeats of the same read path short-circuit in O(1).
            if ro_existing_set.contains(&ev_norm) {
                continue;
            }
            if path_starts_with_any_norm(&ev_norm, &ro_existing_norm) {
                ro_existing_set.insert(ev_norm.clone());
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

/// Derive the path the `Adjusted_*.json` should be written to, next to
/// the operator's config snapshot (`dest_config`).
///
/// **Pure**: this performs only path arithmetic — no filesystem side
/// effects — so it is trivially table-testable and never silently
/// creates directories. The caller (`stop.rs`) is responsible for
/// creating the parent directory (propagating any error) immediately
/// before `save_adjusted_config`.
///
/// Errors rather than falling back to surprising defaults when
/// `dest_config` has no final component (a directory or a bare root
/// like `C:`) — `unwrap_or_default()` would have produced a file
/// literally named `Adjusted_`, and a `Path::new(".")` parent fallback
/// would have silently relocated the output into the current working
/// directory.
pub fn resolve_adjusted_config_path(dest_config: &Path) -> Result<PathBuf> {
    let leaf = dest_config.file_name().ok_or_else(|| {
        anyhow::anyhow!(
            "cannot derive adjusted-config path: {} has no file name",
            dest_config.display()
        )
    })?;
    let parent = dest_config.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "cannot derive adjusted-config path: {} has no parent directory",
            dest_config.display()
        )
    })?;
    let leaf = leaf.to_string_lossy();
    Ok(parent.join(format!("Adjusted_{leaf}")))
}

/// Write the adjusted config atomically: serialize to a uniquely-named
/// temp file in the *same directory* as the destination, flush it to
/// disk, then rename it over the destination. Readers therefore only
/// ever observe the complete old file or the complete new file — never
/// a truncated/partial write from a crash, full disk, or mid-write
/// failure. This matters because a downstream enforcing run consumes
/// this file directly as its policy, and `plm stop` can be re-run
/// against an existing `Adjusted_*.json`.
///
/// Keeping the temp file on the same volume ensures the final rename is
/// an atomic metadata operation rather than a cross-volume copy, and
/// `persist` replaces the destination directory entry itself, so a
/// symlink pre-planted at the destination name is overwritten rather
/// than followed.
pub fn save_adjusted_config(config: &Value, path: &Path) -> Result<()> {
    use std::io::Write;

    let pretty = serde_json::to_string_pretty(config)?;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir)
        .with_context(|| format!("failed to create temp file in {}", dir.display()))?;
    tmp.write_all(pretty.as_bytes())
        .and_then(|_| tmp.as_file().sync_all())
        .with_context(|| format!("failed to write temp adjusted config in {}", dir.display()))?;
    tmp.persist(path)
        .map_err(|e| e.error)
        .with_context(|| format!("failed to replace {}", path.display()))?;
    Ok(())
}

/// Decode a Windows file access mask into a |-separated list of the
/// mnemonic flag names PLM cares about. Unknown bits are reported as a
/// trailing OTHER(0x...) token so nothing is silently dropped.
fn decode_access_mask(mask: u32) -> String {
    let mut parts: Vec<&str> = Vec::new();
    let mut covered: u32 = 0;
    for flag in ACCESS_FLAGS {
        if mask & flag.bit != 0 {
            parts.push(flag.name);
            covered |= flag.bit;
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

    let mut per_path: BTreeMap<&str, u32> = BTreeMap::new();
    for ev in events {
        *per_path.entry(ev.file_path.as_str()).or_insert(0) |= ev.access_mask;
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

/// Merge discovered AppContainer capability names into the config's
/// containment-backend block. Implementation arrives in the
/// capability-extraction PR; until then this is a no-op. Callers may
/// pass a non-empty set (e.g. when a future stop.rs wires in the
/// EventID=14 ACE-blob parser ahead of this merge) without triggering
/// a spurious failure — the actual merge is landed atomically in the
/// capability-extraction PR.
pub fn merge_capabilities(_config: &mut Value, _requested: &HashSet<String>) -> Result<()> {
    Ok(())
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
            file_path: path.to_string(),
            access_mask: 0x2, // FILE_WRITE
        }
    }

    fn ev_read(path: &str) -> LearningModeAccessEvent {
        LearningModeAccessEvent {
            time_created: chrono::Utc::now(),
            process_id: 0,
            thread_id: 0,
            file_path: path.to_string(),
            access_mask: 0x1, // READ_DATA
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
    fn read_at_drive_root_does_not_grant_whole_volume() {
        // A bare drive-root read must never widen the policy to the
        // entire volume. `C:` is the form a `C:\\` root collapses to
        // after `trim_backslashes_in_place` upstream.
        for root in ["C:", "C:\\"] {
            let mut cfg = json!({});
            let added = run_update(&mut cfg, &[ev_read(root)], &[]);
            assert!(
                added.readonly.is_empty(),
                "drive-root read grant leaked for {root:?}: {:?}",
                added.readonly
            );
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn read_via_verbatim_drive_root_does_not_grant_volume() {
        // `\\?\C:\` is the verbatim spelling of a drive root; the read
        // branch's `is_drive_root` guard must skip it just like `C:\`.
        let mut cfg = json!({});
        let added = run_update(&mut cfg, &[ev_read("\\\\?\\C:\\")], &[]);
        assert!(
            added.readonly.is_empty(),
            "verbatim drive-root read grant leaked: {:?}",
            added.readonly
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn read_of_file_under_drive_root_is_still_granted() {
        // Guard must not over-filter: a read of an actual file under
        // the drive root is still recorded at file scope.
        let mut cfg = json!({});
        let added = run_update(&mut cfg, &[ev_read("C:\\pagefile.sys")], &[]);
        assert_eq!(added.readonly, vec!["C:\\pagefile.sys".to_string()]);
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

    // ---- access-mask decode / classify -----------------------------------

    #[test]
    fn read_write_masks_are_disjoint_and_exclude_non_granting_bits() {
        // A bit is never simultaneously read-only and write-only unless
        // it is a ReadWrite bit (the generic-all case).
        assert_eq!(WRITE_MASK & 0x2, 0x2, "FILE_WRITE is a write bit");
        assert_eq!(READ_MASK & 0x1, 0x1, "READ_DATA is a read bit");
        // READ_CONTROL (0x20000) and SYNCHRONIZE (0x100000) are
        // recognized but grant no data access — excluded from both.
        assert_eq!(READ_MASK & 0x20000, 0, "READ_CONTROL must not be read");
        assert_eq!(WRITE_MASK & 0x20000, 0, "READ_CONTROL must not be write");
        assert_eq!(READ_MASK & 0x100000, 0, "SYNCHRONIZE must not be read");
        assert_eq!(WRITE_MASK & 0x100000, 0, "SYNCHRONIZE must not be write");
        // GENERIC_ALL sits in both.
        assert_eq!(READ_MASK & 0x1000_0000, 0x1000_0000);
        assert_eq!(WRITE_MASK & 0x1000_0000, 0x1000_0000);
        // GENERIC_READ read-only, GENERIC_WRITE write-only.
        assert_eq!(READ_MASK & 0x8000_0000, 0x8000_0000);
        assert_eq!(WRITE_MASK & 0x8000_0000, 0);
        assert_eq!(WRITE_MASK & 0x4000_0000, 0x4000_0000);
        assert_eq!(READ_MASK & 0x4000_0000, 0);
    }

    #[test]
    fn classify_mask_table() {
        assert_eq!(classify_mask(0x0), "-");
        assert_eq!(classify_mask(0x1), "R"); // READ_DATA
        assert_eq!(classify_mask(0x2), "W"); // FILE_WRITE
        assert_eq!(classify_mask(0x1 | 0x2), "RW");
        // SYNCHRONIZE / READ_CONTROL alone are neither R nor W now.
        assert_eq!(classify_mask(0x100000), "-", "SYNCHRONIZE-only");
        assert_eq!(classify_mask(0x20000), "-", "READ_CONTROL-only");
        // Generic bits classify.
        assert_eq!(classify_mask(0x8000_0000), "R", "GENERIC_READ");
        assert_eq!(classify_mask(0x4000_0000), "W", "GENERIC_WRITE");
        assert_eq!(classify_mask(0x1000_0000), "RW", "GENERIC_ALL");
    }

    #[test]
    fn decode_access_mask_table() {
        assert_eq!(decode_access_mask(0x0), "NONE");
        assert_eq!(decode_access_mask(0x1), "READ_DATA");
        assert_eq!(decode_access_mask(0x2), "FILE_WRITE");
        assert_eq!(decode_access_mask(0x1 | 0x2), "READ_DATA|FILE_WRITE");
        // Recognized-but-non-granting bits still decode (not OTHER).
        assert_eq!(decode_access_mask(0x100000), "SYNCHRONIZE");
        assert_eq!(decode_access_mask(0x20000), "READ_CONTROL");
        // Generic bits decode instead of falling through to OTHER.
        assert_eq!(decode_access_mask(0x8000_0000), "GENERIC_READ");
        // Unknown-only bit reports OTHER, nothing silently dropped.
        assert_eq!(decode_access_mask(0x800), "OTHER(0x800)");
        // Known + unknown are both surfaced.
        assert_eq!(decode_access_mask(0x1 | 0x800), "READ_DATA|OTHER(0x800)");
    }

    #[test]
    fn generic_only_event_is_promoted() {
        // A path whose only observed access was a generic right must
        // still promote (fail-closed), not silently drop.
        let mut cfg = json!({});
        let mut ev = ev_read("C:\\data\\gen.dat");
        ev.access_mask = 0x8000_0000; // GENERIC_READ
        let added = run_update(&mut cfg, &[ev], &[]);
        assert_eq!(added.readonly, vec!["C:\\data\\gen.dat".to_string()]);
    }

    #[test]
    fn synchronize_only_event_is_not_promoted() {
        // SYNCHRONIZE / READ_CONTROL grant no data access, so an event
        // carrying only one of them must not widen readonlyPaths.
        let mut cfg = json!({});
        let mut ev = ev_read("C:\\data\\sync.dat");
        ev.access_mask = 0x100000; // SYNCHRONIZE
        let added = run_update(&mut cfg, &[ev], &[]);
        assert!(
            added.readonly.is_empty(),
            "SYNCHRONIZE-only must not promote"
        );
    }

    // ---- 8.3 short-name deny-alias guard ---------------------------------

    #[test]
    fn has_short_name_component_detects_mangled_names() {
        assert!(has_short_name_component("c:\\progra~1\\app"));
        assert!(has_short_name_component("c:\\secret~1\\token.dat"));
        assert!(has_short_name_component("c:\\dir\\file~12.txt"));
        // A tilde not followed by digits is a legit long name.
        assert!(!has_short_name_component("c:\\foo~bar\\baz"));
        assert!(!has_short_name_component("c:\\normal\\path.txt"));
    }

    #[test]
    fn short_name_path_is_not_promoted() {
        // 8.3 alias of a denied dir must be refused (fail-closed) even
        // though its normalized form doesn't share the deny prefix.
        let mut cfg = json!({
            "filesystem": { "deniedPaths": ["C:\\Secrets"] }
        });
        let added = run_update(
            &mut cfg,
            &[ev_write("C:\\secret~1\\token.dat")],
            &["C:\\Secrets"],
        );
        assert!(
            added.readwrite.is_empty(),
            "8.3 short-name alias of a denied dir must not be promoted"
        );
    }

    // Documented limitation: junction/symlink reparse aliases are NOT
    // resolved (no filesystem access on this hot path), so a lexically
    // distinct alias of a denied dir is NOT caught by deny matching and
    // would be promoted. This test pins that stated limitation (see
    // `readme.md`) so a future change that closes the gap updates it
    // deliberately.
    #[test]
    fn junction_alias_of_denied_dir_is_a_known_gap() {
        let mut cfg = json!({
            "filesystem": { "deniedPaths": ["C:\\Secrets"] }
        });
        let added = run_update(
            &mut cfg,
            // C:\work\link is a junction to C:\Secrets on a real system.
            &[ev_write("C:\\work\\link\\token.dat")],
            &["C:\\Secrets"],
        );
        assert_eq!(
            added.readwrite,
            vec!["C:\\work\\link\\token.dat".to_string()],
            "known limitation: reparse-point aliases are not resolved"
        );
    }

    // ---- resolve_adjusted_config_path (pure) -----------------------------

    #[test]
    fn resolve_adjusted_derives_sibling_name() {
        let got = resolve_adjusted_config_path(Path::new("C:\\logs\\config.json")).unwrap();
        assert_eq!(got, PathBuf::from("C:\\logs\\Adjusted_config.json"));
    }

    #[test]
    fn resolve_adjusted_relative_leaf() {
        let got = resolve_adjusted_config_path(Path::new("config.json")).unwrap();
        assert_eq!(got, PathBuf::from("Adjusted_config.json"));
    }

    #[test]
    fn resolve_adjusted_errors_without_file_name() {
        // A bare root has no file_name — error rather than emitting a
        // file literally named `Adjusted_`.
        assert!(resolve_adjusted_config_path(Path::new("C:\\")).is_err());
    }

    #[test]
    fn resolve_adjusted_is_pure_no_dir_side_effect() {
        // The resolver must not touch the filesystem: resolving a path
        // under a non-existent directory succeeds and creates nothing.
        let ghost = std::env::temp_dir().join(format!(
            "plm_resolve_pure_{}_{}",
            std::process::id(),
            "does_not_exist"
        ));
        let dest = ghost.join("config.json");
        let got = resolve_adjusted_config_path(&dest).unwrap();
        assert_eq!(got, ghost.join("Adjusted_config.json"));
        assert!(!ghost.exists(), "resolver must not create directories");
    }

    // ---- save_adjusted_config (atomic) -----------------------------------

    #[test]
    fn save_adjusted_config_round_trips() {
        let dir = std::env::temp_dir().join(format!("plm_save_atomic_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("Adjusted_config.json");
        let cfg = json!({"filesystem": {"readonlyPaths": ["C:\\x"]}});
        save_adjusted_config(&cfg, &path).unwrap();
        let back: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(back, cfg);
        // Overwriting an existing target must succeed (temp+rename).
        let cfg2 = json!({"filesystem": {"readonlyPaths": ["C:\\y"]}});
        save_adjusted_config(&cfg2, &path).unwrap();
        let back2: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(back2, cfg2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
