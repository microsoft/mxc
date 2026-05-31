// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Emergency mitigation (MXC issue #330) — silently drops a fixed set of
//! system-folder paths from filesystem-policy requests before they reach
//! `ShareFolderBatchAsync`. The OS API applies grants with subtree
//! inheritance, so granting these top-level folders propagates an agent
//! SID's ACE through their entire subtrees — catastrophic for drive roots,
//! the Windows directory, the Users root, ProgramFiles, and ProgramData.
//!
//! The proper fix belongs in the OS API. When that lands, delete this
//! file and the call site in `manager.rs::share_folders`.
//!
//! Known not covered (caller would have to actively pursue these spellings
//! to evade the text match): 8.3 short names (e.g. `PROGRA~1`), symlinks /
//! junctions (no `canonicalize` disk access), UNC paths,
//! `CommonProgramFiles` / `CommonProgramFiles(x86)`. The `\\?\` long-path
//! prefix on a disk path (`\\?\C:\foo`) IS handled — it normalizes to the
//! same canonical form as `C:\foo` so it cannot be used as a textual bypass.

use std::collections::HashSet;
use std::fmt::Write;
use std::sync::OnceLock;

use crate::logger::Logger;

/// Returns the lazily-computed, cached set of canonical paths the filter
/// rejects. Contents:
///
/// - 26 drive roots (`A:\` through `Z:\`) — static, no `GetLogicalDrives`
///   call so future-mounted drives are also caught.
/// - Normalized env-var-derived paths: `SystemRoot`, parent of `USERPROFILE`,
///   `ProgramFiles`, `ProgramFiles(x86)`, `ProgramData`, plus the aliases
///   `windir`, `ProgramW6432`, `AllUsersProfile`, `SYSTEMDRIVE` (each of
///   which collapses to one of the preceding via normalization-and-dedup).
///
/// Missing or empty env vars are silently skipped — pathological host
/// configuration is not the runner's failure mode.
fn protected_paths_set() -> &'static HashSet<String> {
    static SET: OnceLock<HashSet<String>> = OnceLock::new();
    SET.get_or_init(|| build_protected_paths_set(|var| std::env::var(var).ok()))
}

/// Construction logic for the protected-paths set, parameterised on an
/// env-var lookup so tests can inject synthetic environments without
/// touching the process-wide `OnceLock` cache.
fn build_protected_paths_set(env: impl Fn(&str) -> Option<String>) -> HashSet<String> {
    let mut set = HashSet::new();
    // 26 drive roots, regardless of current mount state.
    for letter in b'A'..=b'Z' {
        if let Some(p) = normalize_protected_path(&format!("{}:\\", letter as char)) {
            set.insert(p);
        }
    }
    // env-var-derived entries; (var name, take-parent flag).
    for (var, take_parent) in [
        ("SystemRoot", false),
        ("windir", false),
        ("USERPROFILE", true),
        ("ProgramFiles", false),
        ("ProgramFiles(x86)", false),
        ("ProgramW6432", false),
        ("ProgramData", false),
        ("AllUsersProfile", false),
        ("SYSTEMDRIVE", false),
    ] {
        let raw = match env(var) {
            Some(v) if !v.is_empty() => v,
            _ => continue,
        };
        let candidate = if take_parent {
            std::path::Path::new(&raw)
                .parent()
                .map(|p| p.to_string_lossy().into_owned())
        } else {
            Some(raw)
        };
        if let Some(c) = candidate {
            if let Some(n) = normalize_protected_path(&c) {
                set.insert(n);
            }
        }
    }
    set
}

/// Normalizes a Windows path for filter-set comparison. Returns `None` for
/// strings without a recognised disk prefix (only local absolute paths are
/// filtered). Applied to both filter-set entries and caller-supplied paths
/// so they compare on the same canonical form.
///
/// Handles (so accidental spellings still match):
/// - Forward slashes → backslashes.
/// - Trailing-slash discipline: drive `C:` → `c:\`; non-root paths drop the
///   trailing `\` via component re-assembly.
/// - `.` / `..` collapse, clamped at root (so `C:\..` stays `c:\`).
/// - Per-component trailing whitespace and dots trim (Win32 silently strips
///   these at the file-open boundary, making them a real bypass shape).
/// - Case-insensitive ASCII compare via lowercase-on-output.
/// - `\\?\` long-path prefix on a disk path (`\\?\C:\foo`): the `\\?\` is
///   dropped and the rest normalizes the same as `C:\foo`.
fn normalize_protected_path(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    let replaced = trimmed.replace('/', "\\");
    let path = std::path::Path::new(&replaced);

    let mut prefix: Option<String> = None;
    let mut has_root = false;
    let mut comps: Vec<String> = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::Prefix(pc) => {
                // `Disk(c)` is the plain `C:` form; `VerbatimDisk(c)` is the
                // `\\?\C:` long-path form, which Win32 strips at file-open
                // time — accept it as the same canonical disk prefix so it
                // cannot be used as a textual bypass. UNC (`\\server\share`)
                // and verbatim UNC remain in the documented skip list —
                // return early so the caller's path passes through.
                match pc.kind() {
                    std::path::Prefix::Disk(_) => {
                        prefix = Some(pc.as_os_str().to_string_lossy().into_owned());
                    }
                    std::path::Prefix::VerbatimDisk(letter) => {
                        prefix = Some(format!("{}:", letter as char));
                    }
                    _ => return None,
                }
            }
            std::path::Component::RootDir => {
                has_root = true;
            }
            std::path::Component::CurDir => { /* skip */ }
            std::path::Component::ParentDir => {
                // Pop within the components we've collected; clamps at root
                // because there's nothing to pop when comps is empty.
                comps.pop();
            }
            std::path::Component::Normal(s) => {
                let mut name = s.to_string_lossy().into_owned();
                while let Some(ch) = name.chars().last() {
                    if ch.is_ascii_whitespace() || ch == '.' {
                        name.pop();
                    } else {
                        break;
                    }
                }
                if !name.is_empty() {
                    comps.push(name);
                }
            }
        }
    }

    let prefix = prefix?;
    let mut out = prefix.to_ascii_lowercase();
    // Always end the prefix with `\` so drive-root spellings normalize to
    // `c:\` regardless of whether the input had the explicit RootDir
    // component (`C:` and `C:\` collapse to the same canonical form).
    out.push('\\');
    if !comps.is_empty() {
        // `C:foo` (prefix + components but no RootDir) is a drive-relative
        // path — `foo` resolves against the per-drive current directory.
        // That's not an absolute spelling of any filter entry; out of scope.
        if !has_root {
            return None;
        }
        let lowered: Vec<String> = comps.iter().map(|s| s.to_ascii_lowercase()).collect();
        out.push_str(&lowered.join("\\"));
    }
    Some(out)
}

/// Drops protected paths from `rw` / `ro` slices before they reach
/// `ShareFolderBatchAsync`. Returns the kept paths in their original
/// caller spelling so the OS API sees verbatim input.
///
/// When `logger` is provided AND at least one entry was dropped, emits a
/// single trace line summarising originals + canonical matches. The
/// state-aware `provision` path passes `None` and silently filters.
pub(super) fn filter_protected_paths(
    rw: &[String],
    ro: &[String],
    logger: Option<&mut Logger>,
) -> (Vec<String>, Vec<String>) {
    let set = protected_paths_set();
    let mut dropped: Vec<(String, String, &'static str)> = Vec::new();

    let mut partition = |list: &'static str, paths: &[String]| -> Vec<String> {
        let mut kept = Vec::with_capacity(paths.len());
        for p in paths {
            match normalize_protected_path(p) {
                Some(n) if set.contains(&n) => {
                    dropped.push((p.clone(), n, list));
                }
                _ => kept.push(p.clone()),
            }
        }
        kept
    };
    let rw_kept = partition("rw", rw);
    let ro_kept = partition("ro", ro);

    if let Some(logger) = logger {
        if !dropped.is_empty() {
            let summary: Vec<String> = dropped
                .iter()
                .map(|(orig, canon, list)| format!("'{}' ({}, matched {})", orig, list, canon))
                .collect();
            let _ = writeln!(
                logger,
                "filesystem policy filter dropped {} paths: {}",
                dropped.len(),
                summary.join(", "),
            );
        }
    }

    (rw_kept, ro_kept)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_drive_root_variants_collapse_to_canonical_form() {
        assert_eq!(normalize_protected_path("C:").as_deref(), Some("c:\\"));
        assert_eq!(normalize_protected_path("C:\\").as_deref(), Some("c:\\"));
        assert_eq!(normalize_protected_path("c:\\").as_deref(), Some("c:\\"));
        assert_eq!(normalize_protected_path("C:/").as_deref(), Some("c:\\"));
    }

    #[test]
    fn normalize_handles_case_and_slash_direction() {
        assert_eq!(
            normalize_protected_path("C:\\Windows").as_deref(),
            Some("c:\\windows")
        );
        assert_eq!(
            normalize_protected_path("c:/windows").as_deref(),
            Some("c:\\windows")
        );
        assert_eq!(
            normalize_protected_path("C:\\WINDOWS").as_deref(),
            Some("c:\\windows")
        );
    }

    #[test]
    fn normalize_drops_trailing_slash_for_non_root() {
        assert_eq!(
            normalize_protected_path("C:\\Windows\\").as_deref(),
            Some("c:\\windows")
        );
    }

    #[test]
    fn normalize_collapses_dot_components() {
        assert_eq!(
            normalize_protected_path("C:\\Windows\\.").as_deref(),
            Some("c:\\windows")
        );
        assert_eq!(
            normalize_protected_path("C:\\.\\Windows").as_deref(),
            Some("c:\\windows")
        );
    }

    #[test]
    fn normalize_pops_parent_components_clamped_at_root() {
        assert_eq!(
            normalize_protected_path("C:\\Windows\\..").as_deref(),
            Some("c:\\")
        );
        assert_eq!(
            normalize_protected_path("C:\\Windows\\System32\\..").as_deref(),
            Some("c:\\windows")
        );
        // Excess pops clamp at root.
        assert_eq!(
            normalize_protected_path("C:\\..\\..").as_deref(),
            Some("c:\\")
        );
    }

    #[test]
    fn normalize_trims_trailing_whitespace_and_dots_per_component() {
        // Win32 silently strips these at the file-open boundary, so they're
        // a real bypass shape (not just a curiosity).
        assert_eq!(
            normalize_protected_path("C:\\Windows ").as_deref(),
            Some("c:\\windows")
        );
        assert_eq!(
            normalize_protected_path("C:\\Windows.").as_deref(),
            Some("c:\\windows")
        );
        assert_eq!(
            normalize_protected_path("C:\\Windows...").as_deref(),
            Some("c:\\windows")
        );
        assert_eq!(
            normalize_protected_path("C:\\Windows . .").as_deref(),
            Some("c:\\windows")
        );
        // Trim applies to every component, not only the last.
        assert_eq!(
            normalize_protected_path("C:\\Windows \\System32").as_deref(),
            Some("c:\\windows\\system32")
        );
    }

    #[test]
    fn normalize_rejects_paths_without_drive_prefix() {
        assert_eq!(normalize_protected_path(""), None);
        assert_eq!(normalize_protected_path("   "), None);
        assert_eq!(normalize_protected_path("relative\\path"), None);
        // UNC: prefix is `\\server\share`, not a drive — out of filter scope.
        assert_eq!(normalize_protected_path("\\\\server\\share\\Windows"), None);
        // Verbatim UNC (`\\?\UNC\server\share\...`): not a disk prefix.
        assert_eq!(
            normalize_protected_path("\\\\?\\UNC\\server\\share\\Windows"),
            None
        );
        // Drive-relative (`C:foo`, no RootDir): `foo` resolves against the
        // per-drive cwd, not absolute. Out of filter scope.
        assert_eq!(normalize_protected_path("C:foo"), None);
    }

    #[test]
    fn normalize_verbatim_disk_prefix_collapses_to_canonical_form() {
        // `\\?\C:\foo` normalizes to the same canonical form as `C:\foo`,
        // so the long-path prefix cannot be used as a textual filter bypass.
        assert_eq!(
            normalize_protected_path("\\\\?\\C:\\Windows").as_deref(),
            Some("c:\\windows")
        );
        assert_eq!(
            normalize_protected_path("\\\\?\\c:\\windows\\").as_deref(),
            Some("c:\\windows")
        );
        assert_eq!(
            normalize_protected_path("\\\\?\\Z:\\").as_deref(),
            Some("z:\\")
        );
    }

    #[test]
    fn build_set_includes_all_26_drive_roots_with_empty_env() {
        let set = build_protected_paths_set(|_| None);
        assert_eq!(set.len(), 26);
        for letter in b'A'..=b'Z' {
            let key = format!("{}:\\", (letter as char).to_ascii_lowercase());
            assert!(set.contains(&key), "missing drive-root entry {}", key);
        }
    }

    #[test]
    fn build_set_includes_canonical_forms_of_supplied_env_vars() {
        let env = |var: &str| {
            Some(match var {
                "SystemRoot" => "C:\\Windows".to_string(),
                "USERPROFILE" => "C:\\Users\\me".to_string(),
                "ProgramFiles" => "C:\\Program Files".to_string(),
                "ProgramFiles(x86)" => "C:\\Program Files (x86)".to_string(),
                "ProgramData" => "C:\\ProgramData".to_string(),
                _ => return None,
            })
        };
        let set = build_protected_paths_set(env);
        assert!(set.contains("c:\\windows"));
        assert!(set.contains("c:\\users")); // USERPROFILE parent
        assert!(set.contains("c:\\program files"));
        assert!(set.contains("c:\\program files (x86)"));
        assert!(set.contains("c:\\programdata"));
    }

    #[test]
    fn build_set_aliases_dedupe_into_their_canonical_entries() {
        let env = |var: &str| {
            Some(match var {
                "SystemRoot" => "C:\\Windows".to_string(),
                "windir" => "C:\\Windows".to_string(),
                "ProgramFiles" => "C:\\Program Files".to_string(),
                "ProgramW6432" => "C:\\Program Files".to_string(),
                "ProgramData" => "C:\\ProgramData".to_string(),
                "AllUsersProfile" => "C:\\ProgramData".to_string(),
                "SYSTEMDRIVE" => "C:".to_string(),
                _ => return None,
            })
        };
        let set = build_protected_paths_set(env);
        // 26 drive roots + 3 unique env entries. SYSTEMDRIVE folds into the
        // drive-root set; the named aliases collapse into their primary.
        assert_eq!(set.len(), 26 + 3);
    }

    #[test]
    fn build_set_silently_skips_missing_or_empty_env_vars() {
        let env = |var: &str| match var {
            "SystemRoot" => Some(String::new()), // empty
            "ProgramFiles" => Some("C:\\Program Files".to_string()),
            _ => None, // everything else missing
        };
        let set = build_protected_paths_set(env);
        // Drive roots + only ProgramFiles (SystemRoot was empty, others missing).
        assert_eq!(set.len(), 26 + 1);
        assert!(set.contains("c:\\program files"));
    }

    #[test]
    fn build_set_handles_userprofile_at_drive_root() {
        // Pathological: USERPROFILE = "C:\" → parent is None → silently skipped.
        let env = |var: &str| match var {
            "USERPROFILE" => Some("C:\\".to_string()),
            _ => None,
        };
        let set = build_protected_paths_set(env);
        assert_eq!(set.len(), 26); // no extra entry from USERPROFILE
    }

    #[test]
    fn filter_drops_protected_drive_roots() {
        // Drive roots are always in the real set regardless of env, so this
        // composition test is hermetic.
        let (rw, _) = filter_protected_paths(
            &[
                "C:\\".to_string(),
                "C:\\Users\\Alice\\work".to_string(),
                "Z:\\".to_string(),
            ],
            &[],
            None,
        );
        assert!(!rw.iter().any(|p| p == "C:\\"));
        assert!(!rw.iter().any(|p| p == "Z:\\"));
        assert!(rw.contains(&"C:\\Users\\Alice\\work".to_string()));
    }

    #[test]
    fn filter_applies_to_readonly_paths_too() {
        let (_, ro) = filter_protected_paths(
            &[],
            &["D:\\".to_string(), "C:\\Users\\Alice\\data".to_string()],
            None,
        );
        assert!(!ro.iter().any(|p| p == "D:\\"));
        assert!(ro.contains(&"C:\\Users\\Alice\\data".to_string()));
    }

    #[test]
    fn filter_preserves_caller_spelling_for_kept_entries() {
        // Kept paths come out byte-for-byte as the caller supplied them
        // (the OS API gets the verbatim string, not the canonical form).
        let (rw, _) = filter_protected_paths(&["C:/Users/Alice/work".to_string()], &[], None);
        assert_eq!(rw, vec!["C:/Users/Alice/work".to_string()]);
    }

    #[test]
    fn filter_empty_input_yields_empty_output() {
        let (rw, ro) = filter_protected_paths(&[], &[], None);
        assert!(rw.is_empty());
        assert!(ro.is_empty());
    }

    #[test]
    fn filter_subdirectory_of_protected_path_passes_through() {
        // Exact-match-only: subdirectories of protected folders are not filtered.
        let (rw, _) = filter_protected_paths(
            &[
                "C:\\subdir-of-drive-root".to_string(),
                "Z:\\my\\subdir".to_string(),
            ],
            &[],
            None,
        );
        assert!(rw.contains(&"C:\\subdir-of-drive-root".to_string()));
        assert!(rw.contains(&"Z:\\my\\subdir".to_string()));
    }

    #[test]
    fn filter_catches_drive_root_bypass_attempts() {
        // Exercises the composition of normalize + set lookup for the
        // always-present drive-root entries.
        let (rw, _) = filter_protected_paths(
            &[
                "c:\\".to_string(),
                "C:/".to_string(),
                "C:".to_string(),
                "c:".to_string(),
                "C:\\..".to_string(),      // .. clamps at root
                "C:\\.".to_string(),       // . skipped
                "C:\\ ".to_string(),       // trailing space (after slash, this empties → root)
                "\\\\?\\C:\\".to_string(), // verbatim disk drive root
                "\\\\?\\Z:\\".to_string(),
            ],
            &[],
            None,
        );
        assert!(
            rw.is_empty(),
            "drive-root bypass variants should drop, got {:?}",
            rw
        );
    }
}
