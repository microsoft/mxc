//! EventID=14 (access-failure) decode + consume.
//!
//! The Permissive-Learning-Mode provider emits one `EventID=14` per
//! file/capability access that *would* have been denied. This module
//! owns:
//!   * the EventData property indices for that schema,
//!   * file-path normalization (NT-object / verbatim / DOS-device
//!     prefixes -> DOS form),
//!   * the post-XPath filters (current-directory, drive-letter,
//!     self-access, invalid filename chars),
//!   * the per-event accumulator helper that pushes the resulting
//!     access event into `ParseAccumulator`.
//!
//! ACE-blob → capability-name extraction lands in a later PR; this PR
//! only collects file paths and access masks.
//!
//! `ParseAccumulator` (in `event_parser`) owns the mutable state;
//! `consume_access_failure` is the only public entry point.

use crate::event_parser::{ParseAccumulator, ParsedEvent};

// File path we treat as "no useful info" and skip.
const MOUNT_POINT_MANAGER: &str = "\\Device\\MountPointManager";

// EventData property indexes for EventID=14 (matches the PowerShell
// parser's index map).
const LEARNING_MODE_INDEX: usize = 0;
const RESOURCE_TYPE_INDEX: usize = 1;
pub(crate) const FILE_PATH_INDEX: usize = 2;
const APP_PATH_INDEX: usize = 3;
const ACCESS_MASK_INDEX: usize = 5;

/// Per-event consume helper for `EventID=14`. Applies the post-XPath
/// filters and pushes a `LearningModeAccessEvent` into
/// `acc.valid_access_events` on success.
pub(crate) fn consume_access_failure(acc: &mut ParseAccumulator<'_>, mut ev: ParsedEvent) {
    // Pull the file path. Absent paths typically mean capability-only
    // resource accesses; the capability-extraction PR will use the
    // DACL ACE blob for those, but this PR drops them.
    let mut file_path = match ev.event_data.get_mut(FILE_PATH_INDEX) {
        Some(s) if !s.is_empty() => std::mem::take(s),
        _ => return,
    };

    if file_path.eq_ignore_ascii_case(MOUNT_POINT_MANAGER) {
        return;
    }

    normalize_file_path_in_place(&mut file_path);
    if acc.is_skippable(&file_path) {
        return;
    }

    // Skip self-events: the app accessing its own binary. The app path
    // is stored without a drive letter (HardDiskVolume form), so we
    // compare against the file path minus its `X:` drive prefix. The
    // drive prefix is exactly two bytes (`C:`), so `get(2..)` — not
    // `get(3..)` — keeps the leading separator/character of the path.
    // Using `get(..)` (rather than slicing) avoids a panic when the
    // path contains a non-ASCII byte spanning the split index.
    let app_path = ev
        .event_data
        .get_mut(APP_PATH_INDEX)
        .map(std::mem::take)
        .unwrap_or_default();
    if !app_path.is_empty() {
        if let Some(tail) = file_path.get(2..) {
            if !tail.is_empty() && app_path.ends_with(tail) {
                return;
            }
        }
    }

    if !looks_like_valid_path(&file_path) {
        return;
    }

    let learning_mode = ev
        .event_data
        .get_mut(LEARNING_MODE_INDEX)
        .map(std::mem::take)
        .unwrap_or_default();
    let resource_type = ev
        .event_data
        .get_mut(RESOURCE_TYPE_INDEX)
        .map(std::mem::take)
        .unwrap_or_default();
    let access_mask = ev
        .event_data
        .get(ACCESS_MASK_INDEX)
        .and_then(|s| parse_int_loose(s))
        .unwrap_or(0);

    if acc.verbose {
        println!("{app_path}");
        println!("{file_path}");
    }

    trim_backslashes_in_place(&mut file_path);

    // Drop duplicate access failures: the provider emits the same
    // (access_mask, path) pair repeatedly across a trace, and each
    // duplicate would otherwise add a redundant entry to the generated
    // config. Insert-and-check keeps the first occurrence only.
    if !acc
        .seen_access_events
        .insert((access_mask, file_path.clone()))
    {
        return;
    }

    acc.valid_access_events
        .push(crate::access_event::LearningModeAccessEvent {
            time_created: ev.time_created,
            process_id: ev.process_id,
            thread_id: ev.thread_id,
            learning_mode,
            resource_type,
            file_path,
            app_path,
            access_mask,
        });
}

/// Strip Windows path-namespace prefixes (`\??\`, `\\?\`, `\\.\`) so
/// downstream filters that expect a DOS form (`C:\...`) see one.
///
/// All three prefixes are exactly 4 bytes; their leading and trailing
/// bytes are both `\\`, and the middle pair is `??`, `\?`, or `\.`.
/// Encoded as a 2-byte tuple match for clarity.
pub(crate) fn normalize_file_path_in_place(s: &mut String) {
    let lead = s.len() - s.trim_start().len();
    if lead > 0 {
        s.drain(..lead);
    }
    let end_len = s.trim_end().len();
    s.truncate(end_len);

    if s.len() >= 4 {
        let h = s.as_bytes();
        let prefix_match = h[0] == b'\\'
            && h[3] == b'\\'
            && matches!((h[1], h[2]), (b'?', b'?') | (b'\\', b'?') | (b'\\', b'.'));
        if prefix_match {
            s.drain(..4);
        }
    }
}

/// Strip leading + trailing `\` from a `String` in place. Mirrors
/// `str::trim_matches('\\')` without the `.to_string()` round-trip the
/// hot path used to do.
pub(crate) fn trim_backslashes_in_place(s: &mut String) {
    let lead = s.len() - s.trim_start_matches('\\').len();
    if lead > 0 {
        s.drain(..lead);
    }
    let end_len = s.trim_end_matches('\\').len();
    s.truncate(end_len);
}

/// `Test-Path -IsValid` equivalent: reject control bytes and Windows
/// wildcards which the OS itself refuses.
pub(crate) fn looks_like_valid_path(path: &str) -> bool {
    const BAD: &[char] = &['<', '>', '"', '|', '?', '*'];
    !path.chars().any(|c| (c as u32) < 32 || BAD.contains(&c))
}

/// Accept decimal or `0x`-prefixed hex.
pub(crate) fn parse_int_loose(s: &str) -> Option<u32> {
    let t = s.trim();
    if let Some(rest) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u32::from_str_radix(rest, 16).ok()
    } else {
        t.parse::<u32>().ok()
    }
}

// ---- Test-only helpers ---------------------------------------------------

/// Allocating sibling of `normalize_file_path_in_place`, kept for tests
/// that want a `&str` -> `String` API. The hot path uses the in-place
/// variant.
#[cfg(test)]
pub(crate) fn normalize_file_path(p: &str) -> String {
    let mut s = p.to_string();
    normalize_file_path_in_place(&mut s);
    s
}

/// Free-function sibling of `ParseAccumulator::is_skippable` exposed
/// for unit tests that don't want to build a whole accumulator. Logic
/// must stay in lock-step with the cached form on `ParseAccumulator`.
#[cfg(test)]
pub(crate) fn is_skippable(
    file_path: &str,
    current_directory: Option<&str>,
    verbose: bool,
) -> bool {
    if let Some(cwd) = current_directory {
        // Defensive: refuse to treat a bare drive root ("C:" / "C:\\") as a
        // CWD prefix — otherwise the `format!("{cwd}\\")` match below would
        // swallow every event under that drive. Equality match still applies.
        let cwd_trimmed = cwd.trim_end_matches('\\');
        let is_drive_root = cwd_trimmed.len() == 2
            && cwd_trimmed.chars().nth(1) == Some(':')
            && cwd_trimmed
                .chars()
                .next()
                .map(|c| c.is_ascii_alphabetic())
                .unwrap_or(false);
        let normalized = file_path.trim_end_matches('\\');
        if normalized.eq_ignore_ascii_case(cwd_trimmed)
            || (!is_drive_root
                && normalized
                    .to_ascii_lowercase()
                    .starts_with(&format!("{}\\", cwd_trimmed.to_ascii_lowercase())))
        {
            if verbose {
                println!("Skipping current-directory event: {file_path}");
            }
            return true;
        }
    }
    if file_path.len() < 4 {
        if verbose {
            println!("Skipping too-short path event: {file_path}");
        }
        return true;
    }
    let second = file_path.chars().nth(1);
    if second != Some(':') {
        if verbose {
            println!("Skipping non-drive-letter path event: {file_path}");
        }
        return true;
    }
    false
}

/// Shared `EventID=14` XML fixture used by tests in this module and
/// by the mixed-stream integration test in `event_parser`.
#[cfg(test)]
pub(crate) fn make_event_xml(file_path: &str, mask_hex: &str) -> String {
    format!(
        r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <EventID>14</EventID>
            <TimeCreated SystemTime="2024-01-02T03:04:05.000Z"/>
            <Execution ProcessID="111" ThreadID="222"/>
          </System>
          <EventData>
            <Data>Permissive</Data>
            <Data>File</Data>
            <Data>{file_path}</Data>
            <Data>App.exe</Data>
            <Data>0</Data>
            <Data>{mask_hex}</Data>
          </EventData>
        </Event>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_parser::parse_events_from_xml;

    #[test]
    fn normalize_file_path_strips_nt_object_prefix() {
        assert_eq!(normalize_file_path("\\??\\C:\\foo"), "C:\\foo");
        assert_eq!(normalize_file_path("\\??\\c:\\foo"), "c:\\foo");
        assert_eq!(normalize_file_path("C:\\foo"), "C:\\foo");
    }

    /// Verbatim (`\\?\C:\...`) and DOS-device (`\\.\C:\...`) prefixes
    /// must be stripped before `is_skippable`'s drive-letter gate;
    /// otherwise the kernel provider's natural rendering of those
    /// forms drops every event.
    #[test]
    fn normalize_file_path_strips_verbatim_and_dos_device_prefixes() {
        // Each `\` doubles in a Rust string literal; on-disk path is
        // `\\?\C:\foo`.
        assert_eq!(normalize_file_path("\\\\?\\C:\\foo"), "C:\\foo");
        assert_eq!(normalize_file_path("\\\\.\\C:\\foo"), "C:\\foo");
        assert_eq!(normalize_file_path("\\\\?\\c:\\foo"), "c:\\foo");
    }

    /// After the prefix strip, a normalized path with a drive letter
    /// must survive `is_skippable`. Integration between
    /// `normalize_file_path` and the drive-letter gate.
    #[test]
    fn verbatim_prefix_path_survives_is_skippable() {
        let normalized = normalize_file_path("\\\\?\\C:\\Users\\test\\foo.txt");
        assert!(!is_skippable(&normalized, None, false));
    }

    #[test]
    fn is_skippable_rejects_short_and_non_drive_letter() {
        assert!(is_skippable("abc", None, false));
        assert!(is_skippable("\\\\server\\share", None, false));
        assert!(!is_skippable("C:\\foo", None, false));
    }

    #[test]
    fn is_skippable_filters_current_directory() {
        assert!(is_skippable(
            "C:\\repo\\src\\main.rs",
            Some("C:\\repo"),
            false
        ));
        assert!(!is_skippable(
            "C:\\not-repo\\src\\main.rs",
            Some("C:\\repo"),
            false
        ));
    }

    /// A CWD of bare `C:\` (drive root) must NOT swallow every event
    /// on that drive. Only an explicit equality match against the
    /// drive root is honored.
    #[test]
    fn is_skippable_does_not_treat_drive_root_cwd_as_prefix() {
        assert!(!is_skippable(
            "C:\\Windows\\System32\\foo.dll",
            Some("C:\\"),
            false
        ));
        assert!(!is_skippable(
            "C:\\Windows\\System32\\foo.dll",
            Some("C:"),
            false
        ));
        assert!(is_skippable("C:\\", Some("C:\\"), false));
    }

    #[test]
    fn looks_like_valid_path_rejects_control_and_wildcards() {
        assert!(!looks_like_valid_path("C:\\f\x00oo"));
        assert!(!looks_like_valid_path("C:\\foo*"));
        assert!(!looks_like_valid_path("C:\\foo?"));
        assert!(looks_like_valid_path("C:\\foo\\bar.txt"));
    }

    #[test]
    fn parse_events_from_xml_accumulates_access_events() {
        let xmls = [
            make_event_xml("C:\\Users\\test\\foo.txt", "0x1"),
            make_event_xml("C:\\Users\\test\\bar.txt", "0x2"),
        ];
        let result = parse_events_from_xml(xmls.iter(), None, false);
        assert_eq!(result.valid_access_events.len(), 2);
        assert_eq!(
            result.valid_access_events[0].file_path,
            "C:\\Users\\test\\foo.txt"
        );
        assert_eq!(result.valid_access_events[0].access_mask, 0x1);
        assert_eq!(result.valid_access_events[1].access_mask, 0x2);
    }

    /// When a single rendered event is malformed we must not abort
    /// the whole trace — every subsequent valid event would silently
    /// disappear, leaving PLM under-granting on the next adjust pass.
    /// The accumulator's `consume` swallows per-event parse failures;
    /// this test pins that.
    #[test]
    fn parse_events_from_xml_skips_malformed_and_continues() {
        let valid_a = make_event_xml("C:\\Users\\test\\a.txt", "0x1");
        let valid_b = make_event_xml("C:\\Users\\test\\b.txt", "0x2");
        let xmls: Vec<String> = vec![
            valid_a,
            "not xml".to_string(),
            "<not-an-event/>".to_string(),
            valid_b,
        ];
        let result = parse_events_from_xml(xmls.iter(), None, false);
        assert_eq!(
            result.valid_access_events.len(),
            2,
            "malformed events should be skipped, valid ones still collected"
        );
        assert_eq!(
            result.valid_access_events[0].file_path,
            "C:\\Users\\test\\a.txt"
        );
        assert_eq!(
            result.valid_access_events[1].file_path,
            "C:\\Users\\test\\b.txt"
        );
    }
}
