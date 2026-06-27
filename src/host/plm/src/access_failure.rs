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
//!   * the per-event accumulator helper that feeds the DACL ACE blob
//!     through `extract_caps` and pushes the resulting access event.
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

/// Per-event consume helper for `EventID=14`. Walks the DACL ACE blob
/// through `extract_caps`, applies the post-XPath filters, and pushes a
/// `LearningModeAccessEvent` into `acc.valid_access_events` on success.
pub(crate) fn consume_access_failure(acc: &mut ParseAccumulator, mut ev: ParsedEvent) {
    if let Some(idx) = ev.complex_data_4_idx {
        // Borrow rather than clone — the ACE hex blob was already pushed
        // by `parse_event_xml`; the other EventData slots taken below
        // (0/1/3) live at different indices so this is safe.
        if let Some(blob) = ev.event_data.get(idx) {
            let blob_str = blob.as_str();
            if !blob_str.trim().is_empty() {
                let _ = crate::extract_caps::extract_caps_with_index_into(
                    blob_str,
                    &acc.capability_index,
                    acc.verbose,
                    &mut acc.requested_capabilities,
                );
            }
        }
    }

    // Pull the file path. Absent paths typically mean capability-only
    // resource accesses whose capability has already been collected
    // from the DACL above. Take the slot out via `mem::take` so we can
    // normalise + trim in place without a second `String` allocation.
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

    // Skip self-events: the app accessing its own binary. ETW reports
    // the accessed path in DOS form (`X:\dir\app.exe`) but the app's own
    // path in volume-device form (`\Device\HarddiskVolumeN\dir\app.exe`),
    // so we compare the *volume-relative* portion of each exactly. A raw
    // `app_path.ends_with(tail)` suffix test produced false positives —
    // e.g. an unrelated decoy `C:\app.exe` at the drive root matched a
    // real `\Device\HarddiskVolume3\Tools\app.exe`, and any short path
    // like `C:\exe` matched every `.exe` — silently dropping genuine
    // events. An exact match on the root-relative path avoids both while
    // still catching true self-access in any casing.
    let app_path = ev
        .event_data
        .get_mut(APP_PATH_INDEX)
        .map(std::mem::take)
        .unwrap_or_default();
    if !app_path.is_empty() {
        if let (Some(app_rel), Some(ev_rel)) = (volume_relative_path(&app_path), file_path.get(2..))
        {
            if !ev_rel.is_empty() && app_rel.eq_ignore_ascii_case(ev_rel) {
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

    // Deduplicate on the (case-insensitive) file path and merge access
    // masks. The provider emits the same denied access many times across
    // a trace, and the same file is often touched with different masks
    // (e.g. opened for read, later for write). Rather than push a fresh
    // near-identical entry per occurrence — which on a large trace
    // balloons `valid_access_events` with hundreds of thousands of
    // redundant rows — keep one entry per unique path and OR each new
    // mask into it. A file first read then written thus ends up
    // correctly flagged read+write in a single entry.
    let dedup_key = file_path.to_ascii_lowercase();
    if let Some(&idx) = acc.access_event_index.get(&dedup_key) {
        acc.valid_access_events[idx].access_mask |= access_mask;
        return;
    }
    acc.access_event_index
        .insert(dedup_key, acc.valid_access_events.len());

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

/// Reduce an application path to its *volume-relative* form — the path
/// from the volume root with a leading separator — so it can be compared
/// exactly against an event path's own root-relative portion
/// (`file_path.get(2..)`). Returns `None` for shapes we can't confidently
/// reduce, in which case the caller keeps the event rather than risk a
/// false self-access drop.
///
///   * DOS form `X:\dir\app.exe`               -> `\dir\app.exe`
///   * Device form `\Device\HarddiskVolumeN\dir\app.exe` -> `\dir\app.exe`
pub(crate) fn volume_relative_path(app_path: &str) -> Option<&str> {
    // DOS form `X:\...`: strip the two-byte `X:` drive prefix, keeping
    // the leading separator.
    let bytes = app_path.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' {
        return app_path.get(2..);
    }
    // Volume-device form `\Device\HarddiskVolumeN\<rest>`: return the
    // slice starting at the separator after the volume number so the
    // result lines up with the DOS root-relative form above.
    const VOL_PREFIX: &str = "\\Device\\HarddiskVolume";
    if app_path.len() > VOL_PREFIX.len()
        && app_path[..VOL_PREFIX.len()].eq_ignore_ascii_case(VOL_PREFIX)
    {
        let after_prefix = &app_path[VOL_PREFIX.len()..];
        if let Some(sep) = after_prefix.find('\\') {
            return Some(&after_prefix[sep..]);
        }
    }
    None
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
        let result = parse_events_from_xml(xmls.iter(), None, false, Vec::new());
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
        let result = parse_events_from_xml(xmls.iter(), None, false, Vec::new());
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

    /// EventData fixture with a caller-controlled `app_path` (index 3),
    /// so the self-access dispatcher branch can be exercised. Mirrors
    /// `make_event_xml`, which hard-codes a non-self `App.exe`.
    fn make_event_xml_with_app(file_path: &str, app_path: &str, mask_hex: &str) -> String {
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
                <Data>{app_path}</Data>
                <Data>0</Data>
                <Data>{mask_hex}</Data>
              </EventData>
            </Event>"#
        )
    }

    /// Dispatcher end-to-end: a `\Device\MountPointManager` record is
    /// dropped before it can reach `valid_access_events`.
    #[test]
    fn consume_drops_mount_point_manager() {
        let xmls = [make_event_xml("\\Device\\MountPointManager", "0x1")];
        let result = parse_events_from_xml(xmls.iter(), None, false, Vec::new());
        assert!(result.valid_access_events.is_empty());
    }

    /// Dispatcher end-to-end: current-directory events are filtered,
    /// while an unrelated path under a different root still passes.
    #[test]
    fn consume_skips_current_directory_but_keeps_others() {
        let xmls = [
            make_event_xml("C:\\repo\\src\\main.rs", "0x1"),
            make_event_xml("C:\\other\\x.txt", "0x1"),
        ];
        let result = parse_events_from_xml(xmls.iter(), Some("C:\\repo"), false, Vec::new());
        assert_eq!(result.valid_access_events.len(), 1);
        assert_eq!(result.valid_access_events[0].file_path, "C:\\other\\x.txt");
    }

    /// Dispatcher end-to-end: too-short and non-drive-letter paths are
    /// both dropped by the `is_skippable` gate.
    #[test]
    fn consume_skips_short_and_non_drive_letter() {
        let xmls = [
            make_event_xml("abc", "0x1"),
            make_event_xml("\\\\server\\share\\x", "0x1"),
        ];
        let result = parse_events_from_xml(xmls.iter(), None, false, Vec::new());
        assert!(result.valid_access_events.is_empty());
    }

    /// Dispatcher end-to-end: paths carrying invalid filename characters
    /// (wildcards, control bytes) are rejected.
    #[test]
    fn consume_drops_invalid_filename_chars() {
        let xmls = [make_event_xml("C:\\foo*bar.txt", "0x1")];
        let result = parse_events_from_xml(xmls.iter(), None, false, Vec::new());
        assert!(result.valid_access_events.is_empty());
    }

    /// Self-access: an event whose path is the running app's own binary
    /// is filtered. Covers both the volume-device (`\Device\...`) and
    /// DOS (`X:\...`) spellings of `app_path`.
    #[test]
    fn consume_filters_true_self_access() {
        let device = [make_event_xml_with_app(
            "C:\\Tools\\app.exe",
            "\\Device\\HarddiskVolume3\\Tools\\app.exe",
            "0x1",
        )];
        assert!(
            parse_events_from_xml(device.iter(), None, false, Vec::new())
                .valid_access_events
                .is_empty()
        );

        let dos = [make_event_xml_with_app(
            "C:\\Tools\\app.exe",
            "C:\\Tools\\app.exe",
            "0x1",
        )];
        assert!(parse_events_from_xml(dos.iter(), None, false, Vec::new())
            .valid_access_events
            .is_empty());

        // Case-insensitive: a differently-cased spelling still matches.
        let cased = [make_event_xml_with_app(
            "C:\\Tools\\App.EXE",
            "\\Device\\HarddiskVolume3\\tools\\app.exe",
            "0x1",
        )];
        assert!(parse_events_from_xml(cased.iter(), None, false, Vec::new())
            .valid_access_events
            .is_empty());
    }

    /// Regression for the old suffix-match self-access filter: a decoy
    /// file that merely shares the app's *filename* at a different
    /// location (`C:\app.exe` vs the real `...\Tools\app.exe`) must NOT
    /// be dropped, because `\app.exe` != `\Tools\app.exe`.
    #[test]
    fn consume_keeps_same_name_decoy_at_different_location() {
        let xmls = [make_event_xml_with_app(
            "C:\\app.exe",
            "\\Device\\HarddiskVolume3\\Tools\\app.exe",
            "0x1",
        )];
        let result = parse_events_from_xml(xmls.iter(), None, false, Vec::new());
        assert_eq!(result.valid_access_events.len(), 1);
        assert_eq!(result.valid_access_events[0].file_path, "C:\\app.exe");
    }

    /// A normal valid event flows all the way through the dispatcher to
    /// `valid_access_events` with its mask intact.
    #[test]
    fn consume_keeps_normal_valid_event() {
        let xmls = [make_event_xml("C:\\Users\\test\\doc.txt", "0x1")];
        let result = parse_events_from_xml(xmls.iter(), None, false, Vec::new());
        assert_eq!(result.valid_access_events.len(), 1);
        assert_eq!(
            result.valid_access_events[0].file_path,
            "C:\\Users\\test\\doc.txt"
        );
        assert_eq!(result.valid_access_events[0].access_mask, 0x1);
    }

    /// Repeated accesses to the same path (any casing) collapse to a
    /// single entry whose mask is the OR of every observed mask, rather
    /// than one near-identical entry per occurrence.
    #[test]
    fn consume_dedups_path_and_merges_masks() {
        let xmls = [
            make_event_xml("C:\\Users\\test\\dup.txt", "0x1"),
            make_event_xml("C:\\USERS\\TEST\\DUP.TXT", "0x2"),
            make_event_xml("C:\\Users\\test\\dup.txt", "0x1"),
        ];
        let result = parse_events_from_xml(xmls.iter(), None, false, Vec::new());
        assert_eq!(
            result.valid_access_events.len(),
            1,
            "same path (case-insensitive) must collapse to one entry"
        );
        assert_eq!(
            result.valid_access_events[0].access_mask, 0x3,
            "merged entry must OR every observed mask"
        );
    }

    #[test]
    fn volume_relative_path_reduces_device_and_dos_forms() {
        assert_eq!(
            volume_relative_path("\\Device\\HarddiskVolume3\\Tools\\app.exe"),
            Some("\\Tools\\app.exe")
        );
        assert_eq!(
            volume_relative_path("C:\\Tools\\app.exe"),
            Some("\\Tools\\app.exe")
        );
        // Unrecognized shapes reduce to None so the caller keeps the
        // event instead of risking a false self-access drop.
        assert_eq!(volume_relative_path("App.exe"), None);
        assert_eq!(volume_relative_path("\\Device\\Nul"), None);
    }
}
