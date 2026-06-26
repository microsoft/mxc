//! EventID=27 (UI violation) decode + consume.
//!
//! The Permissive-Learning-Mode provider emits one `EventID=27` per
//! UI operation that *would* have been blocked by a Job UI Limit or
//! a Win32k subsystem disable. The payload commonly arrives as an
//! opaque `<ProcessingErrorData><EventPayload>` hex blob (when the
//! consumer can't resolve the provider manifest); when the manifest
//! IS available we get named `<Data Name="…">` children instead.
//!
//! This module owns both decoders, the fixed-width binary layout
//! reader, and the per-event accumulator helper that classifies a
//! decoded `UiEvent` by category (`CONVERT_TO_GUI` -> `need_ui`;
//! `UI_OPERATION` -> OR into `ui_operation_flags`).

use crate::event_parser::{ParseAccumulator, ParsedEvent};
use crate::ui_limits::{ui_limit_name, UiEvent, CONVERT_TO_GUI, UI_OPERATION};

// ---- Payload decoders ---------------------------------------------------

/// Documented hex-payload layout:
///
/// * `process_name` — UTF-8 / ASCII bytes, null-terminated.
/// * `process_id` — 8 bytes, little-endian.
/// * `sequence_number` — 8 bytes, little-endian.
/// * `category` — 4 bytes, little-endian.
/// * `detail` — 4 bytes, little-endian.
/// * `denied` — 0, 1, or 4 trailing bytes; non-zero means denied.
fn read_u32_le(bytes: &[u8], off: &mut usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    if end > bytes.len() {
        return None;
    }
    let mut arr = [0u8; 4];
    arr.copy_from_slice(&bytes[*off..end]);
    *off = end;
    Some(u32::from_le_bytes(arr))
}

fn read_u64_le(bytes: &[u8], off: &mut usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    if end > bytes.len() {
        return None;
    }
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&bytes[*off..end]);
    *off = end;
    Some(u64::from_le_bytes(arr))
}

/// Decode a UI-injection event payload from its hex representation.
/// Returns `None` if the hex is malformed or the payload is shorter
/// than the documented fixed-width tail.
pub fn parse_ui_event_payload(payload_hex: &str) -> Option<UiEvent> {
    let bytes = crate::extract_caps::parse_hex_string(payload_hex).ok()?;

    let null_pos = bytes.iter().position(|&b| b == 0)?;
    let process_name = String::from_utf8_lossy(&bytes[..null_pos]).into_owned();
    let mut off = null_pos + 1;

    let process_id = read_u64_le(&bytes, &mut off)?;
    let sequence_number = read_u64_le(&bytes, &mut off)?;
    let category = read_u32_le(&bytes, &mut off)?;
    let detail = read_u32_le(&bytes, &mut off)?;

    // `denied` is optional: trailing 0, 1, or 4 bytes have been
    // observed in the wild. Anything else means the payload doesn't
    // match the documented layout.
    let denied = match bytes.len().checked_sub(off) {
        Some(0) => None,
        Some(1) => Some(bytes[off] != 0),
        Some(4) => {
            let mut a = [0u8; 4];
            a.copy_from_slice(&bytes[off..off + 4]);
            Some(u32::from_le_bytes(a) != 0)
        }
        _ => return None,
    };

    Some(UiEvent {
        process_name,
        process_id,
        sequence_number,
        category,
        detail,
        denied,
    })
}

/// Parse an integer that may be written as decimal or `0x`-prefixed hex.
fn parse_u64_loose(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(rest, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

/// Decode a UI-injection event whose `EventData` carries named `Data`
/// children (i.e. the consumer resolved the provider manifest).
/// Recognised names: `ProcessName`, `ProcessId`, `SequenceNumber`,
/// `Category`, `Detail`, optional `Denied` (`true`/`false`/integer).
pub fn parse_ui_event_from_named(named: &[(String, String)]) -> Option<UiEvent> {
    let mut process_name: Option<String> = None;
    let mut process_id: Option<u64> = None;
    let mut sequence_number: Option<u64> = None;
    let mut category: Option<u32> = None;
    let mut detail: Option<u32> = None;
    let mut denied: Option<bool> = None;

    for (name, val) in named {
        match name.as_str() {
            "ProcessName" => process_name = Some(val.clone()),
            "ProcessId" => process_id = parse_u64_loose(val),
            "SequenceNumber" => sequence_number = parse_u64_loose(val),
            "Category" => category = parse_u64_loose(val).map(|v| v as u32),
            "Detail" => detail = parse_u64_loose(val).map(|v| v as u32),
            "Denied" => {
                let t = val.trim();
                denied = match t.to_ascii_lowercase().as_str() {
                    "true" | "1" => Some(true),
                    "false" | "0" => Some(false),
                    _ => parse_u64_loose(t).map(|v| v != 0),
                };
            }
            _ => {}
        }
    }

    Some(UiEvent {
        process_name: process_name?,
        process_id: process_id?,
        sequence_number: sequence_number?,
        category: category?,
        detail: detail?,
        denied,
    })
}

// ---- Per-event consume --------------------------------------------------

/// Per-event consume helper for `EventID=27`. Prefers the manifest-
/// resolved named form, falls back to the opaque hex payload, then
/// classifies the result by `category`.
pub(crate) fn consume_ui_violation(acc: &mut ParseAccumulator<'_>, ev: ParsedEvent) {
    acc.ui_event_count += 1;

    let ui_opt = parse_ui_event_from_named(&ev.event_data_named).or_else(|| {
        ev.processing_error_payload
            .as_deref()
            .and_then(parse_ui_event_payload)
    });

    match ui_opt {
        Some(ui) => {
            // Classify by category: CONVERT_TO_GUI -> `ui.disable=false`
            // (set via `need_ui`); UI_OPERATION -> per-bit field
            // relaxation via `ui_operation_flags`.
            match ui.category {
                CONVERT_TO_GUI => acc.need_ui = true,
                UI_OPERATION => acc.ui_operation_flags |= ui.detail,
                _ => {}
            }
            if acc.verbose {
                let detail_name = if ui.category == UI_OPERATION {
                    ui_limit_name(ui.detail).unwrap_or("UNKNOWN")
                } else {
                    "-"
                };
                println!(
                    "UI Injection event: process={} pid={} seq={} category=0x{:08X} detail=0x{:08X} ({}) denied={}",
                    ui.process_name,
                    ui.process_id,
                    ui.sequence_number,
                    ui.category,
                    ui.detail,
                    detail_name,
                    match ui.denied {
                        Some(true) => "true",
                        Some(false) => "false",
                        None => "(absent)",
                    },
                );
            }
            acc.ui_events.push(ui);
        }
        None => {
            // Undecodable payload: surface in verbose mode but ignore
            // otherwise. We can't tell the category, so there's no safe
            // relaxation to apply — assuming CONVERT_TO_GUI would over-
            // grant `ui.disable=false` on traces whose only undecoded
            // events were UI_OPERATION variants.
            if acc.verbose {
                if let Some(hex) = ev.processing_error_payload.as_deref() {
                    println!(
                        "UI Injection event observed (payload did not match expected layout, ignored: {hex})"
                    );
                } else {
                    println!(
                        "UI Injection event observed (no EventData / ProcessingErrorData, ignored)"
                    );
                }
            }
        }
    }
}

// ---- Test helpers -------------------------------------------------------

/// Build an `EventID=27` XML record whose payload is delivered as an
/// opaque `<ProcessingErrorData><EventPayload>` hex blob — the common
/// rendering when the consumer doesn't have the provider manifest.
#[cfg(test)]
pub(crate) fn make_ui_event_xml(category: u32, detail: u32) -> String {
    // Layout: process_name\0 | pid u64 | seq u64 | category u32 | detail u32 | denied u8
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"App");
    bytes.push(0);
    bytes.extend_from_slice(&1u64.to_le_bytes());
    bytes.extend_from_slice(&2u64.to_le_bytes());
    bytes.extend_from_slice(&category.to_le_bytes());
    bytes.extend_from_slice(&detail.to_le_bytes());
    bytes.push(1);
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(hex, "{:02X}", b);
    }
    format!(
        r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <EventID>27</EventID>
            <TimeCreated SystemTime="2024-01-02T03:04:05.000Z"/>
            <Execution ProcessID="1" ThreadID="2"/>
          </System>
          <ProcessingErrorData>
            <EventPayload>{hex}</EventPayload>
          </ProcessingErrorData>
        </Event>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_parser::parse_events_from_xml;
    use crate::ui_limits::{JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES};

    fn hex_for(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            use std::fmt::Write;
            let _ = write!(s, "{:02X}", b);
        }
        s
    }

    #[test]
    fn parse_ui_event_payload_decodes_fixed_layout() {
        // process_name="test\0", pid=1, seq=2, category=UI_OPERATION,
        // detail=JOB_OBJECT_UILIMIT_GLOBALATOMS, denied trailing byte 1.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"test");
        bytes.push(0);
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&2u64.to_le_bytes());
        bytes.extend_from_slice(&UI_OPERATION.to_le_bytes());
        bytes.extend_from_slice(&JOB_OBJECT_UILIMIT_GLOBALATOMS.to_le_bytes());
        bytes.push(1);
        let ui = parse_ui_event_payload(&hex_for(&bytes)).expect("should decode");
        assert_eq!(ui.process_name, "test");
        assert_eq!(ui.process_id, 1);
        assert_eq!(ui.sequence_number, 2);
        assert_eq!(ui.category, UI_OPERATION);
        assert_eq!(ui.detail, JOB_OBJECT_UILIMIT_GLOBALATOMS);
        assert_eq!(ui.denied, Some(true));
    }

    #[test]
    fn parse_ui_event_payload_rejects_truncated() {
        let bytes = b"test\0";
        assert!(parse_ui_event_payload(&hex_for(bytes)).is_none());
    }

    #[test]
    fn parse_ui_event_from_named_recognises_decimal_and_hex() {
        let named = vec![
            ("ProcessName".to_string(), "App".to_string()),
            ("ProcessId".to_string(), "42".to_string()),
            ("SequenceNumber".to_string(), "0x10".to_string()),
            ("Category".to_string(), "2".to_string()),
            ("Detail".to_string(), "0x20".to_string()),
            ("Denied".to_string(), "true".to_string()),
        ];
        let ui = parse_ui_event_from_named(&named).expect("should decode");
        assert_eq!(ui.process_name, "App");
        assert_eq!(ui.process_id, 42);
        assert_eq!(ui.sequence_number, 0x10);
        assert_eq!(ui.category, UI_OPERATION);
        assert_eq!(ui.detail, JOB_OBJECT_UILIMIT_GLOBALATOMS);
        assert_eq!(ui.denied, Some(true));
    }

    /// The parser produces a `ui_operation_flags` bitmap;
    /// `apply_ui_operation_flags` rewrites the config's `ui.*` fields.
    /// The two halves are tested individually but their bit-value
    /// contract is not — this integration test pins it. A drift between
    /// `JOB_OBJECT_UILIMIT_*` here and in `config.rs` will fail this
    /// test even when both halves' unit tests still pass.
    #[test]
    fn ui_event_xml_drives_config_relaxation_through_apply_ui_flags() {
        let xmls = [make_ui_event_xml(UI_OPERATION, JOB_OBJECT_UILIMIT_HANDLES)];
        let parse = parse_events_from_xml(xmls.iter(), None, false, Vec::new());

        assert_eq!(
            parse.ui_event_count, 1,
            "EventID=27 should be counted as a UI event"
        );
        assert_eq!(
            parse.ui_operation_flags, JOB_OBJECT_UILIMIT_HANDLES,
            "UI_OPERATION detail must OR into ui_operation_flags",
        );
        assert!(
            !parse.need_ui,
            "UI_OPERATION (not CONVERT_TO_GUI) must not set need_ui",
        );

        let mut config = serde_json::json!({ "ui": { "isolation": "handles" } });
        crate::config::apply_ui_operation_flags(&mut config, parse.ui_operation_flags)
            .expect("apply_ui_operation_flags");
        assert_eq!(
            config["ui"]["isolation"], "desktop",
            "HANDLES relaxation should widen ui.isolation handles -> desktop"
        );
    }

    /// `CONVERT_TO_GUI` violations flow through `set_ui_subsystem_enabled`
    /// rather than `apply_ui_operation_flags`. Pin that integration too.
    #[test]
    fn ui_convert_to_gui_event_sets_need_ui() {
        let xmls = [make_ui_event_xml(CONVERT_TO_GUI, 0)];
        let parse = parse_events_from_xml(xmls.iter(), None, false, Vec::new());

        assert_eq!(parse.ui_event_count, 1);
        assert!(parse.need_ui, "CONVERT_TO_GUI must set need_ui");
        assert_eq!(
            parse.ui_operation_flags, 0,
            "CONVERT_TO_GUI must NOT contribute to ui_operation_flags",
        );

        let mut config = serde_json::json!({});
        crate::config::set_ui_subsystem_enabled(&mut config).expect("set_ui_subsystem_enabled");
        assert_eq!(config["ui"]["disable"], false);
    }
}
