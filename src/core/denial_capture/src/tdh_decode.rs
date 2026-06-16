// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ETW event-record TDH decoder + property formatter.
//!
//! Used by the `session` module's ETW consumer to turn raw
//! `EVENT_RECORD` payloads into `DecodedEventParts` that the
//! extractors (`build_denial_from_*`) can operate on.
//!
//! Ported and slimmed from `feature/denied-resource-capture`
//! (`src/mxc_diagnostic_console/src/etw.rs`). Only the InTypes we
//! actually need for `AccessCheckLog` / `LearningModeViolation`
//! properties are wired up; the rest fall back to a textual
//! placeholder so the extractor still gets the right offset arithmetic
//! but doesn't waste cycles on unsupported encodings.

use windows::Win32::System::Diagnostics::Etw::{
    TdhGetEventInformation, EVENT_PROPERTY_INFO, EVENT_RECORD, TRACE_EVENT_INFO,
};

use crate::extractors::DecodedEventParts;

// TDH InType constants from evntrace.h / tdh.h.
const TDH_INTYPE_UNICODESTRING: u16 = 1;
const TDH_INTYPE_ANSISTRING: u16 = 2;
const TDH_INTYPE_INT8: u16 = 3;
const TDH_INTYPE_UINT8: u16 = 4;
const TDH_INTYPE_INT16: u16 = 5;
const TDH_INTYPE_UINT16: u16 = 6;
const TDH_INTYPE_INT32: u16 = 7;
const TDH_INTYPE_UINT32: u16 = 8;
const TDH_INTYPE_INT64: u16 = 9;
const TDH_INTYPE_UINT64: u16 = 10;
const TDH_INTYPE_BOOLEAN: u16 = 13;
const TDH_INTYPE_POINTER: u16 = 16;
const TDH_INTYPE_HEXINT32: u16 = 20;
const TDH_INTYPE_HEXINT64: u16 = 21;

/// Decodes an `EVENT_RECORD` into `DecodedEventParts`.
///
/// Returns `None` when TDH can't describe the event (rare — usually
/// indicates a corrupted or unknown event).
///
/// # Safety
/// `event_record` must point to a valid `EVENT_RECORD` provided by the
/// ETW callback; the caller must not retain references to its fields
/// after the callback returns.
pub unsafe fn decode_event_parts(event_record: *mut EVENT_RECORD) -> Option<DecodedEventParts> {
    let mut buf_size: u32 = 0;
    // First call: discover required buffer size. ERROR_INSUFFICIENT_BUFFER = 122.
    let status = unsafe { TdhGetEventInformation(event_record, None, None, &mut buf_size) };
    if status != 122 {
        return None;
    }

    let mut buffer = vec![0u8; buf_size as usize];
    let info_ptr = buffer.as_mut_ptr().cast::<TRACE_EVENT_INFO>();
    let status =
        unsafe { TdhGetEventInformation(event_record, None, Some(info_ptr), &mut buf_size) };
    if status != 0 {
        return None;
    }

    let info = unsafe { &*info_ptr };

    let event_id = unsafe { (*event_record).EventHeader.EventDescriptor.Id };
    let props = decode_properties(&buffer, info, event_record);

    Some(DecodedEventParts { event_id, props })
}

fn decode_properties(
    info_buf: &[u8],
    info: &TRACE_EVENT_INFO,
    event_record: *mut EVENT_RECORD,
) -> Vec<(String, String)> {
    // SAFETY: caller passes a valid EVENT_RECORD; the field accesses
    // are reads of POD fields.
    let event = unsafe { &*event_record };
    let user_data = event.UserData as *const u8;
    let user_data_len = event.UserDataLength as usize;

    if user_data.is_null() || user_data_len == 0 {
        return Vec::new();
    }

    let prop_count = info.TopLevelPropertyCount as usize;
    let mut results = Vec::with_capacity(prop_count);
    let mut offset: usize = 0;

    for i in 0..prop_count {
        // SAFETY: EventPropertyInfoArray is a flexible-length array of
        // EVENT_PROPERTY_INFO; TopLevelPropertyCount bounds the index.
        let prop_info = unsafe {
            let base =
                std::ptr::addr_of!(info.EventPropertyInfoArray) as *const EVENT_PROPERTY_INFO;
            &*base.add(i)
        };

        let prop_name =
            wide_str_at(info_buf, prop_info.NameOffset).unwrap_or_else(|| format!("prop{i}"));

        // PROPERTY_FLAGS::PropertyStruct = 1 — skip structured nested
        // properties (not needed for AccessCheckLog / LearningModeViolation).
        if prop_info.Flags.0 & 1 != 0 {
            results.push((prop_name, "<struct>".to_string()));
            continue;
        }

        // SAFETY: nonStructType is valid when PropertyStruct flag is unset.
        let in_type = unsafe { prop_info.Anonymous1.nonStructType.InType };
        // SAFETY: Anonymous3.length is always valid (a u16).
        let declared_length = unsafe { prop_info.Anonymous3.length } as usize;

        let remaining = user_data_len.saturating_sub(offset);
        let data_ptr = if remaining > 0 {
            // SAFETY: user_data is valid for user_data_len bytes; offset <= user_data_len.
            unsafe { user_data.add(offset) }
        } else {
            std::ptr::null()
        };

        let (value_str, consumed) =
            format_property_value(in_type, declared_length, data_ptr, remaining);

        offset += consumed;
        results.push((prop_name, value_str));
    }

    results
}

fn format_property_value(
    in_type: u16,
    declared_length: usize,
    data: *const u8,
    available: usize,
) -> (String, usize) {
    if data.is_null() || available == 0 {
        return ("<no data>".to_string(), 0);
    }

    match in_type {
        TDH_INTYPE_UNICODESTRING => {
            let max_wchars = available / 2;
            // SAFETY: data is valid for `available` bytes; max_wchars
            // bounds the slice.
            let wchars = unsafe { std::slice::from_raw_parts(data.cast::<u16>(), max_wchars) };
            let len = wchars.iter().position(|&c| c == 0).unwrap_or(max_wchars);
            let s = String::from_utf16_lossy(&wchars[..len]);
            // Include the null terminator in consumed bytes when present.
            let consumed = ((len + 1).min(max_wchars)) * 2;
            (format!("\"{s}\""), consumed)
        }
        TDH_INTYPE_ANSISTRING => {
            // SAFETY: data is valid for `available` bytes.
            let bytes = unsafe { std::slice::from_raw_parts(data, available) };
            let len = bytes.iter().position(|&b| b == 0).unwrap_or(available);
            let s = String::from_utf8_lossy(&bytes[..len]);
            let consumed = (len + 1).min(available);
            (format!("\"{s}\""), consumed)
        }
        TDH_INTYPE_INT8 if available >= 1 => {
            let v = unsafe { *data } as i8;
            (v.to_string(), 1)
        }
        TDH_INTYPE_UINT8 if available >= 1 => {
            let v = unsafe { *data };
            (v.to_string(), 1)
        }
        TDH_INTYPE_BOOLEAN if available >= 4 => {
            let v = unsafe { *(data.cast::<u32>()) };
            (if v != 0 { "true" } else { "false" }.to_string(), 4)
        }
        TDH_INTYPE_INT16 if available >= 2 => (unsafe { (*(data.cast::<i16>())).to_string() }, 2),
        TDH_INTYPE_UINT16 if available >= 2 => (unsafe { (*(data.cast::<u16>())).to_string() }, 2),
        TDH_INTYPE_INT32 if available >= 4 => (unsafe { (*(data.cast::<i32>())).to_string() }, 4),
        TDH_INTYPE_UINT32 if available >= 4 => (unsafe { (*(data.cast::<u32>())).to_string() }, 4),
        TDH_INTYPE_HEXINT32 if available >= 4 => {
            (format!("{:#x}", unsafe { *(data.cast::<u32>()) }), 4)
        }
        TDH_INTYPE_INT64 if available >= 8 => (unsafe { (*(data.cast::<i64>())).to_string() }, 8),
        TDH_INTYPE_UINT64 if available >= 8 => (unsafe { (*(data.cast::<u64>())).to_string() }, 8),
        TDH_INTYPE_HEXINT64 if available >= 8 => {
            (format!("{:#x}", unsafe { *(data.cast::<u64>()) }), 8)
        }
        TDH_INTYPE_POINTER if available >= 8 => (
            // 64-bit pointer; on 32-bit hosts this would be 4 bytes but
            // we only target x64.
            format!("{:#x}", unsafe { *(data.cast::<u64>()) }),
            8,
        ),
        // Unknown / unsupported InType: emit a placeholder. Consume the
        // declared length when one is given so offset arithmetic stays
        // consistent; otherwise consume zero.
        _ => ("<unsupported>".to_string(), declared_length.min(available)),
    }
}

fn wide_str_at(buf: &[u8], offset: u32) -> Option<String> {
    let offset = offset as usize;
    if offset == 0 || offset >= buf.len() {
        return None;
    }
    let slice = &buf[offset..];
    // The buffer is u8-aligned but the names are u16-aligned by
    // construction (TDH places them at even offsets). Iterate u16
    // pairs until null terminator or end of buffer.
    let mut end = slice.len();
    let mut i = 0;
    while i + 1 < slice.len() {
        let lo = slice[i] as u16;
        let hi = slice[i + 1] as u16;
        let wchar = lo | (hi << 8);
        if wchar == 0 {
            end = i;
            break;
        }
        i += 2;
    }
    let trimmed = &slice[..end];
    // Build a Vec<u16> from byte pairs.
    let wchars: Vec<u16> = trimmed
        .chunks_exact(2)
        .map(|p| (p[0] as u16) | ((p[1] as u16) << 8))
        .collect();
    if wchars.is_empty() {
        None
    } else {
        Some(String::from_utf16_lossy(&wchars))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_str_at_reads_utf16_until_null() {
        // "hi\0extra" as UTF-16 LE: 68 00 69 00 00 00 65 00 78 00 74 00 72 00 61 00
        let buf = [
            0u8, 0, // padding at offset 0
            b'h', 0, b'i', 0, 0, 0, b'e', 0, b'x', 0,
        ];
        assert_eq!(wide_str_at(&buf, 2).as_deref(), Some("hi"));
    }

    #[test]
    fn wide_str_at_out_of_bounds_returns_none() {
        let buf = [0u8; 4];
        assert!(wide_str_at(&buf, 100).is_none());
        assert!(wide_str_at(&buf, 0).is_none());
    }

    #[test]
    fn format_property_value_unicode_string_extracts_content() {
        let s = "hello";
        let mut bytes: Vec<u8> = s.encode_utf16().flat_map(|w| w.to_le_bytes()).collect();
        bytes.extend_from_slice(&[0, 0]); // null terminator
        let (val, consumed) =
            format_property_value(TDH_INTYPE_UNICODESTRING, 0, bytes.as_ptr(), bytes.len());
        assert_eq!(val, "\"hello\"");
        assert_eq!(consumed, bytes.len()); // 5 chars + null = 12 bytes
    }

    #[test]
    fn format_property_value_uint32_reads_little_endian() {
        let bytes = 0xCAFE_BABEu32.to_le_bytes();
        let (val, consumed) =
            format_property_value(TDH_INTYPE_UINT32, 4, bytes.as_ptr(), bytes.len());
        assert_eq!(val, "3405691582");
        assert_eq!(consumed, 4);
    }

    #[test]
    fn format_property_value_unsupported_consumes_declared_length() {
        let bytes = [0u8; 4];
        let (val, consumed) = format_property_value(0xFFFF, 4, bytes.as_ptr(), bytes.len());
        assert_eq!(val, "<unsupported>");
        assert_eq!(consumed, 4);
    }

    #[test]
    fn format_property_value_null_data_returns_no_data() {
        let (val, consumed) = format_property_value(TDH_INTYPE_UINT32, 4, std::ptr::null(), 0);
        assert_eq!(val, "<no data>");
        assert_eq!(consumed, 0);
    }
}
