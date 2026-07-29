// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ETW event-record TDH decoder + property formatter.
//!
//! Turns raw `EVENT_RECORD` payloads into [`DecodedEventParts`] (a flat
//! `(name, value)` list) that the [`crate::extractors`] operate on. Only
//! the `InType`s we need for the learning-mode denial events are wired up;
//! the rest fall back to a textual placeholder so offset arithmetic stays
//! consistent without wasting cycles on unsupported encodings.

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
const TDH_INTYPE_SID: u16 = 19;
const TDH_INTYPE_HEXINT32: u16 = 20;
const TDH_INTYPE_HEXINT64: u16 = 21;
const PROPERTY_STRUCT: i32 = 0x1;
const PROPERTY_PARAM_LENGTH: i32 = 0x2;
const PROPERTY_PARAM_COUNT: i32 = 0x4;
const MAX_PROPERTY_ELEMENTS: usize = 4096;
const EVENT_HEADER_FLAG_32_BIT_HEADER: u16 = 0x20;

struct TdhInfoBuffer {
    storage: Vec<std::mem::MaybeUninit<TRACE_EVENT_INFO>>,
    len: usize,
}

impl TdhInfoBuffer {
    fn new(len: usize) -> Self {
        let element_size = std::mem::size_of::<TRACE_EVENT_INFO>();
        let element_count = len.div_ceil(element_size).max(1);
        let mut storage = Vec::with_capacity(element_count);
        storage.resize_with(element_count, std::mem::MaybeUninit::uninit);
        // SAFETY: `storage` owns `element_count` writable elements. Zeroing
        // them makes the complete byte view initialized before TDH fills it.
        unsafe {
            std::ptr::write_bytes(storage.as_mut_ptr(), 0, element_count);
        }
        Self { storage, len }
    }

    fn as_mut_ptr(&mut self) -> *mut TRACE_EVENT_INFO {
        self.storage.as_mut_ptr().cast()
    }

    fn as_bytes(&self) -> &[u8] {
        // SAFETY: `new` zero-initializes the allocation, and `len` never
        // exceeds its capacity in bytes. The storage alignment is that of
        // `TRACE_EVENT_INFO`, while this view is used only for byte offsets.
        unsafe { std::slice::from_raw_parts(self.storage.as_ptr().cast(), self.len) }
    }
}

/// Decodes an `EVENT_RECORD` into `DecodedEventParts`.
///
/// Returns `None` when TDH can't describe the event (rare — usually
/// indicates a corrupted or unknown event).
///
/// # Safety
/// `event_record` must point to a valid `EVENT_RECORD` provided by the
/// ETW callback; the caller must not retain references to its fields
/// after the callback returns.
pub unsafe fn decode_event_parts(
    event_record: *mut EVENT_RECORD,
) -> Result<DecodedEventParts, String> {
    let mut buf_size: u32 = 0;
    // First call: discover required buffer size. ERROR_INSUFFICIENT_BUFFER = 122.
    let status = unsafe { TdhGetEventInformation(event_record, None, None, &mut buf_size) };
    if status != 122 {
        return Err(format!(
            "TdhGetEventInformation(size) failed with Win32 error {status}"
        ));
    }

    let mut buffer = TdhInfoBuffer::new(buf_size as usize);
    let info_ptr = buffer.as_mut_ptr();
    let status =
        unsafe { TdhGetEventInformation(event_record, None, Some(info_ptr), &mut buf_size) };
    if status != 0 {
        return Err(format!(
            "TdhGetEventInformation(data) failed with Win32 error {status}"
        ));
    }

    let info = unsafe { &*info_ptr };

    let header = unsafe { (*event_record).EventHeader };
    let event_id = header.EventDescriptor.Id;
    let pointer_size = pointer_size_from_header_flags(header.Flags);
    let props = decode_properties(buffer.as_bytes(), info, event_record, pointer_size)?;

    Ok(DecodedEventParts {
        provider: header.ProviderId,
        event_id,
        props,
    })
}

fn decode_properties(
    info_buf: &[u8],
    info: &TRACE_EVENT_INFO,
    event_record: *mut EVENT_RECORD,
    pointer_size: usize,
) -> Result<Vec<(String, String)>, String> {
    // SAFETY: caller passes a valid EVENT_RECORD; the field accesses
    // are reads of POD fields.
    let event = unsafe { &*event_record };
    let user_data = event.UserData as *const u8;
    let user_data_len = event.UserDataLength as usize;

    if user_data.is_null() || user_data_len == 0 {
        return Ok(Vec::new());
    }

    let property_count = info.PropertyCount as usize;
    let prop_count = info.TopLevelPropertyCount as usize;
    let mut results = Vec::with_capacity(prop_count);
    let mut numeric_values = vec![None; property_count];
    let mut offset: usize = 0;
    let context = PropertyDecodeContext {
        info_buf,
        info,
        user_data,
        user_data_len,
        pointer_size,
    };

    for i in 0..prop_count {
        let value = decode_property(i, &context, &mut offset, &mut numeric_values)?;
        results.push(value);
    }

    Ok(results)
}

struct PropertyDecodeContext<'a> {
    info_buf: &'a [u8],
    info: &'a TRACE_EVENT_INFO,
    user_data: *const u8,
    user_data_len: usize,
    pointer_size: usize,
}

fn decode_property(
    index: usize,
    context: &PropertyDecodeContext<'_>,
    offset: &mut usize,
    numeric_values: &mut [Option<usize>],
) -> Result<(String, String), String> {
    if index >= context.info.PropertyCount as usize {
        return Err(format!("property index {index} is out of range"));
    }
    let prop_info = event_property_info(context.info, index);
    let prop_name = wide_str_at(context.info_buf, prop_info.NameOffset)
        .unwrap_or_else(|| format!("prop{index}"));
    let flags = prop_info.Flags.0;
    let count = resolve_property_count(prop_info, flags, numeric_values, index)?;
    if count > MAX_PROPERTY_ELEMENTS {
        return Err(format!(
            "property '{prop_name}' count {count} exceeds limit {MAX_PROPERTY_ELEMENTS}"
        ));
    }

    if flags & PROPERTY_STRUCT != 0 {
        let start_index = unsafe { prop_info.Anonymous1.structType.StructStartIndex } as usize;
        let member_count = unsafe { prop_info.Anonymous1.structType.NumOfStructMembers } as usize;
        for _ in 0..count {
            for child_index in start_index..start_index + member_count {
                let _ = decode_property(child_index, context, offset, numeric_values)?;
            }
        }
        return Ok((prop_name, "<struct>".to_string()));
    }

    let in_type = unsafe { prop_info.Anonymous1.nonStructType.InType };
    let declared_length = if flags & PROPERTY_PARAM_LENGTH != 0 {
        let length_index = unsafe { prop_info.Anonymous3.lengthPropertyIndex } as usize;
        resolved_metadata(numeric_values, length_index, "length", index)?
    } else {
        (unsafe { prop_info.Anonymous3.length }) as usize
    };

    let mut values = Vec::with_capacity(count.min(available_element_bound(
        in_type,
        context.user_data_len.saturating_sub(*offset),
        context.pointer_size,
    )));
    let mut numeric_value = None;
    for _ in 0..count {
        let remaining = context.user_data_len.saturating_sub(*offset);
        if remaining == 0 {
            return Err(format!("property '{prop_name}' exceeds the event payload"));
        }
        let data_ptr = if remaining > 0 {
            unsafe { context.user_data.add(*offset) }
        } else {
            std::ptr::null()
        };
        let (value, consumed) = format_property_value_with_pointer_size(
            in_type,
            declared_length,
            data_ptr,
            remaining,
            context.pointer_size,
        );
        if consumed == 0 && remaining > 0 {
            return Err(format!(
                "property '{prop_name}' has unsupported variable length"
            ));
        }

        *offset = offset.saturating_add(consumed);
        if count == 1 {
            numeric_value = parse_numeric_metadata(&value);
        }
        values.push(value);
    }
    numeric_values[index] = numeric_value;

    let rendered = if values.len() == 1 {
        values.pop().unwrap_or_default()
    } else {
        format!("[{}]", values.join(", "))
    };
    Ok((prop_name, rendered))
}

fn resolve_property_count(
    prop_info: &EVENT_PROPERTY_INFO,
    flags: i32,
    numeric_values: &[Option<usize>],
    property_index: usize,
) -> Result<usize, String> {
    if flags & PROPERTY_PARAM_COUNT != 0 {
        let count_index = unsafe { prop_info.Anonymous2.countPropertyIndex } as usize;
        resolved_metadata(numeric_values, count_index, "count", property_index)
    } else {
        let count = unsafe { prop_info.Anonymous2.count } as usize;
        Ok(count.max(1))
    }
}

fn pointer_size_from_header_flags(flags: u16) -> usize {
    if flags & EVENT_HEADER_FLAG_32_BIT_HEADER != 0 {
        4
    } else {
        8
    }
}

fn available_element_bound(in_type: u16, available: usize, pointer_size: usize) -> usize {
    let element_size = match in_type {
        TDH_INTYPE_INT8 | TDH_INTYPE_UINT8 => 1,
        TDH_INTYPE_INT16 | TDH_INTYPE_UINT16 => 2,
        TDH_INTYPE_INT32 | TDH_INTYPE_UINT32 | TDH_INTYPE_BOOLEAN | TDH_INTYPE_HEXINT32 => 4,
        TDH_INTYPE_POINTER => pointer_size,
        TDH_INTYPE_INT64 | TDH_INTYPE_UINT64 | TDH_INTYPE_HEXINT64 => 8,
        _ => 1,
    };
    (available / element_size).max(1)
}

fn event_property_info(info: &TRACE_EVENT_INFO, index: usize) -> &EVENT_PROPERTY_INFO {
    unsafe {
        let base = std::ptr::addr_of!(info.EventPropertyInfoArray) as *const EVENT_PROPERTY_INFO;
        &*base.add(index)
    }
}

fn resolved_metadata(
    numeric_values: &[Option<usize>],
    metadata_index: usize,
    kind: &str,
    property_index: usize,
) -> Result<usize, String> {
    numeric_values
        .get(metadata_index)
        .and_then(|value| *value)
        .ok_or_else(|| {
            format!(
                "property {property_index} references unresolved {kind} property {metadata_index}"
            )
        })
}

fn parse_numeric_metadata(value: &str) -> Option<usize> {
    let value = value.trim().trim_matches('"');
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .and_then(|hex| usize::from_str_radix(hex, 16).ok())
        .or_else(|| value.parse().ok())
}

fn format_property_value_with_pointer_size(
    in_type: u16,
    declared_length: usize,
    data: *const u8,
    available: usize,
    pointer_size: usize,
) -> (String, usize) {
    if data.is_null() || available == 0 {
        return ("<no data>".to_string(), 0);
    }

    match in_type {
        TDH_INTYPE_UNICODESTRING => {
            let byte_len = if declared_length > 0 {
                declared_length.min(available)
            } else {
                available
            };
            let max_wchars = byte_len / 2;
            // SAFETY: data is valid for `available` bytes; byte_len is bounded
            // by available. Decode from byte pairs because ETW does not
            // guarantee payload alignment.
            let bytes = unsafe { std::slice::from_raw_parts(data, byte_len) };
            let mut wchars = Vec::with_capacity(max_wchars);
            let mut terminator_index = None;
            for (index, chunk) in bytes.chunks_exact(2).enumerate() {
                let wchar = u16::from_le_bytes([chunk[0], chunk[1]]);
                if wchar == 0 {
                    terminator_index = Some(index);
                    break;
                }
                wchars.push(wchar);
            }
            let s = String::from_utf16_lossy(&wchars);
            // Include the null terminator in consumed bytes when present.
            let consumed = if declared_length > 0 {
                byte_len
            } else {
                terminator_index.map_or(max_wchars * 2, |index| (index + 1) * 2)
            };
            (format!("\"{s}\""), consumed)
        }
        TDH_INTYPE_ANSISTRING => {
            let byte_len = if declared_length > 0 {
                declared_length.min(available)
            } else {
                available
            };
            let bytes = unsafe { std::slice::from_raw_parts(data, byte_len) };
            let len = bytes.iter().position(|&b| b == 0).unwrap_or(byte_len);
            let s = String::from_utf8_lossy(&bytes[..len]);
            let consumed = if declared_length > 0 {
                byte_len
            } else {
                (len + 1).min(available)
            };
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
            // SAFETY: data points to >=4 valid bytes; read_unaligned because
            // ETW payload alignment is not guaranteed.
            let v = unsafe { (data.cast::<u32>()).read_unaligned() };
            (if v != 0 { "true" } else { "false" }.to_string(), 4)
        }
        TDH_INTYPE_INT16 if available >= 2 => (
            unsafe { (data.cast::<i16>()).read_unaligned() }.to_string(),
            2,
        ),
        TDH_INTYPE_UINT16 if available >= 2 => (
            unsafe { (data.cast::<u16>()).read_unaligned() }.to_string(),
            2,
        ),
        TDH_INTYPE_INT32 if available >= 4 => (
            unsafe { (data.cast::<i32>()).read_unaligned() }.to_string(),
            4,
        ),
        TDH_INTYPE_UINT32 if available >= 4 => (
            unsafe { (data.cast::<u32>()).read_unaligned() }.to_string(),
            4,
        ),
        TDH_INTYPE_HEXINT32 if available >= 4 => (
            format!("{:#x}", unsafe { (data.cast::<u32>()).read_unaligned() }),
            4,
        ),
        TDH_INTYPE_INT64 if available >= 8 => (
            unsafe { (data.cast::<i64>()).read_unaligned() }.to_string(),
            8,
        ),
        TDH_INTYPE_UINT64 if available >= 8 => (
            unsafe { (data.cast::<u64>()).read_unaligned() }.to_string(),
            8,
        ),
        TDH_INTYPE_HEXINT64 if available >= 8 => (
            format!("{:#x}", unsafe { (data.cast::<u64>()).read_unaligned() }),
            8,
        ),
        TDH_INTYPE_POINTER if pointer_size == 4 && available >= 4 => (
            format!("{:#x}", unsafe { (data.cast::<u32>()).read_unaligned() }),
            4,
        ),
        TDH_INTYPE_POINTER if pointer_size == 8 && available >= 8 => (
            format!("{:#x}", unsafe { (data.cast::<u64>()).read_unaligned() }),
            8,
        ),
        TDH_INTYPE_SID if available >= 8 => format_sid(data, available),
        // Unknown / unsupported InType: emit a placeholder. Consume the
        // declared length when one is given so offset arithmetic stays
        // consistent; otherwise consume zero.
        _ => ("<unsupported>".to_string(), declared_length.min(available)),
    }
}

#[cfg(test)]
fn format_property_value(
    in_type: u16,
    declared_length: usize,
    data: *const u8,
    available: usize,
) -> (String, usize) {
    format_property_value_with_pointer_size(in_type, declared_length, data, available, 8)
}

fn format_sid(data: *const u8, available: usize) -> (String, usize) {
    let header = unsafe { std::slice::from_raw_parts(data, available.min(8)) };
    if header.len() < 8 {
        return ("<invalid SID>".to_string(), available);
    }
    let sub_authority_count = header[1] as usize;
    let length = 8usize.saturating_add(sub_authority_count.saturating_mul(4));
    if length > available {
        return ("<invalid SID>".to_string(), available);
    }
    let bytes = unsafe { std::slice::from_raw_parts(data, length) };
    let authority = bytes[2..8]
        .iter()
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
    let mut sid = format!("S-{}-{authority}", bytes[0]);
    for index in 0..sub_authority_count {
        let start = 8 + index * 4;
        let value = u32::from_le_bytes([
            bytes[start],
            bytes[start + 1],
            bytes[start + 2],
            bytes[start + 3],
        ]);
        sid.push_str(&format!("-{value}"));
    }
    (sid, length)
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
    fn tdh_info_buffer_is_aligned_and_initialized() {
        let mut buffer = TdhInfoBuffer::new(std::mem::size_of::<TRACE_EVENT_INFO>() + 7);

        assert_eq!(
            buffer
                .as_mut_ptr()
                .align_offset(std::mem::align_of::<TRACE_EVENT_INFO>()),
            0
        );
        assert!(buffer.as_bytes().iter().all(|byte| *byte == 0));
    }

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
    fn format_property_value_unicode_string_accepts_unaligned_data() {
        let encoded: Vec<u8> = "hello"
            .encode_utf16()
            .flat_map(|wchar| wchar.to_le_bytes())
            .chain([0, 0])
            .collect();
        let mut storage = vec![0u8; encoded.len() + 1];
        let base = storage.as_ptr() as usize;
        let offset = usize::from(base.is_multiple_of(std::mem::align_of::<u16>()));
        storage[offset..offset + encoded.len()].copy_from_slice(&encoded);
        let data = unsafe { storage.as_ptr().add(offset) };
        assert_ne!((data as usize) % std::mem::align_of::<u16>(), 0);

        let (value, consumed) =
            format_property_value(TDH_INTYPE_UNICODESTRING, 0, data, encoded.len());

        assert_eq!(value, "\"hello\"");
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn format_property_value_unicode_string_honors_fixed_length() {
        let bytes: Vec<u8> = "abc".encode_utf16().flat_map(|w| w.to_le_bytes()).collect();
        let (val, consumed) =
            format_property_value(TDH_INTYPE_UNICODESTRING, 4, bytes.as_ptr(), bytes.len());
        assert_eq!(val, "\"ab\"");
        assert_eq!(consumed, 4);
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
    fn pointer_width_follows_event_header_flags() {
        assert_eq!(pointer_size_from_header_flags(0), 8);
        assert_eq!(
            pointer_size_from_header_flags(EVENT_HEADER_FLAG_32_BIT_HEADER),
            4
        );
    }

    #[test]
    fn format_property_value_pointer_supports_32_and_64_bit_events() {
        let pointer32 = 0xCAFE_BABEu32.to_le_bytes();
        let (value, consumed) = format_property_value_with_pointer_size(
            TDH_INTYPE_POINTER,
            0,
            pointer32.as_ptr(),
            pointer32.len(),
            4,
        );
        assert_eq!(value, "0xcafebabe");
        assert_eq!(consumed, 4);

        let pointer64 = 0xCAFE_BABE_DEAD_BEEFu64.to_le_bytes();
        let (value, consumed) = format_property_value_with_pointer_size(
            TDH_INTYPE_POINTER,
            0,
            pointer64.as_ptr(),
            pointer64.len(),
            8,
        );
        assert_eq!(value, "0xcafebabedeadbeef");
        assert_eq!(consumed, 8);
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

    #[test]
    fn numeric_metadata_parses_decimal_and_hex() {
        assert_eq!(parse_numeric_metadata("12"), Some(12));
        assert_eq!(parse_numeric_metadata("0x10"), Some(16));
        assert_eq!(parse_numeric_metadata("\"7\""), Some(7));
        assert_eq!(parse_numeric_metadata("not-a-number"), None);
    }

    #[test]
    fn format_property_value_sid_decodes_identifier() {
        // S-1-15-3-1
        let bytes = [
            1, 2, // revision, sub-authority count
            0, 0, 0, 0, 0, 15, // identifier authority
            3, 0, 0, 0, // sub-authority 0
            1, 0, 0, 0, // sub-authority 1
        ];
        let (value, consumed) =
            format_property_value(TDH_INTYPE_SID, 0, bytes.as_ptr(), bytes.len());
        assert_eq!(value, "S-1-15-3-1");
        assert_eq!(consumed, bytes.len());
    }
}
