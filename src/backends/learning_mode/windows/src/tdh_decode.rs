// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ETW event-record TDH decoder + property formatter.
//!
//! Turns raw `EVENT_RECORD` payloads into [`DecodedEventParts`] (a flat
//! `(name, value)` list) that the [`crate::extractors`] operate on. Only
//! the `InType`s we need for the learning-mode denial events are wired up;
//! the rest fall back to a textual placeholder so offset arithmetic stays
//! consistent without wasting cycles on unsupported encodings.

use std::collections::HashMap;
use std::fmt::Write as _;

use windows::core::GUID;
use windows::Win32::System::Diagnostics::Etw::{
    TdhGetEventInformation, EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL, EVENT_PROPERTY_INFO,
    EVENT_RECORD, TRACE_EVENT_INFO,
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
const TDH_INTYPE_FLOAT: u16 = 11;
const TDH_INTYPE_DOUBLE: u16 = 12;
const TDH_INTYPE_BOOLEAN: u16 = 13;
const TDH_INTYPE_BINARY: u16 = 14;
const TDH_INTYPE_GUID: u16 = 15;
const TDH_INTYPE_POINTER: u16 = 16;
const TDH_INTYPE_FILETIME: u16 = 17;
const TDH_INTYPE_SYSTEMTIME: u16 = 18;
const TDH_INTYPE_SID: u16 = 19;
const TDH_INTYPE_HEXINT32: u16 = 20;
const TDH_INTYPE_HEXINT64: u16 = 21;
const TDH_INTYPE_UNICODECHAR: u16 = 306;
const TDH_INTYPE_ANSICHAR: u16 = 307;
const TDH_INTYPE_SIZET: u16 = 308;
const PROPERTY_STRUCT: i32 = 0x1;
const PROPERTY_PARAM_LENGTH: i32 = 0x2;
const PROPERTY_PARAM_COUNT: i32 = 0x4;
const MAX_PROPERTY_ELEMENTS: usize = 4096;
const MAX_STRUCT_DEPTH: usize = 32;
const MAX_DECODE_WORK: usize = 100_000;
const MAX_SCHEMA_CACHE_ENTRIES: usize = 4096;
const EVENT_HEADER_FLAG_32_BIT_HEADER: u16 = 0x20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct EventSchemaKey {
    provider: GUID,
    id: u16,
    version: u8,
    channel: u8,
    level: u8,
    opcode: u8,
    task: u16,
    keyword: u64,
}

impl EventSchemaKey {
    fn from_record(event_record: &EVENT_RECORD) -> Self {
        let header = event_record.EventHeader;
        let descriptor = header.EventDescriptor;
        Self {
            provider: header.ProviderId,
            id: descriptor.Id,
            version: descriptor.Version,
            channel: descriptor.Channel,
            level: descriptor.Level,
            opcode: descriptor.Opcode,
            task: descriptor.Task,
            keyword: descriptor.Keyword,
        }
    }
}

#[derive(Default)]
pub(crate) struct EventSchemaCache {
    schemas: HashMap<EventSchemaKey, TdhInfoBuffer>,
}

#[derive(Debug)]
pub(crate) enum DecodeError {
    Schema(String),
    Event {
        kind: EventDecodeKind,
        event_name: Option<String>,
        message: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EventDecodeKind {
    PayloadMalformed,
    DecoderLimitReached,
    UnsupportedPropertyEncoding,
}

impl DecodeError {
    pub(crate) fn is_schema_error(&self) -> bool {
        matches!(self, Self::Schema(_))
    }

    pub(crate) fn event_kind(&self) -> Option<EventDecodeKind> {
        match self {
            Self::Event { kind, .. } => Some(*kind),
            Self::Schema(_) => None,
        }
    }

    pub(crate) fn event_name(&self) -> Option<&str> {
        match self {
            Self::Event { event_name, .. } => event_name.as_deref(),
            Self::Schema(_) => None,
        }
    }

    pub(crate) fn event(
        kind: EventDecodeKind,
        message: String,
        event_name: Option<String>,
    ) -> Self {
        Self::Event {
            kind,
            event_name,
            message,
        }
    }
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Schema(message) | Self::Event { message, .. } => f.write_str(message),
        }
    }
}

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

    fn as_ptr(&self) -> *const TRACE_EVENT_INFO {
        self.storage.as_ptr().cast()
    }

    fn as_bytes(&self) -> &[u8] {
        // SAFETY: `new` zero-initializes the allocation, and `len` never
        // exceeds its capacity in bytes. The storage alignment is that of
        // `TRACE_EVENT_INFO`, while this view is used only for byte offsets.
        unsafe { std::slice::from_raw_parts(self.storage.as_ptr().cast(), self.len) }
    }

    #[cfg(test)]
    fn as_bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: same allocation and bounds as `as_bytes`, with exclusive
        // access through `&mut self`.
        unsafe { std::slice::from_raw_parts_mut(self.storage.as_mut_ptr().cast(), self.len) }
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
    schema_cache: &mut EventSchemaCache,
) -> Result<DecodedEventParts, DecodeError> {
    let event = unsafe { &*event_record };
    let mut uncached_schema = None;
    let buffer = unsafe { event_schema(event_record, event, schema_cache, &mut uncached_schema) }?;
    let info = unsafe { &*buffer.as_ptr() };

    let header = event.EventHeader;
    let event_id = header.EventDescriptor.Id;
    let pointer_size = pointer_size_from_header_flags(header.Flags);
    let event_name = schema_event_name(buffer.as_bytes(), info);
    let props = decode_properties(buffer.as_bytes(), info, event_record, pointer_size)
        .map_err(|error| map_property_decode_error(error, event_name))?;

    Ok(DecodedEventParts {
        provider: header.ProviderId,
        event_id,
        props,
    })
}

/// Decodes one named property without decoding properties that follow it.
///
/// # Safety
/// `event_record` must satisfy the same requirements as [`decode_event_parts`].
pub unsafe fn decode_event_property(
    event_record: *mut EVENT_RECORD,
    schema_cache: &mut EventSchemaCache,
    property_name: &str,
) -> Result<Option<String>, DecodeError> {
    let event = unsafe { &*event_record };
    let mut uncached_schema = None;
    let buffer = unsafe { event_schema(event_record, event, schema_cache, &mut uncached_schema) }?;
    let info = unsafe { &*buffer.as_ptr() };
    let event_name = schema_event_name(buffer.as_bytes(), info);
    decode_named_property(
        buffer.as_bytes(),
        info,
        event_record,
        pointer_size_from_header_flags(event.EventHeader.Flags),
        property_name,
    )
    .map_err(|error| map_property_decode_error(error, event_name))
}

unsafe fn event_schema<'a>(
    event_record: *mut EVENT_RECORD,
    event: &EVENT_RECORD,
    schema_cache: &'a mut EventSchemaCache,
    uncached_schema: &'a mut Option<TdhInfoBuffer>,
) -> Result<&'a TdhInfoBuffer, DecodeError> {
    let key = EventSchemaKey::from_record(event);
    let cacheable = !unsafe { has_trace_logging_schema(event) };
    if !cacheable {
        *uncached_schema = Some(unsafe { load_event_schema(event_record) }?);
    } else if !schema_cache.schemas.contains_key(&key) {
        let schema = unsafe { load_event_schema(event_record) }?;
        if schema_cache.schemas.len() < MAX_SCHEMA_CACHE_ENTRIES {
            schema_cache.schemas.insert(key, schema);
        } else {
            *uncached_schema = Some(schema);
        }
    }
    schema_buffer(schema_cache, &key, uncached_schema)
}

fn schema_buffer<'a>(
    schema_cache: &'a EventSchemaCache,
    key: &EventSchemaKey,
    uncached_schema: &'a Option<TdhInfoBuffer>,
) -> Result<&'a TdhInfoBuffer, DecodeError> {
    if let Some(buffer) = uncached_schema {
        return Ok(buffer);
    }
    schema_cache
        .schemas
        .get(key)
        .ok_or_else(|| DecodeError::Schema("event schema cache lookup failed".to_string()))
}

fn map_property_decode_error(
    error: PropertyDecodeError,
    event_name: Option<String>,
) -> DecodeError {
    match error.kind {
        PropertyDecodeErrorKind::Schema => DecodeError::Schema(error.message),
        PropertyDecodeErrorKind::PayloadMalformed => {
            DecodeError::event(EventDecodeKind::PayloadMalformed, error.message, event_name)
        }
        PropertyDecodeErrorKind::DecoderLimitReached => DecodeError::event(
            EventDecodeKind::DecoderLimitReached,
            error.message,
            event_name,
        ),
        PropertyDecodeErrorKind::UnsupportedPropertyEncoding => DecodeError::event(
            EventDecodeKind::UnsupportedPropertyEncoding,
            error.message,
            event_name,
        ),
    }
}

fn schema_event_name(info_buf: &[u8], info: &TRACE_EVENT_INFO) -> Option<String> {
    // SAFETY: `info` points into the TDH buffer and this union member is the
    // event-name offset for the decoding sources used by these providers.
    let event_name_offset = unsafe { info.Anonymous1.EventNameOffset };
    wide_str_at(info_buf, event_name_offset).or_else(|| wide_str_at(info_buf, info.TaskNameOffset))
}

unsafe fn load_event_schema(event_record: *mut EVENT_RECORD) -> Result<TdhInfoBuffer, DecodeError> {
    let mut buf_size: u32 = 0;
    // First call: discover required buffer size. ERROR_INSUFFICIENT_BUFFER = 122.
    let status = unsafe { TdhGetEventInformation(event_record, None, None, &mut buf_size) };
    if status != 122 {
        return Err(DecodeError::Schema(format!(
            "TdhGetEventInformation(size) failed with Win32 error {status}"
        )));
    }

    let mut buffer = TdhInfoBuffer::new(buf_size as usize);
    let info_ptr = buffer.as_mut_ptr();
    let status =
        unsafe { TdhGetEventInformation(event_record, None, Some(info_ptr), &mut buf_size) };
    if status != 0 {
        return Err(DecodeError::Schema(format!(
            "TdhGetEventInformation(data) failed with Win32 error {status}"
        )));
    }

    Ok(buffer)
}

unsafe fn has_trace_logging_schema(event_record: &EVENT_RECORD) -> bool {
    if event_record.ExtendedData.is_null() || event_record.ExtendedDataCount == 0 {
        return false;
    }
    // SAFETY: ETW owns an array of `ExtendedDataCount` entries for the
    // callback lifetime.
    let items = unsafe {
        std::slice::from_raw_parts(
            event_record.ExtendedData,
            event_record.ExtendedDataCount as usize,
        )
    };
    items
        .iter()
        .any(|item| u32::from(item.ExtType) == EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PropertyDecodeErrorKind {
    Schema,
    PayloadMalformed,
    DecoderLimitReached,
    UnsupportedPropertyEncoding,
}

#[derive(Debug)]
struct PropertyDecodeError {
    kind: PropertyDecodeErrorKind,
    message: String,
}

impl PropertyDecodeError {
    fn schema(message: String) -> Self {
        Self {
            kind: PropertyDecodeErrorKind::Schema,
            message,
        }
    }

    fn payload(message: String) -> Self {
        Self {
            kind: PropertyDecodeErrorKind::PayloadMalformed,
            message,
        }
    }

    fn limit(message: String) -> Self {
        Self {
            kind: PropertyDecodeErrorKind::DecoderLimitReached,
            message,
        }
    }

    fn unsupported(message: String) -> Self {
        Self {
            kind: PropertyDecodeErrorKind::UnsupportedPropertyEncoding,
            message,
        }
    }
}

fn decode_properties(
    info_buf: &[u8],
    info: &TRACE_EVENT_INFO,
    event_record: *mut EVENT_RECORD,
    pointer_size: usize,
) -> Result<Vec<(String, String)>, PropertyDecodeError> {
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
    if prop_count > property_count {
        return Err(PropertyDecodeError::schema(format!(
            "top-level property count {prop_count} exceeds property count {property_count}"
        )));
    }

    let mut results = Vec::with_capacity(prop_count);
    let mut numeric_values = vec![None; property_count];
    let mut offset: usize = 0;
    let mut work_remaining = MAX_DECODE_WORK;
    let context = PropertyDecodeContext {
        info_buf,
        info,
        user_data,
        user_data_len,
        pointer_size,
    };

    for i in 0..prop_count {
        decode_property(
            i,
            &context,
            &mut offset,
            &mut numeric_values,
            0,
            &mut work_remaining,
            &mut results,
        )?;
    }

    Ok(results)
}

fn decode_named_property(
    info_buf: &[u8],
    info: &TRACE_EVENT_INFO,
    event_record: *mut EVENT_RECORD,
    pointer_size: usize,
    property_name: &str,
) -> Result<Option<String>, PropertyDecodeError> {
    // SAFETY: caller passes a valid EVENT_RECORD; the field accesses
    // are reads of POD fields.
    let event = unsafe { &*event_record };
    let user_data = event.UserData as *const u8;
    let user_data_len = event.UserDataLength as usize;
    if user_data.is_null() || user_data_len == 0 {
        return Ok(None);
    }

    let property_count = info.PropertyCount as usize;
    let prop_count = info.TopLevelPropertyCount as usize;
    if prop_count > property_count {
        return Err(PropertyDecodeError::schema(format!(
            "top-level property count {prop_count} exceeds property count {property_count}"
        )));
    }

    let mut numeric_values = vec![None; property_count];
    let mut offset = 0;
    let mut work_remaining = MAX_DECODE_WORK;
    let mut decoded = Vec::new();
    let context = PropertyDecodeContext {
        info_buf,
        info,
        user_data,
        user_data_len,
        pointer_size,
    };
    for index in 0..prop_count {
        decode_property(
            index,
            &context,
            &mut offset,
            &mut numeric_values,
            0,
            &mut work_remaining,
            &mut decoded,
        )?;
        if let Some((_, value)) = decoded
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(property_name))
        {
            return Ok(Some(value.clone()));
        }
        decoded.clear();
    }
    Ok(None)
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
    depth: usize,
    work_remaining: &mut usize,
    results: &mut Vec<(String, String)>,
) -> Result<(), PropertyDecodeError> {
    *work_remaining = work_remaining.checked_sub(1).ok_or_else(|| {
        PropertyDecodeError::limit(format!(
            "property decode work exceeds limit {MAX_DECODE_WORK}"
        ))
    })?;
    if depth > MAX_STRUCT_DEPTH {
        return Err(PropertyDecodeError::limit(format!(
            "property nesting exceeds limit {MAX_STRUCT_DEPTH}"
        )));
    }
    if index >= context.info.PropertyCount as usize {
        return Err(PropertyDecodeError::schema(format!(
            "property index {index} is out of range"
        )));
    }
    let prop_info = event_property_info(context.info, index);
    let prop_name = wide_str_at(context.info_buf, prop_info.NameOffset)
        .unwrap_or_else(|| format!("prop{index}"));
    let flags = prop_info.Flags.0;
    let count = resolve_property_count(prop_info, flags, numeric_values, index)?;
    if count > MAX_PROPERTY_ELEMENTS {
        return Err(PropertyDecodeError::limit(format!(
            "property '{prop_name}' count {count} exceeds limit {MAX_PROPERTY_ELEMENTS}"
        )));
    }

    if flags & PROPERTY_STRUCT != 0 {
        let start_index = unsafe { prop_info.Anonymous1.structType.StructStartIndex } as usize;
        let member_count = unsafe { prop_info.Anonymous1.structType.NumOfStructMembers } as usize;
        let end_index = start_index.checked_add(member_count).ok_or_else(|| {
            PropertyDecodeError::schema(format!(
                "property '{prop_name}' struct member range overflows"
            ))
        })?;
        if end_index > context.info.PropertyCount as usize {
            return Err(PropertyDecodeError::schema(format!(
                "property '{prop_name}' struct member range {start_index}..{end_index} exceeds property count {}",
                context.info.PropertyCount
            )));
        }
        if member_count == 0 {
            return Err(PropertyDecodeError::schema(format!(
                "property '{prop_name}' has no struct members"
            )));
        }
        results.push((prop_name, "<struct>".to_string()));
        for _ in 0..count {
            for child_index in start_index..end_index {
                decode_property(
                    child_index,
                    context,
                    offset,
                    numeric_values,
                    depth + 1,
                    work_remaining,
                    results,
                )?;
            }
        }
        return Ok(());
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
            return Err(PropertyDecodeError::payload(format!(
                "property '{prop_name}' exceeds the event payload"
            )));
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
            return Err(zero_consumption_error(&prop_name, in_type));
        }

        *offset = offset
            .checked_add(consumed)
            .filter(|next| *next <= context.user_data_len)
            .ok_or_else(|| {
                PropertyDecodeError::payload(format!(
                    "property '{prop_name}' exceeds the event payload"
                ))
            })?;
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
    results.push((prop_name, rendered));
    Ok(())
}

fn resolve_property_count(
    prop_info: &EVENT_PROPERTY_INFO,
    flags: i32,
    numeric_values: &[Option<usize>],
    property_index: usize,
) -> Result<usize, PropertyDecodeError> {
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
) -> Result<usize, PropertyDecodeError> {
    let Some(value) = numeric_values.get(metadata_index) else {
        return Err(PropertyDecodeError::schema(format!(
            "property {property_index} references out-of-range {kind} property {metadata_index}"
        )));
    };
    value.ok_or_else(|| {
        PropertyDecodeError::schema(format!(
            "property {property_index} references unresolved {kind} property {metadata_index}"
        ))
    })
}

fn is_known_property_type(in_type: u16) -> bool {
    matches!(
        in_type,
        TDH_INTYPE_UNICODESTRING
            | TDH_INTYPE_ANSISTRING
            | TDH_INTYPE_INT8
            | TDH_INTYPE_UINT8
            | TDH_INTYPE_INT16
            | TDH_INTYPE_UINT16
            | TDH_INTYPE_INT32
            | TDH_INTYPE_UINT32
            | TDH_INTYPE_INT64
            | TDH_INTYPE_UINT64
            | TDH_INTYPE_FLOAT
            | TDH_INTYPE_DOUBLE
            | TDH_INTYPE_BOOLEAN
            | TDH_INTYPE_BINARY
            | TDH_INTYPE_GUID
            | TDH_INTYPE_POINTER
            | TDH_INTYPE_FILETIME
            | TDH_INTYPE_SYSTEMTIME
            | TDH_INTYPE_SID
            | TDH_INTYPE_HEXINT32
            | TDH_INTYPE_HEXINT64
            | TDH_INTYPE_UNICODECHAR
            | TDH_INTYPE_ANSICHAR
            | TDH_INTYPE_SIZET
    )
}

fn zero_consumption_error(property_name: &str, in_type: u16) -> PropertyDecodeError {
    let message = format!("property '{property_name}' could not be decoded");
    if is_known_property_type(in_type) {
        PropertyDecodeError::payload(message)
    } else {
        PropertyDecodeError::unsupported(message)
    }
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
            if declared_length > available || !declared_length.is_multiple_of(2) {
                return ("<truncated unicode string>".to_string(), 0);
            }
            let byte_len = if declared_length > 0 {
                declared_length
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
                let Some(index) = terminator_index else {
                    return ("<truncated unicode string>".to_string(), 0);
                };
                (index + 1) * 2
            };
            (format!("\"{s}\""), consumed)
        }
        TDH_INTYPE_ANSISTRING => {
            if declared_length > available {
                return ("<truncated ansi string>".to_string(), 0);
            }
            let byte_len = if declared_length > 0 {
                declared_length
            } else {
                available
            };
            let bytes = unsafe { std::slice::from_raw_parts(data, byte_len) };
            let terminator = bytes.iter().position(|&b| b == 0);
            if declared_length == 0 && terminator.is_none() {
                return ("<truncated ansi string>".to_string(), 0);
            }
            let len = terminator.unwrap_or(byte_len);
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
        TDH_INTYPE_BINARY if declared_length > 0 && declared_length <= available => {
            let bytes = unsafe { std::slice::from_raw_parts(data, declared_length) };
            let mut rendered = String::with_capacity(4 + declared_length * 2);
            rendered.push_str("hex:");
            for byte in bytes {
                let _ = write!(rendered, "{byte:02X}");
            }
            (rendered, declared_length)
        }
        // Known-but-unformatted fixed-width values still have an implicit
        // payload size when TDH reports a zero declared length.
        _ => {
            let length = if declared_length > 0 {
                Some(declared_length)
            } else {
                implicit_fixed_width(in_type, pointer_size)
            };
            match length {
                Some(length) if length <= available => ("<unsupported>".to_string(), length),
                _ => ("<unsupported>".to_string(), 0),
            }
        }
    }
}

fn implicit_fixed_width(in_type: u16, pointer_size: usize) -> Option<usize> {
    match in_type {
        TDH_INTYPE_INT8 | TDH_INTYPE_UINT8 | TDH_INTYPE_ANSICHAR => Some(1),
        TDH_INTYPE_INT16 | TDH_INTYPE_UINT16 | TDH_INTYPE_UNICODECHAR => Some(2),
        TDH_INTYPE_INT32 | TDH_INTYPE_UINT32 | TDH_INTYPE_FLOAT | TDH_INTYPE_BOOLEAN
        | TDH_INTYPE_HEXINT32 => Some(4),
        TDH_INTYPE_INT64 | TDH_INTYPE_UINT64 | TDH_INTYPE_DOUBLE | TDH_INTYPE_FILETIME
        | TDH_INTYPE_HEXINT64 => Some(8),
        TDH_INTYPE_GUID | TDH_INTYPE_SYSTEMTIME => Some(16),
        TDH_INTYPE_POINTER | TDH_INTYPE_SIZET => Some(pointer_size),
        _ => None,
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
        return ("<invalid SID>".to_string(), 0);
    }
    let sub_authority_count = header[1] as usize;
    let length = 8usize.saturating_add(sub_authority_count.saturating_mul(4));
    if length > available {
        return ("<invalid SID>".to_string(), 0);
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

    fn utf16_bytes(value: &str) -> Vec<u8> {
        value
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    fn uint32_property_buffer(names: &[&str]) -> TdhInfoBuffer {
        assert!(!names.is_empty());
        let encoded_names = names
            .iter()
            .map(|name| utf16_bytes(name))
            .collect::<Vec<_>>();
        let metadata_len = std::mem::size_of::<TRACE_EVENT_INFO>()
            + (names.len() - 1) * std::mem::size_of::<EVENT_PROPERTY_INFO>();
        let mut offsets = Vec::with_capacity(names.len());
        let mut next_offset = metadata_len;
        for name in &encoded_names {
            offsets.push(next_offset);
            next_offset += name.len();
        }

        let mut buffer = TdhInfoBuffer::new(next_offset);
        for (name, offset) in encoded_names.iter().zip(&offsets) {
            buffer.as_bytes_mut()[*offset..*offset + name.len()].copy_from_slice(name);
        }
        let info = unsafe { &mut *buffer.as_mut_ptr() };
        info.PropertyCount = names.len() as u32;
        info.TopLevelPropertyCount = names.len() as u32;
        let properties =
            std::ptr::addr_of_mut!(info.EventPropertyInfoArray) as *mut EVENT_PROPERTY_INFO;
        for (index, offset) in offsets.into_iter().enumerate() {
            let property = unsafe { &mut *properties.add(index) };
            property.NameOffset = offset as u32;
            property.Anonymous1.nonStructType.InType = TDH_INTYPE_UINT32;
            property.Anonymous2.count = 1;
            property.Anonymous3.length = 4;
        }
        buffer
    }

    fn event_record_for_payload(payload: &[u8]) -> EVENT_RECORD {
        let mut record: EVENT_RECORD = unsafe { core::mem::zeroed() };
        record.UserData = payload.as_ptr().cast_mut().cast();
        record.UserDataLength = payload.len() as u16;
        record
    }

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
    fn uncached_schema_is_used_when_cache_does_not_contain_key() {
        let cache = EventSchemaCache::default();
        let record: EVENT_RECORD = unsafe { core::mem::zeroed() };
        let key = EventSchemaKey::from_record(&record);
        let uncached = Some(TdhInfoBuffer::new(std::mem::size_of::<TRACE_EVENT_INFO>()));

        let selected = schema_buffer(&cache, &key, &uncached).unwrap();

        assert!(std::ptr::eq(selected, uncached.as_ref().unwrap()));
    }

    #[test]
    fn decode_property_surfaces_struct_children() {
        let struct_name = utf16_bytes("AccessCheck");
        let child_name = utf16_bytes("Denied");
        let metadata_len =
            std::mem::size_of::<TRACE_EVENT_INFO>() + std::mem::size_of::<EVENT_PROPERTY_INFO>();
        let struct_name_offset = metadata_len;
        let child_name_offset = struct_name_offset + struct_name.len();
        let mut buffer = TdhInfoBuffer::new(child_name_offset + child_name.len());
        buffer.as_bytes_mut()[struct_name_offset..child_name_offset].copy_from_slice(&struct_name);
        buffer.as_bytes_mut()[child_name_offset..].copy_from_slice(&child_name);

        let info = unsafe { &mut *buffer.as_mut_ptr() };
        info.PropertyCount = 2;
        let properties =
            std::ptr::addr_of_mut!(info.EventPropertyInfoArray) as *mut EVENT_PROPERTY_INFO;
        unsafe {
            (*properties).NameOffset = struct_name_offset as u32;
            (*properties).Flags.0 = PROPERTY_STRUCT;
            (*properties).Anonymous1.structType.StructStartIndex = 1;
            (*properties).Anonymous1.structType.NumOfStructMembers = 1;
            (*properties).Anonymous2.count = 1;

            let child = properties.add(1);
            (*child).NameOffset = child_name_offset as u32;
            (*child).Anonymous1.nonStructType.InType = TDH_INTYPE_UINT32;
            (*child).Anonymous2.count = 1;
            (*child).Anonymous3.length = 4;
        }

        let payload = 1u32.to_le_bytes();
        let info = unsafe { &*buffer.as_mut_ptr() };
        let context = PropertyDecodeContext {
            info_buf: buffer.as_bytes(),
            info,
            user_data: payload.as_ptr(),
            user_data_len: payload.len(),
            pointer_size: 8,
        };
        let mut offset = 0;
        let mut numeric_values = vec![None; 2];
        let mut properties = Vec::new();
        let mut work_remaining = MAX_DECODE_WORK;

        decode_property(
            0,
            &context,
            &mut offset,
            &mut numeric_values,
            0,
            &mut work_remaining,
            &mut properties,
        )
        .unwrap();

        assert_eq!(
            properties,
            vec![
                ("AccessCheck".to_string(), "<struct>".to_string()),
                ("Denied".to_string(), "1".to_string()),
            ]
        );
        assert_eq!(offset, payload.len());
    }

    #[test]
    fn decode_named_property_stops_after_requested_property() {
        let buffer = uint32_property_buffer(&["Count", "ProcessId", "Trailing"]);
        let payload = [7u32, 42, 99]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        let mut record = event_record_for_payload(&payload);
        let info = unsafe { &*buffer.as_ptr() };

        let process_id =
            decode_named_property(buffer.as_bytes(), info, &mut record, 8, "processid").unwrap();

        assert_eq!(process_id.as_deref(), Some("42"));
    }

    #[test]
    fn decode_named_property_reports_missing_and_truncated_properties() {
        let buffer = uint32_property_buffer(&["Count", "ProcessId"]);
        let payload = [7u32, 42]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        let mut record = event_record_for_payload(&payload);
        let info = unsafe { &*buffer.as_ptr() };

        assert_eq!(
            decode_named_property(buffer.as_bytes(), info, &mut record, 8, "Missing").unwrap(),
            None
        );

        let truncated_payload = 7u32.to_le_bytes();
        let mut truncated_record = event_record_for_payload(&truncated_payload);
        let error = decode_named_property(
            buffer.as_bytes(),
            info,
            &mut truncated_record,
            8,
            "ProcessId",
        )
        .unwrap_err();
        assert_eq!(error.kind, PropertyDecodeErrorKind::PayloadMalformed);
    }

    fn decode_single_property(
        buffer: &TdhInfoBuffer,
        payload: &[u8],
    ) -> Result<Vec<(String, String)>, PropertyDecodeError> {
        let info = unsafe { &*buffer.as_ptr() };
        let context = PropertyDecodeContext {
            info_buf: buffer.as_bytes(),
            info,
            user_data: payload.as_ptr(),
            user_data_len: payload.len(),
            pointer_size: 8,
        };
        let mut offset = 0;
        let mut numeric_values = vec![None; info.PropertyCount as usize];
        let mut results = Vec::new();
        let mut work_remaining = MAX_DECODE_WORK;
        decode_property(
            0,
            &context,
            &mut offset,
            &mut numeric_values,
            0,
            &mut work_remaining,
            &mut results,
        )?;
        Ok(results)
    }

    #[test]
    fn invalid_struct_member_range_is_rejected() {
        let name = utf16_bytes("BadStruct");
        let name_offset = std::mem::size_of::<TRACE_EVENT_INFO>();
        let mut buffer = TdhInfoBuffer::new(name_offset + name.len());
        buffer.as_bytes_mut()[name_offset..].copy_from_slice(&name);
        let info = unsafe { &mut *buffer.as_mut_ptr() };
        info.PropertyCount = 1;
        let property =
            std::ptr::addr_of_mut!(info.EventPropertyInfoArray) as *mut EVENT_PROPERTY_INFO;
        unsafe {
            (*property).NameOffset = name_offset as u32;
            (*property).Flags.0 = PROPERTY_STRUCT;
            (*property).Anonymous1.structType.StructStartIndex = 1;
            (*property).Anonymous1.structType.NumOfStructMembers = 1;
            (*property).Anonymous2.count = 1;
        }

        let error = decode_single_property(&buffer, &[1]).unwrap_err();

        assert_eq!(error.kind, PropertyDecodeErrorKind::Schema);
        assert!(error.message.contains("struct member range"));
    }

    #[test]
    fn empty_struct_is_rejected() {
        let name = utf16_bytes("EmptyStruct");
        let name_offset = std::mem::size_of::<TRACE_EVENT_INFO>();
        let mut buffer = TdhInfoBuffer::new(name_offset + name.len());
        buffer.as_bytes_mut()[name_offset..].copy_from_slice(&name);
        let info = unsafe { &mut *buffer.as_mut_ptr() };
        info.PropertyCount = 1;
        let property =
            std::ptr::addr_of_mut!(info.EventPropertyInfoArray) as *mut EVENT_PROPERTY_INFO;
        unsafe {
            (*property).NameOffset = name_offset as u32;
            (*property).Flags.0 = PROPERTY_STRUCT;
            (*property).Anonymous1.structType.StructStartIndex = 0;
            (*property).Anonymous1.structType.NumOfStructMembers = 0;
            (*property).Anonymous2.count = 4096;
        }

        let error = decode_single_property(&buffer, &[1]).unwrap_err();

        assert_eq!(error.kind, PropertyDecodeErrorKind::Schema);
        assert!(error.message.contains("has no struct members"));
    }

    #[test]
    fn recursive_struct_schema_hits_depth_limit() {
        let name = utf16_bytes("Recursive");
        let name_offset = std::mem::size_of::<TRACE_EVENT_INFO>();
        let mut buffer = TdhInfoBuffer::new(name_offset + name.len());
        buffer.as_bytes_mut()[name_offset..].copy_from_slice(&name);
        let info = unsafe { &mut *buffer.as_mut_ptr() };
        info.PropertyCount = 1;
        let property =
            std::ptr::addr_of_mut!(info.EventPropertyInfoArray) as *mut EVENT_PROPERTY_INFO;
        unsafe {
            (*property).NameOffset = name_offset as u32;
            (*property).Flags.0 = PROPERTY_STRUCT;
            (*property).Anonymous1.structType.StructStartIndex = 0;
            (*property).Anonymous1.structType.NumOfStructMembers = 1;
            (*property).Anonymous2.count = 1;
        }

        let error = decode_single_property(&buffer, &[1]).unwrap_err();

        assert_eq!(error.kind, PropertyDecodeErrorKind::DecoderLimitReached);
        assert!(error.message.contains("nesting exceeds limit"));
    }

    #[test]
    fn invalid_metadata_references_are_rejected() {
        let count_error = resolved_metadata(&[None], 3, "count", 0).unwrap_err();
        assert_eq!(count_error.kind, PropertyDecodeErrorKind::Schema);
        assert!(count_error
            .message
            .contains("out-of-range count property 3"));

        let length_error = resolved_metadata(&[None], 2, "length", 0).unwrap_err();
        assert_eq!(length_error.kind, PropertyDecodeErrorKind::Schema);
        assert!(length_error
            .message
            .contains("out-of-range length property 2"));

        let unresolved_error = resolved_metadata(&[None], 0, "count", 1).unwrap_err();
        assert_eq!(unresolved_error.kind, PropertyDecodeErrorKind::Schema);
        assert!(unresolved_error
            .message
            .contains("unresolved count property 0"));
    }

    #[test]
    fn decode_work_budget_is_enforced() {
        let name = utf16_bytes("Value");
        let name_offset = std::mem::size_of::<TRACE_EVENT_INFO>();
        let mut buffer = TdhInfoBuffer::new(name_offset + name.len());
        buffer.as_bytes_mut()[name_offset..].copy_from_slice(&name);
        let info = unsafe { &mut *buffer.as_mut_ptr() };
        info.PropertyCount = 1;
        let property =
            std::ptr::addr_of_mut!(info.EventPropertyInfoArray) as *mut EVENT_PROPERTY_INFO;
        unsafe {
            (*property).NameOffset = name_offset as u32;
            (*property).Anonymous1.nonStructType.InType = TDH_INTYPE_UINT8;
            (*property).Anonymous2.count = 1;
            (*property).Anonymous3.length = 1;
        }
        let payload = [1u8];
        let info = unsafe { &*buffer.as_ptr() };
        let context = PropertyDecodeContext {
            info_buf: buffer.as_bytes(),
            info,
            user_data: payload.as_ptr(),
            user_data_len: payload.len(),
            pointer_size: 8,
        };
        let mut offset = 0;
        let mut numeric_values = vec![None; 1];
        let mut results = Vec::new();
        let mut work_remaining = 0;

        let error = decode_property(
            0,
            &context,
            &mut offset,
            &mut numeric_values,
            0,
            &mut work_remaining,
            &mut results,
        )
        .unwrap_err();

        assert_eq!(error.kind, PropertyDecodeErrorKind::DecoderLimitReached);
        assert!(error.message.contains("decode work exceeds limit"));
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
    fn property_decode_errors_use_typed_categories() {
        assert_eq!(
            zero_consumption_error("Name", TDH_INTYPE_UNICODESTRING).kind,
            PropertyDecodeErrorKind::PayloadMalformed
        );
        assert_eq!(
            zero_consumption_error("Value", u16::MAX).kind,
            PropertyDecodeErrorKind::UnsupportedPropertyEncoding
        );
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
    fn unterminated_variable_strings_are_rejected() {
        let unicode: Vec<u8> = "abc".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(
            format_property_value(TDH_INTYPE_UNICODESTRING, 0, unicode.as_ptr(), unicode.len()).1,
            0
        );

        let ansi = b"abc";
        assert_eq!(
            format_property_value(TDH_INTYPE_ANSISTRING, 0, ansi.as_ptr(), ansi.len()).1,
            0
        );
    }

    #[test]
    fn declared_strings_larger_than_payload_are_rejected() {
        let unicode = [b'a', 0];
        assert_eq!(
            format_property_value(TDH_INTYPE_UNICODESTRING, 4, unicode.as_ptr(), unicode.len()).1,
            0
        );

        let ansi = [b'a'];
        assert_eq!(
            format_property_value(TDH_INTYPE_ANSISTRING, 2, ansi.as_ptr(), ansi.len()).1,
            0
        );
    }

    #[test]
    fn odd_declared_utf16_length_is_rejected() {
        let unicode = [b'a', 0, b'b'];
        assert_eq!(
            format_property_value(TDH_INTYPE_UNICODESTRING, 3, unicode.as_ptr(), unicode.len()).1,
            0
        );
    }

    #[test]
    fn unsupported_fixed_width_types_advance_without_declared_length() {
        let bytes = [0u8; 16];
        for (in_type, expected) in [
            (TDH_INTYPE_FLOAT, 4),
            (TDH_INTYPE_DOUBLE, 8),
            (TDH_INTYPE_GUID, 16),
            (TDH_INTYPE_FILETIME, 8),
            (TDH_INTYPE_SYSTEMTIME, 16),
        ] {
            let (value, consumed) = format_property_value(in_type, 0, bytes.as_ptr(), bytes.len());
            assert_eq!(value, "<unsupported>");
            assert_eq!(consumed, expected);
        }
    }

    #[test]
    fn trace_logging_schema_events_are_not_cacheable_by_descriptor_alone() {
        let mut item: windows::Win32::System::Diagnostics::Etw::EVENT_HEADER_EXTENDED_DATA_ITEM =
            unsafe { std::mem::zeroed() };
        item.ExtType = EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL as u16;
        let mut record: EVENT_RECORD = unsafe { std::mem::zeroed() };
        record.ExtendedDataCount = 1;
        record.ExtendedData = &mut item;

        assert!(unsafe { has_trace_logging_schema(&record) });
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
        assert_eq!(consumed, bytes.len()); // 8 header + 2*4 sub-authorities
    }

    #[test]
    fn format_property_value_sid_decodes_package_sid() {
        // A package SID (S-1-15-2-...): authority 15, first sub-authority 2
        // (package type), then 7 hash RIDs — 8 sub-authorities total.
        let rids: [u32; 8] = [
            2, 1596788311, 800953881, 392591971, 523554621, 937337662, 1483227527, 333310193,
        ];
        let mut bytes = vec![1u8, rids.len() as u8];
        bytes.extend_from_slice(&[0, 0, 0, 0, 0, 15]); // authority 15
        for rid in rids {
            bytes.extend_from_slice(&rid.to_le_bytes());
        }
        let (val, consumed) = format_property_value(TDH_INTYPE_SID, 0, bytes.as_ptr(), bytes.len());
        assert_eq!(
            val,
            "S-1-15-2-1596788311-800953881-392591971-523554621-937337662-1483227527-333310193"
        );
        assert_eq!(consumed, bytes.len()); // 8 header + 8*4 sub-authorities
    }

    #[test]
    fn format_property_value_sid_decodes_well_known_local_system() {
        // A 1-sub-authority well-known SID: S-1-5-18 (LocalSystem), the shape
        // carried by the event-28 `UserSid` field.
        let mut bytes = vec![1u8, 1];
        bytes.extend_from_slice(&[0, 0, 0, 0, 0, 5]); // authority 5 (NT)
        bytes.extend_from_slice(&18u32.to_le_bytes());
        let (val, consumed) = format_property_value(TDH_INTYPE_SID, 0, bytes.as_ptr(), bytes.len());
        assert_eq!(val, "S-1-5-18");
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn format_property_value_sid_truncated_is_placeholder() {
        // SubAuthorityCount claims 3 (needs 20 bytes) but only 8 present.
        let bytes = [1u8, 3, 0, 0, 0, 0, 0, 15];
        let (val, consumed) = format_property_value(TDH_INTYPE_SID, 0, bytes.as_ptr(), bytes.len());
        assert_eq!(val, "<invalid SID>");
        assert_eq!(consumed, 0);
    }

    #[test]
    fn format_property_value_binary_preserves_hex_payload() {
        let bytes = [0x00, 0x0a, 0xfe, 0xff];
        let (value, consumed) =
            format_property_value(TDH_INTYPE_BINARY, bytes.len(), bytes.as_ptr(), bytes.len());
        assert_eq!(value, "hex:000AFEFF");
        assert_eq!(consumed, bytes.len());
    }
}
