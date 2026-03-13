use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::PSID;

/// Convert a UTF-8 string to a null-terminated UTF-16 wide string.
pub fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Convert a UTF-16 slice to a UTF-8 String, stopping at the first null terminator if present.
pub fn from_wide(wide: &[u16]) -> String {
    let len = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    OsString::from_wide(&wide[..len])
        .to_string_lossy()
        .into_owned()
}

/// Convert a SID pointer to its string representation (e.g. "S-1-5-...").
/// Returns `default_value` on failure.
///
/// # Safety
/// The caller must ensure `sid` points to a valid SID structure.
pub unsafe fn sid_to_string(sid: *mut std::ffi::c_void, default_value: &str) -> String {
    let mut string_sid = windows_core::PWSTR::null();
    let psid = PSID(sid);

    let ok = unsafe { ConvertSidToStringSidW(psid, &mut string_sid) };
    if ok.is_err() {
        return default_value.to_string();
    }

    let result = unsafe { string_sid.to_string() }.unwrap_or_else(|_| default_value.to_string());

    unsafe {
        let _ = LocalFree(HLOCAL(string_sid.0 as *mut std::ffi::c_void));
    }

    result
}

/// Decode a Base64-encoded string to raw bytes.
pub fn base64_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    STANDARD.decode(input)
}

/// Encode raw bytes to a Base64 string.
pub fn base64_encode(input: &[u8]) -> String {
    STANDARD.encode(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== Base64 Encode ==========

    #[test]
    fn base64_encode_empty() {
        assert_eq!(base64_encode(b""), "");
    }

    #[test]
    fn base64_encode_simple_string() {
        assert_eq!(base64_encode(b"Hello World"), "SGVsbG8gV29ybGQ=");
    }

    #[test]
    fn base64_encode_json_string() {
        let input = r#"{"script":{"code":"print('test')"}}"#;
        assert_eq!(
            base64_encode(input.as_bytes()),
            "eyJzY3JpcHQiOnsiY29kZSI6InByaW50KCd0ZXN0JykifX0="
        );
    }

    #[test]
    fn base64_encode_special_characters() {
        let encoded = base64_encode(b"Line1\nLine2\tTabbed");
        assert!(!encoded.is_empty());
        assert!(!encoded.contains('\n'));
        assert!(!encoded.contains('\r'));
    }

    #[test]
    fn base64_encode_binary_data() {
        assert_eq!(base64_encode(&[0x00, 0x01, 0x02, 0xFF]), "AAEC/w==");
    }

    // ========== Base64 Decode ==========

    #[test]
    fn base64_decode_empty() {
        assert_eq!(base64_decode("").unwrap(), b"");
    }

    #[test]
    fn base64_decode_valid() {
        assert_eq!(
            base64_decode("SGVsbG8gV29ybGQ=").unwrap(),
            b"Hello World"
        );
    }

    #[test]
    fn base64_decode_json_string() {
        let decoded = base64_decode("eyJzY3JpcHQiOnsiY29kZSI6InByaW50KCd0ZXN0JykifX0=").unwrap();
        assert_eq!(
            String::from_utf8(decoded).unwrap(),
            r#"{"script":{"code":"print('test')"}}"#
        );
    }

    #[test]
    fn base64_decode_invalid() {
        assert!(base64_decode("Invalid!!!Base64").is_err());
    }

    #[test]
    fn base64_decode_binary_data() {
        let decoded = base64_decode("AAEC/w==").unwrap();
        assert_eq!(decoded.len(), 4);
        assert_eq!(decoded, vec![0x00, 0x01, 0x02, 0xFF]);
    }

    // ========== Base64 Round-Trip ==========

    #[test]
    fn base64_roundtrip_simple_string() {
        let original = b"Hello World";
        let decoded = base64_decode(&base64_encode(original)).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn base64_roundtrip_json_config() {
        let original = br#"{"script":{"code":"print('Hello')"}}"#;
        let decoded = base64_decode(&base64_encode(original)).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn base64_roundtrip_special_characters() {
        let original = b"Test\nWith\tSpecial \"Characters\" and 'quotes'";
        let decoded = base64_decode(&base64_encode(original)).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn base64_roundtrip_empty() {
        let decoded = base64_decode(&base64_encode(b"")).unwrap();
        assert_eq!(decoded, b"");
    }

    #[test]
    fn base64_roundtrip_large_string() {
        let original = vec![b'A'; 10_000];
        let decoded = base64_decode(&base64_encode(&original)).unwrap();
        assert_eq!(decoded, original);
    }

    // ========== to_wide / from_wide ==========

    #[test]
    fn to_wide_empty_string() {
        let wide = to_wide("");
        // Should be just the null terminator
        assert_eq!(wide, vec![0u16]);
    }

    #[test]
    fn to_wide_simple_ascii() {
        let wide = to_wide("Hello World");
        let expected: Vec<u16> = "Hello World"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        assert_eq!(wide, expected);
    }

    #[test]
    fn to_wide_extended_ascii() {
        let wide = to_wide("Café");
        let expected: Vec<u16> = "Café".encode_utf16().chain(std::iter::once(0)).collect();
        assert_eq!(wide, expected);
        // 'é' is U+00E9
        assert_eq!(wide[3], 0x00E9);
    }

    #[test]
    fn to_wide_chinese_characters() {
        let wide = to_wide("Hello 世界");
        // 世 = U+4E16, 界 = U+754C
        let no_null = &wide[..wide.len() - 1];
        let expected: Vec<u16> = "Hello 世界".encode_utf16().collect();
        assert_eq!(no_null, &expected[..]);
    }

    #[test]
    fn to_wide_emoji() {
        let wide = to_wide("Test 😀");
        // 😀 = U+1F600, encoded as surrogate pair in UTF-16
        assert!(!wide.is_empty());
        let s = from_wide(&wide);
        assert_eq!(s, "Test 😀");
    }

    #[test]
    fn to_wide_mixed_characters() {
        let wide = to_wide("ASCII é 中 😀");
        let s = from_wide(&wide);
        assert_eq!(s, "ASCII é 中 😀");
    }

    #[test]
    fn to_wide_special_characters() {
        let wide = to_wide("Line1\nLine2\tTabbed");
        let s = from_wide(&wide);
        assert_eq!(s, "Line1\nLine2\tTabbed");
    }

    #[test]
    fn from_wide_empty_string() {
        let wide: Vec<u16> = vec![0u16];
        assert_eq!(from_wide(&wide), "");
    }

    #[test]
    fn from_wide_simple_ascii() {
        let wide: Vec<u16> = "Hello World"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        assert_eq!(from_wide(&wide), "Hello World");
    }

    #[test]
    fn from_wide_unicode_characters() {
        // "Hello 世界"
        let wide: Vec<u16> = "Hello 世界"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        assert_eq!(from_wide(&wide), "Hello 世界");
    }

    #[test]
    fn from_wide_emoji() {
        let wide: Vec<u16> = "Test 😀"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        assert_eq!(from_wide(&wide), "Test 😀");
    }

    #[test]
    fn from_wide_no_null_terminator() {
        // from_wide should handle slices without null terminator
        let wide: Vec<u16> = "Hello".encode_utf16().collect();
        assert_eq!(from_wide(&wide), "Hello");
    }

    #[test]
    fn from_wide_extended_ascii() {
        let wide: Vec<u16> = "Café".encode_utf16().chain(std::iter::once(0)).collect();
        assert_eq!(from_wide(&wide), "Café");
    }

    #[test]
    fn from_wide_large_string() {
        let original = "A".repeat(10_000);
        let wide: Vec<u16> = original
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        assert_eq!(from_wide(&wide), original);
    }

    // ========== Wide Round-Trip ==========

    #[test]
    fn wide_roundtrip_simple() {
        let original = "Hello World";
        assert_eq!(from_wide(&to_wide(original)), original);
    }

    #[test]
    fn wide_roundtrip_unicode() {
        let original = "Hello 世界";
        assert_eq!(from_wide(&to_wide(original)), original);
    }

    #[test]
    fn wide_roundtrip_emoji() {
        let original = "Test 😀 👍";
        assert_eq!(from_wide(&to_wide(original)), original);
    }

    #[test]
    fn wide_roundtrip_special_characters() {
        let original = "Test\nWith\tSpecial \"Characters\" and 'quotes'";
        assert_eq!(from_wide(&to_wide(original)), original);
    }

    #[test]
    fn wide_roundtrip_empty() {
        assert_eq!(from_wide(&to_wide("")), "");
    }

    #[test]
    fn wide_roundtrip_mixed_characters() {
        let original = "ASCII é 中 😀 test";
        assert_eq!(from_wide(&to_wide(original)), original);
    }

    #[test]
    fn wide_roundtrip_large_unicode() {
        let original = "中".repeat(1000);
        assert_eq!(from_wide(&to_wide(&original)), original);
    }

    // ========== sid_to_string ==========

    #[test]
    fn sid_to_string_null_returns_default() {
        let result = unsafe { sid_to_string(std::ptr::null_mut(), "DEFAULT") };
        assert_eq!(result, "DEFAULT");
    }

    #[test]
    fn sid_to_string_null_returns_empty_default() {
        let result = unsafe { sid_to_string(std::ptr::null_mut(), "") };
        assert_eq!(result, "");
    }

}
