// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Helpers for building child-process environment blocks on Windows.
//!
//! Lifted out of `appcontainer_runner.rs` so multiple Windows runners
//! (AppContainer, RestrictedToken / Tier 4) can share the same env-block
//! construction logic without duplicating it. All entry points are
//! security-conscious: the parent process's environment is **not**
//! inherited by default (`CreateEnvironmentBlock(bInherit=FALSE)`).

use std::ptr;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::TOKEN_QUERY;
use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::error::WxcError;
use crate::models::ProxyAddress;

/// Proxy-related env var names to strip/override when building the child env block.
pub const PROXY_VAR_NAMES: &[&str] = &["HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY"];

/// Serialize `KEY=VALUE` pairs into a double-null-terminated UTF-16
/// environment block.
///
/// Entries are sorted case-insensitively by key as required by
/// `CreateProcessW` / `CreateProcessAsUserW`.
pub fn encode_env_block(entries: &[(String, String)]) -> Vec<u16> {
    let mut sorted: Vec<&(String, String)> = entries.iter().collect();
    sorted.sort_by(|(a, _), (b, _)| a.to_ascii_uppercase().cmp(&b.to_ascii_uppercase()));

    let mut block = Vec::new();
    for (key, value) in sorted {
        for ch in format!("{}={}", key, value).encode_utf16() {
            block.push(ch);
        }
        block.push(0);
    }
    block.push(0);
    block
}

/// Create a default environment block for the current user without inheriting
/// the parent process's environment variables.
///
/// Calls `CreateEnvironmentBlock` with `bInherit = FALSE` so that only the
/// system/user profile variables are included (no process-level vars leak in).
/// Returns the entries as `(key, value)` pairs.
pub fn create_default_env_entries() -> Result<Vec<(String, String)>, WxcError> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .map_err(|e| WxcError::Process(format!("OpenProcessToken failed: {e}")))?;

        let mut block_ptr: *mut core::ffi::c_void = ptr::null_mut();
        // bInherit = FALSE: do not inherit the calling process's environment.
        let result = CreateEnvironmentBlock(&mut block_ptr, Some(token), false);
        // Close the token handle regardless of success.
        let _ = CloseHandle(token);
        result.map_err(|e| WxcError::Process(format!("CreateEnvironmentBlock failed: {e}")))?;

        let entries = parse_environment_block(block_ptr as *const u16);
        let _ = DestroyEnvironmentBlock(block_ptr);
        Ok(entries)
    }
}

/// Parse a double-null-terminated UTF-16 environment block into `(key, value)` pairs.
///
/// # Safety
///
/// `block` must point to a valid double-null-terminated UTF-16 string,
/// as produced by `CreateEnvironmentBlock` or [`encode_env_block`].
fn parse_environment_block(block: *const u16) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    let mut offset = 0usize;
    loop {
        // SAFETY: the block is a valid double-null-terminated UTF-16 string.
        let ch = unsafe { *block.add(offset) };
        if ch == 0 {
            break; // double-null terminator
        }
        let start = offset;
        while unsafe { *block.add(offset) } != 0 {
            offset += 1;
        }
        let slice = unsafe { std::slice::from_raw_parts(block.add(start), offset - start) };
        let entry = String::from_utf16_lossy(slice);
        offset += 1; // skip the null terminator

        // Split on the first '=' (env vars can have '=' in the value).
        // Entries that start with '=' are hidden per-drive current-directory vars
        // (e.g. "=C:=C:\Users\foo"). For those, the key includes the leading '='
        // and we split on the second '='.
        if let Some(stripped) = entry.strip_prefix('=') {
            if let Some(eq_pos) = stripped.find('=') {
                let key = format!("={}", &stripped[..eq_pos]);
                let value = stripped[eq_pos + 1..].to_string();
                entries.push((key, value));
            }
        } else if let Some(eq_pos) = entry.find('=') {
            let key = entry[..eq_pos].to_string();
            let value = entry[eq_pos + 1..].to_string();
            entries.push((key, value));
        }
    }
    entries
}

/// Parse explicit `KEY=VALUE` strings into entry pairs, optionally injecting
/// proxy env vars (stripping any pre-existing proxy vars first).
pub fn build_explicit_entries(
    env_vars: &[String],
    proxy_address: Option<&ProxyAddress>,
) -> Vec<(String, String)> {
    let mut entries: Vec<(String, String)> = env_vars
        .iter()
        .filter_map(|entry| {
            entry
                .split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect();

    inject_proxy(&mut entries, proxy_address);
    entries
}

/// Strip any pre-existing proxy vars from `entries` (case-insensitive) and,
/// when `proxy_address` is supplied, append `HTTP_PROXY` / `HTTPS_PROXY`
/// pointing at it. No-op when `proxy_address` is `None`.
pub fn inject_proxy(entries: &mut Vec<(String, String)>, proxy_address: Option<&ProxyAddress>) {
    let Some(addr) = proxy_address else { return };
    entries.retain(|(key, _)| {
        !PROXY_VAR_NAMES
            .iter()
            .any(|name| key.eq_ignore_ascii_case(name))
    });
    let proxy_url = addr.to_url();
    entries.push(("HTTP_PROXY".to_string(), proxy_url.clone()));
    entries.push(("HTTPS_PROXY".to_string(), proxy_url));
}

/// Build a Unicode environment block for `CreateProcessW` /
/// `CreateProcessAsUserW` with proxy env vars injected.
///
/// Sources the base entries from [`create_default_env_entries`] (which
/// calls `CreateEnvironmentBlock(bInherit=FALSE)` — the parent process's
/// environment is **not** inherited), strips any pre-existing proxy
/// vars, injects `HTTP_PROXY` / `HTTPS_PROXY` for `address`, and serializes
/// via [`encode_env_block`]. The returned block is double-null-terminated
/// and sorted case-insensitively by key.
///
/// This is the convenience entry point used by the Tier 4
/// `RestrictedTokenRunner`, which is proxy-only per the v1
/// policy-satisfiability matrix.
pub fn build_proxy_env_block(address: &ProxyAddress) -> Result<Vec<u16>, WxcError> {
    let mut entries = create_default_env_entries()?;
    inject_proxy(&mut entries, Some(address));
    Ok(encode_env_block(&entries))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_block(pairs: &[(&str, &str)]) -> Vec<u16> {
        let mut block: Vec<u16> = Vec::new();
        for (k, v) in pairs {
            for ch in format!("{k}={v}").encode_utf16() {
                block.push(ch);
            }
            block.push(0);
        }
        block.push(0);
        block
    }

    fn decode_block(block: &[u16]) -> Vec<String> {
        let mut entries = Vec::new();
        let mut start = 0usize;
        for i in 0..block.len() {
            if block[i] == 0 {
                if i == start {
                    break;
                }
                entries.push(String::from_utf16_lossy(&block[start..i]));
                start = i + 1;
            }
        }
        entries
    }

    #[test]
    fn parse_environment_block_basic_entries() {
        let block = make_block(&[("FOO", "bar"), ("BAZ", "qux")]);
        let entries = parse_environment_block(block.as_ptr());
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|(k, v)| k == "FOO" && v == "bar"));
        assert!(entries.iter().any(|(k, v)| k == "BAZ" && v == "qux"));
    }

    #[test]
    fn parse_environment_block_preserves_drive_letter_vars() {
        let block = make_block(&[("=C:", r"C:\Users\foo"), ("PATH", r"C:\Windows")]);
        let entries = parse_environment_block(block.as_ptr());
        assert!(entries
            .iter()
            .any(|(k, v)| k == "=C:" && v == r"C:\Users\foo"));
        assert!(entries
            .iter()
            .any(|(k, v)| k == "PATH" && v == r"C:\Windows"));
    }

    #[test]
    fn parse_environment_block_value_with_equals() {
        let block = make_block(&[("URL", "http://example.com/?a=1&b=2")]);
        let entries = parse_environment_block(block.as_ptr());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "URL");
        assert_eq!(entries[0].1, "http://example.com/?a=1&b=2");
    }

    #[test]
    fn parse_environment_block_empty_block() {
        let block: Vec<u16> = vec![0, 0];
        let entries = parse_environment_block(block.as_ptr());
        assert!(entries.is_empty());
    }

    #[test]
    fn encode_env_block_sorts_case_insensitively() {
        let entries = vec![
            ("zebra".to_string(), "1".to_string()),
            ("ALPHA".to_string(), "2".to_string()),
            ("middle".to_string(), "3".to_string()),
        ];
        let block = encode_env_block(&entries);
        let parsed = parse_environment_block(block.as_ptr());
        let keys: Vec<&str> = parsed.iter().map(|(k, _)| k.as_str()).collect();
        // Sort is case-insensitive (uppercase): ALPHA < middle < zebra.
        assert_eq!(keys, vec!["ALPHA", "middle", "zebra"]);
    }

    #[test]
    fn encode_env_block_double_null_terminated() {
        let entries = vec![("FOO".to_string(), "bar".to_string())];
        let block = encode_env_block(&entries);
        let parsed = parse_environment_block(block.as_ptr());
        assert_eq!(parsed, vec![("FOO".to_string(), "bar".to_string())]);
        // Double-null terminator: last element zero, and the entry before it
        // also ends with a single null.
        assert_eq!(block[block.len() - 1], 0);
    }

    #[test]
    fn build_explicit_entries_no_proxy() {
        let env = vec!["FOO=bar".to_string(), "BAZ=qux".to_string()];
        let entries = build_explicit_entries(&env, None);
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|(k, v)| k == "FOO" && v == "bar"));
        assert!(entries.iter().any(|(k, v)| k == "BAZ" && v == "qux"));
    }

    #[test]
    fn build_explicit_entries_strips_and_injects_proxy() {
        let env = vec![
            "FOO=bar".to_string(),
            "http_proxy=http://stale:1234".to_string(),
            "HTTPS_PROXY=https://other:5678".to_string(),
        ];
        let proxy = ProxyAddress::new("127.0.0.1".to_string(), 18080);
        let entries = build_explicit_entries(&env, Some(&proxy));
        // Stale proxy vars stripped (case-insensitive).
        assert!(!entries
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("http_proxy")
                && entries
                    .iter()
                    .filter(|(k2, _)| k2.eq_ignore_ascii_case("http_proxy"))
                    .count()
                    > 1));
        let proxy_url = proxy.to_url();
        assert!(entries
            .iter()
            .any(|(k, v)| k == "HTTP_PROXY" && *v == proxy_url));
        assert!(entries
            .iter()
            .any(|(k, v)| k == "HTTPS_PROXY" && *v == proxy_url));
        // Non-proxy entry preserved.
        assert!(entries.iter().any(|(k, v)| k == "FOO" && v == "bar"));
    }

    #[test]
    fn inject_proxy_noop_when_none() {
        let mut entries = vec![
            ("FOO".to_string(), "bar".to_string()),
            ("HTTP_PROXY".to_string(), "http://keep:1".to_string()),
        ];
        inject_proxy(&mut entries, None);
        assert_eq!(entries.len(), 2);
        assert!(entries
            .iter()
            .any(|(k, v)| k == "HTTP_PROXY" && v == "http://keep:1"));
    }

    #[test]
    fn build_proxy_env_block_injects_http_and_https() {
        let addr = ProxyAddress::new("127.0.0.1".to_string(), 18080);
        let block = build_proxy_env_block(&addr).expect("build_proxy_env_block");
        let entries = decode_block(&block);
        let proxy_url = addr.to_url();
        assert!(
            entries
                .iter()
                .any(|e| e.eq_ignore_ascii_case(&format!("HTTP_PROXY={}", proxy_url))),
            "missing HTTP_PROXY in {entries:?}",
        );
        assert!(
            entries
                .iter()
                .any(|e| e.eq_ignore_ascii_case(&format!("HTTPS_PROXY={}", proxy_url))),
            "missing HTTPS_PROXY in {entries:?}",
        );
    }

    #[test]
    fn build_proxy_env_block_is_double_null_terminated() {
        let addr = ProxyAddress::new("127.0.0.1".to_string(), 18080);
        let block = build_proxy_env_block(&addr).expect("build_proxy_env_block");
        assert!(block.len() >= 2);
        assert_eq!(block[block.len() - 1], 0);
    }

    #[test]
    fn build_proxy_env_block_keys_sorted_case_insensitively() {
        let addr = ProxyAddress::new("127.0.0.1".to_string(), 18080);
        let block = build_proxy_env_block(&addr).expect("build_proxy_env_block");
        let entries = decode_block(&block);
        let keys: Vec<String> = entries
            .iter()
            .filter_map(|e| e.split_once('=').map(|(k, _)| k.to_ascii_uppercase()))
            .collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "env block keys must be sorted (uppercase)");
    }
}
