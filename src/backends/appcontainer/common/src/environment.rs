// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::ptr;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::TOKEN_QUERY;
use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use wxc_common::error::WxcError;
use wxc_common::logger::Logger;
use wxc_common::models::ProxyAddress;

const PROXY_VAR_NAMES: &[&str] = &["HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY"];
const CAP_LEARNING_MODE_LOGGING: &str = "learningModeLogging";
const CAP_PERMISSIVE_LEARNING_MODE: &str = "permissiveLearningMode";
const LEARNING_MODE_INFORMATION: &str =
    "learningModeLogging is ENABLED: failed access attempts are logged; accesses are still denied \
     (deny-and-record).";
const PERMISSIVE_LEARNING_MODE_WARNING: &str =
    "*** SECURITY WARNING *** permissiveLearningMode is ENABLED: every access check is logged AND \
     ALLOWED (audit mode); the container is not enforcing deny-by-default.";
const PERMISSIVE_OVERRIDES_LEARNING_WARNING: &str =
    "*** SECURITY WARNING *** permissiveLearningMode overrides learningModeLogging: every access \
     check is logged AND ALLOWED (audit mode); the container is not enforcing deny-by-default.";

pub(crate) fn encode_env_block(entries: &[(String, String)]) -> Vec<u16> {
    let mut sorted: Vec<&(String, String)> = entries.iter().collect();
    sorted.sort_by(|(a, _), (b, _)| a.to_ascii_uppercase().cmp(&b.to_ascii_uppercase()));

    let mut block = Vec::new();
    for (key, value) in sorted {
        block.extend(format!("{key}={value}").encode_utf16());
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    block
}

pub(crate) fn create_default_env_entries() -> Result<Vec<(String, String)>, WxcError> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .map_err(|e| WxcError::Process(format!("OpenProcessToken failed: {e}")))?;

        let mut block_ptr: *mut core::ffi::c_void = ptr::null_mut();
        let result = CreateEnvironmentBlock(&mut block_ptr, Some(token), false);
        let _ = CloseHandle(token);
        result.map_err(|e| WxcError::Process(format!("CreateEnvironmentBlock failed: {e}")))?;

        let entries = parse_environment_block(block_ptr.cast());
        let _ = DestroyEnvironmentBlock(block_ptr);
        Ok(entries)
    }
}

fn parse_environment_block(block: *const u16) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    let mut offset = 0usize;
    loop {
        if unsafe { *block.add(offset) } == 0 {
            break;
        }
        let start = offset;
        while unsafe { *block.add(offset) } != 0 {
            offset += 1;
        }
        let slice = unsafe { std::slice::from_raw_parts(block.add(start), offset - start) };
        let entry = String::from_utf16_lossy(slice);
        offset += 1;

        if let Some(stripped) = entry.strip_prefix('=') {
            if let Some(eq_pos) = stripped.find('=') {
                entries.push((
                    format!("={}", &stripped[..eq_pos]),
                    stripped[eq_pos + 1..].to_string(),
                ));
            }
        } else if let Some((key, value)) = entry.split_once('=') {
            entries.push((key.to_string(), value.to_string()));
        }
    }
    entries
}

pub(crate) fn build_inherited_entries(
    env_vars: &[String],
    proxy_address: Option<&ProxyAddress>,
) -> Result<Vec<(String, String)>, WxcError> {
    let mut entries = create_default_env_entries()?;

    for (key, value) in env_vars
        .iter()
        .filter_map(|entry| entry.split_once('='))
        .map(|(key, value)| (key.to_string(), value.to_string()))
    {
        match entries
            .iter_mut()
            .find(|(existing, _)| existing.eq_ignore_ascii_case(&key))
        {
            Some(slot) => *slot = (key, value),
            None => entries.push((key, value)),
        }
    }

    if let Some(address) = proxy_address {
        inject_proxy_vars(&mut entries, address);
    }

    Ok(entries)
}

pub(crate) fn build_explicit_entries(
    env_vars: &[String],
    proxy_address: Option<&ProxyAddress>,
) -> Vec<(String, String)> {
    let mut entries = env_vars
        .iter()
        .filter_map(|entry| entry.split_once('='))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect();

    if let Some(address) = proxy_address {
        inject_proxy_vars(&mut entries, address);
    }

    entries
}

pub(crate) fn inject_proxy_vars(entries: &mut Vec<(String, String)>, address: &ProxyAddress) {
    entries.retain(|(key, _)| {
        !PROXY_VAR_NAMES
            .iter()
            .any(|name| key.eq_ignore_ascii_case(name))
    });
    let proxy_url = address.to_url();
    entries.push(("HTTP_PROXY".to_string(), proxy_url.clone()));
    entries.push(("HTTPS_PROXY".to_string(), proxy_url));
}

enum LearningModeDiagnostic {
    Information(&'static str),
    SecurityWarning(&'static str),
}

fn effective_learning_mode_diagnostic(capabilities: &[String]) -> Option<LearningModeDiagnostic> {
    let learning = capabilities
        .iter()
        .any(|value| value.eq_ignore_ascii_case(CAP_LEARNING_MODE_LOGGING));
    let permissive = capabilities
        .iter()
        .any(|value| value.eq_ignore_ascii_case(CAP_PERMISSIVE_LEARNING_MODE));

    if permissive {
        Some(LearningModeDiagnostic::SecurityWarning(if learning {
            PERMISSIVE_OVERRIDES_LEARNING_WARNING
        } else {
            PERMISSIVE_LEARNING_MODE_WARNING
        }))
    } else if learning {
        Some(LearningModeDiagnostic::Information(
            LEARNING_MODE_INFORMATION,
        ))
    } else {
        None
    }
}

pub(crate) fn log_learning_mode_capability_diagnostics(
    capabilities: &[String],
    logger: &mut Logger,
) {
    match effective_learning_mode_diagnostic(capabilities) {
        Some(LearningModeDiagnostic::SecurityWarning(message)) => logger.warning_line(message),
        Some(LearningModeDiagnostic::Information(message)) => logger.log_line(message),
        None => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16_block(entries: &[&str]) -> Vec<u16> {
        let mut block = Vec::new();
        for entry in entries {
            block.extend(entry.encode_utf16());
            block.push(0);
        }
        block.push(0);
        block
    }

    #[test]
    fn parses_environment_entries() {
        let block = utf16_block(&["FOO=bar", "=C:=C:\\Users\\test", "A=b=c"]);
        assert_eq!(
            parse_environment_block(block.as_ptr()),
            vec![
                ("FOO".to_string(), "bar".to_string()),
                ("=C:".to_string(), "C:\\Users\\test".to_string()),
                ("A".to_string(), "b=c".to_string()),
            ]
        );
    }

    #[test]
    fn proxy_values_replace_inherited_values() {
        let mut entries = vec![
            ("HTTP_PROXY".to_string(), "old".to_string()),
            ("PATH".to_string(), "value".to_string()),
        ];
        inject_proxy_vars(
            &mut entries,
            &ProxyAddress::new("127.0.0.1".to_string(), 8080),
        );
        assert_eq!(
            entries,
            vec![
                ("PATH".to_string(), "value".to_string()),
                (
                    "HTTP_PROXY".to_string(),
                    "http://127.0.0.1:8080".to_string()
                ),
                (
                    "HTTPS_PROXY".to_string(),
                    "http://127.0.0.1:8080".to_string()
                ),
            ]
        );
    }
}
